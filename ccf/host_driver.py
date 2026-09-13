#!/usr/bin/env python3
"""Untrusted transport and wakeup helper for the CCF Rust authority.

No signing secrets or private zone keys enter this process. CCF produces TSIG
packets and verifies raw secondary responses. Every returned HTTP mutation must
be globally committed. The TLS service certificate is an explicit trust input.
"""
import argparse
import base64
import concurrent.futures
import http.client
import ipaddress
import json
import logging
import signal
import socket
import socketserver
import ssl
import threading
import time
from urllib.parse import urlsplit

MAX_DNS = 65535
MAX_TRANSFER_BYTES = 64 * 1024 * 1024
MAX_TRANSFER_FRAMES = 4096
MAX_TCP_CONNECTIONS = 8
MAX_UDP_HANDLERS = 32
MAX_REQUESTS_PER_CONNECTION = 16
MAX_CONNECTION_SECONDS = 60
MAX_SECONDARY_WORK = 256
SECONDARY_WORKERS = 8
MAX_OUTSTANDING_EXCHANGES = 16
LOG = logging.getLogger("agentdns-driver")


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(text):
    if not isinstance(text, str) or len(text) > MAX_DNS * 4 // 3 + 4:
        raise ValueError("invalid DNS packet encoding")
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if len(raw) > MAX_DNS or encode(raw) != text:
        raise ValueError("noncanonical DNS packet encoding")
    return raw


def endpoint(text):
    if text.startswith("["):
        host, separator, port = text[1:].partition("]:")
        if not separator:
            raise ValueError("IPv6 endpoint must be [address]:port")
    else:
        host, separator, port = text.rpartition(":")
        if not separator:
            raise ValueError("endpoint must be address:port")
    # No hostname lookup: responses are attributed to governed numeric addresses.
    address = ipaddress.ip_address(host)
    port = int(port)
    if not 0 < port <= 65535:
        raise ValueError("invalid endpoint port")
    expected = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    if text != expected:
        raise ValueError("endpoint must use canonical numeric socket presentation")
    return host, port


class Enclave:
    def __init__(self, base_url, ca_file, timeout=10):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("CCF base URL must be an HTTPS origin")
        if parsed.path not in ("", "/"):
            raise ValueError("CCF base URL cannot contain a path")
        if not parsed.hostname:
            raise ValueError("CCF base URL requires a host")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.context = ssl.create_default_context(cafile=ca_file)
        # CCF global-commit callbacks are HTTP/1.1 only; never negotiate HTTP/2.
        self.context.set_alpn_protocols(["http/1.1"])
        self.timeout = timeout

    def post(self, path, body, content_type="application/json", binary=False, framed=True):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":")).encode()
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=self.timeout)
        try:
            connection.request("POST", "/app/internal/" + path, body, {"Content-Type": content_type})
            response = connection.getresponse()
            maximum = (MAX_TRANSFER_BYTES if framed else 1232) if binary else 4 * 1024 * 1024
            data = bounded_response(response, maximum, self.timeout)
            if len(data) > maximum:
                raise ValueError("CCF response too large")
            if response.status != 200:
                raise RuntimeError(f"CCF {path} returned HTTP {response.status}")
            if response.getheader("x-agentdns-commit-status") != "committed":
                raise RuntimeError("CCF response is not globally committed")
            if binary:
                if framed:
                    validate_frames(data)
                elif not 12 <= len(data) <= 1232:
                    raise ValueError("invalid authenticated UDP response size")
                return data
            result = json.loads(data)
            if not isinstance(result, dict) or result.get("status") != "committed":
                raise RuntimeError("CCF response does not confirm global commitment")
            return result
        finally:
            connection.close()


def bounded_response(response, maximum, timeout):
    # read1 performs at most one underlying read per call. A trickling body
    # cannot reset the total deadline indefinitely.
    deadline = time.monotonic() + timeout
    chunks = bytearray()
    while len(chunks) <= maximum:
        if time.monotonic() >= deadline:
            raise TimeoutError("CCF response deadline exceeded")
        chunk = response.read1(min(65536, maximum + 1 - len(chunks)))
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
    raise ValueError("CCF response too large")


def validate_frames(data):
    if len(data) > MAX_TRANSFER_BYTES:
        raise ValueError("zone transfer exceeds byte bound")
    position = 0
    count = 0
    while position < len(data):
        if len(data) - position < 2:
            raise ValueError("truncated DNS TCP length")
        length = int.from_bytes(data[position:position + 2], "big")
        position += 2
        if length < 12 or length > len(data) - position:
            raise ValueError("invalid DNS TCP frame")
        position += length
        count += 1
        if count > MAX_TRANSFER_FRAMES:
            raise ValueError("zone transfer exceeds frame bound")
    if count == 0:
        raise ValueError("empty zone transfer")


def exact(stream, size, deadline=None):
    data = bytearray()
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("DNS connection deadline exceeded")
            stream.settimeout(min(10, remaining))
        block = stream.recv(size - len(data))
        if not block:
            if not data:
                return None
            raise EOFError("truncated TCP request")
        data.extend(block)
    return bytes(data)


class TransferHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            deadline = time.monotonic() + MAX_CONNECTION_SECONDS
            for _ in range(MAX_REQUESTS_PER_CONNECTION):
                length = exact(self.request, 2, deadline)
                if length is None:
                    return
                length = int.from_bytes(length, "big")
                if length < 12:
                    raise ValueError("short DNS request")
                packet = exact(self.request, length, deadline)
                if packet is None:
                    raise EOFError("missing DNS request")
                signed_frames = self.server.enclave.post("axfr", packet, "application/dns-message", binary=True)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("DNS connection deadline exceeded")
                self.request.settimeout(min(10, remaining))
                self.request.sendall(signed_frames)
        except (OSError, ValueError, RuntimeError, EOFError, http.client.HTTPException) as error:
            LOG.warning("transfer rejected: %s", error)


class AdmissionBoundMixin:
    # Admission must precede ThreadingMixIn.process_request: acquiring inside
    # handle() bounds work but still allows an unbounded burst of new threads.
    def process_request(self, request, client_address):
        if not self.permits.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.permits.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.permits.release()


class TransferServer(AdmissionBoundMixin, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, enclave):
        self.enclave = enclave
        self.permits = threading.BoundedSemaphore(MAX_TCP_CONNECTIONS)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, TransferHandler)


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            packet, udp = self.request
            if not 12 <= len(packet) <= MAX_DNS:
                return
            response = self.server.enclave.post("udp", packet, "application/dns-message", binary=True, framed=False)
            udp.sendto(response, self.client_address)
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
            LOG.warning("UDP query rejected: %s", error)


class UdpServer(AdmissionBoundMixin, socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = MAX_DNS

    def __init__(self, address, enclave):
        self.enclave = enclave
        self.permits = threading.BoundedSemaphore(MAX_UDP_HANDLERS)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, UdpHandler)


def validate_work(work):
    if not isinstance(work, dict) or set(work) != {"id", "endpoint", "kind", "packet_base64url"}:
        raise ValueError("invalid secondary work fields")
    if not isinstance(work["id"], str) or len(work["id"]) != 32 or any(c not in "0123456789abcdef" for c in work["id"]):
        raise ValueError("invalid secondary work ID")
    if not isinstance(work["endpoint"], str) or work["kind"] not in ("soa", "notify"):
        raise ValueError("invalid secondary work scope")
    endpoint(work["endpoint"])
    packet = decode(work["packet_base64url"])
    if not 12 <= len(packet) <= MAX_DNS:
        raise ValueError("invalid outbound DNS message")
    return work


def exchange(work, enclave):
    validate_work(work)
    host, port = endpoint(work["endpoint"])
    packet = decode(work["packet_base64url"])
    if not 12 <= len(packet) <= MAX_DNS:
        raise ValueError("invalid outbound DNS message")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    # Connected UDP restricts datagrams to the configured peer; the enclave also
    # validates the MAC, request ID, question, serial and challenge freshness.
    with socket.socket(family, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        udp.connect((host, port))
        udp.send(packet)
        response = udp.recv(MAX_DNS + 1)
    if len(response) > MAX_DNS:
        raise ValueError("oversized secondary response")
    enclave.post("secondary/response", {"id": work["id"], "endpoint": work["endpoint"], "response_base64url": encode(response)})


def lifecycle(enclave, stop, interval):
    # Secondary network delays must never postpone signature maintenance. Keep
    # a bounded queue, run due maintenance every cycle, and dispatch only up to
    # a bounded in-flight window rather than blocking on all 256 exchanges.
    from collections import deque
    backlog = deque()
    futures = set()
    batch_started = 0.0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=SECONDARY_WORKERS)
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                enclave.post("maintenance", {})
                for future in list(futures):
                    if future.done():
                        futures.remove(future)
                        try:
                            future.result()
                        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
                            LOG.warning("secondary not confirmed: %s", error)
                if backlog and time.monotonic() - batch_started >= 240:
                    backlog.clear()
                    LOG.warning("discarded undispatched secondary work before its 300-second expiry")
                if not backlog and not futures:
                    result = enclave.post("secondary/requests", {})
                    if not isinstance(result, dict):
                        raise ValueError("invalid secondary work response")
                    work = result.get("work", [])
                    if not isinstance(work, list) or len(work) > MAX_SECONDARY_WORK:
                        raise ValueError("invalid secondary work list")
                    ids = set()
                    for item in work:
                        validate_work(item)
                        if item["id"] in ids:
                            raise ValueError("duplicate secondary work ID")
                        ids.add(item["id"])
                    backlog.extend(work)
                    batch_started = time.monotonic()
                while backlog and len(futures) < MAX_OUTSTANDING_EXCHANGES:
                    futures.add(executor.submit(exchange, backlog.popleft(), enclave))
            except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
                LOG.error("autonomous maintenance failed: %s", error)
            stop.wait(max(0, interval - (time.monotonic() - started)))
    finally:
        # At most eight bounded socket operations remain running. Do not drain
        # stale queued work during shutdown, or block wakeups behind a dead peer.
        executor.shutdown(wait=False, cancel_futures=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ccf-url", default="https://127.0.0.1:8001")
    parser.add_argument("--service-cert", required=True)
    parser.add_argument("--listen", default="0.0.0.0:5353")
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()
    if not 1 <= args.interval <= 60:
        parser.error("maintenance interval must be between 1 and 60 seconds")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    enclave = Enclave(args.ccf_url, args.service_cert)
    stop = threading.Event()
    with TransferServer(endpoint(args.listen), enclave) as server, UdpServer(endpoint(args.listen), enclave) as udp_server:
        def shutdown(*_):
            if stop.is_set():
                return
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()
            threading.Thread(target=udp_server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        worker = threading.Thread(target=lifecycle, args=(enclave, stop, args.interval), daemon=True)
        worker.start()
        udp_thread = threading.Thread(target=udp_server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
        udp_thread.start()
        server.serve_forever(poll_interval=0.5)
        stop.set()
        udp_server.shutdown()
        udp_thread.join(timeout=5)
        worker.join(timeout=15)


if __name__ == "__main__":
    main()
