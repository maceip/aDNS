#!/usr/bin/env python3
"""Untrusted transport and wakeup helper for the CCF Rust authority.

No signing secrets or private zone keys enter this process. CCF produces TSIG
packets and verifies raw secondary responses. Every returned HTTP mutation must
be globally committed. The TLS service certificate is an explicit trust input.
"""
import argparse
import base64
import concurrent.futures
import contextvars
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import socketserver
import ssl
import threading
import time
from urllib.parse import urlsplit

if __package__:
    from . import telemetry as diagnostics
else:
    try:
        import telemetry as diagnostics
    except ModuleNotFoundError:
        from ccf import telemetry as diagnostics

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


def canonical_transaction(value):
    return (isinstance(value,str) and bool(re.fullmatch(r"(0|[1-9][0-9]{0,19})\.(0|[1-9][0-9]{0,19})",value))
            and all(int(part)<2**64 for part in value.split('.')))


def tracer_for(enclave):
    candidate = getattr(enclave,"telemetry",None)
    return candidate if isinstance(candidate,(diagnostics.Telemetry,diagnostics.NoTelemetry)) else diagnostics.NoTelemetry()


def initialize_diagnostics():
    try:
        return diagnostics.initialize("agentdns-driver",receive_socket=os.environ.get("AGENTDNS_TRACE_SOCKET"))
    except (ImportError,OSError,ValueError):
        LOG.error("OpenTelemetry unavailable; continuing without diagnostics")
        return diagnostics.NoTelemetry()


def dns_metadata(packet):
    """Read only bounded public question/first-SOA metadata for diagnostic links.

    This parser never authorizes DNS traffic. Failure omits metadata and leaves
    the unchanged original packet to the enclave's authoritative validator.
    """
    try:
        if not isinstance(packet,bytes) or not 12<=len(packet)<=MAX_DNS:
            return {}
        def name(offset):
            labels,seen,end = [],set(),None
            for _ in range(128):
                if offset>=len(packet) or offset in seen: raise ValueError()
                seen.add(offset);size=packet[offset]
                if size&0xc0==0xc0:
                    if len(seen)>10 or offset+1>=len(packet): raise ValueError()
                    if end is None: end=offset+2
                    offset=((size&0x3f)<<8)|packet[offset+1]
                    continue
                if size&0xc0 or size>63 or offset+1+size>len(packet): raise ValueError()
                offset+=1
                if size==0:
                    text='.'.join(labels)+'.'
                    if len(text)>255: raise ValueError()
                    return text,end if end is not None else offset
                label=packet[offset:offset+size].decode('ascii').lower()
                if not re.fullmatch('[a-z0-9_-]{1,63}',label): raise ValueError()
                labels.append(label);offset+=size
            raise ValueError()
        if int.from_bytes(packet[4:6],'big')!=1: return {}
        owner,offset=name(12)
        if offset+4>len(packet): return {}
        qtype=int.from_bytes(packet[offset:offset+2],'big');offset+=4
        result={'dns.zone':owner} if qtype in (6,251,252) else {}
        for _ in range(min(int.from_bytes(packet[6:8],'big'),16)):
            rr_owner,offset=name(offset)
            if offset+10>len(packet): raise ValueError()
            kind=int.from_bytes(packet[offset:offset+2],'big')
            size=int.from_bytes(packet[offset+8:offset+10],'big');offset+=10
            end=offset+size
            if end>len(packet): raise ValueError()
            if kind==6:
                _,cursor=name(offset);_,cursor=name(cursor)
                if cursor+20!=end: raise ValueError()
                result.update({'dns.zone':rr_owner,'dns.zone.serial':int.from_bytes(packet[cursor:cursor+4],'big')})
                break
            offset=end
        return result
    except (ValueError,UnicodeError,IndexError):
        return {}


def context_of(span):
    return None if span is None else span.get_span_context()


def link_snapshot(tracer, span, metadata):
    if span is None or 'dns.zone.serial' not in metadata: return
    key=('zone_serial',metadata['dns.zone'],metadata['dns.zone.serial'])
    previous=tracer.cache.get(key)
    if previous is not None and previous!=context_of(span): span.add_link(previous)
    for key,value in metadata.items(): span.set_attribute(key,value)


def exchange_queued(context, work, enclave, queued):
    # Python contextvars do not automatically cross ThreadPoolExecutor.submit.
    return context.run(exchange,work,enclave,queued)


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
    def __init__(self, base_url, ca_file, timeout=10, telemetry=None):
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
        self.telemetry = telemetry if telemetry is not None else diagnostics.NoTelemetry()

    def post(self, path, body, content_type="application/json", binary=False, framed=True):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":")).encode()
        attributes = {"http.route":"/app/internal/"+path,"http.request.method":"POST",
                      "agentdns.committed":False}
        with self.telemetry.span("driver.ccf.request",attributes,kind="CLIENT") as span:
            connection = http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=self.timeout)
            deadline = time.monotonic()+self.timeout
            raw = None
            try:
                # Retain the concrete socket across handshake and buffered HTTP
                # parsing: per-read timeouts alone permit trickled headers.
                raw = socket.create_connection((self.host,self.port),timeout=self.timeout)
                secured = self.context.wrap_socket(raw,server_hostname=self.host,do_handshake_on_connect=False)
                raw = secured
                connection.sock = secured
                with diagnostics.SocketDeadline(secured,deadline):
                    secured.do_handshake()
                    headers = {"Content-Type":content_type}
                    parent = self.telemetry.traceparent()
                    if parent is not None: headers["traceparent"] = parent
                    with self.telemetry.span("driver.ccf.commit_wait",attributes) as wait_span:
                        connection.request("POST","/app/internal/"+path,body,headers)
                        response = connection.getresponse()
                        maximum = (MAX_TRANSFER_BYTES if framed else 1232) if binary else 4*1024*1024
                        data = diagnostics.read_bounded(response,maximum,deadline)
                        for item in (span,wait_span):
                            if item is not None: item.set_attribute("http.response.status_code",response.status)
                        if response.status != 200:
                            raise RuntimeError(f"CCF {path} returned HTTP {response.status}")
                        if response.getheader("x-agentdns-commit-status") != "committed":
                            raise RuntimeError("CCF response is not globally committed")
                        if binary:
                            if framed: validate_frames(data)
                            elif not 12 <= len(data) <= 1232: raise ValueError("invalid authenticated UDP response size")
                            result = data
                        else:
                            result = json.loads(data)
                            if not isinstance(result,dict) or result.get("status") != "committed":
                                raise RuntimeError("CCF response does not confirm global commitment")
                        transaction = response.getheader("x-agentdns-transaction-id")
                        for item in (span,wait_span):
                            if item is not None:
                                item.set_attribute("agentdns.committed",True)
                                if canonical_transaction(transaction): item.set_attribute("ccf.transaction_id",transaction)
                        return result
            finally:
                connection.close()
                if raw is not None: raw.close()


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
        tracer = tracer_for(self.server.enclave)
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
                with tracer.span("driver.dns.axfr",dict(dns_metadata(packet),**{"network.transport":"tcp"}),kind="SERVER") as span:
                    signed_frames = self.server.enclave.post("axfr", packet, "application/dns-message", binary=True)
                    transferred = {}
                    if span is not None:
                        first_length=int.from_bytes(signed_frames[:2],'big')
                        transferred=dns_metadata(signed_frames[2:2+first_length])
                        link_snapshot(tracer,span,transferred)
                        span.set_attribute("agentdns.transfer.bytes",len(signed_frames))
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DNS connection deadline exceeded")
                    self.request.settimeout(min(10, remaining))
                    self.request.sendall(signed_frames)
                    if span is not None and 'dns.zone.serial' in transferred:
                        tracer.cache.put(('zone_serial',transferred['dns.zone'],transferred['dns.zone.serial']),context_of(span))
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
        tracer = tracer_for(self.server.enclave)
        try:
            packet, udp = self.request
            if not 12 <= len(packet) <= MAX_DNS:
                return
            with tracer.span("driver.dns.udp",dict(dns_metadata(packet),**{"network.transport":"udp"}),kind="SERVER") as span:
                response = self.server.enclave.post("udp", packet, "application/dns-message", binary=True, framed=False)
                link_snapshot(tracer,span,dns_metadata(response))
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


def exchange(work, enclave, queued=None):
    validate_work(work)
    host, port = endpoint(work["endpoint"])
    packet = decode(work["packet_base64url"])
    if not 12 <= len(packet) <= MAX_DNS:
        raise ValueError("invalid outbound DNS message")
    tracer = tracer_for(enclave)
    metadata=dns_metadata(packet)
    attributes=dict(metadata,**{"agentdns.work.kind":work['kind'],"agentdns.work.id":work['id'],"network.transport":"udp"})
    if queued is not None: attributes['agentdns.queue.age_ms']=max(0,int((time.monotonic()-queued)*1000))
    links=[tracer.cache.get(('work',work['id']))]
    with tracer.span("driver.secondary.exchange",attributes,links=links,kind="CLIENT") as span:
        link_snapshot(tracer,span,metadata)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        # Connected UDP restricts datagrams to the configured peer; the enclave
        # validates MAC, ID, question, serial and freshness. No trace wire fields.
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            udp.connect((host, port))
            udp.send(packet)
            response = udp.recv(MAX_DNS + 1)
        if len(response) > MAX_DNS:
            raise ValueError("oversized secondary response")
        with tracer.span("driver.secondary.response",attributes) as accepted:
            accepted_result=enclave.post("secondary/response", {"id":work["id"],"endpoint":work["endpoint"],"response_base64url":encode(response)})
            # Response metadata is linked only after the CCF TSIG/nonce checker
            # accepts it and the response transaction is globally committed.
            confirmed=dns_metadata(response)
            # NOTIFY has no serial in its DNS payload. Use only the actual
            # committed response's recorded notified serial, never the newest
            # cached zone serial or a guessed relation to another operation.
            if work['kind']=='notify' and 'dns.zone' in metadata and isinstance(accepted_result,dict):
                state=accepted_result.get('secondary')
                value=state.get('last_notified_serial') if isinstance(state,dict) else None
                if type(value) is int and 0<=value<2**32:
                    confirmed={'dns.zone':metadata['dns.zone'],'dns.zone.serial':value}
            link_snapshot(tracer,accepted,confirmed)
            link_snapshot(tracer,span,confirmed)
            if accepted is not None: accepted.set_attribute('agentdns.committed',True)
            if span is not None and 'dns.zone.serial' in confirmed:
                tracer.cache.put(('zone_serial',confirmed['dns.zone'],confirmed['dns.zone.serial']),context_of(span))
                if work['kind']=='soa':tracer.cache.put(('observed_zone',confirmed['dns.zone']),context_of(accepted))


def lifecycle(enclave, stop, interval):
    # Secondary network delays must never postpone signature maintenance. Keep
    # a bounded queue, run due maintenance every cycle, and dispatch only up to
    # a bounded in-flight window rather than blocking on all 256 exchanges.
    from collections import deque
    backlog = deque()
    futures = set()
    batch_started = 0.0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=SECONDARY_WORKERS)
    tracer = tracer_for(enclave)
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                with tracer.span("driver.lifecycle.poll",{"agentdns.queue.depth":len(backlog)}):
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
                    with tracer.span("driver.secondary.requests",kind="PRODUCER") as produced:
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
                        batch_started = time.monotonic()
                        for item in work:
                            tracer.cache.put(('work',item['id']),context_of(produced))
                            backlog.append((item,batch_started,contextvars.copy_context()))
                while backlog and len(futures) < MAX_OUTSTANDING_EXCHANGES:
                    item,queued,context=backlog.popleft()
                    futures.add(executor.submit(exchange_queued,context,item,enclave,queued))
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
    tracing = initialize_diagnostics()
    enclave = Enclave(args.ccf_url, args.service_cert,telemetry=tracing)
    stop = threading.Event()
    try:
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
    finally:
        tracing.close()


if __name__ == "__main__":
    main()
