#!/usr/bin/env python3
"""Authenticate a CCF TLS node with genuine SNP before trusting its service CA.

Only public GETs are sent during bootstrap. Policy is an independent input,
never synthesized from observed claims. A distinct Rust node audit performs
cryptographic appraisal; this helper cannot bypass service request admission.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import threading
import subprocess
import time
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
BOOTSTRAP_DEADLINE_SECONDS = 15


def connect_unhandshaken(context, host, port, connect_host=None):
    raw = socket.create_connection((connect_host or host, port), timeout=min(10, BOOTSTRAP_DEADLINE_SECONDS))
    try:
        # Arm the absolute timer on the retained TLS socket before handshake.
        return context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
    except BaseException:
        raw.close()
        raise


def public_get(host, port, path, expected_peer=None, connect_host=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=10)
    deadline = time.monotonic() + BOOTSTRAP_DEADLINE_SECONDS
    stream = [None]
    lock = threading.Lock()
    def expire():
        with lock:
            if stream[0] is not None:
                try:
                    # Shutdown wakes a blocking buffered HTTP header/body read.
                    stream[0].shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    timer = threading.Timer(BOOTSTRAP_DEADLINE_SECONDS, expire)
    timer.daemon = True
    timer.start()
    try:
        connection.sock = connect_unhandshaken(context, host, port, connect_host=connect_host)
        with lock:
            stream[0] = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CCF bootstrap response deadline exceeded")
        connection.sock.settimeout(min(10, remaining))
        connection.sock.do_handshake()
        peer = connection.sock.getpeercert(binary_form=True)
        if expected_peer is not None and peer != expected_peer:
            raise ValueError("TLS peer changed after the native node audit")
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"public CCF bootstrap endpoint returned HTTP {response.status}")
        body = bytearray()
        while len(body) <= MAX_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("CCF bootstrap response deadline exceeded")
            block = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        if time.monotonic() >= deadline:
            raise TimeoutError("CCF bootstrap response deadline exceeded")
        if len(body) > MAX_BYTES:
            raise ValueError("CCF bootstrap response too large")
        return bytes(body), peer
    finally:
        timer.cancel()
        timer.join()
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--connect-ip", help="Override socket connect IP (keeps TLS SNI from url)")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, default=Path("target/debug/examples/audit_ccf_node"))
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        parser.error("URL must be an HTTPS origin without credentials or path")
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    kwargs = {"connect_host": args.connect_ip} if args.connect_ip else {}
    quote, peer = public_get(url.hostname, url.port or 443, "/node/quotes/self", **kwargs)
    quote_file, peer_file = args.output / "node-quote.json", args.output / "node-peer.der"
    quote_file.write_bytes(quote)
    peer_file.write_bytes(peer)
    now = int(time.time())
    result = subprocess.run([str(args.verifier.resolve()), str(quote_file), str(peer_file), str(args.policy), str(now)], capture_output=True, check=True, text=True, timeout=30)
    audit = json.loads(result.stdout)
    if audit.get("purpose") != "ccf-node-tls-bootstrap-only" or audit["valid_until"] <= int(time.time()):
        raise ValueError("native node audit did not establish a current TLS identity")
    # This request is sent only after matching the actual TLS peer against the
    # independently audited certificate, before any HTTP bytes are transmitted.
    network_raw, _ = public_get(url.hostname, url.port or 443, "/node/network", expected_peer=peer, **kwargs)
    network = json.loads(network_raw)
    service_pem = network.get("service_certificate")
    if not isinstance(service_pem, str):
        raise ValueError("authenticated node did not return a service certificate")
    service_der = ssl.PEM_cert_to_DER_cert(service_pem)
    subprocess.run(["openssl", "x509", "-inform", "DER", "-noout"], input=service_der, check=True, capture_output=True)
    (args.output / "authenticated-network.json").write_bytes(network_raw)
    (args.output / "service_cert.pem").write_text(service_pem)
    audit["actual_tls_peer_certificate_sha256"] = hashlib.sha256(peer).hexdigest()
    audit["authenticated_service_certificate_sha256"] = hashlib.sha256(service_der).hexdigest()
    audit["audited_at"] = now
    (args.output / "node-audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
