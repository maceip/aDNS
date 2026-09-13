#!/usr/bin/env python3
"""Request one fixed-scope signature from an independently appraised ACI worker.

This sends a control token only after native Rust appraisal succeeds and the
actual pinned TLS peer certificate matches the appraised SPKI. It never submits
the signed operation to CCF; the caller submits and reconciles that envelope.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from http_limits import SocketDeadline, read_bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", type=ipaddress.ip_address, required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--appraiser", type=Path, required=True)
    parser.add_argument("--token-parameters", type=Path, required=True)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--path", choices=("/signed-request", "/lifecycle/action", "/lifecycle/signed-request"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("invalid port")
    spki = (args.capture / "spki.der").read_bytes()
    peer = (args.capture / "peer.der").read_bytes()
    certificate = x509.load_der_x509_certificate(peer)
    if certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != spki:
        raise ValueError("saved peer key differs from evidence key")
    result = subprocess.run([str(args.appraiser.resolve()), "azure-aci-snp", str(args.capture / "evidence.cose"), str(args.capture / "spki.der"), str(args.policy), str(int(time.time()))], capture_output=True, check=True, timeout=30)
    appraisal = json.loads(result.stdout)
    if bytes(appraisal["spki_sha256"]) != hashlib.sha256(spki).digest() or appraisal["valid_until"] <= int(time.time()):
        raise ValueError("appraisal identity or validity mismatch")
    token = json.loads(args.token_parameters.read_text())["parameters"]["captureToken"]["value"]
    if not isinstance(token, str) or re.fullmatch("[0-9a-f]{64}", token) is None:
        raise ValueError("invalid capture token")
    body = args.body.read_bytes()
    if not body or len(body) > 65536:
        raise ValueError("request body exceeds bound")
    context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(peer))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    deadline = time.monotonic() + 30
    connection = http.client.HTTPConnection("agentdns-capture.test", args.port, timeout=30)
    raw = None
    try:
        raw = socket.create_connection((str(args.ip), args.port), timeout=30)
        raw.settimeout(max(.001, deadline-time.monotonic()))
        connection.sock = context.wrap_socket(raw, server_hostname="agentdns-capture.test")
        if connection.sock.getpeercert(binary_form=True) != peer:
            raise ValueError("TLS peer changed after appraisal")
        with SocketDeadline(connection.sock, deadline):
            connection.request("POST", args.path, body, {"Content-Type": "application/json", "Authorization": "Bearer " + token})
            response = connection.getresponse()
            payload = read_bounded(response, 2 * 1024 * 1024, deadline)
            if response.status != 200:
                raise ValueError(f"fixed-scope signing request failed: HTTP {response.status}")
            value = json.loads(payload)
    finally:
        connection.close()
        if raw is not None:
            raw.close()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(value, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "response_sha256": hashlib.sha256(payload).hexdigest(), "peer_spki_sha256": hashlib.sha256(spki).hexdigest(), "native_appraisal_passed": True}))


if __name__ == "__main__":
    main()
