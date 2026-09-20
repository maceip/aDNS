#!/usr/bin/env python3
"""Fetch only public native evidence; this bootstrap does NOT establish trust.

No bearer token or signed mutation is sent. Run the independent Rust appraisal
on the saved evidence/SPKI and a separately reviewed policy before trusting the
saved certificate for subsequent requests. The actual TLS peer key must match.
"""
import argparse
from domain_registry import get
import base64
import hashlib
import http.client
import ipaddress
import json
import pathlib
import socket
import ssl
import subprocess
import time
from http_limits import SocketDeadline, read_bounded


def decode(value):
    if not isinstance(value, str) or len(value) > 2 * 1024 * 1024:
        raise ValueError("base64url input size")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", type=ipaddress.ip_address)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.monotonic() + 15
    raw = None
    connection = http.client.HTTPConnection(str(args.ip), args.port, timeout=15)
    try:
        raw = socket.create_connection((str(args.ip), args.port), timeout=15)
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sock = context.wrap_socket(raw, server_hostname=get("capture_tls_hostname"))
        with SocketDeadline(connection.sock, deadline):
            peer = connection.sock.getpeercert(binary_form=True)
            connection.request("GET", "/capture", headers={"Host": get("capture_tls_hostname")})
            response = connection.getresponse()
            body = read_bounded(response, 2 * 1024 * 1024, deadline)
            if response.status != 200:
                raise ValueError("capture fetch failed")
    finally:
        connection.close()
        if raw is not None:
            raw.close()
    capture = json.loads(body)
    if not isinstance(capture, dict):
        raise ValueError("unexpected capture schema")
    if capture["status"] != "captured_not_appraised" or capture["profile"] != "azure-aci-snp":
        raise ValueError("unexpected capture schema")
    if decode(capture["tls_certificate_der"]) != peer:
        raise ValueError("inventory certificate is not the actual TLS peer")
    pubkey = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"], input=peer, capture_output=True, check=True, timeout=10).stdout
    spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pubkey, capture_output=True, check=True, timeout=10).stdout
    evidence = decode(capture["evidence_payload"])
    if spki != decode(capture["signer_spki_der"]) or hashlib.sha256(spki).hexdigest() != capture["spki_sha256"]:
        raise ValueError("actual TLS peer does not use the captured service key")
    if hashlib.sha256(evidence).hexdigest() != capture["evidence_digest"]:
        raise ValueError("evidence digest mismatch")
    action = capture.get("action")
    if not isinstance(action, dict) or action.get("operation") != "register" or not isinstance(action.get("parameters"), dict):
        raise ValueError("invalid fixed registration action")
    if decode(action.get("signer_spki_der")) != spki or action["parameters"].get("evidence_digest") != capture["evidence_digest"] or action["parameters"].get("evidence_profile") != "azure-aci-snp":
        raise ValueError("fixed action does not match captured evidence and key")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "capture.json").write_text(json.dumps(capture, indent=2) + "\n")
    (args.output / "evidence.cose").write_bytes(evidence)
    (args.output / "spki.der").write_bytes(spki)
    (args.output / "peer.der").write_bytes(peer)
    (args.output / "peer.pem").write_text(ssl.DER_cert_to_PEM_cert(peer))
    (args.output / "action.json").write_text(json.dumps({"action": capture["action"]}, indent=2) + "\n")
    print(json.dumps({"status": "captured_not_appraised", "spki_sha256": capture["spki_sha256"], "evidence_digest": capture["evidence_digest"], "actual_peer_spki_matched": True, "inventory": capture["untrusted_report_inventory"]}, indent=2))


if __name__ == "__main__":
    main()
