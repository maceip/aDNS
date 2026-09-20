#!/usr/bin/env python3
"""Release Authority (D) generation and signing tool for agentdns / agent-hosting.

ADR 0025 / DECISIONS.md #1:
D is a did:x509 P-256 key with a self-signed root certificate held by the operator.
Signatures over canonical JSON {"svn": svn, "payload": payload} use raw 64-byte P-256 (r || s),
base64url-encoded without padding.
"""
import argparse
from domain_registry import get
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def canonical_json(value):
    """JCS-equivalent canonical JSON for bounded primitive structures."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(x) for x in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{json.dumps(k)}:{canonical_json(value[k])}" for k in sorted(value.keys())) + "}"
    raise TypeError(f"unsupported canonical type: {type(value)}")


def mint_d(priv_path: Path, cert_path: Path, valid_years=10):
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, get("release_authority_common_name"))
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365 * valid_years))
        .sign(priv, hashes.SHA256())
    )
    
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_bytes)
        
    cert_path.write_bytes(cert_bytes)
    
    fp = base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).decode().rstrip("=")
    did = get_did(cert_path)
    spki_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return {
        "did": did,
        "public_key_pem": spki_pem,
        "priv_path": str(priv_path),
        "cert_path": str(cert_path),
        "fingerprint": fp
    }


def get_did(cert_path: Path):
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fp = base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).decode().rstrip("=")
    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1 or any(char in common_names[0].value for char in (":", "%", "\n", "\r")):
        raise ValueError("release certificate must have one unambiguous common name")
    return f"did:x509:0:sha256:{fp}::subject:CN:{common_names[0].value}"


def sign_payload(priv_path: Path, cert_path: Path, svn: int, payload: dict):
    did = get_did(cert_path)
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    
    envelope = {"svn": svn, "payload": payload}
    msg_bytes = canonical_json(envelope).encode("utf-8")
    
    der_sig = priv.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode().rstrip("=")
    
    return {
        "did": did,
        "svn": svn,
        "signature": sig_b64
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    
    mint_p = sub.add_parser("mint")
    mint_p.add_argument("--priv", type=Path, required=True)
    mint_p.add_argument("--cert", type=Path, required=True)
    
    sign_p = sub.add_parser("sign")
    sign_p.add_argument("--priv", type=Path, required=True)
    sign_p.add_argument("--cert", type=Path, required=True)
    sign_p.add_argument("--svn", type=int, required=True)
    sign_p.add_argument("--payload", type=Path, required=True)
    sign_p.add_argument("--output", type=Path)
    
    prop_p = sub.add_parser("proposal")
    prop_p.add_argument("--cert", type=Path, required=True)
    prop_p.add_argument("--output", type=Path, required=True)
    prop_p.add_argument("--svn", type=int, default=0)
    
    args = p.parse_args()
    if args.cmd == "mint":
        res = mint_d(args.priv, args.cert)
        print(json.dumps(res, indent=2))
    elif args.cmd == "sign":
        payload = json.loads(args.payload.read_text())
        sig = sign_payload(args.priv, args.cert, args.svn, payload)
        if args.output:
            args.output.write_text(json.dumps(sig, indent=2) + "\n")
        print(json.dumps(sig, indent=2))
    elif args.cmd == "proposal":
        cert = x509.load_pem_x509_certificate(args.cert.read_bytes())
        did = get_did(args.cert)
        spki_pem = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        prop = [
            {
                "name": "adns_set_release_authority",
                "args": {
                    "authority": {
                        "did": did,
                        "public_key_pem": spki_pem,
                        "svn": args.svn,
                        "valid_from": now - 300,
                        "valid_until": now + 10 * 365 * 86400
                    }
                }
            }
        ]
        args.output.write_text(json.dumps(prop, indent=2) + "\n")
        print(f"Wrote proposal to {args.output}")


if __name__ == "__main__":
    main()
