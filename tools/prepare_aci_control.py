#!/usr/bin/env python3
"""Create isolated validation member keys and a public CCF bootstrap manifest.

Run only against a new output directory. Private files are mode0600 and never
printed; only public configuration/member material belongs in a launch image.
"""
import argparse
from domain_registry import get, registry_path, registry_sha256
import base64
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def write(path, data, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, "wb") as target:
        target.write(data if isinstance(data, bytes) else data.encode())


def native_attestation_configuration():
    # CCF 7.0.15 samples/config/start_config_aci_sev_snp.json and its pinned
    # host schema. Azure/AMD HTTPS fallback avoids a host-specific THIM address.
    return {
        "snp_security_policy_file": "$UVM_SECURITY_CONTEXT_DIR/security-policy-base64",
        "snp_uvm_endorsements_file": "$UVM_SECURITY_CONTEXT_DIR/reference-info-base64",
        "snp_endorsements_file": "$UVM_SECURITY_CONTEXT_DIR/host-amd-cert-base64",
        "snp_endorsements_servers": [
            {"type": "Azure", "url": "global.acccache.azure.net:443", "max_retries_count": 3},
            {"type": "AMD", "url": "kdsintf.amd.com:443", "max_retries_count": 3},
        ],
    }


def native_internal_endpoints():
    # CCF returns HTTP503 for an ACL-denied readiness probe. The supervisor
    # authenticates this read-only node route before starting its local driver.
    return ["/app/internal/.*", "/node/state"]


def validate_native_internal_readiness(node):
    internal = node["network"]["rpc_interfaces"]["agentdns-internal"]
    if internal.get("accepted_endpoints") != native_internal_endpoints():
        raise ValueError("native internal ACL must allow exact supervisor readiness and internal application routes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--constitution-sha256", required=True)
    parser.add_argument("--native-snp", action="store_true", help="configure native ACI SNP collateral and UVM files; omitted by the local Virtual runner")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.constitution_sha256) is None:
        parser.error("constitution digest must be the exact packaged image file SHA256")
    args.output.mkdir(mode=0o700)
    public = args.output / "public"
    public.mkdir(mode=0o700)
    private = args.output / "private"
    private.mkdir(mode=0o700)
    member = ec.generate_private_key(ec.SECP384R1())
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "agentdns isolated validation member")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(member.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=5))
                   .not_valid_after(now + datetime.timedelta(days=7)).sign(member, hashes.SHA384()))
    write(private / "member0_privk.pem", member.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write(private / "member0_enc_privk.pem", encryption.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write(public / "member0_cert.pem", certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    write(public / "member0_enc_pubk.pem", encryption.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    config = json.loads((Path(__file__).resolve().parents[1] / "ccf/node.example.json").read_text())
    config["node_certificate"]["subject_alt_names"] = ["iPAddress:127.0.0.1", "dNSName:" + get("ccf_rpc_hostname")]
    config["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"] = get("ccf_rpc_hostname") + ":8000"
    config["node_certificate"]["initial_validity_days"] = 7
    config["command"]["start"]["initial_service_certificate_validity_days"] = 7
    if args.native_snp:
        config["attestation"] = native_attestation_configuration()
        config["network"]["rpc_interfaces"]["agentdns-internal"]["accepted_endpoints"] = native_internal_endpoints()
    write(public / "domain-registry.json", registry_path().read_bytes(), 0o644)
    write(public / "node.json", json.dumps(config, sort_keys=True, indent=2) + "\n", 0o644)
    manifest = {"/config/" + path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(public.iterdir())}
    manifest["/opt/agentdns/governance/constitution.js"] = args.constitution_sha256
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    write(public / "manifest.json", manifest_bytes, 0o644)
    key = secrets.token_bytes(32)
    provision = {"key_name": get("transfer_key_name"), "secret_base64url": base64.urlsafe_b64encode(key).rstrip(b"=").decode(), "zones": [get("validation_zone")]}
    write(private / "transfer-key.json", json.dumps(provision, separators=(",", ":")) + "\n")
    write(private / "transfer-key.b64", base64.b64encode(key) + b"\n")
    metadata = {"member_id": certificate.fingerprint(hashes.SHA256()).hex(),
                "config_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "domain_registry_sha256": registry_sha256(),
                "transfer_secret_sha256": hashlib.sha256(key).hexdigest(),
                "transfer_key_name": get("transfer_key_name"), "secondary_endpoint": "127.0.0.1:53"}
    write(public / "bootstrap-summary.json", json.dumps(metadata, indent=2) + "\n", 0o644)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
