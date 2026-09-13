#!/usr/bin/env python3
"""Prepare isolated two-container ACI validation from reviewed immutable images.

The public template has secure parameter references, never literal TSIG keys.
The separate parameter file is private. This does not deploy Azure resources.
ACI public port numbers are unique regardless of protocol: this auxiliary BIND
exposes UDP53; a separate frontend must supply ordinary TCP+UDP53 service.
"""
import argparse
import base64
import json
import hashlib
import stat
import os
from pathlib import Path
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from prepare_aci_control import native_attestation_configuration, validate_native_internal_readiness


PUBLIC_FILES = ("node.json", "manifest.json", "member0_cert.pem", "member0_enc_pubk.pem")


def read_small(path, maximum=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("control input must be a regular file")
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError("control input size exceeds bound")
    return data


def strict_json(data):
    def object_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate control field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=object_pairs)


def validated_control(directory):
    public = {name: read_small(directory / "public" / name) for name in PUBLIC_FILES}
    summary = strict_json(read_small(directory / "public/bootstrap-summary.json"))
    manifest = strict_json(public["manifest.json"])
    expected = {"/config/node.json", "/config/member0_cert.pem", "/config/member0_enc_pubk.pem", "/opt/agentdns/governance/constitution.js"}
    if not isinstance(manifest, dict) or set(manifest) != expected or any(not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in manifest.values()):
        raise ValueError("bootstrap manifest paths or digests are invalid")
    if not isinstance(summary, dict) or hashlib.sha256(public["manifest.json"]).hexdigest() != summary.get("config_manifest_sha256"):
        raise ValueError("bootstrap manifest digest disagrees with summary")
    for name in PUBLIC_FILES:
        if name != "manifest.json" and hashlib.sha256(public[name]).hexdigest() != manifest["/config/" + name]:
            raise ValueError("public bootstrap file does not match its pinned manifest")
    certificate = x509.load_pem_x509_certificate(public["member0_cert.pem"])
    if certificate.fingerprint(hashes.SHA256()).hex() != summary.get("member_id"):
        raise ValueError("bootstrap member identity mismatch")
    node = strict_json(public["node.json"])
    if node.get("attestation") != native_attestation_configuration():
        raise ValueError("native ACI bootstrap requires explicit SNP collateral and UVM configuration (--native-snp)")
    validate_native_internal_readiness(node)
    interfaces = node["network"]["rpc_interfaces"]
    if interfaces["primary_rpc_interface"]["bind_address"] != "0.0.0.0:8000" or interfaces["primary_rpc_interface"].get("published_address") != "agentdns.test:8000" or interfaces["agentdns-internal"]["bind_address"] != "127.0.0.1:8001":
        raise ValueError("validation CCF interface addresses are inconsistent")
    if any(interface.get("app_protocol", "HTTP1") != "HTTP1" for interface in interfaces.values()) or not {"iPAddress:127.0.0.1", "dNSName:agentdns.test"}.issubset(node["node_certificate"]["subject_alt_names"]):
        raise ValueError("validation CCF TLS names or commitment protocol are inconsistent")
    if node["command"]["type"] != "Start" or node["command"]["start"]["constitution_files"] != ["/opt/agentdns/governance/constitution.js"] or node["command"]["start"]["members"] != [{"certificate_file":"/config/member0_cert.pem", "encryption_public_key_file":"/config/member0_enc_pubk.pem"}]:
        raise ValueError("validation bootstrap references are inconsistent")
    raw_json = read_small(directory / "private/transfer-key.json")
    provision = strict_json(raw_json)
    if not isinstance(provision, dict) or set(provision) != {"key_name", "secret_base64url", "zones"} or provision["key_name"] != "agentdns-transfer." or provision["zones"] != ["example.test."]:
        raise ValueError("validation transfer scope is inconsistent")
    encoded = provision["secret_base64url"]
    if not isinstance(encoded, str) or len(encoded) != 43:
        raise ValueError("invalid transfer key encoding")
    secret = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
    if len(secret) != 32 or base64.urlsafe_b64encode(secret).rstrip(b"=").decode() != encoded:
        raise ValueError("invalid transfer key encoding")
    standard = read_small(directory / "private/transfer-key.b64").decode().strip()
    if standard != base64.b64encode(secret).decode() or hashlib.sha256(secret).hexdigest() != summary.get("transfer_secret_sha256") or summary.get("transfer_key_name") != provision["key_name"] or summary.get("secondary_endpoint") != "127.0.0.1:53":
        raise ValueError("primary, secondary and governed transfer key do not agree")
    return public, summary, standard, raw_json.decode()


def write_output(path, content, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--primary-image", required=True)
    parser.add_argument("--secondary-image", required=True)
    parser.add_argument("--pull-identity", required=True)
    parser.add_argument("--location", default="northeurope")
    args = parser.parse_args()
    for image in (args.primary_image, args.secondary_image):
        if re.fullmatch(r"[a-z0-9]+\.azurecr\.io/[a-z0-9/_-]+@sha256:[0-9a-f]{64}", image) is None:
            parser.error("both images must have immutable Azure registry digests")
    if args.primary_image.split("/")[0] != args.secondary_image.split("/")[0]:
        parser.error("use the same isolated registry for both images")
    if re.fullmatch(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/\s]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/\s]+", args.pull_identity, re.IGNORECASE) is None:
        parser.error("pull identity must be an Azure user-assigned identity resource ID")
    public, summary, transfer_standard, transfer_json = validated_control(args.control)
    ports_https = [{"port": 8000, "protocol": "TCP"}, {"port": 5353, "protocol": "TCP"}]
    ports_dns = [{"port": 53, "protocol": "UDP"}]
    primary = {"name": "primary", "properties": {
        "image": args.primary_image,
        "command": ["python3", "/opt/agentdns/run.py", "--config", "/config/node.json",
                    "--config-manifest", "/config/manifest.json", "--config-manifest-sha256",
                    summary["config_manifest_sha256"], "--provision-tsig-file", "/secrets/transfer-key.json"],
        "ports": ports_https, "resources": {"requests": {"cpu": 2, "memoryInGB": 4}},
        "volumeMounts": [{"name": "public-config", "mountPath": "/config", "readOnly": True},
                         {"name": "transfer-secret", "mountPath": "/secrets", "readOnly": True},
                         {"name": "primary-state", "mountPath": "/state"}]}}
    secondary = {"name": "secondary", "properties": {
        "image": args.secondary_image, "command": ["python3", "/app/secondary_aci.py"],
        "ports": ports_dns, "resources": {"requests": {"cpu": 2, "memoryInGB": 4}},
        "environmentVariables": [{"name": "AGENTDNS_TRANSFER_KEY_B64", "secureValue": "[parameters('transferKeyB64')]"}]}}
    properties = {"sku": "Confidential", "osType": "Linux", "restartPolicy": "Always",
                  "confidentialComputeProperties": {"ccePolicy": ""},
                  "imageRegistryCredentials": [{"server": args.primary_image.split("/")[0], "identity": args.pull_identity}],
                  "containers": [primary, secondary], "ipAddress": {"type": "Public", "ports": ports_https + ports_dns},
                  "volumes": [{"name": "public-config", "secret": {
                      name: base64.b64encode(public[name]).decode()
                      for name in PUBLIC_FILES}},
                              {"name": "transfer-secret", "secret": {"transfer-key.json": "[base64(parameters('transferKeyJson'))]"}},
                              {"name": "primary-state", "emptyDir": {}}]}
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "parameters": {
                    "transferKeyB64": {"type": "secureString"}, "transferKeyJson": {"type": "secureString"}},
                "resources": [{"type": "Microsoft.ContainerInstance/containerGroups", "apiVersion": "2023-05-01",
                               "name": "agentdns-ccf-validation", "location": args.location,
                               "identity": {"type": "UserAssigned", "userAssignedIdentities": {args.pull_identity: {}}},
                               "tags": {"project": "agentdns", "purpose": "port-validation"}, "properties": properties}]}
    parameters = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                  "contentVersion": "1.0.0.0", "parameters": {
                      "transferKeyB64": {"value": transfer_standard},
                      "transferKeyJson": {"value": transfer_json}}}
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_output(args.output / "ccf.template.json", json.dumps(template, indent=2) + "\n", 0o644)
    write_output(args.output / "ccf.parameters.json", json.dumps(parameters) + "\n", 0o600)
    print("Prepared public template and separate secure parameters; CCE policy generation and review are still required.")


if __name__ == "__main__":
    main()
