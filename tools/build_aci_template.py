#!/usr/bin/env python3
"""Prepare isolated two-container ACI validation from reviewed immutable images.

Initial Start/genesis validation only, not the current authority's lifecycle
owner or a Join/Recover generator. The public template has secure parameter
references, never literal TSIG keys.
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
import datetime
from urllib.parse import quote, unquote, urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from prepare_aci_control import native_attestation_configuration, validate_native_internal_readiness


PUBLIC_FILES = ("node.json", "manifest.json", "member0_cert.pem", "member0_enc_pubk.pem")
OTEL_CA_PATH = "/otel/exporter-ca.pem"
OTEL_HEADER_PARAMETER = "otelExporterHeaders"
OTEL_DISABLED_ENVIRONMENT = [{"name": "OTEL_SDK_DISABLED", "value": "true"}]
OTEL_DISABLED_RULE = {"pattern": "OTEL_SDK_DISABLED=true", "required": True, "strategy": "string"}
_B64_ATOM = r"(?:[A-Za-z0-9]|%2B|%2F)"
# The secret is standard percent-encoded Basic or scoped Bearer authorization. Only the
# encoding shape is public; never put one concrete credential in the CCE policy.
OTEL_HEADER_ENV_PATTERN = (r"^OTEL_EXPORTER_OTLP_HEADERS=authorization=(?:Basic%20"
    + r"(?:" + _B64_ATOM + r"{4}){0,106}(?:" + _B64_ATOM + r"{4}|"
    + _B64_ATOM + r"{2}%3D%3D|" + _B64_ATOM + r"{3}%3D)|Bearer%20[A-Za-z0-9_-]{32,256})$")
OTEL_LABEL_KEYS = ("deployment.environment", "service.namespace", "service.instance.id")


def read_small(path, maximum=65536, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("control input must be a regular file")
        if private and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
            raise ValueError("private control input must be owner-only")
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


def validate_otel_endpoint(endpoint):
    if not isinstance(endpoint,str) or len(endpoint)>512:
        raise ValueError("bounded HTTPS OTLP origin or scoped gateway prefix required")
    try:
        parsed=urlsplit(endpoint)
        valid=(parsed.scheme=="https" and parsed.hostname is not None
            and re.fullmatch(r"[A-Za-z0-9.-]{1,253}",parsed.hostname) is not None
            and (parsed.port is None or 1<=parsed.port<=65535)
            and (not parsed.path or re.fullmatch(r"/_ops/telemetry/[a-z][a-z0-9-]{0,39}",parsed.path) is not None)
            and endpoint==f"https://{parsed.hostname}"+(f":{parsed.port}" if parsed.port is not None else "")+parsed.path)
    except ValueError:valid=False
    if not valid:raise ValueError("canonical HTTPS OTLP origin or scoped gateway prefix required")
    return endpoint


def validate_otel_ca(raw):
    if not isinstance(raw,bytes) or not 0<len(raw)<=65536 or b"PRIVATE KEY" in raw:
        raise ValueError("bounded public OTLP CA required")
    try:
        certificates=x509.load_pem_x509_certificates(raw)
        if len(certificates)!=1 or not certificates[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError()
        now=datetime.datetime.now(datetime.timezone.utc)
        certificate=certificates[0]
        # Ubuntu 24.04 ships cryptography 41; its UTC dates are naive. Newer
        # releases expose aware properties and deprecate the old accessors.
        if hasattr(certificate,"not_valid_before_utc"):
            before,after=certificate.not_valid_before_utc,certificate.not_valid_after_utc
        else:
            before=certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            after=certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        if not before<=now<=after:
            raise ValueError()
    except (ValueError,x509.ExtensionNotFound):
        raise ValueError("one currently valid public OTLP CA certificate required") from None
    return hashlib.sha256(raw).hexdigest()


def otel_environment(endpoint, labels):
    validate_otel_endpoint(endpoint)
    if set(labels)!=set(OTEL_LABEL_KEYS) or any(not isinstance(value,str) or re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}",value) is None for value in labels.values()):
        raise ValueError("three bounded public OTLP resource labels required")
    return {"OTEL_EXPORTER_OTLP_ENDPOINT":endpoint,
        "OTEL_EXPORTER_OTLP_PROTOCOL":"http/protobuf",
        "OTEL_EXPORTER_OTLP_CERTIFICATE":OTEL_CA_PATH,
        "OTEL_RESOURCE_ATTRIBUTES":",".join(key+"="+labels[key] for key in OTEL_LABEL_KEYS)}


def otel_policy_rules(environment):
    return ([{"pattern":name+"="+value,"required":True,"strategy":"string"} for name,value in environment.items()]
        + [{"pattern":OTEL_HEADER_ENV_PATTERN,"required":True,"strategy":"re2"}])


def load_otel_settings(endpoint, ca_path, secret_path, labels):
    environment=otel_environment(endpoint,labels)
    ca=read_small(ca_path);ca_sha256=validate_otel_ca(ca)
    try:
        secret=strict_json(read_small(secret_path,4096,private=True))
        if not isinstance(secret,dict) or set(secret)!={"endpoint","OTEL_EXPORTER_OTLP_HEADERS","header_name","header_value"}:
            raise ValueError()
        if secret["endpoint"]!=endpoint or secret["header_name"].lower()!="authorization":raise ValueError()
        value=secret["header_value"]
        if not isinstance(value,str) or len(value)>512:raise ValueError()
        if value.startswith("Basic "):
            token=value[6:];decoded=base64.b64decode(token,validate=True)
            if base64.b64encode(decoded).decode()!=token:raise ValueError()
            user,password=decoded.split(b":",1)
            if not 1<=len(user)<=64 or not 1<=len(password)<=256 or not all(33<=byte<=126 for byte in decoded):raise ValueError()
        elif re.fullmatch(r"Bearer [A-Za-z0-9_-]{32,256}",value) is None:raise ValueError()
        encoded=secret["OTEL_EXPORTER_OTLP_HEADERS"]
        if not isinstance(encoded,str) or len(encoded)>2048:raise ValueError()
        name,supplied=encoded.split("=",1)
        if name.lower()!="authorization" or unquote(supplied,errors="strict")!=value:raise ValueError()
        header="authorization="+quote(value,safe="")
        if re.fullmatch(OTEL_HEADER_ENV_PATTERN,"OTEL_EXPORTER_OTLP_HEADERS="+header) is None:raise ValueError()
    except (ValueError,TypeError,AttributeError,UnicodeError):
        raise ValueError("invalid private OTLP authorization configuration") from None
    return environment,ca,header,{"endpoint":endpoint,"public_ca_sha256":ca_sha256,"resource_labels":labels,
        "header_policy_pattern":OTEL_HEADER_ENV_PATTERN}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--primary-image", required=True)
    parser.add_argument("--secondary-image", required=True)
    parser.add_argument("--pull-identity", required=True)
    parser.add_argument("--location", default="northeurope")
    parser.add_argument("--otel-endpoint",help="Optional HTTPS origin or /_ops/telemetry/<source> prefix")
    parser.add_argument("--otel-public-ca",type=Path)
    parser.add_argument("--otel-secret-file",type=Path,help="Owner-only Basic/Bearer-auth JSON; never copied to public output")
    parser.add_argument("--otel-deployment-environment")
    parser.add_argument("--otel-service-namespace")
    parser.add_argument("--otel-service-instance")
    args = parser.parse_args()
    for image in (args.primary_image, args.secondary_image):
        if re.fullmatch(r"[a-z0-9]+\.azurecr\.io/[a-z0-9/_-]+@sha256:[0-9a-f]{64}", image) is None:
            parser.error("both images must have immutable Azure registry digests")
    if args.primary_image.split("/")[0] != args.secondary_image.split("/")[0]:
        parser.error("use the same isolated registry for both images")
    if re.fullmatch(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/\s]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/\s]+", args.pull_identity, re.IGNORECASE) is None:
        parser.error("pull identity must be an Azure user-assigned identity resource ID")
    public, summary, transfer_standard, transfer_json = validated_control(args.control)
    otel=None
    otel_values=(args.otel_endpoint,args.otel_public_ca,args.otel_secret_file,args.otel_deployment_environment,args.otel_service_namespace,args.otel_service_instance)
    if any(value is not None for value in otel_values):
        if not all(value is not None for value in otel_values):parser.error("all six optional OTLP settings are required together")
        labels=dict(zip(OTEL_LABEL_KEYS,otel_values[3:]))
        otel=load_otel_settings(args.otel_endpoint,args.otel_public_ca,args.otel_secret_file,labels)
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
    if otel is not None:
        environment,ca,header,otel_summary=otel
        primary["properties"]["environmentVariables"]=[{"name":name,"value":value} for name,value in environment.items()]
        primary["properties"]["environmentVariables"].append({"name":"OTEL_EXPORTER_OTLP_HEADERS","secureValue":f"[parameters('{OTEL_HEADER_PARAMETER}')]"})
        primary["properties"]["volumeMounts"].append({"name":"otel-public-ca","mountPath":"/otel","readOnly":True})
        properties["volumes"].append({"name":"otel-public-ca","secret":{"exporter-ca.pem":base64.b64encode(ca).decode()}})
        template["parameters"][OTEL_HEADER_PARAMETER]={"type":"secureString"}
        parameters["parameters"][OTEL_HEADER_PARAMETER]={"value":header}
    else:
        primary["properties"]["environmentVariables"] = list(OTEL_DISABLED_ENVIRONMENT)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_output(args.output / "ccf.template.json", json.dumps(template, indent=2) + "\n", 0o644)
    write_output(args.output / "ccf.parameters.json", json.dumps(parameters) + "\n", 0o600)
    if otel is not None:
        write_output(args.output / "otel-public-summary.json",json.dumps(otel_summary,indent=2)+"\n",0o644)
        write_output(args.output / "otel-env-rules.json",json.dumps(otel_policy_rules(environment),indent=2)+"\n",0o644)
    else:
        write_output(args.output / "otel-public-summary.json",json.dumps({"trace_export_enabled":False,"mode":"explicitly_disabled"},indent=2)+"\n",0o644)
        write_output(args.output / "otel-env-rules.json",json.dumps([OTEL_DISABLED_RULE],indent=2)+"\n",0o644)
    print("Prepared public template and separate secure parameters; CCE policy generation and review are still required.")


if __name__ == "__main__":
    main()
