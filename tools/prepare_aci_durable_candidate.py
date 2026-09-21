#!/usr/bin/env python3
"""Prepare an OFFLINE new-genesis candidate using existing public member keys.

Never generates keys, reads private parameters, starts CCF, or contacts Azure.
The generated secure parameter TEMPLATE is deliberately not deployable as-is.
Durable ledger storage does not make CCF Start a restart/recovery command.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from build_aci_template import PUBLIC_FILES, OTEL_DISABLED_ENVIRONMENT, OTEL_DISABLED_RULE, read_small, strict_json, write_output


STORAGE_KEY_PARAMETER = "durableStorageAccountKey"
LOGGING_PARAMETERS = {"logAnalyticsWorkspaceId": {"type": "string"},
                      "logAnalyticsWorkspaceKey": {"type": "secureString"}}
RESTART_CONTRACT = "one-shot-new-genesis; subsequent startup requires live-peer Join or member-authorized Recover"
PLATFORM_ENV_RULES = [
    {"pattern": r"^UVM_SECURITY_CONTEXT_DIR=/security-context[-a-zA-Z0-9]*$", "required": False, "strategy": "re2"},
    {"pattern": r"^APP_IDENTITY_ENDPOINT=.{1,2048}$", "required": False, "strategy": "re2"},
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def retained_logging_configuration():
    return {"logAnalytics": {
        "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
        "workspaceKey": "[parameters('logAnalyticsWorkspaceKey')]"}}


def logging_workspace_template(location):
    """Public foundation resource; deployment and credential retrieval are separate."""
    return {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0", "resources": [{
                "type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2023-09-01",
                "name": "adns-authority-logs", "location": location,
                "tags": {"project": "agentdns", "purpose": "authority-recovery"},
                "properties": {"sku": {"name": "PerGB2018"}, "retentionInDays": 30,
                               "publicNetworkAccessForIngestion": "Enabled",
                               "publicNetworkAccessForQuery": "Enabled",
                               "features": {"disableLocalAuth": False}}}]}


def validate_retained_logging(template, *, required=False):
    """Validate creation-time collection without opening workspace credentials."""
    resources = template.get("resources", [])
    properties = resources[0]["properties"] if resources else {}
    configured = "diagnostics" in properties
    parameters = template["parameters"]
    if not configured:
        if required or any(name in parameters for name in LOGGING_PARAMETERS):
            raise ValueError("creation-time retained logging is required")
        return {"configured": False}
    if properties["diagnostics"] != retained_logging_configuration():
        raise ValueError("retained logging must use exact workspace parameter references")
    if any(parameters.get(name) != spec for name, spec in LOGGING_PARAMETERS.items()):
        raise ValueError("workspace ID and secure key parameters must have no defaults")
    return {"configured": True, "collection": "ACI stdout/stderr and container events from creation",
            "workspace_id_parameter": "logAnalyticsWorkspaceId",
            "workspace_key_parameter": "logAnalyticsWorkspaceKey",
            "acceptance": "verify native startup logs and events in the selected retained workspace after deployment"}


def validate_durable_candidate(template, containers, volumes, node, policies=None):
    """Reject unsafe path, writer, startup, secret and CCE mount substitutions."""
    resource = template["resources"][0]
    properties = resource["properties"]
    validate_retained_logging(template, required=True)
    if re.fullmatch(r"agentdns-ccf-replacement-[0-9]{8}", resource["name"]) is None:
        raise ValueError("distinct replacement group name required")
    if properties.get("restartPolicy") != "Never" or node["command"]["type"] != "Start":
        raise ValueError("candidate is one-shot Start, never automatic recovery")
    if node["command"]["start"]["constitution_files"] != ["/opt/agentdns/governance/constitution.js"]:
        raise ValueError("candidate must pin the image-packaged constitution")
    if node["command"]["start"]["members"] != [{"certificate_file": "/config/member0_cert.pem", "encryption_public_key_file": "/config/member0_enc_pubk.pem"}]:
        raise ValueError("candidate must use the pinned existing public member inputs")
    if node["ledger"]["directory"] != "/durable/ledger" or node["snapshots"]["directory"] != "/durable/snapshots":
        raise ValueError("ledger and snapshots require exact durable paths")
    if node["ledger"].get("read_only_directories") or node["output_files"]["pid_file"] != "node.pid":
        raise ValueError("no alternate ledger paths; PID must remain local")
    fqdn = resource["name"] + "." + resource["location"] + ".azurecontainer.io"
    interface = node["network"]["rpc_interfaces"]["primary_rpc_interface"]
    if interface["published_address"] != fqdn + ":8000" or "dNSName:" + fqdn not in node["node_certificate"]["subject_alt_names"]:
        raise ValueError("candidate FQDN must bind published address and certificate SAN")
    if properties["ipAddress"].get("dnsNameLabel") != resource["name"]:
        raise ValueError("distinct candidate DNS label required")
    if template["parameters"].get(STORAGE_KEY_PARAMETER) != {"type": "secureString"}:
        raise ValueError("storage key requires secureString without a default")
    if volumes.get("primary-state") != {"name": "primary-state", "emptyDir": {}}:
        raise ValueError("PID and supervisor state must remain on local emptyDir")
    durable = volumes.get("durable-state", {})
    if set(durable) != {"name", "azureFile"}:
        raise ValueError("dedicated Azure Files volume required")
    share = durable["azureFile"]
    if (set(share) != {"shareName", "storageAccountName", "storageAccountKey", "readOnly"}
            or re.fullmatch(r"adnsrecovery[0-9]{8}", share["storageAccountName"]) is None
            or share["shareName"] != "ccf-replacement-" + resource["name"].rsplit("-", 1)[1]
            or share["storageAccountKey"] != "[parameters('" + STORAGE_KEY_PARAMETER + "')]"
            or share["readOnly"] is not False):
        raise ValueError("dedicated recovery account/share and secure key reference required")
    mounts = containers["primary"]["volumeMounts"]
    expected = [{"name": "public-config", "mountPath": "/config", "readOnly": True},
                {"name": "transfer-secret", "mountPath": "/secrets", "readOnly": True},
                {"name": "primary-state", "mountPath": "/state"},
                {"name": "durable-state", "mountPath": "/durable", "readOnly": False}]
    if mounts != expected or containers["secondary"].get("volumeMounts", []):
        raise ValueError("one primary durable writer; exact local and durable mounts required")
    if policies is not None:
        expected_mount = {"destination": "/durable", "options": ["rbind", "rshared", "rw"],
                          "source": "sandbox:///tmp/atlas/azureFileVolume/.+", "type": "bind"}
        actual = [item for item in policies["primary"]["mounts"] if item["destination"] == "/durable"]
        if actual != [expected_mount] or any(item["destination"] == "/durable" for item in policies["secondary"]["mounts"]):
            raise ValueError("CCE must constrain the sole durable mount")
        for policy in policies.values():
            if policy.get("exec_processes") or policy.get("signals") or policy.get("allow_elevated"):
                raise ValueError("candidate CCE must not permit exec, signals or elevation")
            if policy.get("allow_stdio_access") is not True:
                raise ValueError("candidate CCE must permit stdout/stderr collection")
        for expected_rule in PLATFORM_ENV_RULES:
            actual_rules = [rule for rule in policies["primary"]["env_rules"] if rule["pattern"].lstrip("^").startswith(expected_rule["pattern"].lstrip("^").split("=", 1)[0] + "=")]
            if actual_rules != [expected_rule]:
                raise ValueError("exact optional ACI platform environment rules required")
    return {"configured": True, "account": share["storageAccountName"], "share": share["shareName"],
            "ledger": "/durable/ledger", "snapshots": "/durable/snapshots", "local_state": "/state",
            "startup": RESTART_CONTRACT, "writer_limit": "one container group per share; no distributed writer fence"}


def finalize_policy(candidate_template, confcom_template):
    """Retain generated layers/mounts and apply only the reviewed environment rules.

    Confcom requires tags for archive input, so compare every other input byte
    structurally before restoring the independently checked immutable digests.
    Keep the original generated policy separately for a reviewable exact delta.
    """
    comparable = copy.deepcopy(confcom_template)
    actual_properties = comparable["resources"][0]["properties"]
    expected_properties = candidate_template["resources"][0]["properties"]
    for actual, expected in zip(actual_properties["containers"], expected_properties["containers"], strict=True):
        if actual["properties"]["image"].rsplit(":", 1)[0] != expected["properties"]["image"].split("@", 1)[0]:
            raise ValueError("confcom input image repository differs")
        actual["properties"]["image"] = expected["properties"]["image"]
    encoded = actual_properties["confidentialComputeProperties"]["ccePolicy"]
    actual_properties["confidentialComputeProperties"]["ccePolicy"] = ""
    if comparable != candidate_template:
        raise ValueError("confcom input differs beyond image tag and generated policy")
    raw = base64.b64decode(encoded, validate=True).decode()
    match = re.search(r"(?m)^containers\s*:=\s*", raw)
    if match is None:
        raise ValueError("missing generated containers")
    entries, end = json.JSONDecoder().raw_decode(raw[match.end():])
    policies = {entry["name"]: entry for entry in entries}
    if len(entries) != 3 or set(policies) != {"primary", "secondary", "pause-container"}:
        raise ValueError("unexpected generated containers")
    primary = policies["primary"]["env_rules"]
    disabled = next(c["properties"] for c in expected_properties["containers"] if c["name"] == "primary").get("environmentVariables") == OTEL_DISABLED_ENVIRONMENT
    if disabled:
        matches = [i for i, rule in enumerate(primary) if rule["pattern"].lstrip("^").startswith("OTEL_")]
        if len(matches) != 1 or primary[matches[0]] != {**OTEL_DISABLED_RULE, "required": False}:
            raise ValueError("unexpected generated disabled trace export rule")
        primary[matches[0]] = copy.deepcopy(OTEL_DISABLED_RULE)
    if any(rule["pattern"].lstrip("^").startswith(("UVM_SECURITY_CONTEXT_DIR=", "APP_IDENTITY_ENDPOINT=")) for rule in primary):
        raise ValueError("unexpected preexisting platform environment rule")
    primary.extend(copy.deepcopy(PLATFORM_ENV_RULES))
    secondary = policies["secondary"]["env_rules"]
    matches = [i for i, rule in enumerate(secondary) if rule["pattern"].lstrip("^").startswith("AGENTDNS_TRANSFER_KEY_B64=")]
    if len(matches) != 1 or secondary[matches[0]] != {"pattern": "AGENTDNS_TRANSFER_KEY_B64=.*", "required": False, "strategy": "re2"}:
        raise ValueError("unexpected generated transfer environment rule")
    secondary[matches[0]] = {"pattern": "^AGENTDNS_TRANSFER_KEY_B64=[A-Za-z0-9+/]{43}=$", "required": True, "strategy": "re2"}
    final = raw[:match.end()] + json.dumps(entries, separators=(",", ":")) + raw[match.end() + end:]
    result = copy.deepcopy(candidate_template)
    result["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] = base64.b64encode(final.encode()).decode()
    return result, {"generated_policy_sha256": digest(raw.encode()), "final_policy_sha256": digest(final.encode()),
                    "delta": "primary optional UVM/APP_IDENTITY rules retained; explicit disabled trace rule made required when configured; secondary TSIG pattern narrowed; generated mounts/layers/default infrastructure fragments unchanged"}


def prepare(baseline, member_certificate, member_encryption_key, date):
    if re.fullmatch(r"[0-9]{8}", date) is None:
        raise ValueError("eight-digit candidate date required")
    if b"PRIVATE KEY" in member_certificate or b"PRIVATE KEY" in member_encryption_key:
        raise ValueError("public member inputs only")
    certificate = x509.load_pem_x509_certificate(member_certificate)
    encryption_key = serialization.load_pem_public_key(member_encryption_key)
    if not isinstance(encryption_key, rsa.RSAPublicKey) or encryption_key.key_size < 2048:
        raise ValueError("existing RSA recovery public key required")
    template = copy.deepcopy(baseline)
    if len(template["resources"]) != 1:
        raise ValueError("one baseline container group required")
    resource = template["resources"][0]
    properties = resource["properties"]
    containers = {item["name"]: item["properties"] for item in properties["containers"]}
    volumes = {item["name"]: item for item in properties["volumes"]}
    if set(containers) != {"primary", "secondary"} or set(volumes) != {"public-config", "transfer-secret", "primary-state"}:
        raise ValueError("reviewed two-container baseline without optional mounts required")
    encoded = volumes["public-config"]["secret"]
    if set(encoded) != set(PUBLIC_FILES):
        raise ValueError("exact public baseline files required")
    public = {name: base64.b64decode(raw, validate=True) for name, raw in encoded.items()}
    old_manifest = strict_json(public["manifest.json"])
    node = strict_json(public["node.json"])
    if node["command"]["type"] != "Start":
        raise ValueError("new genesis requires an explicit Start baseline")
    name = "agentdns-ccf-replacement-" + date
    fqdn = name + "." + resource["location"] + ".azurecontainer.io"
    resource["name"] = name
    resource["tags"] = {"project": "agentdns", "purpose": "isolated-new-genesis-candidate"}
    properties["restartPolicy"] = "Never"
    properties["ipAddress"]["dnsNameLabel"] = name
    properties["confidentialComputeProperties"]["ccePolicy"] = ""
    properties["diagnostics"] = retained_logging_configuration()
    if not containers["primary"].get("environmentVariables"):
        containers["primary"]["environmentVariables"] = copy.deepcopy(OTEL_DISABLED_ENVIRONMENT)
    template["parameters"].update(copy.deepcopy(LOGGING_PARAMETERS))
    node["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"] = fqdn + ":8000"
    node["node_certificate"]["subject_alt_names"] = ["iPAddress:127.0.0.1", "dNSName:" + fqdn]
    node["ledger"]["directory"] = "/durable/ledger"
    node["snapshots"]["directory"] = "/durable/snapshots"
    public["node.json"] = (json.dumps(node, indent=2, sort_keys=True) + "\n").encode()
    public["member0_cert.pem"] = member_certificate
    public["member0_enc_pubk.pem"] = member_encryption_key
    manifest = {"/config/" + name: digest(raw) for name, raw in public.items() if name != "manifest.json"}
    manifest["/opt/agentdns/governance/constitution.js"] = old_manifest["/opt/agentdns/governance/constitution.js"]
    public["manifest.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    volumes["public-config"]["secret"] = {name: base64.b64encode(raw).decode() for name, raw in public.items()}
    command = containers["primary"]["command"]
    command[command.index("--config-manifest-sha256") + 1] = digest(public["manifest.json"])
    account = "adnsrecovery" + date
    share = "ccf-replacement-" + date
    properties["volumes"].append({"name": "durable-state", "azureFile": {
        "shareName": share, "storageAccountName": account, "storageAccountKey": "[parameters('" + STORAGE_KEY_PARAMETER + "')]", "readOnly": False}})
    containers["primary"]["volumeMounts"].append({"name": "durable-state", "mountPath": "/durable", "readOnly": False})
    template["parameters"][STORAGE_KEY_PARAMETER] = {"type": "secureString"}
    durable = validate_durable_candidate(template, containers, {v["name"]: v for v in properties["volumes"]}, node)
    parameter_template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#", "contentVersion": "1.0.0.0",
                          "parameters": {key: {"value": "REQUIRED_AFTER_APPROVAL__" + key} for key in template["parameters"]}}
    storage = {"$schema": template["$schema"], "contentVersion": "1.0.0.0", "resources": [
        {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-05-01", "name": account,
         "location": resource["location"], "kind": "StorageV2", "sku": {"name": "Standard_ZRS"},
         "tags": resource["tags"], "properties": {"minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": True,
         "allowBlobPublicAccess": False, "allowSharedKeyAccess": True, "publicNetworkAccess": "Enabled",
         "encryption": {"services": {"file": {"enabled": True}}, "keySource": "Microsoft.Storage"}}},
        {"type": "Microsoft.Storage/storageAccounts/fileServices", "apiVersion": "2023-05-01", "name": account + "/default",
         "dependsOn": ["[resourceId('Microsoft.Storage/storageAccounts', '" + account + "')]"],
         "properties": {"shareDeleteRetentionPolicy": {"enabled": True, "days": 14}}},
        {"type": "Microsoft.Storage/storageAccounts/fileServices/shares", "apiVersion": "2023-05-01", "name": account + "/default/" + share,
         "dependsOn": ["[resourceId('Microsoft.Storage/storageAccounts/fileServices', '" + account + "', 'default')]"],
         "properties": {"enabledProtocols": "SMB", "shareQuota": 32}}]}
    summary = {"status": "OFFLINE_ONLY_NOT_DEPLOYED", "new_genesis": True, "old_service_identity_retained": False,
               "member_id": certificate.fingerprint(hashes.SHA256()).hex(), "public_member_reused": True,
               "member_certificate_not_after": (certificate.not_valid_after_utc if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)).isoformat(),
               "config_manifest_sha256": digest(public["manifest.json"]), "constitution_sha256": manifest["/opt/agentdns/governance/constitution.js"],
               "fqdn": fqdn, "durable_state": durable, "resource_name_availability": "not checked",
               "retained_logging": validate_retained_logging(template, required=True),
               "secrets": "none read or generated; template placeholders only"}
    return template, parameter_template, storage, public, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-template", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--member-certificate", type=Path, required=True)
    parser.add_argument("--member-encryption-public-key", type=Path, required=True)
    parser.add_argument("--date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = read_small(args.baseline_template, 1024 * 1024)
    if digest(raw) != args.baseline_sha256:
        parser.error("baseline template does not match reviewed SHA256")
    values = prepare(strict_json(raw), read_small(args.member_certificate), read_small(args.member_encryption_public_key), args.date)
    args.output.mkdir(parents=True, exist_ok=False)
    template, parameters, storage, public, summary = values
    for name, value in (("ccf.template.json", template), ("ccf.parameters.TEMPLATE.json", parameters), ("storage.template.json", storage), ("candidate-summary.json", summary)):
        write_output(args.output / name, json.dumps(value, indent=2) + "\n", 0o644)
    write_output(args.output / "logging-workspace.template.json",
                 json.dumps(logging_workspace_template(template["resources"][0]["location"]), indent=2) + "\n", 0o644)
    (args.output / "public").mkdir()
    for name, value in public.items():
        (args.output / "public" / name).write_bytes(value)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
