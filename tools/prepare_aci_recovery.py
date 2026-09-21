#!/usr/bin/env python3
"""Render/check an explicit isolated Recover variant of a validated Start template.

This never deploys, changes the original group, or reads secure parameters.
Run normal image/archive preflight on the original Start template first. Recover
preflight binds that exact template and permits only the documented recovery delta.
"""
import argparse
import base64
import copy
import json
from pathlib import Path
import re

from build_aci_template import read_small, strict_json
from durable_recovery import digest, encoded, recovery_config, verify_archive, write_new
from prepare_aci_durable_candidate import finalize_policy, validate_durable_candidate, validate_retained_logging


def policies(template):
    raw = base64.b64decode(template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"], validate=True).decode()
    match = re.search(r"(?m)^containers\s*:=\s*", raw)
    if match is None:
        raise ValueError("missing generated policy")
    entries, length = json.JSONDecoder().raw_decode(raw[match.end():])
    if len(entries) != 3 or {e["name"] for e in entries} != {"primary", "secondary", "pause-container"}:
        raise ValueError("unexpected policy container set")
    return raw[:match.end()], entries, raw[match.end() + length:]


def prepare(start, backup, name, share):
    manifest = verify_archive(backup)
    if re.fullmatch(r"agentdns-ccf-recovery-[a-z0-9]+(?:-[a-z0-9]+)*", name) is None or len(name) > 63:
        raise ValueError("isolated recovery resource name required")
    if re.fullmatch(r"ccf-recovery-[a-z0-9]+(?:-[a-z0-9]+)*", share) is None or len(share) > 63:
        raise ValueError("isolated recovery share name required")
    result = copy.deepcopy(start)
    if len(result["resources"]) != 1:
        raise ValueError("one candidate group required")
    resource = result["resources"][0]
    props = resource["properties"]
    containers = {c["name"]: c["properties"] for c in props["containers"]}
    volumes = {v["name"]: v for v in props["volumes"]}
    public = {name: base64.b64decode(data, validate=True) for name, data in volumes["public-config"]["secret"].items()}
    node = strict_json(public["node.json"])
    original_manifest = strict_json(public["manifest.json"])
    if any(digest(data) != original_manifest.get("/config/" + filename) for filename, data in public.items() if filename != "manifest.json"):
        raise ValueError("original public manifest mismatch")
    _, original_entries, _ = policies(start)
    validate_durable_candidate(start, containers, volumes, node, {p["name"]: p for p in original_entries})
    validate_retained_logging(start)
    if resource["name"] == name or volumes["durable-state"]["azureFile"]["shareName"] == share:
        raise ValueError("recovery must use a different group and share")
    fqdn = name + "." + resource["location"] + ".azurecontainer.io"
    resource["name"] = name
    resource.setdefault("tags", {})["purpose"] = "isolated-member-authorized-recovery"
    props["restartPolicy"] = "Never"
    props["ipAddress"]["dnsNameLabel"] = name
    props["confidentialComputeProperties"]["ccePolicy"] = ""
    volumes["durable-state"]["azureFile"]["shareName"] = share
    node = recovery_config(node)
    node["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"] = fqdn + ":8000"
    node["node_certificate"]["subject_alt_names"] = ["iPAddress:127.0.0.1", "dNSName:" + fqdn]
    public["node.json"] = encoded(node)
    public["previous_service_identity.pem"] = read_small(backup / "previous-service.pem")
    bound = {"/config/" + filename: digest(data) for filename, data in public.items() if filename != "manifest.json"}
    bound["/opt/agentdns/governance/constitution.js"] = original_manifest["/opt/agentdns/governance/constitution.js"]
    public["manifest.json"] = encoded(bound)
    volumes["public-config"]["secret"] = {name: base64.b64encode(data).decode() for name, data in public.items()}
    command = containers["primary"]["command"]
    command[command.index("--config-manifest-sha256") + 1] = digest(public["manifest.json"])
    return result, {"mode": "Recover", "resource": name, "share": share,
                    "previous_service_der_sha256": manifest["previous_service_der_sha256"],
                    "backup_manifest_sha256": digest(read_small(backup / "manifest.json", 32 * 1024 * 1024)),
                    "config_manifest_sha256": digest(public["manifest.json"]),
                    "requires": "fresh verified share copy, generated CCE, member acceptance and recovery shares"}


def check(start, backup, recovered):
    resource = recovered["resources"][0]
    share = next(v["azureFile"]["shareName"] for v in resource["properties"]["volumes"] if v["name"] == "durable-state")
    expected, summary = prepare(start, backup, resource["name"], share)
    comparable = copy.deepcopy(recovered)
    comparable["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] = ""
    if comparable != expected:
        raise ValueError("template differs outside reviewed recovery delta")
    prefix, expected_entries, suffix = policies(start)
    actual_prefix, actual_entries, actual_suffix = policies(recovered)
    next(e for e in expected_entries if e["name"] == "primary")["command"] = next(c["properties"]["command"] for c in resource["properties"]["containers"] if c["name"] == "primary")
    if (prefix, expected_entries, suffix) != (actual_prefix, actual_entries, actual_suffix):
        raise ValueError("CCE changed beyond the new bound primary command")
    return {**summary, "status": "reviewed_recovery_delta_verified",
            "limitation": "inherits prior Start template image/archive validation; no live storage or attestation proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("render", "finalize", "check"))
    parser.add_argument("--start-template", type=Path, required=True)
    parser.add_argument("--start-template-sha256", required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--resource-name")
    parser.add_argument("--share-name")
    parser.add_argument("--recover-template", type=Path)
    parser.add_argument("--confcom-template", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = read_small(args.start_template, 1024 * 1024)
    if digest(raw) != args.start_template_sha256:
        raise ValueError("validated Start template digest differs")
    start = strict_json(raw)
    if args.mode == "render":
        if not args.resource_name or not args.share_name:
            parser.error("render requires isolated resource and share names")
        result, summary = prepare(start, args.backup, args.resource_name, args.share_name)
    elif args.mode == "finalize":
        if args.recover_template is None or args.confcom_template is None:
            parser.error("finalize requires rendered --recover-template and generated --confcom-template")
        result, _ = finalize_policy(strict_json(read_small(args.recover_template, 1024 * 1024)),
                                    strict_json(read_small(args.confcom_template, 1024 * 1024)))
        summary = check(start, args.backup, result)
    else:
        if args.recover_template is None:
            parser.error("check requires --recover-template")
        result = summary = check(start, args.backup, strict_json(read_small(args.recover_template, 1024 * 1024)))
    write_new(args.output, encoded(result))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
