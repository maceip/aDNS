#!/usr/bin/env python3
"""Read-only ACI preflight; never opens a deployment parameter or private key file.

Confcom accepts tar mappings but can silently use the first image in a multi-image
archive. Require one distinct archive per image, verify OCI/config/layer digests,
and compare the generated policy's commands and layer counts. Verity roots are
not OCI digests: this guard does not independently recompute dm-verity trees.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import tarfile
from build_aci_template import PUBLIC_FILES, read_small, strict_json
from prepare_aci_control import native_attestation_configuration, validate_native_internal_readiness

HEX = r"[0-9a-f]{64}"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_image(path, image, expected_tag):
    if re.fullmatch(r"[^\s@]+@sha256:" + HEX, image) is None:
        raise ValueError("image must have an immutable SHA256 manifest")
    expected_digest = image.rsplit("@", 1)[1]
    with tarfile.open(path, "r:") as archive:
        members = {}
        for member in archive:
            if len(members) >= 4096 or member.name in members:
                raise ValueError("archive contains excessive or duplicate entries")
            members[member.name] = member

        def read(name, maximum=1024 * 1024):
            member = members.get(name)
            if member is None or not member.isfile() or not 0 < member.size <= maximum:
                raise ValueError("missing, non-regular or oversized archive metadata")
            with archive.extractfile(member) as stream:
                return stream.read(maximum + 1)

        def blob(digest):
            if re.fullmatch("sha256:" + HEX, digest) is None:
                raise ValueError("unsupported archive digest")
            data = read("blobs/sha256/" + digest[7:])
            if sha(data) != digest[7:]:
                raise ValueError("archive metadata digest mismatch")
            return strict_json(data)

        docker = strict_json(read("manifest.json"))
        if not isinstance(docker, list) or len(docker) != 1:
            raise ValueError("confcom requires a single-image archive per mapping")
        entry = docker[0]
        if entry.get("RepoTags") != [expected_tag]:
            raise ValueError("archive tag differs from the tar mapping")
        index = strict_json(read("index.json"))
        found = set()

        def visit(obj, depth=0):
            if depth > 4:
                raise ValueError("OCI index nesting exceeds bound")
            for descriptor in obj.get("manifests", []):
                if not isinstance(descriptor, dict):
                    raise ValueError("invalid OCI descriptor")
                digest = descriptor["digest"]
                child = blob(digest)
                if "manifests" in child:
                    visit(child, depth + 1)
                elif descriptor.get("platform") == {"architecture": "amd64", "os": "linux"}:
                    found.add(digest)

        visit(index)
        if found != {expected_digest}:
            raise ValueError("template image differs from archive linux/amd64 manifest")
        manifest = blob(expected_digest)
        config_digest = manifest["config"]["digest"]
        config = blob(config_digest)
        if config.get("architecture") != "amd64" or config.get("os") != "linux" or entry["Config"] != "blobs/sha256/" + config_digest[7:]:
            raise ValueError("archive config platform or Docker/OCI identity differs")
        layers = manifest["layers"]
        paths = ["blobs/sha256/" + descriptor["digest"][7:] for descriptor in layers]
        if entry["Layers"] != paths or not 1 <= len(paths) <= 128:
            raise ValueError("Docker/OCI layer manifests differ")
        for descriptor, name in zip(layers, paths):
            digest = descriptor["digest"]
            member = members.get(name)
            if re.fullmatch("sha256:" + HEX, digest) is None or member is None or not member.isfile() or member.size != descriptor["size"] or not 0 < member.size <= 4 * 1024**3:
                raise ValueError("invalid archive layer")
            actual = hashlib.sha256()
            with archive.extractfile(member) as stream:
                while chunk := stream.read(1024 * 1024):
                    actual.update(chunk)
            if actual.hexdigest() != digest[7:]:
                raise ValueError("archive layer digest mismatch")
        return {"image": image, "archive_tag": expected_tag,
                "config_sha256": config_digest[7:], "layer_count": len(paths),
                "oci_layer_sha256": [descriptor["digest"][7:] for descriptor in layers]}


def validate_archives(archives, mappings):
    if set(archives) != {"primary", "secondary"} or not isinstance(mappings, dict) or len(mappings) != 2:
        raise ValueError("exactly two distinct image archives and tar mappings are required")
    if any(not isinstance(path, str) or not path.startswith("/") for path in mappings.values()) or len(set(mappings.values())) != 2:
        raise ValueError("multiple images must never map to the same archive")
    identities = [(path.stat().st_dev, path.stat().st_ino) for path in archives.values()]
    if len(set(identities)) != 2:
        raise ValueError("multiple images must never use the same archive file")


def validate_ports(properties):
    """ACI rejects repeated port integers even when their protocols differ."""
    public = properties["ipAddress"]["ports"]
    declared = [port for container in properties["containers"]
                for port in container["properties"]["ports"]]
    for scope, ports in (("public", public), ("container", declared)):
        numbers = [port["port"] for port in ports]
        if len(numbers) != len(set(numbers)):
            raise ValueError(f"ACI {scope} port numbers must be unique regardless of protocol")
        if any(type(port["port"]) is not int or not 1 <= port["port"] <= 65535
               or port["protocol"] not in ("TCP", "UDP") for port in ports):
            raise ValueError("invalid ACI port declaration")
    if any(port not in declared for port in public):
        raise ValueError("ACI public port must also be declared by a container")


def check(template_path, archives, mappings):
    validate_archives(archives, mappings)
    raw = read_small(template_path, 1024 * 1024)
    template = strict_json(raw)
    if len(template["resources"]) != 1:
        raise ValueError("expected one isolated container group")
    properties = template["resources"][0]["properties"]
    validate_ports(properties)
    containers = {c["name"]: c["properties"] for c in properties["containers"]}
    if len(properties["containers"]) != 2 or set(containers) != {"primary", "secondary"}:
        raise ValueError("expected primary and secondary containers")
    encoded = properties["confidentialComputeProperties"]["ccePolicy"]
    policy = base64.b64decode(encoded, validate=True)
    match = re.search(rb"(?m)^containers\s*:=\s*", policy)
    if match is None:
        raise ValueError("missing generated CCE container policy")
    entries, _ = json.JSONDecoder().raw_decode(policy[match.end():].decode())
    policies = {entry["name"]: entry for entry in entries}
    if len(entries) != 3 or set(policies) != {"primary", "secondary", "pause-container"}:
        raise ValueError("unexpected CCE container set")
    summaries = {}
    for name, container in containers.items():
        repository = container["image"].split("@", 1)[0]
        tags = [tag for tag in mappings if tag.rsplit(":", 1)[0] == repository]
        if len(tags) != 1:
            raise ValueError("image repository differs from tar mapping")
        summaries[name] = archive_image(archives[name], container["image"], tags[0])
        rules = policies[name]
        if rules["command"] != container["command"]:
            raise ValueError("CCE command differs from template")
        if len(rules["layers"]) != summaries[name]["layer_count"] or any(re.fullmatch(HEX, value) is None for value in rules["layers"]):
            raise ValueError("CCE layer count differs from the individual image archive")
        summaries[name]["verity_layer_sha256"] = rules["layers"]
    if summaries["primary"]["config_sha256"] == summaries["secondary"]["config_sha256"] or policies["primary"]["layers"] == policies["secondary"]["layers"]:
        raise ValueError("distinct container images have duplicated policy layers")
    if policies["pause-container"]["command"] != ["/pause"] or len(policies["pause-container"]["layers"]) != 1:
        raise ValueError("unexpected ACI pause container")
    volumes = {volume["name"]: volume for volume in properties["volumes"]}
    public = volumes["public-config"]["secret"]
    if set(public) != set(PUBLIC_FILES):
        raise ValueError("unexpected public bootstrap files")
    public = {name: base64.b64decode(value, validate=True) for name, value in public.items()}
    manifest = strict_json(public["manifest.json"])
    expected = {"/config/"+name for name in PUBLIC_FILES if name != "manifest.json"} | {"/opt/agentdns/governance/constitution.js"}
    if set(manifest) != expected or any(re.fullmatch(HEX, value) is None for value in manifest.values()):
        raise ValueError("unexpected bootstrap manifest")
    for name, data in public.items():
        if name != "manifest.json" and sha(data) != manifest["/config/"+name]:
            raise ValueError("embedded public file differs from manifest")
    command = containers["primary"]["command"]
    if command != ["python3", "/opt/agentdns/run.py", "--config", "/config/node.json", "--config-manifest", "/config/manifest.json", "--config-manifest-sha256", sha(public["manifest.json"]), "--provision-tsig-file", "/secrets/transfer-key.json"]:
        raise ValueError("primary launch command does not bind the bootstrap manifest")
    node = strict_json(public["node.json"])
    if node.get("attestation") != native_attestation_configuration():
        raise ValueError("native ACI bootstrap requires explicit SNP collateral and UVM configuration")
    validate_native_internal_readiness(node)
    if node["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"] != "agentdns.test:8000" or node["network"]["rpc_interfaces"]["agentdns-internal"]["bind_address"] != "127.0.0.1:8001" or "dNSName:agentdns.test" not in node["node_certificate"]["subject_alt_names"]:
        raise ValueError("public TLS name or internal interface differs")
    if template["parameters"] != {"transferKeyB64":{"type":"secureString"}, "transferKeyJson":{"type":"secureString"}} or volumes["transfer-secret"]["secret"] != {"transfer-key.json":"[base64(parameters('transferKeyJson'))]"} or containers["secondary"]["environmentVariables"] != [{"name":"AGENTDNS_TRANSFER_KEY_B64","secureValue":"[parameters('transferKeyB64')]"}]:
        raise ValueError("transfer secrets must be secure parameter references")
    secret_rules = [rule for rule in policies["secondary"]["env_rules"] if rule["pattern"].lstrip("^").startswith("AGENTDNS_TRANSFER_KEY_B64=")]
    if len(secret_rules) != 1 or secret_rules[0]["strategy"] != "re2" or not secret_rules[0]["required"] or secret_rules[0]["pattern"] != "^AGENTDNS_TRANSFER_KEY_B64=[A-Za-z0-9+/]{43}=$":
        raise ValueError("transfer environment policy must constrain a key pattern, never embed a literal key")
    return {"template_sha256": sha(raw), "cce_policy_sha256": sha(policy),
            "bootstrap_manifest_sha256": sha(public["manifest.json"]),
            "containers": summaries, "pause_layer_count": 1,
            "checks": "unique ACI port numbers; distinct single-image archives; OCI metadata and layer hashes; policy commands/counts; bootstrap manifest; TLS name; secure parameter references",
            "limitation": "dm-verity roots are confcom output, not independently recomputed by this preflight"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--primary-archive", type=Path, required=True)
    parser.add_argument("--secondary-archive", type=Path, required=True)
    parser.add_argument("--tar-map", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check(args.template, {"primary":args.primary_archive,"secondary":args.secondary_archive}, strict_json(read_small(args.tar_map)))
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
