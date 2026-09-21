#!/usr/bin/env python3
"""Explicit backup/Recover steps; never stops, starts, or deploys an Azure group.

Archive only a stopped writer's immutable share-snapshot download. Member actions
are separate commands, use externally authenticated TLS, and never print shares.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from build_aci_template import read_small, strict_json
from ccf_control import Client, Governance
import verify_ksk_receipt


def digest(data):
    return hashlib.sha256(data).hexdigest()


def service_id(pem):
    return verify_ksk_receipt.certificate(pem).fingerprint(hashes.SHA256()).hex()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def files(root):
    """Reject links/devices, including directory links; return relative regular files."""
    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("real directory required")
    result = []
    for current, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            if not stat.S_ISDIR((Path(current) / name).lstat().st_mode):
                raise ValueError("linked directory prohibited")
        for name in names:
            path = Path(current) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("regular files only")
            result.append(path.relative_to(root).as_posix())
            if len(result) > 100000:
                raise ValueError("file count exceeds bound")
    return sorted(result)


def hash_file(path, destination=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("regular file required")
        if destination is not None:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        value = hashlib.sha256()
        count = 0
        while block := os.read(fd, 1024 * 1024):
            value.update(block)
            count += len(block)
            if target is not None:
                # os.write can be short, even on regular files.
                remaining = memoryview(block)
                while remaining:
                    written = os.write(target, remaining)
                    if written <= 0:
                        raise OSError("copy made no progress")
                    remaining = remaining[written:]
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or count != before.st_size:
            raise ValueError("source changed during copy")
        if target is not None:
            os.fsync(target)
        return {"bytes": count, "sha256": value.hexdigest()}
    finally:
        os.close(fd)
        if target is not None:
            os.close(target)


def state_files(source):
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise ValueError("real state directory required")
    result = []
    for directory in ("ledger", "snapshots"):
        result.extend(directory + "/" + name for name in files(source / directory))
    if not any(re.fullmatch(r"ledger/ledger_[1-9][0-9]*(?:-[1-9][0-9]*\.committed)?", name) for name in result):
        raise ValueError("no CCF ledger chunks found")
    return sorted(result)


def archive(source, destination, previous_service, receipt, zone, provenance):
    """Include unsuffixed open chunks, not only rotated *.committed files."""
    verify_ksk_receipt.verify(receipt, previous_service, zone)
    paths = state_files(source)
    if destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("archive must be outside source")
    private_directory(destination)
    (destination / "state").mkdir(mode=0o700)
    for name in ("ledger", "snapshots"):
        (destination / "state" / name).mkdir(mode=0o700)
    entries = {name: hash_file(source / name, destination / "state" / name) for name in paths}
    if paths != state_files(source) or any(hash_file(source / name) != item for name, item in entries.items()):
        raise ValueError("source changed; discard incomplete archive")
    write_new(destination / "previous-service.pem", previous_service)
    write_new(destination / "before-ksk-receipt.json", encoded(receipt))
    manifest = {"format": "agentdns-durable-recovery-v1", "zone": zone,
                "previous_service_der_sha256": service_id(previous_service),
                "before_receipt_sha256": digest(encoded(receipt)), "files": entries,
                "provenance": provenance,
                "scope": "complete copied directories; CCF Recover must validate ledger continuity"}
    write_new(destination / "manifest.json", encoded(manifest))
    return manifest


def verify_archive(directory):
    manifest = strict_json(read_small(directory / "manifest.json", 32 * 1024 * 1024))
    if manifest.get("format") != "agentdns-durable-recovery-v1":
        raise ValueError("unknown archive format")
    entries = manifest["files"]
    if not isinstance(entries, dict) or sorted(entries) != state_files(directory / "state") or sorted(entries) != files(directory / "state"):
        raise ValueError("archive inventory differs")
    for name, expected in entries.items():
        if hash_file(directory / "state" / name) != expected:
            raise ValueError("archive file changed")
    previous = read_small(directory / "previous-service.pem")
    receipt_raw = read_small(directory / "before-ksk-receipt.json", 1024 * 1024)
    if service_id(previous) != manifest["previous_service_der_sha256"] or digest(receipt_raw) != manifest["before_receipt_sha256"]:
        raise ValueError("archive identity evidence changed")
    verify_ksk_receipt.verify(strict_json(receipt_raw), previous, manifest["zone"])
    return manifest


def restore_copy(backup, destination):
    manifest = verify_archive(backup)
    if destination.resolve().is_relative_to(backup.resolve()):
        raise ValueError("restore must be outside immutable backup")
    private_directory(destination)
    for name in ("ledger", "snapshots"):
        (destination / name).mkdir(mode=0o700)
    for name, expected in manifest["files"].items():
        if hash_file(backup / "state" / name, destination / name) != expected:
            raise ValueError("archive changed during restore")
    if state_files(destination) != sorted(manifest["files"]):
        raise ValueError("restore inventory differs")
    return manifest


def verify_state(backup, state):
    """Compare a downloaded destination share to every immutable backup byte."""
    manifest = verify_archive(backup)
    if files(state) != sorted(manifest["files"]):
        raise ValueError("destination state inventory differs")
    for name, expected in manifest["files"].items():
        if hash_file(state / name) != expected:
            raise ValueError("destination state content differs")
    return {"verified_files": len(manifest["files"]), "exact_backup_match": True}


def recovery_config(config, previous_identity="/config/previous_service_identity.pem",
                    ledger="/durable/ledger", snapshots="/durable/snapshots"):
    result = copy.deepcopy(config)
    result["command"] = {"type": "Recover", "service_certificate_file": "service_cert.pem",
                         "recover": {"previous_service_identity_file": previous_identity,
                                     "initial_service_certificate_validity_days": 7}}
    result["ledger"]["directory"] = ledger
    result["ledger"]["read_only_directories"] = []
    result["snapshots"]["directory"] = snapshots
    return result


def require_stopped_writer(groups, group_id, account, share):
    """Check a fresh subscription ACI inventory, not a globally distributed fence."""
    matches = []
    for group in groups:
        props = group.get("properties", group)
        volumes = {v["name"]: v for v in props.get("volumes", [])}
        mounted = {v["name"] for v in volumes.values()
                   if ((v.get("azureFile") or {}).get("storageAccountName") or "").lower() == account.lower()
                   and (v.get("azureFile") or {}).get("shareName") == share}
        for container in props.get("containers", []):
            cp = container.get("properties", container)
            if any(m.get("name") in mounted for m in cp.get("volumeMounts", [])):
                matches.append((group, props, cp))
    if len(matches) != 1 or matches[0][0].get("id", "").lower() != group_id.lower():
        raise ValueError("exactly one known ACI mount of the source share required")
    _, props, container = matches[0]
    if props.get("restartPolicy") != "Never" or props.get("instanceView", {}).get("state") != "Stopped":
        raise ValueError("source group must be explicitly Stopped with restartPolicy Never")
    if container.get("instanceView", {}).get("currentState", {}).get("state") != "Terminated":
        raise ValueError("source writer has not terminated")
    return {"source_group_id": group_id, "account": account, "share": share,
            "writer_check": "one stopped ACI writer; excludes unrelated clients; not a distributed fence"}


def capture_receipt(client, service_pem, zone):
    response = client.request("GET", "/app/governance/ksk-receipt?zone=" + quote(zone, safe=""))
    if response["http_status"] != 200 or response["headers"].get("x-agentdns-commit-status") != "committed":
        raise ValueError("committed KSK receipt unavailable")
    client.require_committed(response)
    verify_ksk_receipt.verify(response["body"], service_pem, zone)
    return response["body"]


def accept_recovery(client, governance, previous, current):
    if service_id(previous) == service_id(current):
        raise ValueError("Recover must create a fresh service identity")
    state = client.request("GET", "/node/state")
    if state["http_status"] != 200 or state["body"].get("state") != "PartOfPublicNetwork":
        raise ValueError("node has not completed public ledger recovery")
    governance.ack()
    result = governance.propose([{"name": "transition_service_to_open", "args": {
        "previous_service_identity": previous.decode(), "next_service_identity": current.decode()}}])
    return {"proposal_state": result["body"]["proposalState"],
            "confirmed_ccf_transaction_id": result.get("confirmed_ccf_transaction_id")}


def submit_share(client, governance, encryption_key):
    if not isinstance(encryption_key, rsa.RSAPrivateKey) or encryption_key.key_size < 2048:
        raise ValueError("RSA recovery encryption private key required")
    path = "/gov/recovery/encrypted-shares/" + governance.id + "?api-version=2024-07-01"
    encrypted = client.request("GET", path)
    if encrypted["http_status"] != 200:
        raise ValueError("encrypted recovery share unavailable")
    ciphertext = base64.b64decode(encrypted["body"]["encryptedShare"], validate=True)
    if len(ciphertext) != encryption_key.key_size // 8:
        raise ValueError("unexpected encrypted recovery share length")
    share = encryption_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                          algorithm=hashes.SHA256(), label=None))
    try:
        # Share submission starts private recovery; it is not a ledger mutation
        # with a transaction ID. Completion is proven by the later KSK receipt.
        import ccf.cose
        deadline = time.monotonic() + 15
        while True:
            signed = ccf.cose.create_cose_sign1(
                json.dumps({"share": base64.b64encode(share).decode()}).encode(),
                governance.key, governance.cert,
                {"ccf.gov.msg.type": "recovery_share", "ccf.gov.msg.created_at": int(time.time())})
            result = client.request("POST", "/gov/recovery/members/" + governance.id + ":recover?api-version=2024-07-01",
                                    signed, "application/cose", deadline=deadline)
            body = result.get("body")
            if result["http_status"] == 200 and isinstance(body, dict):
                if not isinstance(body.get("submittedCount"), int) or body["submittedCount"] < 1:
                    raise ValueError("invalid recovery share acknowledgment")
                break
            if (time.monotonic() >= deadline or result["http_status"] != 403
                    or not isinstance(body, dict) or body.get("error", {}).get("code") != "ServiceNotWaitingForRecoveryShares"):
                raise ValueError("recovery share submission rejected")
            time.sleep(0.1)
    finally:
        # Python cannot guarantee erasure of immutable copies; never persist them.
        del share
    return {key: body[key] for key in ("submittedCount", "recoveryThreshold") if key in body}


def verify_continuity(before, previous, after, current, zone):
    verify_ksk_receipt.verify(before, previous, zone)
    proof = verify_ksk_receipt.verify(after, current, zone)
    if service_id(previous) == service_id(current):
        raise ValueError("service identity did not change in recovery")
    if before["dnskey_rdata_hex"] != after["dnskey_rdata_hex"]:
        raise ValueError("recovery changed the zone KSK")
    return {**proof, "exact_dnskey_rdata_preserved": True,
            "previous_service_der_sha256": service_id(previous),
            "recovered_service_der_sha256": service_id(current)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    seal = sub.add_parser("archive", help="seal a stopped immutable snapshot download")
    seal.add_argument("--source", type=Path, required=True)
    seal.add_argument("--previous-service", type=Path, required=True)
    seal.add_argument("--before-receipt", type=Path, required=True)
    seal.add_argument("--zone", required=True)
    seal.add_argument("--provenance", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    for mode in ("verify-archive", "restore-copy", "verify-state"):
        command = sub.add_parser(mode)
        command.add_argument("--backup", type=Path, required=True)
        if mode == "restore-copy":
            command.add_argument("--output", type=Path, required=True)
        if mode == "verify-state":
            command.add_argument("--state", type=Path, required=True)
    config = sub.add_parser("recover-config")
    config.add_argument("--backup", type=Path, required=True)
    config.add_argument("--node-config", type=Path, required=True)
    config.add_argument("--output", type=Path, required=True)
    stopped = sub.add_parser("check-stopped", help="validate a sanitized current subscription ACI inventory")
    stopped.add_argument("--inventory", type=Path, required=True)
    stopped.add_argument("--group-id", required=True)
    stopped.add_argument("--account", required=True)
    stopped.add_argument("--share", required=True)
    stopped.add_argument("--output", type=Path, required=True)
    for mode in ("capture", "accept", "submit-share", "verify"):
        command = sub.add_parser(mode)
        command.add_argument("--url", required=True)
        command.add_argument("--connect-ip")
        command.add_argument("--service-cert", type=Path, required=True)
        command.add_argument("--service-sha256", required=True, help="externally authenticated DER SHA256")
        command.add_argument("--output", type=Path, required=True)
        if mode in ("capture", "verify"):
            command.add_argument("--zone", required=True)
        if mode in ("accept", "verify"):
            command.add_argument("--backup", type=Path, required=True)
        if mode in ("accept", "submit-share"):
            command.add_argument("--member-key", type=Path, required=True)
            command.add_argument("--member-cert", type=Path, required=True)
        if mode == "submit-share":
            command.add_argument("--member-encryption-key", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "check-stopped":
        result = require_stopped_writer(strict_json(read_small(args.inventory, 8 * 1024 * 1024)),
                                        args.group_id, args.account, args.share)
        write_new(args.output, encoded(result))
    elif args.mode == "archive":
        result = archive(args.source, args.output, read_small(args.previous_service),
                         strict_json(read_small(args.before_receipt, 1024 * 1024)), args.zone,
                         strict_json(read_small(args.provenance)))
    elif args.mode in ("verify-archive", "restore-copy", "verify-state", "recover-config"):
        result = verify_archive(args.backup)
        if args.mode == "restore-copy":
            result = restore_copy(args.backup, args.output)
        elif args.mode == "verify-state":
            result = verify_state(args.backup, args.state)
        elif args.mode == "recover-config":
            private_directory(args.output)
            config = recovery_config(strict_json(read_small(args.node_config)))
            write_new(args.output / "node.json", encoded(config))
            write_new(args.output / "previous_service_identity.pem", read_small(args.backup / "previous-service.pem"))
    else:
        current = read_small(args.service_cert)
        if service_id(current) != args.service_sha256:
            raise ValueError("service certificate differs from external identity pin")
        client = Client(args.url, args.connect_ip, args.service_cert)
        if args.mode == "capture":
            result = capture_receipt(client, current, args.zone)
        elif args.mode in ("accept", "submit-share"):
            read_small(args.member_key, private=True)
            governance = Governance(client, args.member_key, args.member_cert)
            if args.mode == "accept":
                verify_archive(args.backup)
                result = accept_recovery(client, governance, read_small(args.backup / "previous-service.pem"), current)
            else:
                key = serialization.load_pem_private_key(read_small(args.member_encryption_key, private=True), password=None)
                result = submit_share(client, governance, key)
        else:
            manifest = verify_archive(args.backup)
            if args.zone != manifest["zone"]:
                raise ValueError("verification zone differs from backup")
            before = strict_json(read_small(args.backup / "before-ksk-receipt.json", 1024 * 1024))
            after = capture_receipt(client, current, args.zone)
            result = verify_continuity(before, read_small(args.backup / "previous-service.pem"), after, current, args.zone)
            result["recovered_ksk_receipt"] = after
        write_new(args.output, encoded(result))
    print(json.dumps({"status": "completed", "operation": args.mode,
                      "output": str(getattr(args, "output", args.backup if hasattr(args, "backup") else ""))}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Governance/HTTP exception messages may contain response bodies.
        print("durable recovery step failed (" + type(error).__name__ + ")", file=sys.stderr)
        raise SystemExit(1) from None
