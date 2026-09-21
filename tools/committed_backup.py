#!/usr/bin/env python3
"""Copy immutable committed CCF files without touching a live writer.

This is a byte-integrity backup, not a ledger verifier. Names establish only
declared ranges. A verified KSK receipt does not prove its transaction is inside
the copied bytes. No cloud, governance, pruning, or service actions are performed.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import stat
import sys

from build_aci_template import read_small, strict_json
from durable_recovery import (digest, encoded, files, hash_file, private_directory,
                              service_id, write_new)
import verify_ksk_receipt

FORMAT = "agentdns-committed-backup-v1"
LEDGER = re.compile(r"ledger/ledger_([1-9][0-9]*)-([1-9][0-9]*)\.committed")
SNAPSHOT = re.compile(r"snapshots/snapshot_([1-9][0-9]*)_([1-9][0-9]*)\.committed")


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("UTC timestamp with offset required")
    return result.astimezone(timezone.utc)


def utcnow():
    return datetime.now(timezone.utc)


def layout(paths):
    """Validate declared filenames; deliberately does not certify ledger bytes."""
    chunks, snapshots = [], []
    for name in paths:
        match = LEDGER.fullmatch(name)
        if match:
            first, last = map(int, match.groups())
            if first > last or last >= 1 << 64:
                raise ValueError("invalid declared ledger range")
            chunks.append((first, last, name))
        else:
            match = SNAPSHOT.fullmatch(name)
            if not match:
                raise ValueError("only canonical committed file names allowed")
            seqno, evidence = map(int, match.groups())
            if not seqno < evidence < 1 << 64:
                raise ValueError("invalid declared snapshot range")
            snapshots.append((seqno, evidence, name))
    expected = 1
    for first, last, _ in sorted(chunks):
        if first != expected:
            raise ValueError("declared ledger history has a gap or overlap")
        expected = last + 1
    if not chunks:
        raise ValueError("no committed ledger history")
    return chunks, snapshots, expected - 1


def select(source):
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise ValueError("real source directory required")
    paths, omitted = [], 0
    for directory in ("ledger", "snapshots"):
        for name in files(source / directory):
            if "/" in name:
                raise ValueError("nested state directories prohibited")
            if name.endswith(".committed"):
                paths.append(directory + "/" + name)
            else:
                omitted += 1
    chunks, snapshots, last = layout(paths)
    eligible = [name for _, evidence, name in snapshots if evidence <= last]
    if not eligible:
        raise ValueError("no committed snapshot within declared ledger range")
    return sorted([name for _, _, name in chunks] + eligible), {
        "mutable_or_other_files_omitted": omitted,
        "snapshots_beyond_declared_range_deferred": len(snapshots) - len(eligible)}


def ledger_entries(entries):
    return {name: value for name, value in entries.items() if LEDGER.fullmatch(name)}


def archive(source, destination, service_pem, receipt, zone, provenance,
            previous=None, now=None):
    now = now or utcnow()
    created = timestamp(now.isoformat()).isoformat()
    proof = verify_ksk_receipt.verify(receipt, service_pem, zone)
    paths, omissions = select(source)
    prior = verify(previous) if previous is not None else None
    if destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("backup must be outside source")
    if previous is not None and destination.resolve().is_relative_to(previous.resolve()):
        raise ValueError("new backup must be outside previous backup")
    if prior and (prior["zone"] != zone or timestamp(prior["copied_at"]) > now):
        raise ValueError("previous backup zone or clock differs")
    private_directory(destination)
    (destination / "state").mkdir(mode=0o700)
    for directory in ("ledger", "snapshots"):
        (destination / "state" / directory).mkdir(mode=0o700)
    entries = {name: hash_file(source / name, destination / "state" / name) for name in paths}
    # A live source may add files. Every selected committed file must remain
    # identical; deletion or mutation fails without publishing a manifest.
    for name, expected in entries.items():
        if hash_file(source / name) != expected or hash_file(destination / "state" / name) != expected:
            raise ValueError("committed file changed or destination differs")
    if any(value["bytes"] == 0 for value in entries.values()):
        raise ValueError("empty committed file")
    ledger = ledger_entries(entries)
    unchanged_since = created
    previous_digest = None
    if prior:
        old = ledger_entries(prior["files"])
        if any(ledger.get(name) != value for name, value in old.items()):
            raise ValueError("prior committed ledger history missing or changed")
        if ledger == old:
            unchanged_since = prior["ledger_content_unchanged_since"]
        previous_digest = digest(read_small(previous / "manifest.json", 32 * 1024 * 1024))
    _, _, last = layout(entries)
    write_new(destination / "service.pem", service_pem)
    write_new(destination / "ksk-receipt.json", encoded(receipt))
    manifest = {"format": FORMAT, "zone": zone, "copied_at": created,
                "ledger_content_unchanged_since": unchanged_since,
                "previous_manifest_sha256": previous_digest,
                "service_der_sha256": service_id(service_pem),
                "receipt_sha256": digest(encoded(receipt)),
                "verified_receipt_tx_id": proof["tx_id"],
                "declared_filename_last_seqno": last,
                "transaction_inclusion_verified": False,
                "recovery_exercised": False, "files": entries,
                "omissions": omissions, "provenance": provenance}
    # This completion marker is written only after all copies/readbacks succeed.
    write_new(destination / "manifest.json", encoded(manifest))
    return manifest


def verify(directory):
    manifest = strict_json(read_small(directory / "manifest.json", 32 * 1024 * 1024))
    if manifest.get("format") != FORMAT:
        raise ValueError("unknown committed backup format")
    if manifest.get("transaction_inclusion_verified") is not False or manifest.get("recovery_exercised") is not False:
        raise ValueError("byte backup cannot assert transaction coverage or recovery")
    copied = timestamp(manifest["copied_at"])
    if timestamp(manifest["ledger_content_unchanged_since"]) > copied:
        raise ValueError("invalid progress timestamp")
    entries = manifest["files"]
    if not isinstance(entries, dict) or sorted(entries) != files(directory / "state"):
        raise ValueError("backup inventory differs")
    _, snapshots, last = layout(entries)
    if not snapshots or any(evidence > last for _, evidence, _ in snapshots):
        raise ValueError("snapshot beyond declared history")
    if manifest["declared_filename_last_seqno"] != last:
        raise ValueError("declared range differs")
    for name, expected in entries.items():
        if hash_file(directory / "state" / name) != expected or expected["bytes"] == 0:
            raise ValueError("backup content differs or is empty")
    service = read_small(directory / "service.pem")
    receipt = read_small(directory / "ksk-receipt.json", 1024 * 1024)
    if service_id(service) != manifest["service_der_sha256"] or digest(receipt) != manifest["receipt_sha256"]:
        raise ValueError("backup identity evidence differs")
    proof = verify_ksk_receipt.verify(strict_json(receipt), service, manifest["zone"])
    if proof["tx_id"] != manifest["verified_receipt_tx_id"]:
        raise ValueError("receipt transaction differs")
    return manifest


def report(directory, max_age_seconds, now=None):
    if max_age_seconds <= 0:
        raise ValueError("positive maximum backup age required")
    manifest = verify(directory)
    now = now or utcnow()
    age = (now - timestamp(manifest["copied_at"])).total_seconds()
    unchanged = (now - timestamp(manifest["ledger_content_unchanged_since"])).total_seconds()
    if min(age, unchanged) < 0:
        raise ValueError("backup timestamp is in the future")
    alerts = []
    if age > max_age_seconds:
        alerts.append("copy_stale")
    if unchanged > max_age_seconds:
        alerts.append("ledger_content_not_advancing")
    return {"status": "stale" if alerts else "copied_coverage_unverified",
            "alerts": alerts, "copy_age_seconds": age,
            "ledger_content_unchanged_seconds": unchanged,
            "verified_files": len(manifest["files"]),
            "transaction_inclusion_verified": False, "recovery_exercised": False,
            "declared_filename_last_seqno": manifest["declared_filename_last_seqno"],
            "verified_receipt_tx_id": manifest["verified_receipt_tx_id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    copy = commands.add_parser("copy")
    for name in ("source", "output", "service-cert", "receipt", "provenance"):
        copy.add_argument("--" + name, type=Path, required=True)
    copy.add_argument("--zone", required=True)
    chain = copy.add_mutually_exclusive_group(required=True)
    chain.add_argument("--previous", type=Path)
    chain.add_argument("--initial", action="store_true",
                       help="explicit first copy; recurring runs must retain --previous")
    check = commands.add_parser("verify")
    check.add_argument("--backup", type=Path, required=True)
    health = commands.add_parser("report")
    health.add_argument("--backup", type=Path, required=True)
    health.add_argument("--max-age-seconds", type=int, required=True)
    args = parser.parse_args()
    if args.command == "copy":
        result = archive(args.source, args.output, read_small(args.service_cert),
                         strict_json(read_small(args.receipt, 1024 * 1024)), args.zone,
                         strict_json(read_small(args.provenance)), args.previous)
        print(json.dumps({"copied_files": len(result["files"]), "transaction_inclusion_verified": False}))
    elif args.command == "verify":
        result = verify(args.backup)
        print(json.dumps({"verified_files": len(result["files"]), "transaction_inclusion_verified": False}))
    else:
        result = report(args.backup, args.max_age_seconds)
        print(json.dumps(result, sort_keys=True))
        # A monitor must not translate successful byte copying into a green
        # recoverability check. 3 means fresh bytes, unverified ledger coverage.
        return 2 if result["alerts"] else 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("committed backup failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
