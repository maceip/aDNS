#!/usr/bin/env python3
"""Read-only Azure Files/IMDS backup runner; never uses account keys or governance."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import format_datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
from urllib.parse import quote, urlencode
from urllib.request import (build_opener, HTTPRedirectHandler, ProxyHandler, Request)
import uuid
import xml.etree.ElementTree as ET

import committed_backup as backup


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("credentialed redirects prohibited")


class AzureReader:
    def __init__(self, account, share, client_id=None, object_id=None):
        if not re.fullmatch(r"[a-z0-9]{3,24}", account) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])", share) or "--" in share:
            raise ValueError("invalid Azure account or share")
        if client_id is not None and object_id is not None:
            raise ValueError("select one managed identity")
        for identity in (client_id, object_id):
            if identity is not None:
                uuid.UUID(identity)
        self.account, self.share, self.client_id = account, share, client_id
        self.object_id = object_id
        # IMDS must bypass proxies; storage is TLS-authenticated to a fixed Azure
        # hostname. Do not follow redirects carrying its bearer credential.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.token, self.expires = None, 0

    def access_token(self):
        if self.token is None or time.time() >= self.expires - 60:
            args = {"api-version": "2018-02-01", "resource": "https://storage.azure.com/"}
            if self.client_id:
                args["client_id"] = self.client_id
            if self.object_id:
                args["object_id"] = self.object_id
            url = "http://169.254.169.254/metadata/identity/oauth2/token?" + urlencode(args)
            with self.opener.open(Request(url, headers={"Metadata": "true"}), timeout=10) as response:
                body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("oversized IMDS response")
            value = backup.strict_json(body)
            self.token, self.expires = value["access_token"], int(value["expires_on"])
            if not isinstance(self.token, str) or not self.token or self.expires <= time.time() + 60:
                raise ValueError("invalid or expired IMDS token")
        return self.token

    def request(self, method, path, query=None):
        if method not in ("GET", "HEAD"):
            raise ValueError("read-only methods required")
        if path not in ("ledger", "snapshots") and not (backup.LEDGER.fullmatch(path) or backup.SNAPSHOT.fullmatch(path)):
            raise ValueError("only committed CCF file paths allowed")
        url = f"https://{self.account}.file.core.windows.net/{self.share}/" + quote(path, safe="/")
        if query:
            url += "?" + urlencode(query)
        headers = {"Authorization": "Bearer " + self.access_token(),
                   "x-ms-version": "2022-11-02", "x-ms-file-request-intent": "backup",
                   "x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True),
                   "x-ms-file-extended-info": "true"}
        return self.opener.open(Request(url, method=method, headers=headers), timeout=60)

    def names(self, directory):
        names, seen_markers = set(), set()
        marker = ""
        while True:
            query = {"restype": "directory", "comp": "list", "maxresults": "5000"}
            if marker:
                query["marker"] = marker
            with self.request("GET", directory, query) as response:
                body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024 or b"<!DOCTYPE" in body or b"<!ENTITY" in body:
                raise ValueError("unsafe or oversized directory XML")
            root = ET.fromstring(body)
            entries = root.find("Entries")
            if root.tag != "EnumerationResults" or entries is None:
                raise ValueError("invalid directory response")
            for entry in entries:
                if entry.tag != "File":
                    raise ValueError("nested directories or unknown entries prohibited")
                node = entry.find("Name")
                if node is None or node.attrib or not node.text or "/" in node.text or "\\" in node.text:
                    raise ValueError("unsafe file name")
                name = directory + "/" + node.text
                if not node.text.endswith(".committed"):
                    continue
                if not (backup.LEDGER.fullmatch(name) or backup.SNAPSHOT.fullmatch(name)) or name in names:
                    raise ValueError("invalid or duplicate committed name")
                names.add(name)
                if len(names) > 100000:
                    raise ValueError("file count exceeds bound")
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return sorted(names)
            if marker in seen_markers or len(marker) > 8192:
                raise ValueError("invalid directory continuation")
            seen_markers.add(marker)

    def properties(self, path):
        with self.request("HEAD", path) as response:
            length, etag = int(response.headers["Content-Length"]), response.headers["ETag"]
        if length <= 0 or not etag:
            raise ValueError("empty file or missing ETag")
        return {"bytes": length, "etag": etag}

    def download(self, path, target, max_file_bytes):
        before = self.properties(path)
        if before["bytes"] > max_file_bytes:
            raise ValueError("file exceeds configured byte bound")
        count, digest = 0, hashlib.sha256()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output, self.request("GET", path) as response:
            if int(response.headers["Content-Length"]) != before["bytes"] or response.headers["ETag"] != before["etag"]:
                raise ValueError("file changed before download")
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > before["bytes"]:
                    raise ValueError("download exceeds properties length")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if count != before["bytes"] or self.properties(path) != before:
            raise ValueError("file changed during download or was truncated")
        return {**before, "sha256": digest.hexdigest()}


def download_source(reader, destination, max_file_bytes, max_total_bytes):
    names = reader.names("ledger") + reader.names("snapshots")
    chunks, snapshots, last = backup.layout(names)
    selected = sorted([name for _, _, name in chunks] +
                      [name for _, evidence, name in snapshots if evidence <= last])
    if not any(name.startswith("snapshots/") for name in selected):
        raise ValueError("no snapshot within declared history")
    backup.private_directory(destination)
    for directory in ("ledger", "snapshots"):
        (destination / directory).mkdir(mode=0o700)
    inventory, total = {}, 0
    for name in selected:
        props = reader.properties(name)
        if props["bytes"] > max_file_bytes or total + props["bytes"] > max_total_bytes:
            raise ValueError("download exceeds configured byte bounds")
        # Keep capacity for the sealing copy plus reserve; no pruning is implicit.
        if shutil.disk_usage(destination).free < 2 * props["bytes"] + 64 * 1024 * 1024:
            raise ValueError("insufficient backup disk capacity")
        item = reader.download(name, destination / name, min(max_file_bytes, props["bytes"]))
        total += item["bytes"]
        if total > max_total_bytes:
            raise ValueError("download total exceeds configured bound")
        inventory[name] = item
    return {"kind": "live-committed-files-via-oauth-rest", "account": reader.account,
            "share": reader.share, "read_at": backup.utcnow().isoformat(), "files": inventory,
            "size_source": "per-file HEAD; directory listing sizes not used"}


def atomic_json(path, value):
    temporary = path.parent / ("." + path.name + "." + uuid.uuid4().hex)
    backup.write_new(temporary, backup.encoded(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rotation_checkpoint(config, now=None):
    """Validate fixed-action evidence; filenames still cannot prove inclusion."""
    path = Path(config["backup_root"]) / "rotation.json"
    record = backup.strict_json(backup.read_small(path, 2 * 1024 * 1024))
    now = now or backup.utcnow()
    age = (now - backup.timestamp(record["created_at"])).total_seconds()
    if not 0 <= age <= 180 or record["actions"] != ["trigger_snapshot", "trigger_ledger_chunk"]:
        raise ValueError("missing or stale fixed rotation checkpoint")
    service = backup.read_small(Path(config["service_cert"]))
    if backup.service_id(service) != record["service_der_sha256"]:
        raise ValueError("rotation service identity differs")
    proof = backup.verify_ksk_receipt.verify(record["receipt"], service, config["zone"])
    values = []
    for name in ("snapshot_tx_id", "rotation_tx_id"):
        txid = record[name]
        if not isinstance(txid, str) or re.fullmatch(r"[0-9]+\.[1-9][0-9]*", txid) is None:
            raise ValueError("invalid rotation transaction")
        view, seqno = map(int, txid.split("."))
        if max(view, seqno) >= 1 << 64:
            raise ValueError("rotation transaction exceeds bounds")
        values.append(seqno)
    if not values[0] <= int(proof["tx_id"].split(".")[1]) < values[1]:
        raise ValueError("rotation does not follow the recorded checkpoint")
    return record


def wait_for_rotation(reader, record, timeout=120):
    deadline = time.monotonic() + timeout
    snapshot_seqno = int(record["snapshot_tx_id"].split(".")[1])
    rotation_seqno = int(record["rotation_tx_id"].split(".")[1])
    while True:
        _, snapshots, last = backup.layout(reader.names("ledger") + reader.names("snapshots"))
        if last > rotation_seqno and any(seqno > snapshot_seqno and evidence <= last for seqno, evidence, _ in snapshots):
            return {"declared_filename_last_seqno": last,
                    "rotation_file_names_observed": True, "transaction_inclusion_verified": False}
        if time.monotonic() >= deadline:
            raise TimeoutError("committed rotation files not observed")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


@contextmanager
def exclusive(directory):
    if not stat.S_ISDIR(directory.lstat().st_mode) or directory.stat().st_mode & 0o077:
        raise ValueError("private real backup directory required")
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def cycle(config, initial=False, reader=None):
    root = Path(config["backup_root"])
    with exclusive(root):
        status = {"evaluated_at": backup.utcnow().isoformat(), "account": config["account"],
                  "share": config["share"], "transaction_inclusion_verified": False,
                  "recovery_exercised": False}
        try:
            pointer = root / "latest.json"
            previous = None
            if pointer.exists():
                if initial:
                    raise ValueError("initial mode cannot reset an existing chain")
                name = backup.strict_json(backup.read_small(pointer))["directory"]
                if not re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", name):
                    raise ValueError("invalid previous archive pointer")
                previous = root / name / "backup"
                backup.verify(previous)
            elif not initial:
                raise ValueError("missing prior backup; explicit initial run required")
            run = root / ("run-" + backup.utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex)
            backup.private_directory(run)
            reader = reader or AzureReader(config["account"], config["share"],
                                           config.get("client_id"), config.get("object_id"))
            checkpoint = rotation_checkpoint(config) if config.get("rotation") else None
            rotation = wait_for_rotation(reader, checkpoint) if checkpoint else None
            provenance = download_source(reader, run / "source", int(config["max_file_bytes"]), int(config["max_total_bytes"]))
            if checkpoint:
                provenance["rotation_checkpoint"] = checkpoint
                provenance["rotation_observation"] = rotation
            backup.archive(run / "source", run / "backup", backup.read_small(Path(config["service_cert"])),
                           checkpoint["receipt"] if checkpoint else backup.strict_json(backup.read_small(Path(config["receipt"]), 1024 * 1024)),
                           config["zone"], provenance, previous)
            result = backup.report(run / "backup", int(config["max_age_seconds"]))
            atomic_json(pointer, {"directory": run.name})
            # Only the staging copy created by this invocation is removed.
            shutil.rmtree(run / "source")
            status.update(result)
            status["backup_directory"] = run.name
            status["evaluated_at"] = backup.utcnow().isoformat()
            atomic_json(root / "status.json", status)
            return status
        except Exception as error:
            status.update(status="failed", alerts=["backup_failed"], error_type=type(error).__name__)
            status["evaluated_at"] = backup.utcnow().isoformat()
            atomic_json(root / "status.json", status)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--initial", action="store_true")
    args = parser.parse_args()
    config = backup.strict_json(backup.read_small(args.config))
    result = cycle(config, args.initial)
    print(json.dumps(result, sort_keys=True))
    return 2 if result["alerts"] else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("Azure committed backup failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
