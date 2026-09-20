#!/usr/bin/env python3
"""Reject managed deployment-name literals outside the common registry.

This is a regression check for selected managed identities, not a universal DNS
detector. New external providers and unrelated domains still require a broad
audit. Files come from Git's tracked plus nonignored untracked inventory.
"""
import argparse
from collections import Counter
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from domain_registry import load_registry, registry_path

MANAGED_KEYS = (
    "domain", "public_dns_host", "ccf_rpc_hostname", "mail_relay_host", "secondary_registry", "anycast_validation_domain",
    "ses_feedback_host", "ses_spf_host", "ses_dkim_primary_host", "ses_dkim_secondary_host", "ses_dkim_tertiary_host",
    "caa_primary_domain", "caa_secondary_domain",
)
PATH_CATEGORIES = {"documentation", "historical-evidence", "unit-tests", "fixed-fixtures", "vendored-code", "generated-output"}
LINE_CATEGORIES = {"protocol-identifier", "module-or-telemetry-namespace", "comment-or-branding", "signed-trust-data", "fixed-test-vector"}


def line_hash(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def audit(root=ROOT, registry=None, config_path=None):
    root = Path(root).resolve()
    source = registry_path(registry)
    values = load_registry(source)
    config_path = Path(config_path) if config_path else root / "tools/domain-literal-exceptions.json"
    config = json.loads(config_path.read_text())
    if config.get("schema_version") != 1:
        raise ValueError("invalid domain literal classification schema")
    needles = {values[key].lower() for key in MANAGED_KEYS if key in values}
    for item in config.get("additional_domains", []):
        if not isinstance(item, dict) or not isinstance(item.get("domain"), str) or not re.fullmatch(r"[a-z0-9.-]+", item["domain"]) or not item.get("reason"):
            raise ValueError("additional domain needs a name and reason")
        needles.add(item["domain"].lower())
    exclusions = config.get("path_exclusions", [])
    for item in exclusions:
        if item.get("category") not in PATH_CATEGORIES or not item.get("pattern") or not item.get("reason"):
            raise ValueError("path exclusions need an approved category, pattern and reason")
    exceptions = {}
    for item in config.get("line_exceptions", []):
        if item.get("category") not in LINE_CATEGORIES or not item.get("reason") or not item.get("path") or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")):
            raise ValueError("line exceptions need an approved category, exact path, hash and reason")
        key = (item["path"], item["sha256"])
        if key in exceptions:
            raise ValueError("duplicate exact-line exception")
        exceptions[key] = item
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    paths = sorted(set(raw.decode("utf-8").split("\0")) - {""})
    skipped = Counter()
    used = set()
    violations = []
    checked = 0
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            skipped["nonregular-file"] += 1
            continue
        if relative == "infra/production/topology.json":
            skipped["canonical-registry"] += 1
            continue
        if path.resolve() in {source.resolve(), config_path.resolve()}:
            skipped["registry-or-guard-configuration"] += 1
            continue
        category = next((item["category"] for item in exclusions if fnmatch.fnmatchcase(relative, item["pattern"])), None)
        if category:
            skipped[category] += 1
            continue
        content = path.read_bytes()
        try:
            if b"\0" in content:
                raise UnicodeError()
            lines = content.decode("utf-8").splitlines()
        except UnicodeError:
            skipped["binary-assets"] += 1
            continue
        checked += 1
        for number, line in enumerate(lines, 1):
            found = sorted(needle for needle in needles if needle in line.lower())
            if not found:
                continue
            digest = line_hash(line)
            key = (relative, digest)
            if key in exceptions:
                used.add(key)
                continue
            # Report identifiers and hashes, never complete source lines or secrets.
            violations.append({"path": relative, "line": number, "domains": found, "sha256": digest})
    return {"checked_files": checked, "excluded_files": dict(sorted(skipped.items())),
            "managed_keys": [key for key in MANAGED_KEYS if key in values],
            "violations": violations, "used_line_exceptions": len(used),
            "unused_line_exceptions": [{"path": path, "sha256": digest} for path, digest in sorted(exceptions.keys() - used)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = audit(args.root, args.registry, args.config)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Domain literal audit failed: {error}\n")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result["violations"]:
            print(f'{item["path"]}:{item["line"]}: managed domain literal {", ".join(item["domains"])} (sha256 {item["sha256"]})')
        print(f'Domain literal audit: {result["checked_files"]} files checked, {len(result["violations"])} violations, {result["used_line_exceptions"]} reviewed line exceptions')
        if result["unused_line_exceptions"]:
            print(f'Unused line exceptions: {len(result["unused_line_exceptions"])}; remove stale entries when reviewing configuration')
    raise SystemExit(1 if result["violations"] else 0)


if __name__ == "__main__":
    main()
