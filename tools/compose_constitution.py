#!/usr/bin/env python3
"""Compose the agentdns constitution deterministically.

    pinned CCF 7.0.15 default actions.js (sha256-checked)
  + ccf/governance/actions.js        (agentdns actions, release authority, governors)
  + ccf/governance/exports.js        (validate/apply from the CCF default constitution)
  + ccf/governance/resolve.js        (reputation-weighted vote rule)

Prints the composed text (or writes --output) and its SHA-256, which is what the
live `/gov/service/constitution` must serve after a `set_constitution` proposal.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "ccf" / "governance"
PINNED_DEFAULT = "ccf-7.0.15-actions.js"
PINNED_DEFAULT_SHA256 = "8351bce374f2ffc4a64d94835e79f4faeb45a9aa9c9ca48034d3458b3332c2ff"
PARTS = (PINNED_DEFAULT, "actions.js", "exports.js", "resolve.js")


def compose(root=HERE):
    default = (root / PINNED_DEFAULT).read_bytes()
    if hashlib.sha256(default).hexdigest() != PINNED_DEFAULT_SHA256:
        raise SystemExit(f"{PINNED_DEFAULT} does not match the pinned CCF 7.0.15 default actions.js digest")
    text = b"".join((root / part).read_bytes() if (root / part).read_bytes().endswith(b"\n") else (root / part).read_bytes() + b"\n" for part in PARTS)
    exports = sum(text.count(f"export function {name}(".encode()) for name in ("validate", "apply", "resolve"))
    if exports != 3:
        raise SystemExit("composed constitution must export exactly validate, apply and resolve")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--proposal", type=Path, help="also write a set_constitution proposal body here")
    args = parser.parse_args()
    text = compose()
    digest = hashlib.sha256(text).hexdigest()
    if args.output:
        args.output.write_bytes(text)
    if args.proposal:
        args.proposal.write_text(json.dumps([{"name": "set_constitution", "args": {"constitution": text.decode()}}]))
    print(json.dumps({"sha256": digest, "bytes": len(text), "lines": text.count(b"\n"), "parts": list(PARTS)}))
    if not args.output and not args.proposal:
        sys.stdout.write(text.decode())


if __name__ == "__main__":
    main()
