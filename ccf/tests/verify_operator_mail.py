#!/usr/bin/env python3
"""Verify committed operator mail policy on a real authoritative secondary."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rcode
import dns.rdatatype


def records_at_owner(response, name, kind):
    """A validated alias target is not proof of a record at the governed owner."""
    owner = dns.name.from_text(name)
    record_type = dns.rdatatype.from_text(kind)
    return [record for rrset in response.answer
            if rrset.name == owner and rrset.rdtype == record_type
            for record in rrset]


def caa_matches(records, expected):
    """Compare with the policy actually committed, including flags and tag."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CAA, expected) in records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=ipaddress.ip_address, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(args.expected.read_text())
    if len(expected) != 5 or any(kind not in ("TXT", "CAA") for _, kind, _ in expected):
        raise ValueError("expected the five operator mail policies")
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for name, kind, value in expected:
        response = dns.query.tcp(dns.message.make_query(name, kind, want_dnssec=True), str(args.server), timeout=10)
        if response.rcode() != dns.rcode.NOERROR or not response.flags & dns.flags.AA:
            raise ValueError("secondary did not answer authoritatively")
        records = records_at_owner(response, name, kind)
        if kind == "TXT":
            matched = [record for record in records if b"".join(record.strings) == value.encode("ascii")]
            if not matched or any(len(chunk) > 255 for record in matched for chunk in record.strings):
                raise ValueError("served TXT bytes differ from the committed policy")
            chunks = len(matched[0].strings)
            if name.startswith("selector1.") and chunks < 2:
                raise ValueError("long DKIM value did not exercise multiple DNS character strings")
        else:
            if not caa_matches(records, value):
                raise ValueError("served CAA differs from the committed policy")
            chunks = None
        check = subprocess.run(["delv", "@" + str(args.server), "-p", "53", "-a", str(args.anchor),
                                ('+root=' + VALIDATION_DOMAIN + '.'), name, kind], capture_output=True, text=True, timeout=15)
        (args.output / (name + kind + ".log")).write_text(check.stdout + check.stderr)
        if check.returncode != 0 or "fully validated" not in check.stdout:
            raise ValueError("operator policy failed independent DNSSEC validation")
        results.append({"name": name, "type": kind, "exact_rdata_matches": True, "dnssec_validated": True, "txt_chunks": chunks})
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
