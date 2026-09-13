#!/usr/bin/env python3
"""Verify the exact one-record reconciliation fixture on stock BIND."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

OWNER = 'reconcile.example.test.'
VALUE = 'durable authenticated request reconciliation'


def validate_response(response):
    if response.rcode() != dns.rcode.NOERROR or not response.flags & dns.flags.AA:
        raise ValueError('reconciliation TXT response is not authoritative')
    matches = [rrset for rrset in response.answer
        if rrset.name == dns.name.from_text(OWNER) and rrset.rdtype == dns.rdatatype.TXT]
    if len(matches) != 1 or len(matches[0]) != 1 or matches[0].ttl != 60:
        raise ValueError('expected exactly one TXT record at the governed owner with TTL 60')
    if tuple(matches[0][0].strings) != (VALUE.encode('ascii'),):
        raise ValueError('reconciliation TXT bytes differ from the committed mutation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=ipaddress.ip_address, required=True)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--anchor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if json.loads(args.expected.read_text()) != [[OWNER, 'TXT', VALUE]]:
        raise ValueError('expected the fixed single-record reconciliation fixture')
    args.output.mkdir(parents=True, exist_ok=False)
    response = dns.query.tcp(dns.message.make_query(OWNER, 'TXT', want_dnssec=True), str(args.server), timeout=10)
    (args.output/'response.txt').write_text(response.to_text()+'\n')
    validate_response(response)
    check = subprocess.run(['delv', '@'+str(args.server), '-p', '53', '-a', str(args.anchor),
        '+root=example.test.', OWNER, 'TXT'], capture_output=True, text=True, timeout=15)
    (args.output/(OWNER+'TXT.log')).write_text(check.stdout+check.stderr)
    if check.returncode or 'fully validated' not in check.stdout:
        raise ValueError('reconciliation TXT did not pass independent DNSSEC validation')
    result = {'name':OWNER, 'type':'TXT', 'ttl':60, 'exact_rdata_matches':True,
        'dnssec_validated':True, 'txt_chunks':1}
    (args.output/'results.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
