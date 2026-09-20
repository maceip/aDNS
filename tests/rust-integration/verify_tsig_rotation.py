#!/usr/bin/env python3
"""Stock-library TSIG replacement continuity and revoked-key denial checks."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import TRANSFER_KEY_NAME, VALIDATION_DOMAIN
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import subprocess
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.tsigkeyring
import dns.zone

OLD = (TRANSFER_KEY_NAME)
NEW = 'agentdns-transfer-replacement.'
ZONE = (VALIDATION_DOMAIN + '.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('before', 'after'))
    parser.add_argument('--server', required=True, type=ipaddress.ip_address)
    args = parser.parse_args()
    root = Path('/work')
    results = root/'results'
    out = results/'rotation'/args.phase
    out.mkdir(mode=0o700, exist_ok=False)
    encoded = {}
    for key_name, filename in ((OLD, 'transfer-key.b64'), (NEW, 'replacement-transfer-key.b64')):
        value = (root/'control/private'/filename).read_bytes().strip()
        secret = base64.b64decode(value, validate=True)
        if len(secret) != 32 or base64.b64encode(secret) != value:
            raise ValueError('expected canonical 32-byte private transfer secret')
        encoded[key_name] = value.decode('ascii')
    keys = dns.tsigkeyring.from_text(encoded)
    server = str(args.server)

    def signed_query(name):
        query = dns.message.make_query(ZONE, 'SOA')
        query.use_tsig(keys, keyname=name, algorithm='hmac-sha256')
        return query

    negative = {}
    if args.phase == 'after':
        attempted = dns.query.xfr(server, ZONE, port=5353, keyring=keys, keyname=OLD,
            keyalgorithm='hmac-sha256', timeout=2, lifetime=3)
        try:
            next(attempted)
        except (EOFError, OSError, dns.exception.DNSException) as error:
            negative['revoked_axfr_rejected'] = True
            negative['revoked_axfr_observed_error'] = type(error).__name__
        else:
            raise ValueError('revoked identity received an AXFR message')
        finally:
            attempted.close()
        (out/'negative-observations.json').write_text(json.dumps(negative, indent=2)+'\n')
        try:
            answer = dns.query.udp(signed_query(OLD), server, port=5353, timeout=3)
        except (OSError, dns.exception.DNSException) as error:
            negative['revoked_udp_soa_rejected'] = True
            negative['revoked_udp_observed_error'] = type(error).__name__
        else:
            if answer.answer or answer.rcode() not in (dns.rcode.NOTAUTH, dns.rcode.REFUSED):
                raise ValueError('revoked identity received an accepted UDP SOA')
            negative['revoked_udp_soa_rejected'] = True
            negative['revoked_udp_observed_error'] = dns.rcode.to_text(answer.rcode())
        (out/'negative-observations.json').write_text(json.dumps(negative, indent=2)+'\n')

    # A fresh replacement transfer and authenticated SOA after the negative
    # checks distinguish revocation from an unavailable transfer service.
    messages = []
    size = 0
    for message in dns.query.xfr(server, ZONE, port=5353, keyring=keys, keyname=NEW,
            keyalgorithm='hmac-sha256', relativize=False, timeout=5, lifetime=30):
        size += len(message.to_wire())+2
        if len(messages) >= 4096 or size > 64*1024*1024:
            raise ValueError('replacement transfer exceeds bounded message/byte budget')
        messages.append(message)
    if len(messages) < 2 or not all(m.had_tsig and m.keyname.to_text() == NEW for m in messages):
        raise ValueError('replacement transfer did not authenticate every message with the new identity')
    zone = dns.zone.from_xfr(iter(messages), relativize=False)
    receipt = json.loads((results/'ksk-receipt.json').read_text())
    key = next(k for k in zone.get_rdataset(ZONE, 'DNSKEY') if k.flags == 257)
    if key.to_wire() != bytes.fromhex(receipt['dnskey_rdata_hex']):
        raise ValueError('replacement KSK differs from the independently verified CCF receipt')
    path = out/'transferred.zone'
    zone.to_file(str(path), relativize=False)
    check = subprocess.run(['ldns-verify-zone', '-k', str(results/'trusted-dnskey.txt'), str(path)],
        capture_output=True, text=True, timeout=30)
    (out/'ldns-verify-zone.log').write_text(check.stdout+check.stderr)
    if check.returncode:
        raise ValueError('replacement transfer failed full-zone DNSSEC verification')
    answer = dns.query.udp(signed_query(NEW), server, port=5353, timeout=5)
    if not answer.had_tsig or answer.keyname.to_text() != NEW or not answer.flags & dns.flags.AA or answer.rcode() != dns.rcode.NOERROR:
        raise ValueError('replacement UDP SOA was not authenticated and authoritative')
    soa = zone.get_rdataset(ZONE, 'SOA')[0]
    if answer.answer[0][0].serial != soa.serial:
        raise ValueError('replacement UDP SOA and transfer serial differ')

    work_count = None
    if args.phase == 'after':
        responses = json.loads((results/'rotation/issued-work.json').read_text())
        work_count = 0
        for response in responses:
            for item in response['body'].get('work', []):
                raw = item['packet_base64url']
                packet = base64.urlsafe_b64decode(raw+'='*(-len(raw)%4))
                message = dns.message.from_wire(packet, keyring=keys)
                if not message.had_tsig or message.keyname.to_text() != NEW:
                    raise ValueError('post-revocation work contains an unrecognized or revoked TSIG identity')
                work_count += 1
    result = {'status':'passed', 'phase':args.phase, 'unix_seconds':time.time(), 'server':server,
        'replacement_key_name':NEW, 'transfer_messages':len(messages),
        'transfer_records':sum(len(rr) for message in messages for rr in message.answer),
        'every_message_authenticated_with_replacement':True, 'full_zone_dnssec_validated':True,
        'ksk_matches_verified_receipt':True, 'authenticated_replacement_udp_soa':True,
        'serial':soa.serial, 'post_revocation_returned_work_packets':work_count,
        'scope':'independent replacement AXFR/SOA; replacement BIND propagation is not claimed', **negative}
    (out/'results.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
