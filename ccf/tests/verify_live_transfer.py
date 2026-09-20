#!/usr/bin/env python3
"""Independently verify CCF TSIG transfer and stock BIND against a verified KSK."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import TRANSFER_KEY_NAME, VALIDATION_NS_HOSTNAME, VALIDATION_DOMAIN
import argparse
import base64
import ipaddress
import json
import pathlib
import subprocess
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.tsigkeyring
import dns.zone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=ipaddress.ip_address, required=True)
    parser.add_argument("--key-file", type=pathlib.Path, required=True)
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    parser.add_argument("--anchor", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-key", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    encoded = args.key_file.read_bytes().strip()
    secret = base64.b64decode(encoded, validate=True)
    if len(secret) != 32 or base64.b64encode(secret) != encoded:
        raise ValueError("expected canonical 32-byte TSIG secret file")
    origin, name = (VALIDATION_DOMAIN + '.'), (TRANSFER_KEY_NAME)
    keyring = dns.tsigkeyring.from_text({name: encoded.decode("ascii")})
    messages, transfer_bytes = [], 0
    for message in dns.query.xfr(str(args.server), origin, port=5353, keyring=keyring,
                                 keyname=name, keyalgorithm="hmac-sha256", relativize=False,
                                 timeout=5, lifetime=30):
        transfer_bytes += len(message.to_wire()) + 2
        if len(messages) >= 4096 or transfer_bytes > 64 * 1024 * 1024:
            raise ValueError("transfer exceeds bounded frame or wire-byte budget")
        messages.append(message)
    if not messages or not all(message.had_tsig for message in messages):
        raise ValueError("transfer lacked complete TSIG authentication")
    zone = dns.zone.from_xfr(iter(messages), relativize=False)
    receipt = json.loads(args.receipt.read_text())
    key = next(key for key in zone.get_rdataset(origin, "DNSKEY") if key.flags == 257)
    if key.to_wire() != bytes.fromhex(receipt["dnskey_rdata_hex"]):
        raise ValueError("transferred KSK differs from independently verified CCF receipt")
    path = args.output / "transferred.zone"
    zone.to_file(str(path), relativize=False)
    check = subprocess.run(["ldns-verify-zone", "-k", str(args.trusted_key), str(path)],
                           capture_output=True, text=True, timeout=30)
    (args.output / "ldns-verify-zone.log").write_text(check.stdout + check.stderr)
    if check.returncode != 0:
        raise ValueError("independent full-zone DNSSEC validation failed")
    negatives = {}
    for label, keys in [("unsigned", None), ("wrong_key", dns.tsigkeyring.from_text({name: base64.b64encode(bytes(32)).decode()}))]:
        unauthorized = dns.query.xfr(str(args.server), origin, port=5353, keyring=keys,
                                     keyname=name if keys else None, keyalgorithm="hmac-sha256",
                                     timeout=2, lifetime=3)
        try:
            next(unauthorized)
        except (EOFError, OSError, dns.exception.DNSException):
            negatives[label + "_rejected"] = True
        else:
            raise ValueError("unauthorized transfer disclosed a DNS message")
        finally:
            unauthorized.close()
    validations = []
    for owner, kind in [(origin, "SOA"), (origin, "DNSKEY"), (origin, "TXT"),
                        (('definitely-absent-agentd' + VALIDATION_NS_HOSTNAME + '.'), "A")]:
        check = subprocess.run(["delv", "@" + str(args.server), "-p", "53", "-a", str(args.anchor),
                                ('+root=' + VALIDATION_DOMAIN + '.'), owner, kind], capture_output=True,
                               text=True, timeout=15)
        (args.output / ("delv-" + owner + kind + ".log")).write_text(check.stdout + check.stderr)
        if check.returncode != 0 or "fully validated" not in check.stdout:
            raise ValueError("external DNSSEC query did not validate")
        validations.append({"owner": owner, "type": kind, "validated": True})
    answer = dns.query.udp(dns.message.make_query(origin, "SOA", want_dnssec=True), str(args.server), timeout=5)
    if not answer.flags & dns.flags.AA or answer.answer[0][0].serial != zone.get_rdataset(origin, "SOA")[0].serial:
        raise ValueError("secondary is not authoritative at the transferred serial")
    result = {"unix_seconds": time.time(), "server": str(args.server), "primary_transfer_port": 5353,
              "secondary_port": 53, "transfer_messages": len(messages),
              "transfer_records": sum(len(rr) for message in messages for rr in message.answer),
              "transfer_reserialized_wire_bytes": transfer_bytes,
              "every_message_tsig_verified": True, "ksk_matches_verified_receipt": True,
              "transfer_serial": zone.get_rdataset(origin, "SOA")[0].serial,
              "secondary_serial": answer.answer[0][0].serial,
              "secondary_authoritative": bool(answer.flags & dns.flags.AA),
              "full_zone_ldns_validated": True, "queries": validations, **negatives}
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
