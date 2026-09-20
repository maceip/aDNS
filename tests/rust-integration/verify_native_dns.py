#!/usr/bin/env python3
"""Independent native deployment DNS proof from a trusted CCF KSK receipt.

Only DNS queries and an authenticated AXFR are sent. The TSIG file is an input
secret and is never included in any artifact. Hardware and admission provenance
must be supplied separately; this verifier checks the actual served DNS data.
"""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import TRANSFER_KEY_NAME, VALIDATION_DOMAIN
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.tsigkeyring
import dns.zone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'tools'))
from verify_ksk_receipt import unique_object, verify


def bounded_json(path, limit=1024*1024):
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('public JSON input exceeds bound')
    return json.loads(raw, object_pairs_hook=unique_object)


def exact_records(response, owner, kind):
    """Require the actual owner/type, never an alias's answer or empty set."""
    owner, kind = dns.name.from_text(owner), dns.rdatatype.from_text(kind)
    if response.rcode() != dns.rcode.NOERROR or not response.flags & dns.flags.AA:
        raise ValueError('answer is not an authoritative positive response')
    records = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            if rrset.name != owner or any(signature.type_covered != kind for signature in rrset):
                raise ValueError('signature covers an unexpected owner or type')
            continue
        if rrset.name != owner or rrset.rdtype != kind or rrset.rdclass != 1:
            raise ValueError('answer contains an unexpected owner, class or type')
        records.extend(rrset)
    if not records:
        raise ValueError('expected exact positive answer is absent')
    return records


def require_record_set(records, kind, expected):
    actual = {record.to_digestable() for record in records}
    wanted = {dns.rdata.from_text(1, kind, value).to_digestable() for value in expected}
    if actual != wanted:
        raise ValueError('authoritative record set differs from the complete expected set')


def validate_delv_output(text, owner, kind, expected=None, negative=None):
    """Bind stock validation to the same exact records, not a later different answer."""
    if negative is not None:
        matches = re.findall(r'^;\s+(\S+)\s+\d+\s+IN\s+\\-(\S+)\s+;-\$(NXDOMAIN|NXRRSET)\s*$',text,re.MULTILINE)
        allowed = {'NXDOMAIN','NXRRSET'} if negative == 'absent' else {negative}
        if ('negative response, fully validated' not in text or
                not any(name == owner and result in allowed and query_type == ('ANY' if result == 'NXDOMAIN' else kind)
                        for name,query_type,result in matches)):
            raise ValueError('stock delv did not validate the exact requested absence')
        return
    if not text.startswith('; fully validated\n'):
        raise ValueError('stock delv did not validate a positive answer')
    parsed = dns.zone.from_text(text,origin=(VALIDATION_DOMAIN + '.'),relativize=False,check_origin=False)
    wanted_name,wanted_type = dns.name.from_text(owner),dns.rdatatype.from_text(kind)
    records = []
    for name,node in parsed.nodes.items():
        for dataset in node.rdatasets:
            if name != wanted_name or dataset.rdclass != 1:
                raise ValueError('stock delv returned another owner or class')
            if dataset.rdtype == dns.rdatatype.RRSIG:
                if any(sig.type_covered != wanted_type for sig in dataset):
                    raise ValueError('stock delv returned another covered type')
            elif dataset.rdtype == wanted_type:
                records.extend(dataset)
            else:
                raise ValueError('stock delv returned an alias or unexpected type')
    if not records:
        raise ValueError('stock delv omitted the expected positive records')
    if expected is not None:
        require_record_set(records,kind,expected)


def query(server, port, name, kind):
    request = dns.message.make_query(name, kind, want_dnssec=True)
    response = dns.query.udp(request, server, port=port, timeout=5)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(request, server, port=port, timeout=5)
    return response


def transfer(server, port, origin, key_name, keyring):
    messages, total = [], 0
    stream = dns.query.xfr(server, origin, port=port, keyring=keyring, keyname=key_name,
        keyalgorithm='hmac-sha256', relativize=False, timeout=5, lifetime=30)
    try:
        for message in stream:
            total += len(message.to_wire())+2
            if len(messages) >= 4096 or total > 64*1024*1024:
                raise ValueError('AXFR exceeded bounded frame or wire-byte budget')
            messages.append(message)
    finally:
        stream.close()
    if not messages or not all(message.had_tsig for message in messages):
        raise ValueError('AXFR did not authenticate every frame')
    return dns.zone.from_xfr(iter(messages), relativize=False), messages, total


def receipt_checks(receipt, certificate, zone):
    positive = verify(receipt, certificate, zone)
    negatives = {}
    altered = copy.deepcopy(receipt)
    altered['zone'] = altered['owner_name'] = 'altered.invalid.'
    variants = {'altered_zone':altered}
    altered = copy.deepcopy(receipt)
    rdata = bytearray.fromhex(altered['dnskey_rdata_hex']);rdata[-1] ^= 1
    altered['dnskey_rdata_hex'] = rdata.hex();variants['modified_dnskey_rdata'] = altered
    altered = copy.deepcopy(receipt)
    signature = bytearray(base64.b64decode(altered['proof']['signature'], validate=True));signature[-1] ^= 1
    altered['proof']['signature'] = base64.b64encode(signature).decode()
    variants['invalid_ccf_signature'] = altered
    altered = copy.deepcopy(receipt)
    evidence = altered['proof']['leaf_components']['commit_evidence']
    altered['proof']['leaf_components']['commit_evidence'] = evidence[:-1]+('0' if evidence[-1] != '0' else '1')
    variants['modified_commit_evidence'] = altered
    for name, variant in variants.items():
        try:
            verify(variant, certificate, zone)
        except Exception as error:
            negatives[name] = {'rejected':True, 'error_type':type(error).__name__}
        else:
            raise ValueError('altered KSK receipt was accepted: '+name)
    return positive, negatives


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--primary', type=ipaddress.ip_address, required=True)
    parser.add_argument('--primary-port', type=int, default=5353)
    parser.add_argument('--secondary', type=ipaddress.ip_address, required=True)
    parser.add_argument('--secondary-port', type=int, default=53)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--service-cert', type=Path, required=True)
    parser.add_argument('--spki', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not all(1 <= port <= 65535 for port in (args.primary_port, args.secondary_port)) or not 1 <= len(args.spki) <= 2:
        parser.error('bounded ports and one or two appraised SPKI files required')
    args.output.mkdir(parents=True, exist_ok=False)
    origin, host, key_name = (VALIDATION_DOMAIN + '.'), ('mail.' + VALIDATION_DOMAIN + '.'), (TRANSFER_KEY_NAME)
    receipt = bounded_json(args.receipt)
    positive, negatives = receipt_checks(receipt, args.service_cert.read_text(), origin)
    (args.output/'receipt-verification.json').write_text(json.dumps({'verified':positive,'negative_variants':negatives},indent=2)+'\n')
    rdata = bytes.fromhex(receipt['dnskey_rdata_hex'])
    public_key = base64.b64encode(rdata[4:]).decode()
    anchor = args.output/'trust-anchor.conf'
    anchor.write_text(f'trust-anchors {{ "{origin}" static-key 257 3 14 "{public_key}"; }};\n')
    trusted_key = args.output/'trusted-dnskey.txt'
    trusted_key.write_text(f'{origin} IN DNSKEY 257 3 14 {public_key}\n')
    digests = []
    for path in args.spki:
        data = path.read_bytes()
        if len(data) > 4096:
            raise ValueError('SPKI input exceeds bound')
        key = serialization.load_der_public_key(data)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError('native worker must have a P256 SPKI')
        if key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo) != data:
            raise ValueError('native worker SPKI must use canonical DER')
        digests.append(hashlib.sha256(data).hexdigest())
    if len(set(digests)) != len(digests):
        raise ValueError('rotation inputs must contain distinct worker keys')
    with args.key_file.open('rb') as stream:
        encoded = stream.read(46).strip()
    secret = base64.b64decode(encoded, validate=True)
    if len(secret) != 32 or base64.b64encode(secret) != encoded:
        raise ValueError('expected canonical 32-byte TSIG input')
    keyring = dns.tsigkeyring.from_text({key_name:encoded.decode()})
    zone, messages, total = transfer(str(args.primary), args.primary_port, origin, key_name, keyring)
    if len(messages) < 2:
        raise ValueError('native fixture did not exercise multi-message AXFR')
    ksks = [key for key in zone.get_rdataset(origin,'DNSKEY') if key.flags == 257]
    if len(ksks) != 1 or ksks[0].to_wire() != rdata:
        raise ValueError('transferred KSK differs from verified CCF receipt')
    ds = dns.dnssec.make_ds(origin, ksks[0], 'SHA256')
    if ds.digest.hex() != positive['ds_sha256'] or ds.key_tag != positive['key_tag'] or ds.algorithm != 14:
        raise ValueError('independent DS parameters differ from receipt')
    zone_path = args.output/'transferred.zone'
    zone.to_file(str(zone_path), relativize=False)
    checked = subprocess.run(['ldns-verify-zone','-k',str(trusted_key),str(zone_path)],capture_output=True,text=True,timeout=30)
    (args.output/'ldns-verify-zone.log').write_text(checked.stdout+checked.stderr)
    if checked.returncode:
        raise ValueError('stock ldns rejected the actual transferred signed zone')
    soa = query(str(args.secondary),args.secondary_port,origin,'SOA')
    secondary_serial = exact_records(soa,origin,'SOA')[0].serial
    transfer_serial = zone.get_rdataset(origin,'SOA')[0].serial
    if secondary_serial != transfer_serial:
        raise ValueError('served secondary serial differs from authenticated AXFR; retain this attempt and retry after convergence')
    expected_sets = [(host,'A',['192.0.2.1']), (host,'AAAA',['2001:db8::1']),
        (origin,'MX',['10 '+host]),
        *[(f'_{port}._tcp.{host}','TLSA',['3 1 1 '+digest for digest in sorted(digests)]) for port in (25,465,993)]]
    checked_sets = []
    for owner, kind, expected in expected_sets:
        answer = query(str(args.secondary),args.secondary_port,owner,kind)
        require_record_set(exact_records(answer,owner,kind),kind,expected)
        (args.output/f'answer-{owner}{kind}.txt').write_text(answer.to_text()+'\n')
        checked_sets.append({'owner':owner,'type':kind,'exact_rdata':expected})
    checks = [(origin,'SOA','positive'),(origin,'DNSKEY','positive'),
        *[(owner,kind,'positive') for owner,kind,_ in expected_sets],
        (('absent.branch.' + VALIDATION_DOMAIN + '.'),'A','nxdomain'),
        (('branch.' + VALIDATION_DOMAIN + '.'),'A','nodata'),
        (host,'HINFO','nodata'),
        (('fresh.wild.' + VALIDATION_DOMAIN + '.'),'A','wildcard-positive'),
        (('fresh.wild.' + VALIDATION_DOMAIN + '.'),'AAAA','wildcard-nodata')]
    validations = []
    for owner,kind,meaning in checks:
        answer = query(str(args.secondary),args.secondary_port,owner,kind)
        (args.output/f'answer-{owner}{kind}.txt').write_text(answer.to_text()+'\n')
        if not answer.flags & dns.flags.AA:
            raise ValueError('secondary lost authoritative response')
        if meaning == 'nxdomain':
            if answer.rcode() != dns.rcode.NXDOMAIN or answer.answer:
                raise ValueError('expected NXDOMAIN fixture was not absent')
        elif meaning.endswith('nodata'):
            if answer.rcode() != dns.rcode.NOERROR or answer.answer:
                raise ValueError('expected NODATA fixture had data or wrong status')
        else:
            records = exact_records(answer,owner,kind)
            if meaning == 'wildcard-positive':
                require_record_set(records,kind,['192.0.2.99'])
        if meaning in ('nxdomain','nodata','wildcard-nodata') and not any(rr.rdtype == dns.rdatatype.NSEC3 for rr in answer.authority):
            raise ValueError('denial did not contain native NSEC3 proof')
        checked = subprocess.run(['delv','@'+str(args.secondary),'-p',str(args.secondary_port),
            '-a',str(anchor),'+root='+origin,owner,kind],capture_output=True,text=True,timeout=15)
        (args.output/f'delv-{owner}{kind}.log').write_text(checked.stdout+checked.stderr)
        if checked.returncode or 'fully validated' not in checked.stdout:
            raise ValueError('stock delv rejected '+meaning)
        expected = next((values for name,rtype,values in expected_sets if (name,rtype) == (owner,kind)),None)
        if meaning == 'wildcard-positive':
            expected = ['192.0.2.99']
        negative = 'NXDOMAIN' if meaning == 'nxdomain' else ('NXRRSET' if meaning.endswith('nodata') else None)
        validate_delv_output(checked.stdout,owner,kind,expected,negative)
        validations.append({'owner':owner,'type':kind,'meaning':meaning,'stock_delv_validated':True})
    denied = {}
    wrong_secret = bytes([secret[0] ^ 1])+secret[1:]
    for label, keys in [('unsigned',None),('wrong_key',dns.tsigkeyring.from_text({key_name:base64.b64encode(wrong_secret).decode()}))]:
        stream = dns.query.xfr(str(args.primary),origin,port=args.primary_port,keyring=keys,
            keyname=key_name if keys else None,keyalgorithm='hmac-sha256',timeout=3,lifetime=5)
        try:
            next(stream)
        except (EOFError,OSError,dns.exception.DNSException) as error:
            denied[label] = {'rejected':True,'error_type':type(error).__name__}
        else:
            raise ValueError('unauthorized AXFR disclosed an answer')
        finally:
            stream.close()
    # A fresh authenticated transfer after both negatives rules out an outage.
    after, after_messages, _ = transfer(str(args.primary),args.primary_port,origin,key_name,keyring)
    if not after.get_rdataset(origin,'SOA') or not after_messages:
        raise ValueError('authenticated transfer failed after negative checks')
    result = {'status':'passed','unix_seconds':time.time(),'primary':str(args.primary),
        'primary_port':args.primary_port,'secondary':str(args.secondary),'secondary_port':args.secondary_port,
        'receipt_transaction':positive['tx_id'],'ksk_matches_verified_receipt':True,
        'independent_ds':ds.to_text(),'full_zone_ldns_validated':True,'transfer_messages':len(messages),
        'transfer_reserialized_wire_bytes':total,'all_frames_tsig_verified':True,
        'transfer_serial':transfer_serial,'secondary_serial':secondary_serial,
        'authenticated_axfr_succeeded_after_negatives':True,'unauthorized_transfers':denied,
        'exact_native_record_sets':checked_sets,'external_dnssec_checks':validations,
        'spki_sha256':sorted(digests),'boundary':'Actual external DNS/AXFR and receipt cryptography; native appraisal and global admission are separate inputs.'}
    (args.output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__ == '__main__':
    main()
