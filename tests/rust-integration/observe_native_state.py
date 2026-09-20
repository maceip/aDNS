#!/usr/bin/env python3
"""Bounded read-only observation of exact lifecycle RRsets on public BIND."""

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
import re
import subprocess
import time

import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype

from verify_native_dns import bounded_json, exact_records, query, require_record_set, validate_delv_output


def validate_expectations(value):
    if not isinstance(value,list) or not 1 <= len(value) <= 16:
        raise ValueError('one to sixteen explicit RRsets required')
    seen = set()
    for item in value:
        if not isinstance(item,dict) or set(item) != {'owner','type','rdata'}:
            raise ValueError('exact owner/type/rdata expectation schema required')
        name = dns.name.from_text(item['owner'])
        if (not name.is_subdomain(dns.name.from_text((VALIDATION_DOMAIN + '.'))) or name.to_text() != item['owner']
                or len(item['owner']) > 255 or any(not re.fullmatch('[a-z0-9_-]{1,63}',label) for label in item['owner'][:-1].split('.'))):
            raise ValueError(('fixture owner must be canonical and inside ' + VALIDATION_DOMAIN + '.'))
        if item['type'] not in ('A','AAAA','MX','TLSA','TXT','CAA'):
            raise ValueError('unsupported fixture record type')
        identity = (item['owner'],item['type'])
        if identity in seen:
            raise ValueError('duplicate RRset expectation')
        seen.add(identity)
        if not isinstance(item['rdata'],list) or len(item['rdata']) > 8 or any(not isinstance(v,str) or len(v)>4096 for v in item['rdata']):
            raise ValueError('bounded textual RDATA list required')
    return value


def validate_answer(answer, item):
    if item['rdata']:
        require_record_set(exact_records(answer,item['owner'],item['type']),item['type'],item['rdata'])
    elif (not answer.flags & dns.flags.AA or answer.rcode() not in (dns.rcode.NOERROR,dns.rcode.NXDOMAIN)
            or answer.answer or not any(rr.rdtype == dns.rdatatype.NSEC3 for rr in answer.authority)):
        raise ValueError('withdrawal requires empty authoritative answer and NSEC3 denial')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server',type=ipaddress.ip_address,required=True)
    parser.add_argument('--port',type=int,default=53)
    parser.add_argument('--anchor',type=Path,required=True)
    parser.add_argument('--expected',type=Path,required=True)
    parser.add_argument('--minimum-serial',type=int,required=True)
    parser.add_argument('--deadline-seconds',type=int,default=600)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 <= args.minimum_serial < 2**32 or not 5 <= args.deadline_seconds <= 600:
        parser.error('invalid bounded port, serial or observation deadline')
    expected = validate_expectations(bounded_json(args.expected,65536))
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
    started, started_unix = time.monotonic(), time.time()
    samples = []
    while True:
        sample = {'unix_seconds':time.time(),'elapsed_seconds':time.monotonic()-started,'matches':False}
        try:
            answer = query(str(args.server),args.port,(VALIDATION_DOMAIN + '.'),'SOA')
            serial = exact_records(answer,(VALIDATION_DOMAIN + '.'),'SOA')[0].serial
            sample['serial'] = serial
            if (serial-args.minimum_serial) % 2**32 >= 2**31:
                raise ValueError('secondary has not served the committed minimum serial')
            answers = []
            for item in expected:
                if time.monotonic()-started >= args.deadline_seconds:
                    raise TimeoutError('bounded native-state observation expired')
                answer = query(str(args.server),args.port,item['owner'],item['type'])
                validate_answer(answer,item)
                answers.append((item,answer))
            sample['matches'] = True
            sample['match_completed_unix_seconds'] = time.time()
        except Exception as error:
            sample['error_type'] = type(error).__name__
            sample['error'] = str(error)
        samples.append(sample)
        (args.output/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
        if sample['matches']:
            break
        if time.monotonic()-started >= args.deadline_seconds:
            raise TimeoutError('exact lifecycle RRsets not observed within bounded deadline; samples retained')
        time.sleep(min(5,max(0,args.deadline_seconds-(time.monotonic()-started))))
    checks = []
    for item, answer in answers:
        name = item['owner']+item['type']
        (args.output/(name+'.txt')).write_text(answer.to_text()+'\n')
        check = subprocess.run(['delv','@'+str(args.server),'-p',str(args.port),'-a',str(args.anchor),
            ('+root=' + VALIDATION_DOMAIN + '.'),item['owner'],item['type']],capture_output=True,text=True,timeout=15)
        (args.output/(name+'.delv.log')).write_text(check.stdout+check.stderr)
        if check.returncode or 'fully validated' not in check.stdout:
            raise ValueError('stock delv rejected observed lifecycle RRset')
        validate_delv_output(check.stdout,item['owner'],item['type'],
            item['rdata'] or None,None if item['rdata'] else 'absent')
        checks.append({'owner':item['owner'],'type':item['type'],'expected_rdata':item['rdata'],'dnssec_validated':True})
    result = {'status':'passed','server':str(args.server),'port':args.port,'minimum_committed_serial':args.minimum_serial,
        'observed_serial':serial,'started_unix_seconds':started_unix,'matched_unix_seconds':samples[-1]['match_completed_unix_seconds'],
        'elapsed_seconds':time.monotonic()-started,'poll_samples':len(samples),'checks':checks,
        'boundary':'Exact public authoritative RRsets and stock DNSSEC validation; cause/timing is correlated with separate committed mutation/maintenance evidence.'}
    (args.output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)


if __name__ == '__main__':
    main()
