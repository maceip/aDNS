#!/usr/bin/env python3
"""Keep exercising an external DNSSEC validator throughout real idle refresh."""
import argparse,json,pathlib,subprocess,time
import dns.message,dns.query,dns.rdatatype
parser=argparse.ArgumentParser();parser.add_argument('--seconds',type=int,default=1220);args=parser.parse_args()
root=pathlib.Path('/work');first=json.loads((root/'idle-samples.json').read_text())[0];start=first['unix_seconds']-first['elapsed_seconds'];samples=json.loads((root/'frontend-idle-samples.json').read_text()) if (root/'frontend-idle-samples.json').exists() else []
while True:
    now=int(time.time())
    q=dns.message.make_query('example.test.','SOA',want_dnssec=True)
    a=dns.query.udp(q,'127.0.0.1',port=1053,timeout=3)
    soa=next(r for r in a.answer if r.rdtype==dns.rdatatype.SOA)[0]
    expiry=min(r.expiration for rr in a.answer if rr.rdtype==dns.rdatatype.RRSIG for r in rr if r.type_covered==dns.rdatatype.SOA)
    assert expiry>now,'secondary served expired SOA signature'
    for name,kind in [('example.test.','SOA'),('absent.branch.example.test.','A')]:
        p=subprocess.run(['delv','@127.0.0.1','-p','1053','-a','/work/trust-anchor.conf','+root=example.test.',name,kind],capture_output=True,text=True,timeout=5)
        assert p.returncode==0 and 'fully validated' in p.stdout,p.stdout+p.stderr
    samples.append({'unix_seconds':now,'elapsed_seconds':now-start,'secondary_serial':soa.serial,'soa_signature_expiration':expiry,'external_positive_and_negative_validation':True})
    (root/'frontend-idle-samples.json.tmp').write_text(json.dumps(samples,indent=2)+'\n');(root/'frontend-idle-samples.json.tmp').replace(root/'frontend-idle-samples.json')
    if now-start>=args.seconds:break
    time.sleep(30)
result={'elapsed_seconds':samples[-1]['elapsed_seconds'],'observed_secondary_serials':sorted({s['secondary_serial'] for s in samples}),'external_validations':2*len(samples),'all_passed':True,'first_observed_expiration':samples[0]['soa_signature_expiration'],'last_observed_expiration':samples[-1]['soa_signature_expiration']}
assert len(result['observed_secondary_serials'])>=4
assert samples[-1]['unix_seconds']>result['first_observed_expiration']
(root/'frontend-idle-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
