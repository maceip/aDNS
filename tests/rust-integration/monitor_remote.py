#!/usr/bin/env python3
"""Observe public stock BIND across real CCF-driven signature renewal.

Run from the independent validation image with a separately verified KSK anchor.
This sends only DNS queries and requires no TSIG or DNSSEC private key.
"""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_NS_HOSTNAME, VALIDATION_DOMAIN
import argparse,ipaddress,json,pathlib,subprocess,time
import dns.flags,dns.message,dns.query,dns.rcode,dns.rdatatype
p=argparse.ArgumentParser();p.add_argument('--server',required=True);p.add_argument('--port',type=int,default=53);p.add_argument('--anchor',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--seconds',type=int,default=1250);a=p.parse_args()
ipaddress.ip_address(a.server)
if a.seconds<1200:p.error('require at least two real 600-second signature lifetimes')
a.output.mkdir(parents=True,exist_ok=True);start=time.monotonic();samples=[]
while True:
 now=int(time.time());answer=dns.query.udp(dns.message.make_query((VALIDATION_DOMAIN + '.'),'SOA',want_dnssec=True),a.server,port=a.port,timeout=5)
 assert answer.flags&dns.flags.AA,'public secondary must be authoritative'
 soa=next(rr[0] for rr in answer.answer if rr.rdtype==dns.rdatatype.SOA)
 expiration=min(sig.expiration for rr in answer.answer if rr.rdtype==dns.rdatatype.RRSIG for sig in rr if sig.type_covered==dns.rdatatype.SOA)
 assert expiration>now,'secondary served an expired signature'
 for name,kind in [((VALIDATION_DOMAIN + '.'),'SOA'),(('definitely-absent-agentd' + VALIDATION_NS_HOSTNAME + '.'),'A')]:
  result=subprocess.run(['delv','@'+a.server,'-p',str(a.port),'-a',str(a.anchor),('+root=' + VALIDATION_DOMAIN + '.'),name,kind],capture_output=True,text=True,timeout=15)
  assert result.returncode==0 and 'fully validated' in result.stdout,result.stdout+result.stderr
  if name.startswith('definitely-absent-'):assert 'NXDOMAIN' in result.stdout,'negative test owner unexpectedly exists'
 sample={'unix_seconds':now,'elapsed_seconds':time.monotonic()-start,'serial':soa.serial,'soa_signature_expiration':expiration,'external_positive_and_negative_dnssec_validations':True};samples.append(sample)
 temporary=a.output/'remote-idle-samples.json.tmp';temporary.write_text(json.dumps(samples,indent=2)+'\n');temporary.replace(a.output/'remote-idle-samples.json')
 print(json.dumps(sample),flush=True)
 if time.monotonic()-start>=a.seconds:break
 time.sleep(30)
assert samples[-1]['unix_seconds']>samples[0]['soa_signature_expiration'],'did not cross initial signature expiration; configure real 600-second validity/300-second refresh'
assert len({sample['serial'] for sample in samples})>=3,'need multiple observed automatic refreshes'
result={'source':'independent-public-BIND-DNSSEC-probes','server':a.server,'port':a.port,'elapsed_seconds':samples[-1]['elapsed_seconds'],'observed_serials':sorted({sample['serial'] for sample in samples}),'external_validations':2*len(samples),'crossed_initial_signature_expiration':True,'all_samples_passed':True,'proof_limit':'CCF transaction provenance, leases and hardware require separate evidence; this verifier sends no mutations.'}
(a.output/'remote-idle-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
