#!/usr/bin/env python3
"""Measured frontend throughput/latency on the real BIND secondary."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import json,pathlib,re,statistics,subprocess,time
import dns.message,dns.query
root=pathlib.Path('/work')
queries=[(('mail-good.' + VALIDATION_DOMAIN + '.'),'A'),(('_25._tcp.mail-good.' + VALIDATION_DOMAIN + '.'),'TLSA'),(('absent.branch.' + VALIDATION_DOMAIN + '.'),'A'),(('missing.wild.' + VALIDATION_DOMAIN + '.'),'A')]
(root/'dnsperf-queries.txt').write_text(''.join(n+' '+t+'\n' for n,t in queries))
# Fixed-rate sustained load, not an inferred maximum throughput claim.
p=subprocess.run(['dnsperf','-s','127.0.0.1','-p','1053','-d',str(root/'dnsperf-queries.txt'),'-l','30','-Q','10000','-q','1000'],capture_output=True,text=True,timeout=40)
(root/'dnsperf.log').write_text(p.stdout+p.stderr)
assert p.returncode==0,p.stdout+p.stderr
metrics={}
for label,pattern in [('queries_sent',r'Queries sent:\s+(\d+)'),('queries_completed',r'Queries completed:\s+(\d+)'),('queries_lost',r'Queries lost:\s+(\d+)'),('completed_qps',r'Queries per second:\s+([0-9.]+)')]:
    match=re.search(pattern,p.stdout+p.stderr);assert match,pattern;metrics[label]=float(match.group(1)) if label=='completed_qps' else int(match.group(1))
latencies=[];started=time.perf_counter()
for i in range(3000):
    q=dns.message.make_query(*queries[i%len(queries)],want_dnssec=True)
    begin=time.perf_counter_ns();dns.query.udp(q,'127.0.0.1',port=1053,timeout=2);latencies.append((time.perf_counter_ns()-begin)/1e6)
latencies.sort()
result={'sampling':'sequential 3000 mixed DO=1 queries after 30-second dnsperf fixed offered rate of 10000 qps','duration_seconds':time.perf_counter()-started,'samples':len(latencies),'p50_ms':statistics.median(latencies),'p99_ms':latencies[int(len(latencies)*.99)-1],'max_ms':max(latencies),'dnsperf_log':'dnsperf.log','dnsperf':metrics,'note':'localhost container BIND frontend, development dataset; not a WAN or peak-capacity benchmark'}
(root/'performance-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2),flush=True)
