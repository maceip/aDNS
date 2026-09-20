#!/usr/bin/env python3
"""Sample frontend latency concurrently with a fixed DNSSEC-enabled load."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import json,pathlib,re,statistics,subprocess,time
import dns.message,dns.query
root=pathlib.Path('/work');queries=[(('mail-good.' + VALIDATION_DOMAIN + '.'),'A'),(('_25._tcp.mail-good.' + VALIDATION_DOMAIN + '.'),'TLSA'),(('absent.branch.' + VALIDATION_DOMAIN + '.'),'A'),(('missing.wild.' + VALIDATION_DOMAIN + '.'),'A')]
log=open(root/'dnsperf-dnssec-under-load.log','w');load=subprocess.Popen(['dnsperf','-s','127.0.0.1','-p','1053','-d',str(root/'dnsperf-queries.txt'),'-l','30','-Q','1000','-q','100','-D'],stdout=log,stderr=log)
start=time.perf_counter();start_unix=time.time();latencies=[];failures=0;memory=[]
frontend_pid=int((root/'named-secondary.pid').read_text().strip())
for i in range(3000):
    deadline=start+i/100
    if deadline>time.perf_counter():time.sleep(deadline-time.perf_counter())
    if i % 100 == 0:
        status=pathlib.Path(f'/proc/{frontend_pid}/status').read_text()
        rss=re.search(r'^VmRSS:\s+(\d+)\s+kB$',status,re.MULTILINE);assert rss,'frontend RSS unavailable'
        memory.append({'elapsed_seconds':time.perf_counter()-start,'rss_kib':int(rss[1])})
    q=dns.message.make_query(*queries[i%len(queries)],want_dnssec=True)
    begin=time.perf_counter_ns()
    try:dns.query.udp(q,'127.0.0.1',port=1053,timeout=2);latencies.append((time.perf_counter_ns()-begin)/1e6)
    except Exception:failures+=1
assert load.wait(timeout=10)==0;log.close();latencies.sort();output=(root/'dnsperf-dnssec-under-load.log').read_text()
metrics={}
for label,pattern in [('queries_sent',r'Queries sent:\s+(\d+)'),('queries_completed',r'Queries completed:\s+(\d+)'),('queries_lost',r'Queries lost:\s+(\d+)'),('completed_qps',r'Queries per second:\s+([0-9.]+)')]:
    m=re.search(pattern,output);assert m;metrics[label]=float(m[1]) if label=='completed_qps' else int(m[1])
result={'sampling':'3000 mixed DO=1 requests paced at 100/s during concurrent 1000-qps DO=1 dnsperf load','duration_seconds':time.perf_counter()-start,'start_unix_seconds':start_unix,'end_unix_seconds':time.time(),'frontend_memory':{'process':'BIND secondary','minimum_rss_kib':min(s['rss_kib'] for s in memory),'maximum_rss_kib':max(s['rss_kib'] for s in memory),'samples':memory},'samples':len(latencies),'failed_latency_samples':failures,'p50_ms':statistics.median(latencies),'p99_ms':latencies[int(len(latencies)*.99)-1],'max_ms':max(latencies),'concurrent_load':metrics,'dnsperf_log':'dnsperf-dnssec-under-load.log'}
(root/'performance-under-load.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
