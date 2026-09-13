#!/usr/bin/env python3
"""Observe real idle refresh across 1200 elapsed seconds without mutations."""
import argparse,json,pathlib,time,urllib.request,subprocess
p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--seconds',type=int,default=1200);a=p.parse_args();root=pathlib.Path(a.directory)
first=json.loads(urllib.request.urlopen('http://127.0.0.1:18080/zone/status?zone=example.test.',timeout=5).read())
samples=json.loads((root/'idle-samples.json').read_text()) if (root/'idle-samples.json').exists() else []
start=samples[0]['unix_seconds']-samples[0]['elapsed_seconds'] if samples else first['committed_state']['rrsig_inception']+300
last_serial=None;refresh_due_since=None
while True:
    now=int(time.time());status=json.loads(urllib.request.urlopen('http://127.0.0.1:18080/zone/status?zone=example.test.',timeout=5).read())
    pid=int(subprocess.check_output(['lsof','-tiTCP:18080','-sTCP:LISTEN']).decode().split()[0])
    rss=int(subprocess.check_output(['ps','-o','rss=','-p',str(pid)]).decode().strip())
    state=status['committed_state'];sample={'unix_seconds':now,'elapsed_seconds':now-start,'serial':state['serial'],'earliest_rrsig_expiration':state['earliest_rrsig_expiration'],'health':state['maintenance_health'],'rss_kib':rss,'runtime_pid':pid,'secondaries':status['frontend_propagation']['secondaries']}
    samples.append(sample);(root/'idle-samples.json.tmp').write_text(json.dumps(samples,indent=2)+'\n');(root/'idle-samples.json.tmp').replace(root/'idle-samples.json')
    assert state['earliest_rrsig_expiration']>now,'expired authoritative snapshot'
    assert state['maintenance_health'] in ('ok','refresh_due'),'maintenance unhealthy'
    if state['maintenance_health']=='refresh_due':
        if refresh_due_since is None:refresh_due_since=now
        assert now-refresh_due_since<15,'refresh remained due beyond bounded timer grace'
    else:refresh_due_since=None
    if state['serial']!=last_serial:print(json.dumps(sample),flush=True);last_serial=state['serial']
    if now-start>=a.seconds:break
    time.sleep(10)
serials=sorted({s['serial'] for s in samples})
assert len(serials)>=4,'need repeated real refresh commits'
assert samples[-1]['unix_seconds']>samples[0]['earliest_rrsig_expiration'],'must cross initial signatures expiry'
assert any(s['secondaries'] and all(p['in_sync'] for p in s['secondaries']) and s['serial']==serials[-1] for s in samples),'latest serial must be externally observed'
result={'elapsed_seconds':samples[-1]['elapsed_seconds'],'observed_serials':serials,'samples':len(samples),'initial_signature_expiration':samples[0]['earliest_rrsig_expiration'],'final_time':samples[-1]['unix_seconds'],'final_signature_expiration':samples[-1]['earliest_rrsig_expiration'],'maximum_runtime_rss_kib':max(s['rss_kib'] for s in samples),'mutating_requests_during_window':0,'refresh_due_samples':sum(s['health']=='refresh_due' for s in samples),'development_backend':True}
(root/'idle-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
