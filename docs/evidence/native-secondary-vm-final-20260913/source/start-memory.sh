#!/bin/sh
set -eu
python3 - <<'AGENTDNS_PY'
import hashlib,json,pathlib,subprocess,time
root=pathlib.Path('/opt/agentdns-secondary');marker=root/'native-memory-session.json'
if marker.exists():raise RuntimeError('memory session already exists; preserve prior attempt')
container='agentdns-secondary';info=json.loads(subprocess.check_output(['docker','inspect',container],timeout=15))[0]
if not info['State']['Running']:raise RuntimeError('BIND not running')
code=root/'observe_native_bind.py';expected='6bb1803905af34968bd3c5cd489ba2275dda1ac575649bc5dc15790037fa461e'
if hashlib.sha256(code.read_bytes()).hexdigest()!=expected:raise RuntimeError('collector source changed')
subprocess.run(['docker','exec','-i',container,'python3','-c',"import pathlib,sys,hashlib; p=pathlib.Path('/tmp/observe_native_bind.py'); raw=sys.stdin.buffer.read(20000); assert len(raw)<20000; p.write_bytes(raw); p.chmod(0o600); assert hashlib.sha256(p.read_bytes()).hexdigest()=='6bb1803905af34968bd3c5cd489ba2275dda1ac575649bc5dc15790037fa461e'"],input=code.read_bytes(),check=True,timeout=15,capture_output=True)
path='/tmp/agentdns-native-memory'
subprocess.run(['docker','exec',container,'python3','-c',"import pathlib; assert not pathlib.Path('/tmp/agentdns-native-memory').exists(); assert not pathlib.Path('/tmp/agentdns-native-memory.exit').exists()"],check=True,timeout=15,capture_output=True)
start=time.time()
reservation={'status':'prepared','prepared_unix_seconds':start,'container_id':info['Id'],'observer_sha256':expected}
with marker.open('x') as stream:json.dump(reservation,stream)
command='umask 077; timeout --signal=TERM --kill-after=5s 1445s python3 /tmp/observe_native_bind.py --seconds 1380 --output /tmp/agentdns-native-memory > /tmp/agentdns-native-memory.log 2>&1; result=$?; printf "%s\n" "$result" > /tmp/agentdns-native-memory.exit'
try:
    subprocess.run(['docker','exec','-d',container,'sh','-c',command],check=True,timeout=15,capture_output=True)
except Exception:
    reservation['status']='dispatch_failed_or_uncertain_no_automatic_retry'
    marker.write_text(json.dumps(reservation))
    raise
result={'status':'launched','launched_unix_seconds':start,'container_id':info['Id'],'container_image_id':info['Image'],'host_pid_at_launch':info['State']['Pid'],'observer_sha256':expected,'pid_namespace':'BIND container; actual named PID1','output_directory':path,'scope':'1380 seconds/139 samples; /proc VmRSS+VmHWM KiB, separately cgroup-v2 aggregate bytes, collector CPU/RSS overhead; outer1445s +5s kill bound.'}
temporary=marker.with_suffix('.tmp');temporary.write_text(json.dumps(result));temporary.replace(marker)
print(json.dumps(result))
AGENTDNS_PY
