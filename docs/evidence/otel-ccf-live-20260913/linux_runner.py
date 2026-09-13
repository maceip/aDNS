import os,subprocess,sys,time,json
from pathlib import Path
out=Path('/out');started=time.time()
with (out/'install.log').open('w') as log:
 subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-cache-dir','--target','/tmp/otel','-r','/src/ccf/requirements-otel.txt'],stdout=log,stderr=log,check=True,timeout=150)
with (out/'supervisor-tests.log').open('w') as log:
 subprocess.run([sys.executable,'-m','unittest','discover','-s','/src/ccf/tests','-p','test_supervisor.py','-v'],stdout=log,stderr=log,check=True,timeout=30)
with (out/'live.log').open('w') as log:
 result=subprocess.run([sys.executable,'-u','/src/ccf/tests/live_telemetry.py','--output','/out/proof','--collector-url','http://127.0.0.1:4318/v1/traces'],stdout=log,stderr=log,timeout=300)
(out/'runtime.json').write_text(json.dumps({'started_unix_seconds':started,'ended_unix_seconds':time.time(),'exit_code':result.returncode,'python':sys.version},indent=2)+'\n')
print((out/'live.log').read_text(),flush=True)
sys.exit(result.returncode)
