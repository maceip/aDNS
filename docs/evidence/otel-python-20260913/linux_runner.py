import json,platform,subprocess,sys,time
from pathlib import Path
out=Path('/out')
started=time.time()
with (out/'install.log').open('w') as log:
 subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-cache-dir','--target','/tmp/otel','-r','/src/ccf/requirements-otel.txt'],stdout=log,stderr=log,check=True,timeout=150)
with (out/'tests.log').open('w') as log:
 test=subprocess.run([sys.executable,'-B','-m','unittest','ccf.test_host_driver','ccf.test_telemetry','-v'],cwd='/src',stdout=log,stderr=log,timeout=30)
versions=subprocess.run([sys.executable,'-m','pip','list','--path','/tmp/otel','--format=json'],capture_output=True,text=True,check=True,timeout=10)
result={'status':'passed'if test.returncode==0 else'failed','python':sys.version,'platform':platform.platform(),'started_unix_seconds':started,'ended_unix_seconds':time.time(),'test_exit_code':test.returncode,'packages':json.loads(versions.stdout)}
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2),flush=True)
sys.exit(test.returncode)
