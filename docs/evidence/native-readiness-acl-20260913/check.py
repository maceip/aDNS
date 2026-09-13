"""Public-only local regression: exact CCF ELF/supervisor with explicit Virtual shim."""
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

spec=importlib.util.spec_from_file_location('production_supervisor','/opt/agentdns/run.py')
supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
mode=sys.argv[1]
config=json.loads(Path('/input/node.json').read_bytes())
expected=503 if mode=='old' else 200
manifest=hashlib.sha256(Path('/input/manifest.json').read_bytes()).hexdigest()
exact_hash=hashlib.sha256(Path('/exact/agentdns').read_bytes()).hexdigest()
assert exact_hash=='6bcbf0a885cabdbea18ea3a25e0a3c56a49deaf1cf97e100ec97ff069ada8683'
started=time.time();log=Path('/out/supervisor.log').open('wb')
process=subprocess.Popen(['python3','/opt/agentdns/run.py','--config','/input/node.json','--state-dir','/state','--config-manifest','/input/manifest.json','--config-manifest-sha256',manifest],stdout=log,stderr=subprocess.STDOUT)
result=None
try:
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  if process.poll() is not None:raise RuntimeError('supervisor exited before readiness')
  try:
   status,headers,body=supervisor.bounded_http('127.0.0.1:8000',Path('/state/service_cert.pem'),'GET','/node/state',timeout=1)
   if status==200:break
  except (OSError,http.client.HTTPException,RuntimeError):pass
  time.sleep(.1)
 else:raise TimeoutError('public node readiness missing')
 internal_status,internal_headers,internal_body=supervisor.bounded_http('127.0.0.1:8001',Path('/state/service_cert.pem'),'GET','/node/state',timeout=2)
 assert internal_status==expected,(internal_status,internal_body)
 other_status,other_headers,other_body=supervisor.bounded_http('127.0.0.1:8001',Path('/state/service_cert.pem'),'GET','/node/network',timeout=2)
 assert other_status==503,(other_status,other_body)
 def driver_pids():
  found=[]
  for item in Path('/proc').iterdir():
   if item.name.isdecimal():
    try:args=(item/'cmdline').read_bytes().split(b'\0')
    except FileNotFoundError:continue
    if b'/opt/agentdns/host_driver.py' in args:found.append(int(item.name))
  return sorted(found)
 end=time.monotonic()+3
 observed=[]
 while time.monotonic()<end:
  pids=driver_pids();observed.append({'unix_seconds':time.time(),'driver_present':bool(pids)})
  if mode=='old':assert not pids,'denying ACL unexpectedly started driver'
  elif pids:break
  time.sleep(.1)
 assert bool(driver_pids())==(mode=='new'),'driver presence differs from readiness condition'
 result={'status':'passed','case':mode,'platform':'Virtual via test-only launcher shim; no hardware claim','exact_elf_sha256':exact_hash,
  'packaged_supervisor_sha256':hashlib.sha256(Path('/opt/agentdns/run.py').read_bytes()).hexdigest(),
  'accepted_endpoints':config['network']['rpc_interfaces']['agentdns-internal']['accepted_endpoints'],
  'public_node_state':{'status':status,'body':json.loads(body)},
  'internal_node_state':{'status':internal_status,'raw_body_utf8':internal_body.decode('utf-8')},
  'internal_node_network_remains_denied':{'status':other_status,'raw_body_utf8':other_body.decode('utf-8')},
  'driver_observations':observed,'driver_present':bool(driver_pids()),'started_unix_seconds':started,
  'test_shim_sha256':hashlib.sha256(Path('/usr/local/bin/agentdns').read_bytes()).hexdigest(),
  'config_manifest_sha256':manifest,'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
finally:
 process.terminate()
 try:process.wait(timeout=20)
 except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
 log.close()
if result is not None:
 result['wrapper_terminated']=process.poll() is not None;result['ended_unix_seconds']=time.time()
 Path('/out/results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
