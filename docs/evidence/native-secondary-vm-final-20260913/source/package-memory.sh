#!/bin/sh
set -eu
python3 - <<'AGENTDNS_PY'
import base64,hashlib,json,pathlib,subprocess,zlib
root=pathlib.Path('/opt/agentdns-secondary');name='agentdns-secondary'
marker=json.loads((root/'native-memory-session.json').read_text())
info=json.loads(subprocess.check_output(['docker','inspect',name],timeout=15))[0]
assert info['Id']==marker['container_id'] and info['State']['Pid']==marker['host_pid_at_launch'] and info['State']['Running']
script="""import json,pathlib; p=pathlib.Path('/tmp/agentdns-native-memory'); files={name:(p/name).read_text() for name in ['metadata.json','samples.json','results.json'] if (p/name).is_file()}; files['collector.log']=pathlib.Path('/tmp/agentdns-native-memory.log').read_text(); files['collector.exit']=pathlib.Path('/tmp/agentdns-native-memory.exit').read_text(); print(json.dumps(files))"""
raw=subprocess.check_output(['docker','exec',name,'python3','-c',script],timeout=20)
assert len(raw)<250000
files=json.loads(raw)
results=json.loads(files.get('results.json','{}'));samples=json.loads(files.get('samples.json','[]'))
collection_passed=files['collector.exit'].strip()=='0' and results.get('sample_count')==len(samples)==139 and results.get('requested_seconds')==1380
body=json.dumps({'collection_passed':collection_passed,'files':files,'launch':marker,'final_container':{'id':info['Id'],'image_id':info['Image'],'host_pid':info['State']['Pid'],'restart_count':info['RestartCount']}},sort_keys=True,separators=(',',':')).encode()
encoded=base64.b64encode(zlib.compress(body,9)).decode();assert len(encoded)<=90000
(root/'native-memory-bundle.b64').write_text(encoded)
manifest={'encoding':'zlib+standard-base64','raw_bytes':len(body),'raw_sha256':hashlib.sha256(body).hexdigest(),'base64_chars':len(encoded),'chunk_chars':2700,'chunks':(len(encoded)+2699)//2700,'chunk_sha256':[hashlib.sha256(encoded[i:i+2700].encode()).hexdigest() for i in range(0,len(encoded),2700)]}
(root/'native-memory-bundle-manifest.json').write_text(json.dumps(manifest))
print(json.dumps(manifest))
AGENTDNS_PY
