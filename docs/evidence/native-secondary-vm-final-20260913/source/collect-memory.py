#!/usr/bin/env python3
"""Fetch the explicit public measurement file set through bounded Run Command chunks."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import zlib

root=Path('.validation/azure/native-final-20260913/secondary-vm')
output=Path(tempfile.mkdtemp(prefix='memory-retrieval-',dir=root))
deadline=time.monotonic()+600
prefix=['az','vm','run-command','invoke','--subscription','1b191b4c-2968-420a-b275-5087e94bf355','--resource-group','agentdns-port-validation-20260913','--name','agentdns-secondary-vm','--command-id','RunShellScript']

def invoke(script,label):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('retrieval total deadline')
    r=subprocess.run(prefix+['--scripts','@'+str(script),'--only-show-errors','-o','json'],capture_output=True,timeout=min(120,remaining))
    (output/(label+'.response.json')).write_bytes(r.stdout)
    (output/(label+'.stderr.log')).write_bytes(r.stderr)
    if r.returncode:raise RuntimeError('Azure RunCommand request failed; preserve response')
    result=json.loads(r.stdout)
    values=result.get('value',[])
    if len(values)!=1 or values[0].get('code')!='ProvisioningState/succeeded':raise RuntimeError('unexpected extension status')
    message=values[0]['message']
    raw,stderr=message.split('[stdout]\n',1)[1].split('\n[stderr]',1)
    if stderr.strip():raise RuntimeError('remote script error despite extension status; preserve response')
    return json.loads(raw)

manifest=invoke(root/'management/package-memory.sh','manifest')
if not 1<=manifest['chunks']<=32 or manifest['chunk_chars']!=2700 or len(manifest['chunk_sha256'])!=manifest['chunks']:raise ValueError('chunk manifest bounds')
chunks=[]
for index in range(manifest['chunks']):
    script=output/('chunk-'+str(index)+'.sh')
    script.write_text("#!/bin/sh\nset -eu\npython3 - <<'PY_REMOTE'\nimport pathlib,json\np=pathlib.Path('/opt/agentdns-secondary/native-memory-bundle.b64')\ns=p.read_text(); assert len(s)<=90000\nprint(json.dumps({'index':"+str(index)+",'data':s["+str(index*2700)+":"+str((index+1)*2700)+"]}))\nPY_REMOTE\n")
    chunk=invoke(script,'chunk-'+str(index))
    value=chunk['data']
    if chunk['index']!=index or not 0<len(value)<=2700 or hashlib.sha256(value.encode()).hexdigest()!=manifest['chunk_sha256'][index]:raise ValueError('chunk integrity mismatch')
    chunks.append(value)
encoded=''.join(chunks)
if len(encoded)!=manifest['base64_chars']:raise ValueError('encoded size mismatch')
compressed=base64.b64decode(encoded,validate=True)
decoder=zlib.decompressobj();raw=decoder.decompress(compressed,250001)
if len(raw)>250000 or not decoder.eof or decoder.unused_data or len(raw)!=manifest['raw_bytes'] or hashlib.sha256(raw).hexdigest()!=manifest['raw_sha256']:raise ValueError('assembled integrity mismatch')
bundle=json.loads(raw)
files=bundle['files'];allowed={'metadata.json','samples.json','results.json','collector.log','collector.exit'}
if not set(files)<=allowed:raise ValueError('unexpected exported file')
for name,content in files.items():(output/name).write_text(content)
(output/'bundle.json').write_bytes(raw)
(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'directory':str(output),'collection_passed':bundle['collection_passed'],'files':sorted(files),'raw_sha256':manifest['raw_sha256']}))
if not bundle['collection_passed']:raise SystemExit(1)
