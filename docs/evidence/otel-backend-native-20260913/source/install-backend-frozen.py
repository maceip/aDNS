"""Bounded isolated backend installer; runtime material only from protected env."""
import base64, hashlib, json, os, pathlib, shutil, subprocess, sys, time
ROOT=pathlib.Path('/opt/agentdns-observability')
STATE=pathlib.Path('/var/lib/agentdns-observability')
PROJECT='agentdns-otel-native-validation'
PUBLIC_HASHES = {'compose.yaml': '656a58da7a39802c37dc4a7b75b70a75120b89a1c0d8b175e05083b8d25c0fe0', 'compose.native-https.yaml': '8d8a176c33f6fb360861880e1d7a43da99157db295ebc8dda96b88ec523c4934', 'otel-collector.yaml': 'f81f8d93ae7e16cfe058f654a831008ce52dccaaf3c8c18f81010143b3d6d501', 'otel-native-https.yaml': '1327306db85c33ea1485645aaf728bf1c5ddd91cf1d6c65cca7997e68ad83506', 'tempo.yaml': 'cc49dd21ca2082b5bcfc41ef3984dd43034931d445bcbc0e1ff3f59e310e3f58', 'loki.yaml': '9885792171a9923ab9380ae0c642fb5a7edb33f6519659f140e12c060d9ffcd4', 'grafana-datasources.yaml': '39c34406fbc9f4b195a575605dd9edc5dc1a360872d5af4b715b26f45eb2d1fe', 'grafana-dashboards.yaml': '26294864b983545db186935dbe4f3427745f08c463ae6a2296014dcaf8802091', 'dashboards/architecture.json': 'a9ca7ae4ef18261046b49ab14fc1abc9ce6d4f5ab752f2c36429b9ff9c876ee1', 'compose.vm.yaml': '01dc23ffd3a51fc2300632631c300f0391ff29a1865b094e4c2fdb0f9bb2f2b8', 'runtime-paths.env': '180ad3e38d5614297cdcb19ccb8999845ef316767c0b4f845abf899d4e3fb22d', 'preflight.sh': '8d476bd913ad3d6b545136244065473341456ec89fc36108b5af22393d1419f3', 'verify-backend.py': '3786d244a6f111dd47aebec90e2a282fb525558373c82b45bd3e9370720b77c5', 'exporter-public-ca.pem': 'f6e2a3e66a985d78c5bb912f81e02d59c78923d73f639308405e33d4bc71f524'}
PRIVATE_FILES={'collector/server.pem':(10001,0o600),'collector/server-key.pem':(10001,0o600),'collector/htpasswd':(10001,0o600),'grafana-password':(472,0o600)}
IMAGES={'otel-collector': 'otel/opentelemetry-collector-contrib@sha256:5b66b0dc6921f2a439cf50b942ccb9e2a4375f136239a9fdf709ef33e4bfc668', 'tempo': 'grafana/tempo@sha256:05321ebf1f191fde34282b3dc86e68f511d489133df7963cd1670a2e1e11b33c', 'loki': 'grafana/loki@sha256:550d599ec4efacd8ebc0a5871766855057cba2bd0c669c0711d898c00d6d901f', 'grafana': 'grafana/grafana@sha256:1dec240d14e232597dce9bfa56dae55f4397b138cdc91e3ee92ac6b157e2fc49'}
def sha(data): return hashlib.sha256(data).hexdigest()
def run(args,label,timeout=30):
    with (STATE/'evidence'/f'{label}.stdout').open('wb') as out,(STATE/'evidence'/f'{label}.stderr').open('wb') as err:
        result=subprocess.run(args,stdout=out,stderr=err,timeout=timeout,env={k:v for k,v in os.environ.items() if k!='AGENTDNS_OTEL_PAYLOAD'})
    if result.returncode: raise RuntimeError(f'{label}: exit {result.returncode}')
    return (STATE/'evidence'/f'{label}.stdout').read_bytes()
def main():
    os.umask(0o077)
    encoded=os.environ.pop('AGENTDNS_OTEL_PAYLOAD')
    if len(encoded)>262144: raise RuntimeError('protected payload bound')
    payload=json.loads(base64.b64decode(encoded,validate=True)); del encoded
    if set(payload)!={'version','public','private','smoke_authorization'} or payload['version']!=1: raise RuntimeError('payload schema')
    if set(payload['public'])!=set(PUBLIC_HASHES) or set(payload['private'])!=set(PRIVATE_FILES): raise RuntimeError('file inventory')
    public={k:base64.b64decode(v,validate=True) for k,v in payload['public'].items()}
    private={k:base64.b64decode(v,validate=True) for k,v in payload['private'].items()}
    if any(len(v)>65536 or sha(v)!=PUBLIC_HASHES[k] for k,v in public.items()): raise RuntimeError('public input integrity')
    if any(not 1<=len(v)<=16384 for v in private.values()): raise RuntimeError('private input size')
    auth=payload['smoke_authorization']
    import re
    if not isinstance(auth,str) or not re.fullmatch(r'Basic [A-Za-z0-9+/]{76}',auth): raise RuntimeError('authorization shape')
    if ROOT.exists() or STATE.exists(): raise RuntimeError('installation path already exists; inspect and do not repeat')
    STATE.mkdir(mode=0o700); (STATE/'evidence').mkdir(mode=0o700)
    marker=STATE/'deployment-state.json'
    with marker.open('x') as f: json.dump({'status':'prepared','started_unix':time.time(),'project':PROJECT},f)
    try:
        before=run(['sh','-c',public['preflight.sh'].decode()],'bind-before',30)
        before=json.loads(before); assert before['status']=='passed'
        if not shutil.which('curl'): raise RuntimeError('curl missing; no system package mutation permitted')
        ROOT.mkdir(mode=0o755);ROOT.chmod(0o755)
        for name,data in public.items():
            target=ROOT/name
            target.parent.mkdir(mode=0o755,parents=True,exist_ok=True);target.parent.chmod(0o755)
            with target.open('xb') as f: f.write(data)
            target.chmod(0o644)
        priv=STATE/'private';priv.mkdir(mode=0o700)
        collector=priv/'collector';collector.mkdir(mode=0o700);os.chown(collector,10001,10001)
        for name,data in private.items():
            target=priv/name
            with target.open('xb') as f: f.write(data)
            uid,mode=PRIVATE_FILES[name];os.chown(target,uid,uid);target.chmod(mode)
        del private,payload
        binary=ROOT/'docker-compose'
        run(['curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--tlsv1.2','--max-time','120','--max-filesize','32357318','--output',str(binary),'https://github.com/docker/compose/releases/download/v5.1.2/docker-compose-linux-x86_64'],'download-compose',130)
        if binary.stat().st_size!=32357318 or sha(binary.read_bytes())!='c372e512a36e67716b0b3a1264ccdc461dec7a7beff601b81f7c5fb008e3511e': raise RuntimeError('official compose binary integrity')
        binary.chmod(0o755)
        compose=[str(binary),'--project-directory',str(ROOT),'--env-file',str(ROOT/'runtime-paths.env'),'-p',PROJECT,'-f',str(ROOT/'compose.yaml'),'-f',str(ROOT/'compose.native-https.yaml'),'-f',str(ROOT/'compose.vm.yaml')]
        version=run([str(binary),'version','--short'],'compose-version').decode().strip();assert version=='5.1.2'
        config=json.loads(run(compose+['config','--format','json'],'compose-config'))
        assert config['name']==PROJECT and set(config['services'])==set(IMAGES)
        expected_ports={'otel-collector':[('10.71.0.4',4318,8443)],'tempo':[('127.0.0.1',13200,3200)],'loki':[],'grafana':[('127.0.0.1',13000,3000)]}
        for name,s in config['services'].items():
            assert s['image']==IMAGES[name] and s['platform']=='linux/amd64' and float(s['cpus'])==0.25 and s['pids_limit']==128
            ports=[(p['host_ip'],int(p['published']),p['target']) for p in s.get('ports',[])];assert ports==expected_ports[name]
        run(compose+['pull'],'ordinary-pull',480)
        run(compose+['up','-d','--no-build'],'start-project',90)
        for name in IMAGES:
            raw=run(['docker','inspect',f'{PROJECT}-{name}-1'],f'inspect-{name}')
            v=json.loads(raw)[0];assert v['Config']['Image']==IMAGES[name]
            assert v['HostConfig']['NanoCpus']==250000000 and v['HostConfig']['PidsLimit']==128
        smoke_env=dict(os.environ);smoke_env['AGENTDNS_SMOKE_AUTHORIZATION']=auth;del auth
        with (STATE/'evidence'/'smoke.stdout').open('wb') as out,(STATE/'evidence'/'smoke.stderr').open('wb') as err:
            result=subprocess.run(['python3',str(ROOT/'verify-backend.py')],env=smoke_env,stdout=out,stderr=err,timeout=160)
        smoke_env.pop('AGENTDNS_SMOKE_AUTHORIZATION',None)
        if result.returncode: raise RuntimeError('backend smoke failed; inspect private logs, do not redeploy blindly')
        result=json.loads((STATE/'evidence'/'smoke.stdout').read_bytes());assert result['status']=='passed'
        result.update({'compose_version':version,'compose_sha256':sha(binary.read_bytes()),'source_sha256':PUBLIC_HASHES,'bind_before':before,'project':PROJECT,'finished_unix':time.time()})
        (STATE/'evidence'/'deployment-result.json').write_text(json.dumps(result,indent=2)+'\n')
        marker.write_text(json.dumps({'status':'passed','finished_unix':time.time(),'project':PROJECT}))
        print(json.dumps({'status':'passed','project':PROJECT,'result_path':str(STATE/'evidence'/'deployment-result.json'),'finished_unix':time.time(),'trace_id':result['trace_id'],'bind_pid':result['bind_after']['bind_pid'],'bind_restart_count':result['bind_after']['bind_restart_count'],'tls':result['tls'],'images':IMAGES}))
    except BaseException as exc:
        marker.write_text(json.dumps({'status':'failed','finished_unix':time.time(),'error_type':type(exc).__name__,'project':PROJECT}))
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,'project':PROJECT,'logs':str(STATE/'evidence')}))
        raise
if __name__=='__main__': main()
