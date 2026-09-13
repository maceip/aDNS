#!/usr/bin/env python3
"""Run the real isolated BIND/Postfix acceptance suite on Docker-enabled macOS or Linux.

This starts only development MemoryStorage, never a production CCF service.
Private fixtures remain in the disposable output directory; publish only the
explicit public result/log allowlist documented in README.md.
"""
import argparse,hashlib,json,pathlib,platform,shutil,subprocess,tempfile,time,urllib.request

REPO=pathlib.Path(__file__).resolve().parents[2]
SUITE=pathlib.Path(__file__).resolve().parent

def checked(*args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(REPO/'target/debug/adns-dev'));p.add_argument('--seconds',type=int,default=1200);p.add_argument('--skip-build',action='store_true');a=p.parse_args()
    if a.seconds<1200:p.error('real idle acceptance requires at least 1200 seconds')
    if not a.skip_build:checked('cargo','build','-p','adns-server','--bin','adns-dev',cwd=REPO)
    checked('docker','build','-f',str(REPO/'containers/validation.Dockerfile'),'-t','agentdns-validation:local',str(REPO))
    checked('docker','build','-f',str(SUITE/'Dockerfile'),'-t','agentdns-mail-validation:local',str(SUITE))
    parent=REPO/'.validation/integration';parent.mkdir(parents=True,exist_ok=True)
    root=pathlib.Path(tempfile.mkdtemp(prefix='run-',dir=parent));name='agentdns-acceptance-'+root.name.removeprefix('run-')
    run_binary=root/'adns-dev-run'
    shutil.copy2(pathlib.Path(a.binary).resolve(),run_binary)
    (root/'runtime-build.json').write_text(json.dumps({'binary_sha256':hashlib.sha256(run_binary.read_bytes()).hexdigest(),'snapshot_binary':str(run_binary),'backend':'development-memory'},indent=2)+'\n')
    checked('python3',str(SUITE/'prepare.py'),str(run_binary),str(root))
    runtime=None;monitors=[];started_container=False
    try:
        with open(root/'runtime.log','ab',buffering=0) as log:
            runtime=subprocess.Popen([str(run_binary),str(root/'config.json')],stdout=log,stderr=log)
        for _ in range(100):
            if runtime.poll() is not None:raise RuntimeError('runtime failed: '+(root/'runtime.log').read_text())
            try:urllib.request.urlopen('http://127.0.0.1:18080/zone/status?zone=example.test.',timeout=1);break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('runtime did not become ready')
        host_gateway=['--add-host','host.docker.internal:host-gateway'] if platform.system()=='Linux' else []
        checked('docker','run','-d',*host_gateway,'--name',name,'--publish','127.0.0.1:1053:1053/tcp','--publish','127.0.0.1:1053:1053/udp','--volume',str(root)+':/work','--volume',str(SUITE)+':/suite:ro','agentdns-mail-validation:local','python3','/suite/inside-start.py')
        started_container=True
        checked('docker','exec',name,'python3','/suite/verify_initial.py')
        with open(root/'idle-monitor.log','ab',buffering=0) as log:
            monitors.append(subprocess.Popen(['python3',str(SUITE/'monitor_idle.py'),str(root),'--seconds',str(a.seconds)],stdout=log,stderr=log))
        for _ in range(50):
            if (root/'idle-samples.json').exists():break
            time.sleep(.1)
        with open(root/'frontend-monitor.log','ab',buffering=0) as log:
            monitors.append(subprocess.Popen(['docker','exec',name,'python3','/suite/monitor_frontend.py','--seconds',str(a.seconds+20)],stdout=log,stderr=log))
        checked('docker','exec',name,'python3','/suite/verify_ixfr.py')
        checked('docker','exec',name,'python3','/suite/verify_mail.py')
        checked('docker','exec',name,'python3','/suite/benchmark.py')
        checked('docker','exec',name,'python3','/suite/latency_under_load.py')
        while any(p.poll() is None for p in monitors):
            if runtime.poll() is not None:raise RuntimeError('runtime exited during idle acceptance')
            for process in monitors:
                if process.poll() not in (None,0):raise RuntimeError('monitor failed; inspect '+str(root))
            sample=json.loads((root/'idle-samples.json').read_text())[-1]
            print(json.dumps({'output':str(root),'elapsed_seconds':sample['elapsed_seconds'],'serial':sample['serial'],'health':sample['health']}),flush=True)
            time.sleep(30)
        for process in monitors:
            if process.wait()!=0:raise RuntimeError('monitor failed')
        summary={name:json.loads((root/(name+'.json')).read_text()) for name in ['initial-results','ixfr-results','mail-results','performance-results','performance-under-load','idle-results','frontend-idle-results']}
        (root/'acceptance-results.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps({'status':'passed','backend':'development-memory','output':str(root)},indent=2))
    finally:
        for process in monitors:
            if process.poll() is None:process.terminate()
        if started_container:subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL)
        if runtime and runtime.poll() is None:
            runtime.terminate()
            try:runtime.wait(timeout=10)
            except subprocess.TimeoutExpired:runtime.kill();runtime.wait()
if __name__=='__main__':main()
