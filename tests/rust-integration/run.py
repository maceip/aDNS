#!/usr/bin/env python3
"""Run the real isolated BIND/Postfix acceptance suite on Docker-enabled macOS or Linux.

This starts only development MemoryStorage, never a production CCF service.
Private fixtures remain in the disposable output directory; publish only the
explicit public result/log allowlist documented in README.md.
"""
import argparse,hashlib,json,pathlib,platform,shutil,subprocess,tempfile,time,urllib.request

REPO=pathlib.Path(__file__).resolve().parents[2]
SUITE=pathlib.Path(__file__).resolve().parent

def checked(*args,**kwargs):
    kwargs.setdefault('timeout',180)
    return subprocess.run(args,check=True,**kwargs)

def diagnostics(root,name):
    """Preserve child failure before removing the container; never inspect env."""
    try:
        result=subprocess.run(['docker','inspect','--format','{{json .State}}',name],capture_output=True,text=True,timeout=10)
        if result.returncode==0:
            state=json.loads(result.stdout)
            public={key:state.get(key) for key in ['Status','Running','OOMKilled','Dead','ExitCode','StartedAt','FinishedAt']}
            (root/'container-state.json').write_text(json.dumps(public,indent=2)+'\n')
        log=subprocess.run(['docker','logs','--tail','200',name],capture_output=True,timeout=10)
        for label,data in [('stdout',log.stdout),('stderr',log.stderr)]:
            path=root/('container-'+label+'.private.log');path.write_bytes(data[-1048576:]);path.chmod(0o600)
    except (OSError,ValueError,subprocess.TimeoutExpired) as error:
        (root/'diagnostics-error.json').write_text(json.dumps({'error_type':type(error).__name__})+'\n')

def wait_container(root,name,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        result=checked('docker','inspect','--format','{{json .State}}',name,capture_output=True,text=True,timeout=5)
        if not json.loads(result.stdout).get('Running'):
            raise RuntimeError('fixture container exited before readiness; inspect private diagnostics')
        if (root/'container-ready').exists():return
        time.sleep(.1)
    raise RuntimeError('fixture container readiness timed out')

class OwnedContainer:
    def __init__(self,root,name):
        self.root,self.name,self.attempted=root,name,False

    def start(self,*arguments):
        # A timed-out Docker CLI can leave a daemon-created container behind.
        self.attempted=True
        return checked('docker','run','--name',self.name,'--label','agentdns.acceptance.run='+self.root.name,*arguments)

def remove_container(root,name):
    try:
        result=subprocess.run(['docker','inspect','--format','{{json .Config.Labels}}',name],capture_output=True,text=True,timeout=10)
        if result.returncode:
            if any(result.stderr.strip().endswith(text+name) for text in ('No such object: ','No such container: ')):
                return True
            return False
        labels=json.loads(result.stdout)
        if not isinstance(labels,dict) or labels.get('agentdns.acceptance.run')!=root.name:
            return False # Never remove a same-name container owned by another run.
        subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=True)
        return True
    except (OSError,ValueError,subprocess.SubprocessError):return False

def cleanup(root,container,monitors,runtime):
    errors=[]
    def stop(process,label):
        try:
            if process.poll() is not None:return
            try:process.terminate()
            except OSError as error:errors.append(label+'.terminate:'+type(error).__name__)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        except (OSError,subprocess.SubprocessError) as error:errors.append(label+':'+type(error).__name__)
    for index,process in enumerate(monitors):stop(process,'monitor-'+str(index))
    if container.attempted:
        try:diagnostics(root,container.name)
        except (OSError,ValueError,subprocess.SubprocessError) as error:errors.append('diagnostics:'+type(error).__name__)
        if not remove_container(root,container.name):errors.append('container_remove_failed_or_ownership_unverified')
    if runtime is not None:stop(runtime,'runtime')
    if errors:
        try:(root/'cleanup-error.json').write_text(json.dumps({'errors':errors},indent=2)+'\n')
        except OSError:errors.append('cleanup_error_record_unwritable')
    return errors

def publish_success(root,summary,cleanup_errors):
    if cleanup_errors:
        (root/'failure.json').write_text(json.dumps({'status':'failed','phase':'cleanup','errors':cleanup_errors},indent=2)+'\n')
        raise RuntimeError('acceptance cleanup failed; inspect retained status')
    (root/'acceptance-results.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'status':'passed','backend':'development-memory','output':str(root)},indent=2))

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(REPO/'target/debug/adns-dev'));p.add_argument('--seconds',type=int,default=1200);p.add_argument('--skip-build',action='store_true');a=p.parse_args()
    if a.seconds<1200:p.error('real idle acceptance requires at least 1200 seconds')
    if not a.skip_build:checked('cargo','build','--locked','-p','adns-server','--bin','adns-dev',cwd=REPO,timeout=900)
    checked('docker','build','-f',str(REPO/'containers/validation.Dockerfile'),'-t','agentdns-validation:local',str(REPO),timeout=900)
    checked('docker','build','-f',str(SUITE/'Dockerfile'),'-t','agentdns-mail-validation:local',str(SUITE),timeout=900)
    parent=REPO/'.validation/integration';parent.mkdir(parents=True,exist_ok=True)
    root=pathlib.Path(tempfile.mkdtemp(prefix='run-',dir=parent));name='agentdns-acceptance-'+root.name.removeprefix('run-')
    run_binary=root/'adns-dev-run'
    shutil.copy2(pathlib.Path(a.binary).resolve(),run_binary)
    (root/'runtime-build.json').write_text(json.dumps({'binary_sha256':hashlib.sha256(run_binary.read_bytes()).hexdigest(),'snapshot_binary':str(run_binary),'backend':'development-memory'},indent=2)+'\n')
    checked('python3',str(SUITE/'prepare.py'),str(run_binary),str(root))
    runtime=None;monitors=[];container=OwnedContainer(root,name);phase='runtime-startup'
    try:
        with open(root/'runtime.log','ab',buffering=0) as log:
            runtime=subprocess.Popen([str(run_binary),str(root/'config.json')],stdout=log,stderr=log)
        for _ in range(100):
            if runtime.poll() is not None:raise RuntimeError('runtime failed: '+(root/'runtime.log').read_text())
            try:urllib.request.urlopen('http://127.0.0.1:18080/zone/status?zone=example.test.',timeout=1);break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('runtime did not become ready')
        host_gateway=['--add-host','host.docker.internal:host-gateway'] if platform.system()=='Linux' else []
        phase='container-startup'
        container.start('-d',*host_gateway,'--publish','127.0.0.1:1053:1053/tcp','--publish','127.0.0.1:1053:1053/udp','--volume',str(root)+':/work','--volume',str(SUITE)+':/suite:ro','agentdns-mail-validation:local','python3','/suite/inside-start.py')
        phase='fixture-readiness'
        wait_container(root,name)
        phase='initial-dnssec'
        checked('docker','exec',name,'python3','/suite/verify_initial.py')
        with open(root/'idle-monitor.log','ab',buffering=0) as log:
            monitors.append(subprocess.Popen(['python3',str(SUITE/'monitor_idle.py'),str(root),'--seconds',str(a.seconds)],stdout=log,stderr=log))
        for _ in range(50):
            if (root/'idle-samples.json').exists():break
            time.sleep(.1)
        with open(root/'frontend-monitor.log','ab',buffering=0) as log:
            monitors.append(subprocess.Popen(['docker','exec',name,'python3','/suite/monitor_frontend.py','--seconds',str(a.seconds+20)],stdout=log,stderr=log))
        phase='ixfr'
        checked('docker','exec',name,'python3','/suite/verify_ixfr.py')
        phase='mail'
        checked('docker','exec',name,'python3','/suite/verify_mail.py')
        phase='performance'
        checked('docker','exec',name,'python3','/suite/benchmark.py')
        checked('docker','exec',name,'python3','/suite/latency_under_load.py')
        phase='idle'
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
    except BaseException as error:
        (root/'failure.json').write_text(json.dumps({'status':'failed','phase':phase,'error_type':type(error).__name__,'returncode':getattr(error,'returncode',None)},indent=2)+'\n')
        raise
    finally:
        cleanup_errors=cleanup(root,container,monitors,runtime)
    # This is unreachable after an original test exception. Cleanup never
    # replaces that exception, and a successful test cannot hide cleanup failure.
    publish_success(root,summary,cleanup_errors)
if __name__=='__main__':main()
