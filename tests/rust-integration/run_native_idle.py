#!/usr/bin/env python3
"""Finite external Azure DNSSEC/load window; no control credentials or mutations.

Run only after admissions and an explicit mutation-free window are confirmed.
Public CCF status uses its authenticated service certificate and fixed DNS SNI.
"""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import CCF_RPC_HOSTNAME, CCF_RPC_URL
from domain_registry import registry_path
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

REPOSITORY = Path(__file__).resolve().parents[2]
VALIDATOR = 'sha256:448109ffddaab856945aed9d1d121e6f302db57e7f50dba917c5ba20bcc65615'
FILES = ('tests/rust-integration/run_native_idle.py','tests/rust-integration/run_ccf.py',
    'tests/rust-integration/export_ccf_results.py',
    'tests/rust-integration/monitor_remote.py','tests/rust-integration/benchmark_remote.py',
    'ccf/tests/observe_status.py','tools/http_limits.py',
    'tools/domain_registry.py','tools/validation_names.py')


def load_frozen_guard(source):
    """Resolve the guard's direct dependency from this snapshot, even if cached."""
    missing = object()
    previous = sys.modules.get('export_ccf_results', missing)
    try:
        exporter_spec = importlib.util.spec_from_file_location('export_ccf_results',
            source/'tests/rust-integration/export_ccf_results.py')
        exporter = importlib.util.module_from_spec(exporter_spec)
        exporter_spec.loader.exec_module(exporter)
        sys.modules['export_ccf_results'] = exporter
        spec = importlib.util.spec_from_file_location('frozen_runner',
            source/'tests/rust-integration/run_ccf.py')
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        return guard
    finally:
        if previous is missing:
            sys.modules.pop('export_ccf_results', None)
        else:
            sys.modules['export_ccf_results'] = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--primary',type=ipaddress.IPv4Address,required=True)
    parser.add_argument('--secondary',type=ipaddress.IPv4Address,required=True)
    parser.add_argument('--service-cert',type=Path,required=True)
    parser.add_argument('--anchor',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True,exist_ok=False)
    source, public, results = (args.output/name for name in ('source','public','results'))
    source.mkdir();public.mkdir();results.mkdir()
    hashes = {}
    for name in FILES:
        data = (REPOSITORY/name).read_bytes()
        destination = source/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(data);destination.chmod(0o444)
        hashes[name] = hashlib.sha256(data).hexdigest()
    registry = registry_path().read_bytes()
    registry_file = source/'.domain-registry/topology.json'
    registry_file.parent.mkdir()
    registry_file.write_bytes(registry)
    registry_file.chmod(0o444)
    hashes['.domain-registry/topology.json'] = hashlib.sha256(registry).hexdigest()
    public_hashes = {}
    for name,path in [('service_cert.pem',args.service_cert),('trust-anchor.conf',args.anchor)]:
        with path.open('rb') as stream:
            data = stream.read(1024*1024+1)
        if len(data)>1024*1024 or b'PRIVATE KEY' in data:
            raise ValueError('public input exceeds bounds or contains a private-key marker')
        (public/name).write_bytes(data)
        public_hashes[name] = hashlib.sha256(data).hexdigest()
    # Disable host bytecode creation before importing the frozen inventory guard.
    sys.dont_write_bytecode = True
    guard = load_frozen_guard(source)
    stem = 'agentdns-native-observer-'+uuid.uuid4().hex[:12]
    started, started_unix = time.monotonic(),time.time()
    provenance = {'kind':'external native deployment observation; hardware evidence supplied separately',
        'validator_image':VALIDATOR,'primary':str(args.primary),'secondary':str(args.secondary),
        'started_unix_seconds':started_unix,'frozen_source_files_sha256':hashes,'public_input_sha256':public_hashes,
        'observation_seconds':1250,'fixed_load_seconds':1200,'fixed_offered_qps':1000,
        'sample_target_qps':10,'container_network':'ordinary Docker bridge; external public IPv4',
        'private_credentials_mounted':False,'zone_mutations':False}
    (results/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    children = []
    summary = {'status':'failed'}
    def interrupted(*_):
        raise KeyboardInterrupt('native observation interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:
        jobs = [
            ('status',['/src/ccf/tests/observe_status.py','--url',(CCF_RPC_URL),
                '--service-cert','/public/service_cert.pem','--seconds','1250','--output','/results']),
            ('dnssec',['/src/tests/rust-integration/monitor_remote.py','--server',str(args.secondary),
                '--port','53','--anchor','/public/trust-anchor.conf','--seconds','1250','--output','/results']),
            ('load',['/src/tests/rust-integration/benchmark_remote.py','--server',str(args.secondary),
                '--port','53','--seconds','1200','--qps','1000','--samples-per-second','10','--output','/results'])]
        for label,command in jobs:
            directory = results/label;directory.mkdir()
            name = stem+'-'+label
            log = (results/(label+'.log')).open('wb')
            args_run = ['docker','run','--rm','--name',name,
                '-e','AH_DOMAIN_REGISTRY=/src/.domain-registry/topology.json','--add-host',(CCF_RPC_HOSTNAME + ':')+str(args.primary),
                '-v',str(source)+':/src:ro','-v',str(public)+':/public:ro','-v',str(directory)+':/results',
                '--entrypoint','python3',VALIDATOR,*command]
            process = subprocess.Popen(args_run,stdout=log,stderr=log)
            children.append((name,process,log))
        next_progress = 0
        while any(process.poll() is None for _,process,_ in children):
            elapsed = time.monotonic()-started
            if elapsed > 1430:
                raise TimeoutError('external observation exceeded1250+180 second bound')
            if any(process.poll() not in (None,0) for _,process,_ in children):
                raise RuntimeError('one external observer failed; retain all logs')
            if elapsed >= next_progress:
                print(json.dumps({'elapsed_seconds':elapsed,'running':[name for name,process,_ in children if process.poll() is None]}),flush=True)
                next_progress = elapsed+30
            time.sleep(1)
        if any(process.returncode != 0 for _,process,_ in children):
            raise RuntimeError('external observer failed')
        summary = {'status':'passed','started_unix_seconds':started_unix,'ended_unix_seconds':time.time(),
            'status_observation':json.loads((results/'status/status-results.json').read_text()),
            'dnssec_observation':json.loads((results/'dnssec/remote-idle-results.json').read_text()),
            'fixed_load':json.loads((results/'load/results.json').read_text()),
            'metrics_boundary':'Frontend WAN timing includes network and client overhead. Azure resource memory and signing spans are collected separately; no RSS or signing duration is inferred here.'}
    finally:
        cleanup = []
        for name,process,log in children:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
                removed = subprocess.run(['docker','rm','--force',name],timeout=30,capture_output=True)
                if removed.returncode and b'No such container' not in removed.stderr:
                    cleanup.append({'container':name,'error':'cleanup returned nonzero'})
            except Exception as error:
                cleanup.append({'container':name,'error_type':type(error).__name__})
            finally:
                log.close()
        summary['cleanup_failures'] = cleanup
        if cleanup:
            summary['status'] = 'failed'
        public_reports = results/'public-input-integrity';public_reports.mkdir()
        public_failure = False
        try:
            public_report = guard.finalize_source_integrity(public,public_hashes,public_reports)
        except ValueError:
            public_failure = True
            public_report = json.loads((public_reports/'source-integrity.json').read_text())
            summary['status'] = 'failed'
            summary['failure_reason'] = 'public certificate/anchor integrity mismatch'
        summary['public_input_integrity'] = public_report
        provenance['post_execution_public_input_integrity'] = public_report
        guard.finalize_source_integrity(source,hashes,results,provenance,summary)
        if public_failure:
            raise ValueError('public certificate/anchor changed during native observation')
        if cleanup:
            raise RuntimeError('observer cleanup failed')
    print(json.dumps(summary,indent=2),flush=True)


if __name__ == '__main__':
    main()
