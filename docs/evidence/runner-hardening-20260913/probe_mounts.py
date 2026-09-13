#!/usr/bin/env python3
"""Finite local Docker probe of the acceptance runner's actual mount generator."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
module_path = args.repository/'tests/rust-integration/run_ccf.py'
spec = importlib.util.spec_from_file_location('runner', module_path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
image = 'sha256:448109ffddaab856945aed9d1d121e6f302db57e7f50dba917c5ba20bcc65615'
name = 'agentdns-source-mount-probe-'+uuid.uuid4().hex[:12]
started = datetime.now(timezone.utc).isoformat()
probe = '''
import errno, json
from pathlib import Path
outcomes = {}
for name in ('/src/tests/rust-integration/run_ccf.py', '/work/source/tests/rust-integration/run_ccf.py'):
    try:
        with open(name, 'ab') as destination:
            destination.write(b'forbidden source mutation')
    except OSError as error:
        outcomes[name] = {'write_denied':True, 'errno':error.errno}
        assert error.errno == errno.EROFS, (name, error)
    else:
        raise AssertionError('source alias was writable: '+name)
Path('/work/control').mkdir()
for name in ('/work/control/probe.txt', '/work/results/probe.txt'):
    Path(name).write_text('expected writable fixture')
    outcomes[name] = {'write_succeeded':Path(name).read_text() == 'expected writable fixture'}
print(json.dumps(outcomes))
'''
with tempfile.TemporaryDirectory(prefix='agentdns-source-mount-probe-') as temporary:
    work = Path(temporary)
    source, results = work/'source', work/'results'
    results.mkdir()
    expected = runner.snapshot_sources(source)
    mounts = runner.helper_mounts(work, source, results, 'control')
    command = ['docker', 'run', '--rm', '--name', name, '--network', 'none',
        '--memory', '128m', '--cpus', '0.25', '--pids-limit', '32',
        *mounts, '--entrypoint', 'python3', image, '-c', probe]
    try:
        response = subprocess.run(command, timeout=30, check=True, text=True, capture_output=True)
        outcomes = json.loads(response.stdout)
        for path in (work/'control/probe.txt', results/'probe.txt'):
            assert path.read_text() == 'expected writable fixture'
        integrity = runner.finalize_source_integrity(source, expected, results)
        report = {'status':'passed', 'started_utc':started,
            'ended_utc':datetime.now(timezone.utc).isoformat(), 'image_id':image,
            'runner_sha256':hashlib.sha256(module_path.read_bytes()).hexdigest(),
            'generated_mount_arguments':mounts, 'actual_container_results':outcomes,
            'source_integrity':integrity, 'network':'none',
            'limits':{'deadline_seconds':30, 'memory':'128m', 'cpus':0.25, 'pids':32},
            'scope':'local mount behavior only; no CCF or native attestation claim'}
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
    finally:
        subprocess.run(['docker', 'rm', '--force', name], timeout=15, check=False, capture_output=True)
