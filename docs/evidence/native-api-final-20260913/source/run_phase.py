#!/usr/bin/env python3
"""Run one reviewed native acceptance phase and retain source-integrity evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/Users/mac/agentdns')
BASE = ROOT/'.validation/azure/native-final-20260913'
MANIFEST = BASE/'root-flow-source-v3/manifest.json'
EXPECTED_MANIFEST = '1c74a1d625a9c6305ef8f74a63a538356184730b2b04b6290f54503d33682363'

def inspect():
    data = MANIFEST.read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_MANIFEST
    report = {}
    for name, expected in json.loads(data)['files'].items():
        content = (ROOT/name).read_bytes()
        actual = {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}
        report[name] = {'expected': expected, 'actual': actual, 'matches': actual == expected}
    return {'status': 'passed' if all(x['matches'] for x in report.values()) else 'failed',
            'manifest_sha256': EXPECTED_MANIFEST, 'files': report}

def save(path, value):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')

def main():
    os.umask(0o077)
    args = sys.argv[1:]
    if args == ['--check']:
        result = inspect(); print(json.dumps(result)); return 0 if result['status']=='passed' else 1
    flags = [arg for arg in args if arg.startswith('--')]
    assert len(flags)==len(set(flags)) and all('=' not in flag for flag in flags)
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--worker', choices=['a','b'], required=True)
    parser.add_argument('--mode', choices=['register','lifecycle','conflict'], required=True)
    parser.add_argument('--scope-negatives', action='store_true')
    parser.add_argument('--body', type=Path)
    parser.add_argument('--original-result', type=Path)
    parser.add_argument('--original-envelope', type=Path)
    parsed = parser.parse_args(args)
    assert not parsed.scope_negatives or parsed.mode=='register'
    assert bool(parsed.body)==(parsed.mode=='lifecycle')
    assert bool(parsed.original_result)==bool(parsed.original_envelope)==(parsed.mode=='conflict')
    output = parsed.out.resolve()
    assert output.is_relative_to(BASE) and not output.exists()
    audit = output.with_name(output.name+'-runner.json')
    assert not audit.exists()
    report = {'before': inspect(), 'started_unix_seconds': time.time(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'context_sha256': hashlib.sha256((BASE/'context.json').read_bytes()).hexdigest()}
    save(audit, report)
    assert report['before']['status'] == 'passed'
    command = [sys.executable, str(BASE/'native_flow.py'), '--context', str(BASE/'context.json'),
               '--out', str(output), '--worker', parsed.worker, '--mode', parsed.mode]
    if parsed.scope_negatives: command.append('--scope-negatives')
    for flag, value in [('body',parsed.body), ('original-result',parsed.original_result), ('original-envelope',parsed.original_envelope)]:
        if value: command.extend(['--'+flag, str(value.resolve())])
    report['command'] = command
    try:
        with output.with_name(output.name+'-stdout.log').open('xb') as stdout, output.with_name(output.name+'-stderr.log').open('xb') as stderr:
            process = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=480)
        report['returncode'] = process.returncode
    except Exception as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error)}
        report['returncode'] = 1
    finally:
        report['ended_unix_seconds'] = time.time()
        try:
            report['after'] = inspect()
        except Exception as error:
            report['after'] = {'status':'failed','exception_type':type(error).__name__,'message':str(error)}
        report['status'] = 'failed'
        save(audit, report)
    if report['returncode']==0 and report['after']['status']=='passed':
        try:
            result = json.loads((output/'summary.json').read_text())
            assert result['status']=='passed'
            context_path = BASE/'context.json'
            assert hashlib.sha256(context_path.read_bytes()).hexdigest()==report['context_sha256']
            if result['operation']=='registration':
                context = json.loads(context_path.read_text())
                assert 'registration_id' not in context['workers'][parsed.worker]
                context['workers'][parsed.worker]['registration_id'] = result['registration_id']
                save(context_path, context)
            report['status'] = 'passed'
            report['completed_unix_seconds'] = time.time()
            save(audit, report)
            print(json.dumps(result), flush=True)
            return 0
        except Exception as error:
            report['completion_exception'] = {'type':type(error).__name__,'message':str(error)}
            report['status'] = 'failed'
            save(audit, report)
    print(json.dumps({'status': 'failed', 'retained_evidence': str(output), 'runner': str(audit)}), flush=True)
    return 1

if __name__=='__main__':
    raise SystemExit(main())
