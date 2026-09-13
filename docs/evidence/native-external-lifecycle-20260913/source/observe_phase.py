#!/usr/bin/env python3
"""Run only a root-authorized, read-only terminal lifecycle observation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
IMAGE = 'sha256:448109ffddaab856945aed9d1d121e6f302db57e7f50dba917c5ba20bcc65615'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=('a-port25-withdrawn','a-withdrawn','all-withdrawn'), required=True)
    parser.add_argument('--minimum-serial', type=int, required=True)
    parser.add_argument('--deadline-seconds', type=int, default=300)
    args = parser.parse_args()
    assert 0 <= args.minimum_serial < 2**32 and 5 <= args.deadline_seconds <= 600
    source = ROOT/'live-acceptance-source'
    expected_source = json.loads((ROOT/'live-acceptance-source-sha256.json').read_text())
    def verify_source():
        actual = {}
        for path in source.rglob('*'):
            assert not path.is_symlink()
            if path.is_file(): actual[str(path.relative_to(source))] = digest(path)
        assert actual == expected_source
        return actual
    before_source = verify_source()
    expected = ROOT/'expected'/(args.phase+'.json')
    anchor = ROOT/'dns-overlap-attempt1/verification/trust-anchor.conf'
    before = {'expected_sha256':digest(expected),'anchor_sha256':digest(anchor)}
    output = ROOT/(args.phase+'-attempt1');output.mkdir(exist_ok=False)
    container = 'agentdns-native-'+args.phase+'-'+str(int(time.time()))
    command = ['docker','run','--rm','--pull','never','--name',container,
        '--read-only','--cap-drop','ALL','--tmpfs','/tmp:rw,noexec,nosuid,size=8m',
        '-v',str(source)+':/src:ro',
        '-v',str(expected)+':/input/expected.json:ro',
        '-v',str(anchor)+':/input/trust-anchor.conf:ro',
        '-v',str(output)+':/out','--entrypoint','python3',IMAGE,'-B',
        '/src/tests/rust-integration/observe_native_state.py',
        '--server','20.166.33.141','--port','53','--anchor','/input/trust-anchor.conf',
        '--expected','/input/expected.json','--minimum-serial',str(args.minimum_serial),
        '--deadline-seconds',str(args.deadline_seconds),'--output','/out/verification']
    record = {'command':command, 'started_unix_seconds':time.time(), **before}
    (output/'invocation.json').write_text(json.dumps(record,indent=2)+'\n')
    code = None
    try:
        with (output/'stdout.log').open('wb') as stdout, (output/'stderr.log').open('wb') as stderr:
            result = subprocess.run(command,stdout=stdout,stderr=stderr,timeout=args.deadline_seconds+130)
        code = result.returncode
    finally:
        cleanup = subprocess.run(['docker','rm','--force',container],capture_output=True,timeout=30)
        after_source = verify_source()
        after = {'expected_sha256':digest(expected),'anchor_sha256':digest(anchor)}
        cleanup_ok = cleanup.returncode == 0 or b'No such container' in cleanup.stderr
        record.update({'ended_unix_seconds':time.time(),'exit_code':code,
            'source_sha256_before':before_source,'source_sha256_after':after_source,
            'public_inputs_after':after,'public_inputs_unchanged':before==after,
            'cleanup_passed':cleanup_ok})
        (output/'invocation.json').write_text(json.dumps(record,indent=2)+'\n')
        assert before == after and cleanup_ok
    assert code == 0, 'observer failed; retain diagnostics'
    print((output/'verification/results.json').read_text())


if __name__ == '__main__':
    main()
