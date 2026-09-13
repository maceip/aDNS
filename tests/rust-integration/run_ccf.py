#!/usr/bin/env python3
"""Reproduce isolated Virtual CCF+BIND integration from a pinned local image.

Member/transfer secrets stay in a unique ignored local directory. Only this
run's containers and private CCF state volume are removed on cleanup. No cloud
access, native appraisal, private DNSSEC key export or fake registration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import uuid

from export_ccf_results import read_public_artifact

REPOSITORY = Path(__file__).resolve().parents[2]
SOURCES = (
    'tests/rust-integration/run_ccf.py',
    'tests/rust-integration/ccf_runner_inside.py',
    'tests/rust-integration/export_ccf_results.py',
    'tests/rust-integration/monitor_remote.py',
    'tests/rust-integration/benchmark_remote.py',
    'tests/rust-integration/reconcile_ccf_inside.py',
    'tests/rust-integration/verify_reconciliation.py',
    'tests/rust-integration/rotate_tsig_ccf_inside.py',
    'tests/rust-integration/verify_tsig_rotation.py',
    'ccf/tests/observe_process.py',
    'tools/ccf_control.py', 'tools/prepare_aci_control.py',
    'tools/verify_ksk_receipt.py', 'tools/http_limits.py',
    'ccf/node.example.json', 'ccf/tests/verify_live_transfer.py',
    'ccf/tests/observe_status.py', 'ccf/tests/operator_mail.py',
    'ccf/tests/verify_operator_mail.py',
)


def execute(arguments, *, timeout=60, check=True, **kwargs):
    return subprocess.run(arguments, timeout=timeout, check=check, **kwargs)


def output(arguments, *, timeout=60):
    return execute(arguments, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def image_id(reference):
    return json.loads(output(['docker', 'image', 'inspect', reference]))[0]['Id']


def helper_identity():
    # Linux bind mounts retain numeric ownership. A root helper's private 0700
    # output is unreadable to the hosted runner; do not widen its permissions.
    return ['--user', f'{os.getuid()}:{os.getgid()}']


def result_json(results, name, *, expected_type=dict):
    value = json.loads(read_public_artifact(results, name, max_bytes=8*1024*1024))
    if not isinstance(value, expected_type):
        raise ValueError('result has an unexpected JSON shape: '+name)
    return value


class OwnedVolume:
    """Track even uncertain Docker creation without removing another run's data."""
    label = 'agentdns.acceptance.run'

    def __init__(self, name, owner):
        self.name, self.owner, self.attempted = name, owner, False

    def labels(self):
        response = execute(['docker', 'volume', 'inspect', '--format', '{{json .Labels}}', self.name],
                           check=False, capture_output=True, text=True)
        if response.returncode:
            if 'no such volume' in response.stderr.lower():
                return None
            raise RuntimeError('owned volume inspection failed')
        value = json.loads(response.stdout)
        if value is not None and not isinstance(value, dict):
            raise ValueError('unexpected volume ownership metadata')
        return value or {}

    def create(self):
        if self.labels() is not None:
            raise RuntimeError('refusing to reuse an existing state volume')
        self.attempted = True
        execute(['docker', 'volume', 'create', '--label', self.label+'='+self.owner, self.name],
                stdout=subprocess.DEVNULL)
        if (self.labels() or {}).get(self.label) != self.owner:
            raise RuntimeError('state volume ownership was not established')

    def remove(self):
        if not self.attempted:
            return
        labels = self.labels()
        if labels is None:
            return
        if labels.get(self.label) != self.owner:
            raise RuntimeError('refusing to remove a state volume owned by another run')
        response = execute(['docker', 'volume', 'rm', self.name], check=False, capture_output=True)
        if response.returncode:
            raise RuntimeError('owned state volume removal failed')


def snapshot_sources(destination):
    """Copy explicit files before containers start; hash exactly the copied bytes."""
    result = {}
    for name in SOURCES:
        data = (REPOSITORY/name).read_bytes()
        path = destination/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o444)
        result[name] = hashlib.sha256(data).hexdigest()
    return result


def helper_mounts(work, source, results, access):
    options = ['-v', str(source)+':/src:ro']
    if access == 'control':
        # prepare_aci_control creates /work/control itself. Keep that bootstrap
        # parent writable, but mask the second alias to the copied source too.
        options += ['-v', str(work)+':/work', '-v', str(source)+':/work/source:ro']
    else:
        options += ['-v', str(results)+':/work/results']
        secrets = {'provision':['transfer-key.json'], 'transfer':['transfer-key.b64'],
            'replacement-provision':['replacement-transfer-key.json'],
            'rotation-transfer':['transfer-key.b64', 'replacement-transfer-key.b64']}.get(access, [])
        for secret in secrets:
            options += ['-v', str(work/'control/private'/secret)+':/work/control/private/'+secret+':ro']
    return options


def finalize_source_integrity(source, expected, results, provenance=None, summary=None):
    """Persist the actual post-execution check and refuse a passing mismatch."""
    failures, actual = [], {}
    ordinary_root = not source.is_symlink() and source.is_dir()
    root = source.resolve() if ordinary_root else source.absolute()
    if not ordinary_root:
        failures.append({'path':'.', 'reason':'source root is not an ordinary directory'})
    for name, digest in (expected.items() if ordinary_root else []):
        path = source/name
        try:
            if path.is_symlink() or not path.is_file() or path.resolve() != root/name:
                failures.append({'path':name, 'reason':'missing or non-ordinary source'})
                continue
            if path.stat().st_size > 4*1024*1024:
                failures.append({'path':name, 'reason':'source exceeds4 MiB bound'})
                continue
            data = path.read_bytes()
        except OSError as error:
            failures.append({'path':name, 'reason':'source read failed', 'error':type(error).__name__})
            continue
        actual[name] = hashlib.sha256(data).hexdigest()
        if actual[name] != digest:
            failures.append({'path':name, 'reason':'SHA256 mismatch'})
    # Enumerate only the directories implied by the fixed source allowlist.
    # Each directory stops on its first unlisted child, so an added tree cannot
    # create unbounded traversal or hide newly importable Python source.
    directories = {Path('.')}
    for name in expected:
        directories.update(Path(name).parents)
    for relative in (sorted(directories) if ordinary_root else []):
        directory = source/relative
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() != root/relative:
            failures.append({'path':str(relative), 'reason':'missing or non-ordinary source directory'})
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    child = relative/entry.name
                    if (entry.is_symlink() or
                            not (str(child) in expected and entry.is_file(follow_symlinks=False)
                                 or child in directories and entry.is_dir(follow_symlinks=False))):
                        failures.append({'path':str(child), 'reason':'unexpected source entry'})
                        break
        except OSError as error:
            failures.append({'path':str(relative), 'reason':'source inventory failed', 'error':type(error).__name__})
    report = {'status':'failed' if failures else 'passed', 'checked_unix_seconds':time.time(),
        'expected_source_files':len(expected),
        'verified_source_files':sum(actual.get(name) == digest for name, digest in expected.items()),
        'post_execution_sha256':actual, 'failures':failures}
    (results/'source-integrity.json').write_text(json.dumps(report, indent=2)+'\n')
    if provenance is not None:
        provenance['post_execution_source_integrity'] = report
        (results/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    if summary is not None:
        summary['source_integrity'] = report
        if failures:
            summary['status'] = 'failed'
            summary['failure_reason'] = 'frozen source integrity mismatch'
        (results/'runner-results.json').write_text(json.dumps(summary, indent=2)+'\n')
    if failures:
        raise ValueError('frozen source integrity mismatch; evidence retained')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ccf-image', required=True, help='immutable locally available sha256 ID or repository@sha256 digest')
    parser.add_argument('--secondary-image', default='agentdns-secondary:local')
    parser.add_argument('--toolchain-image', default='agentdns-ccf-toolchain:7.0.15')
    parser.add_argument('--validator-image', default='agentdns-validation:local')
    parser.add_argument('--seconds', type=int, default=30, help='30-second smoke or 1200–3600-second real idle window')
    args = parser.parse_args()
    if not re.fullmatch(r'(?:[^\s]+@)?sha256:[0-9a-f]{64}', args.ccf_image):
        parser.error('CCF image must be an immutable local digest')
    if args.seconds != 30 and not 1200 <= args.seconds <= 3600:
        parser.error('choose 30 seconds for smoke or at least 1200 seconds for idle acceptance')
    def interrupted(*_):
        raise KeyboardInterrupt('runner interrupted; cleaning up its own resources')
    signal.signal(signal.SIGTERM, interrupted)
    references = {'ccf':args.ccf_image, 'secondary':args.secondary_image,
                  'toolchain':args.toolchain_image, 'validator':args.validator_image}
    images = {name:image_id(reference) for name, reference in references.items()}
    parent = REPOSITORY/'.validation/ccf-runs'
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    work.chmod(0o700)
    results, source = work/'results', work/'source'
    results.mkdir(mode=0o700)
    source_hashes = snapshot_sources(source)
    stem = 'agentdns-ccf-runner-'+uuid.uuid4().hex[:12]
    node, secondary, driver = stem+'-node', stem+'-bind', stem+'-driver'
    volume = stem+'-state'
    owned_volume = OwnedVolume(volume, stem)
    containers, monitors = [], []
    succeeded = False
    provenance = None
    started = time.time()

    def invoke(image, command, *, network=None, access=False, timeout=180):
        # Named helper containers are tracked even if their Docker client times
        # out; cleanup can remove them rather than leaving a detached operation.
        name = stem+'-helper-'+uuid.uuid4().hex[:8]
        containers.append(name)
        options = ['docker', 'run', '--rm', '--name', name, *helper_identity()]
        if image in (images['ccf'], images['toolchain']):
            options += ['--platform', 'linux/amd64']
        if network:
            options += ['--network', network]
        options += helper_mounts(work, source, results, access)
        options += ['--entrypoint', 'python3', image, *command]
        try:
            response = execute(options, timeout=timeout, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.TimeoutExpired:
            (results/'last-helper-failure.json').write_text(json.dumps({'helper':command[0],
                'container':name, 'timeout_seconds':timeout, 'error':'TimeoutExpired'}, indent=2)+'\n')
            raise
        if response.returncode != 0:
            # Preserve the actual diagnostic before cleanup. Command arguments
            # contain only file paths and fixed metadata, never secret values.
            (results/'last-helper-failure.json').write_text(json.dumps({'helper':command[0],
                'container':name, 'returncode':response.returncode, 'stdout':response.stdout,
                'stderr':response.stderr}, indent=2)+'\n')
            response.check_returncode()
        return response

    def phase(name, image='toolchain', *, suffix=''):
        access = 'control' if name == 'govern' else ('provision' if name == 'provision' else False)
        log = results/(name+suffix+'-phase.log')
        try:
            response = invoke(images[image], ['/src/tests/rust-integration/ccf_runner_inside.py', name],
                network='container:'+node, access=access, timeout=480 if name == 'ready' else 180)
            log.write_text(response.stdout+response.stderr)
        except subprocess.CalledProcessError as error:
            log.write_text((error.stdout or '')+(error.stderr or ''))
            raise
        except subprocess.TimeoutExpired as error:
            log.write_text('bounded phase deadline exceeded\n')
            raise

    def inspect_running(name):
        return output(['docker', 'inspect', '-f', '{{.State.Running}}', name]).decode().strip() == 'true'

    try:
        constitution = output(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--entrypoint', 'cat',
            images['ccf'], '/opt/agentdns/governance/constitution.js'])
        constitution_digest = hashlib.sha256(constitution).hexdigest()
        binary_hash = output(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--entrypoint', 'sha256sum',
            images['ccf'], '/usr/local/bin/agentdns']).decode().split()[0]
        if not re.fullmatch('[0-9a-f]{64}', binary_hash):
            raise ValueError('invalid image binary digest')
        provenance = {'platform':'Virtual; local CCF protocol test only', 'ccf_version':'7.0.15',
            'requested_images':references, 'resolved_immutable_images':images, 'primary_binary_sha256':binary_hash,
            'packaged_constitution_sha256':constitution_digest, 'frozen_source_files_sha256':source_hashes,
            'started_unix_seconds':started, 'requested_observation_seconds':args.seconds, 'public_host_ports':[],
            'ccf_and_bind_shared_network_namespace':True, 'driver_private_keys_or_tsig_access':False,
            'stock_validator_separate_bridge_container':True,
            'helper_numeric_identity':f'{os.getuid()}:{os.getgid()}',
            'service_identity_source':'public certificate copied from controlled immutable local image; no SNP identity claim'}
        (results/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
        invoke(images['toolchain'], ['/src/tools/prepare_aci_control.py', '/work/control',
            '--constitution-sha256', constitution_digest], access='control')
        owned_volume.create()
        containers.append(node)
        execute(['docker', 'run', '-d', '--platform', 'linux/amd64', '--name', node,
            '-e', 'CCF_PLATFORM_OVERRIDE=Virtual', '-v', str(work/'control/public')+':/config:ro',
            '-v', volume+':/state', '--entrypoint', '/usr/local/bin/agentdns', images['ccf'],
            '--config', '/config/node.json'], stdout=subprocess.DEVNULL)
        deadline = time.monotonic()+45
        while True:
            if not inspect_running(node):
                raise RuntimeError('Virtual CCF exited before producing a service identity')
            probe = execute(['docker', 'exec', node, 'test', '-s', '/state/service_cert.pem'],
                check=False, capture_output=True)
            if probe.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('CCF service certificate was not produced')
            time.sleep(0.2)
        execute(['docker', 'cp', node+':/state/service_cert.pem', str(results/'service_cert.pem')], stdout=subprocess.DEVNULL)
        phase('govern')
        phase('provision', 'ccf')
        containers.append(secondary)
        execute(['docker', 'run', '-d', '--platform', 'linux/amd64', '--name', secondary,
            '--network', 'container:'+node, '-e', 'AGENTDNS_TRANSFER_KEY_FILE=/config/key.b64',
            '-v', str(work/'control/private/transfer-key.b64')+':/config/key.b64:ro', images['secondary']], stdout=subprocess.DEVNULL)
        phase('bind-ready', 'ccf')
        containers.append(driver)
        execute(['docker', 'run', '-d', '--platform', 'linux/amd64', '--name', driver,
            '--network', 'container:'+node, '-v', str(results/'service_cert.pem')+':/public/service_cert.pem:ro',
            '--entrypoint', 'python3', images['ccf'], '/opt/agentdns/host_driver.py',
            '--ccf-url', 'https://127.0.0.1:8001', '--service-cert', '/public/service_cert.pem',
            '--listen', '0.0.0.0:5353'], stdout=subprocess.DEVNULL)
        # A ready DNS listener may still be loading the initial AXFR when the
        # first SOA challenge arrives. Wait for genuine bounded retry, without
        # fabricating observations or resetting the driver/work queue.
        phase('ready')
        phase('receipt')
        address = output(['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', node]).decode().strip()
        def verify(label):
            result = invoke(images['validator'], ['/src/ccf/tests/verify_live_transfer.py', '--server', address,
                '--key-file', '/work/control/private/transfer-key.b64', '--receipt', '/work/results/ksk-receipt.json',
                '--anchor', '/work/results/trust-anchor.conf', '--trusted-key', '/work/results/trusted-dnskey.txt',
                '--output', '/work/results/'+label], access='transfer')
            (results/(label+'-phase.log')).write_text(result.stdout+result.stderr)
            report = result_json(results, label+'/results.json')
            if report['transfer_messages'] < 2:
                raise AssertionError('multi-message TSIG transfer was not exercised')
        verify('initial-transfer')

        def monitor(label, command, network=None, pid_container=None):
            name = stem+'-'+label
            containers.append(name)
            arguments = ['docker', 'run', '--rm', '--name', name, *helper_identity()]
            if network:
                arguments += ['--network', network]
            if pid_container:
                arguments += ['--pid', 'container:'+pid_container]
            arguments += ['-v', str(source)+':/src:ro', '-v', str(results)+':/results',
                images['validator'], 'python3', *command]
            log = (results/(label+'.log')).open('wb')
            monitors.append((label, subprocess.Popen(arguments, stdout=log, stderr=log), log))
        monitor('committed-status', ['/src/ccf/tests/observe_status.py', '--url', 'https://127.0.0.1:8000',
            '--service-cert', '/results/service_cert.pem', '--seconds', str(args.seconds), '--output', '/results/status'],
            network='container:'+node)
        if args.seconds >= 1200:
            monitor('frontend-idle', ['/src/tests/rust-integration/monitor_remote.py', '--server', address,
                '--anchor', '/results/trust-anchor.conf', '--seconds', str(args.seconds), '--output', '/results/frontend'])
            monitor('frontend-load', ['/src/tests/rust-integration/benchmark_remote.py', '--server', address,
                '--seconds', '1200', '--qps', '1000', '--samples-per-second', '10', '--output', '/results/load'])
            for label, container in (('ccf-rss', node), ('bind-rss', secondary)):
                monitor(label, ['/src/ccf/tests/observe_process.py', '--pid', '1', '--name', label,
                    '--seconds', '1200', '--output', '/results/memory'], pid_container=container)
        observation_deadline = time.monotonic()+args.seconds+180
        next_check, next_update = 0, 0
        while any(process.poll() is None for _, process, _ in monitors):
            now = time.monotonic()
            if now >= observation_deadline:
                raise TimeoutError('monitor exceeded requested duration plus bounded overhead')
            for label, process, _ in monitors:
                if process.poll() not in (None, 0):
                    raise RuntimeError(label+' monitor failed')
            if now >= next_check:
                if not all(inspect_running(name) for name in (node, secondary, driver)):
                    raise RuntimeError('a required CCF/BIND/driver container exited')
                next_check = now+10
            if now >= next_update:
                print(json.dumps({'status':'observing', 'platform':'Virtual',
                    'seconds_since_runner_start':round(time.time()-started), 'output':str(results)}), flush=True)
                next_update = now+30
            time.sleep(1)
        for label, process, log in monitors:
            if process.wait(timeout=10) != 0:
                raise RuntimeError(label+' monitor failed')
            log.close()
        verify('final-idle-transfer')
        phase('ready', suffix='-after-idle')
        # Signed operator mutations deliberately begin AFTER the idle window.
        operator = invoke(images['toolchain'], ['/src/ccf/tests/operator_mail.py', '--url', 'https://127.0.0.1:8000',
            '--service-cert', '/work/results/service_cert.pem', '--member-key', '/work/control/private/member0_privk.pem',
            '--member-cert', '/work/control/public/member0_cert.pem', '--output', '/work/results/operator'],
            network='container:'+node, access='control')
        (results/'operator-phase.log').write_text(operator.stdout+operator.stderr)
        phase('ready', suffix='-after-operator')
        external = invoke(images['validator'], ['/src/ccf/tests/verify_operator_mail.py', '--server', address,
            '--expected', '/work/results/operator/expected-records.json', '--anchor', '/work/results/trust-anchor.conf',
            '--output', '/work/results/operator-frontend'])
        (results/'operator-frontend-phase.log').write_text(external.stdout+external.stderr)
        reconciliation = invoke(images['toolchain'], ['/src/tests/rust-integration/reconcile_ccf_inside.py'],
            network='container:'+node, access='control')
        (results/'reconciliation-phase.log').write_text(reconciliation.stdout+reconciliation.stderr)
        phase('ready', suffix='-after-reconciliation')
        external = invoke(images['validator'], ['/src/tests/rust-integration/verify_reconciliation.py', '--server', address,
            '--expected', '/work/results/reconciliation/expected-records.json', '--anchor', '/work/results/trust-anchor.conf',
            '--output', '/work/results/reconciliation-frontend'])
        (results/'reconciliation-frontend-phase.log').write_text(external.stdout+external.stderr)
        # Rotation begins only after all BIND and idle checks. The replacement
        # identity is tested by an independent authenticated AXFR/SOA client;
        # its reserved loopback endpoint has no replacement BIND deployment.
        for stage, image, access in [('create', 'toolchain', 'control'),
                                     ('provision', 'ccf', 'replacement-provision')]:
            result = invoke(images[image], ['/src/tests/rust-integration/rotate_tsig_ccf_inside.py', stage],
                network='container:'+node, access=access)
            (results/('rotation-'+stage+'-phase.log')).write_text(result.stdout+result.stderr)
        def rotation_verify(stage):
            result = invoke(images['validator'], ['/src/tests/rust-integration/verify_tsig_rotation.py', stage,
                '--server', address], access='rotation-transfer')
            (results/('rotation-'+stage+'-phase.log')).write_text(result.stdout+result.stderr)
        rotation_verify('before')
        for stage, access in [('revoke', 'control'), ('work', False)]:
            result = invoke(images['toolchain'], ['/src/tests/rust-integration/rotate_tsig_ccf_inside.py', stage],
                network='container:'+node, access=access)
            (results/('rotation-'+stage+'-phase.log')).write_text(result.stdout+result.stderr)
        rotation_verify('after')
        summary = {'status':'passed', 'kind':'real-idle-window' if args.seconds >= 1200 else 'short-smoke-only',
            'platform':'Virtual; no native appraisal or service registration', 'observation_seconds':args.seconds,
            'total_elapsed_seconds':time.time()-started, 'images':images,
            'independent_receipt_and_multimessage_tsig_dnssec_verified':True,
            'committed_status':result_json(results, 'status/status-results.json'),
            'operator':result_json(results, 'operator/summary.json'),
            'operator_frontend':result_json(results, 'operator-frontend/results.json', expected_type=list),
            'reconciliation':result_json(results, 'reconciliation/summary.json'),
            'reconciliation_frontend':result_json(results, 'reconciliation-frontend/results.json'),
            'tsig_rotation':{stage:result_json(results, f'rotation/{stage}/results.json') for stage in ('before', 'after')},
            'output':str(results)}
        if args.seconds >= 1200:
            summary['frontend'] = result_json(results, 'frontend/remote-idle-results.json')
            summary['performance'] = result_json(results, 'load/results.json')
            summary['process_memory'] = {label:result_json(results, f'memory/{label}-results.json')
                for label in ('ccf-rss', 'bind-rss')}
        succeeded = True
    finally:
        failures = []
        for label, process, log in monitors:
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            except Exception as error:
                # A stuck Docker client must not prevent removal of its named
                # container and the remaining resources owned by this run.
                failures.append({'monitor':label, 'error':type(error).__name__})
            finally:
                log.close()
        # Inventory once; successfully --rm helpers may already be gone.
        try:
            present = set(output(['docker', 'ps', '-a', '--format', '{{.Names}}']).decode().splitlines())
        except Exception as error:
            present = set(containers)
            failures.append({'stage':'inventory', 'error':type(error).__name__})
        for name in reversed(containers):
            if name not in present:
                continue
            try:
                with (results/(name[len(stem)+1:]+'-container.log')).open('wb') as log:
                    execute(['docker', 'logs', name], check=False, stdout=log, stderr=log)
                removed = execute(['docker', 'rm', '--force', name], check=False, capture_output=True)
                if removed.returncode != 0:
                    failures.append({'container':name, 'returncode':removed.returncode})
            except Exception as error:
                failures.append({'container':name, 'error':type(error).__name__})
        if owned_volume.attempted:
            try:
                owned_volume.remove()
            except Exception as error:
                failures.append({'volume':volume, 'error':type(error).__name__})
        cleanup = {'owned_containers_and_state_volume_removed':not failures, 'failures':failures,
            'private_run_directory':str(work)}
        (results/'cleanup.json').write_text(json.dumps(cleanup, indent=2)+'\n')
        print(json.dumps({'cleanup':cleanup}), flush=True)
        if succeeded:
            summary['cleanup'] = cleanup
            if failures:
                summary['status'] = 'failed'
                summary['failure_reason'] = 'resource cleanup failed'
        finalize_source_integrity(source, source_hashes, results, provenance,
            summary if succeeded else None)
        if failures and succeeded:
            raise RuntimeError('validation passed but cleanup failed; inspect cleanup.json')
    if succeeded:
        print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
