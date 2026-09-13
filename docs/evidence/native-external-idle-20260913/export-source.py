#!/usr/bin/env python3
"""Export the fixed, credential-free native observation after all guards pass."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
RUN = BASE / 'native-idle-attempt1'
DEST = Path('/Users/mac/agentdns/docs/evidence/native-external-idle-20260913')
FILES = (
    'runner-results.json', 'provenance.json', 'source-integrity.json',
    'public-input-integrity/source-integrity.json',
    'status/status-results.json', 'status/status-samples.json',
    'dnssec/remote-idle-results.json', 'dnssec/remote-idle-samples.json',
    'load/results.json', 'load/latency-samples.json', 'load/failed-samples.json',
    'load/dnsperf.log', 'load/dnsperf-queries.txt',
    'status.log', 'dnssec.log', 'load.log',
)


def copy_public(source, relative):
    if source.is_symlink() or not source.is_file():
        raise ValueError('export source is not a regular file: ' + str(relative))
    data = source.read_bytes()
    if len(data) > 32 * 1024 * 1024 or (b'PRIVATE ' + b'KEY-----') in data:
        raise ValueError('public export guard: ' + str(relative))
    target = DEST / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def main():
    result = json.loads((RUN / 'results/runner-results.json').read_text())
    provenance = json.loads((RUN / 'results/provenance.json').read_text())
    assert result['status'] == 'passed' and result['cleanup_failures'] == []
    # The immutable runner's guards verify the complete source/public inventories,
    # including unexpected files, symlinks and changed/missing expected files.
    for name in ('source-integrity.json', 'public-input-integrity/source-integrity.json'):
        report = json.loads((RUN / 'results' / name).read_text())
        assert report['status'] == 'passed', report
    DEST.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        copy_public(RUN / 'results' / name, Path('results') / name)
    for name, expected in provenance['frozen_source_files_sha256'].items():
        source = RUN / 'source' / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected
        copy_public(source, Path('source') / name)
    for name, expected in provenance['public_input_sha256'].items():
        source = RUN / 'public' / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected
        copy_public(source, Path('public') / name)
    copy_public(BASE / 'native-idle-runner.log', Path('runner.log'))
    copy_public(Path(__file__), Path('export-source.py'))
    data = result['fixed_load']
    summary = {
        'status': 'passed', 'source': 'actual public Azure native primary and stock BIND VM',
        'primary': provenance['primary'], 'secondary': provenance['secondary'],
        'started_unix_seconds': result['started_unix_seconds'],
        'ended_unix_seconds': result['ended_unix_seconds'],
        'dnssec': result['dnssec_observation'],
        'committed_status': result['status_observation'],
        'fixed_load': data,
        'source_and_public_inputs_rechecked_after_execution': True,
        'cleanup_failures': [],
        'limits': [
            'Fixed offered load, not maximum capacity; WAN timings include client and network.',
            'Latency percentiles use successful probes; timeout and unscheduled counts are separate.',
            'DO=1 load probes check authoritative response codes. Independent periodic stock delv validates signatures.',
            'Native quote, KSK receipt, admission and controlled mail proofs are linked separately.',
            'Signing spans and actual memory measurements are exported separately; none inferred here.',
            'No operator, service, lease or governance mutations during this window; autonomous maintenance continued.',
        ],
    }
    (DEST / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    (DEST / 'README.md').write_text('''# Actual native Azure idle and frontend load observation

This bundle records the public stock BIND VM at `20.166.33.141:53` serving the zone from the genuine confidential CCF primary at `4.208.82.123`. See [the independently verified primary quote](../native-primary-ready-independent-20260913/README.md) and [the receipt, native admission-derived DNS, and controlled mail proofs](../native-external-preidle-20260913/README.md).

The fixed observer ran at least 1,250 seconds across multiple real 600-second RRSIG lifetimes. Independent stock `delv` repeatedly validated positive and NSEC3-negative responses. A separate pinned-CA client observed committed CCF status and authenticated secondary progress. The workload offered 1,000 DO=1 queries/sec for 1,200 seconds alongside a target of ten bounded concurrent latency probes/sec. Actual counts, loss, dispatch misses, elapsed time, and successful-probe percentiles are in [summary.json](summary.json); this is a fixed offered load over the WAN, not maximum capacity.

The runner copied six explicitly selected source files and only the public service certificate and receipt-derived DNSSEC anchor before launch. It mounted them read-only, then checked the exact file inventories and hashes after execution. It declared success only after all child processes completed and cleanup/integrity guards passed. The copied sources, source hashes, raw public observations, and logs are included. No bearer token, TSIG secret, private key, deployment parameter file, or ledger is included.

Actual signing-duration diagnostics and memory measurements have separate provenance and timing boundaries; no RSS, cryptographic signing duration, or leak-freedom claim is inferred from frontend query timing.
''')
    manifest = []
    for path in sorted(DEST.rglob('*')):
        if path.is_file():
            manifest.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(DEST)))
    (DEST / 'SHA256SUMS').write_text('\n'.join(manifest) + '\n')
    print(json.dumps({'destination': str(DEST), 'files': len(manifest)}, indent=2))


if __name__ == '__main__':
    main()
