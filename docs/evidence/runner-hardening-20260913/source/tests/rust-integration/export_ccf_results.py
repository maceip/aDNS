#!/usr/bin/env python3
"""Export only explicitly named public CCF-runner evidence; never private work."""
import argparse
import hashlib
import json
from pathlib import Path

PUBLIC_FILES = (
    'runner-results.json', 'cleanup.json', 'provenance.json', 'source-integrity.json', 'service_cert.pem',
    'last-helper-failure.json', 'diagnostic-scope.json',
    'governance.json', 'provision.json', 'ready.json', 'latest-readiness.json',
    'readiness-failure.json', 'ksk-receipt.json', 'receipt-verification.json',
    'trust-anchor.conf', 'trusted-dnskey.txt', 'node-container.log', 'bind-container.log',
    'driver-container.log', 'govern-phase.log', 'provision-phase.log',
    'bind-ready-phase.log', 'ready-phase.log', 'ready-after-idle-phase.log',
    'ready-after-operator-phase.log', 'receipt-phase.log', 'operator-phase.log',
    'operator-frontend-phase.log', 'initial-transfer-phase.log', 'final-idle-transfer-phase.log',
    'committed-status.log', 'frontend-idle.log', 'frontend-load.log', 'ccf-rss.log', 'bind-rss.log',
    'status/status-samples.json', 'status/status-results.json',
    'frontend/remote-idle-samples.json', 'frontend/remote-idle-results.json',
    'load/results.json', 'load/latency-samples.json', 'load/failed-samples.json',
    'load/dnsperf.log', 'load/dnsperf-queries.txt',
    'memory/ccf-rss-results.json', 'memory/ccf-rss-samples.json',
    'memory/bind-rss-results.json', 'memory/bind-rss-samples.json',
    'operator/summary.json', 'operator/grant.json', 'operator/expected-records.json',
    'operator/signed-request.json', 'operator/result.json', 'operator/retry.json',
    'operator/der-rejection.json', 'operator/conflict.json',
    'operator-frontend/results.json', 'operator-frontend/example.test.TXT.log',
    'operator-frontend/selector1._domainkey.example.test.TXT.log',
    'operator-frontend/_dmarc.example.test.TXT.log',
    'operator-frontend/_smtp._tls.example.test.TXT.log', 'operator-frontend/example.test.CAA.log',
    'reconciliation-phase.log', 'ready-after-reconciliation-phase.log', 'reconciliation-frontend-phase.log',
    'reconciliation/http-history.json', 'reconciliation/grant.json', 'reconciliation/grant-created.json',
    'reconciliation/state-before.json', 'reconciliation/nonce.json', 'reconciliation/signed-request.json',
    'reconciliation/pending.json', 'reconciliation/grant-revoked.json', 'reconciliation/failed-submit.json',
    'reconciliation/failed-transaction.json',
    'reconciliation/failed-observation.json', 'reconciliation/state-after-failure.json',
    'reconciliation/grant-restored.json', 'reconciliation/committed-retry.json',
    'reconciliation/committed-reconciliation.json', 'reconciliation/identical-retry.json',
    'reconciliation/expected-records.json', 'reconciliation/summary.json',
    'reconciliation-frontend/results.json', 'reconciliation-frontend/reconcile.example.test.TXT.log',
    'reconciliation-frontend/response.txt',
    'rotation-create-phase.log', 'rotation-provision-phase.log', 'rotation-revoke-phase.log',
    'rotation-work-phase.log', 'rotation-before-phase.log', 'rotation-after-phase.log',
    'rotation/configuration.json', 'rotation/governed.json', 'rotation/provisioned.json',
    'rotation/provision-http.json',
    'rotation/governance-http-create.json', 'rotation/governance-http-revoke.json',
    'rotation/revoked.json', 'rotation/revoked-identical-retry.json', 'rotation/revocation-summary.json',
    'rotation/issued-work.json', 'rotation/before/results.json', 'rotation/before/transferred.zone',
    'rotation/work-commit-confirmations.json',
    'rotation/before/ldns-verify-zone.log', 'rotation/after/results.json', 'rotation/after/transferred.zone',
    'rotation/after/ldns-verify-zone.log', 'rotation/after/negative-observations.json',
)
TRANSFER_FILES = ('results.json', 'transferred.zone', 'ldns-verify-zone.log',
                  'delv-example.test.SOA.log', 'delv-example.test.DNSKEY.log',
                  'delv-example.test.TXT.log', 'delv-definitely-absent-agentdns.example.test.A.log')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results',type=Path)
    parser.add_argument('destination',type=Path)
    args=parser.parse_args()
    if args.destination.exists():
        parser.error('destination must be new; preserve earlier results separately')
    if not args.results.is_dir():
        parser.error('results directory does not exist')
    args.destination.mkdir(parents=True)
    names=list(PUBLIC_FILES)
    names.extend(f'{prefix}/{name}' for prefix in ('initial-transfer','final-idle-transfer') for name in TRANSFER_FILES)
    names.extend(f'operator/attempt-{attempt}-{kind}-response.json' for attempt in range(1,4) for kind in ('der','operator'))
    copied={}
    root=args.results.resolve()
    for name in names:
        source=args.results/name
        if not source.exists():
            continue
        # Reject symlink escapes and unusual files; a public allowlist entry
        # must be the actual ordinary result file under this exact directory.
        if source.is_symlink() or source.resolve()!=root/name or not source.is_file():
            raise ValueError('result is not an ordinary public artifact: '+name)
        destination=args.destination/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        if source.stat().st_size>64*1024*1024:
            raise ValueError("public artifact exceeds64 MiB bound: "+name)
        data=source.read_bytes()
        if b'-----BEGIN PRIVATE KEY-----' in data or b'-----BEGIN EC PRIVATE KEY-----' in data or b'-----BEGIN RSA PRIVATE KEY-----' in data:
            raise ValueError('private key marker in purported public artifact: '+name)
        destination.write_bytes(data)
        copied[name]=hashlib.sha256(data).hexdigest()
    if not copied:
        raise ValueError('no named public artifacts were found')
    (args.destination/'sha256.json').write_text(json.dumps(copied,indent=2)+'\n')
    print(json.dumps({'public_artifacts':len(copied),'destination':str(args.destination)}))


if __name__=='__main__':
    main()
