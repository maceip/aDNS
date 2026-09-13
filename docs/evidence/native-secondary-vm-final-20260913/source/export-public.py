#!/usr/bin/env python3
"""Export only reviewed public VM/runtime and measurement artifacts; no credentials."""
import argparse
import base64
import hashlib
import json
import zlib
from pathlib import Path

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--memory', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
repo = Path.cwd().resolve()
root = repo / '.validation/azure/native-final-20260913/secondary-vm'
memory = args.memory.resolve()
if memory.parent != root or not memory.name.startswith('memory-retrieval-'):
    raise ValueError('unexpected memory retrieval directory')
results = json.loads((memory / 'results.json').read_text())
bundle_raw = (memory / 'bundle.json').read_bytes()
bundle = json.loads(bundle_raw)
samples = json.loads((memory / 'samples.json').read_text())
if len(samples) != 139 or results['sample_count'] != 139 or results['requested_seconds'] != 1380 or bundle['collection_passed'] is not True:
    raise ValueError('complete long collection required for final export')
files = {
    'vm-status.json': root / 'vm-status.json',
    'initial-runtime.json': root / 'initial-runtime.json',
    'bootstrap-public-review.json': root / 'bootstrap-public-review.json',
    'failed-quota.log': root / 'create.stderr.log',
    'initial-public-listeners.json': root / 'initial-public-listeners.json',
    'readiness/attempt-1.json': root / 'zone-ready-attempt-1.json',
    'readiness/attempt-2.json': root / 'zone-ready-attempt-2.json',
    'readiness/attempt-3.json': root / 'zone-ready-attempt-3.json',
    'readiness/earlier-primary-update.json': root / 'final-primary-update-result.json',
    'readiness/final-primary-update.json': root / 'ready-primary-update-result.json',
    'readiness/bind-transfer-response.json': root / 'ready-bind-transfer-command.json',
    'readiness/bind-transfer.json': root / 'ready-bind-transfer-result.json',
    'readiness/delv-udp.log': root / 'delv-ready-udp.log',
    'readiness/delv-tcp.log': root / 'delv-ready-tcp.log',
    'readiness/delv-provenance.json': root / 'delv-ready-provenance.json',
    'readiness/anchor.conf': repo / '.validation/azure/native-final-20260913/primary/native-v5-ready/anchor.conf',
    'smoke/failed-copy-response.json': root / 'memory-smoke-command.json',
    'smoke/failed-copy-diagnosis.json': root / 'diagnose-copy-command.json',
    'smoke/staged-source-response.json': root / 'stage-observer-command.json',
    'smoke/success-response.json': root / 'memory-smoke-v2-command.json',
    'smoke/samples.json': root / 'memory-smoke-v2-samples.json',
    'smoke/results.json': root / 'memory-smoke-v2-results.json',
    'memory/stage-response.json': root / 'stage-observer-1380-command.json',
    'memory/stage.json': root / 'stage-observer-1380-result.json',
    'memory/launch-response.json': root / 'start-memory-command.json',
    'memory/launch.json': root / 'start-memory-result.json',
    'memory/analysis.json': root / 'memory-analysis.json',
    'source/analyze-memory.py': root / 'management/analyze-memory.py',
    'memory/source-manifest.json': root / 'memory-source-manifest.json',
    'memory/duration-review.json': root / 'root-1380-duration-review.json',
    'source/secondary_vm.py': root / 'source/secondary_vm.py',
    'source/observe_native_bind-smoke.py': root / 'source/observe_native_bind-smoke.py',
    'source/observe_native_bind.py': root / 'source/observe_native_bind.py',
    'source/start-memory.sh': root / 'management/start-memory.sh',
    'source/package-memory.sh': root / 'management/package-memory.sh',
    'source/collect-memory.py': root / 'management/collect-memory.py',
    'source/stage-observer-1380.sh': root / 'management/stage-observer-1380.sh',
    'source/export-public.py': Path(__file__).resolve(),
}
for name in ['metadata.json', 'samples.json', 'results.json', 'collector.log', 'collector.exit', 'bundle.json', 'manifest.json']:
    files['memory/' + name] = memory / name
manifest = json.loads((memory / 'manifest.json').read_text())
if not 1 <= manifest['chunks'] <= 32 or manifest['chunk_chars'] != 2700 or len(manifest['chunk_sha256']) != manifest['chunks']:
    raise ValueError('chunk manifest bounds')
if len(bundle_raw) != manifest['raw_bytes'] or hashlib.sha256(bundle_raw).hexdigest() != manifest['raw_sha256']:
    raise ValueError('reassembled public bundle hash mismatch')
if json.loads(bundle['files']['samples.json']) != samples or json.loads(bundle['files']['results.json']) != results:
    raise ValueError('extracted measurement differs from hashed bundle')
encoded_chunks = []
for index in range(manifest['chunks']):
    response = json.loads((memory / f'chunk-{index}.response.json').read_text())
    raw, stderr = response['value'][0]['message'].split('[stdout]\n', 1)[1].split('\n[stderr]', 1)
    chunk = json.loads(raw)
    if stderr.strip() or chunk['index'] != index or not 0 < len(chunk['data']) <= 2700 or hashlib.sha256(chunk['data'].encode()).hexdigest() != manifest['chunk_sha256'][index]:
        raise ValueError('retrieval chunk response mismatch')
    encoded_chunks.append(chunk['data'])
encoded = ''.join(encoded_chunks)
if len(encoded) != manifest['base64_chars']:
    raise ValueError('retrieval encoded length mismatch')
decoder = zlib.decompressobj()
recovered = decoder.decompress(base64.b64decode(encoded, validate=True), 250001)
if not decoder.eof or decoder.unused_data or len(recovered) > 250000 or recovered != bundle_raw:
    raise ValueError('retrieval responses do not reconstruct exact bundle')
for index in range(manifest['chunks']):
    files[f'memory/retrieval/chunk-{index}.response.json'] = memory / f'chunk-{index}.response.json'
files['memory/retrieval/manifest.response.json'] = memory / 'manifest.response.json'
# The original runtime TSIG is the only secret used by this VM helper. Reject its exact
# raw and encoded variants before copying any public byte. Root performs a wider audit.
secret_path = repo / '.validation/azure/ccf-control-contract/private/transfer-key.b64'
secret_encoded = secret_path.read_bytes().strip()
secret = base64.b64decode(secret_encoded, validate=True)
if len(secret) != 32:
    raise ValueError('unexpected private TSIG length')
forbidden = [secret, secret_encoded, secret.hex().encode(), base64.urlsafe_b64encode(secret), base64.urlsafe_b64encode(secret).rstrip(b'='), b'-----BEGIN RSA ' + b'PRIVATE KEY-----', b'-----BEGIN ENCRYPTED ' + b'PRIVATE KEY-----', b'-----BEGIN ' + b'PRIVATE KEY-----', b'-----BEGIN EC ' + b'PRIVATE KEY-----', b'-----BEGIN OPENSSH ' + b'PRIVATE KEY-----']
prepared = {}
for name, source in files.items():
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1000000:
        raise ValueError('public source must be a bounded regular file')
    raw = source.read_bytes()
    if any(marker in raw for marker in forbidden):
        raise ValueError('private material detected in selected public artifact')
    prepared[name] = raw
args.output.mkdir(parents=True, exist_ok=False)
for name, raw in prepared.items():
    target = args.output / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
(args.output / 'sha256.json').write_text(json.dumps({name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(prepared.items())},indent=2)+'\n')
print(json.dumps({'public_directory':str(args.output),'explicit_artifact_count':len(prepared),'secret_variants_checked':len(forbidden)}))
