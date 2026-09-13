#!/usr/bin/env python3
"""Public capture and genuine appraisal only; never sends a token, nonce or signature request."""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--cloud-state', type=Path, required=True)
args = parser.parse_args()
repo = Path.cwd().resolve()
workers = repo / '.validation/azure/native-final-20260913/workers'
prep = workers / 'restart-a-preparation'
old = workers / 'a'
output = workers / 'a-rotated'
policy_path = workers / 'joint-workload-policy.json'
expected_image = 'agentdnsport20260913.azurecr.io/capture@sha256:61027bfc59833975356d526d58557e2b18e4af76464b52acb448e3a9a5feba7a'
expected_cce = '68f46918d210a8eb57ccbdade383ba459cb5260273be3d5f778ca37eef6ab75a'
binary = repo/'target/debug/examples/appraise'
expected_appraiser = '5f2f84e425b9cc91a9a8e62560c1750a53c0da886638953f7e90dbf2b7513fae'
expected_source_manifest = 'e0d021d1928433490c41c43d48bb9cd36d80d315df11799b630eb30cb23a23f5'
original = json.loads((prep / 'original-inputs.json').read_text())['files']
def check_original():
    for name, expected in original.items():
        if hashlib.sha256((repo / name).read_bytes()).hexdigest() != expected:
            raise ValueError('original A input changed: ' + name)
def check_verifiers():
    if hashlib.sha256(binary.read_bytes()).hexdigest() != expected_appraiser:
        raise ValueError('final appraiser binary changed')
    manifest = (prep / 'source-manifest.json').read_bytes()
    if hashlib.sha256(manifest).hexdigest() != expected_source_manifest:
        raise ValueError('frozen source manifest changed')
    for name, expected in json.loads(manifest).items():
        if hashlib.sha256((prep / name).read_bytes()).hexdigest() != expected:
            raise ValueError('frozen verification source changed: ' + name)
check_original()
check_verifiers()
state = json.loads(args.cloud_state.read_text())
if state['name'] != 'agentdns-native-capture' or state['images'] != [expected_image] or state['states'] != ['Running']:
    raise ValueError('unexpected replacement cloud identity/state')
if hashlib.sha256(base64.b64decode(state['cce_policy'], validate=True)).hexdigest() != expected_cce:
    raise ValueError('replacement cloud CCE differs from approved original')
ip = str(ipaddress.ip_address(state['ip']))
output.mkdir(mode=0o700, exist_ok=False)
def run(command, name, timeout):
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        (output / (name + '.stdout.json')).write_bytes(error.stdout or b'')
        (output / (name + '.stderr.log')).write_bytes(error.stderr or b'')
        (output / (name + '.timeout.json')).write_text(json.dumps({'timeout_seconds':timeout,'status':'failed; captured partial output retained'})+'\n')
        raise
    (output / (name + '.stdout.json')).write_bytes(completed.stdout)
    (output / (name + '.stderr.log')).write_bytes(completed.stderr)
    if completed.returncode:
        raise RuntimeError(name + ' failed; original and failed artifacts preserved')
    return json.loads(completed.stdout)
fetch_started = time.time()
capture_deadline = time.monotonic() + 180
attempts = []
for attempt in range(1, 5):
    attempt_dir = output / 'capture-attempts' / str(attempt)
    attempt_dir.mkdir(parents=True, exist_ok=False)
    remaining = capture_deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('public capture phase deadline exceeded')
    try:
        run([sys.executable, str(prep/'source/fetch_capture.py'), ip, str(attempt_dir)], f'fetch-{attempt}', min(45, remaining))
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        attempts.append({'attempt':attempt,'status':'failed','error_type':type(error).__name__})
        (output/'capture-attempts.json').write_text(json.dumps(attempts,indent=2)+'\n')
        if attempt == 4 or time.monotonic() + 5 >= capture_deadline:
            raise
        time.sleep(5)
        continue
    attempts.append({'attempt':attempt,'status':'public capture fetched; appraisal follows'})
    (output/'capture-attempts.json').write_text(json.dumps(attempts,indent=2)+'\n')
    for name in ['capture.json','evidence.cose','spki.der','peer.der','peer.pem','action.json']:
        (output/name).write_bytes((attempt_dir/name).read_bytes())
    break
spki = (output/'spki.der').read_bytes()
if spki == (old/'spki.der').read_bytes():
    raise ValueError('restart did not produce a new service key')
old_action = json.loads((old/'action.json').read_text())['action']
new_action = json.loads((output/'action.json').read_text())['action']
def fixed(action):
    value=copy.deepcopy(action);del value['signer_spki_der'];del value['parameters']['evidence_digest'];return value
if fixed(new_action) != fixed(old_action):
    raise ValueError('replacement fixed registration scope or IDs changed')
now = int(time.time())
appraisal = run([str(binary), 'azure-aci-snp', str(output/'evidence.cose'), str(output/'spki.der'), str(policy_path), str(now)], 'initial-appraisal', 30)
policy = json.loads(policy_path.read_text())
if bytes(appraisal['host_data']).hex() != expected_cce or appraisal['policy_id'] != policy['policy_id'] or appraisal['valid_until'] <= now:
    raise ValueError('appraisal policy/CCE/validity mismatch')
if bytes(appraisal['spki_sha256']).hex() != hashlib.sha256(spki).hexdigest() or bytes(appraisal['evidence_digest']).hex() != hashlib.sha256((output/'evidence.cose').read_bytes()).hexdigest():
    raise ValueError('appraisal evidence/key mismatch')
(output/'verification-time.txt').write_text(str(now)+'\n')
(output/'policy.json').write_bytes(policy_path.read_bytes())
check_original()
check_verifiers()
summary = {'status':'fresh Rust appraisal and actual peer binding passed; independent verification pending',
           'ip':ip,'image':expected_image,'cce_sha256':expected_cce,'verification_time':now,
           'fetch_started_unix_seconds':fetch_started,'fetch_and_appraise_ended_unix_seconds':time.time(),
           'old_spki_sha256':hashlib.sha256((old/'spki.der').read_bytes()).hexdigest(),
           'new_spki_sha256':hashlib.sha256(spki).hexdigest(),
           'grant_id':new_action['grant_id'],'request_id':new_action['request_id'],
           'fixed_action_unchanged_except_key_and_evidence':True,
           'appraiser_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
           'cloud_state_sha256':hashlib.sha256(args.cloud_state.read_bytes()).hexdigest(),
           'original_inputs_unchanged':True,'no_token_or_signature_sent':True}
(output/'restart-appraisal-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
