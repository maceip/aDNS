#!/usr/bin/env python3
"""Derive transfer/expiry and signing metrics from the public raw evidence only."""
import argparse
import datetime
import hashlib
import json
import re
import statistics
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--input', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
names = ('frontend/remote-idle-samples.json', 'status/status-samples.json',
         'bind-container.log', 'node-container.log', 'provenance.json')
manifest = json.loads((args.input/'sha256.json').read_text())
inputs = {}
for name in names:
    data = (args.input/name).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != manifest[name]:
        raise ValueError('input hash mismatch: '+name)
    inputs[name] = digest
frontend = json.loads((args.input/names[0]).read_text())
status = json.loads((args.input/names[1]).read_text())
expirations = {s['serial']:s['soa_signature_expiration'] for s in frontend}
transfers = []
for line in (args.input/'bind-container.log').read_text().splitlines():
    match = re.match(r'(\d\d-\w\w\w-\d{4} \d\d:\d\d:\d\d\.\d+) .*transferred serial (\d+): TSIG', line)
    if not match:
        continue
    timestamp = datetime.datetime.strptime(match[1], '%d-%b-%Y %H:%M:%S.%f').replace(tzinfo=datetime.timezone.utc).timestamp()
    serial = int(match[2])
    if frontend[0]['unix_seconds'] <= timestamp <= frontend[-1]['unix_seconds'] and serial-1 in expirations:
        transfers.append({'serial':serial, 'transfer_unix_seconds':timestamp,
            'previous_soa_signature_expiration':expirations[serial-1],
            'seconds_before_previous_expiration':expirations[serial-1]-timestamp})
peers = [peer for sample in status for peer in sample['body']['frontend_propagation']['secondaries']]
window = {'input_sha256':inputs, 'first_external_utc':datetime.datetime.fromtimestamp(frontend[0]['unix_seconds'], datetime.timezone.utc).isoformat(),
    'last_external_utc':datetime.datetime.fromtimestamp(frontend[-1]['unix_seconds'], datetime.timezone.utc).isoformat(),
    'external_wall_span_seconds':frontend[-1]['unix_seconds']-frontend[0]['unix_seconds'],
    'external_positive_negative_validations':2*len(frontend),
    'maximum_status_sample_gap_seconds':max(b['unix_seconds']-a['unix_seconds'] for a,b in zip(status,status[1:])),
    'secondary_observations':len(peers), 'secondary_in_sync':sum(p['in_sync'] is True for p in peers),
    'secondary_lag_observations':sum(p['in_sync'] is False for p in peers), 'automatic_transfers':transfers,
    'minimum_transfer_margin_seconds':min(t['seconds_before_previous_expiration'] for t in transfers),
    'method':'For each authenticated transfer during the external window, subtract its BIND UTC timestamp from the preceding serial SOA signature expiration. Status synchronization is counted separately from external DNSSEC validity.'}
events = []
decoder = json.JSONDecoder()
for number, line in enumerate((args.input/'node-container.log').read_text().splitlines(), 1):
    for position, character in enumerate(line):
        if character != '{':
            continue
        try:
            event, _ = decoder.raw_decode(line[position:])
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get('event') != 'agentdns.dnssec.signing':
            continue
        if set(event) != {'event','zone','serial','record_count','elapsed_micros'}:
            raise ValueError('unexpected signing diagnostic schema')
        if any(type(event[k]) is not int or event[k] < 0 for k in ('serial','record_count','elapsed_micros')):
            raise ValueError('invalid signing diagnostic number')
        events.append({**event, 'source_line':number})
        break
values = [event['elapsed_micros']/1000 for event in events]
signing = {'input_sha256':inputs['node-container.log'], 'samples':len(events),
    'minimum_ms':min(values), 'median_ms':statistics.median(values), 'maximum_ms':max(values),
    'observations':events, 'scope':'Actual SignedZone::sign_with_keys spans, including denial/signature generation; excludes preceding storage, following writes and consensus. Small sample count is not a stable tail-latency estimate.'}
args.output.mkdir(parents=True, exist_ok=True)
outputs = {'window-metrics.json':window, 'signing-metrics.json':signing}
for name, value in outputs.items():
    path = args.output/name
    if path.exists():
        raise ValueError('refusing to overwrite existing derived evidence: '+name)
    path.write_text(json.dumps(value, indent=2)+'\n')
print(json.dumps({'window':window, 'signing':signing}, indent=2))
