#!/usr/bin/env python3
"""Summarize actual BIND samples and their overlap with the independently measured load."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import statistics

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--memory', type=Path, required=True)
parser.add_argument('--load', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
paths = {'results': args.memory / 'results.json', 'samples': args.memory / 'samples.json', 'load': args.load}
r = json.loads(paths['results'].read_text())
s = json.loads(paths['samples'].read_text())
load = json.loads(paths['load'].read_text())
if len(s) != r['sample_count'] or len(s) != 139 or r['requested_seconds'] != 1380:
    raise ValueError('not the full approved sample window')
if [v['index'] for v in s] != list(range(139)) or any(v['comm'] != 'named' for v in s):
    raise ValueError('sample sequence or process identity mismatch')
gaps = [b['elapsed_seconds'] - a['elapsed_seconds'] for a, b in zip(s, s[1:])]
if any(g <= 0 for g in gaps) or not 1380 <= r['elapsed_seconds'] <= 1395:
    raise ValueError('measurement time sequence mismatch')
def values(name):
    data = [v[name] for v in s]
    return {'first':data[0], 'last':data[-1], 'minimum':min(data), 'maximum':max(data), 'mean':statistics.fmean(data)}
def utc(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()
first, last = s[0]['unix_seconds'], s[-1]['unix_seconds']
load_start, load_end = load['started_unix_seconds'], load['ended_unix_seconds']
result = {
    'input_sha256': {name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in paths.items()},
    'collector_sha256':r['collector_sha256'], 'sample_count':len(s),
    'pid_in_target_container':r['pid_in_target_container'], 'process_start_clock_ticks':r['process_start_clock_ticks'],
    'started_utc':utc(r['started_unix_seconds']), 'ended_utc':utc(r['ended_unix_seconds']),
    'elapsed_seconds':r['elapsed_seconds'], 'maximum_sample_gap_seconds':max(gaps),
    'named_rss_kib':values('rss_kib'), 'named_lifetime_high_water_rss_kib':values('high_water_rss_kib'),
    'cgroup_charged_memory_bytes':values('cgroup_memory_current_bytes'),
    'cgroup_lifetime_peak_memory_bytes':values('cgroup_memory_peak_bytes'),
    'cgroup_event_deltas':{k:s[-1]['cgroup_memory_events'][k]-v for k,v in s[0]['cgroup_memory_events'].items()},
    'collector_cpu_seconds':r['collector_cpu_seconds'],
    'collector_maximum_rss_kib':r['collector_maximum_rss_kib'],
    'maximum_counter_read_seconds':r['maximum_counter_read_seconds'],
    'external_load_overlap':{
        'load_started_utc':utc(load_start), 'load_ended_utc':utc(load_end),
        'first_sample_lead_seconds':load_start-first, 'last_sample_trail_seconds':last-load_end,
        'samples_within_load_window':sum(load_start <= v['unix_seconds'] <= load_end for v in s),
        'full_load_interval_covered':first <= load_start <= load_end <= last,
        'scope':'Compares independently recorded host UTC wall-clock timestamps; sample gaps and per-host monotonic elapsed times are retained separately.'},
    'scope':'Actual named PID1 process RSS in KiB; cgroup charged aggregate is separate and includes collector/cache. Lifetime high-water counters were not reset. This finite sustained observation does not prove leak freedom.'}
with args.output.open('x') as stream:
    json.dump(result, stream, indent=2);stream.write('\n')
print(json.dumps({'output':str(args.output),'sample_count':len(s),'full_load_interval_covered':result['external_load_overlap']['full_load_interval_covered']}))
