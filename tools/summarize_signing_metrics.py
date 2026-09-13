#!/usr/bin/env python3
"""Summarize actual signing spans emitted by CCF; never infer from HTTP time."""
import argparse
import json
import math
from pathlib import Path
import statistics

FIELDS = {'event', 'zone', 'serial', 'record_count', 'elapsed_micros'}


def parse_events(text, source):
    events = []
    decoder = json.JSONDecoder()
    for number, line in enumerate(text.splitlines(), 1):
        for position, character in enumerate(line):
            if character != '{':
                continue
            try:
                event, _ = decoder.raw_decode(line[position:])
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get('event') != 'agentdns.dnssec.signing':
                continue
            if set(event) != FIELDS or not isinstance(event['zone'], str):
                raise ValueError('unexpected signing diagnostic schema')
            for field in ['serial', 'record_count', 'elapsed_micros']:
                if type(event[field]) is not int or event[field] < 0:
                    raise ValueError('invalid signing diagnostic value')
            events.append({**event, 'source_log': source, 'source_line': number})
            break
    return events


def summarize(events):
    if not events:
        raise ValueError('no actual signing diagnostic spans found')
    times = sorted(event['elapsed_micros'] / 1000 for event in events)
    return {'source': 'actual-agentdns.dnssec.signing-diagnostics', 'samples': len(events),
            'scope': 'SignedZone::sign_with_keys including denial/signature generation; excludes preceding storage reads, following writes and CCF consensus',
            'minimum_ms': min(times), 'p50_ms': statistics.median(times),
            'p99_ms': times[math.ceil(len(times) * .99) - 1], 'maximum_ms': max(times),
            'observations': events, 'proof_limit': 'Measured duration only; no commitment or hardware provenance is inferred from a diagnostic line.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    events = [event for source in args.log for event in parse_events(source.read_text(), source.name)]
    result = summarize(events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
