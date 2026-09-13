#!/usr/bin/env python3
"""Read actual Azure container metrics for a bounded acceptance window.

No diagnostic setting is changed and no container exec is attempted. Azure
MemoryUsage is container memory usage in bytes, not a process RSS measurement.
"""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import statistics
import subprocess
import time

REFERENCE = 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-containerinstance-containergroups-metrics'


def summarize(response):
    records = []
    for metric in response.get('value',[]):
        name = metric.get('name',{}).get('value')
        if name not in ('MemoryUsage','CpuUsage'):
            raise ValueError('unexpected Azure metric')
        unit = 'Bytes' if name == 'MemoryUsage' else 'Count'
        if metric.get('unit') != unit:
            raise ValueError('Azure metric unit differs from observed definitions')
        for series in metric.get('timeseries',[]):
            dimensions = series.get('metadatavalues',[])
            containers = [value.get('value') for value in dimensions if value.get('name',{}).get('value','').lower() == 'containername']
            if len(containers) != 1 or not isinstance(containers[0],str) or not containers[0]:
                raise ValueError('per-container metric dimension is missing or ambiguous')
            samples = []
            for point in series.get('data',[]):
                values = {key:point[key] for key in ('minimum','average','maximum') if point.get(key) is not None}
                if any(type(value) not in (int,float) or not math.isfinite(value) or value < 0 for value in values.values()):
                    raise ValueError('invalid measured metric value')
                if values:
                    samples.append({'timestamp':point['timeStamp'],**values})
            averages = [point['average'] for point in samples if 'average' in point]
            minima = [point['minimum'] for point in samples if 'minimum' in point]
            maxima = [point['maximum'] for point in samples if 'maximum' in point]
            records.append({'metric':name,'container':containers[0],'api_unit':unit,
                'semantics':'container memory usage bytes; not process RSS' if name == 'MemoryUsage' else 'CPU usage across cores in millicores; Azure API unit is Count',
                'available_points':len(samples),'returned_points':len(series.get('data',[])),
                'minimum_of_reported_minima':min(minima) if minima else None,
                'maximum_of_reported_maxima':max(maxima) if maxima else None,
                'mean_of_available_1m_averages':statistics.mean(averages) if averages else None,'samples':samples})
    return {'status':'available' if any(row['available_points'] for row in records) else 'unavailable',
        'source':'Azure Monitor platform metrics','metric_interval':response.get('interval'),
        'timespan':response.get('timespan'),'metrics':records,'definition_reference':REFERENCE,
        'boundary':'Control-plane container metrics, not hardware-attested process measurements. Missing points remain missing; no RSS or signing duration is inferred.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resource',required=True)
    parser.add_argument('--start',required=True)
    parser.add_argument('--end',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    start,end = (datetime.fromisoformat(value.replace('Z','+00:00')) for value in (args.start,args.end))
    if start.tzinfo is None or end.tzinfo is None or not 1 <= (end-start).total_seconds() <= 7200:
        parser.error('timezone-qualified positive window of at most two hours required')
    if '/providers/microsoft.containerinstance/containergroups/' not in args.resource.lower() or not args.resource.lower().startswith('/subscriptions/'):
        parser.error('explicit ACI resource ID required')
    args.output.mkdir(parents=True,exist_ok=False)
    command = ['az','monitor','metrics','list','--resource',args.resource,'--metrics','MemoryUsage','CpuUsage',
        '--aggregation','Minimum','Average','Maximum','--dimension','containerName','--interval','PT1M',
        '--start-time',args.start,'--end-time',args.end,'--only-show-errors','--output','json']
    result = subprocess.run(command,capture_output=True,text=True,timeout=60)
    (args.output/'metrics.stdout.json').write_text(result.stdout)
    (args.output/'metrics.stderr.txt').write_text(result.stderr)
    result.check_returncode()
    summary = summarize(json.loads(result.stdout))
    summary.update({'resource_id':args.resource,'queried_unix_seconds':time.time(),'command':command})
    (args.output/'results.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__ == '__main__':
    main()
