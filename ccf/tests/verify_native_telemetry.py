#!/usr/bin/env python3
"""Exercise real C++ bounded transport, parentage and commit outcome filtering.

Run inside the pinned Linux CCF toolchain with the compiled fixture path.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def run(binary, mode, root):
    path=root/(mode+'.sock')
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    listener.bind(str(path));listener.settimeout(.05)
    env={**os.environ,'AGENTDNS_TRACE_SOCKET':str(path)}
    if mode=='disabled':env.pop('AGENTDNS_TRACE_SOCKET')
    process=subprocess.Popen([binary,mode],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10;records=[]
    try:
        while time.monotonic()<deadline:
            try:
                records.append(json.loads(listener.recv(60001)))
                if mode=='valid' and len(records)==1:
                    process.stdin.write(b'\n');process.stdin.flush()
                if mode=='pressure' and len(records)==1:
                    # A real Linux AF_UNIX queue fills while its live receiver
                    # is briefly descheduled; one request has 66 span messages.
                    time.sleep(.01)
            except socket.timeout:
                if process.poll() is not None:break
        stdout,stderr=process.communicate(timeout=1)
        assert process.returncode==0,(mode,process.returncode,stderr.decode())
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=1)
        listener.close()
    for row in records:
        assert row['v']==1 and row['start_unix_nanos']<=row['end_unix_nanos']
        assert 'fixture-sensitive' not in json.dumps(row)
    return records,stdout


def main():
    binary=str(Path(sys.argv[1]).resolve());summary={}
    with tempfile.TemporaryDirectory(prefix='adns-otel-') as directory:
        root=Path(directory)
        for mode in ('disabled','unsampled','rejected','invalid','abandoned','receipt-error','committed-error','bad-parent','overflow','malformed','valid','pressure'):
            rows,_=run(binary,mode,root)
            if mode in ('disabled','unsampled'):assert rows==[]
            elif mode in ('rejected','invalid','abandoned'):
                assert len(rows)==1 and rows[0]['name']=='ccf.request'
                assert 'ccf.transaction_id' not in rows[0]['attributes']
                assert 'dns.zone' not in rows[0]['attributes']
                assert rows[0]['status']=='error'
            else:
                assert rows,(mode,'no records received')
                first=rows[0];attrs=first['attributes']
                assert attrs['ccf.transaction_id']=='2.1' and attrs['ccf.observation_transaction_id']=='2.1'
                assert attrs['dns.zone.serial']==42
                if mode in ('bad-parent','overflow'):
                    assert [x['name'] for x in rows]==['ccf.request','ccf.commit.wait']
                elif mode=='valid':
                    assert len(rows)==6
                    request,application,signature,wait,retry,retrywait=rows
                    assert request['trace_id']=='12345678901234567890123456789012'
                    assert request['parent_span_id']=='1234567890123456'
                    assert application['parent_span_id']==request['span_id']
                    assert signature['parent_span_id']==application['span_id']
                    assert wait['parent_span_id']==request['span_id']
                    assert retry['links']==[{'trace_id':request['trace_id'],'span_id':request['span_id']}]
                    assert retry['attributes']['ccf.transaction_id']=='2.1'
                    assert retry['attributes']['ccf.observation_transaction_id']=='2.2'
                    assert retrywait['parent_span_id']==retry['span_id']
                elif mode=='malformed':assert first['parent_span_id'] is None
                elif mode=='committed-error':
                    assert first['status']=='error' and attrs['http.response.status_code']==403
                    assert attrs['agentdns.outcome']=='committed'
                elif mode=='pressure':
                    assert len(rows)==66,('partial request batch',len(rows))
                    assert rows[-1]['name']=='ccf.commit.wait'
                    assert attrs['agentdns.telemetry.dropped_batches']==0
                elif mode=='receipt-error':
                    assert first['status']=='error' and attrs['agentdns.outcome']=='receipt_error'
                    assert rows[-1]['name']=='ccf.receipt' and rows[-1]['status']=='error'
            summary[mode]={'passed':True,'records':len(rows)}
        # An absent consumer cannot block request or consensus completion.
        started=time.monotonic()
        result=subprocess.run([binary,'stress'],env={**os.environ,'AGENTDNS_TRACE_SOCKET':str(root/'absent.sock')},capture_output=True,timeout=10,check=True)
        seconds,dropped=result.stdout.split();assert int(dropped)>0
        summary['dead-consumer']={'passed':True,'requests':10000,'concurrent_producers':4,
            'request_loop_seconds':float(seconds),'reported_dropped_batches':int(dropped),
            'total_seconds':time.monotonic()-started}
        # A live receiver which permanently stops draining must also leave
        # producers nonblocking and shutdown finite, despite bounded retries.
        stalled=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        stalled.bind(str(root/'stalled.sock'))
        try:
            started=time.monotonic()
            result=subprocess.run([binary,'stress'],env={**os.environ,'AGENTDNS_TRACE_SOCKET':str(root/'stalled.sock')},capture_output=True,timeout=10,check=True)
            seconds,dropped=result.stdout.split();assert int(dropped)>0
            summary['stalled-consumer']={'passed':True,'requests':10000,
                'request_loop_seconds':float(seconds),'reported_dropped_batches':int(dropped),
                'total_seconds':time.monotonic()-started}
        finally:stalled.close()
    print(json.dumps({'status':'passed','cases':summary},indent=2))


if __name__=='__main__':main()
