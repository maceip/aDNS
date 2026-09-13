#!/usr/bin/env python3
"""Real CCF quorum/recovery through the Python SDK and bounded OTLP/protobuf.

Run in the CCF toolchain with /build/agentdns and pinned requirements-otel.txt
installed. This imports the existing live_smoke scenarios, including their real
governance, stopped peers, killed leader, disk recovery and receipt verification.
Only public trace IDs, transaction IDs and operator-envelope digests are saved;
member keys, TSIG provisioning bodies, ledgers and HTTP bodies stay private.
An optional collector receives the exact protobuf already checked locally.
"""
import argparse
import contextlib
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import telemetry
import live_smoke
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

MAX_BODY=1024*1024
MAX_TOTAL=16*1024*1024
MAX_REQUESTS=4096
TXID=re.compile(r"(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})\Z")


def canonical_txid(value):
    return isinstance(value,str) and TXID.fullmatch(value) and all(int(x)<1<<64 for x in value.split('.'))


class OtlpSink:
    """A single bounded loopback HTTP receiver for the actual SDK exporter."""
    def __init__(self):
        self.payloads=[];self.errors=[];self.total=0;self.lock=threading.Lock()
        owner=self
        def failure(kind):
            with owner.lock:
                if len(owner.errors)<16:owner.errors.append(kind)
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def handle(self):
                try:
                    with telemetry.SocketDeadline(self.connection,time.monotonic()+2):
                        super().handle()
                except (OSError,TimeoutError):
                    failure('ConnectionDeadline')
            def do_POST(self):
                try:
                    with telemetry.SocketDeadline(self.connection,time.monotonic()+2):
                        lengths=self.headers.get_all('Content-Length',[])
                        assert self.path=='/v1/traces' and len(lengths)==1
                        assert lengths[0].isdigit() and 0<int(lengths[0])<=MAX_BODY
                        assert self.headers.get('Content-Type')=='application/x-protobuf'
                        assert self.headers.get('Transfer-Encoding') is None
                        body=self.rfile.read(int(lengths[0]));assert len(body)==int(lengths[0])
                        message=ExportTraceServiceRequest();message.ParseFromString(body)
                        with owner.lock:
                            assert owner.total+len(body)<=MAX_TOTAL and len(owner.payloads)<256
                            owner.total+=len(body);owner.payloads.append(body)
                        self.send_response(200);self.send_header('Content-Length','0')
                        self.send_header('Connection','close');self.end_headers()
                except Exception as error:
                    failure(type(error).__name__)
                    self.close_connection=True
            def log_message(self,*_):pass
        self.server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        self.server.timeout=.2
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.endpoint=f'http://127.0.0.1:{self.server.server_port}/v1/traces'

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        assert not self.thread.is_alive(),'OTLP sink did not stop'


def client_class(records,lock):
    class TracedClient(live_smoke.Client):
        def request(self,method,path,body=None,content_type='application/json'):
            if body is not None and not isinstance(body,bytes):body=json.dumps(body).encode()
            trace_id=secrets.token_hex(16);parent_id=secrets.token_hex(8)
            route=path.split('?',1)[0]
            row={'trace_id':trace_id,'parent_span_id':parent_id,'method':method,
                 'route':route,'port':self.port,'started_unix_ns':time.time_ns()}
            if route=='/app/zone/operator/records' and body is not None:
                row['operator_envelope_sha256']=hashlib.sha256(body).hexdigest()
            with lock:
                assert len(records)<MAX_REQUESTS,'bounded request inventory exceeded'
                records.append(row)
            conn=http.client.HTTPSConnection('127.0.0.1',self.port,context=self.context,timeout=15)
            raw_socket=None;stream=None
            try:
                deadline=time.monotonic()+15
                raw_socket=socket.create_connection(('127.0.0.1',self.port),timeout=15)
                stream=self.context.wrap_socket(raw_socket,server_hostname='127.0.0.1',do_handshake_on_connect=False)
                with telemetry.SocketDeadline(stream,deadline):
                    stream.do_handshake();conn.sock=stream
                    conn.request(method,path,body,{'content-type':content_type,'connection':'close',
                        'traceparent':f'00-{trace_id}-{parent_id}-01'})
                    response=conn.getresponse();payload=response.read(MAX_BODY+1)
                    assert len(payload)<=MAX_BODY,'bounded CCF response exceeded'
                    headers={}
                    for key,value in response.getheaders():
                        key=key.lower()
                        if key in ('x-agentdns-commit-status','x-agentdns-transaction-id'):
                            assert key not in headers,'duplicate CCF commitment header'
                        headers[key]=value
                try:data=json.loads(payload)
                except (ValueError,UnicodeError):data=payload
                row['http_status']=response.status
                row['committed']=headers.get('x-agentdns-commit-status')=='committed'
                for key,value in [('transaction_id',headers.get('x-agentdns-transaction-id')),
                                  ('body_transaction_id',data.get('tx_id') if isinstance(data,dict) else None),
                                  ('body_observation_transaction_id',data.get('observation_tx_id') if isinstance(data,dict) else None)]:
                    if value is not None:
                        assert canonical_txid(value),'noncanonical committed transaction identity'
                        row[key]=value
                return response.status,headers,data
            except Exception as error:
                row['transport_error']=type(error).__name__
                raise
            finally:
                row['ended_unix_ns']=time.time_ns()
                conn.close()
                if stream is not None:stream.close()
                if raw_socket is not None:raw_socket.close()
    return TracedClient


def attributes(values):
    result={}
    for item in values:
        assert item.key not in result,'duplicate OTLP attribute'
        kind=item.value.WhichOneof('value')
        assert kind in ('string_value','int_value','bool_value'),'unexpected OTLP attribute type'
        result[item.key]=getattr(item.value,kind)
    return result


def decode_payloads(payloads):
    rows=[];ids=set()
    for payload in payloads:
        message=ExportTraceServiceRequest();message.ParseFromString(payload)
        for resource in message.resource_spans:
            assert attributes(resource.resource.attributes)=={
                'service.name':'agentdns-authority','service.version':'0.1.0','agentdns.component':'authority'}
            for scope in resource.scope_spans:
                assert scope.scope.name=='agentdns.native'
                for span in scope.spans:
                    identity=(span.trace_id.hex(),span.span_id.hex())
                    assert identity not in ids,'duplicate OTLP span'
                    ids.add(identity)
                    assert len(span.trace_id)==16 and any(span.trace_id) and len(span.span_id)==8 and any(span.span_id)
                    assert (len(span.parent_span_id)==8 and any(span.parent_span_id)) or (
                        span.name=='ccf.request' and not span.parent_span_id)
                    assert span.name in telemetry.NATIVE_NAMES and not span.events and not span.trace_state
                    assert not span.status.message and span.status.code in (0,1,2)
                    assert 0<span.start_time_unix_nano<=span.end_time_unix_nano
                    attrs=attributes(span.attributes)
                    # Reuse the production attribute/type allowlist for the
                    # already decoded native datagram, then check OTLP links.
                    telemetry._attributes(attrs)
                    links=[]
                    for link in span.links:
                        assert not link.attributes and not link.trace_state
                        assert len(link.trace_id)==16 and any(link.trace_id) and len(link.span_id)==8 and any(link.span_id)
                        links.append({'trace_id':link.trace_id.hex(),'span_id':link.span_id.hex()})
                    rows.append({'trace_id':identity[0],'span_id':identity[1],
                        'parent_span_id':span.parent_span_id.hex(),'name':span.name,
                        'kind':span.kind,'start_unix_ns':span.start_time_unix_nano,
                        'end_unix_ns':span.end_time_unix_nano,'status':span.status.code,
                        'attributes':attrs,'links':links})
    assert rows,'no actual OTLP spans received'
    return rows


def verify(records,spans,scenario):
    by_trace={};by_id={}
    for span in spans:
        by_trace.setdefault(span['trace_id'],[]).append(span)
        by_id[(span['trace_id'],span['span_id'])]=span
    proven=[];committed_errors=[];historical=[];lost=[];long_waits=[];rejected=[]
    for request in records:
        children=by_trace.get(request['trace_id'],[])
        roots=[span for span in children if span['name']=='ccf.request']
        if request.get('transport_error'):
            assert all(span['name']=='ccf.request' for span in children),'lost request exported business spans'
            assert all(span['attributes'].get('agentdns.outcome')=='invalid' for span in children)
            if request['port']==8000 and request['route'] in ('/app/zone/operator/records','/app/service/request'):
                lost.append(request['trace_id'])
            continue
        if not request.get('committed'):
            if roots:
                assert len(roots)==1 and len(children)==1,'uncommitted rejection exported business spans'
                attrs=roots[0]['attributes']
                assert roots[0]['status']==2 and attrs['agentdns.outcome'] in ('rejected','invalid')
                assert 'ccf.transaction_id' not in attrs and 'dns.zone' not in attrs
                rejected.append(request['trace_id'])
            continue
        if not request['route'].startswith('/app/'):
            continue
        assert len(roots)==1,('missing/duplicate actual committed request span',request['route'],request['trace_id'])
        root=roots[0];attrs=root['attributes'];tx=request['transaction_id']
        assert root['parent_span_id']==request['parent_span_id'] and root['kind']==2
        assert request['started_unix_ns']<=root['start_unix_ns']<=root['end_unix_ns']<=request['ended_unix_ns']
        assert attrs['http.route']==request['route'][4:] and attrs['http.request.method']==request['method']
        assert attrs['http.response.status_code']==request['http_status']
        assert attrs['ccf.transaction_id']==tx and attrs['agentdns.outcome']=='committed'
        assert attrs['agentdns.telemetry.dropped_batches']==0
        assert root['status']==(2 if request['http_status']>=400 else 1)
        if 'body_transaction_id' in request:assert request['body_transaction_id']==tx
        if 'body_observation_transaction_id' in request:
            assert attrs['ccf.observation_transaction_id']==request['body_observation_transaction_id']
        waits=[span for span in children if span['name']=='ccf.commit.wait']
        assert len(waits)==1 and waits[0]['parent_span_id']==root['span_id'] and waits[0]['status']==1
        if waits[0]['end_unix_ns']-waits[0]['start_unix_ns']>=1_000_000_000:long_waits.append(request['trace_id'])
        for child in children:
            assert root['start_unix_ns']<=child['start_unix_ns']<=child['end_unix_ns']<=root['end_unix_ns']
            if child is not root:
                assert (child['trace_id'],child['parent_span_id']) in by_id,'orphan native child span'
        if request['http_status']==403:
            assert any(span['name']=='adns.auth.grant' and span['status']==2 for span in children)
            committed_errors.append(request['trace_id'])
        if attrs['ccf.transaction_id']!=attrs['ccf.observation_transaction_id'] and root['links']:
            for link in root['links']:
                original=by_id[(link['trace_id'],link['span_id'])]
                assert original['name']=='ccf.request' and original['attributes']['ccf.transaction_id']==tx
                assert original['attributes']['ccf.observation_transaction_id']==tx
                historical.append({'retry_trace_id':request['trace_id'],'original_trace_id':link['trace_id'],'transaction_id':tx})
        proven.append(request['trace_id'])
    assert committed_errors,'real revoked-grant403 did not export committed error semantics'
    assert rejected,'real unauthenticated rejection coverage missing'
    assert historical,'no actual historical transaction SpanLink'
    names={span['name'] for span in spans}
    for name in ('adns.dnssec.sign','ccf.receipt','adns.receipt.claims','adns.auth.signature','adns.storage.stage'):
        assert name in names,('missing real phase',name)
    # The same original signed envelope is rejected under revoked governance,
    # then succeeds after reauthorization and returns the historical result.
    envelopes={}
    for request in records:
        if 'operator_envelope_sha256' in request:
            envelopes.setdefault(request['operator_envelope_sha256'],[]).append(request)
    retry_groups=[group for group in envelopes.values() if any(row.get('http_status')==403 and row.get('committed') for row in group)
                  and sum(row.get('http_status')==200 and row.get('committed') for row in group)>=2]
    assert retry_groups,'same-envelope failed/successful/historical sequence missing'
    if scenario=='quorum':
        assert len(lost)==4,('expected actual killed-leader requests',lost)
        assert len(long_waits)>=10,('missing actual partitioned commit waits',len(long_waits))
    else:assert not lost,'unexpected lost request during disk recovery'
    return {'status':'passed','scenario':scenario,'requests':len(records),'otlp_spans':len(spans),
            'committed_parentage_checks':len(proven),'committed403_trace_ids':committed_errors,
            'historical_links':historical,'killed_leader_no_business_span_trace_ids':lost,
            'rejected_no_business_span_trace_ids':rejected,
            'commit_wait_over_one_second_trace_ids':long_waits,'native_span_names':sorted(names),
            'same_envelope_rejection_then_commit_and_retry':len(retry_groups)}


def forward(payloads,url):
    parsed=urlsplit(url)
    assert parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','otel-collector')
    assert parsed.port==4318 and parsed.path=='/v1/traces' and not parsed.query and not parsed.fragment and not parsed.username
    for body in payloads:
        connection=http.client.HTTPConnection(parsed.hostname,4318,timeout=2)
        stream=None
        try:
            deadline=time.monotonic()+2;connection.connect();stream=connection.sock
            with telemetry.SocketDeadline(stream,deadline):
                connection.request('POST','/v1/traces',body,{'content-type':'application/x-protobuf','connection':'close'})
                response=connection.getresponse();reply=response.read(65537)
                assert response.status==200 and len(reply)<=65536,'collector rejected actual protobuf'
        finally:
            connection.close()
            if stream is not None:stream.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=('quorum','recovery','both'),default='both')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--collector-url',help='Optional exact loopback or Docker-network HTTP OTLP endpoint on4318')
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    initial_client=live_smoke.Client;initial_argv=sys.argv[:]
    old_socket=os.environ.get('AGENTDNS_TRACE_SOCKET')
    summaries=[]
    for scenario in ('quorum','recovery') if args.scenario=='both' else (args.scenario,):
        directory=output/scenario;directory.mkdir()
        sink=OtlpSink();records=[];lock=threading.Lock();handle=None
        started=time.time();live_summary=None
        with tempfile.TemporaryDirectory(prefix='adns-live-otel-',dir='/tmp') as runtime:
            try:
                socket_path=str(Path(runtime)/'spans.sock')
                handle=telemetry.initialize('agentdns-driver',socket_path,
                    environ={'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT':sink.endpoint})
                os.environ['AGENTDNS_TRACE_SOCKET']=socket_path
                live_smoke.Client=client_class(records,lock)
                sys.argv=['live_smoke.py','--'+scenario]
                captured=io.StringIO()
                with contextlib.redirect_stdout(captured):live_smoke.main()
                live_summary=json.loads(captured.getvalue())
                # Native exporter runs every5ms; the original scenario has
                # stopped/reaped every CCF process before this drain/flush.
                time.sleep(.3)
                assert handle.provider.force_flush(timeout_millis=3000),'SDK flush failed'
                assert handle.rejected==0,'receiver rejected real CCF datagrams'
            finally:
                live_smoke.Client=initial_client;sys.argv=initial_argv
                if old_socket is None:os.environ.pop('AGENTDNS_TRACE_SOCKET',None)
                else:os.environ['AGENTDNS_TRACE_SOCKET']=old_socket
                if handle is not None:handle.close()
                sink.close()
                (directory/'requests.json').write_text(json.dumps(records,indent=2)+'\n')
                # These private diagnostics survive a failed scenario/check.
                # A separate allowlist export follows only a verified pass.
                for index,payload in enumerate(sink.payloads):
                    (directory/f'otlp-{index:03d}.protobuf').write_bytes(payload)
        assert not sink.errors,('OTLP receiver errors',sink.errors)
        spans=decode_payloads(sink.payloads)
        (directory/'spans.json').write_text(json.dumps(spans,indent=2)+'\n')
        summary=verify(records,spans,scenario)
        summary.update({'started_unix_seconds':started,'ended_unix_seconds':time.time(),
                        'sdk_native_received':handle.received,'sdk_native_rejected':handle.rejected,
                        'otlp_http_batches':len(sink.payloads),'otlp_http_bytes':sink.total,
                        'platform':'real CCF Virtual consensus/recovery; not native hardware'})
        assert len(spans)==handle.received,'lost spans between receiver and OTLP'
        assert live_summary['status']=='passed'
        live_summary.pop('artifacts',None)
        (directory/'ccf-results.json').write_text(json.dumps(live_summary,indent=2)+'\n')
        if args.collector_url:
            forward(sink.payloads,args.collector_url)
            summary['collector_forwarded_batches']=len(sink.payloads)
        (directory/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        summaries.append(summary)
        print(json.dumps(summary),flush=True)
    result={'status':'passed','binary_sha256':hashlib.sha256(Path('/build/agentdns').read_bytes()).hexdigest(),'scenarios':summaries}
    (output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
