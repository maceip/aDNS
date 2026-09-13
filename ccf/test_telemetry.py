import contextvars
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from ccf import telemetry
from ccf import host_driver as driver
from opentelemetry.sdk.trace.export import SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest


def native_span():
    now=time.time_ns()
    return {'v':1,'trace_id':'12'*16,'span_id':'34'*8,'parent_span_id':'56'*8,
        'name':'adns.dnssec.sign','kind':'internal','start_unix_nanos':now-1000,
        'end_unix_nanos':now,'status':'ok',
        'attributes':{'dns.zone':'example.test.','dns.zone.serial':42,'dns.record.count':12},
        'links':[{'trace_id':'78'*16,'span_id':'90'*8}]}


def soa_packet(serial=None, flags=0x8400, qtype=6):
    question=b'\x07example\x04test\0'+qtype.to_bytes(2,'big')+b'\0\x01'
    packet=b'\x12\x34'+flags.to_bytes(2,'big')+b'\0\x01'+(1 if serial is not None else 0).to_bytes(2,'big')+bytes(4)+question
    if serial is not None:
        data=b'\xc0\x0c\xc0\x0c'+serial.to_bytes(4,'big')+bytes(16)
        packet+=b'\xc0\x0c\0\x06\0\x01'+bytes(4)+len(data).to_bytes(2,'big')+data
    return packet


@contextmanager
def listener(handler, tls=None):
    stop=threading.Event();errors=[]
    server=socket.socket();server.bind(('127.0.0.1',0));server.listen(4);server.settimeout(.1)
    def run():
        while not stop.is_set():
            try:conn,_=server.accept()
            except socket.timeout:continue
            except OSError:return
            try:
                conn.settimeout(2)
                if tls is not None:conn=tls.wrap_socket(conn,server_side=True)
                with conn:handler(conn,stop)
            except (OSError,ssl.SSLError):pass
            except Exception as error:errors.append(error)
    thread=threading.Thread(target=run,daemon=True);thread.start()
    try:yield server.getsockname()[1],errors
    finally:
        stop.set();server.close();thread.join(timeout=2)


def request(conn):
    data=bytearray()
    while not data.endswith(b'\r\n\r\n'):
        part=conn.recv(1)
        if not part:raise EOFError()
        data.extend(part)
        if len(data)>65536:raise ValueError()
    lines=bytes(data).decode().split('\r\n')
    headers={key.lower():value for key,value in (line.split(': ',1) for line in lines[1:] if ': 'in line)}
    body=bytearray();size=int(headers.get('content-length','0'))
    assert size<=4*1024*1024
    while len(body)<size:
        part=conn.recv(size-len(body))
        if not part:raise EOFError()
        body.extend(part)
    return headers,bytes(body)


class NativeSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdk=telemetry._sdk()
        cls.resource=cls.sdk['Resource']({'service.name':'agentdns-authority'})

    def test_identity_timestamps_parent_and_links_preserved(self):
        value=native_span();span=telemetry.decode_native(json.dumps(value).encode(),self.sdk,self.resource)
        self.assertEqual(span.context.trace_id,int(value['trace_id'],16))
        self.assertEqual(span.context.span_id,int(value['span_id'],16))
        self.assertEqual(span.parent.span_id,int(value['parent_span_id'],16))
        self.assertEqual(span.start_time,value['start_unix_nanos'])
        self.assertEqual(span.end_time,value['end_unix_nanos'])
        self.assertEqual(span.links[0].context.trace_id,int('78'*16,16))
        self.assertEqual(span.resource.attributes['service.name'],'agentdns-authority')

    def test_foreign_fields_types_names_secrets_and_invalid_ids_rejected(self):
        original=native_span()
        variants=[dict(original,body='secret'),dict(original,name='secret'),
            dict(original,status='secret'),dict(original,kind=[]),dict(original,v=True),
            dict(original,trace_id='00'*16),dict(original,span_id='a'*15),
            dict(original,start_unix_nanos=True),dict(original,end_unix_nanos=0),
            dict(original,attributes={'authorization':'secret'}),
            dict(original,attributes={'http.route':'/secret?token=secret'}),
            dict(original,attributes={'http.response.status_code':True}),
            dict(original,attributes={'ccf.transaction_id':'02.3'}),
            dict(original,attributes={'dns.zone.serial':2**32}),
            dict(original,links=[{'trace_id':'12'*16,'span_id':'00'*8}]),
            dict(original,links=original['links']*9)]
        for item in variants:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):telemetry.decode_native(json.dumps(item).encode(),self.sdk,self.resource)
        for data in (b'x'*60001,b'{"v":1,"v":1}',b'{"v":NaN}'):
            with self.assertRaises(ValueError):telemetry.decode_native(data,self.sdk,self.resource)

    def test_endpoint_rejects_credentials_query_redirect_targets_and_remote_plaintext(self):
        self.assertEqual(telemetry.trace_endpoint({}),'http://127.0.0.1:4318/v1/traces')
        self.assertEqual(telemetry.trace_endpoint({'OTEL_EXPORTER_OTLP_ENDPOINT':'https://collector.example/'}),'https://collector.example/v1/traces')
        for endpoint in ['http://collector.example/v1/traces','https://a:b@collector.example/v1/traces',
                         'https://collector.example/v1/traces?token=x','https://collector.example/other']:
            with self.assertRaises(ValueError):telemetry.trace_endpoint({'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT':endpoint})

    def test_link_cache_is_bounded_and_expires(self):
        from unittest.mock import patch
        span=telemetry.decode_native(json.dumps(native_span()).encode(),self.sdk,self.resource)
        cache=telemetry.LinkCache(maximum=3,lifetime=5)
        with patch.object(telemetry.time,'monotonic',return_value=1):
            for i in range(10):cache.put(('work',i),span.context)
            self.assertEqual(len(cache.rows),3);self.assertIsNone(cache.get(('work',0)))
        with patch.object(telemetry.time,'monotonic',return_value=7):self.assertIsNone(cache.get(('work',9)))

    def test_header_protocol_and_resource_configuration_is_bounded_without_secret_errors(self):
        self.assertEqual(telemetry.configured_pairs('Authorization=Bearer%20test%3Da%2Cb,x-org=one'),
            {'authorization':'Bearer test=a,b','x-org':'one'})
        bad=['authorization=secret\r\nInjected=x','authorization=secret%0a','authorization=%0dsecret',
             'x='+('a'*4097),'authorization=secret%ZZ',','.join(f'x{i}=a'for i in range(17))]
        for value in bad:
            with self.assertRaises(ValueError) as failure:telemetry.configured_pairs(value)
            self.assertNotIn('secret',str(failure.exception))
        for config in [{'OTEL_EXPORTER_OTLP_PROTOCOL':'grpc'},
                       {'OTEL_EXPORTER_OTLP_TRACES_PROTOCOL':'http/json'},
                       {'OTEL_EXPORTER_OTLP_HEADERS':'authorization=secret'},
                       {'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT':'https://example.test/v1/traces','OTEL_EXPORTER_OTLP_HEADERS':'host=elsewhere'},
                       {'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT':'https://example.test/v1/traces','OTEL_EXPORTER_OTLP_CERTIFICATE':'false'}]:
            with self.assertRaises(ValueError):telemetry.export_configuration(config)
        self.assertEqual(telemetry.resource_attributes({'OTEL_RESOURCE_ATTRIBUTES':'deployment.environment=test,service.namespace=agentdns,service.instance.id=instance-1'}),
            {'deployment.environment':'test','service.namespace':'agentdns','service.instance.id':'instance-1'})
        for value in ['password=secret','service.name=secret','service.version=secret','service.instance.id=%0asecret']:
            with self.assertRaises(ValueError):telemetry.resource_attributes({'OTEL_RESOURCE_ATTRIBUTES':value})


class ExportTests(unittest.TestCase):
    def test_real_http_protobuf_export_keeps_resources_and_ids_and_sends_no_env_secrets(self):
        captured=[]
        def handle(conn,stop):
            headers,body=request(conn);captured.append((headers,body))
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        with listener(handle) as (port,errors), tempfile.TemporaryDirectory(prefix='adns-otel-') as directory:
            path=Path(directory)/'trace.sock'
            config={'OTEL_EXPORTER_OTLP_ENDPOINT':f'http://127.0.0.1:{port}',
                    'OTEL_SERVICE_NAME':'custom-driver',
                    'OTEL_RESOURCE_ATTRIBUTES':'deployment.environment=test,service.namespace=agentdns,service.instance.id=instance-1',
                    'HTTP_PROXY':'http://secret-canary.invalid'}
            tracing=telemetry.initialize('agentdns-driver',str(path),environ=config)
            try:
                with tracing.span('driver.lifecycle.poll',{'dns.zone':'example.test.'}):pass
                packet=native_span()
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:
                    sender.sendto(json.dumps(packet).encode(),str(path))
                    sender.sendto(json.dumps(dict(packet,body='secret-canary')).encode(),str(path))
                deadline=time.monotonic()+1
                while tracing.received<1 and time.monotonic()<deadline:time.sleep(.005)
                self.assertEqual(tracing.received,1)
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertTrue(tracing.processor.force_flush(timeout_millis=1500))
            finally:tracing.close()
            self.assertFalse(path.exists());self.assertFalse(errors)
        self.assertTrue(captured)
        spans=[];services=set()
        for headers,data in captured:
            self.assertEqual(headers['content-type'],'application/x-protobuf')
            self.assertNotIn('authorization',headers);self.assertNotIn(b'secret-canary',data)
            decoded=ExportTraceServiceRequest.FromString(data)
            for resource in decoded.resource_spans:
                services.update(a.value.string_value for a in resource.resource.attributes if a.key=='service.name')
                attributes={a.key:a.value.string_value for a in resource.resource.attributes}
                self.assertEqual(attributes['service.version'],'0.1.0')
                self.assertEqual(attributes['service.namespace'],'agentdns')
                spans.extend(s for scope in resource.scope_spans for s in scope.spans)
        self.assertEqual(services,{'custom-driver','agentdns-authority'})
        native=next(s for s in spans if s.name=='adns.dnssec.sign')
        self.assertEqual(native.trace_id,bytes.fromhex(packet['trace_id']))
        self.assertEqual(native.start_time_unix_nano,packet['start_unix_nanos'])
        self.assertEqual(native.links[0].span_id,bytes.fromhex('90'*8))

    def test_exception_and_arbitrary_attribute_text_are_not_exported(self):
        memory=InMemorySpanExporter();tracing=telemetry.initialize(exporter=memory,environ={})
        try:
            with self.assertRaises(ValueError):
                with tracing.span('driver.lifecycle.poll',{'authorization':'private-canary','error.type':'private-canary',
                        'http.route':'/private-canary','agentdns.work.kind':'private-canary'}):
                    raise ValueError('private-canary')
            tracing.processor.force_flush(timeout_millis=1000)
            span=memory.get_finished_spans()[0]
            self.assertEqual(dict(span.attributes),{'error.type':'ValueError'})
            self.assertEqual(len(span.events),0)
        finally:tracing.close()

    def test_dead_exporter_queue_is_bounded_and_does_not_block_producers_or_shutdown(self):
        class Stalled(InMemorySpanExporter):
            entered=threading.Event();release=threading.Event()
            def export(self,spans):
                self.entered.set();self.release.wait(timeout=5)
                return SpanExportResult.FAILURE
        exporter=Stalled();tracing=telemetry.initialize(exporter=exporter,environ={})
        try:
            for _ in range(256):
                with tracing.span('driver.lifecycle.poll'):pass
            self.assertTrue(exporter.entered.wait(timeout=1))
            started=time.monotonic()
            for _ in range(telemetry.MAX_QUEUE*2):
                with tracing.span('driver.lifecycle.poll'):pass
            self.assertLess(time.monotonic()-started,1.0)
            self.assertLessEqual(len(tracing.processor._batch_processor._queue),telemetry.MAX_QUEUE)
            started=time.monotonic();tracing.close()
            self.assertLess(time.monotonic()-started,2.2)
        finally:exporter.release.set()

    def test_trickled_export_response_obeys_absolute_deadline(self):
        def trickle(conn,stop):
            request(conn);conn.sendall(b'HTTP/1.1 200 OK\r\nX-Trickle: ')
            while not stop.wait(.04):conn.sendall(b'a')
        with listener(trickle) as (port,_):
            tracing=telemetry.initialize(environ={'OTEL_EXPORTER_OTLP_ENDPOINT':f'http://127.0.0.1:{port}'})
            try:
                started=time.monotonic()
                with tracing.span('driver.lifecycle.poll'):pass
                tracing.processor.force_flush(timeout_millis=1500)
                self.assertLess(time.monotonic()-started,1.7)
            finally:tracing.close()

    def test_disabled_telemetry_needs_no_socket_or_provider(self):
        tracing=telemetry.initialize(receive_socket='/missing/socket',environ={'OTEL_SDK_DISABLED':'true'})
        self.assertIsInstance(tracing,telemetry.NoTelemetry)


class DriverTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='adns-tls-')
        root=Path(cls.temp.name);cls.cert=root/'cert.pem';key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(key),'-out',str(cls.cert),'-subj','/CN=127.0.0.1',
            '-addext','subjectAltName=IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        cls.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.tls.load_cert_chain(cls.cert,key)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_real_tls_slow_headers_cannot_hold_driver_operation_open(self):
        def trickle(conn,stop):
            request(conn);conn.sendall(b'HTTP/1.1 200 OK\r\nX-Trickle: ')
            while not stop.wait(.04):conn.sendall(b'a')
        with listener(trickle,self.tls) as (port,_):
            enclave=driver.Enclave(f'https://127.0.0.1:{port}',str(self.cert),timeout=.25)
            started=time.monotonic()
            with self.assertRaises((OSError,ValueError,RuntimeError,http.client.HTTPException)):
                enclave.post('maintenance',{})
            self.assertLess(time.monotonic()-started,.8)

    def test_actual_https_otlp_headers_custom_ca_precedence_and_no_secret_in_trace_or_errors(self):
        captured=[]
        def authenticated(conn,stop):
            headers,body=request(conn);captured.append((headers,body))
            okay=headers.get('authorization')=='Bearer private-canary' and headers.get('x-scope-orgid')=='native-test'
            status='200 OK'if okay else'401 private-canary'
            conn.sendall(('HTTP/1.1 '+status+'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode())
        with listener(authenticated,self.tls) as (port,errors):
            config={'OTEL_EXPORTER_OTLP_ENDPOINT':f'https://127.0.0.1:{port}',
                'OTEL_EXPORTER_OTLP_HEADERS':'authorization=wrong-canary',
                'OTEL_EXPORTER_OTLP_TRACES_HEADERS':'Authorization=Bearer%20private-canary,x-scope-orgid=native-test',
                'OTEL_EXPORTER_OTLP_CERTIFICATE':'/missing/private-canary',
                'OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE':str(self.cert),
                'OTEL_EXPORTER_OTLP_PROTOCOL':'grpc','OTEL_EXPORTER_OTLP_TRACES_PROTOCOL':'http/protobuf'}
            tracing=telemetry.initialize(environ=config)
            try:
                with tracing.span('driver.lifecycle.poll'):pass
                self.assertTrue(tracing.processor.force_flush(timeout_millis=1500))
            finally:tracing.close()
            self.assertFalse(errors);self.assertEqual(len(captured),1)
            self.assertEqual(captured[0][0]['authorization'],'Bearer private-canary')
            self.assertNotIn(b'private-canary',captured[0][1])
            ExportTraceServiceRequest.FromString(captured[0][1])
            # Wrong trust and wrong hostname must fail before HTTP headers/body.
            for wrong in [dict(config,OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE=None),
                          dict(config,OTEL_EXPORTER_OTLP_ENDPOINT=f'https://localhost:{port}')]:
                if wrong['OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE'] is None:
                    del wrong['OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE'];del wrong['OTEL_EXPORTER_OTLP_CERTIFICATE']
                tracing=telemetry.initialize(environ=wrong)
                try:
                    with self.assertLogs('opentelemetry.exporter.otlp.proto.http.trace_exporter',level='ERROR') as log:
                        with tracing.span('driver.lifecycle.poll'):pass
                        tracing.processor.force_flush(timeout_millis=1500)
                    self.assertNotIn('private-canary','\n'.join(log.output))
                finally:tracing.close()
            self.assertEqual(len(captured),1)

    def test_invalid_config_or_missing_sdk_does_not_disable_transport(self):
        from unittest.mock import patch
        for error in [ImportError('private-canary'),ValueError('private-canary')]:
            with patch.object(driver.diagnostics,'initialize',side_effect=error):
                with self.assertLogs('agentdns-driver',level='ERROR') as log:
                    result=driver.initialize_diagnostics()
            self.assertIsInstance(result,telemetry.NoTelemetry)
            self.assertNotIn('private-canary','\n'.join(log.output))

    def test_commit_gate_and_w3c_parent_propagation_without_body_export(self):
        captured=[];committed=[False]
        def respond(conn,stop):
            headers,body=request(conn);captured.append(headers)
            payload=b'{"status":"committed"}'
            header='committed' if committed[0] else 'pending'
            conn.sendall((f'HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\nx-agentdns-commit-status: {header}\r\nx-agentdns-transaction-id: 2.41\r\nConnection: close\r\n\r\n').encode()+payload)
        memory=InMemorySpanExporter();tracing=telemetry.initialize(exporter=memory,environ={})
        try:
            with listener(respond,self.tls) as (port,errors):
                enclave=driver.Enclave(f'https://127.0.0.1:{port}',str(self.cert),telemetry=tracing)
                with self.assertRaises(RuntimeError):enclave.post('maintenance',{'token':'private-canary'})
                committed[0]=True
                self.assertEqual(enclave.post('maintenance',{}),{'status':'committed'})
            tracing.processor.force_flush(timeout_millis=1000)
            spans=memory.get_finished_spans()
            self.assertFalse(errors);self.assertEqual(len(spans),4)
            self.assertTrue(all(not span.attributes['agentdns.committed'] for span in spans[:2]))
            self.assertTrue(all(span.attributes['agentdns.committed'] for span in spans[2:]))
            self.assertTrue(all('private-canary'not in str(dict(span.attributes)) for span in spans))
            request_span=next(span for span in spans if span.name=='driver.ccf.request')
            self.assertEqual(captured[0]['traceparent'].split('-')[1],f'{request_span.context.trace_id:032x}')
            self.assertEqual(captured[0]['traceparent'].split('-')[2],f'{request_span.context.span_id:016x}')
        finally:tracing.close()

    def test_threadpool_context_is_explicit_and_restored(self):
        from unittest.mock import patch
        marker=contextvars.ContextVar('marker',default='none');marker.set('captured')
        context=contextvars.copy_context();marker.set('caller')
        with patch.object(driver,'exchange',side_effect=lambda *args:marker.get()):
            self.assertEqual(driver.exchange_queued(context,{},None,0),'captured')
        self.assertEqual(marker.get(),'caller')

    def test_dns_diagnostic_metadata_is_bounded_and_never_modifies_packet(self):
        question=b'\x07example\x04test\0'+b'\x00\x06\x00\x01'
        response=b'\x12\x34\x84\0\0\x01\0\x01'+bytes(4)+question
        rdata=b'\xc0\x0c\xc0\x0c'+(42).to_bytes(4,'big')+bytes(16)
        response+=b'\xc0\x0c\x00\x06\x00\x01'+bytes(4)+len(rdata).to_bytes(2,'big')+rdata
        before=bytes(response)
        self.assertEqual(driver.dns_metadata(response),{'dns.zone':'example.test.','dns.zone.serial':42})
        self.assertEqual(response,before)
        for value in [b'',bytes(70000),response[:15],bytes(12)+b'\xc0\x0c']:
            self.assertEqual(driver.dns_metadata(value),{})

    def test_committed_notify_axfr_soa_and_next_signing_are_linked_without_dns_context_fields(self):
        # Transport/correlation unit: this fake CCF gate supplies committed typed
        # results. Live TSIG cryptography remains the separate CCF/BIND suite.
        memory=InMemorySpanExporter()
        with tempfile.TemporaryDirectory(prefix='adns-links-') as directory:
            trace_socket=Path(directory)/'trace.sock'
            tracing=telemetry.initialize(receive_socket=str(trace_socket),exporter=memory,environ={})
            class Gate:
                telemetry=tracing
                reject=False
                posted=[]
                def post(self,path,body,*args,**kwargs):
                    self.posted.append((path,body))
                    if self.reject:raise RuntimeError('uncommitted')
                    if path=='axfr':
                        answer=soa_packet(42)
                        return len(answer).to_bytes(2,'big')+answer
                    return {'status':'committed','secondary':{'last_notified_serial':42,'last_observed_serial':42}}
            gate=Gate()
            def native(value,count):
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:
                    sender.sendto(json.dumps(value).encode(),str(trace_socket))
                deadline=time.monotonic()+1
                while tracing.received<count and time.monotonic()<deadline:time.sleep(.002)
                self.assertEqual(tracing.received,count)
            def exchange(kind,packet,response):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1',0));udp.settimeout(1);received=[]
                    def peer():
                        data,address=udp.recvfrom(65536);received.append(data);udp.sendto(response,address)
                    thread=threading.Thread(target=peer);thread.start()
                    work={'id':('ab'if kind=='notify'else'cd')*16,'endpoint':f'127.0.0.1:{udp.getsockname()[1]}',
                          'kind':kind,'packet_base64url':driver.encode(packet)}
                    try:driver.exchange(work,gate)
                    finally:thread.join(timeout=1)
                    self.assertEqual(received,[packet])
            try:
                first=native_span();first['links']=[];native(first,1)
                exchange('notify',soa_packet(flags=0x2400),soa_packet(flags=0xa400))
                notify_context=tracing.cache.get(('zone_serial','example.test.',42))
                self.assertNotEqual(notify_context.span_id,int(first['span_id'],16))
                query=soa_packet(flags=0,qtype=252)
                left,right=socket.socketpair()
                try:
                    right.sendall(len(query).to_bytes(2,'big')+query);right.shutdown(socket.SHUT_WR)
                    driver.TransferHandler(left,('127.0.0.1',12345),SimpleNamespace(enclave=gate))
                    size=int.from_bytes(driver.exact(right,2,time.monotonic()+1),'big')
                    self.assertEqual(driver.exact(right,size,time.monotonic()+1),soa_packet(42))
                finally:left.close();right.close()
                transfer_context=tracing.cache.get(('zone_serial','example.test.',42))
                self.assertNotEqual(transfer_context.span_id,notify_context.span_id)
                exchange('soa',soa_packet(flags=0),soa_packet(42))
                observed=tracing.cache.get(('observed_zone','example.test.'))
                second=native_span();second.update(trace_id='13'*16,span_id='35'*8,links=[])
                second['attributes']['dns.zone.serial']=43;native(second,2)
                tracing.processor.force_flush(timeout_millis=1000)
                spans=memory.get_finished_spans()
                transferred=next(s for s in spans if s.context.span_id==transfer_context.span_id)
                self.assertIn(notify_context.span_id,[link.context.span_id for link in transferred.links])
                accepted=next(s for s in spans if s.context.span_id==observed.span_id)
                self.assertIn(transfer_context.span_id,[link.context.span_id for link in accepted.links])
                refreshed=next(s for s in spans if s.context.span_id==int('35'*8,16))
                self.assertIn(observed.span_id,[link.context.span_id for link in refreshed.links])
                self.assertEqual(refreshed.resource.attributes['service.name'],'agentdns-authority')
                gate.reject=True
                with self.assertRaises(RuntimeError):exchange('soa',soa_packet(flags=0),soa_packet(99))
                self.assertIsNone(tracing.cache.get(('zone_serial','example.test.',99)))
                self.assertEqual(tracing.cache.get(('observed_zone','example.test.')),observed)
            finally:tracing.close()


if __name__=='__main__':unittest.main()
