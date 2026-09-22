#!/usr/bin/env python3
"""Bounded, diagnostic-only OTel spans and an allowlisted native span receiver.

The pinned SDK performs OTLP HTTP/protobuf encoding and batching. Transport has
an absolute deadline and ignores proxy/auth environment variables. Diagnostics
never authorize actions or establish commitment. Native span IDs/times survive
the local Unix datagram handoff; arbitrary text and request bodies cannot enter.
"""
import argparse
from collections import OrderedDict
from contextlib import contextmanager
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import threading
import time
from urllib.parse import unquote, urlsplit

MAX_DATAGRAM = 60000
MAX_QUEUE = 2048
MAX_BATCH = 256
EXPORT_SECONDS = 1.0
MAX_LINKS = 8
NATIVE_NAMES = frozenset(('ccf.request', 'ccf.commit.wait', 'ccf.receipt',
    'adns.application', 'adns.request.parse', 'adns.auth.signature',
    'adns.auth.idempotency', 'adns.auth.nonce', 'adns.auth.grant',
    'adns.attest.appraise', 'adns.attest.cose', 'adns.attest.amd_chain',
    'adns.attest.snp_report', 'adns.attest.uvm', 'adns.attest.key_binding',
    'adns.admission', 'adns.dnssec.sign', 'adns.storage.stage', 'adns.read',
    'adns.maintenance', 'adns.transfer', 'adns.secondary.requests',
    'adns.secondary.response', 'adns.dns.query', 'adns.transfer.provision',
    'adns.receipt.claims'))
_APP_ROUTES = ('/service/nonce','/service/register','/service/renew','/service/deregister',
    '/service/registration','/service/request','/zone/acme-challenge',
    '/zone/operator/records','/zone/status','/governance/ksk-receipt','/dns-query',
    '/internal/maintenance','/internal/secondary/requests','/internal/secondary/response',
    '/internal/axfr','/internal/udp','/internal/transfer-key')
ROUTES = frozenset(_APP_ROUTES + tuple('/app'+route for route in _APP_ROUTES) + ('/node/state',))
STRING_ENUMS = {'http.request.method': frozenset(('GET', 'POST', 'DELETE')),
    'agentdns.outcome': frozenset(('committed', 'rejected', 'invalid', 'receipt_error'))}
INTEGER_ATTRIBUTES = {'http.response.status_code': (100,599),
    'dns.zone.serial': (0,2**32-1), 'dns.record.count': (0,2**31-1),
    'agentdns.telemetry.dropped_batches': (0,2**63-1)}
TX_ATTRIBUTES = frozenset(('ccf.transaction_id', 'ccf.observation_transaction_id'))
ERROR_TYPES = frozenset(('OSError','TimeoutError','Timeout','ValueError','RuntimeError',
    'EOFError','HTTPException','SSLError','ConnectionError','RemoteDisconnected',
    'IncompleteRead','BrokenPipeError','ConnectionResetError','ConnectionRefusedError'))
DRIVER_NAMES = frozenset(('driver.ccf.request','driver.ccf.commit_wait','driver.lifecycle.poll',
    'driver.secondary.requests','driver.secondary.exchange','driver.secondary.response',
    'driver.dns.axfr','driver.dns.udp'))


class SocketDeadline:
    """Interrupt TLS handshakes and buffered header reads at an absolute time."""
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.timer = stream, deadline, None
        self.expired = threading.Event()

    def __enter__(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('absolute socket deadline expired')
        self.stream.settimeout(remaining)
        def expire():
            self.expired.set()
            try: self.stream.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.timer = threading.Timer(remaining, expire)
        self.timer.daemon = True
        self.timer.start()
        return self

    def __exit__(self, *_):
        self.timer.cancel()
        self.timer.join(timeout=.1)
        if self.expired.is_set() or time.monotonic()>=self.deadline:
            raise TimeoutError('absolute socket deadline expired') from None


def read_bounded(response, maximum, deadline):
    data = bytearray()
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('absolute HTTP deadline expired')
        block = response.read1(min(65536, maximum+1-len(data)))
        if not block:
            return bytes(data)
        data.extend(block)
        if len(data) > maximum:
            raise ValueError('HTTP response exceeds bound')


def trace_endpoint(environ):
    value = (environ['OTEL_EXPORTER_OTLP_TRACES_ENDPOINT'] if 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT' in environ
        else environ.get('OTEL_EXPORTER_OTLP_ENDPOINT','http://127.0.0.1:4318').rstrip('/')+'/v1/traces')
    if not isinstance(value,str):raise ValueError('invalid OTLP endpoint type')
    parsed = urlsplit(value)
    if (len(value)>2048 or parsed.scheme not in ('http','https') or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or re.fullmatch(r'(?:/_ops/telemetry/[a-z][a-z0-9-]{0,39})?/v1/traces',parsed.path) is None
            or not 1 <= (parsed.port if parsed.port is not None else 443) <= 65535):
        raise ValueError('OTLP endpoint must be a credential-free HTTP(S) trace URL with an optional scoped gateway prefix')
    if parsed.scheme == 'http':
        try: loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError: loopback = parsed.hostname == 'localhost'
        if not loopback:
            raise ValueError('unencrypted OTLP export is restricted to loopback')
    return value


def configured_pairs(raw):
    """SDK-style comma-separated percent-decoded pairs, without logging input."""
    if (not isinstance(raw,str) or len(raw.encode('utf-8'))>4096 or len(raw.split(','))>16
            or any(ord(char)<32 or ord(char)>126 for char in raw)):
        raise ValueError('telemetry configuration pairs exceed bound')
    values={}
    for item in raw.split(','):
        if not item.strip():continue
        if '='not in item or re.search(r'%(?![0-9A-Fa-f]{2})',item):
            raise ValueError('invalid telemetry configuration pair')
        key,value=item.split('=',1)
        key,value=unquote(key,errors='strict'),unquote(value,errors='strict')
        if any(ord(char)<32 or ord(char)>126 for char in key+value):
            raise ValueError('invalid decoded telemetry configuration characters')
        key,value=key.strip().lower(),value.strip()
        if not key or len(key)>64 or len(value)>2048 or any(ord(char)<32 or ord(char)>126 for char in key+value):
            raise ValueError('invalid telemetry configuration characters')
        values[key]=value
    if sum(len(key)+len(value)+4 for key,value in values.items())>4096:
        raise ValueError('decoded telemetry configuration exceeds bound')
    return values


def export_configuration(environ):
    endpoint=trace_endpoint(environ)
    protocol=environ.get('OTEL_EXPORTER_OTLP_TRACES_PROTOCOL',environ.get('OTEL_EXPORTER_OTLP_PROTOCOL','http/protobuf'))
    if protocol!='http/protobuf':raise ValueError('only OTLP HTTP/protobuf is supported')
    headers=configured_pairs(environ.get('OTEL_EXPORTER_OTLP_TRACES_HEADERS',environ.get('OTEL_EXPORTER_OTLP_HEADERS','')))
    forbidden={'host','content-type','content-length','connection','cookie','set-cookie',
               'proxy-authorization','transfer-encoding','te','upgrade','content-encoding'}
    for key in headers:
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+",key) or key in forbidden:
            raise ValueError('unsupported OTLP transport header')
    certificate=environ.get('OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE',environ.get('OTEL_EXPORTER_OTLP_CERTIFICATE'))
    if any(environ.get(name) for name in ('OTEL_EXPORTER_OTLP_CLIENT_KEY','OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE',
               'OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY','OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE')):
        raise ValueError('client certificates are not supported; use bounded TLS authorization headers')
    secure=urlsplit(endpoint).scheme=='https'
    if (headers or certificate is not None) and not secure:
        raise ValueError('OTLP authorization headers and custom trust require TLS')
    context=ssl.create_default_context() if secure else None
    if certificate is not None:
        path=Path(certificate)
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
            raise ValueError('OTLP CA must be a bounded absolute regular file')
        with path.open('rb') as stream:data=stream.read(1024*1024+1)
        if len(data)>1024*1024 or b'PRIVATE KEY' in data:
            raise ValueError('invalid public OTLP CA data')
        context=ssl.create_default_context(cadata=data.decode('ascii'))
    if context is not None:context.set_alpn_protocols(['http/1.1'])
    return endpoint,headers,context


def resource_attributes(environ):
    values=configured_pairs(environ.get('OTEL_RESOURCE_ATTRIBUTES',''))
    allowed={'deployment.environment','service.namespace','service.instance.id'}
    if any(key not in allowed or not re.fullmatch('[a-zA-Z0-9_.:/-]{1,128}',value) for key,value in values.items()):
        raise ValueError('unsupported or invalid telemetry resource attribute')
    return values


def _sdk():
    # Import lazily so wire/transport tests do not need optional tracing packages.
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http import Compression
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider, ReadableSpan, SpanLimits
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.util.instrumentation import InstrumentationScope
    import requests
    return locals()


def _processor(sdk, endpoint, exporter=None, headers=None, tls_context=None):
    requests = sdk['requests']
    headers=dict(headers or {})
    class BoundedSession(requests.Session):
        def __init__(self):
            super().__init__()
            self.trust_env = False

        def post(self, url, data, verify=True, timeout=EXPORT_SECONDS, cert=None, **_):
            result = requests.Response()
            # Headers and trust are captured from validated configuration only.
            # No redirect, proxy, cookie or arbitrary response text is accepted.
            result.status_code, result.reason = 503, 'bounded export failed'
            if url != endpoint or cert is not None or len(data)>4*1024*1024:
                return result
            parsed = urlsplit(endpoint)
            duration = min(EXPORT_SECONDS, max(0, timeout))
            if duration <= 0:
                return result
            deadline = time.monotonic()+duration
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or (443 if parsed.scheme=='https' else 80), timeout=duration)
            raw = None
            try:
                raw = socket.create_connection((conn.host, conn.port), timeout=duration)
                if parsed.scheme == 'https':
                    secured = tls_context.wrap_socket(raw, server_hostname=conn.host, do_handshake_on_connect=False)
                    raw = secured
                    with SocketDeadline(secured, deadline): secured.do_handshake()
                conn.sock = raw
                with SocketDeadline(raw, deadline):
                    conn.request('POST',parsed.path,data,dict(headers,**{'Content-Type':'application/x-protobuf','Connection':'close'}))
                    response = conn.getresponse()
                    read_bounded(response,65536,deadline)
                    result.status_code = response.status if not 300<=response.status<400 else 400
                    result.reason = 'HTTP '+str(result.status_code)
            except (OSError,ValueError,http.client.HTTPException):
                # A response object avoids requests' unbounded/stale-timeout
                # reconnect path. The SDK retries only within its own budget.
                result.status_code, result.reason = 400, 'bounded export failed'
            finally:
                conn.close()
                if raw is not None:
                    raw.close()
            return result
    class BoundedBatch(sdk['BatchSpanProcessor']):
        def shutdown(self):
            # Pinned SDK1.44 public wrapper has no timeout argument. Its internal
            # BatchProcessor supports this explicit bound (covered by tests).
            self._batch_processor.shutdown(timeout_millis=1500)
    if exporter is None:
        exporter = sdk['OTLPSpanExporter'](endpoint=endpoint,
            headers={'Content-Type':'application/x-protobuf'}, timeout=EXPORT_SECONDS,
            compression=sdk['Compression'].NoCompression, certificate_file=True,
            session=BoundedSession())
    return BoundedBatch(exporter,max_queue_size=MAX_QUEUE,max_export_batch_size=MAX_BATCH,
        schedule_delay_millis=1000,export_timeout_millis=1000)


def _hex_id(value, length):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{'+str(length)+'}',value) or int(value,16)==0:
        raise ValueError('invalid span identity')
    return int(value,16)


def _zone(value):
    return (isinstance(value,str) and len(value)<=255 and value.endswith('.')
        and all(re.fullmatch('[a-z0-9_-]{1,63}',label) for label in value[:-1].split('.')))


def _attributes(values):
    if not isinstance(values,dict) or len(values)>16:
        raise ValueError('attribute map exceeds bound')
    for key,value in values.items():
        if key in INTEGER_ATTRIBUTES:
            low,high = INTEGER_ATTRIBUTES[key]
            good = type(value) is int and low<=value<=high
        elif key in STRING_ENUMS:
            good = isinstance(value,str) and value in STRING_ENUMS[key]
        elif key == 'http.route': good = isinstance(value,str) and value in ROUTES
        elif key in TX_ATTRIBUTES:
            good = (isinstance(value,str) and bool(re.fullmatch(r'(0|[1-9][0-9]{0,19})\.(0|[1-9][0-9]{0,19})',value))
                and all(int(part)<2**64 for part in value.split('.')))
        elif key == 'dns.zone': good = _zone(value)
        else: good = False
        if not good:
            raise ValueError('attribute is not an allowed typed value')
    return values


def _driver_attributes(values):
    safe = {}
    for key,value in values.items():
        valid = False
        if key in ('http.route','http.request.method','http.response.status_code','ccf.transaction_id','dns.zone','dns.zone.serial'):
            try: _attributes({key:value});valid=True
            except ValueError: pass
        elif key in ('agentdns.committed','agentdns.rejected'): valid=type(value) is bool
        elif key=='agentdns.work.kind': valid=value in ('soa','notify')
        elif key=='agentdns.work.id': valid=isinstance(value,str) and bool(re.fullmatch('[0-9a-f]{32}',value))
        elif key in ('agentdns.queue.depth','agentdns.queue.age_ms','agentdns.transfer.bytes','agentdns.transfer.frames'):
            valid=type(value) is int and 0<=value<2**63
        elif key=='network.transport': valid=value in ('tcp','udp')
        elif key=='error.type': valid=isinstance(value,str) and value in ERROR_TYPES
        if valid: safe[key]=value
        if len(safe)==16: break
    return safe


def decode_native(data, sdk, resource):
    if not isinstance(data,bytes) or len(data)>MAX_DATAGRAM:
        raise ValueError('native span datagram exceeds bound')
    def object_pairs(pairs):
        result = {}
        for key,value in pairs:
            if key in result: raise ValueError('duplicate native span field')
            result[key] = value
        return result
    value = json.loads(data,object_pairs_hook=object_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    fields = {'v','trace_id','span_id','parent_span_id','name','kind','start_unix_nanos','end_unix_nanos','status','attributes','links'}
    if not isinstance(value,dict) or set(value)!=fields or type(value['v']) is not int or value['v']!=1:
        raise ValueError('native span schema mismatch')
    if not isinstance(value['name'],str) or value['name'] not in NATIVE_NAMES:
        raise ValueError('unknown native operation')
    kinds = {'internal':'INTERNAL','server':'SERVER','client':'CLIENT','producer':'PRODUCER','consumer':'CONSUMER'}
    statuses = {'unset':'UNSET','ok':'OK','error':'ERROR'}
    if not isinstance(value['kind'],str) or not isinstance(value['status'],str) or value['kind'] not in kinds or value['status'] not in statuses:
        raise ValueError('unknown span enum')
    start,end = value['start_unix_nanos'],value['end_unix_nanos']
    if type(start) is not int or type(end) is not int or not 0<start<=end<2**63 or end-start>3600*10**9:
        raise ValueError('span time outside bounds')
    trace = sdk['trace']
    trace_id = _hex_id(value['trace_id'],32)
    context = trace.SpanContext(trace_id,_hex_id(value['span_id'],16),False,trace.TraceFlags(1))
    parent = None if value['parent_span_id'] is None else trace.SpanContext(trace_id,_hex_id(value['parent_span_id'],16),False,trace.TraceFlags(1))
    if not isinstance(value['links'],list) or len(value['links'])>MAX_LINKS:
        raise ValueError('links exceed bound')
    links = []
    for item in value['links']:
        if not isinstance(item,dict) or set(item)!= {'trace_id','span_id'}:
            raise ValueError('invalid span link')
        linked = trace.SpanContext(_hex_id(item['trace_id'],32),_hex_id(item['span_id'],16),False,trace.TraceFlags(1))
        links.append(trace.Link(linked))
    return sdk['ReadableSpan'](name=value['name'],context=context,parent=parent,resource=resource,
        attributes=_attributes(value['attributes']),links=links,
        kind=getattr(trace.SpanKind,kinds[value['kind']]),
        status=trace.Status(getattr(trace.StatusCode,statuses[value['status']])),
        start_time=start,end_time=end,instrumentation_scope=sdk['InstrumentationScope']('agentdns.native','1'))


class LinkCache:
    def __init__(self, maximum=256, lifetime=600):
        self.maximum,self.lifetime = maximum,lifetime
        self.rows,self.lock = OrderedDict(),threading.Lock()

    def put(self, key, context):
        if context is None or not context.is_valid:
            return
        with self.lock:
            self.rows.pop(key,None)
            self.rows[key] = (time.monotonic(),context)
            while len(self.rows)>self.maximum: self.rows.popitem(last=False)

    def get(self, key):
        with self.lock:
            found = self.rows.get(key)
            if found is None: return None
            if time.monotonic()-found[0]>self.lifetime:
                del self.rows[key]
                return None
            return found[1]


class Telemetry:
    def __init__(self, service_name='agentdns-driver', receive_socket=None, *, exporter=None, environ=None):
        self.sdk = _sdk()
        env = os.environ if environ is None else environ
        self.component = 'authority' if service_name=='agentdns-authority' else 'driver'
        configured = service_name if self.component=='authority' else env.get('OTEL_SERVICE_NAME',service_name)
        if not re.fullmatch('[a-zA-Z0-9_.-]{1,128}',configured): raise ValueError('invalid service name')
        resources=resource_attributes(env)
        self.resource = self.sdk['Resource'](dict(resources,**{'service.name':configured,'service.version':'0.1.0','agentdns.component':self.component}))
        self.native_resource = self.sdk['Resource'](dict(resources,**{'service.name':'agentdns-authority','service.version':'0.1.0','agentdns.component':'authority'}))
        endpoint,headers,tls_context=export_configuration(env)
        self.processor = _processor(self.sdk,endpoint,exporter,headers,tls_context)
        self.provider = self.sdk['TracerProvider'](resource=self.resource,shutdown_on_exit=False,
            span_limits=self.sdk['SpanLimits'](max_attributes=16,max_events=0,max_links=8,max_attribute_length=255))
        self.provider.add_span_processor(self.processor)
        self.tracer = self.provider.get_tracer('agentdns.'+self.component,'1')
        self.cache = LinkCache()
        self.stop = threading.Event()
        self.socket,self.thread,self.socket_path = None,None,None
        self.received,self.rejected = 0,0
        if receive_socket is not None:
            try: self._receiver(Path(receive_socket))
            except BaseException:
                self.close()
                raise

    def _receiver(self,path):
        # Existing endpoints are never silently replaced. Supervisor owns a
        # private runtime directory; permissions also exclude other local UIDs.
        if (len(str(path).encode())>100 or not path.is_absolute() or not path.parent.is_dir()
                or path.parent.stat().st_mode&0o022 or path.exists() or path.is_symlink()):
            raise ValueError('invalid or existing telemetry socket path')
        self.socket = socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.socket.bind(str(path));path.chmod(0o600)
        self.socket.settimeout(.25)
        self.socket_path = path
        self.socket_identity = path.stat().st_ino
        def receive():
            while not self.stop.is_set():
                try: data = self.socket.recv(MAX_DATAGRAM+1)
                except socket.timeout: continue
                except OSError: return
                try:
                    span = decode_native(data,self.sdk,self.native_resource)
                    attributes = span.attributes or {}
                    if span.name=='adns.dnssec.sign' and 'dns.zone' in attributes:
                        observed=self.cache.get(('observed_zone',attributes['dns.zone']))
                        if observed is not None and len(span.links)<MAX_LINKS:
                            # A link to the last actual authenticated observation
                            # describes asynchronous context; it is not a parent
                            # or a claim that this new execution has committed.
                            span=self.sdk['ReadableSpan'](name=span.name,context=span.context,parent=span.parent,
                                resource=span.resource,attributes=span.attributes,events=span.events,
                                links=tuple(span.links)+(self.sdk['trace'].Link(observed),),kind=span.kind,
                                status=span.status,start_time=span.start_time,end_time=span.end_time,
                                instrumentation_scope=span.instrumentation_scope)
                    self.processor.on_end(span)
                    self.received += 1
                    if span.name in ('adns.dnssec.sign','ccf.request') and 'dns.zone' in attributes and 'dns.zone.serial' in attributes:
                        self.cache.put(('zone_serial',attributes['dns.zone'],attributes['dns.zone.serial']),span.context)
                except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
                    self.rejected += 1
        self.thread = threading.Thread(target=receive,name='agentdns-native-spans',daemon=True)
        self.thread.start()

    @contextmanager
    def span(self, name, attributes=None, links=(), kind='INTERNAL'):
        if name not in DRIVER_NAMES:
            yield None
            return
        safe = _driver_attributes(attributes or {})
        linked = [self.sdk['trace'].Link(context) for context in list(links)[:MAX_LINKS] if context is not None and context.is_valid]
        with self.tracer.start_as_current_span(name,attributes=safe,links=linked,
                kind=getattr(self.sdk['trace'].SpanKind,kind),record_exception=False,set_status_on_exception=False) as span:
            try: yield span
            except BaseException as error:
                span.set_attribute('error.type',type(error).__name__ if type(error).__name__ in ERROR_TYPES else 'Error')
                span.set_status(self.sdk['trace'].StatusCode.ERROR)
                raise

    def traceparent(self):
        context = self.sdk['trace'].get_current_span().get_span_context()
        if not context.is_valid: return None
        return f'00-{context.trace_id:032x}-{context.span_id:016x}-{context.trace_flags:02x}'

    def close(self):
        self.stop.set()
        if self.socket is not None: self.socket.close()
        if self.thread is not None: self.thread.join(timeout=.5)
        self.provider.shutdown()
        if self.socket_path is not None:
            try:
                metadata = self.socket_path.lstat()
                if stat.S_ISSOCK(metadata.st_mode) and metadata.st_ino==self.socket_identity:
                    self.socket_path.unlink()
            except FileNotFoundError: pass


class NoTelemetry:
    cache = LinkCache()
    @contextmanager
    def span(self,*_,**__): yield None
    def traceparent(self): return None
    def close(self): pass


def initialize(service_name='agentdns-driver',receive_socket=None,**kwargs):
    env = kwargs.get('environ',os.environ)
    if env.get('OTEL_SDK_DISABLED','false').lower()=='true': return NoTelemetry()
    return Telemetry(service_name,receive_socket,**kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket',required=True)
    args = parser.parse_args()
    handle = initialize('agentdns-authority',args.socket)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stopped.set())
    signal.signal(signal.SIGINT,lambda *_:stopped.set())
    try: stopped.wait()
    finally: handle.close()


if __name__=='__main__': main()
