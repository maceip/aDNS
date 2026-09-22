"""Client and template boundaries; local TLS fixtures are not hardware evidence."""
import base64
import datetime
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import warnings
from urllib.parse import quote
from unittest import mock
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_aci_template as template
import ccf_control as control
import fetch_capture
import http_limits
import prepare_aci_control as prepare


class HttpBoundaryTests(unittest.TestCase):
    def test_byte_limit_and_total_read_deadline(self):
        response = mock.Mock()
        response.read1.side_effect = lambda size: b'x' * size
        with self.assertRaises(ValueError):
            http_limits.read_bounded(response, 1232, time.monotonic()+1)
        self.assertEqual(response.read1.call_args.args[0], 1233)
        with self.assertRaises(TimeoutError):
            http_limits.read_bounded(response, 1232, time.monotonic()-1)

    def test_absolute_deadline_interrupts_trickling_headers_and_body(self):
        for header in (False, True):
            receiving, sending = socket.socketpair()
            stopped = threading.Event()
            def trickle():
                try:
                    if not header:
                        sending.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n')
                    else:
                        sending.sendall(b'HTTP/1.1 200 OK\r\nX-Trickle: ')
                    while not stopped.wait(.01): sending.sendall(b'x')
                except OSError: pass
            worker = threading.Thread(target=trickle, daemon=True)
            worker.start()
            started = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    with http_limits.SocketDeadline(receiving, started+.08):
                        response = http.client.HTTPResponse(receiving)
                        response.begin()
                        http_limits.read_bounded(response, 1000, started+.08)
                self.assertLess(time.monotonic()-started, 1)
            finally:
                stopped.set();sending.close();receiving.close();worker.join(timeout=1)

    def test_untrusted_capture_decoding_is_bounded_and_canonical(self):
        for value in (None, 42, 'AA=', 'AB', 'x'*(2*1024*1024+1)):
            with self.assertRaises(ValueError): fetch_capture.decode(value)
        self.assertEqual(fetch_capture.decode('AA'), b'\x00')


class CommitmentTests(unittest.TestCase):
    def setUp(self):
        self.client = object.__new__(control.Client)
        self.response = {'http_status':200,'headers':{'x-ms-ccf-transaction-id':'2.9'},'body':None}

    def test_preopen_node_endpoint_and_original_application_tx_id(self):
        self.response['headers'].update({'x-agentdns-transaction-id':'2.5'})
        self.response['body'] = {'tx_id':'2.5'}
        self.client.request = mock.Mock(return_value={'http_status':200,'body':{'status':'Committed','transaction_id':'2.5'}})
        result = self.client.require_committed(self.response)
        self.assertEqual(result['confirmed_ccf_transaction_id'],'2.5')
        self.assertEqual(self.client.request.call_args.args,('GET','/node/tx?transaction_id=2.5'))
        self.assertIn('deadline',self.client.request.call_args.kwargs)

    def test_invalid_mismatched_and_malformed_status_are_not_commitment(self):
        for body in (None, [], {'status':'Committed','transaction_id':'2.10'},
                     {'status':'Invalid','transaction_id':'2.9'}, {'status':'unexpected','transaction_id':'2.9'}):
            self.client.request = mock.Mock(return_value={'http_status':200,'body':body})
            with self.assertRaises(ValueError): self.client.require_committed(self.response)

    def test_noncanonical_txids_and_conflicting_application_identity_are_rejected(self):
        self.client.request = mock.Mock()
        for value in ('2.9&ignored=1','02.9','2.09','2.18446744073709551616',None):
            self.response['headers']['x-ms-ccf-transaction-id'] = value
            with self.assertRaises(ValueError): self.client.require_committed(self.response)
        self.response['headers'] = {'x-agentdns-transaction-id':'2.8'}
        self.response['body'] = {'tx_id':'2.9'}
        with self.assertRaises(ValueError): self.client.require_committed(self.response)
        self.client.request.assert_not_called()

    def test_pending_status_cannot_extend_polling_deadline(self):
        clock = [0]
        def request(*args,**kwargs):
            self.assertEqual(kwargs['deadline'],30)
            clock[0] = 31
            return {'http_status':200,'body':{'status':'Pending','transaction_id':'2.9'}}
        self.client.request = request
        with mock.patch.object(control.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(control.time,'sleep'):
            with self.assertRaises(TimeoutError): self.client.require_committed(self.response)


class PinnedTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.seen = []
        cls.sni = []
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'agentdns control test')])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('agentdns.test')]),critical=False)
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        (cls.directory/'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (cls.directory/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.seen.append(self.path)
                body=b'{"status":"Committed","transaction_id":"2.9"}'
                self.send_response(200)
                self.send_header('Content-Length',str(len(body)))
                self.send_header('x-ms-ccf-transaction-id','2.9')
                if self.path=='/duplicate':self.send_header('x-ms-ccf-transaction-id','2.8')
                self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        cls.server = http.server.HTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cls.directory/'ca.pem',cls.directory/'key.pem')
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.set_servername_callback(lambda sock,name,context:cls.sni.append(name))
        cls.server.socket=ctx.wrap_socket(cls.server.socket,server_side=True)
        cls.worker=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.worker.join(timeout=2);cls.temporary.cleanup()

    def test_numeric_connection_preserves_authenticated_dns_sni(self):
        client=control.Client(f'https://agentdns.test:{self.server.server_port}','127.0.0.1',self.directory/'ca.pem')
        self.assertGreaterEqual(client.context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertEqual(client.context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(client.context.check_hostname)
        result=client.request('GET','/node/state')
        self.assertEqual(result['http_status'],200);self.assertEqual(self.sni[-1],'agentdns.test')
        with self.assertRaises(ValueError):client.request('GET','/duplicate')

    def test_wrong_tls_name_fails_before_http_bytes(self):
        count=len(self.seen)
        client=control.Client(f'https://wrong.test:{self.server.server_port}','127.0.0.1',self.directory/'ca.pem')
        with self.assertRaises(ssl.SSLCertVerificationError):client.request('GET','/must-not-send')
        self.assertEqual(len(self.seen),count)

    def test_legacy_tls_offer_is_rejected_before_http(self):
        context=ssl.create_default_context(cafile=str(self.directory/'ca.pem'))
        # Intentionally offer only TLS1.1 to test the fixture's explicit floor,
        # even when a distribution changes Python/OpenSSL default settings.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',DeprecationWarning)
            context.minimum_version=ssl.TLSVersion.TLSv1_1
            context.maximum_version=ssl.TLSVersion.TLSv1_1
        context.set_ciphers('DEFAULT:@SECLEVEL=0')
        count=len(self.seen)
        with socket.create_connection(('127.0.0.1',self.server.server_port),timeout=2) as raw:
            with self.assertRaises(ssl.SSLError) as error:
                context.wrap_socket(raw,server_hostname='agentdns.test')
        self.assertIn('PROTOCOL_VERSION',str(error.exception).upper())
        self.assertEqual(len(self.seen),count)


class BootstrapTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.directory=Path(cls.temporary.name)
        cls.control=cls.directory/'control'
        with mock.patch.object(sys,'argv',['prepare_aci_control.py',str(cls.control),'--constitution-sha256','ab'*32,'--native-snp']),mock.patch('sys.stdout',new_callable=io.StringIO):prepare.main()

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def test_prepared_files_are_pinned_and_private_files_are_owner_only(self):
        public,summary,standard,raw=template.validated_control(self.control)
        self.assertEqual(len(public),4)
        self.assertEqual(summary['transfer_secret_sha256'],hashlib.sha256(base64.b64decode(standard)).hexdigest())
        for path in (self.control/'private').iterdir():self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertNotIn('PRIVATE KEY',b''.join(public.values()).decode())
        self.assertEqual(json.loads(public['node.json'])['attestation'],prepare.native_attestation_configuration())
        self.assertEqual(json.loads(public['node.json'])['network']['rpc_interfaces']['agentdns-internal']['accepted_endpoints'],prepare.native_internal_endpoints())

    def test_local_virtual_control_omits_native_attestation_but_cannot_deploy_as_aci(self):
        local=self.directory/'local-virtual'
        with mock.patch.object(sys,'argv',['prepare_aci_control.py',str(local),'--constitution-sha256','ab'*32]),mock.patch('sys.stdout',new_callable=io.StringIO):prepare.main()
        self.assertNotIn('attestation',json.loads((local/'public/node.json').read_text()))
        with self.assertRaisesRegex(ValueError,'explicit SNP collateral'):
            template.validated_control(local)

    def test_changed_manifest_input_and_mismatched_transfer_pair_are_rejected(self):
        node=self.control/'public/node.json';original=node.read_bytes()
        try:
            node.write_bytes(original+b' ')
            with self.assertRaisesRegex(ValueError,'pinned manifest'):template.validated_control(self.control)
        finally:node.write_bytes(original)
        key=self.control/'private/transfer-key.b64';original=key.read_bytes()
        try:
            key.write_bytes(base64.b64encode(bytes(32))+b'\n')
            with self.assertRaisesRegex(ValueError,'do not agree'):template.validated_control(self.control)
        finally:key.write_bytes(original)

    def test_public_template_contains_only_secure_parameter_references(self):
        output=self.directory/'template'
        argv=['build_aci_template.py','--control',str(self.control),'--output',str(output),
              '--primary-image','example.azurecr.io/agentdns@sha256:'+'01'*32,
              '--secondary-image','example.azurecr.io/secondary@sha256:'+'02'*32,
              '--pull-identity','/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/agentdns-test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agentdns-test']
        with mock.patch.object(sys,'argv',argv),mock.patch('sys.stdout',new_callable=io.StringIO):template.main()
        public=(output/'ccf.template.json').read_text();parameters=json.loads((output/'ccf.parameters.json').read_text())
        standard=parameters['parameters']['transferKeyB64']['value']
        provision=json.loads(parameters['parameters']['transferKeyJson']['value'])
        self.assertNotIn(standard,public);self.assertNotIn(provision['secret_base64url'],public);self.assertNotIn('PRIVATE KEY',public)
        config=json.loads(public)
        self.assertEqual(config['parameters']['transferKeyB64']['type'],'secureString')
        self.assertEqual((output/'ccf.parameters.json').stat().st_mode & 0o777,0o600)
        self.assertEqual(config['resources'][0]['properties']['containers'][1]['properties']['environmentVariables'][0]['secureValue'],"[parameters('transferKeyB64')]")
        properties=config['resources'][0]['properties']
        self.assertEqual(properties['containers'][0]['properties']['environmentVariables'],template.OTEL_DISABLED_ENVIRONMENT)
        self.assertEqual(json.loads((output/'otel-env-rules.json').read_text()),[template.OTEL_DISABLED_RULE])
        self.assertFalse(json.loads((output/'otel-public-summary.json').read_text())['trace_export_enabled'])
        self.assertEqual(properties['ipAddress']['ports'],[
            {'port':8000,'protocol':'TCP'}, {'port':5353,'protocol':'TCP'}, {'port':53,'protocol':'UDP'}])
        self.assertEqual(properties['containers'][1]['properties']['ports'],[{'port':53,'protocol':'UDP'}])

    def otel_fixture(self,directory):
        key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc)
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'OTLP CA fixture')])
        certificate=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(321).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        ca=directory/'ca.pem';ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        header='Basic '+base64.b64encode(b'agentdns:fixture-password-for-bounded-template-test').decode()
        secret={'endpoint':'https://20.166.33.141:4318','header_name':'Authorization','header_value':header,
                'OTEL_EXPORTER_OTLP_HEADERS':'authorization='+quote(header,safe='')}
        path=directory/'secret.json';template.write_output(path,json.dumps(secret),0o600)
        labels=dict(zip(template.OTEL_LABEL_KEYS,('native-validation','agentdns','fixture-run')))
        return ca,path,secret,labels

    def test_optional_otel_preserves_bootstrap_and_separates_secret_from_public_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);ca,secret_path,secret,labels=self.otel_fixture(directory);output=directory/'output'
            original=(self.control/'public/manifest.json').read_bytes()
            argv=['build_aci_template.py','--control',str(self.control),'--output',str(output),
                '--primary-image','example.azurecr.io/agentdns@sha256:'+'01'*32,
                '--secondary-image','example.azurecr.io/secondary@sha256:'+'02'*32,
                '--pull-identity','/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/agentdns-test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agentdns-test',
                '--otel-endpoint',secret['endpoint'],'--otel-public-ca',str(ca),'--otel-secret-file',str(secret_path),
                '--otel-deployment-environment',labels['deployment.environment'],'--otel-service-namespace',labels['service.namespace'],
                '--otel-service-instance',labels['service.instance.id']]
            with mock.patch.object(sys,'argv',argv),mock.patch('sys.stdout',new_callable=io.StringIO):template.main()
            public=(output/'ccf.template.json').read_text();built=json.loads(public)
            private=json.loads((output/'ccf.parameters.json').read_text())
            rules=(output/'otel-env-rules.json').read_text()
            self.assertNotIn(secret['header_value'],public+rules)
            self.assertNotIn(secret['OTEL_EXPORTER_OTLP_HEADERS'],public+rules)
            self.assertEqual(private['parameters'][template.OTEL_HEADER_PARAMETER]['value'],secret['OTEL_EXPORTER_OTLP_HEADERS'])
            self.assertEqual(built['parameters'][template.OTEL_HEADER_PARAMETER],{'type':'secureString'})
            props=built['resources'][0]['properties'];volumes={v['name']:v for v in props['volumes']}
            self.assertEqual(base64.b64decode(volumes['public-config']['secret']['manifest.json']),original)
            self.assertEqual((self.control/'public/manifest.json').read_bytes(),original)
            self.assertEqual(base64.b64decode(volumes['otel-public-ca']['secret']['exporter-ca.pem']),ca.read_bytes())
            self.assertIn({'name':'otel-public-ca','mountPath':'/otel','readOnly':True},props['containers'][0]['properties']['volumeMounts'])
            env=props['containers'][0]['properties']['environmentVariables']
            self.assertIn({'name':'OTEL_EXPORTER_OTLP_HEADERS','secureValue':"[parameters('otelExporterHeaders')]"},env)
            self.assertRegex('OTEL_EXPORTER_OTLP_HEADERS='+secret['OTEL_EXPORTER_OTLP_HEADERS'],template.OTEL_HEADER_ENV_PATTERN)
            self.assertEqual((output/'ccf.parameters.json').stat().st_mode&0o777,0o600)

    def test_otel_private_configuration_rejects_wrong_endpoint_auth_and_permissions_without_values(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);ca,path,secret,labels=self.otel_fixture(directory)
            environment,_,header,_=template.load_otel_settings(secret['endpoint'],ca,path,labels)
            self.assertEqual(environment['OTEL_EXPORTER_OTLP_PROTOCOL'],'http/protobuf')
            self.assertEqual(header,secret['OTEL_EXPORTER_OTLP_HEADERS'])
            for changes in ({'endpoint':'https://attacker.test:4318'}, {'header_value':'Bearer fixture-sensitive'},
                            {'OTEL_EXPORTER_OTLP_HEADERS':secret['OTEL_EXPORTER_OTLP_HEADERS']+',x-extra=fixture-sensitive'},
                            {'header_value':'Basic '+base64.b64encode(b'user:bad\npassword').decode()},
                            {'header_name':'Cookie'}):
                template.write_output(path,json.dumps(dict(secret,**changes)),0o600)
                with self.assertRaises(ValueError) as rejected:template.load_otel_settings(secret['endpoint'],ca,path,labels)
                self.assertNotIn('fixture-sensitive',str(rejected.exception));self.assertNotIn(secret['header_value'],str(rejected.exception))
            template.write_output(path,json.dumps(secret),0o600);path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'invalid private'):template.load_otel_settings(secret['endpoint'],ca,path,labels)

    def test_otel_endpoint_labels_and_public_ca_are_strict(self):
        for endpoint in ('https://example.test', 'https://example.test:443',
                         'https://example.test/_ops/telemetry/adns-authority',
                         'https://example.test:443/_ops/telemetry/adns-authority'):
            self.assertEqual(template.validate_otel_endpoint(endpoint),endpoint)
        for endpoint in ('http://127.0.0.1:4318','https://user:pass@example.test:4318','https://example.test:4318/path',
                         'https://example.test:4318?token=private','https://example.test:0',
                         'https://example.test/_ops/telemetry/a%2Fb','https://example.test/_ops/telemetry/../other',
                         'https://example.test/_ops/telemetry/authority/v1/traces','https://example.test/_ops/telemetry/authority/'):
            with self.assertRaises(ValueError):template.validate_otel_endpoint(endpoint)
        with self.assertRaises(ValueError):template.otel_environment('https://20.166.33.141:4318',{'extra':'credential'})
        for body in (b'not a certificate',b'-----BEGIN PRIVATE KEY-----'):
            with self.assertRaises(ValueError):template.validate_otel_ca(body)

    def test_bounded_bearer_secret_is_private_and_uses_exact_scoped_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            ca,path,secret,labels=self.otel_fixture(Path(temp))
            endpoint='https://grafana.example.test/_ops/telemetry/adns-authority'
            value='Bearer '+'fixture-source-token-'+'a'*48
            secret.update(endpoint=endpoint,header_value=value,OTEL_EXPORTER_OTLP_HEADERS='authorization='+quote(value,safe=''))
            template.write_output(path,json.dumps(secret),0o600)
            environment,_,header,summary=template.load_otel_settings(endpoint,ca,path,labels)
            self.assertEqual(environment['OTEL_EXPORTER_OTLP_ENDPOINT'],endpoint)
            self.assertEqual(header,secret['OTEL_EXPORTER_OTLP_HEADERS'])
            self.assertRegex('OTEL_EXPORTER_OTLP_HEADERS='+header,template.OTEL_HEADER_ENV_PATTERN)
            self.assertNotIn(value,json.dumps(summary)+json.dumps(template.otel_policy_rules(environment)))
            for value in ('Bearer short','Bearer '+'a'*257,'Bearer '+'a'*32+'\n','Bearer '+'a'*32+',extra=1','Digest '+'a'*32):
                changed=dict(secret,header_value=value,OTEL_EXPORTER_OTLP_HEADERS='authorization='+quote(value,safe=''))
                template.write_output(path,json.dumps(changed),0o600)
                with self.assertRaises(ValueError):template.load_otel_settings(endpoint,ca,path,labels)

if __name__=='__main__':unittest.main()
