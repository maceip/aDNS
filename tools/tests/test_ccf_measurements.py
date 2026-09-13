"""Measurement boundary tests, not real backend performance samples."""
import importlib.util
import datetime
import io
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
measure=load('measure_ccf_request');signing=load('summarize_signing_metrics')

class MeasurementTests(unittest.TestCase):
    def test_http_success_requires_exact_global_commit_identity(self):
        headers={'x-agentdns-commit-status':'committed','x-agentdns-transaction-id':'2.5'}
        result={'status':'committed','tx_id':'2.5'}
        self.assertEqual(measure.committed(200,headers,result),'2.5')
        for status,h,r in [(200,{},result),(200,headers,{'status':'pending','tx_id':'2.5'}),(200,headers,{'status':'committed','tx_id':'2.6'}),(503,headers,result)]:
            with self.assertRaises(ValueError):measure.committed(status,h,r)
        for body in (None, [], 'committed'):
            with self.assertRaises(ValueError):measure.committed(200,headers,body)
        for txid in ('02.5','2.05','2.5&ignored=1','2.18446744073709551616','2.5\n'):
            with self.assertRaises(ValueError):
                measure.committed(200,{**headers,'x-agentdns-transaction-id':txid},{'status':'committed','tx_id':txid})
            with self.assertRaises(ValueError):measure.committed(200,{**headers,'x-ms-ccf-transaction-id':txid},result)
        self.assertEqual(measure.committed(200,{**headers,'x-ms-ccf-transaction-id':'3.99'},result),'2.5')

    def test_duplicate_nonfinite_and_nonobject_json_rejected(self):
        for raw in (b'[]',b'null',b'{"status":"pending","status":"committed"}',b'{"nested":{"a":1,"a":2}}',b'{"bad":NaN}'):
            with self.assertRaises(ValueError):measure.strict_object(raw)

    def test_actual_result_preserved_only_after_exact_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); envelope=root/'signed.json';output=root/'result.json'
            envelope.write_text(json.dumps({'action':{'operation':'register','grant_id':'fixture','request_id':'fixture-register'}}))
            result={'status':'committed','tx_id':'2.5','registration_id':'reg-fixture','lease_expires_at':42,'contributions':['public-record']}
            response=(200,{'x-agentdns-commit-status':'committed','x-agentdns-transaction-id':'2.5'},result,1.25)
            argv=['measure_ccf_request.py','--url','https://127.0.0.1:8000','--cacert',str(root/'ca.pem'),'--envelope',str(envelope),'--output',str(output)]
            with mock.patch.object(sys,'argv',argv),mock.patch.object(measure.ssl,'create_default_context'),mock.patch.object(measure,'exchange',side_effect=[response,response]),mock.patch('sys.stdout',new_callable=io.StringIO):
                measure.main()
            self.assertEqual(json.loads(output.read_text())['committed_result'],result)
            output.unlink()
            changed=(*response[:2],{**result,'registration_id':'reg-other'},response[3])
            with mock.patch.object(sys,'argv',argv),mock.patch.object(measure.ssl,'create_default_context'),mock.patch.object(measure,'exchange',side_effect=[response,changed]):
                with self.assertRaisesRegex(ValueError,'reconciliation'):measure.main()
            self.assertFalse(output.exists())

    def test_only_exact_signing_diagnostic_events_are_measured(self):
        raw='CCF prefix {"event":"agentdns.dnssec.signing","zone":"example.test.","serial":7,"record_count":257,"elapsed_micros":12500}\n{"latency_ms":99}\n'
        events=signing.parse_events(raw,'test-only.log');self.assertEqual(len(events),1)
        summary=signing.summarize(events);self.assertEqual(summary['p50_ms'],12.5);self.assertEqual(summary['samples'],1)
        with self.assertRaises(ValueError):signing.summarize([])
        with self.assertRaises(ValueError):signing.parse_events(raw.replace('12500','true'),'test-only.log')


class MeasurementTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();root=Path(cls.temporary.name)
        key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'local measurement test')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
              .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.DNSName('agentdns.test')]),critical=False)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        cls.server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.server_context.load_cert_chain(root/'cert.pem',root/'key.pem')
        cls.client_context=ssl.create_default_context(cafile=str(root/'cert.pem'))
        cls.seen=[];cls.sni=[]
        cls.server_context.set_servername_callback(lambda sock,name,context:cls.sni.append(name))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def exchange_with_fixture(self,prefix,trickle=False,host='127.0.0.1',connect_ip=None):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(2)
        port=listener.getsockname()[1];stopped=threading.Event()
        def serve():
            try:
                stream,_=listener.accept()
                with self.server_context.wrap_socket(stream,server_side=True) as tls:
                    self.seen.append(tls.recv(8192));tls.sendall(prefix)
                    if trickle:
                        while not stopped.wait(.01):tls.sendall(b'x')
            except (OSError,ssl.SSLError):pass
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        try:
            with mock.patch.object(measure,'REQUEST_SECONDS',.25):
                return measure.exchange(host,port,self.client_context,'GET','/fixture',connect_ip=connect_ip)
        finally:
            stopped.set();listener.close();worker.join(timeout=2)

    def test_real_tls_header_and_body_trickle_hit_absolute_deadline(self):
        for prefix in (b'HTTP/1.1 200 OK\r\nX-Trickle: ',b'HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n'):
            started=time.monotonic()
            with self.assertRaises(TimeoutError):self.exchange_with_fixture(prefix,trickle=True)
            self.assertLess(time.monotonic()-started,2)

    def test_duplicate_commitment_headers_and_oversized_body_rejected(self):
        prefix=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-agentdns-commit-status: pending\r\nX-AgentDNS-Commit-Status: committed\r\n\r\n{}'
        with self.assertRaisesRegex(ValueError,'duplicate'):self.exchange_with_fixture(prefix)
        prefix=b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxxx'
        with mock.patch.object(measure,'MAX_BYTES',2):
            with self.assertRaisesRegex(ValueError,'byte bound'):self.exchange_with_fixture(prefix)

    def test_numeric_override_preserves_dns_sni_host_and_certificate_checks(self):
        response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        result=self.exchange_with_fixture(response,host='agentdns.test',connect_ip='127.0.0.1')
        self.assertEqual(result[0],200);self.assertEqual(self.sni[-1],'agentdns.test')
        self.assertIn(b'Host: agentdns.test:',self.seen[-1])
        previous=len(self.seen)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.exchange_with_fixture(response,host='wrong.test',connect_ip='127.0.0.1')
        self.assertEqual(len(self.seen),previous)
        with mock.patch.object(measure.socket,'create_connection') as connect:
            with self.assertRaisesRegex(ValueError,'numeric --connect-ip'):
                measure.exchange('agentdns.test',443,self.client_context,'GET','/')
        connect.assert_not_called()

if __name__=='__main__':unittest.main()
