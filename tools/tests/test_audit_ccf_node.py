"""Bootstrap transport tests; mocked quotes are never hardware acceptance."""
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import http.server
import ssl
import socket
import threading
import time
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('audit_ccf_node',Path(__file__).resolve().parents[1]/'audit_ccf_node.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class BootstrapTests(unittest.TestCase):
    def test_changed_peer_rejected_before_any_http_request(self):
        connection=mock.Mock();connection.sock.getpeercert.return_value=b'changed-peer'
        with mock.patch.object(audit.http.client,'HTTPSConnection',return_value=connection), mock.patch.object(audit,'connect_unhandshaken',return_value=connection.sock):
            with self.assertRaisesRegex(ValueError,'TLS peer changed'):
                audit.public_get('127.0.0.1',8000,'/node/network',expected_peer=b'audited-peer')
        connection.request.assert_not_called();connection.close.assert_called_once()

    def test_matching_peer_allows_only_public_get_and_bounded_response(self):
        connection=mock.Mock();connection.sock.getpeercert.return_value=b'audited-peer'
        response=mock.Mock(status=200);response.read1.side_effect=[b'{"public":true}',b''];connection.getresponse.return_value=response
        with mock.patch.object(audit.http.client,'HTTPSConnection',return_value=connection), mock.patch.object(audit,'connect_unhandshaken',return_value=connection.sock):
            body,peer=audit.public_get('127.0.0.1',8000,'/node/network',expected_peer=b'audited-peer')
        self.assertEqual(body,b'{"public":true}');self.assertEqual(peer,b'audited-peer')
        connection.request.assert_called_once_with('GET','/node/network',headers={'Accept':'application/json'})
        response.read1.side_effect=[b'x'*(audit.MAX_BYTES+1)]
        with mock.patch.object(audit.http.client,'HTTPSConnection',return_value=connection), mock.patch.object(audit,'connect_unhandshaken',return_value=connection.sock):
            with self.assertRaisesRegex(ValueError,'too large'):
                audit.public_get('127.0.0.1',8000,'/node/quotes/self')

    def test_tls_handshake_shares_the_absolute_bootstrap_deadline(self):
        listener=socket.create_server(('127.0.0.1',0))
        finished=threading.Event()
        def stall():
            with listener.accept()[0] as peer:
                peer.settimeout(2)
                peer.recv(65536)  # ClientHello, deliberately no ServerHello.
                finished.wait(2)
        thread=threading.Thread(target=stall);thread.start()
        try:
            with mock.patch.object(audit,'BOOTSTRAP_DEADLINE_SECONDS',0.35):
                started=time.monotonic()
                with self.assertRaises(OSError):
                    audit.public_get('127.0.0.1',listener.getsockname()[1],'/node/quotes/self')
                self.assertLess(time.monotonic()-started,1.2)
        finally:
            finished.set();listener.close();thread.join()

    def test_trickled_headers_and_body_cannot_hold_bootstrap_open(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory)/'cert.pem', Path(directory)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                '-nodes','-subj','/CN=local-bootstrap-test','-days','1','-keyout',str(key),'-out',str(cert)],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            phase=['headers']
            class Slow(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):
                    try:
                        prefix=b'HTTP/1.1 200 OK\r\nX-Trickle: ' if phase[0]=='headers' else b'HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n'
                        self.connection.sendall(prefix)
                        for _ in range(30):
                            self.connection.sendall(b'x');time.sleep(0.06)
                    except OSError:pass
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Slow)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                with mock.patch.object(audit,'BOOTSTRAP_DEADLINE_SECONDS',0.35):
                    for value in ('headers','body'):
                        phase[0]=value;started=time.monotonic()
                        with self.assertRaises((OSError,audit.http.client.HTTPException)):
                            audit.public_get('127.0.0.1',server.server_address[1],'/node/quotes/self')
                        self.assertLess(time.monotonic()-started,1.2)
            finally:
                server.shutdown();server.server_close();thread.join()

    def test_failed_native_audit_never_fetches_or_trusts_service_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments=['audit_ccf_node.py','--url','https://127.0.0.1:8000','--policy',directory+'/policy.json','--output',directory+'/output']
            with mock.patch.object(sys,'argv',arguments),mock.patch.object(audit,'public_get',return_value=(b'{}',b'untrusted-peer')) as get,mock.patch.object(audit.subprocess,'run',side_effect=subprocess.CalledProcessError(1,'native-audit')):
                with self.assertRaises(subprocess.CalledProcessError):audit.main()
            get.assert_called_once_with('127.0.0.1',8000,'/node/quotes/self')
            self.assertFalse((Path(directory)/'output/service_cert.pem').exists())

if __name__=='__main__':unittest.main()
