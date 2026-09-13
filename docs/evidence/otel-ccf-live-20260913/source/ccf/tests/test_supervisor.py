import hashlib
import datetime
import http.server
import ipaddress
import socket
import select
import ssl
import threading
import time
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

spec=importlib.util.spec_from_file_location("supervisor",pathlib.Path(__file__).resolve().parents[1]/"run.py")
supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temporary.name)
        self.state=self.root/"state";self.state.mkdir()
        self.member=self.root/"member.pem";self.member.write_text("public member certificate")
        self.encryption=self.root/"encryption.pem";self.encryption.write_text("public encryption key")
        self.constitution=self.root/"constitution.js";self.constitution.write_text("trusted consortium constitution")
        self.config=self.root/"node.json"
        self.config.write_text(json.dumps({"command":{"type":"Start","start":{"constitution_files":[str(self.constitution)],"members":[{"certificate_file":str(self.member),"encryption_public_key_file":str(self.encryption)}]}}}))
        self.files=[self.config,self.member,self.encryption,self.constitution]
        self.manifest=self.root/"manifest.json"
        self.manifest.write_text(json.dumps({str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in self.files}))
        self.digest=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
    def tearDown(self):self.temporary.cleanup()
    def freeze(self):return supervisor.pinned_configuration(self.config,self.manifest,self.digest,self.state)
    def test_verified_bootstrap_is_frozen_before_input_can_change(self):
        path,config=self.freeze();frozen=pathlib.Path(config["command"]["start"]["members"][0]["certificate_file"])
        self.member.write_text("replacement attacker certificate")
        self.assertEqual(frozen.read_text(),"public member certificate")
        self.assertEqual(stat.S_IMODE(frozen.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode),0o700)
    def test_tampered_file_manifest_and_missing_member_rejected(self):
        with self.assertRaises(ValueError):supervisor.pinned_configuration(self.config,self.manifest,"0"*64,self.state)
        self.member.write_text("tampered")
        with self.assertRaises(ValueError):self.freeze()
        mapping=json.loads(self.manifest.read_text());del mapping[str(self.member)]
        self.manifest.write_text(json.dumps(mapping));self.digest=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.freeze()
    def test_duplicate_manifest_key_rejected(self):
        key=json.dumps(str(self.config));digest=json.dumps(hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.manifest.write_text("{"+key+":"+digest+","+key+":"+digest+"}")
        self.digest=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.freeze()
    def test_confidential_readonly_secret_volume_and_write_permissions(self):
        secret=self.root/"secret.json";body=b'{"key_name":"key.test.","secret_base64url":"opaque","zones":["test."]}'
        secret.write_bytes(body);secret.chmod(0o444)
        self.assertEqual(supervisor.load_transfer_secret(secret),body)
        secret.chmod(0o666)
        with self.assertRaises(ValueError):supervisor.load_transfer_secret(secret)
        secret.chmod(0o600);link=self.root/"link";link.symlink_to(secret)
        with self.assertRaises(OSError):supervisor.load_transfer_secret(link)
        fifo=self.root/"fifo";os.mkfifo(fifo)
        with self.assertRaises(ValueError):supervisor.load_transfer_secret(fifo)
    def test_child_environment_does_not_inherit_secret_values(self):
        with patch.dict(os.environ,{"AZURE_TOKEN":"must-not-reach-CCF-logs","TSIG_SECRET":"private","CCF_PLATFORM_OVERRIDE":"Virtual","UVM_SECURITY_CONTEXT_DIR":"/security-context"}):
            env=supervisor.runtime_environment()
        self.assertNotIn("AZURE_TOKEN",env);self.assertNotIn("TSIG_SECRET",env);self.assertNotIn("CCF_PLATFORM_OVERRIDE",env)
        self.assertEqual(env["UVM_SECURITY_CONTEXT_DIR"],"/security-context")

    def test_provisioning_requires_object_and_matching_committed_transaction(self):
        headers={"x-agentdns-commit-status":"committed","x-agentdns-transaction-id":"2.9"}
        for raw in (b'[]',b'null',b'42',b'"string"',b'{"status":"committed","status":"pending"}'):
            with patch.object(supervisor,"bounded_http",return_value=(200,headers,raw)):
                with self.assertRaisesRegex(RuntimeError,"invalid TSIG provisioning response"):
                    supervisor.provision_transfer_secret("127.0.0.1:8001",self.member,b'{}')
        for identity in ("2.8","02.9","2.18446744073709551616",None):
            raw=json.dumps({"status":"committed","tx_id":identity}).encode()
            with patch.object(supervisor,"bounded_http",return_value=(200,headers,raw)):
                with self.assertRaisesRegex(RuntimeError,"global commit"):
                    supervisor.provision_transfer_secret("127.0.0.1:8001",self.member,b'{}')
        with patch.object(supervisor,"bounded_http",return_value=(200,headers,b'{"status":"committed","tx_id":"2.9"}')):
            self.assertTrue(supervisor.provision_transfer_secret("127.0.0.1:8001",self.member,b'{}'))
        for raw in (b'{"error":"NOT_FOUND: governed transfer key"}',b'{"error":{"code":"FrontendNotOpen"}}'):
            with patch.object(supervisor,"bounded_http",return_value=(404,{},raw)):
                self.assertFalse(supervisor.provision_transfer_secret("127.0.0.1:8001",self.member,b'{}'))
        with patch.object(supervisor,"bounded_http",side_effect=TimeoutError):
            self.assertFalse(supervisor.provision_transfer_secret("127.0.0.1:8001",self.member,b'{}'))

    def test_exporter_credentials_never_enter_ccf_environment(self):
        with patch.dict(os.environ,{"OTEL_EXPORTER_OTLP_HEADERS":"authorization=fixture-sensitive",
             "OTEL_SERVICE_NAME":"test-driver","AGENTDNS_TRACE_SOCKET":"/untrusted.sock",
             "PYTHONPATH":"/untrusted/imports",
             "OTEL_SDK_DISABLED":"false"}):
            node,driver,directory=supervisor.telemetry_environments(self.state)
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS",node)
        self.assertNotIn("OTEL_SERVICE_NAME",node)
        self.assertNotIn("PYTHONPATH",node)
        self.assertEqual(driver["PYTHONPATH"],"/opt/agentdns/python")
        self.assertEqual(driver["OTEL_EXPORTER_OTLP_HEADERS"],"authorization=fixture-sensitive")
        self.assertEqual(driver["OTEL_SERVICE_NAME"],"test-driver")
        self.assertEqual(node["AGENTDNS_TRACE_SOCKET"],driver["AGENTDNS_TRACE_SOCKET"])
        self.assertTrue(pathlib.Path(node["AGENTDNS_TRACE_SOCKET"]).is_relative_to(self.state))
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        self.assertNotEqual(node["AGENTDNS_TRACE_SOCKET"],"/untrusted.sock")

    def test_disabled_or_unavailable_tracing_does_not_prevent_startup(self):
        with patch.dict(os.environ,{"OTEL_SDK_DISABLED":"true"}):
            node,driver,directory=supervisor.telemetry_environments(self.state)
        self.assertIsNone(directory);self.assertNotIn("AGENTDNS_TRACE_SOCKET",node)
        self.assertNotIn("AGENTDNS_TRACE_SOCKET",driver)
        with patch.dict(os.environ,{"OTEL_SDK_DISABLED":"false"}),patch.object(supervisor.tempfile,"mkdtemp",side_effect=OSError):
            node,driver,directory=supervisor.telemetry_environments(self.state)
        self.assertIsNone(directory);self.assertNotIn("AGENTDNS_TRACE_SOCKET",node)


class SupervisorSocketRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="adns-sock-",dir="/tmp")
        self.directory=pathlib.Path(self.temporary.name);self.path=str(self.directory/"spans.sock")
        metadata=self.directory.stat();self.identity=(metadata.st_dev,metadata.st_ino)
        self.children=[]

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:child.kill()
            child.wait(timeout=3)
            child.stdout.close();child.stderr.close()
        self.directory.chmod(0o700)
        self.temporary.cleanup()

    def start_driver(self):
        child=subprocess.Popen([sys.executable,"-c",
            "import socket,sys,time; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); "
            "s.bind(sys.argv[1]); print('ready',flush=True); time.sleep(30)",self.path],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.children.append(child)
        self.assertTrue(select.select([child.stdout],[],[],3)[0],"driver did not become ready")
        self.assertEqual(child.stdout.readline(),"ready\n")
        return child

    def retire(self,child):
        return supervisor.retire_trace_socket(child,self.path,self.directory,self.identity)

    def test_actual_crash_leaves_socket_and_reaped_child_can_restart(self):
        child=self.start_driver()
        self.assertFalse(self.retire(child))
        self.assertTrue(pathlib.Path(self.path).exists())
        child.kill();child.wait(timeout=3)
        self.assertTrue(pathlib.Path(self.path).exists(),"crash must leave the stale fixture")
        self.assertTrue(self.retire(child))
        self.assertFalse(pathlib.Path(self.path).exists())
        replacement=self.start_driver()
        self.assertFalse(self.retire(replacement))
        self.assertTrue(pathlib.Path(self.path).exists())

    def test_active_replacement_listener_is_preserved_after_old_child_death(self):
        old=self.start_driver();old.kill();old.wait(timeout=3)
        os.unlink(self.path)
        replacement=self.start_driver()
        self.assertFalse(self.retire(old))
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:
            client.connect(self.path)
        self.assertIsNone(replacement.poll())

    def test_regular_file_symlink_and_wrong_configured_path_are_never_removed(self):
        child=self.start_driver();child.kill();child.wait(timeout=3)
        self.assertFalse(supervisor.retire_trace_socket(child,self.path+".other",self.directory,self.identity))
        os.unlink(self.path)
        path=pathlib.Path(self.path);path.write_text("preserve unexpected file")
        self.assertFalse(self.retire(child));self.assertEqual(path.read_text(),"preserve unexpected file")
        path.unlink();target=self.directory/"target";target.write_text("preserve target")
        path.symlink_to(target)
        self.assertFalse(self.retire(child));self.assertTrue(path.is_symlink())
        self.assertEqual(target.read_text(),"preserve target")

    def test_nonprivate_replaced_or_wrong_owner_parent_is_preserved(self):
        child=self.start_driver();child.kill();child.wait(timeout=3)
        self.directory.chmod(0o755)
        self.assertFalse(self.retire(child));self.assertTrue(pathlib.Path(self.path).exists())
        self.directory.chmod(0o700)
        with patch.object(supervisor.os,"getuid",return_value=os.getuid()+1):
            self.assertFalse(self.retire(child))
        self.assertFalse(supervisor.retire_trace_socket(child,self.path,self.directory,(0,0)))
        self.assertTrue(pathlib.Path(self.path).exists())

    def test_socket_path_limit_matches_receiver(self):
        # The portable receiver accepts at most 100 encoded bytes, even where
        # the local OS has a longer sockaddr_un limit.
        prefix=pathlib.Path("/tmp")/("x"*80)
        directory=prefix/"telemetry-12345678"
        self.assertGreater(len(os.fsencode(str(directory/"spans.sock"))),100)
        with patch.dict(os.environ,{"OTEL_SDK_DISABLED":"false"}), \
             patch.object(supervisor.tempfile,"mkdtemp",return_value=str(directory)), \
             patch.object(pathlib.Path,"rmdir") as remove:
            node,driver,created=supervisor.telemetry_environments(self.directory)
        self.assertIsNone(created);remove.assert_called_once()
        self.assertNotIn("AGENTDNS_TRACE_SOCKET",node);self.assertNotIn("AGENTDNS_TRACE_SOCKET",driver)


class SupervisorTlsBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();root=pathlib.Path(cls.temporary.name)
        cls.certificate=root/"cert.pem";private=root/"key.pem"
        key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc)
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,"loopback supervisor test")])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(123)
            .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),critical=False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        cls.certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    if self.path in ("/header-trickle","/body-trickle"):
                        first=b'HTTP/1.1 200 OK\r\nX-Trickle: ' if self.path=="/header-trickle" else b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n'
                        self.request.sendall(first)
                        for _ in range(200):
                            time.sleep(.01);self.request.sendall(b'x')
                    else:
                        payload=b'x'*65537 if self.path=="/oversized" else b'ok'
                        self.send_response(200);self.send_header("Content-Length",str(len(payload)))
                        if self.path=="/duplicate":
                            self.send_header("x-agentdns-commit-status","committed");self.send_header("x-agentdns-commit-status","pending")
                        self.end_headers();self.wfile.write(payload)
                except OSError:pass
            def log_message(self,*_):pass
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cls.certificate,private)
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.worker=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.worker.start()
        cls.address=f'127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.worker.join(timeout=2);cls.temporary.cleanup()

    def test_real_tls_trickling_headers_and_body_have_one_absolute_deadline(self):
        for path in ("/header-trickle","/body-trickle"):
            started=time.monotonic()
            with self.assertRaises(TimeoutError):
                supervisor.bounded_http(self.address,self.certificate,"GET",path,timeout=.12)
            self.assertLess(time.monotonic()-started,.8)

    def test_real_tls_response_size_duplicate_header_and_success(self):
        for path,expected in (("/oversized","oversized"),("/duplicate","duplicate")):
            with self.assertRaisesRegex(RuntimeError,expected):
                supervisor.bounded_http(self.address,self.certificate,"GET",path,timeout=1)
        status,_,body=supervisor.bounded_http(self.address,self.certificate,"GET","/ok",timeout=1)
        self.assertEqual((status,body),(200,b'ok'))

    def test_unresponsive_tls_handshake_consumes_the_same_deadline(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        stopped=threading.Event()
        def accept():
            with listener.accept()[0] as stream:stopped.wait(1)
        worker=threading.Thread(target=accept,daemon=True);worker.start()
        started=time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                supervisor.bounded_http(f'127.0.0.1:{listener.getsockname()[1]}',self.certificate,"GET","/",timeout=.12)
            self.assertLess(time.monotonic()-started,.8)
        finally:
            stopped.set();listener.close();worker.join(timeout=2)


if __name__=="__main__":unittest.main()
