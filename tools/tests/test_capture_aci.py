"""Software tests of the capture envelope/scope; none claims hardware appraisal."""
import base64
import copy
import hashlib
import importlib.util
import http.client
import os
import socket
import smtplib
import ssl
import json
from pathlib import Path
import tempfile
import time
import threading
import unittest
from unittest import mock

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MODULE_PATH = Path(__file__).resolve().parents[1] / "capture_aci.py"
spec = importlib.util.spec_from_file_location("capture_aci", MODULE_PATH)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def client_context(**kwargs):
    context = ssl.create_default_context(**kwargs)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def config():
    return {"request_id": "aci-capture-2026-09-13", "audience": "ccf://agentdns.test",
            "grant_id": "aci-test-owner", "zone": "example.test.", "role": "mx-edge",
            "mailbox_domain": "example.test.", "service_host": "mail.example.test.",
            "addresses": {"ipv4": ["192.0.2.1"], "ipv6": ["2001:db8::1"]},
            "ports": [25, 465, 993], "lease_seconds": 3600}


def decode_url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_fixed(key, message, signature):
    if len(signature) != 64:
        raise AssertionError("not P1363")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    key.verify(der, message, ec.ECDSA(hashes.SHA256()))


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        path = Path(self.context.name)
        self.policy = b"unit-test policy, not a governed CCE"
        for name, value in {"security-policy-base64": self.policy,
                            "reference-info-base64": b"unit-test UVM, not signed by Microsoft",
                            "host-amd-cert-base64": b"unit-test endorsements, not signed by AMD"}.items():
            (path / name).write_bytes(base64.b64encode(value))
        # Only unit tests replace the native collector. Runtime has no fixture switch.
        def software_report(binding):
            report = bytearray(1184)
            report[:4] = (2).to_bytes(4, "little")
            report[80:144] = binding
            report[192:224] = hashlib.sha256(self.policy).digest()
            return bytes(report)
        with mock.patch.object(capture, "collect_report", side_effect=software_report), \
                mock.patch.object(capture, "security_context", return_value=path):
            self.state = capture.CaptureState(config())

    def test_outer_cose_signature_and_exact_key_binding(self):
        envelope = cbor2.loads(self.state.evidence)
        self.assertEqual(envelope.tag, 18)
        protected, unprotected, payload, signature = envelope.value
        self.assertEqual(cbor2.loads(protected), {1: -7})
        self.assertEqual(unprotected, {})
        key = serialization.load_der_public_key(self.state.spki)
        verify_fixed(key, cbor2.dumps(["Signature1", protected, b"", payload], canonical=True), signature)
        claims = cbor2.loads(payload)
        self.assertEqual(set(claims), {"att", "eds", "uvm"})
        self.assertEqual(claims["att"][80:144], hashlib.sha256(self.state.spki).digest() + bytes(32))
        self.assertEqual(self.state.inventory()["status"], "captured_not_appraised")
        self.assertEqual(self.state.evidence_digest, hashlib.sha256(self.state.evidence).hexdigest())

    def test_signed_request_fixed_scope_and_signature(self):
        fields = {"nonce": "4a" * 32, "nonce_expires_at": int(time.time()) + 250,
                  "intent_hash": self.state.intent_hash}
        request = self.state.signed_request(fields)
        key = serialization.load_der_public_key(self.state.spki)
        signed = {field: request[field] for field in ("action", "nonce", "nonce_expires_at", "intent_hash")}
        verify_fixed(key, capture.canonical(signed), decode_url(request["client_signature"]))
        self.assertEqual(request["action"]["operation"], "register")
        self.assertEqual(request["action"]["zone"], "example.test.")
        changed = copy.deepcopy(signed)
        changed["action"]["parameters"]["service_host"] = "attacker.example.test."
        with self.assertRaises(InvalidSignature):
            verify_fixed(key, capture.canonical(changed), decode_url(request["client_signature"]))
        for bad in [dict(fields, action=changed["action"]), dict(fields, intent_hash="00" * 32),
                    dict(fields, nonce_expires_at=int(time.time()) - 1),
                    dict(fields, nonce_expires_at=int(time.time()) + 301),
                    dict(fields, nonce_expires_at=True)]:
            with self.assertRaises(ValueError):
                self.state.signed_request(bad)

    def test_json_rejects_duplicate_keys_and_noncanonical_types(self):
        for raw in [b'{"nonce":1,"nonce":2}', b'{"expiry":1.2}', b'{"expiry":NaN}']:
            with self.assertRaises(ValueError):
                capture.strict_json(raw)
        for value in [float("nan"), 1 << 53, {"key": "é"}]:
            with self.assertRaises(ValueError):
                capture.canonical(value)
        self.assertEqual(capture.canonical({"z": 123, "a": ["\\\"\n", True]}), b'{"a":["\\\\\\\"\\n",true],"z":123}')

    def test_config_cannot_change_zone_operation_or_destination(self):
        for change in [{"zone": "agent.hosting."}, {"service_host": "mail.outside.test."},
                       {"ports": [25, 443]}, {"ports": [993, 25]}, {"operation": "deregister"},
                       {"ccf_url": "http://localhost"}, {"lease_seconds": True},
                       {"addresses": {"ipv4": ["192.0.2.2", "192.0.2.1"], "ipv6": []}}]:
            with self.assertRaises(ValueError):
                capture.validate_config({**config(), **change})

    def test_native_collector_rejects_wrong_binding_or_diagnostics(self):
        report = bytearray(1184)
        report[80:144] = b"x" * 64
        for output in [bytes(report).hex().encode(), b"No supported SNP device found", b"00"]:
            with mock.patch.object(capture.subprocess, "run", return_value=mock.Mock(stdout=output)):
                with self.assertRaises(RuntimeError):
                    capture.collect_report(bytes(64))

    def test_tls_certificate_uses_exact_attested_key_and_bounded_validity(self):
        cert = self.state.tls_certificate
        spki = cert.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(spki, self.state.spki)
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm))
        self.assertEqual(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            .value.get_values_for_type(x509.DNSName), [capture.TLS_SERVER_NAME, "mail.example.test"])
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertLessEqual((cert.not_valid_after - cert.not_valid_before).total_seconds(), 24 * 3600 + 300)
        inventory = self.state.inventory()
        self.assertEqual(decode_url(inventory["tls_certificate_der"]), cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(inventory["tls_server_name"], capture.TLS_SERVER_NAME)

    def test_tls_anonymous_descriptors_close_after_success_and_failure(self):
        original = os.memfd_create
        for fail in (False, True):
            descriptors = []
            def recording_memfd(*args):
                fd = original(*args)
                descriptors.append(fd)
                return fd
            with mock.patch.object(capture.os, "memfd_create", side_effect=recording_memfd):
                if fail:
                    with mock.patch.object(capture.ssl.SSLContext, "load_cert_chain", side_effect=OSError("test failure")):
                        with self.assertRaises(OSError):
                            capture.tls_material(ec.generate_private_key(ec.SECP256R1()))
                else:
                    capture.tls_material(ec.generate_private_key(ec.SECP256R1()))
            self.assertEqual(len(descriptors), 2)
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_https_trickled_headers_and_body_hit_absolute_deadline(self):
        token = "ef" * 32
        server = capture.BoundedHTTPServer(("127.0.0.1", 0), capture.handler_type(self.state, token),
            tls_context=self.state.tls_context)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        context = client_context(cadata=self.state.inventory()["tls_certificate_pem"])
        for phase in ("headers", "body"):
            with mock.patch.object(capture, "HTTP_DEADLINE_SECONDS", 0.35):
                with socket.create_connection(server.server_address, timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname=capture.TLS_SERVER_NAME) as peer:
                        if phase == "headers":
                            peer.sendall(b"GET /health HTTP/1.1\r\nX-Trickle: ")
                        else:
                            peer.sendall(("POST /signed-request HTTP/1.1\r\nHost: test\r\n"
                                "Content-Type: application/json\r\nContent-Length: 200\r\n"
                                f"Authorization: Bearer {token}\r\n\r\n").encode())
                        started = time.monotonic()
                        # Every interval is well below the ten-second read timeout.
                        # Without an absolute timer this could retain a slot forever.
                        while time.monotonic() - started < 1.5:
                            try:
                                peer.sendall(b"x")
                            except OSError:
                                break
                            time.sleep(0.06)
                        else:
                            self.fail(f"trickled {phase} escaped the transport deadline")
                        self.assertLess(time.monotonic() - started, 1.2)
            # A timed-out connection releases its handler slot for the next client.
            with socket.create_connection(server.server_address, timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname=capture.TLS_SERVER_NAME) as peer:
                    peer.sendall(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
                    self.assertIn(b"200 OK", peer.recv(4096))

    def test_ccf_trickled_response_headers_and_body_hit_absolute_deadline(self):
        phase = ["headers"]
        class Slow(capture.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                try:
                    self.rfile.read(int(self.headers["Content-Length"]))
                    if phase[0] == "headers":
                        self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Trickle: ")
                    else:
                        self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n")
                    for _ in range(30):
                        self.connection.sendall(b"x")
                        time.sleep(0.06)
                except OSError:
                    pass
        server = capture.BoundedHTTPServer(("127.0.0.1", 0), Slow, tls_context=self.state.tls_context)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        self.state.config["ccf_url"] = f"https://{capture.TLS_SERVER_NAME}:{server.server_address[1]}"
        self.state.config["ccf_ca_pem"] = self.state.inventory()["tls_certificate_pem"]
        original = socket.getaddrinfo
        def resolve(host, *args, **kwargs):
            return original("127.0.0.1" if host == capture.TLS_SERVER_NAME else host, *args, **kwargs)
        with mock.patch.object(capture, "CCF_DEADLINE_SECONDS", 0.35), \
                mock.patch.object(socket, "getaddrinfo", side_effect=resolve):
            for value in ("headers", "body"):
                phase[0] = value
                started = time.monotonic()
                with self.assertRaises((OSError, http.client.HTTPException, ValueError)):
                    self.state._post_ccf("/service/nonce", {"action": self.state.action})
                self.assertLess(time.monotonic() - started, 1.2)

    def test_https_api_exposes_public_capture_and_only_fixed_signing(self):
        token = "ef" * 32
        server = capture.BoundedHTTPServer(("127.0.0.1", 0), capture.handler_type(self.state, token),
            tls_context=self.state.tls_context)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        cert_pem = self.state.tls_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        context = client_context(cadata=cert_pem)
        address = server.server_address
        def connect(context=context, hostname=capture.TLS_SERVER_NAME):
            raw = socket.create_connection(address, timeout=5)
            try:
                return context.wrap_socket(raw, server_hostname=hostname)
            except BaseException:
                raw.close()
                raise
        def request(method, path, fields=None, supplied_token=None):
            connection = http.client.HTTPConnection(*address, timeout=5)
            connection.sock = connect()
            try:
                peer = x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
                self.assertEqual(peer.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo), self.state.spki)
                headers = {"Content-Type": "application/json"}
                if supplied_token is not None:
                    headers["Authorization"] = "Bearer " + supplied_token
                connection.request(method, path, body=json.dumps(fields) if fields is not None else None, headers=headers)
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()
        status, body = request("GET", "/capture")
        inventory = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(inventory["status"], "captured_not_appraised")
        self.assertNotIn("private", body.decode().lower())
        self.assertEqual(request("GET", "/cert.pem"), (200, cert_pem.encode()))
        self.assertEqual(request("GET", "/cert.der"), (200, self.state.tls_certificate.public_bytes(serialization.Encoding.DER)))
        fields = {"nonce": "4a" * 32, "nonce_expires_at": int(time.time()) + 250,
                  "intent_hash": self.state.intent_hash}
        for supplied, authorized, expected in [(fields, False, 401),
                (dict(fields, action={"operation": "deregister"}), True, 400)]:
            self.assertEqual(request("POST", "/signed-request", supplied, token if authorized else "wrong")[0], expected)
        status, body = request("POST", "/signed-request", fields, token)
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(result["action"], self.state.action)
        self.assertEqual(len(decode_url(result["client_signature"])), 64)
        prepare = {"operation": "renew", "request_id": "https-renew", "parameters": {"requested_lease_seconds": 60}}
        self.assertEqual(request("POST", "/lifecycle/action", prepare, "wrong")[0], 401)
        status, raw = request("POST", "/lifecycle/action", prepare, token)
        self.assertEqual(status, 200)
        prepared = json.loads(raw)
        lifecycle = {"action_id": prepared["action_id"], "intent_hash": prepared["intent_hash"],
                     "nonce": "6a" * 32, "nonce_expires_at": int(time.time()) + 100}
        self.assertEqual(request("POST", "/lifecycle/signed-request", lifecycle, "wrong")[0], 401)
        self.assertEqual(request("POST", "/lifecycle/signed-request", dict(lifecycle, action={}), token)[0], 400)
        status, raw = request("POST", "/lifecycle/signed-request", lifecycle, token)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["action"], prepared["action"])
        for untrusted_context, hostname in [(client_context(), capture.TLS_SERVER_NAME),
                                            (context, "wrong.example.test")]:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connect(untrusted_context, hostname)
        # A plain HTTP request cannot reach the handler or retrieve evidence.
        with socket.create_connection(address, timeout=5) as plain:
            plain.sendall(b"GET /capture HTTP/1.0\r\nHost: localhost\r\n\r\n")
            try:
                response = plain.recv(4096)
            except ConnectionResetError:
                response = b""
            self.assertNotIn(b"HTTP/", response)
            self.assertNotIn(b"captured_not_appraised", response)

    def mail_fixture(self, protocol_port):
        server = capture.MailFixtureServer(("127.0.0.1", 0), self.state.tls_context,
            self.state.config["service_host"].rstrip("."), protocol_port)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        return server.server_address

    def test_starttls_smtp_uses_attested_key_and_refuses_mail(self):
        address = self.mail_fixture(25)
        context = client_context(cadata=self.state.tls_certificate.public_bytes(serialization.Encoding.PEM).decode())
        with smtplib.SMTP(*address, timeout=5) as smtp:
            self.assertEqual(smtp.ehlo()[0], 250)
            self.assertTrue(smtp.has_extn("starttls"))
            # The test connects to loopback while retaining the actual service
            # name for SNI and certificate hostname verification.
            smtp._host = "mail.example.test"
            self.assertEqual(smtp.starttls(context=context)[0], 220)
            peer = x509.load_der_x509_certificate(smtp.sock.getpeercert(binary_form=True))
            self.assertEqual(peer.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo), self.state.spki)
            self.assertEqual(smtp.ehlo()[0], 250)
            self.assertFalse(smtp.has_extn("starttls"))
            self.assertEqual(smtp.mail("sender@example.test")[0], 550)
            self.assertEqual(smtp.rcpt("receiver@example.test")[0], 550)
            self.assertEqual(smtp.docmd("AUTH PLAIN", "test-only")[0], 550)

    def test_implicit_mail_tls_binds_key_checks_hostname_and_has_no_mailbox(self):
        context = client_context(cadata=self.state.tls_certificate.public_bytes(serialization.Encoding.PEM).decode())
        for port in (465, 993):
            address = self.mail_fixture(port)
            with socket.create_connection(address, timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="mail.example.test") as tls:
                    peer = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                    self.assertEqual(peer.public_key().public_bytes(serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo), self.state.spki)
                    stream = tls.makefile("rb")
                    self.assertTrue(stream.readline().startswith(b"220" if port == 465 else b"* OK"))
                    tls.sendall(b"MAIL FROM:<sender@example.test>\r\n" if port == 465 else b"a LOGIN test-only disabled\r\n")
                    self.assertTrue(stream.readline().startswith(b"550" if port == 465 else b"a NO"))
                    stream.close()
            for trust, hostname in [(context, "wrong.example.test"), (client_context(), "mail.example.test")]:
                with socket.create_connection(address, timeout=5) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        trust.wrap_socket(raw, server_hostname=hostname)

    def test_mail_fixture_rejects_oversized_protocol_lines(self):
        address = self.mail_fixture(25)
        with socket.create_connection(address, timeout=5) as client:
            self.assertTrue(client.recv(512).startswith(b"220"))
            client.sendall(b"X" * 512 + b"\r\n")
            try:result = client.recv(512)
            except ConnectionResetError:result = b""
            self.assertEqual(result, b"")

    def register_for_lifecycle(self):
        fields = {"nonce": "1a" * 32, "nonce_expires_at": int(time.time()) + 250,
                  "intent_hash": self.state.intent_hash}
        envelope = self.state.signed_request(fields)
        message = {key: envelope[key] for key in ("action", "nonce", "nonce_expires_at", "intent_hash")}
        expected = "reg-" + hashlib.sha256(capture.canonical(message)).hexdigest()[:32]
        self.assertEqual(self.state.registration_id, expected)
        return expected

    def sign_prepared(self, prepared, nonce="2b" * 32):
        fields = {"action_id": prepared["action_id"], "intent_hash": prepared["intent_hash"],
                  "nonce": nonce, "nonce_expires_at": int(time.time()) + 250}
        envelope = self.state.sign_lifecycle(fields)
        message = {key: envelope[key] for key in ("action", "nonce", "nonce_expires_at", "intent_hash")}
        verify_fixed(serialization.load_der_public_key(self.state.spki), capture.canonical(message),
                     decode_url(envelope["client_signature"]))
        self.assertEqual(self.state.sign_lifecycle(fields), envelope)
        with self.assertRaises(ValueError):
            self.state.sign_lifecycle(dict(fields, nonce="ab" * 32))
        return envelope, message

    def test_lifecycle_renew_and_withdraw_are_bound_to_issued_registration(self):
        request = {"operation": "renew", "request_id": "renew-1", "parameters": {"requested_lease_seconds": 600}}
        with self.assertRaises(ValueError):self.state.prepare_lifecycle(request)
        registration = self.register_for_lifecycle()
        prepared = self.state.prepare_lifecycle(request)
        self.assertEqual(self.state.prepare_lifecycle(request), prepared)
        self.assertEqual(prepared["action"]["parameters"]["registration_id"], registration)
        for field in ("audience", "grant_id", "zone", "signer_spki_der"):
            self.assertEqual(prepared["action"][field], self.state.action[field])
        envelope, _ = self.sign_prepared(prepared)
        self.assertEqual(envelope["evidence_payload"], capture.b64url(self.state.evidence))
        for ports, withdraw in [([25], False), ([], True)]:
            prepared = self.state.prepare_lifecycle({"operation": "deregister", "request_id": "withdraw-" + str(withdraw),
                "parameters": {"selected_ports": ports, "withdraw_all": withdraw}})
            envelope, _ = self.sign_prepared(prepared)
            self.assertNotIn("evidence_payload", envelope)
            self.assertEqual(envelope["action"]["parameters"]["registration_id"], registration)
            self.assertEqual(envelope["action"]["parameters"]["selected_ports"], ports)

    def test_lifecycle_scope_overrides_and_unknown_fields_are_rejected(self):
        self.register_for_lifecycle()
        valid = {"operation": "renew", "request_id": "test-renew", "parameters": {"requested_lease_seconds": 600}}
        bad = [dict(valid, zone="escape.test."), dict(valid, grant_id="other"), dict(valid, signer_spki_der="other"),
            dict(valid, operation="register"), dict(valid, request_id=self.state.action["request_id"]),
            dict(valid, parameters={"requested_lease_seconds": 3601}),
            dict(valid, parameters={"requested_lease_seconds": True}),
            dict(valid, parameters={"requested_lease_seconds": 600, "registration_id": "reg-other"})]
        for parameters in [{"selected_ports": [443], "withdraw_all": False},
                           {"selected_ports": [25, 25], "withdraw_all": False},
                           {"selected_ports": [25], "withdraw_all": True},
                           {"selected_ports": [], "withdraw_all": False},
                           {"selected_ports": [25], "withdraw_all": False, "registration_id": "reg-other"}]:
            bad.append({"operation": "deregister", "request_id": "bad-withdraw", "parameters": parameters})
        for request in bad:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):self.state.prepare_lifecycle(request)
        self.state.prepare_lifecycle(valid)
        with self.assertRaises(ValueError):
            self.state.prepare_lifecycle(dict(valid, parameters={"requested_lease_seconds": 601}))
        with self.assertRaises(ValueError):
            self.state.sign_lifecycle({"action_id": "00" * 32, "nonce": "ab" * 32,
                "intent_hash": "00" * 32, "nonce_expires_at": int(time.time()) + 100})

    def test_two_acme_orders_and_only_issued_challenge_deletion(self):
        registration = self.register_for_lifecycle()
        ids = []
        for index in range(2):
            parameters = {"order_id": "order-" + str(index), "txt_value": capture.b64url(hashlib.sha256(str(index).encode()).digest()),
                          "ttl": 30, "lifetime_seconds": 60}
            prepared = self.state.prepare_lifecycle({"operation": "acme_challenge_create", "request_id": "challenge-" + str(index), "parameters": parameters})
            envelope, message = self.sign_prepared(prepared)
            self.assertEqual(envelope["action"]["parameters"]["name"], self.state.config["service_host"])
            self.assertEqual(envelope["action"]["parameters"]["registration_id"], registration)
            ids.append("chal-" + hashlib.sha256(capture.canonical(message)).hexdigest()[:32])
        self.assertNotEqual(ids[0], ids[1])
        self.assertTrue(set(ids) <= self.state._challenge_ids)
        prepared = self.state.prepare_lifecycle({"operation": "acme_challenge_delete", "request_id": "delete-one", "parameters": {"challenge_id": ids[0]}})
        envelope, _ = self.sign_prepared(prepared)
        self.assertEqual(envelope["action"]["parameters"], {"challenge_id": ids[0]})
        for parameters in [{"challenge_id": "chal-unknown"}, {"challenge_id": ids[0], "name": "escape.test."}]:
            with self.assertRaises(ValueError):
                self.state.prepare_lifecycle({"operation": "acme_challenge_delete", "request_id": "bad-delete", "parameters": parameters})
        parameters = {"order_id": "bad-order", "txt_value": capture.b64url(bytes(32)), "ttl": 30, "lifetime_seconds": 60}
        for change in [{"name": "escape.test."}, {"registration_id": "reg-other"}, {"txt_value": "!" * 43},
                       {"txt_value": "a" * 43}, {"ttl": 61}, {"lifetime_seconds": 3601}, {"ttl": True}]:
            with self.assertRaises(ValueError):
                self.state.prepare_lifecycle({"operation": "acme_challenge_create", "request_id": "bad-order", "parameters": {**parameters, **change}})

    def test_prepared_lifecycle_action_memory_is_bounded(self):
        self.register_for_lifecycle()
        for index in range(128):
            self.state.prepare_lifecycle({"operation": "renew", "request_id": "renew-" + str(index), "parameters": {"requested_lease_seconds": 60}})
        with self.assertRaises(ValueError):
            self.state.prepare_lifecycle({"operation": "renew", "request_id": "too-many", "parameters": {"requested_lease_seconds": 60}})

    def test_uncertain_submission_retries_identical_request(self):
        nonce = {"nonce": "ab" * 32, "expires_at": int(time.time()) + 250,
                 "issued_at": int(time.time()), "intent_hash": self.state.intent_hash, "tx_id": "2.41", "status": "committed"}
        submissions = []
        def post(path, body):
            if path == "/service/nonce":
                return {"body": nonce}
            submissions.append(copy.deepcopy(body))
            if len(submissions) == 1:
                raise TimeoutError("ambiguous network failure")
            return {"http_status": 200, "ccf_tx_id": "2.42", "body": {"status": "pending"}}
        with mock.patch.object(self.state, "_post_ccf", side_effect=post):
            with self.assertRaises(TimeoutError):
                self.state.register()
            response = self.state.register()
            self.assertEqual(response["body"]["status"], "pending")
            self.assertEqual(submissions[0], submissions[1])
            self.assertEqual(self.state.register(), response)
            self.assertEqual(len(submissions), 2)


if __name__ == "__main__":
    unittest.main()
