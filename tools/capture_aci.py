#!/usr/bin/env python3
"""Isolated ACI hardware capture and a constrained test-registration signer.

There is no arbitrary signing API, report-file override, virtual-quote fallback,
or private-key export path. A fresh key lives only in this process; TLS loads
its temporary PEM through anonymous Linux memfd descriptors only.
"""
from __future__ import annotations

import base64
from domain_registry import get
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlsplit

import cbor2
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

MAX_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
PROFILE = "azure-aci-snp"
COLLECTOR = "/usr/local/bin/get-snp-report"
TLS_SERVER_NAME = get("capture_tls_hostname")
HTTP_DEADLINE_SECONDS = 30
CCF_DEADLINE_SECONDS = 30


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def strict_json(data: bytes) -> object:
    if len(data) > MAX_BYTES:
        raise ValueError("JSON input exceeds limit")

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate JSON key")
            obj[key] = value
        return obj

    def invalid_number(_):
        raise ValueError("only bounded integer numeric fields are supported")

    return json.loads(data, object_pairs_hook=pairs, parse_float=invalid_number,
                      parse_constant=invalid_number)


def canonical(value: object) -> bytes:
    """RFC8785 for the deliberately ASCII-only, bounded-integer action schema."""
    def validate(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not 0 <= item <= MAX_SAFE_INTEGER:
                raise ValueError("integer outside canonical safe range")
        elif type(item) is str:
            if not item.isascii():
                raise ValueError("test action strings must be ASCII")
        elif type(item) is list:
            for child in item:
                validate(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not key.isascii():
                    raise ValueError("canonical object keys must be ASCII")
                validate(child)
        else:
            raise ValueError("unsupported canonical value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def exact_fields(obj, required, optional=()):
    if type(obj) is not dict or not set(required) <= obj.keys() or not obj.keys() <= set(required) | set(optional):
        raise ValueError("missing or unknown fields")


def name(value):
    if type(value) is not str or len(value) > 240 or value != value.lower() or not value.endswith("."):
        raise ValueError("name must be a bounded lowercase absolute ASCII name")
    labels = value[:-1].split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("invalid DNS name")
    return value


def in_zone(owner, zone):
    return owner == zone or owner.endswith("." + zone)


def validate_config(config):
    exact_fields(config, ("request_id", "audience", "grant_id", "zone", "role", "mailbox_domain",
                          "service_host", "addresses", "ports", "lease_seconds"),
                 ("ccf_url", "ccf_ca_pem", "listen_address", "listen_port"))
    for field in ("request_id", "grant_id", "role"):
        if type(config[field]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", config[field]):
            raise ValueError(f"invalid {field}")
    audience = config["audience"]
    if type(audience) is not str or not audience.isascii() or not audience.startswith("ccf://") or len(audience) > 256:
        raise ValueError("audience must be a fixed CCF service identity")
    zone = name(config["zone"])
    if not (zone.endswith(".test.") or zone.endswith(".invalid.") or zone in ("example.", "example.com.", "example.net.", "example.org.")):
        raise ValueError("capture worker signs only reserved test or example zones")
    for field in ("mailbox_domain", "service_host"):
        if not in_zone(name(config[field]), zone):
            raise ValueError("test names must lie inside the fixed zone")
    exact_fields(config["addresses"], ("ipv4", "ipv6"))
    count = 0
    for field, family in (("ipv4", 4), ("ipv6", 6)):
        addresses = config["addresses"][field]
        if type(addresses) is not list or len(addresses) > 16:
            raise ValueError("invalid address list")
        parsed = []
        for address in addresses:
            value = ipaddress.ip_address(address)
            if value.version != family or str(value) != address:
                raise ValueError("addresses must use canonical presentation")
            parsed.append(int(value))
        if parsed != sorted(set(parsed)):
            raise ValueError("addresses must be sorted and duplicate-free")
        count += len(parsed)
    if count == 0:
        raise ValueError("at least one address is required")
    ports = config["ports"]
    if type(ports) is not list or not ports or any(type(p) is not int or p not in (25, 465, 993) for p in ports) or ports != sorted(set(ports)):
        raise ValueError("capture supports only sorted test mail ports 25,465,993")
    if type(config["lease_seconds"]) is not int or not 1 <= config["lease_seconds"] <= 86400:
        raise ValueError("test lease must be between one second and one day")
    if ("ccf_url" in config) != ("ccf_ca_pem" in config):
        raise ValueError("CCF URL and trusted CA must be configured together")
    if "ccf_url" in config:
        url = urlsplit(config["ccf_url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("CCF URL must be an HTTPS base URL")
        if type(config["ccf_ca_pem"]) is not str or "-----BEGIN CERTIFICATE-----" not in config["ccf_ca_pem"]:
            raise ValueError("explicit CCF CA PEM is required")
    if type(config.get("listen_port", 8080)) is not int or not 1 <= config.get("listen_port", 8080) <= 65535:
        raise ValueError("invalid listen port")
    if config.get("listen_address", "0.0.0.0") not in ("0.0.0.0", "127.0.0.1"):
        raise ValueError("invalid listen address")
    return config


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise ValueError("security-context file is empty or oversized")
    return data


def security_context() -> Path:
    configured = os.environ.get("UVM_SECURITY_CONTEXT_DIR")
    paths = [Path(configured)] if configured else sorted(Path("/").glob("security-context*"))
    matches = [path for path in paths if all((path / file).is_file() for file in
               ("reference-info-base64", "host-amd-cert-base64", "security-policy-base64"))]
    if len(matches) != 1:
        raise RuntimeError("exactly one native ACI security context is required")
    return matches[0]


def collect_report(binding: bytes) -> bytes:
    if len(binding) != 64:
        raise ValueError("report binding must contain exactly 64 bytes")
    result = subprocess.run([COLLECTOR, binding.hex()], check=True, capture_output=True, timeout=20)
    # Native collector prints hex, not raw binary. Reject diagnostics or truncation.
    text = result.stdout.strip()
    if len(text) != 2368 or not re.fullmatch(rb"[0-9a-fA-F]{2368}", text):
        raise RuntimeError("collector did not return a native 1184-byte SNP report")
    report = bytes.fromhex(text.decode("ascii"))
    if not hmac.compare_digest(report[80:144], binding):
        raise RuntimeError("native report does not bind the generated service key")
    if int.from_bytes(report[48:52], "little") != 0 or int.from_bytes(report[8:16], "little") & (1 << 19):
        raise RuntimeError("native report has nonzero VMPL or debug enabled")
    return report


def fixed_signature(key, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def tls_material(key, service_host=None):
    """Load a 24-hour certificate under the attested key without disk files.

    CPython's SSL API requires filenames. Linux memfd plus /proc/self/fd gives
    OpenSSL anonymous in-memory files; CLOEXEC prevents child inheritance and
    descriptors close immediately after loading, including on any failure.
    """
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        raise RuntimeError("capture TLS requires Linux memfd and /proc/self/fd; no disk fallback")
    now = datetime.now(timezone.utc)
    identity = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_SERVER_NAME)])
    names = [TLS_SERVER_NAME]
    if service_host is not None and service_host != TLS_SERVER_NAME:
        names.append(service_host)
    certificate = (x509.CertificateBuilder().subject_name(identity).issuer_name(identity)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=24))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(context, "num_tickets"):
        context.num_tickets = 0
    descriptors = []
    private_pem = key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    try:
        for label, data in (("agentdns-capture-cert", certificate.public_bytes(serialization.Encoding.PEM)),
                            ("agentdns-capture-key", private_pem)):
            fd = os.memfd_create(label, os.MFD_CLOEXEC)
            descriptors.append(fd)
            os.fchmod(fd, 0o600)
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("incomplete anonymous TLS credential write")
                remaining = remaining[written:]
            os.lseek(fd, 0, os.SEEK_SET)
        context.load_cert_chain(f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}")
    finally:
        for fd in descriptors:
            os.close(fd)
        # Private PEM never reaches a filesystem path, response, or log. The
        # cryptographic key and SSL context retain their necessary process memory.
        del private_pem
    return context, certificate


class SocketDeadline:
    """Abort a transport at one absolute deadline, including trickled I/O.

    A socket timeout alone restarts for each read. Shutdown wakes a buffered
    HTTP read even when its makefile still owns the descriptor. The socket is
    retained until the timer joins, so it cannot act on a reused descriptor.
    """
    def __init__(self, seconds, stream=None):
        self.end = time.monotonic() + seconds
        self.stream = stream
        self._lock = threading.Lock()
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def remaining(self):
        value = self.end - time.monotonic()
        if value <= 0:
            raise TimeoutError("transport deadline exceeded")
        return value

    @staticmethod
    def _shutdown(stream):
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _expire(self):
        with self._lock:
            self._shutdown(self.stream)

    def bind(self, stream):
        with self._lock:
            self.stream = stream
            if time.monotonic() >= self.end:
                self._shutdown(stream)
                raise TimeoutError("transport deadline exceeded")
            stream.settimeout(min(10, self.remaining()))

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, *_):
        self._timer.cancel()
        self._timer.join()


class BoundedHTTPServer(ThreadingHTTPServer):
    """Bound concurrent handlers so a public test endpoint cannot spawn endlessly."""
    def __init__(self, *args, tls_context, **kwargs):
        self._tls_context = tls_context
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        try:
            # Handshake happens inside a bounded worker, never the accept loop.
            return self._tls_context.wrap_socket(request, server_side=True,
                do_handshake_on_connect=False), address
        except BaseException:
            request.close()
            raise

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            with SocketDeadline(HTTP_DEADLINE_SECONDS, request):
                request.do_handshake()
                super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self._slots.release()


class MailFixtureServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Bounded test protocol peer; no message queue, mailbox or authentication."""
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, tls_context, service_host, protocol_port):
        self.tls_context = tls_context
        self.service_host = service_host
        self.protocol_port = protocol_port
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(address, MailFixtureHandler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class MailFixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        deadline = time.monotonic() + 30
        secured = False

        def timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("validation connection deadline exceeded")
            stream.settimeout(min(10, remaining))

        def send(line):
            timeout()
            stream.sendall(line.encode("ascii") + b"\r\n")

        def receive():
            line = bytearray()
            while len(line) < 512:
                timeout()
                byte = stream.recv(1)
                if not byte:
                    return None
                line.extend(byte)
                if line.endswith(b"\r\n"):
                    return line[:-2].decode("ascii")
            raise ValueError("validation protocol line exceeds 512 bytes")

        def start_tls():
            nonlocal stream, secured
            timeout()
            stream = self.server.tls_context.wrap_socket(stream, server_side=True)
            secured = True

        try:
            if self.server.protocol_port in (465, 993):
                start_tls()
            if self.server.protocol_port == 993:
                send("* OK agentdns isolated TLS validation fixture")
                for _ in range(16):
                    line = receive()
                    if line is None:
                        break
                    fields = line.split(" ", 2)
                    if len(fields) < 2 or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", fields[0]):
                        send("* BAD invalid validation command")
                        break
                    tag, command = fields[0], fields[1].upper()
                    if command == "LOGOUT":
                        send("* BYE validation session closed")
                        send(tag + " OK LOGOUT completed")
                        break
                    if command == "CAPABILITY":
                        send("* CAPABILITY IMAP4rev1 LOGINDISABLED")
                        send(tag + " OK CAPABILITY completed")
                    elif command == "NOOP":
                        send(tag + " OK NOOP completed")
                    else:
                        send(tag + " NO validation fixture has no authentication or mailbox")
                return
            send("220 " + self.server.service_host + " ESMTP isolated validation fixture")
            for _ in range(16):
                line = receive()
                if line is None:
                    break
                command = line.split(" ", 1)[0].upper()
                if command == "HELO":
                    send("250 " + self.server.service_host)
                elif command == "EHLO":
                    send("250-" + self.server.service_host)
                    if not secured:
                        send("250-STARTTLS")
                    send("250 HELP")
                elif command == "STARTTLS":
                    if line.upper() != "STARTTLS":
                        send("501 5.5.2 STARTTLS accepts no parameters")
                    elif secured:
                        send("503 5.5.1 TLS already active")
                    else:
                        send("220 2.0.0 Ready to start TLS")
                        start_tls()
                elif command == "QUIT":
                    send("221 2.0.0 Validation session closed")
                    break
                elif command in ("NOOP", "RSET", "HELP"):
                    send("250 2.0.0 Validation fixture ready")
                elif command in ("MAIL", "RCPT", "DATA", "AUTH"):
                    send("550 5.7.1 Validation fixture does not accept mail or authentication")
                else:
                    send("502 5.5.1 Unsupported validation command")
        except (OSError, ValueError, UnicodeError):
            # Failed TLS and malformed peers are expected negative test cases.
            pass
        finally:
            stream.close()


def start_mail_fixtures(state):
    servers = []
    try:
        for port in state.config["ports"]:
            server = MailFixtureServer((state.config.get("listen_address", "0.0.0.0"), port),
                state.tls_context, state.config["service_host"].rstrip("."), port)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    except BaseException:
        for server in servers:
            server.shutdown()
            server.server_close()
        raise
    return servers


class CaptureState:
    MAX_LIFECYCLE_ACTIONS = 128

    def __init__(self, config, *, config_validator=validate_config):
        # Copy and validate once. Nothing supplied to HTTP handlers changes this scope.
        self.config = config_validator(strict_json(json.dumps(config).encode()))
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.spki = self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo)
        binding = hashlib.sha256(self.spki).digest() + bytes(32)
        self.report = collect_report(binding)
        context = security_context()
        policy = base64.b64decode(read_bounded(context / "security-policy-base64").strip(), validate=True)
        if not hmac.compare_digest(hashlib.sha256(policy).digest(), self.report[192:224]):
            raise RuntimeError("native report host_data does not match the CCE policy")
        uvm = base64.b64decode(read_bounded(context / "reference-info-base64").strip(), validate=True)
        endorsements = read_bounded(context / "host-amd-cert-base64").strip().decode("ascii")
        # Ensure endorsements are valid base64 before forwarding their original native value.
        base64.b64decode(endorsements, validate=True)
        payload = cbor2.dumps({"att": self.report, "eds": endorsements, "uvm": uvm}, canonical=True)
        protected = cbor2.dumps({1: -7}, canonical=True)
        sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
        self.evidence = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload,
                                                   fixed_signature(self._key, sig_structure)]), canonical=True)
        if len(self.evidence) > MAX_EVIDENCE_BYTES:
            raise RuntimeError("native evidence exceeds server input bound")
        self.tls_context, self.tls_certificate = tls_material(self._key, self.config["service_host"].rstrip("."))
        self.evidence_digest = hashlib.sha256(self.evidence).hexdigest()
        self.captured_at = int(time.time())
        self.action = {key: self.config[key] for key in ("request_id", "audience", "grant_id", "zone")}
        self.action.update(operation="register", signer_spki_der=b64url(self.spki), parameters={
            **{key: self.config[key] for key in ("role", "mailbox_domain", "service_host", "addresses", "ports", "lease_seconds")},
            "evidence_profile": PROFILE, "evidence_digest": self.evidence_digest})
        self.intent_hash = hashlib.sha256(canonical(self.action)).hexdigest()
        self._lock = threading.RLock()
        self._last_signed_request = None
        self._last_registration_result = None
        self.registration_id = None
        self._prepared_actions = {}
        self._request_ids = {self.action["request_id"]: self.intent_hash}
        self._signed_actions = {}
        self._challenge_ids = set()

    def inventory(self):
        def tcb(offset):
            value = self.report[offset:offset + 8]
            return {"bootloader": value[0], "tee": value[1], "snp": value[6], "microcode": value[7]}
        return {"status": "captured_not_appraised", "profile": PROFILE, "captured_at": self.captured_at,
                "tls_server_name": TLS_SERVER_NAME,
                "tls_certificate_der": b64url(self.tls_certificate.public_bytes(serialization.Encoding.DER)),
                "tls_certificate_pem": self.tls_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "signer_spki_der": b64url(self.spki), "spki_sha256": hashlib.sha256(self.spki).hexdigest(),
                "evidence_digest": self.evidence_digest, "evidence_payload": b64url(self.evidence),
                "intent_hash": self.intent_hash, "action": self.action,
                "untrusted_report_inventory": {"version": int.from_bytes(self.report[:4], "little"),
                    "measurement": self.report[144:192].hex(), "host_data": self.report[192:224].hex(),
                    "vmpl": int.from_bytes(self.report[48:52], "little"),
                    "current_tcb": tcb(56), "reported_tcb": tcb(384), "committed_tcb": tcb(480), "launch_tcb": tcb(496)}}

    def _sign_action(self, action, nonce_fields):
        exact_fields(nonce_fields, ("nonce", "nonce_expires_at", "intent_hash"))
        for field in ("nonce", "intent_hash"):
            if type(nonce_fields[field]) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce_fields[field]):
                raise ValueError("nonce and intent hash must be lowercase SHA256-sized hex")
        expected = hashlib.sha256(canonical(action)).hexdigest()
        if not hmac.compare_digest(nonce_fields["intent_hash"], expected):
            raise ValueError("nonce intent hash does not match the prepared test action")
        expiry = nonce_fields["nonce_expires_at"]
        if type(expiry) is not int or not 0 <= expiry <= MAX_SAFE_INTEGER:
            raise ValueError("invalid nonce expiration")
        signed = {"action": action, **nonce_fields}
        message = canonical(signed)
        previous = self._signed_actions.get(expected)
        if previous is not None:
            if previous[0] != message:
                raise ValueError("action already signed with a different nonce; retry the identical envelope")
            return strict_json(canonical(previous[1]))
        now = int(time.time())
        if not now < expiry <= now + 300:
            raise ValueError("nonce must be unexpired and at most 300 seconds ahead")
        envelope = {**signed, "client_signature": b64url(fixed_signature(self._key, message))}
        if action["operation"] in ("register", "renew"):
            envelope["evidence_payload"] = b64url(self.evidence)
        digest = hashlib.sha256(message).hexdigest()
        if action["operation"] == "register":
            derived = "reg-" + digest[:32]
            if self.registration_id is not None and self.registration_id != derived:
                raise ValueError("fixed registration has already been signed")
            self.registration_id = derived
        elif action["operation"] == "acme_challenge_create":
            self._challenge_ids.add("chal-" + digest[:32])
        self._signed_actions[expected] = (message, envelope)
        return strict_json(canonical(envelope))

    def signed_request(self, nonce_fields):
        with self._lock:
            return self._sign_action(self.action, nonce_fields)

    def prepare_lifecycle(self, request):
        exact_fields(request, ("operation", "request_id", "parameters"))
        request_id = request["request_id"]
        if type(request_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id):
            raise ValueError("invalid lifecycle request ID")
        operation = request["operation"]
        values = request["parameters"]
        with self._lock:
            if self.registration_id is None:
                raise ValueError("sign the fixed registration before preparing lifecycle actions")
            parameters = {"registration_id": self.registration_id}
            if operation == "renew":
                exact_fields(values, ("requested_lease_seconds",))
                lease = values["requested_lease_seconds"]
                if type(lease) is not int or not 1 <= lease <= self.config["lease_seconds"]:
                    raise ValueError("renewal exceeds the fixed lease bound")
                parameters.update(requested_lease_seconds=lease,
                    evidence_profile=PROFILE, evidence_digest=self.evidence_digest)
            elif operation == "deregister":
                exact_fields(values, ("selected_ports", "withdraw_all"), ("reason",))
                ports, withdraw = values["selected_ports"], values["withdraw_all"]
                if type(withdraw) is not bool or type(ports) is not list or any(type(port) is not int or port not in self.config["ports"] for port in ports) or ports != sorted(set(ports)):
                    raise ValueError("withdrawal ports must be a sorted subset of fixed mail ports")
                if (withdraw and ports) or (not withdraw and not ports):
                    raise ValueError("withdraw_all requires no ports; partial withdrawal requires ports")
                reason = values.get("reason", "validation_lifecycle")
                if type(reason) is not str or not 1 <= len(reason) <= 128 or not all(32 <= ord(char) <= 126 for char in reason):
                    raise ValueError("invalid withdrawal reason")
                parameters.update(selected_ports=list(ports), withdraw_all=withdraw, reason=reason)
            elif operation == "acme_challenge_create":
                exact_fields(values, ("order_id", "txt_value", "ttl", "lifetime_seconds"))
                order, txt, ttl, lifetime = (values[key] for key in ("order_id", "txt_value", "ttl", "lifetime_seconds"))
                if type(order) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", order):
                    raise ValueError("invalid challenge order ID")
                if type(txt) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", txt):
                    raise ValueError("challenge TXT must be canonical base64url SHA256")
                decoded = base64.b64decode(txt + "=", altchars=b"-_", validate=True)
                if len(decoded) != 32 or b64url(decoded) != txt:
                    raise ValueError("challenge TXT must be canonical base64url SHA256")
                if type(lifetime) is not int or not 1 <= lifetime <= min(3600, self.config["lease_seconds"]) or type(ttl) is not int or not 1 <= ttl <= min(300, lifetime):
                    raise ValueError("challenge TTL or lifetime exceeds the fixed bounds")
                parameters.update(order_id=order, name=self.config["service_host"], txt_value=txt,
                    ttl=ttl, lifetime_seconds=lifetime)
            elif operation == "acme_challenge_delete":
                exact_fields(values, ("challenge_id",))
                challenge = values["challenge_id"]
                if type(challenge) is not str or challenge not in self._challenge_ids:
                    raise ValueError("challenge ID was not issued by this fixed registration signer")
                parameters = {"challenge_id": challenge}
            else:
                raise ValueError("unsupported lifecycle operation")
            action = {key: self.action[key] for key in ("audience", "grant_id", "zone", "signer_spki_der")}
            action.update(request_id=request_id, operation=operation, parameters=parameters)
            action_id = hashlib.sha256(canonical(action)).hexdigest()
            previous = self._request_ids.get(request_id)
            if previous is not None and previous != action_id:
                raise ValueError("request ID already belongs to a different fixed action")
            if action_id not in self._prepared_actions and len(self._prepared_actions) >= self.MAX_LIFECYCLE_ACTIONS:
                raise ValueError("bounded validation lifecycle action capacity reached")
            self._request_ids[request_id] = action_id
            self._prepared_actions[action_id] = action
            return strict_json(canonical({"action_id": action_id, "action": action, "intent_hash": action_id}))

    def sign_lifecycle(self, request):
        exact_fields(request, ("action_id", "nonce", "nonce_expires_at", "intent_hash"))
        action_id = request["action_id"]
        if type(action_id) is not str:
            raise ValueError("invalid prepared action ID")
        with self._lock:
            action = self._prepared_actions.get(action_id)
            if action is None:
                raise ValueError("unknown prepared lifecycle action")
            return self._sign_action(action, {key: request[key] for key in ("nonce", "nonce_expires_at", "intent_hash")})

    def _post_ccf(self, path, body):
        if "ccf_url" not in self.config:
            raise ValueError("automatic registration has no configured CCF endpoint")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=self.config["ccf_ca_pem"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        url = urlsplit(self.config["ccf_url"])
        target = url.path.rstrip("/") + path
        connection = http.client.HTTPSConnection(url.hostname, url.port or 443,
            timeout=min(10, CCF_DEADLINE_SECONDS), context=context)
        try:
            # No proxy/redirect adapter is installed. The absolute deadline
            # starts before connection setup and keeps a reference to the TLS
            # socket even if HTTPConnection releases it after response headers.
            with SocketDeadline(CCF_DEADLINE_SECONDS) as deadline:
                connection.connect()
                deadline.bind(connection.sock)
                connection.request("POST", target, body=canonical(body),
                    headers={"Content-Type": "application/json", "Accept": "application/json",
                             "Connection": "close"})
                with connection.getresponse() as response:
                    if response.status >= 300:
                        raise HTTPError(self.config["ccf_url"] + path, response.status,
                            "CCF HTTP request failed", response.headers, None)
                    raw = response.read(MAX_BYTES + 1)
                    deadline.remaining()
                    parsed = strict_json(raw)
                    # A successful transport never proves global commitment.
                    return {"http_status": response.status, "ccf_tx_id": response.headers.get("x-agentdns-transaction-id") or response.headers.get("x-ms-ccf-transaction-id"),
                            "body": parsed}
        finally:
            connection.close()


    def register(self):
        with self._lock:
            if self._last_registration_result is not None:
                return self._last_registration_result
            if self._last_signed_request is None and self.intent_hash in self._signed_actions:
                self._last_signed_request = strict_json(canonical(self._signed_actions[self.intent_hash][1]))
            if self._last_signed_request is None:
                response = self._post_ccf("/service/nonce", {"action": self.action})["body"]
                exact_fields(response, ("nonce", "intent_hash", "issued_at", "expires_at"), ("tx_id", "status"))
                self._last_signed_request = self.signed_request({"nonce": response["nonce"],
                    "intent_hash": response["intent_hash"], "nonce_expires_at": response["expires_at"]})
            # Retry uses precisely the same request after uncertain transport failure.
            self._last_registration_result = self._post_ccf("/service/register", self._last_signed_request)
            return self._last_registration_result


def handler_type(state, token):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "agentdns-aci-capture"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            # No headers, request bodies, bearer token, private key or evidence dumps.
            sys.stderr.write("capture-http " + format % args + "\n")

        def send(self, status, data, content_type="application/json"):
            if not isinstance(data, bytes):
                data = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_GET(self):
            if self.path == "/health":
                self.send(200, {"status": "captured_not_appraised", "profile": PROFILE})
            elif self.path == "/capture":
                self.send(200, state.inventory())
            elif self.path == "/action":
                self.send(200, {"action": state.action, "intent_hash": state.intent_hash})
            elif self.path == "/cert.pem":
                self.send(200, state.tls_certificate.public_bytes(serialization.Encoding.PEM), "application/x-pem-file")
            elif self.path == "/cert.der":
                self.send(200, state.tls_certificate.public_bytes(serialization.Encoding.DER), "application/pkix-cert")
            elif self.path == "/spki.der":
                self.send(200, state.spki, "application/octet-stream")
            elif self.path == "/evidence.cose":
                self.send(200, state.evidence, "application/cose")
            elif self.path == "/report.bin":
                self.send(200, state.report, "application/octet-stream")
            else:
                self.send(404, {"error": "NOT_FOUND"})

        def do_POST(self):
            if self.path not in ("/signed-request", "/register", "/lifecycle/action", "/lifecycle/signed-request"):
                self.send(404, {"error": "NOT_FOUND"})
                return
            if len(self.headers.get_all("Authorization", [])) != 1 or not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                self.send(401, {"error": "UNAUTHORIZED"})
                return
            try:
                if self.headers.get_all("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1 or self.headers.get("Content-Type") != "application/json":
                    raise ValueError("exact JSON Content-Type and one Content-Length are required")
                text = self.headers["Content-Length"]
                if not re.fullmatch(r"[0-9]{1,7}", text) or int(text) > 4096:
                    raise ValueError("invalid request length")
                body = self.rfile.read(int(text))
                if len(body) != int(text):
                    raise ValueError("truncated request")
                request = strict_json(body)
                if self.path == "/signed-request":
                    self.send(200, state.signed_request(request))
                elif self.path == "/lifecycle/action":
                    self.send(200, state.prepare_lifecycle(request))
                elif self.path == "/lifecycle/signed-request":
                    self.send(200, state.sign_lifecycle(request))
                else:
                    exact_fields(request, ())
                    self.send(200, state.register())
            except ValueError as error:
                self.send(400, {"error": "INVALID_REQUEST", "detail": str(error)})
            except HTTPError as error:
                self.send(502, {"error": "CCF_HTTP_ERROR", "status": error.code})
            except Exception:
                self.send(502, {"error": "CAPTURE_OPERATION_FAILED"})
    return Handler


def main():
    # Disable crash dumps before generating private material.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    token = os.environ.get("AGENTDNS_CAPTURE_TOKEN", "")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("AGENTDNS_CAPTURE_TOKEN must be 32 random bytes in lowercase hex")
    encoded = os.environ.get("AGENTDNS_CAPTURE_CONFIG_B64", "")
    config = strict_json(base64.b64decode(encoded, validate=True))
    state = CaptureState(config)
    server = BoundedHTTPServer((state.config.get("listen_address", "0.0.0.0"),
                                 state.config.get("listen_port", 8080)), handler_type(state, token),
                                 tls_context=state.tls_context)
    server.daemon_threads = True
    mail_servers = start_mail_fixtures(state)
    print(json.dumps({"status": "captured_not_appraised", "profile": PROFILE,
                      "spki_sha256": hashlib.sha256(state.spki).hexdigest(),
                      "evidence_digest": state.evidence_digest, "transport": "https",
                      "tls_server_name": TLS_SERVER_NAME, "mail_fixture_ports": state.config["ports"]}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        for mail_server in mail_servers:
            mail_server.shutdown()
            mail_server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"capture startup failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
