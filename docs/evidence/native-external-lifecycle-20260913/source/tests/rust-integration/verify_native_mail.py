#!/usr/bin/env python3
"""Validate DNSSEC/DANE against an explicit, disclosed fixture connection route.

Run only inside a disposable Linux test container with NET_ADMIN. This changes
packet destination routing inside that container, never DNS answers or TLS.
No mutation signature, bearer token, private attested key or AXFR key is needed.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import platform
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def checked_name(value):
    if value != value.lower() or not value.endswith('.') or len(value) > 240 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value[:-1].split('.')):
        raise ValueError('expected a bounded lowercase absolute DNS name')
    return value


def anchor_text(path, zone):
    match = re.fullmatch(r'\s*trust-anchors\s*\{\s*"([a-z0-9.-]+)"\s+static-key\s+257\s+3\s+(\d{1,3})\s+"([A-Za-z0-9+/=]+)"\s*;\s*\}\s*;\s*', path.read_text())
    if not match or match[1] != zone or not 1 <= int(match[2]) <= 255:
        raise ValueError('supply exactly one independently authenticated static zone KSK')
    key = base64.b64decode(match[3], validate=True)
    if not key or base64.b64encode(key).decode() != match[3]:
        raise ValueError('invalid DNSKEY encoding')
    return f'trust-anchors {{ "{zone}" static-key 257 3 {match[2]} "{match[3]}"; }};\n'


def authenticated_rrs(name, kind):
    result = dns.query.udp(dns.message.make_query(name, kind, want_dnssec=True), '127.0.0.1', timeout=5)
    if result.flags & dns.flags.TC:
        result = dns.query.tcp(dns.message.make_query(name, kind, want_dnssec=True), '127.0.0.1', timeout=5)
    if result.rcode() != 0 or not result.flags & dns.flags.AD:
        raise AssertionError(f'{name} {kind} lacks successful local DNSSEC validation')
    records = [record for rrset in result.answer if rrset.rdtype == dns.rdatatype.from_text(kind) for record in rrset]
    if not records:
        raise AssertionError(f'{name} {kind} has no authenticated answers')
    return records


@contextmanager
def routed(published, target, target_port=25):
    rule = ['-d', f'{published}/32', '-p', 'tcp', '--dport', '25', '-j', 'DNAT',
            '--to-destination', f'{target}:{target_port}']
    subprocess.run(['iptables', '-t', 'nat', '-I', 'OUTPUT', '1', *rule], check=True)
    try:
        yield
    finally:
        subprocess.run(['iptables', '-t', 'nat', '-D', 'OUTPUT', *rule], check=True)


def postfix_probe(mailbox, output, positive, peer_digest):
    command = ['posttls-finger', '-l', 'dane-only', '-L', 'summary,verbose', '-t', '5', '-T', '5',
        '-o', 'inet_protocols=ipv4', '-o', 'smtp_dns_support_level=dnssec', mailbox.rstrip('.')]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    log = result.stdout + result.stderr
    output.write_text(log)
    fingerprint = re.search(r'pkey_fingerprint=([0-9A-F:]+)', log)
    if not fingerprint or fingerprint[1].replace(':', '').lower() != peer_digest.hex():
        raise AssertionError('stock Postfix did not observe the expected actual peer key')
    verified = 'Verified TLS connection established' in log
    rejected = 'Untrusted TLS connection established' in log or 'Server certificate not trusted' in log
    # Postfix's diagnostic program returns zero for an untrusted connection too.
    # Connection refused, timeout or missing TLSA is not an adequate negative.
    if positive and not verified:
        raise AssertionError('stock Postfix did not authenticate the matching TLS peer; inspect its log')
    if not positive and (verified or not rejected):
        raise AssertionError('wrong-key peer did not reach a rejected TLS handshake; inspect its log')
    return {'exit_code': result.returncode, 'verified': verified, 'key_mismatch_rejected': rejected,
            'actual_peer_spki_sha256': peer_digest.hex(),
            'command': command, 'log': output.name}


class WrongKeySMTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class WrongKeyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.request
        peer.settimeout(5)
        try:
            peer.sendall(b'220 controlled-wrong-key ESMTP validation\r\n')
            for _ in range(8):
                line = bytearray()
                while len(line) < 512:
                    value = peer.recv(1)
                    if not value:
                        return
                    line.extend(value)
                    if value == b'\n':
                        break
                else:
                    return
                command = bytes(line).upper()
                if command.startswith(b'EHLO '):
                    peer.sendall(b'250-controlled-wrong-key\r\n250 STARTTLS\r\n')
                elif command == b'STARTTLS\r\n':
                    peer.sendall(b'220 Ready for TLS\r\n')
                    peer = self.server.context.wrap_socket(peer, server_side=True)
                elif command == b'QUIT\r\n':
                    peer.sendall(b'221 Bye\r\n')
                    return
                else:
                    peer.sendall(b'550 Validation fixture does not accept messages\r\n')
        except OSError:
            pass
        finally:
            peer.close()


def wrong_peer(directory):
    # This intentionally unrelated negative-test key is local fixture material,
    # never a replacement for the native workload's private key or evidence.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'controlled-wrong-key')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(hours=1)).sign(key, hashes.SHA256()))
    key_file, cert_file = directory/'negative.key', directory/'negative.pem'
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_file.chmod(0o600)
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    server = WrongKeySMTP(('127.0.0.1', 0), WrongKeyHandler)
    server.context = context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return server, hashlib.sha256(spki).digest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dns-server', required=True)
    parser.add_argument('--dns-port', type=int, default=53)
    parser.add_argument('--connection-address', required=True)
    parser.add_argument('--published-address', default='192.0.2.1')
    parser.add_argument('--zone', default='example.test.')
    parser.add_argument('--mailbox-domain', default='example.test.')
    parser.add_argument('--service-host', default='mail.example.test.')
    parser.add_argument('--anchor', required=True, type=Path)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--spki', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or not Path("/.dockerenv").is_file():
        raise RuntimeError("run only in a disposable Docker container with a private network namespace")
    for field in ('dns_server', 'connection_address', 'published_address'):
        setattr(args, field, str(ipaddress.IPv4Address(getattr(args, field))))
    if not 1 <= args.dns_port <= 65535:
        raise ValueError('invalid DNS port')
    for field in ('zone', 'mailbox_domain', 'service_host'):
        setattr(args, field, checked_name(getattr(args, field)))
    for name in (args.mailbox_domain, args.service_host):
        if name != args.zone and not name.endswith('.'+args.zone):
            raise ValueError('fixture name is outside the supplied anchor zone')
    args.output.mkdir(parents=True, exist_ok=True)
    certificate = x509.load_pem_x509_certificate(args.certificate.read_bytes())
    spki = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if spki != args.spki.read_bytes():
        raise ValueError('controlled trust certificate does not contain the independently appraised key')
    digest = hashlib.sha256(spki).digest()
    context = ssl.create_default_context(cafile=str(args.certificate))
    results = {'recorded_at': int(time.time()), 'dns_server': args.dns_server, 'dns_port': args.dns_port,
        'service_host': args.service_host, 'mailbox_domain': args.mailbox_domain, 'expected_spki_sha256': digest.hex(),
        'input_certificate_der_sha256': hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest(),
        'input_anchor_file_sha256': hashlib.sha256(args.anchor.read_bytes()).hexdigest(),
        'connection_override': {'kind': 'container OUTPUT DNAT', 'signed_address': args.published_address,
            'actual_positive_peer': args.connection_address, 'port': 25, 'dns_answers_changed': False,
            'tls_terminated_by_override': False},
        'limits': ['controlled routing; advertised reserved addresses are not proved publicly routable',
            'controlled certificate trust; not public ACME issuance', 'SMTP TLS probe; no email delivery',
            'this tool consumes appraised public artifacts and cannot itself prove hardware or CCF commitment']}
    with tempfile.TemporaryDirectory(prefix='agentdns-native-mail-') as temporary:
        temporary = Path(temporary)
        anchor = anchor_text(args.anchor, args.zone)
        resolver_config = temporary/'named.conf'
        resolver_config.write_text(anchor + f'''
options {{ directory "{temporary}"; listen-on port 53 {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
recursion yes; allow-recursion {{ 127.0.0.1; }}; dnssec-validation yes; empty-zones-enable no;
pid-file "{temporary}/named.pid"; session-keyfile "{temporary}/session.key"; }};
controls {{ }};
zone "{args.zone}" {{ type forward; forward only; forwarders {{ {args.dns_server} port {args.dns_port}; }}; }};
''')
        subprocess.run(['named-checkconf', str(resolver_config)], check=True)
        with (args.output/'validating-resolver.log').open('wb') as log:
            resolver = subprocess.Popen(['named', '-g', '-n', '1', '-c', str(resolver_config)], stdout=log, stderr=log)
            negative = None
            try:
                for _ in range(60):
                    try:
                        authenticated_rrs(args.zone, 'SOA')
                        break
                    except (OSError, dns.exception.DNSException, AssertionError):
                        if resolver.poll() is not None:
                            raise RuntimeError('validating resolver exited')
                        time.sleep(0.2)
                else:
                    raise RuntimeError('validating resolver did not authenticate the supplied zone')
                Path('/etc/resolv.conf').write_text('nameserver 127.0.0.1\noptions timeout:2 attempts:2 trust-ad\n')
                addresses = authenticated_rrs(args.service_host, 'A')
                if {r.address for r in addresses} != {args.published_address}:
                    raise AssertionError('signed A set differs from the sole explicit connection route')
                if {r.exchange.to_text() for r in authenticated_rrs(args.mailbox_domain, 'MX')} != {args.service_host}:
                    raise AssertionError('authenticated MX does not designate the tested service host')
                tlsa = {}
                original_tlsa = {}
                for port in (25, 465, 993):
                    records = authenticated_rrs(f'_{port}._tcp.{args.service_host}', 'TLSA')
                    original_tlsa[port] = sorted(r.to_text() for r in records)
                    matches = {r.cert for r in records if (r.usage, r.selector, r.mtype) == (3, 1, 1)}
                    if digest not in matches:
                        raise AssertionError('authenticated TLSA does not authorize the independently appraised key')
                    tlsa[port] = matches
                results['dnssec_validated_a_mx_and_all_tlsa'] = True
                with routed(args.published_address, args.connection_address):
                    results['dane_positive'] = postfix_probe(args.mailbox_domain, args.output/'postfix-native-positive.log', True, digest)
                negative, wrong_digest = wrong_peer(temporary)
                if wrong_digest in tlsa[25]:
                    raise AssertionError('negative fixture unexpectedly appears in the authenticated TLSA set')
                with routed(args.published_address, '127.0.0.1', negative.server_address[1]):
                    results['dane_wrong_key'] = postfix_probe(args.mailbox_domain, args.output/'postfix-native-wrong-key.log', False, wrong_digest)
                results['dane_wrong_key']['peer_spki_sha256'] = wrong_digest.hex()
                # DNSSEC TLSA answers stay unchanged across both routed connections.
                for port, original in original_tlsa.items():
                    if sorted(r.to_text() for r in authenticated_rrs(f'_{port}._tcp.{args.service_host}', 'TLSA')) != original:
                        raise AssertionError('TLSA answer changed during positive/negative route test')
                results['authenticated_tlsa_unchanged'] = original_tlsa
                results['pkix'] = {}
                for port in (465, 993):
                    with socket.create_connection((args.connection_address, port), 5) as raw:
                        with context.wrap_socket(raw, server_hostname=args.service_host.rstrip('.')) as peer:
                            actual = x509.load_der_x509_certificate(peer.getpeercert(binary_form=True))
                            actual_spki = actual.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                            if actual_spki != spki:
                                raise AssertionError('implicit TLS peer presents a different key')
                            results['pkix'][str(port)] = {'controlled_trust_verified': True, 'peer_spki_matches_native_input_and_dnssec_tlsa': True, 'tls_version': peer.version()}
                    for label, trust, name in [('wrong_hostname', context, 'wrong.invalid'),
                            ('untrusted', ssl.create_default_context(), args.service_host.rstrip('.'))]:
                        try:
                            with socket.create_connection((args.connection_address, port), 5) as raw:
                                with trust.wrap_socket(raw, server_hostname=name):
                                    pass
                        except ssl.SSLCertVerificationError:
                            results['pkix'][str(port)][label+'_rejected'] = True
                        else:
                            raise AssertionError(f'implicit TLS {label} was accepted')
            finally:
                if negative is not None:
                    negative.shutdown()
                    negative.server_close()
                resolver.terminate()
                resolver.wait(timeout=10)
    (args.output/'native-mail-results.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(results, indent=2), flush=True)


if __name__ == '__main__':
    main()
