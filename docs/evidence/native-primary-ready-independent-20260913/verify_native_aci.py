#!/usr/bin/env python3
"""Independent cryptographic cross-check of one approved native ACI capture.

Requires cbor2 and cryptography (available in agentdns-capture:local). Inputs are
explicit public allowlisted files only; no deployment-parameter or secret file
is opened. Does not contact Azure or the worker, or obtain/export its key.
"""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def timestamp(value):
    return int(value.replace(tzinfo=datetime.timezone.utc).timestamp())


def check_chain(chain, at, directory, label):
    for cert in chain:
        assert timestamp(cert.not_valid_before) <= at < timestamp(cert.not_valid_after)
    for cert, issuer in zip(chain, chain[1:]):
        cert.verify_directly_issued_by(issuer)
    chain[-1].verify_directly_issued_by(chain[-1])
    paths = []
    for i, cert in enumerate(chain):
        path = directory / f'{label}-{i}.pem'
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        paths.append(path)
    intermediates = directory / f'{label}-intermediates.pem'
    intermediates.write_bytes(b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain[1:-1]))
    result = subprocess.run(['openssl', 'verify', '-no-CApath', '-no-CAstore', '-auth_level', '2',
                             '-check_ss_sig', '-attime', str(at), '-CAfile', str(paths[-1]),
                             '-untrusted', str(intermediates), str(paths[0])], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def der_items(data):
    """Bounded TLV walk for extracting authenticated native AMD extensions.

    cryptography 41 rejects AMD's explicit RSA-PSS default trailerField. Path
    validation uses OpenSSL; extraction here never confers trust on a value.
    """
    at = 0
    while at < len(data):
        tag = data[at]
        size = data[at + 1]
        at += 2
        if size & 128:
            count = size & 127
            assert 1 <= count <= 4 and at + count <= len(data)
            size = int.from_bytes(data[at:at + count], 'big')
            at += count
        assert at + size <= len(data)
        yield tag, data[at:at + size]
        at += size


def oid_text(encoded):
    numbers = [encoded[0] // 40, encoded[0] % 40]
    n = 0
    for byte in encoded[1:]:
        n = (n << 7) | (byte & 127)
        if not byte & 128:
            numbers.append(n)
            n = 0
    assert not encoded[-1] & 128
    return '.'.join(map(str, numbers))


def amd_certificate(pem):
    raw = base64.b64decode(re.sub(rb'-----[^-]+-----|\s', b'', pem), validate=True)
    outer = list(der_items(raw))
    assert len(outer) == 1 and outer[0][0] == 0x30
    tbs = list(der_items(outer[0][1]))[0]
    assert tbs[0] == 0x30
    extensions = {}
    wrapped = [value for tag, value in der_items(tbs[1]) if tag == 0xa3]
    assert len(wrapped) == 1
    sequence = list(der_items(wrapped[0]))
    assert len(sequence) == 1 and sequence[0][0] == 0x30
    for tag, value in der_items(sequence[0][1]):
        assert tag == 0x30
        fields = list(der_items(value))
        assert fields[0][0] == 6 and fields[-1][0] == 4
        oid = oid_text(fields[0][1])
        assert oid not in extensions
        extensions[oid] = fields[-1][1]
    public = subprocess.run(['openssl', 'x509', '-pubkey', '-noout'], input=pem, capture_output=True, check=True).stdout
    dates = subprocess.run(['openssl', 'x509', '-dates', '-noout'], input=pem, capture_output=True, check=True).stdout.decode()
    validity = {}
    for line in dates.splitlines():
        label, value = line.split('=', 1)
        validity[label] = timestamp(datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z'))
    return {'pem': pem, 'der': raw, 'key': serialization.load_pem_public_key(public),
            'extensions': extensions, **validity}


def check_amd_chain(chain, at, directory):
    for cert in chain:
        assert cert['notBefore'] <= at < cert['notAfter']
    paths = []
    for i, cert in enumerate(chain):
        path = directory / f'amd-{i}.pem'
        path.write_bytes(cert['pem'])
        paths.append(path)
    result = subprocess.run(['openssl', 'verify', '-no-CApath', '-no-CAstore', '-auth_level', '2',
                             '-check_ss_sig', '-attime', str(at), '-CAfile', str(paths[2]),
                             '-untrusted', str(paths[1]), str(paths[0])], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def verify_sign1(encoded, key):
    tagged = cbor2.loads(encoded)
    assert isinstance(tagged, cbor2.CBORTag) and tagged.tag == 18
    protected, unprotected, payload, signature = tagged.value
    assert isinstance(payload, bytes)
    header = cbor2.loads(protected)
    signed_bytes = cbor2.dumps(['Signature1', protected, b'', payload])
    if header[1] == -7:
        assert isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
        assert len(signature) == 64
        signature = utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
        key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
    elif header[1] == -38:
        key.verify(signature, signed_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
    else:
        raise AssertionError(f'unexpected native signature algorithm: {header[1]}')
    return header, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=pathlib.Path, required=True)
    parser.add_argument('--policy', type=pathlib.Path, required=True)
    parser.add_argument('--repository', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--now', type=int, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    policy = json.loads(args.policy.read_bytes())
    assert policy['valid_from'] <= args.now < policy['valid_until']
    assert policy['uvm_endorsement_time_policy'] == 'approved_release'
    artifacts = {name: (args.capture / name).read_bytes() for name in ['capture.json', 'evidence.cose', 'spki.der', 'peer.der']}
    capture = json.loads(artifacts['capture.json'])
    evidence, public_der = artifacts['evidence.cose'], artifacts['spki.der']
    assert b64(capture['evidence_payload']) == evidence
    assert b64(capture['signer_spki_der']) == public_der
    assert b64(capture['action']['signer_spki_der']) == public_der
    assert sha(evidence) == capture['evidence_digest'] == capture['action']['parameters']['evidence_digest']
    assert sha(public_der) == capture['spki_sha256']
    assert b64(capture['tls_certificate_der']) == artifacts['peer.der']
    peer = x509.load_der_x509_certificate(artifacts['peer.der'])
    assert der(peer) == artifacts['peer.der'] and spki(peer.public_key()) == public_der
    peer.verify_directly_issued_by(peer)
    assert timestamp(peer.not_valid_before) <= args.now < timestamp(peer.not_valid_after)
    peer.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName).index(capture['tls_server_name'])
    key = serialization.load_der_public_key(public_der)
    header, raw_payload = verify_sign1(evidence, key)
    assert header == {1: -7}
    native = cbor2.loads(raw_payload)
    assert set(native) == {'att', 'eds', 'uvm'}
    report = native['att']
    assert len(report) == 1184
    assert report[80:112] == hashlib.sha256(public_der).digest()
    assert report[112:144] == bytes(32)
    assert int.from_bytes(report[48:52], 'little') == 0
    assert int.from_bytes(report[52:56], 'little') == 1
    guest_policy = int.from_bytes(report[8:16], 'little')
    assert guest_policy & (1 << 17) and not guest_policy & ((1 << 18) | (1 << 19))
    assert guest_policy >> 26 == 0
    assert int.from_bytes(report[72:76], 'little') & ~1 == 0
    assert report[144:192].hex() in policy['approved_measurements']
    assert report[192:224].hex() in policy['approved_host_data']
    thim = json.loads(base64.b64decode(native['eds'], validate=True))
    raw_amd = (thim['vcekCert'] + thim['certificateChain']).encode()
    amd_chain = [amd_certificate(pem) for pem in re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', raw_amd, re.S)]
    assert len(amd_chain) == 3
    pinned_ark = serialization.load_pem_public_key((args.repository / 'crates/adns-attest/src/amd_genoa_ark.pem').read_bytes())
    assert spki(amd_chain[-1]['key']) == spki(pinned_ark)
    vcek_key = amd_chain[0]['key']
    assert isinstance(vcek_key.curve, ec.SECP384R1)
    report_signature = utils.encode_dss_signature(int.from_bytes(report[672:720], 'little'), int.from_bytes(report[744:792], 'little'))
    vcek_key.verify(report_signature, report[:672], ec.ECDSA(hashes.SHA384()))
    def extension(oid):
        return amd_chain[0]['extensions'][oid]
    def spl(suffix):
        raw = extension(f'1.3.6.1.4.1.3704.1.3.{suffix}')
        assert raw[0] == 2 and raw[1] == len(raw) - 2
        return int.from_bytes(raw[2:], 'big')
    reported = dict(zip(['bootloader', 'tee', 'snp', 'microcode'], [report[384], report[385], report[390], report[391]]))
    assert reported == dict(zip(reported, [spl(1), spl(2), spl(3), spl(8)]))
    assert all(spl(i) == 0 for i in [4, 5, 6, 7])
    assert extension('1.3.6.1.4.1.3704.1.4') == report[416:480]
    product = extension('1.3.6.1.4.1.3704.1.2')
    assert product[0] == 0x16 and product[1] == len(product) - 2 and product[2:].startswith(b'Genoa')
    minimum = policy['minimum_tcb']['Genoa']
    for offset in [56, 384, 480, 496]:
        assert report[offset + 2:offset + 6] == bytes(4)
        for name, displacement in zip(reported, [0, 1, 6, 7]):
            assert report[offset + displacement] >= minimum[name]
    assert report[392] == 0x19 and 0x10 <= report[393] <= 0x1f
    uvm = cbor2.loads(native['uvm'])
    uvm_header = cbor2.loads(uvm.value[0])
    uvm_chain = [x509.load_der_x509_certificate(raw) for raw in uvm_header[33]]
    verify_sign1(native['uvm'], uvm_chain[0].public_key())
    identity = next(i for i in policy['uvm'] if i['did'] == uvm_header['iss'] and i['feed'] == uvm_header['feed'])
    fingerprint, eku = identity['did'].removeprefix('did:x509:0:sha256:').split('::eku:')
    assert base64.urlsafe_b64encode(hashlib.sha256(der(uvm_chain[-1])).digest()).rstrip(b'=').decode() == fingerprint
    assert x509.ObjectIdentifier(eku) in uvm_chain[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert uvm_chain[0].extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    assert not uvm_chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    descriptor = json.loads(uvm.value[2])
    assert bytes.fromhex(descriptor['x-ms-sevsnpvm-launchmeasurement']) == report[144:192]
    svn = int(descriptor['x-ms-sevsnpvm-guestsvn'])
    assert svn >= identity['minimum_svn']
    historical_time = max(timestamp(cert.not_valid_before) for cert in uvm_chain)
    assert historical_time <= args.now
    with tempfile.TemporaryDirectory() as temporary:
        check_amd_chain(amd_chain, args.now, pathlib.Path(temporary))
        check_chain(uvm_chain, historical_time, pathlib.Path(temporary), 'uvm')
    assert args.now >= timestamp(uvm_chain[0].not_valid_after), 'strict-expiry negative needs an expired native UVM publisher'
    # Mutate only the captured public bytes. The in-guest private key is never
    # available, so these envelopes intentionally retain their invalid old MAC.
    variants = args.output / 'variants'
    variants.mkdir(exist_ok=True)
    for label, offset in [('report-tamper', 144), ('padding-tamper', 112)]:
        tagged = cbor2.loads(evidence)
        items = list(tagged.value)
        inner = cbor2.loads(items[2])
        altered = bytearray(inner['att'])
        altered[offset] ^= 1
        inner['att'] = bytes(altered)
        items[2] = cbor2.dumps(inner)
        changed = cbor2.dumps(cbor2.CBORTag(18, items))
        (variants / f'{label}.cose').write_bytes(changed)
        try:
            verify_sign1(changed, key)
        except InvalidSignature:
            pass
        else:
            raise AssertionError('tampered outer envelope authenticated')
        try:
            vcek_key.verify(report_signature, bytes(altered[:672]), ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            pass
        else:
            raise AssertionError('tampered native report authenticated')
    # A deliberately public deterministic test key, unrelated to the guest key.
    (variants / 'wrong-spki.der').write_bytes(spki(ec.derive_private_key(1, ec.SECP256R1()).public_key()))
    (args.output / 'report.bin').write_bytes(report)
    (args.output / 'uvm.cose').write_bytes(native['uvm'])
    result = {
        'verification_time': args.now, 'outer_es256_verified': True, 'tls_peer_certificate_self_signature_verified': True,
        'tls_peer_spki_matches_attested_spki': True, 'report_data_exact_sha256_spki_and_zero_padding': True,
        'amd_pinned_ark_chain_currently_valid': True, 'native_snp_p384_sha384_signature_verified': True,
        'vcek_chip_id_and_reported_tcb_match': True, 'all_four_tcb_states_meet_policy': True,
        'product': 'Genoa', 'reported_tcb': reported, 'uvm_ps384_signature_verified': True,
        'uvm_pinned_did_eku_and_feed_match': True, 'uvm_chain_verified_at_common_past_validity': historical_time,
        'uvm_svn': svn, 'uvm_publisher_certificate_expires_at': timestamp(uvm_chain[0].not_valid_after),
        'uvm_release_time_policy': policy['uvm_endorsement_time_policy'],
        'exact_governed_measurement': report[144:192].hex(), 'exact_governed_host_data': report[192:224].hex(),
        'evidence_sha256': sha(evidence), 'spki_sha256': sha(public_der),
        'policy_source': 'explicit supplied governed policy; no observed-field auto-approval',
        'amd_certificate_parser_note': 'Native AMD explicit RSA-PSS default trailerField is rejected by cryptography41; AMD chain verified with OpenSSL CLI and VCEK P384 report signature with cryptography',
        'tamper_tests': 'modified captured bytes; unchanged original outer and AMD signatures both rejected; no freshly signed malformed hardware report',
    }
    (args.output / 'independent-crypto.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
