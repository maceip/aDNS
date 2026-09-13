#!/usr/bin/env python3
"""Offline, independent verification of an actual raw CCF SNP-v5 node quote.

Consumes only the supplied public quote, actual captured TLS peer certificate,
preapproved policy and pinned AMD public key. There is no worker COSE wrapper,
service admission, network request, or trust-policy mutation. Shared certificate
primitives use OpenSSL; the hardware signature uses Python cryptography.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import io
import json
import pathlib
import platform
import subprocess
import tempfile

import cbor2
import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import verify_native_aci as common

SPEC = 'https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf'
MAX_INPUT = 1024 * 1024
NAMES = ('bootloader', 'tee', 'snp', 'microcode')


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'duplicate JSON field')
        result[name] = value
    return result


def json_read(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def b64(encoded):
    require(isinstance(encoded, str) and len(encoded) <= MAX_INPUT, 'base64 input size/type')
    result = base64.b64decode(encoded, validate=True)
    require(base64.b64encode(result).decode() == encoded, 'noncanonical base64')
    return result


def cbor_read(raw):
    source = io.BytesIO(raw)
    result = cbor2.CBORDecoder(source).decode()
    require(not source.read(1), 'trailing CBOR bytes')
    return result


def read_bounded(path, limit=MAX_INPUT):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'input exceeds bound')
    return raw


def u64(raw, offset):
    return int.from_bytes(raw[offset:offset + 8], 'little')


def layout(report):
    require(len(report) == 1184, 'SNP report length')
    require(int.from_bytes(report[:4], 'little') == 5, 'this independent verifier requires report version 5')
    for begin, end in [(76, 80), (395, 416), (491, 492), (495, 496),
                       (520, 672), (720, 744), (792, 1184)]:
        require(not any(report[begin:end]), f'nonzero reserved bytes {begin}:{end}')
    require(int.from_bytes(report[48:52], 'little') == 0, 'guest VMPL must be zero')
    require(int.from_bytes(report[52:56], 'little') == 1, 'P384/SHA384 report algorithm required')
    guest_policy = u64(report, 8)
    require(guest_policy & (1 << 17) and not guest_policy & ((1 << 18) | (1 << 19))
            and guest_policy >> 26 == 0, 'debug/migration/reserved guest policy')
    require(int.from_bytes(report[72:76], 'little') & ~1 == 0, 'unmasked VCEK signing required')
    require(report[392] == 0x19 and 0x10 <= report[393] <= 0x1f, 'Genoa CPUID required')
    states = {}
    for name, offset in [('current', 56), ('reported', 384), ('committed', 480), ('launch', 496)]:
        require(report[offset + 2:offset + 6] == bytes(4), 'reserved TCB bytes')
        states[name] = dict(zip(NAMES, [report[offset + n] for n in (0, 1, 6, 7)]))
    return {'version': 5, 'signed_region': {'start': 0, 'end_inclusive': 671},
            'launch_mitigation_vector': u64(report, 504), 'current_mitigation_vector': u64(report, 512),
            'mitigation_vector_policy': 'authenticated inventory; supplied policy has no mitigation-bit floor',
            'reserved_520_through_671_zero': True, 'tcb_states': states}


def policy_and_binding(report, public_der, policy, now, fields):
    require('azure-aci-snp' in policy['active_profiles'], 'inactive profile')
    require(policy['valid_from'] <= now < policy['valid_until'], 'expired/not-yet-valid policy')
    require(report[80:144] == hashlib.sha256(public_der).digest() + bytes(32), 'fixed REPORT_DATA binding')
    require(report[144:192].hex() in policy['approved_measurements'], 'unapproved measurement')
    require(report[192:224].hex() in policy['approved_host_data'], 'unapproved CCE host data')
    minimum = policy['minimum_tcb']['Genoa']
    for state in fields['tcb_states'].values():
        require(all(state[name] >= minimum[name] for name in NAMES), 'TCB below minimum')


def hardware_signature(report, key):
    require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1),
            'VCEK must be P384')
    signature = utils.encode_dss_signature(int.from_bytes(report[672:720], 'little'),
                                           int.from_bytes(report[744:792], 'little'))
    key.verify(signature, report[:672], ec.ECDSA(hashes.SHA384()))


def verify_uvm(encoded, measurement, policy, now, directory):
    sign1 = cbor_read(encoded)
    require(isinstance(sign1, cbor2.CBORTag) and sign1.tag == 18 and len(sign1.value) == 4, 'UVM Sign1')
    protected, unprotected, payload, signature = sign1.value
    require(isinstance(protected, bytes) and isinstance(unprotected, dict)
            and isinstance(payload, bytes) and isinstance(signature, bytes), 'UVM field types')
    header = cbor_read(protected)
    require(header[1] == -38, 'native UVM PS384 algorithm required')
    raw_chain = header[33]
    require(isinstance(raw_chain, list) and 2 <= len(raw_chain) <= 6, 'UVM chain length')
    chain = [x509.load_der_x509_certificate(raw) for raw in raw_chain]
    require(all(len(raw) <= 16384 and common.der(cert) == raw for cert, raw in zip(chain, raw_chain)),
            'noncanonical UVM certificate')
    common.verify_sign1(encoded, chain[0].public_key())
    if 15 in header:
        require(header[259] == 'application/octet-stream', 'UVM preimage content type')
        claims = header[15]
        did, feed, svn = claims[1], claims[2], claims['svn']
        issuance = claims[6]
        if isinstance(issuance, datetime.datetime):
            issuance = int(issuance.timestamp())
        require(type(issuance) is int and 0 <= issuance <= now, 'UVM issuance time')
        require(type(svn) is int and 0 <= svn <= 0xffffffff, 'UVM SVN type')
        endorsed = payload
    else:
        require(header[3] == 'application/json', 'legacy UVM content type')
        did, feed = header['iss'], header['feed']
        descriptor = json_read(payload)
        svn = descriptor['x-ms-sevsnpvm-guestsvn']
        require(type(svn) is int or isinstance(svn, str) and svn.isascii() and svn.isdecimal(), 'UVM SVN type')
        svn = int(svn)
        require(0 <= svn <= 0xffffffff, 'UVM SVN bounds')
        endorsed = bytes.fromhex(descriptor['x-ms-sevsnpvm-launchmeasurement'])
        issuance = None
    require(endorsed == measurement, 'UVM measurement mismatch')
    identities = [value for value in policy['uvm'] if value['did'] == did and value['feed'] == feed]
    require(identities and svn >= min(value['minimum_svn'] for value in identities), 'UVM identity/feed/SVN')
    require(did.startswith('did:x509:0:sha256:'), 'UVM DID format')
    fingerprint, eku = did.removeprefix('did:x509:0:sha256:').split('::eku:')
    require(base64.urlsafe_b64encode(hashlib.sha256(raw_chain[-1]).digest()).rstrip(b'=').decode() == fingerprint,
            'UVM pinned DID root')
    require(x509.ObjectIdentifier(eku) in chain[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
            'UVM leaf EKU')
    require(chain[0].extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
            and not chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'UVM leaf usage')
    mode = policy.get('uvm_endorsement_time_policy', 'current_certificate')
    require(mode in ('approved_release', 'current_certificate'), 'unknown UVM expiry mode')
    historical_time = issuance if issuance is not None else max(common.timestamp(cert.not_valid_before) for cert in chain)
    require(historical_time <= now, 'future UVM chain validity')
    common.check_chain(chain, historical_time, directory, 'uvm-release')
    strict_valid = all(common.timestamp(cert.not_valid_before) <= now < common.timestamp(cert.not_valid_after) for cert in chain)
    if mode == 'current_certificate':
        common.check_chain(chain, now, directory, 'uvm-current')
    return {'ps384_signature_verified': True, 'did': did, 'feed': feed, 'svn': svn,
            'time_policy': mode, 'authenticated_issuance_time': issuance,
            'verified_certificate_path_time': historical_time, 'current_certificate_time_valid': strict_valid,
            'publisher_certificate_not_after': common.timestamp(chain[0].not_valid_after)}


def reject(operation):
    try:
        operation()
    except (ValueError, AssertionError, InvalidSignature):
        return True
    raise ValueError('negative variant unexpectedly accepted')


def verify(quote_raw, peer_raw, policy_raw, ark_pem, now):
    require(__debug__, 'shared verifier assertions require Python without optimization')
    quote, policy = json_read(quote_raw), json_read(policy_raw)
    require(set(quote) <= {'node_id', 'raw', 'endorsements', 'format', 'measurement', 'uvm_endorsements'}, 'unknown quote field')
    require(quote['format'] == 'AMD_SEV_SNP_v1', 'CCF quote profile')
    report, amd_pem, uvm = b64(quote['raw']), b64(quote['endorsements']), b64(quote['uvm_endorsements'])
    fields = layout(report)
    peer = x509.load_der_x509_certificate(peer_raw)
    require(common.der(peer) == peer_raw, 'noncanonical TLS peer DER')
    public_der = common.spki(peer.public_key())
    require(isinstance(peer.public_key(), ec.EllipticCurvePublicKey)
            and isinstance(peer.public_key().curve, (ec.SECP256R1, ec.SECP384R1)), 'node EC key curve')
    require(common.timestamp(peer.not_valid_before) <= now < common.timestamp(peer.not_valid_after), 'TLS peer validity')
    require(quote['node_id'] == common.sha(public_der), 'CCF node ID must equal attested peer SPKI SHA256')
    require(quote.get('measurement', report[144:192].hex()) == report[144:192].hex(), 'outer quote measurement mismatch')
    policy_and_binding(report, public_der, policy, now, fields)
    import re
    pem_blocks = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', amd_pem, re.S)
    require(len(pem_blocks) == 3 and not re.sub(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', b'', amd_pem, flags=re.S).strip(),
            'AMD PEM chain must contain exactly three certificates')
    chain = [common.amd_certificate(pem) for pem in pem_blocks]
    pinned = serialization.load_pem_public_key(ark_pem)
    require(common.spki(chain[-1]['key']) == common.spki(pinned), 'pinned AMD Genoa ARK public key mismatch')
    hardware_signature(report, chain[0]['key'])
    extensions = chain[0]['extensions']
    def spl(suffix):
        raw = extensions[f'1.3.6.1.4.1.3704.1.3.{suffix}']
        require(raw[0] == 2 and raw[1] == len(raw) - 2 and 1 <= raw[1] <= 2, 'AMD SPL integer')
        value = int.from_bytes(raw[2:], 'big')
        require(0 <= value <= 255, 'AMD SPL range')
        return value
    require(fields['tcb_states']['reported'] == dict(zip(NAMES, [spl(i) for i in (1, 2, 3, 8)])), 'VCEK reported TCB mismatch')
    require(all(spl(i) == 0 for i in (4, 5, 6, 7)), 'AMD reserved SPL')
    require(extensions['1.3.6.1.4.1.3704.1.4'] == report[416:480], 'VCEK chip ID mismatch')
    product = extensions['1.3.6.1.4.1.3704.1.2']
    require(product[0] == 0x16 and product[1] == len(product) - 2 and product[2:].startswith(b'Genoa'), 'VCEK product')
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        common.check_amd_chain(chain, now, directory)
        uvm_result = verify_uvm(uvm, report[144:192], policy, now, directory)
        negatives = {}
        for name, offset in [('report_data', 80), ('report_data_padding', 112), ('measurement', 144), ('cce', 192),
                             ('launch_mitigation_vector', 504), ('current_mitigation_vector', 512), ('reserved_520', 520)]:
            altered = bytearray(report)
            altered[offset] ^= 1
            negatives[name + '_original_hardware_signature_rejected'] = reject(lambda: hardware_signature(bytes(altered), chain[0]['key']))
        altered = bytearray(report)
        altered[520] = 1
        negatives['nonzero_reserved_520_structurally_rejected'] = reject(lambda: layout(bytes(altered)))
        wrong_spki = common.spki(ec.derive_private_key(1, ec.SECP256R1()).public_key())
        negatives['wrong_spki_binding_rejected'] = reject(lambda: policy_and_binding(report, wrong_spki, policy, now, fields))
        for name, mutate in [('wrong_cce', lambda p: p.update(approved_host_data=['00' * 32])),
                             ('wrong_measurement', lambda p: p.update(approved_measurements=['00' * 48])),
                             ('inactive_profile', lambda p: p.update(active_profiles=[])),
                             ('expired_policy', lambda p: p.update(valid_until=now)),
                             ('tcb_floor_above_actual', lambda p: p['minimum_tcb']['Genoa'].update(microcode=255))]:
            altered_policy = copy.deepcopy(policy)
            mutate(altered_policy)
            negatives[name + '_rejected'] = reject(lambda: policy_and_binding(report, public_der, altered_policy, now, fields))
        altered_policy = copy.deepcopy(policy)
        for identity in altered_policy['uvm']:
            identity['minimum_svn'] = 0xffffffff
        negatives['uvm_svn_floor_above_actual_rejected'] = reject(lambda: verify_uvm(uvm, report[144:192], altered_policy, now, directory))
        if not uvm_result['current_certificate_time_valid']:
            altered_policy = copy.deepcopy(policy)
            altered_policy['uvm_endorsement_time_policy'] = 'current_certificate'
            negatives['strict_current_uvm_certificate_expiry_rejected'] = reject(lambda: verify_uvm(uvm, report[144:192], altered_policy, now, directory))
    result = {'status': 'passed', 'purpose': 'independent-offline-ccf-node-quote-cross-check-only', 'verification_time': now,
              'specification': {'url': SPEC, 'revision': '1.58 May 2025', 'table': 23},
              'quote_format': quote['format'], 'node_id': quote['node_id'], 'node_key_curve': peer.public_key().curve.name,
              'report': fields, 'tls_peer_spki_matches_hardware_report_data': True,
              'report_data_sha256_spki_plus_zero32': True, 'native_p384_sha384_signature_verified': True,
              'amd_genoa_pinned_ark_chain_currently_valid': True, 'vcek_chip_id_and_reported_tcb_match': True,
              'exact_preapproved_measurement': report[144:192].hex(), 'exact_preapproved_host_data': report[192:224].hex(),
              'uvm': uvm_result, 'negative_checks': negatives, 'negative_check_count': len(negatives),
              'provenance': {'quote_json_sha256': common.sha(quote_raw), 'raw_report_sha256': common.sha(report),
                             'actual_tls_peer_der_sha256': common.sha(peer_raw), 'node_spki_sha256': common.sha(public_der),
                             'policy_json_sha256': common.sha(policy_raw), 'policy_id': bytes(policy['policy_id']).hex(),
                             'amd_chain_sha256': common.sha(amd_pem), 'uvm_sha256': common.sha(uvm), 'pinned_ark_pem_sha256': common.sha(ark_pem)},
              'limits': ['Offline check of the supplied captured actual TLS peer; this command makes no fresh TLS connection.',
                         'No worker Sign1 envelope exists or was synthesized. This is not a service registration appraisal.',
                         'TLS peer certificate issuer validation is not used as the bootstrap trust source; its key is authenticated directly by SNP.',
                         'Policy was supplied independently; no observed measurement, CCE, TCB or UVM value was auto-approved.',
                         'Negative report edits retain the original hardware signature; no freshly hardware-signed malformed report is claimed.']}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quote', required=True, type=pathlib.Path)
    parser.add_argument('--peer', required=True, type=pathlib.Path)
    parser.add_argument('--policy', required=True, type=pathlib.Path)
    parser.add_argument('--ark', required=True, type=pathlib.Path)
    parser.add_argument('--now', required=True, type=int)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    require(not args.output.exists(), 'output directory must be new')
    quote, peer, policy, ark = (read_bounded(args.quote), read_bounded(args.peer, 16384), read_bounded(args.policy), read_bounded(args.ark, 16384))
    result = verify(quote, peer, policy, ark, args.now)
    args.output.mkdir(parents=True)
    artifacts = {'node-quote.json': quote, 'node-peer.der': peer, 'node-policy.json': policy, 'amd_genoa_ark.pem': ark,
                 'verify_native_ccf.py': pathlib.Path(__file__).read_bytes(),
                 'verify_native_aci.py': pathlib.Path(common.__file__).read_bytes()}
    for name, raw in artifacts.items():
        (args.output / name).write_bytes(raw)
    result['runtime'] = {'python': platform.python_version(), 'cryptography': cryptography.__version__,
                         'openssl': subprocess.run(['openssl', 'version'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()}
    result['public_artifact_sha256'] = {name: common.sha(raw) for name, raw in artifacts.items()}
    (args.output / 'independent-crypto.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
