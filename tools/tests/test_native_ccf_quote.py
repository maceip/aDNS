"""Bounds/layout guards; synthetic structures are never called hardware evidence."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import verify_native_ccf as verifier


def synthetic_layout():
    raw = bytearray(1184)
    raw[:4] = (5).to_bytes(4, 'little')
    raw[8:16] = (1 << 17).to_bytes(8, 'little')
    raw[52:56] = (1).to_bytes(4, 'little')
    raw[392:395] = bytes([0x19, 0x11, 1])
    return raw


class NodeQuoteGuards(unittest.TestCase):
    def test_v5_vectors_are_independent_unsigned_little_endian(self):
        raw = synthetic_layout()
        raw[504:512] = (1 << 63).to_bytes(8, 'little')
        raw[512:520] = (7).to_bytes(8, 'little')
        fields = verifier.layout(raw)
        self.assertEqual(fields['launch_mitigation_vector'], 1 << 63)
        self.assertEqual(fields['current_mitigation_vector'], 7)
        self.assertEqual(fields['signed_region'], {'start': 0, 'end_inclusive': 671})

    def test_reserved_and_signature_padding_cannot_be_treated_as_vectors(self):
        for offset in (76, 395, 491, 495, 520, 671, 720, 743, 792, 1183):
            with self.subTest(offset=offset):
                raw = synthetic_layout()
                raw[offset] = 1
                with self.assertRaisesRegex(ValueError, 'reserved'):
                    verifier.layout(raw)

    def test_unsupported_layout_is_never_silently_treated_as_v5(self):
        for version in (0, 2, 4, 6, 0xffffffff):
            with self.subTest(version=version):
                raw = synthetic_layout()
                raw[:4] = version.to_bytes(4, 'little')
                with self.assertRaisesRegex(ValueError, 'versions 3 and 5'):
                    verifier.layout(raw)
        for size in (0, 1183, 1185):
            with self.assertRaisesRegex(ValueError, 'length'):
                verifier.layout(bytes(size))

    def test_v3_has_no_mitigation_vectors_and_reserves_all_504_onward(self):
        raw = synthetic_layout()
        raw[:4] = (3).to_bytes(4, 'little')
        fields = verifier.layout(raw)
        self.assertEqual(fields['version'], 3)
        self.assertIsNone(fields['launch_mitigation_vector'])
        self.assertIsNone(fields['current_mitigation_vector'])
        self.assertEqual(fields['reserved_start'], 504)
        for offset in (504, 511, 512, 519, 520, 671):
            altered = raw.copy()
            altered[offset] = 1
            with self.assertRaisesRegex(ValueError, 'reserved'):
                verifier.layout(altered)

    def test_security_flags_vmpl_and_reserved_tcb_are_checked(self):
        for offset, value in ((48, 1), (52, 2), (72, 2), (72, 4), (58, 1), (386, 1), (482, 1), (498, 1)):
            with self.subTest(offset=offset, value=value):
                raw = synthetic_layout()
                raw[offset] = value
                with self.assertRaises(ValueError):
                    verifier.layout(raw)
        for forbidden in (1 << 18, 1 << 19, 1 << 26):
            raw = synthetic_layout()
            raw[8:16] = ((1 << 17) | forbidden).to_bytes(8, 'little')
            with self.assertRaises(ValueError):
                verifier.layout(raw)

    def test_fixed_binding_rejects_nonzero_upper_half(self):
        raw = synthetic_layout()
        public = b'public-test-spki-bytes-for-binding-only'
        raw[80:112] = verifier.hashlib.sha256(public).digest()
        policy = {'active_profiles': ['azure-aci-snp'], 'valid_from': 1, 'valid_until': 100,
                  'approved_measurements': ['00' * 48], 'approved_host_data': ['00' * 32],
                  'minimum_tcb': {'Genoa': dict.fromkeys(verifier.NAMES, 0)}}
        verifier.policy_and_binding(raw, public, policy, 50, verifier.layout(raw))
        raw[143] = 1
        with self.assertRaisesRegex(ValueError, 'REPORT_DATA'):
            verifier.policy_and_binding(raw, public, policy, 50, verifier.layout(raw))

    def test_ambiguous_json_and_noncanonical_base64_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verifier.json_read('{"format":"AMD_SEV_SNP_v1","format":"other"}')
        self.assertEqual(verifier.b64('AA=='), b'\0')
        with self.assertRaises(ValueError):
            verifier.b64('AB==')
        with self.assertRaises(ValueError):
            verifier.b64('AA==\n')
        with self.assertRaises(ValueError):
            verifier.cbor_read(b'\x01\x02')


if __name__ == '__main__':
    unittest.main()
