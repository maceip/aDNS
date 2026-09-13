"""Exercise the retained demo binding primitive without obsolete demo dependencies."""
import ast
import hashlib
import hmac
from pathlib import Path
import re
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SOURCE = Path(__file__).resolve().parents[2]/'demo/client/ksk.py'
tree = ast.parse(SOURCE.read_text())
definition = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == 'verify_tls_report_binding')
namespace = {'hmac':hmac, 're':re}
exec(compile(ast.Module(body=[definition], type_ignores=[]), str(SOURCE), 'exec'), namespace)
verify = namespace['verify_tls_report_binding']


class LegacyBindingTests(unittest.TestCase):
    def test_actual_distinct_public_keys_and_every_report_digest_byte(self):
        keys = [ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            for _ in range(2)]
        digests = [hashlib.sha256(key).digest() for key in keys]
        report = digests[0] + bytes(32)
        verify(digests[0].hex(), report)
        with self.assertRaises(ValueError):verify(digests[1].hex(), report)
        for index in range(32):
            changed = bytearray(report);changed[index] ^= 1
            with self.subTest(index=index),self.assertRaises(ValueError):
                verify(digests[0].hex(), changed)
        for value in (report[:32], report[:-1], report+b'\0', None):
            with self.assertRaises(ValueError):verify(digests[0].hex(), value)
        for value in ('ab', 'AB'*32, 'zz'*32, None):
            with self.assertRaises(ValueError):verify(value, report)

    def test_main_checks_actual_tls_value_against_authenticated_report(self):
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'verify_tls_report_binding']
        self.assertEqual(len(calls), 1)
        self.assertEqual([ast.unparse(value) for value in calls[0].args],
                         ['tls_key_digest', 'report.report_data'])


if __name__ == '__main__':unittest.main()
