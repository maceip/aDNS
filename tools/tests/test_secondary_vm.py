import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("secondary_vm", Path(__file__).parents[1] / "secondary_vm.py")
secondary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secondary)


class SecondaryVmTests(unittest.TestCase):
    def test_private_canonical_secret_and_rejected_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key"
            encoded = base64.b64encode(bytes(range(32)))
            path.write_bytes(encoded + b"\n")
            path.chmod(0o600)
            self.assertEqual(secondary.secret_from_file(path), encoded.decode())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                secondary.secret_from_file(path)
            path.chmod(0o600)
            link = Path(temporary) / "alias"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                secondary.secret_from_file(link)

    def test_oversized_or_noncanonical_secret_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key"
            for value in (base64.b64encode(bytes(32)) + b"\n MORE", base64.b64encode(bytes(31)), b" " + base64.b64encode(bytes(32))):
                path.write_bytes(value)
                path.chmod(0o600)
                with self.assertRaises(ValueError):
                    secondary.secret_from_file(path)

    def test_configuration_cannot_escape_fixed_dns_scope(self):
        for primary in ("1.2.3.4; include attack", "example.com", "::1"):
            with self.assertRaises(ValueError):
                secondary.configuration(primary)
        config = secondary.configuration("192.0.2.44")
        self.assertIn("192.0.2.44 port 5353", config)
        self.assertIn("recursion no;", config)
        self.assertIn("allow-transfer { none; };", config)
        self.assertNotIn("auto-dnssec", config)


if __name__ == "__main__":
    unittest.main()
