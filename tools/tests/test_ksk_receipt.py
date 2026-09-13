"""Cryptographic negative controls; generated identity is a test CA, not CCF proof."""
import base64
import copy
import datetime
import importlib.util
import pathlib
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

spec = importlib.util.spec_from_file_location("verify_ksk", pathlib.Path(__file__).parents[1] / "verify_ksk_receipt.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()

def cert(key, subject, issuer, issuer_key):
    time = datetime.datetime(2026, 1, 1)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(time).not_valid_after(time + datetime.timedelta(days=365)).sign(issuer_key, hashes.SHA256()))

class ReceiptChecks(unittest.TestCase):
    def setUp(self):
        service = ec.generate_private_key(ec.SECP384R1())
        node = ec.generate_private_key(ec.SECP384R1())
        service_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test service")])
        node_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test node")])
        service_cert = cert(service, service_name, service_name, service)
        node_cert = cert(node, node_name, service_name, service)
        ksk = ec.generate_private_key(ec.SECP384R1())
        rdata = bytes([1, 1, 3, 14]) + ksk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        checksum = sum(v << 8 if i % 2 == 0 else v for i, v in enumerate(rdata))
        claim = verifier.claims_digest("example.", rdata)
        leaf = {"write_set_digest": "ab" * 32, "commit_evidence": "ce:2.42:" + "ef" * 32, "claims_digest": claim.hex()}
        root = verifier.digest(bytes.fromhex(leaf["write_set_digest"]) + verifier.digest(leaf["commit_evidence"].encode()) + claim)
        root = verifier.digest(bytes.fromhex("cd" * 32) + root)
        self.receipt = {"zone": "example.", "owner_name": "example.", "dnskey_rdata_hex": rdata.hex(), "key_tag": (checksum + (checksum >> 16)) & 65535, "algorithm": 14, "ds_digest": {"digest_type": 2, "digest_hex": verifier.digest(verifier.owner_wire("example.") + rdata).hex()}, "tx_id": "2.42", "ccf_service_identity": pem(service_cert), "proof": {"cert": pem(node_cert), "leaf_components": leaf, "proof": [{"left": "cd" * 32}], "signature": base64.b64encode(node.sign(root, ec.ECDSA(utils.Prehashed(hashes.SHA256())))).decode()}}
        self.trust = pem(service_cert)

    def test_verifies_valid_crypto_chain(self):
        self.assertEqual(verifier.verify(self.receipt, self.trust, "example.")["tx_id"], "2.42")
        self.assertEqual(verifier.verify(self.receipt, self.trust.encode(), "example.")["tx_id"], "2.42")

    def test_altered_claim_path_signature_and_untrusted_identity_fail(self):
        modifications = [lambda r: r.update(zone="other."), lambda r: r.update(dnskey_rdata_hex="00" * 100), lambda r: r["proof"]["leaf_components"].update(claims_digest="00" * 32), lambda r: r["proof"]["proof"][0].update(left="00" * 32), lambda r: r["proof"].update(signature=base64.b64encode(bytes(96)).decode()), lambda r: r["proof"]["proof"].append({"left": "00" * 32, "right": "00" * 32}), lambda r: r["proof"]["leaf_components"].update(commit_evidence="altered")]
        for mutation in modifications:
            altered = copy.deepcopy(self.receipt)
            mutation(altered)
            with self.assertRaises(Exception):
                verifier.verify(altered, self.trust, "example.")
        altered = copy.deepcopy(self.receipt)
        altered["tx_id"] = "2.43"
        with self.assertRaises(ValueError):
            verifier.verify(altered, self.trust, "example.")
        with self.assertRaises(Exception):
            verifier.verify(self.receipt, self.receipt["proof"]["cert"], "example.")

if __name__ == "__main__":
    unittest.main()
