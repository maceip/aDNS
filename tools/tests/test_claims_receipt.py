"""Claims receipts (anchor / policy / anchors document): generated test CA, not CCF proof.

Also asserts the Python claims digest equals the Rust `anchors::claims_digest`
construction (domain || NUL || u32 length || canonical JSON) by recomputing a
fixed vector both sides agree on.
"""
import base64
import copy
import datetime
import hashlib
import importlib.util
import pathlib
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

spec = importlib.util.spec_from_file_location("verify_claims", pathlib.Path(__file__).parents[1] / "verify_claims_receipt.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert(key, subject, issuer, issuer_key):
    time = datetime.datetime(2026, 1, 1)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(time).not_valid_after(time + datetime.timedelta(days=365)).sign(issuer_key, hashes.SHA256()))


class ClaimsReceiptChecks(unittest.TestCase):
    def setUp(self):
        service = ec.generate_private_key(ec.SECP384R1())
        node = ec.generate_private_key(ec.SECP384R1())
        service_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test service")])
        node_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test node")])
        self.service_cert = cert(service, service_name, service_name, service)
        node_cert = cert(node, node_name, service_name, service)
        self.node = node
        self.node_cert = node_cert
        self.anchor = {"type": "agentdns-anchor-v1", "grant_id": "mail-owner", "registration_id": "reg-abc", "zone": "agent.hosting.",
                       "subject": "conversation-1", "sequence": 7, "digest_sha256": "ab" * 32, "anchored_at": 1789523000}
        self.response = self.receipted({"status": "committed", "anchor": self.anchor}, verifier.claims_digest("agentdns-anchor-v1", self.anchor))
        self.trust = pem(self.service_cert)

    def receipted(self, body, claim):
        leaf = {"write_set_digest": "ab" * 32, "commit_evidence": "ce:2.42:" + "ef" * 32, "claims_digest": claim.hex()}
        root = hashlib.sha256(bytes.fromhex(leaf["write_set_digest"]) + hashlib.sha256(leaf["commit_evidence"].encode()).digest() + claim).digest()
        root = hashlib.sha256(bytes.fromhex("cd" * 32) + root).digest()
        return {**body, "tx_id": "2.42", "ccf_service_identity": pem(self.service_cert),
                "proof": {"cert": pem(self.node_cert), "leaf_components": leaf, "proof": [{"left": "cd" * 32}],
                          "signature": base64.b64encode(self.node.sign(root, ec.ECDSA(utils.Prehashed(hashes.SHA256())))).decode()}}

    def test_valid_anchor_receipt(self):
        out = verifier.verify(self.response, self.trust, "agentdns-anchor-v1")
        self.assertEqual(out["tx_id"], "2.42")
        self.assertEqual(out["claims"]["sequence"], 7)

    def test_digest_construction_matches_rust_vector(self):
        # Rust: sha256(domain || 0x00 || be32(len) || canonical). Fixed vector for {"a":1,"b":"x"} under type "t".
        canonical = b'{"a":1,"b":"x"}'
        expected = hashlib.sha256(b"t\0" + len(canonical).to_bytes(4, "big") + canonical).hexdigest()
        self.assertEqual(verifier.claims_digest("t", {"b": "x", "a": 1}).hex(), expected)
        self.assertEqual(verifier.canonical_json({"b": "x", "a": [True, None, 3]}), b'{"a":[true,null,3],"b":"x"}')

    def test_tampered_claims_or_wrong_type_or_wrong_identity_fail(self):
        tampered = copy.deepcopy(self.response)
        tampered["anchor"]["digest_sha256"] = "ba" * 32
        with self.assertRaisesRegex(ValueError, "claims digest mismatch"):
            verifier.verify(tampered, self.trust)
        with self.assertRaisesRegex(ValueError, "unexpected claims type"):
            verifier.verify(self.response, self.trust, "agentdns-anchors-v1")
        other = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Other")])
        with self.assertRaisesRegex(ValueError, "not the trusted service"):
            verifier.verify(self.response, pem(cert(other, name, name, other)))
        wrong_tx = copy.deepcopy(self.response)
        wrong_tx["tx_id"] = "2.43"
        with self.assertRaisesRegex(ValueError, "transaction ID"):
            verifier.verify(wrong_tx, self.trust)
        bad_sig = copy.deepcopy(self.response)
        bad_sig["proof"]["proof"] = [{"left": "dc" * 32}]
        with self.assertRaises(Exception):
            verifier.verify(bad_sig, self.trust)

    def test_policy_and_anchors_documents_use_claims_field(self):
        claims = {"type": "agentdns-anchors-v1", "zones": [], "appraisal_policies": [], "node_join_policy": None, "release_authority": None}
        response = self.receipted({"status": "committed", "claims": claims}, verifier.claims_digest("agentdns-anchors-v1", claims))
        self.assertEqual(verifier.verify(response, self.trust)["type"], "agentdns-anchors-v1")


if __name__ == "__main__":
    unittest.main()
