"""Ensure a valid CNAME target cannot stand in for governed owner records."""
import importlib.util
from pathlib import Path
import unittest

import dns.message
import dns.rrset


spec = importlib.util.spec_from_file_location(
    "verify_operator_mail",
    Path(__file__).resolve().parents[2] / "ccf/tests/verify_operator_mail.py",
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class OperatorOwnerTests(unittest.TestCase):
    def test_alias_target_with_matching_bytes_does_not_prove_governed_owner(self):
        owner = "selector1._domainkey.example.test."
        response = dns.message.make_response(dns.message.make_query(owner, "TXT"))
        response.answer.extend([
            dns.rrset.from_text(owner, 300, "IN", "CNAME", "other.example.test."),
            dns.rrset.from_text("other.example.test.", 300, "IN", "TXT", '"v=DKIM1; p=fixture"'),
        ])
        self.assertEqual(verifier.records_at_owner(response, owner, "TXT"), [])
        response.answer.append(dns.rrset.from_text(owner.upper(), 300, "IN", "TXT", '"v=DKIM1; p=fixture"'))
        records = verifier.records_at_owner(response, owner, "TXT")
        self.assertEqual(len(records), 1)
        self.assertEqual(b"".join(records[0].strings), b"v=DKIM1; p=fixture")
        self.assertEqual(verifier.records_at_owner(response, owner, "CAA"), [])


if __name__ == "__main__":
    unittest.main()
