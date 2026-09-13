"""Reject alias targets and malformed records in the single-TXT acceptance check."""
import importlib.util
from pathlib import Path
import unittest

import dns.flags
import dns.message
import dns.rrset

spec = importlib.util.spec_from_file_location('verify_reconciliation',
    Path(__file__).resolve().parents[2]/'tests/rust-integration/verify_reconciliation.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ReconciliationVerifierTests(unittest.TestCase):
    def response(self, owner=None, ttl=60, value=None):
        result = dns.message.make_response(dns.message.make_query(verifier.OWNER, 'TXT'))
        result.flags |= dns.flags.AA
        result.answer.append(dns.rrset.from_text(owner or verifier.OWNER, ttl, 'IN', 'TXT',
            '"'+(value or verifier.VALUE)+'"'))
        return result

    def test_exact_fixed_fixture_passes(self):
        verifier.validate_response(self.response())

    def test_matching_alias_target_does_not_prove_owner(self):
        response = self.response(owner='alias.example.test.')
        response.answer.insert(0, dns.rrset.from_text(verifier.OWNER, 60, 'IN', 'CNAME', 'alias.example.test.'))
        with self.assertRaises(ValueError):
            verifier.validate_response(response)

    def test_wrong_ttl_extra_record_and_wrong_bytes_fail(self):
        extra = self.response()
        extra.answer[0].add(dns.rdata.from_text('IN', 'TXT', '"unrequested value"'), 60)
        for response in (self.response(ttl=61), self.response(value='wrong value'), extra):
            with self.subTest(response=response.to_text()), self.assertRaises(ValueError):
                verifier.validate_response(response)


if __name__ == '__main__':
    unittest.main()
