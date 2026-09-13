"""Exact native acceptance records must reject aliases and unappraised keys."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

spec = importlib.util.spec_from_file_location('verify_native_dns',
    Path(__file__).resolve().parents[2]/'tests/rust-integration/verify_native_dns.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
state_spec = importlib.util.spec_from_file_location('observe_native_state',
    Path(__file__).resolve().parents[2]/'tests/rust-integration/observe_native_state.py')
state = importlib.util.module_from_spec(state_spec)
with mock.patch.dict(sys.modules,{'verify_native_dns':verifier}):
    state_spec.loader.exec_module(state)

OWNER = '_25._tcp.mail.example.test.'
VALUES = ['3 1 1 '+'ab'*32, '3 1 1 '+'cd'*32]


class NativeDnsVerifierTests(unittest.TestCase):
    def response(self, owner=OWNER, values=None):
        response = dns.message.make_response(dns.message.make_query(OWNER,'TLSA'))
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(owner,60,'IN','TLSA',*(VALUES if values is None else values)))
        return response

    def test_exact_two_native_keys_pass(self):
        verifier.require_record_set(verifier.exact_records(self.response(),OWNER,'TLSA'),'TLSA',VALUES)

    def test_missing_key_and_additional_key_fail(self):
        for values in (VALUES[:1], [*VALUES,'3 1 1 '+'ef'*32]):
            with self.subTest(values=values),self.assertRaises(ValueError):
                verifier.require_record_set(verifier.exact_records(self.response(values=values),OWNER,'TLSA'),'TLSA',VALUES)

    def test_alias_target_or_unexpected_type_is_not_exact_owner_proof(self):
        alias = self.response(owner='alias.example.test.')
        alias.answer.insert(0,dns.rrset.from_text(OWNER,60,'IN','CNAME','alias.example.test.'))
        extra = self.response()
        extra.answer.append(dns.rrset.from_text(OWNER,60,'IN','TXT','"unexpected"'))
        for response in (alias,extra):
            with self.subTest(response=response.to_text()),self.assertRaises(ValueError):
                verifier.exact_records(response,OWNER,'TLSA')

    def test_unauthoritative_absent_and_wrong_rcode_fail(self):
        absent = self.response();absent.answer=[]
        nonauthoritative = self.response();nonauthoritative.flags &= ~dns.flags.AA
        negative = self.response();negative.set_rcode(dns.rcode.NXDOMAIN)
        for response in (absent,nonauthoritative,negative):
            with self.subTest(response=response.to_text()),self.assertRaises(ValueError):
                verifier.exact_records(response,OWNER,'TLSA')

    def test_delv_must_validate_same_exact_keys_not_a_later_different_set(self):
        output = '; fully validated\n'+''.join(f'{OWNER} 60 IN TLSA {value}\n' for value in VALUES)
        verifier.validate_delv_output(output,OWNER,'TLSA',VALUES)
        for wrong in (output.replace(VALUES[0],VALUES[1]),output.replace(OWNER,'alias.example.test.')):
            with self.subTest(output=wrong),self.assertRaises(ValueError):
                verifier.validate_delv_output(wrong,OWNER,'TLSA',VALUES)

    def test_delv_absence_must_match_owner_and_type(self):
        output = '; negative response, fully validated\n; '+OWNER+' 60 IN \\-TLSA ;-$NXRRSET\n'
        verifier.validate_delv_output(output,OWNER,'TLSA',negative='absent')
        for wrong in (output.replace(OWNER,'alias.example.test.'),output.replace('\\-TLSA','\\-TXT')):
            with self.subTest(output=wrong),self.assertRaises(ValueError):
                verifier.validate_delv_output(wrong,OWNER,'TLSA',negative='absent')

    def test_lifecycle_expectations_reject_other_scopes_and_duplicate_sets(self):
        valid = {'owner':OWNER,'type':'TLSA','rdata':VALUES}
        self.assertEqual(state.validate_expectations([valid]),[valid])
        for values in ([dict(valid,owner='outside.invalid.')],[dict(valid,owner='nested/path.example.test.')],[dict(valid,type='ANY')],[valid,valid]):
            with self.subTest(values=values),self.assertRaises(ValueError):
                state.validate_expectations(values)

    def test_acme_coexistence_requires_both_exact_values(self):
        owner = '_acme-challenge.mail.example.test.'
        item = {'owner':owner,'type':'TXT','rdata':['"order-one"','"order-two"']}
        response = dns.message.make_response(dns.message.make_query(owner,'TXT'));response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(owner,30,'IN','TXT',*item['rdata']))
        state.validate_answer(response,item)
        with self.assertRaises(ValueError):
            state.validate_answer(response,dict(item,rdata=['"order-one"']))

    def test_withdrawal_requires_absence_and_nsec3_not_alias_or_empty_error(self):
        response = dns.message.make_response(dns.message.make_query(OWNER,'TLSA'));response.flags |= dns.flags.AA
        item = {'owner':OWNER,'type':'TLSA','rdata':[]}
        with self.assertRaises(ValueError):state.validate_answer(response,item)
        response.authority.append(dns.rrset.from_text('0.example.test.',60,'IN','NSEC3','1 0 0 - 00000000000000000000000000000000 A RRSIG'))
        state.validate_answer(response,item)
        response.answer.append(dns.rrset.from_text(OWNER,60,'IN','CNAME','alias.example.test.'))
        with self.assertRaises(ValueError):state.validate_answer(response,item)


if __name__ == '__main__':
    unittest.main()
