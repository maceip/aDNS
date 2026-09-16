"""Steward agent: deterministic checks, verdict/ballot flow, trap-door window, settle, sponsor."""
import datetime
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TOOLS = pathlib.Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("steward", TOOLS / "steward.py")
steward = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steward)
cspec = importlib.util.spec_from_file_location("compose_constitution", TOOLS / "compose_constitution.py")
composer = importlib.util.module_from_spec(cspec)
cspec.loader.exec_module(composer)

CCE = "package policy\nallow := true\n"
HOST_DATA = hashlib.sha256(CCE.encode()).hexdigest()


def join_policy_body(svn):
    return {"policy": {"svn": svn, "release_id": f"r{svn}", "measurements": ["ab" * 48], "host_data": [HOST_DATA],
                       "uvm_endorsements": [{"did": "did:x509:0:sha256:x::eku:1", "feed": "ContainerPlat-AMD-UVM", "svn": "104"}],
                       "tcb_versions": {"00a10f11": {"boot_loader": 10, "tee": 0, "snp": 27, "microcode": 88}}},
            "signature": {"did": "d", "svn": svn, "signature": "AA"}}


def member_cert():
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "steward-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class FakeLedger:
    def __init__(self):
        self.member_id = "5" * 64
        self._proposals = {}
        self.ballots, self.proposed = [], []
        self.join = {"snp": {"hostData": {HOST_DATA: CCE}, "measurements": [], "uvmEndorsements": {}, "tcbVersions": {}}}

    def add(self, pid, actions, state="Open", proposer="9" * 64):
        self._proposals[pid] = {"proposalId": pid, "proposalState": state, "proposerId": proposer, "actions": actions}

    def proposals(self):
        return [{k: v for k, v in p.items() if k != "actions"} for p in self._proposals.values()]

    def proposal_actions(self, pid):
        return {"actions": self._proposals[pid]["actions"]}

    def join_policy(self):
        return self.join

    def ballot(self, pid, vote):
        self.ballots.append((pid, vote))

    def propose(self, actions):
        self.proposed.append(actions)
        return {"body": {"proposalState": "Accepted"}}


class ChecksTests(unittest.TestCase):
    def test_constitution_check_requires_exact_composition(self):
        good = composer.compose().decode()
        checks, high = steward.run_checks({"actions": [{"name": "set_constitution", "args": {"constitution": good}}]}, compose=composer.compose,
                                          live_join_policy=None, highest_accepted_svn=0, params={}, now=0)
        self.assertTrue(high); self.assertTrue(all(c["passed"] for c in checks))
        checks, _ = steward.run_checks({"actions": [{"name": "set_constitution", "args": {"constitution": good + "\n// tamper"}}]}, compose=composer.compose,
                                       live_join_policy=None, highest_accepted_svn=0, params={}, now=0)
        self.assertFalse(checks[0]["passed"])

    def test_node_join_policy_checks_svn_and_cce_witness(self):
        live = FakeLedger().join
        checks, _ = steward.run_checks({"actions": [{"name": "adns_set_node_join_policy", "args": join_policy_body(2)}]}, compose=composer.compose,
                                       live_join_policy=live, highest_accepted_svn=1, params={}, now=0)
        self.assertTrue(all(c["passed"] for c in checks), checks)
        stale, _ = steward.run_checks({"actions": [{"name": "adns_set_node_join_policy", "args": join_policy_body(1)}]}, compose=composer.compose,
                                      live_join_policy=live, highest_accepted_svn=1, params={}, now=0)
        self.assertFalse(next(c for c in stale if c["name"] == "svn_advances")["passed"])
        body = join_policy_body(2); body["policy"]["host_data"] = ["cd" * 32]
        unknown, _ = steward.run_checks({"actions": [{"name": "adns_set_node_join_policy", "args": body}]}, compose=composer.compose,
                                        live_join_policy=live, highest_accepted_svn=1, params={}, now=0)
        self.assertFalse(next(c for c in unknown if c["name"] == "host_data_witness")["passed"])
        tampered = FakeLedger().join; tampered["snp"]["hostData"][HOST_DATA] = CCE + "\n# changed"
        bad, _ = steward.run_checks({"actions": [{"name": "adns_set_node_join_policy", "args": join_policy_body(2)}]}, compose=composer.compose,
                                    live_join_policy=tampered, highest_accepted_svn=1, params={}, now=0)
        self.assertFalse(next(c for c in bad if c["name"] == "host_data_witness")["passed"], "CCE text must hash to the host_data it claims")

    def test_set_member_checks_certificate_and_open_join(self):
        pem = member_cert()
        checks, high = steward.run_checks({"actions": [{"name": "set_member", "args": {"cert": pem, "encryption_pub_key": "-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----\n", "member_data": {}}}]},
                                          compose=composer.compose, live_join_policy=None, highest_accepted_svn=0, params={"open_join": True}, now=datetime.datetime.now().timestamp())
        self.assertTrue(high); self.assertTrue(all(c["passed"] for c in checks), checks)
        closed, _ = steward.run_checks({"actions": [{"name": "set_member", "args": {"cert": pem, "encryption_pub_key": "x", "member_data": {}}}]},
                                       compose=composer.compose, live_join_policy=None, highest_accepted_svn=0, params={"open_join": False}, now=0)
        self.assertFalse(next(c for c in closed if c["name"] == "open_join")["passed"])
        self.assertFalse(next(c for c in closed if c["name"] == "encryption_key")["passed"])

    def test_llm_review_can_block_but_cannot_rescue(self):
        p = {"actions": [{"name": "adns_set_owner_grant", "args": {}}]}
        checks, _ = steward.run_checks(p, compose=composer.compose, live_join_policy=None, highest_accepted_svn=0, params={}, now=0,
                                       llm=lambda proposal: {"approve": False, "rationale": "grant widens scope"})
        self.assertFalse(all(c["passed"] for c in checks))
        bad = {"actions": [{"name": "set_constitution", "args": {"constitution": "nope"}}]}
        checks, _ = steward.run_checks(bad, compose=composer.compose, live_join_policy=None, highest_accepted_svn=0, params={}, now=0, llm=lambda proposal: {"approve": True, "rationale": "looks fine"})
        self.assertFalse(all(c["passed"] for c in checks), "a passing LLM review does not override a failed deterministic check")


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = FakeLedger()

    def tearDown(self):
        self.tmp.cleanup()

    def test_block_finding_then_no_vote_and_approve_with_trapdoor_window(self):
        self.ledger.add("1" * 64, [{"name": "set_constitution", "args": {"constitution": "tampered"}}])
        self.ledger.add("2" * 64, [{"name": "adns_set_owner_grant", "args": {}}])
        self.ledger.add("3" * 64, [{"name": "adns_set_node_join_policy", "args": join_policy_body(1)}])
        self.ledger.add("4" * 64, [{"name": "adns_record_verdict", "args": {}}])   # another member's statement
        self.ledger.add("6" * 64, [{"name": "adns_set_owner_grant", "args": {}}], proposer=self.ledger.member_id)   # ours
        out = steward.review(self.ledger, self.tmp.name, min_age=3600, compose=composer.compose, now=1000)
        by = {o["proposal_id"]: o for o in out}
        self.assertEqual(by["1" * 64]["action"], "block")
        self.assertEqual(by["2" * 64]["action"], "approve")
        self.assertTrue(by["3" * 64]["action"].startswith("waiting trap-door"))
        self.assertNotIn("4" * 64, by); self.assertNotIn("6" * 64, by)
        verdicts = {a[0]["args"]["proposal_id"]: a[0]["args"]["verdict"] for a in self.ledger.proposed}
        self.assertEqual(verdicts["1" * 64], "block"); self.assertEqual(verdicts["2" * 64], "approve"); self.assertEqual(verdicts["3" * 64], "approve")
        self.assertIn(("1" * 64, False), self.ledger.ballots); self.assertIn(("2" * 64, True), self.ledger.ballots)
        self.assertNotIn(("3" * 64, True), self.ledger.ballots, "no deciding yes inside the window")
        # Window elapsed: the yes ballot is cast, the verdict is not re-recorded.
        before = len(self.ledger.proposed)
        out = steward.review(self.ledger, self.tmp.name, min_age=3600, compose=composer.compose, now=1000 + 3601)
        self.assertEqual({o["proposal_id"]: o["action"] for o in out}, {"3" * 64: "approve"})
        self.assertIn(("3" * 64, True), self.ledger.ballots)
        self.assertEqual(len(self.ledger.proposed), before)
        # Idempotent: nothing left to do.
        self.assertEqual(steward.review(self.ledger, self.tmp.name, min_age=3600, compose=composer.compose, now=1000 + 7200), [])

    def test_settle_proposes_once_per_resolved_proposal_and_skips_statements(self):
        self.ledger.add("1" * 64, [{"name": "adns_set_owner_grant", "args": {}}], state="Accepted")
        self.ledger.add("2" * 64, [{"name": "adns_set_owner_grant", "args": {}}], state="Rejected")
        self.ledger.add("3" * 64, [{"name": "adns_record_verdict", "args": {}}], state="Accepted")
        self.ledger.add("4" * 64, [{"name": "adns_set_owner_grant", "args": {}}], state="Open")
        out = steward.settle(self.ledger, self.tmp.name)
        self.assertEqual(sorted(o["proposal_id"] for o in out), ["1" * 64, "2" * 64])
        self.assertEqual([a[0]["args"]["proposal_id"] for a in self.ledger.proposed], ["1" * 64, "2" * 64])
        self.assertEqual(steward.settle(self.ledger, self.tmp.name), [])

    def test_sponsor_builds_set_member_and_governor_actions(self):
        pem = member_cert()
        out = steward.sponsor(self.ledger, pem, "-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----\n", "agent", "worker steward", dry_run=True)
        self.assertEqual([a["name"] for a in out["actions"]], ["set_member", "adns_set_governor"])
        self.assertEqual(out["actions"][1]["args"]["member_id"], out["member_id"])
        self.assertEqual(len(out["member_id"]), 64)


if __name__ == "__main__":
    unittest.main()
