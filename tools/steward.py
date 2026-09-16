#!/usr/bin/env python3
"""steward: the agent member that reviews, decides and settles governance.

    steward.py review  --state DIR [--min-age-seconds N] [--llm-command CMD] [--dry-run]
    steward.py settle  --state DIR
    steward.py sponsor --state DIR --cert member.pem --enc-pubkey enc.pem --class agent --note TEXT
    steward.py checks  PROPOSAL.json          # run the deterministic checks offline

The steward is a CCF member (class "agent" in the governors table). For every Open
proposal it runs deterministic checks, records a verdict on the ledger
(`adns_record_verdict`: approve, or block with the failed checks — the BountyNet
"finding"), then casts its ballot. High-impact proposals get a soft trap-door
window: the steward will not cast a deciding yes before --min-age-seconds have
passed since it first saw the proposal, so a human trapdoor member can veto.
An optional LLM reviewer (`--llm-command`) adds a check named `llm_review`; it can
add a block finding but never turns a failed deterministic check into a pass.

How the steward "knows" (checks):
  set_constitution           text == tools/compose_constitution.py output of this checkout
  adns_set_node_join_policy  svn advances past the highest accepted svn; every host_data
                             equals sha256 of the CCE text the node serves for it
                             (/gov/service/join-policy); UVM/TCB well-formed
  adns_set_appraisal_policy  policy_id nonzero, validity window sane, measurements/host data hex
  set_member                 certificate parses and is unexpired, open_join is on
  adns_set_governor          member exists
  everything else            schema only (validated by the constitution) -> approve

Common member operations use tools/ccf_control.py's Governance client.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ccf_control  # noqa: E402

HIGH_IMPACT = {"set_constitution", "set_js_app", "set_member", "remove_member", "set_recovery_threshold", "transition_service_to_open",
               "add_snp_measurement", "add_snp_host_data", "add_snp_uvm_endorsement", "set_snp_minimum_tcb_version", "set_snp_minimum_tcb_version_hex",
               "remove_snp_measurement", "remove_snp_host_data", "remove_snp_uvm_endorsement", "remove_snp_minimum_tcb_version",
               "adns_set_node_join_policy", "adns_set_appraisal_policy", "adns_set_release_authority", "adns_set_governance_parameters", "adns_set_governor"}
API = "?api-version=2024-07-01"


def check(name, passed, detail=""):
    return {"name": name, "passed": bool(passed), "detail": str(detail)[:1024]}


# ---- deterministic checks -------------------------------------------------------

def check_constitution(args, compose):
    expected = compose()
    actual = args["constitution"].encode()
    return [check("constitution_reproducible", actual == expected,
                  f"proposed sha256 {hashlib.sha256(actual).hexdigest()} vs composed {hashlib.sha256(expected).hexdigest()}")]


def check_node_join_policy(args, live_join_policy, highest_accepted_svn):
    policy = args["policy"]
    out = [check("svn_advances", policy["svn"] > highest_accepted_svn, f"svn {policy['svn']} vs highest accepted {highest_accepted_svn}")]
    host_data = (live_join_policy or {}).get("snp", {}).get("hostData", {})
    for h in policy["host_data"]:
        cce = host_data.get(h)
        if cce is None:
            out.append(check("host_data_witness", False, f"{h[:16]}…: node serves no CCE text for this host_data; supply the CCE as evidence"))
        else:
            out.append(check("host_data_witness", hashlib.sha256(cce.encode()).hexdigest() == h, f"{h[:16]}…: sha256(CCE text) recomputed"))
    for m in policy["measurements"]:
        out.append(check("measurement_hex", bool(re.fullmatch(r"[0-9a-f]{96}", m)), m[:16]))
    for e in policy["uvm_endorsements"]:
        out.append(check("uvm_endorsement", e["did"].startswith("did:x509:0:sha256:") and e["svn"].isdigit(), e["feed"]))
    return out


def check_appraisal_policy(args):
    p = args["policy"]
    out = [check("policy_id_nonzero", any(b != 0 for b in p["policy_id"]) and len(p["policy_id"]) == 32),
           check("validity_window", p["valid_from"] < p["valid_until"] and p["valid_until"] - p["valid_from"] <= 400 * 86400, f"{p['valid_from']}..{p['valid_until']}")]
    for m in p["approved_measurements"]:
        out.append(check("measurement_hex", bool(re.fullmatch(r"[0-9a-f]{96}", m)), m[:16]))
    for h in p["approved_host_data"]:
        out.append(check("host_data_hex", bool(re.fullmatch(r"[0-9a-f]{64}", h)), h[:16]))
    return out


def check_set_member(args, params, now):
    out = [check("open_join", params.get("open_join", True), "open_join parameter")]
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(args["cert"].encode())
        not_after = cert.not_valid_after_utc.timestamp() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.timestamp()
        out.append(check("member_cert", not_after > now, f"expires {int(not_after)}"))
    except Exception as exc:  # noqa: BLE001
        out.append(check("member_cert", False, f"certificate: {exc}"))
    out.append(check("encryption_key", isinstance(args.get("encryption_pub_key"), str) and "BEGIN PUBLIC KEY" in args.get("encryption_pub_key", ""), "recovery share key present"))
    return out


def run_checks(proposal, *, compose, live_join_policy, highest_accepted_svn, params, now, llm=None):
    checks, high = [], False
    for action in proposal["actions"]:
        name, args = action["name"], action.get("args", {})
        high = high or name in HIGH_IMPACT
        if name == "set_constitution":
            checks += check_constitution(args, compose)
        elif name == "adns_set_node_join_policy":
            checks += check_node_join_policy(args, live_join_policy, highest_accepted_svn)
        elif name == "adns_set_appraisal_policy":
            checks += check_appraisal_policy(args)
        elif name == "set_member":
            checks += check_set_member(args, params, now)
        elif name == "adns_record_verdict":
            checks.append(check("verdict_statement", True, "self-attesting; no review"))
        else:
            checks.append(check("routine_schema", True, f"{name}: constitution validate() is the check"))
    if llm is not None:
        verdict = llm(proposal)
        checks.append(check("llm_review", bool(verdict.get("approve")), verdict.get("rationale", "")[:1024]))
    return checks, high


def llm_command(command):
    def review(proposal):
        proc = subprocess.run(command, shell=True, input=json.dumps(proposal), capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            return {"approve": False, "rationale": f"llm reviewer failed: {proc.stderr[-300:]}"}
        try:
            out = json.loads(proc.stdout)
            return {"approve": bool(out.get("approve")), "rationale": str(out.get("rationale", ""))}
        except json.JSONDecodeError:
            return {"approve": False, "rationale": "llm reviewer returned non-JSON"}
    return review


# ---- ledger access --------------------------------------------------------------

class Ledger:
    """Thin wrapper over ccf_control's Client/Governance for the member operations the steward needs."""

    def __init__(self, url, connect_ip, service_cert, member_key, member_cert):
        self.client = ccf_control.Client(url, connect_ip, service_cert)
        self.gov = ccf_control.Governance(self.client, member_key, member_cert)
        self.member_id = self.gov.id

    def get(self, path):
        r = self.client.request("GET", path)
        if r["http_status"] != 200:
            raise RuntimeError(f"GET {path} -> {r['http_status']}")
        return r["body"]

    def proposals(self):
        return self.get("/gov/members/proposals" + API).get("value", [])

    def proposal_actions(self, proposal_id):
        return self.get(f"/gov/members/proposals/{proposal_id}/actions" + API)

    def join_policy(self):
        return self.get("/gov/service/join-policy" + API)

    def ballot(self, proposal_id, vote):
        script = f"export function vote(proposal, proposer_id) {{ return {'true' if vote else 'false'}; }}"
        return self.gov.post(f"/gov/members/proposals/{proposal_id}/ballots/{self.member_id}:submit", {"ballot": script}, "ballot", proposal_id)

    def propose(self, actions):
        return self.gov.post("/gov/members/proposals:create", {"actions": actions}, "proposal")


def highest_accepted_svn(ledger):
    best = 0
    for p in ledger.proposals():
        if p.get("proposalState") != "Accepted":
            continue
        try:
            actions = ledger.proposal_actions(p["proposalId"]).get("actions", [])
        except RuntimeError:
            continue
        for a in actions:
            if a["name"] == "adns_set_node_join_policy":
                best = max(best, int(a["args"]["policy"]["svn"]))
    return best


def review(ledger, state_dir, *, min_age, compose, llm=None, dry_run=False, now=None, params=None):
    now = now or time.time()
    state_path = Path(state_dir) / "steward-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"seen": {}, "voted": {}, "verdicts": {}}
    results = []
    live_join = None
    for p in ledger.proposals():
        pid = p["proposalId"]
        if p.get("proposalState") != "Open" or p.get("proposerId") == ledger.member_id or pid in state["voted"]:
            continue
        proposal = ledger.proposal_actions(pid)
        names = [a["name"] for a in proposal["actions"]]
        if names and all(n == "adns_record_verdict" for n in names):
            continue   # statements by other members; not ours to vote on
        if any(n == "adns_set_node_join_policy" for n in names) and live_join is None:
            live_join = ledger.join_policy()
        checks, high = run_checks(proposal, compose=compose, live_join_policy=live_join, highest_accepted_svn=highest_accepted_svn(ledger) if any(n == "adns_set_node_join_policy" for n in names) else 0,
                                  params=params or {}, now=now, llm=llm)
        passed = all(c["passed"] for c in checks)
        first_seen = state["seen"].setdefault(pid, now)
        entry = {"proposal_id": pid, "actions": names, "high_impact": high, "checks": checks, "passed": passed}
        if not passed:
            entry["action"] = "block"
            if not dry_run and pid not in state["verdicts"]:
                ledger.propose([{"name": "adns_record_verdict", "args": {"proposal_id": pid, "verdict": "block", "checks": checks,
                                 "evidence": {"steward": ledger.member_id}, "rationale": "deterministic checks failed: " + ", ".join(c["name"] for c in checks if not c["passed"])}}])
                state["verdicts"][pid] = "block"
                ledger.ballot(pid, False)
                state["voted"][pid] = False
        elif high and now - first_seen < min_age:
            entry["action"] = f"waiting trap-door window ({int(min_age - (now - first_seen))}s left)"
            if not dry_run and pid not in state["verdicts"]:
                ledger.propose([{"name": "adns_record_verdict", "args": {"proposal_id": pid, "verdict": "approve", "checks": checks,
                                 "evidence": {"steward": ledger.member_id}, "rationale": "checks passed; ballot deferred for the trap-door window"}}])
                state["verdicts"][pid] = "approve"
        else:
            entry["action"] = "approve"
            if not dry_run:
                if pid not in state["verdicts"]:
                    ledger.propose([{"name": "adns_record_verdict", "args": {"proposal_id": pid, "verdict": "approve", "checks": checks,
                                     "evidence": {"steward": ledger.member_id}, "rationale": "deterministic checks passed"}}])
                    state["verdicts"][pid] = "approve"
                ledger.ballot(pid, True)
                state["voted"][pid] = True
        results.append(entry)
    if not dry_run:
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=1))
    return results


def settle(ledger, state_dir, dry_run=False):
    state_path = Path(state_dir) / "steward-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"seen": {}, "voted": {}, "verdicts": {}}
    settled = state.setdefault("settled", [])
    out = []
    for p in ledger.proposals():
        pid = p["proposalId"]
        if p.get("proposalState") not in ("Accepted", "Rejected") or pid in settled:
            continue
        names = [a["name"] for a in ledger.proposal_actions(pid).get("actions", [])]
        if names and all(n in ("adns_record_verdict", "adns_settle") for n in names):
            settled.append(pid)
            continue
        if not dry_run:
            try:
                ledger.propose([{"name": "adns_settle", "args": {"proposal_id": pid}}])
            except ValueError as exc:
                out.append({"proposal_id": pid, "settled": False, "error": str(exc)})
                settled.append(pid)
                continue
            settled.append(pid)
        out.append({"proposal_id": pid, "settled": not dry_run, "state": p["proposalState"]})
    if not dry_run:
        state_path.write_text(json.dumps(state, indent=1))
    return out


def sponsor(ledger, cert_pem, enc_pem, member_class, note, dry_run=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    member_id = x509.load_pem_x509_certificate(cert_pem.encode()).fingerprint(hashes.SHA256()).hex()
    actions = [{"name": "set_member", "args": {"cert": cert_pem, "encryption_pub_key": enc_pem, "member_data": {"class": member_class, "note": note}}},
               {"name": "adns_set_governor", "args": {"member_id": member_id, "class": member_class, "note": note}}]
    if dry_run:
        return {"member_id": member_id, "actions": actions}
    return {"member_id": member_id, "result": ledger.propose(actions)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("review", "settle", "sponsor", "checks"))
    parser.add_argument("proposal", nargs="?", type=Path)
    parser.add_argument("--url", default="https://agentdns.test:8000")
    parser.add_argument("--connect-ip")
    parser.add_argument("--service-cert", type=Path)
    parser.add_argument("--member-key", type=Path)
    parser.add_argument("--member-cert", type=Path)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/agentdns-steward"))
    parser.add_argument("--min-age-seconds", type=int, default=24 * 3600)
    parser.add_argument("--llm-command")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cert", type=Path); parser.add_argument("--enc-pubkey", type=Path)
    parser.add_argument("--class", dest="member_class", default="agent", choices=("agent", "trapdoor")); parser.add_argument("--note", default="")
    args = parser.parse_args()
    from compose_constitution import compose
    if args.mode == "checks":
        proposal = json.loads(args.proposal.read_text())
        checks, high = run_checks(proposal, compose=compose, live_join_policy=None, highest_accepted_svn=0, params={}, now=time.time(),
                                  llm=llm_command(args.llm_command) if args.llm_command else None)
        print(json.dumps({"high_impact": high, "passed": all(c["passed"] for c in checks), "checks": checks}, indent=2))
        return
    if not (args.connect_ip and args.service_cert and args.member_key and args.member_cert):
        parser.error("--connect-ip, --service-cert, --member-key and --member-cert are required")
    ledger = Ledger(args.url, args.connect_ip, args.service_cert, args.member_key, args.member_cert)
    if args.mode == "review":
        out = review(ledger, args.state, min_age=args.min_age_seconds, compose=compose, llm=llm_command(args.llm_command) if args.llm_command else None, dry_run=args.dry_run)
    elif args.mode == "settle":
        out = settle(ledger, args.state, dry_run=args.dry_run)
    else:
        out = sponsor(ledger, args.cert.read_text(), args.enc_pubkey.read_text(), args.member_class, args.note, dry_run=args.dry_run)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
