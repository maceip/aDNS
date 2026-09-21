# Live code upgrade runbook (primary in native ACI SNP)

`operations.md` covers rollback, cutover and recovery. This runbook covers the
one thing it did not: replacing the running primary's code with a new release
while the service stays open, so that the accepted node set is exactly what the
release authority last signed and a retired release cannot rejoin.

## Roles

- **Release authority D** signs node join policies and workload appraisal
  policies (`adns_set_release_authority`). Its key is not on the node and not
  the operator's member key.
- **Consortium members** vote the proposals (`tools/ccf_control.py propose`).
- **Operator** builds images, runs containers, never signs policy.

## Choreography

1. **Build and measure.** Build the new primary image; generate its CCE
   security policy; record `host_data = SHA256(CCE)`, the UVM endorsement
   `{did, feed, svn}` from the target ACI platform, and the minimum TCB.
   Independently review the CCE. Reproduce the source manifest from the tagged
   commit (`tools/check_aci_template.py`, `docs/ccf-measurements.md`).
2. **D signs the node join policy** `P(svn = current + 1)` listing *only* the
   measurements/host data/UVM endorsements that may join after the upgrade
   (normally: the new release, plus the current release for the overlap
   window). Signature: fixed 64-byte r||s over canonical JSON of
   `{"svn": svn, "payload": P}` with D's P-256 key.
3. **Propose `adns_set_node_join_policy {policy: P, signature}`.** The
   constitution verifies D's signature, requires `P.svn` to advance, and SETS
   CCF's SNP join tables. Record the commit transaction ID. Fetch
   `GET /app/governance/anchors` and verify its receipt: `node_join_policy.svn`
   must equal `P.svn`.
4. **Start the new node** as a joiner (`ccf/run.py` join configuration, ACI
   template from `tools/build_aci_template.py`) against the current primary.
   It is admitted only if its quote matches `P`. Wait for it to be trusted and
   caught up (`/node/network`, `/node/state`).
5. **Verify on the new node**: `tools/audit_ccf_node.py` against `P`'s
   measurement (a bootstrap-only audit), `tools/verify_ksk_receipt.py` for
   each zone, `tools/verify_claims_receipt.py` on `/app/governance/anchors`,
   `tests/rust-integration/verify_native_dns.py` for signed answers.
6. **Overlap.** Registrations continue on either node (single CCF service,
   same ledger). Consumers such as the hosting publisher re-audit the node they
   connect to against the pinned service identity and the *new* node policy;
   agent-hosting updates `infra/trust/pins.json node_policy` via a reviewed
   commit after verifying the policy receipt.
7. **Retire the old node**: `remove_node` proposal, then stop its container.
8. **Close the window.** D signs `P'(svn + 1)` listing only the new release;
   propose it. From now on the retired measurement cannot rejoin even with a
   valid quote.

## Rollback

Before step 8 the old release is still admissible: stop the new node and
propose `remove_node` for it. After step 8 a rollback is a *new* signed policy
with `svn + 1` that re-lists the old measurement; anti-rollback is about the
policy sequence, not about forbidding a deliberate, signed decision to run older
code. Recovery from ledger loss is `operations.md`, not this document.

## What must be true before the first use

- `adns_set_release_authority` has been proposed with a D whose custody is
  recorded in both repositories.
- The current primary's measurement/host data/UVM/TCB are known, so `P(svn=1)`
  can list them (the live node was bootstrapped with `add_snp_*`; `P(1)` makes
  the current state signed and SVN-gated without changing it).
- The consortium is more than one member; otherwise every step above is one
  person's decision, whatever the ledger says.
