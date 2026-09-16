# 0001 — Shared interface with agent-hosting

Status: proposed 2026-09-16 (agentdns side). Accepted when agent-hosting's
ADR 0024 and this document agree and both are merged.

## Decision

agentdns is the authority; agent-hosting is a consumer. agentdns defines and
enforces the rules below; agent-hosting automates its side against them.

1. **Upgrade choreography for any registered workload.** The release
   authority **D** signs the new workload appraisal policy (new `policy_id`,
   `svn + 1`); governance commits it (`adns_set_appraisal_policy` with D's
   signature), which invalidates registrations under the old `policy_id`
   (`registration_authority_invalid`); the new instance registers with
   evidence; both keys overlap; the old instance deregisters. For the primary
   itself the same rule applies through `adns_set_node_join_policy`
   (`docs/upgrade-runbook.md`).
2. **Recovery-chain acceptance.** After recovery agentdns serves receipts under
   both the previous and the new service identity. A consumer accepts the
   transition only when, for the same zone, receipts under each identity verify
   and bind identical DNSKEY RDATA. agentdns records identities in
   `docs/anchors.md` with the recovery transaction.
3. **Custody.** D is a `did:x509` whose key is held outside the node. **Decided
   2026-09-16 (agent-hosting `docs/workstreams/DECISIONS.md` #1, #14):** the
   operator mints and holds D; the consortium's second member is the steward
   agent whose key moves to a VPS at a third provider, still the operator's.
   The earlier requirement "not by the sole operator" is **not met** and this
   ADR records that plainly: governance is single-organisation by decision
   until a second party holds a key. Live state (applied 2026-09-16): D minted on
   operator laptop (`did:x509:0:sha256:1YRq01voPnpplmc8U1z8JuIM6iTla__bGbck-J6rd7c::subject:CN:agent.hosting-release-authority`),
   committed via `adns_set_release_authority` at tx `2.330709` (svn 0).
   Constitution v0.2.0 (`1a05b637…`, adding `adns_ksk_rollover`) committed at tx `2.330731`.
4. **Attested records.** Owner grants carry `attested_names` and
   `attested_record_types`; a registration may publish TXT under exactly those
   names as its own contributions (DKIM selector keys, receipt keys). SVCB is
   not implemented (no wire codec); it is a follow-up, not a promise.
5. **Anchors.** `POST /app/service/anchor` binds `(registration, subject,
   sequence, digest)` under an active registration's key with a receipt;
   sequences per subject only advance; the same digest may be re-anchored
   idempotently. Consumers store the transaction ID and receipt in their next
   record.
6. **Published anchors.** `GET /app/governance/anchors` (receipted) is the
   in-band source for zone KSK/DS, appraisal policies, node join policy and
   release authority; `docs/anchors.md` is the human record.

## Consequences

- Constitution changes: `adns_set_release_authority`, `adns_set_node_join_policy`,
  grant fields, `anchor` operation, D-signature required on appraisal policies
  once D exists. These are `set_constitution` proposals, not code deploys.
- Application changes (attested contributions, anchor endpoints, receipt reads)
  require a primary upgrade under the runbook above; until deployed the live
  primary serves the previous release.
- Nothing here changes the public `agent.hosting` delegation.

## Blockers this ADR does not remove

- Real multi-member consortium (item 4 of the end-state list).
- Online KSK rollover (item 5): required before `agent.hosting.` is delegated.
- D custody (item 9): mechanism is in place; the key is not.
