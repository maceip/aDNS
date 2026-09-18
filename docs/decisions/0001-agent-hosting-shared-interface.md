# 0001 — Shared interface with agent-hosting

Status: **accepted** 2026-09-17 (pairs with agent-hosting ADR 0024).
Amended 2026-09-17: register/evidence follows [0002](0002-unified-quote-appraisal.md)
(`uq-eat-v2`). Choreography, recovery, D, grants, and anchors are unchanged.

## Decision

agentdns is the authority; agent-hosting is a consumer. agentdns defines and
enforces the rules below; agent-hosting automates its side against them.

1. **Upgrade choreography for any registered workload.** The release
   authority **D** signs the new workload appraisal policy (new `policy_id`,
   `svn + 1`); governance commits it (`adns_set_appraisal_policy` with D's
   signature), which invalidates registrations under the old `policy_id`
   (`registration_authority_invalid`); the new instance registers with
   evidence under **`uq-eat-v2`** ([0002](0002-unified-quote-appraisal.md));
   both keys overlap; the old instance deregisters. Mail-host and worker are
   **separate measured builds** and separate registrations. For the primary
   itself the same rule applies through `adns_set_node_join_policy`
   (`docs/upgrade-runbook.md`) — node-join is **not** `uq-eat-v2`.
   Legacy `azure-aci-snp` / `azure-cvm-snp` remain implemented profiles; they
   are not the hosting register path.
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
   `attested_record_types`; a registration may publish TXT and SVCB under
   exactly those names as its own contributions (DKIM selector keys, receipt
   keys, service bindings). Type 64 wire encoding and registration ownership
   are implemented; SVCB grants still require Agent A to update the constitution.
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
- Register/renew evidence for hosting workloads is **`uq-eat-v2`**
  ([0002](0002-unified-quote-appraisal.md)), not ACI `REPORT_DATA` padding.

## Blockers this ADR does not remove

- Real multi-member consortium (item 4 of the end-state list).
- Online KSK rollover (item 5): required before `agent.hosting.` is delegated.
- D custody (item 9): mechanism is in place; the key is not.

## Evidence profile (amended 2026-09-17)

Hosting register/renew uses **`uq-eat-v2`**: raw unified-quote `EatToken` CBOR
as `evidence_payload`. Binding is `tls_spki_hash == SHA256(signer_spki_der)`
plus uq `binding_bytes()` in `report_data`. The ACI rule
`REPORT_DATA = SHA256(SPKI) || 0^32` **must not** be applied to `uq-eat-v2`.
See [0002](0002-unified-quote-appraisal.md).

### Legacy Azure CVM (Decision #11, 2026-09-16) — not the hosting path

`azure-cvm-snp` remains in `adns-attest` for HCL/vTPM captures. It verifies the
HCL SNP report with VCEK/ASK/ARK (Genoa ARK DER SHA256
`4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1`).
That path is **legacy**. New mail/worker registrations follow 0002.
Profile contract: [azure-cvm-snp.md](../azure-cvm-snp.md).
