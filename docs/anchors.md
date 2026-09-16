# Published anchors

What a consumer (today: agent-hosting, `infra/trust/pins.json`) pins about this
authority, where each value is served with a CCF receipt, and how it changes.
Values below are as observed on 2026-09-16 against the native ACI SNP primary;
the endpoints are the source of truth.

## Endpoints (all receipt-bearing; verify with `tools/verify_claims_receipt.py` or `tools/verify_ksk_receipt.py`)

| Endpoint | Claims type | Binds |
|---|---|---|
| `GET /app/governance/anchors` | `agentdns-anchors-v1` | every zone's KSK/DS, every appraisal policy (policy_id, canonical digest, validity), the node join policy (svn, measurements, host data, UVM endorsements, TCB) and the release authority (DID, key, svn) |
| `GET /app/governance/policy-receipt?zone=` | `agentdns-appraisal-policy-v1` | the appraisal policy in force for one zone, including its full body |
| `GET /app/governance/ksk-receipt?zone=` | KSK receipt (`agentdns.ksk.receipt.v1`) | owner name + complete DNSKEY RDATA; DS is recomputed by the verifier |
| `POST /app/service/anchor` / `GET /app/service/anchor` | `agentdns-anchor-v1` | (registration, subject, sequence, digest) anchored under an active registration's key |

Every response carries `ccf_service_identity`, the service certificate that
endorses the receipt. The verifier compares it to an externally trusted copy;
receipt-supplied certificates are never trust anchors.

## Service identity history

| SHA-256 (DER) | Valid | How it was established |
|---|---|---|
| `ed6c695f7fa97ecb6539cc05ed8d7cc77a820bf12b8dcf73954157f98372ceae` | 2026-09-13 10:46:26Z → 2026-09-20 10:46:25Z | native ACI SNP primary opened 2026-09-13 (`docs/acceptance-native-final-20260913.md`); audited by `tools/audit_ccf_node.py` |

On disaster recovery a new service identity is created and CCF records the
previous one in `public:ccf.gov.service.previous_service_identity`. The
recovery drill (`ccf/tests/live_smoke.py --recovery`) verifies KSK receipts
under both identities; consumers accept the transition only under the rule in
agent-hosting ADR 0023 (same zone, both receipts verify, identical DNSKEY
RDATA). Append the new identity here with its recovery transaction ID.

## Zone anchors

| Zone | KSK algorithm / key tag | DS (type 2) | Public delegation |
|---|---|---|---|
| `attestation.agent.hosting.` | 14 / 45132 | `d746e07e0b7214b995b195310db4f5bb0e4c2dc7cb8817c6afae1ff55c1e6aa2` | none (private integration zone) |
| `agent.hosting.` | 14 / 59729 | `63db4cd20f2596721ce86bd43add9adb90e83d870eb3d3fe6beb8e5b534fcc14` (created 2026-09-16, tx `2.273965`) | Azure DNS remains authoritative (DS `8806 13 2 39FAF5…`) until the owner re-delegates |

No online KSK rollover exists (see `operations.md`); a KSK change is a new zone
or an offline procedure with domain-owner sign-off.

## Node join policy (SVN-gated)

Set only by `adns_set_node_join_policy`, which requires the release authority's
signature over `{svn, payload}` with `svn` = current or current+1, replaces
CCF's SNP join tables wholesale (measurements, host data, UVM endorsements, TCB
minimums), and is mirrored to `public:agentdns.lifecycle/governance/node-join-policy`
with its canonical digest and signer DID. The ad-hoc `add_snp_*` actions remain
in the pinned CCF defaults for bootstrap only; a live upgrade uses the
choreography in `docs/upgrade-runbook.md`.

Current: **not yet set** on the live primary (the node was admitted with
`add_snp_*` during bootstrap). The first `adns_set_node_join_policy` proposal
(svn 1) is the first step of the upgrade runbook.

## Release authority D

`adns_set_release_authority` governs `{did (did:x509), public_key_pem (P-256
SPKI), svn, valid_from, valid_until}`. Once set, every `adns_set_appraisal_policy`
and `adns_set_node_join_policy` proposal must carry D's signature; D's `svn`
ratchets to the highest signed svn and a rotation cannot lower it.

Current: **not set**. Custody is an organisational decision recorded in both
repositories' shared-interface ADRs; the operator running this node must not be
the sole holder of D.

## Appraisal policies

| Zone | policy_id | release_id | valid until |
|---|---|---|---|
| `attestation.agent.hosting.` (authority node policy used by the hosting publisher) | `8dbbeaa16908c7ee4764366c8df5f99963dc7b843c72c596850764ae1b029052` | `agentdns-otel-native-v4-20260913` | 2026-09-16 16:36:36Z |

`/app/governance/policy-receipt?zone=` returns the current policy with a
receipt; a consumer that sees a different `policy_id_hex` must obtain and verify
that receipt before updating its pin (agent-hosting `infra/trust/verify.py --authority-policy`).

## Owner grants for agent-hosting

See `docs/governance/agent.hosting/`. Grants carry `attested_names` and
`attested_record_types`; records under those names are published on the
attested path as registration contributions (withdrawn with the registration),
distinct from operator records.

## Change log

| Date | Change | Transaction |
|---|---|---|
| 2026-09-16 | constitution `cf33091aa0135ca69354c406692428b51b95d32651cb231dc3d56f925c8960db`: `adns_set_release_authority`, `adns_set_node_join_policy`, grant `attested_names`/`attested_record_types`, `anchor` operation, D-signature requirement on appraisal policies | `2.273944` |
| 2026-09-16 | `adns_create_zone agent.hosting.` (private, not delegated) | `2.273965` |
| 2026-09-16 | owner grant `agent-hosting-mail-20260916` | `2.273969` |
| 2026-09-16 | owner grant `agent-hosting-worker-20260916` | `2.273971` |
| 2026-09-16 | constitution v2/v2.1 `5f28aa7c79ed2eefad95fc7151fab0faa91bf66a472517b6af6c649649c7b107`: governance v2 (ADR 0002) — reputation-weighted `resolve()`, governors, verdicts, settle | `2.303357`, `2.303431` |
| 2026-09-16 | operator member classified trapdoor; steward agent member `11c6ae7f…` admitted and active | `2.303439`, `2.303498`, `2.303603` |
| 2026-09-16 | first agent-decided proposal (governance parameters) | `2.303625` (create); accepted by the steward's ballot |

The running primary is still the pre-`anchors.rs` release: grants with
`attested_names` are stored but unreadable by that binary until the primary is
upgraded under `docs/upgrade-runbook.md`; the anchor and receipt endpoints do
not exist on it yet. Nothing uses those grants before agent-hosting phase 2.
