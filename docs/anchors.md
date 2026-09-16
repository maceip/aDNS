# Published anchors

What a consumer (today: agent-hosting, `infra/trust/pins.json`) pins about this
authority, where each value is served with a CCF receipt, and how it changes.
Values below are as observed on 2026-09-16 against the upgraded native ACI SNP
primary (`agentdns-ccf-joiner-20260916.northeurope.azurecontainer.io` / `4.231.185.243`);
the receipted endpoints are the source of truth.

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
| `ed6c695f7fa97ecb6539cc05ed8d7cc77a820bf12b8dcf73954157f98372ceae` | 2026-09-13 10:46:26Z → 2026-09-20 10:46:25Z | native ACI SNP primary opened 2026-09-13 (`docs/acceptance-native-final-20260913.md`); audited by `tools/audit_ccf_node.py`; preserved across 2026-09-16 primary upgrade to node `f37a7b439a78` |

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
| `agent.hosting.` | 14 / 22434 | `ea02f545b3b20b8ee68c6c75e9d29c252b8022458670109cde9d4d26f0282947` (rolled over 2026-09-16, tx `3.361273`) | Azure DNS remains authoritative (DS `8806 13 2 39FAF5…`) until the owner re-delegates |
| `example.test.` | 14 / 9190 | `460abdec2424c10315522b207bc690ff06491f0d2fe7c0344cf709755057460e` | testing zone |

Online KSK rollover is governed (`adns_ksk_rollover`, steward `v0.2.1`) and
applied by the app in maintenance (`operations.md` → KSK rollover). During a
rollover the anchors document and the KSK receipt show the incoming key; the
parent DS switch stays a domain-owner action attested in the `complete` command.

## Node join policy (SVN-gated)

Set only by `adns_set_node_join_policy`, which requires the release authority's
signature over `{svn, payload}` with `svn` = current or current+1, replaces
CCF's SNP join tables wholesale (measurements, host data, UVM endorsements, TCB
minimums), and is mirrored to `public:agentdns.lifecycle/governance/node-join-policy`
with its canonical digest and signer DID.

Live policy: **P(svn=4)** committed at tx `3.359116` closing the upgrade window
after node `f37a7b439a78` joined and old primary `42f2b35133ff` was retired (tx `2.359089`).

- **Release ID**: `agentdns-20260916-v0.2.1`
- **Policy SHA-256**: `f120c82088019194e111f2437a6a391c500d5e4cae1828b9f01f20f7020a3183`
- **SVN**: 4
- **Approved Measurements**:
  - `dc3f5a934489232a9b1818f12a0a88d2324ced00f8ab370f40451a76b7880bc3e211849a0739642d3d6c3b2b4bfb9866`
- **Approved Host Data (CCE digests)**:
  - `366e4fdf131fb42a01d0e92b3b71829d1ad2b79b41602a6517f88578d5f18a28`
  - `65d4c4bea5ce65cd95d86a4b6f1f6ac1574f101bcd95e586ecce3f4ce3c6d289`
  - `8603aef5c7e35fb24ec32902fcad8572474e814f7b7f54abaa4b6e83ad50a94e`
- **UVM Endorsements**:
  - DID: `did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2`
  - Feed: `ContainerPlat-AMD-UVM`, SVN `104`
- **TCB Minimums**:
  - Genoa `00a10f11`: boot_loader 10, tee 0, snp 23, microcode 84

## Release authority D

`adns_set_release_authority` governs `{did (did:x509), public_key_pem (P-256
SPKI), svn, valid_from, valid_until}`. Once set, every `adns_set_appraisal_policy`
and `adns_set_node_join_policy` proposal must carry D's signature; D's `svn`
ratchets to the highest signed svn and a rotation cannot lower it.

- **DID**: `did:x509:0:sha256:1YRq01voPnpplmc8U1z8JuIM6iTla__bGbck-J6rd7c::subject:CN:agent.hosting-release-authority`
- **Algorithm**: ECDSA P-256, SHA-256
- **Current SVN**: 4
- **Valid**: 2026-09-16 14:46:55Z → 2036-09-13 14:51:55Z
- **Set**: tx `2.330709` (minted 2026-09-16 on operator laptop per `DECISIONS.md` #1).

## Appraisal policies

| Zone | policy_id | release_id | valid until |
|---|---|---|---|
| `example.test.` | `48c9cc8a269a1fae429f6e0df33ea9604404b053bf6cd6ce8333567d97d0859a` | `isolated-native-two-worker-final-20260913` | 2026-09-13 09:33:38Z |
| `attestation.agent.hosting.` | `0211a5f729c609ceb03f1deabd02d84a1811d8a87021ac0d75457512fbff5346` | `hosting-native-relay-20260915-v3-edge` | 2026-09-16 16:36:36Z |

`/app/governance/policy-receipt?zone=` returns the current policy with a
receipt; a consumer that sees a different `policy_id_hex` must obtain and verify
that receipt before updating its pin (agent-hosting `infra/trust/verify.py --authority-policy`).

## Owner grants for agent-hosting

See steward `governance/agent.hosting/`. Grants carry `attested_names` and
`attested_record_types`; records under those names are published on the
attested path as registration contributions (withdrawn with the registration),
distinct from operator records.

- `agent-hosting-mail-20260916`: re-issued tx `3.359156` (SPKI `43facdec…`, address `168.62.201.66/32`), supersedes initial grant tx `2.273969`.
- `agent-hosting-worker-20260916`: re-issued tx `3.359156` (SPKI `f7c6e0c2…`, address `52.241.250.148/32`), supersedes initial grant tx `2.273971`.

## Change log

| Date | Change | Transaction |
|---|---|---|
| 2026-09-16 | constitution `cf33091aa0135ca69354c406692428b51b95d32651cb231dc3d56f925c8960db`: `adns_set_release_authority`, `adns_set_node_join_policy`, grant `attested_names`/`attested_record_types`, `anchor` operation, D-signature requirement on appraisal policies | `2.273944` |
| 2026-09-16 | `adns_create_zone agent.hosting.` (private, not delegated) | `2.273965` |
| 2026-09-16 | owner grant `agent-hosting-mail-20260916` | `2.273969` |
| 2026-09-16 | owner grant `agent-hosting-worker-20260916` | `2.273971` |
| 2026-09-16 | constitution v2/v2.1 `5f28aa7c79ed2eefad95fc7151fab0faa91bf66a472517b6af6c649649c7b107`: governance v2 (ADR 0002) — reputation-weighted `resolve()`, governors, verdicts, settle | `2.303357`, `2.303431` |
| 2026-09-16 | operator member classified trapdoor; steward agent member `11c6ae7f…` admitted and active | `2.303439`, `2.303498`, `2.303603` |
| 2026-09-16 | first agent-decided proposal (governance parameters) | `2.303625` |
| 2026-09-16 | release authority D minted and set (`adns_set_release_authority`) | `2.330709` |
| 2026-09-16 | constitution upgraded to v0.2.1 (`6fd2190b…`) | `2.354622` |
| 2026-09-16 | node join policy P(svn=1) opening upgrade window (`adns_set_node_join_policy`) | `2.354714` |
| 2026-09-16 | primary joiner node `f37a7b439a78` trusted at `agentdns-ccf-joiner-20260916.northeurope.azurecontainer.io` (`4.231.185.243`) | — |
| 2026-09-16 | old primary `42f2b35133ff` retired (`remove_node`) | `2.359089` |
| 2026-09-16 | upgrade window closed with D-signed policy P(svn=4) | `3.359116` |
| 2026-09-16 | re-issued owner grants for mail and worker CVMs | `3.359156` |
| 2026-09-16 | receipted `/app/governance/anchors` verified live | `3.359743` |
