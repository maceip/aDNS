# 0002 — Unified-quote appraisal for agentdns (AWS-first, not Azure-locked)

Status: **accepted** 2026-09-17 (owner approved; items 1–4 locked below).
Policy/schema scaffolding is present as of 2026-09-18; verification is not
implemented and the profile remains rejected. Existing Azure profiles are
retained. This design does not authorize a live deploy.
Owner: agentdns / `adns-attest`.

## Decisions locked (the four approved deliverables)

| # | Decision |
|---|---|
| **1. Claim map** | §1 — `EatToken` v2 → `VerifiedAppraisal` / `AppraisalPolicy` (+ system surfaces). Crypto verify **delegated** to `unified-quote`. |
| **2. Profile ids** | §2 — one agentdns profile **`uq-eat-v2`**; Nitro vs AWS-SNP selected by `EatToken.platform` + policy pins, not separate profile strings. |
| **3. Wire format** | §3 — **`evidence_payload` = raw `EatToken` CBOR** (no COSE wrap). Digest + SPKI + nonce rules preserved as specified. |
| **4. 72h non-goals** | §4 — no eat-pass token economy for DNS registration; list is normative for agents. |

Shelved owner notes (attestation levels, “code that ran”, AAMP headers): §Shelved — not in this cut.

## Context

- Azure billing killed the live ACI primary; the next durable hub is **AWS**.
- Within ~72h we may **add** an Azure node again; multi-profile is the end state.
- `adns-attest` today implements only `azure-aci-snp` and `azure-cvm-snp`.
  `nitro` / `tdx` fail closed as `UNSUPPORTED_PROFILE` (WS 3.5 by design).
- **maceip/unified-quote** already verifies Nitro / SEV-SNP / TDX (and Azure SNP
  via vTPM) under one EAT (`EatToken`, profile `https://uq.secure.build/eat/v2`).
- That stack is **not** wired into agentdns. This ADR is the cutover design.

EAT is the universal **TEE evidence** claim map we will use unless a strictly
better one appears. It does **not** replace AAMP mail semantics, DKIM, or CCF
governance receipts — those are separate claim layers (see §1.0).
We are **not** inventing a third TEE envelope. We are **not** requiring eat-pass
tokens for DNS registration.

---

## 1. Claim map

### 1.0 System surfaces (what claims what)

Attestation is only one layer. The full product trust story is several claim
families that must not be collapsed into a single EAT.

Primary TEE claim (owner clarification): the quote answers **which measured
build / code ran** on that host. Keys in the registration are **bound to** that
code claim; they are not themselves the claim. Mail-host and worker are both
required as **separate** measured subjects.

```text
Internet mail (AAMP / SMTP / IMAP / JMAP)
        │
        ▼
   ┌─────────────┐   IMAP pickup / submission    ┌──────────────┐
   │  mail host  │ ◄────────────────────────────►│ worker host  │
   │  measured   │                               │  measured    │
   │  mail build │                               │  worker build│
   └──────┬──────┘                               └──────┬───────┘
          │  owner grants + register (uq-eat-v2)         │
          │  EAT ↔ code + bound subject key             │
          └──────────────────┬──────────────────────────┘
                             ▼
                    ┌─────────────────┐
                    │ agentdns (CCF)  │  appraisal → registration → DNSSEC zone
                    │ + BIND secondary│  anchors, grants, D / constitution
                    └─────────────────┘
```

| Surface | Protocol / artifact | Claims it can make | Does **not** claim |
|---|---|---|---|
| **Mail ↔ Worker** | SMTP/IMAP/JMAP + AAMP lifecycle | Message accepted; job queued; reply submitted; DMARC/DKIM disposition | Hardware TEE; CCF commit; DNSSEC |
| **AAMP** | Headers, MIME parts, `AAMP-Receipt` | Content-ID ↔ part digest ↔ kid; lifecycle ops the worker implements | That the receipt key’s *code* was hardware-attested (needs registration + EAT) |
| **Worker execution record** | COSE Sign1 over record CBOR | Exact inbound MIME hash, extracts, reply bytes, sequence chain | `security_claim: true` until that worker build/key is appraised+registered |
| **DKIM `default` / `cvm1`** | DKIM-Signature | Named key signed these bytes | By itself: which TEE code held the key (needs EAT registration of that subject) |
| **AAMP ↔ CCF** | `AgentdnsAnchor` → `POST /app/service/anchor` | CCF receipt binds `(registration, subject, sequence, digest)` | AAMP semantics; mail delivery |
| **CCF governance** | constitution, D, steward ballots, grants | Who may register which names/roles; which measurements/Value X are allowed | That a given email was processed correctly |
| **CCF DNSSEC** | zone KSK/RRSIG, secondary AXFR | Authoritative attested names after registration | SMTP path authenticity |
| **Edge / anycast** (lab) | eligibility snapshot | Operator-signed eligibility (today); later TEE if profiled | Production MX path until explicitly cut over |
| **Client / pins** | `pins.json`, verify-cli | What keys/policies the client accepts | Live TEE by itself |

**Mail vs worker (must stay distinct in grants and EATs)**

| Role | Measured code (EAT `value_x` / measurement) | Bound subject key at register | Publishes via registration |
|---|---|---|---|
| **mail** | Mail-host / Stalwart stack build | One SPKI per registration (TLS and/or DKIM `default` as separate regs if both need attestation) | MX, A/AAAA, TLSA, DKIM TXT under `attested_names` |
| **worker** | Worker (+ executor) build | Receipt ES256 SPKI; `cvm1` DKIM as second registration if attested | `_receipt…` TXT, `cvm1._domainkey…` TXT, optional SVCB later |

Rules:

1. One EAT ↔ one `signer_spki_der` ↔ one registration subject. Mail and worker are **separate** registrations (separate grants already: `agent-hosting-mail-*`, `agent-hosting-worker-*`).
2. Do not reuse a mail EAT to register a worker subject (or vice versa): `value_x` / measurement pins differ per role **build**.
3. AAMP never talks to CCF directly. Only the worker’s anchor client does, and only after that worker subject is registered.
4. `security_claim` / `NO HARDWARE CLAIM` stay false until the relevant **build+key** registration is live under an appraised `uq-eat-v2` (or legacy Azure) policy — AAMP headers alone never flip it.

**AAMP ↔ CCF claim bridge**

| Step | Claim produced | Input | Verifier |
|---|---|---|---|
| 0. Register | TEE appraisal of worker (or mail) build + bound key | `uq-eat-v2` evidence | agentdns `appraise` |
| 1. Worker finishes turn | Execution record + COSE receipt (AAMP-facing) | MIME digests, kid=receipt SPKI | verify-cli / mail client |
| 2. Optional header | `AAMP-Receipt: cid; sha256; kid` | Part digest | Same; mismatch → `header_digest_mismatch_receipt_valid` (prior pain shelved) |
| 3. Anchor | CCF receipt over `(registration_id, subject, sequence, record_sha256)` | Active worker registration | `verify_claims_receipt` / pins |
| 4. Next record | Embeds prior anchor tx/receipt | Step 3 | Chain check |

EAT is required at **step 0**. It is **not** re-sent per AAMP message. Per-message trust is COSE receipt ± anchor, not a new EatToken.

**CCF node vs workload**

| Subject | Evidence | Profile / path |
|---|---|---|
| agentdns **node join** | CCF platform attestation / node-join policy (D-signed) | **Not** `uq-eat-v2` service registration; keep node-join separate |
| mail / worker / edge **workloads** | `EatToken` in `evidence_payload` | `uq-eat-v2` → this ADR |

---

### 1.1 Crypto / admission: `EatToken` → appraisal (must pass before any TEE claim is trusted)

Source: unified-quote `v2/src/eat.rs` (`EAT_VERSION = 2`,
`EAT_PROFILE = "https://uq.secure.build/eat/v2"`).
Target: `crates/adns-attest` `VerifiedAppraisal` + `AppraisalPolicy`.

| Unified-quote check | agentdns obligation |
|---|---|
| Decode CBOR `EatToken`; `version == 2`; `eat_profile` ∈ accepted set | Fail closed on mismatch |
| Verify `platform_quote` → vendor root (Nitro CA / AMD ARK / Intel) via `unified-quote::quote::verify` | **Delegate** — do not reimplement |
| `report_data[0..32] == EatToken::binding_bytes()` | **Delegate** to uq (not ACI’s `SHA256(SPKI)‖0³²`) |
| `tls_spki_hash == SHA256(DER SPKI of attested channel key)` | For registration: require `tls_spki_hash == SHA256(signer_spki_der)` (same key registers and is channel-bound) |
| Walk `previous_attestation` chain when present; stable `value_x` | Required for stage-1 receipts; stage-0 alone is insufficient for **service** registration |

agentdns keeps its existing outer gates unchanged:

- `SHA256(evidence_payload) == action.evidence_digest`
- client ES256 over JCS(action…) under `signer_spki_der`
- nonce / grant / intent_hash from `adns-auth`

### 1.2 Complete `EatToken` field → agentdns disposition

Every `EatToken` field (uq v2) must have an explicit fate:

| `EatToken` field | Disposition |
|---|---|
| `version` | Must be `2`; else reject |
| `eat_profile` | Must be in `unified_quote.accepted_eat_profiles` (default `https://uq.secure.build/eat/v2`; legacy `https://bountynet.dev/eat/v2` optional) |
| `binding_suite` | Must be in `unified_quote.binding_suites` (default `{0}` only in 72h) |
| `value_x` | Must be in `unified_quote.approved_value_x`; **not** stored on today’s `VerifiedAppraisal` — pin-only unless impl adds an optional serialized extension later |
| `platform` | Must map to `unified_quote.approved_platforms` (`1=nitro`, `2=sev-snp`, `3=tdx`) |
| `platform_measurement` | → `VerifiedAppraisal.measurement` (require len 48 for v1); must be in `approved_measurements` |
| `platform_quote` | Verified by uq; not copied into `VerifiedAppraisal` |
| `tls_spki_hash` | Must equal `SHA256(signer_spki_der)`; feeds `spki_sha256` consistency |
| `source_hash` | Integrity via `binding_bytes` only; **not** separately allowlisted in 72h |
| `artifact_hash` | Same as `source_hash` |
| `iat` | Skew check vs `now` (±300s) and within policy window |
| `eat_nonce` | **Locked:** must equal the raw 32-byte agentdns registration nonce from `POST /service/nonce` (same bytes, not a hash). Mismatch → reject |
| `previous_attestation` | If `require_stage1_chain`: must be non-empty and verify recursively under uq; else reject stage-0-only |

Quote-derived extras (from verified `platform_quote`, not bare EAT fields):

| Derived | → `VerifiedAppraisal` |
|---|---|
| SNP `host_data` or `[0;32]` | `host_data` |
| SNP product or `"nitro"` / `"tdx"` | `product` |
| SNP TCB or documented zero sentinel | `reported_tcb` |
| — | `uvm_*` empty for uq path |
| lease formula | `valid_until` as today |

Also always set: `profile = "uq-eat-v2"`, `policy_id` / `release_id` from KV policy, `evidence_digest = SHA256(evidence_payload)`, `spki_sha256 = SHA256(signer_spki_der)`.

### 1.3 Field map → `AppraisalPolicy` (extensions)

Existing fields reused:

| Policy field | Pins |
|---|---|
| `active_profiles` | Must contain `"uq-eat-v2"` |
| `approved_measurements` | Lowercase hex of allowed `platform_measurement` values (PCR0 / MEASUREMENT / MRTD) |
| `approved_host_data` | SNP-only; empty allowlist must fail closed for SevSnp; **ignored** for Nitro |
| `minimum_tcb` | SNP-only products |
| `valid_*`, `max_appraisal_lifetime`, `policy_id`, `release_id` | Unchanged |

**New optional block** (constitution must allowlist before live settle):

```text
unified_quote?: {
  approved_value_x: set<hex48>      // required nonempty when uq-eat-v2 active
  approved_platforms: set<"nitro"|"sev-snp"|"tdx">
  require_stage1_chain: bool        // default true for service registration
  accepted_eat_profiles: set<uri>   // default {https://uq.secure.build/eat/v2}
  binding_suites: set<u16>          // default {0}
}
```

`uvm` / `azure_cvm` remain Azure-native; unused for uq profiles.

### 1.4 Role-scoped policy pins (mail vs worker)

AppraisalPolicy is per zone today; grants already separate mail vs worker.
For `uq-eat-v2`, pins must not silently allow either role under the other’s
measurement:

| Pin | Mail registration | Worker registration |
|---|---|---|
| `approved_measurements` | mail image PCR0 / MEASUREMENT only | worker (+ executor) image only |
| `approved_value_x` | mail stack Value X | worker Value X |
| `approved_platforms` | may differ (e.g. both `sev-snp`) | may include `nitro` for enclave worker later |
| Owner grant `roles` / `attested_names` | MX, mailbox domain, DKIM default selectors | receipt TXT, cvm1 selector, worker hosts |

If a single zone policy object cannot express two pin sets, use **two policy_ids**
(mail release vs worker release) — same as separate grants. Do not OR all
measurements into one allowlist that either host can satisfy.

### 1.5 What is *out* of the EAT claim map (explicit)

| Artifact | Why not in EatToken |
|---|---|
| AAMP intent / conversation ids | Application protocol; bound in execution record |
| Inbound/outbound MIME bodies | Privacy + size; hashed in record, not in TEE quote |
| DKIM signature bytes | Mail auth layer; subject key may be EAT-registered |
| CCF transaction id / Merkle proof | Produced by ledger after admission/anchor |
| Steward ballot / D signature | Governance; inputs to policy, not workload evidence |
| DNS RRSIG / DS | Zone authority after commit |
| eat-pass spend tokens | Non-goal (72h); not required for register/anchor |
| Attestation *level* taxonomy (bare hash vs TEE vs RA-TLS) | Shelved — see §Shelved |

---

## 2. Profile id(s) and what Nitro vs AWS-SNP pin

### 2.1 Decision: one agentdns profile, platform inside the EAT

| agentdns `evidence_profile` | Meaning |
|---|---|
| **`uq-eat-v2`** | Evidence is a unified-quote `EatToken` v2 CBOR blob; platform is `EatToken.platform` |

Do **not** invent separate agentdns ids per cloud for the first cut (`uq-nitro`, `uq-sev-snp`, …). That re-creates Azure lock-in at the dispatcher. `active_profiles = {"uq-eat-v2"}` plus `unified_quote.approved_platforms` selects Nitro and/or SNP.

Azure legacy profiles stay:

- `azure-aci-snp` — unchanged COSE+UVM path
- `azure-cvm-snp` — unchanged HCL path (still constitution-incomplete)

When Azure returns in ~72h, prefer **emitting uq EATs from Azure SNP nodes** (uq already does AMD-rooted Azure via vTPM) and admitting them under `uq-eat-v2` with `approved_platforms` including `sev-snp`. Keep `azure-aci-snp` only for old ACI captures, not as the long-term multi-cloud path.

### 2.2 Pins by platform (under `uq-eat-v2`)

| | **Nitro** (`platform = 1`) | **AWS SEV-SNP** (`platform = 2`) |
|---|---|---|
| Trust root | AWS Nitro Root CA (via uq) | AMD ARK (VCEK or VLEK→ASVK→ARK via uq) |
| Measurement pin | `approved_measurements` ← **PCR0** (48B) | `approved_measurements` ← SNP **MEASUREMENT** (48B; often OVMF-only — see caveat) |
| Host / launch pin | none (`host_data` zero; `approved_host_data` ignored) | `approved_host_data` ← SNP `host_data` if used; else document empty-reject |
| App identity (code) | `approved_value_x` | same |
| Key binding | `tls_spki_hash == SHA256(signer_spki)` + uq `binding_bytes` in `report_data` | same |
| Honest claim | Provider-rooted enclave **image/code** | Silicon-rooted firmware launch; **kernel/workload not in MEASUREMENT alone** |

**AWS SNP caveat (from uq docs):** SNP `MEASUREMENT` on EC2 often covers firmware launch, not kernel/initrd. Full coverage needs NitroTPM linkage (`REPORT_DATA` binds `sha256(nitrotpm_doc)`).

**72h rule:**
- If admitting **bare** `sev-snp` EATs: document that security-class claims do **not** cover guest kernel unless linked evidence is present and verified by uq.
- Prefer **Nitro** for the first AWS *workload* registration if the first goal is “image PCR0 matches what we built.”
- Prefer **SEV-SNP** (or linked SNP+NitroTPM) for the *agentdns primary* trust story when silicon root matters.

Both may be in `approved_platforms` at once; that is intentional for the 72h Azure add-back.

### 2.3 Dispatcher sketch

```text
appraise(profile, evidence, spki, policy, now):
  if profile == "azure-cvm-snp": → existing
  if profile == "azure-aci-snp": → existing
  if profile == "uq-eat-v2":     → uq_adapter::appraise(...)
  else: UNSUPPORTED_PROFILE
```

`uq_adapter` calls the `unified-quote` crate (git dep, same as attestation-service) — **no vendored copy**.

---

## 3. `evidence_payload`: raw EAT vs COSE-wrapping EAT

### Decision: **raw `EatToken` CBOR bytes** (no agentdns COSE wrapper)

Rationale (aligned with unified-quote `eat.rs`):

> EAT per RFC 9711 is often COSE-wrapped. unified-quote **deliberately skips**
> COSE: the TEE hardware quote **is** the signature. Claims are bound via
> `binding_bytes()` → `report_data`. A second COSE key adds no trust.

| Layer | Format |
|---|---|
| `evidence_payload` | Exact CBOR serialization of `EatToken` (uq encoder) |
| `evidence_digest` | `SHA256(evidence_payload)` — unchanged agentdns rule |
| `evidence_profile` | `"uq-eat-v2"` |
| Outer client auth | Existing ES256 SignedRequest (unchanged) |
| Azure profiles | Still COSE Sign1 with `att/eds/uvm` or CVM map — **unchanged** |

### Binding rules preserved

1. **Digest gate:** tampering with EAT bytes fails `evidence_digest` before appraisal.
2. **SPKI gate:** `tls_spki_hash == SHA256(signer_spki_der)`; uq binding includes `tls_spki_hash`, so hardware signed that commitment.
3. **Freshness:** `eat_nonce` **must equal** the raw 32-byte agentdns registration nonce (§1.2). Reject reuse via existing nonce consume.
4. **Do not** apply ACI `report_data == SHA256(SPKI)‖0³²` to uq evidence — that would false-reject every real uq quote.

### Rejected alternative

COSE Sign1 wrapping the EAT “for consistency with ACI” — rejected: duplicate signing model, fights uq, invites a soft key that isn’t the TEE.

---

## 4. Explicit non-goals (72 hours)

Out of scope for the first AWS-capable appraisal cut. Do not let agents expand into these:

1. **eat-pass / token economy** — no PoMFRIT, no attestation-gated unlinkable tokens, no spend API for DNS registration.
2. **Replacing DNSSEC / CCF** — uq appraisal admits registrations; it does not replace the ledger or zone signing.
3. **Rewriting `azure-aci-snp` / `azure-cvm-snp` into EAT** — leave legacy paths; new work is `uq-eat-v2` only.
4. **GCP / TDX production pins** — may appear in `approved_platforms` later; no GCP deploy required in 72h.
5. **Live Azure ACI bring-up** — blocked/irrelevant until billing; design must not depend on ACI.
6. **Public zone delegation / anycast MX / `security_claim: true` product flip** — separate ladder.
7. **Constitution settle on a dead primary** — code + unit tests + Virtual CCF may land; live `adns_set_appraisal_policy` waits for a durable AWS (or restored) hub.
8. **Full NitroTPM↔SNP linked appraisal policy UX** — may use uq’s linker if already in-crate; do not build a second linker in agentdns in 72h.
9. **Attested-TLS termination inside CCF** — registration evidence is enough; serving agentdns over attested-TLS is later.
10. **Vendor-neutrality theater** — one working AWS path + claim map beats three unfinished clouds.
11. **Attestation-level taxonomy / multi-tier labels** — shelved (§Shelved).
12. **AAMP header / profile surgery** — shelved (§Shelved).

### In scope for 72h (implementation follow-on, after this ADR)

- `uq-eat-v2` adapter behind `appraise`, git dep on `unified-quote`
- Policy struct + tests with Nitro and SEV-SNP fixtures from uq testdata / live captures
- Constitution field allowlist for `unified_quote` (steward) — can land offline compose/tests first
- Document honest trust roots (Nitro = AWS; SNP = AMD)

---

## Shelved (owner, 2026-09-17) — do not implement in this cut

Recorded so it is not lost; **out of scope until explicitly reopened.**

1. **Attestation levels / honest multi-tier claims.** Same hashed WASM (or build) on a plain CPU vs inside SGX/TEE vs that TEE plus RA-TLS/attested channel are *different* assurance levels. Collapsing them into one “verified” / one `security_claim` bit is dishonest. Likely needs work in unified-quote tiers and/or eat-pass policy (and agentdns admission labels) — not decided here.
2. **Quote = which code ran**, not “server authentication.” Mail-host and worker are both in scope as *separate* measured builds, each with its own registration/EAT. Keys are bound to that code claim; they are not the claim. (Framing accepted into §1.0; *level taxonomy* remains shelved.)
3. **Prior AAMP/header mapping pain.** Last time this map was done, receipt/header carriage was problematic (headers not working cleanly; possible AAMP profile changes). Do not reopen that rabbit hole under this ADR.

## Consequences

- agentdns stops being Azure-shaped at the **appraisal boundary** while keeping Azure profiles for old evidence.
- Multi-cloud = multiple `approved_platforms` + multiple nodes, **one** evidence profile.
- Mail and worker each register their own measured build under `uq-eat-v2`; AAMP stays mail-facing; CCF stays ledger/DNS — EAT only at register (and thus later anchors).
- Sitrep “ephemeral CCF hub” is still fixed with **durable disk on AWS**, independent of this ADR.

## References

- `crates/adns-attest/src/lib.rs` — `AppraisalPolicy`, `VerifiedAppraisal`, profile dispatch
- `port.md` WS 3.5 — intentional Nitro/TDX stubs; AAMP/mail out of agentdns scope
- `docs/decisions/0001-agent-hosting-shared-interface.md` — grants, anchors, upgrade choreography
- agent-hosting `docs/decisions/0024-agentdns-shared-interface.md` — AAMP-Receipt, phases, `security_claim`
- https://github.com/maceip/unified-quote — `v2/src/eat.rs`, `v2/DESIGN.md`, `v2/src/tiers.rs`
- https://github.com/maceip/eat-pass — out of scope for DNS registration (72h); policy/tiers interaction shelved above
