# Rust native attestation implementation and evidence

`crates/adns-attest` implements WS 3.1–3.5. Native crypto paths are exercised against actual AMD/Microsoft signed evidence, including [both deployed ACI test workers](evidence/native-workers-final-20260913/README.md). Their genuine reports bind their separate guest-generated service SPKIs and passed Rust and independent Python/OpenSSL appraisal at the recorded verification time. Historical fixtures binding the bytes `1234` remain separate regression inputs. The user has approved native deployment, runtime test credentials, signing and remaining acceptance. The rebuilt primary has also passed genuine hardware/TLS bootstrap appraisal and generated a receipt-verified DNSSEC key; sustained native lifecycle and performance acceptance remains in progress.

## API and trust boundary

```rust
appraise(profile, evidence_cose_bytes, signer_spki_der, &committed_governance_policy, unix_seconds)
    -> Result<VerifiedAppraisal, AttestationError>
```

Only `azure-aci-snp` is implemented. It also must be activated by `AppraisalPolicy.active_profiles`. Virtual reports, TDX, Nitro, vTPM, and unknown profiles fail closed. Empty policy allowlists cannot admit evidence. Duplicate publisher DID/feed entries are rejected as ambiguous governance. A successful `VerifiedAppraisal` is serializable for storage but not deserializable or constructible outside the crate. Its lifetime is bounded by policy, the maximum appraisal interval, and current AMD certificate expiry. In the default strict UVM mode it is also bounded by UVM certificate expiry.

The caller must read `AppraisalPolicy` and time from trusted committed service state. It must never accept a client-supplied policy, clock or preconstructed appraisal. Nonces, owner scope, replay protection and committed request results belong to `adns-auth` and `adns-server`.

The input is tagged COSE Sign1 with an attached payload. The protected algorithm must be ES256 and its signature must be fixed 64-byte `r || s`. The key must be a canonical DER P-256 SPKI. The payload contains the existing `att` (1184-byte report), `eds` (standard-base64 THIM JSON or PEM chain), and `uvm` (COSE endorsement) fields. The supplied request SPKI verifies the outer signature and must match the signed SNP report's entire `SHA256(SPKI) || 32 zero bytes` field. Header claims never grant DNS names or owner authority.

## Implemented checks

- COSE parsing uses `coset`; CBOR has an input limit, depth limit, collection limits, duplicate-key rejection, exact outer shape, trailing-data rejection, header-bucket overlap rejection and fail-closed critical headers.
- AMD verification pins the existing Milan and Genoa ARK public keys, verifies the ordered ARK → ASK → VCEK path and self-signed root with OpenSSL, validates certificate time intervals and X509 constraints, rejects duplicate extensions, and bounds certificate/key sizes.
- The report is parsed using fixed-offset checked slices, with no unsafe code or raw-memory cast. Versions 2, 3 and 5 are supported explicitly; version 4 and unknown future versions fail closed. Version-specific and signature reserved bytes are checked. Version 5 mitigation vectors at offsets 504 and 512 are typed authenticated observations; the reserved remainder starts at 520. No mitigation authorization floor is inferred from their observed values.
- The report's P-384/SHA-384 signature is checked over its exact first 672 bytes. Little-endian padded AMD `r`/`s` fields are converted to canonical ECDSA values.
- VMPL must equal zero; debug and migration agents are prohibited; VCEK signing and an unmasked chip ID are required. AMD VCEK extensions must exactly match reported TCB and chip ID. Product names and version-3/version-5 CPUID must match the pinned product root. All four TCB states meet governed component-wise minima.
- Every byte of key binding is checked. UVM measurement and CCE `host_data` must match explicit lowercase-hex governance allowlists.
- Microsoft UVM paths verify their protected `x5chain`, DID-x509 root certificate SHA-256 fingerprint, required publisher EKU, digital-signature key usage, non-CA leaf, certificate time under the governed mode below, and cryptographic COSE signature. RSA-PSS uses the specified hash, MGF1 hash and digest-length salt; ES256/ES384 are also implemented. SVN comparisons are numeric.
- Legacy signed JSON and ContainerPlat 0.2.10 CWT endorsements are supported. A present but invalid CWT does not fall back to legacy parsing. CWT issuance time must be no later than appraisal and fall within each certificate's validity interval.

The genuine 0.2.10 Microsoft fixture encodes `iat` as CBOR epoch tag 1, despite RFC 8392 specifying an untagged NumericDate. The parser deliberately supports precisely that observed native form and an unsigned untagged integer. Other tags, nested tags, negative values and floating dates fail. Signatures cover the original protected bytes in either case.

## Governed immutable-release certificate semantics

`AppraisalPolicy.uvm_endorsement_time_policy` defaults to `"current_certificate"`: the UVM certificate chain must be valid at appraisal time, and its earliest expiry bounds the appraisal. No missing field silently enables a historical trust mode.

Governance may explicitly activate `"approved_release"` for native CCF-compatible immutable UVM endorsements. Microsoft CCF's pinned verifier passes `true /* ignore time */` to its DID resolver because a code-signing certificate's later expiry does not automatically revoke an already approved UVM release. This mode is restricted to an exact launch measurement already present in the governed allowlist. It retains every publisher identity, feed, SVN, measurement, COSE signature and pinned certificate-path check. CWT endorsements validate the chain at their authenticated `iat`, which must not be in the future. Legacy descriptors must have a common certificate validity interval in the past and the full path is verified at an instant in that interval. This does not claim an independent trusted timestamp for legacy signatures.

`approved_release` continues validating AMD VCEK/ASK/ARK certificates at current appraisal time. An expired UVM code-signing certificate does not cap the service lease; `policy.valid_until`, `max_appraisal_lifetime` and current AMD certificate expiry do. Governance must withdraw obsolete release measurements, raise minimum SVN, remove publisher identities or deactivate profiles to revoke an approved release. This behavior is an explicit native-profile compatibility choice, covered by genuine-fixture regressions, rather than silent removal of time checks.

The offline verifier performs no network CRL/OCSP retrieval. Deployment must define its certificate-revocation distribution policy; no live revocation checking is claimed.

## Verified fixtures and outcomes

`cargo test -p adns-attest --locked` passes 23 tests. `cargo clippy -p adns-attest --all-targets --locked -- -D warnings` passes. The tests include:

- Genuine repository Milan and Genoa AMD chains, report signatures, and Microsoft UVM signatures accepted at 2025-02-19, inside their certificate validity intervals.
- Genuine 2026-09-13 Genoa version 5 primary quote accepted with its actual TLS peer SPKI at the fixed fixture time 07:42 UTC. Both mitigation fields remain covered by the original AMD signature. Mutations, a rewritten version downgrade, CPUID/product mismatches and every reserved-byte boundary are rejected.
- The same genuine reports, wrapped in a valid newly signed ES256 envelope, rejected with `KEY_BINDING_MISMATCH`. Their signed `report_data` contains ASCII `1234` followed by zeros. Replacing those bytes would invalidate AMD's signature; tests never present modified bytes as genuine evidence.
- Microsoft-signed UVM 0.2.9 and 0.2.10 accepted at 2026-01-01 with their exact endorsed measurements and numeric SVN 103/104. The latter exercises CWT and the native tagged `iat`.
- Altered report and UVM signatures, swapped product endorsements, attacker roots, wrong service key, DER-sized outer signatures, nonzero report-data padding, disallowed measurements/CCE, wrong publisher/feed, low SVN/TCB, expired certificates in strict mode, duplicate headers and malformed/truncated inputs rejected.

The original UVM leaf expired on 2025-08-20. The imported 0.2.9/0.2.10 leaf expired on 2026-05-15. The crypto regression tests select historical verification times, and additional tests explicitly activate governed `approved_release` at a later time while rejecting the same expired UVM chains in default strict mode. Neither path represents a newly captured hardware report or repairs the existing `1234` service binding.

## Fixture provenance

The repository's `tests/sample_snp_attestation_milan.cbor` and `tests/sample_snp_attestation_genoa.cbor` are retained unmodified. The AMD public keys are copied from the existing `tools/attestation.py` pins.

Two additional genuine UVM fixtures and their Apache-2.0 license are imported from Microsoft CCF revision `33a90b076f0143b7a92e5da399b1b0de675625b8`:

| Local fixture | SHA-256 |
| --- | --- |
| `crates/adns-attest/tests/fixtures/ccf_uvm_0.2.9.cose` | `5c9f4dd2c502d4b0bad23f47df749f36de195e50a4520aee863debf6ffe792a6` |
| `crates/adns-attest/tests/fixtures/ccf_uvm_0.2.10.cose` | `f4f5321316ac3cf876292f41cb7bdcd1056aef3a815fb137887a4ef93c3210bc` |

Primary implementation references checked:

- [AMD SNP Firmware ABI specification](https://docs.amd.com/v/u/en-US/56860_PUB_SEV_SNP).
- [AMD VCEK certificate and KDS specification](https://docs.amd.com/v/u/en-US/57230).
- [Microsoft CCF SNP verification](https://github.com/microsoft/CCF/blob/33a90b076f0143b7a92e5da399b1b0de675625b8/src/pal/attestation.cpp).
- [Microsoft CCF UVM formats and verification](https://github.com/microsoft/CCF/blob/33a90b076f0143b7a92e5da399b1b0de675625b8/src/node/uvm_endorsements.cpp).
- [Microsoft CCF UVM fixtures](https://github.com/microsoft/CCF/tree/33a90b076f0143b7a92e5da399b1b0de675625b8/tests/uvm_endorsements).

The crate requires OpenSSL development headers/libraries (`libssl-dev` and `pkg-config` on Debian/Ubuntu). The `time` dependency is explicitly pinned to 0.3.44 to preserve the declared Rust 1.85 minimum; native verification does not fetch libraries, roots, or endorsements at request time.

## Remaining native acceptance work

Both final-image ACI workers were deployed and independently appraised at **2026-09-13 07:06:42 UTC**. The [76-artifact public bundle](evidence/native-workers-final-20260913/README.md) preserves each original report/COSE/SPKI, actual TLS peer certificate, jointly selected policy approving both CCE values, successful Rust appraisal and independent Python/OpenSSL checks, and sixteen rejected variations per worker. Their image includes the constrained lifecycle/mail fixture and absolute transport deadlines. No private service key is exported. The [earlier native capture](evidence/native-aci-20260913/README.md), appraised at 01:11:45 UTC, remains separate historical evidence.

The provisional primary's version 5 report passed the corrected Rust node auditor at **07:46:16 UTC**, including the exact TLS peer key, approved CCE policy, current AMD chain and Microsoft UVM identity. Its initial unsupported-version rejection and preceding ELF identity are retained. The [rebuilt primary bootstrap bundle](evidence/native-primary-v5-ready-20260913/README.md) separately identifies image manifest `4f1e45729cf74748f897cb64ec86c6be3e7e6fbdd711774c698222e9f38d2dff`, ELF `6bcbf0a885cabdbea18ea3a25e0a3c56a49deaf1cf97e100ec97ff069ada8683`, and approved CCE `8603aef5c7e35fb24ec32902fcad8572474e814f7b7f54abaa4b6e83ad50a94e`. That final allocation produced a genuine version 3 report and passed fresh appraisal at **08:19:06 UTC**, with an independent Rust reappraisal at **08:20:02 UTC**. No hardware generation was selected to avoid version 5, and no policy floor was lowered. The authenticated service opened, accepted governance, autonomously signed its zone and returned an independently verified KSK receipt.

Globally committed CCF registration, nonce possession, native lifecycle and DNS/DANE publication remain active acceptance work. The user has explicitly authorized those operations; they are no longer waiting for permission. Historical appraisal reproduction does not assert later certificate or policy validity.


## Offline CLI

The small example invokes exactly the production appraisal function and never accepts fabricated appraisals:

```sh
cargo run -p adns-attest --example appraise -- azure-aci-snp evidence.cose signer.spki.der policy.json 1789259343
```

The final argument must be the trusted evaluation time for the intended validation. The CLI emits `VerifiedAppraisal` JSON on success and a nonzero exit with the appraisal error otherwise. Selecting a historical time is appropriate for a labeled fixture regression, not for claiming current service admission.

A separate CCF node TLS bootstrap audit now reuses the genuine native verifier under an independently supplied node policy. It returns a distinct audit type and cannot create a service-admission appraisal; see [ccf-node-bootstrap.md](ccf-node-bootstrap.md). Its genuine version 5 node fixture verifies the actual peer key and remains negative for unrelated key binding.

The version 5 report, actual public TLS peer certificate and independently selected test policy are preserved in [the fixture provenance](../crates/adns-attest/tests/fixtures/README.md), with the AMD ABI reference and exact source hashes. This node audit remains a separate trust result and cannot construct a service-admission appraisal.
