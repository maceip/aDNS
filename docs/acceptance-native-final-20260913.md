# Native Azure acceptance — September 13, 2026

Execution is in progress. This document does not yet claim all twelve checks
have passed. The user explicitly authorized deployment, runtime test
credentials, and the remaining attestation, registration, DNS and lifecycle
acceptance. Ordinary image pulls are retained.

## Deployment under test

All resources are confined to `agentdns-port-validation-20260913` in North
Europe. The primary and both workload fixtures use confidential ACI. The
canonical stock BIND secondary uses a two-core `Standard_EC2as_v5` VM because
ACI rejected public TCP and UDP mappings sharing port 53. BIND receives signed
public zone data and a runtime transfer key; DNSSEC private keys remain in CCF.
No VM attestation claim is substituted for the primary or worker appraisal.

The published primary uses OCI index
`sha256:c921354c712a293af58925657404be3e28853cc70e652d164e4f793da3f2ed1a`,
AMD64 manifest
`sha256:4f1e45729cf74748f897cb64ec86c6be3e7e6fbdd711774c698222e9f38d2dff`,
and ELF SHA256
`6bcbf0a885cabdbea18ea3a25e0a3c56a49deaf1cf97e100ec97ff069ada8683`.
Registry bytes were fetched independently and matched the reviewed local
image. All six layers use ordinary gzip; no lazy-pull conversion was applied.

Runtime bootstrap credentials are supplied separately from the image. The
first primary start generated an SNP quote but failed because its public
configuration omitted CCF's attestation collateral settings. The corrected
bootstrap adds the native UVM input paths and Azure/AMD collateral servers;
its manifest and CCE policy are regenerated before quote appraisal. This
configuration correction does not change the published image or ELF.

That corrected deployment subsequently returned a genuine version 5 SNP
report. The original parser supported versions 2/3 and rejected it before
service-CA trust. The image above includes reviewed version 5 parsing and
regressions, with 109 Rust tests, Rust 1.85.1 compatibility, strict Clippy,
and exact-ELF CCF quorum/recovery checks passing. Independent image-layer
inspection found none of the 113 representations of actual test secrets
across 2,401 files in all six layers. The new primary then passed both Rust
and independent raw-quote verification; its authenticated governance setup
committed successfully.

Startup subsequently exposed an internal readiness ACL defect: CCF returns
HTTP 503 when `/node/state` is denied on the loopback interface, leaving the
supervisor waiting and the lifecycle driver unstarted. The native bootstrap
now explicitly permits that read-only route alongside internal application
routes. The exact packaged supervisor regression passed, and the corrected
deployment at `4.208.82.123` passed fresh hardware verification before
governance. Its CCE digest is
`8603aef5c7e35fb24ec32902fcad8572474e814f7b7f54abaa4b6e83ad50a94e`,
with bootstrap manifest
`f4d501a1521ef98ea87135ce955fba638a733d7acd2236f52cf7cc475278838a`.
This allocation returned a genuine supported version 3 report. Image and ELF
pins remain unchanged; version 5 support remains exercised by the earlier
actual reports and regression evidence. No registration was sent to either
incomplete startup.

The corrected driver initialized the zone autonomously. Worker A committed
at transaction `2.143`, serial 8; worker B committed at `2.173`, serial 9.
Their measured submission-to-committed-response times, including TLS and WAN
transport, were 1,508.392166 ms and 1,429.411 ms respectively (one sample each).

## Evidence and remaining checks

| Check | Native execution status |
| --- | --- |
| Hardware appraisal | Both workers and the corrected primary passed actual TLS/SPKI binding, Rust appraisal, independent cryptographic verification and sixteen evidence negatives each. Both genuine signed registrations committed. |
| Owner scope | Six authentic signed native denials passed: hostname, role, address, port, expired grant and revoked grant. Each retained a globally committed failure observation without consuming the nonce or changing the zone. |
| Signed requests | Native fixed-width/JCS signatures, DER rejection, altered signature/evidence, consumed nonce and exact historical retries passed. Changed-key conflict still pending. |
| Commitment | Both native registrations and six authenticated failure observations were independently confirmed committed; exact retries preserved original transaction IDs. Lifecycle and sustained served-serial observations remain pending. |
| DNSSEC | Native full-zone and stock-validator checks pending primary/secondary readiness. |
| AXFR | Runtime BIND provisioning and public TCP/UDP port 53 serving passed with transferred signed SOA serial 9. Independent full transfer-chain and negative tests are running. |
| Idle maintenance | A 1,250-second mutation-free observation with a 1,200-second fixed load is prepared; not yet run. |
| TLSA rotation | Both independently appraised keys are available; coexistence and selective withdrawal pending registration. |
| ACME concurrency | Signed create/create/delete and natural expiry prepared; not yet run. |
| Mail interoperability | Controlled DANE/PKIX checks against actual native worker keys pending published TLSA records. |
| KSK receipt | Native receipt at transaction 2.48 verified; KSK tag 9055. Independent tamper variants are running with the full DNS verifier. |
| Performance | Native registration, signing, WAN frontend and Azure memory measurements pending. Local measurements are reported separately. |

Worker evidence is published in
[the native worker bundle](evidence/native-workers-final-20260913/README.md).
Rebuilt-primary hardware verification is preserved in
[the independent primary bundle](evidence/native-primary-final-v5-independent-20260913/README.md),
and exact-ELF quorum/recovery evidence is in
[the version 5 build bundle](evidence/ccf-native-v5-20260913/README.md).
Earlier exact-image local checks remain in
[the local acceptance report](acceptance-ccf-final-20260913.md).
Private execution material stays under
`.validation/azure/native-final-20260913/`; public artifacts require an explicit
allowlist, integrity verification and a scan against actual test credentials.
