# Native Azure acceptance — September 13, 2026

All twelve original `port.md` acceptance checks are complete for the image
and ELF identified below. The user authorized deployment, runtime test credentials
and native acceptance. Ordinary image pulls are retained. OpenTelemetry and
CI/CD improvements were requested afterwards and have separate validation;
this report does not attribute these measurements to a later instrumented image.

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
| Hardware appraisal | Primary and both original workers passed native Rust and independent cryptographic/TLS verification. Freshly restarted A passed again before its changed-key conflict test. Genuine report versions and explicit UVM release-time policy are recorded. |
| Owner scope | Six authentic native hostname/role/address/port/expired/revoked-grant denials committed failure observations without consuming the nonce or changing the zone. |
| Signed requests | Fixed-width/JCS signatures, DER/altered-signature/evidence/consumed-nonce negatives and historical retries passed. The freshly appraised changed key received HTTP409 `REQUEST_ID_CONFLICT`; original transaction2.143 and zone serial remained unchanged. |
| Commitment | Native responses, failed-attempt observations and exact original historical transaction identities were independently confirmed. The exact ELF separately passed real CCF quorum loss/rollback and disk recovery in Virtual mode. |
| DNSSEC | Full zone passed independent ldns validation; stock delv verified initial positive/NSEC3/wildcard cases, 84 sustained checks and 18 final withdrawal/expiry checks. |
| AXFR | Ten authenticated frames transferred the native signed zone to stock BIND. Wrong/missing TSIG requests failed; public TCP/UDP53 serving and authenticated served-SOA observations passed. |
| Idle maintenance | 1,267.964-second external run and 1,250.901-second committed-status observation passed across four autonomous refreshes, serials14–18. No registration or zone mutation was issued during that window. |
| TLSA rotation | Both keys coexisted at25/465/993. A's port25 withdrawal committed2.2587/serial20; full withdrawal2.2696/serial21 preserved B and shared records. B naturally expired after a signed short lease, leaving all six dynamic RRsets absent at serial22. A's old listener remained through the full300-second cache grace before its restart. |
| ACME concurrency | Signed create/create/delete, exact coexistence, survivor preservation and natural expiry passed through stock DNSSEC validators. |
| Mail interoperability | Stock Postfix DANE-only authenticated each actual worker key and rejected a wrong key. Controlled PKIX465/993 and wrong-name/system-trust negatives passed. Client-side DNAT and private test trust are explicit; no public certificate issuance or mail delivery is claimed. |
| KSK receipt | Native receipt2.48 binds owner/full DNSKEY/DS; owner/RDATA/proof/ID tampering failed. Exact-ELF disk recovery separately preserved its own KSK and verified the recovered receipt. |
| Performance | Native admission samples, 1,200-second WAN load, independent latency sampling, signing durations, Azure container metrics and actual BIND process RSS were collected and are distinguished below. |

The fixed load sent 1,199,461 queries and completed 1,192,214 over 1,200.501 seconds:
993.38948 completed queries/second and 7,247 losses (0.604188%). The independent
sampler attempted all12,000 probes, with zero missed schedule slots, 11,985
successes and15 failures. Successful-probe p50/p99 were152.115665/220.194206ms.
This measures the observed WAN path under fixed offered load, not maximum capacity.

All84 stock DNSSEC checks and115 committed-status observations passed. Eight
status samples briefly reported `in_sync=false` after serial advances; each caught
up. The first-in-sync sample followed the first-new-serial sample by roughly11–33s,
which bounds observation intervals rather than exact transfer latency.
Four actual signing diagnostics measured209.325–216.897ms for260 source records.
Those pre-OpenTelemetry diagnostic lines have no event timestamps; the log
snapshot/serial correlation method is preserved.

The1,380.002-second BIND process collector retained139 samples, fully covering the
load. Named RSS ranged54,684–54,752KiB with the same PID/start identity throughout.
Separate Azure primary container memory samples ranged79,343,616–81,993,728bytes,
with CPU28–41millicores. Container usage is not process RSS, and this finite
measurement does not establish general leak freedom.

Evidence: [native API and terminal review](evidence/native-api-final-20260913/README.md),
[initial DNS/mail/ACME](evidence/native-external-preidle-20260913/README.md),
[idle/load raw samples](evidence/native-external-idle-20260913/README.md),
[withdrawal and expiry DNS](evidence/native-external-lifecycle-20260913/README.md),
[primary signing/platform metrics](evidence/native-primary-idle-20260913/README.md),
[actual BIND process samples](evidence/native-secondary-vm-final-20260913/README.md),
and [fresh restarted worker appraisal](evidence/native-worker-a-rotated-20260913/README.md).

B's requested total lease2425s produced the exact deadline1789290242. Final
absence was first probed at1789290354.490,112.490s later; this is an observation
bound, not a measured112-second removal delay. The fresh-key409 test preserves
its complete signed envelope and does not represent a new admitted registration.

Worker evidence is published in
[the native worker bundle](evidence/native-workers-final-20260913/README.md).
Rebuilt-primary hardware verification is preserved in
[the independent primary bundle](evidence/native-primary-ready-independent-20260913/README.md),
and exact-ELF quorum/recovery evidence is in
[the version 5 build bundle](evidence/ccf-native-v5-20260913/README.md).
Earlier exact-image local checks remain in
[the local acceptance report](acceptance-ccf-final-20260913.md).
Private execution material stays under
`.validation/azure/native-final-20260913/`; public artifacts require an explicit
allowlist, integrity verification and a scan against actual test credentials.
