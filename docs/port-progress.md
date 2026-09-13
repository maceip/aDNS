# Rust port acceptance ledger

`port.md` is the contract. The preserved C++ baseline is
`0315259c5ce274eab36843967e9725ca8705f92d`. All implementation, validation images
and isolated resources belong to this repository; no `agent-hosting` checkout
or hosting deployment was modified. Public delegation, public certificate
issuance and mail handling remain outside this project.

The Rust implementation and local CCF integration are built and tested. Contract
review added committed pending/failed request reconciliation,
permanent governed TSIG identity revocation, and immutable appraisal-policy
identities. These mechanisms are implemented and have passed unit, real CCF
consensus/recovery and governance checks. The earlier assembled BIND/rotation
smoke and sustained local run passed on executable `7b41a3a9…`. The current
native image contains executable `6bcbf0a8…`, including reviewed SNP version 5
support; its exact ELF separately passed CCF quorum/rollback and disk recovery.

The original port is **accepted on the identified pre-OpenTelemetry image**.
Both genuine registrations, independent DNS/TSIG/DNSSEC and controlled mail,
ACME concurrency/expiry, the complete idle/load window, selective/full withdrawal,
natural lease expiry and the freshly appraised changed-key conflict all passed.
See the [native acceptance report](acceptance-native-final-20260913.md) for raw
proof, measured packet loss, transient synchronization states and test boundaries.

The subsequent OpenTelemetry and CI/CD requests are being completed separately.
CI corrections are pushed as `a40fae9` and `99c4bed`; the latter fixes Linux helper
ownership while preserving private file permissions. Its [four-job Rust workflow](https://github.com/maceip/agentdns/actions/runs/34750223266)
and [five-language CodeQL workflow](https://github.com/maceip/agentdns/actions/runs/34750223261)
passed. All 24 findings from the first analysis were reviewed, including
two demonstrated defects in retained legacy code, with focused fixes and tests.
The instrumented Rust workspace passed 116 tests, strict Clippy and Rust 1.85.1
compilation. Exact executable `6ba239f1…` passed real CCF quorum/rollback and disk
recovery with all 324 native spans reaching the SDK's OTLP output and collector.
The local Collector/Tempo/Loki/Grafana stack passed authenticated transport,
resource and privacy checks; [Tempo independently returned all 78 traces](evidence/otel-tempo-ccf-20260913/README.md).
The [isolated Azure backend](evidence/otel-backend-native-20260913/README.md) passed
TLS/authentication and synthetic ingest checks without restarting BIND.
Fresh native primary deployment and trace acceptance remain
in progress. Earlier image proofs are not relabeled for this candidate.
Deployment, runtime credentials, publication and acceptance are authorized;
there is no current approval hold.

## Implemented workstreams

| Contract items | Implementation and reviewed evidence |
| --- | --- |
| 1.1–1.6 wire | `adns-wire`: stack names, bounded compression, borrowed typed RDATA, message codecs and encoders; zero-allocation measurements for the named operations and 8,823,657 bounded ASAN fuzz executions. [Wire/DNSSEC report](wire-dnssec-status.md). |
| 2.1–2.6 DNSSEC | `adns-dnssec`: canonical ordering, SHA256/SHA384 DS, P384 fixed signatures, NSEC and complete NSEC3 denial, contributions retaining TLSA overlap. Independent full-zone and wire-response validation. [Wire/DNSSEC report](wire-dnssec-status.md). |
| 3.1–3.5 attestation | `adns-attest`: native COSE, AMD chain/report/TCB, complete 64-byte SPKI binding, UVM publisher/feed/SVN and CCE policy, fail-closed profile selection. [Genuine ACI evidence](evidence/native-aci-20260913/README.md) and [trust semantics](attestation-status.md). |
| 4.1–4.5 authorization | `adns-auth`: governed exact Owner Grants, strict schemas/JCS, fixed P256 signatures, random nonces and atomic historical result cache. [Authorization report](auth-status.md). |
| 5.1–5.5 storage | Consolidated collections, MVCC development driver, narrow live CCF transaction bridge, private encrypted key/TSIG maps. Real CCF quorum rollback and member-share disk recovery preserve keys, results and nonces. [CCF integration](ccf-integration.md). |
| 6.1–6.7 API and distribution | Registration/renewal/withdrawal, ACME/operator/status, real receipts, DoH, TSIG AXFR/IXFR fallback, committed NOTIFY and authenticated served-SOA observation. [Transfer review](transfer-review.md), [local CCF/BIND report](acceptance-ccf-local.md). |
| 7.1–7.4 lifecycle and acceptance | Independent timer driver, bounded active indexes, idle/expiry tests, stock BIND/validator/mail harnesses, fuzz/leak/load measurements, CI and operational runbook. Full native acceptance passed on the recorded image. [Capacity/state format](lifecycle-bounds.md), [runbook](operations.md). |

Owned messages/snapshots allocate their storage; the zero-allocation claim is
limited to the measured name/borrowed-RDATA/exact-query operations. TDX, Nitro
and vTPM remain explicitly unsupported as specified. Native CCF endpoints use
the framework's `/app` prefix with unversioned logical paths.

## Twelve mandatory acceptance checks

| # | Verified evidence | Original acceptance |
| --- | --- | --- |
| 1 hardware appraisal | Native primary, original A/B and fresh restarted A passed Rust and independent cryptographic/TLS verification. | Complete. |
| 2 owner scope | Six genuine signed scope/grant denials committed failure metadata, preserved nonce and zone, then allowed the authorized request. | Complete. |
| 3 signed requests | JCS/fixed64, negative variants, nonce safety, exact retries and fresh-key409 preserving original2.143 passed. | Complete. |
| 4 commitment | Exact-ELF Virtual quorum/rollback/recovery plus actual native commit confirmations and115 sustained observations passed. | Complete; Virtual/native boundaries remain explicit. |
| 5 DNSSEC | Independent full-zone validation and initial, sustained and terminal stock delv checks passed. | Complete. |
| 6 secondary transfer | Ten authenticated AXFR frames, missing/wrong TSIG denials and public dual-transport BIND serving passed. | Complete; eight sampled synchronization transitions are reported. |
| 7 idle maintenance | Complete1,250-second observation crossed four autonomous refreshes; ACME and registration natural expiry passed. | Complete. |
| 8 TLSA rotation | Both keys coexisted; A port25/full withdrawal preserved B; B expiry removed the final dynamic records; old-A cache grace was respected. | Complete. |
| 9 ACME concurrency | Create/create/delete and natural expiry passed through stock DNSSEC validators. | Complete. |
| 10 mail interoperability | Stock Postfix DANE-only and controlled PKIX465/993 passed for actual worker keys with negative cases. | Complete within controlled DNAT/private-trust tests. |
| 11 KSK receipt | Native receipt2.48 and independent tamper negatives passed; exact-ELF recovery separately retained its KSK/receipt. | Complete. |
| 12 performance | Native1,200-second load,12,000 latency probes, signing durations, Azure container metrics and139 BIND process samples retained. | Complete;993.38948 completedqps and0.604188%WAN loss, not a lossless/max-capacity claim. |

## Earlier local candidate and test boundaries

The pre-native local image is pinned in [the build record](evidence/ccf/build.json):
OCI index `f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7`,
AMD64 manifest `34bb5ecc0fad0d2a37552b4161d3b3fc366ec7992ce82de10b83c06f202b9e65`,
executable `7b41a3a9c147a923542bdda424d9c669f0d166d5c5c8601934b164928218e888`,
constitution `bc18a726e061fcb0b45c64fb4e67e774355c5c0abcfb772966bb9704ee129346`.
All 85 frozen production inputs matched their recorded source snapshot. The
current native build and later external bootstrap corrections have distinct
input manifests and recorded deltas. The exact ELF copied
from this image passed real CCF smoke, quorum loss/rollback and disk recovery;
it was not rebuilt for those tests. All three public receipts were independently
reverified after export, including unchanged KSK/DS under the recovered identity.

The Rust workspace passes **105 tests across 18 suites**, formatting and strict
Clippy. All targets pass locked offline Rust 1.85.1 compilation; tests used
Rust 1.95. [Exact commands, logs and source hashes](evidence/rust-contract-20260913/README.md)
are retained. The final frozen Linux suite passed **87 Python tests**: 55 tools,
12 host-driver, 9 supervisor and 11 runner/export guards. Six actual JavaScript
governance-action tests separately passed on Node 24.15.0.
[Runtime and frozen source evidence](evidence/python-contract-20260913/README.md)
records the distinction. New reconciliation frontend-verifier checks are included.

The [real governance run](evidence/governance-contract-20260913/README.md)
committed permanent old-key revocation, denied reprovisioning and reactivation,
provisioned a replacement, accepted exact policy repeats and rejected changed
trust under current or historical policy IDs. The [request reconciliation
contract](request-reconciliation.md) explains bounded pending/failure observations,
commit gating, retry semantics and expiration without claiming in-flight execution.

A native ARM64 Valgrind 3.22 workload completed with zero definite, indirect or
possible leaks and zero errors: 48 signed-zone constructions, 264 contributed
records,64 overlay drops / 64 flushes, 16 authenticated failures, 8 same-nonce
reauthorized successes, 8 expired-attempt cleanups,1,536 DNS round trips and 128
TSIG packets. Its 337,549 allocations total 252,370,395 bytes. The single 544-byte
reachable Rust runtime allocation is disclosed in [the finite leak check](evidence/leakcheck-20260913/README.md).
This finite core workload does not claim leak freedom for every CCF/C++/Python path.

The completed [pre-contract sustained baseline](acceptance-ccf-baseline-20260913.md)
preserves executable `eb62c060…`, before the final three mechanisms. It passed
1,262 seconds across original signature expiry, 86 external DNSSEC validations,
1.2 million frontend queries with zero loss, and the actual signed operator
phase including all five mail policies, DER rejection, exact retry and signed HTTP 409.
Its 126 committed/unexpired samples include 122 in sync and four transient
propagation observations. Full-zone exports each had 978 records in 10 TSIG frames.
The much smaller earlier `be6131ec…` measurements remain separately documented in
[the original local report](acceptance-ccf-local.md). Neither is substituted for
the final candidate's repeatable run or native registration timing.

The first final-image assembled smoke proved committed failed HTTP 403 reconciliation
and reauthorized same-nonce success, then encountered a harness that expected
five mail policies when given the single reconciliation TXT fixture. Its
[actual failure is preserved](evidence/ccf-runner-reconciliation-verifier-failure-20260913/last-helper-failure.json).
A dedicated exact-owner/TTL/bytes TXT verifier and three negative-fixture tests
now cover that path. A subsequent run passed reconciliation and its external
TXT/DNSSEC check, then confirmed that the TSIG work response was committed but
queried its status through the restricted internal interface. The [original
response and failure](evidence/ccf-runner-internal-confirmation-failure-20260913/last-helper-failure.json)
are preserved. The harness now confirms that exact transaction through the
CA-pinned public interface and saves the confirmation responses. The unchanged
final image's complete [assembled smoke passed](evidence/ccf-runner-final-smoke-20260913/runner-results.json):
committed reconciliation at 2.345, exact DNSSEC-valid TXT on BIND, old-key rejection,
and successful replacement-key AXFR/SOA before and after revocation. Each full
replacement transfer contained 1,001 records in ten authenticated messages.
Three post-revocation work batches were empty; no nonempty work-generation or
replacement-BIND propagation claim is made. All 107 public artifacts passed
hash/secret review, and the exported receipt was independently verified again.
The final [sustained run also passed](acceptance-ccf-final-20260913.md) on that
exact image and executed helper snapshot. Its 122 public artifacts retain the
complete window, final operator transaction 2.1799/serial 13, reconciliation
2.1830/serial 14, replacement transfer/revocation checks and successful cleanup.
All 1,200,000 offered frontend queries completed without loss; latency p50 was
0.498 ms and p99 was 1.362 ms across 12,001 successful samples. CCF RSS ranged
76,716–81,716 KiB; BIND ranged 38,812–40,868 KiB across 121 samples each. Eight
actual signing spans ranged 143.573–163.647 ms. This is a fixed offered load on
a shared development host with AMD64 emulation, not maximum capacity or native
registration latency. The report discloses the brief mount-probe overlap and
later Python tests outside the load/RSS window.

Independent review then tightened two acceptance-harness conditions: both request
observation transaction fields must be present and equal the externally confirmed
transaction; control helpers must not receive a writable alias to the copied
source tree. The executed smoke's actual pending/failed responses satisfy the
stronger ID checks, and all 19 copied helper files still match their initial hashes.
[Additional reviewer assertions](evidence/ccf-runner-review-20260913/short.json)
record these facts and the older mount limitation. The completed sustained run kept
its original frozen source. Its final 19-file inventory and every byte hash match
the initial provenance protected outside the helpers' writable directory. The
actual pending/failed body IDs equal their response headers and recorded committed
node-status confirmations; historical result 2.1830 remains unchanged. All 122
exported files match the original outputs byte-for-byte. These [independent
post-run checks](evidence/ccf-runner-review-20260913/README.md) establish actual
output/source facts without claiming filesystem-enforced immutability throughout
the older run. The newer harness passed 11 guards and an actual Docker read-only
mount probe; its final 87-test Python snapshot has a separate identity.

## Earlier Azure continuation and resolved approval history

The following dated preparation and failure history preserves earlier identities
and decisions. The current deployed state and remaining work are reported above
and in [the native acceptance report](acceptance-native-final-20260913.md).

Earlier primary, revised capture and secondary images were published in the
isolated registry `agentdnsport20260913.azurecr.io`, resource group
`agentdns-port-validation-20260913`, North Europe. The **final primary was
published** as `primary:20260913-contract`; remote index and AMD64 manifest bytes
were independently fetched and matched the reviewed build, with six ordinary
gzip layers and no eStargz conversion. Its deployment is now authorized and in
progress. Both revised mail/lifecycle workers are deployed and freshly
appraised. The primary reached native startup but requires the bootstrap
correction described below. The pull identity has only `AcrPull` on that registry.

[Originally prepared templates/policies](evidence/azure-prepared-contract-20260913/README.md)
pin the initial primary CCE
`844c94305e5e55edabc3d92894f177f4bf2c04deed48f2ccc6de5c9dabbbf4d3`
and workload CCEs
`68f46918d210a8eb57ccbdade383ba459cb5260273be3d5f778ca37eef6ab75a`
and `d8251696c7dcad3eaca72e3eb34b86dd28c936b056567e3a6ad5e6049024fd29`.
The bootstrap manifest is
`d80a23a9fbf2042f0a62ede46a64c4d22861ed1f3439648cd1affa3d1f89dcfb`.
Separate single-image archives, OCI config/layer hashes, exact launch commands,
bootstrap manifest, TLS names and secure parameter references passed preflight,
independently repeated by the primary reviewer against the actual local archives.
Pinned Linux confcom ran without networking, Azure credentials or Docker socket.
Preflight does not independently recompute confcom's dm-verity roots.
All containers forbid exec/elevation. The referenced primary image has now been
published and its registry bytes independently verified.

The [native continuation runbook](azure-native-continuation.md) carries the
concrete remaining procedure. Under the explicit approval, deploy the exact candidate,
appraise fresh node/workload TLS peers, govern both workload keys and one policy
approving both CCE hashes, then obtain fresh nonces and fixed-scope signatures.
Replacing a worker changes its key; prior evidence/key/nonce cannot prove its
replacement. No registration currently depends on the older worker key.

Private parameters, test TSIG/control tokens, member keys and ledgers remain in
ignored mode-restricted `.validation/`. Public evidence uses explicit allowlists
and actual-secret scans. Existing private material was cloned unchanged for the
replacement local preparation. Validation state uses ephemeral `emptyDir`;
production still requires durable storage and backup/restore verification.

Automatic approval review rejected three distinct operations:

1. Deployment of the public-facing isolated CCF/BIND group with new test-only
   TSIG/bootstrap material, because the broad porting request did not explicitly
   authorize that secret-bearing payload and destination.
2. Sending the validation control token and committed nonce to the existing ACI
   worker for a fixed native registration signature.
3. Publishing the replacement project image to the isolated Azure registry,
   because project-code export required explicit authorization.

The user has now explicitly approved image publication (completed), isolated
deployment/test-secret provisioning and the remaining attestation, registration,
DNS and lifecycle validation. The approved native run preserves the reviewed
images and records fresh evidence in `.validation/azure/native-final-20260913/`.
No rejected operation was retried while its authorization was absent.

The new worker A and B deployments have passed fresh native appraisal, actual
TLS/SPKI binding, independent cryptographic verification and sixteen rejected
evidence variants each. Their [public evidence](evidence/native-workers-final-20260913/README.md)
is separate from the still-pending signed registration proof.

Actual ARM deployment exposed a previously untested ACI networking limitation:
public port numbers must be unique across protocols. Three rejected template
variants are preserved in the private primary run directory; none created the
CCF group. The reviewed primary image remains unchanged. The primary
group is being deployed with public HTTPS8000, authenticated transfer TCP5353
and auxiliary BIND UDP53. A stock BIND secondary on a VM in the same isolated
resource group will provide the canonical public TCP53/UDP53 endpoint.
The secondary receives runtime configuration, a transfer credential and signed
public zone data; DNSSEC private signing keys remain in CCF. Its actual transfer,
served serial, DNSSEC results and
both transport paths must pass before this fallback counts as acceptance.

The BIND VM is running at `20.166.33.141`, using an available two-core
`Standard_EC2as_v5` after the ordinary small SKUs were subscription-restricted
and the attempted DC family had no core quota. This VM's hardware isolation is
not used as evidence for the CCF primary or test workers. Its runtime BIND
configuration and transfer are still being completed.

The primary's preserved first-start log reports genuine `AMD_SEV_SNP_v1` quote
generation followed by `One or more SNP endorsements servers must be specified
to fetch the collateral for the attestation`. The original public node config
omitted the native attestation section. The correction adds the CCF7.0.15
collateral and UVM-file configuration to the runtime bootstrap, regenerates its
manifest and primary CCE policy, and is reviewed before accepting a new quote.
The image and ELF remain unchanged; native registration has not yet started.

The corrected bootstrap reached running state at `4.207.179.55`. Its first
external audit then correctly rejected SNP report version 5, which the parser
had not implemented. [AMD ABI1.58 Table23](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf)
assigns two mitigation vectors at
offsets504 and512, previously reserved in versions2/3, while retaining the
1184-byte report and signed bytes0–671. The captured report has both vectors7
and a Genoa TCB above the already approved minimum. A reviewed parser correction,
regression checks, independent verification and a new frozen image build are
required before final native acceptance. No service CA has been trusted and no
governance or registration submitted to this node.

Historically, a read-only Azure recheck at 04:02 UTC on September 13 confirmed that the
isolated resource group still contains only the original capture group, and the
registry returns `manifest unknown` for final primary digest `34bb5ecc…f202b9e65`.
No final primary/secondary group exists there. The original capture group's
runtime state was not supplied by the listing, so this check does not claim
that worker is currently running. No rejected operation was retried.

The goal was recorded as **blocked**, after the same approval barrier remained
across three consecutive goal turns. A further read-only Azure inventory check
confirmed the same original capture group and no final deployment. All 85
production inputs still match the tested image. This status does not waive any
requirement. Image publication is now complete; native deployment, fresh
appraisal and signed registration/lifecycle acceptance are being executed under
the user's subsequent explicit approval.

## Obstacles and corrections retained for review

- The referenced hosting rollout/native fixture was absent in this checkout.
  No unrelated repository was read; fresh isolated ACI evidence was captured.
- CCF7 uses a standalone executable. The old CCF6 shared-library target was
  replaced. SDK/RPM/base image are pinned. Two Rust runtimes needed a narrowly
  checked, build-local namespacing of the SDK exception-personality symbols;
  both complete runtime implementations remain linked.
- CCF governance cannot read application maps. Governance validation mirrors
  and application values are written atomically by the constitution.
- Live tests found HTTP2 bypassing the required consensus response gate,
  empty-write reads bypassing it when writes were disabled, and a delayed
  callback deadlocking when reacquiring the Raft lock. HTTP1 is required;
  successful reads finalize their transaction; callbacks use captured lineage.
- The first BIND refresh used IXFR with an authority SOA, which was rejected.
  Authenticated AXFR fallback and equal-serial replies fixed this. The initial
  recovery reached the prior expiration boundary, so that phase is retained as
  a failure, not relabeled uninterrupted service.
- Initial SOA/NOTIFY work can precede a listening or fully loaded secondary.
  Failed work expires after 300 seconds; readiness waits for authenticated
  observed serving. The production driver keeps signature maintenance
  independent of bounded secondary I/O.
- Driver review fixed admission after thread creation, retained slow
  connections, unbounded reads and malformed work handling. Supervisor/tool
  HTTP operations use absolute deadlines and bounded response sizes.
- macOS confcom could not generate policies. A pinned Linux tool generates
  them locally without Azure credentials or a Docker socket. Review caught
  multi-image archives causing the first image's layers to be reused; separate
  single-image archives and rejecting preflight checks corrected this.
- Final review fixed parent-side DS routing with parent/child zones, missing
  lifecycle-format validation in DoH, DNS opcode/RD/CD response flags, immediate
  eligibility reporting before maintenance, and tightened ACME issuer scope.
  Registration GET separates effective status from still-committed rows;
  authoritative withdrawal cannot purge resolver caches.
- An assembled operator test exposed mixed TTLs between governed base records
  and dynamic records in the same RRset. The complete signed snapshot now uses
  the minimum TTL and deduplicates afterward, without rewriting ownership or
  stored source TTLs. New signed regressions cover both TTL orders, duplicate
  RDATA, withdrawal/restoration, signature verification and conflict rollback;
  the corrected image passed that exact operator case through real CCF and
  independent BIND/DNSSEC validation, including the completed pre-contract long run.
- Final contract review found that `/service/request` represented successful
  historical results but lacked committed pending/failed attempt states, and
  that deletion-only TSIG revocation allowed same-name reactivation and left
  pending work until expiry.
  These mechanisms and immutable appraisal-policy identities are implemented
  with bounded state and passing commit/rollback/recovery regressions. Earlier
  binary evidence is preserved as a baseline. Authenticated failed attempts
  commit diagnostic state and monotonic time only; application effects roll back.
- The actual ACI UVM endorsement uses an expired code-signing certificate.
  Default current-certificate policy rejects it. Explicit governed
  `approved_release` verifies the immutable approved release's signature/path
  at its valid interval while retaining current AMD validity and every
  identity/measurement/SVN check. No independent legacy timestamp or live
  revocation retrieval is claimed; see [attestation trust semantics](attestation-status.md).

The remaining native steps are required work. They are not waived by local
passing tests, prepared images or the recorded approval obstacle.
