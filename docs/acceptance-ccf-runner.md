# Reproducible local CCF and BIND acceptance

`tests/rust-integration/run_ccf.py` builds a fresh, real CCF network from the immutable runtime image and exercises a stock BIND secondary. The runtime uses the explicit `Virtual` platform override only for this isolated local protocol test. No virtual quote is admitted as hardware evidence, and the runner does not create an attested service registration.

The runner snapshots an explicit helper-source allowlist before starting containers and hashes exactly those copied bytes. It records the requested image reference, resolved immutable image IDs, actual packaged CCF binary SHA256, constitution SHA256, and all frozen helper hashes. Later host edits or mutable tag changes cannot alter the running code or helper files.

## Commands and isolation

Build the CCF toolchain/runtime, validation image and stock secondary using their existing Dockerfiles, then resolve the actual CCF image's immutable ID. The replacement candidate with durable request reconciliation and governed TSIG revocation now under acceptance is:

- OCI index: `sha256:f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7`
- amd64 manifest: `sha256:34bb5ecc0fad0d2a37552b4161d3b3fc366ec7992ce82de10b83c06f202b9e65`
- Executable SHA256: `7b41a3a9c147a923542bdda424d9c669f0d166d5c5c8601934b164928218e888`

```sh
python3 tests/rust-integration/run_ccf.py \
  --ccf-image sha256:f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7 \
  --seconds 30

python3 tests/rust-integration/run_ccf.py \
  --ccf-image sha256:f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7 \
  --seconds 1250
```

A mutable CCF tag is rejected before Docker access. Other helper-image references are resolved to immutable IDs before startup. The short mode proves a bounded smoke only. Long mode requires at least 1,200 seconds and keeps the real 600-second DNSSEC validity/300-second refresh policy.

Each run gets a unique `.validation/ccf-runs/run-*` directory, container names and private CCF state volume. No host ports are published. The CCF node receives only public member/configuration inputs; its private ledger and DNSSEC keys stay in its state volume. The separate driver container receives only the public service CA. BIND receives only its TSIG secret. Provisioning receives the TSIG JSON and public CA, and the independent transfer validator receives only its TSIG file and public results. The member private keys are accessible only to the local governance-control helper. Source mounts contain the explicit frozen files, not the repository's private validation directory.

The node and BIND share a private network namespace, matching the proposed same-ACI-group loopback connection arrangement. A separate stock-client container reaches their bridge IP for DNSSEC and transfer verification. This establishes independent process/client protocol validation, not independent hardware isolation or public Internet deployment. CCF runs directly because the production supervisor deliberately strips the testing platform override; the supervisor's production protections are tested separately.

## Actual acceptance sequence

The tested member-control tool creates fresh keys, activates the member, opens the service, and governs the audience, zone and transfer key digest. The supervisor's actual provisioning function installs that exact TSIG secret only after governance and confirms an identical retry without replacing it.

BIND starts and opens its DNS listener before the immutable packaged driver starts. A listener can still be awaiting its first AXFR when the driver's first SOA challenge arrives. Readiness therefore waits for a globally committed signed zone **and a genuinely authenticated observed secondary serial**, including the normal bounded retry. It does not fabricate observations, manually notify, reset the driver or truncate real signature lifetimes. The readiness phase allows 420 seconds, with a 480-second outer process deadline, to cover initial outstanding-work expiry and retry.

The runner then independently verifies the genuine CCF KSK receipt using the public service identity from this controlled local node. It derives the DNSSEC trust anchor only after receipt verification. The stock validator authenticates every message of a large AXFR, compares the transferred KSK with the verified receipt, rejects unsigned/wrong-key transfers, verifies the entire signed zone through `ldns-verify-zone`, and validates positive/negative answers through `delv`.

During the requested observation window, a CA-pinned status observer requires globally committed, unexpired state. Long mode also runs external positive/negative DNSSEC checks across automatic signature refresh, a fixed 1,000-qps DO=1 load plus 10 sampled qps for 1,200 seconds, and 121 RSS observations for the actual CCF and BIND PID 1 processes. The observers read only `/proc/<pid>/status` in explicitly shared container PID namespaces. All observers finish before any operator mutation. Lost requests and failed latency samples are retained; offered load is not a maximum-capacity measurement.

After the window, the real signed operator fixture governs a fresh temporary operator key and commits SPF, DKIM, DMARC, TLSRPT and CAA records. It rejects DER-encoded request signatures, preserves the original committed result on exact retry, and rejects a changed action under an existing request ID. A separate stock verifier checks exact DNS bytes, multi-string DKIM encoding and external DNSSEC validation after genuine secondary synchronization. The operator key remains in its process memory. These are operator policy records, not attested registration, public ACME issuance or mail delivery.

The runner also exercises durable reconciliation after the operator checks. A fresh in-memory operator key obtains a real nonce; the committed observation reports pending execution. The governor revokes its grant, and the exact signed request receives a commit-gated failure. The helper independently verifies the failure transaction through `/node/tx`, checks persisted nonce/intent/signed-message bindings, and confirms the failed action left the zone serial unchanged. Restoring the grant permits the identical envelope and nonce to commit once; reconciliation and exact retry must return the original historical result. Stock BIND then independently serves the resulting TXT bytes with valid DNSSEC.

Finally, a new random TSIG secret and canonical replacement identity are governed and provisioned. An independent client validates a complete replacement AXFR and authenticated UDP SOA before and after the original identity is revoked. The old signed AXFR and UDP SOA must fail while the new identity continues to work; repeated revocation must succeed. Three committed work responses are inspected, and every returned packet must authenticate under the replacement identity. The packet count is reported even when the driver has already consumed the available work and the inspected batches are empty. This proves direct transfer identity continuity; the reserved replacement endpoint on loopback port 1053 has no replacement BIND deployment, and no frontend key rotation is claimed. Existing stock BIND validation finishes before these final revocation tests. These phases passed both the complete replacement-image short run and the final long run described below. They are absent from the earlier baseline snapshots.

Every synchronous Docker command has a deadline; monitor lifetime is capped at requested duration plus 180 seconds. The host wait loop sleeps and checks process health at most every 10 seconds. Cleanup attempts every owned resource, records exact failures, and claims removal only if those operations succeed. A failed observation preserves its files and cannot become a passing summary.

## Evidence handling

Use the explicit exporter rather than copying a run directory:

```sh
python3 .validation/ccf-runs/run-IDENTIFIER/source/tests/rust-integration/export_ccf_results.py \
  .validation/ccf-runs/run-IDENTIFIER/results \
  docs/evidence/ccf-runner-IDENTIFIER
```

It copies only named public artifacts and hashes them, refuses an existing destination and symlink escapes, and rejects private-key markers. Member/transfer secrets, live node state, environment/deployment files and unlisted helper outputs are excluded. Preserve failed attempts separately from passing runs.

The first superseded-image attempt (`run-s61mkexz`) demonstrated an actual 10-message signed transfer but its 90-second readiness budget ended before the initial authenticated observation retry. Its `readiness-failure.json` retained committed, unexpired serial 7 with `in_sync:false`; it is a failed prefix, not an idle success. The revised smoke and long run have their own directories and evidence, and must be reported with their actual completion state.

The next complete short-window attempt (`run-gniw5f4x`) reached authenticated secondary synchronization at serial 8, independently verified the KSK receipt and multi-message transfer, and passed its 30-second committed-state observation. It then failed the operator fixture, so it is not marked as passing acceptance. Its public artifacts remain in [ccf-runner-operator-failure-20260913](evidence/ccf-runner-operator-failure-20260913/sha256.json).

A separate labeled diagnostic kept the same immutable runtime and the same base TXT TTL 60/operator TXT TTL 300 inputs, while skipping only secondary readiness waiting to isolate the error quickly. The actual API returned HTTP 503 with a DNSSEC error requiring consistent RRset TTLs. That exact response, changed diagnostic-helper hash, and explicit exclusion from acceptance are preserved in [ccf-runner-ttl-failure-20260913](evidence/ccf-runner-ttl-failure-20260913/diagnostic-scope.json). An independent signed server transaction regression reproduced the complete-RRset composition defect. The fixture is retained for validation of the repaired image; changing its TTL or deleting the base record would hide the defect.

## Corrected candidate smoke

The unmodified complete runner passed against executable `eb62c06083bdb7fe446f4d8cacd9629545e14ea049f1ebeaaf1c20ac59ef6d8e` in `run-a1142n4z`. Its [59 public artifacts](evidence/ccf-runner-corrected-smoke-20260913/sha256.json) preserve the frozen sources, actual image identities, signed requests, responses, independent verification and successful cleanup.

The initial authenticated transfer contained ten TSIG-verified messages and 978 records. Four committed-state samples passed over 30.04 seconds. With the original base TXT TTL 60 and operator TXT TTL 300 retained, the signed operator mutation committed transaction `2.317`, serial 9. Stock BIND then served exact SPF, DKIM, DMARC, TLSRPT and CAA data with independently validated DNSSEC; DKIM retained its two TXT strings. DER signatures failed without consuming the nonce, exact retry preserved the original result, and a changed signed action returned a conflict. The run lasted 362.71 seconds including the normal initial observation retry and cleanup. This is a passed short smoke; the full observation window is recorded separately when completed. Later review identified durable pending/failed request reconciliation and governed TSIG identity revocation work. This executable predates those changes, so its results remain an explicit pre-reconciliation/revocation baseline; a replacement executable requires its own acceptance evidence.

The complete mixed-TTL-corrected pre-reconciliation/revocation baseline subsequently passed a real 1,262-second external window, sustained load, final operator checks and cleanup. Its [separate baseline report](acceptance-ccf-baseline-20260913.md) records exact identities, metrics and limits. It does not claim coverage for later request-observation or TSIG-revocation changes.


The first replacement-image short run (`run-bbp5b9sy`, executable `7b41a3a9…18e888`) passed actual pending/failed reconciliation and restored-grant exact-envelope retry, then exposed a harness mismatch: the five-policy mail verifier rejected a one-record reconciliation input before issuing a DNS query. Its [79 public artifacts](evidence/ccf-runner-reconciliation-verifier-failure-20260913/sha256.json) preserve the failure and successful cleanup. A dedicated fixed single-TXT verifier was added, with adversarial owner/TTL/data/extra-record tests. This test-tool failure does not imply a production mutation failure, and the attempt is not marked as complete acceptance.


The next attempt (`run-tlv9fbfk`) passed the dedicated external TXT check, replacement-key transfer and authenticated SOA, and both revocation proposals. A final harness confirmation used `/node/tx` through the restricted internal interface, which permits only `/app/internal/.*`. The saved work response itself was HTTP 200 with `status:committed` and matching transaction `2.376`; the later node-status response was not retained by that helper revision, so no exact status/body for that rejected confirmation is claimed. The [100 public artifacts](evidence/ccf-runner-internal-confirmation-failure-20260913/sha256.json) preserve the actual work response, trace, identity and successful cleanup. Confirmation now uses the public CA-pinned client for the exact work transaction and preserves all node-status responses. This second harness failure is also excluded from passing acceptance.


## Final replacement-image short run

The complete short run `run-l344jkdb` passed against immutable image `sha256:f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7`, executable `7b41a3a9c147a923542bdda424d9c669f0d166d5c5c8601934b164928218e888`, and constitution `bc18a726e061fcb0b45c64fb4e67e774355c5c0abcfb772966bb9704ee129346`. Its [107 public artifacts](evidence/ccf-runner-final-smoke-20260913/sha256.json) preserve the exact frozen sources, complete result, public requests and responses, independent verification and successful cleanup. Every artifact hash was rechecked; neither TSIG secret appeared in raw, base64, base64url or hexadecimal form.

The 30.10-second committed-state observation and all operator policy checks passed. Actual request reconciliation reported a committed pending observation, persisted an authenticated HTTP 403 failure with independently confirmed CCF commitment, and accepted the original signed envelope and nonce after its grant was restored. The resulting transaction `2.345` advanced the zone exactly once to serial 10. Reconciliation and identical retry returned the original historical result. Stock BIND served the exact single TXT value at the governed owner with TTL 60 and valid DNSSEC.

The replacement identity authenticated 1,001 records across ten AXFR messages before and after the original identity was revoked. Complete-zone DNSSEC, KSK receipt comparison and authenticated UDP SOA passed both times. The old AXFR was rejected with EOF and the old UDP SOA timed out; the subsequent successful replacement transfer/SOA establishes that the transfer service remained available. Three post-revocation work queries were confirmed through the public CCF transaction API and returned zero packets. This does not claim observation of nonempty post-revocation work or replacement BIND propagation. Repeated revocation succeeded.

The run took 392.17 seconds including its normal initial retry, all post-window phases and cleanup. The final long run subsequently passed with identical frozen helper hashes and the same immutable image; its separate evidence follows.


## Final replacement-image long run

The complete `run-px_xd2d2` passed all observers, operator changes, durable reconciliation and TSIG replacement/revocation, reporting 1,625.87 seconds before successful cleanup. Its [final report](acceptance-ccf-final-20260913.md) and [122 public artifacts](evidence/ccf-runner-final-20260913/sha256.json) record the exact `7b41a3a9…18e888` executable and executed helper identities. External validation spanned 03:31:02–03:52:04 UTC on 2026-09-13: 86 positive/negative DNSSEC validations passed across four automatic refreshes and the initial signature expiration. All 126 committed-state samples were unexpired; secondary synchronization was true in 123 samples and briefly false in three. All 1,200,000 load queries completed with zero loss at the fixed 1,000-qps offer. These are local Virtual CCF measurements on a shared development host.

The executed runner predates two later harness-only hardening changes: explicit presence checks for observation transaction IDs and masking the writable source alias. The [independent post-run audit](evidence/ccf-runner-review-20260913/README.md) verifies the actual transaction fields and all 19 ending source files against protected initial provenance. Later [guard tests and Docker mount checks](evidence/runner-hardening-20260913/README.md) apply to the future runner, and are not claimed as assertions executed during this measured window. Earlier failures and superseded-image evidence above remain preserved.
