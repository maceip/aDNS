# aDNS startup failure: findings, repair, and test evidence

On September 19, 2026, aDNS repeatedly exited because a stale `node.pid` survived an earlier termination. Commit [`6b15e2e`](https://github.com/maceip/aDNS/commit/6b15e2e987ddbbce739868e17b81546595aea185), in [PR #2](https://github.com/maceip/aDNS/pull/2), fixes this restart blocker. A local regression reproduces the failure with the deployed CCF binary and verifies startup after cleanup. The repaired image also started a separate Azure confidential authority, reached `Open`, and served independently validated DNSSEC answers.

These are two complementary checks: the local test exercises stale-PID recovery; the isolated Azure deployment exercises native startup and DNS serving. No crash/restart was deliberately induced on Azure, and the original authority was not recovered or replaced.

## Confirmed failure and contributing configuration

The live `agentdns-ccf-joiner/primary` log captured at **11:52:07 UTC** reported:

```text
CCF/src/host/run.cpp:1069 | PID file node.pid already exists. Exiting.
```

CCF 7.0.15 rejects an existing PID file with exit **103**. The previous supervisor propagated the exit and never retired that file, so repeated container starts encountered the same failure. The [recorded diagnosis](../evidence/startup-repair-20260919/incident.json) preserves the diagnostic, configuration, and image/source identities. The relevant upstream check is in [CCF's pinned host implementation](https://github.com/microsoft/CCF/blob/ccf-7.0.15/src/host/run.cpp#L1066-L1075).

The old node had a second startup obstacle: its `Join` configuration targeted `agentdns.test:8000`, mapped by the supervisor to `128.251.125.64`. That peer had been retired and stopped on September 16. PID cleanup cannot make an unavailable peer accept a join. The test deployment therefore uses `Start` with fresh member and authority identities; this is a fresh bootstrap, not ledger or trust continuity.

The earlier exit **250** is consistent with a Python-propagated `SIGABRT`, but its original fatal log is unavailable. The original abort cause remains **undetermined**. Retained memory samples provide no evidence of memory exhaustion; they do not exclude an unobserved spike. An unavailable seed explains unsuccessful joining, but has not been established as the cause of the abort.

## Implemented repair

The [supervisor](../../ccf/run.py) now holds one exclusive lock per state directory until its children are reaped. It removes a PID file only when the file is regular, owned, appropriately protected, contains a valid PID, still matches the inspected inode, and that process no longer exists. Live, inaccessible, ambiguous, or replaced files are retained. Cleanup also runs after child shutdown. Ledger and snapshot paths are not removed.

The image changes only the supervisor; the CCF executable and governance constitution remain unchanged. The immutable image, configuration manifest, generated confidential policy, and their hashes are retained in the [deployment evidence](../evidence/startup-repair-20260919/deployment/).

## Proof in test and isolated Azure staging

| Check | Observed result | Evidence and boundary |
| --- | --- | --- |
| Supervisor regression suite | 21 tests pass, no skips | [Local test record](../evidence/startup-repair-20260919/local-test/). One regression runs the actual production CCF binary; the other tests cover supervisor contracts and adverse cases. |
| Before repair behavior | Actual CCF exits103 and reports the existing PID file | The real-binary test seeds a stale PID from a reaped process, then launches CCF without the guard. |
| After repair behavior | With `ccf_pid_guard`, the same CCF configuration creates `node.pem` and a live matching PID; cleanup removes the PID after killing and reaping the child | [Test implementation](../../ccf/tests/test_supervisor.py). This uses Virtual mode and an intentionally unreachable loopback join target. It proves node creation, not a completed join or the full supervisor loop. |
| Confidential startup | Repaired primary and secondary started at **12:17:20 UTC** | [Azure container snapshot](../evidence/startup-repair-20260919/initial-staging/container-state.json). Resource: `agentdns-ccf-startup-20260919`, public IP `20.166.175.47`. Both had zero restarts in the initial approximately three-minute observation window. |
| Native trust verification | SEV-SNP quote, reviewed CCE, and actual TLS peer matched independently prepared pins | [Audit](../evidence/startup-repair-20260919/attestation/node-audit.json), [public inputs and policy provenance](../evidence/startup-repair-20260919/attestation/). This establishes attested TLS bootstrap. |
| Service usable | Member acknowledgment committed at2.5; service opening at2.9; test-zone bootstrap at2.15 | [Authenticated Open response](../evidence/startup-repair-20260919/initial-staging/open-network.json) and retained governance responses. |
| Signed DNS serving | KSK receipt verified against the authenticated service certificate; BIND9.20 `delv` reported `fully validated` for SOA and A | [KSK receipt](../evidence/startup-repair-20260919/initial-staging/ksk-receipt.json), [SOA](../evidence/startup-repair-20260919/initial-staging/dnssec-soa.txt), [A](../evidence/startup-repair-20260919/initial-staging/dnssec-a.txt). Direct public UDP53 queries use the freshly verified `example.test.` trust anchor, not public DNS delegation. |
| Read-only follow-up | Both containers still running with zero restarts approximately40minutes after startup; service Open; serial advanced from7 to14; secondary `in_sync=true`; fresh DNSSEC validation passes | [Timestamped follow-up, 12:57–12:58 UTC](../evidence/startup-repair-20260919/staging-follow-up/README.md). Fresh signatures expire at13:03:54, beyond the initial12:28:53 expiration. No governance, cloud-resource, or DNS changes were made for this follow-up. |

The initial Azure attempt failed before the primary executed: the policy did not allow Azure's injected `APP_IDENTITY_ENDPOINT`, and an optional UVM environment variable had incorrectly been made required. The corrected policy permits only the bounded, optional endpoint variable and restores optional UVM handling. The supervisor excludes the endpoint variable from child environments. Exec, elevation, and signal permissions remain disabled. The [rejected attempt](../evidence/startup-repair-20260919/deployment/rejected-attempt.json), [review](../evidence/startup-repair-20260919/deployment/policy-review.json), and successful retry are retained so that a passing preflight is not confused with a passing deployment.

## Limits and reproduction

The original broken instance and existing DNS routing/client pins remain unchanged. Candidate state still uses ephemeral `emptyDir`. These results do not establish old-ledger recovery, production cutover, mail integration, or long-term uptime.

The initial zone status reported maintenance health `ok`, but `in_sync=false` with no recorded secondary observation, despite independently validated answers. By the read-only follow-up, observation had converged: notified, observed and served serials were14, and `in_sync=true`. Both snapshots are retained. Serial advancement and later valid signatures demonstrate continued maintenance between checks. The roughly40-minute uptime comes from Azure's start timestamps and restart counters; the follow-up itself lasted102seconds. This was not continuous observation, a long-duration soak, or a recovery test.

The native audit used the preexisting, explicitly selected `approved_release` UVM endorsement policy. The approved release's publisher certificate had expired on May15; the release endorsement is checked at issuance time. A strict `current_certificate` policy would reject it. The exact choice, hardware pins, CCE binding, and audit validity interval are recorded in [policy provenance](../evidence/startup-repair-20260919/attestation/policy-provenance.json).

The [evidence bundle](../evidence/startup-repair-20260919/README.md) contains replay instructions, checksums, the local test transcript, and separately timestamped read-only staging follow-up. Public certificates, quotes, policies, DNS records, and receipts are included. Private member keys, transfer secrets, deployment parameter values, and ledgers are excluded.
