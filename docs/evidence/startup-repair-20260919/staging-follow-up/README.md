# Staging follow-up: 2026-09-19

The isolated Azure candidate **passed this read-only follow-up**, observed from **12:57:02.578 to 12:58:44.370 UTC on 2026-09-19** (101.791 seconds). This is a short observation of `agentdns-ccf-startup-20260919` at `20.166.175.47`, serving `example.test.`.

| Check | Result | Evidence |
| --- | --- | --- |
| Azure lifecycle | Primary and secondary both `Running`, restart counts **0**; both started at 12:17:20 UTC | [Azure snapshot](azure-state.json) |
| Attested TLS identity | Native SNP verification passed against the independently supplied policy; actual peer bound to the verified node key | [Audit](native-audit/node-audit.json), [policy](candidate-node-policy.json), [run](native-audit-run.json) |
| Authenticated network | HTTP 200, service `Open`, recovery count 0 | [Network response](network-response.json) |
| Authenticated zone | HTTP 200, globally committed transaction `2.2710`, serial 14, maintenance `ok` | [Zone response](zone-status.json) |
| Secondary propagation | **`in_sync: true`**; observed and notified serial 14 | [Zone response](zone-status.json) |
| KSK trust anchor | Existing committed receipt `2.39` freshly verified against the service CA authenticated by this live audit; exact DNSKEY match to anchor | [Verification](ksk-receipt-verification.json), [public receipt](ksk-receipt.json), [anchor](trust-anchor.conf) |
| DNSSEC SOA | `example.test. SOA` fully validated; serial 14 | [SOA output](dnssec-soa.txt) |
| DNSSEC A | `ns.example.test. A` fully validated; `192.0.2.1` | [A output](dnssec-a.txt) |

The exact primary image is `agentdnsport20260913.azurecr.io/primary@sha256:9bd3f7246333ecb6098dace3e6e1abf6da3cad3f02247a66c897944e457f1401`; the secondary is `agentdnsport20260913.azurecr.io/secondary@sha256:dfd9158f60a9a0cd67b445b001ee636a0389c66ce926af3c386588d886976861`. The native policy binds reviewed CCE SHA256 `0b9f3597e1bcf9b2299daac52915e67301cf0116712f90e8d9e70355f926353c`, preserves preapproved hardware/UVM pins and the explicit `approved_release` endorsement-time policy, and expires at 14:11:22 UTC. The current audit expires at 13:27:03 UTC.

BIND `delv 9.20.27` ran in the recorded immutable Docker image; both corrected queries exited 0 and reported `fully validated`. [The run record](dnssec-validation-run.json) records image identity, exact commands and timestamps. The first invocations used unsupported `+time`/`+tries` options and failed locally before DNS queries; those rejected invocations remain in `initial-cli-rejection-*` files. The existing anchor's `trusted-keys` syntax produced a deprecation warning without preventing validation.

Azure reported approximately 39 minutes 43 seconds since container start when sampled. **This was not continuous monitoring of that interval or a long-duration soak.** The earlier startup capture reported secondary `in_sync: false`; this later authenticated observation reports `true`. No production cutover, previous authority recovery, multi-cloud failover or crash-restart exercise is claimed. This follow-up sent only public bootstrap and authenticated read requests plus DNS queries; it made no Azure, governance, DNS-record or delegation changes. The bundle contains public evidence only, with no deployment parameters or private keys.

[Machine-readable summary](summary.json) and [artifact hashes](sha256-manifest.json) make the observation and its limits explicit.
