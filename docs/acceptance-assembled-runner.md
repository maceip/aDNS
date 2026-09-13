# Complete assembled acceptance runner, 2026-09-13

`python3 tests/rust-integration/run.py --seconds 1250` completed successfully from initialization through automatic cleanup. The fresh isolated run used the development MemoryStorage backend and a snapshotted debug binary with SHA256 `e90fe92882ad92c26c30a2d881714b0698bc9d99f3e1af114458b329eace2408`. The running binary was copied before launch, so later builds could not change this process's executable. The original earlier transfer failure, recovery and instrumentation interruption remain preserved separately in [the original report](acceptance-external.md).

The public [result bundle](evidence/assembled-runner-20260913/sha256.json) contains 32 explicitly allowlisted public artifacts. No private TLS key, transfer secret/configuration, sealing key, sealed state or compiled binary was copied. The full combined result is [acceptance-results.json](evidence/assembled-runner-20260913/acceptance-results.json).

## Real idle refresh and transfer

The external frontend was independently observed from **01:31:32 through 01:53:04 UTC**, a span of **1,292 real seconds**. The monitor's initial-runtime-relative elapsed value is 1,295 seconds; the difference is the three seconds before its first sample. Both values exceed two actual 600-second signature lifetimes. Eighty-eight positive/negative `delv` validations passed, observing serials 1–5. There were no registration mutations, runtime restarts or manual NOTIFY requests during the window.

Host status sampling covered 1,254 seconds across 125 samples, with a maximum sample gap of 11 seconds, one runtime PID, no unhealthy or expired-signature observation, and every recorded secondary observation in sync. Peak recorded runtime RSS was 39,776 KiB. Each automatic BIND transfer arrived at least **299.199 seconds before** its preceding signatures expired. The [complete window details](evidence/assembled-runner-20260913/complete-window-results.json) correlate sample timestamps and authenticated BIND transfer receipt times. This is periodic external validation plus transfer/expiry evidence, not a claim that every possible query instant was probed.

The independently verified AXFR had 1,036 records in 11 TSIG-authenticated messages. Unsigned and wrong-key transfers failed. Authenticated UDP SOA, older-serial IXFR with full AXFR fallback, and equal-serial IXFR with one SOA passed. The entire transferred zone passed `ldns-verify-zone`; positive, NXDOMAIN, NODATA and wildcard answers passed `delv`. Stock BIND's later refreshes used the standard NOTIFY/SOA/IXFR interaction automatically.

## Mail and measured performance

Stock Postfix 3.8.6 in DANE-only mode verified the matching SMTP key and rejected mismatching TLSA authorization. Implicit TLS 465/993 passed controlled-CA and hostname validation, matched actual peer DER SPKIs to DNSSEC-authenticated TLSA records, and rejected wrong hostnames. These are independent protocol checks under an isolated trust anchor; they are not public ACME issuance, mail delivery or native CCF registration.

| Workload | Completed / sent | Loss | Sampled p50 / p99 |
|---|---:|---:|---:|
| 30 seconds at 10,000 offered qps, DO=0 | 299,021 / 299,861 | 840 (0.28%) | Separate samples below |
| 3,000 sequential mixed DO=1 queries afterward | 3,000 / 3,000 | 0 | 0.144 / 0.322 ms |
| 30 seconds at 1,000 offered DO=1 qps plus 100 sampled qps | 30,000 /30,000 load; 3,000 samples | 0 | 0.181 / 0.925 ms |

The high-rate run completed 9,967.36 qps; all 840 losses remain recorded. The concurrent load completed 999.999 qps plus separate samples. BIND RSS during that concurrent run ranged 36,492–36,512 KiB across 30 samples. These are local Docker measurements of a small zone on a shared development host, not WAN measurements or capacity limits. The separate later controlled-routing mail test and capture image builds did not share this early 30-second sampling interval, but other system activity was not excluded. A sibling's finite ARM64 Valgrind workload/compile ran during the later idle window at Unix 1789263884.7–1789263898.8; its coexistence is disclosed in the window details.

Five actual development-runtime signing diagnostics measured `SignedZone::sign_with_keys`, including denial/signature generation and excluding surrounding storage and consensus: minimum 379.330 ms, median 437.921 ms, maximum 455.128 ms. The [raw diagnostics and summary](evidence/assembled-runner-20260913/signing-metrics.json) describe the measurement boundary. Five samples are not a stable tail-latency estimate, and these debug development-memory timings do not establish native CCF signing or transaction performance.

The complete convenience runner is now exercised locally. Its Ubuntu GitHub Actions job is configured but no remote CI execution is claimed by this run. Actual CCF consensus, native admission, remote frontend publication, public trust and cloud lifecycle acceptance retain their separate requirements.
