# Independent external DNS and mail acceptance

This report records the isolated run on 2026-09-13 UTC using the Rust `adns-dev` development MemoryStorage backend, BIND 9.18.39, dnspython, ldns, delv and Postfix 3.8.6. The reserved zone is `example.test.`. The authoritative secondary listens on container port 1053, published only to localhost; the separate validating resolver uses container port 53. SMTP/TLS peers are confined to the container. This is external protocol interoperability evidence, not production CCF or public Internet deployment evidence.

The reproducible harness is [tests/rust-integration](../tests/rust-integration/README.md). Its individual steps were exercised in this original run. A later fresh execution of the complete convenience runner passed without recovery or sampling interruption; see [the complete assembled-runner report](acceptance-assembled-runner.md). The Ubuntu CI job is configured but its remote execution remains separate. Public results, original failure logs and hashes are retained under [the evidence directory](evidence/external-acceptance-20260913/sha256.json). Private keys, TSIG configuration and sealed state were excluded through an explicit allowlist.

## DNS and transfer results

The fixture has 257 base records and a signed transfer of 1,036 records across 10 messages, approximately 152 KB. dnspython independently verified every response's chained TSIG. Unsigned and wrong-key AXFR requests were rejected. Stock BIND received and served the authoritative zone. The corrected implementation also passed authenticated UDP SOA, an older-serial IXFR with full AXFR fallback, and equal-serial IXFR returning one authenticated SOA.

`ldns-verify-zone` verified the entire signed zone. `delv` validated positive data, NXDOMAIN, NODATA and wildcard answers against an isolated anchor derived from the transferred KSK. This proves correctness under the test anchor; it is not public parent DS publication or a CCF receipt proof.

## Failure discovered and repaired

The original runtime sent NOTIFY but rejected stock BIND's IXFR request, which includes an authority SOA. It also lacked authenticated UDP SOA refresh. At 00:34:33.599 UTC the transfer ended with EOF and the secondary remained on serial 1. The runtime was repaired and restarted at 00:38:32 with its sealed serial 2 state preserved. One explicit recovery NOTIFY at 00:39:03.040 produced serial 2 at 00:39:03.139; automatic serial 3 followed at 00:39:03.851.

The initial serial 1 signatures expired at 00:39:03. The 139 ms before serial 2 arrived means the original phase cannot be called uninterrupted. The original failure and recovery notification are retained in the BIND log. Successful acceptance starts after the automatic serial 3 transfer, and excludes this failed prefix.

## Successful idle window

After recovery, the independent frontend monitor ran from 00:39:12 to 01:00:06 UTC: **1,254 real seconds**, exceeding two 600-second signature lifetimes. It completed 86 positive/negative external DNSSEC validations, observing serials 3 through 7. The four subsequent automatic transfers each arrived at least 299.12 seconds before the preceding signatures expired. There were no registrations, mutations, manual NOTIFY messages or runtime restarts in this successful window. Host status observations extended to 01:00:46; all recorded signature expirations were future and all recorded secondary observations were in sync. Peak recorded Rust runtime RSS was 40,640 KiB.

At the final renewal boundary, the host monitor's original `health == ok` assertion stopped polling. The status implementation temporarily returns `refresh_due` while the one-second lifecycle timer starts renewal; source inspection and timing indicate that boundary caused the assertion, but the failed response body was not retained. The host sample gap was 114 seconds. The separate frontend monitor continued through that interval and independently validated serial 7. The runtime was not restarted. The corrected monitor records responses before assertions, tolerates `refresh_due` for at most 15 seconds, and still rejects expired signatures and other unhealthy states. This instrumentation interruption is retained in the evidence and is not described as uninterrupted host sampling.

The successful claim relies on periodic external validations together with the logged transfer times and signature expiration margins; it is not a claim that every possible query instant was probed. Detailed timestamps and assertions are in [recovery-window-results.json](evidence/external-acceptance-20260913/recovery-window-results.json).

## Mail interoperability

A real Postfix `posttls-finger -l dane-only` probe used a DNSSEC-validating resolver. Matching SMTP TLSA data produced a verified TLS connection; a deliberately wrong TLSA key produced an untrusted connection and a DANE mismatch. Postfix's diagnostic probe returns zero even for some untrusted connections, so assertions inspect its authenticated outcome rather than relying on process exit status. No message delivery is claimed.

TLS 1.3 on ports 465 and 993 passed controlled-CA PKIX and hostname checks; wrong hostnames were rejected. The actual peer certificates were read from those TLS sessions, their DER SPKIs extracted independently with OpenSSL, and their SHA256 digests matched to DNSSEC-authenticated `TLSA 3 1 1` records. This does not test a public ACME issuer.

## Measured frontend performance

| Workload | Completed / sent | Loss | p50 / p99 latency |
|---|---:|---:|---:|
| 30 seconds, 10,000 offered qps, DO=0 | 299,033 / 299,881 | 848 (0.28%) | Separately sampled below |
| 3,000 sequential mixed DO=1 requests after that load | 3,000 / 3,000 | 0 | 0.145 / 0.307 ms |
| 30 seconds, 1,000 offered DO=1 qps, plus 100 sampled qps | 30,000 / 30,000 load; 3,000 samples | 0 | 0.179 / 0.767 ms |
| Same concurrent workload, repeated to add memory sampling | 29,949 / 29,949 load; 3,000 samples | 0 | 0.338 / 1.592 ms |

The high-rate workload completed 9,967.76 qps and its losses are preserved. The second concurrent run completed 998.27 load qps plus the separate latency samples. During that run the actual BIND secondary's RSS ranged from 25,960 to 25,996 KiB across 30 samples. These local Docker measurements use a small zone and shared development host; they do not establish WAN latency, maximum capacity or absence of memory leaks. Registration transaction latency and signing duration require separate backend measurements.

