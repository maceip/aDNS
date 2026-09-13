# Independent DNS and mail acceptance harness

This suite drives the real Rust `adns-dev` runtime, BIND 9 secondary, `dnspython`, `ldns-verify-zone`, `delv`, and Postfix `posttls-finger`. It creates an isolated `example.test.` zone and local SMTP/TLS peers. It never deploys production CCF, contacts a real mail recipient, changes system DNS, or touches `agent-hosting`.

On a Docker-enabled macOS or Linux development host, run:

```sh
python3 tests/rust-integration/run.py
```

The runner builds the local validation images and debug runtime, creates a fresh private directory under `.validation/integration/`, and starts a disposable container. Fixed localhost ports 18080 (HTTP) and 1053 (secondary DNS) must be free. The Rust transfer listener uses 18535 so the Docker container can reach it through `host.docker.internal` (the runner adds Docker’s host-gateway alias on Linux); all transfers require a randomly generated HMAC-SHA256 TSIG key. The container's SMTP25 and TLS465/993 peers have no published host ports. Its `/etc/resolv.conf` change is confined to that disposable container.

The runner stops its runtime and removes its own container on completion or failure. The output directory is retained for diagnosis and contains private test keys. Do not publish it wholesale.

## What the suite verifies

- A 250+ base-record zone produces multiple AXFR messages. `dnspython` independently validates the request/response TSIG chain for every message, and unauthenticated/wrong-key requests must fail.
- A stock BIND 9 secondary obtains the signed zone, reports AA, and serves its observed serial. Its subsequent IXFR requests receive the RFC 1995 full-AXFR fallback; an equal-serial IXFR receives a single authenticated SOA. Authenticated UDP SOA refresh queries also work.
- `ldns-verify-zone` verifies the full transferred zone against the exact transferred KSK. `delv` verifies positive, NXDOMAIN, NODATA and wildcard responses using an isolated test trust anchor.
- A separate local validating resolver establishes DNSSEC trust for MX/address/TLSA lookups. Postfix's `dane-only` TLS probe must log verified authentication for a matching `3 1 1` record and a DANE mismatch for the wrong key. `posttls-finger` can return zero for diagnostic sessions with untrusted TLS, so the assertion checks authenticated outcome in its log, not exit status alone. No delivery claim is made.
- Standard PKIX CA and hostname validation succeeds on 465/993 and rejects a wrong hostname. Their actual peer SPKI digests also match the DNSSEC-authenticated TLSA records. The CA is controlled and isolated; this does not test public ACME issuance.
- Autonomous signatures use the runtime's genuine 600-second expiration and 300-second refresh margin. The suite performs no mutating requests while watching at least 1200 real seconds, repeated commits, secondary observations, and repeated external DNSSEC validation across the first signatures' expiration. Status samples are retained before assertions; a `refresh_due` transition has a bounded 15-second grace while signatures must remain unexpired.
- A 30-second fixed 10,000-qps offered workload measures actual completed queries, loss and throughput. A separate 3000-query DO=1 sample measures frontend p50/p99 latency. An additional 3000-query paced sample measures latency during a simultaneous 1000-qps DO=1 workload. BIND RSS is sampled each second during the concurrent workload. These are local BIND/debug-runtime measurements, not cloud registration latency or a peak-capacity claim.

The prototype runtime's memory persistence and lifecycle are labeled `development-memory`. Passing these tests cannot establish production CCF global-commit, enclave attestation, current native service-key binding, public delegation, or genuine CCF receipt acceptance.

## Outputs safe to publish

Only publish these explicit result files and logs after inspection:

- `initial-results.json`, `ixfr-results.json`, `mail-results.json`, `performance-results.json`, `performance-under-load.json`, `idle-results.json`, `frontend-idle-results.json`, and `acceptance-results.json`.
- `idle-samples.json`, `frontend-idle-samples.json`, `fixture-summary.json`.
- `ldns-verify-zone.log`, `delv-*.log`, `postfix-dane-*.log`, `dnsperf*.log`, and the BIND logs.
- `transferred.zone` and `trusted.key` contain DNS public material; their signatures naturally expire and are retained only as evidence of the recorded run.

Do not publish `*.key` (except the public `trusted.key`), `bind-key.conf`, `config.json`, `state.sealed`, certificate-signing artifacts, or directories through a wildcard copy.
