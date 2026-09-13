# Transfer and host-driver review

2026-09-13, independent review of the Rust transfer library and untrusted CCF
transport driver. All limits below are explicit admission or construction bounds.

## Corrections

- TCP/UDP permits now precede thread creation (8 TCP / 32 UDP handlers).
  Saturated requests are closed/dropped before another thread starts.
- TCP clients have a 60-second absolute connection lifetime and at most 16
  requests; a slow trickle cannot keep resetting a socket timeout forever.
- CCF UDP responses are read with a 1232-byte limit, JSON with 4 MiB, and transfer
  streams with 64 MiB. Body reads have a total deadline. Every successful route
  requires the CCF global-commit header; JSON also requires its commit status.
- Secondary work is validated before dispatch and malformed rows remain
  recoverable errors. Eight workers, sixteen outstanding exchanges and at most
  256 buffered work items bound network work. Maintenance runs each cycle while
  exchanges are pending. Undispatched stale work is dropped before expiry.
- AXFR enforces 64 MiB framed bytes and 4096 messages while building output,
  replacing the previous post-allocation check. Conservative packet packing
  uses uncompressed record sizes and serializes each completed message once,
  avoiding quadratic repeated serialization and an extra full-zone clone.
- TSIG validates continuation prerequisites, question classes and query flags.
  Its algorithm spelling is case insensitive, while algorithm compression is
  rejected. IXFR implements wraparound and rejects the undefined RFC 1982
  exactly-half-range serial comparison.

## Verification

`cargo test -p adns-transfer`: eight tests passed. They cover multi-message
chaining/order, transfer construction bounds, request flags/classes, algorithm
encoding, time/MAC failures, IXFR fallback/equality/wraparound/undefined distance,
and observation freshness. `cargo clippy -p adns-transfer --all-targets -- -D
warnings` passed.

`python3 -m unittest discover -s ccf -p test_host_driver.py -v`: twelve tests
passed, including pre-thread admission under 100 saturated requests, semaphore
release on both thread-start and handler failure, absolute deadline enforcement,
route-specific read limits, frame-count bounds and maintenance progress while
secondary futures remain unfinished.

Independent round trip using stock Ubuntu dnspython in
`agentdns-validation:local`: dnspython generated an authenticated query; Rust
verified it and returned 112 real TSIG-chained packets for a 1001-record
snapshot; dnspython authenticated every packet and recovered every record. It
also rejected two continuation packets replayed as the first response. Reproduce:

```sh
docker run --rm -v "$PWD:/work" agentdns-validation:local python3 /work/tests/transfer/verify_vectors.py prepare /work/.validation/transfer-review
cargo run -p adns-transfer --example interop_vectors -- .validation/transfer-review
docker run --rm -v "$PWD:/work" agentdns-validation:local python3 /work/tests/transfer/verify_vectors.py verify /work/.validation/transfer-review
```

The fixture uses deliberately public test key material. This review proves
local protocol and resource behavior; genuine CCF execution, BIND secondary
operation, and hardware attestation have separate acceptance evidence.

## Cross-workstream findings

The CCF adapter owner accepted findings about all-or-nothing 256-work overflow,
stale governed transfer-key digests, and globally committed read delivery. The
adapter's tests and status document track those fixes. Bounded registration and
zone-maintenance admission is implemented and documented in
[lifecycle bounds](lifecycle-bounds.md).
