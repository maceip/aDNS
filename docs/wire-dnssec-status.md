# Wire and DNSSEC implementation evidence

WS1 and WS2 are implemented in `crates/adns-wire` and `crates/adns-dnssec`. The evidence below is native/local and independently validated; it does not establish enclave execution, public delegation, or production readiness.

## Implemented interfaces

- `WireName` is a canonical, stack-allocated `[u8;255]` name with inline offsets, lowercase ASCII folding, escaped binary-label presentation, right-to-left RFC4034 ordering, and allocation-free suffix/ancestor operations. Parsing bounds compression to 10 pointers, rejects cycles, reserved label tags, overlong labels/names, truncation and invalid offsets.
- `PacketReader`, `RecordView::typed()` and `RDataRef` expose borrowed typed record data, including TXT iterators, EDNS option iterators and NSEC type bitmaps. `RData`/`ResourceRecord` are owned storage forms. DNS messages and immutable zone snapshots intentionally own their storage; owned decoding and response serialization are not described as zero-allocation.
- The checked message codec supports A, AAAA, NS, CNAME, PTR, SOA, MX, TXT, OPT, TLSA, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, CAA and unknown records. It rejects trailing bytes, impossible section counts, misplaced/duplicate OPT, malformed bitmap windows and malformed EDNS. Compression indexes only fully uncompressed suffixes to prevent the writer producing overly deep chains. Numeric record-code equality, hashing and ordering agree even for `Unknown(known_code)`.
- Base32Hex and hex use fixed-table selection scans, without data-indexed alphabet lookup or early return for individual invalid digits. RFC4648 vectors and nonzero padding are tested. This is a source-level timing design, not a formal compiler/microarchitectural constant-time proof.
- `SigningKey` supports generation and PKCS8 persistence through an external private-store adapter. It emits native 96-byte P1363 signatures using `ring` P384/SHA384. Canonical RRset input, wildcard-label reconstruction, key tags, SHA256/SHA384 DS digests, and serial-arithmetic signature intervals are implemented. Inception is backdated 300 seconds; validity bounds exclude ambiguous serial half ranges.
- `SignedZone::sign_with_keys` uses distinct KSK/ZSK roles. `sign` supports a combined key. `from_signed_records` rehydrates committed snapshots without accessing a private key or changing any record. It checks zone shape, signatures' shape/coverage, denial-chain completeness and applicable NSEC3 parameters; provenance/authenticity of the stored snapshot remains the committed storage adapter's responsibility.
- NSEC and NSEC3 cover NXDOMAIN, exact NODATA, empty nonterminals, wildcard positive/NODATA, unsigned delegations and DS denial. NSEC3 includes closest-encloser, next-closer and wildcard proofs, with zero iterations/no salt by default. Iterations are capped at 250 and salt at 255 bytes; SHA1 hashing is limited to this standards-required denial construction. Opt-out is deliberately not enabled: every authoritative name and insecure delegation participates in the chain.
- Exact positive responses borrow precomputed RRsets. Minimal ANY responses return a real RRset per RFC8482. Non-DO responses remove all RRSIGs. Delegation referrals carry applicable DS/denial and in-bailiwick glue. Wildcard responses recreate owners while preserving signature label counts.
- `TlsaOverlap` indexes contributions by registration and owner. Two keys coexist independently at ports 25,465,993; removing one registration or selected owner preserves the others.

## Verification performed on 2026-09-13 UTC

`cargo test -p adns-wire -p adns-dnssec --offline`: 23 tests passed. These include the published RFC6605 P384 signature, key-tag and SHA384 DS vector, RFC5155 iterated salted hash vectors, malformed packet sweeps, every-byte truncation tests, wildcard signatures, full negative proof semantics, delegation handling and snapshot rehydration. `cargo clippy -p adns-wire -p adns-dnssec --all-targets --offline -- -D warnings` passed. Both crates forbid unsafe code and inherit Rust1.85 as their minimum.

Allocation-counter instrumentation measured **zero allocations and zero allocated bytes** for borrowed typed RDATA, 1,000 canonical name parses/suffix operations, and 1,000 exact positive DNSSEC resolutions. These measurements cover the specified operations, not whole HTTP/UDP transactions or zone-signing work.

`ldns-verify-zone` independently reported **Zone is verified and complete** for both exported NSEC and NSEC3 zones. The zone includes separate KSK/ZSK, MX, dual-stack address records, CAA, a wildcard, an empty nonterminal, a CNAME and delegation glue.

ISC `delv` independently validated **18 actual Rust-generated response packets** across both denial modes: NXDOMAIN, NODATA, empty nonterminal A/DS, wildcard A, wildcard NODATA, existing/wildcard ANY, and delegation DS denial. It rejected four deliberate corruptions (missing denial proof and altered answer signature in each mode). The fixture server only substitutes each query's transaction ID; the positive response records/signatures come directly from Rust. See `docs/evidence/dnssec/delv-validation.txt` and `crates/adns-dnssec/tests/validate_packets.py`.

The ASAN-instrumented `cargo-fuzz` harness completed **7,370,945 executions in 61 seconds**, with a 65,535-byte input bound and 1GiB RSS cap, without a crash. A final 11-second pass completed **1,452,712 executions**, with peak RSS429MiB and no crash; its statistics are saved in `docs/evidence/dnssec/fuzz-validation.txt`. This bounded run is evidence against exercised memory/bounds failures, not an exhaustive correctness proof or a measured zero-leak claim for a deployed server. The harness compares borrowed/owned parser acceptance and checks parse/serialize/parse equality, and seeds compression loops, max names, count overflow, malformed EDNS and real DNSSEC responses.

## Reproduction

```sh
cargo test -p adns-wire -p adns-dnssec --offline
cargo clippy -p adns-wire -p adns-dnssec --all-targets --offline -- -D warnings
cargo run -p adns-dnssec --example export -- --caa-issuer "$(python3 tools/domain_registry.py get caa_primary_domain)" docs/evidence/dnssec
docker run --rm -v "$PWD:/work" agentdns-validation:local ldns-verify-zone /work/docs/evidence/dnssec/nsec.zone
docker run --rm -v "$PWD:/work" agentdns-validation:local ldns-verify-zone /work/docs/evidence/dnssec/nsec3.zone
docker run --rm -v "$PWD:/work" agentdns-validation:local python3 /work/crates/adns-dnssec/tests/validate_packets.py /work/docs/evidence/dnssec
cargo +nightly fuzz run wire fuzz/corpus/wire fuzz/seeds/wire -- -max_total_time=60 -max_len=65535 -rss_limit_mb=1024
```

The host's Homebrew Cargo/Rust binaries shadow rustup proxies. On that host, prefix PATH with the actual nightly toolchain `bin` directory and `~/.cargo/bin` to run fuzzing. This was an environment issue resolved during verification. The standard command above works with normal rustup proxies. Fuzz target dependencies have their own lockfile and generated corpus/artifacts are ignored; committed seeds remain in `fuzz/seeds/wire`.

Regenerate the short-lived signatures before repeating external validation after expiry. Key files under the evidence directory contain **public DNSKEY anchors only**; generated private keys are never exported by the example.

Standards checked directly: [RFC4034](https://www.rfc-editor.org/rfc/rfc4034), [RFC5155](https://www.rfc-editor.org/rfc/rfc5155), [RFC6605](https://www.rfc-editor.org/rfc/rfc6605).

A separate [native Linux Valgrind workload](evidence/leakcheck-20260913/README.md) now exercises repeated signing, snapshot recovery, DNS queries and authenticated transfers through normal exit. It observed zero definite, indirect or possible leaks and zero memory errors; one 544-byte reachable Rust runtime allocation is disclosed. It does not replace the bounded fuzzing or establish deployed-server leak absence.
