# Finite native Linux leak check, 2026-09-13

Valgrind 3.22.0 observed **zero definitely lost, indirectly lost, or possibly lost
bytes and zero memory errors** after a finite Rust workload exited normally.
No suppression file was used. One 544-byte allocation remained reachable in the
Rust standard library's process-wide stack-overflow thread-info map; its full
allocation trace is preserved in `valgrind.log`.

The native ARM64 Linux run used Rust/Cargo 1.95.0 and Ubuntu glibc 2.39. It ran on
an ARM64 Docker host without CPU emulation. Its locked dependency versions match
the root workspace lockfile; the only extra package is the test executable.
`provenance.json` records compiler/tool details, executable SHA256, container image
ID and the exact source hashes. `SHA256SUMS` covers all evidence files.

The eight complete create/use/drop epochs exercised:

- 40 signed-zone constructions: separate P384 KSK/ZSK generation, initial NSEC3
  signing, contribution changes, autonomous refresh, removal signing and NSEC.
- 256 contributed records, MVCC commits, aborted transactions, conflicting
  writers, encrypted snapshot seal/restore and wrong-key rejection.
- 1,536 DNS query/answer/serialization round trips covering positive, NODATA,
  NXDOMAIN, wildcard, empty-nonterminal and ANY responses with DNSSEC requested.
- 128 authenticated AXFR packets with chained TSIG verification and exact
  transferred-record counts.

The workload allocated roughly 177.2 MB across 201,405 allocations. The native
baseline and final Valgrind run both exited normally. Random key/signature bytes
make serialized snapshot sizes vary slightly between runs.

This repeat includes the combined base/contribution RRset TTL normalization
fix. Source hashes before and after the run matched the recorded provenance.
The [earlier pre-fix run](../leakcheck-pre-ttl-20260913/README.md) is preserved
separately with its original executable and allocation counts.

This is an observed absence of leaks for the stated finite core workload. It
is not a universal proof and does not cover the CCF C++ host, network runtimes,
Python drivers, live attestation appraisal, or Azure SNP execution. Separate
long-running RSS, external DNS, consensus and genuine hardware evidence retain
their own boundaries. Signing diagnostics produced under Valgrind must not be
used as performance measurements.

Reproduce from the repository root on a native ARM64 Docker host:

```sh
python3 tests/leakcheck/run.py
```

The runner builds the isolated `tests/leakcheck/Dockerfile` runtime, uses its
committed `Cargo.lock`, checks a normal native baseline, then runs:

```sh
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
  --log-file=docs/evidence/leakcheck-20260913/valgrind.log \
  /build/release/agentdns-leakcheck
```
