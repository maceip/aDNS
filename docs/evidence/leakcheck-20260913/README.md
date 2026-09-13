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
ID and the exact source hashes. Compilation and execution use a copied source
allowlist mounted read-only; no live source mount is used. No source changes
occurred during this run. `SHA256SUMS` covers all evidence files.

The eight complete create/use/drop epochs exercised:

- 48 signed-zone constructions: separate P384 KSK/ZSK generation, initial NSEC3
  signing, contribution/operator changes, autonomous refresh, removal signing and NSEC.
- 264 committed contributed records, MVCC commits, aborted transactions, conflicting
  writers, encrypted snapshot seal/restore and wrong-key rejection.
- 64 explicit overlay drops and 64 explicit overlay flushes, including staged
  put/delete/point-read/prefix-scan paths and checks of the resulting backend rows.
- 16 authenticated failed attempts: eight grant revocations followed by
  reauthorization and successful execution of the exact same signed nonce,
  and eight malformed second mutations after a staged TXT write. The latter
  discard partial writes, retain the nonce and failure observation until expiry,
  then remove both through maintenance. Successful execution removes its failed
  observation and nonce atomically and preserves historical reconciliation.
- 1,536 DNS query/answer/serialization round trips covering positive, NODATA,
  NXDOMAIN, wildcard, empty-nonterminal and ANY responses with DNSSEC requested.
- 128 authenticated AXFR packets with chained TSIG verification and exact
  transferred-record counts.

The workload allocated 252,370,395 bytes across 337,549 allocations. The native
baseline and final Valgrind run both exited normally. Random key/signature bytes
make serialized snapshot sizes vary slightly between runs.

This repeat includes the final request-reconciliation and write-overlay source,
as well as the combined base/contribution RRset TTL normalization fix. The
native executable SHA256 is
`419cc10c8292b5d82cc7f2df1d6e7125effccb43ece4d4ad67e8a9e99d7970bf`.
Compilation, baseline and Valgrind ran from 03:04:42.677 through 03:05:02.110 UTC
on September 13. Those times describe a shared development host, not production
performance. The [preceding post-TTL workload](../leakcheck-pre-contract-20260913/README.md)
and [earlier pre-TTL run](../leakcheck-pre-ttl-20260913/README.md) are preserved
separately with their original binaries and allocation counts.

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
committed `Cargo.lock`, checks a normal native baseline, then runs the command
below with a 900-second process deadline. Preserve the existing evidence directory
under a different name before reproducing: the runner refuses to overwrite an
existing provenance record.

```sh
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
  --log-file=/out/valgrind.log \
  /build/release/agentdns-leakcheck
```
