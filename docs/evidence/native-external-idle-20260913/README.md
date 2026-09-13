# Actual native Azure idle and frontend load observation

This bundle records the public stock BIND VM at `20.166.33.141:53` serving the zone from the genuine confidential CCF primary at `4.208.82.123`. See [the independently verified primary quote](../native-primary-ready-independent-20260913/README.md) and [the receipt, native admission-derived DNS, and controlled mail proofs](../native-external-preidle-20260913/README.md).

The fixed observer ran at least 1,250 seconds across multiple real 600-second RRSIG lifetimes. Independent stock `delv` repeatedly validated positive and NSEC3-negative responses. A separate pinned-CA client observed committed CCF status and authenticated secondary progress. The workload offered 1,000 DO=1 queries/sec for 1,200 seconds alongside a target of ten bounded concurrent latency probes/sec. Actual counts, loss, dispatch misses, elapsed time, and successful-probe percentiles are in [summary.json](summary.json); this is a fixed offered load over the WAN, not maximum capacity.

The runner copied six explicitly selected source files and only the public service certificate and receipt-derived DNSSEC anchor before launch. It mounted them read-only, then checked the exact file inventories and hashes after execution. It declared success only after all child processes completed and cleanup/integrity guards passed. The copied sources, source hashes, raw public observations, and logs are included. No bearer token, TSIG secret, private key, deployment parameter file, or ledger is included.

Actual signing-duration diagnostics and memory measurements have separate provenance and timing boundaries; no RSS, cryptographic signing duration, or leak-freedom claim is inferred from frontend query timing.
