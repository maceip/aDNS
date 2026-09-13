# Final contract Python and governance checks

The final copied snapshot passed **87 Python tests** on native ARM64 Linux:
55 tools, 12 host-driver, 9 supervisor and 11 runner/export guards. Six actual
governance JavaScript action tests separately passed on Node.js v24.15.0 on the
macOS host. Commands, return codes, runtime versions and 67 explicit public
source hashes are preserved. Frozen and live source hashes matched after execution.

This final repeat covers required observation transaction fields, read-only
source aliases, bounded post-run source inventory/hash checks, rejection of
unexpected files and symlinks, and publishing a passing result only after cleanup
and integrity verification. The [actual Docker mount probe](../runner-hardening-20260913/README.md)
and [review of recorded final CCF responses](../ccf-runner-review-20260913/README.md)
provide separate direct evidence. The final CCF sustained run deliberately retained
its earlier frozen helper snapshot; this suite does not relabel those executed
helpers as the newer version.

The immutable Linux base image was
`sha256:448109ffddaab856945aed9d1d121e6f302db57e7f50dba917c5ba20bcc65615`.
`python3-cbor2` was installed in the disposable container; the dependency log and
runtime record describe the resulting environment. Sources and the runner were
mounted read-only, with a separate writable results mount. No cloud or
credential-bearing request was involved. This repeat began after the final DNS
load and RSS measurement ended; it could overlap the final mutation checks.

The [preceding 82-test snapshot](../python-contract-before-source-hardening-20260913/README.md)
is preserved unchanged. Earlier Node-path and verifier-harness obstacles are
recorded there. Real CCF, BIND, hardware and native registration acceptance retain
their own evidence and boundaries in the top-level ledger.
