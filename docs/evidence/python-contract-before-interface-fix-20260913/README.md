# Final contract Python and governance checks

The copied source snapshot passed **82 Python tests** on native ARM64 Linux:
55 tools (including three new reconciliation TXT-verifier checks), 12 host-driver,
9 supervisor and 6 runner/export guards. Six actual governance JavaScript action
tests separately passed on Node.js v24.15.0 on the macOS host. All commands and
return codes are preserved; the source manifest covers 67 explicit public inputs.
The frozen inputs and live source hashes matched after execution.

The Python runtime used immutable base image
`sha256:448109ffddaab856945aed9d1d121e6f302db57e7f50dba917c5ba20bcc65615`.
`python3-cbor2` was installed in the disposable container; its package operation,
Python and dependency versions are recorded. The source and runner mounts were
read-only. Results had their own writable mount. No cloud or credential-bearing
request was involved.

An earlier orchestration used an absent Homebrew Node path after all 79 then-current
Python tests passed. Those six JavaScript tests were run with the installed Node
executable. Subsequent addition of the dedicated reconciliation verifier motivated
this complete final repeat, including its three new tests. These results cover
unit and harness guards; real CCF/BIND and native Azure evidence have separate scope.
