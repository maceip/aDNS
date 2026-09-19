# Local CCF startup repair evidence — 2026-09-19

All **21 existing supervisor tests passed**, with no skips, in an isolated
Linux/amd64 Docker container. No tests or application source were changed for
this evidence run. `console.log` contains the complete unittest console output;
`results.json` records every test result, timestamps and source hashes.

The executable is the production CCF binary, SHA256
`7c1fc373c35dccf7158e14fa11c03d15ae297a9c08263d7c71a45efa1df0a203`,
from the cached production image's Linux/amd64 manifest
`sha256:302cea65f4272bd722d38bd3df18f5a06c2081d2d30bc3a5efc01737eb654802`.
The tested supervisor source is commit
`6b15e2e987ddbbce739868e17b81546595aea185`, SHA256
`db08df37e3ad98809b76da02bf2c096313007fcd3314527e24ac17081551bad3`.
`production-image.json` records the platform-specific Docker descriptor and
hashes of the executable, original supervisor and packaged constitution.

## Actual CCF before/after oracle

The unchanged test
`SupervisorPidRecoveryTests.test_real_ccf_exit_103_and_supervised_restart`
asserts each outcome below. Its passing result is recorded in `console.log` and
`results.json`; the child process's captured output is checked by that test,
rather than printed by unittest.

| Stage | Setup and required result |
| --- | --- |
| Before repair | Write the PID of a real, exited and reaped process into `node.pid`. Start the actual CCF binary directly. It must exit **103** and log `PID file node.pid already exists`. |
| Inside the repaired guard | Enter `ccf_pid_guard` with the same configuration and state directory, then start the actual CCF binary. It must remain alive, create `node.pem`, and write its actual child PID into `node.pid`. |
| After child termination | Kill and reap the CCF child before leaving the guard. On leaving the guard, `node.pid` must no longer exist. |

This test runs the real CCF process directly under the repaired context guard.
It does **not** invoke the complete supervisor CLI or demonstrate a complete
supervisor/container restart. CCF explicitly uses **Virtual** mode and `Join`
against unreachable loopback port 65530: node creation is the success criterion,
not an open CCF network, native SNP attestation, or recovered production state.

Other passing tests cover an actual killed fixture process leaving a PID file,
restart under the guard, unchanged ledger sentinel bytes, live/inaccessible
process preservation, replaced or malformed files, symlinks/FIFOs, concurrent
supervisors sharing a state directory even with different PID filenames, and
the existing socket, TLS, secret-isolation and bootstrap-manifest checks.
The ledger sentinel check is a file-preservation test, not a database restore.

## Reproduce

`invocation.json` contains the exact Docker argument vector and working
directory. `test-dependencies.json` records the isolated test-only Python package
versions and a command to prepare that directory. The production image itself
is unchanged: patched source and test dependencies are readonly bind mounts.

Run the argument vector from `invocation.json` after making the referenced image
and readonly input directories available. The container has no network, a
readonly root filesystem and disposable `/tmp` tmpfs. It mounts no cloud
credentials, production configuration, member keys or ledger. The real-binary
test creates its own temporary test certificate and does not export its key.

No Azure, public DNS, governance or other infrastructure changes were made by
this local evidence run.
