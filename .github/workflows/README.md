# CI and source analysis

`rust-port.yml` is the current build and acceptance gate for pushes to `main`,
pull requests, merge queues, manual dispatch and the weekly schedule. It runs
Rust tests/lints/MSRV, Python and governance regressions, recorded native quote
appraisal, actual Virtual CCF commitment/quorum/recovery tests, and two separate
stock-BIND suites. Virtual and development-memory results remain labeled;
neither job claims live confidential hardware acceptance.

`codeql-analysis.yml` scans Rust, C/C++, Python, JavaScript and GitHub Actions on
the same triggers. It uses the official pinned CodeQL v4 action and supported
`none` build mode. This source analysis complements the real pinned CCF 7.0.15
builds in `rust-port.yml`; it is not a replacement for compilation or generated
CXX bridge validation. See [CodeQL build modes](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages).

The inherited CCF 6.0.12 `ci.yml` was retired. It built the superseded C++ tree,
used a Microsoft-only self-hosted runner pool for pull requests, hardcoded the
upstream checkout path, and uploaded ledger directories. There is no automated
cloud deployment or publishing job: release image review, credential supply,
policy preflight and native acceptance remain explicit operator operations.

All jobs use GitHub-hosted disposable runners. Checkout credentials are not left
in the worktree; normal tests have only `contents: read`, and only CodeQL has the
additional security-report permission. Action references are immutable commits.

Artifacts are explicitly public result/log allowlists. The CCF integration job
first runs its checked public exporter. Explicit paths below `.validation` work
with `include-hidden-files: false`, as verified by the original CCF consensus
artifact. Hidden-file exclusion remains enabled, and complete fixture directory
wildcards are prohibited. The [upload action documentation](https://github.com/actions/upload-artifact/blob/ea165f8d65b6e75b540449e92b4886f43607fa02/README.md#inputs)
describes that default. Missing expected artifacts fail the upload step. Private
keys, raw container stdout/stderr, configurations and ledger state are excluded.

The development BIND fixture creates container-local mode-0700 workspaces for
named. This keeps the host's mode-0700, runner-owned private directory intact:
named drops filesystem capabilities and cannot traverse that host directory on
Linux. Container/child exit state and BIND logs are captured before cleanup, so
an early child exit cannot be misreported as an unexplained Docker-exec 137/OOM.
