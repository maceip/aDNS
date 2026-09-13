# Acceptance runner hardening, 2026-09-13

This bundle records a later harness correction. It does not relabel the source used by the already-running 1,250-second CCF/BIND acceptance run. No production image, active run source, cloud deployment, or signing operation was changed.

The reviewed runner now masks both `/src` and `/work/source` read-only for control helpers while keeping `/work/control` and `/work/results` writable. After helper cleanup it checks every original source hash and rejects missing files, changed files, symlinks, unexpected files and unexpected directories. Traversal visits only directories implied by the 19-file source allowlist and stops on the first unexpected child in each directory. It writes `source-integrity.json`, binds that report into provenance and the final runner result, and fails on mismatch. The public exporter includes that report. Pending/failed observation checks now require explicit body and header transaction IDs equal to the transaction actually confirmed by CCF.

`guard-tests.log` records 11 tests on the development host. `linux-guard-tests.log` records the same 11 tests against the five copied source/test files in a network-disabled Linux container. This replaces the previous six runner/export guards; five tests were added. Subcases cover missing observation fields, mismatched/invalid IDs, source mutations, missing source, symlinks, unexpected code and directories, and public report export.

`mount-probe.json` records the actual Docker filesystem check using the runner's generated mount arguments. Both source aliases returned EROFS (errno 30); writes to control and results succeeded. All 19 copied files retained their initial SHA256 hashes. The probe ran from 03:38:26.591 to 03:38:26.859 UTC with networking disabled, a 30-second deadline, 128 MiB memory limit, 0.25 CPU limit and 32 PID limit. This is a mount-semantics check, not a repeated CCF acceptance or hardware attestation test. The short Linux guard run used the same immutable local validation image.

The active long run retains its own initial frozen source provenance. Its transaction fields and complete source inventory must be checked separately against those original bytes; this bundle is not evidence that it executed the later harness.

Reproduce the guards from the copied source with:

```sh
python3 -m unittest discover -s docs/evidence/runner-hardening-20260913/source/tests/rust-integration -p 'test_*.py' -v
```

The mount probe requires the locally available immutable image named in its source and a repository checkout matching the recorded runner/source hashes:

```sh
python3 docs/evidence/runner-hardening-20260913/probe_mounts.py --repository "$PWD" --output /tmp/agentdns-mount-probe.json
```

All exported files are enumerated in `sha256.json`. The copied test source contains deliberate private-key marker strings for negative exporter tests; there are no actual private keys or secret fixture values in this bundle.
