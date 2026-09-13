# Independent control-tool and deployment-input review

The control tools passed local Linux checks against pinned TLS fixtures and an
actual isolated CCF 7.0.15 Virtual node. Public logs and the reviewed ACI image
preflight are in [the evidence directory](evidence/control-tools-20260913/).
This is a local review/test result, not an assertion that GitHub Actions or the
pending Azure primary deployment has run successfully.

## Corrected boundaries

`ccf_control.py` retains the DNS TLS name when connecting to a numeric IP,
validates the service CA, bounds request/response sizes and total HTTP I/O time,
and rejects duplicate commitment headers or noncanonical transaction IDs.
Application responses retain their original transaction ID on idempotent reads;
that ID is polled at `/node/tx`, with matching returned identity, until global
commitment. The original `/app/tx` choice failed before service opening; a real
CCF probe and bootstrap reproduced the problem and verified the correction.
Signed member acknowledgement, constitution proposals and ballots use the CCF
SDK COSE implementation. The real smoke completes acknowledgement, service open
and governed configuration with globally committed transaction IDs.

`fetch_capture.py` is a bounded public bootstrap GET. It compares observed peer
certificate/SPKI with the inventory and verifies evidence/action consistency;
native appraisal remains the required next trust step. `sign_capture_request.py`
performs that appraisal before opening the token file, then requires the actual
TLS peer certificate to equal its appraised pin before sending Authorization.
Tests prove failed appraisal reads no token and changed TLS peer sends no POST.

`prepare_aci_control.py` generates isolated member and TSIG fixtures with private
file permissions. `build_aci_template.py` validates every public manifest input,
member identity, pinned constitution reference, TLS/internal interface settings,
and primary/secondary/governed TSIG consistency before rendering. The public
ARM template contains secure parameter references; only the separate mode0600
parameter file contains the test secret. No private deployment parameters were
opened for the independent final-template preflight.

`check_aci_template.py` rejects combined image archives and two mappings that
alias one archive, including hard links. Each archive must contain one expected
image tag; its immutable linux/amd64 OCI manifest, config and all layer bytes
are hashed and matched to the template. The actual reviewed primary has six
layers, secondary three, and ACI pause one. Policy commands/counts, distinct
verity-layer vectors, embedded manifest and secure references agree. dm-verity
roots are generated confcom values, not independently recomputed by this guard.
This closes the observed confcom first-image-of-combined-archive regression.

## Verification and scope

The original local Linux bundle passed 45 helper tests, 12 host-driver tests and nine
CCF bootstrap-supervisor tests. It also repeated genuine native appraisal:
one positive capture, sixteen negative variants, and independent Python/OpenSSL
signature/binding checks at the fixture's recorded historical verification time.
The workflow installs `bind9-utils`, runs all three Python suites, repeats those
native fixture checks and runs the CCF control bootstrap alongside the existing
real governance/quorum/recovery and secondary/mail jobs. Read-only source and writable
build volume paths were exercised with the actual local toolchain image. The
[later frozen-source run](evidence/final-python-20260913/README.md) passed all
79 tests: 52 tools, 12 host-driver, nine supervisor and six runner/export guards.
It includes the final measurement-client checks and exact-owner operator DNS
verification. CI also checks the locked workspace under Rust 1.85.1.

Independent review found no commitment bypass in the CCF delayed callback:
original transaction view is captured before entering the Raft-held callback,
read-only success creates the write needed to activate it, and response delivery
requires committed status for the relevant sequence. The bootstrap supervisor
pins and freezes manifest inputs, validates its governed TSIG identity and
sanitizes child environments. Readiness/provision HTTP paths now share an absolute deadline across numeric
loopback connection, TLS handshake, headers and body, with a 64KiB response
limit. Tests exercise actual TLS header/body trickling and stalled handshake,
oversize/duplicate-header rejection and malformed/nonobject JSON responses.
Provisioning requires canonical matching body/header transaction IDs plus both
global-commit status markers. The supervisor and host-driver source hashes match
the [final primary build record](evidence/ccf/build.json). The earlier running
acceptance image remains separately identified in its own evidence bundle.

Capture mail/lifecycle review found no signing-scope or private-key escape.
The fixed registration/grant/audience, owned challenge IDs, 128 prepared-action
limit and fixed mail names/ports remain enforced. Mail connections have eight
handlers, sixteen lines, 512-byte lines and a 30-second deadline. The capture
owner fixed HTTP slow-trickle slot exhaustion after review, with actual TLS
incoming/outgoing regression tests; the replacement image has its own CCE hash.

## Port audit for reviewed workstreams

WS1.1–1.6 and WS2.1–2.6 have implemented APIs, adversarial/vector tests and
external DNSSEC evidence, as recorded in [wire/DNSSEC status](wire-dnssec-status.md).
Zero allocation applies to stack names, typed borrowed wire data and exact
immutable query lookup; owned snapshots and output serialization allocate.
TSIG/AXFR and autonomous maintenance bounds have separate evidence in
[transfer review](transfer-review.md) and [lifecycle bounds](lifecycle-bounds.md).
The requested observed-leak measurement is now covered by a
[finite native Linux Valgrind workload](evidence/leakcheck-20260913/README.md),
with zero definite/indirect/possible leaks and its 544-byte reachable runtime
allocation explicitly disclosed. Actual local CCF latency/signing and sustained
external propagation are recorded in the [local CCF/BIND report](acceptance-ccf-local.md).
Native execution of the primary and the complete native registration path
remain separate acceptance stages pending explicit approval.
