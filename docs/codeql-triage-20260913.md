# CodeQL findings from the first expanded analysis

The five-language analysis at commit `a40fae93b0bea646982794b388b719c90c6385b9`
published 23 Python findings and one C++ finding. This review followed each
reported location and its current caller. No alert was dismissed through the
API, and no rule or path was broadly excluded. A successful CodeQL workflow
means analysis/upload succeeded; it does not mean there are zero findings.

The [public evidence](evidence/codeql-triage-20260913/summary.json) records the
exact observations and source hashes. The active Rust/CCF authority was not
changed by these fixes. Frozen native acceptance sources remain unchanged.

| Alert | Path or group | Review and action |
| --- | --- | --- |
| 24 | `3rdparty/test/doctest/doctest.h` | A real retained test-library defect: self-append aliases the source while resizing and ASan reports overlapping `memcpy`. A defensive copy handles self-aliasing before mutation. Eight sizes around the inline/heap boundary, three repeated self-appends, and independent appends pass ASan/UBSan. This header is used by the legacy resolver tests, not the current CCF application build. |
| 22 | `demo/client/ksk.py` | The unverified public quote fetch is in retained demo bootstrap. Following that path uncovered a tautological TLS/report comparison. It now checks the observed TLS SPKI SHA256 against the authenticated 64-byte report's first32 bytes, rejects malformed/mismatched inputs, and remains enforced under `python -O`. Real generated public keys and all32 digest-byte mutations are tested. This does not modernize the rest of the legacy bootstrap. |
| 23, 6 | `demo/server/service.py` | The retained demo still submits to a legacy endpoint with certificate verification disabled and uses a default TLS server context. It is not an approved current registration or deployment path. No active runtime imports this module; its remaining limitations are explicit in the README. |
| 4 | `tools/ccf_control.py` | The current client already sets `minimum_version=TLSv1_2`, uses CA verification, checks the hostname, and preserves SNI with numeric connections. The reported sink does not account for the existing floor. Tests assert those properties and reject the wrong hostname before HTTP. |
| 3, 5 | Archived copies of `ccf_control.py` | The frozen files also contain the explicit TLS1.2 floor. They were preserved byte-for-byte as historical evidence. |
| 18 | Current `verify_native_mail.py` | Set explicit TLS1.2 floors on its positive and untrusted-CA negative client contexts. |
| 19 | Archived `verify_native_mail.py` | Historical source retains its recorded defaults. Current fixture hardening does not retroactively alter that evidence or claim an old-version rejection was measured then. |
| 7–17 | Current SMTP, mail, capture, supervisor and audit test contexts | Set explicit TLS1.2 floors where missing. This matters because the tested Ubuntu Python3.12.3 reports `MINIMUM_SUPPORTED`, while the Azure Linux Python3.12.14 reports TLS1.2. The actual Ubuntu SMTP fixture accepts authenticated TLS1.3 on25/465/993 and rejects a TLS1.1-only offer. The deliberately old-version negative test is isolated loopback and sends no HTTP payload. |
| 2 | `tests/rust-integration/smtp_fixture.py` | All records and callers already use loopback. Narrowed listeners from all interfaces to127.0.0.1 and verified the actual three listening addresses through Linux `/proc/net/tcp`. |
| 20, 21 | ACI template/control output writers | The reported0644 branches write public certificates, public encryption keys, manifests and parameter-reference templates. Private member/TSIG material and the actual parameter file use0600 under0700 directories. Existing tests generate real fixtures, verify these modes, and ensure secret values are absent from the public template. |
| 1 | `tools/secondary_vm.py` | Stock BIND requires a readable TSIG key configuration. This is an intentional provisioned secret file, created under umask077, mode0600, in a private directory and mounted read-only to BIND. DNSSEC private keys remain in CCF. It must not be exported as an artifact; this is not a claim that a plaintext TSIG file is encrypted by the application. |

The fixture suite passed37 tests in the pinned Linux toolchain and14 control
tests in the actual Ubuntu validator, including a real TLS1.1 rejection before
HTTP and normal authenticated TLS. The legacy binding tests passed with Python
assertions disabled. The vendor regression's original ASan failure and fixed
result are retained separately. No result here claims that the old demo is a
supported production client or that test certificates establish hardware trust.
