# Native Azure ACI SNP acceptance, 2026-09-13

A real captured Azure ACI native envelope passes the Rust appraiser under the
explicit reviewed policy. An independent Python/OpenSSL cross-check validates
its signatures and policy bindings. One positive and sixteen negative appraisal
cases passed at the recorded verification instant **2026-09-13 01:11:45 UTC**.

The original capture remains byte-for-byte unchanged:

- Evidence SHA256: `224382f563e279018617a2d032b531e15c7b673263d5a52bc475d1c7dab65a1d`
- DER SPKI SHA256: `d45b785636681b5016d1b93a8a2c8f86f6eea028b458b5264c3ca636766498e8`
- CCE host data: `e06abd902bd317a057587ca9125f735f8113eb5422df5cc8a9640d4382211bfb`
- Measurement: `dc3f5a934489232a9b1818f12a0a88d2324ced00f8ab370f40451a76b7880bc3e211849a0739642d3d6c3b2b4bfb9866`
- Product: Genoa; TCB bootloader/TEE/SNP/microcode: **10/0/23/84**; UVM SVN: **104**.

`independent-crypto.json` records the outer ES256 signature, exact
SHA256(DER-SPKI) plus 32 zero bytes in REPORT_DATA, matching self-signed TLS leaf
SPKI, native AMD P384/SHA384 report signature, pinned Genoa ARK and current AMD
certificate path, matching VCEK chip ID/TCB, component-wise minimum TCB, and
Microsoft UVM PS384 signature/DID/EKU/feed/measurement/SVN checks. The policy was
supplied as an independently reviewed input; this verifier never adds observed
measurements or CCE hashes to its allowlists.

`policy.json` explicitly selects `approved_release`. The genuine Microsoft UVM
publisher certificate expired **2026-05-15 18:57:03 UTC**. Its signed immutable
legacy release endorsement is checked against the exact governed measurement
and an authenticated path with a common past validity instant of
**2025-05-15 18:57:03 UTC**. Switching to `current_certificate` correctly rejects
this capture. Current AMD endorsement validity remains required.

The independent Python cryptography 41 parser rejects AMD's authentic RSA-PSS
certificate AlgorithmIdentifier because it explicitly encodes the default
trailerField. The independent check therefore uses the OpenSSL CLI to validate
the AMD path and extract its VCEK public key, then Python cryptography to verify
the P384 report signature. Python cryptography verifies the Microsoft and TLS
certificate signatures directly, and OpenSSL also checks the Microsoft path.
This documented tool compatibility issue did not change production code.

## Negative cases

`appraisal-results.json` contains each exact error and input path:

| Input change | Expected result |
| --- | --- |
| Different valid P256 SPKI | SIGNATURE_INVALID at outer ES256 |
| Captured report measurement byte changed | SIGNATURE_INVALID at outer ES256 |
| Captured REPORT_DATA padding byte changed | SIGNATURE_INVALID at outer ES256 |
| Unsupported profile | UNSUPPORTED_PROFILE |
| Profile removed from policy | PROFILE_NOT_ACTIVE |
| Wrong approved CCE hash | CCE_HOST_DATA_REJECTED |
| Wrong approved measurement | MEASUREMENT_REJECTED |
| Each of four TCB component minima independently raised | TCB_BELOW_MINIMUM, four cases |
| Minimum UVM SVN raised to 105 | UVM_SVN_BELOW_MINIMUM |
| Expired policy | POLICY_NOT_VALID |
| Policy not yet valid | POLICY_NOT_VALID |
| Strict current UVM certificate policy | CERTIFICATE_INVALID |
| Wrong UVM feed | UVM_IDENTITY_REJECTED |

Report/padding mutations retain the original outer signature, which becomes
invalid. Independent verification also rejects their unchanged original AMD
signatures. These are tampered captured bytes, **not freshly signed malformed
hardware reports**. The separate existing Rust unit test checks every one of the
32 padding bytes at the binding function boundary; its passing transcript is
`direct-binding-unit-test.txt`, and it is not hardware evidence.

## Provenance and reproduction

Only the explicit public allowlist was copied from the capture: `capture.json`,
`evidence.cose`, `spki.der`, and `peer.der`, plus the supplied policy and initial
appraisal. `report.bin`, `uvm.cose`, and negative files are derived public data.
No worker private key, bearer token, deployment-parameter file, or secret was
read or exported. `provenance.json` records source and tool hashes;
`SHA256SUMS` lists a SHA256 digest for every other bundle file.

From the repository root, reproduce using the fixed recorded verification time:

```sh
cargo build -p adns-attest --example appraise
docker run --rm --platform linux/amd64 --entrypoint python3 -v "$PWD:/work" agentdns-capture:local /work/tools/verify_native_aci.py --capture /work/docs/evidence/native-aci-20260913 --policy /work/docs/evidence/native-aci-20260913/policy.json --repository /work --output /work/docs/evidence/native-aci-20260913 --now 1789261905
python3 tools/check_native_appraisal.py --binary target/debug/examples/appraise --bundle docs/evidence/native-aci-20260913
cargo test -p adns-attest tests::report_data_requires_digest_and_every_padding_byte -- --exact
```

Reproduction at that historical instant does not assert certificate or policy
validity at a later time. File hashes provide integrity/provenance, not a
separate signature or ledger receipt. This bundle proves native cryptographic
appraisal of the captured evidence; CCF consensus commitment, fresh mutation
nonce possession, DNS publication, frontend propagation and production DANE
operation require their separate acceptance evidence. The preserved original
capture status `captured_not_appraised` describes the worker response; the
successful independent result is `verified-appraisal.json`.
