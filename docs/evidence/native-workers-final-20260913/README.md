# Final two-worker native ACI evidence

Both approved confidential ACI workers deployed successfully using capture AMD64
manifest `61027bfc59833975356d526d58557e2b18e4af76464b52acb448e3a9a5feba7a`.
Their original public captures passed Rust appraisal and independent Python/OpenSSL
verification at **2026-09-13 07:06:42 UTC** (`1789283202`). Each actual TLS peer
certificate uses the exact service SPKI bound by all 64 SNP REPORT_DATA bytes.
Both passed one genuine positive and sixteen altered-evidence or policy negatives.
No private worker key was exported. This phase sent no control token or
registration-signing request.

| Worker | Public HTTPS endpoint | SPKI SHA256 |
| --- | --- | --- |
| A | `128.251.109.121:8080` | `aec3b0f1c46c6b0d0c5a6e365d06f9edd4df9f9443207477793a9552fd05183c` |
| B | `20.13.225.113:8080` | `632a0f390a030838f11124a26f41ee1f99565f88a8552f5c6465f4e167c147ed` |

A binds approved CCE `68f46918d210a8eb57ccbdade383ba459cb5260273be3d5f778ca37eef6ab75a`;
B binds `d8251696c7dcad3eaca72e3eb34b86dd28c936b056567e3a6ad5e6049024fd29`.
Both match the independently selected Genoa minimum TCB 10/0/23/84, Microsoft
`ContainerPlat-AMD-UVM` SVN 104 and exact previously reviewed launch measurement.
The fixed action scopes match their reviewed deployment configurations; the
public `fixed-actions-review.json` preserves that comparison.

One supplied joint policy approves both CCEs. Its ID is
`71e2d37baddd664f9b292d84c67b2cc31ed7db1a3d8eee2ae4e9debb60a5495d`;
policy validity ends at **11:05:03 UTC**, with a 7,200-second maximum appraisal
interval. These initial appraisals expire at **09:06:42 UTC**. Later operations
must appraise at their actual current time and confirm the actual pinned TLS peer
before transmitting a token. The policy was prepared before either capture and
did not populate its allowlists from newly observed evidence. Its subsequent
CCF governance commitment and service admission need their separate transaction
records; offline verification alone does not establish either.

The explicit `approved_release` mode verifies the immutable Microsoft publisher
endorsement under its exact approved measurement and the certificate path at a
common historical validity instant. Current AMD endorsement validity remains
required. Strict current-certificate mode rejects the expired Microsoft publisher
certificate. Each independent verifier also checks the actual peer certificate's
self-signature, lifetime, name and exact SPKI, the outer ES256 envelope, pinned
AMD chain and native report signature, VCEK chip/TCB extensions, complete key
binding, Microsoft signature/identity/feed/SVN, measurement and CCE digest.

Each worker directory preserves the original capture, report, certificates,
policy, appraisal and exact negative results. Tampered report/padding cases
retain the original outer and AMD signatures and fail both independent signature
checks. They are altered captured public bytes, not newly hardware-signed malformed
reports. Negative policy variants never change governance. The historical worker
capture and prior local acceptance bundles remain unchanged.

`provenance.json` records the actual appraiser and dependency-image hashes.
`scripts/` contains the exact snapshotted verification sources. To reproduce a
worker's recorded appraisal time, run the two verifier scripts using that worker
directory and its `policy.json`; historical reproduction does not assert later
validity. `sha256.json` is an explicit finite public-file allowlist. Both test
control tokens were checked against every exported file in raw, base64,
base64url and hexadecimal forms and were absent. Deployment secret parameters,
worker private keys, member keys and CCF ledgers are excluded.
