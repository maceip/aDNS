# Azure CVM SNP appraisal profile

`azure-cvm-snp` implements Decision #11: direct offline AMD SNP verification
inside `adns-attest`, with no MAA token, network lookup, or system trust store.
It is a workload profile distinct from `azure-aci-snp` and cannot be used for
the primary's ACI node admission. Code deployment rides the next primary image.
Full mail/worker acceptance remains blocked by the captured inputs below.

## Evidence and binding

The registration evidence is the same tagged, attached ES256 COSE Sign1
signed with the registering P-256 key as the ACI path. The CBOR payload has
exactly five text keys:

| Key | Type | Contents |
|---|---|---|
| `hcl` | bytes | Azure HCLA report, including runtime JSON and optional zero NV padding |
| `eds` | text | Ordered VCEK, ASK, ARK PEM chain, or the existing base64 THIM representation |
| `ak` | text | Ordered AK leaf, issuer intermediates, self-signed root PEM chain |
| `quote` | bytes | TPM `TPMS_ATTEST`, no outer TPM2B length; type `TPM_ST_ATTEST_QUOTE` |
| `sig` | bytes | Marshaled `TPMT_SIGNATURE`: RSASSA (0x0014), SHA256 (0x000b), TPM2B signature |

The HCLA v2 header is 32 bytes; SNP is the following 1184 bytes. The runtime
header starts at 1216 and JSON at 1236. All sizes, reserved bytes, report type
SNP (2), hash algorithm SHA256 (1), and zero trailing padding are checked.
`report_data = SHA256(exact runtime JSON bytes) || 0^32` in the mail capture.
The JSON carries one RSA-2048, exponent-65537 `HCLAkPub` signing JWK. Hashing a
reserialized object or substituting `SHA256(workload SPKI)` is rejected.
This layout follows [Microsoft's HCL format](https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design).

The verifier checks AMD's report signature (ECDSA P-384/SHA384), VCEK chip ID,
product and reported TCB extensions, and VCEK → ASK → ARK signatures, X.509
constraints and current validity. The complete Genoa ARK certificate is pinned
in `crates/adns-attest/src/amd_genoa_ark_cert.pem`, extracted from the existing
real ACI fixture, with DER SHA256:

`4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1`

The AK certificate public key must equal HCLAkPub. The AK path must terminate
in a governance-pinned DER certificate hash; its leaf must be unexpired,
non-CA, have digitalSignature and TCG AIK EKU 2.23.133.8.3, and have an allowed
issuer CN. A matching issuer name alone does not establish trust.

The AK must sign a TPM quote whose `extraData` is exactly `SHA256(workload
SPKI DER)`. The parser checks TPM generated magic, quote type, safe clock flag,
a SHA256 qualified signer name, one nonempty SHA256 PCR selection, digest
length, signature algorithm and absence of trailing bytes. The quote proves
AK endorsement of the workload key; it does not prove where that workload
private key was created or stored. PCR values are not appraised by this
profile, so it does not attest Stalwart, a guest application, or its disk.
The quote is a reusable key binding, not a freshness proof. Registration's
existing nonce proves current possession of the workload key; it does not
refresh the boot SNP report. No fresh hardware-liveness claim is made.

## Governance policy

Existing policy fields pin `approved_measurements`, `approved_host_data`
(including explicit all-zero host data in these captures), and component-wise
Genoa `minimum_tcb`. Current, reported, committed and launch TCB must all meet
the floor. SNP debug, migration-agent, signing-key and chip-ID masking checks
remain mandatory. `azure_cvm` adds:

```json
{
  "vmpl": 0,
  "allowed_ak_ca_subjects": ["Azure Cloud Virtual TPM CA - 25"],
  "ak_root_sha256": []
}
```

The empty root allowlist shown here **rejects every appraisal**. Fill it only
from a verified Azure AK certificate chain; a client-supplied root or issuer
label cannot establish it. `uvm` is empty for a CVM-only policy; ACI UVM release
endorsements are not inferred from HCL. Successful results leave ACI-specific
`uvm_svn` at zero and `uvm_did`/`uvm_feed` empty. Appraisal expiry is bounded by
policy, max lifetime, and all AMD/AK certificate expirations.

Policy storage is per zone. Mail and worker grants currently use the same
`agent.hosting.` zone, so two separate policy proposals for that zone replace
each other. The steward branch supplies mail/worker candidate bodies plus a
combined candidate for Agent A to review, sign with D and propose. Measurements
in those candidates are observations, not independently authorized releases.

Agent A must extend the constitution's strict `adnsPolicyIdentity` field list
for `azure_cvm` and the grant validator's TXT-only list for `SVCB`. Agent F does
not own or modify `ccf/governance/` or the steward constitution. Rust support
alone does not make either governance action usable in a deployed primary.

## Captured evidence limits

See `crates/adns-attest/tests/fixtures/azure_cvm_provenance.json` and its README.
Mail HCL hash/AK parsing succeeds. Its AK certificate, VCEK and quote are
missing. Worker HCL has inconsistent lengths and a report-data mismatch; it
must fail. Worker has an AK leaf but no issuer chain, VCEK or workload quote.
There is no successful full CVM appraisal from these captures. Tests keep the
real corrupted worker bytes, verify shared crypto against the existing real
ACI fixtures, exercise AK expiry/foreign issuer/key rejection, and explicitly
label TPM quote signing tests as synthetic. Evidence remains
`security_claim: false`. No live CVM or primary was contacted.

## Attested SVCB records

Grants may authorize `SVCB` under exact `attested_names`. Registration uses
`rdata_strings` as tokens: `["1", "svc.example.", "alpn=h2", "port=8443"]`.
The first two tokens are canonical decimal priority and absolute lowercase
target, followed by parameters in strictly increasing numeric key order.
Known keys: `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`,
`ipv6hint`. Other binary values use `keyNNNN=lowercasehex` (an API encoding,
not zone-file text). Values requiring text escapes use that binary form.
AliasMode (priority 0) accepts no parameters; `.` means unavailable in AliasMode
and the owner in ServiceMode. Duplicate keys, missing mandatory keys, malformed
values and compressed wire targets are rejected. Wire type is 64; target
names preserve their original case for DNSSEC (RFC 3597 section 7) and are emitted uncompressed according to [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).
SVCB contributions are DNSSEC-signed and owned by the registration, with its
lease, grant scope, expiry and withdrawal rules.
