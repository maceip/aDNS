# Genuine Microsoft UVM endorsements

Copied verbatim from Microsoft CCF commit `33a90b076f0143b7a92e5da399b1b0de675625b8`, `tests/uvm_endorsements/uvm_0.2.9.cose` and `uvm_0.2.10.cose`.

License: accompanying `CCF-LICENSE` (Apache-2.0). Full provenance, SHA-256 values, certificate validity and test scope are in `docs/attestation-status.md`.

These are UVM publisher endorsements, not complete SNP reports or newly captured Azure service-key binding evidence.

The three `aci_ccf_genoa_v5_*` files were captured from the isolated native Azure ACI primary on 2026-09-13, before the final parser rebuild. They contain a genuine version 5 AMD report and collateral, its actual public TLS peer certificate, and the independently selected test appraisal policy. They contain no private key or credential. The CCF application was ELF `7b41a3a9c147a923542bdda424d9c669f0d166d5c5c8601934b164928218e888`; this fixture proves offline quote/TLS appraisal at the fixed test time 07:42 UTC, not later deployment acceptance. This is a node bootstrap quote, not service registration evidence.

| File | SHA-256 |
| --- | --- |
| `aci_ccf_genoa_v5_quote.json` | `f0118e0298c7ac5927250c084d329bb1841622300bc51eb94e384c7e4c59fb85` |
| `aci_ccf_genoa_v5_peer.der` | `f6e7feed4d9230ff3517bcf2d05c7786c3541a1a1fa192a02827de347efad822` |
| `aci_ccf_genoa_v5_policy.json` | `5b71e5db24a67ce9495cc66bc3122ec224f90a78e9734b370d8f962f3c60d184` |

AMD [56860 revision 1.58, Table 23](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf) defines report version 5 with launch/current mitigation vectors at offsets `0x1f8`/`0x200`, reserved bytes `0x208..0x29f`, and the unchanged signature over bytes `0..0x29f`. The parser supports versions 2, 3, and 5 explicitly; version 4 and unknown future versions remain rejected. Versions 2/3 retain their prior reserved ranges. The two vectors are authenticated u64 observations, absent for older reports. No minimum mitigation mask is inferred from this fixture's values of 7: admission still requires the independently approved product-specific TCB floor, measurement, CCE policy, Microsoft identity and key binding. A specific mitigation-mask authorization policy would require a separate governed contract.

## Azure CVM captures (2026-09-16)

`azure_cvm_provenance.json` identifies the exact source JSON paths and SHA256
hashes. The mail HCL was copied from the operator's agent-hosting checkout;
the worker JSON was absent there and recovered read-only from Agent D's
`ws-D` worktree. The `.bin` files are decoded bytes without corrections.
The worker AK NV region has one DER leaf certificate followed by zero padding;
`azure_cvm_worker_ak_0.der` is the leaf with padding removed.

The mail HCL parses and its original 1233-byte runtime JSON hash matches
`report_data[0..32]`, with a zero upper half. It contains `HCLAkPub` (RSA-2048),
not a workload SPKI digest. Its VCEK, AK certificate/chain and a TPM workload
quote were **not** present in the source capture.

The worker HCL is a **negative fixture**: declared runtime length 1200, actual
JSON length 1203; declared bytes truncate a JSON string. Neither the declared
nor full JSON hash matches report_data. Do not repair those bytes and then
call them hardware evidence. The AK leaf is valid from 2026-09-16 through
2027-09-15 and names `Azure Cloud Virtual TPM CA - 25` as issuer, but no issuer
chain, AMD VCEK or TPM quote was captured.

Tests distinguish parse/hash checks, real ACI AMD crypto regression tests,
real worker AK leaf constraints, and synthetic TPM quote tests. There is no
successful complete CVM workload appraisal fixture. `security_claim: false`.
The Genoa ARK certificate in `src/amd_genoa_ark_cert.pem` was extracted from
the existing captured `aci_ccf_genoa_v5_quote.json` endorsement chain; its
public key matches the pre-existing pinned AMD Genoa SPKI.
