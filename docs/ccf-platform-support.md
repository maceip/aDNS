# CCF and cloud support boundaries

Checked against the pinned CCF7.0.15 source on September13,2026.

CCF remains the consensus, governance, encrypted ledger, TLS and receipt runtime.
This project ports the DNS/application code to Rust through a narrow C++ CCF
transaction adapter; it does not replace or port CCF itself.

Upstream's [platform list](https://github.com/microsoft/CCF/blob/ccf-7.0.15/doc/operations/platforms/index.rst)
supports AMD SEV-SNP and insecure Virtual operation in one RPM. The
[SEV-SNP instructions](https://github.com/microsoft/CCF/blob/ccf-7.0.15/doc/operations/platforms/snp.rst)
explicitly describe Azure ACI, confidential AKS and non-Azure deployments, including
AMD endorsement retrieval. Thus CCF is not intrinsically Azure-only. A cloud's
advertised confidential-VM support alone does not establish compatibility with
CCF's guest attestation interface, trusted launch measurement, host-data binding,
endorsements and governance configuration.

| Layer | Implemented or verified here |
| --- | --- |
| CCF authority runtime | Pinned CCF7.0.15, with actual native Azure ACI acceptance and separate Virtual consensus/recovery tests. |
| Authority on non-Azure SEV-SNP | Documented upstream capability; not deployed or verified by this project. |
| CCF on TDX or Nitro Enclaves | No supported backend in the pinned release's platform list/attestation dispatch. |
| Service registration evidence | Only the governed `azure-aci-snp` profile is active. TDX, Nitro and vTPM return `UNSUPPORTED_PROFILE`, as required by `port.md`. |
| Stock secondary | BIND consumes signed transfers and needs no CCF runtime or DNSSEC private keys. Actual canonical deployment was an Azure VM. |

Registering a workload from another cloud and running the authority there are
separate extensions. The former requires a verified workload evidence profile;
the latter additionally requires validated CCF node startup, joining, launch
integrity, recovery and governance for that platform. Neither is claimed here.
Virtual mode has fake attestation and is for development; it is not a fallback
that preserves confidential-computing guarantees.
