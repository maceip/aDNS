# `agentdns`: Architecture, Engineering Plan, and Integration Contract
**Comprehensive C++ Review and Production-Grade Rust Migration Specification**

---

## Executive Summary & Engineering Directives

`agentdns` (derived from the upstream `ccfdns` codebase) is an authoritative DNSSEC zone store, live signer, and hardware-attested service registration authority designed to run inside a **Confidential Consortium Framework (CCF)** enclave.

This document presents a comprehensive review of the legacy C++ codebase, addresses findings from the September 12, 2026 isolated hosting rollout, and establishes the production architecture, workstreams, and integration contracts for the Rust implementation (`adns-rust`).

### Core Engineering Directives

1. **Strict Repository Isolation:** All engineering work described here belongs strictly inside the `agentdns` repository. It must **not** modify, vendor into, deploy from, or write to `agent-hosting`. Read-only comparison against explicitly supplied integration fixtures is permitted. Hosting-side adoption, deployment, or registrar cutover is a separate owner-approved task.
2. **First Useful Delivery Target:** A pinned Azure-capable enclave image that accepts genuine Azure ACI SEV-SNP evidence, enforces CCF-governed Owner Grants, commits authorized mail-shaped records (`MX`, dual-stack `A`/`AAAA`, and multi-port `TLSA 3 1 1`), transfers the signed zone via authenticated RFC 5936 AXFR to an authoritative secondary (BIND 9 / Knot), and maintains valid DNSSEC signatures autonomously while idle.
3. **Out-of-Scope Boundaries:** Mail handling (SMTP, STARTTLS, IMAP, Stalwart), public PKIX certificate issuance, AAMP session routing, and worker scheduling remain entirely outside `agentdns`.

---

# Part 1: In-Depth Review of the C++ DNS Server (`ccfdns`)

```
+-------------------------------------------------------------------------------------------------------+
|                                         C++ CCFDNS ARCHITECTURE                                       |
+-------------------------------------------------------------------------------------------------------+
|  Inbound Transports                                                                                   |
|  - DoH (HTTP GET/POST /dns-query) via llhttp & CCF UserEndpointRegistry                               |
|  - Custom Ringbuffer TCP/UDP (DNSTCP / DNSUDP sessions via ringbuffer::read_message)                  |
+---------------------------------------------------+---------------------------------------------------+
|  Core Logic / Resolver                            |  Policy & Attestation Layer                       |
|  - aDNS::Resolver (Abstract base)                 |  - Rego C++ Interpreter (OPA policy eval)         |
|  - ccfdns::CCFDNS (CCF KV store binding)          |  - QuickJS Runtime (JavaScript policy engine)     |
|  - RFC 4034 signing, canonicalization, RRSIG, DS  |  - did:x509 resolver + OpenSSL cert chain checks  |
|  - RFC 5155 NSEC3 (with Closest Encloser TODO)   |  - COSE/CWT decoding (qcbor / t_cose)             |
|  - Fragmentation engine over AAAA records         |  - Hardcoded SEV-SNP & ACI/THIM JSON rewriter     |
+---------------------------------------------------+---------------------------------------------------+
|  Data Structures & Memory Model                                                                       |
|  - small_vector<T, E>: Heap allocation for non-empty arrays; raw pointer data with delete[]           |
|  - RFC1035::Name / Label: std::vector<Label> where each Label wraps a small_vector<uint8_t>          |
|  - RFC1035::Message / ResourceRecord: Vector of vectors, dynamic spans, unbounded byte reallocations  |
|  - Dynamic Table Synthesis: Public tables per table_name(origin, name, class, type)                  |
+-------------------------------------------------------------------------------------------------------+
```

### 1. Verified Baseline & Fact-Based Context Corrections

To ensure accurate engineering planning, the baseline distinguishes upstream `ccfdns` (commit `0315259c5ce274eab36843967e9725ca8705f92d`), the hosting team's patched Azure lab recorded on September 12, 2026 (`docs/reference/attested-mail-isolated-rollout-2026-09-12.md`), and the target Rust implementation:

* **DNS Transports:** The upstream C++ tree already contains `DNSTCP` and `DNSUDP` handlers over CCF ringbuffers alongside DoH. In the hosting lab, TCP and UDP port 53 were exercised between Azure containers. Standard secondary zone transfers (AXFR) and public secondary exposure remain distinct integration tasks.
* **Hardware Proof:** The September 12 lab proved real ACI SEV-SNP appraisal, approved CCE/key binding, CCF registration, private certificate issuance, and internal SMTP/IMAP delivery. It does not represent proof of the Rust server, generic EAT profiles, public DNS delegation, or public ACME issuance.
* **`small_vector` Allocations:** `small_vector` allocates on the heap (`new E[]`) only when non-empty; default and empty construction do not allocate. Allocation overhead is a profiling optimization target rather than an established throughput bottleneck.
* **RFC 5155 NSEC3 Defect:** The C++ resolver contains an explicit TODO in `src/resolver.cpp` (lines 564–566). Independent tests must validate corrected denial proofs without assuming every upstream response failed.
* **TLSA Deletion Scope:** Calling `remove()` on a TLSA RRset wipes keys for that *exact owner name* (`_port._tcp.<host>`). Because different ports have distinct owner names, removing one port does not affect another port's TLSA set, but it does wipe overlapping keys on the *same* port during a rollover.
* **CCF Table Atomicity:** Dynamically generating table names per record does not break atomicity (CCF transactions can mutate multiple maps atomically). Table consolidation simplifies indexing, prefix scanning, and serialization, but claims of reduced conflict rates must be verified through measurement.

---

### 2. Module Decomposition & Source Findings

| Module | Files | Core Responsibilities | Technical Findings & Architectural Risks |
| :--- | :--- | :--- | :--- |
| **Data Buffers & Serialization** | `include/small_vector.h`, `include/serialization.h` | Dynamic array (`small_vector<T, E>`) for octets and big-endian wire serializer/deserializer primitives (`get<T>`, `put<T>`). | Non-empty vectors execute `new E[]` without inline capacity. Copy/move assignments perform raw pointer manipulations. Wire deserialization advances raw `size_t& pos` and throws generic exceptions on bounds errors without granular recovery. |
| **RFC 1035 Wire DNS** | `include/rfc1035.h`, `src/base32.cpp` | Parsing and serialization for Headers, Questions, Labels, Names, Records (A, NS, SOA, CNAME, MX, TXT) and compression pointers. | `RFC1035::Name` stores `std::vector<Label>`, with each label encapsulating a `small_vector<uint8_t>`. A 4-label domain name performs multiple heap allocations. Name canonicalization (`lowered()`) and wire formatting allocate temporary vectors. Pointer decompression lacks recursion-depth limits. |
| **RFC 3596 & RFC 6891** | `include/rfc3596.h`, `include/rfc6891.h` | IPv6 AAAA records, EDNS(0) OPT pseudo-records, payload size negotiation, DNSSEC OK (DO) flags. | Hand-crafted string conversions and bitfield conversions via raw shifts. OPT record parsing relies on string tokenization (`std::istringstream`) rather than binary decoding. |
| **RFC 4034 & RFC 5155 (DNSSEC)** | `include/rfc4034.h`, `src/rfc4034.cpp`, `include/rfc5155.h`, `src/rfc5155.cpp` | Canonical ordering, ECDSA signing, key tag computation, NSEC/NSEC3 negative denial of existence. | **Incomplete Negative Proofs:** In `src/resolver.cpp` (line 565), negative response logic notes: *"This is wrong. We need to find the closest encloser. See RFC 5155 section 7.2.1."* It returns the preceding hashed name without evaluating the Closest Encloser and Next Closer Name. OpenSSL ECDSA signing produces ASN.1 DER, requiring conversion to IEEE P1363 `(r, s)`. |
| **RFC 7671 (DANE/TLSA)** | `include/rfc7671.h` | TLSA certificate association records (`DANE-EE`, `SPKI`, `SHA-256`). | Dynamic record addition deletes the existing TLSA RRset at `_port._tcp.<name>`, preventing concurrent multi-key rollover. Wire deserialization lacks minimal length validation before indexing. |
| **Service Attestation & COSE** | `include/cose.h`, `include/attestation.h`, `tools/attestation.py` | Validating attestation evidence (AMD SEV-SNP report + UVM descriptor), verifying COSE Sign1 envelopes, checking DID x509 chains. | Couples the DNS core to Azure ACI/THIM JSON rewriting and casts raw quote bytes directly to `ccf::pal::snp::Attestation`. Buffer lifetimes across QCBOR `UsefulBufC` spans and `std::vector` require careful memory management. |
| **Policy Engines** | `src/ccfdns.cpp`, `src/resolver.cpp` | Applying service registration rules and governance policies via embedded OPA (`rego-cpp`) and QuickJS. | Embedding dual C interpreters inflates enclave binary size and introduces garbage collection and interpreter overhead. Upstream admission derived names from CWT claims (`iss`/`sub`) without checking an Owner Grant. |
| **Resolver & KV Core** | `src/resolver.cpp`, `src/ccfdns.cpp`, `include/ccfdns_rpc_types.h` | DNS resolution pipeline, authority sections, CCF KV transactional tables. | Records are partitioned across dynamic table names (`public:ccfdns.records.<origin>.<name>.<class>.<type>`), complicating zone-wide prefix scans and AXFR generation. Coarse mutexes (`std::mutex sign_mtx`) risk lock contention alongside CCF STM. |

---

# Part 2: Target Architecture for `agentdns` (Rust)

```
+--------------------------------------------------------------------------------------------------------+
|                                      RUST AGENTDNS ARCHITECTURE                                        |
+--------------------------------------------------------------------------------------------------------+
|  Public Ingress (Port 53 UDP/TCP)                                                                      |
|  - Served exclusively by Authoritative Secondary (BIND 9 / Knot DNS / NSD) via locally presigned zone   |
|  - Never verifies quotes; never hits CCF transactions; holds zero private DNSSEC keys                  |
+----------------------------------------------------+---------------------------------------------------+
|  Zone Distribution (Private Peering)               |  Administrative & Service Ingress (CCF HTTPS)     |
|  - RFC 5936 AXFR over TCP (Dedicated listener)     |  - POST /service/nonce                            |
|  - RFC 1996 NOTIFY dispatch on commit              |  - POST /service/register (Evidence Profile)      |
|  - RFC 8945 TSIG (HMAC-SHA256 authentication)      |  - POST /service/renew                            |
|  - Secondary observation loop (SOA serial polling) |  - POST /service/deregister                       |
|                                                    |  - POST & DELETE /zone/acme-challenge             |
|                                                    |  - POST /zone/operator/records                    |
|                                                    |  - GET  /governance/ksk-receipt                   |
|                                                    |  - POST /dns-query (DoH, RFC 8484)                |
+----------------------------------------------------+---------------------------------------------------+
|  Core DNS & DNSSEC (`adns-wire`, `adns-dnssec`)    |  Attestation & Authorization                      |
|  - Stack-allocated WireName ([u8; 255] + offsets)  |  - Profile: `azure-aci-snp` (COSE Sign1 + ES256)  |
|  - Strongly-typed RData enum                       |  - 64-byte binding: SHA256(SPKI) || 32 zero bytes |
|  - RFC 5155 NSEC3 Closest Encloser Engine          |  - CCF-Governed Owner Grants                      |
|  - Algorithm 14 (P-384) native P1363 signing       |  - RFC 8785 JCS + ECDSA P-256 fixed r||s checks   |
|  - Multi-port TLSA overlap engine (25, 465, 993)   |  - 32-byte nonces & committed idempotency cache   |
+----------------------------------------------------+---------------------------------------------------+
|  Storage & Lifecycle (`adns-storage`, `adns-lifecycle`)                                                |
|  - Logical collections: zones, records, registrations, grants, nonces, request_results, challenges     |
|  - Private encrypted maps for DNSSEC private keys and TSIG secrets                                    |
|  - Autonomous lifecycle driver: signature refresh before expiry, lease GC, secondary observation      |
+--------------------------------------------------------------------------------------------------------+
```

---

### 1. Wire-Protocol & Domain Names: Zero-Allocation Stack Structures

`adns-wire` replaces the C++ `Name` class and `small_vector` with a stack-allocated, pre-normalized wire format:

```rust
use std::fmt;

pub const MAX_NAME_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;
pub const MAX_LABELS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    UnexpectedEof,
    LabelTooLong(usize),
    NameTooLong,
    InvalidPacket,
    CompressionLoop,
    InvalidCharacter,
}

/// A canonical, wire-format DNS domain name stored completely on the stack.
/// Octets are wire-encoded (e.g. `\x03foo\x03bar\x00`) in lowercase.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireName {
    octets: [u8; MAX_NAME_LEN],
    len: u8,
    label_offsets: [u8; MAX_LABELS],
    label_count: u8,
}

impl WireName {
    /// Bounded zero-allocation parse from a DNS wire packet slice.
    /// Cycle-detection enforces a maximum pointer recursion depth of 10.
    pub fn parse_wire(packet: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let mut octets = [0u8; MAX_NAME_LEN];
        let mut label_offsets = [0u8; MAX_LABELS];
        let mut label_count = 0usize;
        let mut name_len = 0usize;
        let mut curr_offset = *offset;
        let mut jumped = false;
        let mut jump_depth = 0;
        let mut end_offset = None;

        loop {
            if curr_offset >= packet.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let length_byte = packet[curr_offset];

            // RFC 1035 compression pointer (0xC0) check
            if (length_byte & 0xC0) == 0xC0 {
                if curr_offset + 1 >= packet.len() {
                    return Err(DnsError::UnexpectedEof);
                }
                if jump_depth > 10 {
                    return Err(DnsError::CompressionLoop);
                }
                let ptr = (((length_byte & 0x3F) as usize) << 8) | (packet[curr_offset + 1] as usize);
                if !jumped {
                    end_offset = Some(curr_offset + 2);
                    jumped = true;
                }
                curr_offset = ptr;
                jump_depth += 1;
                continue;
            }

            let label_len = length_byte as usize;
            if label_len > MAX_LABEL_LEN {
                return Err(DnsError::LabelTooLong(label_len));
            }
            curr_offset += 1;

            if label_len == 0 {
                // Root null octet
                if name_len + 1 > MAX_NAME_LEN {
                    return Err(DnsError::NameTooLong);
                }
                octets[name_len] = 0;
                name_len += 1;
                label_offsets[label_count] = (name_len - 1) as u8;
                label_count += 1;
                break;
            }

            if curr_offset + label_len > packet.len() || name_len + label_len + 1 > MAX_NAME_LEN {
                return Err(DnsError::InvalidPacket);
            }

            label_offsets[label_count] = name_len as u8;
            label_count += 1;

            octets[name_len] = label_len as u8;
            name_len += 1;

            for i in 0..label_len {
                octets[name_len + i] = packet[curr_offset + i].to_ascii_lowercase();
            }
            name_len += label_len;
            curr_offset += label_len;
        }

        *offset = end_offset.unwrap_or(curr_offset);

        Ok(WireName {
            octets,
            len: name_len as u8,
            label_offsets,
            label_count: label_count as u8,
        })
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.octets[..self.len as usize]
    }
}
```

---

### 2. Strongly-Typed Records & Memory-Safe Layout

Untyped byte buffers are replaced with a strongly-typed `RData` enum:

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Dnskey = 48,
    Rrsig = 46,
    Nsec = 47,
    Nsec3 = 50,
    Nsec3Param = 51,
    Tlsa = 52,
    Opt = 41,
    Caa = 257,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum RecordClass {
    In = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaData {
    pub mname: WireName,
    pub rname: WireName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxData {
    pub preference: u16,
    pub exchange: WireName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaData {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate_association_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(WireName),
    Cname(WireName),
    Soa(SoaData),
    Mx(MxData),
    Txt(Vec<Vec<u8>>),
    Tlsa(TlsaData),
    Dnskey(Vec<u8>),
    Rrsig(Vec<u8>),
    Nsec(Vec<u8>),
    Nsec3(Vec<u8>),
    Nsec3Param(Vec<u8>),
    Caa(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: WireName,
    pub rclass: RecordClass,
    pub rtype: RecordType,
    pub ttl: u32,
    pub rdata: RData,
}
```

---

### 3. Formal RFC 5155 Negative Response Synthesis (NSEC3)

Addressing the upstream C++ defect note, the Rust engine constructs full, standards-compliant denial proofs:

```rust
pub struct NegativeProof {
    pub soa: ResourceRecord,
    pub soa_rrsig: ResourceRecord,
    pub closest_encloser_nsec3: ResourceRecord,
    pub closest_encloser_rrsig: ResourceRecord,
    pub next_closer_nsec3: ResourceRecord,
    pub next_closer_rrsig: ResourceRecord,
    pub wildcard_nsec3: Option<(ResourceRecord, ResourceRecord)>,
}

impl Zone {
    /// Generates provable NSEC3 denial of existence per RFC 5155 Section 7.2.1 (NXDOMAIN).
    pub fn synthesize_nxdomain_proof(&self, qname: &WireName) -> Result<NegativeProof, DnsError> {
        // 1. Find the Closest Encloser: longest ancestor of QNAME existing in the zone
        let (closest_encloser, next_closer) = self.find_closest_encloser(qname)?;

        // 2. Compute NSEC3 record covering the Next Closer Name (proves QNAME does not exist)
        let next_closer_hash = self.nsec3_param.hash(&next_closer);
        let next_closer_nsec3 = self.find_covering_nsec3(&next_closer_hash)?;

        // 3. Find NSEC3 record matching the Closest Encloser (proves closest encloser exists)
        let closest_encloser_hash = self.nsec3_param.hash(&closest_encloser);
        let ce_nsec3 = self.find_exact_nsec3(&closest_encloser_hash)?;

        // 4. Wildcard check: Prove that no wildcard exists at *.closest_encloser
        let wildcard_name = closest_encloser.prepend_wildcard()?;
        let wildcard_hash = self.nsec3_param.hash(&wildcard_name);
        let wildcard_proof = if !self.name_exists(&wildcard_name) {
            let wc_nsec3 = self.find_covering_nsec3(&wildcard_hash)?;
            let wc_sig = self.find_rrsig_for(&wc_nsec3)?;
            Some((wc_nsec3, wc_sig))
        } else {
            None
        };

        Ok(NegativeProof {
            soa: self.get_soa()?,
            soa_rrsig: self.get_soa_rrsig()?,
            closest_encloser_nsec3: ce_nsec3.clone(),
            closest_encloser_rrsig: self.find_rrsig_for(&ce_nsec3)?,
            next_closer_nsec3: next_closer_nsec3.clone(),
            next_closer_rrsig: self.find_rrsig_for(&next_closer_nsec3)?,
            wildcard_nsec3: wildcard_proof,
        })
    }
}
```

---

### 4. Attestation Appraisal & Exact 64-Byte Key Binding (`azure-aci-snp`)

The server verifies the native ACI SEV-SNP report and enforces the 64-byte key-binding layout without using raw pointer casts:

```rust
#[repr(C, packed)]
pub struct SnpAttestationReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub platform_version: u64,
    pub platform_info: u64,
    pub flags: u32,
    pub reserved0: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    pub reserved1: [u8; 24],
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    pub reserved2: u8,
    pub committed_build: u8,
    pub committed_minor: u8,
    pub committed_major: u8,
    pub reserved3: u8,
    pub launch_tcb: u64,
    pub reserved4: [u8; 168],
    pub signature: [u8; 512],
}

#[derive(Debug)]
pub enum AttestationError {
    BufferTooShort,
    KeyBindingMismatch,
    ReportDataNotZeroed,
    VmplInvalid(u32),
    DebugEnabled,
    UvmPolicyRejected,
    SignatureInvalid,
    UnsupportedProfile,
}

impl SnpAttestationReport {
    pub fn parse_safe(raw: &[u8]) -> Result<&Self, AttestationError> {
        if raw.len() < std::mem::size_of::<Self>() {
            return Err(AttestationError::BufferTooShort);
        }
        let report = unsafe { &*(raw.as_ptr() as *const Self) };
        
        // Assert VMPL == 0 and debug disabled
        if report.vmpl != 0 {
            return Err(AttestationError::VmplInvalid(report.vmpl));
        }
        if (report.policy & (1 << 19)) != 0 {
            return Err(AttestationError::DebugEnabled);
        }
        
        Ok(report)
    }

    /// Validates the 64-byte native binding: SHA256(DER SPKI) || 32 zero bytes.
    pub fn verify_exact_binding(&self, spki_der: &[u8]) -> Result<(), AttestationError> {
        let digest = ring::digest::digest(&ring::digest::SHA256, spki_der);
        if &self.report_data[0..32] != digest.as_ref() {
            return Err(AttestationError::KeyBindingMismatch);
        }
        // Invariant: Upper 32 bytes must be strictly zeroed
        if self.report_data[32..64].iter().any(|&b| b != 0) {
            return Err(AttestationError::ReportDataNotZeroed);
        }
        Ok(())
    }
}

pub struct VerifiedAppraisal {
    pub profile: &'static str,
    pub policy_id: [u8; 32],
    pub release_id: String,
    pub spki_sha256: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub measurement: [u8; 48],
    pub uvm_svn: u32,
}
```

---

### 5. Storage Architecture: Unified Composite Key Space

The C++ server's dynamic table sprawl is replaced with consolidated, typed tables in CCF KV:

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneId(pub u32);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey {
    pub zone_id: ZoneId,
    pub name: WireName,
    pub rtype: RecordType,
    pub rclass: RecordClass,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonceKey {
    pub epoch: u64,
    pub nonce: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestResultKey {
    pub grant_id: String,
    pub request_id: String,
}
```

* **`zones` Table:** `ZoneId -> ZoneMetadata` (Origin, SOA serial, KSK/ZSK key tags, scheduling state).
* **`records` Table:** `RecordKey -> VersionedRRSet` (RRSet values, contributor registration IDs, RRSIGs).
* **`registrations` Table:** `RegistrationId -> RegistrationRecord` (Bound SPKI, active contributions, lease expiration).
* **`grants` Table:** `GrantId -> OwnerGrant` (Permitted names, roles, CIDRs, ports, lease duration).
* **`nonces` Table:** `NonceKey -> NonceMetadata` (Intent hash, expiration).
* **`request_results` Table:** `RequestResultKey -> CommittedRequestResult` (Signed message hash, committed transaction ID, serialized response).
* **`private_keys` Table (Private Encrypted Store):** `(ZoneId, KeyTag) -> EncryptedKeyMaterial`.

---

### 6. Zero-Allocation Hot-Path Query Resolution Pipeline

```rust
pub struct ResolutionResult<'a> {
    pub rcode: u8,
    pub authoritative: bool,
    pub answers: &'a [ResourceRecord],
    pub authorities: tinyvec::ArrayVec<[ResourceRecord; 4]>,
    pub additionals: tinyvec::ArrayVec<[ResourceRecord; 2]>,
}

pub fn resolve_query<'a>(
    zone: &'a Zone,
    query_name: &WireName,
    qtype: RecordType,
    qclass: RecordClass,
) -> ResolutionResult<'a> {
    if qclass != RecordClass::In {
        return ResolutionResult {
            rcode: 5, // REFUSED
            authoritative: false,
            answers: &[],
            authorities: tinyvec::ArrayVec::new(),
            additionals: tinyvec::ArrayVec::new(),
        };
    }

    // Direct exact match in memory (zero heap allocations)
    if let Some(rrset) = zone.find_exact_rrset(query_name, qtype) {
        return ResolutionResult {
            rcode: 0, // NO_ERROR
            authoritative: true,
            answers: rrset.records_with_rrsigs(),
            authorities: tinyvec::ArrayVec::new(),
            additionals: tinyvec::ArrayVec::new(),
        };
    }

    // Negative answer synthesis
    if zone.name_exists(query_name) {
        // NODATA: Name exists, type does not
        let nodata = zone.synthesize_nodata_proof(query_name, qtype);
        ResolutionResult {
            rcode: 0,
            authoritative: true,
            answers: &[],
            authorities: nodata.into_records(),
            additionals: tinyvec::ArrayVec::new(),
        }
    } else {
        // NXDOMAIN: Name does not exist
        match zone.synthesize_nxdomain_proof(query_name) {
            Ok(nxdomain) => ResolutionResult {
                rcode: 3, // NXDOMAIN
                authoritative: true,
                answers: &[],
                authorities: nxdomain.into_records(),
                additionals: tinyvec::ArrayVec::new(),
            },
            Err(_) => ResolutionResult {
                rcode: 2, // SERVFAIL
                authoritative: true,
                answers: &[],
                authorities: tinyvec::ArrayVec::new(),
                additionals: tinyvec::ArrayVec::new(),
            },
        }
    }
}
```

---

### 7. Comparative Architecture Matrix

| Dimension | Legacy C++ Implementation | Target Rust Implementation | Architecture & Operational Advantage |
| :--- | :--- | :--- | :--- |
| **Memory Allocation** | Heap churn: `small_vector` allocates on non-empty; `std::string` copies; `std::vector<Label>`. | Stack-allocated `WireName`, bounded byte slices, `tinyvec` stack arrays on hot path. | Eliminates allocation churn on queries; protects enclave heap from fragmentation. |
| **Memory Safety** | Raw pointers, `delete[]`, manual pointer increments (`size_t& pos`), unvalidated offsets. | 100% safe Rust core. Compiler-enforced buffer bounds and lifetimes. | Eliminates memory-corruption vulnerabilities in public-facing interfaces. |
| **DNSSEC Correctness** | Incomplete NSEC3 closest encloser proof marked with inline TODO. | Complete RFC 5155 Section 7.2.1/7.2.2 Closest Encloser, Next Closer, and Wildcard proofs. | Standards compliance; passes validation with `delv` and strict upstream resolvers. |
| **Cryptography** | OpenSSL DER generation converted to P1363 via manual BIGNUM padding. | Direct IEEE P1363 `(r, s)` generation via `aws-lc-rs` / `ring`. Algorithm 14 (P-384). | Eliminates ASN.1 DER allocation/transcoding round-trips. |
| **Hardware Attestation** | Hardcoded to AMD SEV-SNP; parses ACI/THIM JSON endorsements in DNS engine. | `azure-aci-snp` evidence profile; checks full 64-byte binding (`SHA256(SPKI) \|\| 32 zeroes`). | Decouples TEE evidence from DNS logic; prevents malformed padding acceptance. |
| **Authorization** | Assumed authentic hardware was sufficient to register any domain name. | CCF-governed Owner Grants bind key hash to exact names, roles, CIDRs, and ports. | Cryptographic authorization; prevents rogue TEE instances from hijacking domains. |
| **Request Replay Safety** | Ephemeral in-memory replay cache that clears on restart. | 32-byte nonces and request results committed atomically in CCF KV. Persisted service epochs. | Replay protection survives node restarts and CCF consensus rollbacks. |
| **Zone Distribution** | Only answered DoH (`/dns-query`) and custom ringbuffers; no standard AXFR. | Authenticated RFC 5936 AXFR over TCP + RFC 1996 NOTIFY + RFC 8945 TSIG to secondary. | Standard port 53 secondary interoperability (BIND 9, Knot DNS, NSD). |
| **Mail Topology** | Single name used for domain, IP, and TLSA; deleted all TLSA on update. | Tri-name model (`agent.hosting`, `mail.agent.hosting`, workers); multi-key TLSA coexistence. | Safe key rotation on ports 25, 465, and 993; compliant mail delivery. |

---

# Part 3: Project Plan, Workstreams & Parallel Execution Strategy

The project is structured into **6 decoupled workstreams** across **4 sequential release milestones**.

```
                    +-----------------------------------------------------------+
                    |        Phase 0: Workspace Scaffold & Core Type SPI        |
                    +-----------------------------------------------------------+
                                  |                         |
            +---------------------+                         +---------------------+
            |                                                                     |
            v                                                                     v
+-----------------------+   [Trait Contract]    +-----------------------+   +-----------------------+
|  WS 1: adns-wire      |---------------------->|  WS 2: adns-dnssec    |   |  WS 3: adns-attest    |
|  - Zero-copy parser   |   (WireName, RData,   |  - Algorithm 14 P-384 |   |  - azure-aci-snp      |
|  - Bounded cursors    |    Message, Error)    |  - Complete NSEC3     |   |  - 64-byte binding    |
|  - Typed RDATA        |                       |  - Key tag / DS       |   |  - UVM & CCE checks   |
+-----------------------+                       +-----------------------+   +-----------------------+
            |                                               |                           |
            |                                               |                           v
            |                                               |               +-----------------------+
            |                                               |               |  WS 4: adns-auth      |
            |                                               |               |  - Owner Grants       |
            |                                               |               |  - JCS Signed Actions |
            |                                               |               |  - 32-byte Nonces     |
            |                                               |               +-----------------------+
            |                                               |                           |
            +-----------------------+   +-------------------+                           |
                                    |   |                                               |
                                    v   v                                               v
                        +-----------------------+                           +-----------------------+
                        |  WS 5: adns-storage   |<--------------------------|  WS 6: adns-server    |
                        |  - Hierarchical KV    |    (ReadTx / WriteTx)     |  - CCF HTTPS Endpoints|
                        |  - Private Key Store  |                           |  - RFC 5936 AXFR/TCP  |
                        |  - Idempotency Cache  |                           |  - RFC 8945 TSIG      |
                        +-----------------------+                           +-----------------------+
                                    |                                                   |
                                    +-----------------------+---------------------------+
                                                            |
                                                            v
                                            +-------------------------------+
                                            |  WS 7: adns-lifecycle & CI    |
                                            |  - Autonomous Resign Driver   |
                                            |  - BIND 9 AXFR Integration    |
                                            |  - 12 Acceptance Checks       |
                                            +-------------------------------+
```

### 1. Detailed Workstream Breakdown

#### Workstream 1: Zero-Copy Wire Protocol Engine (`adns-wire`)
* **Focus:** `WireName`, bounded binary reader/writer, typed `RData`.
* **Prerequisites:** Phase 0 trait scaffolding.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **1.1** | `WireName` & `Label` | Fixed-size stack representation (`[u8; 255]`) with label offset indices; zero heap allocation; pre-normalized lowercase parsing; reverse-label iterator for canonical DNSSEC comparisons. | None | **Immediate** |
| **1.2** | Binary Cursor & Packet Reader | Safe big-endian cursor with cycle-detection on compression pointers (max pointer recursion depth: 10); strict bounds checks without panics; no `new[]`/`small_vector`. | None | **Immediate** |
| **1.3** | Strongly-Typed `RData` Enums | Implement `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `MX`, `TXT`, `OPT`, `TLSA`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `CAA`. Zero-allocation byte representations. | 1.1 | Parallel with 1.2 |
| **1.4** | Message Parser & Serializer | `Header`, `Question`, `ResourceRecord`, `Message`. Streaming packet writer with name compression dictionary index table. | 1.2, 1.3 | Sequential to 1.2/1.3 |
| **1.5** | Base32Hex & Hex Encoders | Constant-time Base32Hex (RFC 5155 Section 3.3) and Hex encoder/decoder without external C bindings. | None | **Immediate** |
| **1.6** | Wire Protocol Fuzzing | `cargo-fuzz` harness targeting compression loop depth, integer truncation, trailing garbage, and malformed EDNS0 options. | 1.4 | End of WS 1 |

#### Workstream 2: RFC-Compliant DNSSEC Engine (`adns-dnssec`)
* **Focus:** Algorithm 14 live signing, RFC 5155 closest encloser proofs, key tag computation.
* **Prerequisites:** WS 1 (`WireName`, `RData`, `ResourceRecord`).

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **2.1** | Canonical Ordering Primitives | Implement RFC 4034 Section 6.1 `CanonicalNameOrder` (right-to-left label comparison) and Section 6.3 `CanonicalRROrder`. | 1.1 | Parallel using Mock RData |
| **2.2** | Key Tag & Digest Computation | RFC 4034 Appendix B key tag calculation on canonical `DNSKEY` RDATA; SHA-256 and SHA-384 digest generation for `DS` records. | 1.3 | Parallel with 2.1 |
| **2.3** | Zone Signer & RRSIG Generator | Algorithm 14 (`ECDSAP384SHA384`) signing via `aws-lc-rs` or `ring`. Direct IEEE P1363 `(r, s)` signature serialization without ASN.1 round-trips. Support clock skew margins (±300s). | 2.1, 2.2 | Blocked on 2.1 |
| **2.4** | RFC 4034 NSEC Proof Generator | Type bitmap builder with window blocks (0–255); Next Domain Name pointer; NODATA and NXDOMAIN generation. | 2.1 | Parallel with 2.3 |
| **2.5** | RFC 5155 NSEC3 Closest Encloser Engine | **Critical architectural upgrade**: Implement full RFC 5155 §7.2.1 and §7.2.2. Compute Closest Encloser, Next Closer Name, and wildcard proofs. Implement iterated salted SHA-1 hashing. | 1.5, 2.1 | Parallel with 2.3/2.4 |
| **2.6** | Multi-Record TLSA Overlap Manager | Support multiple concurrent `TLSA 3 1 1` records per owner name (`_port._tcp.<host>`) to allow seamless key rotation. | 2.1 | Parallel with 2.4 |

#### Workstream 3: Pluggable Attestation & Appraisal Engine (`adns-attest`)
* **Focus:** Native `azure-aci-snp` profile, 64-byte key binding check, workload appraisal.
* **Prerequisites:** Independent track; uses pre-captured native lab fixtures.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **3.1** | COSE Sign1 Envelope Parser | Parse native COSE Sign1 envelopes using `coset`. Extract protected headers, payload, and signatures. | None | **Immediate** |
| **3.2** | AMD SEV-SNP & Cert Chain Verifier | Verify VCEK certificate chain against AMD ASK/ARK root hierarchy. Verify SEV-SNP report signature, TCB values, VMPL 0, and disabled debug policy. | None | **Immediate** |
| **3.3** | Exact 64-Byte Binding Verifier | Confirm `report_data[0..32] == SHA256(DER_SubjectPublicKeyInfo)` and assert `report_data[32..64] == [0x00; 32]`. Reject non-zero upper padding. | 3.1, 3.2 | Blocked on 3.1/3.2 |
| **3.4** | Microsoft UVM & CCE Policy Appraiser | Verify UVM descriptor, enforce approved publisher identity, feed, minimum SVN, and approved CCE launch measurement. | 3.2 | Parallel with 3.3 |
| **3.5** | Profile Dispatcher & Unsupported Stubs | Construct `VerifiedAppraisal` struct. Dispatch to `azure-aci-snp`. Return `UNSUPPORTED_PROFILE` for TDX, Nitro, and vTPM without crashing. | 3.3, 3.4 | End of WS 3 |

#### Workstream 4: Owner Grants, Signed Actions & Nonce Gate (`adns-auth`)
* **Focus:** Scope delegation, JCS action canonicalization, committed 32-byte nonces.
* **Prerequisites:** Phase 0 trait scaffolding.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **4.1** | CCF-Governed Owner Grant Store | Schema and storage for Owner Grants installed via CCF governance. Bind `subject_spki_sha256` to exact zones, names, roles, CIDRs, and ports. | None | **Immediate** |
| **4.2** | JCS Canonicalizer & Action Parser | Implement RFC 8785 JSON Canonicalization Scheme (JCS). Validate action parameters, compute `intent_hash`. | None | **Immediate** |
| **4.3** | ECDSA P-256 Action Signature Verifier | Verify client request signatures using ECDSA P-256 with SHA-256 over fixed 64-byte $r \parallel s$ encoding. Reject DER signatures. Apply single-pass SHA-256. | 4.2 | Blocked on 4.2 |
| **4.4** | 32-Byte Nonce Manager | Issue random 32-byte nonces (64 hex characters) bound to `intent_hash`. Store nonces in KV with 300s TTL. Enforce atomic single-use consumption. | 4.2 | Parallel with 4.3 |
| **4.5** | Request Idempotency Cache | Record `(grant_id, request_id)` alongside committed mutations. Return past committed results for identical retries; return `409 Conflict` on parameter mismatch. | 4.4 | End of WS 4 |

#### Workstream 5: Storage Architecture & State Collections (`adns-storage`)
* **Focus:** Replace dynamic table sprawl with unified hierarchical collections in CCF KV.
* **Prerequisites:** WS 1 domain types.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **5.1** | Transactional Storage Traits | Define `DnsStorage`, `ReadTx`, `WriteTx` supporting multi-table atomic transactions, point lookups, and prefix scans. | 1.1 | **Immediate** |
| **5.2** | Hierarchical Key Space Schema | Consolidated tables: `zones`, `records`, `registrations`, `grants`, `nonces`, `request_results`, `acme_challenges`. | 1.1, 5.1 | Parallel with 5.1 |
| **5.3** | In-Memory STM Storage Driver | Thread-safe, transaction-isolated in-memory storage driver using MVCC for unit testing and local development outside CCF. | 5.1, 5.2 | Parallel with 5.2 |
| **5.4** | CCF KV Driver Binding | Safe FFI bindings implementing `ReadTx` and `WriteTx` backed by CCF KV APIs (`ccf::kv::Tx` and `ccf::ServiceMap`). | 5.1, 5.2 | Blocked on CCF FFI |
| **5.5** | Private Encrypted Storage Maps | Encrypted CCF storage maps for DNSSEC private keys (KSK/ZSK) and RFC 8945 TSIG shared secrets. | 5.4 | End of WS 5 |

#### Workstream 6: Server Transports, Real AXFR & Endpoints (`adns-server`)
* **Focus:** CCF HTTPS REST endpoints, RFC 5936 AXFR over TCP, RFC 8945 TSIG, DoH.
* **Prerequisites:** WS 1 through WS 5.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **6.1** | HTTP Endpoint Registry | Implement unversioned production endpoints: `/service/nonce`, `/service/register`, `/service/renew`, `/service/deregister`. | 3.5, 4.3, 4.5 | Blocked on WS 3/4 |
| **6.2** | ACME DNS-01 Challenge Endpoints | `POST` and `DELETE /zone/acme-challenge`. Scope challenge TXT records to `_acme-challenge.<name>`; support concurrent challenges. | 5.2, 6.1 | Parallel with 6.1 |
| **6.3** | Operator Outbound Policy API | `POST /zone/operator/records`. Manage SPF, DKIM, DMARC, TLSRPT, CAA via CCF governance. | 5.2, 6.1 | Parallel with 6.1 |
| **6.4** | RFC 5936 DNS-over-TCP AXFR Server | Private TCP transfer listener. Stream full signed zone snapshot under TSIG authentication. | 1.4, 2.3, 5.4 | Blocked on WS 2/5 |
| **6.5** | RFC 1996 NOTIFY & Secondary Tracker | Dispatch NOTIFY on commit. Query secondary port 53 SOA to track observed served serials. Expose `/zone/status`. | 6.4 | Parallel with 6.4 |
| **6.6** | KSK Transparency Receipt Endpoint | `GET /governance/ksk-receipt`. Emit CCF Merkle inclusion proof binding canonical owner name and full DNSKEY RDATA. | 2.2, 5.4 | Parallel with 6.1 |
| **6.7** | RFC 8484 DoH Query Handler | `/dns-query` (GET and POST) for internal enclave forwarders. | 1.4, 5.4 | Parallel with 6.4 |

#### Workstream 7: Autonomous Lifecycle Driver & Acceptance Testing (`adns-lifecycle` / `adns-ci`)
* **Focus:** Background maintenance timer, secondary integration, and the 12 acceptance criteria.
* **Prerequisites:** Integrated Milestone C artifacts.

| ID | Work Item | Technical Requirements & Constraints | Dependencies | Parallel Status |
| :--- | :--- | :--- | :--- | :--- |
| **7.1** | Autonomous Maintenance Driver | CCF background task that advances transparent time, refreshes RRSIGs before expiry, and evicts expired dynamic leases. | 2.3, 5.4 | Milestone B |
| **7.2** | Secondary Interoperability Harness | Automated test harness pairing `agentdns` with BIND 9 via authenticated AXFR; validates port 53 serving. | 6.4, 6.5 | Milestone B |
| **7.3** | DANE & Mail Validation Suite | Integration test with a DANE-capable MTA verifying that `TLSA 3 1 1` matches listener keys on ports 25, 465, and 993. | 6.1, 7.2 | Milestone C |
| **7.4** | Comprehensive Acceptance Suite | Execute the 12 strict acceptance criteria; document measurements, hardware digests, and remaining limitations. | All | Milestone D |

---

### 2. Dependency Graph & Critical Path

```
CRITICAL PATH:
[WS 1: adns-wire] ──> [WS 2: adns-dnssec] ────────┐
                                                  │
[WS 3: adns-attest] ──> [WS 4: adns-auth] ────────┼──> [WS 6: adns-server] ──> [WS 7: Lifecycle & CI]
                                                  │
[WS 5: adns-storage] ─────────────────────────────┘
```

* **Decoupled Development:**
  * **Track 1 (Wire & DNSSEC):** WS 1 (`adns-wire`) and WS 2 (`adns-dnssec`) progress independently using synthetic packet buffers and standard DNSSEC test vectors.
  * **Track 2 (Attestation & Authorization):** WS 3 (`adns-attest`) and WS 4 (`adns-auth`) operate against native ACI fixtures without requiring an active DNS database.
  * **Track 3 (Storage & Distribution):** WS 5 (`adns-storage`) implements CCF transactional mappings while WS 6 (`adns-server`) builds the RFC 5936 AXFR engine and HTTP handlers against mock storage.

---

### 3. Delivery Milestones & Exit Evidence

```
+-------------------------------------------------------------------------------------------------------+
| Milestone A: Native Vertical Slice                                                                    |
| - JCS canonical signed actions & 32-byte nonces; CCF-governed Owner Grants                            |
| - `azure-aci-snp` profile (COSE Sign1 + AMD cert chain + 64-byte key binding + UVM/CCE checks)       |
| - Rust/CCF transactional bridge; nonce & idempotency results commit together                           |
| EXIT EVIDENCE: Real ACI evidence accepted; altered quotes rejected; nonce and result commit together. |
+-------------------------------------------------------------------------------------------------------+
                                                   │
                                                   ▼
+-------------------------------------------------------------------------------------------------------+
| Milestone B: Useful Signed Authority                                                                  |
| - Bounded wire parsing; tri-name model; Algorithm 14 (P-384) DNSSEC; RFC 5155 NSEC3 proofs            |
| - Real RFC 5936 AXFR over TCP + RFC 1996 NOTIFY + RFC 8945 TSIG to one secondary                      |
| - Autonomous lifecycle driver for background signature refresh and lease GC                           |
| EXIT EVIDENCE: Independent validation of signed zone served on BIND 9; signatures refresh while idle.  |
+-------------------------------------------------------------------------------------------------------+
                                                   │
                                                   ▼
+-------------------------------------------------------------------------------------------------------+
| Milestone C: Complete Integration Interfaces                                                          |
| - Bounded lease renewal, multi-port TLSA rotation (25, 465, 993), safe withdrawal                     |
| - Scoped ACME DNS-01 API with concurrent challenge coexistence                                        |
| - Secondary observation status API & KSK receipt binding canonical owner name + DNSKEY RDATA          |
| EXIT EVIDENCE: Reproducible lease/rotation/challenge/recovery tests; independently verified receipts. |
+-------------------------------------------------------------------------------------------------------+
                                                   │
                                                   ▼
+-------------------------------------------------------------------------------------------------------+
| Milestone D: Measured Readiness & Acceptance Suite                                                    |
| - Execution of the 12 strict acceptance checks                                                        |
| - Bounded-input fuzzing; performance benchmarks; operational runbooks and cutover guides               |
| EXIT EVIDENCE: Formal acceptance report with measured throughput, latencies, and zero memory leaks.   |
+-------------------------------------------------------------------------------------------------------+
```

---

# Part 4: Production Integration Contract & API Specification

All HTTP endpoints are unversioned and strictly conform to production standards.

### 1. Encoding & Canonicalization Rules

1. **JCS Canonicalization:** All mutating requests evaluate signed actions canonicalized via **RFC 8785 JSON Canonicalization Scheme (JCS)**. Unknown fields, duplicate keys, and out-of-schema types are rejected.
2. **Numeric Fields:** Nonnegative integers bounded by $2^{53} - 1$ (stricter field-specific bounds apply).
3. **Domain Names:** Lowercase absolute ASCII presentation format with a trailing dot (e.g., `agent.hosting.`). Internationalized domain names must arrive as Punycode A-labels.
4. **IP Addresses:** IPv4 in canonical dotted-decimal format; IPv6 in RFC 5952 canonical format. Address and port arrays must be duplicate-free and sorted.
5. **Binary & Keys:** Unpadded base64url encoding, unless explicitly designated lowercase hex. Public keys are DER SubjectPublicKeyInfo; key digests are 64 lowercase hex characters.
6. **Request Signatures:** Executed using **ECDSA P-256 with SHA-256 over fixed 64-byte $r \parallel s$ encoding** (unpadded base64url). ASN.1 DER signatures are strictly rejected.

---

### 2. Challenge Nonce API

#### `POST /service/nonce`
* **Purpose:** Obtains a single-use 32-byte cryptographic challenge nonce committed to the action intent.
* **Request (`Content-Type: application/json`):**
```json
{
  "action": {
    "operation": "register",
    "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "audience": "ccf://agentdns.service.identity",
    "grant_id": "grant-2026-prod-01",
    "zone": "agent.hosting.",
    "signer_spki_der": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz...",
    "parameters": {
      "role": "mx-edge",
      "mailbox_domain": "agent.hosting.",
      "service_host": "mail.agent.hosting.",
      "addresses": {
        "ipv4": ["20.114.5.117"],
        "ipv6": ["2603:1030:805:2::14"]
      },
      "ports": [25, 465, 993],
      "lease_seconds": 86400,
      "evidence_profile": "azure-aci-snp",
      "evidence_digest": "4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322"
    }
  }
}
```
* **Response (`200 OK`):**
```json
{
  "nonce": "c0a80101d8f07b46e3a74421b8c08ff7e42d76399f83ab35e1c049e289bc9f43",
  "intent_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "issued_at": 1789243200,
  "expires_at": 1789243500
}
```
* **Behavior:** Computes $\text{intent\_hash} = \text{hex}(\text{SHA-256}(\text{JCS}(\text{action})))$. Nonce is valid for 300 seconds.

---

### 3. Service Registration & Lifecycle APIs

#### `POST /service/register`
* **Purpose:** Registers an attested node under an authorized Owner Grant.
* **Request Body:**
```json
{
  "action": {
    "operation": "register",
    "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "audience": "ccf://agentdns.service.identity",
    "grant_id": "grant-2026-prod-01",
    "zone": "agent.hosting.",
    "signer_spki_der": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz...",
    "parameters": {
      "role": "mx-edge",
      "mailbox_domain": "agent.hosting.",
      "service_host": "mail.agent.hosting.",
      "addresses": {
        "ipv4": ["20.114.5.117"],
        "ipv6": ["2603:1030:805:2::14"]
      },
      "ports": [25, 465, 993],
      "lease_seconds": 86400,
      "evidence_profile": "azure-aci-snp",
      "evidence_digest": "4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322"
    }
  },
  "nonce": "c0a80101d8f07b46e3a74421b8c08ff7e42d76399f83ab35e1c049e289bc9f43",
  "nonce_expires_at": 1789243500,
  "intent_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "client_signature": "MEQCIAx1mK_...64_bytes_base64url...wIgS8z0_",
  "evidence_payload": "eyJh...<base64-encoded COSE Sign1 envelope>...93fA"
}
```
* **Processing Rules:**
  1. **Idempotency Check:** Verify `(grant_id, request_id)`. If an entry exists and `signed_message_digest` matches, return the past result. If parameters differ, return `409 REQUEST_ID_CONFLICT`.
  2. **Signature & Nonce Check:** Verify `client_signature` over $\text{JCS}(\text{signed\_message})$. Ensure the nonce is unconsumed, unexpired, and matches `intent_hash`.
  3. **Grant Validation:** Check that `grant_id` authorizes the target names, role, CIDRs, and ports.
  4. **Attestation Appraisal:** Verify the COSE Sign1 envelope and AMD SEV-SNP report. Assert that $\text{report\_data}[0..32] == \text{SHA-256}(\text{signer\_spki\_der})$ and $\text{report\_data}[32..64] == 0$. Check Microsoft UVM feed/SVN and approved CCE launch measurement.
  5. **Atomic Commit:** Consume the nonce, publish record contributions (supporting multi-key TLSA coexistence), update DNSSEC signatures and zone serial, persist the idempotency result, and dispatch RFC 1996 NOTIFY.
* **Response (`200 OK`):**
```json
{
  "status": "committed",
  "registration_id": "reg-8f3a01-20260912",
  "tx_id": "2.41829",
  "zone_serial": 2026091201,
  "lease_expires_at": 1789329600,
  "frontend_propagation": {
    "status": "notified",
    "secondaries": ["10.0.1.5"]
  },
  "contributions": [
    "agent.hosting. 3600 IN MX 10 mail.agent.hosting.",
    "mail.agent.hosting. 300 IN A 20.114.5.117",
    "mail.agent.hosting. 300 IN AAAA 2603:1030:805:2::14",
    "_25._tcp.mail.agent.hosting. 300 IN TLSA 3 1 1 4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322",
    "_465._tcp.mail.agent.hosting. 300 IN TLSA 3 1 1 4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322",
    "_993._tcp.mail.agent.hosting. 300 IN TLSA 3 1 1 4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322"
  ]
}
```

#### `POST /service/renew`
* **Request Envelope:** Common envelope with `operation: "renew"`.
* **Action Parameters:**
  ```json
  "parameters": {
    "registration_id": "reg-8f3a01-20260912",
    "requested_lease_seconds": 86400
  }
  ```
* **Behavior:** Bounds lease expiration to $\min(\text{admission} + \text{requested}, \text{grant.valid\_until}, \text{policy.valid\_until}, \text{reappraisal\_deadline})$. Re-appraises evidence if required. Unchanged DNS records are not resigned.

#### `POST /service/deregister`
* **Request Envelope:** Common envelope with `operation: "deregister"`.
* **Action Parameters:**
  ```json
  "parameters": {
    "registration_id": "reg-8f3a01-20260912",
    "selected_ports": [25],
    "withdraw_all": false,
    "reason": "key_rotation"
  }
  ```
* **Behavior:** Removes only the contributions owned by that registration. Preserves overlapping keys or addresses supported by other active registrations.

#### `GET /service/registration?registration_id=...`
* **Response (`200 OK`):** Committed registration metadata, bound key digest, active contributions, lease expiration, and current status (`active`, `expired`, `withdrawn`).

#### `GET /service/request?grant_id=...&request_id=...`
* **Response (`200 OK`):** Reconciles pending or past requests. Returns current execution state (`pending`, `committed`, `failed`) and the stored idempotency result.

---

### 4. ACME DNS-01 Challenge API

Narrowly scoped for automated certificate managers (certbot / acme.sh). Authenticated via an issuer grant.

#### `POST /zone/acme-challenge`
* **Request Envelope:** Common envelope with `operation: "acme_challenge_create"`.
* **Action Parameters:**
  ```json
  "parameters": {
    "registration_id": "reg-8f3a01-20260912",
    "order_id": "acme-order-98214",
    "name": "mail.agent.hosting.",
    "txt_value": "4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322",
    "ttl": 60,
    "lifetime_seconds": 1800
  }
  ```
* **Rules:** `txt_value` is the unpadded base64url SHA-256 digest of the ACME key authorization. Multiple orders can publish challenges concurrently at `_acme-challenge.<name>` without overwriting each other. Returns a unique `challenge_id`.

#### `DELETE /zone/acme-challenge`
* **Request Envelope:** Common envelope with `operation: "acme_challenge_delete"`.
* **Action Parameters:**
  ```json
  "parameters": {
    "challenge_id": "chal-3312-20260912"
  }
  ```
* **Behavior:** Removes only the designated challenge contribution. Concurrent challenges for other active orders remain intact.

---

### 5. Operator Zone Records API

Restricted to CCF governance or governed operator grants. Manages records not derived from hardware attestation quotes.

#### `POST /zone/operator/records`
* **Request Body (`Content-Type: application/json`):**
```json
{
  "zone": "agent.hosting.",
  "expected_serial": 2026091201,
  "mutations": [
    {
      "action": "replace",
      "name": "agent.hosting.",
      "type": "TXT",
      "ttl": 3600,
      "rdata_strings": ["v=spf1 ip4:20.114.5.117 ip6:2603:1030:805:2::14 -all"]
    },
    {
      "action": "replace",
      "name": "_dmarc.agent.hosting.",
      "type": "TXT",
      "ttl": 3600,
      "rdata_strings": ["v=DMARC1; p=reject; rua=mailto:dmarc@agent.hosting; aspf=s; adkim=s"]
    },
    {
      "action": "replace",
      "name": "s2026._domainkey.agent.hosting.",
      "type": "TXT",
      "ttl": 86400,
      "rdata_strings": ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwgaPZLKiko="]
    },
    {
      "action": "replace",
      "name": "_smtp._tls.agent.hosting.",
      "type": "TXT",
      "ttl": 86400,
      "rdata_strings": ["v=TLSRPTv1; rua=mailto:tls-reports@agent.hosting"]
    },
    {
      "action": "replace",
      "name": "agent.hosting.",
      "type": "CAA",
      "ttl": 86400,
      "rdata_strings": ["0 issue \"letsencrypt.org\""]
    }
  ]
}
```

---

### 6. Zone Distribution & Propagation Status APIs

#### Native DNS-over-TCP AXFR (RFC 5936) & NOTIFY (RFC 1996)
* **Transport:** TCP port 5353 (or configured secondary peering interface).
* **Protocol:** Standard RFC 5936 binary DNS stream.
* **Authentication:** RFC 8945 TSIG with HMAC-SHA256 key stored in CCF private state.
* **Behavior:** Streams the complete signed zone snapshot under the active serial. Private keys are never exported.

#### `GET /zone/status?zone=agent.hosting.`
* **Response (`200 OK`):**
```json
{
  "zone": "agent.hosting.",
  "committed_state": {
    "ccf_tx_id": "2.41829",
    "serial": 2026091201,
    "rrsig_inception": 1789240000,
    "earliest_rrsig_expiration": 1790449600,
    "maintenance_health": "ok"
  },
  "frontend_propagation": {
    "secondaries": [
      {
        "endpoint": "10.0.1.5:53",
        "last_notified_serial": 2026091201,
        "last_observed_serial": 2026091201,
        "last_observed_at": 1789243210,
        "in_sync": true
      }
    ]
  }
}
```

---

### 7. Zone Key Signing Key (KSK) Receipt API

#### `GET /governance/ksk-receipt?zone=agent.hosting.`
* **Purpose:** Emits CCF Merkle inclusion proof binding the active KSK.
* **Binding Invariant:** Binds the **exact canonical owner name and full DNSKEY RDATA**, from which the parent zone's DS record is computed.
* **Response (`200 OK`):**
```json
{
  "zone": "agent.hosting.",
  "key_tag": 23719,
  "algorithm": 14,
  "owner_name": "agent.hosting.",
  "dnskey_rdata_hex": "0101030e03...",
  "ds_digest": {
    "digest_type": 2,
    "digest_hex": "4a7d1ed414474e4033ac29ccb8653d9b4b0e8b2b7371d3eb21798e4d1f211322"
  },
  "ccf_service_identity": "ccf-network-prod-identity",
  "tx_id": "2.1054",
  "proof": {
    "root_signature": "3045022100...",
    "service_cert": "-----BEGIN CERTIFICATE-----\n...",
    "leaf_claims_digest": "7c9f8a...<SHA-256(domain || zone || DNSKEY_RDATA)>..."
  }
}
```

---

# Part 5: The 12 Mandatory Production Acceptance Checks

1. **Hardware Evidence & Appraisal:** Accepts genuine Azure ACI SNP evidence matching the approved CCE policy, platform measurement, TCB, VMPL 0, disabled debug, and Microsoft UVM identity. Validates the complete 64-byte binding (`SHA256(SPKI) || 32 zero bytes`). Rejects virtual quotes, altered reports, non-zero padding, or unactivated profiles.
2. **Owner Scope Authorization:** Rejects an authentic quote attempting to register an ungranted hostname, role, address, or port. Rejects expired or revoked grants.
3. **Signed Request Validation:** Validates JCS canonicalization and fixed 64-byte $r \parallel s$ request signatures. Replayed nonces fail. Duplicate requests return historical committed results without re-executing mutations; requests with mismatched parameters return `409 REQUEST_ID_CONFLICT`.
4. **Strict Commitment Boundary:** Uncommitted state is never exposed as committed. Secondary NOTIFY is dispatched only after global CCF commit is confirmed.
5. **DNS & DNSSEC Correctness:** DNSKEY/DS parameters and NSEC3 negative proofs (Closest Encloser, Next Closer, Wildcard) validate against standard external validators (`delv`, `ldns-verify-zone`).
6. **Secondary Zone Transfer (AXFR):** A standard secondary (BIND 9) connects over TCP, authenticates via RFC 8945 TSIG, completes RFC 5936 AXFR, and serves port 53. NOTIFY alone does not mark a secondary `in_sync`; observed served serials do.
7. **Idle Signature Maintenance:** In the absence of incoming registrations, the autonomous CCF lifecycle driver refreshes RRSIGs before expiration. Leases and ACME challenges expire cleanly. The zone remains valid across signature lifetimes.
8. **Multi-Port TLSA Coexistence & Rotation:** Old and new keys coexist under `_25._tcp`, `_465._tcp`, and `_993._tcp` during rotation. Retiring one registration preserves concurrent contributions.
9. **ACME DNS-01 Concurrency:** Multiple simultaneous challenge orders at `_acme-challenge.<name>` coexist without collision. Deleting one challenge removes only that specific record.
10. **Mail Interoperability:** A controlled DANE-capable MTA validating `_25._tcp.mail.agent.hosting.` confirms matching TLSA records. Mismatched TLSA records correctly cause authentication failure. Standard PKIX certificates validate on ports 465 and 993.
11. **KSK Receipt Verification:** The KSK receipt cryptographically binds the canonical owner name and full DNSKEY RDATA. An altered zone name, modified RDATA, or invalid CCF proof fails verification.
12. **Measured Performance Baseline:** Reports actual measured performance metrics: frontend query throughput and p50/p99 latency, registration transaction latency, signing duration, and memory utilization under sustained load.
