# aDNS

Hardware-attested, verifiable authoritative DNS for modern networks and autonomous agent fleets.

`aDNS` solves a fundamental problem in distributed systems: **how to provide cryptographic hardware attestation and identity verification at internet scale without breaking caching or throughput.**

Instead of forcing every client connection to execute an expensive remote attestation handshake, `aDNS` anchors attestation into the authoritative DNS control plane. A confidential primary running inside hardware-encrypted memory appraises cryptographic measurements and signs the zone with DNSSEC. Standard authoritative secondary servers and edge resolvers then serve RFC-compliant DNS over UDP/TCP port 53 and DNS-over-HTTPS (DoH) at wire speed.

Every client and autonomous agent gets cacheable, hardware-rooted endpoint discovery using standard DNS resolvers without custom client libraries.

---

## The Pitch: Why Hardware-Attested DNS?

When coordinating fleets of autonomous AI agents, microservices, or secure workloads, clients must verify two things before transacting:
1. **Who am I talking to?** (Cryptographic identity and endpoint discovery)
2. **Is that endpoint actually running authentic, untampered code in a genuine secure enclave?** (Hardware attestation)

The common approach today is **RA-TLS (Remote Attestation TLS)**: every single client initiates a TLS handshake that exchanges an AMD SEV-SNP or Intel SGX hardware quote and verifies platform certificates. 

While RA-TLS works for one-off point-to-point channels, it fails as a discovery layer:
* **Zero Edge Caching:** Every connection requires a full cryptographic quote generation and round-trip verification.
* **Massive Latency Tax:** Quote generation and verification adds hundreds of milliseconds per connection.
* **Brittle Dependencies:** Every client application must link platform-specific attestation SDKs.

### The aDNS Model: Attest Once at Registration, Verify Everywhere with DNSSEC

`aDNS` decouples **attestation appraisal** from **lookup serving**:

1. **Hardware-Gated Control Plane:** When a service or agent spins up inside a Confidential VM (CVM), it submits its hardware quote (e.g. AMD SEV-SNP) and public keys to the `aDNS` primary.
2. **Confidential Governance:** The `aDNS` primary verifies the hardware quote, checks that the software measurement matches approved policies, and commits the registration to an immutable ledger.
3. **Automated DNSSEC Signing:** The primary signs the zone records (A, AAAA, TXT, SVCB, TLSA) using hardware-protected keys.
4. **Standard High-Speed Serving:** The signed zone transfers (via authenticated TSIG/AXFR) to standard secondary nameservers (BIND 9, Knot, or edge relays).
5. **Universal Client Verification:** Resolvers and agents validate standard DNSSEC signatures in sub-millisecond lookups. No attestation SDKs needed on the client.

```text
 ┌────────────────────────────────────────────────────────┐
 │           Confidential VM (AMD SEV-SNP Enclave)        │
 │                                                        │
 │   Agent Registration        Microsoft CCF Engine       │
 │   with Hardware Quote ───►  [ Hardware Appraisal ]     │
 │                                    │                   │
 │                             [ Raft Ledger ]            │
 │                                    │                   │
 │                       [ DNSSEC Signer (KSK/ZSK) ]      │
 └────────────────────────────────────┬───────────────────┘
                                      │ TSIG / AXFR
                                      ▼
                        ┌───────────────────────────┐
                        │ Standard Authoritative    │
                        │ Secondary (BIND 9 / Knot) │
                        └─────────────┬─────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              │ UDP/TCP 53                                    │ DoH (RFC 8484)
              ▼                                               ▼
   ┌──────────────────────┐                       ┌──────────────────────┐
   │ Autonomous AI Agent  │                       │ Standard Resolvers / │
   │ (Validates DNSSEC)   │                       │ Edge Caches          │
   └──────────────────────┘                       └──────────────────────┘
```

---

## Origin: Microsoft ccfdns & Azure CCF

`aDNS` originated as a Rust port and architectural extension of Microsoft's [ccfdns](https://github.com/microsoft/ccfdns) project, built on the **Confidential Consortium Framework (CCF)**.

We preserved Microsoft's core design—a strict boundary between a confidential primary and a conventional secondary—while porting the codebase to pure, modern Rust (`crates/adns-*`), hardening the cryptographic primitives, and implementing production-grade DNSSEC validation pipelines:

* **Primary (Control Plane):** Runs inside a CCF-governed confidential enclave on AMD SEV-SNP hardware. Manages DNSSEC signing keys (KSK and ZSK), policy enforcement, hardware appraisal, and Raft consensus. Private keys never leave encrypted memory.
* **Secondary (Data Plane):** Runs unmodified BIND 9 or Knot instances that receive signed zone transfers via TSIG over private interfaces. Handles raw public query traffic, ensuring complete isolation between the public internet and confidential signing keys.

---

## Measured Benchmarks

Performance has been evaluated across both local enclave baselines and native cloud deployments:

### 1. Local CCF & BIND Secondary Baseline
* **Query Throughput:** **1,200,000 queries sustained with 0 packet loss** (999.999875 completed QPS).
* **Latency Profile:** **0.498 ms median**, **1.362 ms p99**, max 20.176 ms (measured over 12,001 independent latency samples).
* **In-Flight Zone Signing:** **2.034 ms to 2.932 ms** (median 2.126 ms) to sign zone records, generate denial proofs, and write signatures under active load.
* **Memory Footprint:** CCF primary process RSS remained stable between **65 MB and 66 MB**; BIND secondary RSS remained under **39 MB**.
* **Freshness:** Zone serial propagation completed within **2.06 to 2.73 seconds** of signing.

### 2. Native Azure Cloud Deployment
* **Infrastructure:** CCF primary running on confidential Azure Container Instances (ACI) backed by AMD SEV-SNP hardware; BIND secondary deployed on an Azure `Standard_EC2as_v5` instance in North Europe.
* **Throughput:** **993.389 completed QPS** over public WAN load.
* **WAN Latency:** **152.116 ms median**, **220.194 ms p99** (including transatlantic public internet transit).
* **Hardware Verification:** Production deployment verified against raw SEV-SNP hardware reports (supporting report formats v3 and v5).

---

## Verification & Independent Proofs

DNSSEC implementation correctness is notoriously difficult to guarantee. `aDNS` validates its output against external, independent reference implementations rather than trusting internal test assertions.

### 1. Multi-Implementation Zone Validation (`tools/validate_live_zone.sh`)
The end-to-end validator exports fresh zones from our signer, serves them through BIND 9, and validates them across three independent industry implementations with strict `pipefail` exits:

```sh
# Run full suite in NSEC3 or NSEC mode
./tools/validate_live_zone.sh --mode nsec3
./tools/validate_live_zone.sh --mode nsec
```

1. **ISC `delv` (Static Key Anchor):**
   * Configured with `+root=example.` and our static KSK anchor.
   * Asserts that positive queries and authenticated negative responses (validated NXDOMAIN denial proofs) both exit `0`.
2. **DNSViz (`probe` + `print` with Injected `-D` DS):**
   * Full-chain cryptographic analysis inspecting every `RRSIG`, `DNSKEY`, `DS`, and denial span.
   * **Zero `[!]` warnings** across all DNSSEC material in both NSEC and NSEC3 modes.
   * *Engineered Discoveries Baked Into Script:*
     * Never pass `-4`: the `-N`/`-D` probe flow synthesizes its parent on an IPv6 loopback; passing `-4` causes it to abort with `"No IPv4 servers to query"`.
     * The script isolates DNSSEC-specific validation lines from unroutable TEST-NET-1 documentation glue timeouts, ensuring strict, non-vacuous cryptographic evaluation.
3. **Zonemaster Engine Undelegated Suite (`zonemaster/cli`):**
   * Evaluates the zone against official registry and root standards under synthetic delegation.
   * **Zero CRITICAL, zero DNSSEC/DS/Zone ERRORs** in both NSEC and NSEC3 modes.
   * Testbed artifacts (unroutable RFC 5737 TEST-NET-1 documentation IP glue and single-host loopback parent) are triaged and accounted for.
4. **Dual Nameserver Support:**
   * Export fixtures utilize dual nameserver declarations (`ns1`, `ns2`) to ensure realistic multi-server topology verification.
   * Detailed architecture and lessons documented in [`docs/dns-validation.md`](docs/dns-validation.md).

### 2. Complete RFC Known-Answer Vectors in CI
Enforced continuously in CI under `cargo test --workspace`:
* **RFC 6605:** P-384 ECDSA key tag calculation (**10771**), DS-SHA384 digest generation, and RRSIG signature verification.
* **RFC 4034 §5.4:** Generic key-tag calculation test vector (**60485** for `dskey.example.com`).
* **RFC 5155 Appendix A:** All 12 published NSEC3 hash vectors (salt `aabbccdd`, 12 iterations) verified against our base32hex encoder.

### 3. Differential Fuzzing Oracle
* **Differential Testing Tool:** `tools/differential_wire.py` fuzzes our parser (`crates/adns-wire/examples/parse_wire.rs`) against `dnspython`.
* **Corpus & Mutation:** 2,000 seeded packet mutations executed against both parsers.
* **Results:** **2,000/2,000 agreed, 0 unsound outcomes** (caught and eliminated an RR vs RRset counting defect during development).
* **CI Integration:** Automated in GitHub Actions (`rust-port.yml`), running differential fuzzing alongside `validate_packets.py` across 22 `delv 9.18` packet checks.

---

## Live System

The system is deployed and serving live cryptographic proofs today:

* **Authoritative DNS (IPv4):** `142.248.222.1`
* **Authoritative DNS (IPv6):** `2a05:f480:1400:25f6::53`
* **DNS-over-HTTPS (DoH):** `https://dns.secure.build/dns-query` (RFC 8484 GET/POST `application/dns-message`)
* **Live Proof Zone:** `proof.dns.secure.build`

### Querying the Live Endpoints

Query port 53 directly via `dig`:
```sh
dig @142.248.222.1 proof.dns.secure.build SOA +dnssec
dig @2a05:f480:1400:25f6::53 proof.dns.secure.build A +dnssec
```

Query DoH via `curl`:
```sh
curl -s -H "accept: application/dns-json" \
  "https://dns.secure.build/dns-query?name=proof.dns.secure.build&type=A"
```

---

## Agent Fleet & Autonomous Network Use Cases

1. **Hardware-Rooted Agent Discovery:**
   Autonomous agents dynamically publish their service locations. Interacting agents verify that an endpoint belongs to an authentic enclave executing verified binaries simply by resolving a DNS record with DNSSEC.
2. **Key Distribution & Attested Senders:**
   Publish public keys, DKIM records, TLSA certificates, or WireGuard endpoints inside the DNSSEC chain. Senders and receivers verify key provenance without out-of-band certificate authorities.
3. **Elimination of Handshake Overhead:**
   High-frequency agent micro-tasks can cache verified records locally according to standard TTL semantics, eliminating the latency of repeated attestation handshakes.

---

## Repository Structure

```text
crates/
  adns-attest/     # Hardware quote appraisal (AMD SEV-SNP reports v3/v5)
  adns-auth/       # Authentication and authorization logic
  adns-ccf/        # Microsoft CCF integration and enclave runtime bindings
  adns-dnssec/     # DNSSEC signing, KSK/ZSK key management, NSEC/NSEC3 denial
  adns-server/     # High-performance server runtime and DoH endpoints
  adns-storage/    # State storage and ledger abstractions
  adns-telemetry/  # OpenTelemetry metrics and tracing
  adns-transfer/   # TSIG-authenticated AXFR/IXFR transfer engine
  adns-wire/       # Zero-copy DNS wire-format parser and serializer
tools/
  validate_live_zone.sh   # 3-implementation validator (delv, DNSViz, Zonemaster)
  differential_wire.py    # Differential wire fuzzer vs dnspython
  doh_smoke.py            # DoH verification suite
docs/
  dns-validation.md       # Technical notes on validators, delv anchors, and flags
```

---

## Building and Testing

### Prerequisites
* Rust 1.85+ (`cargo`)
* Docker (for multi-implementation container tests)
* Python 3 with `dnspython` (for differential testing)

### Run Rust Test Suite
```sh
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

### Run Differential Fuzzer
```sh
python3 tools/differential_wire.py \
  --binary target/debug/examples/parse_wire \
  --cases 2000 \
  --seed 20260914
```

### Run Live Multi-Implementation Validation
```sh
./tools/validate_live_zone.sh --mode nsec3
```

---

## License

See [`LICENSE`](LICENSE) for details.
