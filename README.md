<img width="627" height="291" alt="noflex" src="https://github.com/user-attachments/assets/773c7ee3-3f88-407f-8370-c903c0f54fa2" />


# agentdns

Organizations running millions of agents need every lookup to be fast, repeatable, and independently accountable. `agentdns` puts an authoritative DNS control plane inside a confidential virtual machine (CVM), so the zone, signing keys, registration decisions, and audit receipts are protected by hardware-backed isolation while ordinary clients continue to use ordinary DNS. For a large agent fleet, this makes DNS a small, testable trust boundary instead of another service that must be trusted on the host.

This repository is a Rust port and extension of Microsoft's [ccfdns](https://github.com/microsoft/ccfdns). It keeps the useful split between a confidential authoritative primary and a conventional BIND secondary: Microsoft CCF stores governed state and signs the zone; BIND serves the public DNS interface and performs authenticated transfers. DNSSEC proofs, CCF receipts, hardware appraisal, and scoped service registration can therefore be tested independently and inspected together.

## Why this DNS design

The measured acceptance runs show the practical shape of the system. In the local CCF baseline, the primary and BIND secondary sustained 1,200,000 queries with zero loss (999.999875 queries per second); 12,001 latency probes recorded a 0.498 ms median and a 1.362 ms p99. The native Azure run measured 993.389 completed queries per second over a fixed WAN load, with a 152.116 ms median and 220.194 ms p99. The native numbers include the network path and are not a maximum-capacity claim. See the [local acceptance report](docs/acceptance-ccf-local.md) and [native acceptance report](docs/acceptance-native-final-20260913.md).

This is the performance argument for testable DNS compared with RATLS-style designs. DNS answers are cacheable, replicated at the edge, and validated with compact DNSSEC data; the confidential service handles governed state and signing rather than an attestation handshake for every application session. RATLS remains useful when a client must attest an individual service connection, but making that handshake part of every lookup adds latency and makes large-scale caching harder. The comparison is architectural; the repository's measured values are the acceptance results linked above.

## Two deployment tracks

The changes beyond the Microsoft upstream support an internal, global agent deployment in two complementary ways:

1. **Private authoritative service.** The CCF primary keeps DNSSEC keys, TSIG material, governance records, registration grants, and service lifecycle state in its confidential ledger. Registration is accepted only after hardware evidence, approved software identity, and the service public key are checked. A normal BIND secondary receives signed transfers, so existing resolvers and agents do not need a modified client.
2. **Public relay and anycast edge.** The public path is designed to place ordinary DNS serving and relay capacity close to agents while the confidential primary remains protected. Anycast or regional relays can answer from the signed zone and forward controlled updates or observations to the private service; the trust boundary and the public serving path stay separately testable.

The reviewed native image is available from Azure Container Registry as:

```text
agentdnsport20260913.azurecr.io/primary:20260913-native-v5
```

The ordinary-pull contract candidate is recorded separately in the [CCF build evidence](docs/evidence/ccf/build.json). Image digests, deployment identities, and acceptance boundaries are intentionally kept in the evidence bundles rather than inferred from a mutable tag.

## Repository layout

- `crates/` — Rust service, DNS, attestation, registration, and policy code.
- `ccf/` — the CCF application, governance code, and runtime integration.
- `containers/` — reproducible image definitions.
- `tools/` — setup, appraisal, control, and verification tools.
- `tests/` — Rust integration and acceptance tests.
- `docs/` — design notes, operating procedures, and measured evidence.
- `port.md` — the porting contract and acceptance checklist.

## Local checks

Use Rust 1.85 or newer:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Build the pinned CCF images with the ordinary pull path:

```sh
docker build --platform linux/amd64 -f containers/ccf-toolchain.Dockerfile -t agentdns-ccf-toolchain:7.0.15 .
docker build --platform linux/amd64 -f containers/agentdns-ccf.Dockerfile -t agentdns-ccf:7.0.15 .
```

A local build is not proof of confidential hardware execution. Follow the native procedure in [`docs/azure-native-continuation.md`](docs/azure-native-continuation.md) and read the acceptance reports before making that claim.

## Scope

This repository provides the confidential DNS service, its public serving path, and controlled test fixtures. It does not provide public DNS delegation, public certificate issuance, or public mail delivery.

## License

See [`LICENSE`](LICENSE) for licensing information.
