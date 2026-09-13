<img width="627" height="291" alt="noflex" src="https://github.com/user-attachments/assets/773c7ee3-3f88-407f-8370-c903c0f54fa2" />


# agentdns

agentdns is a DNS service. It stores a DNS zone, signs the zone with DNSSEC,
and serves the signed answers through a normal DNS server.

The service runs its important state inside Microsoft CCF. CCF keeps changes
in a shared record and requires approved members to agree before a change is
accepted. Private DNS signing keys and transfer keys stay in CCF. A regular
BIND server receives signed zone transfers and answers DNS queries.

The service can register another service only after checking its hardware
evidence, its approved software, and the public key used by that service.
Owners give each service a limited grant. The grant controls which zones,
names, addresses, ports, and actions it may use. Every request has a nonce so
an old signed request cannot be replayed.

The main implementation is Rust. A small C++ layer connects the Rust code to
the CCF 7.0.15 runtime; it is part of the current CCF build and is not the old
upstream DNS implementation. The C code under `3rdparty/get-snp-report` is a
small hardware-report helper used by the confidential worker image.

## Repository layout

- `crates/` contains the Rust service and its libraries.
- `ccf/` contains the CCF application, governance code, and test drivers.
- `containers/` contains the image definitions.
- `tools/` contains setup, appraisal, control, and verification tools.
- `tests/` contains Rust integration and acceptance tests.
- `docs/` contains design notes, operating instructions, and test evidence.
- `port.md` is the porting contract and acceptance checklist.

## Local checks

Use Rust 1.85 or newer:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

The CCF image uses the pinned CCF toolchain:

```sh
docker build --platform linux/amd64 -f containers/ccf-toolchain.Dockerfile -t agentdns-ccf-toolchain:7.0.15 .
docker build --platform linux/amd64 -f containers/agentdns-ccf.Dockerfile -t agentdns-ccf:7.0.15 .
```

Do not treat a local build as proof of confidential hardware execution. Follow
the native deployment and appraisal procedure in
`docs/azure-native-continuation.md` and read the acceptance reports in `docs/`
before making that claim.

## Scope

This repository provides the service and its controlled test fixtures. It does
not provide public DNS delegation, public certificate issuance, or public mail
delivery.

## License

See `LICENSE` for licensing information.
