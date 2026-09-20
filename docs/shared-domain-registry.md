# aDNS domain registry integration

The authoritative store is the hosting repository's
`infra/production/topology.json`. This repository contains a reader and a source
locator, not another list of operational domain values. `AH_DOMAIN_REGISTRY`
selects an explicit file and fails closed if that file is unavailable. Local
sibling checkouts, the installed `/etc/agent-hosting/domain-registry.json`, and an
explicitly fetched snapshot use the same reader contract.

`domain-registry.source.json` pins an immutable hosting commit, including the
registry schema and naming fields required by these consumers. Fetch uses that
exact commit; the hosting branch does not need to be merged into `main` first.
Changing the pin is an explicit source update, not an automatic runtime refresh.

## Consumers

| Consumer | Shared values and propagation |
| --- | --- |
| ACI preparation and preflight | CCF hostname/SAN, reserved test zone and TSIG name; exact registry bytes are included in the bootstrap manifest. Preflight rejects a different selected registry. |
| Secondary container and VM provisioning | Registry-selected zone, transfer-key name, and image-registry hostname; the ACI secondary mounts the same public snapshot as the primary bootstrap. |
| Capture server and clients | The same TLS hostname drives certificate creation, SNI and HTTP Host. |
| Release authority | Newly minted certificates use the configured CN. Reading an existing certificate derives its DID from that certificate's own CN. |
| Executable acceptance harnesses | DNS owners, CCF audience, TLS hostname and transfer names come through `tools/validation_names.py`. Frozen CCF/native runner inventories include the reader and exact registry snapshot. |
| CAA policies and signed packet exporter | Operator-mail policy uses the registry issuer; verification compares exact committed RDATA. The Rust example exporter requires `--caa-issuer`, supplied by the shared reader in CI and the live validation script. |
| Images and CI | CI fetches the declared hosting revision. The three runtime Dockerfiles require a BuildKit `domain-registry` context and record its SHA256. The build wrapper retains source provenance outside the image. |

The supervisor no longer appends a retired seed IP to `/etc/hosts`. Join targets
must be resolvable from their configured address; cloud-assigned IPs are not
stored as naming defaults. This refactor does not mutate existing cloud groups,
public DNS, CCF governance, or stored ledger state.

## Build

```sh
python3 tools/domain_registry.py fetch
python3 tools/build_images.py secondary --tag agentdns-secondary:local --provenance .validation/secondary-build.json
```

For a local authoritative checkout, set `AH_DOMAIN_REGISTRY` to its absolute
`infra/production/topology.json` path instead of fetching. The build wrapper
creates an isolated snapshot, passes it as a named build context and writes the
resulting image identity and registry digest to the requested provenance file.
It does not push or deploy. `primary` and `capture` are also supported; the primary
requires the pinned CCF toolchain image described in the integration runbook.

For direct Docker invocation:

```sh
python3 tools/domain_registry.py snapshot .domain-registry/topology.json
docker build --platform linux/amd64 --build-context domain-registry=.domain-registry -f containers/secondary.Dockerfile -t agentdns-secondary:local .
```

Regenerate ACI control material and its confidential-compute policy after changing
the store. Existing controls must not silently acquire names from another revision.
The public registry contains no credentials; it is safe to pin with the other
public bootstrap inputs.

## Preserved literals

- Historical evidence remains unchanged: 2,082 tracked files, 20,337,023 bytes at
  the initial audit. Recorded certificate names, signatures, receipts and command
  outputs must retain the bytes they describe.
- Static DNS wire/cryptographic fixtures and unit-test inputs retain reserved
  test names. The Rust packet-export validator uses its corresponding fixed
  packet fixture names. Executable deployment/acceptance harnesses use the store.
- The UQ EAT v2 profile URI is a versioned protocol identifier in governed policy,
  not an endpoint selected by this refactor. It remains unchanged; no environment
  or filesystem reads enter the Rust consensus path.
- Vendor download/collateral/API origins, Docker's host gateway name, loopback
  security binds, telemetry namespace keys and cryptographic domain separators
  are protocol/dependency values rather than deployment naming defaults.
- The packaged CCF constitution remains byte-identical to its pinned Steward
  source; this change does not perform a governance migration.

## Local verification

The Linux tools suite passed 101 tests, including alternate-store generation,
manifest drift rejection, image build-context propagation and authority identity
continuity. The Linux integration guard suite passed all 34 tests. The supervisor
suite passed 20 tests with its opt-in real-CCF-binary case skipped for this change.

An actual secondary image was built using a separate alternate registry snapshot.
Inside the built image, the generated zone and transfer-key name followed that
snapshot and stock `named-checkconf` accepted the configuration. The registry
SHA256 inside the image matched the build provenance. This exercises local image
packaging and configuration; it is not a new live DNS, CCF quorum, cloud deployment
or failover proof.

The real Rust packet exporter generated both NSEC and NSEC3 signed zones using
an alternate CAA issuer selected through the registry CLI. Independent dnspython
checks verified the CAA signatures in both exported zones. The exporter rejects
invocation without an explicit issuer. Only this standalone example's argument handling
changed; the Rust consensus and DNS server implementation remains unchanged.
