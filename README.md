# agentdns

A CCF-governed authoritative DNSSEC service with hardware-attested service
registration. The Rust migration is specified in [port.md](port.md); the
original C++ implementation remains below for baseline comparison.

## Rust implementation

The workspace contains the safe Rust wire, DNSSEC, native ACI SNP appraisal,
Owner Grant authorization, storage, transfer and lifecycle engines, plus a
narrow CCF 7.0.15 bridge. The primary generates and retains DNSSEC keys in CCF
private maps. A stock BIND secondary serves public DNS from authenticated,
presigned transfers.

Start with these documents:

- [Acceptance ledger and current limitations](docs/port-progress.md)
- [Pinned CCF build, endpoints and consensus tests](docs/ccf-integration.md)
- [Release, backup, recovery and cutover runbook](docs/operations.md)
- [Native node bootstrap verification](docs/ccf-node-bootstrap.md)
- [Stock secondary, DNSSEC and controlled mail validation](docs/acceptance-external.md)
- [Lifecycle capacity and state-format bounds](docs/lifecycle-bounds.md)

Tests use Rust 1.95.0; all targets also compile with the declared Rust 1.85
minimum (checked with 1.85.1). Validate the core with:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Build the pinned CCF executable image with:

```sh
docker build --platform linux/amd64 -f containers/ccf-toolchain.Dockerfile -t agentdns-ccf-toolchain:7.0.15 .
docker build --platform linux/amd64 -f containers/agentdns-ccf.Dockerfile -t agentdns-ccf:7.0.15 .
```

Production entry points use CCF's `/app` prefix, for example
`/app/service/register`. Supply an independently approved bootstrap manifest
and confidential launch policy, govern the application configuration and Owner
Grants, and authenticate the node before trusting its service certificate.
See the runbook for the full procedure. `adns-dev` and CCF's explicit Virtual
platform are local development/consensus test environments.

All validation resources belong to this repository. Public DNS delegation,
hosting adoption, mail handling and public certificate issuance are separate
tasks. Consult the acceptance ledger for exercised evidence; an image build
alone does not establish confidential deployment or production readiness.

## Legacy C++ build

The build depends on a local installation of [CCF](https://github.com/microsoft/ccf) 6.0.0 or above, on Azure Linux 3.0.

```
mkdir build
cd build
cmake -GNinja -DCOMPILE_TARGET=virtual ..
ninja
```

## Legacy C++ sandbox

```
cd build
/opt/ccf_virtual/bin/sandbox.sh -p libccfdns.virtual.so
```

## Legacy C++ end-to-end demo

Make sure you're running in the container (devcontainer setup is suitable). Check out [demo](./demo/README.md) for details.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
