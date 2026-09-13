# Real CCF governance contract checks

The exact replacement executable `7b41a3a9…18e888` passed these checks in an
isolated local Virtual CCF node. The full identity, pinned runtime and frozen
public source hashes are in `provenance.json` and `source-sha256.json`. The
application was copied from its image and was not recompiled for this test.
This is governance and confidential-table API evidence, not hardware evidence.

Every accepted mutation was confirmed through CCF transaction status. The run
verified member acknowledgement and service opening, governed configuration,
one-time digest-pinned private TSIG provisioning and its exact restart retry.
It then committed old-key revocation, rejected reprovisioning with HTTP403,
accepted repeated revocation, rejected same-name reactivation, and successfully
governed and provisioned a replacement identity. No private key or shared secret
is included in this bundle.

Policy checks installed an ID, repeated its exact contents with reordered object
fields, rejected changed trust under that ID, accepted the trust change under a
new ID, rejected changed historical-ID reuse, and rejected an unsafe numeric
value. Accepted transaction IDs and explicit outcomes are in `results.json`.
The separate Rust adapter and JavaScript action regressions cover queued TSIG
responses, replacement transfer continuity, bounds and malformed policy input.
Stock-library replacement AXFR/SOA and BIND validation belong to the assembled
runner evidence; this small control test does not claim those paths.

The preserved superseded harness log shows a test assertion expecting `false`
when the supervisor correctly raised its hard HTTP403 rejection. The assertion
was corrected to require that exact exception; the full final run passed. An
earlier omitted public node-config fixture prevented launch and was corrected
before either recorded governance run. Neither issue required production edits.

Reproduce after building the exact CCF executable as described in
[the CCF integration guide](../../ccf-integration.md):

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD:/src:ro" -v agentdns-ccf-build:/build \
  agentdns-ccf-toolchain:7.0.15 \
  python3 /src/tools/tests/ccf_control_smoke.py
```

Use a disposable build/state volume with its own compiled `/build/agentdns`;
the reproduction creates a fresh node directory and always terminates its
process. The recorded run additionally bind-mounted its verified ELF read-only.
`SHA256SUMS` covers each public file in this directory.
