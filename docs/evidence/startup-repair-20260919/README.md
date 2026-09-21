# Startup repair evidence — September 19, 2026

Read the [findings and proof report](../../reviews/2026-09-19-adns-startup-repair.md) first. This bundle records a local stale-PID regression and a separate native Azure fresh-start validation. It does not claim a crash/restart rehearsal on Azure or recovery of the original authority.

| Directory/file | Evidence |
| --- | --- |
| [incident.json](incident.json) | Captured exit103 diagnostic, unavailable join peer, repair identities, and limits of the original-abort investigation. |
| [local-test/](local-test/README.md) | Exact invocation, full console, 21 passing tests with zero skips, production binary/image hashes, test input hashes, and the actual CCF before/after oracle. |
| [deployment/](deployment/) | Immutable image/template/CCE inputs, preflight, policy review, rejected first launch and successful retry. The template contains public configuration and secure parameter references, not parameter values. |
| [attestation/](attestation/) | Initial public SNP quote, actual TLS peer, authenticated service certificate, independently prepared policy and its provenance, and audit result. |
| [initial-staging/](initial-staging/) | Acknowledgment/Open/bootstrap transactions, initial restart counts, receipt and DNSSEC answers. [timing.json](initial-staging/timing.json) distinguishes approximate snapshot time from the later summary creation time. |
| [staging-follow-up/](staging-follow-up/README.md) | Separately timestamped, read-only Azure state, fresh native audit, authenticated service/zone responses, and DNSSEC checks after approximately40minutes. |
| [SHA256SUMS](SHA256SUMS) | Byte hashes for every other bundle file. These detect modification; they are not an external signature or independent authenticity claim. |

Public keys, certificates, quotes, signed records and receipts are intentionally included. Private keys, transfer secrets, runtime parameter values and ledgers are excluded. Local paths in command/provenance records describe the actual run; adjust them when reproducing elsewhere.

## Reproduce the local failure and repair

Run from the repository root, with Docker and access to the recorded registry image. The test creates temporary state and its own disposable test certificate. Its direct CCF invocation uses Virtual mode; it performs no Azure or DNS changes.

```sh
ADNS_TEST_DEPS=$(mktemp -d)
python3 -m pip install --target "$ADNS_TEST_DEPS" \
  --platform manylinux2014_x86_64 --python-version 3.12 \
  --implementation cp --abi cp312 --only-binary=:all: \
  cffi==2.1.1 cryptography==50.0.1 pycparser==3.0

docker run --rm --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp \
  --mount "type=bind,src=$PWD/ccf,dst=/work/ccf,readonly" \
  --mount "type=bind,src=$ADNS_TEST_DEPS,dst=/test-python,readonly" \
  --env PYTHONPATH=/test-python \
  --env ADNS_CCF_BINARY=/usr/local/bin/agentdns \
  --entrypoint python3 \
  agentdnsport20260913.azurecr.io/primary@sha256:302cea65f4272bd722d38bd3df18f5a06c2081d2d30bc3a5efc01737eb654802 \
  -B -m unittest discover -s /work/ccf/tests -p test_supervisor.py -v
```

Expected: **21 tests, OK, zero skips**. In particular, `test_real_ccf_exit_103_and_supervised_restart` must pass. It requires actual CCF to exit103 without the guard, create a live node under the guard, and leave no PID after the child is killed and reaped. An `OK` result with that test skipped is insufficient. See [the precise oracle](local-test/README.md) for what node creation does and does not prove.

## Replay the saved cryptographic evidence

From the repository root:

```sh
ADNS_PROOF=docs/evidence/startup-repair-20260919
(
  cd "$ADNS_PROOF"
  shasum -a 256 -c SHA256SUMS
)

cargo build --locked -p adns-attest --example audit_ccf_node
target/debug/examples/audit_ccf_node \
  "$ADNS_PROOF/attestation/node-quote.json" \
  "$ADNS_PROOF/attestation/node-peer.der" \
  "$ADNS_PROOF/attestation/node-policy.json" \
  1789820288

python3 tools/verify_ksk_receipt.py \
  "$ADNS_PROOF/initial-staging/ksk-receipt.json" \
  --service-cert "$ADNS_PROOF/attestation/service_cert.pem" \
  --zone example.test.
```

The explicit Unix timestamp is the initial audit's recorded time, **12:18:08 UTC**. This replays historical validation; it does not turn an expired audit into fresh evidence. Native policy uses the preapproved immutable UVM release and the explicit `approved_release` endorsement time rule documented in [provenance](attestation/policy-provenance.json). The KSK verifier authenticates the receipt against the service certificate obtained through that audited TLS peer.

The DNS transcripts record direct public UDP53 requests with the receipt-derived test-zone trust anchor. A new live check must use current signatures and fresh attestation; old transcripts, snapshots and expiring signatures are historical evidence. The exact successful BIND invocation and capture times are in [the follow-up bundle](staging-follow-up/README.md).

The saved ARM template is deployment provenance for this isolated fresh authority. Reusing its `Start` configuration or resource name is not a recovery procedure for an existing authority. No redeployment is needed to review or replay the retained evidence.
