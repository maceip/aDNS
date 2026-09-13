# Local deployment candidate: complete request contract

This bundle is prepared locally. The replacement primary image has **not been published to the registry or deployed**. Explicit user approval remains pending for code publication, cloud deployment and secret provisioning, and token-bearing native worker signing after automatic approval review rejected those operations. A future registry reference in these files does not establish registry availability.

The primary uses the reviewed image with committed pending/failed request observations, permanent TSIG identity revocation and immutable appraisal-policy identities. `summary.json` identifies its immutable OCI manifest, executable, constitution, complete build-input manifest, bootstrap and CCE policy hashes. Unchanged capture/rotation policies and the secondary image are included to keep the approved continuation concrete. The actual build and local consensus evidence are in `../ccf/`.

The CCE generator ran with networking disabled, no Azure credentials or Docker socket, and two distinct read-only single-image archives. `ccf-preflight.json` verifies each OCI manifest/config/layer digest, separate layer counts, launch commands, embedded bootstrap files, TLS names and secure parameter references. The generated verity roots are confcom outputs; the preflight does not independently recompute their trees. The policy retains the reviewed optional UVM security-context path and requires the canonical 32-byte TSIG environment pattern without embedding a key.

`bootstrap/` contains only public node configuration, member certificate, encryption public key, manifest and bootstrap summary. Secure deployment parameters, transfer secret values, member/recovery private keys, worker tokens, node state and image archives are intentionally outside this public bundle. The local template builder reused the existing private control material without generating new secrets.

This remains an isolated validation deployment: its primary-state `emptyDir` is ephemeral. It does not meet production durability requirements. Follow `../../operations.md` for durable volumes, complete ledger/snapshot backups and member-share recovery. DS delegation and native cloud acceptance are separate actions requiring the stated approval.

`sha256.json` lists every public file in this bundle. Prior candidates remain under their original evidence paths with supersession labels.
