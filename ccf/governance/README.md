# Packaged constitution

`constitution.js` is composed from Steward, pinned by `constitution.source.json`.
`constitution.sha256` verifies exact LF bytes. Do not edit the artifact directly;
update the reviewed Steward source, recompose, and replace all three files.
CI checks the packaged artifact against that pinned source checkout.

This is the packaged source revision, not a statement about the live service.
Existing deployments retain their constitution until a governed
`set_constitution` action is approved and committed. No governance transaction
was submitted during the 2026-09-18 source reconciliation.

The updated schema supports Azure CVM policy fields and SVCB grants alongside
optional unified_quote policy fields. `uq-eat-v2` evidence remains unsupported
by the Rust dispatcher; adding policy fields does not activate a verifier.
