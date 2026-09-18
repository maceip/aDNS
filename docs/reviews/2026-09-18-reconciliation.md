# Reconcile provider policy contract and packaged governance

The Windows checkout carried the accepted unified-quote ADR and policy schema,
while Azure CVM verification was already on main. Preserve both: uq-eat-v2
remains explicitly unsupported by the dispatcher until crypto integration exists.
Existing Azure ACI and CVM behavior is retained and rejection tests remain active.

Package the reconciled Steward constitution with source commit and byte digest.
CI recomposes it from that pinned source; no live constitution was changed.
Steward now accepts Azure CVM policy fields and SVCB grants already understood
by aDNS. Preserve the Mac governance-request diagnostic patch.

Validation: full Rust workspace/all-target tests, fmt and clippy; existing
Azure mock/genuine evidence regressions. GitHub additionally exercises the CCF
container path. Schema preservation is not attestation activation or cloud proof.
