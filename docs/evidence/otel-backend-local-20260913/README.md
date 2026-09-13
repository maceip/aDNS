# Local AgentDNS observability backend evidence — 2026-09-13

This bundle proves synthetic OTLP→Collector→Tempo/Loki and authenticated Grafana resource APIs on an isolated local ARM64 Docker stack. It does not prove native CCF commitment, execution attestation, or browser rendering. Native/real CCF traces have separate evidence.

`source/` contains the explicit frozen configuration and reproducible shell-smoke allowlist; `verification/` contains exact synthetic input, Tempo traces, the preserved async link, and authenticated Grafana trace/data-source/dashboard resources. The three bounded public resource labels survived; forbidden and incorrectly typed fields did not. `logs/` records the final log-pipeline test with the same resource labels and deliberate synthetic secret/type negatives.

`https/` contains the local TLS/auth test: missing/wrong credentials401, wrongCA rejection, authenticatedPOST200, and exact trace retrieval. This test preceded the later public-resource-label addition; its exact Collector variant is in `earlier-tls-config/`, verified against the retained historical source hash. It used no cloud endpoint. Its temporary ingress container was removed; the base stack remains available for the separate liveCCF harness.

Actual failures retained privately: initial Tempo2-style compactor configuration rejected by Tempo3, and the first resource-label smoke sent immediately after a restart before the OTLP listener was ready. The config was corrected and the public verifier now performs a bounded read-only readiness probe before posting. The final retry passed; failed results are not represented as successful runs.

No runtime environment file, password, Basic-auth value, cookie, private certificate key, or container environment dump is in this bundle. The runtime environment example contains placeholders only. `sha256.json` inventories every public file; `source-inventory.json` binds the final executed source bytes. Per-link attribute privacy remains the reviewed receiver/SDK's ID-only-link contract; the Collector does not claim to sanitize arbitrary third-party link attributes.
