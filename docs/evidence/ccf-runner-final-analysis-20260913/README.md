# Final CCF/BIND result derivations

These files are **post-run calculations** from the completed final runner's
[public raw evidence](../ccf-runner-final-20260913/sha256.json). The derivation
script was not executed inside the measured workload. It checks the five named
input hashes against that raw manifest before reading their contents, and records
the exact input hashes in its outputs. The raw evidence remains unchanged.

`window-metrics.json` counts the independently validated external samples and
committed-state secondary observations, calculates the maximum state-sampling
gap, and correlates each BIND TSIG transfer timestamp with the preceding serial's
sampled SOA signature expiration. BIND transfer-log timestamps give a minimum
296.340-second margin. The separate primary review's later periodic external
observations give 289–290-second margins; these are different observation points,
not conflicting transfer timestamps. Neither method probes every possible query
instant. Three temporarily lagging secondary status observations are retained.

`signing-metrics.json` extracts only actual `agentdns.dnssec.signing` diagnostics
from the final node log, preserving source line numbers and all eight samples.
These spans cover `SignedZone::sign_with_keys`, including denial and signature
generation, and exclude surrounding storage and CCF consensus. Eight samples do
not establish a stable latency tail.

Reproduce from the repository root into a new output directory:

```sh
python3 docs/evidence/ccf-runner-final-analysis-20260913/derive.py \
  --input docs/evidence/ccf-runner-final-20260913 \
  --output /tmp/agentdns-final-derived-new
```

The script refuses to overwrite existing derived JSON files. The finite
`sha256.json` allowlist covers this README, the script and the two derived files.
The [final acceptance report](../../acceptance-ccf-final-20260913.md) records the
executed image, helper provenance, independent audit and measurement limits.
