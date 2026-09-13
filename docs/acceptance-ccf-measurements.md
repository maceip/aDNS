# Actual CCF request, signing and public DNS measurements

The tools below are prepared for the isolated native Azure CCF deployment. Their boundary tests are software checks; they are not measured CCF results. Actual outputs must be retained separately with the deployment's image/CCE digests, node audit, policy and transaction identities.

A completed [local Virtual CCF/BIND run](evidence/ccf-bind-local-20260913/sha256.json) separately records 1,262 seconds of external DNSSEC observation, sustained query load, actual process RSS and signing diagnostics. Its [build record](evidence/ccf-bind-local-20260913/build.json) identifies the earlier immutable primary used for that run; the final candidate has a different image digest. Those measurements prove the stated local protocol/runtime behavior, not native registration latency or Azure execution.

First authenticate the real node and service certificate with [the node bootstrap audit](ccf-node-bootstrap.md). Obtain a nonce and signed envelope from the constrained capture worker only after independently appraising its genuine evidence and pinning its TLS peer. The measurement tool submits exactly that already-authorized envelope once:

```sh
python3 tools/measure_ccf_request.py --url https://agentdns.test:8000 --connect-ip NODE_IP --cacert authenticated-service-cert.pem --envelope signed-register.json --output .validation/azure/registration-timing.json
```

A DNS-name URL requires `--connect-ip` so the numeric destination is explicit while TLS SNI, certificate verification and HTTP Host retain the URL name. No DNS or hosts-file change is needed. The timer includes a new verified TLS connection and ends after receiving a successful response with globally committed status and a canonical, consistent transaction ID. Header/body reads have an absolute deadline; duplicate commitment headers, duplicate JSON fields, non-object responses and oversized bodies fail closed. A separate timed read must return the identical historical request result under that original transaction. The output retains that actual `committed_result`, including lifecycle IDs and lease expiry, so later steps can audit their derivation. One envelope produces one sample; the tool does not call a single sample a latency distribution, infer pure signing time from HTTP latency, retry with a different nonce, or generate any key/signature. The same tool accepts signed renew, deregister and ACME lifecycle envelopes.

Extract actual signing spans from CCF logs separately:

```sh
python3 tools/summarize_signing_metrics.py --log ccf-container.log --output .validation/azure/signing-timing.json
```

The parser selects only exact `agentdns.dnssec.signing` JSON events and retains zone, serial, record count, microseconds and source-line references. The span directly surrounds `SignedZone::sign_with_keys`, including denial/signature generation and excluding preceding storage reads, following writes and consensus. p50/p99 always include sample count. A diagnostic line alone establishes neither global commitment nor hardware provenance.

For an independent public DNS renewal window, mount an independently verified KSK trust-anchor file and output directory into the validation image, then run:

```sh
python3 tests/rust-integration/monitor_remote.py --server PUBLIC_IP --anchor verified-trust-anchor.conf --output .validation/azure/public-dns --seconds 1250
```

This requires external `delv` and dnspython. It queries only authoritative public port53, checks the SOA signature's current expiration, validates positive and NXDOMAIN responses, observes at least three serials, and crosses the first observed expiration. Configure the real CCF signature validity as600 seconds with a300-second refresh margin before starting; a long signature lifetime will correctly fail the crossing criterion. No registration mutations, TSIG secret or DNSSEC private keys are required by the external monitor. Common-container-group topology remains disclosed in [aci-secondary.md](aci-secondary.md).
