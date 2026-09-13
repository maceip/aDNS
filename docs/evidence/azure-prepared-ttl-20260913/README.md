# Prepared isolated Azure validation artifacts

> Superseded after the final contract audit. Do not deploy this primary policy.
> The replacement includes request reconciliation, permanent TSIG revocation
> and immutable appraisal-policy identities; it needs its own image/CCE pins.

These public templates and policies describe the corrected candidate after
the mixed base/dynamic RRset TTL signing fix. They are
**not deployment or native execution evidence**. The code-only images were
published to the isolated registry, while deploying the CCF/BIND group,
replacing the original capture worker, and creating its rotation peer remain
pending explicit user approval. No registration depends on the older worker.

The summary pins the OCI manifests, primary executable, bootstrap manifest and
CCE policy bytes. Policy generation used the pinned Linux confcom tool and a
distinct single-image archive for each container. Preflight checked archive
metadata and layer hashes, policy commands/counts, the bootstrap manifest, TLS
names and secure parameter references. It did not independently recompute the
generator's dm-verity roots. Every container forbids exec and elevation.

The two workload templates use the same immutable image but separate fixed
request/grant identities and CCE policies. After deployment, obtain fresh
reports and TLS peers, appraise both against the independently reviewed CCE
hashes, govern both keys and a policy approving both workers, then request
nonces and fixed-scope signatures. A report from the old image/key cannot
authenticate these new workers.

Primary state uses ephemeral emptyDir for isolated validation. Production
persistence, consortium membership and backup decisions require the runbook's
durable-storage and recovery steps before promotion. Public DNS53 is served by
stock BIND; internal8001 and transfer5353 are not public. The workload advertises
reserved example.test addresses: controlled DANE uses the documented test-only
DNAT route and does not establish public address reachability.

Only public templates, policy bytes and digest summaries are included. Private
member/recovery keys, TSIG values, capture control tokens and secure deployment
parameter files remain in ignored, mode-restricted local validation state.
