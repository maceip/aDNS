# Committed request observations

`GET /app/service/request?grant_id=...&request_id=...` returns HTTP200 for a committed successful result or a live issued intent with no successful result. The native CCF route includes `/app`; a configured frontend may expose the specification's unprefixed path.

| `status` | What the committed snapshot establishes |
|---|---|
| `committed` | The immutable successful result exists. Its original result and transaction ID take precedence over every nonce or later failed attempt. |
| `pending` | A live nonce for this grant/request exists, and the latest observation is its issuance. `phase: awaiting_committed_result` does not mean a handler is running or that a signed submission has arrived. |
| `failed` | The latest observation is an authenticated rejected submission bound to a live nonce. `phase: last_authenticated_attempt` describes that observation, not a permanent failure of the request ID. |

Pending and failed responses include `execution_state`, `grant_id`, `request_id`, `matching_nonces`, `multiple_nonce_ambiguity`, `latest_observation`, and `retryable`. The selected observation exposes the exact nonce, intent hash, issuance and expiration times. Failed observations additionally expose the exact signed-message digest, HTTP status, error and failure time. When more than one nonce matches, the newest committed KV observation wins; an equal-version tie uses the encoded nonce key. A newer nonce issuance can therefore change the observed state to pending. The explicit ambiguity flag prevents implying that a particular unseen submission is executing.

`observation_status: committed` and `observation_tx_id` refer to the committed **read snapshot**, not successful execution of the requested mutation. The response's `tx_id` and `x-agentdns-transaction-id` identify that snapshot. `x-agentdns-commit-status: committed` means the response crossed the global consensus gate. Clients must also inspect `status`/`execution_state`; a committed observation can truthfully report pending or failed.

A signed mutation that is rejected with an eligible HTTP4xx keeps that HTTP status. Its response may contain `execution_state: failed`, `observation_status: committed`, and a committed observation transaction ID. This confirms only diagnostic metadata. Application records, registrations, signatures, serials and nonce consumption from the rejected operation are discarded. The diagnostic transaction advances the monotonic time watermark so later clock rollback cannot bypass expiry checks.

The server first evaluates application mutations in a discardable overlay. It records a rejection only after strict parsing, endpoint binding, valid signature and current-epoch unexpired nonce/intent validation against the original transaction. A revoked grant can be observed using a nonce issued while it was authorized. Invalid signatures, invalid/expired nonces, internal/storage/cryptographic failures, and conflicts against an existing successful result produce no diagnostic row. A backend flush failure requires discarding the complete underlying transaction, even if some staged writes reached its tentative write set.

Failures do not consume nonces. After authorization is restored, the client can retry the exact original signed envelope while its nonce remains valid. Successful execution atomically consumes/removes that nonce, removes its diagnostic row and stores the immutable historical result. Once successful, an identical retry returns that historical result despite later grant revocation or nonce expiry; a changed action or nonce under the same request ID conflicts.

Diagnostic rows are keyed by epoch and nonce and are limited by the existing nonce bounds: 4,096 globally, 64 per grant, and a 300-second nonce lifetime. Expiration and epoch invalidation remove nonce and diagnostic together during maintenance or subsequent nonce issuance. GET returns HTTP404 when no successful result and no live current-epoch matching nonce remain, including unknown and pruned attempts. It never invents failed history from a network timeout or consensus rollback. A rolled-back mutation with a previously committed live nonce reconciles as pending.

Successful historical results retain their existing point-lookup lifetime. They are not scanned by the bounded observation query and do not acquire transient observation fields. The development adapter uses `local_committed` observation metadata and explicitly provides no CCF consensus proof.

The focused Rust tests exercise grant restoration and exact retry, multiple nonce ordering, successful-result precedence, partial application-write rollback, time rollback rejection, nonce expiry/epoch garbage collection, and encrypted local recovery. Real CCF tests additionally exercise the global gate for HTTP4xx observations, rollback on primary loss, and disk-ledger recovery. Their public build identities and outcomes are recorded in `docs/evidence/ccf`.
