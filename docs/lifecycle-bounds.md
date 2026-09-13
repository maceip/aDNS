# Bounded autonomous maintenance and recovery format

The server admits bounded live state. Capacity errors return HTTP 413 and
discard every staged application change. No nonce consumption, partial
contribution update, signature or serial advance is committed on failure.
An eligible authenticated rejection may commit only its bounded diagnostic
observation and monotonic clock watermark, through the global consensus gate.
Invalid signatures/nonces and internal or storage failures commit no diagnostic
state; backend flush failures require discarding the entire transaction. See
[request reconciliation](request-reconciliation.md) for the exact boundary.

| Live resource | Bound |
| --- | ---: |
| Zones | 32 |
| Active registrations across the authority | 1,024 |
| ACME challenges across the authority | 1,024 |
| Outstanding nonces across the authority | 4,096 |
| Outstanding nonces per grant | 64 |
| Governed base records per zone | 4,096 |
| Base RRsets plus dynamic RRsets per zone | 4,096 |
| Dynamic contributions per zone | 16,384 |
| Contributions per dynamic RRset | 256 |
| Combined base and dynamic uncompressed canonical record bytes per zone | 4 MiB |

Base and dynamic RRsets are counted separately even when they share an owner and
type; this conservative admission rule may reject a zone before its deduplicated
RRset count reaches the limit. Multiple owners contributing identical values
consume separate contribution capacity, preserving withdrawal ownership.

The version-one lifecycle marker and active-registration index live under the
server's reserved `server/` key namespace in `Collection::Lifecycle`. The marker
records the active count; each active entry identifies exactly one retained
registration row. Registration, withdrawal and expiry update the index in the
same transaction as contributions and results. Historical registration rows and
request results remain available through keyed reads. Maintenance never scans
those historical tables. CCF's underlying unordered map still visits the bounded
Lifecycle collection during a prefix scan; the active index prevents a scan of
the separately growing registration history.

Maintenance scans at most the live registration index, challenge and nonce
bounds, and the configured zones. It collects expired contributors by zone,
then removes them in one record scan per affected zone before signing. A burst
of 1,024 expirations therefore does not cause 1,024 full-zone removal scans.
Canonical-record sets also replace quadratic vector-based record deduplication.

Consumed nonce rows are removed. The committed historical request result is
checked before nonce lookup, so an exact retry still returns its original
transaction result. Expired nonce rows are collected both by maintenance and by
new nonce issuance; consumed and expired rows release quota. Challenge and
registration expiry release their own admission capacity through maintenance.

## Recovery compatibility

Fresh initialization creates the format marker and per-zone usage rows before
signing. Sealed snapshots and CCF ledger recovery preserve these rows with the
rest of their transaction state. A missing/unsupported marker, missing active
entry, count mismatch or missing zone usage fails closed. The development
runtime checks the marker before serving a restored snapshot.

Pre-index development snapshots are intentionally incompatible. Recreate an
isolated development authority from its original governed configuration and
re-run its registrations; do not copy historic active rows into a fresh indexed
authority. Production must not adopt a legacy ledger by merely inserting the
marker: a separately governed migration would need to validate every active
registration, reconstruct ownership and usage, enforce all bounds, and install
the marker/index atomically before activation. No such legacy deployment is
claimed by this port, and automatic unbounded backfill is deliberately absent.
The public `index_active_registration` helper exists for explicit development
test fixtures and is not an authorization or migration endpoint.

## Verification and diagnostics

The final workspace run passed 28 server tests (27 transaction tests and one
byte-budget unit test), recorded in the [contract workspace test log](evidence/rust-contract-20260913/test.log).
The tests exercise full zone/RRset/registration limits,
per-grant and global nonce limits, challenge rejection without nonce loss,
partial operator-write rollback, quota reuse, legacy sealed-recovery refusal,
and maintenance expiry while historical scans are forbidden. A 1,024-active,
2,048-historical fixture expires every active registration with one removal scan
and one signing-read scan for its zone. The same log records 11 passing CCF
adapter regression tests, including permanent transfer revocation and
replacement-key continuity.

`resign_zone` emits a JSON diagnostic line around the actual DNSSEC signing
call, including initial signing: `event=agentdns.dnssec.signing`, `zone`, `serial`,
`record_count`, and monotonic `elapsed_micros`. The measurement includes the
DNSSEC library's signing/denial construction call, excludes preceding storage
reads and subsequent writes, and is emitted only after success. This timing is
never replicated, used for security decisions, or presented as a ledger proof.
Native CCF/SNP runtime logs can supply platform-specific measurements. The
admission tests do not establish a worst-case real-time latency guarantee;
configured limits should be lowered if platform measurements require it.

Authenticated failed-request observations add at most one diagnostic per outstanding nonce. Success, expiry and epoch invalidation remove that diagnostic together with the nonce. GET reconciliation scans only the bounded nonce collection; successful historical results retain point lookups and take precedence. See [request-reconciliation.md](request-reconciliation.md) for pending/failed semantics and retention.
