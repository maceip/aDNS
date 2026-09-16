use adns_storage::{Collection, Entries, ReadTx, StorageError, VersionedValue, WriteTx};
use std::pin::Pin;

// SAFETY: CcfTx is a stack-owned, non-copyable C++ wrapper over the endpoint's
// live CCF transaction. cxx synchronously borrows it and copies all KV buffers.
// C++ functions never retain slices, strings or callbacks into these borrows.
#[cxx::bridge(namespace = "adns::ffi")]
mod ffi {
    struct Entry {
        present: bool,
        version: u64,
        bytes: Vec<u8>,
    }
    struct KeyEntry {
        key: Vec<u8>,
        value: Entry,
    }
    struct DiagnosticSpan {
        name: String,
        start_unix_ns: u64,
        end_unix_ns: u64,
        parent_index: i32,
        outcome: u8,
    }
    struct Response {
        status: u16,
        body: Vec<u8>,
        content_type: String,
        apply_writes: bool,
        original_version: u64,
        changed_zones: Vec<String>,
        claims_digest: Vec<u8>,
        commit_error: bool,
        promote_status_on_commit: bool,
        diagnostic_spans: Vec<DiagnosticSpan>,
    }
    unsafe extern "C++" {
        include!("adns-ccf/ccf_tx.h");
        type CcfTx;
        fn get(self: &CcfTx, table: u8, key: &[u8]) -> Result<Entry>;
        fn scan_prefix(self: &CcfTx, table: u8, prefix: &[u8]) -> Result<Vec<KeyEntry>>;
        fn put(self: Pin<&mut CcfTx>, table: u8, key: &[u8], value: &[u8]) -> Result<()>;
        fn remove(self: Pin<&mut CcfTx>, table: u8, key: &[u8]) -> Result<()>;
    }
    extern "Rust" {
        fn handle_mutation(
            tx: Pin<&mut CcfTx>,
            method: &str,
            path: &str,
            body: &[u8],
            now: u64,
        ) -> Response;
        fn handle_read(tx: Pin<&mut CcfTx>, path: &str, query: &str, now: u64) -> Response;
        fn handle_maintenance(tx: Pin<&mut CcfTx>, now: u64) -> Response;
        fn handle_transfer(tx: Pin<&mut CcfTx>, body: &[u8], now: u64) -> Response;
        fn handle_secondary_requests(tx: Pin<&mut CcfTx>, body: &[u8], now: u64) -> Response;
        fn handle_secondary_response(tx: Pin<&mut CcfTx>, body: &[u8], now: u64) -> Response;
        fn handle_udp(tx: Pin<&mut CcfTx>, body: &[u8], now: u64) -> Response;
        fn handle_doh(
            tx: Pin<&mut CcfTx>,
            method: &str,
            query: &str,
            body: &[u8],
            now: u64,
        ) -> Response;
        fn handle_transfer_key(tx: Pin<&mut CcfTx>, body: &[u8]) -> Response;
        fn handle_ksk_receipt(tx: Pin<&mut CcfTx>, query: &str, now: u64) -> Response;
        fn handle_receipt_read(tx: Pin<&mut CcfTx>, path: &str, query: &str, now: u64) -> Response;
    }
}
struct Adapter<'a> {
    inner: Pin<&'a mut ffi::CcfTx>,
}
fn table_id(table: Collection) -> u8 {
    match table {
        Collection::Zones => 0,
        Collection::Records => 1,
        Collection::Registrations => 2,
        Collection::Grants => 3,
        Collection::Nonces => 4,
        Collection::RequestResults => 5,
        Collection::AcmeChallenges => 6,
        Collection::Policies => 7,
        Collection::Lifecycle => 8,
        Collection::SecondaryStatus => 9,
        Collection::PrivateKeys => 10,
        Collection::TsigSecrets => 11,
    }
}
fn error(e: cxx::Exception) -> StorageError {
    StorageError::Backend(e.to_string())
}
impl ReadTx for Adapter<'_> {
    fn get(&self, t: Collection, k: &[u8]) -> adns_storage::Result<Option<VersionedValue>> {
        let value = self
            .inner
            .as_ref()
            .get_ref()
            .get(table_id(t), k)
            .map_err(error)?;
        Ok(value.present.then_some(VersionedValue {
            version: value.version,
            bytes: value.bytes,
        }))
    }
    fn scan_prefix(&self, t: Collection, p: &[u8]) -> adns_storage::Result<Entries> {
        Ok(self
            .inner
            .as_ref()
            .get_ref()
            .scan_prefix(table_id(t), p)
            .map_err(error)?
            .into_iter()
            .map(|e| {
                (
                    e.key,
                    VersionedValue {
                        version: e.value.version,
                        bytes: e.value.bytes,
                    },
                )
            })
            .collect())
    }
}
impl WriteTx for Adapter<'_> {
    fn put(&mut self, t: Collection, k: Vec<u8>, v: Vec<u8>) -> adns_storage::Result<()> {
        self.inner.as_mut().put(table_id(t), &k, &v).map_err(error)
    }
    fn remove(&mut self, t: Collection, k: &[u8]) -> adns_storage::Result<()> {
        self.inner.as_mut().remove(table_id(t), k).map_err(error)
    }
}
fn diagnosed(
    name: adns_telemetry::Name,
    operation: impl FnOnce() -> ffi::Response,
) -> ffi::Response {
    let scope = adns_telemetry::RequestScope::new();
    let mut span = adns_telemetry::Span::start(name);
    let mut response = operation();
    span.set_success(response.status < 400);
    drop(span);
    response.diagnostic_spans = scope
        .finish()
        .into_iter()
        .map(|span| ffi::DiagnosticSpan {
            name: span.name.as_str().into(),
            start_unix_ns: span.start_unix_ns,
            end_unix_ns: span.end_unix_ns,
            parent_index: span.parent_index,
            outcome: span.outcome,
        })
        .collect();
    response
}

fn json_response(
    result: adns_server::Result<adns_server::AppResponse>,
    write: bool,
) -> ffi::Response {
    match result {
        Ok(result) => ffi::Response {
            status: result.http_status,
            body: result.body.to_string().into_bytes(),
            content_type: "application/json".into(),
            apply_writes: write,
            original_version: result.original_version.unwrap_or(0),
            changed_zones: result.changed_zones,
            claims_digest: result.claims_digest.map_or(Vec::new(), |d| d.to_vec()),
            commit_error: result.commit_error,
            promote_status_on_commit: result.promote_status_on_commit,
            diagnostic_spans: Vec::new(),
        },
        Err(e) => ffi::Response {
            status: e.http_status(),
            body: serde_json::json!({"error":e.to_string()})
                .to_string()
                .into_bytes(),
            content_type: "application/json".into(),
            apply_writes: false,
            original_version: 0,
            changed_zones: Vec::new(),
            claims_digest: Vec::new(),
            commit_error: false,
            promote_status_on_commit: false,
            diagnostic_spans: Vec::new(),
        },
    }
}
fn handle_mutation(
    tx: Pin<&mut ffi::CcfTx>,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> ffi::Response {
    diagnosed(adns_telemetry::Name::Application, || {
        json_response(
            adns_server::mutate_observed(&mut Adapter { inner: tx }, method, path, body, now),
            true,
        )
    })
}
fn handle_read(tx: Pin<&mut ffi::CcfTx>, path: &str, query: &str, now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::Read, || {
        let result = crate::query_pairs(query)
            .and_then(|query| adns_server::read_json(&Adapter { inner: tx }, path, &query, now));
        json_response(result, false)
    })
}
fn handle_maintenance(tx: Pin<&mut ffi::CcfTx>, now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::Maintenance, || {
        json_response(
            crate::governed_maintenance(&mut Adapter { inner: tx }, now).map(|zones| {
                let mut response = adns_server::AppResponse::new(
                    serde_json::json!({"status":"pending","maintained_at":now}),
                );
                response.changed_zones = zones;
                response
            }),
            true,
        )
    })
}
fn handle_transfer(tx: Pin<&mut ffi::CcfTx>, body: &[u8], now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::Transfer, || {
        match crate::transfer(&Adapter { inner: tx }, body, now) {
            Ok(body) => ffi::Response {
                status: 200,
                body,
                content_type: "application/octet-stream".into(),
                apply_writes: false,
                original_version: 0,
                changed_zones: Vec::new(),
                claims_digest: Vec::new(),
                commit_error: false,
                promote_status_on_commit: false,
                diagnostic_spans: Vec::new(),
            },
            Err(e) => json_response(Err(e), false),
        }
    })
}
fn handle_transfer_key(tx: Pin<&mut ffi::CcfTx>, body: &[u8]) -> ffi::Response {
    diagnosed(adns_telemetry::Name::TransferKey, || {
        json_response(
            crate::provision_transfer_key(&mut Adapter { inner: tx }, body),
            true,
        )
    })
}
fn handle_receipt_read(
    tx: Pin<&mut ffi::CcfTx>,
    path: &str,
    query: &str,
    now: u64,
) -> ffi::Response {
    diagnosed(adns_telemetry::Name::ReceiptClaims, || {
        json_response(
            crate::receipt_read(&mut Adapter { inner: tx }, path, query, now),
            true,
        )
    })
}
fn handle_ksk_receipt(tx: Pin<&mut ffi::CcfTx>, query: &str, now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::ReceiptClaims, || {
        json_response(
            crate::ksk_receipt_claims(&mut Adapter { inner: tx }, query, now),
            true,
        )
    })
}

fn handle_secondary_requests(tx: Pin<&mut ffi::CcfTx>, body: &[u8], now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::SecondaryRequests, || {
        json_response(
            crate::secondary_requests(&mut Adapter { inner: tx }, body, now),
            true,
        )
    })
}
fn handle_secondary_response(tx: Pin<&mut ffi::CcfTx>, body: &[u8], now: u64) -> ffi::Response {
    diagnosed(adns_telemetry::Name::SecondaryResponse, || {
        json_response(
            crate::secondary_response(&mut Adapter { inner: tx }, body, now),
            true,
        )
    })
}

fn handle_udp(tx: Pin<&mut ffi::CcfTx>, body: &[u8], now: u64) -> ffi::Response {
    diagnosed(
        adns_telemetry::Name::Transfer,
        || match crate::transfer_datagram(&Adapter { inner: tx }, body, now) {
            Ok(body) => ffi::Response {
                status: 200,
                body,
                content_type: "application/octet-stream".into(),
                apply_writes: false,
                original_version: 0,
                changed_zones: Vec::new(),
                claims_digest: Vec::new(),
                commit_error: false,
                promote_status_on_commit: false,
                diagnostic_spans: Vec::new(),
            },
            Err(e) => json_response(Err(e), false),
        },
    )
}

fn handle_doh(
    tx: Pin<&mut ffi::CcfTx>,
    method: &str,
    query: &str,
    body: &[u8],
    now: u64,
) -> ffi::Response {
    diagnosed(adns_telemetry::Name::DnsQuery, || {
        match crate::doh(&Adapter { inner: tx }, method, query, body, now) {
            Ok(body) => ffi::Response {
                status: 200,
                body,
                content_type: "application/dns-message".into(),
                apply_writes: false,
                original_version: 0,
                changed_zones: Vec::new(),
                claims_digest: Vec::new(),
                commit_error: false,
                promote_status_on_commit: false,
                diagnostic_spans: Vec::new(),
            },
            Err(e) => json_response(Err(e), false),
        }
    })
}
