//! Bounded request-local diagnostics. No exporter, I/O, KV, or borrowed application data.
//! These are execution attempts; only the CCF commit callback may publish committed spans.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const MAX_SPANS: usize = 64;
pub const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name {
    Application,
    Parse,
    Signature,
    Idempotency,
    Nonce,
    Grant,
    Appraisal,
    Cose,
    AmdChain,
    Snp,
    Uvm,
    KeyBinding,
    Admission,
    DnssecSign,
    StorageStage,
    Read,
    Maintenance,
    Transfer,
    SecondaryRequests,
    SecondaryResponse,
    DnsQuery,
    TransferKey,
    ReceiptClaims,
}
impl Name {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "adns.application",
            Self::Parse => "adns.request.parse",
            Self::Signature => "adns.auth.signature",
            Self::Idempotency => "adns.auth.idempotency",
            Self::Nonce => "adns.auth.nonce",
            Self::Grant => "adns.auth.grant",
            Self::Appraisal => "adns.attest.appraise",
            Self::Cose => "adns.attest.cose",
            Self::AmdChain => "adns.attest.amd_chain",
            Self::Snp => "adns.attest.snp_report",
            Self::Uvm => "adns.attest.uvm",
            Self::KeyBinding => "adns.attest.key_binding",
            Self::Admission => "adns.admission",
            Self::DnssecSign => "adns.dnssec.sign",
            Self::StorageStage => "adns.storage.stage",
            Self::Read => "adns.read",
            Self::Maintenance => "adns.maintenance",
            Self::Transfer => "adns.transfer",
            Self::SecondaryRequests => "adns.secondary.requests",
            Self::SecondaryResponse => "adns.secondary.response",
            Self::DnsQuery => "adns.dns.query",
            Self::TransferKey => "adns.transfer.provision",
            Self::ReceiptClaims => "adns.receipt.claims",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticSpan {
    pub name: Name,
    pub start_unix_ns: u64,
    pub end_unix_ns: u64,
    pub parent_index: i32,
    /// 0 unset, 1 successful execution, 2 failed execution; never a commit claim.
    pub outcome: u8,
}
struct Buffer {
    unix_ns: u64,
    started: Instant,
    spans: Vec<DiagnosticSpan>,
    stack: Vec<usize>,
}
impl Buffer {
    fn timestamp(&self) -> u64 {
        self.unix_ns
            .saturating_add(u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }
}
thread_local! {
    static ACTIVE: RefCell<Option<Rc<RefCell<Buffer>>>> = const { RefCell::new(None) };
}

/// !Send request scope; nested scopes restore their parent without mixing span records.
pub struct RequestScope {
    buffer: Rc<RefCell<Buffer>>,
    previous: Option<Rc<RefCell<Buffer>>>,
}
impl Default for RequestScope {
    fn default() -> Self {
        Self::new()
    }
}
impl RequestScope {
    pub fn new() -> Self {
        let unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(0);
        let buffer = Rc::new(RefCell::new(Buffer {
            unix_ns,
            started: Instant::now(),
            spans: Vec::with_capacity(MAX_SPANS),
            stack: Vec::with_capacity(MAX_DEPTH),
        }));
        let previous = ACTIVE
            .try_with(|active| {
                active
                    .try_borrow_mut()
                    .ok()
                    .and_then(|mut active| active.replace(buffer.clone()))
            })
            .ok()
            .flatten();
        Self { buffer, previous }
    }
    pub fn finish(self) -> Vec<DiagnosticSpan> {
        if let Ok(mut buffer) = self.buffer.try_borrow_mut() {
            let end = buffer.timestamp();
            for span in &mut buffer.spans {
                if span.end_unix_ns == 0 {
                    span.end_unix_ns = end;
                    span.outcome = 2;
                }
            }
            buffer.stack.clear();
            std::mem::take(&mut buffer.spans)
        } else {
            Vec::new()
        }
    }
}
impl Drop for RequestScope {
    fn drop(&mut self) {
        let _ = ACTIVE.try_with(|active| {
            if let Ok(mut active) = active.try_borrow_mut() {
                if active.as_ref().is_some_and(|v| Rc::ptr_eq(v, &self.buffer)) {
                    *active = self.previous.take();
                }
            }
        });
    }
}

/// A span accepts only a fixed enum and numerical outcome; no input can become an attribute.
pub struct Span {
    buffer: Option<Rc<RefCell<Buffer>>>,
    index: usize,
    outcome: u8,
}
impl Span {
    pub fn start(name: Name) -> Self {
        let mut span = Self {
            buffer: None,
            index: 0,
            outcome: 2,
        };
        let current = ACTIVE
            .try_with(|active| active.try_borrow().ok().and_then(|v| v.clone()))
            .ok()
            .flatten();
        if let Some(current) = current {
            if let Ok(mut buffer) = current.try_borrow_mut() {
                if buffer.unix_ns != 0
                    && buffer.spans.len() < MAX_SPANS
                    && buffer.stack.len() < MAX_DEPTH
                {
                    let index = buffer.spans.len();
                    let record = DiagnosticSpan {
                        name,
                        start_unix_ns: buffer.timestamp(),
                        end_unix_ns: 0,
                        parent_index: buffer.stack.last().map_or(-1, |v| *v as i32),
                        outcome: 0,
                    };
                    buffer.spans.push(record);
                    buffer.stack.push(index);
                    span.index = index;
                    span.buffer = Some(current.clone());
                }
            }
        }
        span
    }
    pub fn success(&mut self) {
        self.outcome = 1;
    }
    pub fn set_success(&mut self, success: bool) {
        self.outcome = if success { 1 } else { 2 };
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(buffer) = &self.buffer {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                let end = buffer.timestamp();
                if let Some(record) = buffer.spans.get_mut(self.index) {
                    if record.end_unix_ns == 0 {
                        record.end_unix_ns = end;
                        record.outcome = self.outcome;
                    }
                }
                if let Some(position) = buffer.stack.iter().position(|v| *v == self.index) {
                    buffer.stack.truncate(position);
                }
            }
        }
    }
}
pub fn observe<T, E>(name: Name, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let mut span = Span::start(name);
    let result = operation();
    span.set_success(result.is_ok());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolation_parentage_and_unchanged_results() {
        assert_eq!(observe(Name::Signature, || Ok::<_, ()>(42)), Ok(42));
        let scope = RequestScope::new();
        assert_eq!(
            observe(Name::Application, || observe(Name::Signature, || Err::<
                (),
                _,
            >(
                "private error bytes"
            ))),
            Err("private error bytes")
        );
        let spans = scope.finish();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].parent_index, -1);
        assert_eq!(spans[1].parent_index, 0);
        assert!(
            spans
                .iter()
                .all(|s| s.outcome == 2 && s.end_unix_ns >= s.start_unix_ns)
        );
        assert!(!format!("{spans:?}").contains("private error bytes"));
        assert!(RequestScope::new().finish().is_empty());
    }
    #[test]
    fn capacity_and_depth_are_bounded() {
        let scope = RequestScope::new();
        for _ in 0..1000 {
            let _ = observe(Name::Parse, || Ok::<_, ()>(()));
        }
        assert_eq!(scope.finish().len(), MAX_SPANS);
        let scope = RequestScope::new();
        let mut guards = Vec::new();
        for _ in 0..100 {
            guards.push(Span::start(Name::Application));
        }
        while guards.pop().is_some() {}
        assert_eq!(scope.finish().len(), MAX_DEPTH);
    }
    #[test]
    fn unavailable_diagnostic_state_is_a_noop_not_a_business_failure() {
        ACTIVE.with(|active| {
            let _borrow = active.borrow_mut();
            let scope = RequestScope::new();
            assert_eq!(observe(Name::Signature, || Ok::<_, ()>(7)), Ok(7));
            assert!(scope.finish().is_empty());
        });
        assert!(RequestScope::new().finish().is_empty());
    }

    #[test]
    fn nested_requests_threads_and_unwind_do_not_contaminate() {
        let outer = RequestScope::new();
        let _ = observe(Name::Parse, || Ok::<_, ()>(()));
        let inner = RequestScope::new();
        let _ = observe(Name::Signature, || Ok::<_, ()>(()));
        assert_eq!(inner.finish()[0].name, Name::Signature);
        assert!(
            std::thread::spawn(|| RequestScope::new().finish())
                .join()
                .unwrap()
                .is_empty()
        );
        assert_eq!(outer.finish()[0].name, Name::Parse);
        let _ = std::panic::catch_unwind(|| {
            let _scope = RequestScope::new();
            let _span = Span::start(Name::Admission);
            panic!("test failure")
        });
        assert!(RequestScope::new().finish().is_empty());
    }
}
