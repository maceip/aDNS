//! Transport-independent enclave application. All mutation effects remain inside
//! the caller's transaction; only its consensus adapter may report commitment.
#![forbid(unsafe_code)]
pub mod anchors;
mod attempts;
mod limits;
mod service;
mod state;
mod zone;
use adns_storage::StorageError;
pub use attempts::*;
pub use limits::*;
pub use service::*;
pub use state::*;
pub use zone::*;
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Auth(#[from] adns_auth::AuthError),
    #[error(transparent)]
    Attestation(#[from] adns_attest::AttestationError),
    #[error(transparent)]
    Wire(#[from] adns_wire::DnsError),
    #[error("DNSSEC: {0}")]
    Dnssec(String),
    #[error("NOT_FOUND: {0}")]
    NotFound(&'static str),
    #[error("CONFLICT: {0}")]
    Conflict(&'static str),
    #[error("CAPACITY_EXCEEDED: {0}")]
    Capacity(&'static str),
    #[error("INVALID_REQUEST: {0}")]
    Invalid(&'static str),
}
impl AppError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotFound(_) => 404,
            Self::Capacity(_) => 413,
            Self::Conflict(_) | Self::Auth(adns_auth::AuthError::RequestIdConflict) => 409,
            Self::Auth(_) | Self::Attestation(_) => 403,
            Self::Wire(_) | Self::Invalid(_) => 400,
            Self::Storage(_) | Self::Dnssec(_) => 503,
        }
    }
}
pub type Result<T> = std::result::Result<T, AppError>;
mod query;
pub use query::*;
