#![forbid(unsafe_code)]
//! Algorithm 14 signing and NSEC/NSEC3 authenticated denial proofs.
mod denial;
mod sign;
mod tlsa;
mod zone;
pub use denial::*;
pub use sign::*;
pub use tlsa::*;
pub use zone::*;
#[derive(Debug, thiserror::Error)]
pub enum DnssecError {
    #[error(transparent)]
    Wire(#[from] adns_wire::DnsError),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("invalid DNS RRset")]
    InvalidRrset,
    #[error("invalid DNSSEC signature")]
    InvalidSignature,
    #[error("unsupported DNSSEC algorithm")]
    UnsupportedAlgorithm,
    #[error(
        "signature validity must exceed 300 seconds and be below the serial arithmetic half range"
    )]
    InvalidValidity,
    #[error("invalid NSEC3 parameters")]
    InvalidNsec3Parameters,
    #[error(
        "zone requires exactly one apex SOA, apex NS, consistent TTLs, no CNAME conflicts, and only in-zone IN records"
    )]
    InvalidZone,
    #[error("no applicable denial proof")]
    NoProof,
    #[error("NSEC3 hash collision")]
    HashCollision,
}
