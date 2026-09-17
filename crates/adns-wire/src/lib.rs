#![forbid(unsafe_code)]
//! Bounded DNS wire codec. Names are canonical stack values; opaque RDATA can
//! also be inspected without copying with [`RecordView`].
mod codec;
mod encoding;
mod name;
mod svcb;
pub use codec::*;
pub use encoding::*;
pub use name::*;
pub use svcb::*;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("unexpected end of DNS packet")]
    UnexpectedEof,
    #[error("DNS label exceeds 63 octets: {0}")]
    LabelTooLong(usize),
    #[error("DNS name exceeds 255 octets")]
    NameTooLong,
    #[error("invalid DNS packet")]
    InvalidPacket,
    #[error("DNS compression loop or more than 10 pointers")]
    CompressionLoop,
    #[error("invalid domain character or escape")]
    InvalidCharacter,
    #[error("DNS packet exceeds 65535 bytes")]
    PacketTooLong,
    #[error("invalid record data")]
    InvalidRdata,
}
