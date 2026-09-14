//! RFC 8945 authentication and RFC 5936 stream framing. Secrets stay with caller.
#![forbid(unsafe_code)]
use adns_wire::{Header, Message, RecordClass, RecordType, ResourceRecord, WireName};
use ring::hmac;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("malformed DNS transfer request")]
    Malformed,
    #[error("transfer key is not authorized")]
    BadKey,
    #[error("invalid transfer authenticator")]
    BadSignature,
    #[error("TSIG time outside permitted window")]
    BadTime,
    #[error("wire encoding failed: {0}")]
    Wire(String),
}
pub const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TRANSFER_MESSAGES: usize = 4096;

type Result<T> = std::result::Result<T, TransferError>;
#[derive(Clone)]
pub struct TsigKey {
    pub name: WireName,
    secret: Vec<u8>,
}
impl TsigKey {
    pub fn new(name: WireName, secret: Vec<u8>) -> Result<Self> {
        if !(32..=128).contains(&secret.len()) {
            return Err(TransferError::BadKey);
        }
        Ok(Self { name, secret })
    }
    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &self.secret)
    }
}
#[derive(Clone, Debug)]
pub struct AuthenticatedQuery {
    pub message: Message,
    pub request_mac: Vec<u8>,
}
fn u16_at(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        b.get(p..p + 2)
            .ok_or(TransferError::Malformed)?
            .try_into()
            .map_err(|_| TransferError::Malformed)?,
    ))
}
fn time_bytes(t: u64) -> Result<[u8; 6]> {
    if t >> 48 != 0 {
        return Err(TransferError::BadTime);
    }
    t.to_be_bytes()[2..]
        .try_into()
        .map_err(|_| TransferError::BadTime)
}
fn variables(key: &TsigKey, time: u64, fudge: u16, timers_only: bool) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    if !timers_only {
        b.extend(key.name.as_slice());
        b.extend(255u16.to_be_bytes());
        b.extend(0u32.to_be_bytes());
        b.extend(b"\x0bhmac-sha256\x00");
    }
    b.extend(time_bytes(time)?);
    b.extend(fudge.to_be_bytes());
    if !timers_only {
        b.extend([0; 4]);
    }
    Ok(b)
}
fn continuation_without_prior(prior: Option<&[u8]>, continuation: bool) -> bool {
    (continuation && prior.is_none()) || prior.is_some_and(|mac| mac.len() != 32)
}

fn mac_input(
    unsigned: &[u8],
    key: &TsigKey,
    time: u64,
    fudge: u16,
    prior: Option<&[u8]>,
    timers_only: bool,
) -> Result<Vec<u8>> {
    if continuation_without_prior(prior, timers_only) {
        return Err(TransferError::Malformed);
    }
    let mut b = Vec::with_capacity(unsigned.len() + 512);
    if let Some(mac) = prior {
        b.extend(
            u16::try_from(mac.len())
                .map_err(|_| TransferError::Malformed)?
                .to_be_bytes(),
        );
        b.extend(mac);
    }
    b.extend(unsigned);
    b.extend(variables(key, time, fudge, timers_only)?);
    Ok(b)
}
/// Signs a request or one response. First response includes full TSIG variables;
/// subsequent TCP response messages include only Time Signed and Fudge.
pub fn sign_message(
    unsigned: &[u8],
    key: &TsigKey,
    time: u64,
    prior: Option<&[u8]>,
    continuation: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if !(12..=65535).contains(&unsigned.len()) || continuation_without_prior(prior, continuation) {
        return Err(TransferError::Malformed);
    }
    let mac = hmac::sign(
        &key.key(),
        &mac_input(unsigned, key, time, 300, prior, continuation)?,
    )
    .as_ref()
    .to_vec();
    let mut data = Vec::new();
    data.extend(b"\x0bhmac-sha256\x00");
    data.extend(time_bytes(time)?);
    data.extend(300u16.to_be_bytes());
    data.extend(32u16.to_be_bytes());
    data.extend(&mac);
    data.extend(&unsigned[0..2]);
    data.extend([0; 4]);
    let mut out = unsigned.to_vec();
    let ar = u16_at(unsigned, 10)?
        .checked_add(1)
        .ok_or(TransferError::Malformed)?;
    out[10..12].copy_from_slice(&ar.to_be_bytes());
    out.extend(key.name.as_slice());
    out.extend(250u16.to_be_bytes());
    out.extend(255u16.to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend((data.len() as u16).to_be_bytes());
    out.extend(data);
    if out.len() > 65535 {
        return Err(TransferError::Malformed);
    }
    Ok((out, mac))
}
/// Verifies the raw packet, preserving original compression and header bytes.
pub fn verify_message(
    packet: &[u8],
    key: &TsigKey,
    now: u64,
    prior: Option<&[u8]>,
    continuation: bool,
) -> Result<AuthenticatedQuery> {
    if packet.len() < 12 || packet.len() > 65535 || continuation_without_prior(prior, continuation)
    {
        return Err(TransferError::Malformed);
    }
    let counts = [
        u16_at(packet, 4)?,
        u16_at(packet, 6)?,
        u16_at(packet, 8)?,
        u16_at(packet, 10)?,
    ];
    if counts[3] == 0 {
        return Err(TransferError::BadSignature);
    }
    let mut p = 12;
    for _ in 0..counts[0] {
        WireName::parse_wire(packet, &mut p).map_err(|_| TransferError::Malformed)?;
        p = p
            .checked_add(4)
            .filter(|p| *p <= packet.len())
            .ok_or(TransferError::Malformed)?;
    }
    let total = counts[1] as usize + counts[2] as usize + counts[3] as usize;
    let mut tsig_start = 0;
    let mut tsig_data = 0;
    let mut tsig_name = None;
    for i in 0..total {
        let start = p;
        let name = WireName::parse_wire(packet, &mut p).map_err(|_| TransferError::Malformed)?;
        let rt = u16_at(packet, p)?;
        let class = u16_at(packet, p + 2)?;
        let ttl = packet.get(p + 4..p + 8).ok_or(TransferError::Malformed)?;
        let len = u16_at(packet, p + 8)? as usize;
        p += 10;
        if rt == 250 {
            if i + 1 != total || class != 255 || ttl != [0, 0, 0, 0] {
                return Err(TransferError::Malformed);
            }
            tsig_start = start;
            tsig_data = p;
            tsig_name = Some(name);
        }
        p = p
            .checked_add(len)
            .filter(|p| *p <= packet.len())
            .ok_or(TransferError::Malformed)?;
    }
    if p != packet.len() {
        return Err(TransferError::Malformed);
    }
    if tsig_name != Some(key.name) {
        return Err(TransferError::BadKey);
    }
    let mut q = tsig_data;
    let algo = WireName::parse_wire(packet, &mut q).map_err(|_| TransferError::Malformed)?;
    // Compression is forbidden in the algorithm field. Canonicalization is
    // case-insensitive, so uppercase uncompressed spellings remain valid.
    let algorithm_wire = packet.get(tsig_data..q).ok_or(TransferError::Malformed)?;
    if algo.as_slice() != b"\x0bhmac-sha256\x00"
        || algorithm_wire.len() != algo.as_slice().len()
        || !algorithm_wire
            .iter()
            .zip(algo.as_slice())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    {
        return Err(TransferError::BadKey);
    }
    let rawtime = packet.get(q..q + 6).ok_or(TransferError::Malformed)?;
    let mut tb = [0; 8];
    tb[2..].copy_from_slice(rawtime);
    let time = u64::from_be_bytes(tb);
    q += 6;
    let fudge = u16_at(packet, q)?;
    q += 2;
    let maclen = u16_at(packet, q)? as usize;
    q += 2;
    if maclen != 32 {
        return Err(TransferError::BadSignature);
    }
    let mac = packet.get(q..q + maclen).ok_or(TransferError::Malformed)?;
    q += maclen;
    let original_id = u16_at(packet, q)?;
    let error = u16_at(packet, q + 2)?;
    let other = u16_at(packet, q + 4)?;
    q += 6;
    if q != packet.len() || error != 0 || other != 0 || original_id != u16_at(packet, 0)? {
        return Err(TransferError::Malformed);
    }
    let mut unsigned = packet[..tsig_start].to_vec();
    unsigned[10..12].copy_from_slice(&(counts[3] - 1).to_be_bytes());
    unsigned[..2].copy_from_slice(&original_id.to_be_bytes());
    hmac::verify(
        &key.key(),
        &mac_input(&unsigned, key, time, fudge, prior, continuation)?,
        mac,
    )
    .map_err(|_| TransferError::BadSignature)?;
    if fudge > 300 || now.abs_diff(time) > fudge as u64 {
        return Err(TransferError::BadTime);
    }
    let message = Message::parse(&unsigned).map_err(|e| TransferError::Wire(e.to_string()))?;
    Ok(AuthenticatedQuery {
        message,
        request_mac: mac.to_vec(),
    })
}
pub fn verify_request(packet: &[u8], key: &TsigKey, now: u64) -> Result<AuthenticatedQuery> {
    let q = verify_message(packet, key, now, None, false)?;
    if q.message.header.flags & !0x0130 != 0
        || q.message.questions.len() != 1
        || !q.message.answers.is_empty()
    {
        return Err(TransferError::Malformed);
    }
    let question = &q.message.questions[0];
    if question.qclass != RecordClass::In
        || !matches!(
            question.qtype,
            RecordType::Soa | RecordType::Axfr | RecordType::Ixfr
        )
    {
        return Err(TransferError::Malformed);
    }
    if question.qtype == RecordType::Ixfr {
        if q.message.authorities.len() != 1
            || q.message.authorities[0].name != question.name
            || q.message.authorities[0].rclass != RecordClass::In
            || !matches!(q.message.authorities[0].rdata, adns_wire::RData::Soa(_))
        {
            return Err(TransferError::Malformed);
        }
    } else if !q.message.authorities.is_empty() {
        return Err(TransferError::Malformed);
    }
    Ok(q)
}
/// A complete snapshot is captured before iteration. Start/end SOA must be identical.
/// Every response is authenticated; first and last signatures cannot be omitted.
pub fn axfr_messages(
    query: &AuthenticatedQuery,
    origin: &WireName,
    records: &[ResourceRecord],
    key: &TsigKey,
    now: u64,
    max_message: usize,
) -> Result<Vec<Vec<u8>>> {
    let question = query
        .message
        .questions
        .first()
        .ok_or(TransferError::Malformed)?;
    if question.name != *origin
        || !matches!(question.qtype, RecordType::Axfr | RecordType::Ixfr)
        || question.qclass != RecordClass::In
        || !(512..=64000).contains(&max_message)
    {
        return Err(TransferError::Malformed);
    }
    let soa = records
        .iter()
        .find(|r| r.name == *origin && r.rtype == RecordType::Soa)
        .ok_or(TransferError::Malformed)?;
    if records
        .iter()
        .filter(|r| r.rtype == RecordType::Soa)
        .count()
        != 1
        || records.iter().any(|r| !r.name.is_subdomain_of(origin))
    {
        return Err(TransferError::Malformed);
    }
    if question.qtype == RecordType::Ixfr {
        let current = match &soa.rdata {
            adns_wire::RData::Soa(s) => s.serial,
            _ => return Err(TransferError::Malformed),
        };
        let previous = match query.message.authorities.first().map(|r| &r.rdata) {
            Some(adns_wire::RData::Soa(s)) => s.serial,
            _ => return Err(TransferError::Malformed),
        };
        // RFC 1995 section 3: current clients receive one SOA. A client with an
        // older serial receives the permitted full-zone AXFR fallback. Serial
        // arithmetic follows RFC 1982, including wraparound.
        let delta = current.wrapping_sub(previous);
        if delta == 0x8000_0000 {
            return Err(TransferError::Malformed);
        }
        if delta == 0 || delta > 0x8000_0000 {
            let message = Message {
                header: Header {
                    id: query.message.header.id,
                    flags: 0x8400,
                },
                questions: vec![question.clone()],
                answers: vec![soa.clone()],
                ..Message::default()
            };
            return Ok(vec![
                sign_message(
                    &message
                        .to_wire()
                        .map_err(|e| TransferError::Wire(e.to_string()))?,
                    key,
                    now,
                    Some(&query.request_mac),
                    false,
                )?
                .0,
            ]);
        }
    }
    let overhead = key.name.as_slice().len() + 71;
    let mut result = Vec::new();
    let mut total_bytes = 0usize;
    let mut prior = query.request_mac.clone();
    let mut msg = Message {
        header: Header {
            id: query.message.header.id,
            flags: 0x8400,
        },
        questions: vec![question.clone()],
        ..Message::default()
    };
    let mut size = 12 + question.name.as_slice().len() + 4 + overhead;
    // Pack using each RR's uncompressed upper bound; compression can only
    // shrink a packet. Encode each completed message once, rather than encoding
    // the growing packet for every record (quadratic cost on large RRsets).
    let stream = std::iter::once(soa)
        .chain(records.iter().filter(|r| r.rtype != RecordType::Soa))
        .chain(std::iter::once(soa));
    for rr in stream {
        let rr_size = rr
            .canonical_wire()
            .map_err(|e| TransferError::Wire(e.to_string()))?
            .len();
        if size.saturating_add(rr_size) > max_message {
            if msg.answers.is_empty() {
                return Err(TransferError::Malformed);
            }
            let (signed, mac) = sign_message(
                &msg.to_wire()
                    .map_err(|e| TransferError::Wire(e.to_string()))?,
                key,
                now,
                Some(&prior),
                !result.is_empty(),
            )?;
            append_bounded(&mut result, &mut total_bytes, signed)?;
            prior = mac;
            msg.questions.clear();
            msg.answers.clear();
            size = 12 + overhead;
            if size.saturating_add(rr_size) > max_message {
                return Err(TransferError::Malformed);
            }
        }
        msg.answers.push(rr.clone());
        size += rr_size;
    }
    if !msg.answers.is_empty() {
        let (signed, _) = sign_message(
            &msg.to_wire()
                .map_err(|e| TransferError::Wire(e.to_string()))?,
            key,
            now,
            Some(&prior),
            !result.is_empty(),
        )?;
        append_bounded(&mut result, &mut total_bytes, signed)?;
    }
    Ok(result)
}
fn append_bounded(messages: &mut Vec<Vec<u8>>, bytes: &mut usize, packet: Vec<u8>) -> Result<()> {
    let size = bytes
        .checked_add(packet.len())
        .and_then(|n| n.checked_add(2))
        .ok_or(TransferError::Malformed)?;
    if size > MAX_TRANSFER_BYTES || messages.len() >= MAX_TRANSFER_MESSAGES {
        return Err(TransferError::Malformed);
    }
    *bytes = size;
    messages.push(packet);
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecondaryState {
    pub endpoint: String,
    pub last_notified_serial: Option<u32>,
    pub last_observed_serial: Option<u32>,
    pub last_observed_at: Option<u64>,
}
impl SecondaryState {
    pub fn notified(&mut self, serial: u32) {
        self.last_notified_serial = Some(serial);
    }
    pub fn observed(&mut self, serial: u32, now: u64) {
        self.last_observed_serial = Some(serial);
        self.last_observed_at = Some(now);
    }
    pub fn in_sync(&self, committed_serial: u32, now: u64, max_age: u64) -> bool {
        self.last_observed_serial == Some(committed_serial)
            && self
                .last_observed_at
                .is_some_and(|t| t <= now && now - t <= max_age)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use adns_wire::Question;
    fn query() -> Message {
        Message {
            header: Header { id: 123, flags: 0 },
            questions: vec![Question {
                name: "example.".parse().unwrap(),
                qtype: RecordType::Axfr,
                qclass: RecordClass::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }
    #[test]
    fn request_authentication_and_tcp_chain() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        let wire = query().to_wire().unwrap();
        let (signed, request_mac) = sign_message(&wire, &key, 100, None, false).unwrap();
        assert!(verify_request(&signed, &key, 101).is_ok());
        assert!(matches!(
            verify_request(&signed, &key, 1000),
            Err(TransferError::BadTime)
        ));
        let mut corrupt = signed;
        corrupt[20] ^= 1;
        assert!(verify_request(&corrupt, &key, 100).is_err());
        let mut response = query();
        response.header.flags = 0x8400;
        let (first, mac) = sign_message(
            &response.to_wire().unwrap(),
            &key,
            100,
            Some(&request_mac),
            false,
        )
        .unwrap();
        assert!(verify_message(&first, &key, 100, Some(&request_mac), false).is_ok());
        let (second, _) =
            sign_message(&response.to_wire().unwrap(), &key, 100, Some(&mac), true).unwrap();
        assert!(verify_message(&second, &key, 100, Some(&mac), true).is_ok());
        assert!(verify_message(&second, &key, 100, Some(&request_mac), true).is_err());
    }
    #[test]
    fn request_fields_and_chaining_prerequisites_are_checked() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        let valid = query().to_wire().unwrap();
        for (prior, continuation) in [(None, true), (Some(&[1u8; 31][..]), false)] {
            assert!(sign_message(&valid, &key, 100, prior, continuation).is_err());
            assert!(verify_message(&valid, &key, 100, prior, continuation).is_err());
        }
        for flags in [0x8000, 0x7800, 0x0400, 0x0200, 0x0080, 0x0040, 0x0001] {
            let mut message = query();
            message.header.flags = flags;
            let (signed, _) =
                sign_message(&message.to_wire().unwrap(), &key, 100, None, false).unwrap();
            assert!(
                verify_request(&signed, &key, 100).is_err(),
                "flags {flags:x}"
            );
        }
        let mut message = query();
        message.header.flags = 0x0130;
        let (signed, _) =
            sign_message(&message.to_wire().unwrap(), &key, 100, None, false).unwrap();
        assert!(verify_request(&signed, &key, 100).is_ok());
        for class in [RecordClass::None, RecordClass::Any, RecordClass::Unknown(3)] {
            message.questions[0].qclass = class;
            let (signed, _) =
                sign_message(&message.to_wire().unwrap(), &key, 100, None, false).unwrap();
            assert!(verify_request(&signed, &key, 100).is_err());
        }
    }
    #[test]
    fn algorithm_spelling_is_case_insensitive_but_uncompressed() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        let valid = query().to_wire().unwrap();
        let (mut signed, _) = sign_message(&valid, &key, 100, None, false).unwrap();
        let start = valid.len() + key.name.as_slice().len() + 10;
        signed[start + 1..start + 12].make_ascii_uppercase();
        assert!(verify_request(&signed, &key, 100).is_ok());
        // Put the algorithm label in an earlier question and compress to it.
        // TSIG variables are unchanged, but RFC 8945 forbids this encoding.
        let mut message = query();
        message.questions[0].name = "hmac-sha256.".parse().unwrap();
        let valid = message.to_wire().unwrap();
        let (mut signed, _) = sign_message(&valid, &key, 100, None, false).unwrap();
        let start = valid.len() + key.name.as_slice().len() + 10;
        let len = u16::from_be_bytes(signed[start - 2..start].try_into().unwrap());
        signed[start - 2..start].copy_from_slice(&(len - 11).to_be_bytes());
        signed.splice(start..start + 13, [0xc0, 12]);
        assert!(matches!(
            verify_request(&signed, &key, 100),
            Err(TransferError::BadKey)
        ));
    }
    #[test]
    fn aggregate_transfer_limits_are_enforced_during_construction() {
        let mut messages = Vec::new();
        let mut bytes = MAX_TRANSFER_BYTES - 14;
        append_bounded(&mut messages, &mut bytes, vec![0; 12]).unwrap();
        assert_eq!(bytes, MAX_TRANSFER_BYTES);
        assert!(append_bounded(&mut messages, &mut bytes, vec![0; 12]).is_err());
        assert_eq!(messages.len(), 1);
        let mut messages = vec![vec![]; MAX_TRANSFER_MESSAGES];
        assert!(append_bounded(&mut messages, &mut 0, vec![0; 12]).is_err());
    }
    #[test]
    fn notification_is_not_observation() {
        let mut s = SecondaryState::default();
        s.notified(4);
        assert!(!s.in_sync(4, 100, 60));
        s.observed(4, 100);
        assert!(s.in_sync(4, 120, 60));
        assert!(!s.in_sync(5, 120, 60));
        assert!(!s.in_sync(4, 161, 60));
    }
}

#[cfg(test)]
mod ixfr_tests {
    use super::*;
    use adns_wire::{Question, RData, SoaData};
    fn soa(serial: u32) -> ResourceRecord {
        ResourceRecord::new(
            "example.".parse().unwrap(),
            300,
            RData::Soa(SoaData {
                mname: "ns.example.".parse().unwrap(),
                rname: "hostmaster.example.".parse().unwrap(),
                serial,
                refresh: 5,
                retry: 2,
                expire: 3600,
                minimum: 60,
            }),
        )
        .unwrap()
    }
    #[test]
    fn ixfr_serial_arithmetic_handles_wraparound_and_undefined_distance() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        for (current, previous, expected) in [
            (0, u32::MAX, Some(2)),
            (u32::MAX, 0, Some(1)),
            (10, 10, Some(1)),
            (0, 0x8000_0000, None),
        ] {
            let query = Message {
                header: Header { id: 123, flags: 0 },
                questions: vec![Question {
                    name: "example.".parse().unwrap(),
                    qtype: RecordType::Ixfr,
                    qclass: RecordClass::In,
                }],
                authorities: vec![soa(previous)],
                ..Message::default()
            };
            let signed = sign_message(&query.to_wire().unwrap(), &key, 100, None, false)
                .unwrap()
                .0;
            let authenticated = verify_request(&signed, &key, 100).unwrap();
            let result = axfr_messages(
                &authenticated,
                &"example.".parse().unwrap(),
                &[soa(current)],
                &key,
                100,
                512,
            );
            if let Some(count) = expected {
                let packets = result.unwrap();
                let response = verify_message(
                    &packets[0],
                    &key,
                    100,
                    Some(&authenticated.request_mac),
                    false,
                )
                .unwrap();
                assert_eq!(response.message.answers.len(), count);
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn packing_stays_bounded_and_preserves_authenticated_snapshot_order() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        let query = Message {
            header: Header { id: 123, flags: 0 },
            questions: vec![Question {
                name: "example.".parse().unwrap(),
                qtype: RecordType::Axfr,
                qclass: RecordClass::In,
            }],
            ..Message::default()
        };
        let signed = sign_message(&query.to_wire().unwrap(), &key, 100, None, false)
            .unwrap()
            .0;
        let authenticated = verify_request(&signed, &key, 100).unwrap();
        let mut zone = vec![soa(7)];
        for i in 0..100 {
            zone.push(
                ResourceRecord::new(
                    format!("record{i}.example.").parse().unwrap(),
                    300,
                    RData::Txt(vec![vec![b'x'; 200]]),
                )
                .unwrap(),
            );
        }
        let packets = axfr_messages(
            &authenticated,
            &"example.".parse().unwrap(),
            &zone,
            &key,
            100,
            512,
        )
        .unwrap();
        assert!(packets.len() > 10);
        let mut prior = authenticated.request_mac;
        let mut records = Vec::new();
        for (i, packet) in packets.iter().enumerate() {
            assert!(packet.len() <= 512);
            let response = verify_message(packet, &key, 100, Some(&prior), i > 0).unwrap();
            assert_eq!(response.message.questions.len(), usize::from(i == 0));
            records.extend(response.message.answers);
            prior = response.request_mac;
        }
        zone.push(soa(7));
        assert_eq!(records, zone);
    }
    #[test]
    fn stock_secondary_ixfr_falls_back_to_authenticated_full_snapshot() {
        let key = TsigKey::new("transfer.".parse().unwrap(), vec![7; 32]).unwrap();
        let mut query = Message {
            header: Header { id: 123, flags: 0 },
            questions: vec![Question {
                name: "example.".parse().unwrap(),
                qtype: RecordType::Ixfr,
                qclass: RecordClass::In,
            }],
            authorities: vec![soa(1)],
            ..Message::default()
        };
        let zone = vec![
            soa(2),
            ResourceRecord::new(
                "mail.example.".parse().unwrap(),
                300,
                RData::A("192.0.2.1".parse().unwrap()),
            )
            .unwrap(),
        ];
        let signed = sign_message(&query.to_wire().unwrap(), &key, 100, None, false)
            .unwrap()
            .0;
        let authenticated = verify_request(&signed, &key, 100).unwrap();
        let packets = axfr_messages(
            &authenticated,
            &"example.".parse().unwrap(),
            &zone,
            &key,
            100,
            512,
        )
        .unwrap();
        let mut mac = authenticated.request_mac;
        let mut answers = vec![];
        for (i, packet) in packets.iter().enumerate() {
            let response = verify_message(packet, &key, 100, Some(&mac), i != 0).unwrap();
            mac = response.request_mac;
            answers.extend(response.message.answers);
        }
        assert_eq!(answers.first(), Some(&soa(2)));
        assert_eq!(answers.last(), Some(&soa(2)));
        assert_eq!(answers.len(), 3);
        query.authorities = vec![soa(2)];
        let signed = sign_message(&query.to_wire().unwrap(), &key, 100, None, false)
            .unwrap()
            .0;
        let authenticated = verify_request(&signed, &key, 100).unwrap();
        let packets = axfr_messages(
            &authenticated,
            &"example.".parse().unwrap(),
            &zone,
            &key,
            100,
            512,
        )
        .unwrap();
        let response = verify_message(
            &packets[0],
            &key,
            100,
            Some(&authenticated.request_mac),
            false,
        )
        .unwrap();
        assert_eq!(response.message.answers, vec![soa(2)]);
        query.authorities.clear();
        let signed = sign_message(&query.to_wire().unwrap(), &key, 100, None, false)
            .unwrap()
            .0;
        assert!(verify_request(&signed, &key, 100).is_err());
    }
}
