//! RFC 9460 SVCB wire data and a bounded, unescaped token form for registration.
use crate::{DnsError, WireName, hex_decode};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcParam {
    pub key: u16,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcbData {
    pub priority: u16,
    /// Uncompressed DNS name bytes; preserve case for RFC 3597 DNSSEC.
    pub target: Vec<u8>,
    pub params: Vec<SvcParam>,
}
impl SvcbData {
    pub fn validate(&self) -> Result<(), DnsError> {
        validate_target(&self.target)?;
        if self.priority == 0 && !self.params.is_empty() {
            return Err(DnsError::InvalidRdata);
        }
        if self.params.len() > 64 || self.params.windows(2).any(|p| p[0].key >= p[1].key) {
            return Err(DnsError::InvalidRdata);
        }
        for p in &self.params {
            let v = &p.value;
            if v.len() > u16::MAX as usize {
                return Err(DnsError::InvalidRdata);
            }
            match p.key {
                0 => {
                    if v.is_empty() || v.len() % 2 != 0 {
                        return Err(DnsError::InvalidRdata);
                    }
                    let mut last = 0;
                    for k in v.chunks_exact(2) {
                        let key = u16::from_be_bytes([k[0], k[1]]);
                        if key <= last || !self.params.iter().any(|p| p.key == key) {
                            return Err(DnsError::InvalidRdata);
                        }
                        last = key;
                    }
                }
                1 => {
                    if v.is_empty() {
                        return Err(DnsError::InvalidRdata);
                    }
                    let mut rest = v.as_slice();
                    while !rest.is_empty() {
                        let len = usize::from(rest[0]);
                        if len == 0 || len >= rest.len() {
                            return Err(DnsError::InvalidRdata);
                        }
                        rest = &rest[1 + len..];
                    }
                }
                2 if !v.is_empty() || !self.params.iter().any(|p| p.key == 1) => {
                    return Err(DnsError::InvalidRdata);
                }
                3 if v.len() != 2 => return Err(DnsError::InvalidRdata),
                4 if v.is_empty() || v.len() % 4 != 0 => return Err(DnsError::InvalidRdata),
                6 if v.is_empty() || v.len() % 16 != 0 => return Err(DnsError::InvalidRdata),
                65535 => return Err(DnsError::InvalidRdata),
                _ => {}
            }
        }
        Ok(())
    }
    /// `[priority, target, key=value, ...]`; ascending numeric key order.
    /// Known keys use ordinary text. `keyNNNN=lowercasehex` is the binary escape.
    pub fn from_tokens(tokens: &[String]) -> Result<Self, DnsError> {
        if !(2..=66).contains(&tokens.len())
            || tokens
                .iter()
                .any(|s| s.len() > 4096 || !s.bytes().all(|b| (0x21..0x7f).contains(&b)))
        {
            return Err(DnsError::InvalidRdata);
        }
        let priority = tokens[0]
            .parse::<u16>()
            .map_err(|_| DnsError::InvalidRdata)?;
        let target = tokens[1].parse::<WireName>()?;
        if priority.to_string() != tokens[0] || target.to_string() != tokens[1] {
            return Err(DnsError::InvalidRdata);
        }
        let mut params = Vec::new();
        for token in &tokens[2..] {
            let (name, text) = token.split_once('=').unwrap_or((token, ""));
            let key = key_number(name)?;
            let value = if name.starts_with("key") {
                if text.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(DnsError::InvalidRdata);
                }
                hex_decode(text)?
            } else {
                match key {
                    0 => text
                        .split(',')
                        .map(key_number)
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flat_map(u16::to_be_bytes)
                        .collect(),
                    1 => {
                        let mut v = Vec::new();
                        for protocol in text.split(',') {
                            v.push(
                                u8::try_from(protocol.len()).map_err(|_| DnsError::InvalidRdata)?,
                            );
                            v.extend(protocol.as_bytes());
                        }
                        v
                    }
                    2 if text.is_empty() => Vec::new(),
                    3 => text
                        .parse::<u16>()
                        .map_err(|_| DnsError::InvalidRdata)?
                        .to_be_bytes()
                        .to_vec(),
                    4 => text
                        .split(',')
                        .map(|s| {
                            s.parse::<Ipv4Addr>()
                                .map(|a| a.octets())
                                .map_err(|_| DnsError::InvalidRdata)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect(),
                    6 => text
                        .split(',')
                        .map(|s| {
                            s.parse::<Ipv6Addr>()
                                .map(|a| a.octets())
                                .map_err(|_| DnsError::InvalidRdata)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect(),
                    _ => return Err(DnsError::InvalidRdata),
                }
            };
            params.push(SvcParam { key, value });
        }
        let data = Self {
            priority,
            target: target.as_slice().to_vec(),
            params,
        };
        data.validate()?;
        Ok(data)
    }
}
fn key_number(name: &str) -> Result<u16, DnsError> {
    Ok(match name {
        "mandatory" => 0,
        "alpn" => 1,
        "no-default-alpn" => 2,
        "port" => 3,
        "ipv4hint" => 4,
        "ipv6hint" => 6,
        _ => {
            let n = name.strip_prefix("key").ok_or(DnsError::InvalidRdata)?;
            let k = n.parse::<u16>().map_err(|_| DnsError::InvalidRdata)?;
            if k.to_string() != n {
                return Err(DnsError::InvalidRdata);
            }
            k
        }
    })
}

// SVCB names cannot use compression and must not be downcased in canonical
// RDATA (RFC 3597 section 7), unlike the codec's general WireName type.
pub(crate) fn validate_target(bytes: &[u8]) -> Result<(), DnsError> {
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(DnsError::InvalidRdata);
    }
    let mut p = 0;
    loop {
        let len = usize::from(*bytes.get(p).ok_or(DnsError::InvalidRdata)?);
        if len > 63 {
            return Err(DnsError::InvalidRdata);
        }
        p += 1 + len;
        if len == 0 {
            return if p == bytes.len() {
                Ok(())
            } else {
                Err(DnsError::InvalidRdata)
            };
        }
        if p >= bytes.len() {
            return Err(DnsError::InvalidRdata);
        }
    }
}
