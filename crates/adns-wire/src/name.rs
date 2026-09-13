use crate::DnsError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{cmp::Ordering, fmt, str::FromStr};

pub const MAX_NAME_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;
pub const MAX_LABELS: usize = 127;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireName {
    octets: [u8; MAX_NAME_LEN],
    len: u8,
    offsets: [u8; MAX_LABELS],
    count: u8,
}
impl WireName {
    pub const fn root() -> Self {
        Self {
            octets: [0; 255],
            len: 1,
            offsets: [0; 127],
            count: 0,
        }
    }
    pub fn from_ascii(text: &str) -> Result<Self, DnsError> {
        if !text.is_ascii() || text.is_empty() {
            return Err(DnsError::InvalidCharacter);
        }
        if text == "." {
            return Ok(Self::root());
        }
        let mut name = Self::root();
        let mut label = [0u8; 63];
        let mut len = 0;
        let mut i = 0;
        let bytes = text.as_bytes();
        while i < bytes.len() {
            let mut b = bytes[i];
            i += 1;
            if b == b'.' {
                if len == 0 {
                    return Err(DnsError::InvalidCharacter);
                }
                name.push_label(&label[..len])?;
                len = 0;
                continue;
            }
            if b == b'\\' {
                b = *bytes.get(i).ok_or(DnsError::InvalidCharacter)?;
                i += 1;
                if b.is_ascii_digit() {
                    let b2 = *bytes.get(i).ok_or(DnsError::InvalidCharacter)?;
                    let b3 = *bytes.get(i + 1).ok_or(DnsError::InvalidCharacter)?;
                    if !b2.is_ascii_digit() || !b3.is_ascii_digit() {
                        return Err(DnsError::InvalidCharacter);
                    }
                    let value = u16::from(b - b'0') * 100
                        + u16::from(b2 - b'0') * 10
                        + u16::from(b3 - b'0');
                    b = u8::try_from(value).map_err(|_| DnsError::InvalidCharacter)?;
                    i += 2;
                }
            } else if !(33..=126).contains(&b) {
                return Err(DnsError::InvalidCharacter);
            }
            if len == 63 {
                return Err(DnsError::LabelTooLong(64));
            }
            label[len] = b;
            len += 1;
        }
        if len != 0 {
            name.push_label(&label[..len])?;
        }
        Ok(name)
    }
    fn push_label(&mut self, label: &[u8]) -> Result<(), DnsError> {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::LabelTooLong(label.len()));
        }
        let start = usize::from(self.len) - 1;
        let end = start + 1 + label.len();
        if end >= 255 || usize::from(self.count) >= MAX_LABELS {
            return Err(DnsError::NameTooLong);
        }
        self.offsets[usize::from(self.count)] = start as u8;
        self.count += 1;
        self.octets[start] = label.len() as u8;
        for (dst, src) in self.octets[start + 1..end].iter_mut().zip(label) {
            *dst = src.to_ascii_lowercase();
        }
        self.octets[end] = 0;
        self.len = (end + 1) as u8;
        Ok(())
    }
    /// Pointer hops are bounded and cycles detected without allocating. On
    /// failure the caller's cursor is unchanged.
    pub fn parse_wire(packet: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let mut name = Self::root();
        let mut pos = *offset;
        let mut end = None;
        let mut visited = [usize::MAX; 10];
        let mut hops = 0;
        loop {
            let b = *packet.get(pos).ok_or(DnsError::UnexpectedEof)?;
            match b & 0xc0 {
                0xc0 => {
                    let low = *packet.get(pos + 1).ok_or(DnsError::UnexpectedEof)?;
                    let ptr = (usize::from(b & 0x3f) << 8) | usize::from(low);
                    if hops == 10 || visited[..hops].contains(&ptr) {
                        return Err(DnsError::CompressionLoop);
                    }
                    if ptr >= packet.len() {
                        return Err(DnsError::UnexpectedEof);
                    }
                    visited[hops] = ptr;
                    hops += 1;
                    end.get_or_insert(pos + 2);
                    pos = ptr;
                }
                0 => {
                    pos += 1;
                    if b == 0 {
                        *offset = end.unwrap_or(pos);
                        return Ok(name);
                    }
                    let next = pos
                        .checked_add(usize::from(b))
                        .ok_or(DnsError::InvalidPacket)?;
                    name.push_label(packet.get(pos..next).ok_or(DnsError::UnexpectedEof)?)?;
                    pos = next;
                }
                _ => return Err(DnsError::InvalidPacket),
            }
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.octets[..usize::from(self.len)]
    }
    pub fn label_count(&self) -> u8 {
        self.count
    }
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &[u8]> + ExactSizeIterator {
        self.offsets[..usize::from(self.count)].iter().map(|&o| {
            let o = usize::from(o);
            &self.octets[o + 1..o + 1 + usize::from(self.octets[o])]
        })
    }
    pub fn parent(&self) -> Option<Self> {
        if self.count == 0 {
            return None;
        }
        let mut result = Self::root();
        for label in self.labels().skip(1) {
            result.push_label(label).expect("suffix fits original name");
        }
        Some(result)
    }
    pub fn is_subdomain_of(&self, parent: &Self) -> bool {
        self.count >= parent.count
            && self
                .labels()
                .rev()
                .zip(parent.labels().rev())
                .all(|(a, b)| a == b)
    }
    pub fn prepend_label(&self, label: &[u8]) -> Result<Self, DnsError> {
        let mut result = Self::root();
        result.push_label(label)?;
        for label in self.labels() {
            result.push_label(label)?;
        }
        Ok(result)
    }
    pub fn prepend_wildcard(&self) -> Result<Self, DnsError> {
        self.prepend_label(b"*")
    }
}
impl Default for WireName {
    fn default() -> Self {
        Self::root()
    }
}
impl Ord for WireName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.labels().rev().cmp(other.labels().rev())
    }
}
impl PartialOrd for WireName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Display for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.count == 0 {
            return f.write_str(".");
        }
        for label in self.labels() {
            for &b in label {
                match b {
                    b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' | b'$' => {
                        write!(f, "\\{}", char::from(b))?
                    }
                    33..=126 => write!(f, "{}", char::from(b))?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}
impl fmt::Debug for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl FromStr for WireName {
    type Err = DnsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ascii(s)
    }
}
impl Serialize for WireName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for WireName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
