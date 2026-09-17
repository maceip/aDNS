use crate::{DnsError, SvcParam, SvcbData, WireName};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

macro_rules! code_enum {
    ($name:ident, $($variant:ident=$code:literal),+ $(,)?)=>{
        #[derive(Debug,Clone,Copy,Serialize,Deserialize)]
        pub enum $name {$($variant,)+ Unknown(u16)}
        impl $name {pub const fn code(self)->u16 {match self {$ (Self::$variant=>$code,)+Self::Unknown(n)=>n}}}
        impl From<u16> for $name {fn from(n:u16)->Self {match n {$($code=>Self::$variant,)+_=>Self::Unknown(n)}}}
        impl PartialEq for $name {fn eq(&self,other:&Self)->bool{self.code()==other.code()}}
        impl Eq for $name {}
        impl std::hash::Hash for $name {fn hash<H:std::hash::Hasher>(&self,state:&mut H){std::hash::Hash::hash(&self.code(),state);}}
        impl Ord for $name {fn cmp(&self,other:&Self)->std::cmp::Ordering {self.code().cmp(&other.code())}}
        impl PartialOrd for $name {fn partial_cmp(&self,other:&Self)->Option<std::cmp::Ordering>{Some(self.cmp(other))}}
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {match Self::from(self.code()) {$(Self::$variant=>f.write_str(&stringify!($variant).to_ascii_uppercase()),)+Self::Unknown(n)=>write!(f,"TYPE{n}")}}}
    }
}
code_enum!(
    RecordType,
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Opt = 41,
    Ds = 43,
    Rrsig = 46,
    Nsec = 47,
    Dnskey = 48,
    Nsec3 = 50,
    Nsec3Param = 51,
    Tlsa = 52,
    Svcb = 64,
    Tsig = 250,
    Ixfr = 251,
    Axfr = 252,
    Any = 255,
    Caa = 257
);
code_enum!(RecordClass, In = 1, None = 254, Any = 255);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoaData {
    pub mname: WireName,
    pub rname: WireName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxData {
    pub preference: u16,
    pub exchange: WireName,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsaData {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate_association_data: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnskeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RrsigData {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: WireName,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecData {
    pub next_domain_name: WireName,
    pub types: Vec<RecordType>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nsec3Data {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Vec<u8>,
    pub types: Vec<RecordType>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nsec3ParamData {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaaData {
    pub flags: u8,
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OptData {
    pub options: Vec<EdnsOption>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Inline WireName is intentional: boxing would allocate on the DNS path.
#[allow(clippy::large_enum_variant)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(WireName),
    Cname(WireName),
    Ptr(WireName),
    Soa(SoaData),
    Mx(MxData),
    Txt(Vec<Vec<u8>>),
    Svcb(SvcbData),
    Tlsa(TlsaData),
    Dnskey(DnskeyData),
    Ds(DsData),
    Rrsig(RrsigData),
    Nsec(NsecData),
    Nsec3(Nsec3Data),
    Nsec3Param(Nsec3ParamData),
    Caa(CaaData),
    Opt(OptData),
    Unknown(Vec<u8>),
}
impl RData {
    pub fn record_type(&self) -> Option<RecordType> {
        Some(match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::Ns(_) => RecordType::Ns,
            Self::Cname(_) => RecordType::Cname,
            Self::Ptr(_) => RecordType::Ptr,
            Self::Soa(_) => RecordType::Soa,
            Self::Mx(_) => RecordType::Mx,
            Self::Txt(_) => RecordType::Txt,
            Self::Svcb(_) => RecordType::Svcb,
            Self::Tlsa(_) => RecordType::Tlsa,
            Self::Dnskey(_) => RecordType::Dnskey,
            Self::Ds(_) => RecordType::Ds,
            Self::Rrsig(_) => RecordType::Rrsig,
            Self::Nsec(_) => RecordType::Nsec,
            Self::Nsec3(_) => RecordType::Nsec3,
            Self::Nsec3Param(_) => RecordType::Nsec3Param,
            Self::Caa(_) => RecordType::Caa,
            Self::Opt(_) => RecordType::Opt,
            Self::Unknown(_) => return None,
        })
    }
    pub fn to_wire(&self) -> Result<Vec<u8>, DnsError> {
        let mut w = PacketWriter::new(false);
        w.rdata(self)?;
        Ok(w.into_bytes())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRecord {
    pub name: WireName,
    pub rclass: RecordClass,
    pub rtype: RecordType,
    pub ttl: u32,
    pub rdata: RData,
}
impl ResourceRecord {
    pub fn new(name: WireName, ttl: u32, rdata: RData) -> Result<Self, DnsError> {
        let rtype = rdata.record_type().ok_or(DnsError::InvalidRdata)?;
        Ok(Self {
            name,
            rclass: RecordClass::In,
            rtype,
            ttl,
            rdata,
        })
    }
    pub fn canonical_wire(&self) -> Result<Vec<u8>, DnsError> {
        let mut w = PacketWriter::new(false);
        w.record(self)?;
        Ok(w.into_bytes())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
}
impl Header {
    pub fn rcode(&self) -> u8 {
        (self.flags & 15) as u8
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 15) as u8
    }
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub name: WireName,
    pub qtype: RecordType,
    pub qclass: RecordClass,
}
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

/// Checked cursor over a complete packet, with a restricted current RDATA range.
pub struct PacketReader<'a> {
    packet: &'a [u8],
    pub position: usize,
    end: usize,
}
impl<'a> PacketReader<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        Self {
            packet,
            position: 0,
            end: packet.len(),
        }
    }
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.position)
    }
    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], DnsError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&e| e <= self.end)
            .ok_or(DnsError::UnexpectedEof)?;
        let bytes = &self.packet[self.position..end];
        self.position = end;
        Ok(bytes)
    }
    pub fn u8(&mut self) -> Result<u8, DnsError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, DnsError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, DnsError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn name(&mut self) -> Result<WireName, DnsError> {
        let mut pos = self.position;
        let name = WireName::parse_wire(self.packet, &mut pos)?;
        if pos > self.end {
            return Err(DnsError::UnexpectedEof);
        }
        self.position = pos;
        Ok(name)
    }
    pub fn record_view(&mut self) -> Result<RecordView<'a>, DnsError> {
        let name = self.name()?;
        let rtype = self.u16()?.into();
        let rclass = self.u16()?.into();
        let ttl = self.u32()?;
        let len = usize::from(self.u16()?);
        let offset = self.position;
        let rdata = self.bytes(len)?;
        Ok(RecordView {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
            packet: self.packet,
            offset,
        })
    }
    pub fn record(&mut self) -> Result<ResourceRecord, DnsError> {
        self.record_view()?.to_owned()
    }
    fn tail(&mut self) -> Vec<u8> {
        let v = self.packet[self.position..self.end].to_vec();
        self.position = self.end;
        v
    }
    fn counted(&mut self) -> Result<Vec<u8>, DnsError> {
        let n = usize::from(self.u8()?);
        Ok(self.bytes(n)?.to_vec())
    }
    fn rdata(&mut self, t: RecordType) -> Result<RData, DnsError> {
        Ok(match t {
            RecordType::A => {
                let b = self.bytes(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RecordType::Aaaa => {
                let b = self.bytes(16)?;
                let mut a = [0; 16];
                a.copy_from_slice(b);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            RecordType::Ns => RData::Ns(self.name()?),
            RecordType::Cname => RData::Cname(self.name()?),
            RecordType::Ptr => RData::Ptr(self.name()?),
            RecordType::Soa => RData::Soa(SoaData {
                mname: self.name()?,
                rname: self.name()?,
                serial: self.u32()?,
                refresh: self.u32()?,
                retry: self.u32()?,
                expire: self.u32()?,
                minimum: self.u32()?,
            }),
            RecordType::Mx => RData::Mx(MxData {
                preference: self.u16()?,
                exchange: self.name()?,
            }),
            RecordType::Txt => {
                if self.remaining() == 0 {
                    return Err(DnsError::InvalidRdata);
                }
                let mut v = Vec::new();
                while self.remaining() > 0 {
                    v.push(self.counted()?);
                }
                RData::Txt(v)
            }
            RecordType::Tlsa => RData::Tlsa(TlsaData {
                usage: self.u8()?,
                selector: self.u8()?,
                matching_type: self.u8()?,
                certificate_association_data: self.tail(),
            }),
            RecordType::Svcb => {
                let priority = self.u16()?;
                let start = self.position;
                let mut cursor = start;
                loop {
                    let len = usize::from(
                        *self
                            .packet
                            .get(cursor)
                            .filter(|_| cursor < self.end)
                            .ok_or(DnsError::UnexpectedEof)?,
                    );
                    if len > 63 {
                        return Err(DnsError::InvalidRdata);
                    }
                    cursor += 1 + len;
                    if cursor > self.end {
                        return Err(DnsError::UnexpectedEof);
                    }
                    if len == 0 {
                        break;
                    }
                }
                let target = self.bytes(cursor - start)?.to_vec();
                let mut params = Vec::new();
                while self.remaining() > 0 {
                    let key = self.u16()?;
                    let n = usize::from(self.u16()?);
                    params.push(SvcParam {
                        key,
                        value: self.bytes(n)?.to_vec(),
                    });
                }
                let data = SvcbData {
                    priority,
                    target,
                    params,
                };
                data.validate()?;
                RData::Svcb(data)
            }
            RecordType::Dnskey => RData::Dnskey(DnskeyData {
                flags: self.u16()?,
                protocol: self.u8()?,
                algorithm: self.u8()?,
                public_key: self.tail(),
            }),
            RecordType::Ds => RData::Ds(DsData {
                key_tag: self.u16()?,
                algorithm: self.u8()?,
                digest_type: self.u8()?,
                digest: self.tail(),
            }),
            RecordType::Rrsig => RData::Rrsig(RrsigData {
                type_covered: self.u16()?.into(),
                algorithm: self.u8()?,
                labels: self.u8()?,
                original_ttl: self.u32()?,
                expiration: self.u32()?,
                inception: self.u32()?,
                key_tag: self.u16()?,
                signer_name: self.name()?,
                signature: self.tail(),
            }),
            RecordType::Nsec => RData::Nsec(NsecData {
                next_domain_name: self.name()?,
                types: parse_type_bitmap(self.bytes(self.remaining())?)?,
            }),
            RecordType::Nsec3 => RData::Nsec3(Nsec3Data {
                hash_algorithm: self.u8()?,
                flags: self.u8()?,
                iterations: self.u16()?,
                salt: self.counted()?,
                next_hashed_owner: self.counted()?,
                types: parse_type_bitmap(self.bytes(self.remaining())?)?,
            }),
            RecordType::Nsec3Param => RData::Nsec3Param(Nsec3ParamData {
                hash_algorithm: self.u8()?,
                flags: self.u8()?,
                iterations: self.u16()?,
                salt: self.counted()?,
            }),
            RecordType::Caa => {
                let flags = self.u8()?;
                let tag = self.counted()?;
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(DnsError::InvalidRdata);
                }
                RData::Caa(CaaData {
                    flags,
                    tag,
                    value: self.tail(),
                })
            }
            RecordType::Opt => {
                let mut options = Vec::new();
                while self.remaining() > 0 {
                    let code = self.u16()?;
                    let n = usize::from(self.u16()?);
                    options.push(EdnsOption {
                        code,
                        data: self.bytes(n)?.to_vec(),
                    });
                }
                RData::Opt(OptData { options })
            }
            _ => RData::Unknown(self.tail()),
        })
    }
}
/// Borrowed, allocation-free envelope for inspecting arbitrary RDATA. Convert
/// to typed ownership only when storing or modifying a record.
pub struct RecordView<'a> {
    pub name: WireName,
    pub rtype: RecordType,
    pub rclass: RecordClass,
    pub ttl: u32,
    pub rdata: &'a [u8],
    packet: &'a [u8],
    offset: usize,
}
impl RecordView<'_> {
    pub fn to_owned(&self) -> Result<ResourceRecord, DnsError> {
        let mut r = PacketReader {
            packet: self.packet,
            position: self.offset,
            end: self.offset + self.rdata.len(),
        };
        let rdata = r.rdata(self.rtype)?;
        if r.remaining() != 0 {
            return Err(DnsError::InvalidRdata);
        }
        Ok(ResourceRecord {
            name: self.name,
            rclass: self.rclass,
            rtype: self.rtype,
            ttl: self.ttl,
            rdata,
        })
    }
}

pub fn type_bitmap(types: &[RecordType]) -> Vec<u8> {
    let mut windows = BTreeMap::<u8, [u8; 32]>::new();
    for t in types {
        let n = t.code();
        let byte = ((n & 255) / 8) as usize;
        windows.entry((n >> 8) as u8).or_insert([0; 32])[byte] |= 0x80 >> (n % 8);
    }
    let mut out = Vec::new();
    for (w, b) in windows {
        let len = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
        out.push(w);
        out.push(len as u8);
        out.extend_from_slice(&b[..len]);
    }
    out
}
pub fn parse_type_bitmap(bytes: &[u8]) -> Result<Vec<RecordType>, DnsError> {
    let mut r = PacketReader::new(bytes);
    let mut types = Vec::new();
    let mut last = None;
    while r.remaining() > 0 {
        let window = r.u8()?;
        let len = usize::from(r.u8()?);
        if len == 0 || len > 32 || last.is_some_and(|v| window <= v) {
            return Err(DnsError::InvalidRdata);
        }
        last = Some(window);
        let bitmap = r.bytes(len)?;
        if bitmap[len - 1] == 0 {
            return Err(DnsError::InvalidRdata);
        }
        for (i, &b) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if b & (0x80 >> bit) != 0 {
                    types.push(RecordType::from(
                        (u16::from(window) << 8) | (i as u16 * 8 + bit),
                    ));
                }
            }
        }
    }
    Ok(types)
}

pub struct PacketWriter {
    bytes: Vec<u8>,
    compression: bool,
    names: BTreeMap<WireName, u16>,
}
impl PacketWriter {
    pub fn new(compression: bool) -> Self {
        Self {
            bytes: Vec::new(),
            compression,
            names: BTreeMap::new(),
        }
    }
    pub fn position(&self) -> usize {
        self.bytes.len()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), DnsError> {
        if self.bytes.len().saturating_add(b.len()) > 65535 {
            return Err(DnsError::PacketTooLong);
        }
        self.bytes.extend_from_slice(b);
        Ok(())
    }
    pub fn u8(&mut self, n: u8) -> Result<(), DnsError> {
        self.bytes(&[n])
    }
    pub fn u16(&mut self, n: u16) -> Result<(), DnsError> {
        self.bytes(&n.to_be_bytes())
    }
    pub fn u32(&mut self, n: u32) -> Result<(), DnsError> {
        self.bytes(&n.to_be_bytes())
    }
    pub fn name(&mut self, name: &WireName) -> Result<(), DnsError> {
        if !self.compression {
            return self.bytes(name.as_slice());
        }
        let mut suffix = *name;
        let mut pending = Vec::new();
        while suffix.label_count() > 0 {
            if let Some(&pointer) = self.names.get(&suffix) {
                return self.u16(0xc000 | pointer);
            }
            if self.bytes.len() < 0x4000 {
                pending.push((suffix, self.bytes.len() as u16));
            }
            let label = suffix.labels().next().ok_or(DnsError::InvalidPacket)?;
            self.u8(label.len() as u8)?;
            self.bytes(label)?;
            suffix = suffix.parent().ok_or(DnsError::InvalidPacket)?;
        }
        self.u8(0)?;
        // Index only uncompressed suffixes, so writer output never creates
        // pointer chains exceeding the bounded parser limit.
        self.names.extend(pending);
        Ok(())
    }
    fn counted(&mut self, b: &[u8]) -> Result<(), DnsError> {
        self.u8(u8::try_from(b.len()).map_err(|_| DnsError::InvalidRdata)?)?;
        self.bytes(b)
    }
    pub fn record(&mut self, rr: &ResourceRecord) -> Result<(), DnsError> {
        if rr.rdata.record_type().is_some_and(|t| t != rr.rtype) {
            return Err(DnsError::InvalidRdata);
        }
        self.name(&rr.name)?;
        self.u16(rr.rtype.code())?;
        self.u16(rr.rclass.code())?;
        self.u32(rr.ttl)?;
        let start = self.position();
        self.u16(0)?;
        self.rdata(&rr.rdata)?;
        let size =
            u16::try_from(self.position() - start - 2).map_err(|_| DnsError::InvalidRdata)?;
        self.bytes[start..start + 2].copy_from_slice(&size.to_be_bytes());
        Ok(())
    }
    pub fn rdata(&mut self, data: &RData) -> Result<(), DnsError> {
        match data {
            RData::A(ip) => self.bytes(&ip.octets())?,
            RData::Aaaa(ip) => self.bytes(&ip.octets())?,
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => self.name(n)?,
            RData::Soa(s) => {
                self.name(&s.mname)?;
                self.name(&s.rname)?;
                for n in [s.serial, s.refresh, s.retry, s.expire, s.minimum] {
                    self.u32(n)?;
                }
            }
            RData::Mx(m) => {
                self.u16(m.preference)?;
                self.name(&m.exchange)?;
            }
            RData::Txt(v) => {
                if v.is_empty() {
                    return Err(DnsError::InvalidRdata);
                }
                for s in v {
                    self.counted(s)?;
                }
            }
            RData::Tlsa(t) => {
                self.bytes(&[t.usage, t.selector, t.matching_type])?;
                self.bytes(&t.certificate_association_data)?;
            }
            RData::Svcb(s) => {
                s.validate()?;
                self.u16(s.priority)?;
                self.bytes(&s.target)?;
                for p in &s.params {
                    self.u16(p.key)?;
                    self.u16(u16::try_from(p.value.len()).map_err(|_| DnsError::InvalidRdata)?)?;
                    self.bytes(&p.value)?;
                }
            }
            RData::Dnskey(k) => {
                self.u16(k.flags)?;
                self.bytes(&[k.protocol, k.algorithm])?;
                self.bytes(&k.public_key)?;
            }
            RData::Ds(d) => {
                self.u16(d.key_tag)?;
                self.bytes(&[d.algorithm, d.digest_type])?;
                self.bytes(&d.digest)?;
            }
            RData::Rrsig(s) => {
                self.u16(s.type_covered.code())?;
                self.bytes(&[s.algorithm, s.labels])?;
                for n in [s.original_ttl, s.expiration, s.inception] {
                    self.u32(n)?;
                }
                self.u16(s.key_tag)?;
                self.bytes(s.signer_name.as_slice())?;
                self.bytes(&s.signature)?;
            }
            RData::Nsec(n) => {
                self.bytes(n.next_domain_name.as_slice())?;
                self.bytes(&type_bitmap(&n.types))?;
            }
            RData::Nsec3(n) => {
                self.bytes(&[n.hash_algorithm, n.flags])?;
                self.u16(n.iterations)?;
                self.counted(&n.salt)?;
                self.counted(&n.next_hashed_owner)?;
                self.bytes(&type_bitmap(&n.types))?;
            }
            RData::Nsec3Param(n) => {
                self.bytes(&[n.hash_algorithm, n.flags])?;
                self.u16(n.iterations)?;
                self.counted(&n.salt)?;
            }
            RData::Caa(c) => {
                if c.tag.is_empty() || !c.tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(DnsError::InvalidRdata);
                }
                self.u8(c.flags)?;
                self.counted(&c.tag)?;
                self.bytes(&c.value)?;
            }
            RData::Opt(o) => {
                for option in &o.options {
                    self.u16(option.code)?;
                    self.u16(
                        u16::try_from(option.data.len()).map_err(|_| DnsError::InvalidRdata)?,
                    )?;
                    self.bytes(&option.data)?;
                }
            }
            RData::Unknown(b) => self.bytes(b)?,
        }
        Ok(())
    }
}
impl Message {
    pub fn parse(packet: &[u8]) -> Result<Self, DnsError> {
        if packet.len() > 65535 {
            return Err(DnsError::PacketTooLong);
        }
        let mut r = PacketReader::new(packet);
        let header = Header {
            id: r.u16()?,
            flags: r.u16()?,
        };
        let q = r.u16()?;
        let a = r.u16()?;
        let n = r.u16()?;
        let e = r.u16()?;
        // A question takes >=5 bytes; a record >=11. Reject absurd section counts before allocation.
        if usize::from(q) * 5 + (usize::from(a) + usize::from(n) + usize::from(e)) * 11
            > r.remaining()
        {
            return Err(DnsError::UnexpectedEof);
        }
        let mut m = Self {
            header,
            ..Self::default()
        };
        for _ in 0..q {
            m.questions.push(Question {
                name: r.name()?,
                qtype: r.u16()?.into(),
                qclass: r.u16()?.into(),
            });
        }
        for (count, section) in [
            (a, &mut m.answers),
            (n, &mut m.authorities),
            (e, &mut m.additionals),
        ] {
            for _ in 0..count {
                section.push(r.record()?);
            }
        }
        if r.remaining() != 0 {
            return Err(DnsError::InvalidPacket);
        }
        let mut opt = false;
        for rr in m.answers.iter().chain(&m.authorities) {
            if rr.rtype == RecordType::Opt {
                return Err(DnsError::InvalidPacket);
            }
        }
        for rr in &m.additionals {
            if rr.rtype == RecordType::Opt {
                if opt || rr.name != WireName::root() {
                    return Err(DnsError::InvalidPacket);
                }
                opt = true;
            }
        }
        Ok(m)
    }
    pub fn to_wire(&self) -> Result<Vec<u8>, DnsError> {
        self.serialize(true)
    }
    pub fn to_wire_uncompressed(&self) -> Result<Vec<u8>, DnsError> {
        self.serialize(false)
    }
    fn serialize(&self, compression: bool) -> Result<Vec<u8>, DnsError> {
        let mut w = PacketWriter::new(compression);
        w.u16(self.header.id)?;
        w.u16(self.header.flags)?;
        for n in [
            self.questions.len(),
            self.answers.len(),
            self.authorities.len(),
            self.additionals.len(),
        ] {
            w.u16(u16::try_from(n).map_err(|_| DnsError::PacketTooLong)?)?;
        }
        for q in &self.questions {
            w.name(&q.name)?;
            w.u16(q.qtype.code())?;
            w.u16(q.qclass.code())?;
        }
        for rr in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            w.record(rr)?;
        }
        Ok(w.into_bytes())
    }
}

#[path = "borrowed.rs"]
mod borrowed;
pub use borrowed::*;
