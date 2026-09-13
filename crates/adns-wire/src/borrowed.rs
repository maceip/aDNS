use super::*;
/// Zero-copy typed RDATA. Variable-length byte fields borrow the packet; names
/// are bounded canonical stack values, including when the source is compressed.
#[derive(Debug, Clone)]
// Names remain inline to preserve the measured zero-allocation borrowed API.
#[allow(clippy::large_enum_variant)]
pub enum RDataRef<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(WireName),
    Cname(WireName),
    Ptr(WireName),
    Soa(SoaData),
    Mx(MxData),
    Txt(CharacterStrings<'a>),
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        certificate_association_data: &'a [u8],
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: &'a [u8],
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &'a [u8],
    },
    Rrsig {
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: WireName,
        signature: &'a [u8],
    },
    Nsec {
        next_domain_name: WireName,
        types: TypeBitmap<'a>,
    },
    Nsec3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
        next_hashed_owner: &'a [u8],
        types: TypeBitmap<'a>,
    },
    Nsec3Param {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
    },
    Caa {
        flags: u8,
        tag: &'a [u8],
        value: &'a [u8],
    },
    Opt(EdnsOptions<'a>),
    Unknown(&'a [u8]),
}
#[derive(Debug, Clone, Copy)]
pub struct CharacterStrings<'a>(&'a [u8]);
impl<'a> CharacterStrings<'a> {
    pub fn iter(self) -> impl Iterator<Item = &'a [u8]> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let end = usize::from(rest[0]) + 1;
            let value = &rest[1..end];
            rest = &rest[end..];
            Some(value)
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct EdnsOptions<'a>(&'a [u8]);
impl<'a> EdnsOptions<'a> {
    pub fn iter(self) -> impl Iterator<Item = (u16, &'a [u8])> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let code = u16::from_be_bytes([rest[0], rest[1]]);
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            let value = &rest[4..4 + len];
            rest = &rest[4 + len..];
            Some((code, value))
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct TypeBitmap<'a>(&'a [u8]);
impl<'a> TypeBitmap<'a> {
    pub fn as_slice(self) -> &'a [u8] {
        self.0
    }
    pub fn contains(self, rtype: RecordType) -> bool {
        self.iter().any(|t| t == rtype)
    }
    pub fn iter(self) -> impl Iterator<Item = RecordType> + 'a {
        let mut rest = self.0;
        let mut current: &[u8] = &[];
        let mut window = 0u16;
        let mut bit = 0usize;
        std::iter::from_fn(move || {
            loop {
                if bit >= current.len() * 8 {
                    if rest.is_empty() {
                        return None;
                    }
                    window = u16::from(rest[0]) << 8;
                    let len = usize::from(rest[1]);
                    current = &rest[2..2 + len];
                    rest = &rest[2 + len..];
                    bit = 0;
                }
                let index = bit;
                bit += 1;
                if current[index / 8] & (0x80 >> (index % 8)) != 0 {
                    return Some(RecordType::from(window | index as u16));
                }
            }
        })
    }
    fn checked(bytes: &'a [u8]) -> Result<Self, DnsError> {
        let mut r = PacketReader::new(bytes);
        let mut previous = None;
        while r.remaining() > 0 {
            let window = r.u8()?;
            let len = usize::from(r.u8()?);
            if len == 0 || len > 32 || previous.is_some_and(|p| window <= p) {
                return Err(DnsError::InvalidRdata);
            }
            let b = r.bytes(len)?;
            if b[len - 1] == 0 {
                return Err(DnsError::InvalidRdata);
            }
            previous = Some(window);
        }
        Ok(Self(bytes))
    }
}
impl<'a> PacketReader<'a> {
    fn borrowed_tail(&mut self) -> Result<&'a [u8], DnsError> {
        self.bytes(self.remaining())
    }
    fn borrowed_counted(&mut self) -> Result<&'a [u8], DnsError> {
        let n = usize::from(self.u8()?);
        self.bytes(n)
    }
}
impl<'a> RecordView<'a> {
    pub fn typed(&self) -> Result<RDataRef<'a>, DnsError> {
        let mut r = PacketReader {
            packet: self.packet,
            position: self.offset,
            end: self.offset + self.rdata.len(),
        };
        let data = match self.rtype {
            RecordType::A => {
                let b = r.bytes(4)?;
                RDataRef::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RecordType::Aaaa => {
                let mut b = [0; 16];
                b.copy_from_slice(r.bytes(16)?);
                RDataRef::Aaaa(Ipv6Addr::from(b))
            }
            RecordType::Ns => RDataRef::Ns(r.name()?),
            RecordType::Cname => RDataRef::Cname(r.name()?),
            RecordType::Ptr => RDataRef::Ptr(r.name()?),
            RecordType::Soa => RDataRef::Soa(SoaData {
                mname: r.name()?,
                rname: r.name()?,
                serial: r.u32()?,
                refresh: r.u32()?,
                retry: r.u32()?,
                expire: r.u32()?,
                minimum: r.u32()?,
            }),
            RecordType::Mx => RDataRef::Mx(MxData {
                preference: r.u16()?,
                exchange: r.name()?,
            }),
            RecordType::Txt => {
                let bytes = r.borrowed_tail()?;
                if bytes.is_empty() {
                    return Err(DnsError::InvalidRdata);
                }
                let mut check = PacketReader::new(bytes);
                while check.remaining() > 0 {
                    check.borrowed_counted()?;
                }
                RDataRef::Txt(CharacterStrings(bytes))
            }
            RecordType::Tlsa => RDataRef::Tlsa {
                usage: r.u8()?,
                selector: r.u8()?,
                matching_type: r.u8()?,
                certificate_association_data: r.borrowed_tail()?,
            },
            RecordType::Dnskey => RDataRef::Dnskey {
                flags: r.u16()?,
                protocol: r.u8()?,
                algorithm: r.u8()?,
                public_key: r.borrowed_tail()?,
            },
            RecordType::Ds => RDataRef::Ds {
                key_tag: r.u16()?,
                algorithm: r.u8()?,
                digest_type: r.u8()?,
                digest: r.borrowed_tail()?,
            },
            RecordType::Rrsig => RDataRef::Rrsig {
                type_covered: r.u16()?.into(),
                algorithm: r.u8()?,
                labels: r.u8()?,
                original_ttl: r.u32()?,
                expiration: r.u32()?,
                inception: r.u32()?,
                key_tag: r.u16()?,
                signer_name: r.name()?,
                signature: r.borrowed_tail()?,
            },
            RecordType::Nsec => RDataRef::Nsec {
                next_domain_name: r.name()?,
                types: TypeBitmap::checked(r.borrowed_tail()?)?,
            },
            RecordType::Nsec3 => RDataRef::Nsec3 {
                hash_algorithm: r.u8()?,
                flags: r.u8()?,
                iterations: r.u16()?,
                salt: r.borrowed_counted()?,
                next_hashed_owner: r.borrowed_counted()?,
                types: TypeBitmap::checked(r.borrowed_tail()?)?,
            },
            RecordType::Nsec3Param => RDataRef::Nsec3Param {
                hash_algorithm: r.u8()?,
                flags: r.u8()?,
                iterations: r.u16()?,
                salt: r.borrowed_counted()?,
            },
            RecordType::Caa => {
                let flags = r.u8()?;
                let tag = r.borrowed_counted()?;
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(DnsError::InvalidRdata);
                }
                RDataRef::Caa {
                    flags,
                    tag,
                    value: r.borrowed_tail()?,
                }
            }
            RecordType::Opt => {
                let bytes = r.borrowed_tail()?;
                let mut check = PacketReader::new(bytes);
                while check.remaining() > 0 {
                    check.u16()?;
                    let n = usize::from(check.u16()?);
                    check.bytes(n)?;
                }
                RDataRef::Opt(EdnsOptions(bytes))
            }
            _ => RDataRef::Unknown(r.borrowed_tail()?),
        };
        if r.remaining() != 0 {
            return Err(DnsError::InvalidRdata);
        }
        Ok(data)
    }
}
