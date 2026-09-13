use crate::DnssecError;
use adns_wire::*;
use ring::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use sha2::{Digest, Sha256, Sha384};

pub const ALGORITHM: u8 = 14;
/// Secret bytes are deliberately excluded from Debug/Serialize. Persist only
/// through the storage adapter's encrypted private key collection.
pub struct SigningKey {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
}
impl SigningKey {
    pub fn generate() -> Result<Self, DnssecError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
            .map_err(|_| DnssecError::Crypto)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, DnssecError> {
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            bytes,
            &SystemRandom::new(),
        )
        .map_err(|_| DnssecError::Crypto)?;
        Ok(Self {
            pair,
            pkcs8: bytes.to_vec(),
        })
    }
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }
    pub fn dnskey(&self, flags: u16) -> DnskeyData {
        DnskeyData {
            flags,
            protocol: 3,
            algorithm: ALGORITHM,
            public_key: self.pair.public_key().as_ref()[1..].to_vec(),
        }
    }
    pub fn key_tag(&self, flags: u16) -> Result<u16, DnssecError> {
        Ok(key_tag(&RData::Dnskey(self.dnskey(flags)).to_wire()?))
    }
    pub fn sign_rrset(
        &self,
        rrset: &[ResourceRecord],
        signer: WireName,
        flags: u16,
        now: u32,
        validity: u32,
    ) -> Result<ResourceRecord, DnssecError> {
        if validity <= 300 || validity >= 0x7fff_ffff - 300 {
            return Err(DnssecError::InvalidValidity);
        }
        let first = rrset.first().ok_or(DnssecError::InvalidRrset)?;
        let labels = first.name.label_count() - u8::from(first.name.labels().next() == Some(b"*"));
        let mut sig = RrsigData {
            type_covered: first.rtype,
            algorithm: ALGORITHM,
            labels,
            original_ttl: first.ttl,
            expiration: now.wrapping_add(validity),
            inception: now.wrapping_sub(300),
            key_tag: self.key_tag(flags)?,
            signer_name: signer,
            signature: Vec::new(),
        };
        let data = signature_input(rrset, &sig)?;
        sig.signature = self
            .pair
            .sign(&SystemRandom::new(), &data)
            .map_err(|_| DnssecError::Crypto)?
            .as_ref()
            .to_vec();
        if sig.signature.len() != 96 {
            return Err(DnssecError::Crypto);
        }
        Ok(ResourceRecord::new(
            first.name,
            first.ttl,
            RData::Rrsig(sig),
        )?)
    }
}
pub fn key_tag(rdata: &[u8]) -> u16 {
    // Appendix B's exception applies to legacy algorithm 1.
    if rdata.len() >= 4 && rdata[3] == 1 {
        return u16::from_be_bytes([rdata[rdata.len() - 3], rdata[rdata.len() - 2]]);
    }
    let sum = rdata.iter().enumerate().fold(0u32, |a, (i, &b)| {
        a.wrapping_add(if i & 1 == 0 {
            u32::from(b) << 8
        } else {
            u32::from(b)
        })
    });
    ((sum.wrapping_add((sum >> 16) & 0xffff)) & 0xffff) as u16
}
pub fn ds(owner: &WireName, key: &DnskeyData, digest_type: u8) -> Result<DsData, DnssecError> {
    let rdata = RData::Dnskey(key.clone()).to_wire()?;
    let mut input = owner.as_slice().to_vec();
    input.extend_from_slice(&rdata);
    let digest = match digest_type {
        2 => Sha256::digest(&input).to_vec(),
        4 => Sha384::digest(&input).to_vec(),
        _ => return Err(DnssecError::UnsupportedAlgorithm),
    };
    Ok(DsData {
        key_tag: key_tag(&rdata),
        algorithm: key.algorithm,
        digest_type,
        digest,
    })
}
/// RFC 4034 canonical RRset signing data, including wildcard owner recreation.
pub fn signature_input(rrset: &[ResourceRecord], sig: &RrsigData) -> Result<Vec<u8>, DnssecError> {
    let first = rrset.first().ok_or(DnssecError::InvalidRrset)?;
    if first.name.label_count() < sig.labels {
        return Err(DnssecError::InvalidRrset);
    }
    let mut owner = first.name;
    if owner.label_count() > sig.labels {
        while owner.label_count() > sig.labels {
            owner = owner.parent().ok_or(DnssecError::InvalidRrset)?;
        }
        owner = owner.prepend_wildcard()?;
    }
    let mut unsigned = sig.clone();
    unsigned.signature.clear();
    let mut result = RData::Rrsig(unsigned).to_wire()?;
    let mut canonical = Vec::with_capacity(rrset.len());
    for rr in rrset {
        if rr.name != first.name
            || rr.rtype != first.rtype
            || rr.rtype != sig.type_covered
            || rr.rclass != first.rclass
            || rr.ttl != first.ttl
            || rr.rclass != RecordClass::In
        {
            return Err(DnssecError::InvalidRrset);
        }
        canonical.push(rr.rdata.to_wire()?);
    }
    canonical.sort();
    canonical.dedup();
    for data in canonical {
        result.extend_from_slice(owner.as_slice());
        result.extend_from_slice(&first.rtype.code().to_be_bytes());
        result.extend_from_slice(&first.rclass.code().to_be_bytes());
        result.extend_from_slice(&sig.original_ttl.to_be_bytes());
        result.extend_from_slice(
            &(u16::try_from(data.len()).map_err(|_| DnssecError::InvalidRrset)?).to_be_bytes(),
        );
        result.extend_from_slice(&data);
    }
    Ok(result)
}
pub fn verify_rrset(
    rrset: &[ResourceRecord],
    sig: &RrsigData,
    key: &DnskeyData,
    now: u32,
) -> Result<(), DnssecError> {
    if sig.algorithm != 14
        || key.algorithm != 14
        || key.protocol != 3
        || key.flags & 256 == 0
        || key.public_key.len() != 96
        || sig.signature.len() != 96
    {
        return Err(DnssecError::UnsupportedAlgorithm);
    }
    if sig.key_tag != key_tag(&RData::Dnskey(key.clone()).to_wire()?)
        || now.wrapping_sub(sig.inception) >= 0x8000_0000
        || sig.expiration.wrapping_sub(now) >= 0x8000_0000
    {
        return Err(DnssecError::InvalidSignature);
    }
    let mut public = vec![4];
    public.extend_from_slice(&key.public_key);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, public)
        .verify(&signature_input(rrset, sig)?, &sig.signature)
        .map_err(|_| DnssecError::InvalidSignature)
}
