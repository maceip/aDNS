use crate::DnssecError;
use adns_wire::*;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialMode {
    Nsec,
    Nsec3 { iterations: u16, salt: Vec<u8> },
}
impl Default for DenialMode {
    fn default() -> Self {
        Self::Nsec3 {
            iterations: 0,
            salt: Vec::new(),
        }
    }
}
/// Bounded work even for attacker-selected parameters; modern deployments use
/// zero iterations and no salt (RFC 9276). Legacy vectors remain supported.
pub fn nsec3_hash(name: &WireName, iterations: u16, salt: &[u8]) -> Result<[u8; 20], DnssecError> {
    if iterations > 250 || salt.len() > 255 {
        return Err(DnssecError::InvalidNsec3Parameters);
    }
    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(name.as_slice());
    ctx.update(salt);
    let mut digest = ctx.finish();
    for _ in 0..iterations {
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(digest.as_ref());
        ctx.update(salt);
        digest = ctx.finish();
    }
    let mut hash = [0; 20];
    hash.copy_from_slice(digest.as_ref());
    Ok(hash)
}
/// A strict open interval on a circular canonical name/hash ordering.
pub fn covers<T: Ord>(owner: &T, next: &T, name: &T) -> bool {
    if owner < next {
        owner < name && name < next
    } else if owner > next {
        owner < name || name < next
    } else {
        name != owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeProof {
    pub soa: ResourceRecord,
    pub soa_rrsig: ResourceRecord,
    pub closest_encloser_nsec3: ResourceRecord,
    pub closest_encloser_rrsig: ResourceRecord,
    pub next_closer_nsec3: ResourceRecord,
    pub next_closer_rrsig: ResourceRecord,
    pub wildcard_nsec3: Option<(ResourceRecord, ResourceRecord)>,
}
impl NegativeProof {
    pub fn into_records(self) -> Vec<ResourceRecord> {
        let mut records = vec![
            self.soa,
            self.soa_rrsig,
            self.closest_encloser_nsec3,
            self.closest_encloser_rrsig,
            self.next_closer_nsec3,
            self.next_closer_rrsig,
        ];
        if let Some((a, b)) = self.wildcard_nsec3 {
            records.extend([a, b]);
        }
        let mut unique = Vec::new();
        for rr in records {
            if !unique.contains(&rr) {
                unique.push(rr);
            }
        }
        unique
    }
}
