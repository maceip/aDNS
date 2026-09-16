use crate::*;
use adns_storage::{Collection, ReadTx, WriteTx, composite_key, get_json, put_json};
use adns_wire::{RecordType, ResourceRecord, WireName};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZoneId(pub u32);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordKey {
    pub zone: WireName,
    pub owner: WireName,
    pub rtype: RecordType,
}
impl RecordKey {
    pub fn encode(&self) -> Vec<u8> {
        composite_key(&[
            self.zone.as_slice(),
            self.owner.as_slice(),
            &self.rtype.code().to_be_bytes(),
            &1u16.to_be_bytes(),
        ])
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneMetadata {
    pub id: ZoneId,
    pub origin: WireName,
    pub serial: u32,
    pub base_records: Vec<ResourceRecord>,
    pub signed_records: Vec<ResourceRecord>,
    pub signature_validity: u32,
    pub refresh_before: u32,
    pub last_signed_at: u64,
    pub earliest_signature_expiration: u64,
    pub maintenance_health: String,
    pub ksk_dnskey_rdata: Vec<u8>,
    /// RFC 6781 double-signature KSK rollover in progress (None when not rolling).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ksk_rollover: Option<KskRollover>,
}
/// While Some, the zone publishes both KSKs in its DNSKEY RRset and signs that
/// RRset with both, so validators holding either DS keep validating. The parent
/// DS switch is an external, domain-owner action attested through governance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KskRollover {
    pub next_ksk_dnskey_rdata: Vec<u8>,
    pub started_at: u64,
    /// Seconds the double-signature period must last before completion is
    /// accepted: at least the DNSKEY TTL plus propagation, set at start.
    pub minimum_hold_seconds: u64,
    pub stage: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contribution {
    pub contributor: String,
    pub record: ResourceRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct VersionedRrset {
    pub contributions: Vec<Contribution>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub registration_id: String,
    pub grant_id: String,
    pub zone: String,
    pub signer_spki_sha256: String,
    pub parameters: adns_auth::RegisterParameters,
    pub admitted_at: u64,
    pub lease_expires_at: u64,
    pub policy_valid_until: u64,
    pub reappraisal_deadline: u64,
    pub policy_id: String,
    pub evidence_digest: String,
    pub status: String,
    pub active_ports: Vec<u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeChallenge {
    pub challenge_id: String,
    pub grant_id: String,
    pub registration_id: String,
    pub order_id: String,
    pub zone: String,
    pub name: String,
    pub txt_value: String,
    pub ttl: u32,
    pub expires_at: u64,
    pub signer_spki_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestResult {
    pub grant_id: String,
    pub request_id: String,
    pub signed_message_digest: String,
    pub http_status: u16,
    pub body: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceConfiguration {
    pub audience: String,
    pub epoch: u64,
    pub last_time: u64,
}
pub fn request_key(grant: &str, request: &str) -> Vec<u8> {
    composite_key(&[grant.as_bytes(), request.as_bytes()])
}
pub fn nonce_key(epoch: u64, nonce: &str) -> Vec<u8> {
    composite_key(&[&epoch.to_be_bytes(), nonce.as_bytes()])
}
pub fn zone_prefix(zone: &WireName) -> Vec<u8> {
    composite_key(&[zone.as_slice()])
}
pub fn zone_metadata(tx: &impl ReadTx, origin: &WireName) -> Result<ZoneMetadata> {
    validate_lifecycle_format(tx)?;
    get_json(tx, Collection::Zones, origin.as_slice())?.ok_or(AppError::NotFound("zone"))
}
pub fn records(tx: &impl ReadTx, origin: &WireName) -> Result<Vec<ResourceRecord>> {
    zone_usage(tx, origin)?;
    let mut out = Vec::new();
    for (_, v) in tx.scan_prefix(Collection::Records, &zone_prefix(origin))? {
        let rrset: VersionedRrset = serde_json::from_slice(&v.bytes).map_err(StorageError::from)?;
        out.extend(rrset.contributions.into_iter().map(|c| c.record));
    }
    normalize_rrsets(out)
}
/// Materialize one TTL and one copy of each canonical record per RRset. Only
/// snapshot copies are changed: source TTLs and ownership must survive so a
/// withdrawal can restore the remaining contributors' effective TTL.
pub(crate) fn normalize_rrsets(records: Vec<ResourceRecord>) -> Result<Vec<ResourceRecord>> {
    let mut ttls = std::collections::BTreeMap::new();
    for r in &records {
        ttls.entry((r.name, r.rtype, r.rclass))
            .and_modify(|ttl: &mut u32| *ttl = (*ttl).min(r.ttl))
            .or_insert(r.ttl);
    }
    let mut out = Vec::with_capacity(records.len());
    let mut unique = std::collections::BTreeSet::new();
    for mut r in records {
        r.ttl = ttls[&(r.name, r.rtype, r.rclass)];
        // Canonical wire includes TTL, so deduplication follows normalization.
        if unique.insert(r.canonical_wire()?) {
            out.push(r);
        }
    }
    Ok(out)
}
pub fn add_contribution(
    tx: &mut impl WriteTx,
    origin: &WireName,
    contributor: &str,
    record: ResourceRecord,
) -> Result<()> {
    if !record.name.is_subdomain_of(origin)
        || record.rclass != adns_wire::RecordClass::In
        || record.rdata.record_type() != Some(record.rtype)
    {
        return Err(AppError::Invalid(
            "record outside zone or inconsistent type",
        ));
    }
    // CNAME exclusivity applies across all owners and all contributors.
    let prefix = composite_key(&[origin.as_slice(), record.name.as_slice()]);
    for (_, v) in tx.scan_prefix(Collection::Records, &prefix)? {
        let set: VersionedRrset = serde_json::from_slice(&v.bytes).map_err(StorageError::from)?;
        for existing in set.contributions {
            if (existing.record.rtype == RecordType::Cname || record.rtype == RecordType::Cname)
                && (existing.record.rtype != record.rtype || existing.record.rdata != record.rdata)
            {
                return Err(AppError::Conflict("CNAME exclusivity"));
            }
        }
    }
    let key = RecordKey {
        zone: *origin,
        owner: record.name,
        rtype: record.rtype,
    }
    .encode();
    let mut set: VersionedRrset = get_json(tx, Collection::Records, &key)?.unwrap_or_default();
    if !set
        .contributions
        .iter()
        .any(|c| c.contributor == contributor && c.record == record)
    {
        let mut usage = zone_usage(tx, origin)?;
        let bytes = record.canonical_wire()?.len();
        if set.contributions.len() >= MAX_RRSET_CONTRIBUTIONS
            || (set.contributions.is_empty() && usage.rrsets + usage.base_rrsets >= MAX_ZONE_RRSETS)
            || usage.contributions >= MAX_ZONE_CONTRIBUTIONS
            || usage
                .wire_bytes
                .saturating_add(usage.base_wire_bytes)
                .saturating_add(bytes)
                > MAX_ZONE_RECORD_BYTES
        {
            return Err(AppError::Capacity("zone contributions"));
        }
        usage.rrsets += usize::from(set.contributions.is_empty());
        usage.contributions += 1;
        usage.wire_bytes += bytes;
        put_zone_usage(tx, origin, &usage)?;
        set.contributions.push(Contribution {
            contributor: contributor.into(),
            record,
        });
    }
    put_json(tx, Collection::Records, key, &set)?;
    Ok(())
}
pub fn remove_contributions(
    tx: &mut impl WriteTx,
    origin: &WireName,
    contributor: &str,
    owners: Option<&[WireName]>,
) -> Result<bool> {
    remove_matching_contributions(tx, origin, |c| {
        c.contributor == contributor && owners.is_none_or(|names| names.contains(&c.record.name))
    })
}
/// Remove all expired contributors in one bounded zone scan, regardless of how
/// many registrations or challenges expired in the same maintenance tick.
pub(crate) fn remove_contributor_set(
    tx: &mut impl WriteTx,
    origin: &WireName,
    contributors: &std::collections::BTreeSet<String>,
) -> Result<bool> {
    remove_matching_contributions(tx, origin, |c| contributors.contains(&c.contributor))
}
fn remove_matching_contributions(
    tx: &mut impl WriteTx,
    origin: &WireName,
    remove: impl Fn(&Contribution) -> bool,
) -> Result<bool> {
    let mut changed = false;
    let mut usage = zone_usage(tx, origin)?;
    for (key, v) in tx.scan_prefix(Collection::Records, &zone_prefix(origin))? {
        let mut set: VersionedRrset =
            serde_json::from_slice(&v.bytes).map_err(StorageError::from)?;
        let before = set.contributions.len();
        let mut retained = Vec::new();
        for c in set.contributions {
            if remove(&c) {
                usage.contributions = usage
                    .contributions
                    .checked_sub(1)
                    .ok_or_else(|| inconsistent("zone contribution count underflow"))?;
                usage.wire_bytes = usage
                    .wire_bytes
                    .checked_sub(c.record.canonical_wire()?.len())
                    .ok_or_else(|| inconsistent("zone contribution bytes underflow"))?;
            } else {
                retained.push(c);
            }
        }
        set.contributions = retained;
        if before != set.contributions.len() {
            changed = true;
            if set.contributions.is_empty() {
                usage.rrsets = usage
                    .rrsets
                    .checked_sub(1)
                    .ok_or_else(|| inconsistent("zone RRset count underflow"))?;
                tx.remove(Collection::Records, &key)?;
            } else {
                put_json(tx, Collection::Records, key, &set)?;
            }
        }
    }
    if changed {
        put_zone_usage(tx, origin, &usage)?;
    }
    Ok(changed)
}
