//! Admission bounds and versioned indexes for autonomous work. Historical
//! registration/request rows remain available by key and are never scanned by
//! maintenance. All updates belong to the caller's atomic write transaction.
//!
//! This module is the lifecycle driver together with `state.rs` (maintenance
//! entry) and `zone.rs` (re-sign): there is no separate `adns-lifecycle` crate.
use crate::*;
use adns_storage::{Collection, ReadTx, StorageError, WriteTx, composite_key, get_json, put_json};
use adns_wire::{ResourceRecord, WireName};
use serde::{Deserialize, Serialize};

pub const MAX_ZONES: usize = 32;
pub const MAX_ACTIVE_REGISTRATIONS: usize = 1024;
pub const MAX_ACME_CHALLENGES: usize = 1024;
pub const MAX_OUTSTANDING_NONCES: usize = 4096;
pub const MAX_GRANT_NONCES: usize = 64;
pub const MAX_ZONE_RRSETS: usize = 4096;
pub const MAX_ZONE_CONTRIBUTIONS: usize = 16384;
pub const MAX_RRSET_CONTRIBUTIONS: usize = 256;
pub const MAX_ZONE_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BASE_RECORDS: usize = 4096;
pub const ACTIVE_REGISTRATION_PREFIX: &[u8] = b"server/v1/active-registration/";
const FORMAT_KEY: &[u8] = b"server/lifecycle-format";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleFormat {
    version: u32,
    active_registrations: usize,
}

pub(crate) fn inconsistent(detail: &'static str) -> AppError {
    StorageError::Backend(format!(
        "lifecycle state requires governed migration: {detail}"
    ))
    .into()
}
fn lifecycle_format(tx: &impl ReadTx) -> Result<LifecycleFormat> {
    let format: LifecycleFormat = get_json(tx, Collection::Lifecycle, FORMAT_KEY)?
        .ok_or_else(|| inconsistent("missing format marker"))?;
    if format.version != 1 || format.active_registrations > MAX_ACTIVE_REGISTRATIONS {
        return Err(inconsistent(
            "unsupported format or active registration count",
        ));
    }
    Ok(format)
}
pub fn validate_lifecycle_format(tx: &impl ReadTx) -> Result<()> {
    lifecycle_format(tx).map(|_| ())
}
/// Initialize only a new authority. Old snapshots never silently reconstruct
/// authority from historic registrations; a governed offline migration must
/// validate and rebuild the active index and per-zone usage before activation.
pub(crate) fn initialize_lifecycle(tx: &mut impl WriteTx) -> Result<()> {
    if tx.get(Collection::Lifecycle, FORMAT_KEY)?.is_some() {
        return validate_lifecycle_format(tx);
    }
    for table in [
        Collection::Zones,
        Collection::Registrations,
        Collection::Records,
        Collection::Nonces,
        Collection::AcmeChallenges,
    ] {
        if !tx.scan_prefix(table, b"")?.is_empty() {
            return Err(inconsistent("legacy state has no active index"));
        }
    }
    put_json(
        tx,
        Collection::Lifecycle,
        FORMAT_KEY.to_vec(),
        &LifecycleFormat {
            version: 1,
            active_registrations: 0,
        },
    )?;
    Ok(())
}
fn active_key(id: &str) -> Vec<u8> {
    [ACTIVE_REGISTRATION_PREFIX, id.as_bytes()].concat()
}
pub fn require_active_registration_index(tx: &impl ReadTx, id: &str) -> Result<()> {
    validate_lifecycle_format(tx)?;
    let entry: String = get_json(tx, Collection::Lifecycle, &active_key(id))?
        .ok_or_else(|| inconsistent("active registration missing index entry"))?;
    if entry != id {
        return Err(inconsistent("active registration index identity"));
    }
    Ok(())
}
/// Also used by explicitly seeded development fixtures. This does not authorize
/// a registration; production calls it only after successful admission.
pub fn index_active_registration(tx: &mut impl WriteTx, id: &str) -> Result<()> {
    let mut format = lifecycle_format(tx)?;
    if tx.get(Collection::Lifecycle, &active_key(id))?.is_some() {
        return Err(inconsistent("duplicate active registration index"));
    }
    let registration: Registration = get_json(tx, Collection::Registrations, id.as_bytes())?
        .ok_or_else(|| inconsistent("index references missing registration"))?;
    if registration.status != "active" || registration.registration_id != id {
        return Err(inconsistent("index references inactive registration"));
    }
    if format.active_registrations >= MAX_ACTIVE_REGISTRATIONS {
        return Err(AppError::Capacity("active registrations"));
    }
    format.active_registrations += 1;
    put_json(tx, Collection::Lifecycle, active_key(id), &id)?;
    put_json(tx, Collection::Lifecycle, FORMAT_KEY.to_vec(), &format)?;
    Ok(())
}
pub(crate) fn unindex_active_registration(tx: &mut impl WriteTx, id: &str) -> Result<()> {
    require_active_registration_index(tx, id)?;
    let mut format = lifecycle_format(tx)?;
    format.active_registrations = format
        .active_registrations
        .checked_sub(1)
        .ok_or_else(|| inconsistent("active registration count underflow"))?;
    tx.remove(Collection::Lifecycle, &active_key(id))?;
    put_json(tx, Collection::Lifecycle, FORMAT_KEY.to_vec(), &format)?;
    Ok(())
}
pub(crate) fn active_registration_ids(tx: &impl ReadTx) -> Result<Vec<String>> {
    let format = lifecycle_format(tx)?;
    let entries = tx.scan_prefix(Collection::Lifecycle, ACTIVE_REGISTRATION_PREFIX)?;
    if entries.len() != format.active_registrations {
        return Err(inconsistent(
            "active registration count disagrees with index",
        ));
    }
    entries
        .into_iter()
        .map(|(key, value)| {
            let id: String = serde_json::from_slice(&value.bytes).map_err(StorageError::from)?;
            if active_key(&id) != key {
                return Err(inconsistent("active index key"));
            }
            Ok(id)
        })
        .collect()
}
pub(crate) fn admit_registration(tx: &impl ReadTx) -> Result<()> {
    if lifecycle_format(tx)?.active_registrations >= MAX_ACTIVE_REGISTRATIONS {
        return Err(AppError::Capacity("active registrations"));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ZoneUsage {
    pub rrsets: usize,
    pub contributions: usize,
    pub wire_bytes: usize,
    pub base_wire_bytes: usize,
    pub base_rrsets: usize,
}
fn usage_key(zone: &WireName) -> Vec<u8> {
    composite_key(&[b"server/v1/zone-usage", zone.as_slice()])
}
pub(crate) fn zone_usage(tx: &impl ReadTx, zone: &WireName) -> Result<ZoneUsage> {
    let usage: ZoneUsage = get_json(tx, Collection::Lifecycle, &usage_key(zone))?
        .ok_or_else(|| inconsistent("missing zone usage"))?;
    if usage.rrsets.saturating_add(usage.base_rrsets) > MAX_ZONE_RRSETS
        || usage.contributions > MAX_ZONE_CONTRIBUTIONS
        || usage.wire_bytes > MAX_ZONE_RECORD_BYTES
        || usage.base_wire_bytes > MAX_ZONE_RECORD_BYTES
        || usage.wire_bytes.saturating_add(usage.base_wire_bytes) > MAX_ZONE_RECORD_BYTES
    {
        return Err(inconsistent("zone usage exceeds supported bounds"));
    }
    Ok(usage)
}
pub(crate) fn put_zone_usage(
    tx: &mut impl WriteTx,
    zone: &WireName,
    usage: &ZoneUsage,
) -> Result<()> {
    put_json(tx, Collection::Lifecycle, usage_key(zone), usage)?;
    Ok(())
}
pub(crate) fn initialize_zone_usage(
    tx: &mut impl WriteTx,
    zone: &WireName,
    base: &[ResourceRecord],
) -> Result<()> {
    if base.len() > MAX_BASE_RECORDS {
        return Err(AppError::Capacity("base records"));
    }
    let mut usage = ZoneUsage {
        base_rrsets: base
            .iter()
            .map(|r| (r.name, r.rtype))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        ..ZoneUsage::default()
    };
    for record in base {
        usage.base_wire_bytes = usage
            .base_wire_bytes
            .checked_add(record.canonical_wire()?.len())
            .ok_or(AppError::Capacity("zone record bytes"))?;
        if usage.base_wire_bytes > MAX_ZONE_RECORD_BYTES {
            return Err(AppError::Capacity("zone record bytes"));
        }
    }
    put_zone_usage(tx, zone, &usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adns_storage::{DnsStorage, MemoryStorage};
    use adns_wire::RData;
    #[test]
    fn byte_budget_rejects_large_governed_initial_records_before_signing() {
        let db = MemoryStorage::default();
        let mut tx = db.write().unwrap();
        initialize_lifecycle(&mut tx).unwrap();
        let origin = "example.".parse().unwrap();
        let record =
            ResourceRecord::new(origin, 300, RData::Txt(vec![vec![b'x'; 255]; 255])).unwrap();
        let below_limit = MAX_ZONE_RECORD_BYTES / record.canonical_wire().unwrap().len();
        initialize_zone_usage(&mut tx, &origin, &vec![record.clone(); below_limit]).unwrap();
        assert!(matches!(
            initialize_zone_usage(&mut tx, &origin, &vec![record; below_limit + 1]),
            Err(AppError::Capacity(_))
        ));
    }
}
