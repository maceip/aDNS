use crate::*;
use adns_dnssec::{DenialMode, SignedZone, SigningKey};
use adns_storage::{Collection, WriteTx, composite_key, put_json};
use adns_telemetry::{Name, observe};
use adns_wire::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Called only by a governance adapter, never from an unauthenticated endpoint.
pub fn initialize_zone(tx: &mut impl WriteTx, mut metadata: ZoneMetadata, now: u64) -> Result<()> {
    initialize_lifecycle(tx)?;
    if tx
        .get(Collection::Zones, metadata.origin.as_slice())?
        .is_some()
    {
        return Err(AppError::Conflict("zone exists"));
    }
    if metadata.signature_validity < 600
        || metadata.refresh_before < 300
        || metadata.refresh_before >= metadata.signature_validity
        || metadata
            .base_records
            .iter()
            .any(|r| !r.name.is_subdomain_of(&metadata.origin))
    {
        return Err(AppError::Invalid("zone signature settings or owner"));
    }
    if tx.scan_prefix(Collection::Zones, b"")?.len() >= MAX_ZONES {
        return Err(AppError::Capacity("zones"));
    }
    initialize_zone_usage(tx, &metadata.origin, &metadata.base_records)?;
    let ksk = SigningKey::generate().map_err(|e| AppError::Dnssec(e.to_string()))?;
    let zsk = SigningKey::generate().map_err(|e| AppError::Dnssec(e.to_string()))?;
    tx.put(
        Collection::PrivateKeys,
        composite_key(&[metadata.origin.as_slice(), b"ksk"]),
        ksk.pkcs8().to_vec(),
    )?;
    tx.put(
        Collection::PrivateKeys,
        composite_key(&[metadata.origin.as_slice(), b"zsk"]),
        zsk.pkcs8().to_vec(),
    )?;
    metadata.signed_records.clear();
    metadata.last_signed_at = 0;
    metadata.earliest_signature_expiration = 0;
    put_json(
        tx,
        Collection::Zones,
        metadata.origin.as_slice().to_vec(),
        &metadata,
    )?;
    resign_zone(tx, &metadata.origin, now, false)?;
    Ok(())
}
pub fn resign_zone(
    tx: &mut impl WriteTx,
    origin: &WireName,
    now: u64,
    advance_serial: bool,
) -> Result<()> {
    let mut metadata = zone_metadata(tx, origin)?;
    if advance_serial {
        metadata.serial = metadata.serial.wrapping_add(1);
    }
    let key = |kind: &[u8]| -> Result<SigningKey> {
        let value = tx
            .get(
                Collection::PrivateKeys,
                &composite_key(&[origin.as_slice(), kind]),
            )?
            .ok_or(AppError::NotFound("DNSSEC private key"))?;
        SigningKey::from_pkcs8(&value.bytes).map_err(|e| AppError::Dnssec(e.to_string()))
    };
    let ksk = key(b"ksk")?;
    let zsk = key(b"zsk")?;
    let next_ksk = match &metadata.ksk_rollover {
        Some(_) => Some(key(b"ksk-next")?),
        None => None,
    };
    zone_usage(tx, origin)?;
    // Pre-size for owned contributions to avoid a reallocation on extend;
    // full-zone re-sign is still O(RRsets) — incremental signing is tracked
    // work, and benches/adns-dnssec-sign now pins the current cost.
    let owned = records(tx, origin)?;
    let mut all = Vec::with_capacity(metadata.base_records.len() + owned.len());
    all.extend(metadata.base_records.iter().cloned());
    for r in &mut all {
        if let RData::Soa(soa) = &mut r.rdata {
            soa.serial = metadata.serial;
        }
    }
    all.extend(owned);
    // Governed base records and owned contributions may share an RRset. Its
    // TTL and duplicate handling must include every source before signing.
    let all = normalize_rrsets(all)?;
    let ksks: Vec<&SigningKey> = match &next_ksk {
        Some(next) => vec![&ksk, next],
        None => vec![&ksk],
    };
    let signed = observe(Name::DnssecSign, || {
        SignedZone::sign_with_keysets(
            *origin,
            all,
            &ksks,
            &zsk,
            u32::try_from(now).map_err(|_| AppError::Invalid("DNSSEC time range"))?,
            metadata.signature_validity,
            DenialMode::Nsec3 {
                iterations: 0,
                salt: vec![],
            },
        )
        .map_err(|e| AppError::Dnssec(e.to_string()))
    })?;
    metadata.signed_records = signed.records;
    metadata.ksk_dnskey_rdata = RData::Dnskey(ksk.dnskey(257)).to_wire()?;
    if let (Some(rollover), Some(next)) = (&mut metadata.ksk_rollover, &next_ksk) {
        rollover.next_ksk_dnskey_rdata = RData::Dnskey(next.dnskey(257)).to_wire()?;
    }
    metadata.last_signed_at = now;
    metadata.earliest_signature_expiration = now + u64::from(metadata.signature_validity);
    metadata.maintenance_health = "ok".into();
    put_json(tx, Collection::Zones, origin.as_slice().to_vec(), &metadata)?;
    Ok(())
}
/// Explicit domain separation and lengths bind the canonical owner and COMPLETE
/// DNSKEY RDATA. The CCF adapter records this as its transaction claims digest.
pub fn ksk_claims_digest(owner: &WireName, rdata: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"agentdns.ksk.receipt.v1\0");
    h.update((owner.as_slice().len() as u16).to_be_bytes());
    h.update(owner.as_slice());
    h.update((rdata.len() as u32).to_be_bytes());
    h.update(rdata);
    h.finalize().into()
}
pub fn mail_contributions(
    parameters: &adns_auth::RegisterParameters,
    spki_digest: &str,
) -> Result<Vec<ResourceRecord>> {
    let host: WireName = parameters.service_host.parse()?;
    let mut out = Vec::new();
    // Only mail exchangers contribute an MX. Other attested workloads (e.g. a
    // worker publishing its DKIM and receipt keys) get A/AAAA/TLSA and their
    // attested records without becoming a mail destination.
    if parameters.role == "mx-edge" {
        out.push(ResourceRecord::new(
            parameters.mailbox_domain.parse()?,
            3600,
            RData::Mx(MxData {
                preference: 10,
                exchange: host,
            }),
        )?);
    }
    for ip in &parameters.addresses.ipv4 {
        out.push(ResourceRecord::new(
            host,
            300,
            RData::A(ip.parse().map_err(|_| AppError::Invalid("IPv4"))?),
        )?);
    }
    for ip in &parameters.addresses.ipv6 {
        out.push(ResourceRecord::new(
            host,
            300,
            RData::Aaaa(ip.parse().map_err(|_| AppError::Invalid("IPv6"))?),
        )?);
    }
    let digest = hex::decode(spki_digest).map_err(|_| AppError::Invalid("SPKI digest"))?;
    if digest.len() != 32 {
        return Err(AppError::Invalid("SPKI digest"));
    }
    for port in &parameters.ports {
        out.push(ResourceRecord::new(
            format!("_{port}._tcp.{}", parameters.service_host).parse()?,
            300,
            RData::Tlsa(TlsaData {
                usage: 3,
                selector: 1,
                matching_type: 1,
                certificate_association_data: digest.clone(),
            }),
        )?);
    }
    Ok(out)
}
/// Attested-path records requested at registration (DKIM TXT, receipt-key TXT).
/// They are contributions owned by the registration: published with it,
/// bounded by its lease and withdrawn with it. Authorization against the
/// grant's exact `attested_names`/`attested_record_types` happened earlier.
pub fn attested_contributions(
    parameters: &adns_auth::RegisterParameters,
) -> Result<Vec<ResourceRecord>> {
    let mut out = Vec::new();
    for record in &parameters.attested_records {
        let owner: WireName = record.name.parse()?;
        match record.record_type {
            adns_auth::AttestedRecordType::Txt => out.push(ResourceRecord::new(
                owner,
                record.ttl,
                RData::Txt(
                    record
                        .rdata_strings
                        .iter()
                        .map(|s| s.as_bytes().to_vec())
                        .collect(),
                ),
            )?),
        }
    }
    Ok(out)
}
/// Applies TXT/CAA and other governed static records; contribution ownership
/// prevents operator replacements from deleting independent dynamic records.
pub fn apply_operator_records(
    tx: &mut impl WriteTx,
    origin: &WireName,
    grant: &str,
    p: &adns_auth::OperatorParameters,
) -> Result<()> {
    use adns_auth::{MutationAction, OperatorRecordType};
    if zone_metadata(tx, origin)?.serial != p.expected_serial {
        return Err(AppError::Conflict("expected_serial"));
    }
    for m in &p.mutations {
        let owner: WireName = m.name.parse()?;
        let contributor = format!("operator:{grant}:{}:{:?}", m.name, m.record_type);
        if m.action != MutationAction::Add {
            remove_contributions(tx, origin, &contributor, Some(&[owner]))?;
        }
        if m.action == MutationAction::Delete && m.rdata_strings.is_empty() {
            continue;
        }
        if m.action == MutationAction::Delete {
            return Err(AppError::Invalid("delete uses empty rdata_strings"));
        }
        for s in &m.rdata_strings {
            let data = match m.record_type {
                OperatorRecordType::A => {
                    RData::A(s.parse().map_err(|_| AppError::Invalid("A RDATA"))?)
                }
                OperatorRecordType::Aaaa => {
                    RData::Aaaa(s.parse().map_err(|_| AppError::Invalid("AAAA RDATA"))?)
                }
                OperatorRecordType::Ns => RData::Ns(s.parse()?),
                OperatorRecordType::Cname => RData::Cname(s.parse()?),
                OperatorRecordType::Mx => {
                    let (pref, name) = s.split_once(' ').ok_or(AppError::Invalid("MX RDATA"))?;
                    RData::Mx(MxData {
                        preference: pref
                            .parse()
                            .map_err(|_| AppError::Invalid("MX preference"))?,
                        exchange: name.parse()?,
                    })
                }
                OperatorRecordType::Txt => {
                    RData::Txt(s.as_bytes().chunks(255).map(|c| c.to_vec()).collect())
                }
                OperatorRecordType::Caa => {
                    let mut parts = s.splitn(3, ' ');
                    let flags = parts
                        .next()
                        .ok_or(AppError::Invalid("CAA flags"))?
                        .parse()
                        .map_err(|_| AppError::Invalid("CAA flags"))?;
                    let tag = parts.next().ok_or(AppError::Invalid("CAA tag"))?;
                    let value = parts.next().ok_or(AppError::Invalid("CAA value"))?;
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .ok_or(AppError::Invalid("CAA quoted value"))?;
                    if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                        return Err(AppError::Invalid("CAA tag"));
                    }
                    RData::Caa(CaaData {
                        flags,
                        tag: tag.as_bytes().to_vec(),
                        value: value.as_bytes().to_vec(),
                    })
                }
            };
            add_contribution(
                tx,
                origin,
                &contributor,
                ResourceRecord::new(owner, m.ttl, data)?,
            )?;
        }
    }
    Ok(())
}

/// Governed KSK rollover commands, written by the constitution to
/// `public:agentdns.lifecycle/governance/ksk-rollover/<origin>` and drained by
/// maintenance inside the enclave. The parent DS change is never automated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KskRolloverCommand {
    pub zone: String,
    pub command: String,
    #[serde(default)]
    pub new_key_tag: Option<u16>,
    #[serde(default)]
    pub new_ds_sha256: Option<String>,
    #[serde(default)]
    pub minimum_hold_seconds: Option<u64>,
}

pub fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac = 0u32;
    for (i, b) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 {
            u32::from(*b) << 8
        } else {
            u32::from(*b)
        };
    }
    ac += (ac >> 16) & 0xffff;
    ac as u16
}

pub fn ds_sha256(owner: &WireName, rdata: &[u8]) -> String {
    let mut data = owner.as_slice().to_vec();
    data.extend_from_slice(rdata);
    let mut h = Sha256::new();
    h.update(&data);
    hex::encode(h.finalize())
}

/// Start: generate the incoming KSK in the enclave, publish both, sign DNSKEY
/// with both. Complete: only after the hold and only when governance attests the
/// parent DS now names the incoming key (tag + DS recomputed here must match);
/// the old key is then removed. Abort: allowed only while double-signing.
pub fn apply_ksk_rollover(
    tx: &mut impl WriteTx,
    command: &KskRolloverCommand,
    now: u64,
) -> Result<()> {
    let origin: WireName = command.zone.parse()?;
    let mut metadata = zone_metadata(tx, &origin)?;
    let next_key = composite_key(&[origin.as_slice(), b"ksk-next"]);
    let current_key = composite_key(&[origin.as_slice(), b"ksk"]);
    match command.command.as_str() {
        "start" => {
            if metadata.ksk_rollover.is_some() {
                return Err(AppError::Conflict("KSK rollover already in progress"));
            }
            let next = SigningKey::generate().map_err(|e| AppError::Dnssec(e.to_string()))?;
            tx.put(Collection::PrivateKeys, next_key, next.pkcs8().to_vec())?;
            let dnskey_ttl = metadata
                .base_records
                .iter()
                .map(|r| u64::from(r.ttl))
                .max()
                .unwrap_or(3600);
            metadata.ksk_rollover = Some(KskRollover {
                next_ksk_dnskey_rdata: RData::Dnskey(next.dnskey(257)).to_wire()?,
                started_at: now,
                minimum_hold_seconds: command
                    .minimum_hold_seconds
                    .unwrap_or_else(|| 2 * dnskey_ttl.max(3600)),
                stage: "double-signature".into(),
            });
        }
        "complete" => {
            let rollover = metadata
                .ksk_rollover
                .clone()
                .ok_or(AppError::Conflict("no KSK rollover in progress"))?;
            if now
                < rollover
                    .started_at
                    .saturating_add(rollover.minimum_hold_seconds)
            {
                return Err(AppError::Conflict("double-signature hold has not elapsed"));
            }
            let next_rdata = &rollover.next_ksk_dnskey_rdata;
            if command.new_key_tag != Some(key_tag(next_rdata))
                || command.new_ds_sha256.as_deref() != Some(ds_sha256(&origin, next_rdata).as_str())
            {
                return Err(AppError::Invalid(
                    "completion must name the incoming KSK's key tag and DS exactly",
                ));
            }
            let next_pkcs8 = tx
                .get(Collection::PrivateKeys, &next_key)?
                .ok_or(AppError::NotFound("incoming KSK"))?;
            tx.put(Collection::PrivateKeys, current_key, next_pkcs8.bytes)?;
            tx.remove(Collection::PrivateKeys, &next_key)?;
            metadata.ksk_rollover = None;
        }
        "abort" => {
            let rollover = metadata
                .ksk_rollover
                .clone()
                .ok_or(AppError::Conflict("no KSK rollover in progress"))?;
            if rollover.stage != "double-signature" {
                return Err(AppError::Conflict(
                    "rollover past double-signature cannot be aborted",
                ));
            }
            tx.remove(Collection::PrivateKeys, &next_key)?;
            metadata.ksk_rollover = None;
        }
        _ => return Err(AppError::Invalid("KSK rollover command")),
    }
    put_json(tx, Collection::Zones, origin.as_slice().to_vec(), &metadata)?;
    resign_zone(tx, &origin, now, true)
}
