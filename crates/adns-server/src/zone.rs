use crate::*;
use adns_dnssec::{DenialMode, SignedZone, SigningKey};
use adns_storage::{Collection, WriteTx, composite_key, put_json};
use adns_telemetry::{Name, observe};
use adns_wire::*;
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
    zone_usage(tx, origin)?;
    let mut all = metadata.base_records.clone();
    for r in &mut all {
        if let RData::Soa(soa) = &mut r.rdata {
            soa.serial = metadata.serial;
        }
    }
    all.extend(records(tx, origin)?);
    // Governed base records and owned contributions may share an RRset. Its
    // TTL and duplicate handling must include every source before signing.
    let all = normalize_rrsets(all)?;
    let signed = observe(Name::DnssecSign, || {
        SignedZone::sign_with_keys(
            *origin,
            all,
            &ksk,
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
    let mut out = vec![ResourceRecord::new(
        parameters.mailbox_domain.parse()?,
        3600,
        RData::Mx(MxData {
            preference: 10,
            exchange: host,
        }),
    )?];
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
