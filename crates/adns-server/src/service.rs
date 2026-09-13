use crate::*;
use adns_attest::AppraisalPolicy;
use adns_auth::*;
use adns_storage::{Collection, ReadTx, WriteTx, get_json, put_json};
use adns_wire::{RData, ResourceRecord, WireName};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppResponse {
    pub http_status: u16,
    pub body: Value,
    /// Set on a replay, so the adapter can recover the ORIGINAL transaction ID.
    pub original_version: Option<u64>,
    pub changed_zones: Vec<String>,
    pub claims_digest: Option<[u8; 32]>,
    /// A rejected authenticated attempt may commit ONLY its bounded diagnostic
    /// metadata. The adapter must gate this error response on global commit.
    pub commit_error: bool,
    /// Reconciliation's pending/failed execution status must not become success
    /// merely because its observation transaction committed.
    pub promote_status_on_commit: bool,
}
impl AppResponse {
    pub fn new(body: Value) -> Self {
        Self {
            http_status: 200,
            body,
            original_version: None,
            changed_zones: Vec::new(),
            claims_digest: None,
            commit_error: false,
            promote_status_on_commit: true,
        }
    }
}
pub(crate) fn configuration(tx: &impl ReadTx) -> Result<ServiceConfiguration> {
    validate_lifecycle_format(tx)?;
    get_json(tx, Collection::Lifecycle, b"configuration")?
        .ok_or(AppError::NotFound("governed service configuration"))
}
fn grant(tx: &impl ReadTx, id: &str) -> Result<OwnerGrant> {
    get_json(tx, Collection::Grants, id.as_bytes())?.ok_or(AppError::NotFound("owner grant"))
}
fn policy(tx: &impl ReadTx, origin: &WireName) -> Result<AppraisalPolicy> {
    get_json(tx, Collection::Policies, origin.as_slice())?
        .ok_or(AppError::NotFound("appraisal policy"))
}
fn registration(tx: &impl ReadTx, id: &str) -> Result<Registration> {
    let r: Registration = get_json(tx, Collection::Registrations, id.as_bytes())?
        .ok_or(AppError::NotFound("registration"))?;
    if r.registration_id != id {
        return Err(inconsistent("registration identity"));
    }
    if r.status == "active" {
        require_active_registration_index(tx, id)?;
    }
    Ok(r)
}
fn active_registration(tx: &impl ReadTx, id: &str, now: u64) -> Result<Registration> {
    let r = registration(tx, id)?;
    if r.status != "active"
        || r.lease_expires_at <= now
        || r.reappraisal_deadline <= now
        || registration_authority_invalid(tx, &r, now)?
    {
        return Err(AppError::Conflict("registration inactive"));
    }
    Ok(r)
}
fn registration_authority_invalid(tx: &impl ReadTx, r: &Registration, now: u64) -> Result<bool> {
    let g = get_json::<OwnerGrant>(tx, Collection::Grants, r.grant_id.as_bytes())?;
    let origin: WireName = r.zone.parse()?;
    let p = get_json::<AppraisalPolicy>(tx, Collection::Policies, origin.as_slice())?;
    Ok(g.as_ref().is_none_or(|g| {
        g.revoked
            || g.valid_from > now
            || g.valid_until <= now
            || g.subject_spki_sha256 != r.signer_spki_sha256
            || !g.zones.contains(&r.zone)
            || authorize_registration_scope(&r.parameters, g).is_err()
    }) || p.as_ref().is_none_or(|p| {
        p.valid_from > now
            || p.valid_until <= now
            || !p.active_profiles.contains(&r.parameters.evidence_profile)
            || hex::encode(p.policy_id) != r.policy_id
    }))
}
pub(crate) fn expected_route(operation: Operation) -> (&'static str, &'static str) {
    match operation {
        Operation::Register => ("POST", "/service/register"),
        Operation::Renew => ("POST", "/service/renew"),
        Operation::Deregister => ("POST", "/service/deregister"),
        Operation::AcmeChallengeCreate => ("POST", "/zone/acme-challenge"),
        Operation::AcmeChallengeDelete => ("DELETE", "/zone/acme-challenge"),
        Operation::OperatorRecords => ("POST", "/zone/operator/records"),
    }
}
/// The caller MUST discard the entire transaction on ANY returned error.
/// Do not send the response or notify a secondary before global commitment.
pub fn mutate(
    tx: &mut impl WriteTx,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<AppResponse> {
    let mut config = configuration(tx)?;
    if now < config.last_time {
        return Err(AppError::Invalid("time moved backwards"));
    }
    if method == "POST" && path == "/service/nonce" {
        let request = parse_nonce_request(body)?;
        let g = grant(tx, &request.action.grant_id)?;
        authorize_action(&request.action, &g, &config.audience, now)?;
        let origin: WireName = request.action.zone.parse()?;
        zone_metadata(tx, &origin)?;
        let nonces = collect_live_nonces(tx, now, config.epoch)?;
        if nonces.len() >= MAX_OUTSTANDING_NONCES
            || nonces
                .iter()
                .filter(|nonce| nonce.grant_id == g.grant_id)
                .count()
                >= MAX_GRANT_NONCES
        {
            return Err(AppError::Capacity("outstanding nonces"));
        }
        let nonce = issue_nonce(&request.action, now)?;
        let key = nonce_key(config.epoch, &nonce.nonce);
        if tx.get(Collection::Nonces, &key)?.is_some() {
            return Err(AppError::Conflict("nonce collision"));
        }
        put_json(tx, Collection::Nonces, key, &nonce)?;
        config.last_time = now;
        put_json(
            tx,
            Collection::Lifecycle,
            b"configuration".to_vec(),
            &config,
        )?;
        return Ok(AppResponse::new(json!(nonce.response())));
    }
    let request = parse_signed_request(body)?;
    if expected_route(request.action.operation()) != (method, path) {
        return Err(AppError::Invalid("operation does not match endpoint"));
    }
    let verified = verify_request_signature(&request)?;
    let result_key = request_key(&request.action.grant_id, &request.action.request_id);
    if let Some(v) = tx.get(Collection::RequestResults, &result_key)? {
        let result: RequestResult =
            serde_json::from_slice(&v.bytes).map_err(adns_storage::StorageError::from)?;
        if result.signed_message_digest != verified.signed_message_digest {
            return Err(AppError::Auth(AuthError::RequestIdConflict));
        }
        let mut response = AppResponse::new(result.body);
        response.http_status = result.http_status;
        response.original_version = Some(v.version);
        return Ok(response);
    }
    let key = nonce_key(config.epoch, &request.nonce);
    let nonce: NonceRecord =
        get_json(tx, Collection::Nonces, &key)?.ok_or(AppError::Auth(AuthError::InvalidNonce))?;
    validate_nonce(&request, &nonce, now)?;
    let g = grant(tx, &request.action.grant_id)?;
    authorize_action(&request.action, &g, &config.audience, now)?;
    let origin: WireName = request.action.zone.parse()?;
    zone_metadata(tx, &origin)?;
    let mut changed = false;
    let result = match &request.action.parameters {
        ActionParameters::Register(p) => {
            admit_registration(tx)?;
            let policy = policy(tx, &origin)?;
            let appraisal = adns_attest::appraise(
                &p.evidence_profile,
                verified
                    .evidence_payload
                    .as_deref()
                    .ok_or(AppError::Invalid("missing evidence"))?,
                &verified.signer_spki_der,
                &policy,
                now,
            )?;
            let id = format!("reg-{}", &verified.signed_message_digest[..32]);
            if tx.get(Collection::Registrations, id.as_bytes())?.is_some() {
                return Err(AppError::Conflict("registration ID collision"));
            }
            let lease = bounded_lease_expiration(
                now,
                p.lease_seconds,
                g.valid_until,
                policy.valid_until,
                appraisal.valid_until,
            )?;
            let mut contributions = mail_contributions(p, &verified.signer_spki_sha256)?;
            for record in &mut contributions {
                record.ttl = record
                    .ttl
                    .min((lease - now).min(u64::from(u32::MAX)) as u32);
                add_contribution(tx, &origin, &id, record.clone())?;
            }
            let r = Registration {
                registration_id: id.clone(),
                grant_id: g.grant_id.clone(),
                zone: request.action.zone.clone(),
                signer_spki_sha256: verified.signer_spki_sha256.clone(),
                parameters: p.clone(),
                admitted_at: now,
                lease_expires_at: lease,
                policy_valid_until: policy.valid_until,
                reappraisal_deadline: appraisal.valid_until,
                policy_id: hex::encode(appraisal.policy_id),
                evidence_digest: p.evidence_digest.clone(),
                status: "active".into(),
                active_ports: p.ports.clone(),
            };
            put_json(tx, Collection::Registrations, id.as_bytes().to_vec(), &r)?;
            index_active_registration(tx, &id)?;
            changed = true;
            json!({"status":"pending","registration_id":id,"lease_expires_at":lease,"contributions":contributions})
        }
        ActionParameters::Renew(p) => {
            let mut r = registration(tx, &p.registration_id)?;
            if r.status != "active" || r.lease_expires_at <= now {
                return Err(AppError::Conflict("registration inactive"));
            }
            authorize_registration_target(
                &request.action,
                &r.grant_id,
                &r.signer_spki_sha256,
                &r.zone,
            )?;
            authorize_registration_scope(&r.parameters, &g)?;
            let policy = policy(tx, &origin)?;
            if let Some(profile) = &p.evidence_profile {
                let appraisal = adns_attest::appraise(
                    profile,
                    verified
                        .evidence_payload
                        .as_deref()
                        .ok_or(AppError::Invalid("missing evidence"))?,
                    &verified.signer_spki_der,
                    &policy,
                    now,
                )?;
                r.policy_valid_until = policy.valid_until;
                r.reappraisal_deadline = appraisal.valid_until;
                r.policy_id = hex::encode(appraisal.policy_id);
                r.evidence_digest = p
                    .evidence_digest
                    .clone()
                    .ok_or(AppError::Invalid("missing evidence digest"))?;
            } else if !policy
                .active_profiles
                .contains(&r.parameters.evidence_profile)
                || hex::encode(policy.policy_id) != r.policy_id
                || policy.valid_from > now
                || policy.valid_until <= now
            {
                return Err(AppError::Conflict("fresh appraisal required"));
            }
            r.lease_expires_at = bounded_lease_expiration(
                r.admitted_at,
                p.requested_lease_seconds,
                g.valid_until,
                r.policy_valid_until.min(policy.valid_until),
                r.reappraisal_deadline,
            )?;
            if r.lease_expires_at <= now {
                return Err(AppError::Conflict(
                    "requested lease already elapsed since admission",
                ));
            }
            put_json(
                tx,
                Collection::Registrations,
                r.registration_id.as_bytes().to_vec(),
                &r,
            )?;
            json!({"status":"pending","registration_id":r.registration_id,"lease_expires_at":r.lease_expires_at})
        }
        ActionParameters::Deregister(p) => {
            let mut r = registration(tx, &p.registration_id)?;
            authorize_registration_target(
                &request.action,
                &r.grant_id,
                &r.signer_spki_sha256,
                &r.zone,
            )?;
            if p.withdraw_all {
                changed = remove_contributions(tx, &origin, &r.registration_id, None)?;
                if r.status == "active" {
                    unindex_active_registration(tx, &r.registration_id)?;
                }
                r.status = "withdrawn".into();
                r.active_ports.clear();
            } else {
                if p.selected_ports.iter().any(|p| !r.active_ports.contains(p)) {
                    return Err(AppError::Invalid("port not active in registration"));
                }
                let owners = p
                    .selected_ports
                    .iter()
                    .map(|port| format!("_{port}._tcp.{}", r.parameters.service_host).parse())
                    .collect::<std::result::Result<Vec<WireName>, _>>()?;
                changed = remove_contributions(tx, &origin, &r.registration_id, Some(&owners))?;
                r.active_ports.retain(|p| !p_selected(p, &request));
            }
            put_json(
                tx,
                Collection::Registrations,
                r.registration_id.as_bytes().to_vec(),
                &r,
            )?;
            json!({"status":"pending","registration_id":r.registration_id,"registration_status":r.status,"active_ports":r.active_ports})
        }
        ActionParameters::AcmeChallengeCreate(p) => {
            if tx.scan_prefix(Collection::AcmeChallenges, b"")?.len() >= MAX_ACME_CHALLENGES {
                return Err(AppError::Capacity("ACME challenges"));
            }
            let r = active_registration(tx, &p.registration_id, now)?;
            authorize_acme_registration_target(
                &request.action,
                &r.zone,
                &r.parameters.service_host,
                true,
            )?;
            let id = format!("chal-{}", &verified.signed_message_digest[..32]);
            let expires = now
                .checked_add(p.lifetime_seconds)
                .ok_or(AppError::Invalid("challenge expiration"))?
                .min(g.valid_until)
                .min(r.lease_expires_at);
            if expires <= now {
                return Err(AppError::Invalid("challenge lifetime"));
            }
            let c = AcmeChallenge {
                challenge_id: id.clone(),
                grant_id: g.grant_id.clone(),
                registration_id: r.registration_id,
                order_id: p.order_id.clone(),
                zone: request.action.zone.clone(),
                name: p.name.clone(),
                txt_value: p.txt_value.clone(),
                ttl: p.ttl.min((expires - now).min(u64::from(u32::MAX)) as u32),
                expires_at: expires,
                signer_spki_sha256: verified.signer_spki_sha256.clone(),
            };
            add_contribution(
                tx,
                &origin,
                &id,
                ResourceRecord::new(
                    format!("_acme-challenge.{}", p.name).parse()?,
                    c.ttl,
                    RData::Txt(vec![p.txt_value.as_bytes().to_vec()]),
                )?,
            )?;
            put_json(tx, Collection::AcmeChallenges, id.as_bytes().to_vec(), &c)?;
            changed = true;
            json!({"status":"pending","challenge_id":id,"expires_at":expires})
        }
        ActionParameters::AcmeChallengeDelete(p) => {
            let c: AcmeChallenge =
                get_json(tx, Collection::AcmeChallenges, p.challenge_id.as_bytes())?
                    .ok_or(AppError::NotFound("challenge"))?;
            authorize_challenge_target(&request.action, &c.grant_id, &c.zone)?;
            if c.signer_spki_sha256 != verified.signer_spki_sha256 {
                return Err(AppError::Auth(AuthError::GrantDenied(
                    "challenge key".into(),
                )));
            }
            changed = remove_contributions(tx, &origin, &c.challenge_id, None)?;
            tx.remove(Collection::AcmeChallenges, c.challenge_id.as_bytes())?;
            json!({"status":"pending","challenge_id":c.challenge_id,"deleted":true})
        }
        ActionParameters::OperatorRecords(p) => {
            apply_operator_records(tx, &origin, &g.grant_id, p)?;
            changed = true;
            json!({"status":"pending"})
        }
    };
    if changed {
        resign_zone(tx, &origin, now, true)?;
    }
    let metadata = zone_metadata(tx, &origin)?;
    let mut result = result;
    result["zone_serial"] = json!(metadata.serial);
    result["frontend_propagation"] = json!({"status":"pending_commit"});
    // RequestResults is checked before nonce lookup, so committed retries still
    // return their original result without retaining consumed live nonce rows.
    tx.remove(Collection::Nonces, &key)?;
    remove_failed_attempt(tx, &key)?;
    let historical = RequestResult {
        grant_id: g.grant_id,
        request_id: request.action.request_id,
        signed_message_digest: verified.signed_message_digest,
        http_status: 200,
        body: result.clone(),
    };
    put_json(tx, Collection::RequestResults, result_key, &historical)?;
    config.last_time = now;
    put_json(
        tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &config,
    )?;
    let mut response = AppResponse::new(result);
    if changed {
        response.changed_zones.push(origin.to_string());
    }
    Ok(response)
}
fn p_selected(port: &u16, request: &SignedRequest) -> bool {
    matches!(&request.action.parameters,ActionParameters::Deregister(p) if p.selected_ports.contains(port))
}

/// A single autonomous transaction performs expiry and signing without requiring
/// a service request. The CCF timer schedules this independently of HTTP traffic.
pub fn maintenance(tx: &mut impl WriteTx, now: u64) -> Result<Vec<String>> {
    let mut config = configuration(tx)?;
    if now < config.last_time {
        return Err(AppError::Invalid("time moved backwards"));
    }
    let mut dirty = BTreeSet::new();
    let mut removals: BTreeMap<WireName, BTreeSet<String>> = BTreeMap::new();
    for id in active_registration_ids(tx)? {
        let mut r = registration(tx, &id)?;
        if r.status != "active" {
            return Err(inconsistent("inactive registration in active index"));
        }
        let origin: WireName = r.zone.parse()?;
        let invalid = registration_authority_invalid(tx, &r, now)?;
        if r.lease_expires_at <= now || r.reappraisal_deadline <= now || invalid {
            removals
                .entry(origin)
                .or_default()
                .insert(r.registration_id.clone());
            r.status = if invalid { "withdrawn" } else { "expired" }.into();
            r.active_ports.clear();
            unindex_active_registration(tx, &r.registration_id)?;
            put_json(tx, Collection::Registrations, id.as_bytes().to_vec(), &r)?;
        }
    }
    let challenges = tx.scan_prefix(Collection::AcmeChallenges, b"")?;
    if challenges.len() > MAX_ACME_CHALLENGES {
        return Err(inconsistent("challenge capacity"));
    }
    for (key, v) in challenges {
        let c: AcmeChallenge =
            serde_json::from_slice(&v.bytes).map_err(adns_storage::StorageError::from)?;
        let g = get_json::<OwnerGrant>(tx, Collection::Grants, c.grant_id.as_bytes())?;
        let r =
            get_json::<Registration>(tx, Collection::Registrations, c.registration_id.as_bytes())?;
        if c.expires_at <= now
            || g.is_none_or(|g| {
                g.validate().is_err()
                    || g.revoked
                    || g.valid_from > now
                    || g.valid_until <= now
                    || g.subject_spki_sha256 != c.signer_spki_sha256
                    || !g.zones.contains(&c.zone)
                    || !g.acme_names.contains(&c.name)
                    || !g
                        .allowed_operations
                        .contains(&Operation::AcmeChallengeCreate)
            })
            || r.is_none_or(|r| {
                r.status != "active"
                    || r.lease_expires_at <= now
                    || r.reappraisal_deadline <= now
                    || r.zone != c.zone
                    || r.parameters.service_host != c.name
            })
        {
            removals
                .entry(c.zone.parse()?)
                .or_default()
                .insert(c.challenge_id.clone());
            tx.remove(Collection::AcmeChallenges, &key)?;
        }
    }
    for (origin, contributors) in removals {
        if remove_contributor_set(tx, &origin, &contributors)? {
            dirty.insert(origin);
        }
    }
    collect_live_nonces(tx, now, config.epoch)?;
    let zones = tx.scan_prefix(Collection::Zones, b"")?;
    if zones.len() > MAX_ZONES {
        return Err(inconsistent("zone count exceeds supported bound"));
    }
    for (_, v) in zones {
        let zone: ZoneMetadata =
            serde_json::from_slice(&v.bytes).map_err(adns_storage::StorageError::from)?;
        if now.saturating_add(zone.refresh_before.into()) >= zone.earliest_signature_expiration {
            dirty.insert(zone.origin);
        }
    }
    for origin in &dirty {
        resign_zone(tx, origin, now, true)?;
    }
    config.last_time = now;
    put_json(
        tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &config,
    )?;
    Ok(dirty.into_iter().map(|n| n.to_string()).collect())
}
/// Nonces have a separate bounded live table; consumed rows are deleted by the
/// successful mutation, and expiry collection never scans historical results.
fn collect_live_nonces(tx: &mut impl WriteTx, now: u64, epoch: u64) -> Result<Vec<NonceRecord>> {
    let entries = tx.scan_prefix(Collection::Nonces, b"")?;
    if entries.len() > MAX_OUTSTANDING_NONCES {
        return Err(inconsistent("nonce capacity"));
    }
    let mut live = Vec::new();
    for (key, value) in entries {
        let nonce: NonceRecord =
            serde_json::from_slice(&value.bytes).map_err(adns_storage::StorageError::from)?;
        if nonce.expires_at <= now || nonce.consumed || key != nonce_key(epoch, &nonce.nonce) {
            tx.remove(Collection::Nonces, &key)?;
            remove_failed_attempt(tx, &key)?;
        } else {
            live.push(nonce);
        }
    }
    Ok(live)
}

/// Read endpoints operate on a caller-provided committed snapshot. A CCF adapter
/// must globally confirm the read version, including for status and retries.
pub fn read_json(
    tx: &impl ReadTx,
    path: &str,
    query: &[(String, String)],
    now: u64,
) -> Result<AppResponse> {
    let parameter = |name: &str| -> Result<&str> {
        let mut matches = query.iter().filter(|(k, _)| k == name);
        let value = matches
            .next()
            .ok_or(AppError::Invalid("missing query parameter"))?;
        if matches.next().is_some() {
            return Err(AppError::Invalid("duplicate query parameter"));
        }
        Ok(&value.1)
    };
    match path {
        "/service/registration" => {
            let registration = registration(tx, parameter("registration_id")?)?;
            let origin: WireName = registration.zone.parse()?;
            let effective_status = if registration.status != "active" {
                registration.status.as_str()
            } else if registration_authority_invalid(tx, &registration, now)? {
                "withdrawn"
            } else if registration.lease_expires_at <= now
                || registration.reappraisal_deadline <= now
            {
                "expired"
            } else {
                "active"
            };
            let mut contributions = Vec::new();
            for (_, value) in tx.scan_prefix(Collection::Records, &zone_prefix(&origin))? {
                let rrset: VersionedRrset = serde_json::from_slice(&value.bytes)
                    .map_err(adns_storage::StorageError::from)?;
                contributions.extend(
                    rrset
                        .contributions
                        .into_iter()
                        .filter(|c| c.contributor == registration.registration_id)
                        .map(|c| c.record),
                );
            }
            let mut body = json!(registration);
            // Reads must not describe expired/revoked authority as eligible
            // while the independent maintenance transaction catches up. Keep
            // committed rows explicit; these are not secondary/cache claims.
            body["committed_status"] = json!(registration.status);
            body["status"] = json!(effective_status);
            body["committed_contributions"] = json!(contributions);
            body["active_contributions"] = if effective_status == "active" {
                json!(contributions)
            } else {
                body["active_ports"] = json!([]);
                json!([])
            };
            Ok(AppResponse::new(body))
        }
        "/service/request" => {
            let key = request_key(parameter("grant_id")?, parameter("request_id")?);
            let Some(v) = tx.get(Collection::RequestResults, &key)? else {
                return reconcile_uncompleted(
                    tx,
                    parameter("grant_id")?,
                    parameter("request_id")?,
                    now,
                );
            };
            let result: RequestResult =
                serde_json::from_slice(&v.bytes).map_err(adns_storage::StorageError::from)?;
            let mut response = AppResponse::new(result.body);
            response.original_version = Some(v.version);
            Ok(response)
        }
        "/zone/status" => {
            let origin: WireName = parameter("zone")?.parse()?;
            let zone = zone_metadata(tx, &origin)?;
            let mut secondaries = Vec::new();
            for (_, v) in tx.scan_prefix(Collection::SecondaryStatus, &zone_prefix(&origin))? {
                let state: adns_transfer::SecondaryState =
                    serde_json::from_slice(&v.bytes).map_err(adns_storage::StorageError::from)?;
                let mut value = json!(state);
                value["in_sync"] = json!(state.in_sync(zone.serial, now, 60));
                secondaries.push(value);
            }
            Ok(AppResponse::new(
                json!({"zone":origin.to_string(),"committed_state":{"serial":zone.serial,"rrsig_inception":zone.last_signed_at.saturating_sub(300),"earliest_rrsig_expiration":zone.earliest_signature_expiration,"maintenance_health":if now>=zone.earliest_signature_expiration{"expired"}else if now.saturating_add(zone.refresh_before.into())>=zone.earliest_signature_expiration{"refresh_due"}else{&zone.maintenance_health}},"frontend_propagation":{"secondaries":secondaries}}),
            ))
        }
        "/governance/ksk-receipt" => {
            Err(AppError::Invalid("CCF historical receipt adapter required"))
        }
        _ => Err(AppError::NotFound("endpoint")),
    }
}
