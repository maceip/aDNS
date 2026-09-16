//! Anchors and governance receipts (agent-hosting shared interface, items 2, 3, 8).
//!
//! * `POST /service/anchor` binds a caller digest (e.g. an execution-record chain
//!   head) to a committed transaction under an active registration's key. The
//!   response carries a CCF receipt whose claims digest covers exactly the
//!   stored anchor claims, so any later reader can re-verify it offline.
//! * `GET /service/anchor` re-emits a receipt for a stored anchor.
//! * `GET /governance/policy-receipt` and `GET /governance/anchors` emit
//!   receipts over the currently governed appraisal policy, node join policy,
//!   release authority and zone KSKs, so consumers can pin them in-band.
//!
//! Claims digests use explicit domain separation over canonical JSON. The
//! verifier recomputes them from the `claims` object in the response body; the
//! body never carries anything the digest does not cover.
use crate::*;
use adns_auth::{
    ActionParameters, SignedRequest, VerifiedRequest, authorize_registration_target, canonical_json,
};
use adns_storage::{Collection, ReadTx, WriteTx, get_json, put_json};
use adns_wire::WireName;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ANCHOR_CLAIMS_TYPE: &str = "agentdns-anchor-v1";
pub const POLICY_CLAIMS_TYPE: &str = "agentdns-appraisal-policy-v1";
pub const ANCHORS_CLAIMS_TYPE: &str = "agentdns-anchors-v1";
pub const MAX_ANCHORS_PER_REGISTRATION: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub grant_id: String,
    pub registration_id: String,
    pub zone: String,
    pub subject: String,
    pub sequence: u64,
    pub digest_sha256: String,
    pub anchored_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorHead {
    pub sequence: u64,
    pub digest_sha256: String,
    pub anchored_at: u64,
    pub count: u64,
}

/// Governance-written node join policy mirror (`adns_set_node_join_policy`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJoinPolicy {
    pub svn: u64,
    pub release_id: String,
    pub measurements: Vec<String>,
    pub host_data: Vec<String>,
    pub uvm_endorsements: Vec<Value>,
    pub tcb_versions: Value,
    pub policy_sha256: String,
}

/// Governance-written release authority mirror (`adns_set_release_authority`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAuthority {
    pub did: String,
    pub public_key_pem: String,
    pub svn: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

pub fn claims_digest(domain: &str, claims: &Value) -> Result<[u8; 32]> {
    let canonical = canonical_json(claims).map_err(AppError::Auth)?;
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\0");
    h.update((canonical.len() as u32).to_be_bytes());
    h.update(&canonical);
    Ok(h.finalize().into())
}

fn anchor_key(registration_id: &str, subject: &str, sequence: u64) -> Vec<u8> {
    format!("anchor/{registration_id}/{subject}/{sequence:020}").into_bytes()
}
fn head_key(registration_id: &str, subject: &str) -> Vec<u8> {
    format!("anchor-head/{registration_id}/{subject}").into_bytes()
}

fn anchor_claims(anchor: &Anchor) -> Value {
    json!({
        "type": ANCHOR_CLAIMS_TYPE,
        "grant_id": anchor.grant_id,
        "registration_id": anchor.registration_id,
        "zone": anchor.zone,
        "subject": anchor.subject,
        "sequence": anchor.sequence,
        "digest_sha256": anchor.digest_sha256,
        "anchored_at": anchor.anchored_at,
    })
}

/// Mutation arm for `ActionParameters::Anchor`. Caller has verified the request
/// signature, nonce, grant and idempotency; this checks registration ownership
/// and monotonic sequence, then stores the anchor and returns receipt claims.
pub fn anchor(
    tx: &mut impl WriteTx,
    request: &SignedRequest,
    verified: &VerifiedRequest,
    now: u64,
) -> Result<(Value, [u8; 32])> {
    let ActionParameters::Anchor(p) = &request.action.parameters else {
        return Err(AppError::Invalid("anchor parameters"));
    };
    let r = active_registration(tx, &p.registration_id, now)?;
    authorize_registration_target(&request.action, &r.grant_id, &r.signer_spki_sha256, &r.zone)?;
    if verified.signer_spki_sha256 != r.signer_spki_sha256 {
        return Err(AppError::Auth(adns_auth::AuthError::GrantDenied(
            "anchor signer".into(),
        )));
    }
    let key = anchor_key(&p.registration_id, &p.subject, p.sequence);
    if let Some(existing) = get_json::<Anchor>(tx, Collection::Lifecycle, &key)? {
        if existing.digest_sha256 != p.digest_sha256 {
            return Err(AppError::Conflict(
                "anchor sequence already bound to a different digest",
            ));
        }
        // Same digest under a new request ID: idempotent success with the
        // stored claims. The receipt is for this transaction, the claims for
        // the original anchoring time.
        return Ok((
            json!({"status":"pending","anchor":anchor_claims(&existing),"duplicate":true}),
            claims_digest(ANCHOR_CLAIMS_TYPE, &anchor_claims(&existing))?,
        ));
    }
    let head_key = head_key(&p.registration_id, &p.subject);
    let head: Option<AnchorHead> = get_json(tx, Collection::Lifecycle, &head_key)?;
    if let Some(head) = &head {
        if p.sequence <= head.sequence {
            return Err(AppError::Conflict("anchor sequence must advance"));
        }
        if head.count >= MAX_ANCHORS_PER_REGISTRATION as u64 {
            return Err(AppError::Capacity("anchors per registration"));
        }
    }
    let anchor = Anchor {
        grant_id: r.grant_id.clone(),
        registration_id: r.registration_id.clone(),
        zone: r.zone,
        subject: p.subject.clone(),
        sequence: p.sequence,
        digest_sha256: p.digest_sha256.clone(),
        anchored_at: now,
    };
    put_json(tx, Collection::Lifecycle, key, &anchor)?;
    put_json(
        tx,
        Collection::Lifecycle,
        head_key,
        &AnchorHead {
            sequence: p.sequence,
            digest_sha256: p.digest_sha256.clone(),
            anchored_at: now,
            count: head.map(|h| h.count).unwrap_or(0) + 1,
        },
    )?;
    let claims = anchor_claims(&anchor);
    let digest = claims_digest(ANCHOR_CLAIMS_TYPE, &claims)?;
    Ok((json!({"status":"pending","anchor":claims}), digest))
}

/// `GET /service/anchor?registration_id=&subject=&sequence=` (or `head=1`).
pub fn read_anchor(
    tx: &impl ReadTx,
    registration_id: &str,
    subject: &str,
    sequence: Option<u64>,
) -> Result<AppResponse> {
    adns_auth::validate_identifier(registration_id).map_err(AppError::Auth)?;
    adns_auth::validate_identifier(subject).map_err(AppError::Auth)?;
    let sequence = match sequence {
        Some(s) => s,
        None => {
            get_json::<AnchorHead>(
                tx,
                Collection::Lifecycle,
                &head_key(registration_id, subject),
            )?
            .ok_or(AppError::NotFound("anchor head"))?
            .sequence
        }
    };
    let anchor: Anchor = get_json(
        tx,
        Collection::Lifecycle,
        &anchor_key(registration_id, subject, sequence),
    )?
    .ok_or(AppError::NotFound("anchor"))?;
    let claims = anchor_claims(&anchor);
    let mut response = AppResponse::new(json!({"status":"pending","anchor":claims}));
    response.claims_digest = Some(claims_digest(ANCHOR_CLAIMS_TYPE, &claims)?);
    Ok(response)
}

fn ksk_summary(owner: &WireName, rdata: &[u8]) -> Result<Value> {
    if rdata.len() < 5 {
        return Err(AppError::Invalid("KSK DNSKEY RDATA"));
    }
    let mut ds_data = owner.as_slice().to_vec();
    ds_data.extend_from_slice(rdata);
    let mut ac = 0u32;
    for (i, b) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 {
            u32::from(*b) << 8
        } else {
            u32::from(*b)
        };
    }
    ac += (ac >> 16) & 0xffff;
    Ok(json!({
        "zone": owner.to_string(),
        "algorithm": rdata[3],
        "key_tag": ac as u16,
        "dnskey_rdata_hex": hex::encode(rdata),
        "ds_digest": {"digest_type": 2, "digest_hex": adns_auth::sha256_hex(&ds_data)},
    }))
}

fn policy_claims(zone: &WireName, policy: &Value) -> Result<Value> {
    let canonical = canonical_json(policy).map_err(AppError::Auth)?;
    Ok(json!({
        "type": POLICY_CLAIMS_TYPE,
        "zone": zone.to_string(),
        "policy_id_hex": policy.get("policy_id").and_then(|v| v.as_array()).map(|a| a.iter().map(|b| format!("{:02x}", b.as_u64().unwrap_or(0))).collect::<String>()).unwrap_or_default(),
        "release_id": policy.get("release_id").cloned().unwrap_or(Value::Null),
        "valid_from": policy.get("valid_from").cloned().unwrap_or(Value::Null),
        "valid_until": policy.get("valid_until").cloned().unwrap_or(Value::Null),
        "policy_sha256": adns_auth::sha256_hex(&canonical),
        "policy": policy,
    }))
}

/// `GET /governance/policy-receipt?zone=`: receipt over the governed appraisal
/// policy currently in force for `zone`. Consumers pin `policy_id_hex` and
/// `policy_sha256`; a successor policy is legitimate only if this receipt for
/// it verifies under a pinned service identity.
pub fn policy_receipt(tx: &impl ReadTx, zone: &str) -> Result<AppResponse> {
    adns_auth::validate_name(zone, false).map_err(AppError::Auth)?;
    let origin: WireName = zone.parse()?;
    let policy: Value = get_json(tx, Collection::Policies, origin.as_slice())?
        .ok_or(AppError::NotFound("appraisal policy"))?;
    let claims = policy_claims(&origin, &policy)?;
    let mut response = AppResponse::new(json!({"status":"pending","claims":claims}));
    response.claims_digest = Some(claims_digest(POLICY_CLAIMS_TYPE, &claims)?);
    Ok(response)
}

/// `GET /governance/anchors`: everything a consumer pins, in one receipted
/// document: zone KSK/DS, appraisal policies, node join policy (with SVN) and
/// the release authority. The service identity itself arrives with the receipt.
pub fn anchors(tx: &impl ReadTx) -> Result<AppResponse> {
    let mut zones = Vec::new();
    let mut policies = Vec::new();
    for (_, value) in tx.scan_prefix(Collection::Zones, b"")? {
        let zone: ZoneMetadata =
            serde_json::from_slice(&value.bytes).map_err(StorageError::from)?;
        let owner = zone.origin;
        if !zone.ksk_dnskey_rdata.is_empty() {
            zones.push(ksk_summary(&owner, &zone.ksk_dnskey_rdata)?);
        }
        if let Some(policy) = get_json::<Value>(tx, Collection::Policies, owner.as_slice())? {
            let mut summary = policy_claims(&owner, &policy)?;
            summary.as_object_mut().map(|o| o.remove("policy"));
            summary.as_object_mut().map(|o| o.remove("type"));
            policies.push(summary);
        }
    }
    let node_join_policy: Option<NodeJoinPolicy> =
        get_json(tx, Collection::Lifecycle, b"governance/node-join-policy")?;
    let release_authority: Option<ReleaseAuthority> =
        get_json(tx, Collection::Lifecycle, b"governance/release-authority")?;
    let claims = json!({
        "type": ANCHORS_CLAIMS_TYPE,
        "zones": zones,
        "appraisal_policies": policies,
        "node_join_policy": node_join_policy,
        "release_authority": release_authority.map(|a| json!({"did": a.did, "public_key_pem": a.public_key_pem, "svn": a.svn, "valid_from": a.valid_from, "valid_until": a.valid_until})),
    });
    let mut response = AppResponse::new(json!({"status":"pending","claims":claims}));
    response.claims_digest = Some(claims_digest(ANCHORS_CLAIMS_TYPE, &claims)?);
    Ok(response)
}
