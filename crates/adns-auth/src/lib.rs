#![forbid(unsafe_code)]
//! Strict signed requests and stateless authorization for the agentdns contract.
//!
//! Grants must come from authenticated governance state. The caller must read the
//! nonce, authorize, consume it, mutate records, and store the request result in
//! ONE durable transaction. Returning a [`VerifiedRequest`] does not consume a
//! nonce and is never evidence of global commit.

mod canonical;
mod grants;
mod schema;

pub use canonical::{canonical_json, canonicalize, parse_strict_json};
pub use grants::*;
pub use schema::*;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NONCE_TTL_SECONDS: u64 = 300;
pub const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("INVALID_JSON: {0}")]
    InvalidJson(String),
    #[error("INVALID_FIELD: {0}")]
    InvalidField(String),
    #[error("INVALID_SIGNATURE")]
    InvalidSignature,
    #[error("INVALID_SPKI")]
    InvalidSpki,
    #[error("INVALID_NONCE")]
    InvalidNonce,
    #[error("NONCE_EXPIRED")]
    NonceExpired,
    #[error("NONCE_CONSUMED")]
    NonceConsumed,
    #[error("INTENT_MISMATCH")]
    IntentMismatch,
    #[error("EVIDENCE_DIGEST_MISMATCH")]
    EvidenceDigestMismatch,
    #[error("AUDIENCE_MISMATCH")]
    AudienceMismatch,
    #[error("GRANT_DENIED: {0}")]
    GrantDenied(String),
    #[error("REQUEST_ID_CONFLICT")]
    RequestIdConflict,
    #[error("RANDOM_GENERATOR_FAILURE")]
    RandomFailure,
}

pub(crate) fn invalid(field: &str) -> AuthError {
    AuthError::InvalidField(field.into())
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Decode canonical unpadded base64url. Padding, whitespace and nonzero spare
/// bits are rejected; a re-encode check makes the wire encoding unique.
pub fn decode_base64url(value: &str, max_bytes: usize) -> Result<Vec<u8>, AuthError> {
    if value.len() > max_bytes.saturating_mul(4).div_ceil(3) {
        return Err(invalid("base64url length"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("base64url"))?;
    if bytes.len() > max_bytes || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(invalid("base64url"));
    }
    Ok(bytes)
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical id-ecPublicKey + namedCurve prime256v1 SPKI, with an uncompressed
/// SEC1 point. This admits exactly the DER encoding hashed into report_data.
pub fn decode_p256_spki(encoded: &str) -> Result<Vec<u8>, AuthError> {
    const PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    let der = decode_base64url(encoded, 91).map_err(|_| AuthError::InvalidSpki)?;
    if der.len() != 91 || !der.starts_with(PREFIX) {
        return Err(AuthError::InvalidSpki);
    }
    Ok(der)
}

pub fn intent_hash(action: &Action) -> Result<String, AuthError> {
    action.validate()?;
    Ok(sha256_hex(&canonicalize(action)?))
}

/// Persistent nonce row. Its entire contents are authenticated by the CCF KV
/// transaction; do not reconstruct this from client-provided fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceRecord {
    pub nonce: String,
    pub intent_hash: String,
    pub grant_id: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub consumed: bool,
}

impl NonceRecord {
    pub fn response(&self) -> NonceResponse {
        NonceResponse {
            nonce: self.nonce.clone(),
            intent_hash: self.intent_hash.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceResponse {
    pub nonce: String,
    pub intent_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Generates a nonce row that MUST be committed before returning its response.
/// Call authorize_action before issuance to avoid storing unauthorized intents.
pub fn issue_nonce(action: &Action, now: u64) -> Result<NonceRecord, AuthError> {
    let intent_hash = intent_hash(action)?;
    let expires_at = now
        .checked_add(NONCE_TTL_SECONDS)
        .filter(|v| *v <= MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid("time"))?;
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| AuthError::RandomFailure)?;
    Ok(NonceRecord {
        nonce: hex::encode(random),
        intent_hash,
        grant_id: action.grant_id.clone(),
        request_id: action.request_id.clone(),
        issued_at: now,
        expires_at,
        consumed: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub action: Action,
    pub nonce: String,
    pub nonce_expires_at: u64,
    pub intent_hash: String,
    pub client_signature: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "schema::optional_string"
    )]
    pub evidence_payload: Option<String>,
}

#[derive(Serialize)]
struct SignedMessage<'a> {
    action: &'a Action,
    nonce: &'a str,
    nonce_expires_at: u64,
    intent_hash: &'a str,
}

impl SignedRequest {
    /// JCS(action, nonce, nonce_expires_at, intent_hash). The evidence digest is
    /// inside action; neither evidence_payload nor client_signature is signed.
    pub fn signed_message(&self) -> Result<Vec<u8>, AuthError> {
        self.action.validate()?;
        validate_hex_digest(&self.nonce)?;
        validate_hex_digest(&self.intent_hash)?;
        if self.nonce_expires_at > MAX_SAFE_INTEGER {
            return Err(invalid("nonce_expires_at"));
        }
        canonicalize(&SignedMessage {
            action: &self.action,
            nonce: &self.nonce,
            nonce_expires_at: self.nonce_expires_at,
            intent_hash: &self.intent_hash,
        })
    }
    pub fn signed_message_digest(&self) -> Result<String, AuthError> {
        Ok(sha256_hex(&self.signed_message()?))
    }
    pub fn evidence(&self) -> Result<Option<Vec<u8>>, AuthError> {
        let expected = self.action.parameters.evidence_digest();
        match (expected, self.evidence_payload.as_deref()) {
            (Some(digest), Some(payload)) => {
                let bytes = decode_base64url(payload, MAX_EVIDENCE_BYTES)?;
                if bytes.is_empty() || sha256_hex(&bytes) != digest {
                    return Err(AuthError::EvidenceDigestMismatch);
                }
                Ok(Some(bytes))
            }
            (None, None) => Ok(None),
            _ => Err(invalid("evidence_payload")),
        }
    }
}

pub fn parse_signed_request(bytes: &[u8]) -> Result<SignedRequest, AuthError> {
    let value = parse_strict_json(bytes)?;
    let request: SignedRequest =
        serde_json::from_value(value).map_err(|e| AuthError::InvalidJson(e.to_string()))?;
    request.signed_message()?;
    if decode_base64url(&request.client_signature, 64)?.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }
    request.evidence()?;
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceRequest {
    pub action: Action,
}

pub fn parse_nonce_request(bytes: &[u8]) -> Result<NonceRequest, AuthError> {
    let request: NonceRequest = serde_json::from_value(parse_strict_json(bytes)?)
        .map_err(|e| AuthError::InvalidJson(e.to_string()))?;
    request.action.validate()?;
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    pub intent_hash: String,
    pub signed_message_digest: String,
    pub signer_spki_der: Vec<u8>,
    pub signer_spki_sha256: String,
    pub evidence_payload: Option<Vec<u8>>,
}

/// Verifies the single SHA-256 ECDSA operation (ring hashes the raw JCS bytes).
/// This check is also required for historical retries before returning a cached
/// result. Retry reconciliation deliberately does not recheck current grant or
/// nonce expiration, because an authenticated committed result is historical.
pub fn verify_request_signature(request: &SignedRequest) -> Result<VerifiedRequest, AuthError> {
    let message = request.signed_message()?;
    let intent = intent_hash(&request.action)?;
    if request.intent_hash != intent {
        return Err(AuthError::IntentMismatch);
    }
    let der = decode_p256_spki(&request.action.signer_spki_der)?;
    let sig =
        decode_base64url(&request.client_signature, 64).map_err(|_| AuthError::InvalidSignature)?;
    if sig.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &der[26..])
        .verify(&message, &sig)
        .map_err(|_| AuthError::InvalidSignature)?;
    Ok(VerifiedRequest {
        intent_hash: intent,
        signed_message_digest: sha256_hex(&message),
        signer_spki_sha256: sha256_hex(&der),
        signer_spki_der: der,
        evidence_payload: request.evidence()?,
    })
}

pub fn validate_nonce(
    request: &SignedRequest,
    row: &NonceRecord,
    now: u64,
) -> Result<(), AuthError> {
    if row.consumed {
        return Err(AuthError::NonceConsumed);
    }
    if now < row.issued_at || now >= row.expires_at {
        return Err(AuthError::NonceExpired);
    }
    if row.expires_at.checked_sub(row.issued_at) != Some(NONCE_TTL_SECONDS)
        || row.expires_at > MAX_SAFE_INTEGER
        || row.nonce != request.nonce
        || row.expires_at != request.nonce_expires_at
        || row.grant_id != request.action.grant_id
        || row.request_id != request.action.request_id
    {
        return Err(AuthError::InvalidNonce);
    }
    if row.intent_hash != request.intent_hash || intent_hash(&request.action)? != row.intent_hash {
        return Err(AuthError::IntentMismatch);
    }
    validate_hex_digest(&row.nonce)?;
    Ok(())
}

pub fn verify_signed_request(
    request: &SignedRequest,
    nonce: &NonceRecord,
    grant: &OwnerGrant,
    audience: &str,
    now: u64,
) -> Result<VerifiedRequest, AuthError> {
    let verified = verify_request_signature(request)?;
    validate_nonce(request, nonce, now)?;
    authorize_action(&request.action, grant, audience, now)?;
    Ok(verified)
}

/// A row exists only after its result and all effects are atomically committed.
/// Persist the actual HTTP outcome, including status and body, verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedRequestResult {
    pub grant_id: String,
    pub request_id: String,
    pub signed_message_digest: String,
    pub http_status: u16,
    pub body: serde_json::Value,
    pub tx_id: String,
}

/// Call verify_request_signature before cache reconciliation. A fresh nonce is
/// a different signed message and intentionally conflicts with a committed ID.
pub fn reconcile_result<'a>(
    request: &SignedRequest,
    stored: &'a CommittedRequestResult,
) -> Result<&'a CommittedRequestResult, AuthError> {
    if stored.grant_id != request.action.grant_id
        || stored.request_id != request.action.request_id
        || stored.signed_message_digest != request.signed_message_digest()?
    {
        return Err(AuthError::RequestIdConflict);
    }
    Ok(stored)
}
