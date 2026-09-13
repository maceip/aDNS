//! Bounded observations of authenticated attempts, separate from success replay.
use crate::*;
use adns_auth::{
    AuthError, NonceRecord, parse_signed_request, validate_nonce, verify_request_signature,
};
use adns_storage::{Collection, ReadTx, WriteOverlay, WriteTx, composite_key, get_json, put_json};
use adns_telemetry::{Name, Span, observe};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailedAttempt {
    grant_id: String,
    request_id: String,
    nonce: String,
    intent_hash: String,
    signed_message_digest: String,
    failed_at: u64,
    expires_at: u64,
    http_status: u16,
    error: String,
}
fn attempt_key(nonce_key: &[u8]) -> Vec<u8> {
    composite_key(&[b"server/v1/request-attempt", nonce_key])
}
pub(crate) fn remove_failed_attempt(tx: &mut impl WriteTx, nonce_key: &[u8]) -> Result<()> {
    tx.remove(Collection::Lifecycle, &attempt_key(nonce_key))?;
    Ok(())
}

/// Production entry point. Failed application writes never reach the backend;
/// only an authenticated, nonce-bound 4xx rejection may commit attempt metadata.
/// A flush/storage error requires discarding the entire backend transaction.
pub fn mutate_observed(
    tx: &mut impl WriteTx,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<AppResponse> {
    let mut staged = WriteOverlay::new(tx);
    let error = match mutate(&mut staged, method, path, body, now) {
        Ok(response) => {
            observe(Name::StorageStage, || staged.flush())?;
            return Ok(response);
        }
        Err(error) => error,
    };
    drop(staged);
    // Never persist internal/storage failures, unverifiable requests, or
    // request-ID conflicts against a previously successful historical result.
    if !(400..500).contains(&error.http_status())
        || matches!(
            error,
            AppError::Auth(AuthError::RandomFailure)
                | AppError::Attestation(adns_attest::AttestationError::Crypto(_))
        )
        || matches!(error, AppError::NotFound(kind) if !matches!(kind, "registration" | "challenge"))
    {
        return Err(error);
    }
    let authenticated = (|| {
        let config = crate::service::configuration(tx)?;
        if now < config.last_time {
            return Err(AppError::Invalid("time moved backwards"));
        }
        let request = observe(Name::Parse, || parse_signed_request(body))?;
        if crate::service::expected_route(request.action.operation()) != (method, path) {
            return Err(AppError::Invalid("operation does not match endpoint"));
        }
        let verified = observe(Name::Signature, || verify_request_signature(&request))?;
        if tx
            .get(
                Collection::RequestResults,
                &request_key(&request.action.grant_id, &request.action.request_id),
            )?
            .is_some()
        {
            return Err(AppError::Auth(AuthError::RequestIdConflict));
        }
        let key = nonce_key(config.epoch, &request.nonce);
        let nonce: NonceRecord = get_json(tx, Collection::Nonces, &key)?
            .ok_or(AppError::Auth(AuthError::InvalidNonce))?;
        observe(Name::Nonce, || validate_nonce(&request, &nonce, now))?;
        Ok((key, nonce, verified.signed_message_digest, config))
    })();
    let (key, nonce, digest, mut config) = match authenticated {
        Ok(value) => value,
        Err(AppError::Storage(error)) => return Err(AppError::Storage(error)),
        Err(_) => return Err(error),
    };
    let attempt = FailedAttempt {
        grant_id: nonce.grant_id,
        request_id: nonce.request_id,
        nonce: nonce.nonce,
        intent_hash: nonce.intent_hash,
        signed_message_digest: digest,
        failed_at: now,
        expires_at: nonce.expires_at,
        http_status: error.http_status(),
        error: error.to_string().chars().take(4096).collect(),
    };
    let mut storage_span = Span::start(Name::StorageStage);
    config.last_time = now;
    put_json(
        tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &config,
    )?;
    put_json(tx, Collection::Lifecycle, attempt_key(&key), &attempt)?;
    storage_span.success();
    drop(storage_span);
    let mut response = AppResponse::new(json!({
        "status":"failed", "execution_state":"failed", "phase":"last_authenticated_attempt",
        "error":attempt.error, "http_status":attempt.http_status, "retryable":true,
        "grant_id":attempt.grant_id, "request_id":attempt.request_id,
        "signed_message_digest":attempt.signed_message_digest, "nonce":attempt.nonce,
        "nonce_expires_at":attempt.expires_at, "observation_status":"pending_commit"
    }));
    response.http_status = attempt.http_status;
    response.commit_error = true;
    response.promote_status_on_commit = false;
    Ok(response)
}

/// Read only committed observations. A nonce proves an issued intent, not an
/// executing handler. Multiple nonces are explicit; newest KV observation wins.
pub(crate) fn reconcile_uncompleted(
    tx: &impl ReadTx,
    grant_id: &str,
    request_id: &str,
    now: u64,
) -> Result<AppResponse> {
    adns_auth::validate_identifier(grant_id)?;
    adns_auth::validate_identifier(request_id)?;
    let config = crate::service::configuration(tx)?;
    let rows = tx.scan_prefix(Collection::Nonces, b"")?;
    if rows.len() > MAX_OUTSTANDING_NONCES {
        return Err(inconsistent("nonce capacity"));
    }
    let mut observations = Vec::new();
    for (key, value) in rows {
        let nonce: NonceRecord =
            serde_json::from_slice(&value.bytes).map_err(adns_storage::StorageError::from)?;
        if key != nonce_key(config.epoch, &nonce.nonce)
            || nonce.grant_id != grant_id
            || nonce.request_id != request_id
            || nonce.consumed
            || nonce.expires_at <= now
        {
            continue;
        }
        let mut version = value.version;
        let mut observation = json!({"nonce":nonce.nonce,"intent_hash":nonce.intent_hash,"issued_at":nonce.issued_at,"expires_at":nonce.expires_at});
        let mut failed = false;
        if let Some(row) = tx.get(Collection::Lifecycle, &attempt_key(&key))? {
            let attempt: FailedAttempt =
                serde_json::from_slice(&row.bytes).map_err(adns_storage::StorageError::from)?;
            if attempt.grant_id != nonce.grant_id
                || attempt.request_id != nonce.request_id
                || attempt.nonce != nonce.nonce
                || attempt.intent_hash != nonce.intent_hash
                || attempt.expires_at != nonce.expires_at
            {
                return Err(inconsistent("failed attempt nonce identity"));
            }
            version = version.max(row.version);
            observation["signed_message_digest"] = json!(attempt.signed_message_digest);
            observation["http_status"] = json!(attempt.http_status);
            observation["error"] = json!(attempt.error);
            observation["failed_at"] = json!(attempt.failed_at);
            failed = true;
        }
        observations.push((version, key, failed, observation));
    }
    let count = observations.len();
    let Some((_, _, failed, latest)) = observations
        .into_iter()
        .max_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)))
    else {
        return Err(AppError::NotFound("request"));
    };
    let state = if failed { "failed" } else { "pending" };
    let mut response = AppResponse::new(json!({
        "status":state,"execution_state":state,
        "phase":if failed {"last_authenticated_attempt"} else {"awaiting_committed_result"},
        "grant_id":grant_id,"request_id":request_id,"matching_nonces":count,
        "multiple_nonce_ambiguity":count>1,"latest_observation":latest,
        "retryable":true,"observation_status":"pending_commit"
    }));
    response.promote_status_on_commit = false;
    Ok(response)
}
