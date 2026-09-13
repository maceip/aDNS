//! Offline audit of native CCF node quotes for TLS bootstrap only.
//! This API never constructs a service `VerifiedAppraisal` and is not used by
//! service admission. Callers must obtain the certificate from the actual TLS
//! peer and pin that audited peer key before trusting any service identity.
use crate::{
    AppraisalPolicy, AttestationError, MAX_EVIDENCE_BYTES, cose, validate_policy, verify_native,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{asn1::Asn1Time, nid::Nid, x509::X509};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeQuote {
    node_id: String,
    raw: String,
    endorsements: String,
    format: String,
    measurement: Option<String>,
    uvm_endorsements: String,
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AuditedNodeQuote {
    pub purpose: &'static str,
    pub node_spki_sha256: String,
    pub quote_sha256: String,
    pub measurement: String,
    pub host_data: String,
    pub product: String,
    pub policy_id: String,
    pub uvm_did: String,
    pub uvm_feed: String,
    pub uvm_svn: u32,
    pub valid_until: u64,
}

fn decode(encoded: &str) -> Result<Vec<u8>, AttestationError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| AttestationError::Malformed("CCF quote base64"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(AttestationError::Malformed("noncanonical CCF quote base64"));
    }
    Ok(bytes)
}

/// Audit CCF 7.0.15 `/node/quotes/self` against an independently selected policy
/// and actual peer certificate DER. No service request signature is bypassed:
/// this separate result cannot be passed to registration as an appraisal.
pub fn audit(
    quote_json: &[u8],
    tls_peer_certificate_der: &[u8],
    policy: &AppraisalPolicy,
    now: u64,
) -> Result<AuditedNodeQuote, AttestationError> {
    validate_policy(policy, now)?;
    if quote_json.len() > MAX_EVIDENCE_BYTES || tls_peer_certificate_der.len() > 16 * 1024 {
        return Err(AttestationError::Malformed("CCF audit input size"));
    }
    let quote: NodeQuote = serde_json::from_slice(quote_json)
        .map_err(|_| AttestationError::Malformed("CCF node quote JSON"))?;
    if quote.format != "AMD_SEV_SNP_v1" {
        return Err(AttestationError::UnsupportedProfile);
    }
    let certificate = X509::from_der(tls_peer_certificate_der)?;
    if certificate.to_der()? != tls_peer_certificate_der {
        return Err(AttestationError::Malformed(
            "noncanonical TLS certificate DER",
        ));
    }
    let (_, parsed_certificate) = x509_parser::parse_x509_certificate(tls_peer_certificate_der)
        .map_err(|_| AttestationError::Malformed("TLS certificate validity"))?;
    let key = certificate.public_key()?;
    if !matches!(
        key.ec_key()?.group().curve_name(),
        Some(Nid::SECP384R1 | Nid::X9_62_PRIME256V1)
    ) {
        return Err(AttestationError::UnsupportedAlgorithm);
    }
    let spki = key.public_key_to_der()?;
    if parsed_certificate.public_key().raw != spki.as_slice() {
        return Err(AttestationError::Malformed("noncanonical node SPKI DER"));
    }
    let digest = hex::encode(Sha256::digest(&spki));
    if quote.node_id != digest {
        return Err(AttestationError::KeyBindingMismatch);
    }
    let current =
        Asn1Time::from_unix(i64::try_from(now).map_err(|_| AttestationError::PolicyNotValid)?)?;
    if certificate.not_before().compare(&current)? == Ordering::Greater
        || certificate.not_after().compare(&current)? != Ordering::Greater
    {
        return Err(AttestationError::CertificateInvalid(
            "TLS peer certificate outside validity interval".into(),
        ));
    }
    let certificate_expiry = u64::try_from(parsed_certificate.validity().not_after.timestamp())
        .map_err(|_| AttestationError::CertificateInvalid("TLS certificate expiry".into()))?;
    let raw = decode(&quote.raw)?;
    decode(&quote.endorsements)?;
    let payload = cose::NativePayload {
        report: raw.clone(),
        endorsements: quote.endorsements,
        uvm: decode(&quote.uvm_endorsements)?,
    };
    let verified = verify_native(&payload, policy, now)?;
    verified.report.verify_key_binding(&spki)?;
    let measurement = hex::encode(verified.report.measurement);
    if quote
        .measurement
        .is_some_and(|expected| expected != measurement)
    {
        return Err(AttestationError::MeasurementRejected);
    }
    let deadline = now
        .checked_add(policy.max_appraisal_lifetime)
        .ok_or(AttestationError::PolicyNotValid)?;
    Ok(AuditedNodeQuote {
        purpose: "ccf-node-tls-bootstrap-only",
        node_spki_sha256: digest,
        quote_sha256: hex::encode(Sha256::digest(raw)),
        measurement,
        host_data: hex::encode(verified.report.host_data),
        product: verified.product,
        policy_id: hex::encode(policy.policy_id),
        uvm_did: verified.uvm.did,
        uvm_feed: verified.uvm.feed,
        uvm_svn: verified.uvm.svn,
        valid_until: policy
            .valid_until
            .min(deadline)
            .min(verified.certificates_valid_until)
            .min(certificate_expiry),
    })
}
