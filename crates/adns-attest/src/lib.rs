//! Native Azure ACI SNP appraisal. A successful appraisal is derived from real
//! signatures, pinned trust roots, the complete SPKI binding and governed policy.
#![forbid(unsafe_code)]

mod certificates;
mod cose;
pub mod node_audit;
mod snp;
mod uvm;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use snp::{SnpAttestationReport, TcbVersion};
use std::collections::{BTreeMap, BTreeSet};
pub use uvm::{UvmEndorsementTimePolicy, UvmIdentity};

pub const AZURE_ACI_SNP: &str = "azure-aci-snp";
pub const MICROSOFT_UVM_DID: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
pub const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;

/// This must come from committed governance state, never from the request.
/// Empty allowlists fail closed. Hexadecimal digests must be lowercase.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppraisalPolicy {
    pub policy_id: [u8; 32],
    pub release_id: String,
    pub active_profiles: BTreeSet<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    /// Bounds service reappraisal even when the policy has a long lifetime.
    pub max_appraisal_lifetime: u64,
    /// Supported product names are Milan and Genoa, pinned to their AMD ARKs.
    pub minimum_tcb: BTreeMap<String, TcbVersion>,
    pub approved_measurements: BTreeSet<String>,
    pub approved_host_data: BTreeSet<String>,
    pub uvm: Vec<UvmIdentity>,
    #[serde(default)]
    pub uvm_endorsement_time_policy: UvmEndorsementTimePolicy,
}

/// Fields are readable but cannot be constructed outside the verifier crate.
/// The server must never deserialize an appraisal submitted by a client.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct VerifiedAppraisal {
    pub profile: &'static str,
    pub policy_id: [u8; 32],
    pub release_id: String,
    pub spki_sha256: [u8; 32],
    pub evidence_digest: [u8; 32],
    #[serde(serialize_with = "serialize_measurement")]
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub product: String,
    pub reported_tcb: TcbVersion,
    pub uvm_svn: u32,
    pub uvm_did: String,
    pub uvm_feed: String,
    pub valid_until: u64,
}

fn serialize_measurement<S: serde::Serializer>(
    m: &[u8; 48],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(m)
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("UNSUPPORTED_PROFILE")]
    UnsupportedProfile,
    #[error("PROFILE_NOT_ACTIVE")]
    ProfileNotActive,
    #[error("POLICY_NOT_VALID")]
    PolicyNotValid,
    #[error("MALFORMED_EVIDENCE: {0}")]
    Malformed(&'static str),
    #[error("UNSUPPORTED_ALGORITHM")]
    UnsupportedAlgorithm,
    #[error("SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("CERTIFICATE_INVALID: {0}")]
    CertificateInvalid(String),
    #[error("UNTRUSTED_ROOT")]
    UntrustedRoot,
    #[error("REPORT_POLICY_REJECTED: {0}")]
    ReportPolicyRejected(&'static str),
    #[error("TCB_MISMATCH")]
    TcbMismatch,
    #[error("TCB_BELOW_MINIMUM")]
    TcbBelowMinimum,
    #[error("KEY_BINDING_MISMATCH")]
    KeyBindingMismatch,
    #[error("REPORT_DATA_NOT_ZEROED")]
    ReportDataNotZeroed,
    #[error("UVM_IDENTITY_REJECTED")]
    UvmIdentityRejected,
    #[error("UVM_SVN_BELOW_MINIMUM")]
    UvmSvnBelowMinimum,
    #[error("MEASUREMENT_REJECTED")]
    MeasurementRejected,
    #[error("CCE_HOST_DATA_REJECTED")]
    HostDataRejected,
    #[error("CRYPTOGRAPHIC_OPERATION_FAILED")]
    Crypto(#[from] openssl::error::ErrorStack),
}

/// Verify an attached, tagged COSE Sign1 envelope containing the native CBOR
/// `att`, `eds` (base64 THIM JSON or PEM chain), and `uvm` evidence fields.
/// Outer ES256 signature uses the exact P-256 DER SPKI that the SNP report binds.
pub fn appraise(
    profile: &str,
    evidence: &[u8],
    spki_der: &[u8],
    policy: &AppraisalPolicy,
    now: u64,
) -> Result<VerifiedAppraisal, AttestationError> {
    if profile != AZURE_ACI_SNP {
        return Err(AttestationError::UnsupportedProfile);
    }
    validate_policy(policy, now)?;
    let envelope = cose::parse_sign1(evidence)?;
    cose::verify_es256(&envelope, spki_der)?;
    let payload = cose::parse_native_payload(
        envelope
            .payload
            .as_deref()
            .ok_or(AttestationError::Malformed("detached payload"))?,
    )?;
    let verified = verify_native(&payload, policy, now)?;
    verified.report.verify_key_binding(spki_der)?;
    let deadline = now
        .checked_add(policy.max_appraisal_lifetime)
        .ok_or(AttestationError::PolicyNotValid)?;
    Ok(VerifiedAppraisal {
        profile: AZURE_ACI_SNP,
        policy_id: policy.policy_id,
        release_id: policy.release_id.clone(),
        spki_sha256: Sha256::digest(spki_der).into(),
        evidence_digest: Sha256::digest(evidence).into(),
        measurement: verified.report.measurement,
        host_data: verified.report.host_data,
        product: verified.product,
        reported_tcb: verified.report.reported_tcb,
        uvm_svn: verified.uvm.svn,
        uvm_did: verified.uvm.did,
        uvm_feed: verified.uvm.feed,
        valid_until: policy
            .valid_until
            .min(deadline)
            .min(verified.certificates_valid_until),
    })
}

fn validate_policy(policy: &AppraisalPolicy, now: u64) -> Result<(), AttestationError> {
    if !policy.active_profiles.contains(AZURE_ACI_SNP) {
        return Err(AttestationError::ProfileNotActive);
    }
    if now < policy.valid_from
        || now >= policy.valid_until
        || policy.max_appraisal_lifetime == 0
        || policy.release_id.is_empty()
        || policy.policy_id == [0; 32]
    {
        return Err(AttestationError::PolicyNotValid);
    }
    let mut identities = BTreeSet::new();
    if policy
        .uvm
        .iter()
        .any(|identity| !identities.insert((&identity.did, &identity.feed)))
    {
        return Err(AttestationError::PolicyNotValid);
    }
    Ok(())
}

struct NativeVerification {
    report: SnpAttestationReport,
    product: String,
    uvm: uvm::VerifiedUvm,
    certificates_valid_until: u64,
}

fn verify_native(
    payload: &cose::NativePayload,
    policy: &AppraisalPolicy,
    now: u64,
) -> Result<NativeVerification, AttestationError> {
    let report = SnpAttestationReport::parse(&payload.report)?;
    report.verify_security_policy()?;
    let endorsements = certificates::verify_amd_endorsements(&payload.endorsements, now)?;
    report.verify_signature(&payload.report, &endorsements.vcek)?;
    certificates::verify_vcek_extensions(&endorsements.vcek, &report, &endorsements.product)?;
    let minimum = policy
        .minimum_tcb
        .get(&endorsements.product)
        .ok_or(AttestationError::TcbBelowMinimum)?;
    // All four TCB states are checked component-wise; integer ordering is unsafe.
    for tcb in [
        report.current_tcb,
        report.reported_tcb,
        report.committed_tcb,
        report.launch_tcb,
    ] {
        if !tcb.meets(minimum) {
            return Err(AttestationError::TcbBelowMinimum);
        }
    }
    if !policy
        .approved_measurements
        .contains(&hex::encode(report.measurement))
    {
        return Err(AttestationError::MeasurementRejected);
    }
    if !policy
        .approved_host_data
        .contains(&hex::encode(report.host_data))
    {
        return Err(AttestationError::HostDataRejected);
    }
    let uvm = uvm::verify(
        &payload.uvm,
        &report.measurement,
        &policy.uvm,
        now,
        policy.uvm_endorsement_time_policy,
    )?;
    let certificates_valid_until = endorsements.valid_until.min(uvm.valid_until);
    Ok(NativeVerification {
        report,
        product: endorsements.product,
        uvm,
        certificates_valid_until,
    })
}

#[cfg(test)]
mod tests;
