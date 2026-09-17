//! Azure HCL SNP profile. HCL authenticates the vTPM AK, not the workload key.
//! A TPM2 quote signed by that AK must separately bind SHA256(workload SPKI).
use crate::{
    AZURE_CVM_SNP, AppraisalPolicy, AttestationError, SnpAttestationReport, VerifiedAppraisal,
    certificates, cose,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::Verifier,
    x509::X509,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use x509_parser::prelude::*;

pub const AZURE_AK_CA_25: &str = "Azure Cloud Virtual TPM CA - 25";
pub const GENOA_ARK_CERT: &[u8] = include_bytes!("amd_genoa_ark_cert.pem");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCvmPolicy {
    pub vmpl: u32,
    /// Exact issuer common names, in addition to a cryptographic root pin.
    pub allowed_ak_ca_subjects: BTreeSet<String>,
    /// SHA256 of DER root certificates. A subject string alone is not trust.
    pub ak_root_sha256: BTreeSet<String>,
}

/// Parsed claims remain untrusted until the AMD signature/chain is verified.
#[derive(Debug)]
pub struct HclReport<'a> {
    pub raw_snp: &'a [u8],
    pub runtime_data: &'a [u8],
    pub report: SnpAttestationReport,
}
impl<'a> HclReport<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, AttestationError> {
        if !(1236..=64 * 1024).contains(&bytes.len()) {
            return Err(AttestationError::Malformed("HCL size"));
        }
        let word = |p| u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        if &bytes[..4] != b"HCLA"
            || word(4) != 2
            || word(12) != 2
            || bytes[16..32].iter().any(|b| *b != 0)
            || word(1220) != 1
            || word(1224) != 2
            || word(1228) != 1
        {
            return Err(AttestationError::Malformed(
                "HCL header or unsupported report/hash type",
            ));
        }
        let size = word(8) as usize;
        let claims_size = word(1232) as usize;
        if size != 1236 + claims_size
            || word(1216) as usize != 20 + claims_size
            || size > bytes.len()
            || bytes[size..].iter().any(|b| *b != 0)
        {
            return Err(AttestationError::Malformed("HCL lengths or NV padding"));
        }
        let raw_snp = &bytes[32..1216];
        Ok(Self {
            raw_snp,
            runtime_data: &bytes[1236..size],
            report: SnpAttestationReport::parse(raw_snp)?,
        })
    }
    /// Hash the exact original JSON bytes, without reserialization.
    pub fn verify_runtime_binding(&self) -> Result<(), AttestationError> {
        self.report.verify_key_binding(self.runtime_data)
    }
    pub fn ak_public_key_der(&self) -> Result<Vec<u8>, AttestationError> {
        self.verify_runtime_binding()?;
        runtime_ak(self.runtime_data)?
            .public_key_to_der()
            .map_err(Into::into)
    }
}

#[derive(Deserialize)]
struct RuntimeClaims {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    e: String,
    n: String,
    key_ops: Vec<String>,
}
fn runtime_ak(runtime: &[u8]) -> Result<PKey<Public>, AttestationError> {
    // Typed serde fields reject duplicate keys rather than last-value-wins.
    let claims: RuntimeClaims = serde_json::from_slice(runtime)
        .map_err(|_| AttestationError::Malformed("HCL runtime JSON"))?;
    if claims.keys.len() > 8 {
        return Err(AttestationError::Malformed("HCL key count"));
    }
    let mut keys = claims.keys.iter().filter(|key| key.kid == "HCLAkPub");
    let key = keys
        .next()
        .ok_or(AttestationError::Malformed("missing HCLAkPub"))?;
    if keys.next().is_some() || key.kty != "RSA" || key.key_ops != ["sign"] {
        return Err(AttestationError::Malformed("HCLAkPub type or duplicate"));
    }
    let n = URL_SAFE_NO_PAD
        .decode(&key.n)
        .map_err(|_| AttestationError::Malformed("AK modulus"))?;
    let e = URL_SAFE_NO_PAD
        .decode(&key.e)
        .map_err(|_| AttestationError::Malformed("AK exponent"))?;
    if n.len() != 256 || n[0] < 128 || n[255] & 1 == 0 || e != [1, 0, 1] {
        return Err(AttestationError::Malformed(
            "AK must be RSA-2048 exponent 65537",
        ));
    }
    Ok(PKey::from_rsa(Rsa::from_public_components(
        BigNum::from_slice(&n)?,
        BigNum::from_slice(&e)?,
    )?)?)
}

struct Payload {
    hcl: Vec<u8>,
    endorsements: String,
    ak_chain: String,
    quote: Vec<u8>,
    signature: Vec<u8>,
}
fn payload(bytes: &[u8]) -> Result<Payload, AttestationError> {
    let v = cose::decode(bytes)?;
    if v.as_map().is_none_or(|m| m.len() != 5) {
        return Err(AttestationError::Malformed(
            "CVM payload requires hcl, eds, ak, quote, sig",
        ));
    }
    Ok(Payload {
        hcl: cose::bytes(cose::map_text(&v, "hcl")?)?.to_vec(),
        endorsements: cose::text(cose::map_text(&v, "eds")?)?.into(),
        ak_chain: cose::text(cose::map_text(&v, "ak")?)?.into(),
        quote: cose::bytes(cose::map_text(&v, "quote")?)?.to_vec(),
        signature: cose::bytes(cose::map_text(&v, "sig")?)?.to_vec(),
    })
}

pub(crate) fn appraise(
    evidence: &[u8],
    spki: &[u8],
    policy: &AppraisalPolicy,
    now: u64,
) -> Result<VerifiedAppraisal, AttestationError> {
    let cvm = policy
        .azure_cvm
        .as_ref()
        .ok_or(AttestationError::PolicyNotValid)?;
    if cvm.vmpl > 3
        || cvm.allowed_ak_ca_subjects.is_empty()
        || cvm.ak_root_sha256.is_empty()
        || cvm.ak_root_sha256.iter().any(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(AttestationError::PolicyNotValid);
    }
    let envelope = cose::parse_sign1(evidence)?;
    cose::verify_es256(&envelope, spki)?;
    let p = payload(
        envelope
            .payload
            .as_deref()
            .ok_or(AttestationError::Malformed("detached payload"))?,
    )?;
    let hcl = HclReport::parse(&p.hcl)?;
    let amd = verify_platform(&hcl, &p.endorsements, policy, cvm, now)?;
    let ak = PKey::public_key_from_der(&hcl.ak_public_key_der()?)?;
    let ak_valid_until = verify_ak_chain(&p.ak_chain, &ak, cvm, now)?;
    verify_quote(&p.quote, &p.signature, &ak, spki)?;
    let deadline = now
        .checked_add(policy.max_appraisal_lifetime)
        .ok_or(AttestationError::PolicyNotValid)?;
    Ok(VerifiedAppraisal {
        profile: AZURE_CVM_SNP,
        policy_id: policy.policy_id,
        release_id: policy.release_id.clone(),
        spki_sha256: Sha256::digest(spki).into(),
        evidence_digest: Sha256::digest(evidence).into(),
        measurement: hcl.report.measurement,
        host_data: hcl.report.host_data,
        product: amd.product,
        reported_tcb: hcl.report.reported_tcb,
        // HCL has no ACI UVM endorsement; never invent a UVM release identity.
        uvm_svn: 0,
        uvm_did: String::new(),
        uvm_feed: String::new(),
        valid_until: policy
            .valid_until
            .min(deadline)
            .min(amd.valid_until)
            .min(ak_valid_until),
    })
}

fn verify_platform(
    hcl: &HclReport<'_>,
    endorsements: &str,
    policy: &AppraisalPolicy,
    cvm: &AzureCvmPolicy,
    now: u64,
) -> Result<certificates::AmdEndorsements, AttestationError> {
    hcl.report.verify_security_policy_at_vmpl(cvm.vmpl)?;
    let amd = certificates::verify_amd_endorsements(endorsements, now)?;
    if amd.product != "Genoa" {
        return Err(AttestationError::UntrustedRoot);
    }
    // Pin the certificate as well as the existing AMD SPKI pin. The chain helper
    // validates signatures, constraints, expiry and self-signed root offline.
    let supplied = certificates::amd_certificates(endorsements)?;
    let supplied_der = supplied[2].to_der()?;
    #[allow(unused_mut)]
    let mut pinned = supplied_der == X509::from_pem(GENOA_ARK_CERT)?.to_der()?;
    #[cfg(test)]
    {
        pinned |= certificates::test_ark::cert_der().as_deref() == Some(supplied_der.as_slice());
    }
    if !pinned {
        return Err(AttestationError::UntrustedRoot);
    }
    hcl.report.verify_signature(hcl.raw_snp, &amd.vcek)?;
    certificates::verify_vcek_extensions(&amd.vcek, &hcl.report, "Genoa")?;
    verify_report_policy(&hcl.report, policy)?;
    hcl.verify_runtime_binding()?;
    Ok(amd)
}
fn verify_report_policy(
    report: &SnpAttestationReport,
    policy: &AppraisalPolicy,
) -> Result<(), AttestationError> {
    let min = policy
        .minimum_tcb
        .get("Genoa")
        .ok_or(AttestationError::TcbBelowMinimum)?;
    for tcb in [
        report.current_tcb,
        report.reported_tcb,
        report.committed_tcb,
        report.launch_tcb,
    ] {
        if !tcb.meets(min) {
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
    Ok(())
}

fn verify_ak_leaf(
    cert: &X509,
    ak: &PKey<Public>,
    policy: &AzureCvmPolicy,
    now: u64,
) -> Result<(), AttestationError> {
    let der = cert.to_der()?;
    let (_, parsed) =
        parse_x509_certificate(&der).map_err(|_| AttestationError::Malformed("AK certificate"))?;
    let now = i64::try_from(now).map_err(|_| AttestationError::PolicyNotValid)?;
    if now < parsed.validity().not_before.timestamp()
        || now >= parsed.validity().not_after.timestamp()
    {
        return Err(AttestationError::CertificateInvalid(
            "AK outside validity interval".into(),
        ));
    }
    let mut names = cert.issuer_name().entries_by_nid(Nid::COMMONNAME);
    let name = names
        .next()
        .ok_or_else(|| AttestationError::CertificateInvalid("AK issuer CN absent".into()))?;
    let name = name.data().to_string()?;
    if names.next().is_some() || !policy.allowed_ak_ca_subjects.contains(&name) {
        return Err(AttestationError::CertificateInvalid(
            "AK issuer not allowed".into(),
        ));
    }
    if cert.public_key()?.public_key_to_der()? != ak.public_key_to_der()? {
        return Err(AttestationError::KeyBindingMismatch);
    }
    let ku = parsed
        .key_usage()
        .map_err(|_| AttestationError::Malformed("AK key usage"))?;
    let eku = parsed
        .extended_key_usage()
        .map_err(|_| AttestationError::Malformed("AK EKU"))?;
    if parsed.is_ca()
        || ku.is_none_or(|v| !v.value.digital_signature())
        || eku.is_none_or(|v| {
            !v.value
                .other
                .iter()
                .any(|oid| oid.to_id_string() == "2.23.133.8.3")
        })
    {
        return Err(AttestationError::CertificateInvalid("AK usage".into()));
    }
    Ok(())
}
fn verify_ak_chain(
    pem: &str,
    ak: &PKey<Public>,
    policy: &AzureCvmPolicy,
    now: u64,
) -> Result<u64, AttestationError> {
    if pem.len() > 96 * 1024 {
        return Err(AttestationError::Malformed("AK chain size"));
    }
    let chain = X509::stack_from_pem(pem.as_bytes())?;
    if !(2..=6).contains(&chain.len()) {
        return Err(AttestationError::Malformed("AK chain length"));
    }
    verify_ak_leaf(&chain[0], ak, policy, now)?;
    let root = chain.last().ok_or(AttestationError::UntrustedRoot)?;
    if !policy
        .ak_root_sha256
        .contains(&hex::encode(Sha256::digest(root.to_der()?)))
    {
        return Err(AttestationError::UntrustedRoot);
    }
    certificates::verify_chain(&chain, now)
}

struct TpmReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> TpmReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestationError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(AttestationError::Malformed("TPM length"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or(AttestationError::Malformed("truncated TPM quote"))?;
        self.pos = end;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, AttestationError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, AttestationError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn sized(&mut self) -> Result<&'a [u8], AttestationError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}
/// Raw TPMS_ATTEST (no TPM2B size prefix), TPMT_SIGNATURE RSASSA/SHA256.
/// PCR contents are not a software-integrity appraisal in this profile.
fn verify_quote(
    quote: &[u8],
    signature: &[u8],
    ak: &PKey<Public>,
    spki: &[u8],
) -> Result<(), AttestationError> {
    if quote.len() > 4096 || signature.len() != 262 {
        return Err(AttestationError::Malformed("TPM quote size"));
    }
    let mut r = TpmReader {
        bytes: quote,
        pos: 0,
    };
    if r.u32()? != 0xff544347 || r.u16()? != 0x8018 {
        return Err(AttestationError::Malformed(
            "TPM generated magic or quote type",
        ));
    }
    let signer = r.sized()?;
    if signer.len() != 34 || signer[..2] != [0, 0x0b] {
        return Err(AttestationError::Malformed("TPM qualified signer"));
    }
    if r.sized()? != Sha256::digest(spki).as_slice() {
        return Err(AttestationError::KeyBindingMismatch);
    }
    let clock = r.take(17)?;
    if clock[16] != 1 {
        return Err(AttestationError::ReportPolicyRejected("TPM clock unsafe"));
    }
    r.take(8)?;
    // One SHA256 bank, at least one PCR. Other profiles can add PCR policy later.
    if r.u32()? != 1 || r.u16()? != 0x000b || r.take(1)? != [3] {
        return Err(AttestationError::Malformed("TPM PCR selection"));
    }
    if r.take(3)? == [0; 3] || r.sized()?.len() != 32 || r.pos != quote.len() {
        return Err(AttestationError::Malformed(
            "TPM PCR digest or trailing data",
        ));
    }
    let mut s = TpmReader {
        bytes: signature,
        pos: 0,
    };
    if s.u16()? != 0x0014 || s.u16()? != 0x000b {
        return Err(AttestationError::UnsupportedAlgorithm);
    }
    let raw = s.sized()?;
    if raw.len() != 256 || s.pos != signature.len() {
        return Err(AttestationError::Malformed("TPM signature"));
    }
    let mut verifier = Verifier::new(MessageDigest::sha256(), ak)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    verifier.update(quote)?;
    if !verifier.verify(raw)? {
        return Err(AttestationError::SignatureInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod mock_tests;
#[cfg(test)]
mod tests;
