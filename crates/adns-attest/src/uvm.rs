use crate::{AttestationError, certificates, cose};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Governance chooses whether a UVM publisher certificate must still be valid
/// now, or authenticates an explicitly approved immutable release endorsement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmEndorsementTimePolicy {
    #[default]
    CurrentCertificate,
    /// Requires the exact platform measurement to have already matched the
    /// governed allowlist. Does not change current AMD VCEK validation.
    ApprovedRelease,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UvmIdentity {
    pub did: String,
    pub feed: String,
    pub minimum_svn: u32,
}
pub(crate) struct VerifiedUvm {
    pub did: String,
    pub feed: String,
    pub svn: u32,
    pub valid_until: u64,
}

pub(crate) fn verify(
    encoded: &[u8],
    measurement: &[u8; 48],
    identities: &[UvmIdentity],
    now: u64,
    time_policy: UvmEndorsementTimePolicy,
) -> Result<VerifiedUvm, AttestationError> {
    let signed = cose::parse_sign1(encoded)?;
    let protected = cose::protected_value(&signed)?;
    let payload = signed
        .payload
        .as_deref()
        .ok_or(AttestationError::Malformed("UVM detached payload"))?;
    // Since ContainerPlat 0.2.10, CWT claims carry issuer, feed, numeric SVN
    // and issuance time; legacy descriptors carry these in protected headers
    // and signed JSON. A present CWT claim cannot fall back to legacy parsing.
    let (did, feed, svn, endorsed_measurement, issuance_time) =
        if let Ok(cwt) = cose::map_int(&protected, 15) {
            if cose::text(cose::map_int(&protected, 259)?)? != "application/octet-stream" {
                return Err(AttestationError::Malformed("UVM preimage content type"));
            }
            let did = cose::text(cose::map_int(cwt, 1)?)?.to_owned();
            let feed = cose::text(cose::map_int(cwt, 2)?)?.to_owned();
            let svn = cbor_u32(cose::map_text(cwt, "svn")?)?;
            let iat = cbor_time(cose::map_int(cwt, 6)?)?;
            if iat > now {
                return Err(AttestationError::Malformed("UVM future issuance time"));
            }
            (did, feed, svn, payload.to_vec(), Some(iat))
        } else {
            if cose::text(cose::map_int(&protected, 3)?)? != "application/json" {
                return Err(AttestationError::Malformed("UVM content type"));
            }
            let did = cose::text(cose::map_text(&protected, "iss")?)?.to_owned();
            let feed = cose::text(cose::map_text(&protected, "feed")?)?.to_owned();
            #[derive(Deserialize)]
            struct Descriptor {
                #[serde(rename = "x-ms-sevsnpvm-guestsvn")]
                svn: serde_json::Value,
                #[serde(rename = "x-ms-sevsnpvm-launchmeasurement")]
                measurement: String,
            }
            let descriptor: Descriptor = serde_json::from_slice(payload)
                .map_err(|_| AttestationError::Malformed("UVM JSON descriptor"))?;
            let svn = match descriptor.svn {
                serde_json::Value::String(s)
                    if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) =>
                {
                    s.parse()
                        .map_err(|_| AttestationError::Malformed("UVM SVN overflow"))?
                }
                serde_json::Value::Number(n) => n
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or(AttestationError::Malformed("UVM SVN number"))?,
                _ => return Err(AttestationError::Malformed("UVM SVN")),
            };
            let measurement = hex::decode(descriptor.measurement)
                .map_err(|_| AttestationError::Malformed("UVM measurement hex"))?;
            (did, feed, svn, measurement, None)
        };
    let identity = identities
        .iter()
        .filter(|i| i.did == did && i.feed == feed)
        .min_by_key(|i| i.minimum_svn)
        .ok_or(AttestationError::UvmIdentityRejected)?;
    if svn < identity.minimum_svn {
        return Err(AttestationError::UvmSvnBelowMinimum);
    }
    let raw_chain = cose::map_int(&protected, 33)?
        .as_array()
        .ok_or(AttestationError::Malformed("UVM x5chain"))?;
    if !(2..=6).contains(&raw_chain.len()) {
        return Err(AttestationError::Malformed("UVM x5chain length"));
    }
    let raw_chain: Vec<&[u8]> = raw_chain
        .iter()
        .map(cose::bytes)
        .collect::<Result<_, _>>()?;
    let chain: Vec<X509> = raw_chain
        .iter()
        .map(|der| X509::from_der(der))
        .collect::<Result<_, _>>()?;
    for (raw, cert) in raw_chain.iter().zip(&chain) {
        if raw.len() > 16 * 1024 || cert.to_der()? != *raw {
            return Err(AttestationError::Malformed(
                "noncanonical UVM certificate DER",
            ));
        }
    }
    verify_did(&did, &raw_chain)?;
    // Authenticate all publisher claims before applying their issuance time.
    cose::verify_with_key(&signed, &chain[0].public_key()?, None)?;
    let valid_until = match time_policy {
        UvmEndorsementTimePolicy::CurrentCertificate => {
            let expires = certificates::verify_chain(&chain, now)?;
            if let Some(iat) = issuance_time {
                certificates::verify_chain(&chain, iat)?;
            }
            expires
        }
        UvmEndorsementTimePolicy::ApprovedRelease => {
            // CCF deliberately ignores current expiry of immutable code-signing
            // endorsements. We retain path/time validation at authenticated iat,
            // or a common historical validity interval for legacy descriptors.
            // The caller has already checked the exact governed measurement.
            let at = match issuance_time {
                Some(iat) => iat,
                None => certificates::common_validity_time(&chain, now)?,
            };
            certificates::verify_chain(&chain, at)?;
            // Release lifetime is governed by policy, not an expired signing
            // certificate. appraise still caps by current AMD certificate expiry.
            u64::MAX
        }
    };
    if endorsed_measurement != measurement {
        return Err(AttestationError::MeasurementRejected);
    }
    Ok(VerifiedUvm {
        did,
        feed,
        svn,
        valid_until,
    })
}

fn cbor_u64(v: &Value) -> Result<u64, AttestationError> {
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(AttestationError::Malformed("unsigned CBOR integer"))
}
// Microsoft's genuine 0.2.10 endorsement uses the CBOR epoch tag 1 even
// though RFC 8392 NumericDate omits it. Accept precisely this native form and
// plain unsigned seconds; reject other tags, floats, and nested tags.
fn cbor_time(v: &Value) -> Result<u64, AttestationError> {
    match v {
        Value::Tag(1, inner) => cbor_u64(inner),
        _ => cbor_u64(v),
    }
}
fn cbor_u32(v: &Value) -> Result<u32, AttestationError> {
    cbor_u64(v)?
        .try_into()
        .map_err(|_| AttestationError::Malformed("SVN overflow"))
}

/// The activated profile supports the actual Microsoft DID-x509 SHA256 + EKU
/// identity form. Unknown DID policies fail closed, never silently ignored.
fn verify_did(did: &str, chain: &[&[u8]]) -> Result<(), AttestationError> {
    let (prefix, eku) = did
        .split_once("::eku:")
        .ok_or(AttestationError::UvmIdentityRejected)?;
    let fingerprint = prefix
        .strip_prefix("did:x509:0:sha256:")
        .ok_or(AttestationError::UvmIdentityRejected)?;
    if eku.is_empty() || !eku.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return Err(AttestationError::UvmIdentityRejected);
    }
    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(
        chain.last().ok_or(AttestationError::UvmIdentityRejected)?,
    ));
    if fingerprint != actual {
        return Err(AttestationError::UntrustedRoot);
    }
    let (remaining, leaf) = parse_x509_certificate(chain[0])
        .map_err(|_| AttestationError::Malformed("UVM leaf certificate"))?;
    if !remaining.is_empty() {
        return Err(AttestationError::Malformed("trailing certificate DER"));
    }
    let usage = leaf
        .extended_key_usage()
        .map_err(|_| AttestationError::UvmIdentityRejected)?
        .ok_or(AttestationError::UvmIdentityRejected)?;
    if !usage
        .value
        .other
        .iter()
        .any(|oid| oid.to_id_string() == eku)
    {
        return Err(AttestationError::UvmIdentityRejected);
    }
    let key_usage = leaf
        .key_usage()
        .map_err(|_| AttestationError::UvmIdentityRejected)?
        .ok_or(AttestationError::UvmIdentityRejected)?;
    if !key_usage.value.digital_signature() {
        return Err(AttestationError::UvmIdentityRejected);
    }
    if leaf.is_ca() {
        return Err(AttestationError::UvmIdentityRejected);
    }
    Ok(())
}
