use crate::{AttestationError, MAX_EVIDENCE_BYTES};
use ciborium::value::Value;
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable, iana};
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Verifier},
};
use std::io::Cursor;

pub(crate) struct NativePayload {
    pub report: Vec<u8>,
    pub endorsements: String,
    pub uvm: Vec<u8>,
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Value, AttestationError> {
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(AttestationError::Malformed("CBOR size"));
    }
    let mut reader = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut reader, 16)
        .map_err(|_| AttestationError::Malformed("CBOR"))?;
    if reader.position() != bytes.len() as u64 {
        return Err(AttestationError::Malformed("trailing CBOR"));
    }
    validate(&value, 0)?;
    Ok(value)
}

fn validate(value: &Value, depth: usize) -> Result<(), AttestationError> {
    if depth > 16 {
        return Err(AttestationError::Malformed("CBOR depth"));
    }
    match value {
        Value::Map(entries) => {
            if entries.len() > 128 {
                return Err(AttestationError::Malformed("CBOR map size"));
            }
            for (i, (key, value)) in entries.iter().enumerate() {
                if !matches!(key, Value::Integer(_) | Value::Text(_))
                    || entries[..i].iter().any(|(k, _)| k == key)
                {
                    return Err(AttestationError::Malformed(
                        "CBOR duplicate or complex map key",
                    ));
                }
                validate(value, depth + 1)?;
            }
        }
        Value::Array(items) => {
            if items.len() > 128 {
                return Err(AttestationError::Malformed("CBOR array size"));
            }
            for item in items {
                validate(item, depth + 1)?;
            }
        }
        Value::Tag(_, value) => validate(value, depth + 1)?,
        _ => {}
    }
    Ok(())
}

pub(crate) fn parse_sign1(bytes: &[u8]) -> Result<CoseSign1, AttestationError> {
    let value = decode(bytes)?;
    let Value::Tag(18, inner) = value else {
        return Err(AttestationError::Malformed("COSE Sign1 tag required"));
    };
    let Value::Array(items) = *inner else {
        return Err(AttestationError::Malformed("COSE Sign1 array"));
    };
    if items.len() != 4 {
        return Err(AttestationError::Malformed("COSE Sign1 arity"));
    }
    let Value::Bytes(protected) = &items[0] else {
        return Err(AttestationError::Malformed("COSE protected header"));
    };
    let protected = decode(protected)?;
    let Value::Map(protected_map) = &protected else {
        return Err(AttestationError::Malformed("COSE protected map"));
    };
    let Value::Map(unprotected) = &items[1] else {
        return Err(AttestationError::Malformed("COSE unprotected map"));
    };
    if unprotected
        .iter()
        .any(|(key, _)| protected_map.iter().any(|(p, _)| p == key))
    {
        return Err(AttestationError::Malformed("header in both buckets"));
    }
    let sign1 = CoseSign1::from_tagged_slice(bytes)
        .map_err(|_| AttestationError::Malformed("COSE Sign1"))?;
    // No extension is currently understood as critical. Reject instead of ignoring.
    if !sign1.protected.header.crit.is_empty() || !sign1.unprotected.crit.is_empty() {
        return Err(AttestationError::Malformed("unsupported critical headers"));
    }
    if sign1.protected.header.alg.is_none()
        || sign1.unprotected.alg.is_some()
        || sign1.payload.is_none()
    {
        return Err(AttestationError::Malformed(
            "protected algorithm and attached payload required",
        ));
    }
    Ok(sign1)
}

pub(crate) fn protected_value(sign1: &CoseSign1) -> Result<Value, AttestationError> {
    decode(
        sign1
            .protected
            .original_data
            .as_deref()
            .ok_or(AttestationError::Malformed("missing raw protected header"))?,
    )
}

pub(crate) fn map_text<'a>(v: &'a Value, key: &str) -> Result<&'a Value, AttestationError> {
    map_get(v, &Value::Text(key.into()))
}
pub(crate) fn map_int(v: &Value, key: i64) -> Result<&Value, AttestationError> {
    map_get(v, &Value::Integer(key.into()))
}
fn map_get<'a>(v: &'a Value, key: &Value) -> Result<&'a Value, AttestationError> {
    v.as_map()
        .and_then(|m| m.iter().find(|(k, _)| k == key).map(|(_, v)| v))
        .ok_or(AttestationError::Malformed("missing CBOR claim"))
}
pub(crate) fn text(v: &Value) -> Result<&str, AttestationError> {
    v.as_text()
        .ok_or(AttestationError::Malformed("expected CBOR text"))
}
pub(crate) fn bytes(v: &Value) -> Result<&[u8], AttestationError> {
    v.as_bytes()
        .map(Vec::as_slice)
        .ok_or(AttestationError::Malformed("expected CBOR bytes"))
}

pub(crate) fn parse_native_payload(bytes: &[u8]) -> Result<NativePayload, AttestationError> {
    let value = decode(bytes)?;
    if value.as_map().is_none_or(|m| m.len() != 3) {
        return Err(AttestationError::Malformed(
            "native payload must contain att, eds, uvm",
        ));
    }
    Ok(NativePayload {
        report: self::bytes(map_text(&value, "att")?)?.to_vec(),
        endorsements: text(map_text(&value, "eds")?)?.to_owned(),
        uvm: self::bytes(map_text(&value, "uvm")?)?.to_vec(),
    })
}

pub(crate) fn verify_es256(sign1: &CoseSign1, spki_der: &[u8]) -> Result<(), AttestationError> {
    if spki_der.len() > 4096 {
        return Err(AttestationError::Malformed("SPKI size"));
    }
    let key = PKey::public_key_from_der(spki_der)?;
    // Reject alternate encodings/trailing bytes: binding is to exact canonical DER.
    if key.public_key_to_der()? != spki_der {
        return Err(AttestationError::Malformed("noncanonical SPKI"));
    }
    verify_with_key(sign1, &key, Some(iana::Algorithm::ES256))
}

pub(crate) fn verify_with_key(
    sign1: &CoseSign1,
    key: &PKey<Public>,
    required: Option<iana::Algorithm>,
) -> Result<(), AttestationError> {
    let Some(RegisteredLabelWithPrivate::Assigned(algorithm)) = sign1.protected.header.alg else {
        return Err(AttestationError::UnsupportedAlgorithm);
    };
    if required.is_some_and(|r| r != algorithm) {
        return Err(AttestationError::UnsupportedAlgorithm);
    }
    let (digest, signature, pss) = match algorithm {
        iana::Algorithm::ES256 | iana::Algorithm::ES384 => {
            let (curve, length, digest) = if algorithm == iana::Algorithm::ES256 {
                (Nid::X9_62_PRIME256V1, 32, MessageDigest::sha256())
            } else {
                (Nid::SECP384R1, 48, MessageDigest::sha384())
            };
            if key.ec_key()?.group().curve_name() != Some(curve)
                || sign1.signature.len() != 2 * length
            {
                return Err(AttestationError::UnsupportedAlgorithm);
            }
            let sig = EcdsaSig::from_private_components(
                BigNum::from_slice(&sign1.signature[..length])?,
                BigNum::from_slice(&sign1.signature[length..])?,
            )?
            .to_der()?;
            (digest, sig, false)
        }
        iana::Algorithm::PS256 | iana::Algorithm::PS384 | iana::Algorithm::PS512 => {
            if key.rsa()?.size() < 256 || sign1.signature.len() != key.size() {
                return Err(AttestationError::UnsupportedAlgorithm);
            }
            let md = match algorithm {
                iana::Algorithm::PS256 => MessageDigest::sha256(),
                iana::Algorithm::PS384 => MessageDigest::sha384(),
                _ => MessageDigest::sha512(),
            };
            (md, sign1.signature.clone(), true)
        }
        _ => return Err(AttestationError::UnsupportedAlgorithm),
    };
    let mut verifier = Verifier::new(digest, key)?;
    if pss {
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_mgf1_md(digest)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
    }
    verifier.update(&sign1.tbs_data(&[]))?;
    if !verifier.verify(&signature)? {
        return Err(AttestationError::SignatureInvalid);
    }
    Ok(())
}
