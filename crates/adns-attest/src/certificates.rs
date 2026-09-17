use crate::{AttestationError, SnpAttestationReport, TcbVersion};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    pkey::PKey,
    stack::Stack,
    x509::{
        X509, X509StoreContext,
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
    },
};
use serde::Deserialize;
use x509_parser::prelude::*;

pub(crate) struct AmdEndorsements {
    pub vcek: X509,
    pub product: String,
    pub valid_until: u64,
}
#[derive(Deserialize)]
struct ThimEndorsements {
    #[serde(rename = "vcekCert")]
    vcek_cert: String,
    #[serde(rename = "certificateChain")]
    certificate_chain: String,
}

pub(crate) fn verify_amd_endorsements(
    encoded: &str,
    now: u64,
) -> Result<AmdEndorsements, AttestationError> {
    let certs = amd_certificates(encoded)?;
    let ark_spki = certs[2].public_key()?.public_key_to_der()?;
    let product = [
        ("Milan", include_bytes!("amd_milan_ark.pem").as_slice()),
        ("Genoa", include_bytes!("amd_genoa_ark.pem").as_slice()),
    ]
    .into_iter()
    .find_map(|(product, pem)| {
        let expected = PKey::public_key_from_pem(pem)
            .ok()?
            .public_key_to_der()
            .ok()?;
        (ark_spki == expected).then_some(product)
    })
    .ok_or(AttestationError::UntrustedRoot)?;
    let valid_until = verify_chain(&certs, now)?;
    Ok(AmdEndorsements {
        vcek: certs[0].clone(),
        product: product.into(),
        valid_until,
    })
}

pub(crate) fn amd_certificates(encoded: &str) -> Result<Vec<X509>, AttestationError> {
    if encoded.len() > 128 * 1024 {
        return Err(AttestationError::Malformed("endorsements size"));
    }
    // THIM native payload contains standard base64 JSON. Also accept the
    // upstream byte-chain representation as literal PEM for offline adapters.
    let raw = if encoded.starts_with("-----BEGIN CERTIFICATE-----") {
        encoded.as_bytes().to_vec()
    } else {
        STANDARD
            .decode(encoded)
            .map_err(|_| AttestationError::Malformed("endorsements base64"))?
    };
    let certs = if raw.starts_with(b"-----BEGIN CERTIFICATE-----") {
        X509::stack_from_pem(&raw)?
    } else {
        let thim: ThimEndorsements =
            serde_json::from_slice(&raw).map_err(|_| AttestationError::Malformed("THIM JSON"))?;
        let mut chain = X509::stack_from_pem(thim.vcek_cert.as_bytes())?;
        if chain.len() != 1 {
            return Err(AttestationError::Malformed("one VCEK required"));
        }
        chain.extend(X509::stack_from_pem(thim.certificate_chain.as_bytes())?);
        chain
    };
    if certs.len() != 3 {
        return Err(AttestationError::Malformed("VCEK ASK ARK chain required"));
    }
    Ok(certs)
}

/// Verify exactly the supplied ordered path against its externally pinned root.
/// Never uses the system root store or allows network-based chain completion.
pub(crate) fn verify_chain(chain: &[X509], now: u64) -> Result<u64, AttestationError> {
    if !(2..=6).contains(&chain.len()) {
        return Err(AttestationError::Malformed("certificate chain length"));
    }
    let mut valid_until = u64::MAX;
    let now = i64::try_from(now).map_err(|_| AttestationError::Malformed("verification time"))?;
    for cert in chain {
        let der = cert.to_der()?;
        if der.len() > 16 * 1024 || cert.public_key()?.bits() > 8192 {
            return Err(AttestationError::Malformed(
                "certificate or public key size",
            ));
        }
        let (_, parsed) =
            parse_x509_certificate(&der).map_err(|_| AttestationError::Malformed("X509 DER"))?;
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        if now < not_before || now >= not_after {
            return Err(AttestationError::CertificateInvalid(
                "certificate outside validity interval".into(),
            ));
        }
        valid_until = valid_until.min(not_after as u64);
        for (i, extension) in parsed.extensions().iter().enumerate() {
            if parsed.extensions()[..i]
                .iter()
                .any(|e| e.oid == extension.oid)
            {
                return Err(AttestationError::Malformed(
                    "duplicate certificate extension",
                ));
            }
        }
    }
    for pair in chain.windows(2) {
        let issuer_key = pair[1].public_key()?;
        if pair[0].issuer_name().to_der()? != pair[1].subject_name().to_der()?
            || !pair[0].verify(&issuer_key)?
        {
            return Err(AttestationError::CertificateInvalid(
                "certificate path signature or issuer".into(),
            ));
        }
    }
    let root = chain
        .last()
        .ok_or(AttestationError::Malformed("empty certificate chain"))?;
    let root_key = root.public_key()?;
    if root.issuer_name().to_der()? != root.subject_name().to_der()? || !root.verify(&root_key)? {
        return Err(AttestationError::CertificateInvalid(
            "root not self-signed".into(),
        ));
    }
    let mut params = X509VerifyParam::new()?;
    params.set_time(now);
    params.set_auth_level(2);
    params.set_depth(5);
    // Strict checks are compatible with Microsoft UVM paths. AMD's published
    // VCEK leaf intentionally lacks generic keyUsage/basicConstraints, so use
    // standard X509 path validation and the mandatory AMD extension checks.
    params.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE)?;
    let mut builder = X509StoreBuilder::new()?;
    builder.add_cert(root.clone())?;
    builder.set_param(&params)?;
    let store = builder.build();
    let mut intermediates = Stack::new()?;
    for cert in &chain[1..chain.len() - 1] {
        intermediates.push(cert.clone())?;
    }
    let mut context = X509StoreContext::new()?;
    let (valid, reason) = context.init(&store, &chain[0], &intermediates, |ctx| {
        let valid = ctx.verify_cert()?;
        Ok((valid, ctx.error().to_string()))
    })?;
    if !valid {
        return Err(AttestationError::CertificateInvalid(reason));
    }
    Ok(valid_until)
}

pub(crate) fn verify_vcek_extensions(
    cert: &X509,
    report: &SnpAttestationReport,
    product: &str,
) -> Result<(), AttestationError> {
    let der = cert.to_der()?;
    let (_, parsed) =
        parse_x509_certificate(&der).map_err(|_| AttestationError::Malformed("VCEK DER"))?;
    let extension = |oid: &str| -> Result<&[u8], AttestationError> {
        parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == oid)
            .map(|e| e.value)
            .ok_or(AttestationError::Malformed("missing AMD extension"))
    };
    // ASN.1 INTEGER encoded SPLs are nonnegative canonical u8 values.
    let spl = |suffix: u8| -> Result<u8, AttestationError> {
        let value = extension(&format!("1.3.6.1.4.1.3704.1.3.{suffix}"))?;
        match value {
            [2, 1, n] if *n < 128 => Ok(*n),
            [2, 2, 0, n] if *n >= 128 => Ok(*n),
            _ => Err(AttestationError::Malformed("AMD SPL integer")),
        }
    };
    let endorsed = TcbVersion {
        bootloader: spl(1)?,
        tee: spl(2)?,
        snp: spl(3)?,
        microcode: spl(8)?,
    };
    if report.reported_tcb != endorsed {
        return Err(AttestationError::TcbMismatch);
    }
    for suffix in [4, 5, 6, 7] {
        if spl(suffix)? != 0 {
            return Err(AttestationError::Malformed("reserved AMD SPL"));
        }
    }
    if extension("1.3.6.1.4.1.3704.1.4")? != report.chip_id {
        return Err(AttestationError::ReportPolicyRejected(
            "VCEK chip ID mismatch",
        ));
    }
    let name_der = extension("1.3.6.1.4.1.3704.1.2")?;
    if name_der.len() < 2 || name_der[0] != 0x16 || usize::from(name_der[1]) != name_der.len() - 2 {
        return Err(AttestationError::Malformed("AMD productName"));
    }
    let name = std::str::from_utf8(&name_der[2..])
        .map_err(|_| AttestationError::Malformed("AMD productName text"))?;
    if name != product && !name.starts_with(&format!("{product}-")) {
        return Err(AttestationError::ReportPolicyRejected(
            "AMD product and root mismatch",
        ));
    }
    if report.version >= 3
        && !(report.cpuid_family == 0x19
            && match product {
                "Milan" => report.cpuid_model <= 0x0f,
                "Genoa" => (0x10..=0x1f).contains(&report.cpuid_model),
                _ => false,
            })
    {
        return Err(AttestationError::ReportPolicyRejected(
            "CPUID and VCEK product mismatch",
        ));
    }
    Ok(())
}

/// Pick a historical instant at which every certificate in a legacy immutable
/// release-endorsement path was valid. This confers no trust by itself: the
/// caller must verify the pinned path and the exact governed release identity.
pub(crate) fn common_validity_time(chain: &[X509], now: u64) -> Result<u64, AttestationError> {
    let mut first = 0_i64;
    let mut last = i64::MAX;
    for cert in chain {
        let der = cert.to_der()?;
        let (_, parsed) =
            parse_x509_certificate(&der).map_err(|_| AttestationError::Malformed("X509 DER"))?;
        first = first.max(parsed.validity().not_before.timestamp());
        last = last.min(parsed.validity().not_after.timestamp());
    }
    let first =
        u64::try_from(first).map_err(|_| AttestationError::Malformed("certificate time"))?;
    if chain.is_empty() || first > now || i64::try_from(first).unwrap_or(i64::MAX) >= last {
        return Err(AttestationError::CertificateInvalid(
            "release certificates have no past common validity interval".into(),
        ));
    }
    Ok(first)
}
