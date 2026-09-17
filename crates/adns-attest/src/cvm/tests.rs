use super::*;
use crate::{
    TcbVersion,
    tests::{encode, genoa_v5_fixture, key, signed},
};
use ciborium::value::Value;
use openssl::{pkey::Private, sign::Signer};
const MAIL: &[u8] = include_bytes!("../../tests/fixtures/azure_cvm_mail_hcl.bin");
const WORKER: &[u8] = include_bytes!("../../tests/fixtures/azure_cvm_worker_hcl.bin");
const AK: &[u8] = include_bytes!("../../tests/fixtures/azure_cvm_worker_ak_0.der");
const NOW: u64 = 1_789_595_100; // 2026-09-16 17:45 UTC
fn cvm_policy() -> AzureCvmPolicy {
    AzureCvmPolicy {
        vmpl: 0,
        allowed_ak_ca_subjects: [AZURE_AK_CA_25.into()].into(),
        ak_root_sha256: BTreeSet::new(),
    }
}
fn policy() -> AppraisalPolicy {
    let h = HclReport::parse(MAIL).unwrap();
    AppraisalPolicy {
        policy_id: [8; 32],
        release_id: "cvm-fixture-candidate".into(),
        active_profiles: [AZURE_CVM_SNP.into()].into(),
        valid_from: NOW - 100,
        valid_until: NOW + 3600,
        max_appraisal_lifetime: 600,
        minimum_tcb: [("Genoa".into(), h.report.reported_tcb)].into(),
        approved_measurements: [hex::encode(h.report.measurement)].into(),
        approved_host_data: [hex::encode(h.report.host_data)].into(),
        azure_cvm: Some(cvm_policy()),
        ..Default::default()
    }
}
#[test]
fn captured_mail_hcl_binds_original_runtime_json_and_rsa_ak() {
    let h = HclReport::parse(MAIL).unwrap();
    assert_eq!(h.report.version, 5);
    assert_eq!(
        h.report.reported_tcb,
        TcbVersion {
            bootloader: 12,
            tee: 0,
            snp: 28,
            microcode: 88
        }
    );
    assert_eq!(h.runtime_data.len(), 1233);
    h.verify_runtime_binding().unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(h.runtime_data)),
        "c5f86ab82f0eba4c4ab1d42c0742f37746812c52c5a3731f144a95943ad4b5e5"
    );
    assert_eq!(
        PKey::public_key_from_der(&h.ak_public_key_der().unwrap())
            .unwrap()
            .bits(),
        2048
    );
    assert!(matches!(
        h.report
            .verify_key_binding(&key().public_key_to_der().unwrap()),
        Err(AttestationError::KeyBindingMismatch)
    ));
    // This is a parse/hash check, not a successful hardware appraisal: no VCEK was captured.
}
#[test]
fn captured_worker_corruption_is_rejected_without_repairing_fixture() {
    assert!(matches!(
        HclReport::parse(WORKER),
        Err(AttestationError::Malformed("HCL lengths or NV padding"))
    ));
    let snp = SnpAttestationReport::parse(&WORKER[32..1216]).unwrap();
    assert!(matches!(
        snp.verify_key_binding(&WORKER[1236..2436]),
        Err(AttestationError::KeyBindingMismatch)
    ));
    assert!(serde_json::from_slice::<serde_json::Value>(&WORKER[1236..2436]).is_err());
}
#[test]
fn wrong_report_data_and_nonzero_tail_reject() {
    for offset in [112usize, 144] {
        let mut b = MAIL.to_vec();
        b[offset] ^= 1;
        let h = HclReport::parse(&b).unwrap();
        assert!(h.verify_runtime_binding().is_err());
    }
    let mut b = MAIL.to_vec();
    b[1236 + 20] ^= 1;
    assert!(matches!(
        HclReport::parse(&b).unwrap().verify_runtime_binding(),
        Err(AttestationError::KeyBindingMismatch)
    ));
}
#[test]
fn hcl_truncation_headers_lengths_and_padding_fail_closed() {
    for end in 0..2469 {
        assert!(HclReport::parse(&MAIL[..end]).is_err(), "length {end}");
    }
    for offset in [0, 4, 8, 12, 16, 20, 1216, 1220, 1224, 1228, 1232, 2599] {
        let mut b = MAIL.to_vec();
        b[offset] ^= 1;
        assert!(HclReport::parse(&b).is_err(), "offset {offset}");
    }
    HclReport::parse(&MAIL[..2469])
        .unwrap()
        .verify_runtime_binding()
        .unwrap();
}
#[test]
fn tcb_floor_checks_each_component_of_every_state() {
    let h = HclReport::parse(MAIL).unwrap();
    let mut p = policy();
    verify_report_policy(&h.report, &p).unwrap();
    for component in 0..4 {
        let mut min = h.report.reported_tcb;
        match component {
            0 => min.bootloader += 1,
            1 => min.tee += 1,
            2 => min.snp += 1,
            _ => min.microcode += 1,
        }
        p.minimum_tcb.insert("Genoa".into(), min);
        assert!(matches!(
            verify_report_policy(&h.report, &p),
            Err(AttestationError::TcbBelowMinimum)
        ));
    }
    p = policy();
    for state in 0..4 {
        let mut r = h.report.clone();
        let t = match state {
            0 => &mut r.current_tcb,
            1 => &mut r.reported_tcb,
            2 => &mut r.committed_tcb,
            _ => &mut r.launch_tcb,
        };
        t.snp -= 1;
        assert!(matches!(
            verify_report_policy(&r, &p),
            Err(AttestationError::TcbBelowMinimum)
        ));
    }
    p.approved_measurements.clear();
    assert!(matches!(
        verify_report_policy(&h.report, &p),
        Err(AttestationError::MeasurementRejected)
    ));
    p = policy();
    p.approved_host_data.clear();
    assert!(matches!(
        verify_report_policy(&h.report, &p),
        Err(AttestationError::HostDataRejected)
    ));
    assert!(matches!(
        h.report.verify_security_policy_at_vmpl(1),
        Err(AttestationError::ReportPolicyRejected("VMPL rejected"))
    ));
}
#[test]
fn pinned_genoa_certificate_matches_existing_pin_and_real_aci_chain() {
    let (native, _) = genoa_v5_fixture();
    let amd = certificates::verify_amd_endorsements(&native.endorsements, NOW).unwrap();
    let certs = certificates::amd_certificates(&native.endorsements).unwrap();
    assert_eq!(
        certs[2].to_der().unwrap(),
        X509::from_pem(GENOA_ARK_CERT).unwrap().to_der().unwrap()
    );
    assert_eq!(
        hex::encode(Sha256::digest(certs[2].to_der().unwrap())),
        "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1"
    );
    let report = SnpAttestationReport::parse(&native.report).unwrap();
    report.verify_signature(&native.report, &amd.vcek).unwrap();
    let mut bad = native.report.clone();
    bad[144] ^= 1;
    assert!(matches!(
        report.verify_signature(&bad, &amd.vcek),
        Err(AttestationError::SignatureInvalid)
    ));
    // A valid VCEK from another physical host cannot appraise the CVM report.
    let mail = HclReport::parse(MAIL).unwrap();
    assert!(matches!(
        verify_platform(&mail, &native.endorsements, &policy(), &cvm_policy(), NOW),
        Err(AttestationError::SignatureInvalid)
    ));
}
#[test]
fn wrong_ark_rejects_even_when_it_is_a_valid_microsoft_certificate() {
    let (native, _) = genoa_v5_fixture();
    let mut certs = certificates::amd_certificates(&native.endorsements).unwrap();
    certs[2] = X509::from_der(AK).unwrap();
    let pem = certs
        .iter()
        .flat_map(|c| c.to_pem().unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        certificates::verify_amd_endorsements(std::str::from_utf8(&pem).unwrap(), NOW),
        Err(AttestationError::UntrustedRoot)
    ));
}
#[test]
fn real_ak_certificate_expiry_foreign_ca_and_key_mismatch_reject() {
    let cert = X509::from_der(AK).unwrap();
    let ak = cert.public_key().unwrap();
    let mut p = cvm_policy();
    verify_ak_leaf(&cert, &ak, &p, NOW).unwrap(); // Leaf constraints only: no captured issuer chain.
    for now in [NOW - 86400, 1_850_000_000] {
        assert!(matches!(
            verify_ak_leaf(&cert, &ak, &p, now),
            Err(AttestationError::CertificateInvalid(_))
        ));
    }
    p.allowed_ak_ca_subjects = ["Foreign CA".into()].into();
    assert!(matches!(
        verify_ak_leaf(&cert, &ak, &p, NOW),
        Err(AttestationError::CertificateInvalid(_))
    ));
    let wrong = runtime_ak(HclReport::parse(MAIL).unwrap().runtime_data).unwrap();
    assert!(matches!(
        verify_ak_leaf(&cert, &wrong, &cvm_policy(), NOW),
        Err(AttestationError::KeyBindingMismatch)
    ));
    let pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    assert!(verify_ak_chain(&pem, &ak, &cvm_policy(), NOW).is_err());
    // A client-supplied root with the right issuer label has no authority.
    assert!(matches!(
        verify_ak_chain(&(pem.clone() + &pem), &ak, &cvm_policy(), NOW),
        Err(AttestationError::UntrustedRoot)
    ));
}
fn quote(spki: &[u8], ak: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
    let mut q = hex::decode("ff54434780180022000b").unwrap();
    q.extend([7; 32]);
    q.extend(32u16.to_be_bytes());
    q.extend(Sha256::digest(spki));
    q.extend([0; 16]);
    q.push(1);
    q.extend([0; 8]);
    q.extend(hex::decode("00000001000b030100000020").unwrap());
    q.extend([9; 32]);
    let mut signer = Signer::new(MessageDigest::sha256(), ak).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    signer.update(&q).unwrap();
    let mut sig = hex::decode("0014000b0100").unwrap();
    sig.extend(signer.sign_to_vec().unwrap());
    (q, sig)
}
#[test]
fn synthetic_tpm_quote_requires_ak_signature_and_exact_workload_binding() {
    // Synthetic TPM unit test; never represented as a CVM capture.
    let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public = PKey::public_key_from_der(&ak.public_key_to_der().unwrap()).unwrap();
    let spki = key().public_key_to_der().unwrap();
    let (q, s) = quote(&spki, &ak);
    verify_quote(&q, &s, &public, &spki).unwrap();
    assert!(matches!(
        verify_quote(&q, &s, &public, &key().public_key_to_der().unwrap()),
        Err(AttestationError::KeyBindingMismatch)
    ));
    let mut bad = s.clone();
    bad[100] ^= 1;
    assert!(matches!(
        verify_quote(&q, &bad, &public, &spki),
        Err(AttestationError::SignatureInvalid)
    ));
    for offset in [0, 5, 113] {
        let mut bad = q.clone();
        bad[offset] ^= 1;
        assert!(verify_quote(&bad, &s, &public, &spki).is_err());
    }
    for end in 0..q.len() {
        assert!(verify_quote(&q[..end], &s, &public, &spki).is_err());
    }
    let mut bad = q;
    bad.push(0);
    assert!(verify_quote(&bad, &s, &public, &spki).is_err());
}
#[test]
fn profile_dispatch_and_missing_trust_or_quote_fail_closed() {
    let k = key();
    let spki = k.public_key_to_der().unwrap();
    let mut p = policy();
    assert!(matches!(
        crate::appraise(AZURE_CVM_SNP, b"", &spki, &p, NOW),
        Err(AttestationError::PolicyNotValid)
    ));
    p.azure_cvm
        .as_mut()
        .unwrap()
        .ak_root_sha256
        .insert("11".repeat(32));
    let incomplete = encode(Value::Map(vec![(
        Value::Text("hcl".into()),
        Value::Bytes(MAIL.to_vec()),
    )]));
    let evidence = signed(&incomplete, &k);
    assert!(matches!(
        crate::appraise(AZURE_CVM_SNP, &evidence, &spki, &p, NOW),
        Err(AttestationError::Malformed(
            "CVM payload requires hcl, eds, ak, quote, sig"
        ))
    ));
    p.active_profiles.clear();
    assert!(matches!(
        crate::appraise(AZURE_CVM_SNP, &evidence, &spki, &p, NOW),
        Err(AttestationError::ProfileNotActive)
    ));
}
