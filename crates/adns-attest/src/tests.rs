use super::*;
use ciborium::value::Value;
use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};

const MILAN: &[u8] = include_bytes!("../../../tests/sample_snp_attestation_milan.cbor");
const GENOA: &[u8] = include_bytes!("../../../tests/sample_snp_attestation_genoa.cbor");
const HISTORICAL_TIME: u64 = 1_740_000_000; // 2025-02-19: both VCEKs and UVM chain valid.
const MEASUREMENT: &str = "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1";
const HOST_DATA: &str = "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10";
const GENOA_V5_QUOTE: &[u8] = include_bytes!("../tests/fixtures/aci_ccf_genoa_v5_quote.json");
const GENOA_V5_PEER: &[u8] = include_bytes!("../tests/fixtures/aci_ccf_genoa_v5_peer.der");
const GENOA_V5_TIME: u64 = 1_789_285_320; // 2026-09-13 07:42 UTC, captured peer valid.

fn genoa_v5_fixture() -> (cose::NativePayload, AppraisalPolicy) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let quote: serde_json::Value = serde_json::from_slice(GENOA_V5_QUOTE).unwrap();
    let payload = cose::NativePayload {
        report: STANDARD.decode(quote["raw"].as_str().unwrap()).unwrap(),
        endorsements: quote["endorsements"].as_str().unwrap().to_owned(),
        uvm: STANDARD
            .decode(quote["uvm_endorsements"].as_str().unwrap())
            .unwrap(),
    };
    let policy = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/aci_ccf_genoa_v5_policy.json"
    ))
    .unwrap();
    (payload, policy)
}

#[test]
fn genuine_genoa_v5_chain_mitigations_and_actual_ccf_tls_key_verify() {
    let (payload, policy) = genoa_v5_fixture();
    let verified = verify_native(&payload, &policy, GENOA_V5_TIME).unwrap();
    assert_eq!(verified.report.version, 5);
    assert_eq!(verified.product, "Genoa");
    assert_eq!(verified.report.launch_mitigation_vector, Some(7));
    assert_eq!(verified.report.current_mitigation_vector, Some(7));
    assert_eq!(verified.report.reported_tcb.snp, 27);
    assert_eq!(verified.report.reported_tcb.microcode, 88);
    let audited = node_audit::audit(GENOA_V5_QUOTE, GENOA_V5_PEER, &policy, GENOA_V5_TIME).unwrap();
    assert_eq!(audited.purpose, "ccf-node-tls-bootstrap-only");
    let peer = openssl::x509::X509::from_der(GENOA_V5_PEER).unwrap();
    let spki = peer.public_key().unwrap().public_key_to_der().unwrap();
    assert_eq!(audited.node_spki_sha256, hex::encode(Sha256::digest(&spki)));
    // CCF's peer key cannot silently be replaced by another valid key.
    assert!(matches!(
        verified
            .report
            .verify_key_binding(&key().public_key_to_der().unwrap()),
        Err(AttestationError::KeyBindingMismatch)
    ));
}

#[test]
fn v5_mitigation_bytes_are_signed_and_cannot_be_downgraded() {
    let (payload, policy) = genoa_v5_fixture();
    for offset in [504, 511, 512, 519, 671] {
        let (mut altered, _) = genoa_v5_fixture();
        altered.report[offset] ^= 1;
        if offset == 671 {
            assert!(matches!(
                verify_native(&altered, &policy, GENOA_V5_TIME),
                Err(AttestationError::Malformed("nonzero reserved report bytes"))
            ));
        } else {
            assert!(matches!(
                verify_native(&altered, &policy, GENOA_V5_TIME),
                Err(AttestationError::SignatureInvalid)
            ));
        }
    }
    // Version + newly assigned fields cannot be rewritten to pass as v3.
    let mut downgraded = payload;
    downgraded.report[..4].copy_from_slice(&3u32.to_le_bytes());
    downgraded.report[504..520].fill(0);
    assert!(matches!(
        verify_native(&downgraded, &policy, GENOA_V5_TIME),
        Err(AttestationError::SignatureInvalid)
    ));
}

#[test]
fn report_layout_reserves_exact_version_specific_boundaries() {
    let (payload, _) = genoa_v5_fixture();
    for version in [2u32, 3, 5] {
        let mut raw = payload.report.clone();
        raw[..4].copy_from_slice(&version.to_le_bytes());
        if version == 2 {
            raw[392..395].fill(0);
        }
        if version != 5 {
            raw[504..520].fill(0);
        }
        let report = SnpAttestationReport::parse(&raw).unwrap();
        assert_eq!(report.launch_mitigation_vector.is_some(), version == 5);
        assert_eq!(report.current_mitigation_vector.is_some(), version == 5);
        let reserved_start = if version == 5 { 520 } else { 504 };
        for offset in (76..80)
            .chain(395..416)
            .chain(reserved_start..672)
            .chain(720..744)
            .chain(792..1184)
            .chain([491, 495])
        {
            let mut altered = raw.clone();
            altered[offset] = 1;
            assert!(
                SnpAttestationReport::parse(&altered).is_err(),
                "version {version}, offset {offset}"
            );
        }
    }
    for version in [0u32, 1, 4, 6, u32::MAX] {
        let mut raw = payload.report.clone();
        raw[..4].copy_from_slice(&version.to_le_bytes());
        assert!(matches!(
            SnpAttestationReport::parse(&raw),
            Err(AttestationError::Malformed(
                "unsupported SNP report version"
            ))
        ));
    }
    // Both little-endian u64 fields are parsed independently, including high bits.
    let mut raw = payload.report;
    raw[504..512].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    raw[512..520].copy_from_slice(&0xfedc_ba98_7654_3210u64.to_le_bytes());
    let parsed = SnpAttestationReport::parse(&raw).unwrap();
    assert_eq!(parsed.launch_mitigation_vector, Some(0x1234_5678_9abc_def0));
    assert_eq!(
        parsed.current_mitigation_vector,
        Some(0xfedc_ba98_7654_3210)
    );
}

#[test]
fn v5_cpuid_must_match_the_authenticated_vcek_product() {
    let (payload, _) = genoa_v5_fixture();
    let endorsements =
        certificates::verify_amd_endorsements(&payload.endorsements, GENOA_V5_TIME).unwrap();
    let original = SnpAttestationReport::parse(&payload.report).unwrap();
    certificates::verify_vcek_extensions(&endorsements.vcek, &original, "Genoa").unwrap();
    for (family, model) in [(0x1a, 0x11), (0x19, 0x01), (0x19, 0x20)] {
        let mut report = original.clone();
        report.cpuid_family = family;
        report.cpuid_model = model;
        assert!(matches!(
            certificates::verify_vcek_extensions(&endorsements.vcek, &report, "Genoa"),
            Err(AttestationError::ReportPolicyRejected(
                "CPUID and VCEK product mismatch"
            ))
        ));
    }
}

fn policy() -> AppraisalPolicy {
    AppraisalPolicy {
        policy_id: [1; 32],
        release_id: "historical-native-fixture".into(),
        active_profiles: [AZURE_ACI_SNP.to_owned()].into(),
        valid_from: 1_730_000_000,
        valid_until: 1_900_000_000,
        max_appraisal_lifetime: 3600,
        minimum_tcb: [
            (
                "Milan".into(),
                TcbVersion {
                    bootloader: 4,
                    tee: 0,
                    snp: 24,
                    microcode: 219,
                },
            ),
            (
                "Genoa".into(),
                TcbVersion {
                    bootloader: 10,
                    tee: 0,
                    snp: 23,
                    microcode: 84,
                },
            ),
        ]
        .into(),
        approved_measurements: [MEASUREMENT.into()].into(),
        approved_host_data: [HOST_DATA.into()].into(),
        uvm_endorsement_time_policy: UvmEndorsementTimePolicy::CurrentCertificate,
        uvm: vec![UvmIdentity {
            did: MICROSOFT_UVM_DID.into(),
            feed: "ContainerPlat-AMD-UVM".into(),
            minimum_svn: 101,
        }],
    }
}
fn encode(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}
fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}
fn signed(payload: &[u8], key: &PKey<Private>) -> Vec<u8> {
    let envelope = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        )
        .payload(payload.to_vec())
        .create_signature(&[], |tbs| {
            let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
            signer.update(tbs).unwrap();
            let der = signer.sign_to_vec().unwrap();
            let sig = EcdsaSig::from_der(&der).unwrap();
            [
                sig.r().to_vec_padded(32).unwrap(),
                sig.s().to_vec_padded(32).unwrap(),
            ]
            .concat()
        })
        .build();
    envelope.to_tagged_vec().unwrap()
}

#[test]
fn genuine_milan_and_genoa_report_and_microsoft_uvm_are_verified() {
    for (bytes, product) in [(MILAN, "Milan"), (GENOA, "Genoa")] {
        let payload = cose::parse_native_payload(bytes).unwrap();
        let verified = verify_native(&payload, &policy(), HISTORICAL_TIME).unwrap();
        assert_eq!(verified.product, product);
        assert_eq!(hex::encode(verified.report.measurement), MEASUREMENT);
        assert_eq!(verified.uvm.svn, 101);
        assert_eq!(verified.report.report_data[..4], *b"1234");
    }
}
#[test]
fn native_test_quotes_cannot_be_presented_as_bound_service_evidence() {
    let key = key();
    for bytes in [MILAN, GENOA] {
        let envelope = signed(bytes, &key);
        assert!(matches!(
            appraise(
                AZURE_ACI_SNP,
                &envelope,
                &key.public_key_to_der().unwrap(),
                &policy(),
                HISTORICAL_TIME
            ),
            Err(AttestationError::KeyBindingMismatch)
        ));
    }
}
#[test]
fn report_data_requires_digest_and_every_padding_byte() {
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let mut report = SnpAttestationReport::parse(&payload.report).unwrap();
    let spki = key().public_key_to_der().unwrap();
    report.report_data[..32].copy_from_slice(&Sha256::digest(&spki));
    report.verify_key_binding(&spki).unwrap();
    assert!(matches!(
        report.verify_key_binding(b"different"),
        Err(AttestationError::KeyBindingMismatch)
    ));
    for i in 32..64 {
        report.report_data[i] = 1;
        assert!(matches!(
            report.verify_key_binding(&spki),
            Err(AttestationError::ReportDataNotZeroed)
        ));
        report.report_data[i] = 0;
    }
}
#[test]
fn modified_hardware_report_signature_fails() {
    let mut payload = cose::parse_native_payload(MILAN).unwrap();
    payload.report[90] ^= 1;
    assert!(matches!(
        verify_native(&payload, &policy(), HISTORICAL_TIME),
        Err(AttestationError::SignatureInvalid)
    ));
}
#[test]
fn swapped_milan_and_genoa_endorsements_fail() {
    let mut payload = cose::parse_native_payload(MILAN).unwrap();
    payload.endorsements = cose::parse_native_payload(GENOA).unwrap().endorsements;
    assert!(matches!(
        verify_native(&payload, &policy(), HISTORICAL_TIME),
        Err(AttestationError::SignatureInvalid)
    ));
}
#[test]
fn outer_signature_key_and_p1363_format_are_enforced() {
    let key = key();
    let spki = key.public_key_to_der().unwrap();
    let envelope = signed(MILAN, &key);
    let mut parsed = cose::parse_sign1(&envelope).unwrap();
    cose::verify_es256(&parsed, &spki).unwrap();
    let other = self::key().public_key_to_der().unwrap();
    assert!(matches!(
        cose::verify_es256(&parsed, &other),
        Err(AttestationError::SignatureInvalid)
    ));
    parsed.signature[4] ^= 1;
    assert!(matches!(
        cose::verify_es256(&parsed, &spki),
        Err(AttestationError::SignatureInvalid)
    ));
    parsed.signature = vec![0; 72];
    assert!(matches!(
        cose::verify_es256(&parsed, &spki),
        Err(AttestationError::UnsupportedAlgorithm)
    ));
    let mut trailing = spki.clone();
    trailing.push(0);
    assert!(cose::verify_es256(&parsed, &trailing).is_err());
}
#[test]
fn unsupported_and_inactive_profiles_fail_before_decoding() {
    for profile in ["tdx", "nitro", "vtpm", "insecure_virtual", ""] {
        assert!(matches!(
            appraise(profile, b"", b"", &policy(), HISTORICAL_TIME),
            Err(AttestationError::UnsupportedProfile)
        ));
    }
    let mut p = policy();
    p.active_profiles.clear();
    assert!(matches!(
        appraise(AZURE_ACI_SNP, b"", b"", &p, HISTORICAL_TIME),
        Err(AttestationError::ProfileNotActive)
    ));
    p = policy();
    p.valid_until = HISTORICAL_TIME;
    assert!(matches!(
        appraise(AZURE_ACI_SNP, b"", b"", &p, HISTORICAL_TIME),
        Err(AttestationError::PolicyNotValid)
    ));
}
#[test]
fn every_security_policy_and_tcb_component_is_enforced() {
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let original = SnpAttestationReport::parse(&payload.report).unwrap();
    for (vmpl, policy_bit, flags) in [
        (1, 0, 0),
        (0, 1 << 19, 0),
        (0, 1 << 18, 0),
        (0, 0, 2),
        (0, 0, 4),
        (0, 0, 32),
    ] {
        let mut report = original.clone();
        report.vmpl = vmpl;
        report.policy |= policy_bit;
        report.flags = flags;
        assert!(report.verify_security_policy().is_err());
    }
    for field in 0..4 {
        let mut p = policy();
        let tcb = p.minimum_tcb.get_mut("Milan").unwrap();
        match field {
            0 => tcb.bootloader += 1,
            1 => tcb.tee += 1,
            2 => tcb.snp += 1,
            _ => tcb.microcode += 1,
        }
        assert!(matches!(
            verify_native(&payload, &p, HISTORICAL_TIME),
            Err(AttestationError::TcbBelowMinimum)
        ));
    }
    assert!(
        !TcbVersion {
            bootloader: 0,
            tee: 9,
            snp: 255,
            microcode: 255
        }
        .meets(&TcbVersion {
            bootloader: 1,
            tee: 0,
            snp: 0,
            microcode: 0
        })
    );
}
#[test]
fn workload_allowlists_and_uvm_identity_fail_closed() {
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let mut p = policy();
    p.approved_host_data.clear();
    assert!(matches!(
        verify_native(&payload, &p, HISTORICAL_TIME),
        Err(AttestationError::HostDataRejected)
    ));
    p = policy();
    p.approved_measurements.clear();
    assert!(matches!(
        verify_native(&payload, &p, HISTORICAL_TIME),
        Err(AttestationError::MeasurementRejected)
    ));
    p = policy();
    p.uvm[0].feed = "WrongFeed".into();
    assert!(matches!(
        verify_native(&payload, &p, HISTORICAL_TIME),
        Err(AttestationError::UvmIdentityRejected)
    ));
    p = policy();
    p.uvm[0].did = MICROSOFT_UVM_DID.replace("I__i", "A__i");
    assert!(matches!(
        verify_native(&payload, &p, HISTORICAL_TIME),
        Err(AttestationError::UvmIdentityRejected)
    ));
    p = policy();
    p.uvm[0].minimum_svn = 102;
    assert!(matches!(
        verify_native(&payload, &p, HISTORICAL_TIME),
        Err(AttestationError::UvmSvnBelowMinimum)
    ));
    // Numeric comparison: 101 cannot be compared lexicographically with 99.
    p.uvm[0].minimum_svn = 99;
    verify_native(&payload, &p, HISTORICAL_TIME).unwrap();
}
#[test]
fn altered_uvm_payload_and_signature_are_rejected() {
    let mut payload = cose::parse_native_payload(MILAN).unwrap();
    let original = payload.uvm.clone();
    let mut signed = cose::parse_sign1(&payload.uvm).unwrap();
    signed.signature[0] ^= 1;
    payload.uvm = signed.to_tagged_vec().unwrap();
    assert!(matches!(
        verify_native(&payload, &policy(), HISTORICAL_TIME),
        Err(AttestationError::SignatureInvalid)
    ));
    signed = cose::parse_sign1(&original).unwrap();
    let p = signed.payload.as_mut().unwrap();
    let last = p.len() - 2;
    p[last] ^= 1;
    payload.uvm = signed.to_tagged_vec().unwrap();
    assert!(verify_native(&payload, &policy(), HISTORICAL_TIME).is_err());
}
#[test]
fn expired_historical_uvm_certificates_are_not_current_proof() {
    let payload = cose::parse_native_payload(MILAN).unwrap();
    assert!(matches!(
        verify_native(&payload, &policy(), 1_789_257_600),
        Err(AttestationError::CertificateInvalid(_))
    ));
}
#[test]
fn malformed_inputs_are_bounded_and_do_not_panic() {
    let payload = cose::parse_native_payload(MILAN).unwrap();
    for len in 0..payload.report.len() {
        assert!(SnpAttestationReport::parse(&payload.report[..len]).is_err());
    }
    for len in [0, 1, 2, 5, 8, 80, MILAN.len() - 1] {
        assert!(cose::parse_native_payload(&MILAN[..len]).is_err());
    }
    let duplicate = Value::Map(vec![
        (Value::Text("att".into()), Value::Null),
        (Value::Text("att".into()), Value::Null),
    ]);
    assert!(cose::decode(&encode(duplicate)).is_err());
    let mut nested = Value::Null;
    for _ in 0..20 {
        nested = Value::Array(vec![nested]);
    }
    assert!(cose::decode(&encode(nested)).is_err());
    let mut trailing = MILAN.to_vec();
    trailing.push(0);
    assert!(cose::parse_native_payload(&trailing).is_err());
    assert!(cose::parse_sign1(MILAN).is_err()); // Raw payload is never an envelope.
}

#[test]
fn genuine_legacy_and_current_cwt_uvm_endorsements_verify() {
    let identities = policy().uvm;
    let legacy = include_bytes!("../tests/fixtures/ccf_uvm_0.2.9.cose");
    let current = include_bytes!("../tests/fixtures/ccf_uvm_0.2.10.cose");
    let legacy_measurement: [u8; 48] = hex::decode("d0c9e2be22046e60779be88868cff64c2aa22047c15d3127ba495cee3fbc2854c5633f9da2096e6c64ae2b69bbff8082").unwrap().try_into().unwrap();
    let current_measurement: [u8; 48] = hex::decode("4904167aa9102a7557b97ac102469f50289d5be76036fcbb8107897ee146a6184772c4ea6e3f050a1bac6951c285bc89").unwrap().try_into().unwrap();
    let now = 1_767_225_600; // 2026-01-01, chain valid and after signed issuance.
    assert_eq!(
        uvm::verify(
            legacy,
            &legacy_measurement,
            &identities,
            now,
            UvmEndorsementTimePolicy::CurrentCertificate
        )
        .unwrap()
        .svn,
        103
    );
    assert_eq!(
        uvm::verify(
            current,
            &current_measurement,
            &identities,
            now,
            UvmEndorsementTimePolicy::CurrentCertificate
        )
        .unwrap()
        .svn,
        104
    );
    assert!(matches!(
        uvm::verify(
            current,
            &legacy_measurement,
            &identities,
            now,
            UvmEndorsementTimePolicy::CurrentCertificate
        ),
        Err(AttestationError::MeasurementRejected)
    ));
    assert!(
        uvm::verify(
            current,
            &current_measurement,
            &identities,
            1_760_000_000,
            UvmEndorsementTimePolicy::CurrentCertificate
        )
        .is_err()
    ); // future iat
}

#[test]
fn pinned_amd_root_is_not_replaceable_by_an_attacker() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let other = cose::parse_native_payload(GENOA).unwrap();
    let mut thim: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(payload.endorsements).unwrap()).unwrap();
    let other: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(other.endorsements).unwrap()).unwrap();
    // Even a genuine second AMD product root cannot authenticate the first product path.
    thim["certificateChain"] = other["certificateChain"].clone();
    assert!(
        certificates::verify_amd_endorsements(
            &STANDARD.encode(serde_json::to_vec(&thim).unwrap()),
            HISTORICAL_TIME
        )
        .is_err()
    );
    // A self-signed attacker root is rejected before any path is trusted.
    let k = key();
    let mut builder = openssl::x509::X509::builder().unwrap();
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "attacker").unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&k).unwrap();
    builder
        .set_not_before(&openssl::asn1::Asn1Time::from_unix(HISTORICAL_TIME as i64 - 3600).unwrap())
        .unwrap();
    builder
        .set_not_after(&openssl::asn1::Asn1Time::from_unix(HISTORICAL_TIME as i64 + 3600).unwrap())
        .unwrap();
    builder.sign(&k, MessageDigest::sha256()).unwrap();
    let cert = String::from_utf8(builder.build().to_pem().unwrap()).unwrap();
    thim["certificateChain"] = serde_json::Value::String(format!("{cert}{cert}"));
    assert!(matches!(
        certificates::verify_amd_endorsements(
            &STANDARD.encode(serde_json::to_vec(&thim).unwrap()),
            HISTORICAL_TIME
        ),
        Err(AttestationError::UntrustedRoot)
    ));
}

#[test]
fn duplicate_algorithm_and_critical_headers_are_rejected() {
    let key = key();
    let mut value = cose::decode(&signed(MILAN, &key)).unwrap();
    let Value::Tag(_, inner) = &mut value else {
        panic!()
    };
    let arr = inner.as_array_mut().unwrap();
    arr[1] = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer((-7).into()),
    )]);
    assert!(cose::parse_sign1(&encode(value)).is_err());
    let mut sign1 = cose::parse_sign1(&signed(MILAN, &key)).unwrap();
    sign1.protected.original_data = None;
    sign1.protected.header.crit = vec![coset::RegisteredLabelWithPrivate::Assigned(
        iana::HeaderParameter::Alg,
    )];
    sign1
        .protected
        .header
        .rest
        .push((coset::Label::Int(555), Value::Bool(true)));
    assert!(cose::parse_sign1(&sign1.to_tagged_vec().unwrap()).is_err());
}

#[test]
fn ambiguous_governance_publisher_entries_fail_closed() {
    let mut p = policy();
    let mut duplicate = p.uvm[0].clone();
    duplicate.minimum_svn = 1;
    p.uvm.push(duplicate);
    assert!(matches!(
        appraise(AZURE_ACI_SNP, b"", b"", &p, HISTORICAL_TIME),
        Err(AttestationError::PolicyNotValid)
    ));
}

#[test]
fn governed_immutable_release_mode_accepts_genuine_expired_uvm_signers() {
    let now = 1_789_257_600;
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let mut p = policy();
    assert!(matches!(
        verify_native(&payload, &p, now),
        Err(AttestationError::CertificateInvalid(_))
    ));
    p.uvm_endorsement_time_policy = UvmEndorsementTimePolicy::ApprovedRelease;
    let verified = verify_native(&payload, &p, now).unwrap();
    assert_eq!(verified.uvm.svn, 101);
    assert!(verified.certificates_valid_until > now);
    let current = include_bytes!("../tests/fixtures/ccf_uvm_0.2.10.cose");
    let measurement = hex::decode("4904167aa9102a7557b97ac102469f50289d5be76036fcbb8107897ee146a6184772c4ea6e3f050a1bac6951c285bc89").unwrap().try_into().unwrap();
    let current = uvm::verify(
        current,
        &measurement,
        &p.uvm,
        now,
        p.uvm_endorsement_time_policy,
    )
    .unwrap();
    assert_eq!(current.svn, 104);
    assert_eq!(current.valid_until, u64::MAX);
}

#[test]
fn approved_release_keeps_governance_signatures_and_amd_time_checks() {
    let now = 1_789_257_600;
    let mut payload = cose::parse_native_payload(MILAN).unwrap();
    let mut p = policy();
    p.uvm_endorsement_time_policy = UvmEndorsementTimePolicy::ApprovedRelease;
    p.approved_measurements.clear();
    assert!(matches!(
        verify_native(&payload, &p, now),
        Err(AttestationError::MeasurementRejected)
    ));
    p.approved_measurements.insert(MEASUREMENT.into());
    p.uvm[0].minimum_svn = 102;
    assert!(matches!(
        verify_native(&payload, &p, now),
        Err(AttestationError::UvmSvnBelowMinimum)
    ));
    p.uvm[0].minimum_svn = 101;
    assert!(matches!(
        verify_native(&payload, &p, 2_100_000_000),
        Err(AttestationError::CertificateInvalid(_))
    ));
    let mut signed = cose::parse_sign1(&payload.uvm).unwrap();
    signed.signature[0] ^= 1;
    payload.uvm = signed.to_tagged_vec().unwrap();
    assert!(matches!(
        verify_native(&payload, &p, now),
        Err(AttestationError::SignatureInvalid)
    ));
    let mut v = serde_json::to_value(&p).unwrap();
    v.as_object_mut()
        .unwrap()
        .remove("uvm_endorsement_time_policy");
    assert_eq!(
        serde_json::from_value::<AppraisalPolicy>(v)
            .unwrap()
            .uvm_endorsement_time_policy,
        UvmEndorsementTimePolicy::CurrentCertificate
    );
}

#[test]
fn ccf_node_audit_checks_real_crypto_and_cannot_relabel_unbound_reports() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use openssl::{
        asn1::Asn1Time,
        x509::{X509, X509NameBuilder},
    };
    let node_key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "test node").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&node_key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix((HISTORICAL_TIME - 60) as i64).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix((HISTORICAL_TIME + 600) as i64).unwrap())
        .unwrap();
    builder.sign(&node_key, MessageDigest::sha256()).unwrap();
    let peer = builder.build().to_der().unwrap();
    let payload = cose::parse_native_payload(MILAN).unwrap();
    let mut quote = serde_json::json!({
        "node_id":hex::encode(Sha256::digest(node_key.public_key_to_der().unwrap())),
        "format":"AMD_SEV_SNP_v1", "raw":STANDARD.encode(&payload.report),
        "endorsements":payload.endorsements, "uvm_endorsements":STANDARD.encode(payload.uvm),
        "measurement":MEASUREMENT,
    });
    let audit = |q: &serde_json::Value| {
        node_audit::audit(
            &serde_json::to_vec(q).unwrap(),
            &peer,
            &policy(),
            HISTORICAL_TIME,
        )
    };
    assert!(matches!(
        audit(&quote),
        Err(AttestationError::KeyBindingMismatch)
    ));
    quote["format"] = "Insecure_Virtual".into();
    assert!(matches!(
        audit(&quote),
        Err(AttestationError::UnsupportedProfile)
    ));
    quote["format"] = "AMD_SEV_SNP_v1".into();
    let mut altered = payload.report;
    altered[90] ^= 1;
    quote["raw"] = STANDARD.encode(altered).into();
    assert!(matches!(
        audit(&quote),
        Err(AttestationError::SignatureInvalid)
    ));
    assert!(matches!(
        node_audit::audit(
            &serde_json::to_vec(&quote).unwrap(),
            &peer,
            &policy(),
            HISTORICAL_TIME + 601
        ),
        Err(AttestationError::CertificateInvalid(_))
    ));
}

#[test]
fn request_diagnostics_preserve_genuine_native_verification_and_hide_evidence() {
    use adns_telemetry::{Name, RequestScope};
    let (payload, policy) = genoa_v5_fixture();
    let baseline = verify_native(&payload, &policy, GENOA_V5_TIME).unwrap();
    let scope = RequestScope::new();
    let traced = verify_native(&payload, &policy, GENOA_V5_TIME).unwrap();
    assert_eq!(traced.report.measurement, baseline.report.measurement);
    assert_eq!(traced.product, baseline.product);
    assert_eq!(
        traced.certificates_valid_until,
        baseline.certificates_valid_until
    );
    let spans = scope.finish();
    for name in [Name::AmdChain, Name::Snp, Name::Uvm] {
        assert!(
            spans
                .iter()
                .any(|span| span.name == name && span.outcome == 1)
        );
    }
    let diagnostic_text = format!("{spans:?}");
    assert!(!diagnostic_text.contains(&hex::encode(traced.report.measurement)));
    assert!(!diagnostic_text.contains(&hex::encode(traced.report.host_data)));
    assert!(!diagnostic_text.contains(&traced.uvm.did));
    let scope = RequestScope::new();
    assert!(matches!(
        appraise(
            "unactivated",
            b"PRIVATE_EVIDENCE_MARKER",
            b"PRIVATE_KEY_MARKER",
            &policy,
            GENOA_V5_TIME
        ),
        Err(AttestationError::UnsupportedProfile)
    ));
    let rejected = scope.finish();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].name, Name::Appraisal);
    assert_eq!(rejected[0].outcome, 2);
    assert!(!format!("{rejected:?}").contains("PRIVATE_"));
}
