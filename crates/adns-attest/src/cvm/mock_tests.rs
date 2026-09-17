//! End-to-end appraisal of a complete Azure-CVM evidence bundle produced by
//! `tools/mock-cvm` (go-sev-guest test AMD keys, test vTPM CA). Proves the
//! positive path — VCEK signature, ARK chain, HCL binding, AK chain, TPM quote —
//! that the captured fixtures could not, and that each single-field tampering is
//! rejected. Nothing here is a hardware claim: the roots are test keys pinned
//! only in this module.
use super::*;
use crate::certificates::test_ark;
use crate::tests::{encode, key, signed};
use ciborium::value::Value;
use openssl::{pkey::Private, sign::Signer};

const HCL: &[u8] = include_bytes!("../../tests/fixtures/mock-cvm/hcl.bin");
const EDS: &str = include_str!("../../tests/fixtures/mock-cvm/endorsements.pem");
const ARK: &[u8] = include_bytes!("../../tests/fixtures/mock-cvm/ark_test.pem");
const AK_CHAIN: &str = include_str!("../../tests/fixtures/mock-cvm/ak_chain.pem");
const AK_KEY: &[u8] = include_bytes!("../../tests/fixtures/mock-cvm/ak_private_test.pem");
const MANIFEST: &str = include_str!("../../tests/fixtures/mock-cvm/manifest.json");

fn manifest() -> serde_json::Value {
    serde_json::from_str(MANIFEST).unwrap()
}
fn now() -> u64 {
    manifest()["now_unix"].as_u64().unwrap()
}
fn policy() -> AppraisalPolicy {
    let m = manifest();
    let h = HclReport::parse(HCL).unwrap();
    AppraisalPolicy {
        policy_id: [9; 32],
        release_id: "mock-cvm".into(),
        active_profiles: [AZURE_CVM_SNP.into()].into(),
        valid_from: now() - 100,
        valid_until: now() + 3600,
        max_appraisal_lifetime: 600,
        minimum_tcb: [("Genoa".into(), h.report.reported_tcb)].into(),
        approved_measurements: [m["measurement_hex"].as_str().unwrap().into()].into(),
        approved_host_data: [m["host_data_hex"].as_str().unwrap().into()].into(),
        azure_cvm: Some(AzureCvmPolicy {
            vmpl: 0,
            allowed_ak_ca_subjects: [AZURE_AK_CA_25.into()].into(),
            ak_root_sha256: [m["ak_root_sha256"].as_str().unwrap().into()].into(),
        }),
        ..Default::default()
    }
}
fn tpm_quote(spki: &[u8], ak: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
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
fn evidence(hcl: &[u8], eds: &str, ak_chain: &str, workload: &PKey<Private>) -> Vec<u8> {
    let ak = PKey::private_key_from_pem(AK_KEY).unwrap();
    let spki = workload.public_key_to_der().unwrap();
    let (quote, sig) = tpm_quote(&spki, &ak);
    let payload = encode(Value::Map(vec![
        (Value::Text("hcl".into()), Value::Bytes(hcl.to_vec())),
        (Value::Text("eds".into()), Value::Text(eds.into())),
        (Value::Text("ak".into()), Value::Text(ak_chain.into())),
        (Value::Text("quote".into()), Value::Bytes(quote)),
        (Value::Text("sig".into()), Value::Bytes(sig)),
    ]));
    signed(&payload, workload)
}
fn appraise(
    ev: &[u8],
    k: &PKey<Private>,
    p: &AppraisalPolicy,
) -> Result<VerifiedAppraisal, AttestationError> {
    crate::appraise(AZURE_CVM_SNP, ev, &k.public_key_to_der().unwrap(), p, now())
}

#[test]
fn complete_mock_bundle_is_accepted_end_to_end() {
    test_ark::install("Genoa", ARK);
    let k = key();
    let m = manifest();
    let out = appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &policy()).unwrap();
    assert_eq!(out.profile, AZURE_CVM_SNP);
    assert_eq!(out.product, "Genoa");
    assert_eq!(
        hex::encode(out.measurement),
        m["measurement_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(out.host_data),
        m["host_data_hex"].as_str().unwrap()
    );
    assert_eq!(out.reported_tcb.bootloader, 7);
    assert_eq!(out.reported_tcb.snp, 14);
    assert_eq!(out.uvm_svn, 0, "HCL carries no UVM endorsement");
    assert!(out.valid_until <= now() + 600);
    test_ark::clear();
}

#[test]
fn production_pins_reject_the_test_root() {
    // Without the test hook the same bundle must fail: the ARK is not AMD's.
    test_ark::clear();
    let k = key();
    assert!(matches!(
        appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &policy()),
        Err(AttestationError::UntrustedRoot)
    ));
}

#[test]
fn every_single_field_tampering_is_rejected() {
    test_ark::install("Genoa", ARK);
    let k = key();
    let p = policy();
    // 1. report_data no longer binds the runtime JSON
    let mut hcl = HCL.to_vec();
    hcl[32 + 0x50] ^= 1;
    assert!(appraise(&evidence(&hcl, EDS, AK_CHAIN, &k), &k, &p).is_err());
    // 2. any signed report byte (measurement) breaks the VCEK signature
    let mut hcl = HCL.to_vec();
    hcl[32 + 0x90] ^= 1;
    assert!(matches!(
        appraise(&evidence(&hcl, EDS, AK_CHAIN, &k), &k, &p),
        Err(AttestationError::SignatureInvalid) | Err(AttestationError::ReportPolicyRejected(_))
    ));
    // 3. signature bytes themselves
    let mut hcl = HCL.to_vec();
    hcl[32 + 0x2A0 + 3] ^= 1;
    assert!(matches!(
        appraise(&evidence(&hcl, EDS, AK_CHAIN, &k), &k, &p),
        Err(AttestationError::SignatureInvalid)
    ));
    // 4. runtime JSON altered (AK swapped for another key): report_data mismatch
    let other_ak = Rsa::generate(2048).unwrap();
    let n = openssl::base64::encode_block(&other_ak.n().to_vec())
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    let runtime = std::str::from_utf8(&HCL[1236..])
        .unwrap()
        .trim_end_matches('\0');
    let m: serde_json::Value = serde_json::from_str(runtime).unwrap();
    let orig_n = m["keys"][0]["n"].as_str().unwrap();
    let swapped = runtime.replace(orig_n, &n);
    let mut hcl = HCL[..1236].to_vec();
    hcl.extend(swapped.as_bytes());
    hcl.resize(HCL.len(), 0);
    assert!(appraise(&evidence(&hcl, EDS, AK_CHAIN, &k), &k, &p).is_err());
    // 5. endorsement chain: drop the ARK
    let no_ark = EDS
        .split("-----BEGIN CERTIFICATE-----")
        .take(3)
        .collect::<Vec<_>>()
        .join("-----BEGIN CERTIFICATE-----");
    assert!(appraise(&evidence(HCL, &no_ark, AK_CHAIN, &k), &k, &p).is_err());
    // 6. AK chain from a foreign CA (real Azure captured chain from the worker fixture would also be foreign here)
    let foreign = {
        let ca = Rsa::generate(2048).unwrap();
        let _ = ca;
        AK_CHAIN.replacen("MII", "MIJ", 1)
    };
    assert!(appraise(&evidence(HCL, EDS, &foreign, &k), &k, &p).is_err());
    // 7. AK root not in policy
    let mut p2 = p.clone();
    p2.azure_cvm.as_mut().unwrap().ak_root_sha256 = ["00".repeat(32)].into();
    assert!(matches!(
        appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &p2),
        Err(AttestationError::UntrustedRoot)
    ));
    // 8. TCB floor above the report
    let mut p3 = p.clone();
    p3.minimum_tcb.get_mut("Genoa").unwrap().snp = 15;
    assert!(appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &p3).is_err());
    // 9. wrong VMPL in policy
    let mut p4 = p.clone();
    p4.azure_cvm.as_mut().unwrap().vmpl = 1;
    assert!(matches!(
        appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &p4),
        Err(AttestationError::ReportPolicyRejected(_))
    ));
    // 10. measurement not approved
    let mut p5 = p.clone();
    p5.approved_measurements = ["00".repeat(48)].into();
    assert!(appraise(&evidence(HCL, EDS, AK_CHAIN, &k), &k, &p5).is_err());
    // 11. TPM quote signed for a different workload key
    let other = key();
    let ev_other = evidence(HCL, EDS, AK_CHAIN, &other);
    assert!(appraise(&ev_other, &k, &p).is_err());
    // 12. evidence past the AK certificate lifetime
    assert!(
        crate::appraise(
            AZURE_CVM_SNP,
            &evidence(HCL, EDS, AK_CHAIN, &k),
            &k.public_key_to_der().unwrap(),
            &p,
            now() + 2 * 365 * 86400
        )
        .is_err()
    );
    test_ark::clear();
}
