use adns_auth::*;
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{Value, json};

const NOW: u64 = 1_789_243_200;
const AUDIENCE: &str = "ccf://agentdns.service.identity";

fn key() -> signature::EcdsaKeyPair {
    let rng = SystemRandom::new();
    let der =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        der.as_ref(),
        &rng,
    )
    .unwrap()
}
fn spki(key: &signature::EcdsaKeyPair) -> String {
    let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
    der.extend_from_slice(key.public_key().as_ref());
    encode_base64url(&der)
}
fn action(key: &signature::EcdsaKeyPair) -> Action {
    Action {
        request_id: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
        audience: AUDIENCE.into(),
        grant_id: "grant-2026-prod-01".into(),
        zone: "agent.hosting.".into(),
        signer_spki_der: spki(key),
        parameters: ActionParameters::Register(RegisterParameters {
            role: "mx-edge".into(),
            mailbox_domain: "agent.hosting.".into(),
            service_host: "mail.agent.hosting.".into(),
            addresses: Addresses {
                ipv4: vec!["20.114.5.117".into()],
                ipv6: vec!["2603:1030:805:2::14".into()],
            },
            ports: vec![25, 465, 993],
            lease_seconds: 86400,
            evidence_profile: "azure-aci-snp".into(),
            evidence_digest: sha256_hex(b"test signed COSE fixture"),
            attested_records: Vec::new(),
        }),
    }
}
fn grant(action: &Action) -> OwnerGrant {
    OwnerGrant {
        grant_id: action.grant_id.clone(),
        subject_spki_sha256: sha256_hex(&decode_p256_spki(&action.signer_spki_der).unwrap()),
        zones: vec!["agent.hosting.".into()],
        mailbox_domains: vec!["agent.hosting.".into()],
        service_hosts: vec!["mail.agent.hosting.".into()],
        roles: vec!["mx-edge".into()],
        address_cidrs: vec!["20.114.5.0/24".into(), "2603:1030:805:2::/64".into()],
        ports: vec![25, 465, 993],
        allowed_operations: vec![
            Operation::Register,
            Operation::Renew,
            Operation::Deregister,
            Operation::AcmeChallengeCreate,
            Operation::AcmeChallengeDelete,
            Operation::OperatorRecords,
        ],
        acme_names: vec!["mail.agent.hosting.".into()],
        operator_names: vec!["agent.hosting.".into(), "_dmarc.agent.hosting.".into()],
        operator_record_types: vec![OperatorRecordType::Txt, OperatorRecordType::Caa],
        attested_names: Vec::new(),
        attested_record_types: Vec::new(),
        max_lease_seconds: 86400,
        max_challenge_lifetime_seconds: 1800,
        valid_from: NOW - 60,
        valid_until: NOW + 172800,
        revoked: false,
    }
}
fn signed(key: &signature::EcdsaKeyPair, action: Action) -> (SignedRequest, NonceRecord) {
    let nonce = issue_nonce(&action, NOW).unwrap();
    let evidence_payload = action
        .parameters
        .evidence_digest()
        .map(|_| encode_base64url(b"test signed COSE fixture"));
    let mut request = SignedRequest {
        action,
        nonce: nonce.nonce.clone(),
        nonce_expires_at: nonce.expires_at,
        intent_hash: nonce.intent_hash.clone(),
        client_signature: String::new(),
        evidence_payload,
    };
    request.client_signature = encode_base64url(
        key.sign(&SystemRandom::new(), &request.signed_message().unwrap())
            .unwrap()
            .as_ref(),
    );
    (request, nonce)
}
fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn jcs_vectors_use_utf16_sorting_minimal_escapes_and_safe_integer_subset() {
    let value = parse_strict_json(
        br#"{ "z": [true,null,9007199254740991], "a": "x\n\u0001\/\\\"", "b":0 }"#,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(canonical_json(&value).unwrap()).unwrap(),
        r#"{"a":"x\n\u0001/\\\"","b":0,"z":[true,null,9007199254740991]}"#
    );
    // A supplementary scalar sorts before U+E000 because its high surrogate is D800.
    assert_eq!(
        String::from_utf8(canonical_json(&json!({"\u{e000}":1,"\u{10000}":2})).unwrap()).unwrap(),
        "{\"𐀀\":2,\"\":1}"
    );
    for bad in [
        r#"{"x":1,"x":2}"#,
        r#"{"x":1,"\u0078":2}"#,
        r#"{"nested":{"a":1,"a":2}}"#,
        r#"{"x":1.0}"#,
        r#"{"x":1e0}"#,
        r#"{"x":-0}"#,
        r#"{"x":-1}"#,
        r#"{"x":9007199254740992}"#,
        r#"{"x":"\ud800"}"#,
        r#"{} {}"#,
    ] {
        assert!(parse_strict_json(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(canonical_json(&json!(1.0)).is_err());
}

#[test]
fn actual_p256_signature_round_trip_and_single_hash() {
    let key = key();
    let action = action(&key);
    let owner = grant(&action);
    let (request, nonce) = signed(&key, action);
    assert_eq!(nonce.nonce.len(), 64);
    assert_eq!(nonce.expires_at - NOW, 300);
    let reparsed = parse_signed_request(&serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    let verified = verify_signed_request(&reparsed, &nonce, &owner, AUDIENCE, NOW).unwrap();
    assert_eq!(verified.signer_spki_der.len(), 91);
    assert_eq!(
        verified.evidence_payload.unwrap(),
        b"test signed COSE fixture"
    );
    // Signing a pre-hashed message would double hash and must not authenticate.
    let mut double_hash = request.clone();
    double_hash.client_signature = encode_base64url(
        key.sign(
            &SystemRandom::new(),
            &hex::decode(sha256_hex(&request.signed_message().unwrap())).unwrap(),
        )
        .unwrap()
        .as_ref(),
    );
    assert_eq!(
        verify_request_signature(&double_hash).unwrap_err(),
        AuthError::InvalidSignature
    );
    let raw = request.signed_message().unwrap();
    let v: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        v.as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
        vec!["action", "intent_hash", "nonce", "nonce_expires_at"]
    );
}

#[test]
fn strict_schema_rejects_unknown_duplicate_float_null_and_bad_encoding() {
    let key = key();
    let (request, _) = signed(&key, action(&key));
    let value = serde_json::to_value(&request).unwrap();
    for mutated in [
        {
            let mut v = value.clone();
            v["unknown"] = json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["action"]["unknown"] = json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["action"]["parameters"]["unknown"] = json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["action"]["parameters"]["addresses"]["unknown"] = json!(true);
            v
        },
        {
            let mut v = value.clone();
            v["action"]["parameters"]["lease_seconds"] = json!(1.0);
            v
        },
        {
            let mut v = value.clone();
            v["action"]["parameters"]["lease_seconds"] = json!("86400");
            v
        },
        {
            let mut v = value.clone();
            v["action"]["parameters"]["ports"] = json!([25, 65536]);
            v
        },
        {
            let mut v = value.clone();
            v["evidence_payload"] = Value::Null;
            v
        },
        {
            let mut v = value;
            v["client_signature"] = json!(format!("{}=", request.client_signature));
            v
        },
    ] {
        assert!(
            parse_signed_request(&json_bytes(&mutated)).is_err(),
            "{mutated}"
        );
    }
    let json = serde_json::to_string(&request).unwrap().replace(
        "\"lease_seconds\":86400",
        "\"lease_seconds\":86400,\"lease_seconds\":86400",
    );
    assert!(parse_signed_request(json.as_bytes()).is_err());
    let mut renew = action(&key);
    renew.parameters = ActionParameters::Renew(RenewParameters {
        registration_id: "reg-1".into(),
        requested_lease_seconds: 86400,
        evidence_profile: None,
        evidence_digest: None,
    });
    let (renew, _) = signed(&key, renew);
    let mut v = serde_json::to_value(&renew).unwrap();
    v["action"]["parameters"]["evidence_digest"] = Value::Null;
    assert!(parse_signed_request(&json_bytes(&v)).is_err());
}

#[test]
fn all_tampering_and_der_signatures_fail() {
    let key = key();
    let (request, nonce) = signed(&key, action(&key));
    let owner = grant(&request.action);
    let mut altered = request.clone();
    altered.evidence_payload = Some(encode_base64url(b"altered quote"));
    assert_eq!(
        verify_request_signature(&altered).unwrap_err(),
        AuthError::EvidenceDigestMismatch
    );
    let mut altered = request.clone();
    altered.action.request_id = "different".into();
    assert_eq!(
        verify_request_signature(&altered).unwrap_err(),
        AuthError::IntentMismatch
    );
    let mut altered = request.clone();
    altered.nonce = "aa".repeat(32);
    assert_eq!(
        verify_request_signature(&altered).unwrap_err(),
        AuthError::InvalidSignature
    );
    let mut altered = request.clone();
    altered.nonce_expires_at += 1;
    assert_eq!(
        verify_request_signature(&altered).unwrap_err(),
        AuthError::InvalidSignature
    );
    let mut altered = request.clone();
    let mut sig = decode_base64url(&altered.client_signature, 64).unwrap();
    sig[0] ^= 1;
    altered.client_signature = encode_base64url(&sig);
    assert_eq!(
        verify_request_signature(&altered).unwrap_err(),
        AuthError::InvalidSignature
    );
    // A valid ASN.1 ECDSA signature must be rejected despite using the same key.
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap();
    let asn1 = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let mut altered = request.clone();
    altered.action.signer_spki_der = spki(&asn1);
    altered.intent_hash = intent_hash(&altered.action).unwrap();
    altered.client_signature = encode_base64url(
        asn1.sign(&rng, &altered.signed_message().unwrap())
            .unwrap()
            .as_ref(),
    );
    assert!(matches!(
        verify_request_signature(&altered),
        Err(AuthError::InvalidSignature)
    ));
    let mut der = decode_p256_spki(&request.action.signer_spki_der).unwrap();
    der.push(0);
    assert_eq!(
        decode_p256_spki(&encode_base64url(&der)).unwrap_err(),
        AuthError::InvalidSpki
    );
    assert_eq!(
        verify_signed_request(&request, &nonce, &owner, "wrong-audience", NOW).unwrap_err(),
        AuthError::AudienceMismatch
    );
}

#[test]
fn nonce_boundaries_corruption_and_consumption_fail_closed() {
    let key = key();
    let (request, nonce) = signed(&key, action(&key));
    assert!(validate_nonce(&request, &nonce, NOW + 299).is_ok());
    assert_eq!(
        validate_nonce(&request, &nonce, NOW + 300),
        Err(AuthError::NonceExpired)
    );
    assert_eq!(
        validate_nonce(&request, &nonce, NOW - 1),
        Err(AuthError::NonceExpired)
    );
    let mut consumed = nonce.clone();
    consumed.consumed = true;
    assert_eq!(
        validate_nonce(&request, &consumed, NOW),
        Err(AuthError::NonceConsumed)
    );
    for altered in [
        {
            let mut n = nonce.clone();
            n.expires_at += 1;
            n
        },
        {
            let mut n = nonce.clone();
            n.grant_id = "other".into();
            n
        },
        {
            let mut n = nonce.clone();
            n.request_id = "other".into();
            n
        },
        {
            let mut n = nonce.clone();
            n.nonce = "00".repeat(32);
            n
        },
        {
            let mut n = nonce.clone();
            n.intent_hash = "00".repeat(32);
            n
        },
    ] {
        assert!(validate_nonce(&request, &altered, NOW).is_err());
    }
    assert!(issue_nonce(&request.action, MAX_SAFE_INTEGER - 299).is_err());
    assert_ne!(
        issue_nonce(&request.action, NOW).unwrap().nonce,
        nonce.nonce
    );
}

#[test]
fn historical_idempotency_is_exact_and_authenticates_retries() {
    let key = key();
    let (request, nonce) = signed(&key, action(&key));
    let mut owner = grant(&request.action);
    let verified = verify_signed_request(&request, &nonce, &owner, AUDIENCE, NOW).unwrap();
    let result = CommittedRequestResult {
        grant_id: request.action.grant_id.clone(),
        request_id: request.action.request_id.clone(),
        signed_message_digest: verified.signed_message_digest,
        http_status: 200,
        body: json!({"status":"committed","zone_serial":7}),
        tx_id: "2.9".into(),
    };
    owner.revoked = true;
    verify_request_signature(&request).unwrap();
    assert_eq!(
        reconcile_result(&request, &result).unwrap().body["zone_serial"],
        7
    );
    assert!(verify_signed_request(&request, &nonce, &owner, AUDIENCE, NOW + 301).is_err());
    let (same_action_new_nonce, _) = signed(&key, request.action.clone());
    assert_eq!(
        reconcile_result(&same_action_new_nonce, &result),
        Err(AuthError::RequestIdConflict)
    );
    let mut different = request.action;
    if let ActionParameters::Register(p) = &mut different.parameters {
        p.lease_seconds = 60;
    }
    let (different, _) = signed(&key, different);
    assert_eq!(
        reconcile_result(&different, &result),
        Err(AuthError::RequestIdConflict)
    );
}

#[test]
fn canonical_names_addresses_and_scope_boundaries() {
    for bad in [
        "Mail.agent.hosting.",
        "mail.agent.hosting",
        "mañana.agent.hosting.",
        "mail..agent.hosting.",
        "-bad.agent.hosting.",
        "bad-.agent.hosting.",
        "*.agent.hosting.",
        ".",
    ] {
        assert!(validate_name(bad, false).is_err(), "{bad}");
    }
    assert!(validate_name("xn--maana-pta.agent.hosting.", false).is_ok());
    assert!(validate_name("_dmarc.agent.hosting.", true).is_ok());
    assert!(!name_in_zone("evilagent.hosting.", "agent.hosting."));
    assert!(name_in_zone("mail.agent.hosting.", "agent.hosting."));
    for address in [
        Addresses {
            ipv4: vec!["020.114.5.117".into()],
            ipv6: vec![],
        },
        Addresses {
            ipv4: vec!["20.114.5.117".into(), "20.114.5.117".into()],
            ipv6: vec![],
        },
        Addresses {
            ipv4: vec!["20.114.5.117".into(), "20.114.5.2".into()],
            ipv6: vec![],
        },
        Addresses {
            ipv4: vec![],
            ipv6: vec!["2603:1030:0805:2::14".into()],
        },
        Addresses {
            ipv4: vec![],
            ipv6: vec!["2603:1030:805:2:0:0:0:14".into()],
        },
    ] {
        assert!(address.validate().is_err());
    }
    assert!(
        Addresses {
            ipv4: vec!["20.114.5.2".into(), "20.114.5.117".into()],
            ipv6: vec![]
        }
        .validate()
        .is_ok()
    );
    for cidr in [
        "20.114.5.117/24",
        "20.114.5.0/024",
        "20.114.5.0/33",
        "2603:1030:805:2::14/64",
        "::/129",
    ] {
        assert!(Cidr::parse(cidr).is_err(), "{cidr}");
    }
    assert!(
        Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("255.255.255.255".parse().unwrap())
    );
    assert!(
        !Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("::ffff:20.114.5.117".parse().unwrap())
    );
    assert!(
        Cidr::parse("::/0")
            .unwrap()
            .contains("ffff::".parse().unwrap())
    );
}

#[test]
fn owner_grant_rejects_authentic_keys_outside_every_scope() {
    let key = key();
    let action = action(&key);
    let owner = grant(&action);
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    for bad in [
        {
            let mut g = owner.clone();
            g.revoked = true;
            g
        },
        {
            let mut g = owner.clone();
            g.valid_until = NOW;
            g
        },
        {
            let mut g = owner.clone();
            g.valid_from = NOW + 1;
            g
        },
        {
            let mut g = owner.clone();
            g.subject_spki_sha256 = "00".repeat(32);
            g
        },
        {
            let mut g = owner.clone();
            g.mailbox_domains.clear();
            g
        },
        {
            let mut g = owner.clone();
            g.service_hosts = vec!["other.agent.hosting.".into()];
            g
        },
        {
            let mut g = owner.clone();
            g.roles = vec!["rogue-role".into()];
            g
        },
        {
            let mut g = owner.clone();
            g.address_cidrs = vec!["10.0.0.0/8".into()];
            g
        },
        {
            let mut g = owner.clone();
            g.ports = vec![25, 465];
            g
        },
        {
            let mut g = owner.clone();
            g.allowed_operations = vec![Operation::Renew];
            g
        },
        {
            let mut g = owner;
            g.max_lease_seconds = 100;
            g
        },
    ] {
        assert!(authorize_action(&action, &bad, AUDIENCE, NOW).is_err());
    }
}

#[test]
fn lifecycle_and_acme_target_ownership_and_lease_bounds() {
    let key = key();
    let mut action = action(&key);
    let owner = grant(&action);
    action.parameters = ActionParameters::Renew(RenewParameters {
        registration_id: "reg-1".into(),
        requested_lease_seconds: 86400,
        evidence_profile: None,
        evidence_digest: None,
    });
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    authorize_registration_target(
        &action,
        &owner.grant_id,
        &owner.subject_spki_sha256,
        &action.zone,
    )
    .unwrap();
    assert!(
        authorize_registration_target(
            &action,
            "other-grant",
            &owner.subject_spki_sha256,
            &action.zone
        )
        .is_err()
    );
    assert!(
        authorize_registration_target(&action, &owner.grant_id, &"00".repeat(32), &action.zone)
            .is_err()
    );
    assert_eq!(
        bounded_lease_expiration(NOW, 86400, NOW + 300, NOW + 200, NOW + 100).unwrap(),
        NOW + 100
    );
    assert!(bounded_lease_expiration(NOW, 86400, NOW + 300, NOW + 200, NOW).is_err());
    action.parameters = ActionParameters::AcmeChallengeCreate(AcmeChallengeCreateParameters {
        registration_id: "reg-1".into(),
        order_id: "order-1".into(),
        name: "mail.agent.hosting.".into(),
        txt_value: encode_base64url(&[1; 32]),
        ttl: 60,
        lifetime_seconds: 1800,
    });
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    authorize_acme_registration_target(&action, &action.zone, "mail.agent.hosting.", true).unwrap();
    assert!(
        authorize_acme_registration_target(&action, &action.zone, "other.agent.hosting.", true)
            .is_err()
    );
    assert!(
        authorize_acme_registration_target(&action, &action.zone, "mail.agent.hosting.", false)
            .is_err()
    );
    action.parameters = ActionParameters::AcmeChallengeDelete(AcmeChallengeDeleteParameters {
        challenge_id: "challenge-1".into(),
    });
    authorize_challenge_target(&action, &owner.grant_id, &action.zone).unwrap();
    assert!(authorize_challenge_target(&action, "other-issuer", &action.zone).is_err());
}

#[test]
fn operator_and_withdrawal_schemas_are_narrow_and_round_trip() {
    let key = key();
    let mut action = action(&key);
    let owner = grant(&action);
    action.parameters = ActionParameters::Deregister(DeregisterParameters {
        registration_id: "reg-1".into(),
        selected_ports: vec![25],
        withdraw_all: false,
        reason: "key_rotation".into(),
    });
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    if let ActionParameters::Deregister(p) = &mut action.parameters {
        p.withdraw_all = true;
    }
    assert!(action.validate().is_err());
    if let ActionParameters::Deregister(p) = &mut action.parameters {
        p.selected_ports.clear();
    }
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    action.parameters = ActionParameters::OperatorRecords(OperatorParameters {
        expected_serial: 7,
        mutations: vec![RecordMutation {
            action: MutationAction::Replace,
            name: "_dmarc.agent.hosting.".into(),
            record_type: OperatorRecordType::Txt,
            ttl: 3600,
            rdata_strings: vec!["v=DMARC1; p=reject".into()],
        }],
    });
    let (request, nonce) = signed(&key, action.clone());
    let bytes = serde_json::to_vec(&request).unwrap();
    let parsed = parse_signed_request(&bytes).unwrap();
    verify_signed_request(&parsed, &nonce, &owner, AUDIENCE, NOW).unwrap();
    if let ActionParameters::OperatorRecords(p) = &mut action.parameters {
        p.mutations[0].record_type = OperatorRecordType::A;
    }
    assert!(authorize_action(&action, &owner, AUDIENCE, NOW).is_err());
    if let ActionParameters::OperatorRecords(p) = &mut action.parameters {
        p.mutations[0].name = "evil.example.".into();
    }
    assert!(action.validate().is_err());
}

#[test]
fn renewal_rechecks_scope_without_requiring_register_permission() {
    let key = key();
    let mut action = action(&key);
    let mut owner = grant(&action);
    let ActionParameters::Register(original) = action.parameters.clone() else {
        panic!()
    };
    owner.allowed_operations = vec![Operation::Renew];
    action.parameters = ActionParameters::Renew(RenewParameters {
        registration_id: "reg-1".into(),
        requested_lease_seconds: 120,
        evidence_profile: None,
        evidence_digest: None,
    });
    owner.max_lease_seconds = 120;
    authorize_action(&action, &owner, AUDIENCE, NOW).unwrap();
    authorize_registration_scope(&original, &owner).unwrap();
    owner.roles = vec!["changed-role".into()];
    assert!(authorize_registration_scope(&original, &owner).is_err());
}
