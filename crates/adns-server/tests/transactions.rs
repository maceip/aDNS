use adns_auth::*;
use adns_server::Result;
use adns_server::*;
use adns_storage::*;
use adns_wire::*;
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::json;
fn setup() -> (MemoryStorage, signature::EcdsaKeyPair, OwnerGrant) {
    setup_with_base(Vec::new())
}
fn setup_with_base(
    extra_records: Vec<ResourceRecord>,
) -> (MemoryStorage, signature::EcdsaKeyPair, OwnerGrant) {
    let db = MemoryStorage::default();
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    let signer = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let grant = OwnerGrant {
        grant_id: "owner".into(),
        subject_spki_sha256: sha256_hex(&spki(&signer)),
        zones: vec!["example.".into()],
        mailbox_domains: vec!["example.".into()],
        service_hosts: vec!["mail.example.".into()],
        roles: vec!["mx-edge".into()],
        address_cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
        ports: vec![25, 465, 993],
        allowed_operations: vec![
            Operation::Register,
            Operation::Renew,
            Operation::Deregister,
            Operation::AcmeChallengeCreate,
            Operation::AcmeChallengeDelete,
            Operation::OperatorRecords,
            Operation::Anchor,
        ],
        acme_names: vec!["mail.example.".into()],
        operator_names: vec!["example.".into()],
        operator_record_types: vec![OperatorRecordType::Txt],
        attested_names: vec![
            "cvm1._domainkey.example.".into(),
            "_receipt.mail.example.".into(),
        ],
        attested_record_types: vec![AttestedRecordType::Txt],
        max_lease_seconds: 86400,
        max_challenge_lifetime_seconds: 1800,
        valid_from: 0,
        valid_until: 100000,
        revoked: false,
    };
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &ServiceConfiguration {
            audience: "ccf://test".into(),
            epoch: 1,
            last_time: 1000,
        },
    )
    .unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
    initialize_zone(
        &mut tx,
        ZoneMetadata {
            id: ZoneId(1),
            origin: "example.".parse().unwrap(),
            serial: 1,
            base_records: [
                vec![
                    ResourceRecord::new(
                        "example.".parse().unwrap(),
                        300,
                        RData::Soa(SoaData {
                            mname: "ns.example.".parse().unwrap(),
                            rname: "hostmaster.example.".parse().unwrap(),
                            serial: 1,
                            refresh: 60,
                            retry: 30,
                            expire: 3600,
                            minimum: 60,
                        }),
                    )
                    .unwrap(),
                    ResourceRecord::new(
                        "example.".parse().unwrap(),
                        300,
                        RData::Ns("ns.example.".parse().unwrap()),
                    )
                    .unwrap(),
                    ResourceRecord::new(
                        "ns.example.".parse().unwrap(),
                        300,
                        RData::A("192.0.2.53".parse().unwrap()),
                    )
                    .unwrap(),
                ],
                extra_records,
            ]
            .concat(),
            signed_records: vec![],
            signature_validity: 900,
            refresh_before: 300,
            last_signed_at: 0,
            earliest_signature_expiration: 0,
            maintenance_health: String::new(),
            ksk_dnskey_rdata: vec![],
            ksk_rollover: None,
        },
        1000,
    )
    .unwrap();
    tx.commit().unwrap();
    (db, signer, grant)
}
fn spki(s: &signature::EcdsaKeyPair) -> Vec<u8> {
    let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
    der.extend(s.public_key().as_ref());
    der
}
fn action(s: &signature::EcdsaKeyPair, id: &str, parameters: ActionParameters) -> Action {
    Action {
        request_id: id.into(),
        audience: "ccf://test".into(),
        grant_id: "owner".into(),
        zone: "example.".into(),
        signer_spki_der: encode_base64url(&spki(s)),
        parameters,
    }
}
fn envelope(
    db: &MemoryStorage,
    s: &signature::EcdsaKeyPair,
    action: Action,
    now: u64,
) -> SignedRequest {
    let mut tx = db.write().unwrap();
    let result = mutate(
        &mut tx,
        "POST",
        "/service/nonce",
        &serde_json::to_vec(&json!({"action":action})).unwrap(),
        now,
    )
    .unwrap();
    tx.commit().unwrap();
    let nonce: NonceResponse = serde_json::from_value(result.body).unwrap();
    let mut request = SignedRequest {
        action,
        nonce: nonce.nonce,
        nonce_expires_at: nonce.expires_at,
        intent_hash: nonce.intent_hash,
        client_signature: String::new(),
        evidence_payload: None,
    };
    request.client_signature = encode_base64url(
        s.sign(&SystemRandom::new(), &request.signed_message().unwrap())
            .unwrap()
            .as_ref(),
    );
    request
}
fn operator(s: &signature::EcdsaKeyPair, id: &str, serial: u32) -> Action {
    action(
        s,
        id,
        ActionParameters::OperatorRecords(OperatorParameters {
            expected_serial: serial,
            mutations: vec![RecordMutation {
                action: MutationAction::Replace,
                name: "example.".into(),
                record_type: OperatorRecordType::Txt,
                ttl: 300,
                rdata_strings: vec!["v=spf1 -all".into()],
            }],
        }),
    )
}
fn verify_published_rrsets(metadata: &ZoneMetadata, now: u32) {
    for rr in &metadata.signed_records {
        let RData::Rrsig(signature) = &rr.rdata else {
            continue;
        };
        let records: Vec<_> = metadata
            .signed_records
            .iter()
            .filter(|r| r.name == rr.name && r.rtype == signature.type_covered)
            .cloned()
            .collect();
        let key = metadata
            .signed_records
            .iter()
            .find_map(|r| {
                let RData::Dnskey(key) = &r.rdata else {
                    return None;
                };
                (adns_dnssec::key_tag(&r.rdata.to_wire().unwrap()) == signature.key_tag)
                    .then_some(key)
            })
            .unwrap();
        adns_dnssec::verify_rrset(&records, signature, key, now).unwrap();
    }
}
#[test]
fn base_and_operator_txt_share_minimum_ttl_without_losing_ownership() {
    for (base_ttl, operator_ttl) in [(60, 300), (300, 60)] {
        let origin: WireName = "example.".parse().unwrap();
        let base = ResourceRecord::new(origin, base_ttl, RData::Txt(vec![b"base-policy".to_vec()]))
            .unwrap();
        let (db, signer, _) = setup_with_base(vec![base.clone()]);
        let mut action = operator(&signer, "mixed-ttl", 1);
        let ActionParameters::OperatorRecords(parameters) = &mut action.parameters else {
            unreachable!()
        };
        parameters.mutations[0].ttl = operator_ttl;
        parameters.mutations[0].rdata_strings = vec!["base-policy".into(), "v=spf1 -all".into()];
        let request = envelope(&db, &signer, action, 1000);
        let mut tx = db.write().unwrap();
        mutate(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&request).unwrap(),
            1001,
        )
        .unwrap();
        tx.commit().unwrap();
        let read = db.read().unwrap();
        let metadata = zone_metadata(&read, &origin).unwrap();
        let published: Vec<_> = metadata
            .signed_records
            .iter()
            .filter(|r| r.name == origin && r.rtype == RecordType::Txt)
            .collect();
        assert_eq!(
            published.len(),
            2,
            "duplicate base/operator RDATA is published only once"
        );
        assert!(
            published
                .iter()
                .all(|r| r.ttl == base_ttl.min(operator_ttl))
        );
        assert!(metadata.signed_records.iter().any(|r| matches!(&r.rdata,
            RData::Rrsig(signature) if r.name == origin && signature.type_covered == RecordType::Txt
                && signature.original_ttl == base_ttl.min(operator_ttl))));
        assert!(
            metadata
                .signed_records
                .iter()
                .filter(|r| r.rtype == RecordType::Ns)
                .all(|r| r.ttl == 300)
        );
        verify_published_rrsets(&metadata, 1001);
        assert_eq!(
            metadata.base_records.last().unwrap(),
            &base,
            "governed input TTL stays intact"
        );
        let key = RecordKey {
            zone: origin,
            owner: origin,
            rtype: RecordType::Txt,
        }
        .encode();
        let owned: VersionedRrset = get_json(&read, Collection::Records, &key).unwrap().unwrap();
        assert_eq!(owned.contributions.len(), 2);
        assert!(owned.contributions.iter().all(
            |c| c.record.ttl == operator_ttl && c.contributor == "operator:owner:example.:Txt"
        ));
        drop(read);
        let mut action = operator(&signer, "remove-mixed-ttl", 2);
        let ActionParameters::OperatorRecords(parameters) = &mut action.parameters else {
            unreachable!()
        };
        parameters.mutations[0].action = MutationAction::Delete;
        parameters.mutations[0].rdata_strings.clear();
        let request = envelope(&db, &signer, action, 1002);
        let mut tx = db.write().unwrap();
        mutate(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&request).unwrap(),
            1003,
        )
        .unwrap();
        tx.commit().unwrap();
        let metadata = zone_metadata(&db.read().unwrap(), &origin).unwrap();
        let restored: Vec<_> = metadata
            .signed_records
            .iter()
            .filter(|r| r.name == origin && r.rtype == RecordType::Txt)
            .collect();
        assert_eq!(
            restored,
            vec![&base],
            "withdrawal reveals the original governed record and TTL"
        );
        verify_published_rrsets(&metadata, 1003);
    }
}
#[test]
fn complete_snapshot_deduplicates_case_canonical_base_records_after_ttl_normalization() {
    let origin: WireName = "example.".parse().unwrap();
    let alias: WireName = "alias.example.".parse().unwrap();
    let records = vec![
        ResourceRecord::new(origin, 60, RData::Ns("NS.EXAMPLE.".parse().unwrap())).unwrap(),
        ResourceRecord::new(alias, 600, RData::Cname("TARGET.EXAMPLE.".parse().unwrap())).unwrap(),
        ResourceRecord::new(alias, 60, RData::Cname("target.example.".parse().unwrap())).unwrap(),
    ];
    let (db, _, _) = setup_with_base(records.clone());
    let metadata = zone_metadata(&db.read().unwrap(), &origin).unwrap();
    assert_eq!(&metadata.base_records[3..], &records);
    let ns: Vec<_> = metadata
        .signed_records
        .iter()
        .filter(|r| r.rtype == RecordType::Ns)
        .collect();
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0].ttl, 60);
    let cname: Vec<_> = metadata
        .signed_records
        .iter()
        .filter(|r| r.rtype == RecordType::Cname)
        .collect();
    assert_eq!(cname.len(), 1);
    assert_eq!(cname[0], &records[2]);
    verify_published_rrsets(&metadata, 1000);
}
#[test]
fn normalization_does_not_hide_base_cname_conflicts_or_consume_rejected_nonce() {
    for record_type in [OperatorRecordType::Txt, OperatorRecordType::Cname] {
        let origin: WireName = "example.".parse().unwrap();
        let alias: WireName = "alias.example.".parse().unwrap();
        let base = ResourceRecord::new(alias, 60, RData::Cname("target.example.".parse().unwrap()))
            .unwrap();
        let (db, signer, mut grant) = setup_with_base(vec![base]);
        grant.operator_names = vec![alias.to_string()];
        grant.operator_record_types = vec![record_type];
        let mut tx = db.write().unwrap();
        put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
        tx.commit().unwrap();
        let mut action = operator(&signer, "invalid-alias", 1);
        let ActionParameters::OperatorRecords(parameters) = &mut action.parameters else {
            unreachable!()
        };
        parameters.mutations[0].name = alias.to_string();
        parameters.mutations[0].record_type = record_type;
        parameters.mutations[0].rdata_strings = vec!["different.example.".into()];
        let request = envelope(&db, &signer, action, 1000);
        let mut tx = db.write().unwrap();
        assert!(matches!(
            mutate(
                &mut tx,
                "POST",
                "/zone/operator/records",
                &serde_json::to_vec(&request).unwrap(),
                1001
            ),
            Err(AppError::Dnssec(_))
        ));
        drop(tx);
        let read = db.read().unwrap();
        assert_eq!(zone_metadata(&read, &origin).unwrap().serial, 1);
        assert!(records(&read, &origin).unwrap().is_empty());
        assert!(
            get_json::<RequestResult>(
                &read,
                Collection::RequestResults,
                &request_key("owner", "invalid-alias")
            )
            .unwrap()
            .is_none()
        );
        assert!(
            !get_json::<NonceRecord>(&read, Collection::Nonces, &nonce_key(1, &request.nonce))
                .unwrap()
                .unwrap()
                .consumed
        );
    }
}
#[test]
fn signed_mutation_is_atomic_replayed_historically_and_conflict_does_not_consume_nonce() {
    let (db, s, _) = setup();
    let request = envelope(&db, &s, operator(&s, "request-1", 1), 1000);
    let body = serde_json::to_vec(&request).unwrap();
    let before = db.read().unwrap();
    let mut tx = db.write().unwrap();
    let result = mutate(&mut tx, "POST", "/zone/operator/records", &body, 1001).unwrap();
    assert_eq!(result.body["status"], "pending");
    assert_eq!(
        zone_metadata(&before, &"example.".parse().unwrap())
            .unwrap()
            .serial,
        1
    );
    let version = tx.commit().unwrap();
    let read = db.read().unwrap();
    assert!(
        read.get(Collection::Nonces, &nonce_key(1, &request.nonce))
            .unwrap()
            .is_none()
    );
    let stored = read
        .get(
            Collection::RequestResults,
            &request_key("owner", "request-1"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(version, stored.version);
    let mut tx = db.write().unwrap();
    let retry = mutate(&mut tx, "POST", "/zone/operator/records", &body, 10000).unwrap();
    assert_eq!(retry.body, result.body);
    assert_eq!(retry.original_version, Some(version));
    assert_eq!(tx.commit().unwrap(), version);
    let conflict = envelope(&db, &s, operator(&s, "request-1", 2), 10002);
    let mut tx = db.write().unwrap();
    assert!(matches!(
        mutate(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&conflict).unwrap(),
            10003
        ),
        Err(AppError::Auth(AuthError::RequestIdConflict))
    ));
    drop(tx);
    let n: NonceRecord = get_json(
        &db.read().unwrap(),
        Collection::Nonces,
        &nonce_key(1, &conflict.nonce),
    )
    .unwrap()
    .unwrap();
    assert!(!n.consumed);
}
#[test]
fn failed_dns_write_rolls_back_nonce_records_and_serial() {
    let (db, s, _) = setup();
    let req = envelope(&db, &s, operator(&s, "wrong-serial", 999), 1000);
    let mut tx = db.write().unwrap();
    assert!(
        mutate(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&req).unwrap(),
            1001
        )
        .is_err()
    );
    drop(tx);
    let read = db.read().unwrap();
    assert_eq!(
        zone_metadata(&read, &"example.".parse().unwrap())
            .unwrap()
            .serial,
        1
    );
    let nonce: NonceRecord = get_json(&read, Collection::Nonces, &nonce_key(1, &req.nonce))
        .unwrap()
        .unwrap();
    assert!(!nonce.consumed);
}
fn params() -> RegisterParameters {
    RegisterParameters {
        role: "mx-edge".into(),
        mailbox_domain: "example.".into(),
        service_host: "mail.example.".into(),
        addresses: Addresses {
            ipv4: vec!["192.0.2.1".into()],
            ipv6: vec!["2001:db8::1".into()],
        },
        ports: vec![25, 465, 993],
        lease_seconds: 10000,
        evidence_profile: "azure-aci-snp".into(),
        evidence_digest: "01".repeat(32),
        attested_records: Vec::new(),
    }
}
#[test]
fn rotation_and_challenge_contributions_do_not_delete_other_owners() {
    let (db, _, _) = setup();
    let mut tx = db.write().unwrap();
    let zone = "example.".parse().unwrap();
    for (id, digest) in [("old", "01".repeat(32)), ("new", "02".repeat(32))] {
        for rr in mail_contributions(&params(), &digest).unwrap() {
            add_contribution(&mut tx, &zone, id, rr).unwrap();
        }
    }
    let before = records(&tx, &zone).unwrap();
    assert_eq!(
        before
            .iter()
            .filter(|r| r.rtype == RecordType::Tlsa)
            .count(),
        6
    );
    remove_contributions(
        &mut tx,
        &zone,
        "old",
        Some(&["_25._tcp.mail.example.".parse().unwrap()]),
    )
    .unwrap();
    assert_eq!(
        records(&tx, &zone)
            .unwrap()
            .iter()
            .filter(|r| r.rtype == RecordType::Tlsa)
            .count(),
        5
    );
    remove_contributions(&mut tx, &zone, "old", None).unwrap();
    assert_eq!(
        records(&tx, &zone)
            .unwrap()
            .iter()
            .filter(|r| r.rtype == RecordType::Tlsa)
            .count(),
        3
    );
    for (id, value) in [("chal-1", "a"), ("chal-2", "b")] {
        add_contribution(
            &mut tx,
            &zone,
            id,
            ResourceRecord::new(
                "_acme-challenge.mail.example.".parse().unwrap(),
                60,
                RData::Txt(vec![value.as_bytes().to_vec()]),
            )
            .unwrap(),
        )
        .unwrap();
    }
    remove_contributions(&mut tx, &zone, "chal-1", None).unwrap();
    let remain = records(&tx, &zone).unwrap();
    assert!(
        remain
            .iter()
            .any(|r| r.rdata == RData::Txt(vec![b"b".to_vec()]))
    );
    assert!(
        !remain
            .iter()
            .any(|r| r.rdata == RData::Txt(vec![b"a".to_vec()]))
    );
}
#[test]
fn idle_maintenance_refreshes_and_sealed_recovery_keeps_signing_keys() {
    let (db, _, _) = setup();
    let old = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    let mut tx = db.write().unwrap();
    assert!(maintenance(&mut tx, 1599).unwrap().is_empty());
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    assert_eq!(maintenance(&mut tx, 1600).unwrap(), vec!["example."]);
    tx.commit().unwrap();
    let refreshed = zone_metadata(&db.read().unwrap(), &old.origin).unwrap();
    assert_eq!(refreshed.serial, 2);
    assert!(refreshed.earliest_signature_expiration > old.earliest_signature_expiration);
    let restored = MemoryStorage::restore(&db.seal(&[1; 32]).unwrap(), &[1; 32]).unwrap();
    let mut tx = restored.write().unwrap();
    assert_eq!(maintenance(&mut tx, 2200).unwrap(), vec!["example."]);
    tx.commit().unwrap();
    assert_eq!(
        zone_metadata(&restored.read().unwrap(), &old.origin)
            .unwrap()
            .ksk_dnskey_rdata,
        old.ksk_dnskey_rdata
    );
}
#[test]
fn ksk_claims_bind_owner_and_full_rdata() {
    let (db, _, _) = setup();
    let zone = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    let digest = ksk_claims_digest(&zone.origin, &zone.ksk_dnskey_rdata);
    assert_ne!(
        digest,
        ksk_claims_digest(&"other.".parse().unwrap(), &zone.ksk_dnskey_rdata)
    );
    let mut altered = zone.ksk_dnskey_rdata;
    altered[1] ^= 1;
    assert_ne!(digest, ksk_claims_digest(&zone.origin, &altered));
}

fn seed_registration(db: &MemoryStorage, grant: &OwnerGrant) -> Registration {
    let mut tx = db.write().unwrap();
    let origin = "example.".parse().unwrap();
    let p = params();
    let policy = adns_attest::AppraisalPolicy {
        policy_id: [1; 32],
        release_id: "approved-fixture-state".into(),
        active_profiles: ["azure-aci-snp".into()].into(),
        valid_from: 0,
        valid_until: 2000,
        max_appraisal_lifetime: 1000,
        ..Default::default()
    };
    put_json(&mut tx, Collection::Policies, origin_wire(), &policy).unwrap();
    let r = Registration {
        registration_id: "seeded-registration".into(),
        grant_id: grant.grant_id.clone(),
        zone: "example.".into(),
        signer_spki_sha256: grant.subject_spki_sha256.clone(),
        parameters: p.clone(),
        admitted_at: 1000,
        lease_expires_at: 1400,
        policy_valid_until: 2000,
        reappraisal_deadline: 1500,
        policy_id: "01".repeat(32),
        evidence_digest: p.evidence_digest.clone(),
        status: "active".into(),
        active_ports: p.ports.clone(),
    };
    for record in mail_contributions(&p, &grant.subject_spki_sha256).unwrap() {
        add_contribution(&mut tx, &origin, &r.registration_id, record).unwrap();
    }
    put_json(
        &mut tx,
        Collection::Registrations,
        r.registration_id.as_bytes().to_vec(),
        &r,
    )
    .unwrap();
    index_active_registration(&mut tx, &r.registration_id).unwrap();
    resign_zone(&mut tx, &origin, 1000, true).unwrap();
    tx.commit().unwrap();
    r
}
fn origin_wire() -> Vec<u8> {
    "example.".parse::<WireName>().unwrap().as_slice().to_vec()
}
#[test]
fn renewal_keeps_signatures_and_honors_all_validity_bounds() {
    let (db, s, g) = setup();
    let seeded = seed_registration(&db, &g);
    let before = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    let req = envelope(
        &db,
        &s,
        action(
            &s,
            "renew-1",
            ActionParameters::Renew(RenewParameters {
                registration_id: seeded.registration_id,
                requested_lease_seconds: 1000,
                evidence_profile: None,
                evidence_digest: None,
            }),
        ),
        1100,
    );
    let mut tx = db.write().unwrap();
    let outcome = mutate(
        &mut tx,
        "POST",
        "/service/renew",
        &serde_json::to_vec(&req).unwrap(),
        1101,
    )
    .unwrap();
    assert_eq!(outcome.body["lease_expires_at"], 1500);
    assert!(outcome.changed_zones.is_empty());
    tx.commit().unwrap();
    let after = zone_metadata(&db.read().unwrap(), &before.origin).unwrap();
    assert_eq!(before.signed_records, after.signed_records);
    assert_eq!(before.serial, after.serial);
    let mut tx = db.write().unwrap();
    maintenance(&mut tx, 1500).unwrap();
    tx.commit().unwrap();
    let remaining = records(&db.read().unwrap(), &before.origin).unwrap();
    assert!(remaining.is_empty());
}
#[test]
fn signed_challenge_orders_coexist_delete_individually_and_expire() {
    let (db, s, g) = setup();
    let registration = seed_registration(&db, &g);
    let mut ids = vec![];
    for i in 0..2 {
        let req = envelope(
            &db,
            &s,
            action(
                &s,
                &format!("order-{i}"),
                ActionParameters::AcmeChallengeCreate(AcmeChallengeCreateParameters {
                    registration_id: registration.registration_id.clone(),
                    order_id: format!("order-{i}"),
                    name: "mail.example.".into(),
                    txt_value: encode_base64url(&[i; 32]),
                    ttl: 60,
                    lifetime_seconds: 180,
                }),
            ),
            1100 + i as u64,
        );
        let mut tx = db.write().unwrap();
        let outcome = mutate(
            &mut tx,
            "POST",
            "/zone/acme-challenge",
            &serde_json::to_vec(&req).unwrap(),
            1101 + i as u64,
        )
        .unwrap();
        ids.push(outcome.body["challenge_id"].as_str().unwrap().to_owned());
        tx.commit().unwrap();
    }
    let origin = "example.".parse().unwrap();
    assert_eq!(
        records(&db.read().unwrap(), &origin)
            .unwrap()
            .iter()
            .filter(|r| r.rtype == RecordType::Txt)
            .count(),
        2
    );
    let req = envelope(
        &db,
        &s,
        action(
            &s,
            "delete-1",
            ActionParameters::AcmeChallengeDelete(AcmeChallengeDeleteParameters {
                challenge_id: ids[0].clone(),
            }),
        ),
        1103,
    );
    let mut tx = db.write().unwrap();
    mutate(
        &mut tx,
        "DELETE",
        "/zone/acme-challenge",
        &serde_json::to_vec(&req).unwrap(),
        1104,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        records(&db.read().unwrap(), &origin)
            .unwrap()
            .iter()
            .filter(|r| r.rtype == RecordType::Txt)
            .count(),
        1
    );
    let mut tx = db.write().unwrap();
    maintenance(&mut tx, 1282).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        records(&db.read().unwrap(), &origin)
            .unwrap()
            .iter()
            .filter(|r| r.rtype == RecordType::Txt)
            .count(),
        0
    );
}
#[test]
fn revoked_grants_are_withdrawn_by_idle_maintenance() {
    let (db, _, mut g) = setup();
    seed_registration(&db, &g);
    g.revoked = true;
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &g).unwrap();
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    assert_eq!(maintenance(&mut tx, 1100).unwrap(), vec!["example."]);
    tx.commit().unwrap();
    assert!(
        records(&db.read().unwrap(), &"example.".parse().unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn renewal_duration_is_measured_from_admission_and_cannot_end_in_the_past() {
    let (db, signer, grant) = setup();
    let registration = seed_registration(&db, &grant);
    for (id, duration, should_pass) in [("bounded-renew", 200, true), ("past-renew", 50, false)] {
        let request = envelope(
            &db,
            &signer,
            action(
                &signer,
                id,
                ActionParameters::Renew(RenewParameters {
                    registration_id: registration.registration_id.clone(),
                    requested_lease_seconds: duration,
                    evidence_profile: None,
                    evidence_digest: None,
                }),
            ),
            1102,
        );
        let mut tx = db.write().unwrap();
        let result = mutate(
            &mut tx,
            "POST",
            "/service/renew",
            &serde_json::to_vec(&request).unwrap(),
            1102,
        );
        if should_pass {
            assert_eq!(result.unwrap().body["lease_expires_at"], 1200);
            tx.commit().unwrap();
        } else {
            assert!(result.is_err());
        }
    }
    let response = read_json(
        &db.read().unwrap(),
        "/service/registration",
        &[("registration_id".into(), registration.registration_id)],
        1102,
    )
    .unwrap();
    assert_eq!(
        response.body["active_contributions"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
}

#[test]
fn issuer_cannot_use_revoked_registration_before_maintenance_runs() {
    let (db, signer, mut owner) = setup();
    let registration = seed_registration(&db, &owner);
    let mut issuer = owner.clone();
    issuer.grant_id = "issuer".into();
    owner.revoked = true;
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &owner).unwrap();
    put_json(&mut tx, Collection::Grants, b"issuer".to_vec(), &issuer).unwrap();
    tx.commit().unwrap();
    let mut action = action(
        &signer,
        "issuer-revoked-registration",
        ActionParameters::AcmeChallengeCreate(AcmeChallengeCreateParameters {
            registration_id: registration.registration_id,
            order_id: "order".into(),
            name: "mail.example.".into(),
            txt_value: encode_base64url(&[1; 32]),
            ttl: 60,
            lifetime_seconds: 180,
        }),
    );
    action.grant_id = "issuer".into();
    let request = envelope(&db, &signer, action, 1100);
    let mut tx = db.write().unwrap();
    assert!(
        mutate(
            &mut tx,
            "POST",
            "/zone/acme-challenge",
            &serde_json::to_vec(&request).unwrap(),
            1101
        )
        .is_err()
    );
    assert!(
        tx.scan_prefix(Collection::AcmeChallenges, b"")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn registration_reads_distinguish_current_eligibility_from_pending_withdrawal() {
    for revoke in [false, true] {
        let (db, _, mut grant) = setup();
        let r = seed_registration(&db, &grant);
        if revoke {
            grant.revoked = true;
            let mut tx = db.write().unwrap();
            put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
            tx.commit().unwrap();
        }
        let now = if revoke { 1100 } else { r.lease_expires_at };
        let read = db.read().unwrap();
        let version = read.revision();
        let response = read_json(
            &read,
            "/service/registration",
            &[("registration_id".into(), r.registration_id.clone())],
            now,
        )
        .unwrap();
        assert_eq!(
            response.body["status"],
            if revoke { "withdrawn" } else { "expired" }
        );
        assert_eq!(response.body["committed_status"], "active");
        assert_eq!(response.body["active_ports"], json!([]));
        assert_eq!(response.body["active_contributions"], json!([]));
        assert_eq!(
            response.body["committed_contributions"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            db.read().unwrap().revision(),
            version,
            "a status read must not withdraw rows"
        );
        let stored: Registration = get_json(
            &read,
            Collection::Registrations,
            r.registration_id.as_bytes(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "active");
        let mut tx = db.write().unwrap();
        maintenance(&mut tx, now).unwrap();
        tx.commit().unwrap();
        let response = read_json(
            &db.read().unwrap(),
            "/service/registration",
            &[("registration_id".into(), r.registration_id)],
            now,
        )
        .unwrap();
        assert_eq!(response.body["committed_status"], response.body["status"]);
        assert_eq!(response.body["committed_contributions"], json!([]));
    }
}

#[test]
fn challenge_maintenance_rechecks_tightened_issuer_scope() {
    for case in [
        "name",
        "operation",
        "future",
        "zone",
        "key",
        "expiry",
        "revoked",
    ] {
        let (db, signer, owner) = setup();
        let registration = seed_registration(&db, &owner);
        let mut issuer = owner.clone();
        issuer.grant_id = "issuer".into();
        let mut tx = db.write().unwrap();
        put_json(&mut tx, Collection::Grants, b"issuer".to_vec(), &issuer).unwrap();
        tx.commit().unwrap();
        let mut request_action = action(
            &signer,
            "issuer-challenge",
            ActionParameters::AcmeChallengeCreate(AcmeChallengeCreateParameters {
                registration_id: registration.registration_id.clone(),
                order_id: "order".into(),
                name: "mail.example.".into(),
                txt_value: encode_base64url(&[1; 32]),
                ttl: 60,
                lifetime_seconds: 180,
            }),
        );
        request_action.grant_id = issuer.grant_id.clone();
        let request = envelope(&db, &signer, request_action, 1100);
        let mut tx = db.write().unwrap();
        mutate(
            &mut tx,
            "POST",
            "/zone/acme-challenge",
            &serde_json::to_vec(&request).unwrap(),
            1101,
        )
        .unwrap();
        tx.commit().unwrap();
        match case {
            "name" => issuer.acme_names.clear(),
            "operation" => issuer
                .allowed_operations
                .retain(|op| *op != Operation::AcmeChallengeCreate),
            "future" => issuer.valid_from = 1200,
            "zone" => {
                issuer.zones = vec!["elsewhere.".into()];
                issuer.mailbox_domains.clear();
                issuer.service_hosts.clear();
                issuer.acme_names.clear();
                issuer.operator_names.clear();
                issuer.attested_names.clear();
            }
            "key" => issuer.subject_spki_sha256 = "ab".repeat(32),
            "expiry" => issuer.valid_until = 1102,
            "revoked" => issuer.revoked = true,
            _ => unreachable!(),
        }
        issuer.validate().unwrap();
        let mut tx = db.write().unwrap();
        put_json(&mut tx, Collection::Grants, b"issuer".to_vec(), &issuer).unwrap();
        tx.commit().unwrap();
        let mut tx = db.write().unwrap();
        assert_eq!(
            maintenance(&mut tx, 1102).unwrap(),
            vec!["example."],
            "{case}"
        );
        tx.commit().unwrap();
        let read = db.read().unwrap();
        assert!(
            read.scan_prefix(Collection::AcmeChallenges, b"")
                .unwrap()
                .is_empty(),
            "{case}"
        );
        let records = records(&read, &"example.".parse().unwrap()).unwrap();
        assert_eq!(
            records.len(),
            6,
            "issuer change must preserve the separate owner's registration: {case}"
        );
        assert!(
            records.iter().all(|rr| rr.rtype != RecordType::Txt),
            "{case}"
        );
        let stored: Registration = get_json(
            &read,
            Collection::Registrations,
            registration.registration_id.as_bytes(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "active", "{case}");
    }
}

#[test]
fn live_nonce_quota_is_freed_by_success_and_expiry() {
    let (db, signer, _) = setup();
    let mut issued = Vec::new();
    for i in 0..MAX_GRANT_NONCES {
        issued.push(envelope(
            &db,
            &signer,
            operator(&signer, &format!("quota-{i}"), 1),
            1000,
        ));
    }
    let issue = |tx: &mut MemoryWrite, now| {
        mutate(
            tx,
            "POST",
            "/service/nonce",
            &serde_json::to_vec(&json!({"action":operator(&signer, "quota-extra", 2)})).unwrap(),
            now,
        )
    };
    let mut tx = db.write().unwrap();
    assert!(matches!(issue(&mut tx, 1001), Err(AppError::Capacity(_))));
    drop(tx);
    assert_eq!(
        db.read()
            .unwrap()
            .scan_prefix(Collection::Nonces, b"")
            .unwrap()
            .len(),
        MAX_GRANT_NONCES
    );
    let mut tx = db.write().unwrap();
    mutate(
        &mut tx,
        "POST",
        "/zone/operator/records",
        &serde_json::to_vec(&issued[0]).unwrap(),
        1001,
    )
    .unwrap();
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    issue(&mut tx, 1002).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        db.read()
            .unwrap()
            .scan_prefix(Collection::Nonces, b"")
            .unwrap()
            .len(),
        MAX_GRANT_NONCES
    );
    let mut tx = db.write().unwrap();
    issue(&mut tx, 1302).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        db.read()
            .unwrap()
            .scan_prefix(Collection::Nonces, b"")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn global_nonce_quota_and_challenge_capacity_fail_without_partial_mutation() {
    let (db, signer, grant) = setup();
    let registration = seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    for i in 0..MAX_OUTSTANDING_NONCES {
        let nonce = NonceRecord {
            nonce: format!("{i:064x}"),
            intent_hash: "01".repeat(32),
            grant_id: format!("other-{}", i / MAX_GRANT_NONCES),
            request_id: format!("nonce-{i}"),
            issued_at: 1000,
            expires_at: 1300,
            consumed: false,
        };
        put_json(
            &mut tx,
            Collection::Nonces,
            nonce_key(1, &nonce.nonce),
            &nonce,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    let result = mutate(
        &mut tx,
        "POST",
        "/service/nonce",
        &serde_json::to_vec(&json!({"action":operator(&signer, "global-extra", 2)})).unwrap(),
        1001,
    );
    assert_eq!(result.unwrap_err().http_status(), 413);
    drop(tx);
    let req = envelope(
        &db,
        &signer,
        action(
            &signer,
            "challenge-cap",
            ActionParameters::AcmeChallengeCreate(AcmeChallengeCreateParameters {
                registration_id: registration.registration_id.clone(),
                order_id: "order".into(),
                name: "mail.example.".into(),
                txt_value: encode_base64url(&[7; 32]),
                ttl: 60,
                lifetime_seconds: 60,
            }),
        ),
        1300,
    );
    let mut tx = db.write().unwrap();
    for i in 0..MAX_ACME_CHALLENGES {
        let challenge = AcmeChallenge {
            challenge_id: format!("seed-{i}"),
            grant_id: "owner".into(),
            registration_id: registration.registration_id.clone(),
            order_id: format!("order-{i}"),
            zone: "example.".into(),
            name: "mail.example.".into(),
            txt_value: "x".into(),
            ttl: 60,
            expires_at: 1400,
            signer_spki_sha256: grant.subject_spki_sha256.clone(),
        };
        put_json(
            &mut tx,
            Collection::AcmeChallenges,
            challenge.challenge_id.as_bytes().to_vec(),
            &challenge,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let before = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    let mut tx = db.write().unwrap();
    assert!(matches!(
        mutate(
            &mut tx,
            "POST",
            "/zone/acme-challenge",
            &serde_json::to_vec(&req).unwrap(),
            1301
        ),
        Err(AppError::Capacity(_))
    ));
    drop(tx);
    let read = db.read().unwrap();
    assert!(
        read.get(Collection::Nonces, &nonce_key(1, &req.nonce))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        zone_metadata(&read, &before.origin).unwrap().signed_records,
        before.signed_records
    );
}

struct MaintenanceProbe {
    inner: MemoryWrite,
    record_scans: std::cell::Cell<usize>,
}
impl ReadTx for MaintenanceProbe {
    fn get(&self, table: Collection, key: &[u8]) -> adns_storage::Result<Option<VersionedValue>> {
        self.inner.get(table, key)
    }
    fn scan_prefix(&self, table: Collection, prefix: &[u8]) -> adns_storage::Result<Entries> {
        assert!(
            !matches!(
                table,
                Collection::Registrations | Collection::RequestResults
            ),
            "maintenance scanned unbounded history"
        );
        if table == Collection::Records {
            self.record_scans.set(self.record_scans.get() + 1);
        }
        self.inner.scan_prefix(table, prefix)
    }
}
impl WriteTx for MaintenanceProbe {
    fn put(&mut self, table: Collection, key: Vec<u8>, value: Vec<u8>) -> adns_storage::Result<()> {
        self.inner.put(table, key, value)
    }
    fn remove(&mut self, table: Collection, key: &[u8]) -> adns_storage::Result<()> {
        self.inner.remove(table, key)
    }
}

#[test]
fn maintenance_uses_active_index_and_batches_expiry_per_zone() {
    let (db, _, grant) = setup();
    let original = seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    for i in 1..MAX_ACTIVE_REGISTRATIONS {
        let mut r = original.clone();
        r.registration_id = format!("active-{i}");
        put_json(
            &mut tx,
            Collection::Registrations,
            r.registration_id.as_bytes().to_vec(),
            &r,
        )
        .unwrap();
        index_active_registration(&mut tx, &r.registration_id).unwrap();
    }
    for i in 0..2048 {
        let mut r = original.clone();
        r.registration_id = format!("historic-{i}");
        r.status = "withdrawn".into();
        put_json(
            &mut tx,
            Collection::Registrations,
            r.registration_id.as_bytes().to_vec(),
            &r,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let mut extra = original.clone();
    extra.registration_id = "too-many".into();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Registrations,
        extra.registration_id.as_bytes().to_vec(),
        &extra,
    )
    .unwrap();
    assert!(matches!(
        index_active_registration(&mut tx, &extra.registration_id),
        Err(AppError::Capacity(_))
    ));
    drop(tx);
    assert!(
        db.read()
            .unwrap()
            .get(Collection::Registrations, b"too-many")
            .unwrap()
            .is_none()
    );
    let mut probe = MaintenanceProbe {
        inner: db.write().unwrap(),
        record_scans: Default::default(),
    };
    assert_eq!(maintenance(&mut probe, 1500).unwrap(), vec!["example."]);
    // One removal scan and one signing read, independent of 1024 expirations.
    assert_eq!(probe.record_scans.get(), 2);
    probe.inner.commit().unwrap();
    let read = db.read().unwrap();
    assert!(
        read.scan_prefix(Collection::Lifecycle, ACTIVE_REGISTRATION_PREFIX)
            .unwrap()
            .is_empty()
    );
    let historical = read_json(
        &read,
        "/service/registration",
        &[("registration_id".into(), "historic-0".into())],
        1500,
    )
    .unwrap();
    assert_eq!(historical.body["status"], "withdrawn");
    let mut replacement = original;
    replacement.registration_id = "slot-reused".into();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Registrations,
        replacement.registration_id.as_bytes().to_vec(),
        &replacement,
    )
    .unwrap();
    index_active_registration(&mut tx, &replacement.registration_id).unwrap();
}

#[test]
fn legacy_or_inconsistent_active_indexes_fail_closed_after_recovery() {
    let (db, _, grant) = setup();
    let r = seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    tx.remove(Collection::Lifecycle, b"server/lifecycle-format")
        .unwrap();
    tx.commit().unwrap();
    let recovered = MemoryStorage::restore(&db.seal(&[9; 32]).unwrap(), &[9; 32]).unwrap();
    assert!(validate_lifecycle_format(&recovered.read().unwrap()).is_err());
    assert!(maintenance(&mut recovered.write().unwrap(), 1400).is_err());
    assert!(zone_metadata(&recovered.read().unwrap(), &"example.".parse().unwrap()).is_err());
    let (db, _, grant) = setup();
    seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    tx.remove(
        Collection::Lifecycle,
        &[ACTIVE_REGISTRATION_PREFIX, r.registration_id.as_bytes()].concat(),
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(maintenance(&mut db.write().unwrap(), 1400).is_err());
}

#[test]
fn contribution_limits_roll_back_partial_operator_mutations_and_release_quota() {
    let (db, signer, _) = setup();
    let origin = "example.".parse().unwrap();
    let mut tx = db.write().unwrap();
    for i in 0..MAX_RRSET_CONTRIBUTIONS - 1 {
        add_contribution(
            &mut tx,
            &origin,
            "fixture",
            ResourceRecord::new(
                origin,
                300,
                RData::Txt(vec![format!("value-{i}").into_bytes()]),
            )
            .unwrap(),
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let request = envelope(
        &db,
        &signer,
        action(
            &signer,
            "oversized-operator",
            ActionParameters::OperatorRecords(OperatorParameters {
                expected_serial: 1,
                mutations: vec![RecordMutation {
                    action: MutationAction::Add,
                    name: "example.".into(),
                    record_type: OperatorRecordType::Txt,
                    ttl: 300,
                    rdata_strings: vec!["fills-last-slot".into(), "exceeds-cap".into()],
                }],
            }),
        ),
        1000,
    );
    let mut tx = db.write().unwrap();
    assert!(matches!(
        mutate(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&request).unwrap(),
            1001
        ),
        Err(AppError::Capacity(_))
    ));
    drop(tx);
    assert!(
        db.read()
            .unwrap()
            .get(Collection::Nonces, &nonce_key(1, &request.nonce))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        records(&db.read().unwrap(), &origin).unwrap().len(),
        MAX_RRSET_CONTRIBUTIONS - 1
    );
    let mut tx = db.write().unwrap();
    remove_contributions(&mut tx, &origin, "fixture", None).unwrap();
    mutate(
        &mut tx,
        "POST",
        "/zone/operator/records",
        &serde_json::to_vec(&request).unwrap(),
        1002,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(records(&db.read().unwrap(), &origin).unwrap().len(), 2);
}

#[test]
fn zone_rrset_admission_counts_base_records_and_reuses_removed_slots() {
    let (db, _, _) = setup();
    let origin = "example.".parse().unwrap();
    let mut tx = db.write().unwrap();
    for i in 0..MAX_ZONE_RRSETS - 3 {
        add_contribution(
            &mut tx,
            &origin,
            "bulk",
            ResourceRecord::new(
                format!("bulk-{i}.example.").parse().unwrap(),
                300,
                RData::A("192.0.2.1".parse().unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
    }
    let extra = ResourceRecord::new(
        "extra.example.".parse().unwrap(),
        300,
        RData::A("192.0.2.2".parse().unwrap()),
    )
    .unwrap();
    assert!(matches!(
        add_contribution(&mut tx, &origin, "extra", extra.clone()),
        Err(AppError::Capacity(_))
    ));
    remove_contributions(
        &mut tx,
        &origin,
        "bulk",
        Some(&["bulk-0.example.".parse().unwrap()]),
    )
    .unwrap();
    add_contribution(&mut tx, &origin, "extra", extra).unwrap();
    assert_eq!(records(&tx, &origin).unwrap().len(), MAX_ZONE_RRSETS - 3);
}

#[test]
fn zone_and_initial_record_admission_caps_are_enforced() {
    let (db, _, _) = setup();
    let mut template = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    template.base_records = vec![template.base_records[0].clone(); MAX_BASE_RECORDS + 1];
    template.origin = "oversized.example.".parse().unwrap();
    for rr in &mut template.base_records {
        rr.name = template.origin;
    }
    let mut tx = db.write().unwrap();
    assert!(matches!(
        initialize_zone(&mut tx, template, 1000),
        Err(AppError::Capacity(_))
    ));
    drop(tx);
    let template = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    let mut tx = db.write().unwrap();
    for i in 1..MAX_ZONES {
        let mut metadata = template.clone();
        metadata.origin = format!("zone-{i}.example.").parse().unwrap();
        metadata.base_records = vec![
            ResourceRecord::new(
                metadata.origin,
                300,
                RData::Soa(SoaData {
                    mname: metadata.origin,
                    rname: metadata.origin,
                    serial: 1,
                    refresh: 60,
                    retry: 30,
                    expire: 3600,
                    minimum: 60,
                }),
            )
            .unwrap(),
            ResourceRecord::new(metadata.origin, 300, RData::Ns(metadata.origin)).unwrap(),
        ];
        initialize_zone(&mut tx, metadata, 1000).unwrap();
    }
    let mut extra = template;
    extra.origin = "excess.example.".parse().unwrap();
    for rr in &mut extra.base_records {
        rr.name = extra.origin;
    }
    assert!(matches!(
        initialize_zone(&mut tx, extra, 1000),
        Err(AppError::Capacity(_))
    ));
    assert_eq!(
        tx.scan_prefix(Collection::Zones, b"").unwrap().len(),
        MAX_ZONES
    );
}

fn reconcile_request(db: &MemoryStorage, id: &str, now: u64) -> Result<AppResponse> {
    read_json(
        &db.read().unwrap(),
        "/service/request",
        &[
            ("grant_id".into(), "owner".into()),
            ("request_id".into(), id.into()),
        ],
        now,
    )
}
fn attempt_rows(db: &MemoryStorage) -> Entries {
    db.read()
        .unwrap()
        .scan_prefix(
            Collection::Lifecycle,
            &composite_key(&[b"server/v1/request-attempt"]),
        )
        .unwrap()
}
#[test]
fn reconciliation_tracks_committed_nonce_failed_attempt_and_success_without_burning_nonce() {
    let (db, signer, mut grant) = setup();
    let action = operator(&signer, "observable", 1);
    let request = envelope(&db, &signer, action.clone(), 1000);
    let raw = serde_json::to_vec(&request).unwrap();
    let pending = reconcile_request(&db, "observable", 1000).unwrap();
    assert_eq!(pending.body["status"], "pending");
    assert_eq!(pending.body["phase"], "awaiting_committed_result");
    assert!(!pending.promote_status_on_commit);
    assert!(attempt_rows(&db).is_empty());
    grant.revoked = true;
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
    tx.commit().unwrap();
    let snapshot = db.read().unwrap();
    let mut tx = db.write().unwrap();
    let failure = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1001).unwrap();
    assert_eq!(failure.http_status, 403);
    assert!(failure.commit_error && !failure.promote_status_on_commit);
    assert!(failure.changed_zones.is_empty());
    assert!(
        snapshot
            .scan_prefix(
                Collection::Lifecycle,
                &composite_key(&[b"server/v1/request-attempt"])
            )
            .unwrap()
            .is_empty()
    );
    tx.commit().unwrap();
    let failed = reconcile_request(&db, "observable", 1001).unwrap();
    let config: ServiceConfiguration =
        get_json(&db.read().unwrap(), Collection::Lifecycle, b"configuration")
            .unwrap()
            .unwrap();
    assert_eq!(config.last_time, 1001);
    let mut rollback = db.write().unwrap();
    assert!(matches!(
        mutate_observed(&mut rollback, "POST", "/zone/operator/records", &raw, 1000),
        Err(AppError::Invalid("time moved backwards"))
    ));
    drop(rollback);
    assert_eq!(failed.body["execution_state"], "failed");
    assert_eq!(
        failed.body["latest_observation"]["signed_message_digest"],
        request.signed_message_digest().unwrap()
    );
    let read = db.read().unwrap();
    assert_eq!(
        zone_metadata(&read, &"example.".parse().unwrap())
            .unwrap()
            .serial,
        1
    );
    assert!(
        !get_json::<NonceRecord>(&read, Collection::Nonces, &nonce_key(1, &request.nonce))
            .unwrap()
            .unwrap()
            .consumed
    );
    drop(read);
    // A newer issued nonce is an explicit newer observation, never a claim
    // that an actual signed request has reached a handler.
    grant.revoked = false;
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
    tx.commit().unwrap();
    let newer = envelope(&db, &signer, action, 1002);
    let pending = reconcile_request(&db, "observable", 1002).unwrap();
    assert_eq!(pending.body["status"], "pending");
    assert_eq!(pending.body["matching_nonces"], 2);
    assert_eq!(pending.body["multiple_nonce_ambiguity"], true);
    assert_eq!(pending.body["latest_observation"]["nonce"], newer.nonce);
    let mut tx = db.write().unwrap();
    let success = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1003).unwrap();
    let version = tx.commit().unwrap();
    assert!(attempt_rows(&db).is_empty());
    let reconciled = reconcile_request(&db, "observable", 1004).unwrap();
    assert_eq!(reconciled.body, success.body);
    assert_eq!(reconciled.original_version, Some(version));
    let mut tx = db.write().unwrap();
    assert!(matches!(
        mutate_observed(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&newer).unwrap(),
            1004
        ),
        Err(AppError::Auth(AuthError::RequestIdConflict))
    ));
    drop(tx);
    assert!(attempt_rows(&db).is_empty());
    assert_eq!(
        reconcile_request(&db, "observable", 1004).unwrap().body,
        success.body
    );
}

#[test]
fn failed_attempt_overlay_discards_partial_records_and_preserves_nonce_quota() {
    let (db, signer, mut grant) = setup();
    grant.operator_record_types.push(OperatorRecordType::Mx);
    grant.operator_record_types.sort();
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Grants, b"owner".to_vec(), &grant).unwrap();
    tx.commit().unwrap();
    let mut action = operator(&signer, "partial-failure", 1);
    let ActionParameters::OperatorRecords(p) = &mut action.parameters else {
        unreachable!()
    };
    p.mutations.push(RecordMutation {
        action: MutationAction::Add,
        name: "example.".into(),
        record_type: OperatorRecordType::Mx,
        ttl: 300,
        rdata_strings: vec!["invalid-mx".into()],
    });
    let request = envelope(&db, &signer, action, 1000);
    let mut tx = db.write().unwrap();
    let result = mutate_observed(
        &mut tx,
        "POST",
        "/zone/operator/records",
        &serde_json::to_vec(&request).unwrap(),
        1001,
    )
    .unwrap();
    assert_eq!(result.http_status, 400);
    assert!(result.commit_error);
    tx.commit().unwrap();
    let read = db.read().unwrap();
    assert!(
        records(&read, &"example.".parse().unwrap())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        zone_metadata(&read, &"example.".parse().unwrap())
            .unwrap()
            .serial,
        1
    );
    assert_eq!(read.scan_prefix(Collection::Nonces, b"").unwrap().len(), 1);
    assert_eq!(attempt_rows(&db).len(), 1);
    assert!(
        read.get(
            Collection::RequestResults,
            &request_key("owner", "partial-failure")
        )
        .unwrap()
        .is_none()
    );
    drop(read);
    assert!(matches!(
        reconcile_request(&db, "partial-failure", 1300),
        Err(AppError::NotFound(_))
    ));
    let mut tx = db.write().unwrap();
    maintenance(&mut tx, 1300).unwrap();
    tx.commit().unwrap();
    assert!(attempt_rows(&db).is_empty());
    assert!(
        db.read()
            .unwrap()
            .scan_prefix(Collection::Nonces, b"")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unverifiable_attempts_and_internal_failures_leave_no_diagnostic_state() {
    let (db, signer, _) = setup();
    let request = envelope(&db, &signer, operator(&signer, "bad-signature", 999), 1000);
    let mut bad = request.clone();
    bad.client_signature = encode_base64url(&[0; 64]);
    let mut tx = db.write().unwrap();
    assert!(
        mutate_observed(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&bad).unwrap(),
            1001
        )
        .is_err()
    );
    tx.commit().unwrap();
    assert!(attempt_rows(&db).is_empty());
    let mut tx = db.write().unwrap();
    assert!(
        mutate_observed(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&request).unwrap(),
            1300
        )
        .is_err()
    );
    tx.commit().unwrap();
    assert!(attempt_rows(&db).is_empty());
    let request = envelope(&db, &signer, operator(&signer, "missing-key", 1), 1301);
    let origin: WireName = "example.".parse().unwrap();
    let mut tx = db.write().unwrap();
    tx.remove(
        Collection::PrivateKeys,
        &composite_key(&[origin.as_slice(), b"zsk"]),
    )
    .unwrap();
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    // A missing private key is currently a404 at the core boundary. It is an
    // internal failure and must never become durable application rejection.
    assert!(
        mutate_observed(
            &mut tx,
            "POST",
            "/zone/operator/records",
            &serde_json::to_vec(&request).unwrap(),
            1302
        )
        .is_err()
    );
    tx.commit().unwrap();
    assert!(attempt_rows(&db).is_empty());
}

#[test]
fn failed_attempts_expire_on_epoch_change_and_survive_authenticated_recovery() {
    let (db, signer, _) = setup();
    let request = envelope(
        &db,
        &signer,
        operator(&signer, "failed-before-recovery", 999),
        1000,
    );
    let mut tx = db.write().unwrap();
    mutate_observed(
        &mut tx,
        "POST",
        "/zone/operator/records",
        &serde_json::to_vec(&request).unwrap(),
        1001,
    )
    .unwrap();
    tx.commit().unwrap();
    let image = db.seal(&[73; 32]).unwrap();
    let restored = MemoryStorage::restore(&image, &[73; 32]).unwrap();
    assert_eq!(
        reconcile_request(&restored, "failed-before-recovery", 1002)
            .unwrap()
            .body["status"],
        "failed"
    );
    let mut tx = restored.write().unwrap();
    let mut config: ServiceConfiguration = get_json(&tx, Collection::Lifecycle, b"configuration")
        .unwrap()
        .unwrap();
    config.epoch += 1;
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &config,
    )
    .unwrap();
    maintenance(&mut tx, 1002).unwrap();
    tx.commit().unwrap();
    assert!(attempt_rows(&restored).is_empty());
    assert!(matches!(
        reconcile_request(&restored, "failed-before-recovery", 1002),
        Err(AppError::NotFound(_))
    ));
}

#[test]
fn changing_appraisal_policy_identity_withdraws_existing_registration() {
    let (db, _, grant) = setup();
    let registration = seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    let mut policy: adns_attest::AppraisalPolicy =
        get_json(&tx, Collection::Policies, &origin_wire())
            .unwrap()
            .unwrap();
    policy.policy_id = [2; 32];
    put_json(&mut tx, Collection::Policies, origin_wire(), &policy).unwrap();
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    assert_eq!(maintenance(&mut tx, 1100).unwrap(), vec!["example."]);
    tx.commit().unwrap();
    let read = db.read().unwrap();
    let withdrawn: Registration = get_json(
        &read,
        Collection::Registrations,
        registration.registration_id.as_bytes(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(withdrawn.status, "withdrawn");
    assert!(
        records(&read, &"example.".parse().unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn request_diagnostics_preserve_transaction_results_and_isolate_exact_retries() {
    use adns_telemetry::{Name, RequestScope};
    let (db, signer, _) = setup();
    let request = envelope(&db, &signer, operator(&signer, "traced-operation", 1), 1000);
    let raw = serde_json::to_vec(&request).unwrap();
    let mut uncommitted = db.write().unwrap();
    let baseline = mutate_observed(
        &mut uncommitted,
        "POST",
        "/zone/operator/records",
        &raw,
        1001,
    )
    .unwrap();
    drop(uncommitted);
    let scope = RequestScope::new();
    let mut tx = db.write().unwrap();
    let traced = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1001).unwrap();
    let spans = scope.finish();
    assert_eq!(
        serde_json::to_value(&baseline).unwrap(),
        serde_json::to_value(&traced).unwrap()
    );
    for name in [
        Name::Parse,
        Name::Signature,
        Name::Idempotency,
        Name::Nonce,
        Name::Grant,
        Name::DnssecSign,
        Name::StorageStage,
    ] {
        assert!(
            spans
                .iter()
                .any(|span| span.name == name && span.outcome == 1),
            "{name:?}"
        );
    }
    let diagnostic_text = format!("{spans:?}");
    for sensitive in [
        &request.nonce,
        &request.client_signature,
        &request.action.signer_spki_der,
    ] {
        assert!(!diagnostic_text.contains(sensitive));
    }
    tx.commit().unwrap();
    let metadata = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    verify_published_rrsets(&metadata, 1001);
    let replay_scope = RequestScope::new();
    let replay = mutate_observed(
        &mut db.write().unwrap(),
        "POST",
        "/zone/operator/records",
        &raw,
        1002,
    )
    .unwrap();
    assert_eq!(replay.body, traced.body);
    assert!(replay.original_version.is_some());
    let replay_spans = replay_scope.finish();
    assert!(
        replay_spans
            .iter()
            .any(|span| span.name == Name::Idempotency)
    );
    assert!(
        !replay_spans
            .iter()
            .any(|span| matches!(span.name, Name::DnssecSign | Name::Nonce | Name::Grant))
    );
    assert!(RequestScope::new().finish().is_empty());
}

#[test]
fn saturated_diagnostics_do_not_change_business_failure_or_commit_partial_records() {
    use adns_telemetry::{MAX_SPANS, Name, RequestScope, observe};
    let (db, signer, _) = setup();
    let request = envelope(&db, &signer, operator(&signer, "traced-conflict", 9), 1000);
    let raw = serde_json::to_vec(&request).unwrap();
    let baseline = mutate_observed(
        &mut db.write().unwrap(),
        "POST",
        "/zone/operator/records",
        &raw,
        1001,
    )
    .unwrap();
    let scope = RequestScope::new();
    for _ in 0..1000 {
        observe(Name::Parse, || Ok::<_, ()>(())).unwrap();
    }
    let mut tx = db.write().unwrap();
    let traced = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1001).unwrap();
    assert_eq!(
        serde_json::to_value(&baseline).unwrap(),
        serde_json::to_value(&traced).unwrap()
    );
    assert_eq!(traced.http_status, 409);
    assert!(traced.commit_error);
    tx.commit().unwrap();
    assert_eq!(scope.finish().len(), MAX_SPANS);
    let metadata = zone_metadata(&db.read().unwrap(), &"example.".parse().unwrap()).unwrap();
    assert_eq!(metadata.serial, 1);
    assert!(
        !metadata
            .signed_records
            .iter()
            .any(|record| record.rtype == RecordType::Txt)
    );
}

fn attested(name: &str, text: &str) -> AttestedRecord {
    AttestedRecord {
        name: name.into(),
        record_type: AttestedRecordType::Txt,
        ttl: 300,
        rdata_strings: vec![text.into()],
    }
}

#[test]
fn attested_records_publish_with_registration_and_withdraw_with_it() {
    let (db, signer, grant) = setup();
    let mut p = params();
    p.attested_records = vec![
        attested("cvm1._domainkey.example.", "v=DKIM1; k=rsa; p=AAAA"),
        attested("_receipt.mail.example.", "v=AHRK1; k=es256; spki_sha256=ab"),
    ];
    let origin: WireName = "example.".parse().unwrap();
    // Exact grant scope: a name outside attested_names is denied before any state changes.
    let mut outside = p.clone();
    outside
        .attested_records
        .push(attested("evil._domainkey.example.", "x"));
    assert!(matches!(
        authorize_action(
            &action(&signer, "reg-outside", ActionParameters::Register(outside)),
            &grant,
            "ccf://test",
            1000
        ),
        Err(AuthError::GrantDenied(_))
    ));
    // Ownership: contributions carry the registration id and are removed on withdraw_all.
    let r = seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    for record in attested_contributions(&p).unwrap() {
        add_contribution(&mut tx, &origin, &r.registration_id, record).unwrap();
    }
    resign_zone(&mut tx, &origin, 1000, true).unwrap();
    tx.commit().unwrap();
    let published = |db: &MemoryStorage| {
        let tx = db.read().unwrap();
        tx.scan_prefix(Collection::Records, &zone_prefix(&origin))
            .unwrap()
            .into_iter()
            .map(|(_, v)| serde_json::from_slice::<VersionedRrset>(&v.bytes).unwrap())
            .filter(|set| {
                set.contributions.iter().any(|c| {
                    c.contributor == "seeded-registration" && c.record.rtype == RecordType::Txt
                })
            })
            .count()
    };
    assert_eq!(published(&db), 2);
    let withdraw = envelope(
        &db,
        &signer,
        action(
            &signer,
            "withdraw-attested",
            ActionParameters::Deregister(DeregisterParameters {
                registration_id: r.registration_id.clone(),
                selected_ports: vec![],
                withdraw_all: true,
                reason: "key_rotation".into(),
            }),
        ),
        1100,
    );
    let mut tx = db.write().unwrap();
    mutate(
        &mut tx,
        "POST",
        "/service/deregister",
        &serde_json::to_vec(&withdraw).unwrap(),
        1100,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        published(&db),
        0,
        "attested TXT contributions leave with their registration"
    );
    // A non-MX role publishes no MX record.
    let mut worker = params();
    worker.role = "worker".into();
    worker.service_host = "worker.example.".into();
    let records = mail_contributions(&worker, &grant.subject_spki_sha256).unwrap();
    assert!(records.iter().all(|r| r.rtype != RecordType::Mx));
    assert!(records.iter().any(|r| r.rtype == RecordType::Tlsa));
    assert!(
        mail_contributions(&params(), &grant.subject_spki_sha256)
            .unwrap()
            .iter()
            .any(|r| r.rtype == RecordType::Mx)
    );
}

#[test]
fn anchors_are_owner_bound_monotonic_idempotent_and_receipted() {
    let (db, signer, grant) = setup();
    let r = seed_registration(&db, &grant);
    let anchor = |seq: u64, digest: &str, id: &str| {
        action(
            &signer,
            id,
            ActionParameters::Anchor(AnchorParameters {
                registration_id: r.registration_id.clone(),
                subject: "conversation-1".into(),
                sequence: seq,
                digest_sha256: digest.repeat(32),
            }),
        )
    };
    let submit = |db: &MemoryStorage, request: &SignedRequest, now: u64| {
        let mut tx = db.write().unwrap();
        let out = mutate(
            &mut tx,
            "POST",
            "/service/anchor",
            &serde_json::to_vec(request).unwrap(),
            now,
        );
        if out.is_ok() {
            tx.commit().unwrap();
        }
        out
    };
    let first = envelope(&db, &signer, anchor(1, "aa", "anchor-1"), 1100);
    let response = submit(&db, &first, 1100).unwrap();
    assert_eq!(response.body["anchor"]["sequence"], 1);
    assert_eq!(response.body["anchor"]["type"], anchors::ANCHOR_CLAIMS_TYPE);
    let expected =
        anchors::claims_digest(anchors::ANCHOR_CLAIMS_TYPE, &response.body["anchor"]).unwrap();
    assert_eq!(
        response.claims_digest,
        Some(expected),
        "receipt claims digest covers exactly the returned anchor claims"
    );
    // Same sequence, different digest: rejected.
    let fork = envelope(&db, &signer, anchor(1, "bb", "anchor-1-fork"), 1101);
    assert!(matches!(
        submit(&db, &fork, 1101),
        Err(AppError::Conflict(_))
    ));
    // Sequence must advance.
    assert!(
        anchor(0, "cc", "anchor-0").validate().is_err(),
        "sequence 0 is rejected by schema"
    );
    let next = envelope(&db, &signer, anchor(2, "cc", "anchor-2"), 1103);
    submit(&db, &next, 1103).unwrap();
    let behind = envelope(&db, &signer, anchor(2, "dd", "anchor-2b"), 1104);
    assert!(matches!(
        submit(&db, &behind, 1104),
        Err(AppError::Conflict(_))
    ));
    // Same digest re-anchored under a new request id: idempotent, still receipted.
    let dup = envelope(&db, &signer, anchor(2, "cc", "anchor-2-again"), 1105);
    let again = submit(&db, &dup, 1105).unwrap();
    assert_eq!(again.body["duplicate"], true);
    assert!(again.claims_digest.is_some());
    // Another key cannot anchor under this registration.
    let rng = SystemRandom::new();
    let other = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap()
            .as_ref(),
        &rng,
    )
    .unwrap();
    let foreign = action(
        &other,
        "anchor-foreign",
        ActionParameters::Anchor(AnchorParameters {
            registration_id: r.registration_id.clone(),
            subject: "conversation-1".into(),
            sequence: 3,
            digest_sha256: "ee".repeat(32),
        }),
    );
    assert!(matches!(
        authorize_action(&foreign, &grant, "ccf://test", 1106),
        Err(AuthError::GrantDenied(_))
    ));
    // Reads re-emit receipt claims for a stored anchor and for the head.
    let tx = db.read().unwrap();
    let head = read_json(
        &tx,
        "/service/anchor",
        &[
            ("registration_id".into(), r.registration_id.clone()),
            ("subject".into(), "conversation-1".into()),
        ],
        1200,
    )
    .unwrap();
    assert_eq!(head.body["anchor"]["sequence"], 2);
    assert_eq!(head.body["anchor"]["digest_sha256"], "cc".repeat(32));
    assert!(head.claims_digest.is_some());
    let explicit = read_json(
        &tx,
        "/service/anchor",
        &[
            ("registration_id".into(), r.registration_id.clone()),
            ("subject".into(), "conversation-1".into()),
            ("sequence".into(), "1".into()),
        ],
        1200,
    )
    .unwrap();
    assert_eq!(explicit.body["anchor"]["digest_sha256"], "aa".repeat(32));
    assert!(matches!(
        read_json(
            &tx,
            "/service/anchor",
            &[
                ("registration_id".into(), r.registration_id.clone()),
                ("subject".into(), "nope".into())
            ],
            1200
        ),
        Err(AppError::NotFound(_))
    ));
}

#[test]
fn governance_receipts_cover_policy_and_anchors_document() {
    let (db, _, grant) = setup();
    seed_registration(&db, &grant);
    let mut tx = db.write().unwrap();
    put_json(&mut tx, Collection::Lifecycle, b"governance/node-join-policy".to_vec(), &json!({
        "svn": 3, "release_id": "agentdns-v5", "measurements": ["ab".repeat(48)], "host_data": ["cd".repeat(32)],
        "uvm_endorsements": [{"did": "did:x509:0:sha256:x::eku:1", "feed": "ContainerPlat-AMD-UVM", "svn": "104"}],
        "tcb_versions": {"Genoa": {"boot_loader": 10, "tee": 0, "snp": 23, "microcode": 84}}, "policy_sha256": "ef".repeat(32)})).unwrap();
    put_json(&mut tx, Collection::Lifecycle, b"governance/release-authority".to_vec(), &json!({
        "did": "did:x509:0:sha256:abc::subject:CN:agent.hosting", "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
        "svn": 3, "valid_from": 0, "valid_until": 4000})).unwrap();
    tx.commit().unwrap();
    let tx = db.read().unwrap();
    let policy = read_json(
        &tx,
        "/governance/policy-receipt",
        &[("zone".into(), "example.".into())],
        1200,
    )
    .unwrap();
    assert_eq!(policy.body["claims"]["policy_id_hex"], "01".repeat(32));
    assert_eq!(
        policy.body["claims"]["release_id"],
        "approved-fixture-state"
    );
    assert_eq!(
        policy.claims_digest,
        Some(anchors::claims_digest(anchors::POLICY_CLAIMS_TYPE, &policy.body["claims"]).unwrap())
    );
    assert!(matches!(
        read_json(
            &tx,
            "/governance/policy-receipt",
            &[("zone".into(), "missing.".into())],
            1200
        ),
        Err(AppError::NotFound(_))
    ));
    let anchors = read_json(&tx, "/governance/anchors", &[], 1200).unwrap();
    let claims = &anchors.body["claims"];
    assert_eq!(claims["zones"][0]["zone"], "example.");
    assert_eq!(claims["zones"][0]["algorithm"], 14);
    assert_eq!(
        claims["appraisal_policies"][0]["policy_id_hex"],
        "01".repeat(32)
    );
    assert_eq!(claims["node_join_policy"]["svn"], 3);
    assert_eq!(
        claims["release_authority"]["did"],
        "did:x509:0:sha256:abc::subject:CN:agent.hosting"
    );
    assert_eq!(
        anchors.claims_digest,
        Some(anchors::claims_digest(anchors::ANCHORS_CLAIMS_TYPE, claims).unwrap())
    );
    assert!(matches!(
        read_json(
            &tx,
            "/governance/anchors",
            &[("x".into(), "y".into())],
            1200
        ),
        Err(AppError::Invalid(_))
    ));
}

#[test]
fn ksk_rollover_double_signs_then_swaps_only_after_hold_and_attested_ds() {
    let (db, _, _) = setup();
    let origin: WireName = "example.".parse().unwrap();
    let before = {
        let tx = db.read().unwrap();
        zone_metadata(&tx, &origin).unwrap()
    };
    let old_rdata = before.ksk_dnskey_rdata.clone();
    assert!(before.ksk_rollover.is_none());
    let dnskeys = |db: &MemoryStorage| {
        let tx = db.read().unwrap();
        let z = zone_metadata(&tx, &origin).unwrap();
        let keys = z
            .signed_records
            .iter()
            .filter(|r| {
                r.rtype == RecordType::Dnskey
                    && matches!(&r.rdata, RData::Dnskey(k) if k.flags == 257)
            })
            .count();
        let sigs = z
            .signed_records
            .iter()
            .filter(|r| matches!(&r.rdata, RData::Rrsig(s) if s.type_covered == RecordType::Dnskey))
            .count();
        (keys, sigs, z)
    };
    assert_eq!(dnskeys(&db).0, 1);
    // start: incoming KSK generated in the enclave, both published, DNSKEY signed twice
    let mut tx = db.write().unwrap();
    apply_ksk_rollover(
        &mut tx,
        &KskRolloverCommand {
            zone: "example.".into(),
            command: "start".into(),
            new_key_tag: None,
            new_ds_sha256: None,
            minimum_hold_seconds: Some(1000),
        },
        2000,
    )
    .unwrap();
    tx.commit().unwrap();
    let (ksks, sigs, z) = dnskeys(&db);
    assert_eq!(
        (ksks, sigs),
        (2, 2),
        "two KSKs published, DNSKEY RRset signed by both"
    );
    let rollover = z.ksk_rollover.clone().unwrap();
    assert_eq!(rollover.stage, "double-signature");
    assert_eq!(
        z.ksk_dnskey_rdata, old_rdata,
        "current KSK unchanged during double-signature"
    );
    let next_tag = key_tag(&rollover.next_ksk_dnskey_rdata);
    let next_ds = ds_sha256(&origin, &rollover.next_ksk_dnskey_rdata);
    assert_ne!(next_tag, key_tag(&old_rdata));
    // a second start is refused; completion before the hold is refused; wrong attestation is refused
    let mut tx = db.write().unwrap();
    assert!(matches!(
        apply_ksk_rollover(
            &mut tx,
            &KskRolloverCommand {
                zone: "example.".into(),
                command: "start".into(),
                new_key_tag: None,
                new_ds_sha256: None,
                minimum_hold_seconds: None
            },
            2001
        ),
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        apply_ksk_rollover(
            &mut tx,
            &KskRolloverCommand {
                zone: "example.".into(),
                command: "complete".into(),
                new_key_tag: Some(next_tag),
                new_ds_sha256: Some(next_ds.clone()),
                minimum_hold_seconds: None
            },
            2500
        ),
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        apply_ksk_rollover(
            &mut tx,
            &KskRolloverCommand {
                zone: "example.".into(),
                command: "complete".into(),
                new_key_tag: Some(next_tag ^ 1),
                new_ds_sha256: Some(next_ds.clone()),
                minimum_hold_seconds: None
            },
            3001
        ),
        Err(AppError::Invalid(_))
    ));
    assert!(matches!(
        apply_ksk_rollover(
            &mut tx,
            &KskRolloverCommand {
                zone: "example.".into(),
                command: "complete".into(),
                new_key_tag: Some(next_tag),
                new_ds_sha256: Some(ds_sha256(&origin, &old_rdata)),
                minimum_hold_seconds: None
            },
            3001
        ),
        Err(AppError::Invalid(_))
    ));
    drop(tx);
    // status and anchors show the rollover
    {
        let tx = db.read().unwrap();
        let status = read_json(
            &tx,
            "/zone/status",
            &[("zone".into(), "example.".into())],
            2500,
        )
        .unwrap();
        assert_eq!(status.body["ksk_rollover"]["next_key_tag"], next_tag);
        let anchors = read_json(&tx, "/governance/anchors", &[], 2500).unwrap();
        assert_eq!(
            anchors.body["claims"]["zones"][0]["rollover"]["next_ds_sha256"],
            next_ds
        );
    }
    // complete after the hold with the exact incoming tag/DS: old key gone, new key current, single signature again
    let mut tx = db.write().unwrap();
    apply_ksk_rollover(
        &mut tx,
        &KskRolloverCommand {
            zone: "example.".into(),
            command: "complete".into(),
            new_key_tag: Some(next_tag),
            new_ds_sha256: Some(next_ds.clone()),
            minimum_hold_seconds: None,
        },
        3001,
    )
    .unwrap();
    tx.commit().unwrap();
    let (ksks, sigs, z) = dnskeys(&db);
    assert_eq!((ksks, sigs), (1, 1));
    assert!(z.ksk_rollover.is_none());
    assert_eq!(key_tag(&z.ksk_dnskey_rdata), next_tag);
    assert_eq!(ds_sha256(&origin, &z.ksk_dnskey_rdata), next_ds);
    assert!(
        db.read()
            .unwrap()
            .get(
                Collection::PrivateKeys,
                &composite_key(&[origin.as_slice(), b"ksk-next"])
            )
            .unwrap()
            .is_none()
    );
    // abort path: start then abort restores the single current key
    let mut tx = db.write().unwrap();
    apply_ksk_rollover(
        &mut tx,
        &KskRolloverCommand {
            zone: "example.".into(),
            command: "start".into(),
            new_key_tag: None,
            new_ds_sha256: None,
            minimum_hold_seconds: None,
        },
        4000,
    )
    .unwrap();
    apply_ksk_rollover(
        &mut tx,
        &KskRolloverCommand {
            zone: "example.".into(),
            command: "abort".into(),
            new_key_tag: None,
            new_ds_sha256: None,
            minimum_hold_seconds: None,
        },
        4001,
    )
    .unwrap();
    tx.commit().unwrap();
    let (ksks, _, z) = dnskeys(&db);
    assert_eq!(ksks, 1);
    assert_eq!(
        key_tag(&z.ksk_dnskey_rdata),
        next_tag,
        "abort keeps the current key"
    );
}
