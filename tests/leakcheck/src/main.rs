//! Finite normal-exit allocation workload. Not a network/CCF/hardware test.
#![forbid(unsafe_code)]
use adns_auth::{
    Action, ActionParameters, MutationAction, NonceResponse, OperatorParameters,
    OperatorRecordType, OwnerGrant, RecordMutation, SignedRequest, encode_base64url, sha256_hex,
};
use adns_dnssec::{DenialMode, SignedZone, SigningKey};
use adns_server::*;
use adns_storage::*;
use adns_transfer::*;
use adns_wire::*;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::json;
use std::error::Error;
fn n(value: &str) -> WireName {
    value.parse().unwrap()
}
fn rr(name: &str, data: RData) -> ResourceRecord {
    ResourceRecord::new(n(name), 300, data).unwrap()
}
fn exercise_overlay(db: &MemoryStorage) -> std::result::Result<(), Box<dyn Error>> {
    for _ in 0..8 {
        let mut tx = db.write()?;
        tx.put(
            Collection::Lifecycle,
            b"leakcheck/keep".to_vec(),
            vec![42; 4096],
        )?;
        {
            let mut overlay = WriteOverlay::new(&mut tx);
            overlay.remove(Collection::Lifecycle, b"leakcheck/keep")?;
            overlay.put(
                Collection::Lifecycle,
                b"leakcheck/discard".to_vec(),
                vec![43; 2048],
            )?;
            assert!(
                overlay
                    .get(Collection::Lifecycle, b"leakcheck/keep")?
                    .is_none()
            );
            assert_eq!(
                overlay
                    .scan_prefix(Collection::Lifecycle, b"leakcheck/")?
                    .len(),
                1
            );
        }
        assert!(tx.get(Collection::Lifecycle, b"leakcheck/keep")?.is_some());
        assert!(
            tx.get(Collection::Lifecycle, b"leakcheck/discard")?
                .is_none()
        );
        let mut overlay = WriteOverlay::new(&mut tx);
        overlay.remove(Collection::Lifecycle, b"leakcheck/keep")?;
        overlay.put(
            Collection::Lifecycle,
            b"leakcheck/flush".to_vec(),
            vec![44; 4096],
        )?;
        assert_eq!(
            overlay
                .get(Collection::Lifecycle, b"leakcheck/flush")?
                .unwrap()
                .bytes
                .len(),
            4096
        );
        overlay.flush()?;
        assert!(tx.get(Collection::Lifecycle, b"leakcheck/keep")?.is_none());
        assert_eq!(
            tx.scan_prefix(Collection::Lifecycle, b"leakcheck/")?.len(),
            1
        );
        tx.remove(Collection::Lifecycle, b"leakcheck/flush")?;
        tx.commit()?;
    }
    Ok(())
}
fn exercise_observed_attempts(db: &MemoryStorage) -> std::result::Result<(), Box<dyn Error>> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let mut spki = hex_decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")?;
    spki.extend(signer.public_key().as_ref());
    let mut grant = OwnerGrant {
        grant_id: "leak-owner".into(),
        subject_spki_sha256: sha256_hex(&spki),
        zones: vec!["example.test.".into()],
        mailbox_domains: vec![],
        service_hosts: vec![],
        roles: vec![],
        address_cidrs: vec![],
        ports: vec![],
        allowed_operations: vec![adns_auth::Operation::OperatorRecords],
        acme_names: vec![],
        operator_names: vec!["example.test.".into()],
        operator_record_types: vec![OperatorRecordType::Mx, OperatorRecordType::Txt],
        max_lease_seconds: 600,
        max_challenge_lifetime_seconds: 600,
        valid_from: 0,
        valid_until: 100000,
        revoked: false,
    };
    grant.operator_record_types.sort();
    let mut tx = db.write()?;
    put_json(&mut tx, Collection::Grants, b"leak-owner".to_vec(), &grant)?;
    tx.commit()?;
    let origin = n("example.test.");
    let serial = zone_metadata(&db.read()?, &origin)?.serial;
    let action = |id: &str, expected_serial: u32, malformed: bool| {
        let mut mutations = vec![RecordMutation {
            action: MutationAction::Replace,
            name: origin.to_string(),
            record_type: OperatorRecordType::Txt,
            ttl: 300,
            rdata_strings: vec![if malformed {
                "must not survive".into()
            } else {
                "v=spf1 -all".into()
            }],
        }];
        if malformed {
            mutations.push(RecordMutation {
                action: MutationAction::Add,
                name: origin.to_string(),
                record_type: OperatorRecordType::Mx,
                ttl: 300,
                rdata_strings: vec!["invalid-mx".into()],
            });
        }
        Action {
            request_id: id.into(),
            audience: "ccf://local-leakcheck".into(),
            grant_id: grant.grant_id.clone(),
            zone: origin.to_string(),
            signer_spki_der: encode_base64url(&spki),
            parameters: ActionParameters::OperatorRecords(OperatorParameters {
                expected_serial,
                mutations,
            }),
        }
    };
    let issue = |action: Action, now: u64| -> std::result::Result<SignedRequest, Box<dyn Error>> {
        let mut tx = db.write()?;
        let response = mutate_observed(
            &mut tx,
            "POST",
            "/service/nonce",
            &serde_json::to_vec(&json!({"action":action}))?,
            now,
        )?;
        tx.commit()?;
        let nonce: NonceResponse = serde_json::from_value(response.body)?;
        let mut request = SignedRequest {
            action,
            nonce: nonce.nonce,
            nonce_expires_at: nonce.expires_at,
            intent_hash: nonce.intent_hash,
            client_signature: String::new(),
            evidence_payload: None,
        };
        request.client_signature = encode_base64url(
            signer
                .sign(&rng, &request.signed_message()?)
                .unwrap()
                .as_ref(),
        );
        Ok(request)
    };
    let status = |id: &str, now: u64| {
        read_json(
            &db.read().unwrap(),
            "/service/request",
            &[
                ("grant_id".into(), "leak-owner".into()),
                ("request_id".into(), id.into()),
            ],
            now,
        )
    };
    let attempts = |read: &MemoryRead| {
        read.scan_prefix(
            Collection::Lifecycle,
            &composite_key(&[b"server/v1/request-attempt"]),
        )
    };
    let request = issue(action("reauthorized", serial, false), 1101)?;
    let raw = serde_json::to_vec(&request)?;
    assert_eq!(status("reauthorized", 1101)?.body["status"], "pending");
    grant.revoked = true;
    let mut tx = db.write()?;
    put_json(&mut tx, Collection::Grants, b"leak-owner".to_vec(), &grant)?;
    tx.commit()?;
    let mut tx = db.write()?;
    let failed = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1102)?;
    assert_eq!(failed.http_status, 403);
    assert!(failed.commit_error && !failed.promote_status_on_commit);
    tx.commit()?;
    assert_eq!(attempts(&db.read()?)?.len(), 1);
    assert_eq!(status("reauthorized", 1102)?.body["status"], "failed");
    assert_eq!(zone_metadata(&db.read()?, &origin)?.serial, serial);
    grant.revoked = false;
    let mut tx = db.write()?;
    put_json(&mut tx, Collection::Grants, b"leak-owner".to_vec(), &grant)?;
    tx.commit()?;
    let mut tx = db.write()?;
    let success = mutate_observed(&mut tx, "POST", "/zone/operator/records", &raw, 1103)?;
    assert_eq!(success.http_status, 200);
    assert!(!success.commit_error);
    let version = tx.commit()?;
    assert_eq!(
        status("reauthorized", 1103)?.original_version,
        Some(version)
    );
    assert!(attempts(&db.read()?)?.is_empty());
    assert!(db.read()?.scan_prefix(Collection::Nonces, b"")?.is_empty());
    // The second request writes TXT in its overlay before malformed MX fails.
    let before = records(&db.read()?, &origin)?;
    let request = issue(action("expire-failed", serial + 1, true), 1104)?;
    let mut tx = db.write()?;
    let failed = mutate_observed(
        &mut tx,
        "POST",
        "/zone/operator/records",
        &serde_json::to_vec(&request)?,
        1105,
    )?;
    assert_eq!(failed.http_status, 400);
    assert!(failed.commit_error);
    tx.commit()?;
    assert_eq!(records(&db.read()?, &origin)?, before);
    assert_eq!(zone_metadata(&db.read()?, &origin)?.serial, serial + 1);
    assert_eq!(attempts(&db.read()?)?.len(), 1);
    let mut tx = db.write()?;
    assert!(maintenance(&mut tx, 1404)?.is_empty());
    tx.commit()?;
    assert!(attempts(&db.read()?)?.is_empty());
    assert!(db.read()?.scan_prefix(Collection::Nonces, b"")?.is_empty());
    assert!(matches!(
        status("expire-failed", 1404),
        Err(AppError::NotFound(_))
    ));
    Ok(())
}
fn main() -> std::result::Result<(), Box<dyn Error>> {
    let origin = n("example.test.");
    let base = vec![
        rr(
            "example.test.",
            RData::Soa(SoaData {
                mname: n("ns.example.test."),
                rname: n("hostmaster.example.test."),
                serial: 1,
                refresh: 60,
                retry: 30,
                expire: 3600,
                minimum: 60,
            }),
        ),
        rr("example.test.", RData::Ns(n("ns.example.test."))),
        rr("ns.example.test.", RData::A("192.0.2.53".parse()?)),
        rr("*.wild.example.test.", RData::A("192.0.2.99".parse()?)),
        rr(
            "leaf.ent.example.test.",
            RData::Txt(vec![b"allocation workload".to_vec()]),
        ),
    ];
    let mut query_count = 0usize;
    let mut transfer_packets = 0usize;
    let mut snapshot_bytes = 0usize;
    for epoch in 1..=8 {
        let db = MemoryStorage::default();
        let mut tx = db.write()?;
        put_json(
            &mut tx,
            Collection::Lifecycle,
            b"configuration".to_vec(),
            &ServiceConfiguration {
                audience: "ccf://local-leakcheck".into(),
                epoch,
                last_time: 1000,
            },
        )?;
        initialize_zone(
            &mut tx,
            ZoneMetadata {
                id: ZoneId(1),
                origin,
                serial: 1,
                base_records: base.clone(),
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
        )?;
        tx.commit()?;
        // Aborted writes and optimistic conflict paths must release snapshots.
        let mut aborted = db.write()?;
        aborted.put(
            Collection::RequestResults,
            b"aborted".to_vec(),
            vec![42; 4096],
        )?;
        drop(aborted);
        assert!(
            db.read()?
                .get(Collection::RequestResults, b"aborted")?
                .is_none()
        );
        let mut first = db.write()?;
        let mut second = db.write()?;
        first.put(
            Collection::RequestResults,
            b"conflict".to_vec(),
            vec![1; 1024],
        )?;
        second.put(
            Collection::RequestResults,
            b"conflict".to_vec(),
            vec![2; 1024],
        )?;
        first.commit()?;
        assert!(second.commit().is_err());
        let mut tx = db.write()?;
        for host in 0..16 {
            add_contribution(
                &mut tx,
                &origin,
                "workload",
                rr(
                    &format!("host{host}.example.test."),
                    RData::A("192.0.2.1".parse()?),
                ),
            )?;
            add_contribution(
                &mut tx,
                &origin,
                "workload",
                rr(
                    &format!("host{host}.example.test."),
                    RData::Txt(vec![vec![b'x'; 128]]),
                ),
            )?;
        }
        resign_zone(&mut tx, &origin, 1100, true)?;
        tx.commit()?;
        exercise_overlay(&db)?;
        exercise_observed_attempts(&db)?;
        let image = db.seal(&[17; 32])?;
        snapshot_bytes += image.len();
        let restored = MemoryStorage::restore(&image, &[17; 32])?;
        assert!(MemoryStorage::restore(&image, &[18; 32]).is_err());
        let metadata = zone_metadata(&restored.read()?, &origin)?;
        let signed = SignedZone::from_signed_records(origin, metadata.signed_records)?;
        // DNSSEC positive, negative, wildcard, empty-nonterminal and ANY answers.
        for _ in 0..32 {
            for (owner, typ) in [
                ("host0.example.test.", RecordType::A),
                ("host0.example.test.", RecordType::Aaaa),
                ("missing.example.test.", RecordType::A),
                ("x.wild.example.test.", RecordType::A),
                ("ent.example.test.", RecordType::Txt),
                ("host0.example.test.", RecordType::Any),
            ] {
                let query = Message {
                    header: Header { id: 1234, flags: 0 },
                    questions: vec![Question {
                        name: n(owner),
                        qtype: typ,
                        qclass: RecordClass::In,
                    }],
                    additionals: vec![ResourceRecord {
                        name: WireName::root(),
                        rclass: RecordClass::Unknown(1232),
                        rtype: RecordType::Opt,
                        ttl: 0x8000,
                        rdata: RData::Opt(OptData::default()),
                    }],
                    ..Message::default()
                };
                let answer = answer_query(&signed, &query.to_wire()?)?;
                let parsed = Message::parse(&answer)?;
                assert!(parsed.header.is_response());
                assert_eq!(Message::parse(&parsed.to_wire()?)?, parsed);
                query_count += 1;
            }
        }
        let key = TsigKey::new(n("transfer.example.test."), vec![23; 32])?;
        let query = Message {
            header: Header { id: 123, flags: 0 },
            questions: vec![Question {
                name: origin,
                qtype: RecordType::Axfr,
                qclass: RecordClass::In,
            }],
            ..Message::default()
        };
        let (packet, _) = sign_message(&query.to_wire()?, &key, 1100, None, false)?;
        let authenticated = verify_request(&packet, &key, 1100)?;
        let frames = axfr_messages(&authenticated, &origin, &signed.records, &key, 1100, 1232)?;
        let mut previous = authenticated.request_mac;
        let mut records = 0;
        for (index, frame) in frames.iter().enumerate() {
            let result = verify_message(frame, &key, 1100, Some(&previous), index > 0)?;
            records += result.message.answers.len();
            previous = result.request_mac;
            transfer_packets += 1;
        }
        assert_eq!(records, signed.records.len() + 1);
        let mut tx = restored.write()?;
        assert_eq!(maintenance(&mut tx, 1750)?, vec![origin.to_string()]);
        tx.commit()?;
        let mut tx = restored.write()?;
        assert!(remove_contributions(&mut tx, &origin, "workload", None)?);
        resign_zone(&mut tx, &origin, 1800, true)?;
        tx.commit()?;
        // Also construct and drop a distinct NSEC tree, with separate KSK/ZSK.
        let ksk = SigningKey::generate()?;
        let zsk = SigningKey::generate()?;
        let plain = SignedZone::sign_with_keys(
            origin,
            base.clone(),
            &ksk,
            &zsk,
            1800,
            900,
            DenialMode::Nsec,
        )?;
        assert_eq!(
            plain
                .resolve(&n("missing.example.test."), RecordType::A, true)
                .rcode,
            3
        );
    }
    println!(
        "{{\"epochs\":8,\"signed_zone_constructions\":48,\"contributed_records\":264,\"explicit_overlay_drops\":64,\"explicit_overlay_flushes\":64,\"authenticated_failed_attempts\":16,\"same_nonce_reauthorized_successes\":8,\"failed_attempt_expiry_cleanups\":8,\"dns_queries_and_roundtrips\":{query_count},\"authenticated_transfer_packets\":{transfer_packets},\"encrypted_snapshot_bytes\":{snapshot_bytes},\"normal_exit\":true}}"
    );
    Ok(())
}
