use adns_auth::{decode_base64url, encode_base64url, sha256_hex};
use adns_ccf::*;
use adns_server::{ServiceConfiguration, ZoneId, ZoneMetadata, initialize_zone, ksk_claims_digest};
use adns_storage::{
    Collection, DnsStorage, MemoryStorage, ReadTx, WriteTx, composite_key, get_json, put_json,
};
use adns_transfer::{SecondaryState, TsigKey, sign_message, verify_message};
use adns_wire::*;
use serde_json::json;
const NOW: u64 = 1_789_243_200;
fn database() -> MemoryStorage {
    let db = MemoryStorage::default();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &ServiceConfiguration {
            audience: "ccf://test".into(),
            epoch: 1,
            last_time: NOW,
        },
    )
    .unwrap();
    let origin: WireName = "example.test.".parse().unwrap();
    let soa = ResourceRecord::new(
        origin,
        300,
        RData::Soa(SoaData {
            mname: "ns.example.test.".parse().unwrap(),
            rname: "hostmaster.example.test.".parse().unwrap(),
            serial: 7,
            refresh: 60,
            retry: 30,
            expire: 600,
            minimum: 60,
        }),
    )
    .unwrap();
    let ns =
        ResourceRecord::new(origin, 300, RData::Ns("ns.example.test.".parse().unwrap())).unwrap();
    let a = ResourceRecord::new(
        "ns.example.test.".parse().unwrap(),
        300,
        RData::A("192.0.2.1".parse().unwrap()),
    )
    .unwrap();
    initialize_zone(
        &mut tx,
        ZoneMetadata {
            id: ZoneId(1),
            origin,
            serial: 7,
            base_records: vec![soa, ns, a],
            signed_records: vec![],
            signature_validity: 600,
            refresh_before: 300,
            last_signed_at: 0,
            earliest_signature_expiration: 0,
            maintenance_health: "initializing".into(),
            ksk_dnskey_rdata: vec![],
            ksk_rollover: None,
        },
        NOW,
    )
    .unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"governance/transfer/secondary.example.test.".to_vec(),
        &TransferConfiguration {
            key_name: "secondary.example.test.".into(),
            endpoint: "192.0.2.53:53".into(),
            zones: vec!["example.test.".into()],
            secret_sha256: sha256_hex(&[42; 32]),
            revoked: false,
        },
    )
    .unwrap();
    provision_transfer_key(&mut tx, &serde_json::to_vec(&secret()).unwrap()).unwrap();
    tx.commit().unwrap();
    db
}
fn secret() -> TransferSecret {
    TransferSecret {
        key_name: "secondary.example.test.".into(),
        secret_base64url: encode_base64url(&[42; 32]),
        zones: vec!["example.test.".into()],
    }
}
fn key() -> TsigKey {
    TsigKey::new("secondary.example.test.".parse().unwrap(), vec![42; 32]).unwrap()
}
#[test]
fn governed_configuration_cannot_regress_live_time_watermark() {
    let db = database();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"governance/configuration".to_vec(),
        &ServiceConfiguration {
            audience: "ccf://new".into(),
            epoch: 2,
            last_time: NOW - 600,
        },
    )
    .unwrap();
    governed_maintenance(&mut tx, NOW).unwrap();
    let actual: ServiceConfiguration = get_json(&tx, Collection::Lifecycle, b"configuration")
        .unwrap()
        .unwrap();
    assert_eq!(actual.last_time, NOW);
    assert_eq!(actual.epoch, 2);
    assert_eq!(actual.audience, "ccf://new");
    assert!(
        get_json::<ServiceConfiguration>(&tx, Collection::Lifecycle, b"governance/configuration")
            .unwrap()
            .is_none()
    );
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"governance/configuration".to_vec(),
        &ServiceConfiguration {
            audience: "ccf://old".into(),
            epoch: 1,
            last_time: NOW,
        },
    )
    .unwrap();
    assert!(governed_maintenance(&mut tx, NOW).is_err());
}
fn query(rtype: RecordType) -> Vec<u8> {
    query_with_key(rtype, &key())
}
fn query_with_key(rtype: RecordType, signing_key: &TsigKey) -> Vec<u8> {
    let message = Message {
        header: Header { id: 17, flags: 0 },
        questions: vec![Question {
            name: "example.test.".parse().unwrap(),
            qtype: rtype,
            qclass: RecordClass::In,
        }],
        ..Default::default()
    };
    sign_message(&message.to_wire().unwrap(), signing_key, NOW, None, false)
        .unwrap()
        .0
}
#[test]
fn complete_revocation_invalidates_pending_work_and_preserves_replacement() {
    let db = database();
    let mut tx = db.write().unwrap();
    let replacement = TransferConfiguration {
        key_name: "replacement.example.test.".into(),
        endpoint: "192.0.2.53:53".into(),
        zones: vec!["example.test.".into()],
        secret_sha256: sha256_hex(&[43; 32]),
        revoked: false,
    };
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"governance/transfer/replacement.example.test.".to_vec(),
        &replacement,
    )
    .unwrap();
    provision_transfer_key(
        &mut tx,
        &serde_json::to_vec(&TransferSecret {
            key_name: replacement.key_name.clone(),
            secret_base64url: encode_base64url(&[43; 32]),
            zones: replacement.zones.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    let replacement_key =
        TsigKey::new(replacement.key_name.parse().unwrap(), vec![43; 32]).unwrap();
    let work = secondary_requests(&mut tx, b"{}", NOW).unwrap().body["work"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(work.len(), 4);
    let mut replies = Vec::new();
    for item in &work {
        let packet = decode_base64url(item["packet_base64url"].as_str().unwrap(), 65535).unwrap();
        let old = Message::parse(&packet)
            .unwrap()
            .additionals
            .last()
            .unwrap()
            .name
            == "secondary.example.test.".parse::<WireName>().unwrap();
        let signing_key = if old { key() } else { replacement_key.clone() };
        let request = verify_message(&packet, &signing_key, NOW, None, false).unwrap();
        let mut response = Message {
            header: Header {
                id: request.message.header.id,
                flags: if item["kind"] == "notify" {
                    0xa400
                } else {
                    0x8400
                },
            },
            questions: request.message.questions,
            ..Default::default()
        };
        if item["kind"] == "soa" {
            response.answers = adns_server::zone_metadata(&tx, &"example.test.".parse().unwrap())
                .unwrap()
                .signed_records
                .into_iter()
                .filter(|record| record.rtype == RecordType::Soa)
                .collect();
        }
        let packet = sign_message(
            &response.to_wire().unwrap(),
            &signing_key,
            NOW,
            Some(&request.request_mac),
            false,
        )
        .unwrap()
        .0;
        replies.push((old, serde_json::to_vec(&json!({"id":item["id"],"endpoint":item["endpoint"],"response_base64url":encode_base64url(&packet)})).unwrap()));
    }
    tx.commit().unwrap();

    let mut tx = db.write().unwrap();
    let row = b"governance/transfer/secondary.example.test.";
    let mut revoked: TransferConfiguration =
        get_json(&tx, Collection::Lifecycle, row).unwrap().unwrap();
    revoked.revoked = true; // Exact output of the committed governance action.
    put_json(&mut tx, Collection::Lifecycle, row.to_vec(), &revoked).unwrap();
    tx.commit().unwrap();
    let denied = |error: adns_server::AppError| {
        assert!(matches!(
            error,
            adns_server::AppError::Auth(adns_auth::AuthError::GrantDenied(_))
        ));
    };
    denied(transfer(&db.read().unwrap(), &query(RecordType::Axfr), NOW).unwrap_err());
    denied(transfer_datagram(&db.read().unwrap(), &query(RecordType::Soa), NOW).unwrap_err());
    denied(
        provision_transfer_key(
            &mut db.write().unwrap(),
            &serde_json::to_vec(&secret()).unwrap(),
        )
        .unwrap_err(),
    );
    assert!(
        transfer(
            &db.read().unwrap(),
            &query_with_key(RecordType::Axfr, &replacement_key),
            NOW
        )
        .is_ok()
    );
    // These are otherwise-valid chained MACs from before governance committed;
    // revocation rejects both kinds before changing shared endpoint status.
    for (_, reply) in replies.iter().filter(|(old, _)| *old) {
        let mut tx = db.write().unwrap();
        denied(secondary_response(&mut tx, reply, NOW).unwrap_err());
        assert!(
            tx.scan_prefix(Collection::SecondaryStatus, b"")
                .unwrap()
                .is_empty()
        );
    }
    let mut tx = db.write().unwrap();
    assert!(
        secondary_requests(&mut tx, b"{}", NOW).unwrap().body["work"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let remaining = tx
        .scan_prefix(Collection::Lifecycle, b"secondary/pending/")
        .unwrap();
    assert_eq!(remaining.len(), 2);
    for (_, row) in remaining {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&row.bytes).unwrap()["key_name"],
            replacement.key_name
        );
    }
    for (_, reply) in replies.iter().filter(|(old, _)| !*old) {
        secondary_response(&mut tx, reply, NOW).unwrap();
    }
    let next = secondary_requests(&mut tx, b"{}", NOW + 1).unwrap();
    let next = next.body["work"].as_array().unwrap();
    assert_eq!(next.len(), 1);
    let packet = decode_base64url(next[0]["packet_base64url"].as_str().unwrap(), 65535).unwrap();
    verify_message(&packet, &replacement_key, NOW + 1, None, false).unwrap();
    let state: SecondaryState = get_json(
        &tx,
        Collection::SecondaryStatus,
        &composite_key(&[
            "example.test.".parse::<WireName>().unwrap().as_slice(),
            replacement.endpoint.as_bytes(),
        ]),
    )
    .unwrap()
    .unwrap();
    assert!(state.in_sync(7, NOW + 1, 60));
    assert!(
        get_json::<TransferSecret>(
            &tx,
            Collection::TsigSecrets,
            "secondary.example.test."
                .parse::<WireName>()
                .unwrap()
                .as_slice()
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(
        adns_server::zone_metadata(&tx, &"example.test.".parse().unwrap())
            .unwrap()
            .serial,
        7
    );
    tx.commit().unwrap();
}

#[test]
fn legacy_transfer_configuration_is_active_but_explicit_revocation_is_preserved() {
    let mut value = json!({"key_name":"secondary.example.test.","endpoint":"192.0.2.53:53","zones":["example.test."],"secret_sha256":sha256_hex(&[42;32])});
    assert!(
        !serde_json::from_value::<TransferConfiguration>(value.clone())
            .unwrap()
            .revoked
    );
    value["revoked"] = json!(true);
    assert!(
        serde_json::from_value::<TransferConfiguration>(value)
            .unwrap()
            .revoked
    );
}
#[test]
fn private_transfer_key_one_time_digest_pin_and_revocation() {
    let db = database();
    let mut tx = db.write().unwrap();
    assert_eq!(
        provision_transfer_key(&mut tx, &serde_json::to_vec(&secret()).unwrap())
            .unwrap()
            .body["already_provisioned"],
        true
    );
    let mut wrong = secret();
    wrong.secret_base64url = encode_base64url(&[99; 32]);
    assert!(provision_transfer_key(&mut tx, &serde_json::to_vec(&wrong).unwrap()).is_err());
    assert!(transfer(&db.read().unwrap(), &query(RecordType::Axfr), NOW).is_ok());
    tx.remove(
        Collection::Lifecycle,
        b"governance/transfer/secondary.example.test.",
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(transfer(&db.read().unwrap(), &query(RecordType::Axfr), NOW).is_err());
}
#[test]
fn axfr_frames_and_udp_soa_are_authenticated_and_no_key_export_occurs() {
    let db = database();
    let packet = query(RecordType::Axfr);
    let request = verify_message(&packet, &key(), NOW, None, false).unwrap();
    let frames = transfer(&db.read().unwrap(), &packet, NOW).unwrap();
    let mut prior = request.request_mac;
    let mut pos = 0;
    let mut count = 0;
    let mut records = Vec::new();
    while pos < frames.len() {
        let length = u16::from_be_bytes([frames[pos], frames[pos + 1]]) as usize;
        pos += 2;
        let verified = verify_message(
            &frames[pos..pos + length],
            &key(),
            NOW,
            Some(&prior),
            count > 0,
        )
        .unwrap();
        pos += length;
        prior = verified.request_mac;
        records.extend(verified.message.answers);
        count += 1;
    }
    assert_eq!(pos, frames.len());
    assert!(count > 0);
    assert_eq!(records.first(), records.last());
    assert_eq!(records[0].rtype, RecordType::Soa);
    let packet = query(RecordType::Soa);
    let request = verify_message(&packet, &key(), NOW, None, false).unwrap();
    let response = transfer_datagram(&db.read().unwrap(), &packet, NOW).unwrap();
    assert!(response.len() <= 1232);
    let response =
        verify_message(&response, &key(), NOW, Some(&request.request_mac), false).unwrap();
    assert_eq!(response.message.answers[0].rtype, RecordType::Soa);
    assert!(transfer_datagram(&db.read().unwrap(), &query(RecordType::Axfr), NOW).is_err());
}
#[test]
fn secondary_work_commits_before_observation_and_rejects_replays_forgery_and_source_mismatch() {
    let db = database();
    let mut tx = db.write().unwrap();
    let result = secondary_requests(&mut tx, b"{}", NOW).unwrap();
    assert_eq!(result.body["status"], "pending");
    assert!(!result.body.to_string().contains(&secret().secret_base64url));
    assert_eq!(result.body["work"].as_array().unwrap().len(), 2);
    tx.commit().unwrap();
    let work = result.body["work"].as_array().unwrap();
    for item in work {
        let packet = decode_base64url(item["packet_base64url"].as_str().unwrap(), 65535).unwrap();
        let request = verify_message(&packet, &key(), NOW, None, false).unwrap();
        let notify = item["kind"] == "notify";
        let mut response = Message {
            header: Header {
                id: request.message.header.id,
                flags: if notify { 0xa400 } else { 0x8400 },
            },
            questions: request.message.questions,
            ..Default::default()
        };
        if !notify {
            response.answers = vec![
                ResourceRecord::new(
                    "example.test.".parse().unwrap(),
                    300,
                    RData::Soa(SoaData {
                        mname: "ns.example.test.".parse().unwrap(),
                        rname: "hostmaster.example.test.".parse().unwrap(),
                        serial: 7,
                        refresh: 60,
                        retry: 30,
                        expire: 600,
                        minimum: 60,
                    }),
                )
                .unwrap(),
            ];
        }
        let signed = sign_message(
            &response.to_wire().unwrap(),
            &key(),
            NOW,
            Some(&request.request_mac),
            false,
        )
        .unwrap()
        .0;
        let body = json!({"id":item["id"],"endpoint":item["endpoint"],"response_base64url":encode_base64url(&signed)});
        // Governance changes take effect for queued observations immediately,
        // without waiting for private-key deletion or the pending work expiry.
        {
            let mut revoked = db.write().unwrap();
            let row = b"governance/transfer/secondary.example.test.";
            let mut config: TransferConfiguration = get_json(&revoked, Collection::Lifecycle, row)
                .unwrap()
                .unwrap();
            config.secret_sha256 = sha256_hex(&[99; 32]);
            put_json(&mut revoked, Collection::Lifecycle, row.to_vec(), &config).unwrap();
            assert!(
                secondary_response(&mut revoked, &serde_json::to_vec(&body).unwrap(), NOW).is_err()
            );
            assert!(secondary_requests(&mut revoked, b"{}", NOW).is_err());
        }
        let mut wrong = body.clone();
        wrong["endpoint"] = json!("192.0.2.54:53");
        assert!(
            secondary_response(
                &mut db.write().unwrap(),
                &serde_json::to_vec(&wrong).unwrap(),
                NOW
            )
            .is_err()
        );
        let mut wrong = body.clone();
        let mut corrupt = signed.clone();
        corrupt[1] ^= 1;
        wrong["response_base64url"] = json!(encode_base64url(&corrupt));
        assert!(
            secondary_response(
                &mut db.write().unwrap(),
                &serde_json::to_vec(&wrong).unwrap(),
                NOW
            )
            .is_err()
        );
        assert!(
            secondary_response(
                &mut db.write().unwrap(),
                &serde_json::to_vec(&body).unwrap(),
                NOW + 300
            )
            .is_err()
        );
        let mut tx = db.write().unwrap();
        secondary_response(&mut tx, &serde_json::to_vec(&body).unwrap(), NOW).unwrap();
        tx.commit().unwrap();
        assert!(
            secondary_response(
                &mut db.write().unwrap(),
                &serde_json::to_vec(&body).unwrap(),
                NOW
            )
            .is_err()
        );
        let state: SecondaryState = get_json(
            &db.read().unwrap(),
            Collection::SecondaryStatus,
            &composite_key(&[
                "example.test.".parse::<WireName>().unwrap().as_slice(),
                b"192.0.2.53:53",
            ]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.in_sync(7, NOW, 300), !notify);
    }
}

#[test]
fn secondary_partial_batches_make_progress_and_rotate_past_fast_earlier_peers() {
    let db = database();
    let mut tx = db.write().unwrap();
    for index in 0..129 {
        let name = format!("key{index:03}.example.test.");
        let config = TransferConfiguration {
            key_name: name.clone(),
            endpoint: format!("127.0.0.1:{}", 10000 + index),
            zones: vec!["example.test.".into()],
            secret_sha256: sha256_hex(&[42; 32]),
            revoked: false,
        };
        put_json(
            &mut tx,
            Collection::Lifecycle,
            format!("governance/transfer/{name}").into_bytes(),
            &config,
        )
        .unwrap();
        let mut secret = secret();
        secret.key_name = name;
        provision_transfer_key(&mut tx, &serde_json::to_vec(&secret).unwrap()).unwrap();
    }
    let first = secondary_requests(&mut tx, b"{}", NOW).unwrap();
    let first = first.body["work"].as_array().unwrap();
    assert_eq!(first.len(), 256);
    // Model the first ten peers answering before the next scheduler tick.
    for item in first.iter().take(20) {
        tx.remove(
            Collection::Lifecycle,
            format!("secondary/pending/{}", item["id"].as_str().unwrap()).as_bytes(),
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let mut tx = db.write().unwrap();
    let next = secondary_requests(&mut tx, b"{}", NOW + 1).unwrap();
    let next = next.body["work"].as_array().unwrap();
    assert_eq!(next.len(), 24);
    assert_eq!(next[0]["endpoint"], "127.0.0.1:10128");
    assert!(next.iter().any(|item| item["endpoint"] == "192.0.2.53:53"));
    assert!(
        next.iter()
            .any(|item| item["endpoint"] == "127.0.0.1:10000")
    );
    tx.commit().unwrap();
    assert!(
        secondary_requests(&mut db.write().unwrap(), b"{}", NOW + 2)
            .unwrap()
            .body["work"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn doh_refuses_expired_signed_snapshots_and_noncanonical_queries() {
    let db = database();
    let packet = Message {
        header: Header {
            id: 31,
            flags: 0x0130, // RD, CD and untrusted query AD.
        },
        questions: vec![Question {
            name: "example.test.".parse().unwrap(),
            qtype: RecordType::Soa,
            qclass: RecordClass::In,
        }],
        ..Default::default()
    }
    .to_wire()
    .unwrap();
    let answer = doh(&db.read().unwrap(), "POST", "", &packet, NOW).unwrap();
    let answer = Message::parse(&answer).unwrap();
    assert_eq!(answer.header.flags & 15, 0);
    assert_eq!(answer.header.flags & 0x0030, 0x0010);
    let expired = doh(&db.read().unwrap(), "POST", "", &packet, NOW + 601).unwrap();
    let expired = Message::parse(&expired).unwrap();
    assert_eq!(expired.header.flags & 15, 2);
    assert_eq!(expired.header.flags & 0x0030, 0x0010);
    assert!(expired.answers.is_empty() && expired.authorities.is_empty());
    assert!(
        doh(
            &db.read().unwrap(),
            "GET",
            &format!(
                "dns={}&dns={}",
                encode_base64url(&packet),
                encode_base64url(&packet)
            ),
            &[],
            NOW
        )
        .is_err()
    );
    let mut unsupported = Message::parse(&packet).unwrap();
    unsupported.header.flags = 0x2130; // NOTIFY opcode, RD, CD, query AD.
    let error = Message::parse(
        &doh(
            &db.read().unwrap(),
            "POST",
            "",
            &unsupported.to_wire().unwrap(),
            NOW,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(error.header.opcode(), 4);
    assert_eq!(error.header.flags & 15, 4); // NOTIMP.
    assert_ne!(error.header.flags & 0x0100, 0);
    assert_eq!(error.header.flags & 0x0030, 0x0010);
    unsupported.questions[0].name = "outside.invalid.".parse().unwrap();
    let refused = Message::parse(
        &doh(
            &db.read().unwrap(),
            "POST",
            "",
            &unsupported.to_wire().unwrap(),
            NOW,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(refused.header.flags & 15, 5);
    assert_eq!(refused.header.opcode(), 4);
    assert_eq!(refused.header.flags & 0x0030, 0x0010);
}

#[test]
fn doh_ds_at_a_hosted_child_apex_uses_the_parent_zone() {
    let db = MemoryStorage::default();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"configuration".to_vec(),
        &ServiceConfiguration {
            audience: "ccf://test".into(),
            epoch: 1,
            last_time: NOW,
        },
    )
    .unwrap();
    for (id, text) in [(1, "example.test."), (2, "child.example.test.")] {
        let origin: WireName = text.parse().unwrap();
        let ns: WireName = format!("ns.{text}").parse().unwrap();
        let mut base_records = vec![
            ResourceRecord::new(
                origin,
                300,
                RData::Soa(SoaData {
                    mname: ns,
                    rname: format!("hostmaster.{text}").parse().unwrap(),
                    serial: 7,
                    refresh: 60,
                    retry: 30,
                    expire: 600,
                    minimum: 60,
                }),
            )
            .unwrap(),
            ResourceRecord::new(origin, 300, RData::Ns(ns)).unwrap(),
            ResourceRecord::new(ns, 300, RData::A("192.0.2.1".parse().unwrap())).unwrap(),
        ];
        if id == 1 {
            let child: WireName = "child.example.test.".parse().unwrap();
            base_records.push(ResourceRecord::new(child, 300, RData::Ns(ns)).unwrap());
            base_records.push(
                ResourceRecord::new(
                    child,
                    300,
                    RData::Ds(DsData {
                        key_tag: 123,
                        algorithm: 14,
                        digest_type: 2,
                        digest: vec![42; 32],
                    }),
                )
                .unwrap(),
            );
        }
        initialize_zone(
            &mut tx,
            ZoneMetadata {
                id: ZoneId(id),
                origin,
                serial: 7,
                base_records,
                signed_records: vec![],
                signature_validity: 600,
                refresh_before: 300,
                last_signed_at: 0,
                earliest_signature_expiration: 0,
                maintenance_health: "initializing".into(),
                ksk_dnskey_rdata: vec![],
                ksk_rollover: None,
            },
            NOW,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let packet = Message {
        header: Header { id: 55, flags: 0 },
        questions: vec![Question {
            name: "child.example.test.".parse().unwrap(),
            qtype: RecordType::Ds,
            qclass: RecordClass::In,
        }],
        ..Default::default()
    }
    .to_wire()
    .unwrap();
    let answer =
        Message::parse(&doh(&db.read().unwrap(), "POST", "", &packet, NOW).unwrap()).unwrap();
    assert!(answer.header.flags & 0x0400 != 0);
    assert!(
        answer
            .answers
            .iter()
            .any(|rr| matches!(&rr.rdata, RData::Ds(ds) if ds.key_tag == 123))
    );

    // Ordinary child apex data still comes from the child, and a child-only
    // authority returns its own apex DS NODATA as RFC 4035 requires.
    let mut ordinary = Message::parse(&packet).unwrap();
    ordinary.questions[0].qtype = RecordType::Soa;
    let ordinary = Message::parse(
        &doh(
            &db.read().unwrap(),
            "POST",
            "",
            &ordinary.to_wire().unwrap(),
            NOW,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(ordinary.answers[0].name.to_string(), "child.example.test.");
    let mut tx = db.write().unwrap();
    tx.remove(
        Collection::Zones,
        "example.test.".parse::<WireName>().unwrap().as_slice(),
    )
    .unwrap();
    tx.commit().unwrap();
    let child_only =
        Message::parse(&doh(&db.read().unwrap(), "POST", "", &packet, NOW).unwrap()).unwrap();
    assert!(child_only.answers.is_empty());
    assert_eq!(child_only.header.flags & 15, 0);
    assert!(
        child_only
            .authorities
            .iter()
            .any(|rr| rr.rtype == RecordType::Soa && rr.name.to_string() == "child.example.test.")
    );
}

#[test]
fn doh_rejects_a_missing_lifecycle_recovery_marker() {
    let db = database();
    let mut tx = db.write().unwrap();
    let marker_keys: Vec<_> = ReadTx::scan_prefix(&tx, Collection::Lifecycle, b"server/")
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    assert!(!marker_keys.is_empty());
    for key in marker_keys {
        tx.remove(Collection::Lifecycle, &key).unwrap();
    }
    tx.commit().unwrap();
    let packet = Message {
        questions: vec![Question {
            name: "example.test.".parse().unwrap(),
            qtype: RecordType::Soa,
            qclass: RecordClass::In,
        }],
        ..Default::default()
    }
    .to_wire()
    .unwrap();
    assert!(doh(&db.read().unwrap(), "POST", "", &packet, NOW).is_err());
}
#[test]
fn ksk_claims_bind_canonical_owner_and_complete_rdata_with_real_leaf_counter() {
    let db = database();
    let mut tx = db.write().unwrap();
    let first = ksk_receipt_claims(&mut tx, "zone=example.test.", NOW).unwrap();
    let owner: WireName = first.body["owner_name"].as_str().unwrap().parse().unwrap();
    let rdata = hex::decode(first.body["dnskey_rdata_hex"].as_str().unwrap()).unwrap();
    assert_eq!(first.claims_digest, Some(ksk_claims_digest(&owner, &rdata)));
    let mut altered = rdata;
    altered[4] ^= 1;
    assert_ne!(
        first.claims_digest,
        Some(ksk_claims_digest(&owner, &altered))
    );
    let second = ksk_receipt_claims(&mut tx, "zone=example.test.", NOW).unwrap();
    assert_eq!(first.claims_digest, second.claims_digest);
    assert_eq!(
        get_json::<u64>(&tx, Collection::Lifecycle, b"ksk-receipt-counter").unwrap(),
        Some(2)
    );
    assert!(ksk_receipt_claims(&mut tx, "zone=EXAMPLE.test.", NOW).is_err());
    assert!(query_pairs("zone=a&%7aone=b").is_err());
}
#[test]
fn receipt_reads_force_a_leaf_and_reject_unlisted_paths() {
    let db = database();
    let mut tx = db.write().unwrap();
    // The governed zone from database() has a KSK, so the anchors document has one zone entry.
    let anchors = receipt_read(&mut tx, "/governance/anchors", "", NOW).unwrap();
    assert_eq!(
        anchors.body["claims"]["type"],
        adns_server::anchors::ANCHORS_CLAIMS_TYPE
    );
    assert_eq!(anchors.body["claims"]["zones"][0]["zone"], "example.test.");
    assert!(anchors.body["claims"]["node_join_policy"].is_null());
    assert!(anchors.body["claims"]["release_authority"].is_null());
    assert_eq!(
        anchors.claims_digest,
        Some(
            adns_server::anchors::claims_digest(
                adns_server::anchors::ANCHORS_CLAIMS_TYPE,
                &anchors.body["claims"]
            )
            .unwrap()
        )
    );
    assert_eq!(
        get_json::<u64>(&tx, Collection::Lifecycle, b"receipt-counter").unwrap(),
        Some(1)
    );
    // Unknown anchor: NotFound, no counter bump.
    assert!(
        receipt_read(
            &mut tx,
            "/service/anchor",
            "registration_id=none&subject=x",
            NOW
        )
        .is_err()
    );
    assert_eq!(
        get_json::<u64>(&tx, Collection::Lifecycle, b"receipt-counter").unwrap(),
        Some(1)
    );
    // Non-receipt paths are not served here even though read_json knows them.
    assert!(receipt_read(&mut tx, "/zone/status", "zone=example.test.", NOW).is_err());
    assert!(receipt_read(&mut tx, "/governance/anchors", "zone=example.test.", NOW).is_err());
}
#[test]
fn governed_ksk_rollover_command_is_drained_by_maintenance_and_visible_in_receipt() {
    let db = database();
    let origin: WireName = "example.test.".parse().unwrap();
    let mut tx = db.write().unwrap();
    put_json(
        &mut tx,
        Collection::Lifecycle,
        b"governance/ksk-rollover/example.test.".to_vec(),
        &json!({"zone": "example.test.", "command": "start", "minimum_hold_seconds": 600}),
    )
    .unwrap();
    let changed = governed_maintenance(&mut tx, NOW + 1).unwrap();
    assert!(changed.contains(&"example.test.".to_string()));
    assert!(
        tx.get(
            Collection::Lifecycle,
            b"governance/ksk-rollover/example.test."
        )
        .unwrap()
        .is_none(),
        "command consumed"
    );
    let receipt = ksk_receipt_claims(&mut tx, "zone=example.test.", NOW + 1).unwrap();
    assert_eq!(receipt.body["rollover"]["stage"], "double-signature");
    let next_tag = receipt.body["rollover"]["next_key_tag"].as_u64().unwrap();
    assert_ne!(next_tag, receipt.body["key_tag"].as_u64().unwrap());
    // Claims still bind the current KSK only (verifiers of the v1 receipt are unaffected).
    let rdata = hex::decode(receipt.body["dnskey_rdata_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        receipt.claims_digest,
        Some(ksk_claims_digest(&origin, &rdata))
    );
    // A bad completion command fails maintenance loudly instead of being dropped.
    put_json(&mut tx, Collection::Lifecycle, b"governance/ksk-rollover/example.test.".to_vec(),
        &json!({"zone": "example.test.", "command": "complete", "new_key_tag": next_tag, "new_ds_sha256": "00".repeat(32)})).unwrap();
    assert!(governed_maintenance(&mut tx, NOW + 700).is_err());
}
