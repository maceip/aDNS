use adns_dnssec::*;
use adns_wire::*;
use base64::{Engine, engine::general_purpose::STANDARD};
fn n(s: &str) -> WireName {
    s.parse().unwrap()
}
fn rr(name: &str, data: RData) -> ResourceRecord {
    ResourceRecord::new(n(name), 300, data).unwrap()
}
fn records() -> Vec<ResourceRecord> {
    vec![
        rr(
            "example.",
            RData::Soa(SoaData {
                mname: n("ns.example."),
                rname: n("hostmaster.example."),
                serial: 42,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            }),
        ),
        rr("example.", RData::Ns(n("ns.example."))),
        rr("ns.example.", RData::A("192.0.2.53".parse().unwrap())),
        rr("mail.example.", RData::A("192.0.2.1".parse().unwrap())),
        rr(
            "example.",
            RData::Mx(MxData {
                preference: 10,
                exchange: n("mail.example."),
            }),
        ),
        rr("leaf.ent.example.", RData::Txt(vec![b"deep".to_vec()])),
        rr("*.wild.example.", RData::A("192.0.2.2".parse().unwrap())),
    ]
}
fn zone(mode: DenialMode) -> SignedZone {
    SignedZone::sign(
        n("example."),
        records(),
        &SigningKey::generate().unwrap(),
        1800000000,
        86400,
        mode,
    )
    .unwrap()
}
#[test]
fn rfc6605_p384_key_tag_ds_and_signature_vector() {
    let key = DnskeyData {
        flags: 257,
        protocol: 3,
        algorithm: 14,
        public_key: STANDARD
            .decode(concat!(
                "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1",
                "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8",
                "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"
            ))
            .unwrap(),
    };
    assert_eq!(
        key_tag(&RData::Dnskey(key.clone()).to_wire().unwrap()),
        10771
    );
    assert_eq!(
        hex_encode(&ds(&n("example.net."), &key, 4).unwrap().digest),
        "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6"
    );
    let a = ResourceRecord::new(
        n("www.example.net."),
        3600,
        RData::A("192.0.2.1".parse().unwrap()),
    )
    .unwrap();
    let sig = RrsigData {
        type_covered: RecordType::A,
        algorithm: 14,
        labels: 3,
        original_ttl: 3600,
        expiration: 1284027625,
        inception: 1281608425,
        key_tag: 10771,
        signer_name: n("example.net."),
        signature: STANDARD
            .decode(concat!(
                "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP",
                "95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz",
                "WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"
            ))
            .unwrap(),
    };
    verify_rrset(&[a], &sig, &key, 1282000000).unwrap();
}
#[test]
fn rfc5155_hash_vectors_and_limits() {
    let salt = hex_decode("aabbccdd").unwrap();
    assert_eq!(
        base32hex_encode(&nsec3_hash(&n("example."), 12, &salt).unwrap()),
        "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"
    );
    assert_eq!(
        base32hex_encode(&nsec3_hash(&n("a.example."), 12, &salt).unwrap()),
        "35MTHGPGCU1QG68FAB165KLNSNK3DPVL"
    );
    assert!(nsec3_hash(&n("example."), 251, &salt).is_err());
}
#[test]
fn live_signing_all_rrsets_and_key_persistence() {
    let ksk = SigningKey::generate().unwrap();
    let zsk = SigningKey::generate().unwrap();
    let restored = SigningKey::from_pkcs8(ksk.pkcs8()).unwrap();
    assert_eq!(restored.dnskey(257), ksk.dnskey(257));
    let z = SignedZone::sign_with_keys(
        n("example."),
        records(),
        &ksk,
        &zsk,
        1800000000,
        86400,
        DenialMode::default(),
    )
    .unwrap();
    for rr in &z.records {
        if let RData::Rrsig(s) = &rr.rdata {
            let set: Vec<_> = z
                .records
                .iter()
                .filter(|r| r.name == rr.name && r.rtype == s.type_covered)
                .cloned()
                .collect();
            let key = if s.type_covered == RecordType::Dnskey {
                ksk.dnskey(257)
            } else {
                zsk.dnskey(256)
            };
            verify_rrset(&set, s, &key, 1800000000).unwrap();
            let mut altered = set.clone();
            altered[0].name = n("different.example.");
            assert!(verify_rrset(&altered, s, &key, 1800000000).is_err());
            assert!(verify_rrset(&set, s, &key, 1800086401).is_err());
        }
    }
}
#[test]
fn nsec3_nxdomain_proves_closest_next_and_wildcard() {
    let z = zone(DenialMode::default());
    let q = n("a.b.ent.example.");
    let p = z.synthesize_nxdomain_proof(&q).unwrap();
    assert_eq!(
        z.find_closest_encloser(&q).unwrap(),
        (n("ent.example."), n("b.ent.example."))
    );
    let check_cover = |rr: &ResourceRecord, name: WireName| {
        let RData::Nsec3(data) = &rr.rdata else {
            panic!()
        };
        let owner =
            base32hex_decode(std::str::from_utf8(rr.name.labels().next().unwrap()).unwrap())
                .unwrap();
        let h = nsec3_hash(&name, 0, &[]).unwrap().to_vec();
        assert!(covers(&owner, &data.next_hashed_owner, &h));
    };
    check_cover(&p.next_closer_nsec3, n("b.ent.example."));
    check_cover(&p.wildcard_nsec3.unwrap().0, n("*.ent.example."));
    assert_eq!(
        p.closest_encloser_nsec3.name,
        n("example.")
            .prepend_label(
                base32hex_encode(&nsec3_hash(&n("ent.example."), 0, &[]).unwrap()).as_bytes()
            )
            .unwrap()
    );
}
#[test]
fn both_denial_modes_cover_nodata_empty_nonterminals_and_wildcards() {
    for mode in [DenialMode::Nsec, DenialMode::default()] {
        let z = zone(mode);
        assert_eq!(
            z.resolve(&n("absent.example."), RecordType::A, true).rcode,
            3
        );
        let ent = z.resolve(&n("ent.example."), RecordType::A, true);
        assert_eq!(ent.rcode, 0);
        assert!(!ent.authorities.is_empty());
        let nodata = z.resolve(&n("mail.example."), RecordType::Aaaa, true);
        assert_eq!(nodata.rcode, 0);
        assert!(nodata.answers.is_empty());
        let wildcard = z.resolve(&n("x.y.wild.example."), RecordType::A, true);
        assert_eq!(wildcard.rcode, 0);
        assert_eq!(wildcard.answers.len(), 2);
        assert!(!wildcard.authorities.is_empty());
        let missing = z.resolve(&n("x.wild.example."), RecordType::Txt, true);
        assert_eq!(missing.rcode, 0);
        assert!(missing.answers.is_empty());
        assert!(z.synthesize_nxdomain_proof(&n("x.wild.example.")).is_err());
        let positive = z.resolve(&n("mail.example."), RecordType::A, true);
        assert!(matches!(positive.answers, std::borrow::Cow::Borrowed(_)));
    }
}
#[test]
fn wildcard_signatures_verify_synthesized_owner() {
    let z = zone(DenialMode::default());
    let response = z.resolve(&n("foo.bar.wild.example."), RecordType::A, true);
    let key = z
        .records
        .iter()
        .find_map(|rr| {
            if let RData::Dnskey(k) = &rr.rdata {
                Some(k)
            } else {
                None
            }
        })
        .unwrap();
    let sig = response
        .answers
        .iter()
        .find_map(|rr| {
            if let RData::Rrsig(s) = &rr.rdata {
                Some(s)
            } else {
                None
            }
        })
        .unwrap();
    let answers: Vec<_> = response
        .answers
        .iter()
        .filter(|r| r.rtype == RecordType::A)
        .cloned()
        .collect();
    verify_rrset(&answers, sig, key, 1800000000).unwrap();
}
#[test]
fn immutable_snapshot_rehydration() {
    for mode in [DenialMode::Nsec, DenialMode::default()] {
        let z = zone(mode);
        let snapshot = SignedZone::from_signed_records(z.origin, z.records.clone()).unwrap();
        assert_eq!(snapshot.records, z.records);
        assert_eq!(snapshot.serial, z.serial);
        assert_eq!(snapshot.expiration, z.expiration);
        assert_eq!(
            snapshot
                .resolve(&n("missing.example."), RecordType::A, true)
                .authorities,
            z.resolve(&n("missing.example."), RecordType::A, true)
                .authorities
        );
        let mut invalid = z.records.clone();
        invalid.retain(|r| r.rtype != RecordType::Rrsig);
        assert!(SignedZone::from_signed_records(z.origin, invalid).is_err());
    }
}
#[test]
fn delegation_referral_glue_and_ds_nodata() {
    for mode in [DenialMode::Nsec, DenialMode::default()] {
        let mut r = records();
        r.extend([
            rr("child.example.", RData::Ns(n("ns.child.example."))),
            rr("ns.child.example.", RData::A("192.0.2.80".parse().unwrap())),
        ]);
        let z = SignedZone::sign(
            n("example."),
            r,
            &SigningKey::generate().unwrap(),
            1800000000,
            86400,
            mode,
        )
        .unwrap();
        let referral = z.resolve(&n("www.child.example."), RecordType::A, true);
        assert!(!referral.authoritative);
        assert!(
            referral
                .authorities
                .iter()
                .any(|r| r.rtype == RecordType::Ns)
        );
        assert_eq!(referral.additionals.len(), 1);
        let ds = z.resolve(&n("child.example."), RecordType::Ds, true);
        assert!(ds.authoritative);
        assert_eq!(ds.rcode, 0);
        assert!(!ds.authorities.is_empty());
    }
}
#[test]
fn tlsa_key_overlap_and_scoped_withdrawal() {
    let mut overlap = TlsaOverlap::default();
    overlap
        .add("old", &n("mail.example."), &[25, 465, 993], [1; 32])
        .unwrap();
    overlap
        .add("new", &n("mail.example."), &[25, 465, 993], [2; 32])
        .unwrap();
    assert_eq!(overlap.records(300).len(), 6);
    overlap.withdraw("old", Some(&[n("_25._tcp.mail.example.")]));
    assert_eq!(overlap.records(300).len(), 5);
    overlap.withdraw("old", None);
    assert_eq!(overlap.records(300).len(), 3);
}
#[test]
fn invalid_zones_and_rrset_ttl_mismatch_rejected() {
    let key = SigningKey::generate().unwrap();
    let mut r = records();
    r.push(rr("mail.example.", RData::Cname(n("other.example."))));
    assert!(SignedZone::sign(n("example."), r, &key, 1800000000, 86400, DenialMode::Nsec).is_err());
    let mut r = records();
    let mut duplicate = r[3].clone();
    duplicate.ttl += 1;
    r.push(duplicate);
    assert!(SignedZone::sign(n("example."), r, &key, 1800000000, 86400, DenialMode::Nsec).is_err());
}

#[test]
fn any_returns_real_rrset_and_multiple_signatures_are_filtered() {
    let z = zone(DenialMode::default());
    for name in [n("mail.example."), n("x.wild.example.")] {
        let response = z.resolve(&name, RecordType::Any, true);
        assert_eq!(response.rcode, 0);
        assert!(!response.answers.is_empty());
        assert!(response.answers.iter().any(|r| r.rtype == RecordType::A));
    }
    let mut records = z.records.clone();
    let mut duplicate = records
        .iter()
        .find(|r| r.name == n("mail.example.") && r.rtype == RecordType::Rrsig)
        .unwrap()
        .clone();
    if let RData::Rrsig(s) = &mut duplicate.rdata {
        s.inception += 100;
    }
    records.push(duplicate);
    let restored = SignedZone::from_signed_records(z.origin, records).unwrap();
    assert_eq!(restored.inception, z.inception + 100);
    let response = restored.resolve(&n("mail.example."), RecordType::A, false);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].rtype, RecordType::A);
}
#[test]
fn exact_positive_resolution_allocates_zero_bytes() {
    let z = zone(DenialMode::default());
    let name = n("mail.example.");
    let info = allocation_counter::measure(|| {
        for _ in 0..1000 {
            let answer = z.resolve(&name, RecordType::A, true);
            assert_eq!(answer.answers.len(), 2);
            std::hint::black_box(answer);
        }
    });
    assert_eq!(info.count_total, 0);
    assert_eq!(info.bytes_total, 0);
}
