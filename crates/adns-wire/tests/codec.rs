use adns_wire::*;
fn n(s: &str) -> WireName {
    s.parse().unwrap()
}
#[test]
fn canonical_names_and_rfc4034_order() {
    let expected = [
        "example.",
        "a.example.",
        "yljkjljk.a.example.",
        "Z.a.example.",
        "zABC.a.EXAMPLE.",
        "z.example.",
        "\\001.z.example.",
        "*.z.example.",
        "\\200.z.example.",
    ];
    let names: Vec<_> = expected.iter().map(|s| n(s)).collect();
    let mut reversed = names.iter().rev().copied().collect::<Vec<_>>();
    reversed.sort();
    assert_eq!(reversed, names);
    assert_eq!(n("MiXeD.EXAMPLE"), n("mixed.example."));
    assert!(n("x.example.").is_subdomain_of(&n("example.")));
    assert!(!n("badexample.").is_subdomain_of(&n("example.")));
    for name in names {
        assert_eq!(name, n(&name.to_string()));
        assert_eq!(
            serde_json::from_str::<WireName>(&serde_json::to_string(&name).unwrap()).unwrap(),
            name
        );
    }
}
#[test]
fn name_limits_and_binary_labels() {
    let max = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(n(&max).as_slice().len(), 255);
    assert!(WireName::from_ascii(&(max + "e.")).is_err());
    assert!(WireName::from_ascii(&"a".repeat(64)).is_err());
    assert!(WireName::from_ascii("a..b").is_err());
    assert!(WireName::from_ascii("é.example.").is_err());
    assert!(WireName::from_ascii("\\999.").is_err());
    let name = n("\\000.\\255.\\046.\\092.");
    let mut offset = 0;
    assert_eq!(
        WireName::parse_wire(name.as_slice(), &mut offset).unwrap(),
        name
    );
    let many = vec!["a"; 127].join(".");
    assert_eq!(n(&many).label_count(), 127);
}
#[test]
fn pointer_loops_and_exact_depth_limit() {
    for bytes in [&[0xc0, 0][..], &[0xc0, 2, 0xc0, 0][..]] {
        let mut pos = 0;
        assert_eq!(
            WireName::parse_wire(bytes, &mut pos),
            Err(DnsError::CompressionLoop)
        );
        assert_eq!(pos, 0);
    }
    for hops in [10, 11] {
        let mut packet = Vec::new();
        for i in 0..hops {
            packet.extend([0xc0, (2 * (i + 1)) as u8]);
        }
        packet.push(0);
        let mut pos = 0;
        assert_eq!(WireName::parse_wire(&packet, &mut pos).is_ok(), hops == 10);
    }
    for bytes in [
        &[0x40][..],
        &[0x80][..],
        &[0xc0][..],
        &[0xc0, 255][..],
        &[3, b'a'][..],
    ] {
        assert!(WireName::parse_wire(bytes, &mut 0).is_err());
    }
}
fn data() -> Vec<RData> {
    vec![
        RData::A("192.0.2.1".parse().unwrap()),
        RData::Aaaa("2001:db8::1".parse().unwrap()),
        RData::Ns(n("ns.example.")),
        RData::Cname(n("mail.example.")),
        RData::Soa(SoaData {
            mname: n("ns.example."),
            rname: n("hostmaster.example."),
            serial: u32::MAX,
            refresh: 300,
            retry: 60,
            expire: 86400,
            minimum: 30,
        }),
        RData::Mx(MxData {
            preference: 10,
            exchange: n("mail.example."),
        }),
        RData::Txt(vec![vec![], vec![255; 255]]),
        RData::Tlsa(TlsaData {
            usage: 3,
            selector: 1,
            matching_type: 1,
            certificate_association_data: vec![1; 32],
        }),
        RData::Dnskey(DnskeyData {
            flags: 257,
            protocol: 3,
            algorithm: 14,
            public_key: vec![2; 96],
        }),
        RData::Rrsig(RrsigData {
            type_covered: RecordType::A,
            algorithm: 14,
            labels: 2,
            original_ttl: 300,
            expiration: 10000,
            inception: 1000,
            key_tag: 23,
            signer_name: n("example."),
            signature: vec![3; 96],
        }),
        RData::Nsec(NsecData {
            next_domain_name: n("z.example."),
            types: vec![
                RecordType::A,
                RecordType::Rrsig,
                RecordType::Nsec,
                RecordType::Caa,
            ],
        }),
        RData::Nsec3(Nsec3Data {
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![1, 2],
            next_hashed_owner: vec![0; 20],
            types: vec![RecordType::A, RecordType::Caa],
        }),
        RData::Nsec3Param(Nsec3ParamData {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        }),
        RData::Caa(CaaData {
            flags: 0,
            tag: b"issue".to_vec(),
            value: b"letsencrypt.org".to_vec(),
        }),
    ]
}
#[test]
fn all_typed_records_roundtrip_compression_and_bounds() {
    let mut m = Message {
        header: Header {
            id: 123,
            flags: 0x8400,
        },
        questions: vec![Question {
            name: n("example."),
            qtype: RecordType::Any,
            qclass: RecordClass::In,
        }],
        answers: data()
            .into_iter()
            .map(|d| ResourceRecord::new(n("example."), 300, d).unwrap())
            .collect(),
        ..Message::default()
    };
    m.additionals.push(ResourceRecord {
        name: WireName::root(),
        rclass: RecordClass::Unknown(1232),
        rtype: RecordType::Opt,
        ttl: 0x8000,
        rdata: RData::Opt(OptData {
            options: vec![EdnsOption {
                code: 12,
                data: vec![0; 13],
            }],
        }),
    });
    let wire = m.to_wire().unwrap();
    assert!(wire.len() < m.to_wire_uncompressed().unwrap().len());
    assert_eq!(Message::parse(&wire).unwrap(), m);
    for end in 0..wire.len() {
        assert!(Message::parse(&wire[..end]).is_err(), "truncation {end}");
    }
    let mut trailing = wire;
    trailing.push(0);
    assert!(Message::parse(&trailing).is_err());
    let mut bad = m.clone();
    bad.additionals.push(bad.additionals[0].clone());
    assert!(Message::parse(&bad.to_wire().unwrap()).is_err());
}
#[test]
fn short_rdata_and_edns_rejected() {
    for (rtype, rdata) in [
        (52, vec![]),
        (52, vec![3, 1]),
        (41, vec![0, 12, 0, 4, 0]),
        (16, vec![3, 1]),
        (257, vec![0, 0]),
    ] {
        let mut w = PacketWriter::new(false);
        w.name(&n(".")).unwrap();
        w.u16(rtype).unwrap();
        w.u16(1).unwrap();
        w.u32(0).unwrap();
        w.u16(rdata.len() as u16).unwrap();
        w.bytes(&rdata).unwrap();
        assert!(PacketReader::new(&w.into_bytes()).record().is_err());
    }
    let mut header = vec![0; 12];
    header[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(Message::parse(&header).is_err());
}
#[test]
fn compression_dictionary_does_not_create_deep_chains() {
    let mut m = Message::default();
    let mut name = n("example.");
    for _ in 0..90 {
        name = name.prepend_label(b"a").unwrap();
        m.questions.push(Question {
            name,
            qtype: RecordType::A,
            qclass: RecordClass::In,
        });
    }
    assert_eq!(Message::parse(&m.to_wire().unwrap()).unwrap(), m);
}
#[test]
fn bitmap_windows_and_malformed_input() {
    let types = vec![RecordType::A, RecordType::Caa, RecordType::Unknown(65535)];
    assert_eq!(parse_type_bitmap(&type_bitmap(&types)).unwrap(), types);
    for bad in [
        vec![0, 0],
        vec![0, 33],
        vec![0, 1, 0],
        vec![1, 1, 1, 0, 1, 1],
        vec![1, 1, 1, 1, 1, 1],
    ] {
        assert!(parse_type_bitmap(&bad).is_err());
    }
}
#[test]
fn encoders_rfc4648_vectors_and_padding() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "CO"),
        ("fo", "CPNG"),
        ("foo", "CPNMU"),
        ("foob", "CPNMUOG"),
        ("fooba", "CPNMUOJ1"),
        ("foobar", "CPNMUOJ1E8"),
    ] {
        assert_eq!(base32hex_encode(plain.as_bytes()), encoded);
        assert_eq!(base32hex_decode(encoded).unwrap(), plain.as_bytes());
    }
    for bad in ["A", "CP", "CP=", "CO======", "WW"] {
        assert!(base32hex_decode(bad).is_err());
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(hex_decode(&hex_encode(&all)).unwrap(), all);
    assert!(hex_decode("0x").is_err());
    assert!(hex_decode("f").is_err());
}
#[test]
fn bounded_adversarial_packet_sweep() {
    let mut state = 0x48203174u64;
    for len in 0..1024 {
        let mut packet = vec![0; len];
        for b in &mut packet {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        let _ = Message::parse(&packet);
        let _ = WireName::parse_wire(&packet, &mut 0);
    }
}

#[test]
fn record_code_eq_ord_and_hash_agree() {
    use std::collections::{BTreeSet, HashSet};
    assert_eq!(RecordType::A, RecordType::Unknown(1));
    assert_eq!(RecordClass::In, RecordClass::Unknown(1));
    assert_eq!(
        BTreeSet::from([RecordType::A, RecordType::Unknown(1)]).len(),
        1
    );
    assert_eq!(
        HashSet::from([RecordType::A, RecordType::Unknown(1)]).len(),
        1
    );
}
#[test]
fn borrowed_typed_rdata_and_names_allocate_zero_bytes() {
    let records = data();
    let wires: Vec<_> = records
        .into_iter()
        .map(|d| {
            ResourceRecord::new(n("example."), 300, d)
                .unwrap()
                .canonical_wire()
                .unwrap()
        })
        .collect();
    let packet = n("foo.bar.example.").as_slice().to_vec();
    let info = allocation_counter::measure(|| {
        for wire in &wires {
            let mut reader = PacketReader::new(wire);
            let view = reader.record_view().unwrap();
            let typed = view.typed().unwrap();
            if let RDataRef::Txt(strings) = &typed {
                assert_eq!(strings.iter().count(), 2);
            }
            std::hint::black_box(typed);
        }
        for _ in 0..1000 {
            let mut offset = 0;
            let name = WireName::parse_wire(&packet, &mut offset).unwrap();
            std::hint::black_box(name.parent());
        }
    });
    assert_eq!(info.count_total, 0);
    assert_eq!(info.bytes_total, 0);
}

#[test]
fn svcb_rfc9460_roundtrip_and_uncompressed_target() {
    let s = SvcbData::from_tokens(
        &[
            "1",
            "svc.example.",
            "mandatory=alpn,port",
            "alpn=h2,h3",
            "port=8443",
            "ipv4hint=192.0.2.1",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    let rr = ResourceRecord::new(n("_svc.example."), 300, RData::Svcb(s)).unwrap();
    assert_eq!(rr.rtype.code(), 64);
    let raw = rr.rdata.to_wire().unwrap();
    assert_eq!(
        &raw[..15],
        &[
            0, 1, 3, b's', b'v', b'c', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0
        ]
    );
    let mut w = PacketWriter::new(true);
    w.record(&rr).unwrap();
    w.record(&rr).unwrap();
    let bytes = w.into_bytes();
    let mut reader = PacketReader::new(&bytes);
    assert_eq!(reader.record().unwrap(), rr);
    let view = reader.record_view().unwrap();
    assert!(matches!(
        view.typed().unwrap(),
        RDataRef::Svcb { priority: 1, .. }
    ));
    assert_eq!(view.to_owned().unwrap(), rr);
    // RFC 9460 Appendix D alias example.
    let alias = SvcbData::from_tokens(&["0".into(), "foo.example.com.".into()]).unwrap();
    assert_eq!(
        hex_encode(&RData::Svcb(alias).to_wire().unwrap()),
        "000003666f6f076578616d706c6503636f6d00"
    );
    SvcbData::from_tokens(&["0".into(), ".".into()]).unwrap();
}
#[test]
fn svcb_rejects_duplicate_unsorted_mandatory_bad_values_and_compression() {
    for tokens in [
        vec!["1", ".", "alpn=h2", "alpn=h3"],
        vec!["1", ".", "port=443", "alpn=h2"],
        vec!["1", ".", "mandatory=port", "alpn=h2"],
        vec!["1", ".", "no-default-alpn"],
        vec!["1", ".", "key3=ff"],
        vec!["1", ".", "alpn="],
        vec!["1", ".", "ipv4hint=::1"],
        vec!["0", "svc.example.", "port=443"],
        vec!["1", ".", "key65535="],
    ] {
        assert!(
            SvcbData::from_tokens(&tokens.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .is_err()
        );
    }
    let mut w = PacketWriter::new(false);
    // TargetName points to owner, prohibited even when the pointer is well formed.
    let rr = ResourceRecord {
        name: n("example."),
        rclass: RecordClass::In,
        rtype: RecordType::Svcb,
        ttl: 300,
        rdata: RData::Unknown(vec![0, 1, 0xc0, 0]),
    };
    w.record(&rr).unwrap();
    let bytes = w.into_bytes();
    assert!(PacketReader::new(&bytes).record().is_err());
    // All malformed lengths must return errors, including through the borrowed API.
    let good = SvcbData::from_tokens(&["1", ".", "port=443"].map(str::to_owned)).unwrap();
    let data = RData::Svcb(good).to_wire().unwrap();
    for end in [0, 1, 2, 4, 5, 6, 7, 8] {
        let mut w = PacketWriter::new(false);
        let mut bad = rr.clone();
        bad.rdata = RData::Unknown(data[..end].to_vec());
        w.record(&bad).unwrap();
        let bytes = w.into_bytes();
        let mut r = PacketReader::new(&bytes);
        let view = r.record_view().unwrap();
        assert!(view.to_owned().is_err());
        assert!(view.typed().is_err());
    }
}

#[test]
fn svcb_target_case_is_preserved_for_dnssec_rfc3597() {
    let lower =
        SvcbData::from_tokens(&["1", "svc.example.", "port=443"].map(str::to_owned)).unwrap();
    let mut mixed = lower.clone();
    mixed.target[1] = b'S';
    let rr = ResourceRecord::new(n("example."), 300, RData::Svcb(mixed)).unwrap();
    let mut w = PacketWriter::new(false);
    w.record(&rr).unwrap();
    let bytes = w.into_bytes();
    let decoded = PacketReader::new(&bytes).record().unwrap();
    assert_eq!(decoded, rr);
    assert_ne!(
        decoded.rdata.to_wire().unwrap(),
        RData::Svcb(lower).to_wire().unwrap()
    );
    assert_eq!(
        decoded.canonical_wire().unwrap(),
        rr.canonical_wire().unwrap()
    );
}
