use adns_dnssec::*;
use adns_wire::*;
use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
fn n(s: &str) -> WireName {
    s.parse().unwrap()
}
fn rr(name: &str, data: RData) -> ResourceRecord {
    ResourceRecord::new(n(name), 300, data).unwrap()
}
fn main() -> Result<(), Box<dyn Error>> {
    let mut rest = std::env::args().skip(1);
    if rest.next().as_deref() != Some("--caa-issuer") {
        return Err("usage: export --caa-issuer <registry-selected-domain> [output] [apex] [primary-ns] [extra-ns]".into());
    }
    let caa_issuer = rest.next().ok_or("missing --caa-issuer value")?;
    let _: WireName = caa_issuer.parse()?;
    let path = PathBuf::from(
        rest.next()
            .unwrap_or_else(|| "/tmp/agentdns-wire-validation".into()),
    );
    // Optional apex + NS names. Defaults reproduce the historical example
    // zone byte-for-byte; pass an empty extra NS for single-NS zones.
    let apex: String = rest.next().unwrap_or_else(|| "example.".into());
    let primary: String = rest.next().unwrap_or_else(|| format!("ns.{apex}"));
    let extra: String = rest.next().unwrap_or_else(|| format!("ns2.{apex}"));
    let fq = |label: &str| -> String {
        if label.is_empty() {
            apex.clone()
        } else {
            format!("{label}.{apex}")
        }
    };
    // Glue is only emitted for NS names inside the zone itself.
    let in_zone = |name: &str| -> bool { n(name).is_subdomain_of(&n(&apex)) && name != apex };
    fs::create_dir_all(&path)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let mut records = vec![
        rr(
            &apex,
            RData::Soa(SoaData {
                mname: n(&primary),
                rname: n(&fq("hostmaster")),
                serial: 42,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            }),
        ),
        rr(&apex, RData::Ns(n(&primary))),
    ];
    if !extra.is_empty() {
        records.push(rr(&apex, RData::Ns(n(&extra))));
    }
    if in_zone(&primary) {
        records.push(rr(&primary, RData::A("192.0.2.53".parse()?)));
    }
    if !extra.is_empty() && in_zone(&extra) {
        records.push(rr(&extra, RData::A("192.0.2.54".parse()?)));
    }
    records.extend([
        rr(&fq("mail"), RData::A("192.0.2.1".parse()?)),
        rr(&fq("mail"), RData::Aaaa("2001:db8::1".parse()?)),
        rr(
            &apex,
            RData::Mx(MxData {
                preference: 10,
                exchange: n(&fq("mail")),
            }),
        ),
        rr(&fq("leaf.ent"), RData::Txt(vec![b"deep".to_vec()])),
        rr(&fq("*.wild"), RData::A("192.0.2.2".parse()?)),
        rr(&fq("alias"), RData::Cname(n(&fq("mail")))),
        rr(&fq("child"), RData::Ns(n(&fq("ns.child")))),
        rr(&fq("ns.child"), RData::A("192.0.2.80".parse()?)),
        rr(
            &apex,
            RData::Caa(CaaData {
                flags: 0,
                tag: b"issue".to_vec(),
                value: caa_issuer.as_bytes().to_vec(),
            }),
        ),
    ]);
    for (name, mode) in [("nsec", DenialMode::Nsec), ("nsec3", DenialMode::default())] {
        let ksk = SigningKey::generate()?;
        let zsk = SigningKey::generate()?;
        let zone =
            SignedZone::sign_with_keys(n(&apex), records.clone(), &ksk, &zsk, now, 86400, mode)?;
        fs::write(path.join(format!("{name}.zone")), zone.to_zone_file()?)?;
        let key = ResourceRecord::new(n(&apex), 300, RData::Dnskey(ksk.dnskey(257)))?;
        fs::write(
            path.join(format!("{name}.key")),
            format!(
                "{} {} IN DNSKEY {}\n",
                key.name,
                key.ttl,
                rdata_text(&key.rdata)?
            ),
        )?;
        let cases = [
            ("dnskey", "", RecordType::Dnskey),
            ("ent-ds", "ent", RecordType::Ds),
            ("any", "mail", RecordType::Any),
            ("wildcard-any", "foo.wild", RecordType::Any),
            ("nxdomain", "x.y.ent", RecordType::A),
            ("nodata", "mail", RecordType::Txt),
            ("ent", "ent", RecordType::A),
            ("wildcard", "foo.bar.wild", RecordType::A),
            ("wildcard-nodata", "foo.wild", RecordType::Txt),
            ("ds-nodata", "child", RecordType::Ds),
        ];
        for (case, label, qtype) in cases {
            let qname = n(&fq(label));
            let r = zone.resolve(&qname, qtype, true);
            let m = Message {
                header: Header {
                    id: 1234,
                    flags: 0x8400 | u16::from(r.rcode),
                },
                questions: vec![Question {
                    name: qname,
                    qtype,
                    qclass: RecordClass::In,
                }],
                answers: r.answers.into_owned(),
                authorities: r.authorities,
                additionals: r.additionals,
            };
            fs::write(path.join(format!("{name}-{case}.wire")), m.to_wire()?)?;
        }
    }
    println!("{}", path.display());
    Ok(())
}
