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
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "/tmp/agentdns-wire-validation".into()),
    );
    fs::create_dir_all(&path)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let records = vec![
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
        rr("ns.example.", RData::A("192.0.2.53".parse()?)),
        rr("mail.example.", RData::A("192.0.2.1".parse()?)),
        rr("mail.example.", RData::Aaaa("2001:db8::1".parse()?)),
        rr(
            "example.",
            RData::Mx(MxData {
                preference: 10,
                exchange: n("mail.example."),
            }),
        ),
        rr("leaf.ent.example.", RData::Txt(vec![b"deep".to_vec()])),
        rr("*.wild.example.", RData::A("192.0.2.2".parse()?)),
        rr("alias.example.", RData::Cname(n("mail.example."))),
        rr("child.example.", RData::Ns(n("ns.child.example."))),
        rr("ns.child.example.", RData::A("192.0.2.80".parse()?)),
        rr(
            "example.",
            RData::Caa(CaaData {
                flags: 0,
                tag: b"issue".to_vec(),
                value: b"letsencrypt.org".to_vec(),
            }),
        ),
    ];
    for (name, mode) in [("nsec", DenialMode::Nsec), ("nsec3", DenialMode::default())] {
        let ksk = SigningKey::generate()?;
        let zsk = SigningKey::generate()?;
        let zone = SignedZone::sign_with_keys(
            n("example."),
            records.clone(),
            &ksk,
            &zsk,
            now,
            86400,
            mode,
        )?;
        fs::write(path.join(format!("{name}.zone")), zone.to_zone_file()?)?;
        let key = ResourceRecord::new(n("example."), 300, RData::Dnskey(ksk.dnskey(257)))?;
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
            ("dnskey", "example.", RecordType::Dnskey),
            ("ent-ds", "ent.example.", RecordType::Ds),
            ("any", "mail.example.", RecordType::Any),
            ("wildcard-any", "foo.wild.example.", RecordType::Any),
            ("nxdomain", "x.y.ent.example.", RecordType::A),
            ("nodata", "mail.example.", RecordType::Txt),
            ("ent", "ent.example.", RecordType::A),
            ("wildcard", "foo.bar.wild.example.", RecordType::A),
            ("wildcard-nodata", "foo.wild.example.", RecordType::Txt),
            ("ds-nodata", "child.example.", RecordType::Ds),
        ];
        for (case, owner, qtype) in cases {
            let qname = n(owner);
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
