use adns_dnssec::SignedZone;
use adns_wire::*;
/// Select one immutable hosted zone for an authoritative DNS question.
/// RFC 4035 section 3.1.4.1 places DS data on the parent side of a cut even
/// when this authority also hosts the child. A child-only authority still
/// returns its apex NODATA response, and ordinary questions prefer the child.
pub fn select_query_zone(
    zones: impl IntoIterator<Item = crate::ZoneMetadata>,
    question: &Question,
) -> Option<crate::ZoneMetadata> {
    zones
        .into_iter()
        .filter(|zone| question.name.is_subdomain_of(&zone.origin))
        .map(|zone| {
            let parent_ds = question.qtype == RecordType::Ds
                && question.name != zone.origin
                && zone
                    .signed_records
                    .iter()
                    .any(|record| record.name == question.name && record.rtype == RecordType::Ns);
            (parent_ds, zone.origin.label_count(), zone)
        })
        .max_by_key(|(parent_ds, labels, _)| (*parent_ds, *labels))
        .map(|(_, _, zone)| zone)
}

/// RFC 8484 DNS message handler using an immutable, already signed snapshot.
pub fn answer_query(zone: &SignedZone, packet: &[u8]) -> Result<Vec<u8>, DnsError> {
    let query = Message::parse(packet)?;
    if query.header.is_response() {
        return Err(DnsError::InvalidPacket);
    }
    let mut response = Message {
        header: Header {
            id: query.header.id,
            // Echo OPCODE/RD and RFC 4035 section 3's CD; never copy AD.
            flags: 0x8000 | (query.header.flags & 0x7910),
        },
        questions: query.questions.clone(),
        ..Message::default()
    };
    if query.questions.len() != 1 || !query.answers.is_empty() || !query.authorities.is_empty() {
        response.header.flags |= 1;
        return response.to_wire();
    }
    if query.header.opcode() != 0 {
        response.header.flags |= 4;
        return response.to_wire();
    }
    let q = &query.questions[0];
    let opt = query
        .additionals
        .iter()
        .find(|r| r.rtype == RecordType::Opt);
    let dnssec = opt.is_some_and(|r| r.ttl & 0x8000 != 0);
    if let Some(opt) = opt {
        let version = (opt.ttl >> 16) & 255;
        response.additionals.push(ResourceRecord {
            name: WireName::root(),
            rclass: RecordClass::Unknown(1232),
            rtype: RecordType::Opt,
            ttl: if version != 0 {
                1 << 24
            } else if dnssec {
                0x8000
            } else {
                0
            },
            rdata: RData::Opt(OptData::default()),
        });
        if version != 0 {
            return response.to_wire();
        }
    }
    if q.qclass != RecordClass::In || matches!(q.qtype, RecordType::Axfr | RecordType::Ixfr) {
        response.header.flags |= 5;
        return response.to_wire();
    }
    let resolved = zone.resolve(&q.name, q.qtype, dnssec);
    response.header.flags |= u16::from(resolved.rcode);
    if resolved.authoritative {
        response.header.flags |= 0x0400;
    }
    response.answers = resolved.answers.into_owned();
    response.authorities = resolved.authorities;
    response.additionals.extend(resolved.additionals);
    response.to_wire()
}
