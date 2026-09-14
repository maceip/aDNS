use adns_wire::{RData, ResourceRecord, WireName};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::Ipv4Addr;

fn records() -> Vec<ResourceRecord> {
    let origin: WireName = "example.".parse().unwrap();
    let soa = ResourceRecord::new(
        origin,
        300,
        RData::Soa(adns_wire::SoaData {
            mname: "ns1.example.".parse().unwrap(),
            rname: "hostmaster.example.".parse().unwrap(),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        }),
    )
    .unwrap();
    let a = ResourceRecord::new(origin, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap();
    vec![soa, a]
}

fn bench_name_parse(c: &mut Criterion) {
    c.bench_function("wire/name_from_ascii", |b| {
        b.iter(|| WireName::from_ascii(black_box("www.example.")))
    });
    let name: WireName = "www.example.".parse().unwrap();
    let wire = name.as_slice().to_vec();
    c.bench_function("wire/name_parse_wire", |b| {
        b.iter(|| {
            let mut off = 0;
            WireName::parse_wire(black_box(&wire), &mut off)
        })
    });
}

fn bench_canonical_wire(c: &mut Criterion) {
    let recs = records();
    c.bench_function("wire/canonical_rr", |b| {
        b.iter(|| black_box(&recs[1]).canonical_wire())
    });
}

criterion_group!(benches, bench_name_parse, bench_canonical_wire);
criterion_main!(benches);
