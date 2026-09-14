use adns_dnssec::SigningKey;
use adns_wire::{RData, ResourceRecord, WireName};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::Ipv4Addr;

fn rrset(size: usize) -> (SigningKey, Vec<ResourceRecord>, WireName) {
    let key = SigningKey::generate().unwrap();
    let name: WireName = "host.example.".parse().unwrap();
    let records = (0..size)
        .map(|i| {
            ResourceRecord::new(
                name,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, (i % 250 + 1) as u8)),
            )
            .unwrap()
        })
        .collect();
    (key, records, name)
}

fn bench_sign_rrset(c: &mut Criterion) {
    let (key, records, origin) = rrset(4);
    c.bench_function("dnssec/sign_rrset_p384_4a", |b| {
        b.iter(|| {
            key.sign_rrset(
                black_box(&records),
                black_box(origin),
                256,
                1_700_000_000,
                86400,
            )
        })
    });
}

fn bench_key_tag(c: &mut Criterion) {
    let key = SigningKey::generate().unwrap();
    let dnskey = RData::Dnskey(key.dnskey(257)).to_wire().unwrap();
    c.bench_function("dnssec/key_tag", |b| {
        b.iter(|| adns_dnssec::key_tag(black_box(&dnskey)))
    });
}

criterion_group!(benches, bench_sign_rrset, bench_key_tag);
criterion_main!(benches);
