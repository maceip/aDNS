use adns_storage::{Collection, DnsStorage, MemoryStorage, ReadTx, WriteTx};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn seeded(rows: usize) -> MemoryStorage {
    let db = MemoryStorage::default();
    let mut tx = db.write().unwrap();
    for i in 0..rows {
        tx.put(
            Collection::Records,
            format!("zone/a/{i:05}").into_bytes(),
            vec![1, 2, 3, 4],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    db
}

fn bench_scan_prefix(c: &mut Criterion) {
    let db = seeded(2000);
    for size in [10usize, 100, 1000] {
        c.bench_with_input(
            BenchmarkId::new("storage/scan_prefix", size),
            &size,
            |b, &size| {
                let prefix = format!("zone/a/{:05}", size).into_bytes();
                let prefix = &prefix[..8];
                b.iter(|| {
                    let read = db.read().unwrap();
                    read.scan_prefix(black_box(Collection::Records), black_box(prefix))
                })
            },
        );
    }
}

fn bench_commit(c: &mut Criterion) {
    c.bench_function("storage/commit_10_writes", |b| {
        b.iter_batched(
            || seeded(2000),
            |db| {
                let mut tx = db.write().unwrap();
                for i in 0..10 {
                    tx.put(
                        Collection::Records,
                        format!("zone/b/{i}").into_bytes(),
                        vec![9; 32],
                    )
                    .unwrap();
                }
                black_box(tx.commit())
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_scan_prefix, bench_commit);
criterion_main!(benches);
