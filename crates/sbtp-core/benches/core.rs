//! Criterion benches: parse (F1 to F9), `block_id`, signature verification (C2, C3), full
//! validation, and PoW mining at d = 16 and 20.
//!
//! `cargo bench -p sbtp-core`. Keys from public seeds only (key A: 32 × `0x01`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use sbtp_core::layout::MAX_PARENTS;
use sbtp_core::{BlockBuilder, BlockId, SigningKey, mine, parse, validate_submitted};

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

/// Three block shapes: minimum (118 bytes), typical (3 parents, 1 KiB payload), maximum
/// (8 parents, 65,909 bytes).
fn blocks() -> Vec<(&'static str, Vec<u8>)> {
    let key = key_a();
    let parents: Vec<BlockId> = (1..=MAX_PARENTS).map(|n| BlockId([n; 32])).collect();
    let small = vec![0xabu8; 1024];
    let large = vec![0xcdu8; 65_535];
    let build = |ps: &[BlockId], payload: &[u8]| {
        BlockBuilder::for_key(&key)
            .timestamp(1_700_000_000_000)
            .parents(ps)
            .payload(payload)
            .build(&key, 0)
            .unwrap()
    };
    vec![
        ("min_118B", build(&[], &[])),
        ("3p_1KiB", build(&parents[..3], &small)),
        ("max_65909B", build(&parents, &large)),
    ]
}

fn bench_parse_and_id(c: &mut Criterion) {
    let blocks = blocks();
    let mut group = c.benchmark_group("parse");
    for (name, bytes) in &blocks {
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(*name, |b| b.iter(|| parse(black_box(bytes)).unwrap()));
    }
    group.finish();

    let mut group = c.benchmark_group("block_id");
    for (name, bytes) in &blocks {
        let block = parse(bytes).unwrap();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(*name, |b| b.iter(|| black_box(&block).block_id()));
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let blocks = blocks();
    // C2 + C3 alone, on an identifier already computed.
    let (_, small) = &blocks[0];
    let checked = parse(small).unwrap().check_pow(0).unwrap();
    c.bench_function("verify_signature", |b| {
        b.iter(|| black_box(checked).verify_signature().unwrap());
    });

    // F1 to F9, block_id, C1, C2, C3.
    let mut group = c.benchmark_group("validate_submitted");
    for (name, bytes) in &blocks {
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(*name, |b| {
            b.iter(|| validate_submitted(black_box(bytes), 0).unwrap());
        });
    }
    group.finish();
}

fn bench_pow(c: &mut Criterion) {
    let key = key_a();
    let unsigned = |timestamp: u64| {
        BlockBuilder::for_key(&key)
            .timestamp(timestamp)
            .payload(b"pow bench")
            .build_unsigned()
            .unwrap()
    };

    // Cost of one attempt: 10,000 attempts at d = 256, which none meets.
    let mut group = c.benchmark_group("mine_attempts");
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("10k_attempts_127B", |b| {
        b.iter_batched(
            || unsigned(0),
            |mut block| mine(&mut block, 256, 10_000).unwrap_err(),
            BatchSize::SmallInput,
        );
    });
    group.finish();

    // Full search; each iteration mines a different block (new timestamp), so the time is the mean
    // over about 2^d attempts.
    let mut group = c.benchmark_group("mine");
    group.sample_size(10);
    for d in [16u32, 20] {
        group.measurement_time(Duration::from_secs(if d == 16 { 10 } else { 60 }));
        let mut timestamp = 0u64;
        group.bench_function(format!("d{d}"), |b| {
            b.iter_batched(
                || {
                    timestamp += 1;
                    unsigned(timestamp)
                },
                |mut block| mine(&mut block, d, u64::MAX).unwrap(),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse_and_id, bench_verify, bench_pow);
criterion_main!(benches);
