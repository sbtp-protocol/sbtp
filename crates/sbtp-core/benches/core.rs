//! Criterion benches: decoding, `block_id`, signature verification, proof of work.
//! Key from the public seed 32 x 0x01 (test only).

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sbtp_core::{BlockId, SigningKey, UnsignedBlock, parse, validate_submitted};

fn block(payload: &[u8], parents: &[BlockId]) -> (SigningKey, UnsignedBlock<'static>, Vec<u8>) {
    let key = SigningKey::from_bytes(&[0x01; 32]);
    let fields = UnsignedBlock {
        timestamp: 1_700_000_000_000,
        nonce: 0,
        pubkey: key.verifying_key().to_bytes(),
        parents: &[],
        payload: &[],
    };
    let full = UnsignedBlock {
        parents,
        payload,
        ..fields
    };
    let bytes = full.sign(&key).unwrap();
    (key, fields, bytes)
}

fn benches(c: &mut Criterion) {
    let parents: Vec<BlockId> = (1..=8).map(|n| BlockId([n; 32])).collect();
    let payload = vec![0xab; 65_535];
    let (_, _, small) = block(&[], &[]);
    let (_, _, large) = block(&payload, &parents);

    c.bench_function("parse/118", |b| {
        b.iter(|| parse(black_box(&small)).unwrap());
    });
    c.bench_function("parse/65909", |b| {
        b.iter(|| parse(black_box(&large)).unwrap());
    });
    let parsed_small = parse(&small).unwrap();
    let parsed_large = parse(&large).unwrap();
    c.bench_function("block_id/118", |b| {
        b.iter(|| black_box(parsed_small).block_id());
    });
    c.bench_function("block_id/65909", |b| {
        b.iter(|| black_box(parsed_large).block_id());
    });
    c.bench_function("validate/118", |b| {
        b.iter(|| validate_submitted(black_box(&small), 0).unwrap());
    });
    c.bench_function("mine/d8", |b| {
        let (_, fields, _) = block(&[], &[]);
        b.iter(|| {
            let mut fields = fields;
            fields.mine(8, u64::MAX).unwrap()
        });
    });
}

criterion_group!(core, benches);
criterion_main!(core);
