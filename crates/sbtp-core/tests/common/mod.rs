//! Shared helpers for the integration tests.
//!
//! Test keys come only from documented public seeds:
//! - key A: `SigningKey::from_bytes(&[0x01; 32])`;
//! - key B: `SigningKey::from_bytes(&[0x02; 32])`.
//!
//! They are test keys, never used outside tests and vectors.

#![allow(dead_code)]

use sbtp_core::{BlockBuilder, BlockId, SigningKey, layout};

/// Public seed of key A.
pub const SEED_A: [u8; 32] = [0x01; 32];
/// Public seed of key B.
pub const SEED_B: [u8; 32] = [0x02; 32];

/// A fixed, arbitrary timestamp (2023-11-14T22:13:20Z in milliseconds).
pub const TIMESTAMP: u64 = 1_700_000_000_000;

pub fn key_a() -> SigningKey {
    SigningKey::from_bytes(&SEED_A)
}

pub fn key_b() -> SigningKey {
    SigningKey::from_bytes(&SEED_B)
}

/// A parent hash whose 32 bytes are all `n`.
pub fn pid(n: u8) -> BlockId {
    BlockId([n; 32])
}

/// `count` distinct parents, `pid(1)`, `pid(2)`, ...
pub fn parents(count: u8) -> Vec<BlockId> {
    (1..=count).map(pid).collect()
}

/// A valid block signed by key A, difficulty 0.
pub fn signed(parents: &[BlockId], payload: &[u8]) -> Vec<u8> {
    let key = key_a();
    BlockBuilder::for_key(&key)
        .timestamp(TIMESTAMP)
        .parents(parents)
        .payload(payload)
        .build(&key, 0)
        .unwrap()
}

/// An unsigned block (zero signature) for an arbitrary public key.
pub fn unsigned_with_key(pubkey: [u8; 32], parents: &[BlockId], payload: &[u8]) -> Vec<u8> {
    BlockBuilder::new(pubkey)
        .timestamp(TIMESTAMP)
        .parents(parents)
        .payload(payload)
        .build_unsigned()
        .unwrap()
}

/// Offset of the signature of an encoded block.
pub fn sig_offset(block: &[u8]) -> usize {
    block.len() - layout::SIGNATURE_LEN
}

/// Replaces the 64 signature bytes.
pub fn set_signature(block: &mut [u8], signature: &[u8; 64]) {
    let off = sig_offset(block);
    block[off..].copy_from_slice(signature);
}

/// Decodes 64 hex characters.
pub fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Little-endian encoding of `y + p`, `p = 2^255 − 19`, for a small `y`.
pub fn y_plus_p(y: u8) -> [u8; 32] {
    let mut out = [0xffu8; 32];
    out[0] = 0xed + y;
    out[31] = 0x7f;
    out
}

/// Little-endian encoding of a small `y`, sign bit as given.
pub fn small_y(y: u8, sign: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = y;
    if sign {
        out[31] = 0x80;
    }
    out
}

/// The 8 small-order points, canonical encodings.
pub const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

/// `L = 2^252 + 27742317777372353535851937790883648493`, little-endian.
pub const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `a + b` over 256-bit little-endian integers; panics on overflow (never for `S + L`, `S < L`).
pub fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}
