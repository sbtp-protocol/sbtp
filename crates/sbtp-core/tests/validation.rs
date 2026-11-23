//! One test per rule of SPEC §1 to §4, positive and negative, on blocks built here.
//!
//! Test keys come only from public seeds: key A is `SigningKey::from_bytes(&[0x01; 32])`, key B
//! `SigningKey::from_bytes(&[0x02; 32])`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    missing_docs
)]

use sbtp_core::{
    BLOCK_ID_CONTEXT, BlockId, EncodeError, Error, MAX_BLOCK_LEN, MIN_BLOCK_LEN, ParseBlockIdError,
    SIG_PREFIX, SigningKey, UnsignedBlock, compute_block_id, parse, validate_requested,
    validate_submitted,
};

const TIMESTAMP: u64 = 1_700_000_000_000;

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

fn key_b() -> SigningKey {
    SigningKey::from_bytes(&[0x02; 32])
}

fn pid(n: u8) -> BlockId {
    BlockId([n; 32])
}

fn fields<'a>(parents: &'a [BlockId], payload: &'a [u8]) -> UnsignedBlock<'a> {
    UnsignedBlock {
        timestamp: TIMESTAMP,
        nonce: 0,
        pubkey: key_a().verifying_key().to_bytes(),
        parents,
        payload,
    }
}

fn signed(parents: &[BlockId], payload: &[u8]) -> Vec<u8> {
    fields(parents, payload).sign(&key_a()).unwrap()
}

fn err(bytes: &[u8]) -> Error {
    validate_submitted(bytes, 0).unwrap_err()
}

/// Re-signs a block whose bytes were edited, so that only the intended rule fails.
fn resign(bytes: &mut [u8]) {
    let off = bytes.len() - 64;
    let id = compute_block_id(&bytes[..off]);
    use ed25519_dalek::Signer;
    bytes[off..].copy_from_slice(&key_a().sign(&id.signed_message()).to_bytes());
}

// spec §1, §4: a valid block of every shape passes and reads back its fields.
#[test]
fn valid_blocks_round_trip() {
    let parents = [pid(3), pid(1), pid(2)];
    let bytes = signed(&parents, b"hello");
    assert_eq!(bytes.len(), 118 + 3 * 32 + 5);
    let ok = validate_submitted(&bytes, 0).unwrap();
    let block = ok.block();
    assert_eq!(block.timestamp(), TIMESTAMP);
    assert_eq!(block.parents(), &parents);
    assert_eq!(block.payload(), b"hello");
    assert_eq!(block.as_bytes(), &bytes[..]);
    assert_eq!(
        *ok.block_id(),
        fields(&parents, b"hello").block_id().unwrap()
    );
    assert_eq!(signed(&[], &[]).len(), MIN_BLOCK_LEN);
}

// spec §1: the largest block (8 parents, 65,535-byte payload) is valid.
#[test]
fn max_size_block_is_valid() {
    let parents: Vec<BlockId> = (1..=8).map(pid).collect();
    let bytes = signed(&parents, &vec![7; 65_535]);
    assert_eq!(bytes.len(), MAX_BLOCK_LEN);
    assert!(validate_submitted(&bytes, 0).is_ok());
}

// spec §4 F1.
#[test]
fn f1_too_short() {
    assert_eq!(err(&[]), Error::TooShort);
    assert_eq!(err(&signed(&[], &[])[..117]), Error::TooShort);
}

// spec §4 F2, checked before the magic.
#[test]
fn f2_too_long() {
    assert_eq!(err(&vec![0; MAX_BLOCK_LEN + 1]), Error::TooLong);
}

// spec §4 F3.
#[test]
fn f3_bad_magic() {
    for i in 0..2 {
        let mut bytes = signed(&[], &[]);
        bytes[i] ^= 1;
        assert_eq!(err(&bytes), Error::BadMagic);
    }
}

// spec §4 F4.
#[test]
fn f4_unsupported_version() {
    for version in [0, 2, 0xff] {
        let mut bytes = signed(&[], &[]);
        bytes[2] = version;
        assert_eq!(err(&bytes), Error::UnsupportedVersion);
    }
}

// spec §4 F5, checked before the length.
#[test]
fn f5_too_many_parents() {
    for count in [9, 255] {
        let mut bytes = signed(&[], &[]);
        bytes[51] = count;
        assert_eq!(err(&bytes), Error::TooManyParents);
    }
}

// spec §4 F6: the parents run past the buffer.
#[test]
fn f6_truncated_in_parents() {
    let mut bytes = signed(&[], &[]);
    bytes[51] = 4; // needs 118 + 128 bytes
    assert_eq!(err(&bytes), Error::Truncated);
}

// spec §4 F7: the payload or the signature runs past the buffer.
#[test]
fn f7_truncated() {
    let bytes = signed(&[pid(1)], &[5; 100]);
    assert_eq!(err(&bytes[..bytes.len() - 1]), Error::Truncated);
    assert_eq!(err(&bytes[..bytes.len() - 64]), Error::Truncated);
}

// spec §4 F8.
#[test]
fn f8_trailing_bytes() {
    let mut bytes = signed(&[], b"x");
    bytes.push(0);
    assert_eq!(err(&bytes), Error::TrailingBytes);
}

// spec §4 F9: adjacent and non-adjacent duplicates; order and all-zero parents are fine.
#[test]
fn f9_duplicate_parent() {
    let mut bytes = signed(&[pid(1), pid(2), pid(3)], &[]);
    bytes[52 + 64..52 + 96].copy_from_slice(&[1; 32]);
    resign(&mut bytes);
    assert_eq!(err(&bytes), Error::DuplicateParent);
    bytes[52 + 32..52 + 64].copy_from_slice(&[3; 32]);
    bytes[52 + 64..52 + 96].copy_from_slice(&[3; 32]);
    resign(&mut bytes);
    assert_eq!(err(&bytes), Error::DuplicateParent);
    assert!(validate_submitted(&signed(&[pid(0), pid(9), pid(2)], &[]), 0).is_ok());
}

// spec §4 R1.
#[test]
fn r1_block_id_mismatch() {
    let bytes = signed(&[], b"r1");
    let id = parse(&bytes).unwrap().block_id();
    assert!(validate_requested(&bytes, 0, &id).is_ok());
    assert_eq!(
        validate_requested(&bytes, 0, &pid(0)).unwrap_err(),
        Error::BlockIdMismatch
    );
    // R1 runs after the format checks and before C1.
    assert_eq!(
        validate_requested(&[], 0, &id).unwrap_err(),
        Error::TooShort
    );
    assert_eq!(
        validate_requested(&bytes, 256, &pid(0)).unwrap_err(),
        Error::BlockIdMismatch
    );
}

// spec §4 P1: strictly later than now + margin is rejected; the sum saturates.
#[test]
fn p1_timestamp_too_far_in_future() {
    let bytes = signed(&[], &[]);
    let block = parse(&bytes).unwrap();
    assert_eq!(block.check_timestamp(TIMESTAMP - 10, 10), Ok(()));
    assert_eq!(
        block.check_timestamp(TIMESTAMP - 11, 10),
        Err(Error::TimestampTooFarInFuture)
    );
    let mut max = fields(&[], &[]);
    max.timestamp = u64::MAX;
    let bytes = max.sign(&key_a()).unwrap();
    assert_eq!(parse(&bytes).unwrap().check_timestamp(1, u64::MAX), Ok(()));
    assert_eq!(
        parse(&bytes).unwrap().check_timestamp(1, 0),
        Err(Error::TimestampTooFarInFuture)
    );
}

// spec §3, §4 C1: mining reaches the difficulty, one more bit fails, 0 always passes.
#[test]
fn c1_insufficient_pow() {
    let mut block = fields(&[], b"pow");
    let id = block.mine(10, u64::MAX).unwrap();
    let bytes = block.sign(&key_a()).unwrap();
    assert_eq!(parse(&bytes).unwrap().block_id(), id);
    let bits = id.leading_zero_bits();
    assert!(bits >= 10);
    assert!(validate_submitted(&bytes, bits).is_ok());
    assert_eq!(
        validate_submitted(&bytes, bits + 1).unwrap_err(),
        Error::InsufficientPow
    );
    assert_eq!(
        validate_submitted(&bytes, 257).unwrap_err(),
        Error::InsufficientPow
    );
    assert_eq!(
        validate_submitted(&bytes, u32::MAX).unwrap_err(),
        Error::InsufficientPow
    );
}

// spec §3: leading zero bits read the identifier big-endian.
#[test]
fn leading_zero_bits() {
    let id = |prefix: &[u8]| {
        let mut b = [0xff; 32];
        b[..prefix.len()].copy_from_slice(prefix);
        BlockId(b)
    };
    assert_eq!(id(&[0x80]).leading_zero_bits(), 0);
    assert_eq!(id(&[0x01]).leading_zero_bits(), 7);
    assert_eq!(id(&[0x00, 0x00, 0x0f]).leading_zero_bits(), 20);
    assert_eq!(id(&[0x01, 0x00]).leading_zero_bits(), 7);
    assert_eq!(BlockId([0; 32]).leading_zero_bits(), 256);
    assert!(BlockId([0; 32]).meets_difficulty(256));
    assert!(!BlockId([0; 32]).meets_difficulty(257));
}

/// An unsigned-in-effect block for an arbitrary public key: zero signature.
fn with_key(pubkey: [u8; 32]) -> Vec<u8> {
    let mut bytes = signed(&[], b"key");
    bytes[19..51].copy_from_slice(&pubkey);
    bytes
}

fn small_y(y: u8, sign: bool) -> [u8; 32] {
    let mut out = [0; 32];
    out[0] = y;
    if sign {
        out[31] = 0x80;
    }
    out
}

/// Little-endian `y + p`, `p = 2^255 − 19`: a non-canonical encoding of `y` when `y < 19`.
fn y_plus_p(y: u8) -> [u8; 32] {
    let mut out = [0xff; 32];
    out[0] = 0xed + y;
    out[31] = 0x7f;
    out
}

fn hex32(s: &str) -> [u8; 32] {
    s.parse::<BlockId>().unwrap().0
}

const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

// spec §3 V1, §4 C2: not on the curve, y ≥ p, x = 0 with the sign bit.
#[test]
fn c2_v1_invalid_public_key() {
    let mut minus_one = hex32(SMALL_ORDER[1]);
    minus_one[31] |= 0x80;
    for key in [
        small_y(2, false),
        y_plus_p(3),
        y_plus_p(0),
        y_plus_p(1),
        small_y(1, true),
        minus_one,
    ] {
        assert_eq!(err(&with_key(key)), Error::InvalidPublicKey, "{key:02x?}");
    }
    // Control: y = 3 canonical is a valid key, so only the signature fails.
    assert_eq!(err(&with_key(small_y(3, false))), Error::InvalidSignature);
}

// spec §3 V2, §4 C2: every small-order point, canonical.
#[test]
fn c2_v2_small_order_public_key() {
    for point in SMALL_ORDER {
        assert_eq!(
            err(&with_key(hex32(point))),
            Error::InvalidPublicKey,
            "{point}"
        );
    }
}

/// `L` little-endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

// spec §3 V3: S replaced by S + L.
#[test]
fn c3_v3_s_not_reduced() {
    let mut bytes = signed(&[], b"S + L");
    let off = bytes.len() - 32;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(bytes[off + i]) + u16::from(L_LE[i]) + carry;
        bytes[off + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(err(&bytes), Error::InvalidSignature);
}

// spec §3 V4 and V5: R not a point; R of small order.
#[test]
fn c3_v4_v5_bad_r() {
    let mut bytes = signed(&[], b"R");
    let off = bytes.len() - 64;
    bytes[off..off + 32].copy_from_slice(&small_y(2, false));
    assert_eq!(err(&bytes), Error::InvalidSignature);
    for point in SMALL_ORDER {
        bytes[off..off + 32].copy_from_slice(&hex32(point));
        assert_eq!(err(&bytes), Error::InvalidSignature, "{point}");
    }
}

// spec §3 V6: bit flips, another key, missing prefix, plain BLAKE3.
#[test]
fn c3_v6_equation() {
    use ed25519_dalek::Signer;
    let good = signed(&[], b"v6");
    let off = good.len() - 64;
    for bit in [0, 255, 256, 511] {
        let mut bytes = good.clone();
        bytes[off + bit / 8] ^= 1 << (bit % 8);
        assert_eq!(err(&bytes), Error::InvalidSignature, "bit {bit}");
    }
    let mut payload_flip = good.clone();
    payload_flip[54] ^= 1;
    assert_eq!(err(&payload_flip), Error::InvalidSignature);

    let id = compute_block_id(&good[..off]);
    let plain = blake3::hash(&good[..off]);
    for message in [
        key_b().sign(&id.signed_message()),
        key_a().sign(id.as_bytes()),
        key_a().sign(&BlockId(*plain.as_bytes()).signed_message()),
    ] {
        let mut bytes = good.clone();
        bytes[off..].copy_from_slice(&message.to_bytes());
        assert_eq!(err(&bytes), Error::InvalidSignature);
    }
}

// spec §2, §3: the context and prefix bytes, and the 49-byte message.
#[test]
fn domain_separation_constants() {
    assert_eq!(BLOCK_ID_CONTEXT.len(), 27);
    assert_eq!(&SIG_PREFIX, b"SBTP-v1-block-sig");
    let m = pid(0xab).signed_message();
    assert_eq!(m.len(), 49);
    assert_eq!(&m[..17], &SIG_PREFIX);
    assert_ne!(compute_block_id(b"x").0, *blake3::hash(b"x").as_bytes());
}

// spec §2: the text form is exactly 64 lowercase hexadecimal characters.
#[test]
fn block_id_text_form() {
    let mut raw = [0u8; 32];
    raw[0] = 0xab;
    raw[31] = 0x01;
    let text = BlockId(raw).to_string();
    assert_eq!(text.len(), 64);
    assert!(text.starts_with("ab") && text.ends_with("01"));
    assert_eq!(text.parse::<BlockId>(), Ok(BlockId(raw)));
    let upper = text.to_uppercase();
    for bad in [
        &upper[..],
        &text[..63],
        "",
        &format!("{text}0"),
        &text.replace('a', "g"),
    ] {
        assert_eq!(bad.parse::<BlockId>(), Err(ParseBlockIdError), "{bad:?}");
    }
    let multibyte = format!("é{}", &text[2..]);
    assert_eq!(multibyte.parse::<BlockId>(), Err(ParseBlockIdError));
}

// Encoder errors (sender side).
#[test]
fn encode_errors() {
    let nine: Vec<BlockId> = (1..=9).map(pid).collect();
    assert_eq!(
        fields(&nine, &[]).encoded_len(),
        Err(EncodeError::TooManyParents)
    );
    assert_eq!(
        fields(&[], &vec![0; 65_536]).encoded_len(),
        Err(EncodeError::PayloadTooLong)
    );
    assert_eq!(
        fields(&[pid(1), pid(1)], &[]).block_id(),
        Err(EncodeError::DuplicateParent)
    );
    assert_eq!(
        fields(&[], &[]).sign(&key_b()),
        Err(EncodeError::KeyMismatch)
    );
    assert_eq!(
        fields(&[], &[]).sign_into(&key_a(), &mut [0; 117]),
        Err(EncodeError::BufferTooSmall)
    );
    let mut f = fields(&[], &[]);
    assert_eq!(f.mine(257, u64::MAX), Err(EncodeError::PowNotFound));
    assert_eq!(f.mine(64, 3), Err(EncodeError::PowNotFound));
    assert_eq!(f.nonce, 3, "a failed search leaves the next untried nonce");
    f.nonce = u64::MAX;
    assert_eq!(f.mine(64, 10), Err(EncodeError::PowNotFound));
    let mut buf = [0u8; 200];
    assert_eq!(fields(&[], &[]).sign_into(&key_a(), &mut buf), Ok(118));
    assert!(validate_submitted(&buf[..118], 0).is_ok());
}

// spec §3: signatures are deterministic.
#[test]
fn signing_is_deterministic() {
    assert_eq!(signed(&[pid(1)], b"d"), signed(&[pid(1)], b"d"));
}

// The Error names are those of SPEC §4 and Display shows them.
#[test]
fn error_names() {
    assert_eq!(
        Error::TimestampTooFarInFuture.name(),
        "TimestampTooFarInFuture"
    );
    assert_eq!(Error::InvalidSignature.to_string(), "InvalidSignature");
    assert_eq!(
        EncodeError::KeyMismatch.to_string(),
        "signing key does not match the public key"
    );
}
