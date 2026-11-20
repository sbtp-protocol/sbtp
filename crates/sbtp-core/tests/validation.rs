//! One positive and one negative test per check F1 to F9, R1, C1 to C3 (spec §2.2), the ordering
//! between checks, and the signature edge cases of docs/test-vectors/README.md (spec §3.2, ADR 0003).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ed25519_dalek::{Signer, VerifyingKey};
use sbtp_core::layout::{
    MAX_BLOCK_LEN, MAX_PARENTS, MAX_PAYLOAD_LEN, MIN_BLOCK_LEN, OFFSET_PARENTS,
    OFFSET_PARENTS_COUNT,
};
use sbtp_core::{
    BlockBuilder, BlockId, Error, compute_block_id, mine, parse, sign_block, sign_block_id,
    validate_requested, validate_submitted,
};

fn err(bytes: &[u8]) -> Error {
    validate_submitted(bytes, 0).unwrap_err()
}

fn ok(bytes: &[u8]) {
    if let Err(e) = validate_submitted(bytes, 0) {
        panic!("expected a valid block, got {e:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// F1: TooShort
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_minimum_block_118_bytes_is_valid() {
    let block = signed(&[], &[]);
    assert_eq!(block.len(), MIN_BLOCK_LEN);
    ok(&block);
}

#[test]
fn f1_empty_buffer() {
    assert_eq!(err(&[]), Error::TooShort { len: 0 });
}

#[test]
fn f1_117_bytes() {
    let block = signed(&[], &[]);
    assert_eq!(err(&block[..117]), Error::TooShort { len: 117 });
}

#[test]
fn f1_before_f3() {
    assert_eq!(err(&[0u8; 117]), Error::TooShort { len: 117 });
}

// ---------------------------------------------------------------------------------------------
// F2: TooLong
// ---------------------------------------------------------------------------------------------

#[test]
fn f2_maximum_block_is_valid() {
    let payload = vec![0xa5u8; 65_535];
    let block = signed(&parents(MAX_PARENTS), &payload);
    assert_eq!(block.len(), MAX_BLOCK_LEN);
    ok(&block);
}

#[test]
fn f2_one_byte_over_the_maximum() {
    let payload = vec![0xa5u8; 65_535];
    let mut block = signed(&parents(MAX_PARENTS), &payload);
    block.push(0);
    // F2 fires before F8 would.
    assert_eq!(
        err(&block),
        Error::TooLong {
            len: MAX_BLOCK_LEN + 1
        }
    );
}

#[test]
fn f2_before_f3() {
    assert_eq!(err(&vec![0u8; 70_000]), Error::TooLong { len: 70_000 });
}

// ---------------------------------------------------------------------------------------------
// F3: BadMagic
// ---------------------------------------------------------------------------------------------

#[test]
fn f3_magic_sb_is_valid() {
    let block = signed(&[], &[]);
    assert_eq!(&block[..2], b"SB");
    ok(&block);
}

#[test]
fn f3_wrong_first_byte() {
    let mut block = signed(&[], &[]);
    block[0] = 0x54;
    assert_eq!(
        err(&block),
        Error::BadMagic {
            found: [0x54, 0x42]
        }
    );
}

#[test]
fn f3_wrong_second_byte() {
    let mut block = signed(&[], &[]);
    block[1] = 0x43;
    assert_eq!(
        err(&block),
        Error::BadMagic {
            found: [0x53, 0x43]
        }
    );
}

#[test]
fn f3_before_f4() {
    let mut block = signed(&[], &[]);
    block[0] = 0;
    block[2] = 0x02;
    assert!(matches!(err(&block), Error::BadMagic { .. }));
}

// ---------------------------------------------------------------------------------------------
// F4: UnsupportedVersion
// ---------------------------------------------------------------------------------------------

#[test]
fn f4_version_1_is_valid() {
    let block = signed(&[], &[]);
    assert_eq!(parse(&block).unwrap().version(), 0x01);
    ok(&block);
}

#[test]
fn f4_version_0_and_2() {
    for version in [0x00u8, 0x02, 0xff] {
        let mut block = signed(&[], &[]);
        block[2] = version;
        assert_eq!(err(&block), Error::UnsupportedVersion { version });
    }
}

#[test]
fn f4_before_f5() {
    let mut block = signed(&[], &[]);
    block[2] = 0x02;
    block[OFFSET_PARENTS_COUNT] = MAX_PARENTS + 1;
    assert_eq!(err(&block), Error::UnsupportedVersion { version: 0x02 });
}

// ---------------------------------------------------------------------------------------------
// F5: TooManyParents
// ---------------------------------------------------------------------------------------------

#[test]
fn f5_max_parents_is_valid() {
    let block = signed(&parents(MAX_PARENTS), b"x");
    assert_eq!(
        parse(&block).unwrap().parents().len(),
        usize::from(MAX_PARENTS)
    );
    ok(&block);
}

/// A buffer of the exact length that `count` parents and an empty payload would need, other fields
/// well-formed.
fn with_parent_count(count: u8) -> Vec<u8> {
    let mut block = vec![0u8; MIN_BLOCK_LEN + 32 * usize::from(count)];
    block[..3].copy_from_slice(&[0x53, 0x42, 0x01]);
    block[OFFSET_PARENTS_COUNT] = count;
    // Distinct parents so that only F5 can fire.
    for i in 0..usize::from(count) {
        let off = OFFSET_PARENTS + 32 * i;
        block[off..off + 2].copy_from_slice(&u16::try_from(i + 1).unwrap().to_be_bytes());
    }
    block
}

#[test]
fn f5_one_parent_over_the_maximum() {
    assert_eq!(
        err(&with_parent_count(MAX_PARENTS + 1)),
        Error::TooManyParents {
            count: MAX_PARENTS + 1
        }
    );
}

#[test]
fn f5_255_parents() {
    assert_eq!(
        err(&with_parent_count(255)),
        Error::TooManyParents { count: 255 }
    );
}

#[test]
fn f5_before_f6() {
    // 118 bytes cannot hold MAX_PARENTS + 1 parents: F5 still fires first.
    let mut block = signed(&[], &[]);
    block[OFFSET_PARENTS_COUNT] = MAX_PARENTS + 1;
    assert_eq!(
        err(&block),
        Error::TooManyParents {
            count: MAX_PARENTS + 1
        }
    );
}

// ---------------------------------------------------------------------------------------------
// F6: Truncated (parents)
// ---------------------------------------------------------------------------------------------

#[test]
fn f6_exact_room_for_parents_is_valid() {
    // len = 118 + 32·N exactly (P = 0).
    let block = signed(&parents(MAX_PARENTS), &[]);
    assert_eq!(block.len(), MIN_BLOCK_LEN + 32 * usize::from(MAX_PARENTS));
    ok(&block);
}

#[test]
fn f6_truncated_in_the_middle_of_the_parents() {
    let block = signed(&parents(MAX_PARENTS), &[]);
    // Cut inside the last parent; derived from MAX_PARENTS so the test follows the format limit.
    let cut = OFFSET_PARENTS + 32 * (usize::from(MAX_PARENTS) - 1) + 16;
    assert!(cut >= MIN_BLOCK_LEN, "the cut must pass F1 to exercise F6");
    assert_eq!(
        err(&block[..cut]),
        Error::Truncated {
            expected_min: MIN_BLOCK_LEN + 32 * usize::from(MAX_PARENTS),
            len: cut
        }
    );
}

#[test]
fn f6_before_f7() {
    // N = 3 announced, buffer of 118 bytes: F6 fires without reading Payload Len.
    let mut block = signed(&[], &[]);
    block[OFFSET_PARENTS_COUNT] = 3;
    assert_eq!(
        err(&block),
        Error::Truncated {
            expected_min: 118 + 96,
            len: 118
        }
    );
}

// ---------------------------------------------------------------------------------------------
// F7: Truncated (payload, signature)
// ---------------------------------------------------------------------------------------------

#[test]
fn f7_payload_of_exact_length_is_valid() {
    let block = signed(&parents(2), &[7u8; 100]);
    assert_eq!(block.len(), 118 + 64 + 100);
    ok(&block);
}

#[test]
fn f7_truncated_in_the_middle_of_the_payload() {
    // Payload from offset 118 to 318; cut at 218, above the F6 bound 182.
    let block = signed(&parents(2), &[7u8; 200]);
    let cut = 218;
    assert_eq!(
        err(&block[..cut]),
        Error::Truncated {
            expected_min: 382,
            len: cut
        }
    );
}

#[test]
fn f7_last_signature_byte_missing() {
    let block = signed(&parents(1), b"hello");
    let len = block.len();
    assert_eq!(
        err(&block[..len - 1]),
        Error::Truncated {
            expected_min: len,
            len: len - 1
        }
    );
}

// ---------------------------------------------------------------------------------------------
// F8: TrailingBytes
// ---------------------------------------------------------------------------------------------

#[test]
fn f8_exact_length_is_valid() {
    let block = signed(&parents(1), b"hello");
    assert_eq!(parse(&block).unwrap().as_bytes().len(), block.len());
    ok(&block);
}

#[test]
fn f8_one_extra_byte() {
    let mut block = signed(&parents(1), b"hello");
    let expected = block.len();
    block.push(0);
    assert_eq!(
        err(&block),
        Error::TrailingBytes {
            expected,
            len: expected + 1
        }
    );
}

#[test]
fn f8_before_f9() {
    let mut block = signed(&parents(2), &[]);
    block.copy_within(OFFSET_PARENTS..OFFSET_PARENTS + 32, OFFSET_PARENTS + 32);
    block.push(0);
    assert!(matches!(err(&block), Error::TrailingBytes { .. }));
}

// ---------------------------------------------------------------------------------------------
// F9: DuplicateParent
// ---------------------------------------------------------------------------------------------

#[test]
fn f9_distinct_parents_are_valid() {
    ok(&signed(&parents(MAX_PARENTS), &[]));
}

#[test]
fn f9_zero_parent_is_valid() {
    // ADR 0004: a parent hash is opaque.
    let block = signed(&[BlockId([0u8; 32])], &[]);
    ok(&block);
}

#[test]
fn f9_unsorted_parents_are_valid_and_kept_in_order() {
    let order = [pid(9), pid(3), pid(7), pid(1)];
    let block = signed(&order, &[]);
    ok(&block);
    assert_eq!(parse(&block).unwrap().parents(), &order);
}

/// Copies parent `from` over parent `to`. The signature becomes invalid, which does not matter:
/// F9 fires first.
fn duplicate(block: &mut [u8], from: usize, to: usize) {
    let src = OFFSET_PARENTS + 32 * from;
    block.copy_within(src..src + 32, OFFSET_PARENTS + 32 * to);
}

#[test]
fn f9_adjacent_duplicates() {
    let mut block = signed(&parents(4), &[]);
    duplicate(&mut block, 1, 2);
    assert_eq!(
        err(&block),
        Error::DuplicateParent {
            first: 1,
            second: 2
        }
    );
}

#[test]
fn f9_non_adjacent_duplicates() {
    let last = MAX_PARENTS - 1;
    let mut block = signed(&parents(MAX_PARENTS), &[]);
    duplicate(&mut block, 0, usize::from(last));
    assert_eq!(
        err(&block),
        Error::DuplicateParent {
            first: 0,
            second: last
        }
    );
}

#[test]
fn f9_before_crypto() {
    // A duplicate parent with an all-zero (invalid) pubkey and signature, at high difficulty.
    let mut block = unsigned_with_key([0u8; 32], &parents(3), &[]);
    duplicate(&mut block, 0, 2);
    assert!(matches!(
        validate_requested(&block, 200, &pid(0xee)),
        Err(Error::DuplicateParent { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// R1: BlockIdMismatch
// ---------------------------------------------------------------------------------------------

#[test]
fn r1_requested_id_matches() {
    let block = signed(&parents(1), b"r1");
    let id = parse(&block).unwrap().block_id();
    let validated = validate_requested(&block, 0, &id).unwrap();
    assert_eq!(*validated.block_id(), id);
}

#[test]
fn r1_requested_id_differs() {
    let block = signed(&parents(1), b"r1");
    let actual = parse(&block).unwrap().block_id();
    let expected = pid(0x42);
    assert_eq!(
        validate_requested(&block, 0, &expected).unwrap_err(),
        Error::BlockIdMismatch { expected, actual }
    );
}

#[test]
fn r1_before_c1() {
    let block = signed(&[], &[]);
    assert!(matches!(
        validate_requested(&block, 256, &pid(0x42)),
        Err(Error::BlockIdMismatch { .. })
    ));
}

#[test]
fn r1_not_applied_without_requested_id() {
    // A PUT has no expected identifier.
    ok(&signed(&[], b"put"));
}

// ---------------------------------------------------------------------------------------------
// C1: InsufficientPow
// ---------------------------------------------------------------------------------------------

/// A block mined at difficulty `d`, signed by key A, and the actual leading zero bits of its id.
fn mined(d: u32) -> (Vec<u8>, u32) {
    let key = key_a();
    let block = BlockBuilder::for_key(&key)
        .timestamp(TIMESTAMP)
        .payload(b"pow")
        .build(&key, d)
        .unwrap();
    let zeros = parse(&block).unwrap().block_id().leading_zero_bits();
    assert!(zeros >= d);
    (block, zeros)
}

#[test]
fn c1_pow_exactly_at_threshold_is_valid() {
    let (block, zeros) = mined(8);
    // `zeros` is the exact number of leading zero bits: difficulty = zeros is the boundary.
    validate_submitted(&block, zeros).unwrap();
    validate_submitted(&block, 8).unwrap();
}

#[test]
fn c1_one_bit_short() {
    let (block, zeros) = mined(8);
    assert_eq!(
        validate_submitted(&block, zeros + 1).unwrap_err(),
        Error::InsufficientPow {
            required: zeros + 1,
            actual: zeros
        }
    );
}

#[test]
fn c1_difficulty_zero_accepts_any_id() {
    ok(&signed(&[], b"any"));
}

#[test]
fn c1_difficulty_above_256_rejects_everything() {
    let (block, _) = mined(4);
    assert!(matches!(
        validate_submitted(&block, 257),
        Err(Error::InsufficientPow { required: 257, .. })
    ));
}

#[test]
fn c1_before_c2() {
    let block = unsigned_with_key([0u8; 32], &[], &[]);
    let zeros = parse(&block).unwrap().block_id().leading_zero_bits();
    assert!(matches!(
        validate_submitted(&block, zeros + 1),
        Err(Error::InsufficientPow { .. })
    ));
}

#[test]
fn mine_writes_nonce_big_endian_and_increments() {
    let key = key_a();
    let mut block = BlockBuilder::for_key(&key)
        .nonce(0x0102_0304_0506_0700)
        .build_unsigned()
        .unwrap();
    let (nonce, id) = mine(&mut block, 6, 1 << 20).unwrap();
    assert!(nonce >= 0x0102_0304_0506_0700);
    assert_eq!(&block[11..19], &nonce.to_be_bytes());
    assert_eq!(parse(&block).unwrap().block_id(), id);
    assert!(id.leading_zero_bits() >= 6);
}

#[test]
fn nonce_with_distinct_bytes_is_big_endian() {
    let key = key_a();
    let block = BlockBuilder::for_key(&key)
        .nonce(0x0102_0304_0506_0708)
        .build(&key, 0)
        .unwrap();
    assert_eq!(&block[11..19], &[1, 2, 3, 4, 5, 6, 7, 8]);
    let parsed = validate_submitted(&block, 0).unwrap();
    assert_eq!(parsed.block().nonce(), 0x0102_0304_0506_0708);
}

#[test]
fn timestamp_extremes_are_valid() {
    let key = key_a();
    for timestamp in [0, u64::MAX] {
        let block = BlockBuilder::for_key(&key)
            .timestamp(timestamp)
            .build(&key, 0)
            .unwrap();
        assert_eq!(
            validate_submitted(&block, 0).unwrap().block().timestamp(),
            timestamp
        );
    }
}

// ---------------------------------------------------------------------------------------------
// C2: InvalidPublicKey (V1, V2)
// ---------------------------------------------------------------------------------------------

#[test]
fn c2_honest_key_is_valid() {
    let block = signed(&[], b"c2");
    assert_eq!(
        parse(&block).unwrap().pubkey(),
        key_a().verifying_key().as_bytes()
    );
    ok(&block);
}

fn pubkey_error(pubkey: [u8; 32]) -> Error {
    // The signature bytes are irrelevant: C2 fires before C3.
    err(&unsigned_with_key(pubkey, &[], b"c2"))
}

#[test]
fn c2_v1_y_not_on_curve() {
    assert_eq!(pubkey_error(small_y(2, false)), Error::InvalidPublicKey);
}

#[test]
fn c2_v1_non_canonical_y_not_small_order() {
    assert_eq!(pubkey_error(y_plus_p(3)), Error::InvalidPublicKey);
}

#[test]
fn c2_v1_non_canonical_small_order() {
    for y in [0u8, 1] {
        assert_eq!(pubkey_error(y_plus_p(y)), Error::InvalidPublicKey);
    }
}

#[test]
fn c2_v1_x_zero_sign_bit_set() {
    assert_eq!(pubkey_error(small_y(1, true)), Error::InvalidPublicKey);
}

#[test]
fn c2_v2_each_small_order_point() {
    for point in SMALL_ORDER {
        assert_eq!(
            pubkey_error(hex32(point)),
            Error::InvalidPublicKey,
            "{point}"
        );
    }
}

#[test]
fn c2_before_c3() {
    // A small-order key with an all-zero signature (which would fail V5): C2 is reported.
    assert_eq!(pubkey_error(hex32(SMALL_ORDER[0])), Error::InvalidPublicKey);
}

// ---------------------------------------------------------------------------------------------
// C3: InvalidSignature (V3 to V6)
// ---------------------------------------------------------------------------------------------

#[test]
fn c3_valid_signature() {
    let block = signed(&parents(3), b"c3");
    ok(&block);
}

#[test]
fn c3_deterministic_signature() {
    assert_eq!(signed(&parents(3), b"c3"), signed(&parents(3), b"c3"));
}

fn signature_of(block: &[u8]) -> [u8; 64] {
    block[sig_offset(block)..].try_into().unwrap()
}

/// ADR 0003 rule 16: the mandatory `S + L` vector.
#[test]
fn c3_v3_s_plus_l_is_rejected() {
    let mut block = signed(&parents(1), b"S + L");
    ok(&block);
    let sig = signature_of(&block);
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    let mut malleated = sig;
    malleated[32..].copy_from_slice(&add_le(&s, &L_LE));
    assert_ne!(malleated, sig);
    set_signature(&mut block, &malleated);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_v4_r_not_on_curve() {
    let mut block = signed(&[], b"v4");
    let mut sig = signature_of(&block);
    sig[..32].copy_from_slice(&small_y(2, false));
    set_signature(&mut block, &sig);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_v5_r_small_order() {
    for point in SMALL_ORDER {
        let mut block = signed(&[], b"v5");
        let mut sig = signature_of(&block);
        sig[..32].copy_from_slice(&hex32(point));
        set_signature(&mut block, &sig);
        assert_eq!(err(&block), Error::InvalidSignature, "{point}");
    }
}

#[test]
fn c3_v6_non_canonical_r() {
    // R = y + p with y = 3: decodes (ZIP-215) to a point that is not of small order, but is not the
    // canonical encoding of any [S]B − [k]A.
    assert!(VerifyingKey::from_bytes(&y_plus_p(3)).is_ok());
    let mut block = signed(&[], b"v6");
    let mut sig = signature_of(&block);
    sig[..32].copy_from_slice(&y_plus_p(3));
    set_signature(&mut block, &sig);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_bit_flipped_in_r_and_in_s() {
    let block = signed(&parents(2), b"flip");
    for byte in [0usize, 17, 31, 32, 40, 62] {
        let mut copy = block.clone();
        let off = sig_offset(&copy) + byte;
        copy[off] ^= 0x04;
        assert_eq!(err(&copy), Error::InvalidSignature, "byte {byte}");
    }
}

#[test]
fn c3_bit_flipped_in_payload() {
    let mut block = signed(&parents(2), b"flip");
    let off = sig_offset(&block) - 1;
    block[off] ^= 0x01;
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_signature_over_raw_block_id_without_prefix() {
    // ADR 0002: the signed message is SIG_PREFIX ‖ block_id, not block_id.
    let key = key_a();
    let mut block = signed(&[], b"raw");
    let id = parse(&block).unwrap().block_id();
    let sig = key.sign(id.as_bytes()).to_bytes();
    set_signature(&mut block, &sig);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_signature_over_plain_blake3_id() {
    // ADR 0002: the block_id is derive_key, not plain BLAKE3.
    let key = key_a();
    let mut block = signed(&[], b"plain");
    let plain = BlockId(*blake3::hash(parse(&block).unwrap().hashed_bytes()).as_bytes());
    assert_ne!(plain, parse(&block).unwrap().block_id());
    let sig = sign_block_id(&key, &plain).unwrap();
    set_signature(&mut block, &sig);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn c3_signature_by_another_key() {
    let mut block = signed(&[], b"other");
    let id = parse(&block).unwrap().block_id();
    let sig = sign_block_id(&key_b(), &id).unwrap();
    set_signature(&mut block, &sig);
    assert_eq!(err(&block), Error::InvalidSignature);
}

#[test]
fn sign_block_refuses_a_mismatched_key() {
    let mut block = signed(&[], &[]);
    assert_eq!(
        sign_block(&mut block, &key_b()),
        Err(sbtp_core::BuildError::KeyMismatch)
    );
}

// ---------------------------------------------------------------------------------------------
// Mixed-order public keys: frozen as vectors (docs/test-vectors/v1/valid_mixed_order_pubkey.json,
// c3_v6_cofactored_only.json), replayed by tests/vectors.rs. Forging them needs `hazmat`, which the
// test build no longer enables (review 2026-11-18, L-1 and L-4).
// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------
// Entry points and staged validation (review 2026-11-18, L-6)
// ---------------------------------------------------------------------------------------------

#[test]
fn staged_validation_equals_validate_submitted() {
    let block = signed(&parents(2), b"staged");
    let staged = parse(&block)
        .unwrap()
        .check_pow(0)
        .unwrap()
        .verify_signature()
        .unwrap();
    let direct = validate_submitted(&block, 0).unwrap();
    assert_eq!(staged.block_id(), direct.block_id());
    assert_eq!(staged.block().as_bytes(), direct.block().as_bytes());
}

#[test]
fn staged_validation_keeps_the_errors_of_each_stage() {
    // C1 at the check_pow stage.
    let block = signed(&[], b"staged pow");
    let zeros = parse(&block).unwrap().block_id().leading_zero_bits();
    assert_eq!(
        parse(&block).unwrap().check_pow(zeros + 1).unwrap_err(),
        Error::InsufficientPow {
            required: zeros + 1,
            actual: zeros
        }
    );
    // C2 and C3 at the verify_signature stage.
    let bad_key = unsigned_with_key(small_y(2, false), &[], b"staged");
    let checked = parse(&bad_key).unwrap().check_pow(0).unwrap();
    assert_eq!(
        checked.verify_signature().unwrap_err(),
        Error::InvalidPublicKey
    );
    let mut bad_sig = signed(&[], b"staged");
    let off = sig_offset(&bad_sig);
    bad_sig[off] ^= 0x01;
    let checked = parse(&bad_sig).unwrap().check_pow(0).unwrap();
    assert_eq!(
        checked.verify_signature().unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn pow_checked_exposes_the_id_before_the_signature() {
    // ADR 0003 rule 10: the relay looks the id up after C1, before C2 and C3.
    let block = signed(&[], b"lookup");
    let mut forged = block.clone();
    let off = sig_offset(&forged);
    forged[off + 40] ^= 0x01;
    let checked = parse(&forged).unwrap().check_pow(0).unwrap();
    assert_eq!(*checked.block_id(), compute_block_id(&block[..off]));
    assert_eq!(checked.block().as_bytes(), &forged[..]);
    // Bytes differ from the stored ones: the signature MUST be verified, and it fails.
    assert_eq!(
        checked.verify_signature().unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn validate_requested_and_submitted_agree_when_the_id_matches() {
    for (ps, payload) in [
        (0u8, &b""[..]),
        (3, b"agree"),
        (MAX_PARENTS, b"max parents"),
    ] {
        let block = signed(&parents(ps), payload);
        let id = *validate_submitted(&block, 0).unwrap().block_id();
        assert_eq!(*validate_requested(&block, 0, &id).unwrap().block_id(), id);
    }
}

// ---------------------------------------------------------------------------------------------
// Bounded mining (review 2026-11-18, L-2)
// ---------------------------------------------------------------------------------------------

#[test]
fn mine_refuses_a_difficulty_above_256_at_once() {
    use sbtp_core::BuildError;
    let key = key_a();
    let mut block = BlockBuilder::for_key(&key).build_unsigned().unwrap();
    let before = block.clone();
    for d in [257, 1_000, u32::MAX] {
        assert_eq!(
            mine(&mut block, d, u64::MAX),
            Err(BuildError::DifficultyTooHigh { difficulty: d })
        );
        // No nonce was tried: the block is untouched.
        assert_eq!(block, before);
    }
    // 256 is a legal difficulty: the search runs and stops at the attempt limit.
    assert_eq!(mine(&mut block, 256, 16), Err(BuildError::PowNotFound));
}

#[test]
fn build_refuses_a_difficulty_above_256_at_once() {
    use sbtp_core::BuildError;
    let key = key_a();
    for d in [257, u32::MAX] {
        assert_eq!(
            BlockBuilder::for_key(&key).build(&key, d),
            Err(BuildError::DifficultyTooHigh { difficulty: d })
        );
    }
    assert_eq!(sbtp_core::MAX_DIFFICULTY, 256);
    // ADR 0045 rule 1: the network difficulty.
    assert_eq!(sbtp_core::NETWORK_POW_DIFFICULTY, 16);
}

#[test]
fn build_stops_at_its_attempt_budget() {
    // Review 2026-11-18 M2, F-4: d = 200 can never be met in 64 attempts.
    use sbtp_core::BuildError;
    let key = key_a();
    assert_eq!(
        BlockBuilder::for_key(&key)
            .max_attempts(64)
            .build(&key, 200),
        Err(BuildError::PowNotFound)
    );
    // The default budget is finite and large enough for the difficulties of the tests.
    assert_eq!(sbtp_core::DEFAULT_MAX_ATTEMPTS, 1 << 28);
    assert_eq!(
        BlockBuilder::for_key(&key).build(&key, 4).map(|_| ()),
        Ok(())
    );
    let block = BlockBuilder::for_key(&key)
        .max_attempts(1 << 16)
        .build(&key, 4)
        .unwrap();
    assert!(parse(&block).unwrap().block_id().leading_zero_bits() >= 4);
}

/// Mines `block` in slices of `slice` attempts until it succeeds.
fn mine_in_slices(block: &mut [u8], difficulty: u32, slice: u64) -> (u64, BlockId) {
    loop {
        match mine(block, difficulty, slice) {
            Ok(found) => return found,
            Err(sbtp_core::BuildError::PowNotFound) => {}
            Err(other) => panic!("{other:?}"),
        }
    }
}

#[test]
fn sliced_mining_reaches_the_same_nonce_as_one_call() {
    let key = key_a();
    let unsigned = BlockBuilder::for_key(&key)
        .timestamp(TIMESTAMP)
        .payload(b"slices")
        .build_unsigned()
        .unwrap();
    let mut whole = unsigned.clone();
    let expected = mine(&mut whole, 8, u64::MAX).unwrap();
    // The search must take more than one attempt for the test to mean anything.
    assert!(expected.0 > 7, "winning nonce {}", expected.0);
    for slice in [1, 7] {
        let mut block = unsigned.clone();
        assert_eq!(
            mine_in_slices(&mut block, 8, slice),
            expected,
            "slice {slice}"
        );
        assert_eq!(block, whole, "slice {slice}");
    }
}

#[test]
fn exhaustion_advances_the_nonce_by_exactly_max_attempts() {
    let key = key_a();
    let mut block = BlockBuilder::for_key(&key)
        .nonce(1_000)
        .build_unsigned()
        .unwrap();
    // d = 256 is never met: each call spends its whole budget.
    for (budget, after) in [(0u64, 1_000u64), (1, 1_001), (37, 1_038)] {
        assert_eq!(
            mine(&mut block, 256, budget),
            Err(sbtp_core::BuildError::PowNotFound)
        );
        assert_eq!(parse(&block).unwrap().nonce(), after, "budget {budget}");
    }
    // End of the nonce space: u64::MAX is tried once, then every call fails without moving.
    let mut last = BlockBuilder::for_key(&key)
        .nonce(u64::MAX - 1)
        .build_unsigned()
        .unwrap();
    assert_eq!(
        mine(&mut last, 256, 10),
        Err(sbtp_core::BuildError::NonceSpaceExhausted)
    );
    assert_eq!(parse(&last).unwrap().nonce(), u64::MAX);
}

/// Review finding: the end of the nonce space is its own error, not `PowNotFound`, so that a
/// resume loop ends. Returned at exhaustion and by every later call that starts there.
#[test]
fn nonce_space_exhaustion_is_distinct_and_sticky() {
    use sbtp_core::BuildError;
    let key = key_a();
    let at = |nonce| {
        BlockBuilder::for_key(&key)
            .nonce(nonce)
            .build_unsigned()
            .unwrap()
    };
    // A slice that stops one short of u64::MAX is a spent budget: resumable.
    let mut block = at(u64::MAX - 2);
    assert_eq!(mine(&mut block, 256, 2), Err(BuildError::PowNotFound));
    assert_eq!(parse(&block).unwrap().nonce(), u64::MAX);
    // The next slice tries u64::MAX and reaches the end, whatever budget is left.
    assert_eq!(
        mine(&mut block, 256, 1),
        Err(BuildError::NonceSpaceExhausted)
    );
    assert_eq!(parse(&block).unwrap().nonce(), u64::MAX);
    // Every later call that starts at exhaustion reports it again.
    for budget in [1, 1_000, u64::MAX] {
        assert_eq!(
            mine(&mut block, 256, budget),
            Err(BuildError::NonceSpaceExhausted)
        );
        assert_eq!(parse(&block).unwrap().nonce(), u64::MAX);
    }
    // A slice that crosses the end in one call.
    let mut block = at(u64::MAX - 3);
    assert_eq!(
        mine(&mut block, 256, 10),
        Err(BuildError::NonceSpaceExhausted)
    );
    // The resume loop of a slicing caller now ends.
    let mut block = at(u64::MAX - 20);
    let mut calls = 0;
    let end = loop {
        calls += 1;
        match mine(&mut block, 256, 3) {
            Err(BuildError::PowNotFound) => {}
            other => break other,
        }
    };
    assert_eq!(end, Err(BuildError::NonceSpaceExhausted));
    assert_eq!(calls, 7);
    // `build` reports it too.
    assert_eq!(
        BlockBuilder::for_key(&key).nonce(u64::MAX).build(&key, 256),
        Err(BuildError::NonceSpaceExhausted)
    );
}

/// Review finding: the default mining budget is counted in bytes hashed, so that the cost of one
/// `build` call does not grow with the payload (spec §4, "Client bounds").
#[test]
fn default_mining_budget_is_independent_of_block_size() {
    use sbtp_core::{DEFAULT_MINING_BUDGET_BYTES, default_max_attempts};
    assert_eq!(DEFAULT_MINING_BUDGET_BYTES, 1 << 34);
    // A root block hashes 54 bytes, counted as one 64-byte BLAKE3 block.
    assert_eq!(default_max_attempts(MIN_BLOCK_LEN), 1 << 28);
    assert_eq!(
        default_max_attempts(MIN_BLOCK_LEN),
        sbtp_core::DEFAULT_MAX_ATTEMPTS
    );
    assert_eq!(default_max_attempts(0), 1 << 28);
    // The largest block hashes 65,845 bytes: attempts times bytes stays within the budget.
    let hashed = (MAX_BLOCK_LEN - 64) as u64;
    assert_eq!(hashed, 65_845);
    // Rounded up to whole 64-byte BLAKE3 blocks: 65,856 bytes compressed per attempt.
    let compressed = hashed.div_ceil(64) * 64;
    let attempts = default_max_attempts(MAX_BLOCK_LEN);
    assert_eq!(attempts, DEFAULT_MINING_BUDGET_BYTES / compressed);
    assert!(attempts * compressed <= DEFAULT_MINING_BUDGET_BYTES);
    assert!(attempts > 1 << 17);
    for len in [MIN_BLOCK_LEN, 129, 200, 1_088, 4_096, 30_000, MAX_BLOCK_LEN] {
        let a = default_max_attempts(len);
        let per = ((len - 64) as u64).div_ceil(64).max(1) * 64;
        assert!(a * per <= DEFAULT_MINING_BUDGET_BYTES, "len {len}");
        assert!((a + 1) * per > DEFAULT_MINING_BUDGET_BYTES, "len {len}");
    }
    // At least one attempt, whatever the length.
    assert_eq!(default_max_attempts(usize::MAX), 1);
}

// ---------------------------------------------------------------------------------------------
// R1 in the type and in the staged form (review 2026-11-18 M2, F-5)
// ---------------------------------------------------------------------------------------------

/// Storage code of a client: only accepts blocks checked against the identifier they were fetched
/// by. A `ValidatedBlock<'_, Submitted>` does not type-check here.
fn store_fetched(block: &sbtp_core::ValidatedBlock<'_, sbtp_core::Requested>) -> BlockId {
    *block.block_id()
}

#[test]
fn staged_r1_equals_validate_requested() {
    let block = signed(&parents(2), b"staged r1");
    let id = parse(&block).unwrap().block_id();
    let staged = parse(&block)
        .unwrap()
        .check_requested_id(&id)
        .unwrap()
        .check_pow(0)
        .unwrap()
        .verify_signature()
        .unwrap();
    let direct = validate_requested(&block, 0, &id).unwrap();
    assert_eq!(store_fetched(&staged), store_fetched(&direct));
    assert_eq!(staged.block().as_bytes(), &block[..]);
}

#[test]
fn staged_r1_runs_before_c1() {
    // A wrong identifier is reported at the R1 stage, even with an impossible difficulty.
    let block = signed(&[], b"staged r1 order");
    let id = parse(&block).unwrap().block_id();
    let other = pid(0x42);
    assert_eq!(
        parse(&block)
            .unwrap()
            .check_requested_id(&other)
            .unwrap_err(),
        Error::BlockIdMismatch {
            expected: other,
            actual: id
        }
    );
    let checked = parse(&block).unwrap().check_requested_id(&id).unwrap();
    assert_eq!(*checked.block_id(), id);
    assert!(matches!(
        checked.check_pow(257),
        Err(Error::InsufficientPow { required: 257, .. })
    ));
}

#[test]
fn submitted_and_requested_are_distinct_types() {
    let block = signed(&[], b"types");
    let submitted: sbtp_core::ValidatedBlock<'_, sbtp_core::Submitted> =
        validate_submitted(&block, 0).unwrap();
    let requested: sbtp_core::ValidatedBlock<'_, sbtp_core::Requested> =
        validate_requested(&block, 0, submitted.block_id()).unwrap();
    assert_eq!(submitted.block_id(), requested.block_id());
}

/// Code written once for both markers, through the sealed `Receipt` trait.
fn id_of_any<R: sbtp_core::Receipt>(block: &sbtp_core::ValidatedBlock<'_, R>) -> BlockId {
    *block.block_id()
}

#[test]
fn requested_converts_to_submitted_explicitly() {
    let block = signed(&parents(1), b"convert");
    let id = parse(&block).unwrap().block_id();
    let requested = validate_requested(&block, 0, &id).unwrap();
    // Dropping the R1 proof is explicit and keeps the block and its id.
    let submitted: sbtp_core::ValidatedBlock<'_, sbtp_core::Submitted> = requested.into_submitted();
    assert_eq!(id_of_any(&submitted), id);
    assert_eq!(id_of_any(&requested), id);
    assert_eq!(submitted.block().as_bytes(), &block[..]);
}

// ---------------------------------------------------------------------------------------------
// Accessors and error names
// ---------------------------------------------------------------------------------------------

#[test]
fn accessors_read_every_field() {
    let key = key_a();
    let ps = [pid(5), pid(6)];
    let block = BlockBuilder::for_key(&key)
        .timestamp(42)
        .nonce(7)
        .parents(&ps)
        .payload(b"payload")
        .build(&key, 0)
        .unwrap();
    let v = validate_submitted(&block, 0).unwrap();
    let b = v.block();
    assert_eq!(b.version(), 1);
    assert_eq!(b.timestamp(), 42);
    assert_eq!(b.nonce(), 7);
    assert_eq!(b.pubkey(), key.verifying_key().as_bytes());
    assert_eq!(b.parents(), &ps);
    assert_eq!(b.payload(), b"payload");
    assert_eq!(b.signature(), &signature_of(&block));
    assert_eq!(b.hashed_bytes(), &block[..block.len() - 64]);
    assert_eq!(*v.block_id(), compute_block_id(&block[..block.len() - 64]));
}

#[test]
fn error_names_match_the_spec() {
    let names = [
        Error::TooShort { len: 0 }.name(),
        Error::TooLong { len: 0 }.name(),
        Error::BadMagic { found: [0, 0] }.name(),
        Error::UnsupportedVersion { version: 0 }.name(),
        Error::TooManyParents { count: 0 }.name(),
        Error::Truncated {
            expected_min: 0,
            len: 0,
        }
        .name(),
        Error::TrailingBytes {
            expected: 0,
            len: 0,
        }
        .name(),
        Error::DuplicateParent {
            first: 0,
            second: 0,
        }
        .name(),
        Error::BlockIdMismatch {
            expected: pid(0),
            actual: pid(0),
        }
        .name(),
        Error::InsufficientPow {
            required: 0,
            actual: 0,
        }
        .name(),
        Error::InvalidPublicKey.name(),
        Error::InvalidSignature.name(),
    ];
    assert_eq!(
        names,
        [
            "TooShort",
            "TooLong",
            "BadMagic",
            "UnsupportedVersion",
            "TooManyParents",
            "Truncated",
            "TrailingBytes",
            "DuplicateParent",
            "BlockIdMismatch",
            "InsufficientPow",
            "InvalidPublicKey",
            "InvalidSignature",
        ]
    );
}

#[test]
fn builder_refuses_malformed_input() {
    use sbtp_core::BuildError;
    let key = key_a();
    let too_many = parents(MAX_PARENTS + 1);
    assert_eq!(
        BlockBuilder::for_key(&key).parents(&too_many).encoded_len(),
        Err(BuildError::TooManyParents {
            count: usize::from(MAX_PARENTS) + 1
        })
    );
    let dup = [pid(1), pid(2), pid(1)];
    assert_eq!(
        BlockBuilder::for_key(&key).parents(&dup).encoded_len(),
        Err(BuildError::DuplicateParent {
            first: 0,
            second: 2
        })
    );
    let big = vec![0u8; 65_536];
    assert_eq!(
        BlockBuilder::for_key(&key).payload(&big).encoded_len(),
        Err(BuildError::PayloadTooLong { len: 65_536 })
    );
    let mut small = [0u8; 117];
    assert_eq!(
        BlockBuilder::for_key(&key).write_unsigned(&mut small),
        Err(BuildError::BufferTooSmall {
            needed: 118,
            len: 117
        })
    );
}

#[test]
fn builder_errors_propagate_through_every_entry_point() {
    use sbtp_core::BuildError;
    let key = key_a();
    let too_many = parents(MAX_PARENTS + 1);
    let expected = BuildError::TooManyParents {
        count: usize::from(MAX_PARENTS) + 1,
    };
    let builder = BlockBuilder::for_key(&key).parents(&too_many);
    let mut out = vec![0u8; MAX_BLOCK_LEN];
    assert_eq!(builder.write_unsigned(&mut out), Err(expected));
    assert_eq!(builder.build_unsigned(), Err(expected));
    assert_eq!(builder.build(&key, 0), Err(expected));
    // The key is checked before anything is encoded: a builder that would also fail encoding
    // reports KeyMismatch.
    assert_eq!(builder.build(&key_b(), 0), Err(BuildError::KeyMismatch));
}

#[test]
fn mine_and_sign_refuse_a_malformed_buffer() {
    use sbtp_core::BuildError;
    // Non-zero filler, so that any write into the buffer would show.
    let original = vec![0xa5u8; MIN_BLOCK_LEN - 1];
    let mut short = original.clone();
    let expected = BuildError::Malformed(Error::TooShort {
        len: MIN_BLOCK_LEN - 1,
    });
    assert_eq!(mine(&mut short, 0, 1), Err(expected));
    // "On any other error, the block is unchanged."
    assert_eq!(short, original);
    assert_eq!(sign_block(&mut short, &key_a()), Err(expected));
    assert_eq!(short, original);
}

#[test]
fn validate_requested_reports_c1_after_r1_passes() {
    let (block, zeros) = mined(4);
    let id = parse(&block).unwrap().block_id();
    assert_eq!(
        validate_requested(&block, zeros + 1, &id).unwrap_err(),
        Error::InsufficientPow {
            required: zeros + 1,
            actual: zeros
        }
    );
}

#[test]
fn display_messages_carry_the_error_fields() {
    let bounds = [
        (
            Error::TooShort { len: 3 },
            format!("3 bytes, minimum {MIN_BLOCK_LEN}"),
        ),
        (
            Error::TooLong { len: 70_000 },
            format!("70000 bytes, maximum {MAX_BLOCK_LEN}"),
        ),
        (
            Error::TooManyParents { count: 9 },
            format!("9, maximum {MAX_PARENTS}"),
        ),
        (
            Error::TrailingBytes {
                expected: MIN_BLOCK_LEN,
                len: MIN_BLOCK_LEN + 1,
            },
            format!("{} bytes, exactly {MIN_BLOCK_LEN}", MIN_BLOCK_LEN + 1),
        ),
    ];
    for (error, needle) in bounds {
        let text = error.to_string();
        assert!(text.contains(&needle), "{text:?} lacks {needle:?}");
    }
    let cases = [
        (
            Error::BadMagic {
                found: [0xab, 0x0c],
            },
            "ab 0c",
        ),
        (Error::UnsupportedVersion { version: 2 }, "0x02"),
        (
            Error::Truncated {
                expected_min: 150,
                len: 140,
            },
            "140 bytes, at least 150",
        ),
        (
            Error::DuplicateParent {
                first: 0,
                second: 2,
            },
            "0 and 2",
        ),
        (
            Error::InsufficientPow {
                required: 9,
                actual: 3,
            },
            "3 leading zero bits, 9 required",
        ),
        (Error::InvalidPublicKey, "invalid public key"),
        (Error::InvalidSignature, "invalid signature"),
    ];
    for (error, needle) in cases {
        let text = error.to_string();
        assert!(text.contains(needle), "{text:?} lacks {needle:?}");
    }
    let mismatch = Error::BlockIdMismatch {
        expected: pid(0xaa),
        actual: pid(0x0b),
    }
    .to_string();
    assert!(mismatch.contains(&format!("requested {}", "aa".repeat(32))));
    assert!(mismatch.contains(&format!("received {}", "0b".repeat(32))));
}

#[test]
fn build_and_self_test_errors_display() {
    use sbtp_core::{BuildError, SelfTestError};
    let bounds = [
        (
            BuildError::TooManyParents { count: 9 },
            format!("9, maximum {MAX_PARENTS}"),
        ),
        (
            BuildError::PayloadTooLong {
                len: MAX_PAYLOAD_LEN + 1,
            },
            format!("{} bytes, maximum {MAX_PAYLOAD_LEN}", MAX_PAYLOAD_LEN + 1),
        ),
        (
            BuildError::BufferTooSmall {
                needed: MIN_BLOCK_LEN,
                len: 10,
            },
            format!("10 bytes, {MIN_BLOCK_LEN} needed"),
        ),
    ];
    for (error, needle) in bounds {
        let text = error.to_string();
        assert!(text.contains(&needle), "{text:?} lacks {needle:?}");
    }
    let cases = [
        (
            BuildError::DuplicateParent {
                first: 1,
                second: 3,
            },
            "1 and 3",
        ),
        (
            BuildError::Malformed(Error::TooShort { len: 0 }),
            "malformed block: block too short",
        ),
        (BuildError::KeyMismatch, "does not match"),
        (BuildError::PowNotFound, "no nonce"),
        (BuildError::NonceSpaceExhausted, "nonce space exhausted"),
        (BuildError::DifficultyTooHigh { difficulty: 257 }, "257"),
        (BuildError::Signing, "signing failed"),
    ];
    for (error, needle) in cases {
        let text = error.to_string();
        assert!(text.contains(needle), "{text:?} lacks {needle:?}");
    }
    let self_test_cases = [
        (
            SelfTestError::ValidBlockRejected(Error::InvalidSignature),
            "valid block was rejected: invalid signature",
        ),
        (SelfTestError::SPlusLAccepted, "legacy_compatibility"),
        (
            SelfTestError::SPlusLWrongError(Error::InvalidPublicKey),
            "rejected with invalid public key",
        ),
    ];
    for (error, needle) in self_test_cases {
        let text = error.to_string();
        assert!(text.contains(needle), "{text:?} lacks {needle:?}");
    }
}

#[test]
fn block_id_conversions_and_debug() {
    let raw = [0x5au8; 32];
    let id = BlockId::from_bytes(raw);
    assert_eq!(id, BlockId::from(raw));
    assert_eq!(id.as_ref(), &raw[..]);
    assert_eq!(format!("{id:?}"), format!("BlockId({})", "5a".repeat(32)));

    let block = signed(&parents(2), b"debug");
    let debug = format!("{:?}", parse(&block).unwrap());
    assert!(debug.starts_with("BlockRef"));
    assert!(debug.contains(&format!("len: {}", block.len())));
    assert!(debug.contains("payload_len: 5"));
}
