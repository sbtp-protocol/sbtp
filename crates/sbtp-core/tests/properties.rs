//! Property tests (proptest): encode/parse round trip, no panic on arbitrary input, format checks
//! against an independent model of ADR 0004, and arbitrary keys and signatures in well-formed frames
//! (review 2026-11-18, L-3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use proptest::collection::{btree_set, vec};
use proptest::prelude::*;
use sbtp_core::layout::MAX_PARENTS;
use sbtp_core::{
    BlockBuilder, BlockId, Error, compute_block_id, parse, validate_requested, validate_submitted,
};

/// Up to `MAX_PARENTS` distinct parents, in random (not sorted) order.
fn arb_parents() -> impl Strategy<Value = Vec<BlockId>> {
    btree_set(any::<[u8; 32]>(), 0..=usize::from(MAX_PARENTS))
        .prop_map(|set| set.into_iter().map(BlockId).collect::<Vec<_>>())
        .prop_shuffle()
}

/// Independent model of the format checks F1 to F9 (spec §2.2, ADR 0004), written from the spec
/// table with plain indexing and `u64` arithmetic, without the crate's layout helpers. The bounds
/// are pinned as literals on purpose (spec §2.2, ADR 0014), independently of `layout.rs`.
fn model(b: &[u8]) -> Result<(), Error> {
    let len = b.len();
    let len64 = len as u64;
    if len < 118 {
        return Err(Error::TooShort { len });
    }
    if len > 65_909 {
        return Err(Error::TooLong { len });
    }
    if b[0] != 0x53 || b[1] != 0x42 {
        return Err(Error::BadMagic {
            found: [b[0], b[1]],
        });
    }
    if b[2] != 0x01 {
        return Err(Error::UnsupportedVersion { version: b[2] });
    }
    let count = b[51];
    let n = u64::from(count);
    if n > 8 {
        return Err(Error::TooManyParents { count });
    }
    let min = 118 + 32 * n;
    if len64 < min {
        return Err(Error::Truncated {
            expected_min: usize::try_from(min).unwrap(),
            len,
        });
    }
    let off = usize::try_from(52 + 32 * n).unwrap();
    let p = u64::from(u16::from_be_bytes([b[off], b[off + 1]]));
    let exact = min + p;
    if len64 < exact {
        return Err(Error::Truncated {
            expected_min: usize::try_from(exact).unwrap(),
            len,
        });
    }
    if len64 > exact {
        return Err(Error::TrailingBytes {
            expected: usize::try_from(exact).unwrap(),
            len,
        });
    }
    let n = usize::from(count);
    for i in 0..n {
        for j in i + 1..n {
            if b[52 + 32 * i..84 + 32 * i] == b[52 + 32 * j..84 + 32 * j] {
                return Err(Error::DuplicateParent {
                    first: u8::try_from(i).unwrap(),
                    second: u8::try_from(j).unwrap(),
                });
            }
        }
    }
    Ok(())
}

/// A frame with a correct magic and version, Parents Count `count` (0 to 20 mostly, so F5 fires
/// sometimes), Payload Len `payload_len`, a length equal to `118 + 32·N + P` shifted by a small
/// delta (0 most often, so F8 passes), random bytes everywhere else, and optionally one duplicated
/// parent.
fn arb_frame() -> impl Strategy<Value = Vec<u8>> {
    let count = prop_oneof![
        8 => 0u8..=MAX_PARENTS,
        1 => MAX_PARENTS + 1..=20,
        1 => any::<u8>(),
    ];
    let payload_len = prop_oneof![
        6 => 0u16..600,
        1 => 65_000u16..=65_535,
        1 => any::<u16>(),
    ];
    let delta = prop_oneof![
        6 => Just(0i64),
        1 => prop_oneof![Just(-64i64), Just(-1), Just(1), Just(64)],
        1 => -300i64..300,
    ];
    (count, payload_len, delta)
        .prop_flat_map(|(count, payload_len, delta)| {
            let exact = 118 + 32 * i64::from(count) + i64::from(payload_len);
            let len = usize::try_from((exact + delta).max(0)).unwrap();
            (
                Just(count),
                Just(payload_len),
                vec(any::<u8>(), len),
                proptest::option::of((0..usize::from(MAX_PARENTS), 0..usize::from(MAX_PARENTS))),
            )
        })
        .prop_map(|(count, payload_len, mut bytes, dup)| {
            for (i, b) in [0x53u8, 0x42, 0x01].into_iter().enumerate() {
                if let Some(slot) = bytes.get_mut(i) {
                    *slot = b;
                }
            }
            if let Some(slot) = bytes.get_mut(51) {
                *slot = count;
            }
            let off = 52 + 32 * usize::from(count);
            for (i, b) in payload_len.to_be_bytes().into_iter().enumerate() {
                if let Some(slot) = bytes.get_mut(off + i) {
                    *slot = b;
                }
            }
            if let Some((i, j)) = dup {
                let n = usize::from(count.min(MAX_PARENTS));
                let (src, dst) = (52 + 32 * i, 52 + 32 * j);
                if i != j && i < n && j < n && dst + 32 <= bytes.len() && src + 32 <= bytes.len() {
                    let parent: [u8; 32] = bytes[src..src + 32].try_into().unwrap();
                    bytes[dst..dst + 32].copy_from_slice(&parent);
                }
            }
            bytes
        })
}

/// The 64 signature bytes from `R` and `S`; with `clear_top`, `S < 2^252 < L`, so V3 passes and the
/// later criteria are reached.
fn signature(r: [u8; 32], s: [u8; 32], clear_top: bool) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s);
    if clear_top {
        sig[63] &= 0x0f;
    }
    sig
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// encode → parse gives back every field, and re-encoding the parsed fields gives the same bytes.
    #[test]
    fn encode_parse_round_trip(
        timestamp in any::<u64>(),
        nonce in any::<u64>(),
        pubkey in any::<[u8; 32]>(),
        parents in arb_parents(),
        payload in vec(any::<u8>(), 0..2048),
    ) {
        let bytes = BlockBuilder::new(pubkey)
            .timestamp(timestamp)
            .nonce(nonce)
            .parents(&parents)
            .payload(&payload)
            .build_unsigned()
            .unwrap();
        let block = parse(&bytes).unwrap();
        prop_assert_eq!(block.version(), 1);
        prop_assert_eq!(block.timestamp(), timestamp);
        prop_assert_eq!(block.nonce(), nonce);
        prop_assert_eq!(block.pubkey(), &pubkey);
        prop_assert_eq!(block.parents(), &parents[..]);
        prop_assert_eq!(block.payload(), &payload[..]);
        prop_assert_eq!(block.signature(), &[0u8; 64]);

        let again = BlockBuilder::new(*block.pubkey())
            .timestamp(block.timestamp())
            .nonce(block.nonce())
            .parents(block.parents())
            .payload(block.payload())
            .build_unsigned()
            .unwrap();
        prop_assert_eq!(again, bytes);
    }

    /// A block signed by the seed key A validates through both entry points, and an accepted block
    /// re-encodes to the same bytes (ADR 0004 principle 1).
    #[test]
    fn signed_round_trip(
        timestamp in any::<u64>(),
        parents in arb_parents(),
        payload in vec(any::<u8>(), 0..512),
    ) {
        let key = key_a();
        let bytes = BlockBuilder::for_key(&key)
            .timestamp(timestamp)
            .parents(&parents)
            .payload(&payload)
            .build(&key, 0)
            .unwrap();
        let v = validate_submitted(&bytes, 0).unwrap();
        prop_assert_eq!(v.block().parents(), &parents[..]);
        prop_assert_eq!(v.block().payload(), &payload[..]);
        prop_assert!(validate_requested(&bytes, 0, v.block_id()).is_ok());

        let b = v.block();
        let mut again = BlockBuilder::new(*b.pubkey())
            .timestamp(b.timestamp())
            .nonce(b.nonce())
            .parents(b.parents())
            .payload(b.payload())
            .build_unsigned()
            .unwrap();
        set_signature(&mut again, b.signature());
        prop_assert_eq!(again, bytes);
    }

    /// Arbitrary bytes, half of them with a correct magic and version: parse and validate return,
    /// never panic, and agree on the format error.
    #[test]
    fn arbitrary_bytes_never_panic(
        mut bytes in vec(any::<u8>(), 0..1024),
        fix_prefix in any::<bool>(),
        difficulty in any::<u32>(),
        expected in any::<[u8; 32]>(),
    ) {
        if fix_prefix {
            for (i, b) in [0x53u8, 0x42, 0x01].into_iter().enumerate() {
                if let Some(slot) = bytes.get_mut(i) { *slot = b; }
            }
        }
        let parsed = parse(&bytes);
        let submitted = validate_submitted(&bytes, difficulty);
        let requested = validate_requested(&bytes, difficulty, &BlockId(expected));
        if let Err(e) = parsed {
            prop_assert_eq!(submitted.unwrap_err(), e);
            prop_assert_eq!(requested.unwrap_err(), e);
        }
    }

    /// Structured frames reach every format check, F8 and F9 included, and `parse` agrees with the
    /// independent model on the exact error. Well-formed frames go on to C1 to C3 and are never
    /// accepted (random key and signature).
    #[test]
    fn structured_frames_match_the_model(
        bytes in arb_frame(),
        difficulty in prop_oneof![Just(0u32), 0u32..300],
    ) {
        let parsed = parse(&bytes);
        prop_assert_eq!(parsed.map(|_| ()), model(&bytes));
        if let Ok(block) = parsed {
            let len = bytes.len();
            prop_assert_eq!(block.hashed_bytes(), &bytes[..len - 64]);
            prop_assert_eq!(&block.signature()[..], &bytes[len - 64..]);
            prop_assert_eq!(block.block_id(), compute_block_id(&bytes[..len - 64]));
            let n = usize::from(bytes[51]);
            prop_assert_eq!(block.parents().len(), n);
            prop_assert_eq!(block.payload(), &bytes[54 + 32 * n..len - 64]);
        }
        let result = validate_submitted(&bytes, difficulty);
        match (parsed, result) {
            (Err(e), r) => prop_assert_eq!(r.unwrap_err(), e),
            (Ok(_), Ok(_)) => prop_assert!(false, "random signature accepted"),
            (Ok(_), Err(e)) => {
                let late = matches!(
                    e,
                    Error::InsufficientPow { .. } | Error::InvalidPublicKey | Error::InvalidSignature
                );
                prop_assert!(late, "{:?}", e);
            }
        }
    }

    /// Well-formed frame, arbitrary `PubKey`, `R` and `S`: never accepted, never a panic, only C2 or
    /// C3 errors.
    #[test]
    fn arbitrary_key_and_signature_in_a_valid_frame(
        pubkey in any::<[u8; 32]>(),
        r in any::<[u8; 32]>(),
        s in any::<[u8; 32]>(),
        clear_top in any::<bool>(),
        parents in arb_parents(),
        payload in vec(any::<u8>(), 0..256),
    ) {
        let mut block = unsigned_with_key(pubkey, &parents, &payload);
        set_signature(&mut block, &signature(r, s, clear_top));
        prop_assert!(parse(&block).is_ok());
        let result = validate_submitted(&block, 0);
        prop_assert!(
            matches!(result, Err(Error::InvalidPublicKey | Error::InvalidSignature)),
            "{:?}", result
        );
    }

    /// Honest key A, well-formed frame, arbitrary signature: always `InvalidSignature`.
    #[test]
    fn honest_key_arbitrary_signature(
        r in any::<[u8; 32]>(),
        s in any::<[u8; 32]>(),
        clear_top in any::<bool>(),
        n in 0u8..=MAX_PARENTS,
    ) {
        let mut block = signed(&parents(n), b"arbitrary signature");
        set_signature(&mut block, &signature(r, s, clear_top));
        prop_assert_eq!(validate_submitted(&block, 0).unwrap_err(), Error::InvalidSignature);
    }

    /// Mutations of a valid block (byte flips, truncation, extension) never panic, and a block that
    /// still parses keeps a consistent length.
    #[test]
    fn mutated_valid_block_never_panics(
        flips in vec((any::<usize>(), any::<u8>()), 0..8),
        cut in proptest::option::of(any::<usize>()),
        extra in vec(any::<u8>(), 0..4),
    ) {
        let mut bytes = signed(&parents(3), b"mutation target");
        for (pos, mask) in flips {
            let i = pos % bytes.len();
            bytes[i] ^= mask;
        }
        if let Some(cut) = cut {
            bytes.truncate(cut % (bytes.len() + 1));
        }
        bytes.extend_from_slice(&extra);
        if let Ok(block) = parse(&bytes) {
            prop_assert_eq!(block.as_bytes().len(), bytes.len());
            prop_assert_eq!(block.hashed_bytes().len() + 64, bytes.len());
        }
        let _ = validate_submitted(&bytes, 0);
    }
}

/// The structured strategy does reach the late checks: a fixed sample hits F8 passing, F9 failing
/// and the cryptographic checks (guards against a strategy regression, review L-3).
#[test]
fn structured_strategy_reaches_the_late_checks() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strategy = arb_frame();
    let (mut well_formed, mut duplicate, mut trailing, mut too_many) = (0, 0, 0, 0);
    for _ in 0..512 {
        let bytes = strategy.new_tree(&mut runner).unwrap().current();
        match parse(&bytes) {
            Ok(_) => well_formed += 1,
            Err(Error::DuplicateParent { .. }) => duplicate += 1,
            Err(Error::TrailingBytes { .. }) => trailing += 1,
            Err(Error::TooManyParents { .. }) => too_many += 1,
            Err(_) => {}
        }
    }
    assert!(well_formed > 100, "well-formed: {well_formed}");
    assert!(duplicate > 5, "F9: {duplicate}");
    assert!(trailing > 5, "F8: {trailing}");
    assert!(too_many > 5, "F5: {too_many}");
}

// Inner signature of a sealed payload (`l2-grammar.md` §5.3).
proptest! {
    /// The builder writes the four fields then `msg`, and a signature by key A verifies.
    #[test]
    fn sealed_sig_layout_and_round_trip(
        outer in any::<[u8; 32]>(),
        id in any::<[u8; 32]>(),
        x in any::<[u8; 32]>(),
        msg in vec(any::<u8>(), 0..2_048),
    ) {
        let mut buf = vec![0u8; sbtp_core::SEALED_SIG_FIXED_LEN + msg.len()];
        let m = sbtp_core::sealed_sig_message(&outer, &id, &x, &msg, &mut buf).unwrap();
        let expected = [
            &sbtp_core::SEALED_SIG_PREFIX[..], &outer[..], &id[..], &x[..], &msg[..],
        ]
        .concat();
        prop_assert_eq!(m.as_bytes(), &expected[..]);
        let sig = sbtp_core::sign_sealed(&key_a(), &m).unwrap();
        let from = key_a().verifying_key().to_bytes();
        prop_assert_eq!(sbtp_core::verify_sealed(&from, &sig, &m), Ok(()));
    }

    /// Arbitrary sender keys, signatures and buffers: never a panic, and a random signature is
    /// never accepted.
    #[test]
    fn sealed_sig_arbitrary_inputs(
        from in any::<[u8; 32]>(),
        sig in vec(any::<u8>(), 64),
        msg in vec(any::<u8>(), 0..512),
        buf_len in 0usize..700,
    ) {
        let sig: [u8; 64] = sig.try_into().unwrap();
        let mut buf = vec![0u8; buf_len];
        let outer = [0x11; 32];
        match sbtp_core::sealed_sig_message(&outer, &outer, &outer, &msg, &mut buf) {
            Ok(m) => prop_assert!(sbtp_core::verify_sealed(&from, &sig, &m).is_err()),
            Err(e) => prop_assert!(
                matches!(e, sbtp_core::SealedSigError::BufferTooSmall { .. }),
                "{e:?}"
            ),
        }
    }
}
