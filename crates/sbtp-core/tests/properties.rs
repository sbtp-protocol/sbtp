//! Property tests: encode/decode round trip, and validation never panics. Key A comes from the
//! public seed 32 x 0x01.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use proptest::collection::{hash_set, vec};
use proptest::prelude::*;
use sbtp_core::{
    BlockId, SigningKey, UnsignedBlock, parse, validate_requested, validate_submitted,
};

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // spec §1: every encoded block parses back to its fields, and validates.
    #[test]
    fn round_trip(
        timestamp in any::<u64>(),
        nonce in any::<u64>(),
        parents in hash_set(any::<[u8; 32]>(), 0..=8),
        payload in vec(any::<u8>(), 0..2048),
    ) {
        let parents: Vec<BlockId> = parents.into_iter().map(BlockId).collect();
        let key = key_a();
        let fields = UnsignedBlock {
            timestamp, nonce, pubkey: key.verifying_key().to_bytes(), parents: &parents, payload: &payload,
        };
        let bytes = fields.sign(&key).unwrap();
        prop_assert_eq!(bytes.len(), fields.encoded_len().unwrap());
        let ok = validate_submitted(&bytes, 0).unwrap();
        let block = ok.block();
        prop_assert_eq!(block.timestamp(), timestamp);
        prop_assert_eq!(block.nonce(), nonce);
        prop_assert_eq!(block.parents(), &parents[..]);
        prop_assert_eq!(block.payload(), &payload[..]);
        prop_assert_eq!(*ok.block_id(), fields.block_id().unwrap());
        prop_assert!(validate_requested(&bytes, 0, ok.block_id()).is_ok());
    }

    // spec §4: arbitrary bytes give a Result, never a panic; parse and validation agree.
    #[test]
    fn never_panics(bytes in vec(any::<u8>(), 0..1024), d in any::<u32>()) {
        let parsed = parse(&bytes);
        let submitted = validate_submitted(&bytes, d);
        if let Err(e) = parsed {
            prop_assert_eq!(submitted.unwrap_err(), e);
        }
        let _ = validate_requested(&bytes, d, &BlockId([0; 32]));
    }

    // Mutating a valid block never panics, and a changed byte outside the signature never
    // validates with the old signature.
    #[test]
    fn mutation_is_rejected(index in any::<prop::sample::Index>(), flip in 1u8..=255) {
        let parents = [BlockId([1; 32]), BlockId([2; 32])];
        let key = key_a();
        let fields = UnsignedBlock {
            timestamp: 1, nonce: 2, pubkey: key.verifying_key().to_bytes(), parents: &parents, payload: b"abc",
        };
        let mut bytes = fields.sign(&key).unwrap();
        let i = index.index(bytes.len());
        bytes[i] ^= flip;
        prop_assert!(validate_submitted(&bytes, 0).is_err());
    }
}
