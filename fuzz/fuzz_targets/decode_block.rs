//! Fuzz target for the `sbtp-core` decoder and validation path (ADR 0004 "Security", review
//! 2026-11-18 L-3).
//!
//! Input: one control byte, then the candidate block.
//! - bits 0-2 pick the difficulty among `DIFFICULTIES`;
//! - bits 3-4 pick the mode: 0 submitted (`PUT`), 1 requested by its own `block_id`, 2 requested
//!   by another identifier, 3 re-signed by key A to reach the accepting path.
//!
//! Oracles:
//! - no panic, whatever the input;
//! - `parse`, `validate_submitted`, `validate_requested` and the staged form agree on the first
//!   failing check;
//! - R1: a block requested by another identifier always fails with `BlockIdMismatch` once
//!   well-formed;
//! - an accepted block re-encodes to exactly the input bytes (ADR 0004 principle 1).
//!
//! Key A comes from the public seed 32 x 0x01, a test key.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sbtp_core::{
    BlockBuilder, BlockId, BlockRef, Error, Receipt, SigningKey, ValidatedBlock, layout, parse,
    sign_block,
    validate_requested, validate_submitted,
};

const DIFFICULTIES: [u32; 8] = [0, 1, 4, 8, 16, 256, 257, u32::MAX];

fn key_a() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_bytes(&[0x01; 32]))
}

/// Re-encodes the fields of a parsed block with the builder and the received signature.
fn reencode(block: &BlockRef<'_>) -> Vec<u8> {
    let mut out = BlockBuilder::new(*block.pubkey())
        .timestamp(block.timestamp())
        .nonce(block.nonce())
        .parents(block.parents())
        .payload(block.payload())
        .build_unsigned()
        .expect("a parsed block has a valid shape");
    let off = out.len() - layout::SIGNATURE_LEN;
    out[off..].copy_from_slice(block.signature());
    out
}

fn check_accepted<R: Receipt>(v: &ValidatedBlock<'_, R>, bytes: &[u8]) {
    assert_eq!(v.block().as_bytes(), bytes);
    assert_eq!(reencode(v.block()), bytes, "accepted block does not re-encode");
    assert_eq!(*v.block_id(), v.block().block_id());
}

/// Same verdict: same error, or both accepted with the same identifier.
/// The marker `R` (R1 run or not) may differ between the two results.
fn same<R: Receipt, S: Receipt>(a: &Result<ValidatedBlock<'_, R>, Error>, b: &Result<ValidatedBlock<'_, S>, Error>) {
    match (a, b) {
        (Ok(x), Ok(y)) => assert_eq!(x.block_id(), y.block_id()),
        (Err(x), Err(y)) => assert_eq!(x, y),
        (Ok(x), Err(e)) => panic!("verdicts differ: accepted {} / {e:?}", x.block_id()),
        (Err(e), Ok(y)) => panic!("verdicts differ: {e:?} / accepted {}", y.block_id()),
    }
}

fn check(bytes: &[u8], difficulty: u32, mode: u8) {
    let parsed = parse(bytes);
    let submitted = validate_submitted(bytes, difficulty);

    let block = match parsed {
        Err(e) => {
            // Format errors come first, whatever the entry point.
            assert_eq!(submitted.unwrap_err(), e);
            assert_eq!(
                validate_requested(bytes, difficulty, &BlockId([0; 32])).unwrap_err(),
                e
            );
            return;
        }
        Ok(block) => block,
    };

    // A well-formed block: invariants of the view.
    let len = bytes.len();
    assert!((layout::MIN_BLOCK_LEN..=layout::MAX_BLOCK_LEN).contains(&len));
    assert_eq!(block.as_bytes(), bytes);
    assert_eq!(block.hashed_bytes(), &bytes[..len - layout::SIGNATURE_LEN]);
    assert!(block.parents().len() <= usize::from(layout::MAX_PARENTS));
    let id = block.block_id();

    // The staged form gives the same verdict as the one-call form.
    let staged = block
        .check_pow(difficulty)
        .and_then(sbtp_core::PowChecked::verify_signature);
    same(&staged, &submitted);
    if let Ok(v) = &submitted {
        check_accepted(v, bytes);
    }

    match mode {
        0 => {}
        1 => {
            // R1 passes: same verdict as a PUT, one-call and staged (R1 stage before C1).
            let requested = validate_requested(bytes, difficulty, &id);
            same(&requested, &submitted);
            let staged_r1 = block
                .check_requested_id(&id)
                .and_then(|c| c.check_pow(difficulty))
                .and_then(sbtp_core::PowChecked::verify_signature);
            same(&staged_r1, &requested);
            // Dropping the R1 proof gives the submitted verdict.
            same(&requested.map(ValidatedBlock::into_submitted), &submitted);
        }
        2 => {
            let mut other = id;
            other.0[31] ^= 0x01;
            let mismatch = Error::BlockIdMismatch {
                expected: other,
                actual: id,
            };
            assert_eq!(
                validate_requested(bytes, difficulty, &other).unwrap_err(),
                mismatch
            );
            assert_eq!(block.check_requested_id(&other).unwrap_err(), mismatch);
        }
        _ => {
            // Re-sign under key A: the block must then be accepted at difficulty 0, and at
            // `difficulty` exactly when its block_id has enough leading zero bits.
            let mut copy = bytes.to_vec();
            copy[layout::OFFSET_PUBKEY..layout::OFFSET_PUBKEY + layout::PUBKEY_LEN]
                .copy_from_slice(key_a().verifying_key().as_bytes());
            let new_id = sign_block(&mut copy, key_a()).expect("well-formed block signs");
            let v = validate_submitted(&copy, 0).expect("re-signed block is valid");
            check_accepted(&v, &copy);
            assert_eq!(*v.block_id(), new_id);
            let r = validate_requested(&copy, difficulty, &new_id);
            if new_id.leading_zero_bits() >= difficulty {
                check_accepted(&r.expect("enough PoW"), &copy);
            } else {
                assert!(matches!(r, Err(Error::InsufficientPow { .. })));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, bytes)) = data.split_first() else {
        return;
    };
    let difficulty = DIFFICULTIES[usize::from(control & 0x07)];
    let mode = (control >> 3) & 0x03;
    check(bytes, difficulty, mode);
});
