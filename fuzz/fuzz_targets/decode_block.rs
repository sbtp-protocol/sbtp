//! Fuzz target for the `sbtp-core` decoder and validation path.
//!
//! Input: one control byte, then the candidate block.
//! - bits 0-2 pick the difficulty among `DIFFICULTIES`;
//! - bits 3-4 pick the mode: 0 submitted, 1 requested by its own `block_id`, 2 requested by another
//!   identifier, 3 re-signed by key A to reach the accepting path.
//!
//! Oracles: no panic; `parse`, `validate_submitted`, `validate_requested` and the staged form agree
//! on the first failing check; R1 rejects another identifier once the block is well-formed; a parsed
//! block re-encodes to the same length and `block_id`.
//!
//! Key A comes from the public seed 32 x 0x01, a test key.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbtp_core::{
    BlockId, BlockRef, Error, SigningKey, UnsignedBlock, ValidatedBlock, parse, validate_requested,
    validate_submitted,
};

const DIFFICULTIES: [u32; 8] = [0, 1, 4, 8, 16, 256, 257, u32::MAX];

fn fields<'a>(block: &BlockRef<'a>) -> UnsignedBlock<'a> {
    UnsignedBlock {
        timestamp: block.timestamp(),
        nonce: block.nonce(),
        pubkey: *block.pubkey(),
        parents: block.parents(),
        payload: block.payload(),
    }
}

fn same(a: &Result<ValidatedBlock<'_>, Error>, b: &Result<ValidatedBlock<'_>, Error>) {
    match (a, b) {
        (Ok(x), Ok(y)) => assert_eq!(x.block_id(), y.block_id()),
        (Err(x), Err(y)) => assert_eq!(x, y),
        _ => panic!("verdicts differ: {a:?} / {b:?}"),
    }
}

fn check(bytes: &[u8], difficulty: u32, mode: u8) {
    let submitted = validate_submitted(bytes, difficulty);
    let block = match parse(bytes) {
        Err(e) => {
            assert_eq!(submitted.unwrap_err(), e);
            assert_eq!(
                validate_requested(bytes, difficulty, &BlockId([0; 32])).unwrap_err(),
                e
            );
            return;
        }
        Ok(block) => block,
    };
    assert_eq!(block.as_bytes(), bytes);
    let id = block.block_id();
    assert_eq!(fields(&block).block_id(), Ok(id));
    assert_eq!(fields(&block).encoded_len(), Ok(bytes.len()));
    let staged = block
        .check_pow(difficulty)
        .and_then(sbtp_core::PowChecked::verify_signature);
    same(&staged, &submitted);
    match mode {
        0 => {}
        1 => same(&validate_requested(bytes, difficulty, &id), &submitted),
        2 => {
            let mut other = id;
            other.0[31] ^= 0x01;
            assert_eq!(
                validate_requested(bytes, difficulty, &other).unwrap_err(),
                Error::BlockIdMismatch
            );
        }
        _ => {
            let key = SigningKey::from_bytes(&[0x01; 32]);
            let resigned = UnsignedBlock {
                pubkey: key.verifying_key().to_bytes(),
                ..fields(&block)
            };
            let copy = resigned.sign(&key).expect("a parsed block re-encodes");
            let v = validate_submitted(&copy, 0).expect("a re-signed block is valid");
            assert_eq!(v.block().as_bytes(), &copy[..]);
            let new_id = *v.block_id();
            let r = validate_requested(&copy, difficulty, &new_id);
            assert_eq!(r.is_ok(), new_id.meets_difficulty(difficulty));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, bytes)) = data.split_first() else {
        return;
    };
    let difficulty = DIFFICULTIES[usize::from(control & 0x07)];
    check(bytes, difficulty, (control >> 3) & 0x03);
});
