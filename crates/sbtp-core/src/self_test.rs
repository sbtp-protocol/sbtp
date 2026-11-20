//! Start-up self-test of strict verification (ADR 0003 rule 16, review 2026-11-18 L-5).
//!
//! Cargo unifies features across the dependency graph: one crate enabling
//! `ed25519-dalek/legacy_compatibility` anywhere weakens V3 (`S < L`) in every binary. Rule 16
//! makes this executable: every shipped binary MUST replay the frozen `S + L` vector at start-up
//! and refuse to run if it is accepted. This module provides that check; no binary calls it yet
//! (see [`self_test`]).
//!
//! The two blocks are the frozen vectors `docs/test-vectors/v1/self_test_valid.json` and
//! `docs/test-vectors/v1/c3_v3_s_plus_l.json`: key A (public seed 32 × `0x01`), timestamp
//! 1,700,000,000,000, nonce 0, no parent, payload `"S + L"`. They differ only in the last 32 bytes:
//! `S` and `S + L`, with `L = 2^252 + 27742317777372353535851937790883648493`.

use crate::block_id::BlockId;
use crate::error::Error;
use crate::verify::validate_requested;

/// Length of both self-test blocks: 118 + 5 bytes of payload.
pub const SELF_TEST_BLOCK_LEN: usize = 123;

/// A valid block (vector `self_test_valid`). Must validate at difficulty 0.
///
/// Layout: magic and version (3 bytes), Timestamp (8), Nonce (8), `PubKey` of key A (32), Parents
/// Count 0 (1), Payload Len 5 (2), payload `"S + L"` (5), `R` (32), `S` (32).
pub const SELF_TEST_VALID_BLOCK: [u8; SELF_TEST_BLOCK_LEN] = [
    0x53, 0x42, 0x01, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c,
    0xba, 0x5d, 0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4,
    0x0f, 0x6f, 0x5c, 0x00, 0x00, 0x05, 0x53, 0x20, 0x2b, 0x20, 0x4c, 0xfb, 0x63, 0x07, 0x49, 0x4d,
    0x2c, 0xfd, 0x35, 0x82, 0x0a, 0xb3, 0x9f, 0x52, 0x58, 0xb5, 0xb2, 0xce, 0xd9, 0x93, 0x5d, 0xb2,
    0xb6, 0x46, 0xb1, 0x56, 0xbb, 0xd6, 0x1d, 0x73, 0x36, 0xfc, 0x27, 0x31, 0x44, 0xde, 0xba, 0xe2,
    0xa6, 0x53, 0x2b, 0x91, 0x95, 0x10, 0x7d, 0x83, 0xb1, 0x3a, 0x7b, 0x74, 0xce, 0xdc, 0xe9, 0x83,
    0xc5, 0x41, 0x86, 0xad, 0x25, 0x5d, 0xcf, 0xa4, 0xb1, 0x33, 0x04,
];

/// The `block_id` of both self-test blocks (the signature is not covered by it, spec §3.4).
pub const SELF_TEST_BLOCK_ID: BlockId = BlockId([
    0xf0, 0xce, 0x44, 0x41, 0xbc, 0xd0, 0x47, 0x5f, 0x18, 0xe0, 0x71, 0x86, 0x2d, 0x24, 0xae, 0x65,
    0x27, 0x7f, 0xe5, 0xec, 0xad, 0xca, 0xd8, 0x03, 0x10, 0x0b, 0xb9, 0xd8, 0x50, 0x49, 0x75, 0x5d,
]);

/// [`SELF_TEST_VALID_BLOCK`] with `S` replaced by `S + L` (vector `c3_v3_s_plus_l`). Must be
/// rejected with [`S_PLUS_L_EXPECTED_ERROR`].
pub const S_PLUS_L_BLOCK: [u8; SELF_TEST_BLOCK_LEN] = [
    0x53, 0x42, 0x01, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c,
    0xba, 0x5d, 0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4,
    0x0f, 0x6f, 0x5c, 0x00, 0x00, 0x05, 0x53, 0x20, 0x2b, 0x20, 0x4c, 0xfb, 0x63, 0x07, 0x49, 0x4d,
    0x2c, 0xfd, 0x35, 0x82, 0x0a, 0xb3, 0x9f, 0x52, 0x58, 0xb5, 0xb2, 0xce, 0xd9, 0x93, 0x5d, 0xb2,
    0xb6, 0x46, 0xb1, 0x56, 0xbb, 0xd6, 0x1d, 0x73, 0x36, 0xfc, 0x27, 0x1e, 0x18, 0xd4, 0x17, 0xfd,
    0x09, 0x66, 0x83, 0x67, 0x32, 0x08, 0x20, 0x62, 0xab, 0x19, 0x90, 0x74, 0xce, 0xdc, 0xe9, 0x83,
    0xc5, 0x41, 0x86, 0xad, 0x25, 0x5d, 0xcf, 0xa4, 0xb1, 0x33, 0x14,
];

/// The error the `S + L` block must produce: C3, criterion V3.
pub const S_PLUS_L_EXPECTED_ERROR: Error = Error::InvalidSignature;

/// Why the self-test failed. Any of these means the binary MUST NOT start (ADR 0003 rule 16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestError {
    /// The valid block was rejected: verification is broken or stricter than the spec.
    ValidBlockRejected(Error),
    /// The `S + L` block was accepted: `S < L` is not enforced (`legacy_compatibility` is on).
    SPlusLAccepted,
    /// The `S + L` block was rejected, but not with [`S_PLUS_L_EXPECTED_ERROR`].
    SPlusLWrongError(Error),
}

impl core::fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ValidBlockRejected(error) => {
                write!(f, "self-test: the valid block was rejected: {error}")
            }
            Self::SPlusLAccepted => f.write_str(
                "self-test: the S + L block was accepted; strict verification is off \
                 (is ed25519-dalek/legacy_compatibility enabled?)",
            ),
            Self::SPlusLWrongError(error) => write!(
                f,
                "self-test: the S + L block was rejected with {error}, expected invalid signature"
            ),
        }
    }
}

impl core::error::Error for SelfTestError {}

/// Replays the frozen self-test vectors through the full validation path (ADR 0003 rule 16).
///
/// The relay, the CLI and the WASM initialisation MUST call it at start-up and MUST refuse to run
/// on `Err` (ADR 0003 rule 16). **Not wired yet:** this crate only provides the check; calling it
/// is a task of Phase 2 (relay) and Phase 3 (CLI, WASM), and nothing enforces it today. Within
/// this crate the same vectors run in `cargo test`.
///
/// Cost: two signature verifications. No allocation, `no_std`.
///
/// # Errors
///
/// A [`SelfTestError`] when the library does not behave as the spec requires.
pub fn self_test() -> Result<(), SelfTestError> {
    run(&SELF_TEST_VALID_BLOCK, &SELF_TEST_BLOCK_ID, &S_PLUS_L_BLOCK)
}

fn run(valid: &[u8], id: &BlockId, s_plus_l: &[u8]) -> Result<(), SelfTestError> {
    // Requested by identifier: exercises F1 to F9, R1, C1, C2 and C3.
    validate_requested(valid, 0, id).map_err(SelfTestError::ValidBlockRejected)?;
    // spec §3.2 V3: S ≥ L is rejected. Same block_id, so R1 passes and C3 must fire.
    match validate_requested(s_plus_l, 0, id) {
        Ok(_) => Err(SelfTestError::SPlusLAccepted),
        Err(error) if error == S_PLUS_L_EXPECTED_ERROR => Ok(()),
        Err(error) => Err(SelfTestError::SPlusLWrongError(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_passes() {
        assert_eq!(self_test(), Ok(()));
    }

    // Each failure branch, by feeding the wrong blocks to the same logic.
    #[test]
    fn s_plus_l_accepted_is_reported() {
        assert_eq!(
            run(
                &SELF_TEST_VALID_BLOCK,
                &SELF_TEST_BLOCK_ID,
                &SELF_TEST_VALID_BLOCK
            ),
            Err(SelfTestError::SPlusLAccepted)
        );
    }

    #[test]
    fn valid_block_rejected_is_reported() {
        assert_eq!(
            run(&S_PLUS_L_BLOCK, &SELF_TEST_BLOCK_ID, &S_PLUS_L_BLOCK),
            Err(SelfTestError::ValidBlockRejected(Error::InvalidSignature))
        );
    }

    #[test]
    fn wrong_error_is_reported() {
        let truncated = &S_PLUS_L_BLOCK[..SELF_TEST_BLOCK_LEN - 1];
        assert!(matches!(
            run(&SELF_TEST_VALID_BLOCK, &SELF_TEST_BLOCK_ID, truncated),
            Err(SelfTestError::SPlusLWrongError(Error::Truncated { .. }))
        ));
    }

    #[test]
    fn blocks_differ_only_in_s() {
        let split = SELF_TEST_BLOCK_LEN - 32;
        assert_eq!(SELF_TEST_VALID_BLOCK[..split], S_PLUS_L_BLOCK[..split]);
        assert_ne!(SELF_TEST_VALID_BLOCK[split..], S_PLUS_L_BLOCK[split..]);
    }
}
