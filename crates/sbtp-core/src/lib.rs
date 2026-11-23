//! # sbtp-core
//!
//! Layer 0 of SBTP v1 (`SPEC.md` §1 to §4): the binary block format, the `block_id` (BLAKE3
//! `derive_key`), strict Ed25519 signatures and proof of work.
//!
//! `no_std` without the `std` feature, no `unsafe`, no allocation on the decoding and validation
//! path, no panic on any input.
//!
//! Receiving a block (SPEC §4):
//! - [`validate_submitted`]: a block pushed to a relay (`PUT`): F1 to F9, C1, C2, C3.
//! - [`validate_requested`]: a block fetched by its identifier: F1 to F9, R1, C1, C2, C3.
//! - Staged form for a relay: [`parse`] (F1 to F9), [`BlockRef::check_timestamp`] (P1),
//!   [`BlockRef::check_pow`] (C1), [`PowChecked::verify_signature`] (C2, C3).
//!
//! Only a [`ValidatedBlock`] is authenticated. Sending a block: [`UnsignedBlock`].

#![cfg_attr(not(feature = "std"), no_std)]

mod block;
mod block_id;
mod encode;
mod error;
mod verify;

pub use block::{
    BlockRef, HASH_LEN, MAX_BLOCK_LEN, MAX_PARENTS, MIN_BLOCK_LEN, PUBKEY_LEN, SIGNATURE_LEN, parse,
};
pub use block_id::{
    BLOCK_ID_CONTEXT, BlockId, ParseBlockIdError, SIG_PREFIX, SIGNED_MESSAGE_LEN, compute_block_id,
};
pub use encode::{EncodeError, UnsignedBlock};
pub use error::Error;
pub use verify::{PowChecked, ValidatedBlock, validate_requested, validate_submitted};

/// Re-export of the Ed25519 signing key type, so that callers need no direct dependency.
pub use ed25519_dalek::SigningKey;
