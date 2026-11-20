//! # sbtp-core
//!
//! Layer 0 of the SBTP protocol: binary block format, `block_id` identifier
//! (BLAKE3 `derive_key`), strict Ed25519 signature and proof of work (PoW).
//!
//! Normative specification: `docs/spec/sbtp-core-v0.2.md`, ADRs 0001 to 0005 and 0007.
//! This crate is `no_std` without the `std` feature, contains no `unsafe` (`forbid` lint at
//! workspace level) and does not allocate on the parsing and validation path.
//!
//! Receiving a block (spec §3.4):
//! - [`validate_submitted`]: a block submitted to a relay (`PUT`): F1 to F9, C1, C2, C3. Yields a
//!   [`ValidatedBlock<Submitted>`].
//! - [`validate_requested`]: a block fetched by its identifier (`GET`, synchronisation): F1 to F9,
//!   R1, C1, C2, C3. Yields a [`ValidatedBlock<Requested>`].
//! - Staged form: [`parse`] (F1 to F9), then [`BlockRef::check_pow`] (C1) for a submitted block, or
//!   [`BlockRef::check_requested_id`] (R1) then [`IdChecked::check_pow`] (C1) for a requested one,
//!   then [`PowChecked::verify_signature`] (C2, C3). Only a [`ValidatedBlock`] is authenticated.
//! - [`self_test`]: start-up replay of the frozen `S + L` vector (ADR 0003 rule 16).
//!
//! Sending a block: [`BlockBuilder`], [`mine`], [`sign_block`].
//!
//! Inner signature of a sealed layer 2 payload (`l2-grammar.md` §5.3, ADR 0016 rule 15): the typed
//! builder [`sealed_sig_message`], then [`sign_sealed`] or [`verify_sealed`] (strict, V1 to V6).
//! These and the block signature are the only messages this crate signs or verifies.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

// The `vector-gen` feature only serves the vector generator, which runs in the dev profile. It
// changes no code of this crate, but unifies `ed25519-dalek/hazmat` (and so `raw_sign`) into the
// whole build. Refuse any optimised build without debug assertions, that is any release artefact
// (review 2026-11-18 M2, F-6). A `cargo deny` feature ban cannot express this while
// `[graph] all-features = true` is set.
#[cfg(all(feature = "vector-gen", not(debug_assertions)))]
compile_error!("the `vector-gen` feature is tooling only: never build a release artefact with it");

mod block;
mod block_id;
mod builder;
pub mod consts;
mod error;
pub mod layout;
mod sealed_sig;
mod self_test;
mod verify;

pub use block::{BlockRef, parse};
pub use block_id::{BlockId, MAX_DIFFICULTY, compute_block_id};
pub use builder::{
    BlockBuilder, BuildError, DEFAULT_MAX_ATTEMPTS, DEFAULT_MINING_BUDGET_BYTES,
    default_max_attempts, mine, sign_block, sign_block_id,
};
pub use consts::{
    BLOCK_ID_CONTEXT, ENC_KEY_DIRECTORY_CONTEXT, SEALED_HPKE_INFO, SEALED_SIG_PREFIX, SIG_PREFIX,
    SIGNED_MESSAGE_LEN,
};
pub use error::Error;
pub use sealed_sig::{
    SEALED_SIG_FIXED_LEN, SealedSigError, SealedSigMessage, sealed_sig_message,
    sealed_sig_message_len, sign_sealed, verify_sealed,
};
pub use self_test::{
    S_PLUS_L_BLOCK, S_PLUS_L_EXPECTED_ERROR, SELF_TEST_BLOCK_ID, SELF_TEST_BLOCK_LEN,
    SELF_TEST_VALID_BLOCK, SelfTestError, self_test,
};
pub use verify::{
    IdChecked, PowChecked, Receipt, Requested, Submitted, ValidatedBlock, validate_requested,
    validate_submitted,
};

/// Re-export of the Ed25519 signing key type, so that callers need no direct dependency.
pub use ed25519_dalek::SigningKey;
