//! # sbtp-l2
//!
//! Layer 2 of SBTP, generic part: grammar payloads `{v, kind, edges, body}` (ADR 0015), their
//! deterministic CBOR profile (ADR 0011), [`validate_l2_invariants`] (grammar validation), the
//! kind-row checker [`check_row`] and the `sbtp.*` kinds (`docs/spec/l2-grammar.md` §1 to §3). In
//! this crate, "spec §x" names a section of `l2-grammar.md`.
//!
//! It knows no application kind (ADR 0038 rules 6 and 9). An application runs its own validation
//! on the [`Payload`] that [`validate_l2_invariants`] returns: its kinds come back with a
//! [`Body::Raw`] body, which it reads with [`cbor::Reader`] and the [`body`] helpers, and it
//! checks their rows with [`check_row`]. An application encoder builds its body as a
//! [`cbor::Value`], wraps the bytes in [`Body::Raw`] and calls [`Payload::encode`].
//!
//! Layer 2 lives on clients and indexers only: a relay never parses a payload (ADR 0011 rule 3).
//! An invalid payload is reported as an [`L2Error`] and ignored by the caller; nothing here panics
//! on input.
//!
//! `no_std` with `alloc`.

#![no_std]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

pub mod body;
pub mod cbor;
mod decode;
mod encode;
mod error;
mod payload;

pub use decode::{
    KindRow, MAX_EDGES, MAX_PARENTS, check_row, validate_block, validate_l2_invariants,
};
pub use error::L2Error;
pub use payload::{Body, CHUNK_SIZE, Edge, Id, Manifest, Payload, Rel, Target};
