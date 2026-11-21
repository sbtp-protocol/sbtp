//! # sbtp-seal
//!
//! The sealed envelope of the SBTP layer 2 grammar (`docs/spec/l2-grammar.md` §5, ADR 0016,
//! ADR 0039): HPKE seal and open, the four length buckets and their padding, the inner signature,
//! and the key directory tag. In this crate, "spec §x" names a section of `l2-grammar.md`.
//!
//! - Sender: [`seal`] turns an encoded grammar payload `msg` into the payload of an `sbtp.enc`
//!   block, with a fresh ephemeral signer for the outer block.
//! - Recipient: [`open`] runs steps (4) to (8) of the order of checks of spec §5.3 on an outer
//!   body that already passed layer 0 and grammar validation.
//! - Tags: [`directory_tag`] and [`is_directory_tag`] (spec §5.5), [`application_tag`] for the
//!   tags an application defines (spec §5.4).
//!
//! The suite is fixed (spec §5.1): HPKE base mode, single-shot, DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, `ChaCha20Poly1305`, through `hpke` 0.15.1 (review
//! `docs/security/2026-11-20-hpke-dependency.md`). The inner signature reuses the typed builder
//! and the strict verifier of `sbtp-core`; payloads are validated with `sbtp-l2`.
//!
//! The crate draws no randomness of its own: the caller passes a `CryptoRng`, which MUST be the
//! operating system's secure source outside tests (spec §5.1). Secret material (private keys,
//! seeds, plaintexts) is wiped on drop. Nothing here panics on input. `no_std` with `alloc`.

#![no_std]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

mod bucket;
mod error;
mod keys;
mod open;
mod seal;
mod tag;
#[cfg(test)]
mod tests;

pub use bucket::{AEAD_TAG_LEN, Bucket};
pub use error::{OpenError, SealError, TagError};
pub use keys::RecipientKey;
pub use open::{OpenRequest, Opened, open};
pub use seal::{SealRequest, Sealed, seal};
pub use tag::{Tag, application_tag, directory_tag, is_directory_tag};

/// Re-export of the `rand_core` version the `CryptoRng` bound of [`seal`] and
/// [`RecipientKey::generate`] comes from.
pub use hpke::rand_core;
