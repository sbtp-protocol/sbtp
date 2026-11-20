//! In-WASM Ed25519 signing key, **for demonstrations and CLI-like tools only**.
//!
//! The secret lives in WASM linear memory, which any script of the page can read. A browser
//! application that keeps a long-lived identity should hold its key outside WASM, for example a
//! Web Crypto Ed25519 key created with `extractable: false`, and use the "signing bytes out,
//! signature in" path instead: `signingMessage(block)`, sign the 49 bytes outside, then
//! `attachSignature(block, signature)`. Browser-side key storage is reviewed by the security reviewer
//! with the web client (roadmap, Phase 3).
//!
//! What this type does to limit exposure (best effort, see the last point):
//! - the secret never appears in `Debug`, `Display`, an error message or a log;
//! - the `SigningKey` is wiped when the object is freed, through ed25519-dalek's `zeroize` feature.
//!   Call `free()` in JS as soon as the key is no longer needed: collection by the garbage
//!   collector is neither prompt nor guaranteed. Every JS argument is type-checked without calling
//!   into JS that could throw, so a failed call cannot leave the object borrowed and `free()`
//!   still wipes it (security review 2026-11-19, L-2);
//! - the seed buffers this crate allocates are `Zeroizing` and filled in place; the seed is
//!   exported straight from the key, without an intermediate copy;
//! - the seed leaves WASM only through the explicit `exportSeed()`, and enters only through
//!   `fromSeed()`. Copies made on the JS side (the caller's `Uint8Array`) cannot be wiped from
//!   here: the caller overwrites them (`seed.fill(0)`) once done;
//! - wiping is **best effort**: moves of the `SigningKey` value (into the object wasm-bindgen
//!   allocates) and the signer's internal temporaries may leave transient copies on the WASM
//!   shadow stack, in linear memory, which Rust cannot reliably wipe (review L-4).

use core::fmt;

use sbtp_core::{SigningKey, sign_block};
use zeroize::Zeroizing;

use crate::error::{BindError, names};

/// An Ed25519 signing key held in WASM memory. Demo and CLI-like use only (see the module
/// documentation).
#[wasm_bindgen::prelude::wasm_bindgen]
pub struct DemoSigningKey {
    inner: SigningKey,
}

impl fmt::Debug for DemoSigningKey {
    /// Shows the public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DemoSigningKey")
            .field("public_key", self.inner.verifying_key().as_bytes())
            .finish_non_exhaustive()
    }
}

impl DemoSigningKey {
    /// A fresh key from the platform's random source: Web Crypto `getRandomValues` on
    /// wasm32-unknown-unknown, the OS source natively.
    ///
    /// # Errors
    ///
    /// `EntropyUnavailable` if the random source fails (for example no `crypto` global).
    pub fn generate() -> Result<Self, BindError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|error| {
            BindError::new(
                names::ENTROPY_UNAVAILABLE,
                format!("random source failed: {error}"),
            )
        })?;
        Ok(Self::from_seed(&seed))
    }

    /// The key whose RFC 8032 seed is `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte seed, borrowed from the key (no copy).
    #[must_use]
    pub fn seed_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// The 32-byte public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// Signs the well-formed block `bytes` in place (spec §3.2) and returns it. Mine first: the
    /// nonce is covered by the signed `block_id`.
    ///
    /// # Errors
    ///
    /// The F1 to F9 rule that failed, `KeyMismatch` if the block's public key is not this key's,
    /// `Signing`.
    pub fn sign(&self, mut bytes: Vec<u8>) -> Result<Vec<u8>, BindError> {
        sign_block(&mut bytes, &self.inner)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{build_unsigned, validate_submitted_block};

    #[test]
    fn generated_keys_differ_and_sign_valid_blocks() {
        let a = DemoSigningKey::generate().unwrap();
        let b = DemoSigningKey::generate().unwrap();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
        let block = build_unsigned(&a.public_key_bytes(), 1, 0, &[], b"demo").unwrap();
        let signed = a.sign(block.clone()).unwrap();
        assert!(
            validate_submitted_block(&signed, 0)
                .unwrap()
                .authenticated()
        );
        assert_eq!(b.sign(block.clone()).unwrap_err().name(), "KeyMismatch");
        assert_eq!(a.sign(block[..5].to_vec()).unwrap_err().name(), "TooShort");
    }

    #[test]
    fn seed_round_trips() {
        let key = DemoSigningKey::from_seed(&[0x01; 32]);
        assert_eq!(*key.seed_bytes(), [0x01; 32]);
        let again = DemoSigningKey::from_seed(key.seed_bytes());
        assert_eq!(again.public_key_bytes(), key.public_key_bytes());
    }

    #[test]
    fn debug_shows_no_secret() {
        let key = DemoSigningKey::from_seed(&[0x5a; 32]);
        let text = format!("{key:?}");
        // The seed bytes would print as a run of 90s.
        assert!(!text.contains("90, 90, 90"), "{text}");
        assert!(text.contains("public_key"));
    }
}
