//! Full validation (SPEC §4) with strict Ed25519 verification (SPEC §3, V1 to V6).

use ed25519_dalek::{Signature, VerifyingKey};

use crate::block::{BlockRef, PUBKEY_LEN, SIGNATURE_LEN, parse};
use crate::block_id::BlockId;
use crate::error::Error;

/// A block that passed every check: format, R1 when it was requested, proof of work and signature.
///
/// The only constructors are [`validate_submitted`], [`validate_requested`] and
/// [`PowChecked::verify_signature`].
#[derive(Clone, Copy, Debug)]
pub struct ValidatedBlock<'a> {
    block: BlockRef<'a>,
    id: BlockId,
}

impl<'a> ValidatedBlock<'a> {
    /// The validated block.
    #[must_use]
    pub const fn block(&self) -> &BlockRef<'a> {
        &self.block
    }

    /// Its `block_id`, computed once during validation.
    #[must_use]
    pub const fn block_id(&self) -> &BlockId {
        &self.id
    }
}

/// A well-formed block whose proof of work passed (F1 to F9, C1) and whose signature is **not**
/// checked yet. [`PowChecked::verify_signature`] finishes the validation.
#[derive(Clone, Copy, Debug)]
pub struct PowChecked<'a> {
    block: BlockRef<'a>,
    id: BlockId,
}

impl<'a> PowChecked<'a> {
    fn new(block: BlockRef<'a>, id: BlockId, difficulty: u32) -> Result<Self, Error> {
        // spec §4 C1, §3: at least `difficulty` leading zero bits.
        if !id.meets_difficulty(difficulty) {
            return Err(Error::InsufficientPow);
        }
        Ok(Self { block, id })
    }

    /// The block, still unauthenticated.
    #[must_use]
    pub const fn block(&self) -> &BlockRef<'a> {
        &self.block
    }

    /// Its `block_id`, computed once.
    #[must_use]
    pub const fn block_id(&self) -> &BlockId {
        &self.id
    }

    /// Checks C2 then C3: strict signature verification (spec §3, §4).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] or [`Error::InvalidSignature`].
    pub fn verify_signature(self) -> Result<ValidatedBlock<'a>, Error> {
        verify_signature(self.block.pubkey(), &self.id, self.block.signature())?;
        Ok(ValidatedBlock {
            block: self.block,
            id: self.id,
        })
    }
}

impl<'a> BlockRef<'a> {
    /// Computes the `block_id` and checks C1 at `difficulty` (`0` accepts any `block_id`; above
    /// 256 rejects every block). Validation reads no clock and no other state (spec §3).
    ///
    /// # Errors
    ///
    /// [`Error::InsufficientPow`].
    pub fn check_pow(self, difficulty: u32) -> Result<PowChecked<'a>, Error> {
        let id = self.block_id();
        PowChecked::new(self, id, difficulty)
    }
}

/// Validates a block pushed to a relay (`PUT`): F1 to F9, C1 at `difficulty`, C2, C3 (spec §4).
/// A relay runs P1 too, with the staged form (see the crate documentation).
///
/// # Errors
///
/// The [`Error`] of the first failing check.
pub fn validate_submitted(bytes: &[u8], difficulty: u32) -> Result<ValidatedBlock<'_>, Error> {
    parse(bytes)?.check_pow(difficulty)?.verify_signature()
}

/// Validates a block fetched by the identifier `requested`: F1 to F9, R1, C1, C2, C3 (spec §4).
/// A client passes its own `difficulty` (`0` if it has none), never the serving relay's.
///
/// # Errors
///
/// The [`Error`] of the first failing check.
pub fn validate_requested<'a>(
    bytes: &'a [u8],
    difficulty: u32,
    requested: &BlockId,
) -> Result<ValidatedBlock<'a>, Error> {
    let block = parse(bytes)?;
    let id = block.block_id();
    // spec §4 R1. Public data: an ordinary comparison is fine.
    if id != *requested {
        return Err(Error::BlockIdMismatch);
    }
    PowChecked::new(block, id, difficulty)?.verify_signature()
}

/// spec §3 V1 and V2, in this order. The key when it passes both.
fn check_public_key(pubkey: &[u8; PUBKEY_LEN]) -> Option<VerifyingKey> {
    // V1: `y` on the curve. `from_bytes` follows ZIP-215 and accepts some non-canonical encodings.
    let key = VerifyingKey::from_bytes(pubkey).ok()?;
    // V1: canonical encoding. Recompression rejects `y ≥ 2^255 − 19` and `x = 0` with the sign
    // bit set. Public data: an ordinary comparison is fine.
    if key.to_edwards().compress().as_bytes() != pubkey {
        return None;
    }
    // V2: `[8]A` is not the identity.
    if key.is_weak() {
        return None;
    }
    Some(key)
}

/// Strict verification of `SIG_PREFIX ‖ block_id` (spec §3). Never batch, never cofactored.
fn verify_signature(
    pubkey: &[u8; PUBKEY_LEN],
    id: &BlockId,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    // spec §4 C2: V1 and V2.
    let key = check_public_key(pubkey).ok_or(Error::InvalidPublicKey)?;
    // spec §4 C3: `verify_strict` checks V3 (S < L), V4 (R decodes), V5 (R not of small order) and
    // V6 (the cofactorless equation, `[S]B − [k]A` compressed and compared with R byte for byte,
    // `k` hashed over R and A as received). `Signature::from_bytes` validates nothing.
    key.verify_strict(&id.signed_message(), &Signature::from_bytes(signature))
        .map_err(|_| Error::InvalidSignature)
}
