//! Full validation: F1 to F9, R1, C1, C2, C3 (spec §2.2), with strict Ed25519 verification
//! (spec §3.2, ADR 0003).
//!
//! Two entry points name the two cases of spec §3.4, so that R1 cannot be skipped by passing
//! `None`: [`validate_submitted`] (`PUT`, no expected identifier) and [`validate_requested`] (block
//! fetched by its identifier). The staged form [`crate::parse`] → [`BlockRef::check_pow`] →
//! [`PowChecked::verify_signature`] keeps the order in the types for the relay (P1 between F9 and
//! C1, ADR 0007; replay shortcut after C1, ADR 0003 rule 10). Its R1 variant
//! [`crate::parse`] → [`BlockRef::check_requested_id`] → [`IdChecked::check_pow`] →
//! [`PowChecked::verify_signature`] runs R1 between F9 and C1.
//!
//! Whether R1 ran is part of the type (review 2026-11-18 M2, F-5): the submitted path yields a
//! [`ValidatedBlock<Submitted>`], the requested path a [`ValidatedBlock<Requested>`]. A client or
//! peer that stores blocks fetched by identifier takes `ValidatedBlock<'_, Requested>`, and a block
//! validated with [`validate_submitted`] by mistake does not type-check there.

use core::marker::PhantomData;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::block::{BlockRef, parse};
use crate::block_id::BlockId;
use crate::error::Error;
use crate::layout::{PUBKEY_LEN, SIGNATURE_LEN};

mod sealed {
    /// Seals [`super::Receipt`]: only the two markers of this module implement it.
    pub trait Sealed {}
    impl Sealed for super::Submitted {}
    impl Sealed for super::Requested {}
}

/// How a block was received, recorded in the type of [`ValidatedBlock`] and [`PowChecked`]:
/// [`Submitted`] or [`Requested`]. Sealed: no other implementation exists, so generic code over
/// `R: Receipt` sees exactly these two cases.
pub trait Receipt: sealed::Sealed + Clone + Copy + core::fmt::Debug {}

/// Marker: validated as a **submitted** block (`PUT`), without R1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submitted;

/// Marker: validated as a block **requested** by its identifier: R1 passed, the `block_id` is the
/// requested identifier (spec §3.4 "Receipt").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requested;

impl Receipt for Submitted {}
impl Receipt for Requested {}

/// A block that passed every check: format, R1 when `R` is [`Requested`], PoW and signature.
///
/// The only constructors are [`validate_submitted`], [`validate_requested`] and
/// [`PowChecked::verify_signature`]. Storage and display code should accept this type, never a
/// [`BlockRef`], so that an unauthenticated block cannot reach them by mistake; code that must only
/// see blocks checked against the identifier they were fetched by takes
/// `ValidatedBlock<'_, Requested>`. There is no default for `R`: every use says which one it means.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedBlock<'a, R: Receipt> {
    block: BlockRef<'a>,
    id: BlockId,
    receipt: PhantomData<R>,
}

impl<'a> ValidatedBlock<'a, Requested> {
    /// Drops the record that R1 passed, for code that takes submitted blocks (for example a relay
    /// storing what a peer sent it). Always safe: every check of the submitted path (F1 to F9, C1,
    /// C2, C3) also ran on the requested path. There is no conversion the other way: R1 can only be
    /// established by [`validate_requested`] or [`BlockRef::check_requested_id`].
    #[must_use]
    pub const fn into_submitted(self) -> ValidatedBlock<'a, Submitted> {
        ValidatedBlock {
            block: self.block,
            id: self.id,
            receipt: PhantomData,
        }
    }
}

impl<'a, R: Receipt> ValidatedBlock<'a, R> {
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

/// A well-formed block whose proof of work has been checked (F1 to F9 and C1), and whose signature
/// has **not** been checked yet.
///
/// The intermediate stage of [`validate_submitted`], for the relay shortcut of ADR 0003 rule 10:
/// after format and PoW, a relay looks [`PowChecked::block_id`] up and, if the stored bytes are
/// identical to [`BlockRef::as_bytes`], MAY answer "already present" without verifying the
/// signature. In every other case it MUST call [`PowChecked::verify_signature`] before storing.
///
/// `R` records whether R1 ran before ([`Requested`], from [`IdChecked::check_pow`]) or not
/// ([`Submitted`], from [`BlockRef::check_pow`]).
#[derive(Clone, Copy, Debug)]
pub struct PowChecked<'a, R: Receipt> {
    block: BlockRef<'a>,
    id: BlockId,
    receipt: PhantomData<R>,
}

impl<'a, R: Receipt> PowChecked<'a, R> {
    /// spec §2.2 C1, spec §3.3, on an identifier already computed.
    fn new(block: BlockRef<'a>, id: BlockId, difficulty: u32) -> Result<Self, Error> {
        let actual = id.leading_zero_bits();
        if actual < difficulty {
            return Err(Error::InsufficientPow {
                required: difficulty,
                actual,
            });
        }
        Ok(Self {
            block,
            id,
            receipt: PhantomData,
        })
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

    /// Checks C2 then C3: strict signature verification (spec §2.2, §3.2, ADR 0003 rule 13).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] or [`Error::InvalidSignature`].
    pub fn verify_signature(self) -> Result<ValidatedBlock<'a, R>, Error> {
        // spec §2.2 C2 and C3.
        verify_signature(self.block.pubkey(), &self.id, self.block.signature())?;
        Ok(ValidatedBlock {
            block: self.block,
            id: self.id,
            receipt: PhantomData,
        })
    }
}

/// A well-formed block whose `block_id` equals the identifier it was requested by (F1 to F9 and
/// R1), not yet checked for PoW or signature. Produced by [`BlockRef::check_requested_id`].
#[derive(Clone, Copy, Debug)]
pub struct IdChecked<'a> {
    block: BlockRef<'a>,
    id: BlockId,
}

impl<'a> IdChecked<'a> {
    /// The block, still unauthenticated.
    #[must_use]
    pub const fn block(&self) -> &BlockRef<'a> {
        &self.block
    }

    /// Its `block_id`, equal to the requested identifier.
    #[must_use]
    pub const fn block_id(&self) -> &BlockId {
        &self.id
    }

    /// Checks C1 at difficulty `difficulty` (spec §2.2, §3.3), without hashing again.
    ///
    /// # Errors
    ///
    /// [`Error::InsufficientPow`].
    pub fn check_pow(self, difficulty: u32) -> Result<PowChecked<'a, Requested>, Error> {
        PowChecked::new(self.block, self.id, difficulty)
    }
}

impl<'a> BlockRef<'a> {
    /// Computes the `block_id` and checks R1: it must equal `requested`, the identifier the block
    /// was fetched by (spec §2.2 R1, §3.4 "Receipt", ADR 0003 rule 11). Second stage of
    /// [`validate_requested`], after [`crate::parse`] and before C1.
    ///
    /// # Errors
    ///
    /// [`Error::BlockIdMismatch`].
    pub fn check_requested_id(self, requested: &BlockId) -> Result<IdChecked<'a>, Error> {
        let id = self.block_id();
        // spec §2.2 R1. Public data: an ordinary comparison is fine.
        if *requested != id {
            return Err(Error::BlockIdMismatch {
                expected: *requested,
                actual: id,
            });
        }
        Ok(IdChecked { block: self, id })
    }

    /// Computes the `block_id` and checks C1 at difficulty `difficulty` (spec §2.2, §3.3; `0`
    /// accepts any `block_id`). Second stage of [`validate_submitted`], after [`crate::parse`]; a
    /// relay applies its timestamp policy P1 between the two (spec §2.2, ADR 0007).
    ///
    /// # Errors
    ///
    /// [`Error::InsufficientPow`].
    pub fn check_pow(self, difficulty: u32) -> Result<PowChecked<'a, Submitted>, Error> {
        let id = self.block_id();
        PowChecked::new(self, id, difficulty)
    }
}

/// Validates a **submitted** block (`PUT`, spec §4), cheapest check first: F1 to F9, then C1 at
/// difficulty `difficulty` (`0` accepts any `block_id`), then C2 and C3 (spec §2.2).
///
/// No identifier is expected, so R1 does not apply. A block received in answer to a request by
/// identifier MUST go through [`validate_requested`] instead (spec §3.4).
///
/// Equivalent to `parse(bytes)?.check_pow(difficulty)?.verify_signature()`.
///
/// # Errors
///
/// The [`Error`] of the first failing check.
pub fn validate_submitted(
    bytes: &[u8],
    difficulty: u32,
) -> Result<ValidatedBlock<'_, Submitted>, Error> {
    // spec §2.2 F1 to F9, then C1, then C2 and C3.
    parse(bytes)?.check_pow(difficulty)?.verify_signature()
}

/// Validates a block received in answer to a request for the identifier `requested` (`GET`,
/// synchronisation; spec §3.4 "Receipt", ADR 0003 rule 11): F1 to F9, R1, C1, C2, C3 (spec §2.2).
///
/// Equivalent to
/// `parse(bytes)?.check_requested_id(requested)?.check_pow(difficulty)?.verify_signature()`.
///
/// # Errors
///
/// The [`Error`] of the first failing check; [`Error::BlockIdMismatch`] when the bytes are not
/// those of `requested`.
pub fn validate_requested<'a>(
    bytes: &'a [u8],
    difficulty: u32,
    requested: &BlockId,
) -> Result<ValidatedBlock<'a, Requested>, Error> {
    // spec §2.2 F1 to F9, R1, C1, then C2 and C3.
    parse(bytes)?
        .check_requested_id(requested)?
        .check_pow(difficulty)?
        .verify_signature()
}

/// Which criterion rejected a public key. Internal: both map to [`Error::InvalidPublicKey`], the
/// distinction only lets the tests check that the intended criterion fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRejection {
    /// V1: `from_bytes` failed (not a point on the curve).
    NotOnCurve,
    /// V1: decodes, but is not the canonical encoding of the point.
    NonCanonical,
    /// V2: small order.
    SmallOrder,
}

/// spec §3.2 V1 and V2, ADR 0003 rule 13 steps 1 to 3, in this order.
pub(crate) fn check_public_key(pubkey: &[u8; PUBKEY_LEN]) -> Result<VerifyingKey, KeyRejection> {
    // Step 1: decoding. `from_bytes` follows ZIP-215 and accepts some non-canonical encodings.
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| KeyRejection::NotOnCurve)?;
    // Step 2: recompression; rejects `y ≥ 2^255 − 19` and `x = 0` with the sign bit set (V1).
    // Public data: an ordinary comparison is fine.
    if key.to_edwards().compress().as_bytes() != pubkey {
        return Err(KeyRejection::NonCanonical);
    }
    // Step 3: V2, small-order key.
    if key.is_weak() {
        return Err(KeyRejection::SmallOrder);
    }
    Ok(key)
}

/// Strict verification of a block signature over `SIG_PREFIX ‖ block_id` (spec §3.2,
/// ADR 0003 rule 13). Never uses batch verification (rule 14). Internal: callers go through
/// [`PowChecked::verify_signature`], which keeps the order F1 to F9, C1, C2, C3.
///
/// Errors: [`Error::InvalidPublicKey`] for V1 and V2 (C2), [`Error::InvalidSignature`] for V3 to
/// V6 (C3).
pub(crate) fn verify_signature(
    pubkey: &[u8; PUBKEY_LEN],
    id: &BlockId,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    // spec §2.2 C2: V1 and V2.
    let key = check_public_key(pubkey).map_err(|_| Error::InvalidPublicKey)?;
    // spec §2.2 C3: V3 to V6. `Signature::from_bytes` validates nothing; `verify_strict` checks
    // S < L, R decodes, R not of small order, and the cofactorless equation byte for byte.
    let signature = Signature::from_bytes(signature);
    let message = id.signed_message();
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Little-endian encoding of `y + p`, `p = 2^255 − 19`, for a small `y` (non-canonical when
    /// `y < 19`).
    fn y_plus_p(y: u8) -> [u8; 32] {
        let mut out = [0xffu8; 32];
        out[0] = 0xed + y;
        out[31] = 0x7f;
        out
    }

    /// Little-endian encoding of a small `y`, sign bit as given.
    fn small_y(y: u8, sign: bool) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = y;
        if sign {
            out[31] = 0x80;
        }
        out
    }

    /// The 8 small-order points, canonical encodings.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ];

    // spec §3.2 V1 and V2: positive case, a key derived from the public seed 32 × 0x01.
    #[test]
    fn honest_key_passes() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x01; 32]);
        assert!(check_public_key(key.verifying_key().as_bytes()).is_ok());
    }

    // spec §3.2 V1: `y` not on the curve (y = 2 has no x).
    #[test]
    fn v1_not_on_curve() {
        assert_eq!(
            check_public_key(&small_y(2, false)).err(),
            Some(KeyRejection::NotOnCurve)
        );
    }

    // spec §3.2 V1: y ≥ p, point not of small order (y = 3 is on the curve). ZIP-215 decoding accepts
    // it; the recompression of ADR 0003 rule 13 step 2 rejects it.
    #[test]
    fn v1_non_canonical_y_not_small_order() {
        let canonical = small_y(3, false);
        // Same point, canonical form: decodes and is not of small order.
        assert!(check_public_key(&canonical).is_ok());
        assert_eq!(
            check_public_key(&y_plus_p(3)).err(),
            Some(KeyRejection::NonCanonical)
        );
    }

    // spec §3.2 V1 before V2: non-canonical encodings of small-order points (identity y = 1, and the
    // order-4 points y = 0).
    #[test]
    fn v1_non_canonical_small_order_is_v1() {
        for y in [0u8, 1] {
            assert_eq!(
                check_public_key(&y_plus_p(y)).err(),
                Some(KeyRejection::NonCanonical),
                "y = {y} + p"
            );
        }
    }

    // spec §3.2 V1: x = 0 with the sign bit set (y = 1 and y = −1, the only points with x = 0).
    #[test]
    fn v1_x_zero_with_sign_bit() {
        let mut minus_one = hex32(SMALL_ORDER[1]);
        minus_one[31] |= 0x80;
        for encoding in [small_y(1, true), minus_one] {
            assert_eq!(
                check_public_key(&encoding).err(),
                Some(KeyRejection::NonCanonical)
            );
        }
    }

    // spec §3.2 V2: one case per small-order point, each canonical.
    #[test]
    fn v2_small_order_points() {
        for point in SMALL_ORDER {
            assert_eq!(
                check_public_key(&hex32(point)).err(),
                Some(KeyRejection::SmallOrder),
                "{point}"
            );
        }
    }
}
