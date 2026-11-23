//! Validation errors: exactly one variant per rejection rule of SPEC §4, named as SPEC names them.

use core::fmt;

/// Why a block was rejected. Checks run in the order of SPEC §4 (F1 to F9, R1, P1, C1, C2, C3);
/// the first failing check gives the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// F1: the buffer is shorter than 118 bytes.
    TooShort,
    /// F2: the buffer is longer than 65,909 bytes.
    TooLong,
    /// F3: the Magic field is not `0x53 0x42`.
    BadMagic,
    /// F4: the Version field is not `0x01`.
    UnsupportedVersion,
    /// F5: the Parents Count field is above 8.
    TooManyParents,
    /// F6 or F7: the buffer is shorter than its fields announce.
    Truncated,
    /// F8: bytes follow the signature.
    TrailingBytes,
    /// F9: two parents are equal.
    DuplicateParent,
    /// R1: the computed `block_id` differs from the requested identifier.
    BlockIdMismatch,
    /// P1 (relay `PUT` only): the Timestamp is later than `now + max_future_ms`.
    TimestampTooFarInFuture,
    /// C1: the `block_id` has fewer leading zero bits than the difficulty.
    InsufficientPow,
    /// C2: the public key fails V1 or V2.
    InvalidPublicKey,
    /// C3: the signature fails one of V3 to V6.
    InvalidSignature,
}

impl Error {
    /// The error name of SPEC §4, as used in the vectors' `expect.error` and in relay responses.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::TooShort => "TooShort",
            Self::TooLong => "TooLong",
            Self::BadMagic => "BadMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::TooManyParents => "TooManyParents",
            Self::Truncated => "Truncated",
            Self::TrailingBytes => "TrailingBytes",
            Self::DuplicateParent => "DuplicateParent",
            Self::BlockIdMismatch => "BlockIdMismatch",
            Self::TimestampTooFarInFuture => "TimestampTooFarInFuture",
            Self::InsufficientPow => "InsufficientPow",
            Self::InvalidPublicKey => "InvalidPublicKey",
            Self::InvalidSignature => "InvalidSignature",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::error::Error for Error {}
