//! Validation errors: exactly one variant per rejection rule of spec §2.2 (ADR 0004).

use core::fmt;

use crate::block_id::BlockId;
use crate::layout::{MAX_BLOCK_LEN, MAX_PARENTS};

/// Why a block was rejected. The first failing check, in the order F1 to F9, R1, C1 to C3, determines
/// the variant (spec §2.2).
///
/// The list is closed by ADR 0004: a new rejection rule requires an ADR and a new variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// F1: the buffer is shorter than 118 bytes (empty buffer included).
    TooShort {
        /// Buffer length.
        len: usize,
    },
    /// F2: the buffer is longer than 65,909 bytes (`MAX_BLOCK_LEN`).
    TooLong {
        /// Buffer length.
        len: usize,
    },
    /// F3: bytes 0 and 1 are not `0x53 0x42`.
    BadMagic {
        /// The two bytes found.
        found: [u8; 2],
    },
    /// F4: byte 2 is not `0x01`.
    UnsupportedVersion {
        /// The version byte found.
        version: u8,
    },
    /// F5: the Parents Count field is greater than 8 (`MAX_PARENTS`).
    TooManyParents {
        /// The Parents Count field.
        count: u8,
    },
    /// F6 or F7: the buffer is shorter than the length its fields announce.
    Truncated {
        /// Minimum length required by the fields read so far (F6), or the exact expected length (F7).
        expected_min: usize,
        /// Buffer length.
        len: usize,
    },
    /// F8: bytes follow the signature.
    TrailingBytes {
        /// Exact expected length.
        expected: usize,
        /// Buffer length.
        len: usize,
    },
    /// F9: two parent hashes are identical.
    DuplicateParent {
        /// Index of the first occurrence.
        first: u8,
        /// Index of the second occurrence.
        second: u8,
    },
    /// R1: the computed `block_id` differs from the requested identifier.
    BlockIdMismatch {
        /// The requested identifier.
        expected: BlockId,
        /// The `block_id` computed from the received bytes.
        actual: BlockId,
    },
    /// C1: the `block_id` has fewer leading zero bits than the required difficulty.
    InsufficientPow {
        /// Required difficulty `d`.
        required: u32,
        /// Leading zero bits of the `block_id`.
        actual: u32,
    },
    /// C2: the public key fails criterion V1 or V2 (spec §3.2).
    InvalidPublicKey,
    /// C3: the signature fails a criterion among V3 to V6 (spec §3.2).
    InvalidSignature,
}

impl Error {
    /// Error name as written in spec §2.2 and in the `expect.error` field of the test vectors.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "TooShort",
            Self::TooLong { .. } => "TooLong",
            Self::BadMagic { .. } => "BadMagic",
            Self::UnsupportedVersion { .. } => "UnsupportedVersion",
            Self::TooManyParents { .. } => "TooManyParents",
            Self::Truncated { .. } => "Truncated",
            Self::TrailingBytes { .. } => "TrailingBytes",
            Self::DuplicateParent { .. } => "DuplicateParent",
            Self::BlockIdMismatch { .. } => "BlockIdMismatch",
            Self::InsufficientPow { .. } => "InsufficientPow",
            Self::InvalidPublicKey => "InvalidPublicKey",
            Self::InvalidSignature => "InvalidSignature",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(
                f,
                "block too short: {len} bytes, minimum {}",
                crate::layout::MIN_BLOCK_LEN
            ),
            Self::TooLong { len } => {
                write!(f, "block too long: {len} bytes, maximum {MAX_BLOCK_LEN}")
            }
            Self::BadMagic { found: [a, b] } => write!(f, "bad magic: {a:02x} {b:02x}"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported version: 0x{version:02x}")
            }
            Self::TooManyParents { count } => {
                write!(f, "too many parents: {count}, maximum {MAX_PARENTS}")
            }
            Self::Truncated { expected_min, len } => {
                write!(
                    f,
                    "block truncated: {len} bytes, at least {expected_min} expected"
                )
            }
            Self::TrailingBytes { expected, len } => {
                write!(
                    f,
                    "trailing bytes: {len} bytes, exactly {expected} expected"
                )
            }
            Self::DuplicateParent { first, second } => {
                write!(f, "duplicate parent at indices {first} and {second}")
            }
            Self::BlockIdMismatch { expected, actual } => {
                write!(
                    f,
                    "block_id mismatch: requested {expected}, received {actual}"
                )
            }
            Self::InsufficientPow { required, actual } => {
                write!(
                    f,
                    "insufficient proof of work: {actual} leading zero bits, {required} required"
                )
            }
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::InvalidSignature => f.write_str("invalid signature"),
        }
    }
}

impl core::error::Error for Error {}
