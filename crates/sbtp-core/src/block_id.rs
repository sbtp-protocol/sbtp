//! Block identifier (SPEC §2), its text form, the signed message (SPEC §3) and proof of work.

use core::fmt;
use core::str::FromStr;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::block::HASH_LEN;

/// BLAKE3 `derive_key` context of the `block_id` (SPEC §2): 27 ASCII bytes, no terminator.
pub const BLOCK_ID_CONTEXT: &str = "SBTP 2026-11-18 block_id v1";

/// Prefix of the signed message (SPEC §3): 17 ASCII bytes.
pub const SIG_PREFIX: [u8; 17] = *b"SBTP-v1-block-sig";

/// Length of the signed message `M = SIG_PREFIX ‖ block_id` (SPEC §3): 49 bytes.
pub const SIGNED_MESSAGE_LEN: usize = SIG_PREFIX.len() + HASH_LEN;

/// A 32-byte `block_id`. A parent is a `block_id`, so parents have this type too.
///
/// Public data: comparisons need not be constant-time.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct BlockId(pub [u8; HASH_LEN]);

impl BlockId {
    /// The 32 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Leading zero bits of the identifier read as a 256-bit big-endian integer (SPEC §3), 0 to 256.
    #[must_use]
    pub fn leading_zero_bits(&self) -> u32 {
        let mut count = 0u32;
        for byte in self.0 {
            // At most 32 × 8 = 256: no overflow.
            count = count.saturating_add(byte.leading_zeros());
            if byte != 0 {
                break;
            }
        }
        count
    }

    /// spec §3: the identifier is below `2^(256 − d)`, that is it has at least `d` leading zero
    /// bits. Always true for `d = 0`, always false for `d > 256`.
    #[must_use]
    pub fn meets_difficulty(&self, difficulty: u32) -> bool {
        self.leading_zero_bits() >= difficulty
    }

    /// The 49-byte signed message `SIG_PREFIX ‖ block_id` (spec §3).
    #[must_use]
    pub fn signed_message(&self) -> [u8; SIGNED_MESSAGE_LEN] {
        let mut message = [0u8; SIGNED_MESSAGE_LEN];
        let (prefix, id) = message.split_at_mut(SIG_PREFIX.len());
        prefix.copy_from_slice(&SIG_PREFIX);
        id.copy_from_slice(&self.0);
        message
    }
}

/// Computes `block_id = BLAKE3.derive_key(BLOCK_ID_CONTEXT, hashed)` (spec §2), where `hashed` is
/// the block without its 64 signature bytes.
#[must_use]
pub fn compute_block_id(hashed: &[u8]) -> BlockId {
    // spec §2: derive_key mode, 32-byte output. Plain BLAKE3 hashing would be wrong.
    BlockId(blake3::derive_key(BLOCK_ID_CONTEXT, hashed))
}

impl fmt::Display for BlockId {
    /// spec §2: 64 lowercase hexadecimal characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockId({self})")
    }
}

/// A string is not exactly 64 lowercase hexadecimal characters (spec §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseBlockIdError;

impl fmt::Display for ParseBlockIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a block_id is exactly 64 lowercase hexadecimal characters")
    }
}

impl core::error::Error for ParseBlockIdError {}

impl FromStr for BlockId {
    type Err = ParseBlockIdError;

    /// spec §2: exactly 64 lowercase hexadecimal characters; uppercase is rejected.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn nibble(c: u8) -> Result<u8, ParseBlockIdError> {
            match c {
                b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
                b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
                _ => Err(ParseBlockIdError),
            }
        }
        let (pairs, rest) = s.as_bytes().as_chunks::<2>();
        if pairs.len() != HASH_LEN || !rest.is_empty() {
            return Err(ParseBlockIdError);
        }
        let mut out = [0u8; HASH_LEN];
        for (byte, [hi, lo]) in out.iter_mut().zip(pairs) {
            *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
        }
        Ok(Self(out))
    }
}
