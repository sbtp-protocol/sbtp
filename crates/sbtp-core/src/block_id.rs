//! Block identifier (spec §3.1) and proof of work (spec §3.3).

use core::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::consts::{BLOCK_ID_CONTEXT, SIG_PREFIX, SIGNED_MESSAGE_LEN};
use crate::layout::HASH_LEN;

/// Highest meaningful difficulty: a 256-bit `block_id` has at most 256 leading zero bits. A relay's
/// `min_pow_difficulty` ranges from 0 to this value (spec §3.3, §4 `/info`, ADR 0007). Validation
/// rejects every block above it (C1); mining refuses it at once.
pub const MAX_DIFFICULTY: u32 = 256;

/// The network difficulty `D_NET` (spec §3.3, ADR 0045): the `min_pow_difficulty` a relay SHOULD
/// use, and the most a relay that takes part in replication may ask for. A sender that wants its
/// block accepted by every such relay mines at this value or above. A value of the protocol, not
/// ambient state: validation still takes the difficulty as an argument (ADR 0007 rule 7). It
/// changes only by a revision of the specification.
pub const NETWORK_POW_DIFFICULTY: u32 = 16;

/// A 32-byte BLAKE3 `block_id`. Parent hashes have the same type: a parent is a `block_id`.
///
/// The identifier is public data; comparisons need not be constant-time.
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
    /// Wraps 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The 32 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Number of leading zero bits, reading the identifier as a 256-bit big-endian integer
    /// (spec §3.3). From 0 to 256.
    #[must_use]
    pub fn leading_zero_bits(&self) -> u32 {
        let mut count = 0u32;
        for byte in self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }

    /// Whether the identifier has at least `difficulty` leading zero bits, that is
    /// `block_id < 2^(256 − d)` (spec §3.3). Always true for `difficulty = 0`; always false for
    /// `difficulty > 256`.
    #[must_use]
    pub fn meets_difficulty(&self, difficulty: u32) -> bool {
        self.leading_zero_bits() >= difficulty
    }

    /// The 49-byte signed message `SIG_PREFIX ‖ block_id` (spec §3.2, ADR 0002).
    #[must_use]
    pub fn signed_message(&self) -> [u8; SIGNED_MESSAGE_LEN] {
        let mut message = [0u8; SIGNED_MESSAGE_LEN];
        let (prefix, id) = message.split_at_mut(SIG_PREFIX.len());
        prefix.copy_from_slice(&SIG_PREFIX);
        id.copy_from_slice(&self.0);
        message
    }
}

impl From<[u8; HASH_LEN]> for BlockId {
    fn from(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BlockId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for BlockId {
    /// Lowercase hexadecimal, 64 characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockId({self})")
    }
}

/// Computes the `block_id` of the hashed range `block[0 .. Offset(Signature)]` (spec §3.1, ADR 0002):
/// `BLAKE3_derive_key(BLOCK_ID_CONTEXT, hashed)`.
///
/// The caller passes the range without the signature; [`crate::BlockRef::block_id`] does so for a
/// parsed block.
#[must_use]
pub fn compute_block_id(hashed: &[u8]) -> BlockId {
    // spec §3.1: derive_key mode, 32-byte output, context BLOCK_ID_CONTEXT.
    BlockId(blake3::derive_key(BLOCK_ID_CONTEXT, hashed))
}

/// A `derive_key` hasher already keyed with [`BLOCK_ID_CONTEXT`], to be cloned per mining attempt
/// (ADR 0002, "Cost").
pub(crate) fn block_id_hasher() -> blake3::Hasher {
    blake3::Hasher::new_derive_key(BLOCK_ID_CONTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_with_prefix(prefix: &[u8]) -> BlockId {
        let mut bytes = [0xffu8; HASH_LEN];
        for (dst, src) in bytes.iter_mut().zip(prefix) {
            *dst = *src;
        }
        BlockId(bytes)
    }

    #[test]
    fn leading_zero_bits_counts_big_endian() {
        assert_eq!(id_with_prefix(&[0x80]).leading_zero_bits(), 0);
        assert_eq!(id_with_prefix(&[0x7f]).leading_zero_bits(), 1);
        assert_eq!(id_with_prefix(&[0x01]).leading_zero_bits(), 7);
        assert_eq!(id_with_prefix(&[0x00, 0x80]).leading_zero_bits(), 8);
        assert_eq!(id_with_prefix(&[0x00, 0x00, 0x0f]).leading_zero_bits(), 20);
        // A zero bit after a non-zero byte does not count.
        assert_eq!(id_with_prefix(&[0x01, 0x00]).leading_zero_bits(), 7);
        assert_eq!(BlockId([0u8; HASH_LEN]).leading_zero_bits(), 256);
    }

    #[test]
    fn difficulty_threshold() {
        let id = id_with_prefix(&[0x00, 0x0f]); // 12 leading zero bits
        assert!(id.meets_difficulty(0));
        assert!(id.meets_difficulty(12));
        assert!(!id.meets_difficulty(13));
        assert!(BlockId([0u8; HASH_LEN]).meets_difficulty(256));
        assert!(!BlockId([0u8; HASH_LEN]).meets_difficulty(257));
        assert!(!id.meets_difficulty(u32::MAX));
    }

    #[test]
    fn signed_message_is_prefix_then_id() {
        let id = BlockId([0xab; HASH_LEN]);
        let message = id.signed_message();
        assert_eq!(message.get(..17), Some(&SIG_PREFIX[..]));
        assert_eq!(message.get(17..), Some(&[0xab; HASH_LEN][..]));
    }

    // ADR 0002: derive_key differs from plain BLAKE3, and the incremental form gives the same result.
    #[test]
    fn block_id_uses_derive_key() {
        let data = b"some block bytes";
        let id = compute_block_id(data);
        assert_ne!(id.0, *blake3::hash(data).as_bytes());
        let mut hasher = block_id_hasher();
        hasher.update(data);
        assert_eq!(id.0, *hasher.finalize().as_bytes());
    }

    #[test]
    fn display_is_lowercase_hex() {
        let mut bytes = [0u8; HASH_LEN];
        bytes[0] = 0xab;
        bytes[31] = 0x01;
        let id = BlockId(bytes);
        let mut buf = [0u8; 64];
        let mut cursor = Cursor(&mut buf, 0);
        fmt::write(&mut cursor, format_args!("{id}")).unwrap();
        assert_eq!(cursor.1, 64);
        assert_eq!(&buf[..2], b"ab");
        assert_eq!(&buf[62..], b"01");
    }

    struct Cursor<'a>(&'a mut [u8], usize);
    impl fmt::Write for Cursor<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.1 + s.len();
            self.0
                .get_mut(self.1..end)
                .ok_or(fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }
}
