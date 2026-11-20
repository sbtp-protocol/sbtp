//! Binary layout of an SBTP v0.2-draft block (spec §2).
//!
//! ```text
//! offset  size    field
//! 0       2       magic            "SB" (0x53 0x42)
//! 2       1       version          0x01
//! 3       8       timestamp        u64 big-endian, Unix ms   (ADR 0001)
//! 11      8       nonce            u64 big-endian, PoW       (ADR 0001)
//! 19      32      pubkey           Ed25519
//! 51      1       parents_count    N, 0 to 8 (ADR 0004, ADR 0014)
//! 52      32*N    parents          BLAKE3 hashes
//! ..      2       payload_len      u16 big-endian
//! ..      L       payload          opaque
//! ..      64      signature        Ed25519(SIG_PREFIX ‖ block_id)   (ADR 0002)
//! ```
//!
//! These values follow from the spec and ADRs 0001 to 0004.

/// Magic bytes ("SB").
pub const MAGIC: [u8; 2] = *b"SB";
/// Value of the version field for spec v0.2-draft.
pub const VERSION_V1: u8 = 0x01;

/// Size of a BLAKE3 hash (`block_id`, parents).
pub const HASH_LEN: usize = 32;
/// Size of an Ed25519 public key.
pub const PUBKEY_LEN: usize = 32;
/// Size of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Size of the `payload_len` field.
pub const PAYLOAD_LEN_SIZE: usize = 2;

/// Offset of the magic field.
pub const OFFSET_MAGIC: usize = 0;
/// Offset of the version field.
pub const OFFSET_VERSION: usize = 2;
/// Offset of the timestamp field.
pub const OFFSET_TIMESTAMP: usize = 3;
/// Offset of the nonce field.
pub const OFFSET_NONCE: usize = 11;
/// Offset of the public key.
pub const OFFSET_PUBKEY: usize = 19;
/// Offset of the parent count.
pub const OFFSET_PARENTS_COUNT: usize = 51;
/// Offset of the first parent hash; end of the fixed header.
pub const OFFSET_PARENTS: usize = 52;
/// Size of the fixed header.
pub const FIXED_HEADER_LEN: usize = OFFSET_PARENTS;

/// Maximum number of parents, a format limit (spec §2, ADR 0004, ADR 0014). Values 9 to 255 are
/// reserved.
pub const MAX_PARENTS: u8 = 8;
/// Maximum payload size (u16).
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Minimum block size: 0 parents, empty payload.
pub const MIN_BLOCK_LEN: usize = FIXED_HEADER_LEN + PAYLOAD_LEN_SIZE + SIGNATURE_LEN;
/// Maximum block size: 8 parents, 65,535-byte payload (65,909 bytes, ADR 0014).
pub const MAX_BLOCK_LEN: usize = FIXED_HEADER_LEN
    + (MAX_PARENTS as usize) * HASH_LEN
    + PAYLOAD_LEN_SIZE
    + MAX_PAYLOAD_LEN
    + SIGNATURE_LEN;

/// Offset of the `payload_len` field for `n` parents.
#[must_use]
pub const fn payload_len_offset(n_parents: u8) -> usize {
    FIXED_HEADER_LEN + (n_parents as usize) * HASH_LEN
}

/// Offset of the payload for `n` parents: `52 + 32·N + 2`.
#[must_use]
pub const fn payload_offset(n_parents: u8) -> usize {
    payload_len_offset(n_parents) + PAYLOAD_LEN_SIZE
}

/// Offset of the signature: `payload_offset + payload_len`.
#[must_use]
pub const fn signature_offset(n_parents: u8, payload_len: u16) -> usize {
    payload_offset(n_parents) + payload_len as usize
}

/// Total size of a block. This is also the end of the range covered by `block_id`, plus 64.
#[must_use]
pub const fn block_len(n_parents: u8, payload_len: u16) -> usize {
    signature_offset(n_parents, payload_len) + SIGNATURE_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_header_is_52_bytes() {
        assert_eq!(FIXED_HEADER_LEN, 2 + 1 + 8 + 8 + 32 + 1);
        assert_eq!(OFFSET_PUBKEY + PUBKEY_LEN, OFFSET_PARENTS_COUNT);
    }

    #[test]
    fn offsets_match_spec_formula() {
        assert_eq!(payload_offset(0), 54);
        assert_eq!(payload_offset(3), 52 + 3 * 32 + 2);
        assert_eq!(signature_offset(3, 100), payload_offset(3) + 100);
    }

    #[test]
    fn size_bounds() {
        assert_eq!(MIN_BLOCK_LEN, 118);
        assert_eq!(MAX_PARENTS, 8);
        assert_eq!(MAX_BLOCK_LEN, 65_909);
        assert_eq!(block_len(0, 0), MIN_BLOCK_LEN);
        assert_eq!(block_len(MAX_PARENTS, u16::MAX), MAX_BLOCK_LEN);
    }
}
