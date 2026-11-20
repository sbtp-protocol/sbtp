//! Domain separation strings (spec §3.5, ADR 0002).
//!
//! Both strings are bound to the Version field `0x01`. A new value of the Version field MUST define new
//! strings; a published string never changes and is never reused for another purpose.

use crate::layout::HASH_LEN;

/// BLAKE3 `derive_key` context of the `block_id` (spec §3.1): 27 ASCII bytes, no terminator.
pub const BLOCK_ID_CONTEXT: &str = "SBTP 2026-11-18 block_id v1";

/// Prefix of the signed message (spec §3.2): 17 ASCII bytes, no terminator.
pub const SIG_PREFIX: [u8; 17] = *b"SBTP-v1-block-sig";

/// Length of the signed message `M = SIG_PREFIX ‖ block_id` (spec §3.2): 49 bytes.
pub const SIGNED_MESSAGE_LEN: usize = SIG_PREFIX.len() + HASH_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    // spec §3.1: byte-by-byte value of BLOCK_ID_CONTEXT.
    #[test]
    fn block_id_context_bytes() {
        let expected: [u8; 27] = [
            0x53, 0x42, 0x54, 0x50, 0x20, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x31, 0x31, 0x2d, 0x31,
            0x38, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x69, 0x64, 0x20, 0x76, 0x31,
        ];
        assert_eq!(BLOCK_ID_CONTEXT.as_bytes(), &expected);
    }

    // spec §3.2: byte-by-byte value of SIG_PREFIX and the 49-byte message length.
    #[test]
    fn sig_prefix_bytes() {
        let expected: [u8; 17] = [
            0x53, 0x42, 0x54, 0x50, 0x2d, 0x76, 0x31, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d,
            0x73, 0x69, 0x67,
        ];
        assert_eq!(SIG_PREFIX, expected);
        assert_eq!(SIGNED_MESSAGE_LEN, 49);
    }
}
