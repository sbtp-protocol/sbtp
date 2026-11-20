//! Domain separation strings (spec §3.5, ADR 0002).
//!
//! The two layer 0 strings are bound to the Version field `0x01`. A new value of the Version field
//! MUST define new strings; a published string never changes and is never reused for another
//! purpose. The layer 2 rows of the registry follow them.

use crate::layout::HASH_LEN;

/// BLAKE3 `derive_key` context of the `block_id` (spec §3.1): 27 ASCII bytes, no terminator.
pub const BLOCK_ID_CONTEXT: &str = "SBTP 2026-11-18 block_id v1";

/// Prefix of the signed message (spec §3.2): 17 ASCII bytes, no terminator.
pub const SIG_PREFIX: [u8; 17] = *b"SBTP-v1-block-sig";

/// Length of the signed message `M = SIG_PREFIX ‖ block_id` (spec §3.2): 49 bytes.
pub const SIGNED_MESSAGE_LEN: usize = SIG_PREFIX.len() + HASH_LEN;

// --- Layer 2 rows of the registry (spec §3.5, ADR 0016 rule 31). Not bound to the Version field:
// they belong to the sealed envelope of `l2-grammar.md` §5. ---

/// HPKE `info` of every layer 2 seal (spec §3.5; `l2-grammar.md` §5.1): 27 ASCII bytes, no
/// terminator.
pub const SEALED_HPKE_INFO: [u8; 27] = *b"SBTP 2026-11-20 sbtp.enc v1";

/// Prefix of the Ed25519 signature inside a sealed payload (spec §3.5; `l2-grammar.md` §5.3): 18
/// ASCII bytes, no terminator. Neither it nor [`SIG_PREFIX`] is a prefix of the other.
pub const SEALED_SIG_PREFIX: [u8; 18] = *b"SBTP-v1-sealed-sig";

/// BLAKE3 `derive_key` context of the encryption key directory tag (spec §3.5;
/// `l2-grammar.md` §5.5): 36 ASCII bytes, no terminator.
pub const ENC_KEY_DIRECTORY_CONTEXT: &str = "SBTP 2026-11-20 enc_key directory v1";

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

    // spec §3.5: byte-by-byte values and lengths of the layer 2 rows.
    #[test]
    fn layer2_registry_bytes() {
        let info: [u8; 27] = [
            0x53, 0x42, 0x54, 0x50, 0x20, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x31, 0x31, 0x2d, 0x32,
            0x30, 0x20, 0x73, 0x62, 0x74, 0x70, 0x2e, 0x65, 0x6e, 0x63, 0x20, 0x76, 0x31,
        ];
        assert_eq!(SEALED_HPKE_INFO, info);
        let sealed: [u8; 18] = [
            0x53, 0x42, 0x54, 0x50, 0x2d, 0x76, 0x31, 0x2d, 0x73, 0x65, 0x61, 0x6c, 0x65, 0x64,
            0x2d, 0x73, 0x69, 0x67,
        ];
        assert_eq!(SEALED_SIG_PREFIX, sealed);
        assert_eq!(ENC_KEY_DIRECTORY_CONTEXT.len(), 36);
        assert!(ENC_KEY_DIRECTORY_CONTEXT.is_ascii());
        assert_eq!(
            ENC_KEY_DIRECTORY_CONTEXT.as_bytes(),
            b"SBTP 2026-11-20 enc_key directory v1"
        );
    }

    // spec §3.5 (ADR 0002 rule 11): a signature prefix is not a prefix of another, and every
    // registry string is distinct.
    #[test]
    fn registry_strings_distinct_and_prefix_free() {
        assert!(!SEALED_SIG_PREFIX.starts_with(&SIG_PREFIX));
        assert!(!SIG_PREFIX.starts_with(&SEALED_SIG_PREFIX));
        let all: [&[u8]; 5] = [
            BLOCK_ID_CONTEXT.as_bytes(),
            &SIG_PREFIX,
            &SEALED_HPKE_INFO,
            &SEALED_SIG_PREFIX,
            ENC_KEY_DIRECTORY_CONTEXT.as_bytes(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
