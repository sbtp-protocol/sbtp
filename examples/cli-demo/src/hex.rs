//! Hexadecimal text for identifiers, public keys and the key file.

use sbtp_core::BlockId;

/// Lowercase hexadecimal of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes exactly `N` bytes from `2·N` hexadecimal characters (either case).
pub fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, [hi, lo]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A `block_id` given on the command line: 64 hexadecimal characters. The relay API takes the
/// lowercase form only (spec §4); the CLI accepts either case and always sends lowercase.
pub fn block_id(text: &str) -> Option<BlockId> {
    decode::<32>(text).map(BlockId::from_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejections() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        assert_eq!(encode(&bytes), "007fabff");
        assert_eq!(decode::<4>("007fabff"), Some(bytes));
        assert_eq!(decode::<4>("007FABFF"), Some(bytes));
        assert_eq!(decode::<4>("007fabf"), None);
        assert_eq!(decode::<4>("007fabfg"), None);
        assert_eq!(decode::<4>("+07fabff"), None);
        assert_eq!(decode::<4>("007fabff00"), None);
    }

    #[test]
    fn block_id_display_matches_encode() {
        let id = BlockId::from_bytes([0xa5; 32]);
        assert_eq!(id.to_string(), encode(id.as_bytes()));
        assert_eq!(block_id(&id.to_string()), Some(id));
    }
}
