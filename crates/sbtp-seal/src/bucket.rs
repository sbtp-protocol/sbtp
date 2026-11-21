//! The four length buckets of a sealed block (spec §5.2).

use sbtp_l2::{ENC_OVERHEAD, ENC_PAYLOAD_LENS};

/// The `ChaCha20Poly1305` tag length, `Nt` (RFC 9180 §7.3): the ciphertext is the plaintext plus
/// this many bytes (spec §5.2).
pub const AEAD_TAG_LEN: usize = 16;

/// A length bucket (spec §5.2): the Payload Len of the outer block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bucket {
    /// Payload Len 512, plaintext 406 bytes.
    B512,
    /// Payload Len 2,048, plaintext 1,942 bytes.
    B2048,
    /// Payload Len 8,192, plaintext 8,086 bytes.
    B8192,
    /// Payload Len 65,535, plaintext 65,429 bytes.
    B65535,
}

impl Bucket {
    /// Every bucket, smallest first.
    pub const ALL: [Self; 4] = [Self::B512, Self::B2048, Self::B8192, Self::B65535];

    /// The Payload Len of the outer block (spec §5.2), taken from `sbtp_l2::ENC_PAYLOAD_LENS`.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        match self {
            Self::B512 => ENC_PAYLOAD_LENS[0],
            Self::B2048 => ENC_PAYLOAD_LENS[1],
            Self::B8192 => ENC_PAYLOAD_LENS[2],
            Self::B65535 => ENC_PAYLOAD_LENS[3],
        }
    }

    /// The ciphertext length: Payload Len minus the 90-byte overhead (spec §5.2).
    #[must_use]
    pub const fn ciphertext_len(self) -> usize {
        // Every bucket is larger than the overhead: no underflow (checked by a test).
        self.payload_len() - ENC_OVERHEAD
    }

    /// The plaintext length: ciphertext minus the AEAD tag (spec §5.2): 406, 1,942, 8,086 or
    /// 65,429 bytes.
    #[must_use]
    pub const fn plaintext_len(self) -> usize {
        self.ciphertext_len() - AEAD_TAG_LEN
    }

    /// The bucket whose ciphertext is `ct_len` bytes, if any.
    #[must_use]
    pub fn from_ciphertext_len(ct_len: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.ciphertext_len() == ct_len)
    }

    /// The smallest bucket whose plaintext holds `item_len` bytes (spec §5.3: a sender SHOULD
    /// use the smallest bucket that fits).
    #[must_use]
    pub fn smallest_for(item_len: usize) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|b| b.plaintext_len() >= item_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec §5.2: the payload, ciphertext and plaintext lengths of the four buckets.
    #[test]
    fn lengths() {
        let plain: [usize; 4] = Bucket::ALL.map(Bucket::plaintext_len);
        assert_eq!(plain, [406, 1_942, 8_086, 65_429]);
        let payload: [usize; 4] = Bucket::ALL.map(Bucket::payload_len);
        assert_eq!(payload, [512, 2_048, 8_192, 65_535]);
        for b in Bucket::ALL {
            assert_eq!(Bucket::from_ciphertext_len(b.ciphertext_len()), Some(b));
        }
        assert_eq!(Bucket::from_ciphertext_len(423), None);
        assert_eq!(Bucket::smallest_for(0), Some(Bucket::B512));
        assert_eq!(Bucket::smallest_for(406), Some(Bucket::B512));
        assert_eq!(Bucket::smallest_for(407), Some(Bucket::B2048));
        assert_eq!(Bucket::smallest_for(65_429), Some(Bucket::B65535));
        assert_eq!(Bucket::smallest_for(65_430), None);
    }
}
