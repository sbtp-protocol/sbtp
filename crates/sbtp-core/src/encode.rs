//! Encoding, mining and signing a block (sender side). No allocation outside the `std` feature.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};

use crate::block::{
    MAGIC, MAX_PARENTS, PUBKEY_LEN, SIGNATURE_LEN, VERSION, block_len, has_duplicate,
};
use crate::block_id::{BLOCK_ID_CONTEXT, BlockId};

/// Why a block could not be encoded, mined or signed. Sender side only: validation errors are
/// [`crate::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// More than 8 parents (spec §1).
    TooManyParents,
    /// A payload longer than 65,535 bytes (spec §1).
    PayloadTooLong,
    /// Two equal parents (spec §4 F9).
    DuplicateParent,
    /// The output buffer is shorter than the block.
    BufferTooSmall,
    /// The signing key does not match the `pubkey` field.
    KeyMismatch,
    /// No nonce within the attempt budget meets the difficulty (always the case above 256).
    PowNotFound,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyParents => "more than 8 parents",
            Self::PayloadTooLong => "payload longer than 65,535 bytes",
            Self::DuplicateParent => "two equal parents",
            Self::BufferTooSmall => "output buffer too small",
            Self::KeyMismatch => "signing key does not match the public key",
            Self::PowNotFound => "no nonce within the budget meets the difficulty",
        })
    }
}

impl core::error::Error for EncodeError {}

/// The fields of a block before it is signed. Parents and payload are borrowed.
#[derive(Clone, Copy, Debug)]
pub struct UnsignedBlock<'a> {
    /// Unix time in milliseconds, set by the author.
    pub timestamp: u64,
    /// Free value for the proof of work; [`UnsignedBlock::mine`] changes it.
    pub nonce: u64,
    /// The author's Ed25519 public key.
    pub pubkey: [u8; PUBKEY_LEN],
    /// Parents, in order, at most 8, all distinct.
    pub parents: &'a [BlockId],
    /// Opaque payload, at most 65,535 bytes.
    pub payload: &'a [u8],
}

impl UnsignedBlock<'_> {
    /// Parents Count and Payload Len, once the fields fit the format (spec §1, §4 F9).
    fn lens(&self) -> Result<(u8, u16), EncodeError> {
        let count = u8::try_from(self.parents.len())
            .ok()
            .filter(|n| *n <= MAX_PARENTS)
            .ok_or(EncodeError::TooManyParents)?;
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| EncodeError::PayloadTooLong)?;
        if has_duplicate(self.parents) {
            return Err(EncodeError::DuplicateParent);
        }
        Ok((count, payload_len))
    }

    /// Feeds every byte covered by the `block_id`, in wire order (spec §1), to `put`.
    fn for_each_field(&self, mut put: impl FnMut(&[u8])) -> Result<(), EncodeError> {
        let (count, payload_len) = self.lens()?;
        put(&MAGIC);
        put(&[VERSION]);
        put(&self.timestamp.to_be_bytes());
        put(&self.nonce.to_be_bytes());
        put(&self.pubkey);
        put(&[count]);
        for parent in self.parents {
            put(parent.as_bytes());
        }
        put(&payload_len.to_be_bytes());
        put(self.payload);
        Ok(())
    }

    /// Length of the signed block: `118 + 32·N + P`.
    ///
    /// # Errors
    ///
    /// `TooManyParents`, `PayloadTooLong` or `DuplicateParent`.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        let (count, payload_len) = self.lens()?;
        Ok(block_len(count, payload_len))
    }

    /// The `block_id` these fields give (spec §2), hashed incrementally without a buffer.
    ///
    /// # Errors
    ///
    /// As [`UnsignedBlock::encoded_len`].
    pub fn block_id(&self) -> Result<BlockId, EncodeError> {
        let mut hasher = blake3::Hasher::new_derive_key(BLOCK_ID_CONTEXT);
        self.for_each_field(|bytes| {
            hasher.update(bytes);
        })?;
        Ok(BlockId(*hasher.finalize().as_bytes()))
    }

    /// Mines: tries at most `max_attempts` nonces, from the current one upward, until the
    /// `block_id` has `difficulty` leading zero bits (spec §3). On success the nonce is kept and
    /// the `block_id` returned; on failure the nonce is the next untried one, so a later call
    /// resumes there.
    ///
    /// # Errors
    ///
    /// As [`UnsignedBlock::encoded_len`], or `PowNotFound`.
    pub fn mine(&mut self, difficulty: u32, max_attempts: u64) -> Result<BlockId, EncodeError> {
        self.lens()?;
        if difficulty > 256 {
            return Err(EncodeError::PowNotFound);
        }
        for _ in 0..max_attempts {
            let id = self.block_id()?;
            if id.meets_difficulty(difficulty) {
                return Ok(id);
            }
            self.nonce = self.nonce.checked_add(1).ok_or(EncodeError::PowNotFound)?;
        }
        Err(EncodeError::PowNotFound)
    }

    /// Writes the signed block at the start of `out` and returns its length. The signature is
    /// deterministic (RFC 8032 §5.1.6) over `SIG_PREFIX ‖ block_id` (spec §3).
    ///
    /// # Errors
    ///
    /// As [`UnsignedBlock::encoded_len`], `KeyMismatch` or `BufferTooSmall`.
    pub fn sign_into(&self, key: &SigningKey, out: &mut [u8]) -> Result<usize, EncodeError> {
        if key.verifying_key().as_bytes() != &self.pubkey {
            return Err(EncodeError::KeyMismatch);
        }
        let len = self.encoded_len()?;
        let buf = out.get_mut(..len).ok_or(EncodeError::BufferTooSmall)?;
        let (body, sig) = buf
            .split_last_chunk_mut::<SIGNATURE_LEN>()
            .ok_or(EncodeError::BufferTooSmall)?;
        let mut rest: &mut [u8] = body;
        self.for_each_field(|bytes| {
            // `body` is exactly the field bytes: every split fits.
            if let Some((head, tail)) = core::mem::take(&mut rest).split_at_mut_checked(bytes.len())
            {
                head.copy_from_slice(bytes);
                rest = tail;
            }
        })?;
        let id = crate::block_id::compute_block_id(body);
        *sig = key.sign(&id.signed_message()).to_bytes();
        Ok(len)
    }

    /// Encodes and signs the block into a new vector.
    ///
    /// # Errors
    ///
    /// As [`UnsignedBlock::sign_into`].
    #[cfg(feature = "std")]
    pub fn sign(&self, key: &SigningKey) -> Result<std::vec::Vec<u8>, EncodeError> {
        let mut out = std::vec![0u8; self.encoded_len()?];
        self.sign_into(key, &mut out)?;
        Ok(out)
    }
}
