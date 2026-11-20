//! Building, mining and signing blocks (sender side).
//!
//! Everything here works on a caller-provided `&mut [u8]` and does not allocate; the `std` feature adds
//! [`BlockBuilder::build`] and [`BlockBuilder::build_unsigned`], which return a `Vec<u8>`.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};

use crate::block::parse;
use crate::block_id::{BlockId, MAX_DIFFICULTY, block_id_hasher};
use crate::error::Error;
use crate::layout::{
    MAGIC, MAX_PARENTS, MAX_PAYLOAD_LEN, OFFSET_NONCE, PUBKEY_LEN, SIGNATURE_LEN, VERSION_V1,
    block_len,
};

/// Why a block could not be built, mined or signed. Sender-side only: validation errors are
/// [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// More than 8 parents (`MAX_PARENTS`, spec §2.2 F5).
    TooManyParents {
        /// Number of parents given.
        count: usize,
    },
    /// Payload longer than 65,535 bytes.
    PayloadTooLong {
        /// Payload length given.
        len: usize,
    },
    /// Two identical parents (spec §2.2 F9).
    DuplicateParent {
        /// Index of the first occurrence.
        first: usize,
        /// Index of the second occurrence.
        second: usize,
    },
    /// The output buffer is too small.
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        len: usize,
    },
    /// The buffer to mine or sign is not a well-formed block.
    Malformed(Error),
    /// The signing key does not match the `PubKey` field of the block.
    KeyMismatch,
    /// The nonce space was exhausted (or the attempt limit reached) without meeting the difficulty.
    PowNotFound,
    /// The difficulty is above 256: no `block_id` can meet it (spec §3.3), so mining is refused
    /// without trying a single nonce.
    DifficultyTooHigh {
        /// The difficulty requested.
        difficulty: u32,
    },
    /// The Ed25519 signer returned an error.
    Signing,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyParents { count } => {
                write!(f, "too many parents: {count}, maximum {MAX_PARENTS}")
            }
            Self::PayloadTooLong { len } => {
                write!(
                    f,
                    "payload too long: {len} bytes, maximum {}",
                    crate::layout::MAX_PAYLOAD_LEN
                )
            }
            Self::DuplicateParent { first, second } => {
                write!(f, "duplicate parent at indices {first} and {second}")
            }
            Self::BufferTooSmall { needed, len } => {
                write!(f, "output buffer too small: {len} bytes, {needed} needed")
            }
            Self::Malformed(error) => write!(f, "malformed block: {error}"),
            Self::KeyMismatch => f.write_str("signing key does not match the block public key"),
            Self::PowNotFound => f.write_str("no nonce meets the difficulty"),
            Self::DifficultyTooHigh { difficulty } => {
                write!(f, "difficulty {difficulty} is above the maximum of 256")
            }
            Self::Signing => f.write_str("signing failed"),
        }
    }
}

impl core::error::Error for BuildError {}

impl From<Error> for BuildError {
    fn from(error: Error) -> Self {
        Self::Malformed(error)
    }
}

/// Default attempt budget of [`BlockBuilder::build`]: 2^28 nonces, about 45 s at the measured
/// 5.9 M attempts/s of a native build. Enough for a difficulty up to about 26 (expected 2^d
/// attempts); a hostile relay announcing a difficulty of 60 costs the client that much and no more.
/// Above about d = 26, [`BlockBuilder::build`] may return `PowNotFound`: raise the budget with
/// [`BlockBuilder::max_attempts`].
pub const DEFAULT_MAX_ATTEMPTS: u64 = 1 << 28;

/// Builds the bytes of a block. Parents and payload are borrowed, not copied.
///
/// The builder only produces well-formed blocks: it refuses more than 8 parents, duplicate parents and
/// a payload over 65,535 bytes.
#[derive(Clone, Copy, Debug)]
pub struct BlockBuilder<'a> {
    timestamp: u64,
    nonce: u64,
    pubkey: [u8; PUBKEY_LEN],
    parents: &'a [BlockId],
    payload: &'a [u8],
    max_attempts: u64,
}

impl<'a> BlockBuilder<'a> {
    /// A root block (no parent, empty payload) for `pubkey`, timestamp 0, nonce 0.
    #[must_use]
    pub const fn new(pubkey: [u8; PUBKEY_LEN]) -> Self {
        Self {
            timestamp: 0,
            nonce: 0,
            pubkey,
            parents: &[],
            payload: &[],
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Sets the mining budget of [`BlockBuilder::build`]: at most `max_attempts` nonces are tried
    /// before `PowNotFound`. Default [`DEFAULT_MAX_ATTEMPTS`] (2^28, enough up to about d = 26);
    /// `u64::MAX` removes the bound.
    #[must_use]
    pub const fn max_attempts(mut self, max_attempts: u64) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// A builder for the public key of `key`.
    #[must_use]
    pub fn for_key(key: &SigningKey) -> Self {
        Self::new(key.verifying_key().to_bytes())
    }

    /// Sets the Timestamp field (Unix milliseconds).
    #[must_use]
    pub const fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the Nonce field; also the starting value for [`BlockBuilder::build`] mining.
    #[must_use]
    pub const fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Sets the parents, in order.
    #[must_use]
    pub const fn parents(mut self, parents: &'a [BlockId]) -> Self {
        self.parents = parents;
        self
    }

    /// Sets the payload.
    #[must_use]
    pub const fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }

    /// Length of the encoded block.
    ///
    /// # Errors
    ///
    /// `TooManyParents`, `DuplicateParent` or `PayloadTooLong`.
    pub fn encoded_len(&self) -> Result<usize, BuildError> {
        let count = u8::try_from(self.parents.len())
            .ok()
            .filter(|n| *n <= MAX_PARENTS)
            .ok_or(BuildError::TooManyParents {
                count: self.parents.len(),
            })?;
        let payload_len = u16::try_from(self.payload.len())
            .ok()
            .filter(|_| self.payload.len() <= MAX_PAYLOAD_LEN)
            .ok_or(BuildError::PayloadTooLong {
                len: self.payload.len(),
            })?;
        for (i, a) in self.parents.iter().enumerate() {
            for (j, b) in self.parents.iter().enumerate().skip(i + 1) {
                if a == b {
                    return Err(BuildError::DuplicateParent {
                        first: i,
                        second: j,
                    });
                }
            }
        }
        Ok(block_len(count, payload_len))
    }

    /// Writes the block at the start of `out`, with the 64 signature bytes set to zero, and returns
    /// its length. Sign it with [`sign_block`], after [`mine`] if a difficulty is required.
    ///
    /// # Errors
    ///
    /// The errors of [`BlockBuilder::encoded_len`], or `BufferTooSmall`.
    pub fn write_unsigned(&self, out: &mut [u8]) -> Result<usize, BuildError> {
        let needed = self.encoded_len()?;
        let available = out.len();
        let buf = out.get_mut(..needed).ok_or(BuildError::BufferTooSmall {
            needed,
            len: available,
        })?;
        // encoded_len checked both conversions.
        let count = u8::try_from(self.parents.len()).unwrap_or(u8::MAX);
        let payload_len = u16::try_from(self.payload.len()).unwrap_or(u16::MAX);

        // spec §2, ADR 0001: big-endian integers.
        let mut w = Writer { buf, pos: 0 };
        w.put(&MAGIC)?;
        w.put(&[VERSION_V1])?;
        w.put(&self.timestamp.to_be_bytes())?;
        w.put(&self.nonce.to_be_bytes())?;
        w.put(&self.pubkey)?;
        w.put(&[count])?;
        for parent in self.parents {
            w.put(parent.as_bytes())?;
        }
        w.put(&payload_len.to_be_bytes())?;
        w.put(self.payload)?;
        w.put(&[0u8; SIGNATURE_LEN])?;
        Ok(needed)
    }

    /// Encodes the block with a zeroed signature.
    ///
    /// # Errors
    ///
    /// The errors of [`BlockBuilder::encoded_len`].
    #[cfg(feature = "std")]
    pub fn build_unsigned(&self) -> Result<std::vec::Vec<u8>, BuildError> {
        let mut out = std::vec![0u8; self.encoded_len()?];
        self.write_unsigned(&mut out)?;
        Ok(out)
    }

    /// Encodes, mines (starting from the builder's nonce, increment by 1, ADR 0001 rule 3) and signs
    /// the block.
    ///
    /// **Bounded search.** At most [`BlockBuilder::max_attempts`] nonces are tried:
    /// [`DEFAULT_MAX_ATTEMPTS`] = 2^28 unless set (review 2026-11-18 M2, F-4). A difficulty `d`
    /// needs about 2^d attempts on average, so above about `d = 26` a call with the default budget
    /// may return `PowNotFound`, and above about `d = 28` it usually will. To mine harder blocks,
    /// raise the budget with `.max_attempts(n)`; `.max_attempts(u64::MAX)` makes the search
    /// unbounded again (up to 2^64 nonces). `PowNotFound` (budget spent, a larger budget may
    /// succeed) is distinct from `DifficultyTooHigh` (`d > 256`, no budget can succeed). A caller
    /// that must stay responsive (WASM) mines with [`mine`] in small slices instead, and caps the
    /// difficulty it accepts from a relay.
    ///
    /// # Errors
    ///
    /// The errors of [`BlockBuilder::encoded_len`], `DifficultyTooHigh` (above 256, returned before
    /// any work), `KeyMismatch`, `PowNotFound` (attempt budget spent) or `Signing`.
    #[cfg(feature = "std")]
    pub fn build(
        &self,
        key: &SigningKey,
        difficulty: u32,
    ) -> Result<std::vec::Vec<u8>, BuildError> {
        check_difficulty(difficulty)?;
        if &self.pubkey != key.verifying_key().as_bytes() {
            return Err(BuildError::KeyMismatch);
        }
        let mut out = self.build_unsigned()?;
        if difficulty > 0 {
            mine(&mut out, difficulty, self.max_attempts)?;
        }
        sign_block(&mut out, key)?;
        Ok(out)
    }
}

/// Sequential writer over a fixed buffer.
struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl Writer<'_> {
    /// Copies `src` at the current position and advances.
    fn put(&mut self, src: &[u8]) -> Result<(), BuildError> {
        let available = self.buf.len();
        let end = self
            .pos
            .checked_add(src.len())
            .ok_or(BuildError::BufferTooSmall {
                needed: usize::MAX,
                len: available,
            })?;
        let dst = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(BuildError::BufferTooSmall {
                needed: end,
                len: available,
            })?;
        dst.copy_from_slice(src);
        self.pos = end;
        Ok(())
    }
}

/// Searches a nonce such that the `block_id` has at least `difficulty` leading zero bits
/// (spec §3.3). Starts from the Nonce field already in `block`, increments by 1 (ADR 0001 rule 3),
/// tries at most `max_attempts` values. Returns the nonce and the `block_id`.
///
/// Nonce left in `block`:
/// - on success, the winning nonce;
/// - on `PowNotFound`, the **next untried** nonce (start + `max_attempts`), so that mining in
///   slices, `mine(&mut block, d, k)` called again until it succeeds, resumes where the previous
///   slice stopped and reaches the same nonce as one unbounded call. If the nonce space ends
///   (`u64::MAX` tried), the block keeps `u64::MAX` and every later call fails at once;
/// - on any other error, the block is unchanged.
///
/// The signature bytes are not covered by the `block_id`: sign after mining.
///
/// # Errors
///
/// `DifficultyTooHigh` if `difficulty > 256`, before any hashing (no `block_id` can meet it);
/// `Malformed` if `block` fails F1 to F9; `PowNotFound` if no nonce was found within
/// `max_attempts` attempts.
pub fn mine(
    block: &mut [u8],
    difficulty: u32,
    max_attempts: u64,
) -> Result<(u64, BlockId), BuildError> {
    check_difficulty(difficulty)?;
    let parsed = parse(block)?;
    let hashed_len = parsed.hashed_bytes().len();
    let mut nonce = parsed.nonce();

    // ADR 0002 "Cost": key the derive_key hasher once, clone it per attempt.
    let base = block_id_hasher();
    let mut attempts = 0u64;
    while attempts < max_attempts {
        set_nonce(block, nonce)?;
        let covered = block
            .get(..hashed_len)
            .ok_or(BuildError::Malformed(Error::TooShort { len: 0 }))?;
        let mut hasher = base.clone();
        hasher.update(covered);
        let id = BlockId(*hasher.finalize().as_bytes());
        if id.meets_difficulty(difficulty) {
            return Ok((nonce, id));
        }
        attempts += 1;
        // End of the nonce space: the block keeps u64::MAX, the last nonce tried.
        nonce = nonce.checked_add(1).ok_or(BuildError::PowNotFound)?;
    }
    // Budget spent: leave the next untried nonce, so that the next slice resumes there.
    set_nonce(block, nonce)?;
    Err(BuildError::PowNotFound)
}

/// spec §3.3: a `block_id` has at most 256 leading zero bits; above that, mining could only loop
/// through the whole nonce space (review 2026-11-18, L-2).
fn check_difficulty(difficulty: u32) -> Result<(), BuildError> {
    if difficulty > MAX_DIFFICULTY {
        return Err(BuildError::DifficultyTooHigh { difficulty });
    }
    Ok(())
}

fn set_nonce(block: &mut [u8], nonce: u64) -> Result<(), BuildError> {
    let field = block
        .get_mut(OFFSET_NONCE..OFFSET_NONCE + 8)
        .ok_or(BuildError::Malformed(Error::TooShort { len: 0 }))?;
    field.copy_from_slice(&nonce.to_be_bytes());
    Ok(())
}

/// Signs a well-formed block in place: computes its `block_id` and writes
/// `Ed25519_Sign(sk, SIG_PREFIX ‖ block_id)` into the last 64 bytes (spec §3.2). Signing is
/// deterministic (RFC 8032 §5.1.6). Returns the `block_id`.
///
/// # Errors
///
/// `Malformed` if `block` fails F1 to F9; `KeyMismatch` if `key` is not the `PubKey` field's key;
/// `Signing` if the signer fails.
pub fn sign_block(block: &mut [u8], key: &SigningKey) -> Result<BlockId, BuildError> {
    let parsed = parse(block)?;
    if parsed.pubkey() != key.verifying_key().as_bytes() {
        return Err(BuildError::KeyMismatch);
    }
    let id = parsed.block_id();
    let signature = sign_block_id(key, &id)?;
    let len = block.len();
    let field = block
        .get_mut(len.saturating_sub(SIGNATURE_LEN)..)
        .ok_or(BuildError::Malformed(Error::TooShort { len }))?;
    field.copy_from_slice(&signature);
    Ok(id)
}

/// Signs `SIG_PREFIX ‖ id` (spec §3.2). This is the only message an SBTP key signs (ADR 0002 rule 8).
///
/// # Errors
///
/// `Signing` if the signer fails.
pub fn sign_block_id(key: &SigningKey, id: &BlockId) -> Result<[u8; SIGNATURE_LEN], BuildError> {
    key.try_sign(&id.signed_message())
        .map(|signature| signature.to_bytes())
        .map_err(|_| BuildError::Signing)
}
