//! Block format (SPEC §1) and the format checks F1 to F9 (SPEC §4), read in place with `zerocopy`.

use zerocopy::byteorder::{BigEndian, U16, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::block_id::{BlockId, compute_block_id};
use crate::error::Error;

/// Size of a `block_id` and of a parent.
pub const HASH_LEN: usize = 32;
/// Size of an Ed25519 public key.
pub const PUBKEY_LEN: usize = 32;
/// Size of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Most parents a block may name (spec §1).
pub const MAX_PARENTS: u8 = 8;
/// Smallest block: no parent, empty payload (spec §1).
pub const MIN_BLOCK_LEN: usize = 118;
/// Largest block: 8 parents, 65,535-byte payload (spec §1).
pub const MAX_BLOCK_LEN: usize = 65_909;

pub(crate) const MAGIC: [u8; 2] = *b"SB";
pub(crate) const VERSION: u8 = 0x01;
pub(crate) const HEADER_LEN: usize = 52;

/// The 52-byte fixed header (spec §1). Every field has alignment 1.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    magic: [u8; 2],
    version: u8,
    // spec §1: every integer longer than one byte is big-endian.
    timestamp: U64<BigEndian>,
    nonce: U64<BigEndian>,
    pubkey: [u8; PUBKEY_LEN],
    parents_count: u8,
}

const _: () = assert!(size_of::<Header>() == HEADER_LEN);

/// spec §1: `118 + 32·N + P`. At most 118 + 32·255 + 65,535 = 73,813: no overflow on 32-bit or
/// 64-bit `usize`, whatever the fields hold.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) const fn block_len(parents: u8, payload_len: u16) -> usize {
    MIN_BLOCK_LEN + parents as usize * HASH_LEN + payload_len as usize
}

/// A well-formed block (F1 to F9 passed), read in place from the received buffer.
///
/// **Unauthenticated**: proof of work and signature are not checked. Code that stores, forwards
/// or displays a received block takes a [`crate::ValidatedBlock`].
#[derive(Clone, Copy)]
pub struct BlockRef<'a> {
    bytes: &'a [u8],
    header: &'a Header,
    parents: &'a [BlockId],
    payload: &'a [u8],
    signature: &'a [u8; SIGNATURE_LEN],
    hashed: &'a [u8],
}

impl core::fmt::Debug for BlockRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockRef")
            .field("len", &self.bytes.len())
            .field("timestamp", &self.timestamp())
            .field("nonce", &self.nonce())
            .field("parents", &self.parents)
            .finish_non_exhaustive()
    }
}

impl<'a> BlockRef<'a> {
    /// The whole block, signature included.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Timestamp field, Unix milliseconds, set by the author and not checked by layer 0.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp.get()
    }

    /// Nonce field.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.header.nonce.get()
    }

    /// `PubKey` field, as received.
    #[must_use]
    pub const fn pubkey(&self) -> &'a [u8; PUBKEY_LEN] {
        &self.header.pubkey
    }

    /// Parents, in block order (spec §1: order is significant and kept).
    #[must_use]
    pub const fn parents(&self) -> &'a [BlockId] {
        self.parents
    }

    /// Opaque payload (spec §1: never interpreted by layer 0).
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Signature field, as received.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; SIGNATURE_LEN] {
        self.signature
    }

    /// Computes the `block_id` over the block without its signature (spec §2).
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        compute_block_id(self.hashed)
    }

    /// P1, relay `PUT` only: rejects a Timestamp later than `now_ms + max_future_ms`, `now_ms`
    /// being the relay clock. Run it between [`parse`] and [`BlockRef::check_pow`].
    ///
    /// # Errors
    ///
    /// [`Error::TimestampTooFarInFuture`].
    pub fn check_timestamp(&self, now_ms: u64, max_future_ms: u64) -> Result<(), Error> {
        // spec §4 P1. A sum above u64::MAX exceeds every Timestamp: saturating is exact here.
        if self.timestamp() > now_ms.saturating_add(max_future_ms) {
            return Err(Error::TimestampTooFarInFuture);
        }
        Ok(())
    }
}

/// Runs the format checks F1 to F9 in the order of spec §4 and returns a view over the buffer.
///
/// No byte is read before the buffer is known to hold it; no allocation; no copy. This does not
/// validate a block: see [`crate::validate_submitted`] and [`crate::validate_requested`].
///
/// # Errors
///
/// The first failing check among F1 to F9.
pub fn parse(bytes: &[u8]) -> Result<BlockRef<'_>, Error> {
    let len = bytes.len();
    // spec §4 F1.
    if len < MIN_BLOCK_LEN {
        return Err(Error::TooShort);
    }
    // spec §4 F2.
    if len > MAX_BLOCK_LEN {
        return Err(Error::TooLong);
    }
    // len ≥ 118 > 52: cannot fail, the branch only keeps the code panic-free.
    let (header, rest) = Header::ref_from_prefix(bytes).map_err(|_| Error::TooShort)?;
    // spec §4 F3.
    if header.magic != MAGIC {
        return Err(Error::BadMagic);
    }
    // spec §4 F4.
    if header.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    // spec §4 F5.
    let count = header.parents_count;
    if count > MAX_PARENTS {
        return Err(Error::TooManyParents);
    }
    // spec §4 F6: len ≥ 118 + 32·N, so the parents and Payload Len are in the buffer.
    if len < block_len(count, 0) {
        return Err(Error::Truncated);
    }
    let (parents, rest) = <[BlockId]>::ref_from_prefix_with_elems(rest, usize::from(count))
        .map_err(|_| Error::Truncated)?;
    let (payload_len, rest) =
        U16::<BigEndian>::ref_from_prefix(rest).map_err(|_| Error::Truncated)?;
    let payload_len = payload_len.get();
    let expected = block_len(count, payload_len);
    // spec §4 F7.
    if len < expected {
        return Err(Error::Truncated);
    }
    // spec §4 F8.
    if len > expected {
        return Err(Error::TrailingBytes);
    }
    // len == expected from here: the splits below cannot fail.
    let (payload, signature) = rest
        .split_at_checked(usize::from(payload_len))
        .ok_or(Error::Truncated)?;
    let signature = <&[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| Error::Truncated)?;
    let hashed = bytes
        .get(..len.saturating_sub(SIGNATURE_LEN))
        .ok_or(Error::Truncated)?;
    // spec §4 F9: no two equal parents, at any positions.
    if has_duplicate(parents) {
        return Err(Error::DuplicateParent);
    }
    Ok(BlockRef {
        bytes,
        header,
        parents,
        payload,
        signature,
        hashed,
    })
}

/// spec §4 F9, shared with the encoder. At most 8 parents reach it: 28 comparisons.
pub(crate) fn has_duplicate(parents: &[BlockId]) -> bool {
    parents
        .iter()
        .enumerate()
        .any(|(i, a)| parents.iter().skip(i.saturating_add(1)).any(|b| a == b))
}
