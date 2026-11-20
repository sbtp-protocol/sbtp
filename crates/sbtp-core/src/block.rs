//! Zero-copy view over a received block and format validation F1 to F9 (spec §2.1, §2.2, ADR 0004).

use zerocopy::byteorder::{BigEndian, U16, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::block_id::{BlockId, compute_block_id};
use crate::error::Error;
use crate::layout::{
    FIXED_HEADER_LEN, MAGIC, MAX_BLOCK_LEN, MAX_PARENTS, MIN_BLOCK_LEN, PUBKEY_LEN, SIGNATURE_LEN,
    VERSION_V1, block_len,
};

/// The 52-byte fixed header (spec §2.1, item 1). Every field has alignment 1: `zerocopy` casts it from
/// any offset of the buffer.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Header {
    pub(crate) magic: [u8; 2],
    pub(crate) version: u8,
    // ADR 0001: every multi-byte integer is big-endian.
    pub(crate) timestamp: U64<BigEndian>,
    pub(crate) nonce: U64<BigEndian>,
    pub(crate) pubkey: [u8; PUBKEY_LEN],
    pub(crate) parents_count: u8,
}

// The struct and the layout constants describe the same 52 bytes.
const _: () = assert!(size_of::<Header>() == FIXED_HEADER_LEN);

/// A well-formed block, read in place from the received buffer (spec §2.1, item 3).
///
/// A `BlockRef` exists only once checks F1 to F9 have passed: every accessor is infallible.
///
/// **Unauthenticated.** A `BlockRef` says nothing about the proof of work or the signature: its
/// author and content are attacker-controlled. Code that stores, forwards or displays a received
/// block takes a [`crate::ValidatedBlock`] instead.
#[derive(Clone, Copy)]
pub struct BlockRef<'a> {
    bytes: &'a [u8],
    header: &'a Header,
    parents: &'a [BlockId],
    payload: &'a [u8],
    signature: &'a [u8; SIGNATURE_LEN],
    /// `bytes[0 .. Offset(Signature)]`, the range covered by the `block_id` (spec §3.1).
    hashed: &'a [u8],
}

impl core::fmt::Debug for BlockRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockRef")
            .field("len", &self.bytes.len())
            .field("timestamp", &self.timestamp())
            .field("nonce", &self.nonce())
            .field("parents", &self.parents)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl<'a> BlockRef<'a> {
    /// The whole block, signature included.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Version field (always `0x01` for a well-formed block).
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.header.version
    }

    /// Timestamp field: Unix time in milliseconds, uninterpreted at layer 0 (`[Q-07]`).
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp.get()
    }

    /// Nonce field.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.header.nonce.get()
    }

    /// `PubKey` field, as received (not validated as a curve point before [`crate::validate`]).
    #[must_use]
    pub const fn pubkey(&self) -> &'a [u8; PUBKEY_LEN] {
        &self.header.pubkey
    }

    /// Parent hashes, in the order of the block (spec §2.2: order is significant and kept).
    #[must_use]
    pub const fn parents(&self) -> &'a [BlockId] {
        self.parents
    }

    /// Opaque payload.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Signature field, as received.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; SIGNATURE_LEN] {
        self.signature
    }

    /// The range covered by the `block_id`: the whole block except the 64 signature bytes.
    #[must_use]
    pub const fn hashed_bytes(&self) -> &'a [u8] {
        self.hashed
    }

    /// Computes the `block_id` (spec §3.1).
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        compute_block_id(self.hashed)
    }
}

/// Runs the format checks F1 to F9 in the order of spec §2.2 and returns a view over the buffer.
///
/// No byte is read before the buffer is known to contain it; no allocation; no copy.
///
/// **Format only: this does not validate a block.** `parse` is for tooling, the sender side and the
/// first stage of the staged validation ([`BlockRef::check_pow`], then
/// [`crate::PowChecked::verify_signature`]). A recipient validates with
/// [`crate::validate_submitted`] or [`crate::validate_requested`] (spec §3.4).
///
/// # Errors
///
/// The [`Error`] of the first failing check, among `TooShort`, `TooLong`, `BadMagic`,
/// `UnsupportedVersion`, `TooManyParents`, `Truncated`, `TrailingBytes` and `DuplicateParent`.
pub fn parse(bytes: &[u8]) -> Result<BlockRef<'_>, Error> {
    let len = bytes.len();

    // spec §2.2 F1: len < 118.
    if len < MIN_BLOCK_LEN {
        return Err(Error::TooShort { len });
    }
    // spec §2.2 F2: len > 65,909.
    if len > MAX_BLOCK_LEN {
        return Err(Error::TooLong { len });
    }

    // len ≥ 118 > 52, so the cast cannot fail; the error branch is kept to stay panic-free.
    let (header, after_header) =
        Header::ref_from_prefix(bytes).map_err(|_| Error::TooShort { len })?;

    // spec §2.2 F3: magic.
    if header.magic != MAGIC {
        return Err(Error::BadMagic {
            found: header.magic,
        });
    }
    // spec §2.2 F4: version.
    if header.version != VERSION_V1 {
        return Err(Error::UnsupportedVersion {
            version: header.version,
        });
    }
    // spec §2.2 F5: N > 8.
    let count = header.parents_count;
    if count > MAX_PARENTS {
        return Err(Error::TooManyParents { count });
    }

    // spec §2.2 F6: len < 118 + 32·N. N ≤ 8 here: no overflow, even on a 32-bit target.
    let min_with_parents = block_len(count, 0);
    if len < min_with_parents {
        return Err(Error::Truncated {
            expected_min: min_with_parents,
            len,
        });
    }

    let truncated_f6 = Error::Truncated {
        expected_min: min_with_parents,
        len,
    };
    let (parents, after_parents) =
        <[BlockId]>::ref_from_prefix_with_elems(after_header, usize::from(count))
            .map_err(|_| truncated_f6)?;
    let (payload_len, after_payload_len) =
        U16::<BigEndian>::ref_from_prefix(after_parents).map_err(|_| truncated_f6)?;
    let payload_len = payload_len.get();

    // spec §2.2 F7 and F8: the length must be exactly 118 + 32·N + P.
    let expected = block_len(count, payload_len);
    if len < expected {
        return Err(Error::Truncated {
            expected_min: expected,
            len,
        });
    }
    if len > expected {
        return Err(Error::TrailingBytes { expected, len });
    }

    // From here len == expected: the splits below cannot fail.
    let (payload, signature) = after_payload_len
        .split_at_checked(usize::from(payload_len))
        .ok_or(Error::Truncated {
            expected_min: expected,
            len,
        })?;
    let signature = <&[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| Error::Truncated {
        expected_min: expected,
        len,
    })?;
    let hashed = bytes
        .get(..len - SIGNATURE_LEN)
        .ok_or(Error::TooShort { len })?;

    // spec §2.2 F9: no two identical parents, at any positions (at most 28 comparisons, ADR 0014).
    check_distinct_parents(parents)?;

    Ok(BlockRef {
        bytes,
        header,
        parents,
        payload,
        signature,
        hashed,
    })
}

/// spec §2.2 F9. Reports the first duplicate pair in `(first, second)` lexicographic order.
fn check_distinct_parents(parents: &[BlockId]) -> Result<(), Error> {
    match first_duplicate(parents) {
        None => Ok(()),
        // Indices are < 8 after F5.
        Some((first, second)) => Err(Error::DuplicateParent {
            first: u8::try_from(first).unwrap_or(u8::MAX),
            second: u8::try_from(second).unwrap_or(u8::MAX),
        }),
    }
}

/// spec §2.2 F9: the first pair of equal parents, in `(first, second)` lexicographic order, if
/// any. Shared by the decoder and the builder. At most 8 parents reach it, so 28 comparisons.
pub(crate) fn first_duplicate(parents: &[BlockId]) -> Option<(usize, usize)> {
    parents.iter().enumerate().find_map(|(i, a)| {
        parents
            .iter()
            .enumerate()
            .skip(i + 1)
            .find(|(_, b)| a == *b)
            .map(|(j, _)| (i, j))
    })
}
