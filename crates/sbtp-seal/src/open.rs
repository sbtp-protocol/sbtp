//! Recipient side: steps (4) to (8) of the order of checks of spec §5.3.

use alloc::vec;
use alloc::vec::Vec;

use hpke::{Deserializable, OpModeR};
use sbtp_core::{
    SEALED_HPKE_INFO, SealedSigError, sealed_sig_message, sealed_sig_message_len, verify_sealed,
};
use sbtp_l2::cbor::{self, Reader};
use sbtp_l2::{Enc, L2Error, Payload, body, validate_l2_invariants};
use zeroize::Zeroizing;

use crate::keys::{Aead, Kdf, Kem};
use crate::seal::aad;
use crate::{Bucket, OpenError, RecipientKey, Tag};

/// What a recipient opens, and with which of its keys (spec §5.3).
#[derive(Clone, Copy, Debug)]
pub struct OpenRequest<'a> {
    /// The `PubKey` field of the outer block.
    pub outer_pubkey: &'a [u8; 32],
    /// The outer block's single header parent, the delivery tag.
    pub tag: &'a Tag,
    /// The outer body, as returned by `sbtp_l2::validate_l2_invariants` (step 2).
    pub enc: &'a Enc<'a>,
    /// The recipient's **own** `recipient_id`, as the application that defines the tag fixes it
    /// (spec §5.3, §5.4); never a value read from the block.
    pub recipient_id: &'a [u8; 32],
    /// The private keys to try, newest first (spec §5.3 step 4). The caller selects them: its keys
    /// for the tag's purpose published no later than the end of the day after the outer block's
    /// day.
    pub keys: &'a [RecipientKey],
    /// The `msg` kinds the tag allows (spec §5.3 step 8, §5.4).
    pub allowed_kinds: &'a [&'a str],
}

/// An opened sealed block: steps (4) to (8) of spec §5.3 passed. The plaintext is wiped on drop.
///
/// Steps (9), the tag check of the application, and (10), the checks of the kind, are left to
/// the caller, on [`Opened::payload`].
pub struct Opened {
    msg: Zeroizing<Vec<u8>>,
    from: [u8; 32],
    key_index: usize,
}

impl Opened {
    /// The sender key `from`, checked by `sig` (spec §5.3).
    #[must_use]
    pub const fn from(&self) -> &[u8; 32] {
        &self.from
    }

    /// The `msg` bytes: a grammar payload (spec §5.3).
    #[must_use]
    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    /// `msg` decoded again (it passed this check during [`open`]).
    ///
    /// # Errors
    ///
    /// Not expected; the [`L2Error`] of `sbtp_l2::validate_l2_invariants`.
    pub fn payload(&self) -> Result<Payload<'_>, L2Error> {
        validate_l2_invariants(&[], self.msg())
    }

    /// The index, in [`OpenRequest::keys`], of the key that opened the block.
    #[must_use]
    pub const fn key_index(&self) -> usize {
        self.key_index
    }
}

impl core::fmt::Debug for Opened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opened")
            .field("from", &self.from)
            .field("msg_len", &self.msg.len())
            .field("key_index", &self.key_index)
            .finish_non_exhaustive()
    }
}

/// Opens a sealed block: steps (4) to (8) of spec §5.3, in that order.
///
/// The caller has already run steps (1) layer 0 validation (`sbtp-core`), (2) grammar validation
/// (`sbtp-l2`, which yields `enc`) and (3) "the tag is one it polls". It runs (9) and (10) on the
/// result. A recipient ignores a failed block silently and tells no one which check failed.
///
/// # Errors
///
/// The [`OpenError`] of the first failed check.
pub fn open(request: &OpenRequest<'_>) -> Result<Opened, OpenError> {
    // spec §5.2: the ciphertext is that of a bucket (already checked by grammar validation).
    if Bucket::from_ciphertext_len(request.enc.ct.len()).is_none() {
        return Err(OpenError::CiphertextLength);
    }

    // (4) HPKE Open with each key, newest first (spec §5.1, §5.3).
    let (key_index, key, plaintext) = hpke_open(request)?;

    // (5) padding: one item from the start, then only `0x00` (spec §5.3).
    let item_len = Reader::new(&plaintext)
        .skip()
        .map_err(OpenError::ItemEncoding)?
        .len();
    let (item, padding) = plaintext
        .split_at_checked(item_len)
        .ok_or(OpenError::ItemEncoding(L2Error::Truncated))?;
    if padding.iter().any(|&b| b != 0x00) {
        return Err(OpenError::Padding);
    }

    // (6) the item: deterministic profile, then exactly `from`, `msg`, `sig` (spec §5.3), then
    // `from` differs from the outer PubKey (spec §5.2).
    cbor::check_profile(item).map_err(OpenError::ItemEncoding)?;
    let (from, msg, sig) = read_item(item)?;
    if &from == request.outer_pubkey {
        return Err(OpenError::FromIsOuterPubKey);
    }

    // (7) `sig`, strict V1 to V6, over the message the recipient rebuilds with its own
    // `recipient_id` and the key that opened the block (spec §5.3).
    let len = sealed_sig_message_len(msg.len()).ok_or(OpenError::Signature)?;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    let message = sealed_sig_message(
        request.outer_pubkey,
        request.recipient_id,
        key.public(),
        msg,
        &mut buf,
    )
    .map_err(|_| OpenError::Signature)?;
    verify_sealed(&from, &sig, &message).map_err(|e| match e {
        SealedSigError::InvalidSenderKey => OpenError::SenderKey,
        _ => OpenError::Signature,
    })?;

    // (8) `msg`: a payload of a block with 0 parents (which also rejects `sbtp.enc`: its row
    // requires exactly 1 parent, spec §3), of a kind the tag allows.
    let payload = validate_l2_invariants(&[], msg).map_err(OpenError::MsgInvalid)?;
    if !request.allowed_kinds.contains(&payload.kind) {
        return Err(OpenError::MsgKindNotAllowed);
    }

    Ok(Opened {
        msg: Zeroizing::new(msg.to_vec()),
        from,
        key_index,
    })
}

/// The index of the key that opened the block, the key, and the plaintext.
type HpkeOpened<'k> = (usize, &'k RecipientKey, Zeroizing<Vec<u8>>);

/// Step (4): the first key, in order, under which HPKE Open succeeds.
fn hpke_open<'k>(request: &OpenRequest<'k>) -> Result<HpkeOpened<'k>, OpenError> {
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&request.enc.enc)
        .map_err(|_| OpenError::NoKeyOpens)?;
    let aad = aad(request.outer_pubkey, request.tag);
    for (i, key) in request.keys.iter().enumerate() {
        // The library performs the all-zero shared secret check (RFC 9180 §7.1.4, spec §5.1).
        if let Ok(pt) = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            key.secret(),
            &encapped,
            &SEALED_HPKE_INFO,
            request.enc.ct,
            &aad,
        ) {
            return Ok((i, key, Zeroizing::new(pt)));
        }
    }
    Err(OpenError::NoKeyOpens)
}

/// The fields `from`, `msg` and `sig` of the plaintext item.
type Item<'a> = ([u8; 32], &'a [u8], [u8; 64]);

/// Reads the item `{from, msg, sig}` of a buffer that passed the profile check (spec §5.3).
/// Returns `from`, `msg` and `sig`.
fn read_item(item: &[u8]) -> Result<Item<'_>, OpenError> {
    let mut from = None;
    let mut msg = None;
    let mut sig = None;
    let mut r = Reader::new(item);
    body::fields(&mut r, |key, r| {
        match key {
            "from" => from = Some(r.bytes(body::BAD)?),
            "msg" => msg = Some(r.bytes(body::BAD)?),
            "sig" => sig = Some(r.bytes(body::BAD)?),
            _ => return Ok(false),
        }
        Ok::<_, L2Error>(true)
    })
    .map_err(|_| OpenError::ItemShape)?;
    let from: [u8; 32] = from
        .and_then(|f| f.try_into().ok())
        .ok_or(OpenError::ItemShape)?;
    let sig: [u8; 64] = sig
        .and_then(|s| s.try_into().ok())
        .ok_or(OpenError::ItemShape)?;
    let msg = msg.ok_or(OpenError::ItemShape)?;
    Ok((from, msg, sig))
}
