//! Sender side: building the payload of an `sbtp.enc` block (spec §5.1 to §5.3).

use alloc::vec;
use alloc::vec::Vec;

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, OpModeS, Serializable};
use sbtp_core::{
    BlockId, SEALED_HPKE_INFO, SealedSigError, SealedSigMessage, SigningKey, sealed_sig_message,
    sealed_sig_message_len, sign_sealed, verify_sealed,
};
use sbtp_l2::{Body, Edge, Enc, L2Error, Payload, Rel, Target, validate_l2_invariants};
use zeroize::Zeroizing;

use crate::keys::{Aead, Kdf, Kem};
use crate::{Bucket, SealError, Tag};

/// The kind of the outer block (spec §5.2).
const ENC_KIND: &str = "sbtp.enc";

/// What to seal, and to whom (spec §5.3, §5.4).
///
/// Its `Debug` output shows the length of `msg` and the bucket only: never `msg`, the sender or
/// the recipient, which the envelope hides (spec §5.9).
#[derive(Clone, Copy)]
pub struct SealRequest<'a> {
    /// The recipient's X25519 key: the `x25519` of its current `sbtp.enc_key` (spec §5.5), or
    /// the key the application that defines the tag names.
    pub recipient_x25519: &'a [u8; 32],
    /// The `recipient_id` the application that defines the tag fixes (spec §5.3, §5.4).
    pub recipient_id: &'a [u8; 32],
    /// The delivery tag, the single header parent of the outer block (spec §5.2, §5.4).
    pub tag: &'a Tag,
    /// The sender's key `from`, which makes `sig` (spec §5.3).
    pub sender: &'a SigningKey,
    /// `msg`: an encoded grammar payload with no causal edge (spec §5.3).
    pub msg: &'a [u8],
    /// The bucket to use; `None` picks the smallest that fits (spec §5.3, SHOULD).
    pub bucket: Option<Bucket>,
}

impl core::fmt::Debug for SealRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealRequest")
            .field("msg_len", &self.msg.len())
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// A sealed payload, ready to be put in a block.
///
/// Build the outer block with `ephemeral`'s public key as `PubKey`, [`Sealed::tag`] as its only
/// parent and [`Sealed::payload`] as its payload, mine it, sign it with `ephemeral`, then drop
/// `ephemeral` (spec §5.2: the key signs this block only; `SigningKey` wipes itself on drop).
pub struct Sealed {
    /// The outer payload, exactly `bucket.payload_len()` bytes.
    pub payload: Vec<u8>,
    /// The fresh Ed25519 key of the outer block (spec §5.2, ephemeral signer).
    pub ephemeral: SigningKey,
    /// The delivery tag, the outer block's single parent.
    pub tag: Tag,
    /// The bucket used.
    pub bucket: Bucket,
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("payload_len", &self.payload.len())
            .field("ephemeral", &self.ephemeral.verifying_key())
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// What to seal, and to whom, when the sender's identity key signs outside this crate
/// (spec §5.3): [`SealRequest`] with the sender's public key `from` in place of its private key.
///
/// Its `Debug` output shows the length of `msg` and the bucket only (spec §5.9).
#[derive(Clone, Copy)]
pub struct PrepareRequest<'a> {
    /// The recipient's X25519 key (spec §5.5), as in [`SealRequest::recipient_x25519`].
    pub recipient_x25519: &'a [u8; 32],
    /// The `recipient_id` the application that defines the tag fixes (spec §5.3, §5.4).
    pub recipient_id: &'a [u8; 32],
    /// The delivery tag, the single header parent of the outer block (spec §5.2, §5.4).
    pub tag: &'a Tag,
    /// The sender's Ed25519 public key `from`, whose private key makes `sig` (spec §5.3).
    pub from: &'a [u8; 32],
    /// `msg`: an encoded grammar payload with no causal edge (spec §5.3).
    pub msg: &'a [u8],
    /// The bucket to use; `None` picks the smallest that fits (spec §5.3, SHOULD).
    pub bucket: Option<Bucket>,
}

impl core::fmt::Debug for PrepareRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrepareRequest")
            .field("msg_len", &self.msg.len())
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// A seal waiting for its inner signature `sig` (spec §5.3): the output of [`seal_prepare`].
///
/// Sign [`PendingSeal::message`] with the private key of `from` (a pure Ed25519 signature,
/// RFC 8032 §5.1), then pass the signature to [`PendingSeal::finish`]. The value is single use:
/// `finish` consumes it, whatever its result. It is not `Clone`. It holds the ephemeral key of
/// the outer block, the plaintext (already encoded and padded, `sig` left blank) and the message
/// to sign; all are wiped on drop (`ed25519-dalek` `zeroize`, `Zeroizing`). Its `Debug` output shows the length of `msg` and the bucket only.
///
/// Single use is enforced by the type: a second `finish` does not compile.
///
/// ```compile_fail,E0382
/// fn twice(p: sbtp_seal::PendingSeal, rng: &mut impl sbtp_seal::rand_core::CryptoRng) {
///     let _ = p.finish(&[0; 64], rng);
///     let _ = p.finish(&[0; 64], rng);
/// }
/// ```
pub struct PendingSeal {
    /// The fresh Ed25519 key of the outer block (spec §5.2).
    ephemeral: SigningKey,
    /// `ephemeral`'s public key, the outer `PubKey`.
    outer_pubkey: [u8; 32],
    from: [u8; 32],
    recipient_x25519: [u8; 32],
    recipient_id: [u8; 32],
    tag: Tag,
    bucket: Bucket,
    /// The plaintext, exactly `bucket.plaintext_len()` bytes: the item with 64 zero bytes in
    /// place of `sig`, then the `0x00` padding (spec §5.3). Allocated once, never resized
    /// (security review 2026-11-21, L-1).
    plaintext: Zeroizing<Vec<u8>>,
    /// Where `msg` and `sig` sit in `plaintext`.
    layout: ItemLayout,
    /// The sealed signature message, `sealed_sig_message_len(msg.len())` bytes.
    message: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for PendingSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingSeal")
            .field("msg_len", &self.layout.msg_len)
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// `msg`, inside the plaintext. The error is not reachable: `layout` comes from the encoder.
fn msg_in(plaintext: &[u8], layout: ItemLayout) -> Result<&[u8], SealError> {
    let end = layout.msg_start.checked_add(layout.msg_len);
    end.and_then(|end| plaintext.get(layout.msg_start..end))
        .ok_or(SealError::Encoding(L2Error::Malformed))
}

/// The offsets of `msg` and `sig` in an encoded item.
#[derive(Clone, Copy)]
pub(crate) struct ItemLayout {
    pub(crate) msg_start: usize,
    pub(crate) msg_len: usize,
    pub(crate) sig_start: usize,
}

/// A writer over a fixed buffer: never grows, never panics.
struct Cursor<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), SealError> {
        let end = self.pos.checked_add(bytes.len());
        let dst = end
            .and_then(|end| self.buf.get_mut(self.pos..end))
            .ok_or(SealError::TooLong)?;
        dst.copy_from_slice(bytes);
        self.pos = self.pos.saturating_add(bytes.len());
        Ok(())
    }

    /// A byte string head (major type 2) in its shortest form (spec §1.2).
    fn bytes_head(&mut self, len: usize) -> Result<(), SealError> {
        if let Ok(n) = u8::try_from(len) {
            if n < 24 {
                return self.put(&[0x40 | n]);
            }
            return self.put(&[0x58, n]);
        }
        if let Ok(n) = u16::try_from(len) {
            self.put(&[0x59])?;
            return self.put(&n.to_be_bytes());
        }
        let n = u32::try_from(len).map_err(|_| SealError::TooLong)?;
        self.put(&[0x5a])?;
        self.put(&n.to_be_bytes())
    }
}

/// Encodes the item `{from, msg, sig}` into the start of `buf`, with `sig` left as 64 zero bytes,
/// and returns where `msg` and `sig` are (spec §5.3). Deterministic profile (spec §1.2): a
/// definite-length map whose keys are in bytewise order of their encodings (`"msg"` `0x63 6d`,
/// `"sig"` `0x63 73`, `"from"` `0x64`), shortest heads. Checked byte for byte against
/// `sbtp_l2::cbor::encode` by a test. The rest of `buf` is left as it is (the `0x00` padding).
pub(crate) fn encode_item_into(
    buf: &mut [u8],
    from: &[u8; 32],
    msg: &[u8],
) -> Result<ItemLayout, SealError> {
    let mut w = Cursor { buf, pos: 0 };
    w.put(&[0xa3])?;
    w.put(&[0x63, b'm', b's', b'g'])?;
    w.bytes_head(msg.len())?;
    let msg_start = w.pos;
    w.put(msg)?;
    w.put(&[0x63, b's', b'i', b'g'])?;
    w.bytes_head(64)?;
    let sig_start = w.pos;
    w.put(&[0; 64])?;
    w.put(&[0x64, b'f', b'r', b'o', b'm'])?;
    w.bytes_head(32)?;
    w.put(from)?;
    Ok(ItemLayout {
        msg_start,
        msg_len: msg.len(),
        sig_start,
    })
}

/// The length of the item `{from, msg, sig}` in the deterministic profile (spec §5.3, §1.2): the
/// map head, the three keys, the heads of the three byte strings, 32 + 64 bytes of `from` and
/// `sig`, and `msg`. `None` on overflow. Checked against `cbor::encode` by a test.
pub(crate) fn item_len(msg_len: usize) -> Option<usize> {
    // `0xa3`; `"from"` (5), `"msg"` (4), `"sig"` (4); `0x58 0x20`, `0x58 0x40`; 32 + 64.
    const FIXED: usize = 1 + 5 + 4 + 4 + 2 + 2 + 32 + 64;
    let head = match msg_len {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    };
    FIXED.checked_add(head)?.checked_add(msg_len)
}

/// First phase of a seal whose `sig` is made outside this crate (spec §5.3), for a sender whose
/// identity key cannot leave its key store.
///
/// Steps: `msg` is validated as a payload of a block with 0 parents (spec §5.3); the bucket is
/// chosen from the item length (spec §5.2, §5.3); a fresh ephemeral Ed25519 key is drawn from
/// `rng` (spec §5.2); the typed sealed signature message is built by `sbtp-core` (spec §5.3).
/// The returned [`PendingSeal`] carries that message for the signer.
///
/// `rng` MUST be the operating system's secure source; a seeded generator is for tests only
/// (spec §5.1).
///
/// `from` is not checked here: [`PendingSeal::finish`] verifies `sig` by `from` with criteria V1
/// to V6 of core spec §3.2, so a `from` that fails V1 or V2 is refused there.
///
/// # Errors
///
/// [`SealError::MsgInvalid`], [`SealError::TooLong`], [`SealError::EphemeralIsSender`],
/// [`SealError::Signing`] (not reachable: the message buffer is sized by `sbtp-core`).
pub fn seal_prepare(
    request: &PrepareRequest<'_>,
    rng: &mut impl CryptoRng,
) -> Result<PendingSeal, SealError> {
    // spec §5.3: `msg` is a grammar payload of a block with 0 parents. This also rejects a
    // `msg` of kind `sbtp.enc`, whose row requires exactly 1 parent (spec §3).
    validate_l2_invariants(&[], request.msg).map_err(SealError::MsgInvalid)?;

    // spec §5.2, §5.3: the item must fit the bucket; the smallest that fits by default. `sig`
    // has a fixed length, so the item length is known before signing.
    let item_len = item_len(request.msg.len()).ok_or(SealError::TooLong)?;
    // An item over 65,535 bytes fits no bucket: the check below refuses it.
    let bucket = match request.bucket {
        Some(b) if b.plaintext_len() >= item_len => b,
        Some(_) => return Err(SealError::TooLong),
        None => Bucket::smallest_for(item_len).ok_or(SealError::TooLong)?,
    };

    // spec §5.2: a fresh Ed25519 key, never the sender's.
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(seed.as_mut());
    let ephemeral = SigningKey::from_bytes(&seed);
    let outer_pubkey = ephemeral.verifying_key().to_bytes();
    if &outer_pubkey == request.from {
        return Err(SealError::EphemeralIsSender);
    }

    // spec §5.3: one deterministic CBOR item, then `0x00` up to the bucket's plaintext length.
    // One allocation of the final length; the item is written into it, nothing is resized, so
    // no freed buffer ever holds `msg` (security review 2026-11-21, L-1).
    let mut plaintext = Zeroizing::new(vec![0u8; bucket.plaintext_len()]);
    let layout = encode_item_into(&mut plaintext, request.from, request.msg)?;

    // spec §5.3: the typed sealed message, bound to the outer key, `recipient_id`, the X25519
    // key and `msg`. Allocated once at its final length.
    let sig_len = sealed_sig_message_len(request.msg.len()).ok_or(SealError::Signing)?;
    let mut message = Zeroizing::new(vec![0u8; sig_len]);
    sealed_sig_message(
        &outer_pubkey,
        request.recipient_id,
        request.recipient_x25519,
        request.msg,
        &mut message,
    )
    .map_err(|_| SealError::Signing)?;
    Ok(PendingSeal {
        ephemeral,
        outer_pubkey,
        from: *request.from,
        recipient_x25519: *request.recipient_x25519,
        recipient_id: *request.recipient_id,
        tag: *request.tag,
        bucket,
        plaintext,
        layout,
        message,
    })
}

/// The typed sealed message of `pending`, rebuilt in place from its fields (spec §5.3): the
/// bytes are those of [`PendingSeal::message`].
fn typed_message<'b>(
    outer_pubkey: &[u8; 32],
    recipient_id: &[u8; 32],
    recipient_x25519: &[u8; 32],
    msg: &[u8],
    buf: &'b mut [u8],
) -> Result<SealedSigMessage<'b>, SealError> {
    sealed_sig_message(outer_pubkey, recipient_id, recipient_x25519, msg, buf)
        .map_err(|_| SealError::Signing)
}

impl PendingSeal {
    /// The exact message `sig` signs (spec §5.3):
    /// `SBTP-v1-sealed-sig ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519 ‖ msg`, built by the
    /// typed builder of `sbtp-core`. Sign it with the private key of `from`, nothing else.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The sender key `from` the signature must verify under.
    #[must_use]
    pub const fn from(&self) -> &[u8; 32] {
        &self.from
    }

    /// The bucket chosen.
    #[must_use]
    pub const fn bucket(&self) -> Bucket {
        self.bucket
    }

    /// Signs the message with `sender` (the convenience path of [`seal`]).
    fn sign_with(&mut self, sender: &SigningKey) -> Result<[u8; 64], SealError> {
        let message = typed_message(
            &self.outer_pubkey,
            &self.recipient_id,
            &self.recipient_x25519,
            msg_in(&self.plaintext, self.layout)?,
            &mut self.message,
        )?;
        sign_sealed(sender, &message).map_err(|_| SealError::Signing)
    }

    /// Second phase: checks `sig`, then seals (spec §5.3, §5.1, §5.2).
    ///
    /// Steps: `sig` is verified by `from` over the sealed message with criteria V1 to V6 of core
    /// spec §3.2, as the recipient will (spec §5.3 step 7): nothing is sealed with a bad
    /// signature; `sig` is written into the item `{from, msg, sig}` that [`seal_prepare`]
    /// encoded in the deterministic profile and padded with `0x00` to the bucket's plaintext
    /// length (spec §5.3); HPKE base mode seals the plaintext with
    /// `info` and `aad = PubKey ‖ tag` (spec §5.1); the outer payload is encoded and validated
    /// (spec §5.2).
    ///
    /// `rng` provides the HPKE ephemeral key; it MUST be the operating system's secure source
    /// (spec §5.1). The pending state is consumed on success and on error: after an error, start
    /// again with [`seal_prepare`] (a new ephemeral key).
    ///
    /// # Errors
    ///
    /// [`SealError::SenderKey`], [`SealError::Signature`], [`SealError::Hpke`];
    /// [`SealError::Encoding`] and [`SealError::Signing`] are not reachable.
    pub fn finish(mut self, sig: &[u8; 64], rng: &mut impl CryptoRng) -> Result<Sealed, SealError> {
        // spec §5.3 (step 7 on the recipient side): strict V1 to V6, before any sealing.
        let message = typed_message(
            &self.outer_pubkey,
            &self.recipient_id,
            &self.recipient_x25519,
            msg_in(&self.plaintext, self.layout)?,
            &mut self.message,
        )?;
        verify_sealed(&self.from, sig, &message).map_err(|e| match e {
            SealedSigError::InvalidSenderKey => SealError::SenderKey,
            SealedSigError::InvalidSignature => SealError::Signature,
            _ => SealError::Signing,
        })?;

        // spec §5.3: `sig` goes into its place in the already padded plaintext.
        let end = self.layout.sig_start.checked_add(sig.len());
        end.and_then(|end| self.plaintext.get_mut(self.layout.sig_start..end))
            .ok_or(SealError::Encoding(L2Error::Malformed))?
            .copy_from_slice(sig);

        let payload = hpke_seal(&self, &self.plaintext, rng)?;
        Ok(Sealed {
            payload,
            ephemeral: self.ephemeral,
            tag: self.tag,
            bucket: self.bucket,
        })
    }
}

/// HPKE seal of the padded `plaintext`, then the outer payload (spec §5.1, §5.2).
fn hpke_seal(
    pending: &PendingSeal,
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, SealError> {
    // spec §5.1: base mode, the fixed suite, `info`, `aad = PubKey ‖ tag`. The library rejects
    // an all-zero shared secret (RFC 9180 §7.1.4).
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&pending.recipient_x25519)
        .map_err(|_| SealError::Hpke)?;
    let aad = aad(&pending.outer_pubkey, &pending.tag);
    let (encapped, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &SEALED_HPKE_INFO,
        plaintext,
        &aad,
        rng,
    )
    .map_err(|_| SealError::Hpke)?;

    // spec §5.2: the outer payload, validated against its single parent by the encoder.
    let outer = Payload {
        kind: ENC_KIND,
        edges: vec![Edge {
            target: Target::Parent(0),
            rel: Rel::Tagged,
        }],
        body: Body::Enc(Enc {
            ct: &ct,
            enc: encapped.to_bytes().into(),
        }),
    };
    let payload = outer
        .encode(&[BlockId(pending.tag)])
        .map_err(SealError::Encoding)?;
    // spec §5.2: payload = 90 bytes + ciphertext, at the bucket length (defence in depth).
    if payload.len() != pending.bucket.payload_len() {
        return Err(SealError::Encoding(L2Error::EncCiphertextLen));
    }
    Ok(payload)
}

/// Seals `request.msg` to `request.recipient_x25519` under `request.tag`, signing `sig` with
/// `request.sender`.
///
/// The convenience form of [`seal_prepare`] then [`PendingSeal::finish`], with `sig` made by
/// `request.sender` over [`PendingSeal::message`]; same steps, same checks, and the same output
/// for the same `rng` stream.
///
/// `rng` MUST be the operating system's secure source; a seeded generator is for tests only
/// (spec §5.1). It provides the ephemeral Ed25519 key and the HPKE ephemeral key.
///
/// # Errors
///
/// A [`SealError`]; nothing is to be sent.
pub fn seal(request: &SealRequest<'_>, rng: &mut impl CryptoRng) -> Result<Sealed, SealError> {
    let from = request.sender.verifying_key().to_bytes();
    let mut pending = seal_prepare(
        &PrepareRequest {
            recipient_x25519: request.recipient_x25519,
            recipient_id: request.recipient_id,
            tag: request.tag,
            from: &from,
            msg: request.msg,
            bucket: request.bucket,
        },
        rng,
    )?;
    let sig = pending.sign_with(request.sender)?;
    pending.finish(&sig, rng)
}

/// `aad`: the 64 bytes `PubKey ‖ tag` of the outer block (spec §5.1).
pub(crate) fn aad(outer_pubkey: &[u8; 32], tag: &Tag) -> [u8; 64] {
    let mut out = [0u8; 64];
    let (a, b) = out.split_at_mut(32);
    a.copy_from_slice(outer_pubkey);
    b.copy_from_slice(tag);
    out
}
