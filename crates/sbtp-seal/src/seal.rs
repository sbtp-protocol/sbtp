//! Sender side: building the payload of an `sbtp.enc` block (spec §5.1 to §5.3).

use alloc::vec;
use alloc::vec::Vec;

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, OpModeS, Serializable};
use sbtp_core::{
    BlockId, SEALED_HPKE_INFO, SigningKey, sealed_sig_message, sealed_sig_message_len, sign_sealed,
};
use sbtp_l2::cbor::{self, Value};
use sbtp_l2::{Body, Edge, Enc, L2Error, Payload, Rel, Target, validate_l2_invariants};
use zeroize::Zeroizing;

use crate::keys::{Aead, Kdf, Kem};
use crate::{Bucket, SealError, Tag};

/// The kind of the outer block (spec §5.2).
const ENC_KIND: &str = "sbtp.enc";

/// What to seal, and to whom (spec §5.3, §5.4).
#[derive(Clone, Copy, Debug)]
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

/// Seals `request.msg` to `request.recipient_x25519` under `request.tag`.
///
/// Steps: `msg` is validated as a payload of a block with 0 parents (spec §5.3); a fresh
/// ephemeral Ed25519 key is drawn from `rng` (spec §5.2); `sig` is signed over the typed sealed
/// message of `sbtp-core` (spec §5.3); the item `{from, msg, sig}` is
/// encoded in the deterministic profile and padded with `0x00` to the bucket's plaintext length
/// (spec §5.3); HPKE base mode seals it with `info` and `aad = PubKey ‖ tag` (spec §5.1); the
/// outer payload is encoded and validated (spec §5.2).
///
/// `rng` MUST be the operating system's secure source; a seeded generator is for tests only
/// (spec §5.1). It provides the ephemeral Ed25519 key and the HPKE ephemeral key.
///
/// # Errors
///
/// A [`SealError`]; nothing is to be sent.
pub fn seal(request: &SealRequest<'_>, rng: &mut impl CryptoRng) -> Result<Sealed, SealError> {
    // spec §5.3: `msg` is a grammar payload of a block with 0 parents. This also rejects a
    // `msg` of kind `sbtp.enc`, whose row requires exactly 1 parent (spec §3).
    validate_l2_invariants(&[], request.msg).map_err(SealError::MsgInvalid)?;

    // spec §5.2: a fresh Ed25519 key, never the sender's.
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(seed.as_mut());
    let ephemeral = SigningKey::from_bytes(&seed);
    let outer_pubkey = ephemeral.verifying_key().to_bytes();
    let from = request.sender.verifying_key().to_bytes();
    if outer_pubkey == from {
        return Err(SealError::EphemeralIsSender);
    }

    // spec §5.3: `sig` over the typed sealed message.
    let sig_len = sealed_sig_message_len(request.msg.len()).ok_or(SealError::Signing)?;
    let mut sig_buf = Zeroizing::new(vec![0u8; sig_len]);
    let message = sealed_sig_message(
        &outer_pubkey,
        request.recipient_id,
        request.recipient_x25519,
        request.msg,
        &mut sig_buf,
    )
    .map_err(|_| SealError::Signing)?;
    let sig = sign_sealed(request.sender, &message).map_err(|_| SealError::Signing)?;

    // spec §5.3: one deterministic CBOR item, then `0x00` up to the bucket's plaintext length.
    let item = Value::Map(vec![
        ("from", Value::Bytes(&from)),
        ("msg", Value::Bytes(request.msg)),
        ("sig", Value::Bytes(&sig)),
    ]);
    // An item over 65,535 bytes is refused by the encoder: it fits no bucket either.
    let mut plaintext = Zeroizing::new(cbor::encode(&item).map_err(|e| match e {
        L2Error::PayloadTooLong => SealError::TooLong,
        e => SealError::Encoding(e),
    })?);
    let item_len = plaintext.len();
    let bucket = match request.bucket {
        Some(b) if b.plaintext_len() >= item_len => b,
        Some(_) => return Err(SealError::TooLong),
        None => Bucket::smallest_for(item_len).ok_or(SealError::TooLong)?,
    };
    plaintext.resize(bucket.plaintext_len(), 0x00);

    // spec §5.1: base mode, the fixed suite, `info`, `aad = PubKey ‖ tag`. The library rejects
    // an all-zero shared secret (RFC 9180 §7.1.4).
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(request.recipient_x25519)
        .map_err(|_| SealError::Hpke)?;
    let aad = aad(&outer_pubkey, request.tag);
    let (encapped, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &SEALED_HPKE_INFO,
        &plaintext,
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
        .encode(&[BlockId(*request.tag)])
        .map_err(SealError::Encoding)?;
    // spec §5.2: payload = 90 bytes + ciphertext, at the bucket length (defence in depth).
    if payload.len() != bucket.payload_len() {
        return Err(SealError::Encoding(L2Error::EncCiphertextLen));
    }
    Ok(Sealed {
        payload,
        ephemeral,
        tag: *request.tag,
        bucket,
    })
}

/// `aad`: the 64 bytes `PubKey ‖ tag` of the outer block (spec §5.1).
pub(crate) fn aad(outer_pubkey: &[u8; 32], tag: &Tag) -> [u8; 64] {
    let mut out = [0u8; 64];
    let (a, b) = out.split_at_mut(32);
    a.copy_from_slice(outer_pubkey);
    b.copy_from_slice(tag);
    out
}
