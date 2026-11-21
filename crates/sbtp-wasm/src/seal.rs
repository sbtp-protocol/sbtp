//! The sealed envelope (`sbtp-seal`, `docs/spec/l2-grammar.md` §5), feature `seal`. Every rule
//! (HPKE, buckets, padding, inner signature, order of checks, tags) runs in `sbtp-seal`; this module
//! moves bytes, holds the secrets in WASM memory and turns errors into JS errors.
//!
//! # Secrets
//!
//! - X25519 private keys live in [`EncKeyPair`], the ephemeral Ed25519 key of an outer block in
//!   [`SealedEnvelope`], an opened `msg` in [`OpenedMessage`]. All three are wiped when the object
//!   is freed (`x25519-dalek` and `ed25519-dalek` wipe on drop, `msg` is `Zeroizing`); call
//!   `free()` as soon as possible, garbage collection is neither prompt nor guaranteed.
//! - The ephemeral key never leaves WASM: [`SealedEnvelope::sign_block_js`] signs the outer block
//!   once and wipes it at once (spec §5.2: it signs that block only).
//! - What cannot be wiped from here, once it is in JS: the caller's `msg` argument, every copy a
//!   getter returns (`OpenedMessage.msg`, `.from`, `.kind`), and the bytes of
//!   `EncKeyPair.exportSecret()`. The caller overwrites the typed arrays (`fill(0)`) once done; JS
//!   strings cannot be wiped at all. Moves of the key values into the objects wasm-bindgen
//!   allocates, and the internal temporaries of the HPKE and Ed25519 code, may leave transient
//!   copies on the WASM stack (best effort, as for `DemoSigningKey`).
//! - No secret, no `from` and no `msg` appears in a `Debug` output or an error message.
//!
//! # Randomness (security review 2026-11-21, L-3)
//!
//! The only random source is the platform's, through `getrandom` (Web Crypto
//! `crypto.getRandomValues` on wasm32-unknown-unknown, the OS natively); no caller can pass a
//! generator. `getrandom` is fallible but `sbtp-seal` takes an infallible `CryptoRng`, so [`OsRng`]
//! records a failure instead of panicking, and the result computed after a failure is discarded:
//! the caller gets `EntropyUnavailable`, never a key or a ciphertext made from missing entropy.
//!
//! # Opaque open failures (review I-4)
//!
//! Every reason a sealed block does not open (outer payload not an `sbtp.enc`, any `OpenError` of
//! steps 4 to 8 of spec §5.3) becomes the same `OpenFailed` error with the same message. Only
//! argument shapes (not a `Uint8Array`, a 32-byte field of another length, a kind that is not a
//! string) are reported separately: they depend on the caller's code, not on the block.

use core::convert::Infallible;
use core::fmt;

use js_sys::Uint8Array;
use sbtp_core::layout::{HASH_LEN, MAX_BLOCK_LEN};
use sbtp_core::{BlockId, SigningKey, parse, sign_block};
use sbtp_l2::{Body, validate_l2_invariants};
use sbtp_seal::rand_core::{TryCryptoRng, TryRng};
use sbtp_seal::{
    Bucket, OpenRequest, RecipientKey, SealError, SealRequest, TagError, application_tag,
    directory_tag, is_directory_tag,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::api::build_unsigned;
use crate::error::{BindError, names};
use crate::{DemoSigningKey, bytes_in, exact_into, integer_in, u64_in};

/// Largest `applicationTag` input copied into WASM memory. Only bounds the copy: tag inputs are
/// identifiers, a few hundred bytes at most.
const MAX_TAG_INPUT: usize = 1 << 20;

/// The platform random source as an infallible `CryptoRng` that records failures (see the module
/// documentation). After a failure it fills with zeros; the caller MUST check
/// [`OsRng::failed`] and discard whatever was computed.
struct OsRng {
    failed: bool,
    fill: fn(&mut [u8]) -> Result<(), getrandom::Error>,
}

impl OsRng {
    const fn new() -> Self {
        Self {
            failed: false,
            fill: getrandom::fill,
        }
    }

    fn fill_or_flag(&mut self, dst: &mut [u8]) {
        if (self.fill)(dst).is_err() {
            dst.fill(0);
            self.failed = true;
        }
    }

    /// `Ok(value)` if every draw succeeded; otherwise `value` is dropped (and wiped, for the
    /// secret types) and the caller gets `EntropyUnavailable`.
    fn check<T>(&self, value: T) -> Result<T, BindError> {
        if self.failed {
            drop(value);
            return Err(BindError::new(
                names::ENTROPY_UNAVAILABLE,
                "random source failed",
            ));
        }
        Ok(value)
    }
}

impl TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.fill_or_flag(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.fill_or_flag(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill_or_flag(dst);
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

impl From<SealError> for BindError {
    /// The sender's own errors: detailed, the sender may see why its seal failed.
    fn from(error: SealError) -> Self {
        let name = match error {
            SealError::MsgInvalid(inner) => return inner.into(),
            SealError::TooLong => names::SEAL_TOO_LONG,
            SealError::Hpke => names::INVALID_RECIPIENT_KEY,
            // Probability 2^-252 (`EphemeralIsSender`), or documented as unreachable.
            SealError::EphemeralIsSender | SealError::Signing | SealError::Encoding(_) => {
                names::INTERNAL
            }
        };
        Self::new(name, error.to_string())
    }
}

impl From<TagError> for BindError {
    fn from(error: TagError) -> Self {
        Self::new(names::RESERVED_CONTEXT, error.to_string())
    }
}

/// The one error of a failed open (review I-4). Built from nothing, so it cannot carry anything
/// about the block.
fn open_failed() -> BindError {
    BindError::new(names::OPEN_FAILED, "the sealed block does not open")
}

/// An X25519 recipient key pair (spec §5.5): the private key opens sealed blocks, the public key
/// goes in the `x25519` field of an `sbtp.enc_key` body. Generated independently of the identity
/// key; the private key is wiped when the object is freed.
#[wasm_bindgen]
pub struct EncKeyPair {
    inner: RecipientKey,
}

impl fmt::Debug for EncKeyPair {
    /// Shows the public key only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncKeyPair")
            .field("public_key", self.inner.public())
            .finish_non_exhaustive()
    }
}

impl EncKeyPair {
    /// A fresh key pair from the platform random source.
    ///
    /// # Errors
    ///
    /// `EntropyUnavailable`.
    pub fn generate() -> Result<Self, BindError> {
        Self::generate_with(OsRng::new())
    }

    fn generate_with(mut rng: OsRng) -> Result<Self, BindError> {
        let inner = RecipientKey::generate(&mut rng);
        rng.check(Self { inner })
    }

    /// The key pair of stored private key bytes (clamped by the HPKE library).
    ///
    /// # Errors
    ///
    /// `Internal` if the library refuses the bytes (not expected for X25519).
    pub fn from_secret(bytes: &[u8; 32]) -> Result<Self, BindError> {
        RecipientKey::from_secret_bytes(bytes)
            .map(|inner| Self { inner })
            .ok_or_else(|| BindError::new(names::INTERNAL, "X25519 key refused"))
    }

    /// The 32-byte X25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.inner.public()
    }

    /// The key pair as `sbtp-seal` takes it.
    #[must_use]
    pub const fn recipient_key(&self) -> &RecipientKey {
        &self.inner
    }
}

#[wasm_bindgen]
impl EncKeyPair {
    /// A fresh X25519 key pair from Web Crypto `getRandomValues`. Call `free()` when done.
    ///
    /// # Errors
    ///
    /// `EntropyUnavailable`.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_js() -> Result<EncKeyPair, JsValue> {
        Ok(Self::generate()?)
    }

    /// The key pair of a stored 32-byte private key. Overwrite `secret` (`fill(0)`) afterwards:
    /// this function cannot wipe the caller's copy.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`, `InvalidLength`.
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret_js(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] secret: &JsValue,
    ) -> Result<EncKeyPair, JsValue> {
        let mut buffer = Zeroizing::new([0u8; 32]);
        exact_into("secret", secret, buffer.as_mut_slice())?;
        Ok(Self::from_secret(&buffer)?)
    }

    /// The 32-byte X25519 public key, for an `sbtp.enc_key` body.
    #[wasm_bindgen(getter, js_name = publicKey)]
    #[must_use]
    pub fn public_key_js(&self) -> Vec<u8> {
        self.public_key_bytes().to_vec()
    }

    /// A copy of the 32-byte private key, for the caller to store **encrypted**. Never log it,
    /// never put it in `localStorage` or a URL; overwrite it (`fill(0)`) once stored.
    #[wasm_bindgen(js_name = exportSecret)]
    #[must_use]
    pub fn export_secret_js(&self) -> Uint8Array {
        // The `Zeroizing` copy is wiped when this function returns.
        Uint8Array::from(self.inner.secret_bytes().as_slice())
    }
}

/// A sealed payload and the ephemeral key of its outer block (spec §5.2).
///
/// Build the outer block (`unsignedBlock`), mine it, sign it with `signBlock`, then publish it.
/// The ephemeral key stays in WASM memory and is wiped after its one signature, or on `free()`.
#[wasm_bindgen]
pub struct SealedEnvelope {
    payload: Vec<u8>,
    tag: [u8; 32],
    bucket: Bucket,
    public_key: [u8; 32],
    ephemeral: Option<SigningKey>,
}

impl fmt::Debug for SealedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedEnvelope")
            .field("payload_len", &self.payload.len())
            .field("public_key", &self.public_key)
            .field("signed", &self.ephemeral.is_none())
            .finish_non_exhaustive()
    }
}

impl SealedEnvelope {
    /// The outer payload, exactly one bucket long.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// The ephemeral public key, the outer block's `PubKey`.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The unsigned outer block: `PubKey` the ephemeral key, the tag as single parent, the sealed
    /// payload, nonce 0.
    ///
    /// # Errors
    ///
    /// Not expected (the payload is at most 65,535 bytes).
    pub fn unsigned_block(&self, timestamp: u64) -> Result<Vec<u8>, BindError> {
        build_unsigned(&self.public_key, timestamp, 0, &self.tag, &self.payload)
    }

    /// Signs `block`, which MUST be this envelope's outer block, with the ephemeral key, then wipes
    /// the key (spec §5.2: it signs this block only).
    ///
    /// # Errors
    ///
    /// The F1 to F9 rule that failed; `NotOuterBlock` if `block` does not carry the tag as its only
    /// parent and this payload; `KeyMismatch`; `EphemeralKeyUsed` after a first success. The key is
    /// kept on every error but the last.
    pub fn sign(&mut self, mut block: Vec<u8>) -> Result<Vec<u8>, BindError> {
        let Some(key) = self.ephemeral.as_ref() else {
            return Err(BindError::new(
                names::EPHEMERAL_KEY_USED,
                "the ephemeral key already signed its outer block",
            ));
        };
        let parsed = parse(&block)?;
        if parsed.parents() != [BlockId(self.tag)].as_slice() || parsed.payload() != self.payload {
            return Err(BindError::new(
                names::NOT_OUTER_BLOCK,
                "not the outer block of this envelope (tag parent or payload differ)",
            ));
        }
        sign_block(&mut block, key)?;
        // Dropping the `SigningKey` wipes it (`ed25519-dalek` `zeroize` feature).
        self.ephemeral = None;
        Ok(block)
    }
}

#[wasm_bindgen]
impl SealedEnvelope {
    /// The outer payload (`512`, `2048`, `8192` or `65535` bytes).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// The delivery tag, the outer block's single parent.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tag(&self) -> Vec<u8> {
        self.tag.to_vec()
    }

    /// The bucket used: the outer payload length.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bucket(&self) -> usize {
        self.bucket.payload_len()
    }

    /// The 32-byte ephemeral public key, the outer block's `PubKey`.
    #[wasm_bindgen(getter, js_name = publicKey)]
    #[must_use]
    pub fn public_key_js(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    /// Whether `signBlock` already succeeded (the ephemeral key is gone).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signed(&self) -> bool {
        self.ephemeral.is_none()
    }

    /// The unsigned outer block (nonce 0) at `timestamp` (a `bigint`, Unix milliseconds). Mine it
    /// (`mineSlice`, in a Web Worker), then `signBlock`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`.
    #[wasm_bindgen(js_name = unsignedBlock)]
    pub fn unsigned_block_js(
        &self,
        #[wasm_bindgen(unchecked_param_type = "bigint")] timestamp: &JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let timestamp = u64_in("timestamp", timestamp)?;
        Ok(self.unsigned_block(timestamp)?)
    }

    /// Signs the mined outer block with the ephemeral key and wipes the key: succeeds once.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`, the F1 to F9 rule that failed, `NotOuterBlock`, `KeyMismatch`,
    /// `EphemeralKeyUsed`.
    #[wasm_bindgen(js_name = signBlock)]
    pub fn sign_block_js(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] block: &JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.sign(crate::block_in(block)?)?)
    }
}

/// An opened sealed message (spec §5.3 steps 4 to 8 passed). Steps 9 (the application's tag
/// check) and 10 (the checks of the kind) are the caller's. `msg` is wiped on `free()`.
#[wasm_bindgen]
pub struct OpenedMessage {
    msg: Zeroizing<Vec<u8>>,
    kind: Zeroizing<String>,
    from: [u8; 32],
}

impl fmt::Debug for OpenedMessage {
    /// Never `from` or `msg` (spec §5.9: the sender is hidden).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedMessage")
            .field("msg_len", &self.msg.len())
            .finish_non_exhaustive()
    }
}

impl OpenedMessage {
    /// The `msg` bytes.
    #[must_use]
    pub fn msg_bytes(&self) -> &[u8] {
        &self.msg
    }

    /// The sender key `from`, checked by the inner signature.
    #[must_use]
    pub const fn from_bytes(&self) -> &[u8; 32] {
        &self.from
    }

    /// The kind of `msg`.
    #[must_use]
    pub fn kind_str(&self) -> &str {
        &self.kind
    }
}

#[wasm_bindgen]
impl OpenedMessage {
    /// A copy of `msg`, a grammar payload. Overwrite it (`fill(0)`) once done.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn msg(&self) -> Vec<u8> {
        self.msg.to_vec()
    }

    /// The 32-byte sender identity key `from`, authenticated by the inner signature.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn from(&self) -> Vec<u8> {
        self.from.to_vec()
    }

    /// The kind of `msg`, one of the allowed kinds.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_string()
    }
}

/// Seals `msg` (spec §5.3). `bucket`: `None` picks the smallest that fits.
///
/// # Errors
///
/// `InvalidPayload` (`msg` is not a grammar payload with no causal edge), `SealTooLong`,
/// `InvalidRecipientKey`, `EntropyUnavailable`, `Internal`.
pub fn seal_message(
    sender: &SigningKey,
    recipient_x25519: &[u8; 32],
    recipient_id: &[u8; 32],
    tag: &[u8; 32],
    msg: &[u8],
    bucket: Option<Bucket>,
) -> Result<SealedEnvelope, BindError> {
    seal_with(
        OsRng::new(),
        &SealRequest {
            recipient_x25519,
            recipient_id,
            tag,
            sender,
            msg,
            bucket,
        },
    )
}

fn seal_with(mut rng: OsRng, request: &SealRequest<'_>) -> Result<SealedEnvelope, BindError> {
    let result = sbtp_seal::seal(request, &mut rng);
    // On an entropy failure the result (if any) is dropped, ephemeral key included.
    let sealed = rng.check(result)??;
    let public_key = sealed.ephemeral.verifying_key().to_bytes();
    Ok(SealedEnvelope {
        payload: sealed.payload,
        tag: sealed.tag,
        bucket: sealed.bucket,
        public_key,
        ephemeral: Some(sealed.ephemeral),
    })
}

/// Opens a sealed block with `key` (spec §5.3 steps 2 and 4 to 8), from the outer block's
/// `PubKey`, single parent `tag` and `payload`.
///
/// # Errors
///
/// `OpenFailed`, whatever the reason (review I-4).
pub fn open_sealed(
    key: &RecipientKey,
    outer_public_key: &[u8; 32],
    tag: &[u8; 32],
    payload: &[u8],
    recipient_id: &[u8; 32],
    allowed_kinds: &[&str],
) -> Result<OpenedMessage, BindError> {
    open_inner(
        key,
        outer_public_key,
        tag,
        payload,
        recipient_id,
        allowed_kinds,
    )
    .ok_or_else(open_failed)
}

/// `None` on any failure: the reason is dropped here, before it can reach an error value.
fn open_inner(
    key: &RecipientKey,
    outer_pubkey: &[u8; 32],
    tag: &[u8; 32],
    payload: &[u8],
    recipient_id: &[u8; 32],
    allowed_kinds: &[&str],
) -> Option<OpenedMessage> {
    // Step 2: grammar validation of the outer payload against its single parent, the tag.
    let parents = [BlockId(*tag)];
    let outer = validate_l2_invariants(&parents, payload).ok()?;
    let Body::Enc(enc) = &outer.body else {
        return None;
    };
    // Steps 4 to 8.
    let opened = sbtp_seal::open(&OpenRequest {
        outer_pubkey,
        tag,
        enc,
        recipient_id,
        keys: core::slice::from_ref(key),
        allowed_kinds,
    })
    .ok()?;
    let kind = Zeroizing::new(String::from(opened.payload().ok()?.kind));
    Some(OpenedMessage {
        msg: Zeroizing::new(opened.msg().to_vec()),
        kind,
        from: *opened.from(),
    })
}

/// A bucket argument: `undefined` or `null` for the smallest that fits, otherwise a Payload Len.
fn bucket_in(value: &JsValue) -> Result<Option<Bucket>, BindError> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    integer_in(value, 0.0, 65_535.0)
        // Integral and within 0..=65,535: the conversion is exact.
        .map(
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            |n| n as usize,
        )
        .and_then(|len| Bucket::ALL.into_iter().find(|b| b.payload_len() == len))
        .map(Some)
        .ok_or_else(|| BindError::argument("bucket", "undefined, 512, 2048, 8192 or 65535"))
}

/// The separators of the `allowedKinds` string. A kind is made of `[a-z][a-z0-9_]*` labels joined
/// by `.` (spec §1.3), so neither a space nor a comma can occur inside one.
const KIND_SEPARATORS: [char; 2] = [' ', ','];

/// The `allowedKinds` argument: one string, not an array. Reading an array runs JS (index getters,
/// `length`): inside WASM frames, while the key is borrowed, a throw would leave the key borrowed
/// for ever (no wipe on `free()`); in the wasm-bindgen glue, before the call, an array-like with a
/// huge `length` overflows the allocation size and overwrites the instance's memory. A string
/// needs a single `typeof` check.
fn kinds_in(value: &JsValue) -> Result<String, BindError> {
    value.as_string().ok_or_else(|| {
        BindError::argument(
            "allowedKinds",
            "a string of kinds separated by spaces or commas",
        )
    })
}

/// Seals `msg` for one recipient (`l2-grammar.md` §5.3).
///
/// - `sender`: the identity that signs the inner `sig` (a `DemoSigningKey`: the identity seed must be
///   in WASM memory for now).
/// - `recipientX25519`: the recipient's X25519 key (`x25519` of its current `sbtp.enc_key`).
/// - `recipientId`: the 32-byte `recipient_id` the application that defines the tag fixes.
/// - `tag`: the 32-byte delivery tag (`directoryTag`, `applicationTag`).
/// - `msg`: an encoded grammar payload with no causal edge.
/// - `bucket`: optional Payload Len (`512`, `2048`, `8192`, `65535`); omitted, the smallest that fits.
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`, `InvalidPayload`, `SealTooLong`, `InvalidRecipientKey`,
/// `EntropyUnavailable`, `Internal`.
#[wasm_bindgen(js_name = seal)]
pub fn seal_js(
    sender: &DemoSigningKey,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] recipient_x25519: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] recipient_id: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] tag: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] msg: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "number | undefined")] bucket: &JsValue,
) -> Result<SealedEnvelope, JsValue> {
    let mut x25519 = [0u8; 32];
    exact_into("recipient X25519 key", recipient_x25519, &mut x25519)?;
    let mut id = [0u8; 32];
    exact_into("recipient id", recipient_id, &mut id)?;
    let mut tag_bytes = [0u8; HASH_LEN];
    exact_into("tag", tag, &mut tag_bytes)?;
    let bucket = bucket_in(bucket)?;
    // One allocation of the checked length, wiped on drop.
    let msg = Zeroizing::new(bytes_in("msg", msg, MAX_BLOCK_LEN, |_| {
        SealError::TooLong.into()
    })?);
    Ok(seal_message(
        sender.signing_key(),
        &x25519,
        &id,
        &tag_bytes,
        &msg,
        bucket,
    )?)
}

/// Opens a sealed block with `key` (`l2-grammar.md` §5.3 steps 2 and 4 to 8): `outerPublicKey`,
/// `tag` (its single parent) and `payload` come from the outer block, already validated
/// (`validateRequested`); `recipientId` is the recipient's **own** id for the tag; `allowedKinds`
/// the `msg` kinds the tag allows, as one string separated by spaces or commas
/// (`"app.note app.reply"`; a kind never contains either). With several keys (rotation), call it for each, newest first,
/// and keep the first success.
///
/// # Errors
///
/// `InvalidArgument` or `InvalidLength` for an argument of the wrong shape; otherwise `OpenFailed`,
/// always with the same message, whichever check failed. Ignore such a block silently and tell no
/// one (spec §5.3).
#[wasm_bindgen(js_name = openSealed)]
pub fn open_sealed_js(
    key: &EncKeyPair,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] outer_public_key: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] tag: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] payload: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] recipient_id: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] allowed_kinds: &JsValue,
) -> Result<OpenedMessage, JsValue> {
    let mut outer = [0u8; 32];
    exact_into("outer public key", outer_public_key, &mut outer)?;
    let mut tag_bytes = [0u8; HASH_LEN];
    exact_into("tag", tag, &mut tag_bytes)?;
    let mut id = [0u8; 32];
    exact_into("recipient id", recipient_id, &mut id)?;
    let kinds = kinds_in(allowed_kinds)?;
    let kinds: Vec<&str> = kinds
        .split(KIND_SEPARATORS)
        .filter(|k| !k.is_empty())
        .collect();
    // Above the largest bucket the block cannot open: the same opaque error.
    let payload = bytes_in("payload", payload, MAX_BLOCK_LEN, |_| open_failed())?;
    Ok(open_sealed(
        key.recipient_key(),
        &outer,
        &tag_bytes,
        &payload,
        &id,
        &kinds,
    )?)
}

/// The key directory tag of an identity (`l2-grammar.md` §5.5): the `tagged` parent of its
/// `sbtp.enc_key` blocks.
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`.
#[wasm_bindgen(js_name = directoryTag)]
pub fn directory_tag_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] identity_public_key: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    let mut key = [0u8; 32];
    exact_into("identity public key", identity_public_key, &mut key)?;
    Ok(directory_tag(&key).to_vec())
}

/// Whether `tag`, the `tagged` parent of a key block, is the directory tag of `publicKey`, the
/// block's `PubKey` (`l2-grammar.md` §5.5). A client MUST ignore a key block for which this is
/// `false`.
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`.
#[wasm_bindgen(js_name = isDirectoryTag)]
pub fn is_directory_tag_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] public_key: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] tag: &JsValue,
) -> Result<bool, JsValue> {
    let mut key = [0u8; 32];
    exact_into("public key", public_key, &mut key)?;
    let mut tag_bytes = [0u8; 32];
    exact_into("tag", tag, &mut tag_bytes)?;
    Ok(is_directory_tag(&key, &tag_bytes))
}

/// An application's tag (`l2-grammar.md` §5.4): `derive_key(context, input)`. `input` is the
/// concatenation of the derivation inputs the application's specification lists, in order, with no
/// separator. Inputs SHOULD therefore be of fixed length, or length-prefixed by that
/// specification: otherwise two different tuples can give the same tag (security review
/// 2026-11-21, I-1).
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength` (input over 1 MiB), `ReservedContext` (a context starting with
/// `SBTP ` or `SBTP-`, or a prefix of a core spec §3.5 string).
#[wasm_bindgen(js_name = applicationTag)]
pub fn application_tag_js(
    #[wasm_bindgen(unchecked_param_type = "string")] context: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] input: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    let context = context
        .as_string()
        .ok_or_else(|| BindError::argument("context", "a string"))?;
    let input = bytes_in("input", input, MAX_TAG_INPUT, |len| {
        BindError::length("input", "at most 1 MiB", len)
    })?;
    Ok(application_tag(&context, &[&input])
        .map_err(BindError::from)?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbtp_l2::cbor::{Value, encode};

    const ALLOWED: &[&str] = &["app.note"];

    /// The arguments of `open_sealed`.
    type Case<'a> = (
        &'a RecipientKey,
        &'a [u8; 32],
        &'a [u8; 32],
        &'a [u8],
        &'a [u8; 32],
        &'a [&'a str],
    );

    // Test keys from public seeds only.
    fn sender() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn recipient() -> EncKeyPair {
        EncKeyPair::from_secret(&[0x22; 32]).unwrap()
    }

    fn msg(text: &str) -> Vec<u8> {
        encode(&Value::Map(vec![
            ("body", Value::Map(vec![("t", Value::Text(text))])),
            ("edges", Value::Array(vec![])),
            ("kind", Value::Text("app.note")),
            ("v", Value::Uint(1)),
        ]))
        .unwrap()
    }

    fn failing_rng() -> OsRng {
        OsRng {
            failed: false,
            fill: |_| Err(getrandom::Error::UNSUPPORTED),
        }
    }

    fn sealed(bucket: Option<Bucket>) -> (SealedEnvelope, [u8; 32], [u8; 32]) {
        let key = recipient();
        let id = [0x33; 32];
        let tag = application_tag("app 2026-11-21 test inbox", &[&id]).unwrap();
        let env = seal_message(
            &sender(),
            &key.public_key_bytes(),
            &id,
            &tag,
            &msg("hello"),
            bucket,
        )
        .unwrap();
        (env, id, tag)
    }

    #[test]
    fn seal_sign_open_round_trip() {
        let (mut env, id, tag) = sealed(None);
        assert_eq!(env.payload_bytes().len(), 512);
        let block = env.unsigned_block(1_700_000_000_000).unwrap();
        let signed = env.sign(block.clone()).unwrap();
        assert!(env.ephemeral.is_none());
        let info = crate::api::validate_submitted_block(&signed, 0).unwrap();
        assert!(info.authenticated());
        // One signature only.
        assert_eq!(env.sign(block).unwrap_err().name(), "EphemeralKeyUsed");

        let opened = open_sealed(
            recipient().recipient_key(),
            env.public_key_bytes(),
            &tag,
            env.payload_bytes(),
            &id,
            ALLOWED,
        )
        .unwrap();
        assert_eq!(opened.msg_bytes(), msg("hello").as_slice());
        assert_eq!(opened.from_bytes(), &sender().verifying_key().to_bytes());
        assert_eq!(opened.kind_str(), "app.note");
        let text = format!("{opened:?}");
        assert!(!text.contains("from") && !text.contains("hello"), "{text}");
    }

    #[test]
    fn every_open_failure_is_the_same_error() {
        let (env, id, tag) = sealed(Some(Bucket::B2048));
        assert_eq!(env.payload_bytes().len(), 2048);
        let key = recipient();
        let other = EncKeyPair::from_secret(&[0x44; 32]).unwrap();
        let mut flipped = env.payload_bytes().to_vec();
        *flipped.last_mut().unwrap() ^= 1;
        let cases: [Case<'_>; 7] = [
            // Wrong key (step 4).
            (
                other.recipient_key(),
                env.public_key_bytes(),
                &tag,
                env.payload_bytes(),
                &id,
                ALLOWED,
            ),
            // Tampered ciphertext (step 4).
            (
                key.recipient_key(),
                env.public_key_bytes(),
                &tag,
                &flipped,
                &id,
                ALLOWED,
            ),
            // Wrong outer PubKey (aad, step 4).
            (
                key.recipient_key(),
                &[0x55; 32],
                &tag,
                env.payload_bytes(),
                &id,
                ALLOWED,
            ),
            // Wrong recipient id (inner signature, step 7).
            (
                key.recipient_key(),
                env.public_key_bytes(),
                &tag,
                env.payload_bytes(),
                &[0x66; 32],
                ALLOWED,
            ),
            // Kind not allowed (step 8).
            (
                key.recipient_key(),
                env.public_key_bytes(),
                &tag,
                env.payload_bytes(),
                &id,
                &["app.other"],
            ),
            // Not an `sbtp.enc` payload (step 2).
            (
                key.recipient_key(),
                env.public_key_bytes(),
                &tag,
                &msg("x"),
                &id,
                ALLOWED,
            ),
            // Garbage (step 2).
            (
                key.recipient_key(),
                env.public_key_bytes(),
                &tag,
                &[0xff; 3],
                &id,
                ALLOWED,
            ),
        ];
        for (k, outer, tag, payload, id, kinds) in cases {
            let err = open_sealed(k, outer, tag, payload, id, kinds).unwrap_err();
            assert_eq!(err, open_failed());
        }
    }

    #[test]
    fn sign_refuses_another_block_and_keeps_the_key() {
        let (mut env, _, _) = sealed(None);
        let other = build_unsigned(env.public_key_bytes(), 1, 0, &[], b"other").unwrap();
        assert_eq!(env.sign(other).unwrap_err().name(), "NotOuterBlock");
        assert_eq!(env.sign(vec![0; 3]).unwrap_err().name(), "TooShort");
        assert!(env.ephemeral.is_some());
        let block = env.unsigned_block(1).unwrap();
        assert!(env.sign(block).is_ok());
    }

    #[test]
    fn seal_errors_are_named() {
        let key = recipient();
        let tag = [0x01; 32];
        let id = [0x02; 32];
        let err = seal_message(&sender(), &key.public_key_bytes(), &id, &tag, b"\xa0", None);
        assert_eq!(err.unwrap_err().name(), "InvalidPayload");
        let big = msg(&"x".repeat(600));
        let err = seal_message(
            &sender(),
            &key.public_key_bytes(),
            &id,
            &tag,
            &big,
            Some(Bucket::B512),
        );
        assert_eq!(err.unwrap_err().name(), "SealTooLong");
        // The all-zero point yields an all-zero shared secret.
        let err = seal_message(&sender(), &[0; 32], &id, &tag, &msg("x"), None);
        assert_eq!(err.unwrap_err().name(), "InvalidRecipientKey");
    }

    #[test]
    fn entropy_failure_is_an_error_not_a_panic() {
        let key = recipient();
        let id = [0x02; 32];
        let tag = [0x01; 32];
        let m = msg("x");
        let request = SealRequest {
            recipient_x25519: &key.public_key_bytes(),
            recipient_id: &id,
            tag: &tag,
            sender: &sender(),
            msg: &m,
            bucket: None,
        };
        let err = seal_with(failing_rng(), &request).unwrap_err();
        assert_eq!(err.name(), "EntropyUnavailable");
        let err = EncKeyPair::generate_with(failing_rng()).unwrap_err();
        assert_eq!(err.name(), "EntropyUnavailable");
    }

    #[test]
    fn generated_keys_differ_and_round_trip() {
        let a = EncKeyPair::generate().unwrap();
        let b = EncKeyPair::generate().unwrap();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
        let again = EncKeyPair::from_secret(&a.recipient_key().secret_bytes()).unwrap();
        assert_eq!(again.public_key_bytes(), a.public_key_bytes());
        let text = format!("{a:?}");
        assert!(text.contains("public_key"));
    }

    #[test]
    fn tags() {
        let id = [0x07; 32];
        let tag = directory_tag(&id);
        assert!(is_directory_tag(&id, &tag));
        assert_eq!(
            BindError::from(application_tag("SBTP-x", &[]).unwrap_err()).name(),
            "ReservedContext"
        );
    }

    #[test]
    fn debug_shows_no_secret() {
        let (env, _, _) = sealed(None);
        let text = format!("{env:?}");
        assert!(text.contains("payload_len"));
        let key = EncKeyPair::from_secret(&[0x5a; 32]).unwrap();
        let text = format!("{key:?}");
        assert!(!text.contains("90, 90, 90"), "{text}");
    }
}
