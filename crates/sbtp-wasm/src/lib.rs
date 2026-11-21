//! WebAssembly bindings of `sbtp-core` (target `wasm32-unknown-unknown`), plus, behind the
//! features `l2` and `seal` (on by default), the generic layer 2 grammar of `sbtp-l2` and the
//! sealed envelope of `sbtp-seal` (Q-78: one module, measured within the ADR 0048 budget).
//!
//! Every protocol rule runs in those crates: this crate only moves bytes across the boundary.
//! Browsers MUST verify blocks through these bindings, not through a JS Ed25519 library or Web
//! Crypto `verify`, which diverge from the strict criteria V1 to V6 (interop finding 2026-11-18,
//! the roadmap (not published) Phase 3).
//!
//! # JavaScript API
//!
//! All byte arguments and results are `Uint8Array`; 64-bit fields (`timestamp`, `nonce`) are
//! `bigint`; `difficulty` and `maxAttempts` are integer `number`s. Every failure throws a JS `Error`
//! whose `name` is stable: the spec §2.2 rule name for a validation failure (`TooShort` ...
//! `InvalidSignature`, as in the test vectors), otherwise one of [`names`].
//!
//! | Export | Does |
//! |---|---|
//! | (module start) | Replays the frozen `S + L` vector: instantiation fails on a bad build (ADR 0003 rule 16). |
//! | `selfTest()` | The same check, on demand. |
//! | `parseBlock(bytes)` | F1 to F9 only, returns an unauthenticated `BlockInfo`. |
//! | `validateSubmitted(bytes, difficulty)` | F1 to F9, C1, C2, C3. |
//! | `validateRequested(bytes, difficulty, requestedId)` | F1 to F9, R1, C1, C2, C3: for blocks fetched by id. |
//! | `blockId(bytes)` | The 32-byte `block_id`. |
//! | `buildUnsignedBlock(publicKey, timestamp, nonce, parents, payload)` | Encodes a block, signature zeroed; `parents` is the concatenation of 0 to 8 ids. |
//! | `mineSlice(block, difficulty, maxAttempts)` | Mines in place, returns the `block_id` or `undefined` (call again). |
//! | `signingMessage(block)` | The 49 bytes to sign with an external Ed25519 key. |
//! | `attachSignature(block, signature)` | Inserts an external signature, verified before returning. |
//! | `DemoSigningKey.generate()`, `.fromSeed(seed)` | In-WASM key, demo and CLI-like use only. |
//! | `key.publicKey`, `key.signBlock(block)`, `key.exportSeed()`, `key.free()` | |
//! | `validateL2Payload(parents, payload)` | Layer 2 grammar validation (feature `l2`), returns an `L2Payload`. |
//! | `seal(sender, recipientX25519, recipientId, tag, msg, bucket?)` | Sealed envelope (feature `seal`), returns a `SealedEnvelope`. |
//! | `sealPrepare(from, recipientX25519, recipientId, tag, msg, bucket?)` | Two-phase seal for an identity key outside WASM: returns a `SealPending`. |
//! | `pending.message`, `pending.finish(signature)` | The bytes to sign; the signature is verified, then sealed into a `SealedEnvelope` (once). |
//! | `env.unsignedBlock(timestamp)`, `env.signBlock(block)` | The outer block; the ephemeral key signs once, then is wiped. |
//! | `openSealed(key, outerPublicKey, tag, payload, recipientId, allowedKinds)` | Opens, returns an `OpenedMessage`; every failure is `OpenFailed`. |
//! | `EncKeyPair.generate()`, `.fromSecret(secret)`, `.publicKey`, `.exportSecret()` | X25519 key of `sbtp.enc_key`. |
//! | `directoryTag(pk)`, `isDirectoryTag(pk, tag)`, `applicationTag(context, input)` | Tags (spec §5.4, §5.5). |
//!
//! # Argument checks
//!
//! wasm-bindgen does not type-check arguments, and the WebAssembly JS API coerces numbers silently
//! (`undefined` becomes 0, which would disable C1). So every argument is received as a `JsValue`
//! and checked here, without calling any JS that could throw: a JS exception unwinding through
//! WASM frames skips Rust destructors, and would leave a `DemoSigningKey` borrowed for ever
//! (security review 2026-11-19, L-1, L-2). Byte arguments are length-capped before they are copied
//! into WASM memory, so an oversized argument is an error, never an allocation failure.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

mod api;
mod error;
mod key;
#[cfg(feature = "l2")]
mod l2;
#[cfg(feature = "seal")]
mod seal;

use js_sys::Uint8Array;
use sbtp_core::layout::{HASH_LEN, MAX_BLOCK_LEN, SIGNATURE_LEN};
use sbtp_core::{BuildError, Error, MAX_DIFFICULTY};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub use api::{
    BlockInfo, attach_signature, block_id, build_unsigned, mine_slice, parse_block, run_self_test,
    signing_message, validate_requested_block, validate_submitted_block,
};
pub use error::{BindError, names};
pub use key::DemoSigningKey;
#[cfg(feature = "l2")]
pub use l2::{L2Payload, validate_l2_payload};
#[cfg(feature = "seal")]
pub use seal::{
    EncKeyPair, OpenedMessage, SealPending, SealedEnvelope, open_sealed, prepare_seal, seal_message,
};

/// Largest integer a JS `number` represents exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// The `Uint8Array` behind `value`. `dyn_ref` is an `instanceof` test, which the glue runs inside
/// `try`: it cannot throw.
fn typed<'a>(what: &str, value: &'a JsValue) -> Result<&'a Uint8Array, BindError> {
    value
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| BindError::argument(what, "a Uint8Array"))
}

/// Length of a JS typed array, as `usize` (lossless on wasm32).
fn js_len(bytes: &Uint8Array) -> usize {
    usize::try_from(bytes.length()).unwrap_or(usize::MAX)
}

/// Copies a byte argument of at most `cap` bytes into WASM memory; `too_long` names the error
/// above the cap. Within the cap, `sbtp-core` applies the exact rules.
fn bytes_in(
    what: &str,
    value: &JsValue,
    cap: usize,
    too_long: impl FnOnce(usize) -> BindError,
) -> Result<Vec<u8>, BindError> {
    let array = typed(what, value)?;
    let len = js_len(array);
    if len > cap {
        return Err(too_long(len));
    }
    let mut out = vec![0u8; len];
    // One allocation of the length just checked. `copy_to` asserts the lengths are equal, which
    // holds for a genuine typed array (security review I-1: a lying `length` traps, fails closed).
    array.copy_to(&mut out);
    Ok(out)
}

/// A block argument. Above `MAX_BLOCK_LEN` the block fails F2 anyway: the error is the one
/// `sbtp-core` would give, without the copy.
fn block_in(value: &JsValue) -> Result<Vec<u8>, BindError> {
    // spec §2.2 F2 (F1 cannot fail on a buffer this long).
    bytes_in("block", value, MAX_BLOCK_LEN, |len| {
        Error::TooLong { len }.into()
    })
}

/// Copies a byte argument of exactly `out.len()` bytes into `out`, in place (no intermediate copy,
/// so a `Zeroizing` destination is the only copy).
fn exact_into(what: &str, value: &JsValue, out: &mut [u8]) -> Result<(), BindError> {
    let array = typed(what, value)?;
    let len = js_len(array);
    if len != out.len() {
        return Err(BindError::length(what, &out.len().to_string(), len));
    }
    array.copy_to(out);
    Ok(())
}

/// An integer `number` in `min..=max`, or `None` for anything else (`undefined`, `NaN`, a string, a
/// fraction, out of range).
fn integer_in(value: &JsValue, min: f64, max: f64) -> Option<f64> {
    value
        .as_f64()
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= min && *n <= max)
}

/// A difficulty: an integer from 0 to 256 (spec §3.3).
fn difficulty_in(value: &JsValue) -> Result<u32, BindError> {
    let max = f64::from(MAX_DIFFICULTY);
    match integer_in(value, 0.0, MAX_SAFE_INTEGER) {
        // Integral and within 0..=256: the conversion is exact.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(n) if n <= max => Ok(n as u32),
        Some(_) => Err(BindError::new(
            names::DIFFICULTY_TOO_HIGH,
            format!("difficulty above the maximum of {MAX_DIFFICULTY}"),
        )),
        None => Err(BindError::argument(
            "difficulty",
            "an integer number from 0 to 256",
        )),
    }
}

/// A mining budget: an integer from 1 to `Number.MAX_SAFE_INTEGER`. Zero is refused: a slice that
/// tries nothing would make a "call again" loop spin for ever.
fn attempts_in(value: &JsValue) -> Result<u64, BindError> {
    integer_in(value, 1.0, MAX_SAFE_INTEGER)
        // Integral and within 1..=2^53 − 1: the conversion is exact.
        .map(
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            |n| n as u64,
        )
        .ok_or_else(|| BindError::argument("maxAttempts", "an integer number from 1 to 2^53 - 1"))
}

/// A `bigint` from 0 to 2^64 − 1. A negative or larger value is refused, not wrapped.
fn u64_in(what: &str, value: &JsValue) -> Result<u64, BindError> {
    if !value.is_bigint() {
        return Err(BindError::argument(what, "a bigint"));
    }
    u64::try_from(value.clone())
        .map_err(|_| BindError::argument(what, "a bigint from 0 to 2^64 - 1"))
}

/// Runs when the module is instantiated: replays the frozen `S + L` vector and a valid block
/// through this build's verifier (ADR 0003 rule 16). On failure instantiation rejects, so no
/// export of a bad build can be used.
///
/// # Errors
///
/// `SelfTestFailed`.
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    run_self_test().map_err(JsValue::from)
}

/// Replays the self-test of module start again, on demand.
///
/// # Errors
///
/// `SelfTestFailed`.
#[wasm_bindgen(js_name = selfTest)]
pub fn self_test_js() -> Result<(), JsValue> {
    run_self_test().map_err(JsValue::from)
}

/// Format-only decoding (F1 to F9). The result has `authenticated === false`: its signature and
/// PoW are **not** verified, so it must not be displayed or stored as an authored block.
///
/// # Errors
///
/// `InvalidArgument`, or the F1 to F9 rule that failed.
#[wasm_bindgen(js_name = parseBlock)]
pub fn parse_block_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: &JsValue,
) -> Result<BlockInfo, JsValue> {
    Ok(parse_block(&block_in(bytes)?)?)
}

/// Full validation of a block received without an expected identifier: F1 to F9, C1 at
/// `difficulty`, C2, C3 (spec §3.4).
///
/// # Errors
///
/// `InvalidArgument`, `DifficultyTooHigh`, or the first rule that failed.
#[wasm_bindgen(js_name = validateSubmitted)]
pub fn validate_submitted_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] difficulty: &JsValue,
) -> Result<BlockInfo, JsValue> {
    let difficulty = difficulty_in(difficulty)?;
    Ok(validate_submitted_block(&block_in(bytes)?, difficulty)?)
}

/// Full validation of a block fetched by its identifier: F1 to F9, R1, C1, C2, C3 (spec §3.4
/// "Receipt"). Apply it to every block a relay returns.
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength` for `requested_id`, `DifficultyTooHigh`, otherwise the first
/// rule that failed.
#[wasm_bindgen(js_name = validateRequested)]
pub fn validate_requested_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] difficulty: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] requested_id: &JsValue,
) -> Result<BlockInfo, JsValue> {
    let difficulty = difficulty_in(difficulty)?;
    let mut requested = [0u8; HASH_LEN];
    exact_into("requested block id", requested_id, &mut requested)?;
    Ok(validate_requested_block(
        &block_in(bytes)?,
        difficulty,
        &requested,
    )?)
}

/// The 32-byte `block_id` of a well-formed block (spec §3.1).
///
/// # Errors
///
/// `InvalidArgument`, or the F1 to F9 rule that failed.
#[wasm_bindgen(js_name = blockId)]
pub fn block_id_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    Ok(block_id(&block_in(bytes)?)?.as_bytes().to_vec())
}

/// Encodes a block with a zeroed signature. `parents` is the concatenation of 0 to 8 distinct
/// 32-byte identifiers, in order. Then: `mineSlice` if the relay requires a difficulty, then sign
/// (`DemoSigningKey.signBlock`, or `signingMessage` + `attachSignature`).
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`, `TooManyParents`, `DuplicateParent`, `PayloadTooLong`.
#[wasm_bindgen(js_name = buildUnsignedBlock)]
pub fn build_unsigned_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] public_key: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "bigint")] timestamp: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "bigint")] nonce: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] parents: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] payload: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    let mut key = [0u8; 32];
    exact_into("public key", public_key, &mut key)?;
    let timestamp = u64_in("timestamp", timestamp)?;
    let nonce = u64_in("nonce", nonce)?;
    // One cap per argument, only to bound the copy; within it `build_unsigned` and `sbtp-core`
    // give the exact error.
    let parents = bytes_in("parents", parents, MAX_BLOCK_LEN, |len| {
        BuildError::TooManyParents {
            count: len / HASH_LEN,
        }
        .into()
    })?;
    let payload = bytes_in("payload", payload, MAX_BLOCK_LEN, |len| {
        BuildError::PayloadTooLong { len }.into()
    })?;
    Ok(build_unsigned(&key, timestamp, nonce, &parents, &payload)?)
}

/// Mines `block` **in place**: tries at most `max_attempts` nonces from its current Nonce field.
/// Returns the 32-byte `block_id` when one meets `difficulty`, or `undefined` when the slice is
/// spent; `block` then holds the next nonce to try, so calling again resumes the search. Run it in
/// a Web Worker, in slices of about 2^16 attempts, to keep the page responsive.
///
/// # Errors
///
/// `InvalidArgument`, `DifficultyTooHigh` or the F1 to F9 rule that failed (`block` unchanged);
/// `NonceSpaceExhausted` once nonce 2^64 − 1 has been tried: stop calling, change the timestamp or
/// payload.
#[wasm_bindgen(js_name = mineSlice)]
pub fn mine_slice_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] block: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] difficulty: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] max_attempts: &JsValue,
) -> Result<Option<Vec<u8>>, JsValue> {
    let difficulty = difficulty_in(difficulty)?;
    let max_attempts = attempts_in(max_attempts)?;
    let mut bytes = block_in(block)?;
    let result = mine_slice(&mut bytes, difficulty, max_attempts);
    // Write the nonce back on success, on a spent slice and at the end of the nonce space; on the
    // other errors `bytes` is unchanged anyway. Same length as `block` (checked by `block_in`).
    if let Ok(array) = typed("block", block) {
        array.copy_from(&bytes);
    }
    Ok(result?.map(|id| id.as_bytes().to_vec()))
}

/// The 49 bytes to sign for `block`: `SIG_PREFIX ‖ block_id` (spec §3.2). For a key held outside
/// WASM (Web Crypto Ed25519, `extractable: false`): sign them with plain Ed25519, then call
/// `attachSignature`. Take them after mining.
///
/// # Errors
///
/// `InvalidArgument`, or the F1 to F9 rule that failed.
#[wasm_bindgen(js_name = signingMessage)]
pub fn signing_message_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] block: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    Ok(signing_message(&block_in(block)?)?.to_vec())
}

/// Returns a copy of `block` carrying `signature` (64 bytes), after verifying it under the block's
/// public key (C2, C3; the PoW is not checked).
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`, the F1 to F9 rule that failed, `InvalidPublicKey` or
/// `InvalidSignature`.
#[wasm_bindgen(js_name = attachSignature)]
pub fn attach_signature_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] block: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] signature: &JsValue,
) -> Result<Vec<u8>, JsValue> {
    let mut sig = [0u8; SIGNATURE_LEN];
    exact_into("signature", signature, &mut sig)?;
    Ok(attach_signature(block_in(block)?, &sig)?)
}

#[wasm_bindgen]
impl DemoSigningKey {
    /// A fresh key from Web Crypto `getRandomValues`. **Demo and CLI-like use only**: the secret
    /// lives in WASM memory. Call `free()` when done.
    ///
    /// # Errors
    ///
    /// `EntropyUnavailable`.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_js() -> Result<DemoSigningKey, JsValue> {
        Ok(Self::generate()?)
    }

    /// The key whose 32-byte RFC 8032 seed is `seed`. Overwrite `seed` (`seed.fill(0)`) afterwards:
    /// this function cannot wipe the caller's copy.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`, `InvalidLength`.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed_js(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] seed: &JsValue,
    ) -> Result<DemoSigningKey, JsValue> {
        // Filled in place: the wiped buffer is the only copy this crate makes.
        let mut buffer = Zeroizing::new([0u8; 32]);
        exact_into("seed", seed, buffer.as_mut_slice())?;
        Ok(Self::from_seed(&buffer))
    }

    /// The 32-byte public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    #[must_use]
    pub fn public_key_js(&self) -> Vec<u8> {
        self.public_key_bytes().to_vec()
    }

    /// Returns a signed copy of `block` (well-formed, mined, with this key as `PubKey`).
    ///
    /// # Errors
    ///
    /// `InvalidArgument`, the F1 to F9 rule that failed, `KeyMismatch`, `Signing`.
    #[wasm_bindgen(js_name = signBlock)]
    pub fn sign_block_js(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] block: &JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.sign(block_in(block)?)?)
    }

    /// A copy of the 32-byte secret seed, for the caller to store **encrypted**. Never log it,
    /// never put it in `localStorage` or a URL; overwrite it (`fill(0)`) once stored.
    #[wasm_bindgen(js_name = exportSeed)]
    #[must_use]
    pub fn export_seed_js(&self) -> Uint8Array {
        // Copied straight from the key into a new JS array: no WASM-side copy at all.
        Uint8Array::from(self.seed_bytes().as_slice())
    }
}
