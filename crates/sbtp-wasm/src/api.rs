//! Binding logic over plain Rust slices: everything the JS exports do, minus the copy in and out of
//! WASM memory. Native unit tests and the vector replay exercise this module directly; the
//! `#[wasm_bindgen]` wrappers in `lib.rs` only check input lengths, copy, and convert errors.
//!
//! No protocol rule is implemented here: parsing, `block_id`, PoW, signing and verification are all
//! `sbtp-core` calls. This module only adapts argument shapes (flat byte arrays) and results.

use sbtp_core::layout::{HASH_LEN, MAX_PARENTS, SIGNATURE_LEN};
use sbtp_core::{
    BlockBuilder, BlockId, BlockRef, BuildError, SIGNED_MESSAGE_LEN, mine, parse, self_test,
    validate_requested, validate_submitted,
};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{BindError, names};

/// The decoded fields of a block, copied out of WASM memory.
///
/// `authenticated` says which checks ran: `false` after [`parse_block`] (format only, F1 to F9:
/// the signature has **not** been verified and the content must not be trusted), `true` after
/// [`validate_submitted_block`] or [`validate_requested_block`] (format, PoW, public key and
/// signature).
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    version: u8,
    timestamp: u64,
    nonce: u64,
    public_key: [u8; 32],
    parents: Vec<BlockId>,
    payload: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
    block_id: BlockId,
    authenticated: bool,
}

impl BlockInfo {
    fn from_block(block: &BlockRef<'_>, block_id: BlockId, authenticated: bool) -> Self {
        Self {
            version: block.version(),
            timestamp: block.timestamp(),
            nonce: block.nonce(),
            public_key: *block.pubkey(),
            parents: block.parents().to_vec(),
            payload: block.payload().to_vec(),
            signature: *block.signature(),
            block_id,
            authenticated,
        }
    }

    /// The `block_id` as a core type.
    #[must_use]
    pub const fn id(&self) -> &BlockId {
        &self.block_id
    }
}

#[wasm_bindgen]
impl BlockInfo {
    /// Version byte (always `1` for a block that parsed).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Timestamp field, Unix milliseconds (a `bigint` in JS).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Nonce field (a `bigint` in JS).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The 32-byte Ed25519 public key of the author.
    #[wasm_bindgen(getter, js_name = publicKey)]
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    /// Number of parents, 0 to 8.
    #[wasm_bindgen(getter, js_name = parentCount)]
    #[must_use]
    pub fn parent_count(&self) -> usize {
        self.parents.len()
    }

    /// The parent at `index` (32 bytes), or `undefined` past the end.
    #[must_use]
    pub fn parent(&self, index: usize) -> Option<Vec<u8>> {
        self.parents.get(index).map(|id| id.as_bytes().to_vec())
    }

    /// All parents concatenated, in block order (`32 × parentCount` bytes).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn parents(&self) -> Vec<u8> {
        self.parents
            .iter()
            .flat_map(|id| id.as_bytes().iter().copied())
            .collect()
    }

    /// The payload (opaque at layer 0).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// The 64 signature bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.to_vec()
    }

    /// The 32-byte `block_id` (spec §3.1).
    #[wasm_bindgen(getter, js_name = blockId)]
    #[must_use]
    pub fn block_id(&self) -> Vec<u8> {
        self.block_id.as_bytes().to_vec()
    }

    /// The `block_id` as 64 lowercase hexadecimal characters.
    #[wasm_bindgen(getter, js_name = blockIdHex)]
    #[must_use]
    pub fn block_id_hex(&self) -> String {
        self.block_id.to_string()
    }

    /// Leading zero bits of the `block_id`: the difficulty this block meets (spec §3.3).
    #[wasm_bindgen(getter, js_name = leadingZeroBits)]
    #[must_use]
    pub fn leading_zero_bits(&self) -> u32 {
        self.block_id.leading_zero_bits()
    }

    /// `true` when the signature and the PoW were verified, `false` after a format-only parse.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}

/// Copies a 32-byte argument into an array.
pub(crate) fn array32(what: &str, bytes: &[u8]) -> Result<[u8; 32], BindError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| BindError::length(what, "32", bytes.len()))
}

/// Splits a flat concatenation of parent identifiers. Refuses a ragged length, and more than 8
/// parents before allocating anything.
pub(crate) fn split_parents(flat: &[u8]) -> Result<Vec<BlockId>, BindError> {
    if flat.len() % HASH_LEN != 0 {
        return Err(BindError::length("parents", "a multiple of 32", flat.len()));
    }
    let count = flat.len() / HASH_LEN;
    if count > usize::from(MAX_PARENTS) {
        return Err(BuildError::TooManyParents { count }.into());
    }
    flat.chunks_exact(HASH_LEN)
        .map(|chunk| array32("parent", chunk).map(BlockId::from))
        .collect()
}

/// Format-only decoding (spec §2.2 F1 to F9). The result is **not** authenticated.
///
/// # Errors
///
/// The F1 to F9 rule that failed.
pub fn parse_block(bytes: &[u8]) -> Result<BlockInfo, BindError> {
    let block = parse(bytes)?;
    let id = block.block_id();
    Ok(BlockInfo::from_block(&block, id, false))
}

/// Full validation of a block submitted without an expected identifier (spec §3.4): F1 to F9, C1 at
/// `difficulty`, C2, C3.
///
/// # Errors
///
/// The first rule that failed.
pub fn validate_submitted_block(bytes: &[u8], difficulty: u32) -> Result<BlockInfo, BindError> {
    let valid = validate_submitted(bytes, difficulty)?;
    Ok(BlockInfo::from_block(
        valid.block(),
        *valid.block_id(),
        true,
    ))
}

/// Full validation of a block fetched by its identifier (spec §3.4 "Receipt"): F1 to F9, R1, C1,
/// C2, C3. This is the check to apply to anything a relay returns for `GET`.
///
/// # Errors
///
/// `InvalidLength` if `requested` is not 32 bytes, otherwise the first rule that failed.
pub fn validate_requested_block(
    bytes: &[u8],
    difficulty: u32,
    requested: &[u8],
) -> Result<BlockInfo, BindError> {
    let requested = BlockId::from(array32("requested block id", requested)?);
    let valid = validate_requested(bytes, difficulty, &requested)?;
    Ok(BlockInfo::from_block(
        valid.block(),
        *valid.block_id(),
        true,
    ))
}

/// The `block_id` of a well-formed block (spec §3.1).
///
/// # Errors
///
/// The F1 to F9 rule that failed.
pub fn block_id(bytes: &[u8]) -> Result<BlockId, BindError> {
    Ok(parse(bytes)?.block_id())
}

/// Encodes a block with a zeroed signature.
///
/// # Errors
///
/// `InvalidLength` (public key, parents), `TooManyParents`, `DuplicateParent`, `PayloadTooLong`.
pub fn build_unsigned(
    public_key: &[u8],
    timestamp: u64,
    nonce: u64,
    parents: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, BindError> {
    let public_key = array32("public key", public_key)?;
    let parents = split_parents(parents)?;
    Ok(BlockBuilder::new(public_key)
        .timestamp(timestamp)
        .nonce(nonce)
        .parents(&parents)
        .payload(payload)
        .build_unsigned()?)
}

/// Tries at most `max_attempts` nonces from the block's current Nonce field (spec §3.3, ADR 0001
/// rule 3). Returns the `block_id` when one meets `difficulty`, `None` when the slice is spent; in
/// both cases `block` holds the nonce to keep (the winner) or to resume from (the next untried
/// one), so calling again until `Some` reaches the same nonce as one unbounded search.
///
/// # Errors
///
/// `DifficultyTooHigh` (above 256) or the F1 to F9 rule that failed; `block` is then unchanged.
/// `NonceSpaceExhausted` when the slice reached nonce 2^64 − 1 without success: every later call
/// would fail at once, so a "call again" loop must stop (`block` keeps nonce 2^64 − 1).
pub fn mine_slice(
    block: &mut [u8],
    difficulty: u32,
    max_attempts: u64,
) -> Result<Option<BlockId>, BindError> {
    let start = parse(block)?.nonce();
    match mine(block, difficulty, max_attempts) {
        Ok((_, id)) => Ok(Some(id)),
        // `mine` tries `start, start + 1, ...`: the slice covered nonce u64::MAX exactly when
        // `start + max_attempts` overflows. `mine` reports both "budget spent" and "end of the nonce
        // space" as `PowNotFound`; only the first one can be resumed.
        Err(BuildError::PowNotFound) if start.checked_add(max_attempts).is_none() => {
            Err(BindError::new(
                names::NONCE_SPACE_EXHAUSTED,
                "every nonce up to 2^64 - 1 was tried: change the timestamp or payload and mine again",
            ))
        }
        Err(BuildError::PowNotFound) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The 49 bytes an author signs for this block: `SIG_PREFIX ‖ block_id` (spec §3.2). For a signer
/// held outside WASM (Web Crypto Ed25519 with a non-extractable key): sign these bytes with plain
/// Ed25519, then pass the signature to [`attach_signature`]. Mine before taking them: the nonce is
/// covered by the `block_id`.
///
/// # Errors
///
/// The F1 to F9 rule that failed.
pub fn signing_message(bytes: &[u8]) -> Result<[u8; SIGNED_MESSAGE_LEN], BindError> {
    Ok(parse(bytes)?.block_id().signed_message())
}

/// Writes `signature` into the Signature field of the block `bytes` (taken by value: no copy) and
/// returns it, after checking that it verifies under the block's own public key (C2, C3). A
/// signature over the wrong message, by another key, or failing a strict criterion (V1 to V6) is
/// refused here rather than by a relay. The PoW is not checked (difficulty 0): that is the relay's
/// policy.
///
/// # Errors
///
/// `InvalidLength` if `signature` is not 64 bytes, the F1 to F9 rule that failed, then
/// `InvalidPublicKey` or `InvalidSignature`.
pub fn attach_signature(mut bytes: Vec<u8>, signature: &[u8]) -> Result<Vec<u8>, BindError> {
    let signature = <[u8; SIGNATURE_LEN]>::try_from(signature)
        .map_err(|_| BindError::length("signature", "64", signature.len()))?;
    // F1 to F9 before touching anything; the length is then known to hold a signature field.
    parse(&bytes)?;
    let start = bytes.len().saturating_sub(SIGNATURE_LEN);
    // spec §2.1: the signature is the last 64 bytes of a well-formed block.
    if let Some(field) = bytes.get_mut(start..) {
        field.copy_from_slice(&signature);
    }
    validate_submitted(&bytes, 0)?;
    Ok(bytes)
}

/// Replays the frozen `S + L` vector and a valid block through the verifier of this build
/// (ADR 0003 rule 16).
///
/// # Errors
///
/// `SelfTestFailed` when the verifier of this build accepts `S + L` or rejects the valid block.
pub fn run_self_test() -> Result<(), BindError> {
    self_test().map_err(|error| BindError::new(names::SELF_TEST_FAILED, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbtp_core::SigningKey;
    use sbtp_core::layout::{MAX_PAYLOAD_LEN, MIN_BLOCK_LEN};

    fn key() -> SigningKey {
        // Test key from the public seed of the vectors (docs/test-vectors/README.md).
        SigningKey::from_bytes(&[0x01; 32])
    }

    fn unsigned(parents: &[u8], payload: &[u8]) -> Vec<u8> {
        build_unsigned(
            key().verifying_key().as_bytes(),
            1_700_000_000_000,
            0,
            parents,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn build_then_parse_round_trips_every_field() {
        let mut parents = vec![0xaa; 32];
        parents.extend([0xbb; 32]);
        let block = build_unsigned(
            key().verifying_key().as_bytes(),
            42,
            0x0102_0304_0506_0708,
            &parents,
            b"hello",
        )
        .unwrap();
        let info = parse_block(&block).unwrap();
        assert_eq!(info.version(), 1);
        assert_eq!(info.timestamp(), 42);
        assert_eq!(info.nonce(), 0x0102_0304_0506_0708);
        assert_eq!(info.public_key(), key().verifying_key().as_bytes().to_vec());
        assert_eq!(info.parent_count(), 2);
        assert_eq!(info.parent(1), Some(vec![0xbb; 32]));
        assert_eq!(info.parent(2), None);
        assert_eq!(info.parents(), parents);
        assert_eq!(info.payload(), b"hello".to_vec());
        assert_eq!(info.signature(), vec![0; 64]);
        assert!(!info.authenticated());
        assert_eq!(info.block_id_hex().len(), 64);
        assert_eq!(*info.id(), block_id(&block).unwrap());
    }

    #[test]
    fn build_rejects_bad_arguments_with_named_errors() {
        let pk = key().verifying_key().to_bytes();
        let name = |r: Result<Vec<u8>, BindError>| r.unwrap_err().name();
        assert_eq!(
            name(build_unsigned(&pk[..31], 0, 0, &[], &[])),
            "InvalidLength"
        );
        assert_eq!(
            name(build_unsigned(&pk, 0, 0, &[0; 33], &[])),
            "InvalidLength"
        );
        assert_eq!(
            name(build_unsigned(&pk, 0, 0, &[0; 9 * 32], &[])),
            "TooManyParents"
        );
        assert_eq!(
            name(build_unsigned(&pk, 0, 0, &[7; 64], &[])),
            "DuplicateParent"
        );
        assert_eq!(
            name(build_unsigned(
                &pk,
                0,
                0,
                &[],
                &vec![0; MAX_PAYLOAD_LEN + 1]
            )),
            "PayloadTooLong"
        );
    }

    #[test]
    fn external_signature_path_produces_a_valid_block() {
        // "Signing bytes out, signature in": what a Web Crypto signer would do.
        use sbtp_core::SigningKey;
        use sbtp_core::sign_block_id;
        let mut block = unsigned(&[], b"external");
        assert!(mine_slice(&mut block, 4, 1 << 16).unwrap().is_some());
        let message = signing_message(&block).unwrap();
        let id = block_id(&block).unwrap();
        assert_eq!(message, id.signed_message());
        // An external Ed25519 signer signs `message`; here dalek stands in for it.
        let signature = ed25519_sign(&key(), &message);
        assert_eq!(signature, sign_block_id(&key(), &id).unwrap());
        let signed = attach_signature(block.clone(), &signature).unwrap();
        let info = validate_submitted_block(&signed, 4).unwrap();
        assert!(info.authenticated());
        // The input is not modified.
        assert_eq!(parse_block(&block).unwrap().signature(), vec![0; 64]);
        // A signature by another key is refused at attach time.
        let other = SigningKey::from_bytes(&[0x02; 32]);
        let wrong = ed25519_sign(&other, &message);
        assert_eq!(
            attach_signature(block.clone(), &wrong).unwrap_err().name(),
            "InvalidSignature"
        );
        assert_eq!(
            attach_signature(block.clone(), &signature[..63])
                .unwrap_err()
                .name(),
            "InvalidLength"
        );
        assert_eq!(
            attach_signature(block[..10].to_vec(), &signature)
                .unwrap_err()
                .name(),
            "TooShort"
        );
    }

    /// Plain RFC 8032 Ed25519 over a free message, as Web Crypto `sign("Ed25519", ...)` computes it.
    fn ed25519_sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        key.sign(message).to_bytes()
    }

    #[test]
    fn mining_in_slices_reaches_the_same_nonce_as_one_search() {
        let start = unsigned(&[], b"slices");
        let mut whole = start.clone();
        let expected = mine_slice(&mut whole, 10, u64::MAX).unwrap().unwrap();
        let mut sliced = start;
        let mut calls = 0;
        let found = loop {
            calls += 1;
            if let Some(id) = mine_slice(&mut sliced, 10, 64).unwrap() {
                break id;
            }
        };
        assert!(calls > 1, "the test should need several slices");
        assert_eq!(found, expected);
        assert_eq!(sliced, whole);
        assert!(found.leading_zero_bits() >= 10);
    }

    #[test]
    fn mining_errors_leave_the_block_unchanged() {
        let mut block = unsigned(&[], b"");
        let before = block.clone();
        assert_eq!(
            mine_slice(&mut block, 257, 1).unwrap_err().name(),
            "DifficultyTooHigh"
        );
        assert_eq!(block, before);
        let mut bad = vec![0u8; MIN_BLOCK_LEN];
        assert_eq!(mine_slice(&mut bad, 1, 1).unwrap_err().name(), "BadMagic");
        assert_eq!(bad, vec![0u8; MIN_BLOCK_LEN]);
    }

    #[test]
    fn end_of_the_nonce_space_is_not_a_spent_slice() {
        let at = |nonce: u64| {
            build_unsigned(key().verifying_key().as_bytes(), 0, nonce, &[], b"").unwrap()
        };
        let nonce = |block: &[u8]| parse_block(block).unwrap().nonce();
        // Difficulty 256 never succeeds. Slices that stop short of u64::MAX resume.
        let mut block = at(u64::MAX - 3);
        assert_eq!(mine_slice(&mut block, 256, 2).unwrap(), None);
        assert_eq!(nonce(&block), u64::MAX - 1);
        assert_eq!(mine_slice(&mut block, 256, 1).unwrap(), None);
        assert_eq!(nonce(&block), u64::MAX);
        // u64::MAX is still untried: this slice tries it, then the space is exhausted.
        assert_eq!(
            mine_slice(&mut block, 256, 1).unwrap_err().name(),
            names::NONCE_SPACE_EXHAUSTED
        );
        assert_eq!(nonce(&block), u64::MAX);
        // Every later call fails at once, with the same name.
        assert_eq!(
            mine_slice(&mut block, 256, 1000).unwrap_err().name(),
            names::NONCE_SPACE_EXHAUSTED
        );
        // A slice crossing the end in one call.
        let mut block = at(u64::MAX - 3);
        assert_eq!(
            mine_slice(&mut block, 256, 10).unwrap_err().name(),
            names::NONCE_SPACE_EXHAUSTED
        );
    }

    #[test]
    fn validate_requested_checks_the_identifier() {
        let mut block = unsigned(&[], b"r1");
        sbtp_core::sign_block(&mut block, &key()).unwrap();
        let id = block_id(&block).unwrap();
        assert!(validate_requested_block(&block, 0, id.as_bytes()).is_ok());
        assert_eq!(
            validate_requested_block(&block, 0, &[0; 32])
                .unwrap_err()
                .name(),
            "BlockIdMismatch"
        );
        assert_eq!(
            validate_requested_block(&block, 0, &[0; 31])
                .unwrap_err()
                .name(),
            "InvalidLength"
        );
        assert_eq!(
            validate_submitted_block(&block, 256).unwrap_err().name(),
            "InsufficientPow"
        );
    }

    #[test]
    fn self_test_passes() {
        run_self_test().unwrap();
    }

    #[test]
    fn arbitrary_inputs_never_panic() {
        // A cheap sweep over lengths and byte patterns: every entry point returns, none panics.
        for len in [0usize, 1, 117, 118, 119, 200, 500] {
            for fill in [0u8, 0x53, 0xff] {
                let mut bytes = vec![fill; len];
                if len >= 3 {
                    bytes[0] = b'S';
                    bytes[1] = b'B';
                    bytes[2] = 1;
                }
                let _ = parse_block(&bytes);
                let _ = validate_submitted_block(&bytes, 0);
                let _ = validate_requested_block(&bytes, 0, &[0; 32]);
                let _ = block_id(&bytes);
                let _ = signing_message(&bytes);
                let _ = attach_signature(bytes.clone(), &[0; 64]);
                let _ = mine_slice(&mut bytes, 1, 4);
            }
        }
    }
}
