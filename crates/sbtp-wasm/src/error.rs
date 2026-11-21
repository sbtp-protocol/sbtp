//! Errors crossing the JavaScript boundary.
//!
//! Every failure becomes a JS `Error` whose `name` is a stable identifier and whose `message` is a
//! human-readable explanation. For a validation failure the name is the `sbtp-core` variant name of
//! spec §2.2, exactly as in the `expect.error` field of the test vectors (`TooShort`,
//! `InvalidSignature`...), so a caller can branch on `e.name`. Every other name is a constant of
//! [`names`].

use core::fmt;

use sbtp_core::{BuildError, Error};

/// A binding error: a stable `name` and a message. Converted into a JS `Error` at the boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindError {
    name: &'static str,
    message: String,
}

/// Every `Error.name` JS can see apart from the spec §2.2 validation names.
pub mod names {
    /// An argument is not of the expected JS type (`Uint8Array`, `bigint`, integer `number`), or
    /// a number is out of range.
    pub const INVALID_ARGUMENT: &str = "InvalidArgument";
    /// A byte argument has the wrong length (public key, seed, signature, block identifier,
    /// parents).
    pub const INVALID_LENGTH: &str = "InvalidLength";
    /// More than 8 parents (spec §2.2 F5, sender side).
    pub const TOO_MANY_PARENTS: &str = "TooManyParents";
    /// Payload over 65,535 bytes.
    pub const PAYLOAD_TOO_LONG: &str = "PayloadTooLong";
    /// Two identical parents (spec §2.2 F9, sender side).
    pub const DUPLICATE_PARENT: &str = "DuplicateParent";
    /// A difficulty above 256 (spec §3.3).
    pub const DIFFICULTY_TOO_HIGH: &str = "DifficultyTooHigh";
    /// The whole nonce space (up to 2^64 − 1) was tried without meeting the difficulty: change
    /// the timestamp or payload and mine again.
    pub const NONCE_SPACE_EXHAUSTED: &str = "NonceSpaceExhausted";
    /// The signing key is not the block's `PubKey`.
    pub const KEY_MISMATCH: &str = "KeyMismatch";
    /// The Ed25519 signer failed (`sbtp_core::BuildError::Signing`).
    pub const SIGNING: &str = "Signing";
    /// The random source failed (keygen only).
    pub const ENTROPY_UNAVAILABLE: &str = "EntropyUnavailable";
    /// The start-up replay of the frozen `S + L` vector failed (ADR 0003 rule 16).
    pub const SELF_TEST_FAILED: &str = "SelfTestFailed";
    /// A layer 2 grammar payload is invalid (`l2-grammar.md` §1 to §3). The `message` is exactly
    /// the name of the `sbtp-l2` rule that failed (`MapKeysUnsorted`, `InvalidKind`...).
    pub const INVALID_PAYLOAD: &str = "InvalidPayload";
    /// A sealed block did not open (`l2-grammar.md` §5.3). Deliberately opaque: the message is
    /// always the same and never says which check failed (security review 2026-11-21, I-4).
    pub const OPEN_FAILED: &str = "OpenFailed";
    /// The sealed item does not fit the requested bucket, or any bucket (`l2-grammar.md` §5.2).
    pub const SEAL_TOO_LONG: &str = "SealTooLong";
    /// The recipient X25519 key cannot be sealed to (all-zero shared secret, RFC 9180 §7.1.4).
    pub const INVALID_RECIPIENT_KEY: &str = "InvalidRecipientKey";
    /// A tag context uses a reserved prefix (`l2-grammar.md` §5.4, core spec §3.5).
    pub const RESERVED_CONTEXT: &str = "ReservedContext";
    /// The ephemeral key of a sealed envelope already signed its outer block (`l2-grammar.md`
    /// §5.2: it signs that block only), or the block is not that envelope's outer block.
    pub const EPHEMERAL_KEY_USED: &str = "EphemeralKeyUsed";
    /// `SealPending.finish` (or its `message`) was called after a first `finish`: the pending
    /// seal is single use (`l2-grammar.md` §5.2, one ephemeral key per sealed block).
    pub const PENDING_SEAL_USED: &str = "PendingSealUsed";
    /// The block given to `SealedEnvelope.signBlock` is not the envelope's outer block (other
    /// parents or other payload).
    pub const NOT_OUTER_BLOCK: &str = "NotOuterBlock";
    /// A `sbtp-core` error the bindings never let reach JS (`BufferTooSmall`: the bindings size
    /// every buffer; `PowNotFound`: `mineSlice` turns it into `undefined`). Kept so that the
    /// mapping stays total.
    pub const INTERNAL: &str = "Internal";
}

impl BindError {
    /// A binding-level error.
    pub(crate) fn new(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            message: message.into(),
        }
    }

    /// A byte argument of the wrong length.
    pub(crate) fn length(what: &str, expected: &str, actual: usize) -> Self {
        Self::new(
            names::INVALID_LENGTH,
            format!("{what}: {actual} bytes, {expected} expected"),
        )
    }

    /// An argument of the wrong JS type or out of range.
    pub(crate) fn argument(what: &str, expected: &str) -> Self {
        Self::new(
            names::INVALID_ARGUMENT,
            format!("{what}: expected {expected}"),
        )
    }

    /// The stable identifier, used as the JS `Error.name`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The human-readable explanation, used as the JS `Error.message`.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

impl core::error::Error for BindError {}

impl From<Error> for BindError {
    /// A validation failure keeps the spec §2.2 name of its rule.
    fn from(error: Error) -> Self {
        Self::new(error.name(), error.to_string())
    }
}

impl From<BuildError> for BindError {
    fn from(error: BuildError) -> Self {
        let name = match error {
            // A malformed input is reported under the validation rule that rejected it.
            BuildError::Malformed(inner) => return inner.into(),
            BuildError::TooManyParents { .. } => names::TOO_MANY_PARENTS,
            BuildError::PayloadTooLong { .. } => names::PAYLOAD_TOO_LONG,
            BuildError::DuplicateParent { .. } => names::DUPLICATE_PARENT,
            BuildError::KeyMismatch => names::KEY_MISMATCH,
            BuildError::DifficultyTooHigh { .. } => names::DIFFICULTY_TOO_HIGH,
            BuildError::Signing => names::SIGNING,
            BuildError::NonceSpaceExhausted => names::NONCE_SPACE_EXHAUSTED,
            BuildError::BufferTooSmall { .. } | BuildError::PowNotFound => names::INTERNAL,
        };
        Self::new(name, error.to_string())
    }
}

impl From<BindError> for wasm_bindgen::JsValue {
    /// Builds the JS `Error`. Only meaningful on wasm32: on a native target `js-sys` imports are not
    /// available, so the native tests check [`BindError`] itself, never this conversion.
    fn from(error: BindError) -> Self {
        let js = js_sys::Error::new(&error.message);
        js.set_name(error.name);
        js.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbtp_core::BlockId;

    #[test]
    fn validation_errors_keep_the_spec_name() {
        let cases = [
            Error::TooShort { len: 3 },
            Error::TooLong { len: 70_000 },
            Error::BadMagic { found: [0, 0] },
            Error::UnsupportedVersion { version: 2 },
            Error::TooManyParents { count: 9 },
            Error::Truncated {
                expected_min: 200,
                len: 150,
            },
            Error::TrailingBytes {
                expected: 118,
                len: 119,
            },
            Error::DuplicateParent {
                first: 0,
                second: 1,
            },
            Error::BlockIdMismatch {
                expected: BlockId([0; 32]),
                actual: BlockId([1; 32]),
            },
            Error::InsufficientPow {
                required: 8,
                actual: 2,
            },
            Error::InvalidPublicKey,
            Error::InvalidSignature,
        ];
        for error in cases {
            let bind = BindError::from(error);
            assert_eq!(bind.name(), error.name());
            assert_eq!(bind.message(), error.to_string());
        }
    }

    #[test]
    fn malformed_build_error_reports_the_validation_rule() {
        let bind = BindError::from(BuildError::Malformed(Error::BadMagic { found: [1, 2] }));
        assert_eq!(bind.name(), "BadMagic");
    }

    #[test]
    fn build_errors_have_stable_names() {
        let cases = [
            (BuildError::KeyMismatch, "KeyMismatch"),
            (
                BuildError::DifficultyTooHigh { difficulty: 300 },
                "DifficultyTooHigh",
            ),
            (BuildError::Signing, "Signing"),
            (BuildError::PayloadTooLong { len: 70_000 }, "PayloadTooLong"),
            (BuildError::TooManyParents { count: 9 }, "TooManyParents"),
            (
                BuildError::DuplicateParent {
                    first: 0,
                    second: 1,
                },
                "DuplicateParent",
            ),
            (BuildError::PowNotFound, "Internal"),
            (BuildError::NonceSpaceExhausted, "NonceSpaceExhausted"),
        ];
        for (error, name) in cases {
            assert_eq!(BindError::from(error).name(), name);
        }
    }
}
