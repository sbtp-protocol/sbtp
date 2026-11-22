//! `SigningMessage`: the bytes an external Ed25519 signer receives, built by a typed builder only
//! (ADR 0055 E1; core spec §3.5).
//!
//! A `SigningMessage` comes out of `signingMessage(block)` (kind `"block"`: `SIG_PREFIX ‖
//! block_id`, spec §3.2) or `SealPending.message` (kind `"sealed"`: the sealed signature message of
//! `l2-grammar.md` §5.3). There is no constructor and no function that turns caller bytes into one,
//! so a signer that accepts only a `SigningMessage` (checked with `instanceof` at run time, and by
//! the brand of the shipped `.d.ts` at compile time) only ever signs messages built here.

use core::fmt;

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The kind of a [`SigningMessage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    /// `SIG_PREFIX ‖ block_id` (spec §3.2), 49 bytes.
    Block,
    /// `SBTP-v1-sealed-sig ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519 ‖ msg` (spec §5.3).
    Sealed,
}

impl MessageKind {
    /// The JS name of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Sealed => "sealed",
        }
    }
}

/// A message built by a typed builder, for an external Ed25519 signer (ADR 0055 E1). A sealed
/// message holds the plaintext `msg`: the copy held here is wiped on `free()`; the copies returned
/// by `bytes` belong to the caller (`fill(0)` them after signing).
#[wasm_bindgen]
pub struct SigningMessage {
    bytes: Zeroizing<Vec<u8>>,
    kind: MessageKind,
}

impl fmt::Debug for SigningMessage {
    /// The kind and the length only: a sealed message holds the plaintext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningMessage")
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl SigningMessage {
    /// Crate-private: only the typed builders of this crate create one.
    pub(crate) fn new(kind: MessageKind, bytes: &[u8]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            kind,
        }
    }

    /// The message bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The kind of message.
    #[must_use]
    pub const fn message_kind(&self) -> MessageKind {
        self.kind
    }
}

#[wasm_bindgen]
impl SigningMessage {
    /// A copy of the exact bytes to hand to the signer (Web Crypto
    /// `sign("Ed25519", key, message.bytes)`). Sign them, and nothing else, for this block or seal.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// `"block"` (spec §3.2) or `"sealed"` (spec §5.3).
    #[wasm_bindgen(getter, unchecked_return_type = "\"block\" | \"sealed\"")]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.as_str().into()
    }
}

// Compile-time brand of the shipped declarations: a `Uint8Array`, or an object literal with the
// same members, is not a `SigningMessage`. `export {}` keeps the brand symbol out of the module's
// exports, so no caller can name it.
#[wasm_bindgen(typescript_custom_section)]
const SIGNING_MESSAGE_BRAND: &str = r#"
declare const signingMessageBrand: unique symbol;
export interface SigningMessage {
  /** Type-level brand only (absent at run time): built by signingMessage or SealPending.message. */
  readonly [signingMessageBrand]: true;
}
export {};
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_and_bytes() {
        let block = SigningMessage::new(MessageKind::Block, &[7; 49]);
        assert_eq!(block.kind(), "block");
        assert_eq!(block.message_kind(), MessageKind::Block);
        assert_eq!(block.bytes(), vec![7; 49]);
        assert_eq!(block.as_bytes(), &[7; 49]);
        assert_eq!(
            SigningMessage::new(MessageKind::Sealed, b"x").kind(),
            "sealed"
        );
    }

    #[test]
    fn debug_shows_no_bytes() {
        let sealed = SigningMessage::new(MessageKind::Sealed, b"secret plaintext");
        assert_eq!(
            format!("{sealed:?}"),
            "SigningMessage { kind: Sealed, len: 16 }"
        );
    }
}
