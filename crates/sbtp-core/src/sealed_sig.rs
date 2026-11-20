//! The inner signature of a sealed payload (`l2-grammar.md` §5.3, ADR 0016 rule 15).
//!
//! Inside a sealed plaintext, `sig` is a pure Ed25519 signature by the sender's identity key
//! `from` over
//!
//! ```text
//! SEALED_SIG_PREFIX ‖ outer_pubkey (32) ‖ recipient_id (32) ‖ recipient_x25519_pubkey (32) ‖ msg
//! ```
//!
//! This module is the typed builder that `l2-grammar.md` §5.3 requires ("implementations expose
//! this message through a typed builder only, never a generic signature of arbitrary bytes"):
//! [`sealed_sig_message`] is the only constructor of a [`SealedSigMessage`], and
//! [`sign_sealed`] and [`verify_sealed`] accept nothing else. Verification is strict, criteria V1
//! to V6 of spec §3.2, with this message in place of the block message; batch verification is
//! never used (ADR 0003 rule 14).
//!
//! No allocation: the message is written into a buffer the caller provides, at least
//! [`sealed_sig_message_len`] bytes long. `ed25519-dalek`'s streaming verifier is not used: it
//! needs the `hazmat` feature and does not check that `R` is of small order (V5).
//!
//! What this module does not do (left to the sealing layer, `l2-grammar.md` §5.2 and §5.3):
//! decrypting, padding, decoding the plaintext item, choosing `recipient_id`, and the rule that a
//! sealed block whose `PubKey` equals `from` is ignored.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::consts::SEALED_SIG_PREFIX;
use crate::layout::{PUBKEY_LEN, SIGNATURE_LEN};
use crate::verify::check_public_key;

/// Length of the fixed part of the message, before `msg`: the prefix and the three 32-byte
/// fields, 114 bytes (`l2-grammar.md` §5.3).
pub const SEALED_SIG_FIXED_LEN: usize = SEALED_SIG_PREFIX.len() + 3 * PUBKEY_LEN;

/// Length of the message for a `msg` of `msg_len` bytes, or `None` if it overflows `usize`.
#[must_use]
pub const fn sealed_sig_message_len(msg_len: usize) -> Option<usize> {
    SEALED_SIG_FIXED_LEN.checked_add(msg_len)
}

/// Why the inner signature of a sealed payload could not be built, made or verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedSigError {
    /// The caller's buffer is shorter than the message (not a spec rule: a caller error).
    BufferTooSmall {
        /// Bytes needed, or `None` if the length overflows `usize`.
        needed: Option<usize>,
        /// Bytes available.
        len: usize,
    },
    /// The sender key `from` fails criterion V1 or V2 (spec §3.2): not the canonical encoding of
    /// a point, or of small order.
    InvalidSenderKey,
    /// The signature fails a criterion among V3 to V6 (spec §3.2) over the sealed message.
    InvalidSignature,
    /// The signer failed.
    Signing,
}

impl fmt::Display for SealedSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall {
                needed: Some(needed),
                len,
            } => write!(
                f,
                "sealed signature buffer too small: {len} bytes, {needed} needed"
            ),
            Self::BufferTooSmall { needed: None, len } => write!(
                f,
                "sealed signature buffer too small: {len} bytes, message length overflows"
            ),
            Self::InvalidSenderKey => f.write_str("invalid sealed sender key"),
            Self::InvalidSignature => f.write_str("invalid sealed signature"),
            Self::Signing => f.write_str("signing failed"),
        }
    }
}

impl core::error::Error for SealedSigError {}

/// The message signed by the inner signature of a sealed payload (`l2-grammar.md` §5.3). Its only
/// constructor is [`sealed_sig_message`], so it always starts with [`SEALED_SIG_PREFIX`] and
/// holds the three fixed-length fields before `msg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedSigMessage<'b>(&'b [u8]);

impl<'b> SealedSigMessage<'b> {
    /// The message bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'b [u8] {
        self.0
    }
}

/// Builds the message of the inner signature of a sealed payload into `buf`
/// (`l2-grammar.md` §5.3, ADR 0016 rule 15):
/// `SEALED_SIG_PREFIX ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519 ‖ msg`.
///
/// - `outer_pubkey`: the `PubKey` field of the outer `sbtp.enc` block (the ephemeral signer);
/// - `recipient_id`: the 32-byte identity the application that defines the tag fixes (§5.4);
///   a recipient passes **its own**, never one read from the plaintext;
/// - `recipient_x25519`: the X25519 key the block was sealed to; a recipient passes the key that
///   opened the block;
/// - `msg`: the `msg` byte string of the plaintext, as received.
///
/// The message is the first [`sealed_sig_message_len`]`(msg.len())` bytes of `buf`; the rest of
/// `buf` is left untouched.
///
/// # Errors
///
/// [`SealedSigError::BufferTooSmall`].
pub fn sealed_sig_message<'b>(
    outer_pubkey: &[u8; PUBKEY_LEN],
    recipient_id: &[u8; PUBKEY_LEN],
    recipient_x25519: &[u8; PUBKEY_LEN],
    msg: &[u8],
    buf: &'b mut [u8],
) -> Result<SealedSigMessage<'b>, SealedSigError> {
    let len = buf.len();
    let needed = sealed_sig_message_len(msg.len());
    let too_small = SealedSigError::BufferTooSmall { needed, len };
    let out = needed.and_then(|n| buf.get_mut(..n)).ok_or(too_small)?;
    // spec §5.3: the four fixed-length fields first, then `msg`, so the message has one parse.
    let (prefix, rest) = out.split_at_mut(SEALED_SIG_PREFIX.len());
    prefix.copy_from_slice(&SEALED_SIG_PREFIX);
    let (outer, rest) = rest.split_at_mut(PUBKEY_LEN);
    outer.copy_from_slice(outer_pubkey);
    let (id, rest) = rest.split_at_mut(PUBKEY_LEN);
    id.copy_from_slice(recipient_id);
    let (x25519, rest) = rest.split_at_mut(PUBKEY_LEN);
    x25519.copy_from_slice(recipient_x25519);
    rest.copy_from_slice(msg);
    Ok(SealedSigMessage(out))
}

/// Signs a sealed message with the sender's identity key (`l2-grammar.md` §5.3): a pure,
/// deterministic Ed25519 signature (RFC 8032 §5.1, §5.1.6), the `sig` of the plaintext.
///
/// # Errors
///
/// [`SealedSigError::Signing`] if the signer fails.
pub fn sign_sealed(
    key: &SigningKey,
    message: &SealedSigMessage<'_>,
) -> Result<[u8; SIGNATURE_LEN], SealedSigError> {
    key.try_sign(message.0)
        .map(|signature| signature.to_bytes())
        .map_err(|_| SealedSigError::Signing)
}

/// Strict verification of the inner signature `sig` of a sealed payload by `from`
/// (`l2-grammar.md` §5.3): criteria V1 to V6 of spec §3.2 with `A = from` and `M` the sealed
/// message, in that order. Never uses batch verification (ADR 0003 rule 14).
///
/// # Errors
///
/// [`SealedSigError::InvalidSenderKey`] for V1 and V2, [`SealedSigError::InvalidSignature`] for
/// V3 to V6.
pub fn verify_sealed(
    from: &[u8; PUBKEY_LEN],
    sig: &[u8; SIGNATURE_LEN],
    message: &SealedSigMessage<'_>,
) -> Result<(), SealedSigError> {
    // spec §3.2 V1 and V2, as for a block (ADR 0003 rule 13 steps 1 to 3).
    let key = check_public_key(from).map_err(|_| SealedSigError::InvalidSenderKey)?;
    // spec §3.2 V3 to V6: `Signature::from_bytes` validates nothing; `verify_strict` checks
    // S < L, R decodes, R not of small order, and the cofactorless equation byte for byte.
    let signature = Signature::from_bytes(sig);
    key.verify_strict(message.0, &signature)
        .map_err(|_| SealedSigError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SIG_PREFIX;

    /// Test keys from the documented public seeds.
    fn sender() -> SigningKey {
        SigningKey::from_bytes(&[0x01; 32])
    }
    fn other() -> SigningKey {
        SigningKey::from_bytes(&[0x02; 32])
    }

    const OUTER: [u8; 32] = [0x11; 32];
    const RECIPIENT: [u8; 32] = [0x22; 32];
    const X25519: [u8; 32] = [0x33; 32];
    const MSG: &[u8] = b"a grammar payload";

    /// `outer_pubkey`, `recipient_id`, `recipient_x25519`, `msg`.
    type Fields<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8; 32], &'a [u8]);

    fn build<'b>(
        outer: &[u8; 32],
        id: &[u8; 32],
        x: &[u8; 32],
        msg: &[u8],
        buf: &'b mut [u8],
    ) -> SealedSigMessage<'b> {
        sealed_sig_message(outer, id, x, msg, buf).unwrap()
    }

    // spec §5.3: the layout, field by field, and the fixed length.
    #[test]
    fn message_layout() {
        assert_eq!(SEALED_SIG_FIXED_LEN, 114);
        let mut buf = [0xee; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let b = m.as_bytes();
        assert_eq!(b.len(), 114 + MSG.len());
        assert_eq!(&b[..18], b"SBTP-v1-sealed-sig");
        assert_eq!(&b[18..50], &OUTER);
        assert_eq!(&b[50..82], &RECIPIENT);
        assert_eq!(&b[82..114], &X25519);
        assert_eq!(&b[114..], MSG);
        // The rest of the buffer is untouched.
        assert!(buf[114 + MSG.len()..].iter().all(|&x| x == 0xee));
    }

    // An empty `msg` is a well-formed message (the grammar rejects it later, not this layer).
    #[test]
    fn empty_msg() {
        let mut buf = [0; SEALED_SIG_FIXED_LEN];
        let m = build(&OUTER, &RECIPIENT, &X25519, &[], &mut buf);
        assert_eq!(m.as_bytes().len(), SEALED_SIG_FIXED_LEN);
    }

    // `BufferTooSmall`: one byte short, and an empty buffer.
    #[test]
    fn buffer_too_small() {
        let mut buf = [0; 114 + 16];
        assert_eq!(
            sealed_sig_message(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf),
            Err(SealedSigError::BufferTooSmall {
                needed: Some(131),
                len: 130
            })
        );
        assert_eq!(
            sealed_sig_message(&OUTER, &RECIPIENT, &X25519, MSG, &mut []),
            Err(SealedSigError::BufferTooSmall {
                needed: Some(131),
                len: 0
            })
        );
        assert_eq!(sealed_sig_message_len(usize::MAX), None);
    }

    // spec §5.3: positive case, sign then verify.
    #[test]
    fn sign_then_verify() {
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let sig = sign_sealed(&sender(), &m).unwrap();
        let from = sender().verifying_key().to_bytes();
        assert_eq!(verify_sealed(&from, &sig, &m), Ok(()));
        // Deterministic (RFC 8032 §5.1.6).
        assert_eq!(sign_sealed(&sender(), &m).unwrap(), sig);
    }

    // spec §5.3: the signature binds every field. A recipient that rebuilds the message with
    // another outer PubKey, another identity, another X25519 key or another `msg` rejects it,
    // and so does a check against another sender key.
    #[test]
    fn every_field_is_bound() {
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let sig = sign_sealed(&sender(), &m).unwrap();
        let from = sender().verifying_key().to_bytes();
        let other_key = other().verifying_key().to_bytes();
        assert_eq!(
            verify_sealed(&other_key, &sig, &m),
            Err(SealedSigError::InvalidSignature)
        );
        let flip = [0x44; 32];
        let variants: [Fields<'_>; 4] = [
            (&flip, &RECIPIENT, &X25519, MSG),
            (&OUTER, &flip, &X25519, MSG),
            (&OUTER, &RECIPIENT, &flip, MSG),
            (&OUTER, &RECIPIENT, &X25519, b"another grammar payload"),
        ];
        for (i, (outer, id, x, msg)) in variants.into_iter().enumerate() {
            let mut buf = [0; 200];
            let m = build(outer, id, x, msg, &mut buf);
            assert_eq!(
                verify_sealed(&from, &sig, &m),
                Err(SealedSigError::InvalidSignature),
                "field {i}"
            );
        }
    }

    // Domain separation (spec §3.5): a block signature over `SIG_PREFIX ‖ id` is never a valid
    // sealed signature, even when the sealed message holds the same 32 bytes.
    #[test]
    fn block_signature_is_not_a_sealed_signature() {
        let id = crate::BlockId([0x55; 32]);
        let block_sig = crate::sign_block_id(&sender(), &id).unwrap();
        let from = sender().verifying_key().to_bytes();
        let mut buf = [0; 200];
        let m = build(&id.0, &id.0, &id.0, &[], &mut buf);
        assert_eq!(
            verify_sealed(&from, &block_sig, &m),
            Err(SealedSigError::InvalidSignature)
        );
        assert!(!m.as_bytes().starts_with(&SIG_PREFIX));
    }

    // spec §3.2 V1 and V2 on `from`: `InvalidSenderKey`.
    #[test]
    fn invalid_sender_key() {
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let sig = sign_sealed(&sender(), &m).unwrap();
        // V1: y = 2 is not on the curve.
        let mut not_on_curve = [0u8; 32];
        not_on_curve[0] = 2;
        // V1: y = 3 + p, a non-canonical encoding of a point not of small order.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xed + 3;
        non_canonical[31] = 0x7f;
        // V2: the identity point (y = 1), canonical and of small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        for (i, key) in [not_on_curve, non_canonical, identity].iter().enumerate() {
            assert_eq!(
                verify_sealed(key, &sig, &m),
                Err(SealedSigError::InvalidSenderKey),
                "case {i}"
            );
        }
    }

    // spec §3.2 V3: `S + L` in place of `S`, accepted by a lax verifier, rejected here.
    #[test]
    fn v3_s_plus_l() {
        // L, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let mut sig = sign_sealed(&sender(), &m).unwrap();
        let mut carry = 0u16;
        for (s, l) in sig[32..].iter_mut().zip(L) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        let from = sender().verifying_key().to_bytes();
        assert_eq!(
            verify_sealed(&from, &sig, &m),
            Err(SealedSigError::InvalidSignature)
        );
    }

    // spec §3.2 V4 and V5: `R` not on the curve, `R` of small order (the identity point).
    #[test]
    fn v4_v5_bad_r() {
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let good = sign_sealed(&sender(), &m).unwrap();
        let from = sender().verifying_key().to_bytes();
        for r0 in [2u8, 1] {
            let mut sig = good;
            sig[..32].fill(0);
            sig[0] = r0;
            assert_eq!(
                verify_sealed(&from, &sig, &m),
                Err(SealedSigError::InvalidSignature),
                "R y = {r0}"
            );
        }
    }

    // spec §3.2 V6: one bit flipped in the signature.
    #[test]
    fn v6_flipped_bit() {
        let mut buf = [0; 200];
        let m = build(&OUTER, &RECIPIENT, &X25519, MSG, &mut buf);
        let mut sig = sign_sealed(&sender(), &m).unwrap();
        sig[40] ^= 0x01;
        let from = sender().verifying_key().to_bytes();
        assert_eq!(
            verify_sealed(&from, &sig, &m),
            Err(SealedSigError::InvalidSignature)
        );
    }
}
