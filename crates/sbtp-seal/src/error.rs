//! Why a seal or an open failed: one variant per rule of `l2-grammar.md` §5.

use core::fmt;

use sbtp_l2::L2Error;

/// Why [`crate::seal`], [`crate::seal_prepare`] or [`crate::PendingSeal::finish`] refused to produce a sealed payload. The sender does not send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// `msg` is not a valid grammar payload for a block with 0 parents (spec §5.3). This also
    /// covers "`msg` MUST NOT be of kind `sbtp.enc`": the `sbtp.enc` row requires exactly 1
    /// parent (spec §3), so such a `msg` always fails here.
    MsgInvalid(L2Error),
    /// The plaintext item does not fit the requested bucket, or any bucket (spec §5.2).
    TooLong,
    /// The ephemeral signer equals the sender key `from` (spec §5.2, ephemeral signer).
    EphemeralIsSender,
    /// HPKE encapsulation failed: the recipient key yields an all-zero shared secret (spec §5.1,
    /// RFC 9180 §7.1.4), or the seal failed.
    Hpke,
    /// The inner signature could not be made (spec §5.3). Not reachable with `ed25519-dalek`'s
    /// signer, whose signing does not fail.
    Signing,
    /// `from` fails criterion V1 or V2 of core spec §3.2: no signature by it can verify
    /// (spec §5.3 `sig`; two-phase seal, [`crate::PendingSeal::finish`]).
    SenderKey,
    /// The signature given to [`crate::PendingSeal::finish`] fails a criterion among V3 to V6 of
    /// core spec §3.2 over the sealed message (spec §5.3 `sig`). Nothing is sealed.
    Signature,
    /// The outer payload failed its own grammar validation (spec §5.2). Not reachable with a
    /// conforming encoder; kept as defence in depth.
    Encoding(L2Error),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MsgInvalid(e) => write!(f, "msg is not a valid grammar payload: {e}"),
            Self::TooLong => f.write_str("plaintext item fits no allowed bucket"),
            Self::EphemeralIsSender => f.write_str("ephemeral signer equals the sender key"),
            Self::Hpke => f.write_str("HPKE seal failed"),
            Self::Signing => f.write_str("inner signature failed"),
            Self::SenderKey => f.write_str("invalid sender key"),
            Self::Signature => f.write_str("inner signature does not verify"),
            Self::Encoding(e) => write!(f, "outer payload invalid: {e}"),
        }
    }
}

impl core::error::Error for SealError {}

/// Why [`crate::open`] rejected a sealed block, in the order of the checks of spec §5.3 steps
/// (4) to (8). A recipient ignores the block silently and MUST NOT tell anyone which check
/// failed: these values are for local tests and diagnostics only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The ciphertext length is not that of a length bucket (spec §5.2). Grammar validation
    /// already enforces it; checked again before any HPKE work.
    CiphertextLength,
    /// HPKE Open failed with every key tried, or no key was given (spec §5.3 step 4).
    NoKeyOpens,
    /// The plaintext does not start with one data item of the deterministic profile
    /// (spec §5.3 steps 5 and 6, §1.2).
    ItemEncoding(L2Error),
    /// A byte after the item is not `0x00` (spec §5.3 step 5).
    Padding,
    /// The item is not a map with exactly `from` (32 bytes), `msg` (a byte string) and `sig`
    /// (64 bytes) (spec §5.3 step 6).
    ItemShape,
    /// `from` equals the outer `PubKey` (spec §5.2, §5.3 step 6).
    FromIsOuterPubKey,
    /// `from` fails criterion V1 or V2 of core spec §3.2 (spec §5.3 step 7).
    SenderKey,
    /// `sig` fails a criterion among V3 to V6 of core spec §3.2 (spec §5.3 step 7).
    Signature,
    /// `msg` is not a valid grammar payload for a block with 0 parents (spec §5.3 step 8). This
    /// also covers "`msg` MUST NOT be of kind `sbtp.enc`": the `sbtp.enc` row requires exactly 1
    /// parent (spec §3), so such a `msg` always fails here.
    MsgInvalid(L2Error),
    /// The kind of `msg` is not one the tag allows (spec §5.3 step 8, §5.4).
    MsgKindNotAllowed,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextLength => f.write_str("ciphertext length is not a bucket length"),
            Self::NoKeyOpens => f.write_str("no key opens the block"),
            Self::ItemEncoding(e) => write!(f, "plaintext item malformed: {e}"),
            Self::Padding => f.write_str("non-zero byte after the plaintext item"),
            Self::ItemShape => f.write_str("plaintext item has the wrong shape"),
            Self::FromIsOuterPubKey => f.write_str("from equals the outer PubKey"),
            Self::SenderKey => f.write_str("invalid sender key"),
            Self::Signature => f.write_str("invalid inner signature"),
            Self::MsgInvalid(e) => write!(f, "msg is not a valid grammar payload: {e}"),
            Self::MsgKindNotAllowed => f.write_str("msg kind not allowed by the tag"),
        }
    }
}

impl core::error::Error for OpenError {}

/// Why [`crate::application_tag`] refused a `derive_key` context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagError {
    /// The context starts with a reserved prefix (`SBTP ` or `SBTP-`) or is a prefix of a
    /// string of the core spec §3.5 registry (spec §5.4, core spec §3.5).
    ReservedContext,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedContext => f.write_str("tag context uses a reserved prefix"),
        }
    }
}

impl core::error::Error for TagError {}
