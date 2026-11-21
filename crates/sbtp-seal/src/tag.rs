//! Tags (spec §5.4): the key directory tag of §5.5, and a checked `derive_key` for the tags an
//! application defines.

use sbtp_core::consts::{
    BLOCK_ID_CONTEXT, ENC_KEY_DIRECTORY_CONTEXT, SEALED_HPKE_INFO, SEALED_SIG_PREFIX, SIG_PREFIX,
};

use crate::TagError;

/// A 32-byte tag, carried as a header parent value (spec §5.4). Not a `block_id`.
pub type Tag = [u8; 32];

/// The directory tag of an identity:
/// `derive_key("SBTP 2026-11-20 enc_key directory v1", identity_pubkey)` (spec §5.5).
#[must_use]
pub fn directory_tag(identity_pubkey: &[u8; 32]) -> Tag {
    // spec §5.5, core spec §3.5.
    blake3::derive_key(ENC_KEY_DIRECTORY_CONTEXT, identity_pubkey)
}

/// The state resolution check of spec §5.5 ("Tag and `PubKey`"): whether `tag`, the `tagged`
/// parent of a key block, is the directory tag of `pubkey`, the block's `PubKey`. A client that
/// reads a key directory MUST ignore a key block for which this is `false`.
#[must_use]
pub fn is_directory_tag(pubkey: &[u8; 32], tag: &Tag) -> bool {
    // Public values on both sides: a plain comparison is enough.
    directory_tag(pubkey) == *tag
}

/// A tag of an application: `derive_key(context, inputs[0] ‖ inputs[1] ‖ …)` (spec §5.4). The
/// application states the context and the inputs in its own specification; this function only
/// concatenates the inputs, in order, with no separator or length prefix.
///
/// # Errors
///
/// [`TagError::ReservedContext`] if `context` starts with `SBTP ` or `SBTP-`, or is a prefix of
/// a string of the core spec §3.5 registry (the empty string included).
pub fn application_tag(context: &str, inputs: &[&[u8]]) -> Result<Tag, TagError> {
    // spec §5.4, core spec §3.5 "Reserved prefixes".
    let c = context.as_bytes();
    let registry: [&[u8]; 5] = [
        BLOCK_ID_CONTEXT.as_bytes(),
        &SIG_PREFIX,
        &SEALED_HPKE_INFO,
        &SEALED_SIG_PREFIX,
        ENC_KEY_DIRECTORY_CONTEXT.as_bytes(),
    ];
    if c.starts_with(b"SBTP ")
        || c.starts_with(b"SBTP-")
        || registry.iter().any(|s| s.starts_with(c))
    {
        return Err(TagError::ReservedContext);
    }
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for input in inputs {
        hasher.update(input);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec §5.5: the directory tag is the `derive_key` of the identity key under its context,
    // and differs from a `block_id`-context derivation of the same bytes.
    #[test]
    fn directory_tag_derivation() {
        let id = [0x07; 32];
        let tag = directory_tag(&id);
        assert_eq!(
            tag,
            blake3::derive_key("SBTP 2026-11-20 enc_key directory v1", &id)
        );
        assert_ne!(tag, blake3::derive_key(BLOCK_ID_CONTEXT, &id));
        assert!(is_directory_tag(&id, &tag));
        assert!(!is_directory_tag(&[0x08; 32], &tag));
    }

    // spec §5.4: an application context is used as given, inputs concatenated.
    #[test]
    fn application_tag_concatenates() {
        let ctx = "example 2026-11-21 test tag v1";
        let tag = application_tag(ctx, &[b"ab", b"cd"]).unwrap();
        assert_eq!(tag, blake3::derive_key(ctx, b"abcd"));
        assert_eq!(application_tag(ctx, &[b"abcd"]).unwrap(), tag);
    }

    // core spec §3.5: reserved prefixes and prefixes of registry strings are refused.
    #[test]
    fn reserved_context() {
        for ctx in [
            "",
            "S",
            "SBTP",
            "SBTP ",
            "SBTP 2026-11-20 enc_key directory v1",
            "SBTP x",
            "SBTP-v1-sealed-sig",
            "SBTP-anything",
        ] {
            assert_eq!(
                application_tag(ctx, &[]),
                Err(TagError::ReservedContext),
                "{ctx:?}"
            );
        }
        assert!(application_tag("SBTPx", &[]).is_ok());
        assert!(application_tag("T", &[]).is_ok());
    }
}
