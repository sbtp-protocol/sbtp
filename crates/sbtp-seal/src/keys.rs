//! X25519 recipient keys (spec §5.5) and the fixed HPKE suite (spec §5.1).

use core::fmt;

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem as _, Serializable};
use zeroize::Zeroizing;

/// The only KEM: DHKEM(X25519, HKDF-SHA256), `0x0020` (spec §5.1).
pub(crate) type Kem = hpke::kem::X25519HkdfSha256;
/// The only KDF: HKDF-SHA256, `0x0001` (spec §5.1).
pub(crate) type Kdf = hpke::kdf::HkdfSha256;
/// The only AEAD: `ChaCha20Poly1305`, `0x0003` (spec §5.1).
pub(crate) type Aead = hpke::aead::ChaCha20Poly1305;

type PrivateKey = <Kem as hpke::Kem>::PrivateKey;

/// An X25519 HPKE recipient key pair: the private key that opens sealed blocks and the public
/// key published in an `sbtp.enc_key` body (spec §5.5).
///
/// The private key is wiped on drop (`x25519-dalek`'s `StaticSecret`). There is no `Debug`
/// output of it: [`fmt::Debug`] prints the public key only.
#[derive(Clone)]
pub struct RecipientKey {
    secret: PrivateKey,
    public: [u8; 32],
}

impl RecipientKey {
    /// A fresh key pair from `rng` (spec §5.5: generated independently of the identity key, from
    /// a secure random source). Pass the operating system's source; a seeded generator is for
    /// tests only (spec §5.1).
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let (secret, public) = Kem::gen_keypair_with_rng(rng);
        Self::from_parts(secret, &public)
    }

    /// The key pair of stored private key bytes. The bytes are clamped (RFC 7748 §5) by the
    /// HPKE library.
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let secret = PrivateKey::from_bytes(bytes).ok()?;
        let public = Kem::sk_to_pk(&secret);
        Some(Self::from_parts(secret, &public))
    }

    /// The key pair derived from `ikm` by RFC 9180 §7.1.3 `DeriveKeyPair`. For known-answer
    /// tests and test keys from public seeds; never with low-entropy input in production, and
    /// never from a password or an identity seed (spec §5.5: generated independently). Hidden
    /// from the documentation for that reason.
    #[doc(hidden)]
    #[must_use]
    pub fn derive(ikm: &[u8]) -> Self {
        let (secret, public) = Kem::derive_keypair(ikm);
        Self::from_parts(secret, &public)
    }

    fn from_parts(secret: PrivateKey, public: &<Kem as hpke::Kem>::PublicKey) -> Self {
        Self {
            secret,
            public: public.to_bytes().into(),
        }
    }

    /// The X25519 public key, the `x25519` field of an `sbtp.enc_key` body (spec §5.5).
    #[must_use]
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The private key bytes, for storage (spec §5.5, "Storage"). Wiped when the returned value
    /// is dropped (best effort: the library's serialisation goes through a temporary on the
    /// stack). Never log them.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes().into())
    }

    pub(crate) const fn secret(&self) -> &PrivateKey {
        &self.secret
    }
}

impl fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
