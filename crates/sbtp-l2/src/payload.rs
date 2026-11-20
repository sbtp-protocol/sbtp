//! The grammar payload `{v, kind, edges, body}` (spec §1.3, §2) and the bodies of the `sbtp.*`
//! kinds (spec §3).

use alloc::vec::Vec;

/// A 32-byte identifier: a `block_id`, a `chunk_id` or an Ed25519 public key (spec §1.4).
pub type Id = [u8; 32];

/// A validated grammar payload. Built by [`crate::validate_l2_invariants`]; encoded by
/// [`Payload::encode`]. Text and byte fields borrow from the decoded buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload<'a> {
    /// The `kind` (spec §1.3).
    pub kind: &'a str,
    /// The edges, in wire order: causal edges first, in increasing `p` (spec §2.1).
    pub edges: Vec<Edge<'a>>,
    /// The body, typed for the `sbtp.*` kinds of spec §3, raw for any other kind.
    pub body: Body<'a>,
}

/// One edge (spec §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge<'a> {
    /// The target.
    pub target: Target,
    /// The verb and its metadata.
    pub rel: Rel<'a>,
}

/// The target of an edge (spec §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// `p`: the header parent at that index (causal).
    Parent(u8),
    /// `block`: a `block_id` (not causal).
    Block(Id),
    /// `chunk`: a `chunk_id` (not causal).
    Chunk(Id),
}

impl Target {
    /// Whether the edge is causal (spec §2.1: its target key is `p`).
    #[must_use]
    pub const fn is_causal(&self) -> bool {
        matches!(self, Self::Parent(_))
    }
}

/// A verb with its `meta` (spec §2.2, §2.3). Registry verbs carry their typed metadata; the types
/// of `span`, `task_id` and `status` are provisional (`[Q-25]`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // the variants are the registry verbs of spec §2.2
pub enum Rel<'a> {
    Follows,
    In,
    Supersedes {
        reason: Option<&'a str>,
    },
    ComposedOf {
        seq: u64,
        mime: Option<&'a str>,
    },
    /// Filed under a delivery or directory tag; the target is not a block (spec §5.4).
    Tagged,
    RepliesTo,
    Cites {
        span: Option<(u64, u64)>,
    },
    Endorses,
    Opposes,
    Tombstones,
    Moderates,
    /// A published count over the target's supersession chain. Grammar validation checks its
    /// form; the one application kind that may carry it is checked by application validation
    /// (spec §2.2).
    Tallies,
    Supports {
        confidence: Option<u8>,
    },
    Refutes {
        confidence: Option<u8>,
    },
    Synthesizes,
    DelegatesTo {
        task_id: Option<&'a str>,
    },
    Fulfills {
        status: Option<&'a str>,
    },
    /// An extension verb `x.<app>.<verb>` (spec §2.3). `meta` is the encoded map, if any. Never used
    /// for state resolution.
    Extension {
        verb: &'a str,
        meta: Option<&'a [u8]>,
    },
    /// A verb outside the registry without the `x.` prefix, tolerated (spec §2.3). Never used for
    /// state resolution.
    Unknown {
        verb: &'a str,
        meta: Option<&'a [u8]>,
    },
}

impl<'a> Rel<'a> {
    /// The verb as it appears in `rel`.
    #[must_use]
    pub const fn verb(&self) -> &'a str {
        match self {
            Self::Follows => "follows",
            Self::In => "in",
            Self::Supersedes { .. } => "supersedes",
            Self::ComposedOf { .. } => "composed_of",
            Self::Tagged => "tagged",
            Self::RepliesTo => "replies_to",
            Self::Cites { .. } => "cites",
            Self::Endorses => "endorses",
            Self::Opposes => "opposes",
            Self::Tombstones => "tombstones",
            Self::Moderates => "moderates",
            Self::Tallies => "tallies",
            Self::Supports { .. } => "supports",
            Self::Refutes { .. } => "refutes",
            Self::Synthesizes => "synthesizes",
            Self::DelegatesTo { .. } => "delegates_to",
            Self::Fulfills { .. } => "fulfills",
            Self::Extension { verb, .. } | Self::Unknown { verb, .. } => verb,
        }
    }

    /// Whether the verb is a registry verb of spec §2.2.
    #[must_use]
    pub const fn is_registry(&self) -> bool {
        !matches!(self, Self::Extension { .. } | Self::Unknown { .. })
    }
}

/// The body, by kind (spec §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// `sbtp.manifest` (spec §3).
    Manifest(Manifest<'a>),
    /// `sbtp.enc`, the outer block of a sealed envelope (spec §5.2).
    Enc(Enc<'a>),
    /// `sbtp.enc_key`, an encryption key (spec §5.5).
    EncKey(EncKey),
    /// The body of any other kind, application kinds included: a map or a byte string, as encoded,
    /// not interpreted (spec §1.3, §2.4). An application that defines the kind validates it; a
    /// client that does not know the kind MUST NOT apply the block to any resolved state.
    Raw(&'a [u8]),
}

/// `sbtp.manifest` body (spec §3). `chunk_size` is always [`CHUNK_SIZE`]. Provisional `[Q-01]`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Manifest<'a> {
    pub mime: &'a str,
    pub total_size: u64,
    /// At least one `chunk_id`, in object order.
    pub chunks: Vec<Id>,
    pub duration_ms: Option<u64>,
    /// `(width, height)`.
    pub resolution: Option<(u64, u64)>,
}

/// The only `chunk_size` of a manifest (spec §2.5, ADR 0010).
pub const CHUNK_SIZE: u64 = 262_144;

/// `sbtp.enc` body (spec §5.2, CDDL `enc-body`): its shape only. Grammar validation opens
/// nothing: `ct` is not decrypted and `enc` is not checked as a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enc<'a> {
    /// The HPKE ciphertext.
    pub ct: &'a [u8],
    /// The HPKE encapsulated key, 32 bytes.
    pub enc: Id,
}

/// `sbtp.enc_key` body (spec §5.5, CDDL `enc-key-body`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncKey {
    /// The X25519 HPKE recipient key, 32 bytes.
    pub x25519: Id,
    /// 0 to [`MAX_INTRO_BUCKET`].
    pub intro_bucket: u8,
}

/// The Payload Len values allowed for an `sbtp.enc` block (spec §5.2, length buckets).
pub const ENC_PAYLOAD_LENS: [usize; 4] = [512, 2_048, 8_192, 65_535];

/// An `sbtp.enc` payload is this many bytes plus its ciphertext (spec §5.2).
pub const ENC_OVERHEAD: usize = 90;

/// The largest `intro_bucket` of an `sbtp.enc_key` (spec §5.5, CDDL `0..15`).
pub const MAX_INTRO_BUCKET: u8 = 15;
