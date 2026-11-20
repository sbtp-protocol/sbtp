//! Why a layer 2 payload is invalid: one variant per rule of `l2-grammar.md` §1 to §3.

use core::fmt;

/// The first rule a payload breaks. An invalid payload is ignored by a client (spec §2.4); the block
/// that carries it stays a valid layer 0 block.
///
/// The variants are generic: an application's validation reuses them for its own kinds (the row
/// and body variants) and wraps them in its own error type for the rules only it defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2Error {
    // --- Caller precondition, core spec §2.2 (ADR 0014) ---
    /// More than 8 header parents were passed in. A parsed block never has more; this guards a
    /// caller that builds the parents slice by hand.
    TooManyParents,

    // --- CBOR profile, spec §1.2 (ADR 0011) ---
    /// The payload is longer than 65,535 bytes (ADR 0011 rule 11).
    PayloadTooLong,
    /// The input ends inside a data item (empty payload included).
    Truncated,
    /// Bytes follow the single data item (ADR 0011 rule 11).
    TrailingBytes,
    /// Reserved additional information (28 to 30), or a "break" byte or indefinite length on a type
    /// that has none (RFC 8949 §3, not well-formed).
    Malformed,
    /// An integer, length or count is not in its shortest form (ADR 0011 rules 1 and 6).
    NonShortestForm,
    /// An indefinite-length string, array or map (ADR 0011 rule 1).
    IndefiniteLength,
    /// A floating-point value (ADR 0011 rule 7).
    Float,
    /// A tag, major type 6 (ADR 0011 rule 8).
    Tag,
    /// A simple value other than `false`, `true` and `null` (ADR 0011 rule 9).
    SimpleValue,
    /// A map key that is not a text string (ADR 0011 rule 5).
    MapKeyNotText,
    /// Map keys not in the bytewise order of their encodings (ADR 0011 rule 4).
    MapKeysUnsorted,
    /// Two equal keys in one map (ADR 0011 rule 5).
    DuplicateMapKey,
    /// A text string that is not valid UTF-8 (ADR 0011 rule 10).
    InvalidUtf8,

    // --- Envelope, spec §1.3 (ADR 0015 rules 1 to 5) ---
    /// The payload is not a map with exactly the keys `v`, `kind`, `edges`, `body`.
    BadEnvelope,
    /// `v` is not the unsigned integer 1.
    UnsupportedVersion,
    /// `kind` is not a text string of 3 to 64 bytes made of two or more labels.
    InvalidKind,
    /// `edges` is not an array.
    EdgesNotArray,
    /// `edges` holds more than 64 edges.
    TooManyEdges,
    /// `body` has a CBOR type its kind does not allow, or a map expected inside a body is not a
    /// map.
    BodyType,

    // --- Edges, spec §2.1 to §2.3 (ADR 0015 rules 7 to 15) ---
    /// An edge is not a map with exactly one target key, `rel` and optionally `meta`.
    EdgeShape,
    /// `p` is not an unsigned integer, or `block` / `chunk` is not a 32-byte byte string.
    EdgeTargetValue,
    /// `p` is not lower than the Parents Count.
    ParentIndexOutOfRange,
    /// A header parent is named by no causal edge (coverage).
    UncoveredParent,
    /// Two edges carry the same `p` (coverage).
    DuplicateParentIndex,
    /// The causal edges are not first, in increasing `p`.
    EdgeOrder,
    /// A `block` target equals one of the block's header parents.
    BlockTargetIsParent,
    /// `meta` is not a map, or is an empty map.
    BadMeta,
    /// `meta` is present on a registry verb that takes none.
    MetaNotAllowed,
    /// `meta` holds a key the registry does not allow for the verb.
    MetaUnknownKey,
    /// A `meta` value has the wrong type or range, or a required `meta` key is missing.
    MetaValue,
    /// A registry verb is used with a target form outside its registry row.
    TargetFormNotAllowed,
    /// A verb with the `x.` prefix that is not of the form `x.<app>.<verb>`.
    InvalidExtensionVerb,
    /// A `rel` that is not a text string of 1 to 64 bytes, or an unknown verb (no `x.` prefix, not
    /// a registry verb) that is not one label (spec §2.3).
    InvalidVerb,
    /// A `tagged` edge on a kind other than `sbtp.enc` and `sbtp.enc_key`, application kinds
    /// included (spec §2.2, §5.4).
    TaggedNotAllowed,

    // --- Kinds, spec §3, §3.1 and §2.5 ---
    /// The block's Parents Count is outside the range of its kind's row.
    KindParentCount,
    /// A registry verb that the kind's row does not list.
    EdgeNotAllowedForKind,
    /// A required edge of the kind's row is missing.
    MissingRequiredEdge,
    /// A registry verb appears more often than its kind's multiplicity allows: a required verb more
    /// than once, an optional verb more than once on a row that does not allow it any number of
    /// times, more than
    /// one edge of a `one_of` rule, or an extension or unknown verb on a kind whose edge set is
    /// closed (spec §3.1 and §2.3).
    EdgeMultiplicity,
    /// Two `composed_of` edges carry the same `seq`, whatever the kind (spec §2.2).
    DuplicateComposedSeq,
    /// A required body field is missing.
    BodyMissingField,
    /// A body field the kind's body rule does not define.
    BodyUnknownField,
    /// A body field has the wrong CBOR type (spec §2.5).
    BodyFieldValue,
    /// An empty array that the CDDL declares `[+ ...]`, such as `chunks` (spec §2.5).
    BodyEmptyArray,
    /// A body identifier (public key, `block_id`, `chunk_id`) or another 32-byte body field (the
    /// `enc` of `sbtp.enc`) that is a byte string of another length than 32 bytes (spec §1.4,
    /// §2.5).
    BodyIdSize,
    /// An `sbtp.manifest` whose `chunk_size` is not 262,144 (spec §3).
    ManifestChunkSize,
    /// An `sbtp.manifest` whose `total_size` does not satisfy
    /// `(n − 1) × chunk_size < total_size ≤ n × chunk_size` for its `n` chunks (spec §3).
    ManifestTotalSize,
    /// An `sbtp.enc` payload whose length is not 512, 2,048, 8,192 or 65,535 bytes (spec §5.2,
    /// length buckets).
    EncPayloadLen,
    /// An `sbtp.enc` payload that is not 90 bytes plus its ciphertext `ct` (spec §5.2).
    EncCiphertextLen,
    /// An `sbtp.enc_key` whose `intro_bucket` is above 15 (spec §5.5).
    EncKeyIntroBucket,
}

impl fmt::Display for L2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for L2Error {}
