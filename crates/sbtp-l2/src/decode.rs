//! `validate_l2_invariants`: strict decoding and checking of a grammar payload (spec §2.4,
//! grammar validation).

use alloc::vec::Vec;

use sbtp_core::BlockId;

use crate::L2Error;
use crate::body::{self, BAD, closed_map, required};
use crate::cbor::{self, Major, Reader};
use crate::payload::{
    Body, CHUNK_SIZE, ENC_OVERHEAD, ENC_PAYLOAD_LENS, Edge, Enc, EncKey, MAX_INTRO_BUCKET,
    Manifest, Payload, Rel, Target,
};

/// Most edges in one payload (spec §1.3).
pub const MAX_EDGES: u64 = 64;

/// Most header parents of a block (core spec §2.2, ADR 0014; spec §2.1).
pub const MAX_PARENTS: usize = 8;

/// Decodes and checks a payload against the header parents of the block that carries it.
///
/// Applies spec §1.2 (CBOR profile), §1.3 (envelope), §2.1 to §2.3 (edges, registry, distinct
/// `composed_of` sequence numbers, verb syntax, extension verbs, with the tolerance for an unknown
/// verb, `tagged` only on `sbtp.enc` and `sbtp.enc_key`), and, for the `sbtp.*` kinds of spec
/// §3, their row (§3.1) and their body rule, with the length rules of `sbtp.enc` (§5.2). It
/// opens no ciphertext and checks no key. It knows
/// no application kind: the payload of any other kind passes with its body checked for type only,
/// a map or a byte string, returned as [`Body::Raw`] for the application validation (spec §2.4).
/// It reads no other block. Its cost is linear in the payload size (spec §2.4).
///
/// `parents` are the header parents in header order; only their count and, for the rule "a `block`
/// value MUST NOT equal one of the block's header parents" (spec §2.1), their values are used. A
/// block has at most 8 parents (core spec §2.2); a longer slice cannot come from a parsed block and
/// is rejected with [`L2Error::TooManyParents`] before the payload is read.
///
/// This checks the payload only. It does not make the block authentic: the caller verifies the
/// block (PoW and signature, with `sbtp-core`) before trusting what it says.
///
/// # Errors
///
/// The [`L2Error`] of the first broken rule. A client ignores such a payload; it never fails on it.
pub fn validate_l2_invariants<'a>(
    parents: &[BlockId],
    payload: &'a [u8],
) -> Result<Payload<'a>, L2Error> {
    if parents.len() > MAX_PARENTS {
        return Err(L2Error::TooManyParents); // core spec §2.2, ADR 0014
    }
    cbor::check_profile(payload)?;
    let mut r = Reader::new(payload);
    // spec §1.3: exactly the four keys; the profile sorts them as v, body, kind, edges.
    if r.expect(Major::Map, L2Error::BadEnvelope)? != 4 {
        return Err(L2Error::BadEnvelope);
    }
    expect_key(&mut r, "v")?;
    if r.uint(L2Error::UnsupportedVersion)? != 1 {
        return Err(L2Error::UnsupportedVersion); // spec §1.3
    }
    expect_key(&mut r, "body")?;
    let body_raw = r.skip()?;
    expect_key(&mut r, "kind")?;
    let kind_str = r.text(L2Error::InvalidKind)?;
    if !is_kind(kind_str) {
        return Err(L2Error::InvalidKind); // spec §1.3
    }
    let kind = Kind::parse(kind_str);
    expect_key(&mut r, "edges")?;
    let n_edges = r.expect(Major::Array, L2Error::EdgesNotArray)?;
    if n_edges > MAX_EDGES {
        return Err(L2Error::TooManyEdges); // spec §1.3
    }
    let mut edges = Vec::new();
    for _ in 0..n_edges {
        edges.push(edge(&mut r, parents.len())?);
    }
    check_coverage(parents, &edges)?;
    check_distinct_seq(&edges)?;
    check_shape(kind, parents.len(), &edges)?;
    let body = decode_body(kind, body_raw, payload.len())?;
    Ok(Payload {
        kind: kind_str,
        edges,
        body,
    })
}

/// [`validate_l2_invariants`] on the parents and payload of a parsed block.
///
/// It does not verify the block: a [`sbtp_core::BlockRef`] from `parse` has a well-formed header,
/// but its PoW and signature are unchecked. The caller MUST run the `sbtp-core` verification first;
/// an L2-valid payload in an unverified block is not authentic.
///
/// # Errors
///
/// As [`validate_l2_invariants`].
pub fn validate_block<'a>(block: &sbtp_core::BlockRef<'a>) -> Result<Payload<'a>, L2Error> {
    validate_l2_invariants(block.parents(), block.payload())
}

fn expect_key(r: &mut Reader<'_>, key: &str) -> Result<(), L2Error> {
    if r.text(L2Error::BadEnvelope)? == key {
        Ok(())
    } else {
        Err(L2Error::BadEnvelope)
    }
}

/// A label: a lowercase ASCII letter, then lowercase ASCII letters, digits or `_` (spec §1.3).
fn is_label(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// spec §1.3: 3 to 64 bytes, two or more labels separated by `.`, whole-string match. One pass.
fn is_kind(s: &str) -> bool {
    let mut labels = 0usize;
    (3..=64).contains(&s.len())
        && s.split('.').all(|l| {
            labels += 1;
            is_label(l)
        })
        && labels >= 2
}

/// The kinds of spec §3, parsed once from the `kind` string so that every dispatch on the kind
/// is an exhaustive `match`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `sbtp.manifest` (spec §3).
    Manifest,
    /// `sbtp.enc` (spec §5.2).
    Enc,
    /// `sbtp.enc_key` (spec §5.5).
    EncKey,
    /// A well-formed kind outside spec §3, application kinds included (spec §1.3: checked against
    /// §1 and §2 only).
    ///
    /// This includes an `sbtp.*` kind that spec §3 does not define. The reserved prefix of spec
    /// §1.3 binds authors (an application MUST NOT define such a kind); it gives a decoder no
    /// rejection rule, and spec §2.4 passes "the payload of any other kind" with its body checked
    /// for type only. A later version of the specification may define new `sbtp.*` kinds, which
    /// an older client then validates as unknown and never applies to a resolved state.
    Unknown,
}

impl Kind {
    fn parse(s: &str) -> Self {
        match s {
            "sbtp.manifest" => Self::Manifest,
            "sbtp.enc" => Self::Enc,
            "sbtp.enc_key" => Self::EncKey,
            _ => Self::Unknown,
        }
    }
}

/// spec §2.3: `x.<app>.<verb>`, each part a label.
fn is_extension_verb(s: &str) -> bool {
    let mut parts = s.split('.');
    parts.next() == Some("x")
        && parts.next().is_some_and(is_label)
        && parts.next().is_some_and(is_label)
        && parts.next().is_none()
}

/// Which target forms a registry verb allows (spec §2.2).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Forms {
    P,
    Any,
    BlockOrChunk,
}

/// spec §2.1: exactly one target key.
fn set_target(t: Target, target: &mut Option<Target>) -> Result<(), L2Error> {
    if target.replace(t).is_some() {
        Err(L2Error::EdgeShape)
    } else {
        Ok(())
    }
}

fn edge<'a>(r: &mut Reader<'a>, n_parents: usize) -> Result<Edge<'a>, L2Error> {
    let mut target = None;
    let mut verb = None;
    let mut meta = None;
    closed_map(r, L2Error::EdgeShape, L2Error::EdgeShape, |key, r| {
        match key {
            "p" => {
                let p = r.uint(L2Error::EdgeTargetValue)?;
                // spec §2.1: `p` is 0 to 7 and lower than the Parents Count.
                let p = u8::try_from(p)
                    .ok()
                    .filter(|&p| p < 8 && usize::from(p) < n_parents)
                    .ok_or(L2Error::ParentIndexOutOfRange)?;
                set_target(Target::Parent(p), &mut target)?;
            }
            "block" => set_target(
                Target::Block(r.id32(L2Error::EdgeTargetValue)?),
                &mut target,
            )?,
            "chunk" => set_target(
                Target::Chunk(r.id32(L2Error::EdgeTargetValue)?),
                &mut target,
            )?,
            // spec §2.3: a `rel` that is not a text string is not a verb.
            "rel" => verb = Some(r.text(L2Error::InvalidVerb)?),
            "meta" => meta = Some(r.skip()?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let (Some(target), Some(verb)) = (target, verb) else {
        return Err(L2Error::EdgeShape); // spec §2.1
    };
    if let Some(m) = meta {
        // spec §2.1: `meta`, when present, is a non-empty map.
        let mut mr = Reader::new(m);
        if mr.expect(Major::Map, L2Error::BadMeta)? == 0 {
            return Err(L2Error::BadMeta);
        }
    }
    Ok(Edge {
        target,
        rel: rel(verb, target, meta)?,
    })
}

/// Most bytes in a `rel` value (spec §2.3).
const MAX_VERB_LEN: usize = 64;

/// Resolves the verb against the registry (spec §2.2) or the extension rule (spec §2.3).
fn rel<'a>(verb: &'a str, target: Target, meta: Option<&'a [u8]>) -> Result<Rel<'a>, L2Error> {
    // spec §2.3: 1 to 64 bytes, extension and unknown verbs included.
    if verb.is_empty() || verb.len() > MAX_VERB_LEN {
        return Err(L2Error::InvalidVerb);
    }
    let (forms, rel) = match verb {
        "follows" => (Forms::P, Rel::Follows),
        "in" => (Forms::P, Rel::In),
        "supersedes" => (Forms::P, Rel::Supersedes { reason: None }),
        "composed_of" => (Forms::Any, Rel::ComposedOf { seq: 0, mime: None }),
        // spec §2.2: `p` only, no `meta`. The kinds it may appear on are checked in
        // `check_shape` (spec §2.2, §5.4).
        "tagged" => (Forms::P, Rel::Tagged),
        "replies_to" => (Forms::P, Rel::RepliesTo),
        "cites" => (Forms::BlockOrChunk, Rel::Cites { span: None }),
        "endorses" => (Forms::P, Rel::Endorses),
        "opposes" => (Forms::P, Rel::Opposes),
        "tombstones" => (Forms::P, Rel::Tombstones),
        "moderates" => (Forms::P, Rel::Moderates),
        // spec §2.2: `p` only, no `meta`. "Allowed only on the one application kind that the
        // application requesting the verb designates [...]; application validation checks it":
        // grammar validation knows no application kind, so it checks the form and `meta` only.
        // No `sbtp.*` row lists it, so it is refused on those kinds by their row.
        "tallies" => (Forms::P, Rel::Tallies),
        "supports" => (Forms::P, Rel::Supports { confidence: None }),
        "refutes" => (Forms::P, Rel::Refutes { confidence: None }),
        "synthesizes" => (Forms::P, Rel::Synthesizes),
        "delegates_to" => (Forms::P, Rel::DelegatesTo { task_id: None }),
        "fulfills" => (Forms::P, Rel::Fulfills { status: None }),
        // spec §2.3: an `x.` verb MUST be `x.<app>.<verb>`; any target form, any `meta` map.
        _ if verb.starts_with("x.") => {
            return if is_extension_verb(verb) {
                Ok(Rel::Extension { verb, meta })
            } else {
                Err(L2Error::InvalidExtensionVerb)
            };
        }
        // spec §2.3: an unknown verb without the `x.` prefix does not make the payload invalid,
        // but it MUST be one label.
        _ => {
            return if is_label(verb) {
                Ok(Rel::Unknown { verb, meta })
            } else {
                Err(L2Error::InvalidVerb)
            };
        }
    };
    let form_ok = match forms {
        Forms::P => target.is_causal(),
        Forms::Any => true,
        Forms::BlockOrChunk => !target.is_causal(),
    };
    if !form_ok {
        return Err(L2Error::TargetFormNotAllowed); // spec §2.2
    }
    registry_meta(rel, meta)
}

/// Parses the `meta` of a registry verb against its row of spec §2.2 (spec §2.1: any other key
/// makes the payload invalid). `meta` is already known to be a non-empty map.
fn registry_meta<'a>(rel: Rel<'a>, meta: Option<&'a [u8]>) -> Result<Rel<'a>, L2Error> {
    const BAD_META: L2Error = L2Error::MetaValue;
    let Some(meta) = meta else {
        return match rel {
            Rel::ComposedOf { .. } => Err(BAD_META), // `seq` is required
            other => Ok(other),
        };
    };
    let r = &mut Reader::new(meta);
    Ok(match rel {
        Rel::Supersedes { .. } => Rel::Supersedes {
            reason: Some(one_text(r, "reason")?),
        },
        Rel::ComposedOf { .. } => {
            let (mut seq, mut mime) = (None, None);
            closed_map(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
                match k {
                    "seq" => seq = Some(r.uint(BAD_META)?),
                    "mime" => mime = Some(r.text(BAD_META)?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            Rel::ComposedOf {
                seq: seq.ok_or(BAD_META)?,
                mime,
            }
        }
        Rel::Cites { .. } => {
            let mut span = None;
            closed_map(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
                Ok(k == "span" && {
                    span = Some(body::pair(r, BAD_META)?);
                    true
                })
            })?;
            Rel::Cites { span }
        }
        Rel::Supports { .. } => Rel::Supports {
            confidence: Some(confidence(r)?),
        },
        Rel::Refutes { .. } => Rel::Refutes {
            confidence: Some(confidence(r)?),
        },
        Rel::DelegatesTo { .. } => Rel::DelegatesTo {
            task_id: Some(one_text(r, "task_id")?),
        },
        Rel::Fulfills { .. } => Rel::Fulfills {
            status: Some(one_text(r, "status")?),
        },
        _ => return Err(L2Error::MetaNotAllowed), // the verb takes no `meta`
    })
}

/// The text value of a `meta` map whose only allowed key is `name`.
fn one_text<'a>(r: &mut Reader<'a>, name: &str) -> Result<&'a str, L2Error> {
    let mut value = None;
    closed_map(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
        Ok(k == name && {
            value = Some(r.text(L2Error::MetaValue)?);
            true
        })
    })?;
    value.ok_or(L2Error::MetaValue)
}

/// `confidence`: 0 to 100 (spec §2.2).
fn confidence(r: &mut Reader<'_>) -> Result<u8, L2Error> {
    let mut value = None;
    closed_map(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
        Ok(k == "confidence" && {
            let c = r.uint(L2Error::MetaValue)?;
            value = Some(
                u8::try_from(c)
                    .ok()
                    .filter(|&c| c <= 100)
                    .ok_or(L2Error::MetaValue)?,
            );
            true
        })
    })?;
    value.ok_or(L2Error::MetaValue)
}

/// spec §2.1: coverage, no duplicate `p`, causal edges first in increasing `p`, and no `block`
/// target equal to a header parent.
fn check_coverage(parents: &[BlockId], edges: &[Edge<'_>]) -> Result<(), L2Error> {
    let mut seen: u16 = 0;
    let mut last: Option<u8> = None;
    let mut non_causal = false;
    for e in edges {
        match e.target {
            Target::Parent(p) => {
                let bit = 1u16 << p; // p < 8, checked when decoding the edge
                if seen & bit != 0 {
                    return Err(L2Error::DuplicateParentIndex);
                }
                if non_causal || last.is_some_and(|l| p < l) {
                    return Err(L2Error::EdgeOrder);
                }
                seen |= bit;
                last = Some(p);
            }
            Target::Block(id) => {
                non_causal = true;
                if parents.iter().any(|q| q.0 == id) {
                    return Err(L2Error::BlockTargetIsParent);
                }
            }
            Target::Chunk(_) => non_causal = true,
        }
    }
    // Every set bit is below the Parents Count, so all parents are covered iff the counts match.
    // The Parents Count is at most 8, checked first in `validate_l2_invariants`.
    if u32::try_from(parents.len()).is_ok_and(|n| seen.count_ones() == n) {
        Ok(())
    } else {
        Err(L2Error::UncoveredParent)
    }
}

/// spec §2.2: two `composed_of` edges MUST NOT carry the same `seq`, whatever
/// their target forms and whatever the kind. At most 64 values are sorted.
fn check_distinct_seq(edges: &[Edge<'_>]) -> Result<(), L2Error> {
    let mut seqs: Vec<u64> = edges
        .iter()
        .filter_map(|e| match e.rel {
            Rel::ComposedOf { seq, .. } => Some(seq),
            _ => None,
        })
        .collect();
    seqs.sort_unstable();
    if seqs.windows(2).any(|w| w.first() == w.get(1)) {
        Err(L2Error::DuplicateComposedSeq)
    } else {
        Ok(())
    }
}

/// A kind's row (spec §3.1, read the same way for the `sbtp.*` kinds of spec §3 and for the rows
/// of every application specification): Parents range, registry verbs allowed, required verbs
/// (each exactly once), the optional verbs the row allows "any number" of times, and the two
/// per-kind rules that application tables state in words.
///
/// Multiplicity is per row (spec §3.1: "an optional verb appears at most once, unless the row
/// says 'any number'"): no verb repeats unless its row lists it in `repeatable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KindRow {
    /// The inclusive range of the Parents Count.
    pub parents: (usize, usize),
    /// The optional registry verbs the row lists. Any registry verb outside `allowed` and
    /// `required` makes the payload invalid.
    pub allowed: &'static [&'static str],
    /// The verbs that appear exactly once. They are allowed without being listed in `allowed`.
    pub required: &'static [&'static str],
    /// The verbs of `allowed` that the row allows any number of times; every other verb of the
    /// row appears at most once. A required verb appears exactly once even if listed here.
    pub repeatable: &'static [&'static str],
    /// Exactly one edge among these verbs (for example `endorses` or `opposes`); empty if none.
    pub one_of: &'static [&'static str],
    /// The kind's edge set is closed: no extension or unknown verb (spec §2.3, §3.1).
    pub closed: bool,
}

impl KindRow {
    /// A row with no repeatable verb, no `one_of` rule and an open edge set.
    #[must_use]
    pub const fn new(
        parents: (usize, usize),
        allowed: &'static [&'static str],
        required: &'static [&'static str],
    ) -> Self {
        Self {
            parents,
            allowed,
            required,
            repeatable: &[],
            one_of: &[],
            closed: false,
        }
    }

    /// The same row, with `verbs` allowed any number of times (spec §3.1, "any number").
    #[must_use]
    pub const fn repeatable(mut self, verbs: &'static [&'static str]) -> Self {
        self.repeatable = verbs;
        self
    }

    /// The same row, with a closed edge set: no extension or unknown verb (spec §2.3, §3.1).
    #[must_use]
    pub const fn closed(mut self) -> Self {
        self.closed = true;
        self
    }
}

/// Checks the edges and Parents Count against the row of an `sbtp.*` kind of spec §3. This is
/// the single source of truth for those rows.
fn check_shape(kind: Kind, n_parents: usize, edges: &[Edge<'_>]) -> Result<(), L2Error> {
    // spec §2.2 and §5.4: `tagged` is allowed only on `sbtp.enc` and `sbtp.enc_key`. A rule of
    // the registry, so it holds for every kind, unknown and application kinds included.
    if !matches!(kind, Kind::Enc | Kind::EncKey) && edges.iter().any(|e| e.rel == Rel::Tagged) {
        return Err(L2Error::TaggedNotAllowed);
    }
    // spec §3, table "Kinds".
    let row = match kind {
        // spec §1.3: an unknown kind is checked against §1 and §2 only.
        Kind::Unknown => return Ok(()),
        Kind::Manifest => KindRow::new((0, 1), &["in"], &[]),
        // spec §3 and §5.2: one parent, the delivery tag, named by the single `tagged` edge. The
        // edge set is closed (spec §5.2, ADR 0039 rule 4).
        Kind::Enc => KindRow::new((1, 1), &[], &["tagged"]).closed(),
        // spec §3 and §5.5: the directory tag (`tagged`, `p: 0`), and on an update the previous
        // version (`supersedes`, `p: 1`). The positions are checked below; the edge set stays
        // open for non-causal extension and unknown verbs.
        Kind::EncKey => KindRow::new((1, 2), &["supersedes"], &["tagged"]),
    };
    check_row(&row, n_parents, edges)?;
    if kind == Kind::EncKey {
        check_enc_key_positions(n_parents, edges)?;
    }
    Ok(())
}

/// spec §5.5 (ADR 0039 rules 1 and 2): the parent positions of an `sbtp.enc_key`, on edges that
/// already passed its row and the coverage rule of spec §2.1. `tagged` and `supersedes` take the
/// `p` form only (spec §2.2), so each names a parent position.
fn check_enc_key_positions(n_parents: usize, edges: &[Edge<'_>]) -> Result<(), L2Error> {
    // spec §5.5: the directory tag is `p: 0`, named by the `tagged` edge.
    if edges
        .iter()
        .any(|e| e.rel == Rel::Tagged && e.target != Target::Parent(0))
    {
        return Err(L2Error::EncKeyTagPosition);
    }
    // spec §5.5: an update (2 parents) names the previous version as `p: 1`, by `supersedes`.
    // Coverage guarantees an edge at `p: 1`; it MUST be `supersedes`, not an extension or
    // unknown causal verb.
    if n_parents == 2
        && !edges
            .iter()
            .any(|e| e.target == Target::Parent(1) && matches!(e.rel, Rel::Supersedes { .. }))
    {
        return Err(L2Error::EncKeySupersedesPosition);
    }
    Ok(())
}

/// Checks a payload's edges and its block's Parents Count against a kind row, under the reading
/// rules of spec §3.1. The edges are those of a payload that passed [`validate_l2_invariants`].
///
/// # Errors
///
/// `KindParentCount`, `EdgeNotAllowedForKind`, `MissingRequiredEdge` or `EdgeMultiplicity`, in
/// this order of checks.
pub fn check_row(row: &KindRow, n_parents: usize, edges: &[Edge<'_>]) -> Result<(), L2Error> {
    if n_parents < row.parents.0 || n_parents > row.parents.1 {
        return Err(L2Error::KindParentCount); // spec §3.1, column "Parents"
    }
    let count = |verb: &str| edges.iter().filter(|e| e.rel.verb() == verb).count();
    // spec §3.1: a registry verb outside the row makes the payload invalid; the row's verbs are
    // its required and its optional ones. Extension and unknown verbs are outside every row
    // (spec §2.3), with any target form.
    if edges.iter().any(|e| {
        let verb = e.rel.verb();
        e.rel.is_registry() && !row.allowed.contains(&verb) && !row.required.contains(&verb)
    }) {
        return Err(L2Error::EdgeNotAllowedForKind);
    }
    // spec §3.1: a required verb appears exactly once; a count of 0 is reported as missing, a
    // count above 1 as a multiplicity error, below.
    if row.required.iter().any(|v| count(v) == 0) {
        return Err(L2Error::MissingRequiredEdge);
    }
    // spec §3.1: a required verb exactly once; an optional verb at most once, unless the row
    // allows it any number of times. Extension and unknown verbs do not count (spec §2.3). On a
    // row whose Parents maximum is 1 or less, a second causal edge with the same verb already
    // fails the Parents check above; on any other row, and for non-causal targets, this check is
    // the one that enforces the multiplicity.
    if row.required.iter().any(|v| count(v) > 1)
        || row
            .allowed
            .iter()
            .any(|v| !row.repeatable.contains(v) && !row.required.contains(v) && count(v) > 1)
    {
        return Err(L2Error::EdgeMultiplicity);
    }
    // A `one_of` rule: exactly one edge among its verbs.
    if !row.one_of.is_empty() {
        match row.one_of.iter().map(|v| count(v)).sum::<usize>() {
            0 => return Err(L2Error::MissingRequiredEdge),
            1 => {}
            _ => return Err(L2Error::EdgeMultiplicity),
        }
    }
    // spec §2.3 and §3.1: a closed edge set admits no extension or unknown verb, so only the
    // row's edges.
    if row.closed && edges.iter().any(|e| !e.rel.is_registry()) {
        return Err(L2Error::EdgeMultiplicity);
    }
    Ok(())
}

/// Decodes the body of a payload whose edges already passed [`check_shape`]. `payload_len` is
/// the length of the whole payload, for the length rules of `sbtp.enc` (spec §5.2).
fn decode_body(kind: Kind, raw: &[u8], payload_len: usize) -> Result<Body<'_>, L2Error> {
    let r = &mut Reader::new(raw);
    match kind {
        // spec §1.3 / §2.5: an unknown kind's body is a map or a byte string.
        Kind::Unknown => match r.head()?.0 {
            Major::Map | Major::Bytes => Ok(Body::Raw(raw)),
            _ => Err(L2Error::BodyType),
        },
        // spec §1.3: every kind of §3 has a map body (`body::fields` rejects any other type).
        Kind::Manifest => manifest(r).map(Body::Manifest),
        Kind::Enc => enc(r, payload_len).map(Body::Enc),
        Kind::EncKey => enc_key(r).map(Body::EncKey),
    }
}

// --- Bodies, spec §2.5 and §3. The body maps are closed: any other key is invalid. ---

fn manifest<'a>(r: &mut Reader<'a>) -> Result<Manifest<'a>, L2Error> {
    let (mut mime, mut total, mut size, mut chunks, mut duration, mut resolution) =
        (None, None, None, None, None, None);
    body::fields::<L2Error>(r, |k, r| {
        match k {
            "mime" => mime = Some(r.text(BAD)?),
            "total_size" => total = Some(r.uint(BAD)?),
            "chunk_size" => size = Some(r.uint(BAD)?),
            "chunks" => chunks = Some(body::array(r, true, body::id)?),
            "duration_ms" => duration = Some(r.uint(BAD)?),
            "resolution" => resolution = Some(body::pair(r, BAD)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if required(size)? != CHUNK_SIZE {
        return Err(L2Error::ManifestChunkSize); // spec §3, `sbtp.manifest`
    }
    let (mime, total_size, chunks) = (required(mime)?, required(total)?, required(chunks)?);
    check_total_size(total_size, chunks.len())?;
    Ok(Manifest {
        mime,
        total_size,
        chunks,
        duration_ms: duration,
        resolution,
    })
}

/// spec §5.2 and CDDL `enc-body`: exactly `ct` (a byte string) and `enc` (32 bytes), then the
/// length rules that `validate_l2_invariants` checks "from the payload and the header, with no
/// key". Structure only: nothing is decrypted.
fn enc<'a>(r: &mut Reader<'a>, payload_len: usize) -> Result<Enc<'a>, L2Error> {
    let (mut ct, mut enc) = (None, None);
    body::fields::<L2Error>(r, |k, r| {
        match k {
            "ct" => ct = Some(r.bytes(BAD)?),
            "enc" => enc = Some(body::id(r)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let (ct, enc) = (required(ct)?, required(enc)?);
    // spec §5.2, length buckets: Payload Len is 512, 2,048, 8,192 or 65,535 bytes.
    if !ENC_PAYLOAD_LENS.contains(&payload_len) {
        return Err(L2Error::EncPayloadLen);
    }
    // spec §5.2: "the payload is 90 bytes plus the ciphertext". With the closed edge set, the
    // single `tagged` edge and the closed body, only `ct` is free, and every payload of a
    // bucket's length meets this rule: kept as a defence in depth should the overhead
    // computation and the row ever diverge, and tested on the body decoder directly.
    if ct.len().checked_add(ENC_OVERHEAD) != Some(payload_len) {
        return Err(L2Error::EncCiphertextLen);
    }
    Ok(Enc { ct, enc })
}

/// spec §5.5 and CDDL `enc-key-body`: exactly `x25519` (32 bytes) and `intro_bucket` (0 to 15).
fn enc_key(r: &mut Reader<'_>) -> Result<EncKey, L2Error> {
    let (mut x25519, mut bucket) = (None, None);
    body::fields::<L2Error>(r, |k, r| {
        match k {
            "x25519" => x25519 = Some(body::id(r)?),
            "intro_bucket" => bucket = Some(r.uint(BAD)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let (x25519, bucket) = (required(x25519)?, required(bucket)?);
    let intro_bucket = u8::try_from(bucket)
        .ok()
        .filter(|&b| b <= MAX_INTRO_BUCKET)
        .ok_or(L2Error::EncKeyIntroBucket)?; // spec §5.5: 0 to 15
    Ok(EncKey {
        x25519,
        intro_bucket,
    })
}

/// spec §3, `sbtp.manifest`: `(n − 1) × chunk_size < total_size ≤ n × chunk_size`, `n ≥ 1` (the CDDL
/// `[+ chunk-id]`). Checked arithmetic: an overflow cannot happen within 65,535 bytes, but it is
/// reported rather than wrapped.
fn check_total_size(total_size: u64, n: usize) -> Result<(), L2Error> {
    const E: L2Error = L2Error::ManifestTotalSize;
    let n = u64::try_from(n).map_err(|_| E)?;
    let lower = n.checked_sub(1).and_then(|m| m.checked_mul(CHUNK_SIZE));
    let upper = n.checked_mul(CHUNK_SIZE);
    match (lower, upper) {
        (Some(lo), Some(hi)) if lo < total_size && total_size <= hi => Ok(()),
        _ => Err(E),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{Value as V, encode};

    // spec §5.2: `EncCiphertextLen`. Through `validate_l2_invariants`, every payload of a bucket's
    // length that passes the closed row and the closed body meets the rule, so the variant is
    // tested on the body decoder with a payload length that does not match `ct`.
    #[test]
    fn enc_ciphertext_len() {
        let ct = [0x5a; 422];
        let body = encode(&V::Map(alloc::vec![
            ("ct", V::Bytes(&ct)),
            ("enc", V::Bytes(&[0xaa; 32])),
        ]))
        .unwrap();
        assert!(enc(&mut Reader::new(&body), 512).is_ok());
        assert_eq!(
            enc(&mut Reader::new(&body), 2_048).err(),
            Some(L2Error::EncCiphertextLen)
        );
    }
}
