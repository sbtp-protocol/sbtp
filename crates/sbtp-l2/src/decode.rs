//! `validate_l2_invariants`: strict decoding and checking of a grammar payload (spec §2.4,
//! grammar validation).

use alloc::vec::Vec;

use sbtp_core::BlockId;

use crate::L2Error;
use crate::body::{self, BAD, required};
use crate::cbor::{self, Major, Reader};
use crate::payload::{Body, CHUNK_SIZE, Edge, Manifest, Payload, Rel, Target};

/// Most edges in one payload (spec §1.3).
pub const MAX_EDGES: u64 = 64;

/// Most header parents of a block (core spec §2.2, ADR 0014; spec §2.1).
pub const MAX_PARENTS: usize = 8;

/// Decodes and checks a payload against the header parents of the block that carries it.
///
/// Applies spec §1.2 (CBOR profile), §1.3 (envelope), §2.1 to §2.3 (edges, registry, distinct
/// `composed_of` sequence numbers, verb syntax, extension verbs, with the tolerance for an unknown
/// verb), and, for the `sbtp.*` kinds of spec §3, their row (§3.1) and their body rule. It knows
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
    let body = decode_body(kind, body_raw)?;
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

/// The kinds of spec §3 that this crate validates, parsed once from the `kind` string so that
/// every dispatch on the kind is an exhaustive `match`. `sbtp.enc` and `sbtp.enc_key` are not
/// implemented yet and are validated as unknown kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Manifest,
    /// A well-formed kind outside spec §3, application kinds included (spec §1.3: checked against
    /// §1 and §2 only).
    Unknown,
}

impl Kind {
    fn parse(s: &str) -> Self {
        match s {
            "sbtp.manifest" => Self::Manifest,
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

/// Reads a map item and calls `f` on each key; `f` returns `false` for a key it does not allow.
fn fields<'a>(
    r: &mut Reader<'a>,
    not_map: L2Error,
    unknown: L2Error,
    mut f: impl FnMut(&'a str, &mut Reader<'a>) -> Result<bool, L2Error>,
) -> Result<u64, L2Error> {
    let n = r.expect(Major::Map, not_map)?;
    for _ in 0..n {
        let key = r.text(not_map)?;
        if !f(key, r)? {
            return Err(unknown);
        }
    }
    Ok(n)
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
    fields(r, L2Error::EdgeShape, L2Error::EdgeShape, |key, r| {
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
        "replies_to" => (Forms::P, Rel::RepliesTo),
        "cites" => (Forms::BlockOrChunk, Rel::Cites { span: None }),
        "endorses" => (Forms::P, Rel::Endorses),
        "opposes" => (Forms::P, Rel::Opposes),
        "tombstones" => (Forms::P, Rel::Tombstones),
        "moderates" => (Forms::P, Rel::Moderates),
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
            fields(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
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
            fields(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
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
    fields(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
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
    fields(r, L2Error::BadMeta, L2Error::MetaUnknownKey, |k, r| {
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

/// Registry verbs a kind's row allows any number of times (spec §3.1); every other registry verb
/// of a row appears at most once.
const REPEATABLE: [&str; 2] = ["cites", "composed_of"];

/// A kind's row (spec §3.1, read the same way for the `sbtp.*` kinds of spec §3 and for the rows
/// of every application specification): Parents range, registry verbs allowed, required verbs
/// (each exactly once), and the two per-kind rules that application tables state in words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KindRow {
    /// The inclusive range of the Parents Count.
    pub parents: (usize, usize),
    /// The registry verbs the row lists. Any other registry verb makes the payload invalid.
    pub allowed: &'static [&'static str],
    /// The verbs that appear exactly once.
    pub required: &'static [&'static str],
    /// Exactly one edge among these verbs (for example `endorses` or `opposes`); empty if none.
    pub one_of: &'static [&'static str],
    /// The kind's edge set is closed: no extension or unknown verb (spec §2.3, §3.1).
    pub closed: bool,
}

impl KindRow {
    /// A row with no `one_of` rule and an open edge set.
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
            one_of: &[],
            closed: false,
        }
    }
}

/// Checks the edges and Parents Count against the row of an `sbtp.*` kind of spec §3. This is
/// the single source of truth for those rows.
fn check_shape(kind: Kind, n_parents: usize, edges: &[Edge<'_>]) -> Result<(), L2Error> {
    // spec §3, table "Kinds".
    let row = match kind {
        // spec §1.3: an unknown kind is checked against §1 and §2 only.
        Kind::Unknown => return Ok(()),
        Kind::Manifest => KindRow::new((0, 1), &["in"], &[]),
    };
    check_row(&row, n_parents, edges)
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
    // spec §3.1: a registry verb outside the row makes the payload invalid. Extension and unknown
    // verbs are outside every row (spec §2.3), with any target form.
    if edges
        .iter()
        .any(|e| e.rel.is_registry() && !row.allowed.contains(&e.rel.verb()))
    {
        return Err(L2Error::EdgeNotAllowedForKind);
    }
    // spec §3.1: a required verb appears exactly once; a count of 0 is reported as missing, a
    // count above 1 by the multiplicity check below.
    if row.required.iter().any(|v| count(v) == 0) {
        return Err(L2Error::MissingRequiredEdge);
    }
    // spec §3.1: every registry verb of the row but `cites` and `composed_of` at most once.
    // Extension and unknown verbs do not count (spec §2.3). A repeated verb whose extra edge needs
    // a parent beyond the row's range is reported as `KindParentCount` above; the check is kept as
    // defence in depth.
    if row
        .allowed
        .iter()
        .any(|v| !REPEATABLE.contains(v) && count(v) > 1)
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

/// Decodes the body of a payload whose edges already passed [`check_shape`].
fn decode_body(kind: Kind, raw: &[u8]) -> Result<Body<'_>, L2Error> {
    let r = &mut Reader::new(raw);
    match kind {
        // spec §1.3 / §2.5: an unknown kind's body is a map or a byte string.
        Kind::Unknown => match r.head()?.0 {
            Major::Map | Major::Bytes => Ok(Body::Raw(raw)),
            _ => Err(L2Error::BodyType),
        },
        // spec §1.3: every kind of §3 has a map body (`body::fields` rejects any other type).
        Kind::Manifest => manifest(r).map(Body::Manifest),
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
