//! `validate_l2_invariants`: one valid payload per `sbtp.*` kind and for unknown kinds (round
//! trip), and at least one negative case per `L2Error` variant, with neutral application kinds
//! (`a.b`, `app.*`) as carriers. Application kinds are tested by their application. Draft cases,
//! not frozen test vectors.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    missing_docs
)]

use sbtp_core::{BlockBuilder, BlockId, parse};
use sbtp_l2::cbor::{self, Value as V};
use sbtp_l2::{
    Body, Edge, KindRow, L2Error as E, Rel, Target, check_row, validate_block,
    validate_l2_invariants,
};

const A: [u8; 32] = [0xaa; 32];
const SHORT: [u8; 31] = [0xaa; 31];

fn parents(n: u8) -> Vec<BlockId> {
    (1..=n).map(|i| BlockId([i; 32])).collect()
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn env<'a>(kind: &'a str, edges: Vec<V<'a>>, body: V<'a>) -> Vec<u8> {
    cbor::encode(&V::Map(vec![
        ("v", V::Uint(1)),
        ("kind", V::Text(kind)),
        ("edges", V::Array(edges)),
        ("body", body),
    ]))
    .unwrap()
}

fn e(p: u64, rel: &str) -> V<'_> {
    V::Map(vec![("p", V::Uint(p)), ("rel", V::Text(rel))])
}

fn em<'a>(p: u64, rel: &'a str, meta: V<'a>) -> V<'a> {
    V::Map(vec![
        ("p", V::Uint(p)),
        ("rel", V::Text(rel)),
        ("meta", meta),
    ])
}

/// A non-causal edge: `key` is `block` or `chunk`.
fn en<'a>(key: &'a str, id: &'a [u8], rel: &'a str) -> V<'a> {
    V::Map(vec![(key, V::Bytes(id)), ("rel", V::Text(rel))])
}

fn map<'a>(entries: &[(&'a str, V<'a>)]) -> V<'a> {
    V::Map(entries.to_vec())
}

fn empty<'a>() -> V<'a> {
    V::Map(Vec::new())
}

/// A map body for an application kind, which `sbtp-l2` does not interpret.
fn post_body<'a>() -> V<'a> {
    map(&[("title", V::Text("t")), ("text", V::Text("x"))])
}

/// A larger map body for an application kind.
fn group_body<'a>() -> V<'a> {
    map(&[
        ("name", V::Text("Tech")),
        ("slug", V::Text("tech")),
        ("description", V::Text("d")),
        ("rules", V::Array(vec![V::Text("be kind")])),
        ("moderators", V::Array(vec![V::Bytes(&A)])),
        ("pow_min_difficulty", V::Uint(16)),
    ])
}

fn manifest_body<'a>() -> V<'a> {
    map(&[
        ("mime", V::Text("a")),
        ("total_size", V::Uint(1)),
        ("chunk_size", V::Uint(262_144)),
        ("chunks", V::Array(vec![V::Bytes(&A)])),
    ])
}

fn err(n: u8, bytes: &[u8]) -> E {
    validate_l2_invariants(&parents(n), bytes).unwrap_err()
}

/// Valid, and re-encoding the decoded payload gives the same bytes.
fn ok(n: u8, bytes: &[u8]) -> sbtp_l2::Payload<'_> {
    let ps = parents(n);
    let p = validate_l2_invariants(&ps, bytes).unwrap();
    assert_eq!(p.encode(&ps).unwrap(), bytes);
    p
}

#[test]
fn valid_payload_per_kind_round_trips() {
    // Every edge form on an unknown kind: `sbtp-l2` applies no row to it.
    let edges = env(
        "a.b",
        vec![
            e(0, "in"),
            em(1, "supersedes", map(&[("reason", V::Text("typo"))])),
            en("block", &A, "cites"),
            V::Map(vec![
                ("chunk", V::Bytes(&A)),
                ("rel", V::Text("composed_of")),
                (
                    "meta",
                    map(&[("seq", V::Uint(0)), ("mime", V::Text("image/png"))]),
                ),
            ]),
            en("block", &A, "x.app.like"),
        ],
        post_body(),
    );
    let p = ok(2, &edges);
    assert!(matches!(
        p.edges[4].rel,
        Rel::Extension {
            verb: "x.app.like",
            ..
        }
    ));
    // A crosspost is a `cites` edge, not a parent.
    assert_eq!(p.edges[2].target, Target::Block(A));
    assert!(matches!(p.body, Body::Raw(_)));
    let manifest = map(&[
        ("mime", V::Text("video/mp4")),
        ("total_size", V::Uint(10)),
        ("chunk_size", V::Uint(262_144)),
        ("chunks", V::Array(vec![V::Bytes(&A)])),
        ("duration_ms", V::Uint(1000)),
        ("resolution", V::Array(vec![V::Uint(640), V::Uint(480)])),
    ]);
    let bytes = env("sbtp.manifest", vec![e(0, "in")], manifest);
    assert!(matches!(ok(1, &bytes).body, Body::Manifest(_)));
    ok(0, &env("sbtp.manifest", vec![], manifest_body()));
    // Unknown kinds: map or byte string body, no row applied. An `sbtp.*` kind that spec §3 does
    // not define is an unknown kind too (spec §1.3, §2.4): a later version may define it.
    let bytes = env("other.thing", vec![e(0, "frobnicates")], V::Bytes(b"x"));
    let p = ok(1, &bytes);
    assert!(matches!(p.body, Body::Raw(_)));
    let later = env("sbtp.later", vec![], V::Bytes(b"ciphertext"));
    let future = ok(0, &later);
    assert!(matches!(future.body, Body::Raw(_)));
    ok(1, &env("sbtp.later", vec![e(0, "in")], empty()));
    ok(0, &env("a.b", vec![], empty()));
    let kind64 = format!("{}.{}", "a".repeat(31), "b".repeat(32));
    ok(0, &env(&kind64, vec![], empty()));
    // An application body is returned as encoded.
    let body = cbor::encode(&group_body()).unwrap();
    let bytes = env("app.group", vec![], group_body());
    assert_eq!(ok(0, &bytes).body, Body::Raw(&body));
}

#[test]
fn validate_block_reads_parents_and_payload() {
    let ps = parents(1);
    let payload = env("app.vote", vec![e(0, "endorses")], empty());
    let block = BlockBuilder::new([7; 32])
        .parents(&ps)
        .payload(&payload)
        .build_unsigned()
        .unwrap();
    let block = parse(&block).unwrap();
    assert_eq!(validate_block(&block).unwrap().kind, "app.vote");
}

// --- CBOR profile, spec §1.2 ---

#[test]
fn profile_rejections() {
    let cases: &[(&str, E)] = &[
        ("", E::Truncated),
        ("a1 6161", E::Truncated),
        ("62 61", E::Truncated),
        ("00 00", E::TrailingBytes),
        ("1c", E::Malformed),
        ("ff", E::Malformed),
        ("1f", E::Malformed),
        ("18 17", E::NonShortestForm),
        ("19 00ff", E::NonShortestForm),
        ("1a 0000ffff", E::NonShortestForm),
        ("1b 00000000ffffffff", E::NonShortestForm),
        ("78 01 61", E::NonShortestForm),
        ("5f ff", E::IndefiniteLength),
        ("7f ff", E::IndefiniteLength),
        ("9f ff", E::IndefiniteLength),
        ("bf ff", E::IndefiniteLength),
        ("f9 0000", E::Float),
        ("fa 00000000", E::Float),
        ("fb 0000000000000000", E::Float),
        ("c0 00", E::Tag),
        ("c2 41 01", E::Tag),
        ("f7", E::SimpleValue),
        ("f0", E::SimpleValue),
        ("f8 20", E::SimpleValue),
        ("a1 01 01", E::MapKeyNotText),
        ("a1 41 61 01", E::MapKeyNotText),
        ("a2 6162 01 6161 01", E::MapKeysUnsorted),
        ("a2 6161 01 6161 01", E::DuplicateMapKey),
        ("62 c328", E::InvalidUtf8),
        ("a1 61ff 01", E::InvalidUtf8),
    ];
    for (h, want) in cases {
        assert_eq!(cbor::check_profile(&hex(h)), Err(*want), "{h}");
        assert_eq!(err(0, &hex(h)), *want, "{h}");
    }
    assert_eq!(err(0, &vec![0; 65_536]), E::PayloadTooLong);
    // `false`, `true`, `null` are allowed.
    assert_eq!(cbor::check_profile(&hex("83 f4 f5 f6")), Ok(()));
}

#[test]
fn deep_nesting_does_not_overflow_the_stack() {
    let mut deep = vec![0x81; 65_534];
    deep.push(0x00);
    assert_eq!(cbor::check_profile(&deep), Ok(()));
    assert_eq!(err(0, &deep), E::BadEnvelope);
    let mut wide = vec![0x82; 65_535];
    wide[65_534] = 0x00;
    assert_eq!(err(0, &wide), E::Truncated);
}

#[test]
fn encoder_refuses_non_conforming_values() {
    let dup = V::Map(vec![("a", V::Uint(1)), ("a", V::Uint(2))]);
    assert_eq!(cbor::encode(&dup), Err(E::DuplicateMapKey));
    assert_eq!(cbor::encode(&V::Raw(&[0xf7])), Err(E::SimpleValue));
}

// --- Envelope, spec §1.3 ---

#[test]
fn envelope_rejections() {
    let four = |k: &'static str| {
        cbor::encode(&map(&[
            (k, V::Uint(1)),
            ("kind", V::Text("a.b")),
            ("edges", V::Array(vec![])),
            ("body", empty()),
        ]))
        .unwrap()
    };
    assert_eq!(err(0, &four("w")), E::BadEnvelope);
    assert_eq!(err(0, &hex("80")), E::BadEnvelope);
    let three = map(&[
        ("v", V::Uint(1)),
        ("kind", V::Text("a.b")),
        ("body", empty()),
    ]);
    assert_eq!(err(0, &cbor::encode(&three).unwrap()), E::BadEnvelope);
    let mut five = env("a.b", vec![], empty());
    five[0] = 0xa5;
    five.extend_from_slice(&hex("667a7a7a7a7a7a 00"));
    assert_eq!(err(0, &five), E::BadEnvelope);

    for v in [V::Uint(0), V::Uint(2), V::Text("1"), V::Nint(0)] {
        let bytes = cbor::encode(&map(&[
            ("v", v),
            ("kind", V::Text("a.b")),
            ("edges", V::Array(vec![])),
            ("body", empty()),
        ]))
        .unwrap();
        assert_eq!(err(0, &bytes), E::UnsupportedVersion);
    }

    let long = "a.".repeat(33);
    for kind in [
        "app",
        "ab",
        "a.",
        ".a.b",
        "App.post",
        "app.1x",
        "app..x",
        &long[..65],
    ] {
        assert_eq!(
            err(0, &env(kind, vec![], empty())),
            E::InvalidKind,
            "{kind}"
        );
    }

    let edges_map = cbor::encode(&map(&[
        ("v", V::Uint(1)),
        ("kind", V::Text("a.b")),
        ("edges", empty()),
        ("body", empty()),
    ]))
    .unwrap();
    assert_eq!(err(0, &edges_map), E::EdgesNotArray);

    let cites = |n| (0..n).map(|_| en("chunk", &A, "cites")).collect::<Vec<_>>();
    ok(0, &env("a.b", cites(64), empty()));
    assert_eq!(err(0, &env("a.b", cites(65), empty())), E::TooManyEdges);

    // An unknown kind's body is a map or a byte string; an `sbtp.*` kind's body is a map.
    assert_eq!(err(0, &env("a.b", vec![], V::Array(vec![]))), E::BodyType);
    assert_eq!(err(0, &env("a.b", vec![], V::Uint(0))), E::BodyType);
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], V::Array(vec![]))),
        E::BodyType
    );
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], V::Bytes(b""))),
        E::BodyType
    );
}

// --- Edges, spec §2.1 to §2.3 ---

#[test]
fn edge_rejections() {
    let unknown = |n: u8, edges: Vec<V<'_>>| err(n, &env("a.b", edges, empty()));
    assert_eq!(unknown(0, vec![V::Uint(0)]), E::EdgeShape);
    assert_eq!(unknown(1, vec![map(&[("p", V::Uint(0))])]), E::EdgeShape);
    assert_eq!(
        unknown(0, vec![map(&[("rel", V::Text("cites"))])]),
        E::EdgeShape
    );
    let two_targets = map(&[
        ("p", V::Uint(0)),
        ("block", V::Bytes(&A)),
        ("rel", V::Text("in")),
    ]);
    assert_eq!(unknown(1, vec![two_targets]), E::EdgeShape);
    let extra = map(&[("p", V::Uint(0)), ("rel", V::Text("in")), ("x", V::Uint(0))]);
    assert_eq!(unknown(1, vec![extra]), E::EdgeShape);
    // spec §2.3: a `rel` that is not a text string is an invalid verb, not a bad edge shape.
    assert_eq!(
        unknown(1, vec![map(&[("p", V::Uint(0)), ("rel", V::Uint(1))])]),
        E::InvalidVerb
    );
    assert_eq!(
        unknown(1, vec![map(&[("p", V::Uint(0)), ("rel", V::Bytes(b"in"))])]),
        E::InvalidVerb
    );

    assert_eq!(
        unknown(1, vec![map(&[("p", V::Text("0")), ("rel", V::Text("in"))])]),
        E::EdgeTargetValue
    );
    assert_eq!(
        unknown(0, vec![en("block", &SHORT, "cites")]),
        E::EdgeTargetValue
    );
    let text_chunk = map(&[("chunk", V::Text("x")), ("rel", V::Text("cites"))]);
    assert_eq!(unknown(0, vec![text_chunk]), E::EdgeTargetValue);

    assert_eq!(unknown(1, vec![e(1, "in")]), E::ParentIndexOutOfRange);
    assert_eq!(
        unknown(0, vec![e(u64::MAX, "in")]),
        E::ParentIndexOutOfRange
    );
    let eight: Vec<_> = (0..8).map(|p| e(p, "in")).collect();
    ok(8, &env("a.b", eight.clone(), empty()));
    let mut nine = eight;
    nine.push(e(8, "in"));
    assert_eq!(unknown(8, nine), E::ParentIndexOutOfRange);

    assert_eq!(unknown(2, vec![e(0, "in")]), E::UncoveredParent);
    assert_eq!(unknown(1, vec![]), E::UncoveredParent);
    assert_eq!(
        unknown(2, vec![e(0, "in"), e(0, "follows")]),
        E::DuplicateParentIndex
    );
    assert_eq!(unknown(2, vec![e(1, "in"), e(0, "follows")]), E::EdgeOrder);
    assert_eq!(
        unknown(1, vec![en("chunk", &A, "cites"), e(0, "in")]),
        E::EdgeOrder
    );
    let parent = [1u8; 32];
    assert_eq!(
        unknown(1, vec![e(0, "in"), en("block", &parent, "cites")]),
        E::BlockTargetIsParent
    );
    ok(
        1,
        &env(
            "a.b",
            vec![e(0, "in"), en("chunk", &parent, "cites")],
            empty(),
        ),
    );

    assert_eq!(unknown(1, vec![em(0, "supersedes", empty())]), E::BadMeta);
    assert_eq!(unknown(1, vec![em(0, "x.a.b", V::Uint(1))]), E::BadMeta);
    assert_eq!(
        unknown(1, vec![em(0, "endorses", map(&[("x", V::Uint(1))]))]),
        E::MetaNotAllowed
    );
    let why = map(&[("why", V::Text("x"))]);
    assert_eq!(
        unknown(1, vec![em(0, "supersedes", why)]),
        E::MetaUnknownKey
    );
    let extra = map(&[("seq", V::Uint(0)), ("size", V::Uint(1))]);
    assert_eq!(
        unknown(1, vec![em(0, "composed_of", extra)]),
        E::MetaUnknownKey
    );
    let meta_value: Vec<(&str, Option<V<'_>>)> = vec![
        ("composed_of", None),
        ("composed_of", Some(map(&[("mime", V::Text("a"))]))),
        ("supports", Some(map(&[("confidence", V::Uint(101))]))),
        ("refutes", Some(map(&[("confidence", V::Text("1"))]))),
        ("supersedes", Some(map(&[("reason", V::Uint(1))]))),
        ("delegates_to", Some(map(&[("task_id", V::Uint(1))]))),
        ("fulfills", Some(map(&[("status", V::Bytes(b""))]))),
    ];
    for (rel, meta) in meta_value {
        let edge = meta.map_or_else(|| e(0, rel), |m| em(0, rel, m));
        assert_eq!(unknown(1, vec![edge]), E::MetaValue, "{rel}");
    }
    let bad_span = V::Map(vec![
        ("block", V::Bytes(&A)),
        ("rel", V::Text("cites")),
        ("meta", map(&[("span", V::Array(vec![V::Uint(1)]))])),
    ]);
    assert_eq!(unknown(0, vec![bad_span]), E::MetaValue);

    assert_eq!(
        unknown(0, vec![en("block", &A, "endorses")]),
        E::TargetFormNotAllowed
    );
    assert_eq!(unknown(1, vec![e(0, "cites")]), E::TargetFormNotAllowed);
    ok(
        1,
        &env(
            "a.b",
            vec![em(0, "composed_of", map(&[("seq", V::Uint(1))]))],
            empty(),
        ),
    );

    for verb in ["x.foo", "x.a.b.c", "x.A.b", "x..b"] {
        assert_eq!(
            unknown(0, vec![en("chunk", &A, verb)]),
            E::InvalidExtensionVerb,
            "{verb}"
        );
    }
    // Extension and unknown verbs: any target form and any non-empty `meta` map.
    let any_meta = map(&[("weight", V::Nint(4))]);
    ok(
        1,
        &env(
            "a.b",
            vec![em(0, "x.app.weighs", any_meta.clone())],
            empty(),
        ),
    );
    ok(1, &env("a.b", vec![em(0, "later_verb", any_meta)], empty()));
}

// --- Kinds, spec §3 ---

#[test]
fn kind_row_rejections() {
    // `sbtp.manifest`: 0 or 1 parent, at most one `in`, no other registry verb.
    let two = env(
        "sbtp.manifest",
        vec![e(0, "in"), e(1, "x.a.b")],
        manifest_body(),
    );
    assert_eq!(err(2, &two), E::KindParentCount);
    assert_eq!(
        err(
            1,
            &env("sbtp.manifest", vec![e(0, "follows")], manifest_body())
        ),
        E::EdgeNotAllowedForKind
    );
    let cites = env(
        "sbtp.manifest",
        vec![en("block", &A, "cites")],
        manifest_body(),
    );
    assert_eq!(err(0, &cites), E::EdgeNotAllowedForKind);

    let part = |key, seq| {
        V::Map(vec![
            (key, V::Bytes(&A)),
            ("rel", V::Text("composed_of")),
            ("meta", map(&[("seq", V::Uint(seq))])),
        ])
    };
    // spec §2.2: on a known kind and on an unknown kind alike, before the row.
    let dup_seq = env(
        "sbtp.manifest",
        vec![part("chunk", 1), part("block", 1)],
        manifest_body(),
    );
    assert_eq!(err(0, &dup_seq), E::DuplicateComposedSeq);
    let dup_seq_unknown = env("a.b", vec![part("chunk", 2), part("block", 2)], empty());
    assert_eq!(err(0, &dup_seq_unknown), E::DuplicateComposedSeq);
    ok(
        0,
        &env("a.b", vec![part("chunk", 2), part("block", 3)], empty()),
    );
}

/// spec §3.1, through the public `check_row` that applications use for their own rows: each
/// rule of a row, in its order of checks.
#[test]
fn check_row_reads_a_row() {
    let edge = |p: u8, rel: Rel<'static>| Edge {
        target: Target::Parent(p),
        rel,
    };
    let ext = Edge {
        target: Target::Block(A),
        rel: Rel::Extension {
            verb: "x.a.b",
            meta: None,
        },
    };
    let cite = Edge {
        target: Target::Block(A),
        rel: Rel::Cites { span: None },
    };
    let row = KindRow::new((1, 2), &["in", "follows", "cites"], &["in"]);
    let one_in = [edge(0, Rel::In)];
    assert_eq!(check_row(&row, 1, &one_in), Ok(()));
    assert_eq!(check_row(&row, 0, &[]), Err(E::KindParentCount));
    assert_eq!(check_row(&row, 3, &one_in), Err(E::KindParentCount));
    assert_eq!(
        check_row(&row, 1, &[edge(0, Rel::Endorses)]),
        Err(E::EdgeNotAllowedForKind)
    );
    assert_eq!(
        check_row(&row, 1, &[edge(0, Rel::Follows)]),
        Err(E::MissingRequiredEdge)
    );
    assert_eq!(
        check_row(&row, 2, &[edge(0, Rel::In), edge(1, Rel::In)]),
        Err(E::EdgeMultiplicity)
    );
    // spec §3.1: multiplicity is per row. Without "any number", a second `cites` is refused;
    // extension verbs are outside the row and do not count.
    let many = [
        edge(0, Rel::In),
        cite.clone(),
        cite.clone(),
        ext.clone(),
        ext.clone(),
    ];
    assert_eq!(check_row(&row, 1, &many), Err(E::EdgeMultiplicity));
    let any_cites = row.repeatable(&["cites"]);
    assert_eq!(check_row(&any_cites, 1, &many), Ok(()));
    assert_eq!(check_row(&any_cites, 1, &many[..2]), Ok(()));
    // A required verb is allowed without being listed in `allowed`, and appears exactly once,
    // also on a non-causal target that the Parents column cannot catch.
    let cited = KindRow::new((0, 0), &[], &["cites"]);
    assert_eq!(check_row(&cited, 0, std::slice::from_ref(&cite)), Ok(()));
    assert_eq!(check_row(&cited, 0, &[]), Err(E::MissingRequiredEdge));
    assert_eq!(
        check_row(&cited, 0, &[cite.clone(), cite.clone()]),
        Err(E::EdgeMultiplicity)
    );
    // Listing a required verb as repeatable does not relax "exactly once".
    let cited_any = cited.repeatable(&["cites"]);
    assert_eq!(
        check_row(&cited_any, 0, &[cite.clone(), cite]),
        Err(E::EdgeMultiplicity)
    );
    // A required causal verb twice, on a row whose Parents maximum allows it.
    let two_in = KindRow::new((2, 2), &[], &["in"]);
    assert_eq!(
        check_row(&two_in, 2, &[edge(0, Rel::In), edge(1, Rel::In)]),
        Err(E::EdgeMultiplicity)
    );
    assert_eq!(
        check_row(
            &two_in,
            2,
            &[
                edge(0, Rel::In),
                Edge {
                    target: Target::Parent(1),
                    rel: Rel::Extension {
                        verb: "x.a.b",
                        meta: None
                    }
                }
            ]
        ),
        Ok(())
    );
    // `one_of`: exactly one of its verbs.
    let vote = KindRow {
        one_of: &["endorses", "opposes"],
        ..KindRow::new((1, 2), &["endorses", "opposes", "supersedes"], &[])
    };
    assert_eq!(check_row(&vote, 1, &[edge(0, Rel::Endorses)]), Ok(()));
    assert_eq!(
        check_row(&vote, 1, &[edge(0, Rel::Supersedes { reason: None })]),
        Err(E::MissingRequiredEdge)
    );
    assert_eq!(
        check_row(&vote, 2, &[edge(0, Rel::Endorses), edge(1, Rel::Opposes)]),
        Err(E::EdgeMultiplicity)
    );
    // `closed`: no extension or unknown verb.
    let closed = KindRow {
        closed: true,
        ..row
    };
    assert_eq!(check_row(&closed, 1, &one_in), Ok(()));
    assert_eq!(
        check_row(&closed, 1, &[edge(0, Rel::In), ext]),
        Err(E::EdgeMultiplicity)
    );
}

/// spec §2.3 (security review L-2): extension and unknown verbs are outside every row and
/// allowed on a kind whose edge set is not closed, causal ones included; they do not count toward
/// the multiplicities.
#[test]
fn extension_and_unknown_verbs_on_known_kinds() {
    // "Optional edges: at most one `in`" constrains registry verbs only.
    ok(
        1,
        &env("sbtp.manifest", vec![e(0, "x.a.b")], manifest_body()),
    );
    ok(
        1,
        &env("sbtp.manifest", vec![e(0, "later")], manifest_body()),
    );
    let three = env(
        "sbtp.manifest",
        vec![
            e(0, "in"),
            en("block", &A, "x.a.in"),
            en("chunk", &A, "later"),
        ],
        manifest_body(),
    );
    ok(1, &three);
}

/// spec §2.3: `rel` is 1 to 64 bytes; an unknown verb is one label.
#[test]
fn verb_syntax() {
    let one = |verb: &str| err(0, &env("a.b", vec![en("chunk", &A, verb)], empty()));
    for verb in [
        "",
        "Foo Bar",
        "Replies_to",
        "X.Foo",
        "1abc",
        "_a",
        "a-b",
        "a.b",
        "é",
    ] {
        assert_eq!(one(verb), E::InvalidVerb, "{verb:?}");
    }
    // 64 bytes is the bound, for unknown and extension verbs alike.
    let unknown64 = "a".repeat(64);
    ok(0, &env("a.b", vec![en("chunk", &A, &unknown64)], empty()));
    assert_eq!(one(&"a".repeat(65)), E::InvalidVerb);
    let ext64 = format!("x.app.{}", "v".repeat(58));
    assert_eq!(ext64.len(), 64);
    ok(0, &env("a.b", vec![en("chunk", &A, &ext64)], empty()));
    let ext65 = format!("x.app.{}", "v".repeat(59));
    assert_eq!(one(&ext65), E::InvalidVerb);
    // Single-label unknown verbs stay tolerated.
    for verb in ["x", "later_verb", "a1"] {
        ok(0, &env("a.b", vec![en("chunk", &A, verb)], empty()));
    }
}

/// spec §3, `sbtp.manifest`: `(n − 1) × 262,144 < total_size ≤ n × 262,144`.
#[test]
fn manifest_total_size() {
    const C: u64 = 262_144;
    let manifest = |total, n: usize| {
        env(
            "sbtp.manifest",
            vec![],
            map(&[
                ("mime", V::Text("video/mp4")),
                ("total_size", V::Uint(total)),
                ("chunk_size", V::Uint(C)),
                ("chunks", V::Array(vec![V::Bytes(&A); n])),
            ]),
        )
    };
    for (total, n) in [(1, 1), (C, 1), (C + 1, 2), (2 * C, 2)] {
        ok(0, &manifest(total, n));
    }
    for (total, n) in [
        (0, 1),
        (C + 1, 1),
        (C, 2),
        (2 * C + 1, 2),
        (u64::MAX, 1),
        (0, 3),
    ] {
        assert_eq!(
            err(0, &manifest(total, n)),
            E::ManifestTotalSize,
            "{total} {n}"
        );
    }
}

/// Security review I-2: the registry `meta` shapes not covered above round-trip.
#[test]
fn registry_meta_round_trips() {
    let bytes = env(
        "a.b",
        vec![
            em(0, "supports", map(&[("confidence", V::Uint(0))])),
            em(1, "refutes", map(&[("confidence", V::Uint(100))])),
            em(2, "delegates_to", map(&[("task_id", V::Text("t-1"))])),
            em(3, "fulfills", map(&[("status", V::Text("done"))])),
            e(4, "synthesizes"),
            V::Map(vec![
                ("block", V::Bytes(&A)),
                ("rel", V::Text("cites")),
                (
                    "meta",
                    map(&[("span", V::Array(vec![V::Uint(3), V::Uint(70_000)]))]),
                ),
            ]),
        ],
        empty(),
    );
    let p = ok(5, &bytes);
    let rels: Vec<_> = p.edges.iter().map(|e| e.rel.clone()).collect();
    assert_eq!(
        rels,
        vec![
            Rel::Supports {
                confidence: Some(0)
            },
            Rel::Refutes {
                confidence: Some(100)
            },
            Rel::DelegatesTo {
                task_id: Some("t-1")
            },
            Rel::Fulfills {
                status: Some("done")
            },
            Rel::Synthesizes,
            Rel::Cites {
                span: Some((3, 70_000))
            },
        ]
    );
}

#[test]
fn body_rejections() {
    let manifest = map(&[
        ("mime", V::Text("a")),
        ("total_size", V::Uint(1)),
        ("chunks", V::Array(vec![V::Bytes(&A)])),
    ]);
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], manifest)),
        E::BodyMissingField
    );
    let mut extra = manifest_body();
    if let V::Map(m) = &mut extra {
        m.push(("author", V::Text("a")));
    }
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], extra)),
        E::BodyUnknownField
    );
    let mut bytes_mime = manifest_body();
    if let V::Map(m) = &mut bytes_mime {
        m[0].1 = V::Bytes(b"a");
    }
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], bytes_mime)),
        E::BodyFieldValue
    );
    let mut short_resolution = manifest_body();
    if let V::Map(m) = &mut short_resolution {
        m.push(("resolution", V::Array(vec![V::Uint(1)])));
    }
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], short_resolution)),
        E::BodyFieldValue
    );
    let manifest_with = |chunks: Vec<V<'static>>| {
        map(&[
            ("mime", V::Text("a")),
            ("total_size", V::Uint(1)),
            ("chunk_size", V::Uint(262_144)),
            ("chunks", V::Array(chunks)),
        ])
    };
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], manifest_with(vec![]))),
        E::BodyEmptyArray
    );
    assert_eq!(
        err(
            0,
            &env(
                "sbtp.manifest",
                vec![],
                manifest_with(vec![V::Bytes(&SHORT)])
            )
        ),
        E::BodyIdSize
    );
    let size = map(&[
        ("mime", V::Text("a")),
        ("total_size", V::Uint(1)),
        ("chunk_size", V::Uint(1)),
        ("chunks", V::Array(vec![V::Bytes(&A)])),
    ]);
    assert_eq!(
        err(0, &env("sbtp.manifest", vec![], size)),
        E::ManifestChunkSize
    );
}

/// A parents slice longer than 8 cannot come from a parsed block; it is rejected before the
/// payload is read, even when the payload would otherwise be valid for 9 parents.
#[test]
fn more_than_eight_parents_is_rejected_up_front() {
    let nine: Vec<V<'_>> = (0..9).map(|p| e(p, "x.a.b")).collect();
    let bytes = env("a.b", nine, empty());
    assert_eq!(err(9, &bytes), E::TooManyParents);
    assert_eq!(
        validate_l2_invariants(&parents(9), b"").unwrap_err(),
        E::TooManyParents
    );
    assert_eq!(sbtp_l2::MAX_PARENTS, 8);
    let eight: Vec<V<'_>> = (0..8).map(|p| e(p, "x.a.b")).collect();
    ok(8, &env("a.b", eight, empty()));
}

/// Every truncation and many single-byte changes of valid payloads: no panic, and any payload that
/// is still accepted re-encodes to exactly its own bytes (one value, one encoding: ADR 0011).
#[test]
fn mutations_never_panic_and_accepted_payloads_are_canonical() {
    let reason = map(&[("reason", V::Text("r"))]);
    let seeds = [
        (1, env("app.vote", vec![e(0, "endorses")], empty())),
        (0, env("app.group", vec![], group_body())),
        (
            2,
            env(
                "app.post",
                vec![e(0, "in"), em(1, "supersedes", reason)],
                post_body(),
            ),
        ),
        (1, env("sbtp.manifest", vec![e(0, "in")], manifest_body())),
        (1, sealed(512, vec![])),
        (
            2,
            env(
                "sbtp.enc_key",
                vec![e(0, "tagged"), e(1, "supersedes")],
                enc_key_body(&A, V::Uint(3)),
            ),
        ),
    ];
    let bytes = [
        0x00, 0x01, 0x17, 0x18, 0x1f, 0x20, 0x41, 0x61, 0x7f, 0x80, 0xa0, 0xbf, 0xf6, 0xff,
    ];
    for (n, seed) in seeds {
        let ps = parents(n);
        let check = |m: &[u8]| {
            if let Ok(p) = validate_l2_invariants(&ps, m) {
                assert_eq!(p.encode(&ps).unwrap(), m);
            }
        };
        for len in 0..seed.len() {
            check(&seed[..len]);
        }
        for i in 0..seed.len() {
            let mut m = seed.clone();
            m[i] ^= 0x01;
            check(&m);
            for b in bytes {
                m[i] = b;
                check(&m);
            }
        }
    }
}

// --- `tagged`, `tallies` (spec §2.2) and the sealed envelope kinds (spec §3, §5.2, §5.5) ---

/// `sbtp.enc` body.
fn enc_body<'a>(ct: &'a [u8], enc: &'a [u8]) -> V<'a> {
    map(&[("ct", V::Bytes(ct)), ("enc", V::Bytes(enc))])
}

/// A conforming `sbtp.enc` payload of `bucket` bytes (spec §5.2), with `extra` edges after the
/// `tagged` one and a ciphertext shortened to keep the bucket.
fn sealed(bucket: usize, extra: Vec<V<'_>>) -> Vec<u8> {
    let probe = env("sbtp.enc", extra.clone(), enc_body(&[], &A));
    // `ct` grows from 0 bytes (1-byte head) to 256 or more bytes (3-byte head).
    // + 2 head bytes, + 15 bytes of `{"p": 0, "rel": "tagged"}`.
    let fixed = probe.len() + 2 + 15;
    let ct = vec![0x5a; bucket - fixed];
    let mut edges = vec![e(0, "tagged")];
    edges.extend(extra);
    env("sbtp.enc", edges, enc_body(&ct, &A))
}

fn enc_key_body<'a>(x25519: &'a [u8], bucket: V<'a>) -> V<'a> {
    map(&[("x25519", V::Bytes(x25519)), ("intro_bucket", bucket)])
}

#[test]
fn tagged_and_tallies_are_registry_verbs() {
    // `tallies`: `p` only, no `meta`; grammar validation leaves its kind to the application.
    let bytes = env("a.b", vec![e(0, "tallies")], empty());
    let p = ok(1, &bytes);
    assert_eq!(p.edges[0].rel, Rel::Tallies);
    assert!(p.edges[0].rel.is_registry());
    assert_eq!(
        err(0, &env("a.b", vec![en("block", &A, "tallies")], empty())),
        E::TargetFormNotAllowed
    );
    let meta = map(&[("n", V::Uint(1))]);
    assert_eq!(
        err(
            1,
            &env("a.b", vec![em(0, "tallies", meta.clone())], empty())
        ),
        E::MetaNotAllowed
    );
    // No `sbtp.*` row lists it.
    assert_eq!(
        err(
            1,
            &env("sbtp.manifest", vec![e(0, "tallies")], manifest_body())
        ),
        E::EdgeNotAllowedForKind
    );
    // An application row that lists it accepts it; one that does not refuses it.
    let tally = Edge {
        target: Target::Parent(0),
        rel: Rel::Tallies,
    };
    let listed = KindRow::new((1, 1), &[], &["tallies"]);
    assert_eq!(check_row(&listed, 1, std::slice::from_ref(&tally)), Ok(()));
    let other = KindRow::new((1, 1), &["in"], &[]);
    assert_eq!(
        check_row(&other, 1, &[tally]),
        Err(E::EdgeNotAllowedForKind)
    );

    // `tagged`: `p` only, no `meta`, only on `sbtp.enc` and `sbtp.enc_key`.
    let key = enc_key_body(&A, V::Uint(0));
    let bytes = env("sbtp.enc_key", vec![e(0, "tagged")], key.clone());
    let p = ok(1, &bytes);
    assert_eq!(p.edges[0].rel, Rel::Tagged);
    assert!(p.edges[0].rel.is_registry());
    for kind in ["a.b", "app.item", "sbtp.later"] {
        assert_eq!(
            err(1, &env(kind, vec![e(0, "tagged")], empty())),
            E::TaggedNotAllowed,
            "{kind}"
        );
    }
    assert_eq!(
        err(
            1,
            &env("sbtp.manifest", vec![e(0, "tagged")], manifest_body())
        ),
        E::TaggedNotAllowed
    );
    assert_eq!(
        err(
            1,
            &env(
                "sbtp.enc_key",
                vec![e(0, "tagged"), en("block", &A, "tagged")],
                key.clone()
            )
        ),
        E::TargetFormNotAllowed
    );
    assert_eq!(
        err(1, &env("sbtp.enc_key", vec![em(0, "tagged", meta)], key)),
        E::MetaNotAllowed
    );
}

#[test]
fn sealed_block_row_body_and_buckets() {
    // spec §5.2: one valid payload per length bucket, round trip.
    for bucket in sbtp_l2::ENC_PAYLOAD_LENS {
        let bytes = sealed(bucket, vec![]);
        assert_eq!(bytes.len(), bucket);
        let p = ok(1, &bytes);
        let Body::Enc(enc) = p.body else {
            panic!("not an sbtp.enc body")
        };
        assert_eq!(enc.ct.len(), bucket - sbtp_l2::ENC_OVERHEAD);
        assert_eq!(enc.enc, A);
    }
    let ct = vec![0x5a; 422];
    let body = || enc_body(&ct, &A);
    let tagged = || vec![e(0, "tagged")];
    assert_eq!(ok(1, &env("sbtp.enc", tagged(), body())).edges.len(), 1);

    // Row: exactly 1 parent, the single `tagged` edge (spec §3, §5.2).
    assert_eq!(err(0, &env("sbtp.enc", vec![], body())), E::KindParentCount);
    assert_eq!(
        err(
            2,
            &env("sbtp.enc", vec![e(0, "tagged"), e(1, "x.a.b")], body())
        ),
        E::KindParentCount
    );
    assert_eq!(
        err(1, &env("sbtp.enc", vec![e(0, "x.a.b")], body())),
        E::MissingRequiredEdge
    );
    assert_eq!(
        err(
            1,
            &env(
                "sbtp.enc",
                vec![e(0, "tagged"), en("block", &A, "cites")],
                body()
            )
        ),
        E::EdgeNotAllowedForKind
    );

    // Body: exactly `ct` (bytes) and `enc` (32 bytes).
    let only_ct = map(&[("ct", V::Bytes(&ct))]);
    assert_eq!(
        err(1, &env("sbtp.enc", tagged(), only_ct)),
        E::BodyMissingField
    );
    let extra = map(&[
        ("ct", V::Bytes(&ct)),
        ("enc", V::Bytes(&A)),
        ("from", V::Bytes(&A)),
    ]);
    assert_eq!(
        err(1, &env("sbtp.enc", tagged(), extra)),
        E::BodyUnknownField
    );
    assert_eq!(
        err(1, &env("sbtp.enc", tagged(), enc_body(&ct, &SHORT))),
        E::BodyIdSize
    );
    let text_ct = map(&[("ct", V::Text("x")), ("enc", V::Bytes(&A))]);
    assert_eq!(
        err(1, &env("sbtp.enc", tagged(), text_ct)),
        E::BodyFieldValue
    );
    assert_eq!(
        err(1, &env("sbtp.enc", tagged(), V::Bytes(&ct))),
        E::BodyType
    );

    // Length rules (spec §5.2), checked from the payload alone.
    let short = vec![0x5a; 421];
    let bytes = env("sbtp.enc", tagged(), enc_body(&short, &A));
    assert_eq!(bytes.len(), 511);
    assert_eq!(err(1, &bytes), E::EncPayloadLen);
    let tiny = env("sbtp.enc", tagged(), enc_body(b"ciphertext", &A));
    assert_eq!(err(1, &tiny), E::EncPayloadLen);
    // A payload of a bucket's length that is not 90 bytes plus `ct`: an extra edge took the
    // place of ciphertext bytes.
    let padded = sealed(512, vec![en("chunk", &A, "x.a.b")]);
    assert_eq!(padded.len(), 512);
    assert_eq!(err(1, &padded), E::EncCiphertextLen);
}

#[test]
fn encryption_key_row_and_body() {
    let key = || enc_key_body(&A, V::Uint(7));
    let bytes = env("sbtp.enc_key", vec![e(0, "tagged")], key());
    let p = ok(1, &bytes);
    assert_eq!(
        p.body,
        Body::EncKey(sbtp_l2::EncKey {
            x25519: A,
            intro_bucket: 7
        })
    );
    // An update: the previous version as a second parent, `supersedes` (spec §5.5).
    let reason = map(&[("reason", V::Text("rotation"))]);
    ok(
        2,
        &env(
            "sbtp.enc_key",
            vec![e(0, "tagged"), em(1, "supersedes", reason)],
            key(),
        ),
    );
    // The row is open: extension verbs are allowed (spec §2.3, §3.1).
    ok(
        2,
        &env("sbtp.enc_key", vec![e(0, "tagged"), e(1, "x.a.b")], key()),
    );
    // Row: 1 or 2 parents, exactly one `tagged`, at most one `supersedes`, nothing else.
    assert_eq!(
        err(0, &env("sbtp.enc_key", vec![], key())),
        E::KindParentCount
    );
    let three = vec![e(0, "tagged"), e(1, "supersedes"), e(2, "x.a.b")];
    assert_eq!(
        err(3, &env("sbtp.enc_key", three, key())),
        E::KindParentCount
    );
    assert_eq!(
        err(1, &env("sbtp.enc_key", vec![e(0, "supersedes")], key())),
        E::MissingRequiredEdge
    );
    assert_eq!(
        err(
            2,
            &env("sbtp.enc_key", vec![e(0, "tagged"), e(1, "tagged")], key())
        ),
        E::EdgeMultiplicity
    );
    assert_eq!(
        err(
            2,
            &env("sbtp.enc_key", vec![e(0, "tagged"), e(1, "follows")], key())
        ),
        E::EdgeNotAllowedForKind
    );
    // Body: exactly `x25519` (32 bytes) and `intro_bucket` (0 to 15).
    ok(
        1,
        &env(
            "sbtp.enc_key",
            vec![e(0, "tagged")],
            enc_key_body(&A, V::Uint(0)),
        ),
    );
    ok(
        1,
        &env(
            "sbtp.enc_key",
            vec![e(0, "tagged")],
            enc_key_body(&A, V::Uint(15)),
        ),
    );
    for bucket in [16, 255, 256, u64::MAX] {
        assert_eq!(
            err(
                1,
                &env(
                    "sbtp.enc_key",
                    vec![e(0, "tagged")],
                    enc_key_body(&A, V::Uint(bucket))
                )
            ),
            E::EncKeyIntroBucket,
            "{bucket}"
        );
    }
    let bad = [
        (enc_key_body(&A, V::Nint(0)), E::BodyFieldValue),
        (enc_key_body(&SHORT, V::Uint(0)), E::BodyIdSize),
        (map(&[("x25519", V::Bytes(&A))]), E::BodyMissingField),
        (map(&[("intro_bucket", V::Uint(0))]), E::BodyMissingField),
        (empty(), E::BodyMissingField),
        (V::Bytes(&A), E::BodyType),
    ];
    for (i, (body, expected)) in bad.into_iter().enumerate() {
        let bytes = env("sbtp.enc_key", vec![e(0, "tagged")], body);
        assert_eq!(err(1, &bytes), expected, "case {i}");
    }
    let mut extra = key();
    if let V::Map(m) = &mut extra {
        m.push(("purpose", V::Text("dm")));
    }
    assert_eq!(
        err(1, &env("sbtp.enc_key", vec![e(0, "tagged")], extra)),
        E::BodyUnknownField
    );
}
