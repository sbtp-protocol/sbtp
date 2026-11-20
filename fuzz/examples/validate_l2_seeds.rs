//! Writes (or, with `--check`, verifies) the seed corpus of the `validate_l2` fuzz target.
//!
//! Each seed is the control byte (the number of parents) followed by a valid payload taken from
//! `crates/sbtp-l2/tests/validation.rs`, or a neutral application kind (`app.*`). `sbtp-l2` knows
//! no application kind (ADR 0038): those seeds exercise the grammar paths (edges, verbs, parent
//! coverage, `meta`, body shapes) that application crates build on, with the body returned raw.
//! Every seed is checked with `validate_l2_invariants` and the round trip before it is written, so
//! a seed is always an accepted input.
//!
//! ```bash
//! cargo run --manifest-path fuzz/Cargo.toml --example validate_l2_seeds            # write
//! cargo run --manifest-path fuzz/Cargo.toml --example validate_l2_seeds -- --check # verify
//! ```
//!
//! The default directory is `fuzz/seeds/validate_l2/` (committed); another one can be given as the
//! last argument.

use std::path::PathBuf;
use std::process::ExitCode;

use sbtp_core::BlockId;
use sbtp_l2::cbor::{self, Value as V};
use sbtp_l2::validate_l2_invariants;

const A: [u8; 32] = [0xaa; 32];

/// The ciphertext of the smallest `sbtp.enc` bucket: a 512-byte payload is 90 bytes plus `ct`
/// (l2-grammar §5.2).
const CT: [u8; 422] = [0x5a; 422];

fn env<'a>(kind: &'a str, edges: Vec<V<'a>>, body: V<'a>) -> Vec<u8> {
    cbor::encode(&V::Map(vec![
        ("v", V::Uint(1)),
        ("kind", V::Text(kind)),
        ("edges", V::Array(edges)),
        ("body", body),
    ]))
    .expect("seed encodes")
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

fn en<'a>(key: &'a str, rel: &'a str) -> V<'a> {
    V::Map(vec![(key, V::Bytes(&A)), ("rel", V::Text(rel))])
}

fn map<'a>(entries: &[(&'a str, V<'a>)]) -> V<'a> {
    V::Map(entries.to_vec())
}

fn empty<'a>() -> V<'a> {
    V::Map(Vec::new())
}

fn group_body<'a>() -> V<'a> {
    map(&[
        ("name", V::Text("Tech")),
        ("handle", V::Text("tech")),
        ("description", V::Text("d")),
        ("policies", V::Array(vec![V::Text("be kind")])),
        ("admins", V::Array(vec![V::Bytes(&A)])),
        ("pow_min_difficulty", V::Uint(16)),
    ])
}

/// `(file name, number of parents, payload)`.
fn seeds() -> Vec<(&'static str, u8, Vec<u8>)> {
    let remark = || map(&[("reason", V::Text("spam")), ("note", V::Text("c"))]);
    let entry = |score| {
        V::Map(vec![
            ("block", V::Bytes(&A)),
            ("weight", score),
            ("reply_count", V::Uint(3)),
        ])
    };
    let kind64 = format!("{}.{}", "a".repeat(31), "b".repeat(32));
    vec![
        (
            "reaction",
            1,
            env("app.reaction", vec![e(0, "endorses")], empty()),
        ),
        (
            "reaction_update",
            2,
            env(
                "app.reaction",
                vec![e(0, "opposes"), e(1, "supersedes")],
                empty(),
            ),
        ),
        (
            "group_root",
            0,
            env("app.group", vec![], group_body()),
        ),
        (
            "group_update",
            1,
            env(
                "app.group",
                vec![e(0, "supersedes")],
                group_body(),
            ),
        ),
        (
            "item",
            2,
            env(
                "app.item",
                vec![
                    e(0, "in"),
                    em(1, "supersedes", map(&[("reason", V::Text("typo"))])),
                    en("block", "cites"),
                    V::Map(vec![
                        ("chunk", V::Bytes(&A)),
                        ("rel", V::Text("composed_of")),
                        (
                            "meta",
                            map(&[("seq", V::Uint(0)), ("mime", V::Text("image/png"))]),
                        ),
                    ]),
                    en("block", "x.app.like"),
                ],
                map(&[
                    ("title", V::Text("t")),
                    ("text", V::Text("x")),
                    ("url", V::Text("https://example.org")),
                    ("tags", V::Array(vec![V::Text("rust")])),
                ]),
            ),
        ),
        (
            "reply",
            1,
            env(
                "app.reply",
                vec![e(0, "replies_to")],
                map(&[
                    ("text", V::Text("hi")),
                    ("mentions", V::Array(vec![V::Bytes(&A)])),
                ]),
            ),
        ),
        (
            "retraction",
            1,
            env("app.retraction", vec![e(0, "tombstones")], remark()),
        ),
        (
            "review",
            2,
            env(
                "app.review",
                vec![e(0, "moderates"), e(1, "in")],
                remark(),
            ),
        ),
        (
            "manifest",
            1,
            env(
                "sbtp.manifest",
                vec![e(0, "in")],
                map(&[
                    ("mime", V::Text("video/mp4")),
                    ("total_size", V::Uint(10)),
                    ("chunk_size", V::Uint(262_144)),
                    ("chunks", V::Array(vec![V::Bytes(&A)])),
                    ("duration_ms", V::Uint(1000)),
                    ("resolution", V::Array(vec![V::Uint(640), V::Uint(480)])),
                ]),
            ),
        ),
        (
            "digest",
            2,
            env(
                "app.digest",
                vec![e(0, "in"), e(1, "follows")],
                map(&[
                    ("scope", V::Text("recent")),
                    ("window_start", V::Uint(1)),
                    ("window_end", V::Uint(2)),
                    (
                        "entries",
                        V::Array(vec![entry(V::Nint(u64::MAX)), entry(V::Uint(u64::MAX))]),
                    ),
                ]),
            ),
        ),
        (
            "registry_meta",
            5,
            env(
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
            ),
        ),
        (
            "unknown_kind",
            1,
            env("other.thing", vec![e(0, "frobnicates")], V::Bytes(b"x")),
        ),
        (
            "enc",
            1,
            env(
                "sbtp.enc",
                vec![e(0, "tagged")],
                map(&[("ct", V::Bytes(&CT)), ("enc", V::Bytes(&A))]),
            ),
        ),
        (
            "enc_key",
            2,
            env(
                "sbtp.enc_key",
                vec![e(0, "tagged"), e(1, "supersedes")],
                map(&[("x25519", V::Bytes(&A)), ("intro_bucket", V::Uint(15))]),
            ),
        ),
        ("kind64", 0, env(&kind64, vec![], empty())),
        (
            "eight_parents",
            8,
            env("a.b", (0..8).map(|p| e(p, "x.a.b")).collect(), empty()),
        ),
    ]
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.iter().any(|a| a == "--check");
    let dir = args
        .iter()
        .rfind(|a| !a.starts_with("--"))
        .map_or_else(|| PathBuf::from("fuzz/seeds/validate_l2"), PathBuf::from);
    if !check {
        std::fs::create_dir_all(&dir).expect("create the seed directory");
    }
    let mut stale = 0;
    for (name, n, payload) in seeds() {
        let ps: Vec<BlockId> = (1..=n).map(|i| BlockId([i; 32])).collect();
        let decoded = validate_l2_invariants(&ps, &payload).expect("seed is valid");
        assert_eq!(decoded.encode(&ps).expect("seed re-encodes"), payload);
        let mut bytes = vec![n];
        bytes.extend_from_slice(&payload);
        let path = dir.join(name);
        if check {
            if std::fs::read(&path).ok().as_deref() != Some(&bytes[..]) {
                eprintln!("stale or missing seed: {}", path.display());
                stale += 1;
            }
        } else {
            std::fs::write(&path, &bytes).expect("write the seed");
        }
    }
    if stale == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
