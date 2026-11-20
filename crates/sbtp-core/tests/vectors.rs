//! Replays the frozen interoperability vectors of `docs/test-vectors/v1/` (format:
//! `docs/test-vectors/README.md`) and checks that validation gives exactly the expected result.
//!
//! The vectors are data: this test needs neither `hazmat` nor `digest`, and writes nothing. They are
//! produced by `examples/gen_vectors.rs` (`--features vector-gen`), which a normal `cargo test`
//! never builds.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use sbtp_core::{
    BlockId, S_PLUS_L_BLOCK, S_PLUS_L_EXPECTED_ERROR, SELF_TEST_BLOCK_ID, SELF_TEST_VALID_BLOCK,
    SIG_PREFIX, parse, validate_requested, validate_submitted,
};

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader: objects, strings (with \" \\ \/ \n \t \uXXXX escapes), integers, booleans,
// null. Enough for the vector format; panics on anything else (test code, trusted repository files).
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Obj(BTreeMap<String, Json>),
}

struct Reader<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.s[self.pos] as char, c as char, "at byte {}", self.pos);
        self.pos += 1;
    }

    fn lit(&mut self, word: &str) -> bool {
        if self.s[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Json {
        self.ws();
        let c = self.s[self.pos];
        match c {
            b'{' => return self.object(),
            b'"' => return Json::Str(self.string()),
            b'0'..=b'9' => {
                let start = self.pos;
                while self.pos < self.s.len() && self.s[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.pos]).unwrap();
                return Json::Int(text.parse().unwrap());
            }
            _ => {}
        }
        if self.lit("null") {
            Json::Null
        } else if self.lit("true") {
            Json::Bool(true)
        } else if self.lit("false") {
            Json::Bool(false)
        } else {
            panic!("unexpected {:?} at byte {}", c as char, self.pos)
        }
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = Vec::new();
        loop {
            let c = self.s[self.pos];
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.s[self.pos];
                    self.pos += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.s[self.pos..self.pos + 4]).unwrap();
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap();
                            self.pos += 4;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => panic!("unsupported escape \\{}", e as char),
                    }
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn object(&mut self) -> Json {
        self.eat(b'{');
        let mut map = BTreeMap::new();
        self.ws();
        if self.s[self.pos] == b'}' {
            self.pos += 1;
            return Json::Obj(map);
        }
        loop {
            self.ws();
            let key = self.string();
            self.eat(b':');
            let value = self.value();
            assert!(map.insert(key, value).is_none(), "duplicate key");
            self.ws();
            let c = self.s[self.pos];
            self.pos += 1;
            match c {
                b',' => {}
                b'}' => break,
                _ => panic!("expected , or }} at byte {}", self.pos - 1),
            }
        }
        Json::Obj(map)
    }
}

fn parse_json(text: &str) -> Json {
    let mut r = Reader {
        s: text.as_bytes(),
        pos: 0,
    };
    let v = r.value();
    r.ws();
    assert_eq!(r.pos, r.s.len(), "trailing data");
    v
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(map) => map.get(key).unwrap_or_else(|| panic!("missing key {key}")),
            _ => panic!("not an object"),
        }
    }

    fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    fn opt_str(&self) -> Option<&str> {
        match self {
            Json::Null => None,
            other => Some(other.str()),
        }
    }

    fn keys(&self) -> Vec<&str> {
        match self {
            Json::Obj(map) => map.keys().map(String::as_str).collect(),
            _ => panic!("not an object"),
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

// ---------------------------------------------------------------------------------------------

struct Vector {
    name: String,
    block: Vec<u8>,
    difficulty: u32,
    requested: Option<BlockId>,
    valid: bool,
    block_id: Option<String>,
    signed_message: Option<String>,
    error: Option<String>,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors/v1")
}

fn load() -> Vec<Vector> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(vectors_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let json = parse_json(&std::fs::read_to_string(&path).unwrap());
        // Exactly the fields of the README format.
        assert_eq!(
            json.keys(),
            ["block_hex", "description", "expect", "name", "params"],
            "{}",
            path.display()
        );
        assert_eq!(
            json.get("params").keys(),
            ["difficulty", "requested_block_id"]
        );
        assert_eq!(
            json.get("expect").keys(),
            ["block_id", "error", "signed_message_hex", "valid"]
        );
        let name = json.get("name").str().to_owned();
        assert_eq!(
            path.file_stem().unwrap().to_str().unwrap(),
            name,
            "file name matches the vector name"
        );
        assert_ne!(json.get("description").str(), "");
        let params = json.get("params");
        let expect = json.get("expect");
        let Json::Int(difficulty) = params.get("difficulty") else {
            panic!("{name}: difficulty")
        };
        let Json::Bool(valid) = expect.get("valid") else {
            panic!("{name}: valid")
        };
        out.push(Vector {
            block: unhex(json.get("block_hex").str()),
            difficulty: u32::try_from(*difficulty).unwrap(),
            requested: params
                .get("requested_block_id")
                .opt_str()
                .map(|s| BlockId(unhex32(s))),
            valid: *valid,
            block_id: expect.get("block_id").opt_str().map(str::to_owned),
            signed_message: expect
                .get("signed_message_hex")
                .opt_str()
                .map(str::to_owned),
            error: expect.get("error").opt_str().map(str::to_owned),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

const ERROR_NAMES: [&str; 12] = [
    "TooShort",
    "TooLong",
    "BadMagic",
    "UnsupportedVersion",
    "TooManyParents",
    "Truncated",
    "TrailingBytes",
    "DuplicateParent",
    "BlockIdMismatch",
    "InsufficientPow",
    "InvalidPublicKey",
    "InvalidSignature",
];

#[test]
fn every_vector_validates_exactly_as_expected() {
    let vectors = load();
    assert_eq!(vectors.len(), 82, "vector count");
    for v in &vectors {
        let name = &v.name;
        // Internal consistency of the file.
        assert_eq!(v.valid, v.error.is_none(), "{name}: valid iff no error");
        assert_eq!(
            v.block_id.is_some(),
            v.signed_message.is_some(),
            "{name}: block_id and signed message go together"
        );
        if let Some(e) = &v.error {
            assert!(
                ERROR_NAMES.contains(&e.as_str()),
                "{name}: unknown error {e}"
            );
        }

        // block_id and signed message are given iff F1 to F9 pass.
        let parsed = parse(&v.block);
        assert_eq!(
            parsed.is_ok(),
            v.block_id.is_some(),
            "{name}: well-formedness"
        );
        if let (Ok(block), Some(id), Some(message)) = (&parsed, &v.block_id, &v.signed_message) {
            let computed = block.block_id();
            assert_eq!(&hex(computed.as_bytes()), id, "{name}: block_id");
            assert_eq!(&hex(&computed.signed_message()), message, "{name}: message");
            assert!(message.starts_with(&hex(&SIG_PREFIX)), "{name}: prefix");
        }

        // The verdict: exactly the expected result.
        // (block_id, accepted bytes) of an accepted block, whichever entry point.
        let result = match &v.requested {
            Some(id) => validate_requested(&v.block, v.difficulty, id)
                .map(|ok| (*ok.block_id(), ok.block().as_bytes())),
            None => validate_submitted(&v.block, v.difficulty)
                .map(|ok| (*ok.block_id(), ok.block().as_bytes())),
        };
        match (&result, &v.error) {
            (Ok((id, bytes)), None) => {
                assert_eq!(Some(hex(id.as_bytes())), v.block_id, "{name}: id");
                assert_eq!(*bytes, &v.block[..], "{name}: bytes");
            }
            (Err(e), Some(expected)) => assert_eq!(e.name(), expected, "{name}"),
            (got, want) => panic!("{name}: got {got:?}, expected error {want:?}"),
        }
    }
}

/// Every error variant and every check of spec §2.2 has at least one vector.
#[test]
fn vectors_cover_every_error_variant() {
    let vectors = load();
    for e in ERROR_NAMES {
        assert!(
            vectors.iter().any(|v| v.error.as_deref() == Some(e)),
            "no vector for {e}"
        );
    }
    assert!(vectors.iter().filter(|v| v.valid).count() >= 14);
}

/// The required cases of docs/test-vectors/README.md, by name.
#[test]
fn required_cases_are_present() {
    let names: Vec<String> = load().into_iter().map(|v| v.name).collect();
    for required in [
        "valid_0_parents_empty_payload",
        "valid_1_parent",
        "valid_8_parents",
        "valid_max_size",
        "valid_parents_empty_payload",
        "valid_0_parents_max_payload",
        "valid_zero_parent_hash",
        "valid_unsorted_parents",
        "valid_timestamp_zero",
        "valid_timestamp_max",
        "valid_nonce_distinct_bytes",
        "valid_pow_at_threshold",
        "valid_mixed_order_pubkey",
        "valid_requested_id_matches",
        "f1_empty",
        "f1_117_bytes",
        "f2_65910_bytes",
        "f3_bad_magic_first_byte",
        "f3_bad_magic_second_byte",
        "f4_version_0",
        "f4_version_2",
        "f5_9_parents",
        "f5_255_parents",
        "f6_truncated_in_parents",
        "f7_truncated_in_payload",
        "f7_last_signature_byte_missing",
        "f8_one_extra_byte",
        "f9_adjacent_duplicates",
        "f9_non_adjacent_duplicates",
        "r1_block_id_mismatch",
        "c1_insufficient_pow",
        "c2_v1_y_not_on_curve",
        "c2_v1_non_canonical_not_small_order",
        "c2_v1_non_canonical_small_order_y0",
        "c2_v1_non_canonical_small_order_y1",
        "c2_v1_x_zero_sign_bit_y1",
        "c2_v1_x_zero_sign_bit_y_minus_1",
        "c2_v2_small_order_identity_and_v6",
        "c2_v2_small_order_order2_and_v6",
        "c2_v2_small_order_order4_a_and_v6",
        "c2_v2_small_order_order4_b_and_v6",
        "c2_v2_small_order_order8_a_and_v6",
        "c2_v2_small_order_order8_b_and_v6",
        "c2_v2_small_order_order8_c_and_v6",
        "c2_v2_small_order_order8_d_and_v6",
        "c3_v3_s_plus_l",
        "c3_v4_r_not_on_curve",
        "c3_v5_r_small_order_identity_and_v6",
        "c2_v2_only_identity",
        "c2_v2_only_order2",
        "c2_v2_only_order4_a",
        "c2_v2_only_order4_b",
        "c2_v2_only_order8_a",
        "c2_v2_only_order8_b",
        "c2_v2_only_order8_c",
        "c2_v2_only_order8_d",
        "c2_v2_only_order8_a_torsion_r",
        "c2_v1_v2_non_canonical_identity",
        "c3_v5_only_r_identity",
        "c3_v5_only_r_order2",
        "c3_v5_only_r_order4_a",
        "c3_v5_only_r_order4_b",
        "c3_v5_only_r_order8_a",
        "c3_v5_only_r_order8_b",
        "c3_v5_only_r_order8_c",
        "c3_v5_only_r_order8_d",
        "c3_v6_non_canonical_r",
        "c3_v6_cofactored_only",
        "c3_bit_flipped_in_r",
        "c3_bit_flipped_in_s",
        "c3_bit_flipped_in_payload",
        "c3_signature_without_prefix",
        "c3_signature_over_plain_blake3",
        "c3_signature_by_another_key",
    ] {
        assert!(names.iter().any(|n| n == required), "missing {required}");
    }
}

/// The V2-only and V5-only vectors discriminate (review 2026-11-18 M2, F-1): a plain RFC 8032
/// cofactorless verifier without the small-order checks, `ed25519-dalek`'s non-strict `verify`
/// (no Cargo feature needed), accepts every one of them, and sbtp-core rejects each with the
/// expected error. The combined `*_and_v6` vectors, by contrast, are rejected by both.
#[test]
fn isolating_vectors_discriminate_v2_and_v5() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let lax_accepts = |v: &Vector| {
        let pubkey: [u8; 32] = v.block[19..51].try_into().unwrap();
        let id = parse(&v.block).unwrap().block_id();
        let signature: [u8; 64] = v.block[v.block.len() - 64..].try_into().unwrap();
        VerifyingKey::from_bytes(&pubkey).is_ok_and(|key| {
            key.verify(&id.signed_message(), &Signature::from_bytes(&signature))
                .is_ok()
        })
    };
    let vectors = load();
    let (mut v2, mut v5, mut combined) = (0, 0, 0);
    for v in &vectors {
        let name = v.name.as_str();
        let expected = if name.starts_with("c2_v2_only_") || name.starts_with("c2_v1_v2_") {
            v2 += 1;
            "InvalidPublicKey"
        } else if name.starts_with("c3_v5_only_") {
            v5 += 1;
            "InvalidSignature"
        } else {
            if name.ends_with("_and_v6") {
                combined += 1;
                assert!(!lax_accepts(v), "{name}: a combined case fails V6 too");
            }
            continue;
        };
        assert!(lax_accepts(v), "{name}: the lax verifier must accept it");
        assert_eq!(
            validate_submitted(&v.block, 0).unwrap_err().name(),
            expected,
            "{name}"
        );
        assert_eq!(v.error.as_deref(), Some(expected), "{name}");
    }
    assert_eq!((v2, v5, combined), (10, 8, 16));
}

/// Boundary sizes of the format vectors are what their names say.
#[test]
fn boundary_sizes() {
    let vectors = load();
    let len = |n: &str| vectors.iter().find(|v| v.name == n).unwrap().block.len();
    assert_eq!(len("valid_0_parents_empty_payload"), 118);
    assert_eq!(len("f1_empty"), 0);
    assert_eq!(len("f1_117_bytes"), 117);
    assert_eq!(len("valid_max_size"), 65_909);
    assert_eq!(len("f2_65910_bytes"), 65_910);
    assert_eq!(len("f5_9_parents"), 406);
}

/// The S + L vector exported for the start-up self-test (ADR 0003 rule 16) is the frozen one.
#[test]
fn self_test_constants_are_the_frozen_vectors() {
    let vectors = load();
    let find = |n: &str| vectors.iter().find(|v| v.name == n).unwrap();
    let valid = find("self_test_valid");
    let s_plus_l = find("c3_v3_s_plus_l");
    assert_eq!(valid.block, SELF_TEST_VALID_BLOCK);
    assert_eq!(s_plus_l.block, S_PLUS_L_BLOCK);
    assert_eq!(
        valid.block_id.as_deref(),
        Some(hex(SELF_TEST_BLOCK_ID.as_bytes()).as_str())
    );
    assert_eq!(s_plus_l.block_id, valid.block_id);
    assert_eq!(
        s_plus_l.error.as_deref(),
        Some(S_PLUS_L_EXPECTED_ERROR.name())
    );
    assert_eq!(sbtp_core::self_test(), Ok(()));
}

#[test]
fn json_reader_handles_escapes() {
    assert_eq!(
        parse_json(r#"{"a": "x\"y\\zA", "b": null, "c": 12, "d": true}"#),
        Json::Obj(BTreeMap::from([
            ("a".to_owned(), Json::Str("x\"y\\zA".to_owned())),
            ("b".to_owned(), Json::Null),
            ("c".to_owned(), Json::Int(12)),
            ("d".to_owned(), Json::Bool(true)),
        ]))
    );
}
