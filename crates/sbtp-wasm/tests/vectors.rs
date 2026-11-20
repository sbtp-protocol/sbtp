//! Replays the frozen interoperability vectors of `docs/test-vectors/v1/` through the binding API
//! (the functions the JS exports call), so that the bindings give exactly the result `sbtp-core`
//! gives: same verdict, same spec §2.2 error name, same `block_id` and signed message.
//!
//! Beyond validation, every vector also goes through the sender-side bindings:
//! - a valid block, decoded with `parse_block` and re-encoded with `build_unsigned` then
//!   `attach_signature` (its own signature), comes back byte-identical;
//! - a block rejected by C2 or C3 is also rejected by `attach_signature` with the same name, so the
//!   "signature in" path applies the same strict criteria as verification.
//!
//! These are native tests of the Rust side. The JS glue itself (wasm-bindgen marshalling) is not
//! exercised here: no `wasm-bindgen-test` runner is set up yet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::PathBuf;

use sbtp_wasm::{
    attach_signature, block_id, build_unsigned, parse_block, signing_message,
    validate_requested_block, validate_submitted_block,
};
use serde_json::Value;

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

fn vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors/v1");
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            (name, serde_json::from_str(&text).unwrap())
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn frozen_vectors_pass_through_the_bindings() {
    let all = vectors();
    assert_eq!(all.len(), 82, "the v1 set has 82 vectors");
    let mut valid = 0;
    for (name, vector) in &all {
        let block = hex(vector["block_hex"].as_str().unwrap());
        let difficulty = u32::try_from(vector["params"]["difficulty"].as_u64().unwrap()).unwrap();
        let expect = &vector["expect"];

        // Verdict and error name.
        let result = match vector["params"]["requested_block_id"].as_str() {
            Some(requested) => validate_requested_block(&block, difficulty, &hex(requested)),
            None => validate_submitted_block(&block, difficulty),
        };
        let expected_error = expect["error"].as_str();
        match (&result, expected_error) {
            (Ok(info), None) => {
                assert!(expect["valid"].as_bool().unwrap(), "{name}");
                assert!(info.authenticated(), "{name}");
                valid += 1;
            }
            (Err(error), Some(expected)) => assert_eq!(error.name(), expected, "{name}"),
            _ => panic!("{name}: got {result:?}, expected error {expected_error:?}"),
        }

        // block_id and signed message, whenever the block is well-formed.
        if let Some(expected_id) = expect["block_id"].as_str() {
            assert_eq!(
                to_hex(block_id(&block).unwrap().as_bytes()),
                expected_id,
                "{name}"
            );
            assert_eq!(
                to_hex(&signing_message(&block).unwrap()),
                expect["signed_message_hex"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                parse_block(&block).unwrap().block_id_hex(),
                expected_id,
                "{name}"
            );
        } else {
            assert!(parse_block(&block).is_err(), "{name}");
            assert!(signing_message(&block).is_err(), "{name}");
        }

        // Sender side: rebuild valid blocks, re-attach the signature of every well-formed one.
        if expect["block_id"].is_string() {
            let info = parse_block(&block).unwrap();
            let attached = attach_signature(block.clone(), &info.signature());
            match expected_error {
                None => {
                    let rebuilt = build_unsigned(
                        &info.public_key(),
                        info.timestamp(),
                        info.nonce(),
                        &info.parents(),
                        &info.payload(),
                    )
                    .unwrap();
                    let signed = attach_signature(rebuilt, &info.signature()).unwrap();
                    assert_eq!(signed, block, "{name}: rebuild differs");
                    assert_eq!(attached.unwrap(), block, "{name}");
                }
                Some(error @ ("InvalidPublicKey" | "InvalidSignature")) => {
                    assert_eq!(attached.unwrap_err().name(), error, "{name}");
                }
                // R1 and C1 failures carry a valid signature: attaching it succeeds.
                Some("BlockIdMismatch" | "InsufficientPow") => {
                    assert_eq!(attached.unwrap(), block, "{name}");
                }
                Some(other) => panic!("{name}: unexpected error {other} on a well-formed block"),
            }
        }
    }
    assert!(
        valid >= 14,
        "expected the valid vectors to be replayed, got {valid}"
    );
}
