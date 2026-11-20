//! Fuzz target for the `sbtp-l2` payload decoder (security review 2026-11-20, I-3).
//!
//! It drives the generic grammar validation only (ADR 0038 rule 6). `sbtp-l2` knows no application
//! kind: the `app.*` seeds are checked against the grammar and returned with a raw body, so no
//! application row or body rule is reached. Those live in application crates, outside this fuzz
//! workspace.
//!
//! Input: one control byte, then the candidate payload.
//! - bits 0-3, modulo 10, give the number of header parents `n` (0 to 9; 9 is one more than a
//!   block can carry, to reach `TooManyParents`). Parent `i` is `BlockId([i + 1; 32])`, as in the
//!   `sbtp-l2` tests;
//! - bit 7 replaces the first parent with `[0xaa; 32]`, the identifier the seeds use for `block`
//!   targets, so the rule "a `block` value MUST NOT equal a header parent" (spec §2.1) is reached.
//!
//! Oracles:
//! - no panic in `validate_l2_invariants`, `cbor::check_profile` or `validate_block`, whatever the
//!   input;
//! - more than 8 parents: always `TooManyParents`, before the payload is read;
//! - accepted by `validate_l2_invariants` implies accepted by `cbor::check_profile`, and
//!   `Payload::encode` returns exactly the input bytes (one value, one encoding: ADR 0011);
//! - `validate_block` on a block built from the same parents and payload gives the same verdict;
//! - differential against a lenient CBOR parser (non-shortest heads, any key order, duplicate keys):
//!   if `check_profile` accepts, the lenient parse succeeds and its canonical re-encoding is the
//!   input (soundness: no alternative encoding is accepted); if the lenient parse succeeds, the
//!   canonical re-encoding of that value passes `check_profile` (completeness of the checker
//!   against the encoder).

#![no_main]

use libfuzzer_sys::fuzz_target;
use sbtp_core::{BlockBuilder, BlockId, parse};
use sbtp_l2::cbor::{self, Value};
use sbtp_l2::{L2Error, MAX_PARENTS, validate_block, validate_l2_invariants};

/// The identifier the seeds use for `block` and `chunk` targets.
const SEED_ID: [u8; 32] = [0xaa; 32];

/// Nesting limit of the lenient parser. The parser and `cbor::encode` recurse, so deeper inputs
/// skip the differential; `check_profile` itself is iterative and still runs on them.
const LENIENT_MAX_DEPTH: u32 = 256;

fn parents(control: u8) -> Vec<BlockId> {
    let n = (control & 0x0f) % 10;
    let mut ps: Vec<BlockId> = (1..=n).map(|i| BlockId([i; 32])).collect();
    if control & 0x80 != 0
        && let Some(first) = ps.first_mut()
    {
        *first = BlockId(SEED_ID);
    }
    ps
}

/// An owned CBOR value of the profile's data model, as read by the lenient parser.
enum Owned {
    Uint(u64),
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Owned>),
    Map(Vec<(String, Owned)>),
    Bool(bool),
    Null,
}

impl Owned {
    fn as_value(&self) -> Value<'_> {
        match self {
            Owned::Uint(n) => Value::Uint(*n),
            Owned::Nint(n) => Value::Nint(*n),
            Owned::Bytes(b) => Value::Bytes(b),
            Owned::Text(s) => Value::Text(s),
            Owned::Array(a) => Value::Array(a.iter().map(Owned::as_value).collect()),
            Owned::Map(m) => {
                Value::Map(m.iter().map(|(k, v)| (k.as_str(), v.as_value())).collect())
            }
            Owned::Bool(b) => Value::Bool(*b),
            Owned::Null => Value::Null,
        }
    }
}

enum Lenient {
    /// Outside the data model: float, tag, other simple value, indefinite length, reserved
    /// additional information, non-text key, invalid UTF-8, truncated, trailing bytes.
    Reject,
    /// Deeper than `LENIENT_MAX_DEPTH`: no verdict.
    TooDeep,
}

fn take<'a>(b: &'a [u8], pos: &mut usize, len: u64) -> Result<&'a [u8], Lenient> {
    let len = usize::try_from(len).map_err(|_| Lenient::Reject)?;
    let end = pos.checked_add(len).ok_or(Lenient::Reject)?;
    let s = b.get(*pos..end).ok_or(Lenient::Reject)?;
    *pos = end;
    Ok(s)
}

/// Reads one item, accepting any head width and any map key order.
fn lenient(b: &[u8], pos: &mut usize, depth: u32) -> Result<Owned, Lenient> {
    if depth > LENIENT_MAX_DEPTH {
        return Err(Lenient::TooDeep);
    }
    let ib = *b.get(*pos).ok_or(Lenient::Reject)?;
    *pos += 1;
    let (major, ai) = (ib >> 5, ib & 0x1f);
    match (major, ai) {
        (7, 20) => return Ok(Owned::Bool(false)),
        (7, 21) => return Ok(Owned::Bool(true)),
        (7, 22) => return Ok(Owned::Null),
        (6 | 7, _) => return Err(Lenient::Reject),
        _ => {}
    }
    let arg = match ai {
        0..=23 => u64::from(ai),
        24..=27 => take(b, pos, 1 << (ai - 24))?
            .iter()
            .fold(0u64, |a, &x| (a << 8) | u64::from(x)),
        _ => return Err(Lenient::Reject),
    };
    Ok(match major {
        0 => Owned::Uint(arg),
        1 => Owned::Nint(arg),
        2 => Owned::Bytes(take(b, pos, arg)?.to_vec()),
        3 => Owned::Text(
            String::from_utf8(take(b, pos, arg)?.to_vec()).map_err(|_| Lenient::Reject)?,
        ),
        4 => {
            // Grows one parsed item at a time: a huge declared count fails on the input end.
            let mut items = Vec::new();
            for _ in 0..arg {
                items.push(lenient(b, pos, depth + 1)?);
            }
            Owned::Array(items)
        }
        _ => {
            let mut entries = Vec::new();
            for _ in 0..arg {
                let Owned::Text(key) = lenient(b, pos, depth + 1)? else {
                    return Err(Lenient::Reject);
                };
                entries.push((key, lenient(b, pos, depth + 1)?));
            }
            Owned::Map(entries)
        }
    })
}

fn lenient_item(b: &[u8]) -> Result<Owned, Lenient> {
    let mut pos = 0;
    let item = lenient(b, &mut pos, 0)?;
    if pos == b.len() {
        Ok(item)
    } else {
        Err(Lenient::Reject)
    }
}

fn check_differential(payload: &[u8], profile: Result<(), L2Error>) {
    match lenient_item(payload) {
        Ok(item) => {
            let canonical = cbor::encode(&item.as_value());
            if profile.is_ok() {
                // Soundness: the accepted bytes are the canonical encoding of their value.
                assert_eq!(
                    canonical.as_deref(),
                    Ok(payload),
                    "check_profile accepted a non-canonical encoding"
                );
            }
            // Completeness: what the encoder emits, the checker accepts. `encode` refuses
            // duplicate keys and outputs over 65,535 bytes; those have no canonical form.
            if let Ok(c) = canonical {
                assert_eq!(
                    cbor::check_profile(&c),
                    Ok(()),
                    "check_profile rejected an encoder output"
                );
            }
        }
        Err(Lenient::Reject) => assert!(
            profile.is_err(),
            "check_profile accepted an item outside the data model"
        ),
        Err(Lenient::TooDeep) => {}
    }
}

/// `validate_block` must agree with `validate_l2_invariants` on the same parents and payload.
fn check_block_wrapper(
    ps: &[BlockId],
    payload: &[u8],
    direct: &Result<sbtp_l2::Payload<'_>, L2Error>,
) {
    // Shapes `sbtp-core` refuses (too many parents, block too long) cannot reach `validate_block`.
    let Ok(bytes) = BlockBuilder::new([7; 32])
        .parents(ps)
        .payload(payload)
        .build_unsigned()
    else {
        return;
    };
    let Ok(block) = parse(&bytes) else {
        return;
    };
    assert_eq!(&validate_block(&block), direct, "validate_block disagrees");
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, payload)) = data.split_first() else {
        return;
    };
    let ps = parents(control);
    let verdict = validate_l2_invariants(&ps, payload);
    if ps.len() > MAX_PARENTS {
        assert_eq!(verdict, Err(L2Error::TooManyParents));
        return;
    }
    let profile = cbor::check_profile(payload);
    if let Ok(p) = &verdict {
        assert_eq!(profile, Ok(()), "accepted payload fails the profile");
        assert_eq!(
            p.encode(&ps).as_deref(),
            Ok(payload),
            "accepted payload does not re-encode to its own bytes"
        );
    }
    check_block_wrapper(&ps, payload, &verdict);
    check_differential(payload, profile);
});
