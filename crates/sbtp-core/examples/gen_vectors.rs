//! Generator of the frozen layer 0 interoperability vectors, `docs/test-vectors/v1/`.
//!
//! ```text
//! cargo run -p sbtp-core --features vector-gen --example gen_vectors            # write missing files
//! cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --check # verify, write nothing
//! cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --fuzz-seeds [DIR]
//! ```
//!
//! The three modes are exclusive; the optional argument is the mode's directory. Write and
//! `--check` default to `docs/test-vectors/v1/`. `--fuzz-seeds` first checks
//! `docs/test-vectors/v1/` read-only, then writes the fuzz seed corpus into `DIR`, by default
//! `fuzz/corpus/decode_block/` (gitignored; see fuzz/README.md). `--check` writes nothing at all.
//!
//! A published vector never changes (docs/test-vectors/README.md): in write mode an existing file
//! that differs from the regenerated one is an error, never overwritten. `--check` also fails on a
//! missing or an extra file, and checks that the start-up self-test constants of `sbtp-core` are the
//! frozen bytes.
//!
//! The expected outcome of every vector is stated by construction, below. The generator then runs
//! `sbtp-core` on it and aborts on any disagreement: the library is checked against the vectors,
//! not the other way round. The `block_id` and the signed message are recomputed here with
//! `blake3::derive_key` and the literal strings of spec §3.1 and §3.2, not with `sbtp-core`. The
//! mixed-order cases are classified by recomputing `k = SHA-512(R || A || M) mod L` here
//! (review 2026-11-18, L-4).
//!
//! Every well-formed vector is also run through `analyze`, an evaluation of the six criteria V1 to
//! V6 of spec §3.2 with curve25519-dalek point arithmetic, SHA-512 and the local `mod_l`, outside
//! sbtp-core and `verify_strict`. The expected C2/C3 error must follow from it, and the list of
//! criteria that fail and hold is appended to the description (README rule: a negative vector
//! states every criterion it fails). The V2-only and V5-only vectors must also be accepted by
//! `ed25519-dalek`'s non-strict `verify` (review 2026-11-18 M2, F-1).
//!
//! Keys come only from public seeds: key A = `SigningKey::from_bytes(&[0x01; 32])`, key B =
//! `SigningKey::from_bytes(&[0x02; 32])`. Signing is deterministic (RFC 8032 §5.1.6).
//!
//! Needs the `vector-gen` feature (`ed25519-dalek/hazmat` and `digest`), for the mixed-order cases
//! only. Tooling: it reads no network input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::{Add, Mul};
use std::path::{Path, PathBuf};

use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Digest, Sha512, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sbtp_core::{
    BlockBuilder, BlockId, S_PLUS_L_BLOCK, SELF_TEST_BLOCK_ID, SELF_TEST_VALID_BLOCK, mine, parse,
    validate_requested, validate_submitted,
};

/// spec §3.1, written out again on purpose (not `sbtp_core::BLOCK_ID_CONTEXT`).
const CONTEXT: &str = "SBTP 2026-11-18 block_id v1";
/// spec §3.2, written out again on purpose (not `sbtp_core::SIG_PREFIX`).
const PREFIX: &[u8; 17] = b"SBTP-v1-block-sig";
/// A fixed timestamp: 2023-11-14T22:13:20Z in milliseconds.
const TIMESTAMP: u64 = 1_700_000_000_000;
/// `L`, little-endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
/// The 8 small-order points, canonical encodings.
const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];
/// Names of the small-order points, for the vector names.
const SMALL_ORDER_NAMES: [&str; 8] = [
    "identity", "order2", "order4_a", "order4_b", "order8_a", "order8_b", "order8_c", "order8_d",
];

const KEY_A: &str = "key A (public seed 32 x 0x01)";
const KEY_B: &str = "key B (public seed 32 x 0x02)";

struct Vector {
    name: String,
    description: String,
    block: Vec<u8>,
    difficulty: u32,
    requested: Option<[u8; 32]>,
    /// F1 to F9 pass.
    well_formed: bool,
    /// `None` for a valid block.
    error: Option<&'static str>,
}

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

fn key_b() -> SigningKey {
    SigningKey::from_bytes(&[0x02; 32])
}

fn pid(n: u8) -> BlockId {
    BlockId([n; 32])
}

fn parents(count: u8) -> Vec<BlockId> {
    (1..=count).map(pid).collect()
}

/// A deterministic payload of `len` bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 251) as u8)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Little-endian encoding of `y + p`, `p = 2^255 - 19`, for a small `y`.
fn y_plus_p(y: u8) -> [u8; 32] {
    let mut out = [0xffu8; 32];
    out[0] = 0xed + y;
    out[31] = 0x7f;
    out
}

/// Little-endian encoding of a small `y`, sign bit as given.
fn small_y(y: u8, sign: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = y;
    if sign {
        out[31] = 0x80;
    }
    out
}

/// `a + b` over 256-bit little-endian integers, no overflow allowed.
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// `x mod L` for a 512-bit little-endian `x`, by binary long division. Independent of
/// `curve25519-dalek`. Returns the remainder, little-endian.
fn mod_l(x: &[u8; 64]) -> [u8; 32] {
    let l = le_to_limbs(&L_LE);
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        // r = 2r + bit. r < L < 2^253 before the shift, so 2r + 1 < 2^254: no limb overflows.
        let mut carry = u64::from((x[bit / 8] >> (bit % 8)) & 1);
        for limb in &mut r {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        assert_eq!(carry, 0);
        if ge(&r, &l) {
            sub(&mut r, &l);
        }
    }
    let mut out = [0u8; 32];
    for (i, limb) in r.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn le_to_limbs(x: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(x[8 * i..8 * i + 8].try_into().unwrap());
    }
    out
}

fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
        a[i] = d2;
        borrow = b1 || b2;
    }
    assert!(!borrow);
}

/// The `block_id` of a buffer whose length is known to be exact: `derive_key` over everything but
/// the last 64 bytes (spec §3.1).
fn id_of(block: &[u8]) -> [u8; 32] {
    blake3::derive_key(CONTEXT, &block[..block.len() - 64])
}

fn signed_message(id: &[u8; 32]) -> Vec<u8> {
    let mut m = PREFIX.to_vec();
    m.extend_from_slice(id);
    m
}

fn leading_zero_bits(id: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in id {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// Writes `Ed25519_Sign(key, SIG_PREFIX || block_id)` into the last 64 bytes, the `block_id` being
/// computed over the buffer as it is (also for a buffer that fails F3, F4, F5 or F9).
fn sign_raw(block: &mut [u8], key: &SigningKey) {
    let id = id_of(block);
    let sig = key.sign(&signed_message(&id)).to_bytes();
    set_sig(block, &sig);
}

fn set_sig(block: &mut [u8], sig: &[u8; 64]) {
    let off = block.len() - 64;
    block[off..].copy_from_slice(sig);
}

fn sig_of(block: &[u8]) -> [u8; 64] {
    block[block.len() - 64..].try_into().unwrap()
}

fn builder<'a>(key: &SigningKey) -> BlockBuilder<'a> {
    BlockBuilder::for_key(key).timestamp(TIMESTAMP)
}

/// A valid block signed by key A.
fn signed(ps: &[BlockId], payload: &[u8]) -> Vec<u8> {
    let key = key_a();
    let mut block = builder(&key)
        .parents(ps)
        .payload(payload)
        .build_unsigned()
        .unwrap();
    sign_raw(&mut block, &key);
    block
}

/// An unsigned block for an arbitrary public key.
fn with_key(pubkey: [u8; 32], ps: &[BlockId], payload: &[u8]) -> Vec<u8> {
    BlockBuilder::new(pubkey)
        .timestamp(TIMESTAMP)
        .parents(ps)
        .payload(payload)
        .build_unsigned()
        .unwrap()
}

/// Raw frame with an arbitrary Parents Count (F5 cases): header, `parents` written as given,
/// Payload Len, payload, zero signature.
fn raw_frame(pubkey: &[u8; 32], count: u8, ps: &[BlockId], payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x53, 0x42, 0x01];
    b.extend_from_slice(&TIMESTAMP.to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    b.extend_from_slice(pubkey);
    b.push(count);
    for p in ps {
        b.extend_from_slice(p.as_bytes());
    }
    b.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    b.extend_from_slice(payload);
    b.extend_from_slice(&[0u8; 64]);
    b
}

/// The mixed-order public key `A' = a*B + T`, `T` of order 8, `a` the scalar of key A.
fn mixed_order_key() -> (ExpandedSecretKey, VerifyingKey) {
    let key = key_a();
    let esk = ExpandedSecretKey::from(&key.to_bytes());
    let torsion = VerifyingKey::from_bytes(&hex32(SMALL_ORDER[4]))
        .unwrap()
        .to_edwards();
    let mixed = VerifyingKey::from(key.verifying_key().to_edwards() + torsion);
    assert!(!mixed.is_weak());
    (esk, mixed)
}

/// A block under the mixed-order key, signed with `a` and `A'` in the hash, and the two predictions
/// of the cofactorless equation: with `k` reduced mod `L` (the rule of V6) and unreduced.
/// `[S]B - [k]A' = R - [k]T`, equal to `R` iff `k = 0 (mod 8)`.
fn mixed_order_block(nonce: u64) -> (Vec<u8>, bool, bool) {
    let (esk, mixed) = mixed_order_key();
    let mut block = BlockBuilder::new(mixed.to_bytes())
        .timestamp(TIMESTAMP)
        .nonce(nonce)
        .payload(b"mixed order")
        .build_unsigned()
        .unwrap();
    let id = id_of(&block);
    let message = signed_message(&id);
    let sig = raw_sign::<Sha512>(&esk, &message, &mixed).to_bytes();
    set_sig(&mut block, &sig);

    let mut h = Sha512::new();
    h.update(&sig[..32]);
    h.update(mixed.as_bytes());
    h.update(&message);
    let digest: [u8; 64] = h.finalize().as_slice().try_into().unwrap();
    let reduced_accepts = mod_l(&digest)[0] % 8 == 0;
    let unreduced_accepts = digest[0] % 8 == 0;
    (block, reduced_accepts, unreduced_accepts)
}

// ---------------------------------------------------------------------------------------------
// Independent evaluation of the signature criteria V1 to V6 (spec §3.2), without sbtp-core and
// without `verify_strict`: point arithmetic of curve25519-dalek (reached through values, its types
// are not re-exported), SHA-512 and the local `mod_l`.
// ---------------------------------------------------------------------------------------------

/// Canonical encoding of the identity point.
const IDENTITY: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};
/// Canonical encoding of the base point `B` (RFC 8032 §5.1).
const BASEPOINT: &str = "5866666666666666666666666666666666666666666666666666666666666666";

/// A scalar of the same type as `like`, from a 256-bit little-endian integer (reduced mod `L`).
fn scalar_like<T>(_like: &T, le: &[u8; 32]) -> T
where
    T: Copy + From<u64> + Add<Output = T> + Mul<Output = T>,
{
    let radix = T::from(256);
    le.iter()
        .rev()
        .fold(T::from(0), |acc, b| acc * radix + T::from(u64::from(*b)))
}

/// Canonical encoding of a point.
fn compress<P>(p: P) -> [u8; 32]
where
    VerifyingKey: From<P>,
{
    VerifyingKey::from(p).to_bytes()
}

/// `[8]P`, by three doublings.
fn times8<P: Copy + Add<Output = P>>(p: P) -> P {
    let p2 = p + p;
    let p4 = p2 + p2;
    p4 + p4
}

/// `k = SHA-512(R || A || M) mod L`, `R` and `A` as received (spec §3.2 V6).
fn k_of(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(message);
    mod_l(&h.finalize().as_slice().try_into().unwrap())
}

/// Which of V1 to V6 fail, hold, or cannot be evaluated (a `PubKey` or `R` that does not decode).
#[derive(Debug, Default, PartialEq)]
struct Criteria {
    fails: Vec<&'static str>,
    holds: Vec<&'static str>,
    unevaluated: Vec<&'static str>,
}

impl Criteria {
    fn put(&mut self, name: &'static str, fails: Option<bool>) {
        match fails {
            Some(true) => self.fails.push(name),
            Some(false) => self.holds.push(name),
            None => self.unevaluated.push(name),
        }
    }

    /// The error sbtp-core must return once the format, R1 and C1 have passed (spec §2.2).
    fn expected_error(&self) -> Option<&'static str> {
        if self.fails.iter().any(|c| *c == "V1" || *c == "V2") {
            Some("InvalidPublicKey")
        } else if self.fails.is_empty() {
            None
        } else {
            Some("InvalidSignature")
        }
    }

    /// The sentence appended to every well-formed vector's description.
    fn sentence(&self) -> String {
        let list = |v: &[&str]| v.join(", ");
        let mut s = String::from("Signature criteria (spec 3.2, evaluated by the generator): ");
        if self.fails.is_empty() {
            s.push_str("V1 to V6 all hold.");
            return s;
        }
        write!(
            s,
            "fails {}; holds {}",
            list(&self.fails),
            if self.holds.is_empty() {
                "none".to_owned()
            } else {
                list(&self.holds)
            }
        )
        .unwrap();
        for c in &self.unevaluated {
            let why = if *c == "V5" {
                "R does not decode"
            } else {
                "PubKey does not decode"
            };
            write!(s, "; {c} not evaluable ({why})").unwrap();
        }
        if self.fails.contains(&"V3") && self.holds.contains(&"V6") {
            s.push_str(" (V6 evaluated with S mod L)");
        }
        s.push('.');
        s
    }
}

/// Evaluates V1 to V6 for `pubkey`, `sig` over `message`. V6 is evaluated with `S mod L`, as a
/// verifier that skips V3 would; `k` is reduced mod `L`.
fn analyze(pubkey: &[u8; 32], sig: &[u8; 64], message: &[u8]) -> Criteria {
    let key = key_a();
    let esk = ExpandedSecretKey::from(&key.to_bytes());
    // B = [a^-1]A for key A.
    let base = key.verifying_key().to_edwards() * esk.scalar.invert();
    assert_eq!(hex(&compress(base)), BASEPOINT);

    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    // RFC 8032 §5.1.3 decoding (lenient on canonicity; V1 adds the recompression test).
    let a_point = VerifyingKey::from_bytes(pubkey)
        .ok()
        .map(|k| k.to_edwards());
    let r_point = VerifyingKey::from_bytes(&r).ok().map(|k| k.to_edwards());

    let mut c = Criteria::default();
    c.put("V1", Some(a_point.is_none_or(|p| compress(p) != *pubkey)));
    c.put("V2", a_point.map(|p| compress(times8(p)) == IDENTITY));
    c.put("V3", Some(ge(&le_to_limbs(&s), &le_to_limbs(&L_LE))));
    c.put("V4", Some(r_point.is_none()));
    c.put("V5", r_point.map(|p| compress(times8(p)) == IDENTITY));
    c.put(
        "V6",
        a_point.map(|a| {
            let k = scalar_like(&esk.scalar, &k_of(&r, pubkey, message));
            let s = scalar_like(&esk.scalar, &s);
            compress(base * s - a * k) != r
        }),
    );
    c
}

/// Analyses a well-formed block.
fn analyze_block(block: &[u8]) -> Criteria {
    let pubkey: [u8; 32] = block[19..51].try_into().unwrap();
    analyze(&pubkey, &sig_of(block), &signed_message(&id_of(block)))
}

/// V5 only: `PubKey` `A'` (mixed order), `R` the small-order point `r`, `S = k*a mod L`, nonce
/// searched from 0 until `[S]B - [k]A' = -[k]T = R`. Returns the nonce and the block.
fn v5_only(r: [u8; 32]) -> (u64, Vec<u8>) {
    let (esk, mixed) = mixed_order_key();
    for nonce in 0..1_000u64 {
        let mut block = BlockBuilder::new(mixed.to_bytes())
            .timestamp(TIMESTAMP)
            .nonce(nonce)
            .payload(b"v5 only")
            .build_unsigned()
            .unwrap();
        let message = signed_message(&id_of(&block));
        let k = scalar_like(&esk.scalar, &k_of(&r, mixed.as_bytes(), &message));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&(k * esk.scalar).to_bytes());
        set_sig(&mut block, &sig);
        if analyze_block(&block).fails == ["V5"] {
            return (nonce, block);
        }
    }
    panic!("no V5-only nonce");
}

/// V2 only, or V1 and V2 for a non-canonical identity: `PubKey` `p`, `R = [r]B + torsion`,
/// `S = r = 12345`, nonce searched from 0 until exactly `want` fails (`[k]P = -torsion`).
fn v2_only(p: [u8; 32], torsion: Option<[u8; 32]>, want: &[&str]) -> (u64, Vec<u8>) {
    let key = key_a();
    let esk = ExpandedSecretKey::from(&key.to_bytes());
    let base = key.verifying_key().to_edwards() * esk.scalar.invert();
    let r_scalar = scalar_like(&esk.scalar, &{
        let mut b = [0u8; 32];
        b[..2].copy_from_slice(&12_345u16.to_le_bytes());
        b
    });
    let mut r_point = base * r_scalar;
    if let Some(t) = torsion {
        r_point += VerifyingKey::from_bytes(&t).unwrap().to_edwards();
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&compress(r_point));
    sig[32..].copy_from_slice(&r_scalar.to_bytes());
    for nonce in 0..1_000u64 {
        let mut block = with_key(p, &[], b"v2 only");
        block[11..19].copy_from_slice(&nonce.to_be_bytes());
        set_sig(&mut block, &sig);
        if analyze_block(&block).fails == want {
            return (nonce, block);
        }
    }
    panic!("no V2-only nonce");
}

/// The two blocks of docs/security/2026-11-18-sbtp-core-m2.md (F-1), built there with an
/// independent Python implementation: the generator must reproduce them byte for byte.
const AUDIT_V5_ONLY_IDENTITY: &str = concat!(
    "5342010000018bcfe56800000000000000000a9ea3f11f5bd34f0cd7147fd0a436c088f624c6100c1df6a53c0a29e05d60cea0",
    "0000077635206f6e6c790100000000000000000000000000000000000000000000000000000000000000f44ddf53b87e6e0c",
    "b4c299d6e42af0a87153a98c76cf97bd110a3f4a69868807",
);
/// The report prints 254 hex digits for this 125-byte block: four trailing `0` digits too many
/// (as printed it would fail F8). The 250 digits below are the report's, without that excess.
const AUDIT_V2_ONLY_IDENTITY: &str = concat!(
    "5342010000018bcfe5680000000000000000000100000000000000000000000000000000000000000000000000000000000000",
    "0000077632206f6e6c79ef4f62f8479733ad879cfaced3c89a9c39dd4fc795ef2efa1c3eafe4d729a081393000000000000000",
    "0000000000000000000000000000000000000000000000",
);

fn all_vectors() -> Vec<Vector> {
    let mut v = Vec::new();
    let mut push = |name: &str,
                    description: String,
                    block: Vec<u8>,
                    difficulty: u32,
                    requested: Option<[u8; 32]>,
                    well_formed: bool,
                    error: Option<&'static str>| {
        v.push(Vector {
            name: name.to_owned(),
            description,
            block,
            difficulty,
            requested,
            well_formed,
            error,
        });
    };
    let valid = |s: &str| format!("Valid. {s} Signed by {KEY_A}, timestamp {TIMESTAMP}.");
    let first = "Rule order: this is the first failing check; later checks are not evaluated.";

    // ------------------------------------------------------------------ valid blocks
    push(
        "valid_0_parents_empty_payload",
        valid("Minimum size: 118 bytes, no parent, empty payload."),
        signed(&[], &[]),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_1_parent",
        valid("One parent (32 x 0x01), payload \"one parent\": offsets with N = 1."),
        signed(&parents(1), b"one parent"),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_8_parents",
        valid("8 parents (32 x 0x01 to 32 x 0x08), payload \"eight\": F5 boundary (ADR 0014)."),
        signed(&parents(8), b"eight"),
        0,
        None,
        true,
        None,
    );
    let max_block = signed(&parents(8), &pattern(65_535));
    assert_eq!(max_block.len(), 65_909);
    push(
        "valid_max_size",
        valid(
            "Maximum size: 65,909 bytes, 8 parents, payload of 65,535 bytes \
             (byte i = (31 i + 7) mod 251). F2 boundary.",
        ),
        max_block.clone(),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_parents_empty_payload",
        valid("3 parents, empty payload (P = 0)."),
        signed(&parents(3), &[]),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_0_parents_max_payload",
        valid(
            "No parent, payload of 65,535 bytes (byte i = (31 i + 7) mod 251): P = 65,535, \
             65,653 bytes.",
        ),
        signed(&[], &pattern(65_535)),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_zero_parent_hash",
        valid("Two parents, the first one 32 zero bytes: a parent hash is opaque (ADR 0004)."),
        signed(&[pid(0), pid(7)], b"zero parent"),
        0,
        None,
        true,
        None,
    );
    push(
        "valid_unsorted_parents",
        valid(
            "Parents 32 x 0x03, 32 x 0x01, 32 x 0x02, in this non-sorted order: order is \
             significant and kept.",
        ),
        signed(&[pid(3), pid(1), pid(2)], b"unsorted"),
        0,
        None,
        true,
        None,
    );
    for (name, ts) in [
        ("valid_timestamp_zero", 0),
        ("valid_timestamp_max", u64::MAX),
    ] {
        let key = key_a();
        let mut block = BlockBuilder::for_key(&key)
            .timestamp(ts)
            .payload(b"timestamp")
            .build_unsigned()
            .unwrap();
        sign_raw(&mut block, &key);
        push(
            name,
            format!(
                "Valid. Timestamp {ts}: no format rule on Timestamp (ADR 0004). Signed by {KEY_A}."
            ),
            block,
            0,
            None,
            true,
            None,
        );
    }
    {
        let key = key_a();
        let mut block = builder(&key)
            .nonce(0x0102_0304_0506_0708)
            .payload(b"nonce")
            .build_unsigned()
            .unwrap();
        assert_eq!(&block[11..19], &[1, 2, 3, 4, 5, 6, 7, 8]);
        sign_raw(&mut block, &key);
        push(
            "valid_nonce_distinct_bytes",
            valid(
                "Nonce 0x0102030405060708, encoded big-endian as bytes 01 .. 08 at offset 11 \
                 (ADR 0001).",
            ),
            block,
            0,
            None,
            true,
            None,
        );
    }
    // PoW at the threshold, and one bit short.
    let (pow_block, pow_bits) = {
        let key = key_a();
        let mut block = builder(&key).payload(b"pow").build_unsigned().unwrap();
        mine(&mut block, 12, 1 << 24).unwrap();
        sign_raw(&mut block, &key);
        let bits = leading_zero_bits(&id_of(&block));
        assert!(bits >= 12);
        (block, bits)
    };
    push(
        "valid_pow_at_threshold",
        valid(&format!(
            "Payload \"pow\", nonce mined from 0: the block_id has exactly {pow_bits} leading \
             zero bits and the difficulty is {pow_bits}. C1 boundary."
        )),
        pow_block.clone(),
        pow_bits,
        None,
        true,
        None,
    );

    // Mixed-order key: first nonce where the reduced and unreduced predictions differ, each way.
    let mut accepted = None;
    let mut rejected = None;
    for nonce in 0..10_000u64 {
        let (block, reduced, unreduced) = mixed_order_block(nonce);
        if reduced && !unreduced && accepted.is_none() {
            accepted = Some((nonce, block));
        } else if !reduced && unreduced && rejected.is_none() {
            rejected = Some((nonce, block));
        }
        if accepted.is_some() && rejected.is_some() {
            break;
        }
    }
    let (acc_nonce, acc_block) = accepted.unwrap();
    let (rej_nonce, rej_block) = rejected.unwrap();
    push(
        "valid_mixed_order_pubkey",
        format!(
            "Valid. PubKey A' = a*B + T, a the scalar of {KEY_A}, T the order-8 point {}; nonce \
             {acc_nonce}, payload \"mixed order\". Signed with a and A' in the hash. \
             k = SHA-512(R || A' || M) mod L is 0 mod 8, so [S]B - [k]A' = R and V6 holds; the \
             unreduced digest is not 0 mod 8: this pins the mod L of V6 (ADR 0003).",
            SMALL_ORDER[4]
        ),
        acc_block,
        0,
        None,
        true,
        None,
    );
    let r1_block = signed(&parents(2), b"requested");
    let r1_id = id_of(&r1_block);
    push(
        "valid_requested_id_matches",
        valid("Two parents, payload \"requested\"; requested_block_id is its block_id: R1 passes."),
        r1_block.clone(),
        0,
        Some(r1_id),
        true,
        None,
    );
    push(
        "self_test_valid",
        valid(
            "No parent, payload \"S + L\". The unmodified block of the S + L vector, replayed at \
             start-up (ADR 0003 rule 16); exported by sbtp-core as SELF_TEST_VALID_BLOCK.",
        ),
        self_test_block(),
        0,
        None,
        true,
        None,
    );

    // ------------------------------------------------------------------ F1 to F9
    push(
        "f1_empty",
        "Empty buffer. F1.".to_owned(),
        Vec::new(),
        0,
        None,
        false,
        Some("TooShort"),
    );
    {
        let mut b = signed(&[], &[]);
        b.pop();
        push(
            "f1_117_bytes",
            "The minimum valid block (vector valid_0_parents_empty_payload) without its last \
             byte: 117 bytes. F1; the conditions of F6 and F7 (len < 118) hold too. {first}"
                .replace("{first}", first),
            b,
            0,
            None,
            false,
            Some("TooShort"),
        );
    }
    {
        let mut b = max_block.clone();
        b.push(0x00);
        push(
            "f2_65910_bytes",
            format!(
                "The maximum-size block (vector valid_max_size) followed by one 0x00 byte: \
                 65,910 bytes. F2; F8 would also fail. {first}"
            ),
            b,
            0,
            None,
            false,
            Some("TooLong"),
        );
    }
    for (name, pos, value, what) in [
        (
            "f3_bad_magic_first_byte",
            0usize,
            0x54u8,
            "first magic byte 0x54",
        ),
        (
            "f3_bad_magic_second_byte",
            1,
            0x43,
            "second magic byte 0x43",
        ),
    ] {
        let mut b = signed(&[], b"magic");
        b[pos] = value;
        sign_raw(&mut b, &key_a());
        push(
            name,
            format!(
                "No parent, payload \"magic\", {what}; signed by {KEY_A} over the modified bytes, \
                 so only F3 fails."
            ),
            b,
            0,
            None,
            false,
            Some("BadMagic"),
        );
    }
    for (name, version) in [("f4_version_0", 0x00u8), ("f4_version_2", 0x02)] {
        let mut b = signed(&[], b"version");
        b[2] = version;
        sign_raw(&mut b, &key_a());
        push(
            name,
            format!(
                "No parent, payload \"version\", Version byte 0x{version:02x}; signed by {KEY_A} \
                 over the modified bytes, so only F4 fails."
            ),
            b,
            0,
            None,
            false,
            Some("UnsupportedVersion"),
        );
    }
    for count in [9u8, 255] {
        let ps: Vec<BlockId> = (0..count)
            .map(|i| BlockId(blake3::derive_key("SBTP test vectors v1 parent", &[i])))
            .collect();
        let mut b = raw_frame(key_a().verifying_key().as_bytes(), count, &ps, &[]);
        sign_raw(&mut b, &key_a());
        push(
            &format!("f5_{count}_parents"),
            format!(
                "Parents Count {count}, followed by {count} distinct parents (parent i = \
                 BLAKE3_derive_key(\"SBTP test vectors v1 parent\", [i])), empty payload and a \
                 signature by {KEY_A}: the layout would be consistent, only F5 fails. {} bytes.",
                b.len()
            ),
            b,
            0,
            None,
            false,
            Some("TooManyParents"),
        );
    }
    {
        let mut b = signed(&parents(4), b"parents");
        b.truncate(52 + 32 * 2 + 16);
        push(
            "f6_truncated_in_parents",
            format!(
                "A valid 4-parent block cut after 2.5 parents: {} bytes, 246 needed for 4 \
                 parents, Payload Len and the signature. F6.",
                b.len()
            ),
            b,
            0,
            None,
            false,
            Some("Truncated"),
        );
    }
    {
        let mut b = signed(&[], &pattern(200));
        b.truncate(54 + 150);
        push(
            "f7_truncated_in_payload",
            "A valid block with no parent and a 200-byte payload cut after 150 payload bytes: \
             204 bytes, 318 expected. F7."
                .to_owned(),
            b,
            0,
            None,
            false,
            Some("Truncated"),
        );
    }
    {
        let mut b = signed(&parents(1), b"last byte");
        b.pop();
        push(
            "f7_last_signature_byte_missing",
            "A valid one-parent block without the last signature byte. F7.".to_owned(),
            b,
            0,
            None,
            false,
            Some("Truncated"),
        );
    }
    {
        let mut b = signed(&parents(1), b"extra byte");
        b.push(0x00);
        push(
            "f8_one_extra_byte",
            "A valid one-parent block followed by one 0x00 byte. F8.".to_owned(),
            b,
            0,
            None,
            false,
            Some("TrailingBytes"),
        );
    }
    for (name, ps, what) in [
        (
            "f9_adjacent_duplicates",
            vec![pid(1), pid(2), pid(2), pid(3)],
            "parents 1, 2, 2, 3 (positions 1 and 2 identical)",
        ),
        (
            "f9_non_adjacent_duplicates",
            vec![pid(1), pid(2), pid(3), pid(1)],
            "parents 1, 2, 3, 1 (positions 0 and 3 identical)",
        ),
    ] {
        let mut b = raw_frame(key_a().verifying_key().as_bytes(), 4, &ps, b"duplicate");
        sign_raw(&mut b, &key_a());
        push(
            name,
            format!(
                "Parent n is 32 x n; {what}; payload \"duplicate\"; signed by {KEY_A}, so only \
                 F9 fails."
            ),
            b,
            0,
            None,
            false,
            Some("DuplicateParent"),
        );
    }

    // ------------------------------------------------------------------ R1
    {
        let mut other = r1_id;
        other[31] ^= 0x01;
        push(
            "r1_block_id_mismatch",
            "The block of vector valid_requested_id_matches, requested by its block_id with the \
             lowest bit of the last byte flipped. R1."
                .to_owned(),
            r1_block,
            0,
            Some(other),
            true,
            Some("BlockIdMismatch"),
        );
    }

    // ------------------------------------------------------------------ C1
    push(
        "c1_insufficient_pow",
        format!(
            "The block of vector valid_pow_at_threshold ({pow_bits} leading zero bits) at \
             difficulty {}: one bit short. C1.",
            pow_bits + 1
        ),
        pow_block,
        pow_bits + 1,
        None,
        true,
        Some("InsufficientPow"),
    );

    // ------------------------------------------------------------------ C2
    let c2 = |pubkey: [u8; 32]| {
        let mut b = with_key(pubkey, &[], b"c2");
        sign_raw(&mut b, &key_a());
        b
    };
    let c2_tail = format!(
        "No parent, payload \"c2\", signature by {KEY_A} over the right message, so it is not a \
         signature for this PubKey; C2 is reported before C3."
    );
    push(
        "c2_v1_y_not_on_curve",
        format!("PubKey y = 2, not on the curve (V1). {c2_tail}"),
        c2(small_y(2, false)),
        0,
        None,
        true,
        Some("InvalidPublicKey"),
    );
    push(
        "c2_v1_non_canonical_not_small_order",
        format!(
            "PubKey y = 3 + p, p = 2^255 - 19: non-canonical encoding of a point that is not of \
             small order (V1). {c2_tail}"
        ),
        c2(y_plus_p(3)),
        0,
        None,
        true,
        Some("InvalidPublicKey"),
    );
    for y in [0u8, 1] {
        push(
            &format!("c2_v1_non_canonical_small_order_y{y}"),
            format!(
                "PubKey y = {y} + p: non-canonical encoding of a small-order point; V1 fires \
                 before V2. {c2_tail}"
            ),
            c2(y_plus_p(y)),
            0,
            None,
            true,
            Some("InvalidPublicKey"),
        );
    }
    {
        let mut minus_one = hex32(SMALL_ORDER[1]);
        minus_one[31] |= 0x80;
        for (name, enc, what) in [
            ("c2_v1_x_zero_sign_bit_y1", small_y(1, true), "y = 1"),
            ("c2_v1_x_zero_sign_bit_y_minus_1", minus_one, "y = -1"),
        ] {
            push(
                name,
                format!("PubKey {what} (x = 0) with the sign bit set (V1). {c2_tail}"),
                c2(enc),
                0,
                None,
                true,
                Some("InvalidPublicKey"),
            );
        }
    }
    for (point, pname) in SMALL_ORDER.iter().zip(SMALL_ORDER_NAMES) {
        push(
            &format!("c2_v2_small_order_{pname}_and_v6"),
            format!(
                "PubKey {point}, canonical small-order point (V2). {c2_tail} Combined case: V6 \
                 fails too. V2 alone is isolated by vector c2_v2_only_{pname}."
            ),
            c2(hex32(point)),
            0,
            None,
            true,
            Some("InvalidPublicKey"),
        );
    }
    // V2 alone (review 2026-11-18 M2, F-1): the cofactorless equation holds.
    for (point, pname) in SMALL_ORDER.iter().zip(SMALL_ORDER_NAMES) {
        let (nonce, block) = v2_only(hex32(point), None, &["V2"]);
        if pname == "identity" {
            assert_eq!(hex(&block), AUDIT_V2_ONLY_IDENTITY, "audit V2-only block");
        }
        push(
            &format!("c2_v2_only_{pname}"),
            format!(
                "PubKey P = {point}, canonical small-order point (V2). R = [r]B, S = r = 12345; \
                 nonce {nonce}, searched from 0 so that [k]P is the identity, hence \
                 [S]B - [k]P = R: the cofactorless equation V6 holds. No parent, payload \
                 \"v2 only\". Isolates V2: a verifier without the small-order check on PubKey \
                 accepts this block."
            ),
            block,
            0,
            None,
            true,
            Some("InvalidPublicKey"),
        );
    }
    {
        let t = hex32(SMALL_ORDER[4]);
        let (nonce, block) = v2_only(t, Some(t), &["V2"]);
        push(
            "c2_v2_only_order8_a_torsion_r",
            format!(
                "PubKey P = T = {}, canonical point of order 8 (V2). R = [r]B + T, S = r = 12345: \
                 R has a torsion component but is not of small order. Nonce {nonce}, searched \
                 from 0 so that [k]P = -T, hence [S]B - [k]P = [r]B + T = R: V6 holds. No parent, \
                 payload \"v2 only\". Isolates V2.",
                SMALL_ORDER[4]
            ),
            block,
            0,
            None,
            true,
            Some("InvalidPublicKey"),
        );
    }
    {
        let (nonce, block) = v2_only(y_plus_p(1), None, &["V1", "V2"]);
        push(
            "c2_v1_v2_non_canonical_identity",
            format!(
                "PubKey y = 1 + p, a non-canonical encoding of the identity (V1, and V2 since the \
                 point is the identity). R = [S]B, S = 12345, nonce {nonce}: [S]B - [k]I = R, so V6 \
                 holds with A entering SHA-512 as received. No parent, payload \"v2 only\". A \
                 verifier lacking both the canonicity part of V1 and V2 accepts it."
            ),
            block,
            0,
            None,
            true,
            Some("InvalidPublicKey"),
        );
    }

    // ------------------------------------------------------------------ C3
    push(
        "c3_v3_s_plus_l",
        "The block of vector self_test_valid with S replaced by S + L, \
         L = 2^252 + 27742317777372353535851937790883648493 (V3). Mandatory; replayed at \
         start-up (ADR 0003 rule 16); exported by sbtp-core as S_PLUS_L_BLOCK. Accepted only by \
         a verifier that does not enforce S < L."
            .to_owned(),
        s_plus_l_block(),
        0,
        None,
        true,
        Some("InvalidSignature"),
    );
    let c3_base = signed(&[], b"c3");
    let c3_with = |r: Option<[u8; 32]>| {
        let mut b = c3_base.clone();
        let mut sig = sig_of(&b);
        if let Some(r) = r {
            sig[..32].copy_from_slice(&r);
        }
        set_sig(&mut b, &sig);
        b
    };
    let c3_tail = format!("No parent, payload \"c3\", {KEY_A}, S of the valid signature.");
    push(
        "c3_v4_r_not_on_curve",
        format!("R replaced by y = 2, which does not decode to a point (V4). {c3_tail}"),
        c3_with(Some(small_y(2, false))),
        0,
        None,
        true,
        Some("InvalidSignature"),
    );
    for (point, pname) in SMALL_ORDER.iter().zip(SMALL_ORDER_NAMES) {
        push(
            &format!("c3_v5_r_small_order_{pname}_and_v6"),
            format!(
                "R replaced by the small-order point {point} (V5). {c3_tail} Combined case: \
                 V6 fails too. V5 alone is isolated by vector c3_v5_only_r_{pname}."
            ),
            c3_with(Some(hex32(point))),
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    // V5 alone (review 2026-11-18 M2, F-1): the cofactorless equation holds.
    for (point, pname) in SMALL_ORDER.iter().zip(SMALL_ORDER_NAMES) {
        let (nonce, block) = v5_only(hex32(point));
        if pname == "identity" {
            assert_eq!(hex(&block), AUDIT_V5_ONLY_IDENTITY, "audit V5-only block");
        }
        push(
            &format!("c3_v5_only_r_{pname}"),
            format!(
                "PubKey A' = a*B + T as in vector valid_mixed_order_pubkey (T = {}, order 8). \
                 R = {point}, a small-order point (V5). S = k*a mod L with \
                 k = SHA-512(R || A' || M) mod L, so [S]B - [k]A' = -[k]T; nonce {nonce}, \
                 searched from 0 so that -[k]T = R: the cofactorless equation V6 holds. No \
                 parent, payload \"v5 only\". Isolates V5: a verifier without the small-order \
                 check on R accepts this block.",
                SMALL_ORDER[4]
            ),
            block,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    push(
        "c3_v6_non_canonical_r",
        format!(
            "R replaced by y = 3 + p, a non-canonical encoding of a point not of small order: \
             never the canonical encoding of [S]B - [k]A (V6). {c3_tail}"
        ),
        c3_with(Some(y_plus_p(3))),
        0,
        None,
        true,
        Some("InvalidSignature"),
    );
    push(
        "c3_v6_cofactored_only",
        format!(
            "PubKey A' = a*B + T as in vector valid_mixed_order_pubkey, nonce {rej_nonce}. \
             k = SHA-512(R || A' || M) mod L is not 0 mod 8, so [S]B - [k]A' = R - [k]T differs \
             from R: the cofactorless equation fails, the cofactored one [8][S]B = [8]R + [8][k]A' \
             holds (V6). The unreduced digest is 0 mod 8: a verifier that skips the reduction \
             accepts it."
        ),
        rej_block,
        0,
        None,
        true,
        Some("InvalidSignature"),
    );
    {
        let mut r_flip = c3_base.clone();
        let off = r_flip.len() - 64;
        r_flip[off] ^= 0x04;
        push(
            "c3_bit_flipped_in_r",
            format!("Bit 2 of the first byte of R flipped. {c3_tail}"),
            r_flip,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
        let mut s_flip = c3_base.clone();
        let off = s_flip.len() - 64 + 40;
        s_flip[off] ^= 0x04;
        push(
            "c3_bit_flipped_in_s",
            format!("Bit 2 of byte 8 of S flipped (S stays below L). {c3_tail}"),
            s_flip,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    {
        let mut b = signed(&parents(2), b"flip");
        let off = b.len() - 65;
        b[off] ^= 0x01;
        push(
            "c3_bit_flipped_in_payload",
            format!(
                "Two parents, payload \"flip\" signed by {KEY_A}, then the lowest bit of the last \
                 payload byte flipped (\"flio\"); signature unchanged."
            ),
            b,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    {
        let key = key_a();
        let mut b = signed(&[], b"raw");
        let id = id_of(&b);
        let sig = key.sign(&id).to_bytes();
        set_sig(&mut b, &sig);
        push(
            "c3_signature_without_prefix",
            format!(
                "No parent, payload \"raw\"; signature by {KEY_A} over the 32 raw block_id bytes, \
                 without SIG_PREFIX (ADR 0002)."
            ),
            b,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    {
        let key = key_a();
        let mut b = signed(&[], b"plain");
        let plain = *blake3::hash(&b[..b.len() - 64]).as_bytes();
        assert_ne!(plain, id_of(&b));
        let sig = key.sign(&signed_message(&plain)).to_bytes();
        set_sig(&mut b, &sig);
        push(
            "c3_signature_over_plain_blake3",
            format!(
                "No parent, payload \"plain\"; signature by {KEY_A} over SIG_PREFIX || \
                 BLAKE3(hashed bytes) in plain hash mode instead of derive_key (ADR 0002)."
            ),
            b,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    {
        let mut b = signed(&[], b"other");
        let id = id_of(&b);
        let sig = key_b().sign(&signed_message(&id)).to_bytes();
        set_sig(&mut b, &sig);
        push(
            "c3_signature_by_another_key",
            format!(
                "No parent, payload \"other\", PubKey of {KEY_A}; valid signature of the right \
                 message by {KEY_B}."
            ),
            b,
            0,
            None,
            true,
            Some("InvalidSignature"),
        );
    }
    v
}

/// The unmodified block of the `S + L` vector.
fn self_test_block() -> Vec<u8> {
    signed(&[], b"S + L")
}

/// The block of [`self_test_block`] with `S` replaced by `S + L` (spec §3.2 V3).
fn s_plus_l_block() -> Vec<u8> {
    let mut b = self_test_block();
    let mut sig = sig_of(&b);
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    sig[32..].copy_from_slice(&add_le(&s, &L_LE));
    set_sig(&mut b, &sig);
    b
}

fn json(v: &Vector) -> String {
    let id = v.well_formed.then(|| id_of(&v.block));
    let opt_hex =
        |x: Option<Vec<u8>>| x.map_or_else(|| "null".to_owned(), |b| format!("\"{}\"", hex(&b)));
    let mut s = String::new();
    s.push_str("{\n");
    writeln!(s, "  \"name\": \"{}\",", v.name).unwrap();
    writeln!(s, "  \"description\": \"{}\",", escape(&v.description)).unwrap();
    writeln!(s, "  \"block_hex\": \"{}\",", hex(&v.block)).unwrap();
    writeln!(
        s,
        "  \"params\": {{ \"difficulty\": {}, \"requested_block_id\": {} }},",
        v.difficulty,
        opt_hex(v.requested.map(|r| r.to_vec()))
    )
    .unwrap();
    writeln!(
        s,
        "  \"expect\": {{ \"valid\": {}, \"block_id\": {}, \"signed_message_hex\": {}, \"error\": {} }}",
        v.error.is_none(),
        opt_hex(id.map(|i| i.to_vec())),
        opt_hex(id.map(|i| signed_message(&i))),
        v.error.map_or_else(|| "null".to_owned(), |e| format!("\"{e}\""))
    )
    .unwrap();
    s.push_str("}\n");
    s
}

fn escape(s: &str) -> String {
    assert!(s.is_ascii(), "descriptions stay ASCII: {s}");
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Runs `sbtp-core` on the vector and panics on any disagreement with the stated outcome.
fn cross_check(v: &Vector) {
    let parsed = parse(&v.block);
    assert_eq!(parsed.is_ok(), v.well_formed, "{}: well-formedness", v.name);
    if let Ok(block) = parsed {
        assert_eq!(block.block_id().0, id_of(&v.block), "{}: block_id", v.name);
    }
    let result = match &v.requested {
        Some(id) => {
            validate_requested(&v.block, v.difficulty, &BlockId(*id)).map(|ok| ok.block_id().0)
        }
        None => validate_submitted(&v.block, v.difficulty).map(|ok| ok.block_id().0),
    };
    match (result, v.error) {
        (Ok(id), None) => assert_eq!(id, id_of(&v.block), "{}", v.name),
        (Err(e), Some(name)) => assert_eq!(e.name(), name, "{}", v.name),
        (got, want) => panic!("{}: sbtp-core gives {got:?}, expected {want:?}", v.name),
    }
}

/// The isolating vectors must be accepted by a plain RFC 8032 cofactorless verifier without the
/// small-order checks (`ed25519-dalek`'s non-strict `verify`), and rejected by `verify_strict`:
/// that is what makes them discriminate V2 and V5 (review 2026-11-18 M2, F-1). The same check runs
/// in `cargo test` (tests/vectors.rs); this one guards the generator.
fn discriminates(v: &Vector) {
    let isolating = ["c2_v2_only_", "c3_v5_only_", "c2_v1_v2_"];
    if !isolating.iter().any(|p| v.name.starts_with(p)) {
        return;
    }
    let pubkey: [u8; 32] = v.block[19..51].try_into().unwrap();
    let key = VerifyingKey::from_bytes(&pubkey).unwrap();
    let message = signed_message(&id_of(&v.block));
    let signature = Signature::from_bytes(&sig_of(&v.block));
    assert!(
        key.verify(&message, &signature).is_ok(),
        "{}: non-strict verify must accept",
        v.name
    );
    assert!(
        key.verify_strict(&message, &signature).is_err(),
        "{}",
        v.name
    );
}

/// Writes the fuzz seed corpus: every vector behind each of the 4 mode control bytes at
/// difficulty 0, and mode 0 at difficulty 8 (`fuzz/fuzz_targets/decode_block.rs`), into `dir`.
fn write_seeds(vectors: &[Vector], dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let mut n = 0;
    for v in vectors {
        for control in [0x00u8, 0x08, 0x10, 0x18, 0x03] {
            let mut seed = vec![control];
            seed.extend_from_slice(&v.block);
            std::fs::write(dir.join(format!("{}_{control:02x}", v.name)), seed).unwrap();
            n += 1;
        }
    }
    println!("{n} fuzz seeds written to {}", dir.display());
}

/// What the generator does; the three modes are exclusive.
enum Mode {
    /// Write the missing vector files into the directory.
    Write(PathBuf),
    /// Verify the vector files in the directory; write nothing.
    Check(PathBuf),
    /// Verify the default vector directory (read-only), then write the fuzz seeds into the
    /// directory.
    FuzzSeeds(PathBuf),
}

fn parse_args() -> Mode {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors_dir = manifest.join("../../docs/test-vectors/v1");
    let seeds_dir = manifest.join("../../fuzz/corpus/decode_block");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (flags, dirs): (Vec<&String>, Vec<&String>) =
        args.iter().partition(|a| a.starts_with("--"));
    let usage = "usage: gen_vectors [--check | --fuzz-seeds] [DIR]";
    assert!(dirs.len() <= 1, "{usage}");
    let dir = dirs.first().map(PathBuf::from);
    match flags.as_slice() {
        [] => Mode::Write(dir.unwrap_or(vectors_dir)),
        [f] if *f == "--check" => Mode::Check(dir.unwrap_or(vectors_dir)),
        [f] if *f == "--fuzz-seeds" => Mode::FuzzSeeds(dir.unwrap_or(seeds_dir)),
        _ => panic!("{usage}"),
    }
}

fn main() {
    let mode = parse_args();
    let (dir, check, seeds_dir) = match mode {
        Mode::Write(dir) => (dir, false, None),
        Mode::Check(dir) => (dir, true, None),
        Mode::FuzzSeeds(seeds) => (
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors/v1"),
            true,
            Some(seeds),
        ),
    };

    let mut failures = 0;
    // The self-test constants of sbtp-core must be the frozen bytes; print them otherwise.
    for (name, want, have) in [
        (
            "SELF_TEST_VALID_BLOCK",
            self_test_block(),
            SELF_TEST_VALID_BLOCK.to_vec(),
        ),
        ("S_PLUS_L_BLOCK", s_plus_l_block(), S_PLUS_L_BLOCK.to_vec()),
        (
            "SELF_TEST_BLOCK_ID",
            id_of(&self_test_block()).to_vec(),
            SELF_TEST_BLOCK_ID.0.to_vec(),
        ),
    ] {
        if want != have {
            eprintln!("SELF-TEST CONSTANT DIFFERS: {name} = {want:?}");
            failures += 1;
        }
    }

    let mut vectors = all_vectors();
    for v in &mut vectors {
        if !v.well_formed {
            continue;
        }
        // The expected C2/C3 outcome follows from the independent evaluation of V1 to V6, and the
        // description states every criterion that fails (docs/test-vectors/README.md).
        let criteria = analyze_block(&v.block);
        match v.error {
            None | Some("InvalidPublicKey" | "InvalidSignature") => {
                assert_eq!(criteria.expected_error(), v.error, "{}: criteria", v.name);
            }
            Some(_) => assert!(criteria.fails.is_empty(), "{}: only R1 or C1 fails", v.name),
        }
        v.description = format!("{} {}", v.description, criteria.sentence());
        discriminates(v);
    }
    let mut files = BTreeMap::new();
    for v in &vectors {
        cross_check(v);
        let previous = files.insert(format!("{}.json", v.name), json(v));
        assert!(previous.is_none(), "duplicate name {}", v.name);
    }

    if !check {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let mut written = 0;
    for (file, content) in &files {
        let path = dir.join(file);
        match std::fs::read_to_string(&path) {
            Ok(existing) if existing == *content => {}
            Ok(_) => {
                eprintln!(
                    "DIFFERS (published vectors never change): {}",
                    path.display()
                );
                failures += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && check => {
                eprintln!("MISSING: {}", path.display());
                failures += 1;
            }
            // Only a file that does not exist is ever written; a published file is never
            // overwritten, whatever the read error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&path, content).unwrap();
                written += 1;
            }
            Err(e) => {
                eprintln!("UNREADABLE ({e}), not overwritten: {}", path.display());
                failures += 1;
            }
        }
    }
    if check {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let is_json = path.extension().is_some_and(|e| e == "json");
            if is_json && !files.contains_key(&name) {
                eprintln!("EXTRA: {name}");
                failures += 1;
            }
        }
    }
    println!(
        "{} vectors, {written} written, {failures} problems, directory {}",
        files.len(),
        dir.display()
    );
    if failures > 0 {
        std::process::exit(1);
    }
    // Seeds only from vectors that match the frozen files.
    if let Some(seeds) = seeds_dir {
        write_seeds(&vectors, &seeds);
    }
}
