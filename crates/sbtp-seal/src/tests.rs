//! Tests of the sealed envelope: round trips through real blocks, one test per error variant,
//! the RFC 9180 known-answer test, and properties.
//!
//! Every key comes from a documented public seed: Ed25519 keys from 32 repeated bytes, X25519
//! keys from RFC 9180 `DeriveKeyPair` over an ASCII label, and the test RNG is the BLAKE3 XOF of
//! an ASCII label. None of them may ever be used outside tests.

extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use proptest::prelude::*;
use sbtp_core::{BlockBuilder, BlockId, SigningKey, sealed_sig_message, sign_sealed};
use sbtp_l2::cbor::{self, Value};
use sbtp_l2::{Body, Enc, L2Error, Payload, validate_block};

use crate::keys::{Aead, Kdf, Kem};
use crate::*;

/// A deterministic RNG for tests only: first `prefix`, then the BLAKE3 XOF of `label`.
struct TestRng {
    prefix: Vec<u8>,
    xof: blake3::OutputReader,
}

impl TestRng {
    fn new(label: &str) -> Self {
        Self::with_prefix(label, &[])
    }
    fn with_prefix(label: &str, prefix: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(label.as_bytes());
        Self {
            prefix: prefix.to_vec(),
            xof: h.finalize_xof(),
        }
    }
}

impl TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let n = dst.len().min(self.prefix.len());
        let (head, tail) = dst.split_at_mut(n);
        head.copy_from_slice(&self.prefix[..n]);
        self.prefix.drain(..n);
        self.xof.fill(tail);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

fn sender() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

fn recipient() -> RecipientKey {
    RecipientKey::derive(b"sbtp-seal test recipient 1")
}

fn other_recipient() -> RecipientKey {
    RecipientKey::derive(b"sbtp-seal test recipient 2")
}

const RECIPIENT_ID: [u8; 32] = [0x22; 32];
const TAG: [u8; 32] = [0x33; 32];
const KIND: &str = "example.note";

/// A grammar payload of kind [`KIND`] whose body is a byte string of `n` bytes.
fn msg(n: usize) -> Vec<u8> {
    let data = vec![0x5a; n];
    let raw = cbor::encode(&Value::Bytes(&data)).unwrap();
    Payload {
        kind: KIND,
        edges: vec![],
        body: Body::Raw(&raw),
    }
    .encode(&[])
    .unwrap()
}

fn request<'a>(
    x25519: &'a [u8; 32],
    sender: &'a SigningKey,
    msg: &'a [u8],
    bucket: Option<Bucket>,
) -> SealRequest<'a> {
    SealRequest {
        recipient_x25519: x25519,
        recipient_id: &RECIPIENT_ID,
        tag: &TAG,
        sender,
        msg,
        bucket,
    }
}

/// Builds, signs and validates the outer block (layer 0 and grammar, steps 1 and 2), then
/// opens it with `keys`.
fn deliver(sealed: &Sealed, keys: &[RecipientKey]) -> Result<Opened, OpenError> {
    let parents = [BlockId(sealed.tag)];
    let bytes = BlockBuilder::for_key(&sealed.ephemeral)
        .timestamp(1_763_683_200_000)
        .parents(&parents)
        .payload(&sealed.payload)
        .build(&sealed.ephemeral, 0)
        .unwrap();
    let block = sbtp_core::validate_submitted(&bytes, 0).unwrap();
    let payload = validate_block(block.block()).unwrap();
    let Body::Enc(enc) = &payload.body else {
        panic!("not an sbtp.enc body");
    };
    open(&OpenRequest {
        outer_pubkey: block.block().pubkey(),
        tag: &sealed.tag,
        enc,
        recipient_id: &RECIPIENT_ID,
        keys,
        allowed_kinds: &[KIND],
    })
}

// spec §5.1 to §5.3: a sealed payload goes through a real block and opens.
#[test]
fn round_trip_through_a_block() {
    let m = msg(20);
    let key = recipient();
    let sealed = seal(
        &request(key.public(), &sender(), &m, None),
        &mut TestRng::new("round trip"),
    )
    .unwrap();
    assert_eq!(sealed.bucket, Bucket::B512);
    assert_eq!(sealed.payload.len(), 512);
    let opened = deliver(&sealed, &[other_recipient(), key]).unwrap();
    assert_eq!(opened.msg(), &m[..]);
    assert_eq!(opened.from(), &sender().verifying_key().to_bytes());
    assert_eq!(opened.key_index(), 1);
    assert_eq!(opened.payload().unwrap().kind, KIND);
}

// spec §5.2, §5.3: the smallest bucket that fits, every bucket reachable, an explicit bucket.
#[test]
fn buckets() {
    let key = recipient();
    // The item is the msg plus 114 bytes of keys, fixed fields and CBOR heads, about.
    for (n, want) in [
        (200, Bucket::B512),
        (1_000, Bucket::B2048),
        (5_000, Bucket::B8192),
        (30_000, Bucket::B65535),
    ] {
        let m = msg(n);
        let sealed = seal(
            &request(key.public(), &sender(), &m, None),
            &mut TestRng::new("buckets"),
        )
        .unwrap();
        assert_eq!(sealed.bucket, want, "msg {n}");
        assert_eq!(sealed.payload.len(), want.payload_len());
        assert_eq!(deliver(&sealed, &[recipient()]).unwrap().msg(), &m[..]);
    }
    let m = msg(10);
    let sealed = seal(
        &request(key.public(), &sender(), &m, Some(Bucket::B8192)),
        &mut TestRng::new("explicit"),
    )
    .unwrap();
    assert_eq!(sealed.payload.len(), 8_192);
}

// spec §5.2: `TooLong`, for a requested bucket and for every bucket.
#[test]
fn seal_too_long() {
    let key = recipient();
    let m = msg(400);
    assert!(matches!(
        seal(
            &request(key.public(), &sender(), &m, Some(Bucket::B512)),
            &mut TestRng::new("too long")
        ),
        Err(SealError::TooLong)
    ));
    let m = msg(65_400);
    assert!(matches!(
        seal(
            &request(key.public(), &sender(), &m, None),
            &mut TestRng::new("too long")
        ),
        Err(SealError::TooLong)
    ));
}

// spec §5.3: `msg` must be a payload of a block with 0 parents; `sbtp.enc` never is one.
#[test]
fn seal_msg_invalid() {
    let key = recipient();
    let sender = sender();
    let enc_payload = Payload {
        kind: "sbtp.enc",
        edges: vec![sbtp_l2::Edge {
            target: sbtp_l2::Target::Parent(0),
            rel: sbtp_l2::Rel::Tagged,
        }],
        body: Body::Enc(Enc {
            ct: &[0; 422],
            enc: [0; 32],
        }),
    }
    .encode(&[BlockId(TAG)])
    .unwrap();
    for bad in [&b"\xff"[..], &enc_payload] {
        assert!(matches!(
            seal(
                &request(key.public(), &sender, bad, None),
                &mut TestRng::new("bad msg")
            ),
            Err(SealError::MsgInvalid(_))
        ));
    }
}

// spec §5.2: the ephemeral signer is never the sender key.
#[test]
fn seal_ephemeral_is_sender() {
    let key = recipient();
    let m = msg(5);
    let mut rng = TestRng::with_prefix("ephemeral", &[0x01; 32]);
    assert_eq!(
        seal(&request(key.public(), &sender(), &m, None), &mut rng).unwrap_err(),
        SealError::EphemeralIsSender
    );
}

// spec §5.1, RFC 9180 §7.1.4: a recipient key of small order yields an all-zero shared secret.
#[test]
fn seal_all_zero_shared_secret() {
    let m = msg(5);
    for x in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        assert_eq!(
            seal(&request(&x, &sender(), &m, None), &mut TestRng::new("zero")).unwrap_err(),
            SealError::Hpke
        );
    }
}

/// The encoded item `{from, msg, sig}` with a valid `sig` (spec §5.3).
fn item(from: &SigningKey, outer: &[u8; 32], x25519: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 114 + msg.len()];
    let m = sealed_sig_message(outer, &RECIPIENT_ID, x25519, msg, &mut buf).unwrap();
    let sig = sign_sealed(from, &m).unwrap();
    let from = from.verifying_key().to_bytes();
    cbor::encode(&Value::Map(vec![
        ("from", Value::Bytes(&from)),
        ("msg", Value::Bytes(msg)),
        ("sig", Value::Bytes(&sig)),
    ]))
    .unwrap()
}

/// HPKE-seals an arbitrary `plaintext` with the suite, `info` and `aad` of spec §5.1, then opens
/// it with `open`. `outer` is the outer `PubKey` the recipient sees.
fn open_crafted(plaintext: &[u8], outer: &[u8; 32], allowed: &[&str]) -> Result<Opened, OpenError> {
    let key = recipient();
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(key.public()).unwrap();
    let (encapped, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &sbtp_core::SEALED_HPKE_INFO,
        plaintext,
        &crate::seal::aad(outer, &TAG),
        &mut TestRng::new("crafted"),
    )
    .unwrap();
    open(&OpenRequest {
        outer_pubkey: outer,
        tag: &TAG,
        enc: &Enc {
            ct: &ct,
            enc: encapped.to_bytes().into(),
        },
        recipient_id: &RECIPIENT_ID,
        keys: &[key],
        allowed_kinds: allowed,
    })
}

const OUTER: [u8; 32] = [0x44; 32];

fn padded(mut item: Vec<u8>) -> Vec<u8> {
    item.resize(Bucket::B512.plaintext_len(), 0);
    item
}

// The crafted path is itself correct: a well-formed plaintext opens.
#[test]
fn crafted_positive() {
    let pt = padded(item(&sender(), &OUTER, recipient().public(), &msg(3)));
    assert!(open_crafted(&pt, &OUTER, &[KIND]).is_ok());
    // An item that fills the bucket exactly, no padding byte (spec §5.3: zero or more).
    let exact = (0..Bucket::B512.plaintext_len())
        .map(|n| item(&sender(), &OUTER, recipient().public(), &msg(n)))
        .find(|it| it.len() == Bucket::B512.plaintext_len())
        .unwrap();
    assert!(open_crafted(&exact, &OUTER, &[KIND]).is_ok());
}

// spec §5.2: `CiphertextLength`.
#[test]
fn open_ciphertext_length() {
    let enc = Enc {
        ct: &[0; 421],
        enc: [0x09; 32],
    };
    let err = open(&OpenRequest {
        outer_pubkey: &OUTER,
        tag: &TAG,
        enc: &enc,
        recipient_id: &RECIPIENT_ID,
        keys: &[recipient()],
        allowed_kinds: &[KIND],
    });
    assert_eq!(err.unwrap_err(), OpenError::CiphertextLength);
}

// spec §5.3 step 4: wrong key, no key, wrong tag or outer PubKey (aad), tampered ciphertext.
#[test]
fn open_no_key_opens() {
    let m = msg(5);
    let key = recipient();
    let sealed = seal(
        &request(key.public(), &sender(), &m, None),
        &mut TestRng::new("no key"),
    )
    .unwrap();
    assert_eq!(
        deliver(&sealed, &[other_recipient()]).unwrap_err(),
        OpenError::NoKeyOpens
    );
    assert_eq!(deliver(&sealed, &[]).unwrap_err(), OpenError::NoKeyOpens);

    let payload = sbtp_l2::validate_l2_invariants(&[BlockId(TAG)], &sealed.payload).unwrap();
    let Body::Enc(enc) = payload.body else {
        panic!()
    };
    let outer = sealed.ephemeral.verifying_key().to_bytes();
    let mut ct = enc.ct.to_vec();
    ct[7] ^= 1;
    let tampered = Enc {
        ct: &ct,
        enc: enc.enc,
    };
    let keys = [recipient()];
    let cases: [(&[u8; 32], &[u8; 32], &Enc<'_>); 3] = [
        (&outer, &[0x34; 32], &enc),
        (&OUTER, &TAG, &enc),
        (&outer, &TAG, &tampered),
    ];
    for (i, (outer_pubkey, tag, enc)) in cases.into_iter().enumerate() {
        let r = open(&OpenRequest {
            outer_pubkey,
            tag,
            enc,
            recipient_id: &RECIPIENT_ID,
            keys: &keys,
            allowed_kinds: &[KIND],
        });
        assert_eq!(r.unwrap_err(), OpenError::NoKeyOpens, "case {i}");
    }
}

// spec §5.3 steps 5 and 6, §1.2: the first item is not one item of the profile.
#[test]
fn open_item_encoding() {
    // A reserved head byte, then a map whose keys are not sorted (passes the skip, fails the
    // profile).
    let mut unsorted = vec![0xa2, 0x61, b'b', 0x00, 0x61, b'a', 0x00];
    unsorted.resize(406, 0);
    for pt in [vec![0xff; 406], unsorted] {
        assert!(matches!(
            open_crafted(&pt, &OUTER, &[KIND]).unwrap_err(),
            OpenError::ItemEncoding(_)
        ));
    }
}

// spec §5.3 step 5: a non-zero byte after the item, last byte or first padding byte.
#[test]
fn open_padding() {
    let it = item(&sender(), &OUTER, recipient().public(), &msg(3));
    let n = it.len();
    for pos in [n, 405] {
        let mut pt = padded(it.clone());
        pt[pos] = 0x01;
        assert_eq!(
            open_crafted(&pt, &OUTER, &[KIND]).unwrap_err(),
            OpenError::Padding
        );
    }
}

// spec §5.3 step 6: not a map, a missing key, an extra key, wrong sizes.
#[test]
fn open_item_shape() {
    let from = sender().verifying_key().to_bytes();
    let m = msg(3);
    let sig = [0u8; 64];
    let maps: [Vec<(&str, Value<'_>)>; 5] = [
        vec![("from", Value::Bytes(&from)), ("msg", Value::Bytes(&m))],
        vec![
            ("from", Value::Bytes(&from)),
            ("msg", Value::Bytes(&m)),
            ("sig", Value::Bytes(&sig)),
            ("x", Value::Uint(0)),
        ],
        vec![
            ("from", Value::Bytes(&from[..31])),
            ("msg", Value::Bytes(&m)),
            ("sig", Value::Bytes(&sig)),
        ],
        vec![
            ("from", Value::Bytes(&from)),
            ("msg", Value::Bytes(&m)),
            ("sig", Value::Bytes(&sig[..63])),
        ],
        vec![
            ("from", Value::Bytes(&from)),
            ("msg", Value::Text("text")),
            ("sig", Value::Bytes(&sig)),
        ],
    ];
    let mut cases: Vec<Vec<u8>> = maps
        .into_iter()
        .map(|m| padded(cbor::encode(&Value::Map(m)).unwrap()))
        .collect();
    // All zeros: the item is the integer 0, then padding.
    cases.push(vec![0; 406]);
    for (i, pt) in cases.iter().enumerate() {
        assert_eq!(
            open_crafted(pt, &OUTER, &[KIND]).unwrap_err(),
            OpenError::ItemShape,
            "case {i}"
        );
    }
}

// spec §5.2, §5.3 step 6: `from` equals the outer PubKey.
#[test]
fn open_from_is_outer_pubkey() {
    let outer = sender().verifying_key().to_bytes();
    let pt = padded(item(&sender(), &outer, recipient().public(), &msg(3)));
    assert_eq!(
        open_crafted(&pt, &outer, &[KIND]).unwrap_err(),
        OpenError::FromIsOuterPubKey
    );
}

// spec §5.3 step 7, core spec §3.2 V1 and V2: `from` is not a valid key.
#[test]
fn open_sender_key() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let m = msg(3);
    let pt = padded(
        cbor::encode(&Value::Map(vec![
            ("from", Value::Bytes(&identity)),
            ("msg", Value::Bytes(&m)),
            ("sig", Value::Bytes(&[0u8; 64])),
        ]))
        .unwrap(),
    );
    assert_eq!(
        open_crafted(&pt, &OUTER, &[KIND]).unwrap_err(),
        OpenError::SenderKey
    );
}

// spec §5.3 step 7: `sig` made for another recipient identity, another X25519 key, another
// outer PubKey, or flipped.
#[test]
fn open_signature() {
    let m = msg(3);
    let x = *recipient().public();
    let other_x = *other_recipient().public();
    let mut cases = vec![
        padded(item(&sender(), &OUTER, &other_x, &m)),
        padded(item(&sender(), &[0x45; 32], &x, &m)),
    ];
    // Another recipient_id: sign with the identity [0x23; 32].
    let mut buf = vec![0u8; 114 + m.len()];
    let msg_other = sealed_sig_message(&OUTER, &[0x23; 32], &x, &m, &mut buf).unwrap();
    let sig = sign_sealed(&sender(), &msg_other).unwrap();
    let from = sender().verifying_key().to_bytes();
    let mut flipped = sig;
    flipped[40] ^= 1;
    for s in [sig, flipped] {
        cases.push(padded(
            cbor::encode(&Value::Map(vec![
                ("from", Value::Bytes(&from)),
                ("msg", Value::Bytes(&m)),
                ("sig", Value::Bytes(&s)),
            ]))
            .unwrap(),
        ));
    }
    for (i, pt) in cases.iter().enumerate() {
        assert_eq!(
            open_crafted(pt, &OUTER, &[KIND]).unwrap_err(),
            OpenError::Signature,
            "case {i}"
        );
    }
}

// spec §5.3 step 8: `msg` is not a grammar payload of a block with 0 parents.
#[test]
fn open_msg_invalid() {
    let x = *recipient().public();
    // Not a payload; and a payload with a causal edge (`p: 0` with 0 parents).
    let causal = cbor::encode(&Value::Map(vec![
        ("v", Value::Uint(1)),
        ("kind", Value::Text(KIND)),
        (
            "edges",
            Value::Array(vec![Value::Map(vec![
                ("p", Value::Uint(0)),
                ("rel", Value::Text("replies_to")),
            ])]),
        ),
        ("body", Value::Bytes(b"")),
    ]))
    .unwrap();
    // A `msg` of kind `sbtp.enc` (review I-3): its row needs 1 parent, `msg` has 0.
    let enc_msg = Payload {
        kind: "sbtp.enc",
        edges: vec![sbtp_l2::Edge {
            target: sbtp_l2::Target::Parent(0),
            rel: sbtp_l2::Rel::Tagged,
        }],
        body: Body::Enc(Enc {
            ct: &[0; 422],
            enc: [0; 32],
        }),
    }
    .encode(&[BlockId(TAG)])
    .unwrap();
    // It is a valid payload with its 1 parent (encode checked it), and too long for B512.
    let mut pt = item(&sender(), &OUTER, &x, &enc_msg);
    pt.resize(Bucket::B2048.plaintext_len(), 0);
    assert!(matches!(
        open_crafted(&pt, &OUTER, &["sbtp.enc", KIND]).unwrap_err(),
        OpenError::MsgInvalid(_)
    ));
    for bad in [&b"\x00"[..], &causal] {
        let pt = padded(item(&sender(), &OUTER, &x, bad));
        assert!(matches!(
            open_crafted(&pt, &OUTER, &[KIND]).unwrap_err(),
            OpenError::MsgInvalid(_)
        ));
    }
}

// spec §5.3 step 8, §5.4: a kind the tag does not allow.
#[test]
fn open_msg_kind_not_allowed() {
    let pt = padded(item(&sender(), &OUTER, recipient().public(), &msg(3)));
    assert_eq!(
        open_crafted(&pt, &OUTER, &["example.other"]).unwrap_err(),
        OpenError::MsgKindNotAllowed
    );
    assert_eq!(
        open_crafted(&pt, &OUTER, &[]).unwrap_err(),
        OpenError::MsgKindNotAllowed
    );
}

/// Whether `dbg` contains the `Debug` text of `bytes` or a run of four of its first bytes.
fn leaks(dbg: &str, bytes: &[u8]) -> bool {
    let full = std::format!("{bytes:?}");
    let head = &full[1..full.len().min(1 + 4 * 5)];
    dbg.contains(&full) || dbg.contains(head.trim_end_matches([',', ' ']))
}

// Review L-2: `SealRequest`'s `Debug` shows neither `msg` nor the sender nor the recipient.
#[test]
fn seal_request_debug_hides_secrets() {
    let m = msg(40);
    let key = recipient();
    let sender = sender();
    let req = request(key.public(), &sender, &m, Some(Bucket::B2048));
    let dbg = std::format!("{req:?}");
    assert!(dbg.contains("msg_len"), "{dbg}");
    let from = sender.verifying_key().to_bytes();
    for secret in [
        &m[..],
        &from,
        key.public(),
        &RECIPIENT_ID,
        &sender.to_bytes(),
    ] {
        assert!(!leaks(&dbg, secret), "{dbg}");
    }
}

// Review L-2: `OpenRequest`'s `Debug` shows neither the recipient's identity nor its keys.
#[test]
fn open_request_debug_hides_secrets() {
    let keys = [recipient()];
    let enc = Enc {
        ct: &[0x77; 422],
        enc: [0x66; 32],
    };
    let req = OpenRequest {
        outer_pubkey: &OUTER,
        tag: &TAG,
        enc: &enc,
        recipient_id: &RECIPIENT_ID,
        keys: &keys,
        allowed_kinds: &[KIND],
    };
    let dbg = std::format!("{req:?}");
    assert!(dbg.contains("ct_len"), "{dbg}");
    for secret in [
        &RECIPIENT_ID[..],
        keys[0].public(),
        &*keys[0].secret_bytes(),
    ] {
        assert!(!leaks(&dbg, secret), "{dbg}");
    }
}

// Review L-2: `Opened`'s `Debug` shows neither `from` nor `msg`.
#[test]
fn opened_debug_hides_secrets() {
    let m = msg(40);
    let key = recipient();
    let sealed = seal(
        &request(key.public(), &sender(), &m, None),
        &mut TestRng::new("debug"),
    )
    .unwrap();
    let opened = deliver(&sealed, &[key]).unwrap();
    let dbg = std::format!("{opened:?}");
    assert!(dbg.contains("msg_len"), "{dbg}");
    assert!(!leaks(&dbg, opened.from()), "{dbg}");
    assert!(!leaks(&dbg, opened.msg()), "{dbg}");
}

// Key storage: the private key bytes round-trip; `Debug` shows the public key only.
#[test]
fn recipient_key_bytes() {
    let key = recipient();
    let again = RecipientKey::from_secret_bytes(&key.secret_bytes()).unwrap();
    assert_eq!(again.public(), key.public());
    let generated = RecipientKey::generate(&mut TestRng::new("generate"));
    assert_ne!(generated.public(), key.public());
    let dbg = std::format!("{key:?}");
    assert!(!dbg.contains(&std::format!("{:?}", *key.secret_bytes())));
}

fn hex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    s.chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

// RFC 9180 Appendix A.2.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base
// mode), sequence number 0, through the suite this crate fixes (review 2026-11-20, condition 6).
#[test]
fn rfc9180_a2_known_answer() {
    let ikm_e = hex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
    let ikm_r = hex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
    let pk_rm = hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    let sk_rm = hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    let enc = hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let info = hex("4f6465206f6e2061204772656369616e2055726e");
    let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex("436f756e742d30");
    let ct = hex(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db\
         21993c62ce81883d2dd1b51a28",
    );

    let key = RecipientKey::derive(&ikm_r);
    assert_eq!(&key.public()[..], &pk_rm[..]);
    // `hpke` 0.15 clamps X25519 private keys on serialisation (RFC 7748 §5): compare with the
    // clamped `skRm`.
    let mut sk_clamped = sk_rm.clone();
    sk_clamped[0] &= 0xf8;
    sk_clamped[31] = (sk_clamped[31] & 0x7f) | 0x40;
    assert_eq!(&key.secret_bytes()[..], &sk_clamped[..]);

    // The sender's ephemeral key comes from `ikmE` (DeriveKeyPair of 32 RNG bytes).
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&pk_rm).unwrap();
    let mut rng = TestRng::with_prefix("kat", &ikm_e);
    let (encapped, got_ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        &pt,
        &aad,
        &mut rng,
    )
    .unwrap();
    assert_eq!(&encapped.to_bytes()[..], &enc[..]);
    assert_eq!(got_ct, ct);

    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).unwrap();
    let opened = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        key.secret(),
        &encapped,
        &info,
        &ct,
        &aad,
    )
    .unwrap();
    assert_eq!(opened, pt);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // spec §5.2, §5.3: seal then open returns `msg` for any body size that fits a bucket.
    #[test]
    fn prop_round_trip(n in 0usize..9_000, label in "[a-z]{1,8}") {
        let m = msg(n);
        let key = recipient();
        let sealed = seal(&request(key.public(), &sender(), &m, None), &mut TestRng::new(&label))
            .unwrap();
        prop_assert!(ENC_LENS.contains(&sealed.payload.len()));
        let opened = deliver(&sealed, &[key]).unwrap();
        prop_assert_eq!(opened.msg(), &m[..]);
    }

    // `open` never panics on arbitrary `enc` and `ct` of any length.
    #[test]
    fn prop_open_no_panic(enc in any::<[u8; 32]>(), ct in proptest::collection::vec(any::<u8>(), 0..600)) {
        let r = open(&OpenRequest {
            outer_pubkey: &OUTER,
            tag: &TAG,
            enc: &Enc { ct: &ct, enc },
            recipient_id: &RECIPIENT_ID,
            keys: &[recipient()],
            allowed_kinds: &[KIND],
        });
        prop_assert!(r.is_err());
    }

    // `open` never panics on an arbitrary plaintext that opens (steps 5 to 8 on hostile bytes).
    #[test]
    fn prop_plaintext_no_panic(head in proptest::collection::vec(any::<u8>(), 0..406)) {
        let pt = padded(head);
        let _ = open_crafted(&pt, &OUTER, &[KIND]);
    }
}

const ENC_LENS: [usize; 4] = sbtp_l2::ENC_PAYLOAD_LENS;

// `L2Error` is used by the variants; keep the import exercised.
#[test]
fn item_encoding_carries_the_profile_error() {
    assert_eq!(
        open_crafted(&[0xff; 406], &OUTER, &[KIND]).unwrap_err(),
        OpenError::ItemEncoding(L2Error::Malformed)
    );
}

// --- Two-phase seal: the inner signature made outside the crate (spec §5.3) ---

/// The prepare request matching [`request`], with `from` in place of the signing key.
fn prepare_request<'a>(
    x25519: &'a [u8; 32],
    from: &'a [u8; 32],
    msg: &'a [u8],
    bucket: Option<Bucket>,
) -> PrepareRequest<'a> {
    PrepareRequest {
        recipient_x25519: x25519,
        recipient_id: &RECIPIENT_ID,
        tag: &TAG,
        from,
        msg,
        bucket,
    }
}

/// An external signer: it sees only the bytes of `PendingSeal::message`, splits them into the
/// fields of spec §5.3 and signs them with `key` through the typed builder.
fn external_sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let fixed = sbtp_core::SEALED_SIG_PREFIX.len();
    assert_eq!(&message[..fixed], &sbtp_core::SEALED_SIG_PREFIX);
    let field = |i: usize| -> [u8; 32] {
        message[fixed + 32 * i..fixed + 32 * (i + 1)]
            .try_into()
            .unwrap()
    };
    let mut buf = vec![0u8; message.len()];
    let typed = sealed_sig_message(
        &field(0),
        &field(1),
        &field(2),
        &message[fixed + 96..],
        &mut buf,
    )
    .unwrap();
    assert_eq!(typed.as_bytes(), message);
    sign_sealed(key, &typed).unwrap()
}

fn blake3_of(sealed: &Sealed) -> std::string::String {
    let mut h = blake3::Hasher::new();
    h.update(&sealed.payload);
    h.update(&sealed.ephemeral.verifying_key().to_bytes());
    std::string::ToString::to_string(&h.finalize().to_hex())
}

/// (msg body length, bucket, BLAKE3 of `payload ‖ ephemeral public key`) for the RNG label
/// `"pin"`, recorded with the single-phase `seal` of `d328716`, before the two-phase API.
const PINNED: [(usize, Option<Bucket>, &str); 5] = [
    (
        0,
        None,
        "f3eeb066d14543e42fb48901febffb06585b5f0f616e9ee73ca20e101df94c7f",
    ),
    (
        20,
        None,
        "ef00b2f7db0c363b8679997b4ee3a9af854d346d58ba7bb4e8f5306b6a811df2",
    ),
    (
        1_000,
        None,
        "03f0f402981fcb562827c1171f9cb23ac990702eff9a2dd2eeba4314e25c8c00",
    ),
    (
        10,
        Some(Bucket::B8192),
        "e75b022ef665b651f5c21de3ba6aea827d4cdaefeec265df1fe06136325db0f9",
    ),
    (
        30_000,
        None,
        "459e84a25b2ac93f53aa7b9c11520488c3cfe4d76e7d19d0ee31e67ab7f6f593",
    ),
];

// `seal` produces the same bytes as before the two-phase API, for the same RNG stream.
#[test]
fn seal_output_is_pinned() {
    let key = recipient();
    for (n, bucket, want) in PINNED {
        let m = msg(n);
        let sealed = seal(
            &request(key.public(), &sender(), &m, bucket),
            &mut TestRng::new("pin"),
        )
        .unwrap();
        assert_eq!(blake3_of(&sealed), want, "msg {n}");
    }
}

// spec §5.3: prepare, an external signature, finish: byte-identical to `seal` for the same
// RNG stream and key, and it opens.
#[test]
fn two_phase_equals_seal() {
    let key = recipient();
    let sender = sender();
    let from = sender.verifying_key().to_bytes();
    for (n, bucket, want) in PINNED {
        let m = msg(n);
        let mut rng = TestRng::new("pin");
        let pending =
            seal_prepare(&prepare_request(key.public(), &from, &m, bucket), &mut rng).unwrap();
        assert_eq!(pending.from(), &from);
        let sig = external_sign(&sender, pending.message());
        let two_phase = pending.finish(&sig, &mut rng).unwrap();
        let one_phase = seal(
            &request(key.public(), &sender, &m, bucket),
            &mut TestRng::new("pin"),
        )
        .unwrap();
        assert_eq!(two_phase.payload, one_phase.payload, "msg {n}");
        assert_eq!(
            two_phase.ephemeral.verifying_key(),
            one_phase.ephemeral.verifying_key()
        );
        assert_eq!(two_phase.bucket, one_phase.bucket);
        assert_eq!(blake3_of(&two_phase), want);
        assert_eq!(deliver(&two_phase, &[recipient()]).unwrap().msg(), &m[..]);
    }
}

// spec §5.3: the message to sign is exactly
// `SBTP-v1-sealed-sig ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519 ‖ msg`, with the outer
// block's ephemeral key.
#[test]
fn prepare_message_layout() {
    let key = recipient();
    let sender = sender();
    let from = sender.verifying_key().to_bytes();
    let m = msg(30);
    let mut rng = TestRng::new("layout");
    let pending = seal_prepare(&prepare_request(key.public(), &from, &m, None), &mut rng).unwrap();
    assert_eq!(pending.bucket(), Bucket::B512);
    let message = pending.message().to_vec();
    let sig = external_sign(&sender, &message);
    let sealed = pending.finish(&sig, &mut rng).unwrap();
    let mut want = sbtp_core::SEALED_SIG_PREFIX.to_vec();
    want.extend_from_slice(&sealed.ephemeral.verifying_key().to_bytes());
    want.extend_from_slice(&RECIPIENT_ID);
    want.extend_from_slice(key.public());
    want.extend_from_slice(&m);
    assert_eq!(message, want);
}

// spec §5.3, core spec §3.2 V3 to V6: `finish` refuses a signature that does not verify, and
// seals nothing.
#[test]
fn finish_signature() {
    let key = recipient();
    let sender = sender();
    let from = sender.verifying_key().to_bytes();
    let m = msg(12);
    let pending = || {
        seal_prepare(
            &prepare_request(key.public(), &from, &m, None),
            &mut TestRng::new("bad sig"),
        )
        .unwrap()
    };
    let good = external_sign(&sender, pending().message());
    let mut flipped = good;
    flipped[10] ^= 1;
    // S = L, not canonical (V3).
    let mut s_is_l = good;
    s_is_l[32..].copy_from_slice(&hex(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    ));
    let other = external_sign(&SigningKey::from_bytes(&[0x02; 32]), pending().message());
    // A signature of another message (another `recipient_id`) by the right key.
    let mut buf = vec![0u8; pending().message().len()];
    let wrong_msg = pending().message().to_vec();
    let fixed = sbtp_core::SEALED_SIG_PREFIX.len();
    let typed = sealed_sig_message(
        &wrong_msg[fixed..fixed + 32].try_into().unwrap(),
        &[0x77; 32],
        key.public(),
        &m,
        &mut buf,
    )
    .unwrap();
    let wrong_id = sign_sealed(&sender, &typed).unwrap();
    for sig in [flipped, s_is_l, other, wrong_id, [0; 64]] {
        assert_eq!(
            pending()
                .finish(&sig, &mut TestRng::new("hpke"))
                .unwrap_err(),
            SealError::Signature
        );
    }
    assert!(pending().finish(&good, &mut TestRng::new("hpke")).is_ok());
}

// spec §5.3, core spec §3.2 V1 and V2: a `from` that is not a usable Ed25519 key is refused by
// `finish`, whatever the signature.
#[test]
fn finish_sender_key() {
    let key = recipient();
    let m = msg(12);
    // The identity point (small order, V2) and a non-canonical y = p (V1).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let non_canonical: [u8; 32] =
        hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
            .try_into()
            .unwrap();
    for from in [identity, non_canonical] {
        let mut rng = TestRng::new("bad from");
        let pending =
            seal_prepare(&prepare_request(key.public(), &from, &m, None), &mut rng).unwrap();
        let sig = external_sign(&sender(), pending.message());
        assert_eq!(
            pending.finish(&sig, &mut rng).unwrap_err(),
            SealError::SenderKey
        );
    }
}

// The errors of the first phase come from `seal_prepare` itself, before any signature.
#[test]
fn prepare_errors() {
    let key = recipient();
    let from = sender().verifying_key().to_bytes();
    let rng = || TestRng::new("prepare");
    assert!(matches!(
        seal_prepare(
            &prepare_request(key.public(), &from, b"\xff", None),
            &mut rng()
        ),
        Err(SealError::MsgInvalid(_))
    ));
    let big = msg(400);
    assert_eq!(
        seal_prepare(
            &prepare_request(key.public(), &from, &big, Some(Bucket::B512)),
            &mut rng()
        )
        .unwrap_err(),
        SealError::TooLong
    );
    let m = msg(5);
    let mut same = TestRng::with_prefix("ephemeral", &[0x01; 32]);
    assert_eq!(
        seal_prepare(&prepare_request(key.public(), &from, &m, None), &mut same).unwrap_err(),
        SealError::EphemeralIsSender
    );
    // An all-zero shared secret is found when sealing, in `finish`.
    let zero = [0u8; 32];
    let mut r = rng();
    let pending = seal_prepare(&prepare_request(&zero, &from, &m, None), &mut r).unwrap();
    let sig = external_sign(&sender(), pending.message());
    assert_eq!(pending.finish(&sig, &mut r).unwrap_err(), SealError::Hpke);
}

// `PendingSeal` and `PrepareRequest` show neither `msg`, nor `from`, nor the recipient, nor the
// ephemeral key.
#[test]
fn pending_debug_hides_secrets() {
    let key = recipient();
    let from = sender().verifying_key().to_bytes();
    let m = msg(40);
    let req = prepare_request(key.public(), &from, &m, None);
    let pending = seal_prepare(&req, &mut TestRng::new("debug")).unwrap();
    let outer = &pending.message()[18..50].to_vec();
    for dbg in [std::format!("{req:?}"), std::format!("{pending:?}")] {
        assert!(dbg.contains("msg_len"), "{dbg}");
        for secret in [&m[..], &from, key.public(), &RECIPIENT_ID, outer, &TAG] {
            assert!(!leaks(&dbg, secret), "{dbg}");
        }
    }
}

// The item length used to pick the bucket before signing is the encoder's, at every CBOR head
// size.
#[test]
fn item_len_matches_the_encoder() {
    for n in [0usize, 1, 23, 24, 255, 256, 65_429, 65_535, 65_536] {
        let body = vec![0x5a; n];
        let item = Value::Map(vec![
            ("from", Value::Bytes(&[1; 32])),
            ("msg", Value::Bytes(&body)),
            ("sig", Value::Bytes(&[2; 64])),
        ]);
        // `cbor::encode` refuses items over 65,535 bytes; compare the length below that bound.
        match cbor::encode(&item) {
            Ok(bytes) => assert_eq!(crate::seal::item_len(n), Some(bytes.len()), "msg {n}"),
            Err(L2Error::PayloadTooLong) => assert!(crate::seal::item_len(n).unwrap() > 65_535),
            Err(e) => panic!("{e:?}"),
        }
    }
}

// Review L-1: the item written in place into the bucket buffer is byte for byte the encoder's
// (deterministic profile, spec §1.2), at every head size of `msg`, and it is followed by the
// untouched `0x00` padding.
#[test]
fn in_place_item_matches_the_encoder() {
    let from = [0x01; 32];
    let sig = [0x02; 64];
    for n in [0usize, 1, 23, 24, 255, 256, 1_000, 65_429 - 117] {
        #[allow(clippy::cast_possible_truncation)]
        let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let want = cbor::encode(&Value::Map(vec![
            ("from", Value::Bytes(&from)),
            ("msg", Value::Bytes(&body)),
            ("sig", Value::Bytes(&sig)),
        ]))
        .unwrap();
        let bucket = Bucket::smallest_for(want.len()).unwrap();
        let mut buf = vec![0u8; bucket.plaintext_len()];
        let layout = crate::seal::encode_item_into(&mut buf, &from, &body).unwrap();
        assert_eq!(
            &buf[layout.msg_start..layout.msg_start + layout.msg_len],
            &body[..]
        );
        buf[layout.sig_start..layout.sig_start + 64].copy_from_slice(&sig);
        assert_eq!(&buf[..want.len()], &want[..], "msg {n}");
        assert!(buf[want.len()..].iter().all(|&b| b == 0));
        assert_eq!(crate::seal::item_len(n), Some(want.len()));
    }
    // A buffer too small is an error, not a panic.
    let mut small = [0u8; 100];
    assert!(crate::seal::encode_item_into(&mut small, &from, &[0; 10]).is_err());
}
