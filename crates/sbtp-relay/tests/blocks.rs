//! `PUT /sbtp/v1/block` and `GET /sbtp/v1/block/{block_id}` over real HTTP (spec §4; ADR 0003
//! rules 9 to 11, ADR 0007, ADR 0008, ADR 0009, ADR 0012, ADR 0013 rules 7 to 9 and 18 to 21,
//! ADR 0018 rule 18), and crash consistency between the block files and the index.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use axum::Router;
use common::{
    Response, TestServer, get as http_get, is_closed, now_ms, put_block as put, read_response,
    settings, tmp_dir,
};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};
use sbtp_relay::index::{FileState, IndexBackend, IndexError, Page, Position, RedbIndex};
use sbtp_relay::store::{Store, StoreError, Stored, TREE_CHARGE, cost, index_reserve, reconcile};

const LIMIT: usize = sbtp_core::layout::MAX_BLOCK_LEN;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// A valid block with `payload`, mined at `difficulty`, timestamped now.
fn block(payload: &[u8], difficulty: u32) -> Vec<u8> {
    block_at(payload, difficulty, now_ms())
}

fn block_at(payload: &[u8], difficulty: u32, ts: u64) -> Vec<u8> {
    let k = key();
    BlockBuilder::for_key(&k)
        .timestamp(ts)
        .payload(payload)
        .build(&k, difficulty)
        .unwrap()
}

fn id_of(bytes: &[u8]) -> BlockId {
    sbtp_core::parse(bytes).unwrap().block_id()
}

fn error(r: &Response) -> String {
    r.json()["error"].as_str().unwrap().to_owned()
}

fn start(pairs: &[(&str, &str)]) -> TestServer {
    TestServer::start(&settings(pairs), Router::new())
}

fn path_of(data: &Path, id: &BlockId) -> std::path::PathBuf {
    let b = id.as_bytes();
    data.join(format!("blocks/{:02x}/{id}.bin", b[31]))
}

#[test]
fn new_known_and_served() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "8")]);
    let mut c = relay.connect();
    let b = block(b"hello", 8);
    let id = id_of(&b);
    let r = put(&mut c, &b);
    assert_eq!(r.status, 201);
    assert_eq!(
        r.header("location"),
        Some(format!("/sbtp/v1/block/{id}").as_str())
    );
    assert_eq!(
        r.header("cache-control"),
        Some("no-store"),
        "ADR 0023 rule 13"
    );
    assert!(r.body.is_empty(), "ADR 0012 rule 19");
    // ADR 0009: the exact layout, by the trailing bytes; no temporary file left.
    assert_eq!(std::fs::read(path_of(&relay.data, &id)).unwrap(), b);
    assert_eq!(
        std::fs::read_dir(relay.data.join("tmp")).unwrap().count(),
        0
    );
    let r = put(&mut c, &b);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"");
    assert_eq!(
        r.header("cache-control"),
        Some("no-store"),
        "ADR 0023 rule 13"
    );
    for _ in 0..2 {
        // The second read is a cache hit.
        let r = http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b);
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
    }
    let missing = BlockId([0x11; 32]);
    let r = http_get(&mut c, &format!("/sbtp/v1/block/{missing}"), "");
    assert_eq!((r.status, error(&r).as_str()), (404, "NotFound"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

/// A `200` carries the strong validator `"<block_id>"`; a matching `If-None-Match` (exact, weak,
/// in a list, `*`) gets `304` with the validator, the cache policy, CORS and no body, on a cache
/// miss and on a hit; `HEAD` too. Another tag gets the block; an unknown block stays `404`.
#[test]
fn etag_and_not_modified() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "0")]);
    let mut c = relay.connect();
    let b = block(b"etag", 0);
    let id = id_of(&b);
    assert_eq!(put(&mut c, &b).status, 201);
    let path = format!("/sbtp/v1/block/{id}");
    let etag = format!("\"{id}\"");
    // First request: a cache miss, conditional.
    for cond in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"other\", {etag}"),
        "*".to_owned(),
    ] {
        let r = http_get(&mut c, &path, &format!("If-None-Match: {cond}\r\n"));
        assert_eq!(r.status, 304, "{cond}");
        assert_eq!(r.body, b"");
        assert_eq!(r.header("etag"), Some(etag.as_str()));
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    }
    let r = http_get(&mut c, &path, "If-None-Match: \"other\"\r\n");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b);
    assert_eq!(r.header("etag"), Some(etag.as_str()));
    let r = common::exchange(
        &mut c,
        &format!("HEAD {path} HTTP/1.1\r\nHost: relay.test\r\nIf-None-Match: {etag}\r\n\r\n"),
    );
    assert_eq!(r.status, 304);
    let missing = BlockId([0x22; 32]);
    let r = http_get(
        &mut c,
        &format!("/sbtp/v1/block/{missing}"),
        &format!("If-None-Match: \"{missing}\", *\r\n"),
    );
    assert_eq!(r.status, 404);
    assert_eq!(r.header("etag"), None);
}

#[test]
fn malformed_ids_and_traversal_never_reach_the_store() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let hex = "ab".repeat(32);
    for bad in [
        hex.to_uppercase(),                  // uppercase: not lowercase hex (spec §4)
        hex[..63].to_owned(),                // 63 characters
        format!("{hex}0"),                   // 65 characters
        format!("%61{}", &hex[1..]),         // percent-encoded 'a'
        format!("..%2F..%2F{}", &hex[10..]), // encoded traversal
        format!("{}.bin", &hex[..60]),       // a file name
        "..".to_owned(),
    ] {
        let r = http_get(&mut c, &format!("/sbtp/v1/block/{bad}"), "");
        assert_eq!(
            (r.status, error(&r).as_str()),
            (400, "InvalidParameter"),
            "{bad}"
        );
    }
    // Several segments do not match the route at all.
    let r = http_get(&mut c, "/sbtp/v1/block/../../index.redb", "");
    assert_eq!(r.status, 404);
    let r = http_get(&mut c, "/sbtp/v1/block", "");
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("PUT"));
}

#[test]
fn rejections_carry_the_adr_0004_names() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "8")]);
    let mut c = relay.connect();
    let good = block(b"names", 8);
    // F1, F3, F8.
    for (body, name) in [
        (vec![], "TooShort"),
        ([b"XB".as_slice(), &good[2..]].concat(), "BadMagic"),
        ([good.as_slice(), b"!"].concat(), "TrailingBytes"),
    ] {
        let r = put(&mut c, &body);
        assert_eq!((r.status, error(&r).as_str()), (400, name));
    }
    // C3: last signature byte flipped.
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    let r = put(&mut c, &bad);
    assert_eq!((r.status, error(&r).as_str()), (422, "InvalidSignature"));
    // C1 below the minimum: a block whose id has fewer than 8 leading zero bits.
    let weak = (0..=u8::MAX)
        .map(|n| block(&[n], 0))
        .find(|b| id_of(b).leading_zero_bits() < 8)
        .unwrap();
    let r = put(&mut c, &weak);
    assert_eq!((r.status, error(&r).as_str()), (400, "InsufficientPow"));
    assert!(!path_of(&relay.data, &id_of(&weak)).exists());
    assert!(sbtp_relay::metrics::rejected_total("InsufficientPow") > 0);
}

/// ADR 0007 rules 3 and 8: P1 after the format, before C1; the window is `max_future_ms`.
#[test]
fn timestamp_beyond_the_window_is_rejected() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "0"), ("MAX_FUTURE_MS", "60000")]);
    let mut c = relay.connect();
    let r = put(&mut c, &block_at(b"far", 0, now_ms() + 120_000));
    assert_eq!(
        (r.status, error(&r).as_str()),
        (400, "TimestampTooFarInFuture")
    );
    let r = put(&mut c, &block_at(b"near", 0, now_ms() + 30_000));
    assert_eq!(r.status, 201);
    // P1 comes before C1: a far block with no PoW still gets the P1 error.
    let relay = start(&[("MIN_POW_DIFFICULTY", "200")]);
    let r = put(&mut relay.connect(), &block_at(b"far", 0, u64::MAX));
    assert_eq!(error(&r), "TimestampTooFarInFuture");
}

/// ADR 0007 rule 5: what `/info` publishes is what C1 enforces.
#[test]
fn info_difficulty_is_the_enforced_one() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "10")]);
    let mut c = relay.connect();
    let d = http_get(&mut c, "/sbtp/v1/info", "").json()["min_pow_difficulty"]
        .as_u64()
        .unwrap();
    assert_eq!(d, 10);
    // Mined at 9: about half of such blocks have exactly 9 leading zero bits.
    let below = (0..=u8::MAX)
        .map(|n| block(&[n, 1], 9))
        .find(|b| id_of(b).leading_zero_bits() == 9)
        .unwrap();
    let r = put(&mut c, &below);
    assert_eq!((r.status, error(&r).as_str()), (400, "InsufficientPow"));
    assert_eq!(put(&mut c, &block(b"at", 10)).status, 201);
}

/// ADR 0008 rules 7 and 8: the transport limit, from `Content-Length` and from the bytes read.
#[test]
fn body_limit() {
    let relay = start(&[]);
    let mut c = relay.connect();
    // Exactly the limit is parsed (here: BadMagic).
    let r = put(&mut c, &vec![0u8; LIMIT]);
    assert_eq!((r.status, error(&r).as_str()), (400, "BadMagic"));
    // One byte more: 413 from the head, before the body is read; the connection is closed.
    let mut c = relay.connect();
    c.write_all(
        format!(
            "PUT /sbtp/v1/block HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
            LIMIT + 1
        )
        .as_bytes(),
    )
    .unwrap();
    let r = read_response(&mut c).unwrap();
    assert_eq!((r.status, error(&r).as_str()), (413, "BodyTooLarge"));
    assert!(is_closed(&mut c));
    // Chunked, no length announced: counted while read.
    let mut c = relay.connect();
    c.write_all(b"PUT /sbtp/v1/block HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    let chunk = vec![0u8; 16_384];
    for _ in 0..5 {
        let _ = c.write_all(format!("{:x}\r\n", chunk.len()).as_bytes());
        let _ = c.write_all(&chunk);
        let _ = c.write_all(b"\r\n");
    }
    let r = read_response(&mut c).unwrap();
    assert_eq!((r.status, error(&r).as_str()), (413, "BodyTooLarge"));
}

/// ADR 0008 rule 6: concurrent `PUT`s of one new block: exactly one `201`.
#[test]
fn concurrent_duplicates_get_one_201() {
    let relay = Arc::new(start(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("RATE_LIMIT_EXEMPT", "127.0.0.1/32"),
        ("PUT_MAX_IN_FLIGHT", "8"),
        ("MAX_BLOCKING_THREADS", "16"),
    ]));
    let b = Arc::new(block(&[9; 4_000], 0));
    let go = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (relay, b, go) = (Arc::clone(&relay), Arc::clone(&b), Arc::clone(&go));
            std::thread::spawn(move || {
                let mut c = relay.connect();
                go.wait();
                put(&mut c, &b).status
            })
        })
        .collect();
    let mut statuses: Vec<u16> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 200, 200, 200, 200, 200, 200, 201]);
    let r = http_get(
        &mut relay.connect(),
        &format!("/sbtp/v1/block/{}", id_of(&b)),
        "",
    );
    assert_eq!(r.body, *b, "the stored bytes are intact");
}

/// ADR 0003 rule 10: the signature check is skipped only for bytes identical to the stored ones
/// of an indexed block. The stored file here is indexed, then given a broken signature behind the
/// running relay's back (at start-up the walk would not read it, ADR 0023 rule 15), so the skip
/// is observable: identical bytes get `200`, any other bytes are verified. A valid variant then
/// replaces the damaged file (ADR 0023 rule 8).
#[test]
fn shortcut_only_for_identical_bytes() {
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let relay = TestServer::start(&s, Router::new());
    let good = block(b"shortcut", 0);
    let id = id_of(&good);
    let mut c = relay.connect();
    assert_eq!(put(&mut c, &good).status, 201);
    let mut stored = good.clone();
    *stored.last_mut().unwrap() ^= 1;
    let p = path_of(&relay.data, &id);
    std::fs::write(&p, &stored).unwrap();
    assert_eq!(
        put(&mut c, &stored).status,
        200,
        "identical: not re-verified"
    );
    assert_eq!(std::fs::read(&p).unwrap(), stored, "nothing moved");
    let mut other = good.clone();
    *other.last_mut().unwrap() ^= 2;
    let r = put(&mut c, &other);
    assert_eq!((r.status, error(&r).as_str()), (422, "InvalidSignature"));
    assert_eq!(std::fs::read(&p).unwrap(), stored, "nothing moved");
    assert_eq!(put(&mut c, &good).status, 200);
    assert_eq!(
        std::fs::read(&p).unwrap(),
        good,
        "the damaged file is replaced"
    );
    // A valid stored file is never displaced by other bytes (first write wins, spec §3.4).
    let r = put(&mut c, &other);
    assert_eq!((r.status, error(&r).as_str()), (422, "InvalidSignature"));
    assert_eq!(std::fs::read(&p).unwrap(), good);
}

/// ADR 0013 rules 18 to 21: `507` once the quota is reached, nothing written; known blocks and
/// reads still served.
#[test]
fn quota_gives_507() {
    let relay = start(&[("MIN_POW_DIFFICULTY", "0"), ("MAX_STORE_BYTES", "4194304")]);
    let mut c = relay.connect();
    let mut stored = Vec::new();
    let full = (0u8..80).find_map(|n| {
        let b = block(&vec![n; 60_000], 0);
        let r = put(&mut c, &b);
        if r.status == 201 {
            stored.push(b);
            None
        } else {
            Some((r, b))
        }
    });
    let (r, refused) = full.expect("the quota is reached within 80 blocks of 60 kB");
    assert_eq!((r.status, error(&r).as_str()), (507, "StorageFull"));
    // ADR 0023 rules 13 and 18.
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("retry-after"), None);
    assert!(!path_of(&relay.data, &id_of(&refused)).exists());
    let first = stored.first().expect("at least one block fits");
    assert_eq!(
        put(&mut c, first).status,
        200,
        "a known block still gets 200"
    );
    let r = http_get(&mut c, &format!("/sbtp/v1/block/{}", id_of(first)), "");
    assert_eq!(r.status, 200);
}

/// ADR 0003 rule 11, ADR 0023 rule 10: an indexed file that is not the block of its name is never
/// served; the first `GET` miss moves it to quarantine.
#[test]
fn corrupt_file_is_not_served() {
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let relay = start(&[("MIN_POW_DIFFICULTY", "0")]);
    let blocks: Vec<_> = (0..2u8).map(|n| block(&[n; 50], 0)).collect();
    for b in &blocks {
        assert_eq!(put(&mut relay.connect(), b).status, 201);
    }
    let data = relay.data.clone();
    drop(relay);
    // One payload byte flipped (the id no longer matches), one file truncated.
    let p0 = path_of(&data, &id_of(&blocks[0]));
    let mut bytes = std::fs::read(&p0).unwrap();
    bytes[60] ^= 1;
    std::fs::write(&p0, bytes).unwrap();
    let p1 = path_of(&data, &id_of(&blocks[1]));
    std::fs::write(&p1, &blocks[1][..100]).unwrap();
    let relay = TestServer::start_in(&s, Router::new(), &data);
    let mut c = relay.connect();
    for b in &blocks {
        let r = http_get(&mut c, &format!("/sbtp/v1/block/{}", id_of(b)), "");
        assert_eq!(r.status, 404);
        assert_eq!(r.header("cache-control"), Some("no-store"));
    }
    assert!(!p0.exists() && !p1.exists(), "both moved");
    assert_eq!(
        std::fs::read_dir(data.join("quarantine")).unwrap().count(),
        2
    );
}

/// ADR 0018 rules 18, 29 and 30: the per-client `PUT` bound gives `429`, a full `PUT` class `503`;
/// both before the body is read.
#[test]
fn put_admission() {
    let hold = |relay: &TestServer| {
        let mut c = relay.connect();
        c.write_all(b"PUT /sbtp/v1/block HTTP/1.1\r\nHost: t\r\nContent-Length: 200\r\n\r\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        c
    };
    let relay = start(&[("PUT_MAX_IN_FLIGHT_PER_CLIENT", "1")]);
    let _held = hold(&relay);
    let r = put(&mut relay.connect(), &block(b"x", 16));
    assert_eq!((r.status, error(&r).as_str()), (429, "RateLimited"));
    assert_eq!(r.header("retry-after"), Some("1"));
    assert_eq!(
        r.header("cache-control"),
        Some("no-store"),
        "ADR 0023 rule 13"
    );
    // GET is not affected (ADR 0018 rule 32).
    assert_eq!(
        http_get(&mut relay.connect(), "/sbtp/v1/info", "").status,
        200
    );

    let relay = start(&[
        ("RATE_LIMIT_EXEMPT", "127.0.0.1/32"),
        ("PUT_MAX_IN_FLIGHT", "1"),
        ("PUT_MAX_IN_FLIGHT_PER_CLIENT", "1"),
        ("PUT_MAX_QUEUE", "0"),
    ]);
    let _held = hold(&relay);
    let r = put(&mut relay.connect(), &[0u8; 10]);
    assert_eq!((r.status, error(&r).as_str()), (503, "Unavailable"));
    assert_eq!(r.header("retry-after"), Some("2"));
    assert_eq!(
        r.header("cache-control"),
        Some("no-store"),
        "ADR 0023 rule 13"
    );
}

/// Every frozen vector as a `PUT` body, on a relay at the vector's difficulty. The relay applies
/// P1 (a vector timestamp beyond the window gets `TimestampTooFarInFuture`), and R1 does not
/// apply to a `PUT` (ADR 0004 rule 14).
#[test]
fn frozen_vectors_map_to_http_statuses() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors/v1");
    let mut vectors: Vec<serde_json::Value> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
        .collect();
    assert!(vectors.len() > 80);
    vectors.sort_by_key(|v| v["params"]["difficulty"].as_u64().unwrap());
    let unhex = |s: &str| -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let mut servers = std::collections::HashMap::<u64, TestServer>::new();
    let mut seen = std::collections::HashSet::new();
    for v in &vectors {
        let name = v["name"].as_str().unwrap();
        let d = v["params"]["difficulty"].as_u64().unwrap();
        let relay = servers
            .entry(d)
            .or_insert_with(|| start(&[("MIN_POW_DIFFICULTY", &d.to_string())]));
        let bytes = unhex(v["block_hex"].as_str().unwrap());
        let expect = &v["expect"];
        let far = bytes.len() >= 11
            && u64::from_be_bytes(bytes[3..11].try_into().unwrap()) > now_ms() + 300_000;
        let format = |e: &str| {
            matches!(
                e,
                "TooShort"
                    | "BadMagic"
                    | "UnsupportedVersion"
                    | "TooManyParents"
                    | "Truncated"
                    | "TrailingBytes"
                    | "DuplicateParent"
            )
        };
        let (status, err): (u16, Option<&str>) = match expect["error"].as_str() {
            Some("TooLong") => (413, Some("BodyTooLarge")),
            Some(e) if format(e) => (400, Some(e)),
            _ if far => (400, Some("TimestampTooFarInFuture")),
            Some("BlockIdMismatch") | None => {
                let id = expect["block_id"].as_str().unwrap().to_owned();
                (if seen.insert(id) { 201 } else { 200 }, None)
            }
            Some(e @ ("InvalidPublicKey" | "InvalidSignature")) => (422, Some(e)),
            Some(e) => (400, Some(e)),
        };
        let r = put(&mut relay.connect(), &bytes);
        assert_eq!(r.status, status, "{name}");
        if let Some(e) = err {
            assert_eq!(error(&r), e, "{name}");
        }
    }
}

const CHILD_DIR: &str = "SBTP_BLOCKS_TEST_CHILD_DIR";
const CHILD_INDEX: &str = "SBTP_BLOCKS_TEST_CHILD_INDEX";

/// Child side of the crash tests: does nothing unless started by them. Writes one block file
/// through the store, then (with `CHILD_INDEX`) indexes it with a non-durable commit, says
/// `READY` and waits to be killed. `READY` on standard output is the test protocol.
#[test]
#[allow(clippy::print_stdout)]
fn crash_child() {
    let Ok(dir) = std::env::var(CHILD_DIR) else {
        return;
    };
    let dir = Path::new(&dir);
    let index = RedbIndex::open(&dir.join("index.redb"), 1 << 20).unwrap();
    let store = Store::open(dir, dir.join("index.redb"), 1 << 30).unwrap();
    let b = block(b"crash", 0);
    let v = sbtp_core::validate_submitted(&b, 0).unwrap();
    store.write_new(&v).unwrap();
    if std::env::var(CHILD_INDEX).is_ok() {
        let parents = v.block().parents();
        index
            .insert(v.block_id(), 0, parents, now_ms(), FileState::Created)
            .unwrap();
    }
    println!("READY {}", v.block_id());
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(60));
}

/// Kills `crash_child` with `SIGKILL` at its point, then reconciles as the next start-up does.
fn crash_then_restart(name: &str, indexed: bool) {
    let dir = tmp_dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "crash_child", "--nocapture"])
        .env(CHILD_DIR, &dir)
        .stdout(std::process::Stdio::piped());
    if indexed {
        cmd.env(CHILD_INDEX, "1");
    }
    let mut child = cmd.spawn().unwrap();
    let out = std::io::BufReader::new(child.stdout.take().unwrap());
    let id = out
        .lines()
        .map_while(Result::ok)
        .find_map(|l| l.strip_prefix("READY ").map(str::to_owned));
    child.kill().unwrap();
    child.wait().unwrap();
    let id = sbtp_relay::store::parse_hex_id(&id.expect("child reached READY")).unwrap();
    {
        let index = RedbIndex::open(&dir.join("index.redb"), 1 << 20).unwrap();
        let store = Store::open(&dir, dir.join("index.redb"), 1 << 30).unwrap();
        if !indexed {
            assert_eq!(
                index.contains(&id).unwrap(),
                None,
                "the crash left an orphan"
            );
        }
        let mtime = std::fs::metadata(path_of(&dir, &id))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let found = index.contains(&id).unwrap();
        let epoch = index.epoch();
        let rec = reconcile(&store, &index).unwrap();
        // ADR 0024 rule 1: a new epoch exactly when the walk indexed an orphan.
        assert_eq!(rec.epoch_renewed, found.is_none());
        assert_eq!(index.epoch() != epoch, found.is_none());
        let pos = index
            .contains(&id)
            .unwrap()
            .expect("indexed after reconciliation");
        if found.is_none() {
            assert_eq!(rec.orphans, 1);
            assert_eq!(
                u128::from(pos.received_at),
                mtime,
                "rule 9: the file time is `received_at`"
            );
        }
        let again = reconcile(&store, &index).unwrap();
        assert_eq!(
            (again.orphans, again.epoch_renewed),
            (0, false),
            "idempotent"
        );
        assert_eq!(again.dirs_created, 0, "ADR 0025 rule 17");
    }
    // The relay serves it and knows it.
    let relay = TestServer::start_in(
        &settings(&[("MIN_POW_DIFFICULTY", "0")]),
        Router::new(),
        &dir,
    );
    let mut c = relay.connect();
    let r = http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "");
    assert_eq!(r.status, 200);
    assert_eq!(put(&mut c, &r.body).status, 200);
}

/// Killed between the file and the index insert.
#[test]
fn crash_after_file_before_index() {
    crash_then_restart("crash-file", false);
}

/// Killed after a non-durable index insert (ADR 0013 rule 10): the entry may be lost with the
/// last second; reconciliation restores it.
#[test]
fn crash_after_non_durable_index_insert() {
    crash_then_restart("crash-index", true);
}

/// ADR 0013 rule 8, the reverse case: an index entry whose file is gone (a phantom) gives `404`,
/// and the block can be stored again (`201`).
#[test]
fn phantom_entry_is_tolerated() {
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let relay = start(&[("MIN_POW_DIFFICULTY", "0")]);
    let b = block(b"phantom", 0);
    let id = id_of(&b);
    assert_eq!(put(&mut relay.connect(), &b).status, 201);
    let data = relay.data.clone();
    drop(relay);
    std::fs::remove_file(path_of(&data, &id)).unwrap();
    let relay = TestServer::start_in(&s, Router::new(), &data);
    let mut c = relay.connect();
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "").status,
        404
    );
    assert_eq!(put(&mut c, &b).status, 201);
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "").body,
        b
    );
}

/// Quota bytes in `data` as ADR 0013 rule 18 and ADR 0025 rule 8 count them: the tree charge,
/// block files rounded up to 4,096 bytes plus the entry charge, and the index file.
fn disk_use(data: &Path) -> u64 {
    fn walk(dir: &Path, sum: &mut u64) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            if m.is_dir() {
                walk(&e.path(), sum);
            } else {
                *sum += cost(m.len());
            }
        }
    }
    let mut sum = TREE_CHARGE + std::fs::metadata(data.join("index.redb")).unwrap().len();
    walk(&data.join("blocks"), &mut sum);
    sum
}

/// Security review M-1: the growth of the index is reserved before a block is written, so block
/// files plus index never exceed `max_store_bytes`, with minimum-size blocks of 8 parents (the
/// largest index entries per byte stored). redb doubles its file; the quotas are chosen so that a
/// doubling falls on an admitted block with the reservation of the current size only (measured on
/// macOS: 561,152 → 1,118,208 bytes at block 204 and → 2,232,320 bytes at block 488;
/// `max_store_bytes` is at least 4 MiB, ADR 0025 rule 16).
#[test]
fn quota_includes_index_growth() {
    for quota in [4_194_304u64, 6_291_456] {
        fill_to_quota(quota);
    }
}

fn fill_to_quota(quota: u64) {
    let relay = start(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("MAX_STORE_BYTES", &quota.to_string()),
    ]);
    let mut c = relay.connect();
    let (mut created, mut full) = (0u32, 0u32);
    for i in 0u32..800 {
        let parents: Vec<BlockId> = (0u8..8)
            .map(|k| {
                let mut raw = [0u8; 32];
                raw[0] = k;
                raw[1..5].copy_from_slice(&i.to_be_bytes());
                BlockId(raw)
            })
            .collect();
        let k = key();
        let b = BlockBuilder::for_key(&k)
            .timestamp(now_ms())
            .parents(&parents)
            .build(&k, 0)
            .unwrap();
        match put(&mut c, &b).status {
            201 => created += 1,
            507 => full += 1,
            s => panic!("unexpected status {s}"),
        }
        let used = disk_use(&relay.data);
        assert!(used <= quota, "quota {quota}, block {i}: {used} bytes used");
        if full >= 10 {
            break;
        }
    }
    assert!(
        created > 20,
        "quota {quota}: not all index reserve ({created})"
    );
    assert_eq!(full, 10, "quota {quota} is reached");
    let data = relay.data.clone();
    drop(relay); // closes the index
    assert!(disk_use(&data) <= quota);
}

/// ADR 0013 rule 20: a duplicate that loses the race near the quota is still a known block, not
/// `StorageFull`.
#[test]
fn duplicate_at_the_quota_is_known() {
    let data = tmp_dir("dup-quota");
    std::fs::create_dir_all(&data).unwrap();
    let a = block(b"first", 0);
    let b = block(b"second", 0);
    // Room for `a` and the index reserve, nothing more. No index file: its size is 0.
    let quota = TREE_CHARGE + cost(a.len() as u64) + index_reserve(0);
    let store = Store::open(&data, data.join("index.redb"), quota).unwrap();
    let va = sbtp_core::validate_submitted(&a, 0).unwrap();
    let vb = sbtp_core::validate_submitted(&b, 0).unwrap();
    assert!(matches!(store.write_new(&va), Ok(Stored::Created)));
    assert!(matches!(store.write_new(&vb), Err(StoreError::Full)));
    assert!(
        matches!(store.write_new(&va), Ok(Stored::AlreadyPresent)),
        "a held block near the quota is known"
    );
    assert_eq!(
        store.used_bytes(),
        TREE_CHARGE + cost(a.len() as u64),
        "nothing reserved"
    );
    // Only a regular file with the same bytes is the held block: a differing file or a symbolic
    // link under `b`'s final name leaves the store full.
    let pb = path_of(&data, vb.block_id());
    std::fs::create_dir_all(pb.parent().unwrap()).unwrap();
    std::fs::write(&pb, b"other bytes").unwrap();
    assert!(
        matches!(store.write_new(&vb), Err(StoreError::Full)),
        "differing"
    );
    std::fs::remove_file(&pb).unwrap();
    let target = data.join("outside.bin");
    std::fs::write(&target, &b).unwrap();
    std::os::unix::fs::symlink(&target, &pb).unwrap();
    assert!(
        matches!(store.write_new(&vb), Err(StoreError::Full)),
        "symlink"
    );
}

/// An index that records every insert and delays the `Created` ones, so that a second `PUT` of
/// the block runs while the first has linked its file but not indexed it yet.
struct SlowIndex {
    inner: RedbIndex,
    inserts: Mutex<Vec<(BlockId, FileState, Option<Position>)>>,
}

impl IndexBackend for SlowIndex {
    type Error = IndexError;

    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self {
            inner: RedbIndex::open(path, cache_bytes)?,
            inserts: Mutex::new(Vec::new()),
        })
    }
    fn epoch(&self) -> u64 {
        self.inner.epoch()
    }
    fn renew_epoch(&self) -> Result<u64, IndexError> {
        self.inner.renew_epoch()
    }
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, IndexError> {
        if state == FileState::Created {
            std::thread::sleep(Duration::from_millis(100));
        }
        let pos = self.inner.insert(id, len, parents, now_ms, state)?;
        self.inserts.lock().unwrap().push((*id, state, pos));
        Ok(pos)
    }
    fn flush(&self) -> Result<(), IndexError> {
        self.inner.flush()
    }
    fn flush_pending(&self) -> Result<bool, IndexError> {
        self.inner.flush_pending()
    }
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, IndexError> {
        self.inner.contains(id)
    }
    fn query(
        &self,
        parent: Option<&BlockId>,
        from: Position,
        limit: usize,
    ) -> Result<Page, IndexError> {
        self.inner.query(parent, from, limit)
    }
    fn expired(&self, before: Position, max: usize) -> Result<Vec<Position>, IndexError> {
        self.inner.expired(before, max)
    }
    fn remove(&self, positions: &[Position]) -> Result<usize, IndexError> {
        self.inner.remove(positions)
    }
    fn len(&self) -> Result<u64, IndexError> {
        self.inner.len()
    }
}

/// ADR 0013 rule 6: concurrent `PUT`s of one new block index it once. Without the per-`block_id`
/// lock, a second `PUT` sees the linked file before its index entry, repairs it at one position,
/// and the first `PUT` then re-indexes it at another (`Created` replaces a stale entry).
#[test]
fn concurrent_duplicates_never_move_the_position() {
    let data = tmp_dir("dup-race");
    std::fs::create_dir_all(&data).unwrap();
    let index = Arc::new(SlowIndex::open(&data.join("index.redb"), 1 << 20).unwrap());
    let s = settings(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("RATE_LIMIT_EXEMPT", "127.0.0.1/32"),
        ("PUT_MAX_IN_FLIGHT", "8"),
        ("MAX_BLOCKING_THREADS", "16"),
    ]);
    let relay = Arc::new(TestServer::start_with(
        &s,
        Router::new(),
        &data,
        Arc::clone(&index),
    ));
    let b = Arc::new(block(b"race", 0));
    let go = Arc::new(Barrier::new(6));
    let threads: Vec<_> = (0..6u64)
        .map(|n| {
            let (relay, b, go) = (Arc::clone(&relay), Arc::clone(&b), Arc::clone(&go));
            std::thread::spawn(move || {
                let mut c = relay.connect();
                go.wait();
                // Staggered inside the 100 ms window of the first insert.
                std::thread::sleep(Duration::from_millis(n * 10));
                put(&mut c, &b).status
            })
        })
        .collect();
    let mut statuses: Vec<u16> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 200, 200, 200, 200, 201]);
    let id = id_of(&b);
    let inserts = index.inserts.lock().unwrap().clone();
    let placed: Vec<_> = inserts
        .iter()
        .filter(|(i, _, p)| *i == id && p.is_some())
        .collect();
    assert_eq!(placed.len(), 1, "one position only: {inserts:?}");
    assert_eq!(placed[0].1, FileState::Created);
    assert_eq!(index.contains(&id).unwrap(), placed[0].2);
}

/// Security review L-4: a `tmp/` or `blocks/` that is a symbolic link is refused at start-up and
/// its target is left untouched; created directories are `0700` and files `0600`.
#[cfg(unix)]
#[test]
fn symlinked_store_directories_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    for name in ["tmp", "blocks"] {
        let data = tmp_dir("symlink");
        let target = tmp_dir("symlink-target");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let keep = target.join("keep.tmp");
        std::fs::write(&keep, b"not the relay's").unwrap();
        std::os::unix::fs::symlink(&target, data.join(name)).unwrap();
        let opened = Store::open(&data, data.join("index.redb"), 1 << 30);
        assert!(opened.is_err(), "{name}: a symbolic link is refused");
        assert_eq!(std::fs::read(&keep).unwrap(), b"not the relay's", "{name}");
    }
    let data = tmp_dir("modes");
    std::fs::create_dir_all(&data).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    let b = block(b"modes", 0);
    let v = sbtp_core::validate_submitted(&b, 0).unwrap();
    store.write_new(&v).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let file = path_of(&data, v.block_id());
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
    for d in ["blocks", "tmp", "quarantine"] {
        assert_eq!(mode(&data.join(d)), 0o700, "{d}");
    }
    // A shard directory that is a symbolic link is neither written through nor read through.
    let other = block(b"shard link", 0);
    let vo = sbtp_core::validate_submitted(&other, 0).unwrap();
    let shard = path_of(&data, vo.block_id())
        .parent()
        .unwrap()
        .to_path_buf();
    let target = tmp_dir("shard-target");
    std::fs::create_dir_all(&target).unwrap();
    // ADR 0025 rule 3: every shard directory exists from the start; replace this one by a link.
    assert!(std::fs::symlink_metadata(&shard).unwrap().is_dir());
    std::fs::remove_dir_all(&shard).unwrap();
    std::os::unix::fs::symlink(&target, &shard).unwrap();
    let used = store.used_bytes();
    assert!(matches!(store.write_new(&vo), Err(StoreError::Io(_))));
    assert_eq!(store.used_bytes(), used, "the reservation is released");
    assert!(store.read(vo.block_id()).is_err());
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    assert!(
        std::fs::symlink_metadata(&shard).unwrap().is_symlink(),
        "never replaced by the write path"
    );
}
