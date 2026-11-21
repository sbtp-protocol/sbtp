//! `GET /sbtp/v1/query` over real HTTP (spec §4; ADR 0012 rules 5 to 15, ADR 0013 rules 5 and 14,
//! ADR 0018 rules 9 to 13, 21, 29 and 30) and cursor epochs across restarts (ADR 0024).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use axum::Router;
use common::{
    Response, TestServer, get as http_get, now_ms, put_block, settings, signed_block, tmp_dir,
};
use sbtp_core::BlockId;
use sbtp_relay::index::{FileState, IndexBackend, IndexError, Position, RedbIndex};
use sbtp_relay::metrics;
use sbtp_relay::store::{Store, reconcile};

fn start(pairs: &[(&str, &str)]) -> TestServer {
    let mut all = vec![("MIN_POW_DIFFICULTY", "0")];
    all.extend_from_slice(pairs);
    TestServer::start(&settings(&all), Router::new())
}

fn id_of(b: &[u8]) -> String {
    sbtp_core::parse(b).unwrap().block_id().to_string()
}

/// Stores `n` new blocks with `parents` and returns their identifiers in order.
fn store(c: &mut TcpStream, tag: &str, n: usize, parents: &[BlockId]) -> Vec<String> {
    (0..n)
        .map(|i| {
            let b = signed_block(format!("{tag}{i}").as_bytes(), parents);
            assert_eq!(put_block(c, &b).status, 201);
            id_of(&b)
        })
        .collect()
}

/// `(block_ids, cursor, more)` of a `200` page; checks the headers and the exact members.
fn page(c: &mut TcpStream, query: &str) -> (Vec<String>, String, bool) {
    let r = http_get(c, &format!("/sbtp/v1/query{query}"), "");
    assert_eq!(
        r.status,
        200,
        "{query}: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(
        r.header("cache-control"),
        Some("no-store"),
        "ADR 0012 rule 32"
    );
    let v = r.json();
    let mut keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["block_ids", "cursor", "head", "more"],
        "ADR 0012 rule 10, ADR 0051 rule 18"
    );
    let ids = v["block_ids"].as_array().unwrap();
    let ids = ids.iter().map(|i| i.as_str().unwrap().to_owned()).collect();
    let cursor = v["cursor"].as_str().unwrap().to_owned();
    assert!(
        (1..=128).contains(&cursor.len())
            && cursor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "rule 5: {cursor}"
    );
    (ids, cursor, v["more"].as_bool().unwrap())
}

fn refused(r: &Response) -> (u16, String) {
    assert_eq!(r.header("cache-control"), Some("no-store"));
    (r.status, r.json()["error"].as_str().unwrap().to_owned())
}

/// ADR 0012 rules 6 to 12: acceptance order, children of a parent, walks with a cursor, polling,
/// `since` as reception time, the later of `since` and the cursor, `200` on no match.
#[test]
fn walks_children_and_all_blocks() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let parent = BlockId([0xaa; 32]);
    let t0 = now_ms();
    let mut kids = store(&mut c, "kid", 3, &[parent]);
    let others = store(&mut c, "other", 2, &[]);

    let (ids, cursor, more) = page(&mut c, &format!("?parent={parent}&limit=2"));
    assert_eq!((ids.as_slice(), more), (&kids[..2], true));
    let (ids, cursor, more) = page(&mut c, &format!("?parent={parent}&limit=2&cursor={cursor}"));
    assert_eq!((ids.as_slice(), more), (&kids[2..], false));
    // Polling: the same cursor later returns the children stored since, and only them.
    let (empty, same, more) = page(&mut c, &format!("?parent={parent}&cursor={cursor}"));
    assert!(empty.is_empty() && !more);
    kids.extend(store(&mut c, "late", 1, &[parent]));
    let (ids, _, _) = page(&mut c, &format!("?parent={parent}&cursor={same}"));
    assert_eq!(ids, kids[3..]);

    // Rule 15: no parameter lists every block, in acceptance order.
    let (all, _, more) = page(&mut c, "");
    let mut expected = kids[..3].to_vec();
    expected.extend(others.iter().cloned());
    expected.push(kids[3].clone());
    assert_eq!((all.clone(), more), (expected, false));

    // Rule 7: `since` is the relay's reception time, inclusive.
    let (ids, _, _) = page(&mut c, &format!("?since={t0}"));
    assert_eq!(ids, all);
    // Rule 11: no match is `200` and an empty list, never `404`.
    for q in [
        format!("?parent={}", BlockId([0xbb; 32])),
        format!("?since={}", now_ms() + 3_600_000),
    ] {
        let (ids, _, more) = page(&mut c, &q);
        assert!(ids.is_empty() && !more, "{q}");
    }
    // Rule 9: with both, the later of `since` and the cursor.
    let (first, early, _) = page(&mut c, "?limit=1");
    assert_eq!(first, all[..1]);
    let (ids, _, _) = page(&mut c, &format!("?since=0&cursor={early}"));
    assert_eq!(ids, all[1..]);
    let future = now_ms() + 3_600_000;
    let (ids, _, _) = page(&mut c, &format!("?since={future}&cursor={early}"));
    assert_eq!(ids, Vec::<String>::new());
}

/// ADR 0012 rules 5 and 8: default 100, lowered to `max_query_limit`, never an error above it.
#[test]
fn limit_default_and_maximum() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let all = store(&mut c, "d", 101, &[]);
    let (ids, _, more) = page(&mut c, "");
    assert_eq!((ids.as_slice(), more), (&all[..100], true));
    drop(relay);

    let relay = start(&[("MAX_QUERY_LIMIT", "3")]);
    let mut c = relay.connect();
    let all = store(&mut c, "m", 4, &[]);
    for (q, n) in [
        ("", 3),
        ("?limit=2", 2),
        ("?limit=99999999999999999999999", 3),
    ] {
        let (ids, _, more) = page(&mut c, q);
        assert_eq!((ids.as_slice(), more), (&all[..n], true), "{q}");
    }
}

/// ADR 0012 rules 5, 9 and 17: one `400` per parameter rule, `InvalidCursor` for a well-formed
/// cursor of another epoch or another relay; `405` for another method.
#[test]
fn malformed_requests_get_400() {
    let relay = start(&[]);
    let mut c = relay.connect();
    store(&mut c, "e", 1, &[]);
    let (_, cursor, _) = page(&mut c, "");
    let p = BlockId([0xab; 32]).to_string();
    let invalid = "InvalidParameter";
    let cases = [
        ("?foo=1".to_owned(), invalid),
        ("?limit".to_owned(), invalid),
        ("?limit=0".to_owned(), invalid),
        ("?limit=-1".to_owned(), invalid),
        ("?since=1.5".to_owned(), invalid),
        ("?since=18446744073709551616".to_owned(), invalid),
        (format!("?parent={}", p.to_ascii_uppercase()), invalid),
        (format!("?parent={p}&parent={p}"), invalid),
        ("?limit=1&limit=1".to_owned(), invalid),
        ("?cursor=a.b".to_owned(), invalid),
        (format!("?cursor={}", "a".repeat(129)), invalid),
        ("?cursor=abc".to_owned(), "InvalidCursor"),
        // The same position under another epoch: the first byte of the epoch flipped.
        (
            format!(
                "?cursor={}{}",
                if cursor.starts_with('0') { '1' } else { '0' },
                &cursor[1..]
            ),
            "InvalidCursor",
        ),
    ];
    for (q, name) in cases {
        let r = http_get(&mut c, &format!("/sbtp/v1/query{q}"), "");
        assert_eq!(refused(&r), (400, name.to_owned()), "{q}");
    }
    let r = common::exchange(
        &mut c,
        "PUT /sbtp/v1/query HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(refused(&r), (405, "MethodNotAllowed".to_owned()));
}

/// ADR 0013 rule 14: an expired block is never listed, before any sweep. The block file carries
/// a time older than `block_ttl_ms`; the start-up walk indexes it at that time.
#[test]
fn expired_blocks_are_not_listed() {
    let data = tmp_dir("query-expired");
    let s = settings(&[("MIN_POW_DIFFICULTY", "0"), ("BLOCK_TTL_MS", "60000")]);
    let old = signed_block(b"old", &[]);
    let id = sbtp_core::parse(&old).unwrap().block_id();
    std::fs::create_dir_all(&data).unwrap();
    drop(Store::open(&data, data.join("index.redb"), 1 << 30).unwrap());
    let path = data.join(format!("blocks/{:02x}/{id}.bin", id.as_bytes()[31]));
    std::fs::write(&path, &old).unwrap();
    let long_ago = std::time::SystemTime::now() - Duration::from_secs(120);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();
    let relay = TestServer::start_in(&s, Router::new(), &data);
    let mut c = relay.connect();
    let fresh = store(&mut c, "fresh", 1, &[]);
    let (ids, _, more) = page(&mut c, "?since=0");
    assert_eq!((ids, more), (fresh, false));
    // Still held: `GET /block` MAY serve it until the sweeper deletes it.
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "").status,
        200
    );
}

/// An index whose `/query` pages take 300 ms, to hold the only reader; counts the pages started.
struct SlowQueries(RedbIndex, AtomicUsize);

impl IndexBackend for SlowQueries {
    type Error = IndexError;

    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self(
            RedbIndex::open(path, cache_bytes)?,
            AtomicUsize::new(0),
        ))
    }
    fn epoch(&self) -> u64 {
        self.0.epoch()
    }
    fn renew_epoch(&self) -> Result<u64, IndexError> {
        self.0.renew_epoch()
    }
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, IndexError> {
        self.0.insert(id, len, parents, now_ms, state)
    }
    fn flush(&self) -> Result<(), IndexError> {
        self.0.flush()
    }
    fn flush_pending(&self) -> Result<bool, IndexError> {
        self.0.flush_pending()
    }
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, IndexError> {
        self.0.contains(id)
    }
    fn read_query(
        &self,
        plan: &sbtp_relay::index::QueryPlan,
    ) -> Result<sbtp_relay::index::QueryAnswer, IndexError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        self.0.read_query(plan)
    }
    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, IndexError> {
        self.0.expired(before, max)
    }
    fn remove(&self, positions: &[Position]) -> Result<usize, IndexError> {
        self.0.remove(positions)
    }
    fn len(&self) -> Result<u64, IndexError> {
        self.0.len()
    }
}

/// ADR 0018 rules 12, 13 and 30: with `index_max_readers = 1` and no queue, a second concurrent
/// `/query` gets `503 Unavailable` with `Retry-After`; `GET /block` is not affected.
#[test]
fn index_readers_are_bounded() {
    let data = tmp_dir("query-readers");
    std::fs::create_dir_all(&data).unwrap();
    let index = Arc::new(SlowQueries::open(&data.join("index.redb"), 1 << 20).unwrap());
    let s = settings(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("INDEX_MAX_READERS", "1"),
        ("INDEX_MAX_QUEUE", "0"),
    ]);
    let relay = Arc::new(TestServer::start_with(&s, Router::new(), &data, index));
    let b = signed_block(b"read", &[]);
    assert_eq!(put_block(&mut relay.connect(), &b).status, 201);
    let go = Arc::new(Barrier::new(2));
    let runs: Vec<_> = (0..2)
        .map(|_| {
            let (relay, go) = (Arc::clone(&relay), Arc::clone(&go));
            std::thread::spawn(move || {
                let mut c = relay.connect();
                go.wait();
                let r = http_get(&mut c, "/sbtp/v1/query", "");
                (r.status, r.header("retry-after").map(str::to_owned))
            })
        })
        .collect();
    let mut got: Vec<_> = runs.into_iter().map(|t| t.join().unwrap()).collect();
    got.sort();
    assert_eq!(got, [(200, None), (503, Some("2".to_owned()))]);
    let r = http_get(
        &mut relay.connect(),
        &format!("/sbtp/v1/block/{}", id_of(&b)),
        "",
    );
    assert_eq!(r.status, 200);
}

/// ADR 0018 rules 9 to 11 and clarification M1, ADR 0021 clarification X5: the lookup of a
/// repeated `PUT` of a held block is a job of the reader threads, below the handler. While a slow
/// `/query` holds the only reader, with no queue, the lookup is refused: the `PUT` still gets `200`
/// (a saturated `/query` class does not fail a `PUT`, rule 32) and the skipped repair is counted.
#[test]
fn repeated_put_goes_through_the_reader_pool() {
    let data = tmp_dir("query-put-reader");
    std::fs::create_dir_all(&data).unwrap();
    let index = Arc::new(SlowQueries::open(&data.join("index.redb"), 1 << 20).unwrap());
    let s = settings(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("INDEX_MAX_READERS", "1"),
        ("INDEX_MAX_QUEUE", "0"),
    ]);
    let relay = Arc::new(TestServer::start_with(
        &s,
        Router::new(),
        &data,
        Arc::clone(&index),
    ));
    let b = signed_block(b"held", &[]);
    assert_eq!(put_block(&mut relay.connect(), &b).status, 201);
    let slow = {
        let relay = Arc::clone(&relay);
        std::thread::spawn(move || http_get(&mut relay.connect(), "/sbtp/v1/query", "").status)
    };
    // Security review of 1c-b, I-8: wait until the slow page holds the reader, not a fixed time.
    while index.1.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    let deferred = metrics::index_repairs_deferred_total();
    assert_eq!(put_block(&mut relay.connect(), &b).status, 200, "M1");
    assert!(metrics::index_repairs_deferred_total() > deferred, "X5");
    assert_eq!(slow.join().unwrap(), 200);
    assert_eq!(
        put_block(&mut relay.connect(), &b).status,
        200,
        "reader free"
    );
}

/// ADR 0018 rules 21 and 29, ADR 0020 rules 22 and 23: the `query` bucket of a client allows
/// `rate_query_burst` requests, then `429 RateLimited` with the seconds until the next token, the
/// JSON body and the CORS headers. Other classes are not affected.
#[test]
fn query_bucket_gives_429_with_retry_after() {
    let relay = start(&[("RATE_QUERY_BURST", "4"), ("RATE_QUERY_PER_MIN", "1")]);
    let mut c = relay.connect();
    for _ in 0..4 {
        page(&mut c, "");
    }
    let r = http_get(&mut c, "/sbtp/v1/query", "");
    assert_eq!(r.status, 429);
    assert_eq!(r.json()["error"], "RateLimited");
    // One token per minute: the next one is about 60 s away, rounded up; a second may have passed
    // since the last token was taken.
    let retry: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((59..=60).contains(&retry), "Retry-After {retry}");
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    let r = http_get(&mut c, "/sbtp/v1/query?limit=0", "");
    assert_eq!(r.status, 429, "the bucket runs before the parameter checks");
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
    let b = signed_block(b"bucket", &[]);
    assert_eq!(put_block(&mut c, &b).status, 201);
}

/// ADR 0024: a cursor survives a clean restart; after a start whose walk indexed an orphan (here
/// an older copy of `index.redb` restored, which loses the entries written since, as a crash
/// does), the epoch is new and every earlier cursor gets `400 InvalidCursor`. A walk without a
/// cursor returns every held block.
#[test]
fn cursors_across_restarts() {
    let data = tmp_dir("query-epoch");
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let backup = tmp_dir("query-epoch-backup");
    let first = {
        let relay = TestServer::start_in(&s, Router::new(), &data);
        store(&mut relay.connect(), "one", 1, &[])
    };
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::copy(data.join("index.redb"), backup.join("index.redb")).unwrap();
    let (c1, second, c2) = {
        let relay = TestServer::start_in(&s, Router::new(), &data);
        let mut c = relay.connect();
        let (ids, c1, _) = page(&mut c, "");
        assert_eq!(ids, first);
        let second = store(&mut c, "two", 1, &[]);
        let (ids, c2, _) = page(&mut c, &format!("?cursor={c1}"));
        assert_eq!(ids, second);
        (c1, second, c2)
    };
    {
        // Clean restart (rule 6): no orphan, same epoch, the cursor still walks.
        let relay = TestServer::start_in(&s, Router::new(), &data);
        let (ids, _, _) = page(&mut relay.connect(), &format!("?cursor={c1}"));
        assert_eq!(ids, second);
    }
    std::fs::copy(backup.join("index.redb"), data.join("index.redb")).unwrap();
    {
        let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
        let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
        let before = index.epoch();
        let rec = reconcile(&store, &index).unwrap();
        assert_eq!(
            (rec.orphans, rec.epoch_renewed),
            (1, true),
            "rules 1 and 11"
        );
        assert_ne!(index.epoch(), before);
        index.close().unwrap();
    }
    let relay = TestServer::start_in(&s, Router::new(), &data);
    let mut c = relay.connect();
    for cursor in [&c1, &c2] {
        let r = http_get(&mut c, &format!("/sbtp/v1/query?cursor={cursor}"), "");
        assert_eq!(refused(&r), (400, "InvalidCursor".to_owned()), "rule 7");
    }
    let (ids, _, _) = page(&mut c, "");
    assert_eq!(
        ids,
        [first, second].concat(),
        "rule 8: a new walk sees every block"
    );
}
