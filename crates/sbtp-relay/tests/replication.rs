//! Pull replication (ADR 0048 rules 4 to 19), end to end: real relays started with
//! `sbtp_relay::run` on loopback, and scripted peers that record what the replica asks for.
//!
//! The tests of this file run one at a time ([`SERIAL`]): the replication counters are process
//! wide and every replica's first peer has position 0, so each test reads them as differences.
#![cfg(feature = "replication")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{connect, env, get, now_ms, put_block, tmp_dir};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};
use sbtp_relay::StartError;
use sbtp_relay::replication::metrics::{self, Failed, Skip};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A relay started by `sbtp_relay::run` on its own thread, stopped (cleanly) on drop.
struct Node {
    addr: SocketAddr,
    data: PathBuf,
    stop: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    thread: Option<JoinHandle<Result<(), StartError>>>,
}

impl Node {
    fn start(data: &Path, listen: &str, pairs: &[(&str, &str)]) -> Self {
        Self::try_start(data, listen, pairs).unwrap()
    }

    fn try_start(data: &Path, listen: &str, pairs: &[(&str, &str)]) -> Result<Self, StartError> {
        let data_dir = data.to_str().unwrap().to_owned();
        let mut e: Vec<(OsString, OsString)> = env(&[
            ("DATA_DIR", &data_dir),
            ("LISTEN", listen),
            ("RATE_BLOCK_BURST", "1000000"),
            ("RATE_PUT_BURST", "1000000"),
            ("RATE_QUERY_BURST", "1000000"),
            ("REPLICATION_POLL_MS", "1000"),
            ("LOG_LEVEL", "warn"),
        ]);
        for (k, v) in pairs {
            e.retain(|(n, _)| n.to_str() != Some(&format!("SBTP_RELAY_{k}")));
            e.extend(env(&[(k, v)]));
        }
        if !pairs.iter().any(|(k, _)| *k == "MIN_POW_DIFFICULTY") {
            e.extend(env(&[("MIN_POW_DIFFICULTY", "0")]));
        }
        let (stop, stopped) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sbtp_relay::run(
                sbtp_core::self_test,
                Vec::<OsString>::new(),
                e,
                move || Ok(stopped),
                move |a| {
                    let _ = addr_tx.send(a);
                },
            )
        });
        match addr_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(addr) => Ok(Self {
                addr,
                data: data.to_path_buf(),
                stop: Some(stop),
                thread: Some(thread),
            }),
            Err(_) => Err(thread.join().unwrap().unwrap_err()),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn holds(&self, id: &BlockId) -> bool {
        let mut s = connect(self.addr);
        get(&mut s, &format!("/sbtp/v1/block/{id}"), "").status == 200
    }

    fn put(&self, block: &[u8]) -> u16 {
        put_block(&mut connect(self.addr), block).status
    }

    /// Every `block_id` listed by `/query`.
    fn listed(&self) -> Vec<String> {
        let mut s = connect(self.addr);
        let r = get(&mut s, "/sbtp/v1/query?limit=1000", "").json();
        r["block_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    fn stop(mut self) -> Result<(), StartError> {
        self.halt()
    }

    fn halt(&mut self) -> Result<(), StartError> {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.thread.take().map_or(Ok(()), |t| t.join().unwrap())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.halt();
    }
}

/// A free loopback port (bound then released: a test-only race).
fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    f()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

/// A valid block mined at `difficulty`, timestamped `ts`.
fn block_at(payload: &[u8], difficulty: u32, ts: u64) -> (BlockId, Vec<u8>) {
    let k = key();
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(ts)
        .payload(payload)
        .build(&k, difficulty)
        .unwrap();
    let id = sbtp_core::parse(&bytes).unwrap().block_id();
    (id, bytes)
}

fn block(payload: &[u8], difficulty: u32) -> (BlockId, Vec<u8>) {
    block_at(payload, difficulty, now_ms())
}

/// A request received by a [`Peer`].
#[derive(Clone, Debug)]
struct Seen {
    target: String,
    replication: bool,
    at: Instant,
}

/// One scripted answer.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn page(ids: &[BlockId], cursor: &str, more: bool) -> Self {
        let ids: Vec<String> = ids.iter().map(|i| format!("\"{i}\"")).collect();
        Self::ok(
            format!(
                r#"{{"block_ids":[{}],"cursor":"{cursor}","more":{more}}}"#,
                ids.join(",")
            )
            .into_bytes(),
        )
    }
}

type Script = dyn Fn(&str) -> Answer + Send + Sync;

/// A scripted HTTP/1.1 peer on loopback that records every request.
struct Peer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Peer {
    fn start(script: impl Fn(&str) -> Answer + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Script> = Arc::new(script);
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let (log, script) = (Arc::clone(&log), Arc::clone(&script));
                std::thread::spawn(move || serve(s, &log, &*script));
            }
        });
        Self { addr, seen }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn count(&self, needle: &str) -> usize {
        self.seen()
            .iter()
            .filter(|s| s.target.contains(needle))
            .count()
    }

    fn queries(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.target.starts_with("/sbtp/v1/query"))
            .collect()
    }
}

fn serve(mut s: TcpStream, log: &Mutex<Vec<Seen>>, script: &Script) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let target = lines
            .next()
            .unwrap_or_default()
            .split(' ')
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let replication = lines.any(|l| l.eq_ignore_ascii_case("sbtp-replication: 1"));
        log.lock().unwrap().push(Seen {
            target: target.clone(),
            replication,
            at: Instant::now(),
        });
        let a = script(&target);
        let mut out = format!(
            "HTTP/1.1 {} X\r\nContent-Length: {}\r\n",
            a.status,
            a.body.len()
        );
        for (k, v) in &a.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        if s.write_all(out.as_bytes()).is_err() || s.write_all(&a.body).is_err() {
            return;
        }
    }
}

/// The value of query parameter `name` in `target`.
fn param<'a>(target: &'a str, name: &str) -> Option<&'a str> {
    target
        .split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
}

/// Rules 4, 6 and 17, "Consequences" (loops are harmless): A and B copy from each other, C copies
/// from B. A block sent to A reaches B and C, a block sent to B reaches A and C, each is stored
/// once per relay and listed once, and nothing is fetched again once everyone holds everything.
#[test]
fn relays_replicate_in_a_loop_and_a_chain() {
    let _g = serial();
    let (a_addr, b_addr) = (free_port(), free_port());
    let (a_url, b_url) = (format!("http://{a_addr}"), format!("http://{b_addr}"));
    let a = Node::start(&tmp_dir("repl-a"), &a_addr, &[("PEERS", &b_url)]);
    let b = Node::start(&tmp_dir("repl-b"), &b_addr, &[("PEERS", &a_url)]);
    let c = Node::start(&tmp_dir("repl-c"), "127.0.0.1:0", &[("PEERS", &b.url())]);
    let stored = metrics::stored_total(0);
    let (x, xb) = block(b"sent to a", 0);
    let (y, yb) = block(b"sent to b", 0);
    assert_eq!(a.put(&xb), 201);
    assert_eq!(b.put(&yb), 201);
    for n in [&a, &b, &c] {
        assert!(
            wait_until(Duration::from_secs(30), || n.holds(&x) && n.holds(&y)),
            "{}",
            n.addr
        );
    }
    // A stored y, B stored x, C stored both: four copies, all from peer position 0.
    assert!(wait_until(
        Duration::from_secs(5),
        || metrics::stored_total(0) - stored == 4
    ));
    // Several poll intervals later nothing more was stored, and each relay lists each block once.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(metrics::stored_total(0) - stored, 4);
    for n in [&a, &b, &c] {
        let listed = n.listed();
        assert_eq!(listed.len(), 2, "{listed:?}");
    }
}

/// Rule 8: the cursor and `since` of a peer are kept in the index and used after a restart.
#[test]
fn the_cursor_survives_a_restart() {
    let _g = serial();
    let peer = Peer::start(|_| Answer::page(&[], "c1", false));
    let data = tmp_dir("repl-restart");
    let pairs = [
        ("PEERS", peer.url()),
        ("REPLICATION_RESYNC_MARGIN_MS", "0".to_owned()),
    ];
    let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let b = Node::start(&data, "127.0.0.1:0", &pairs);
    assert!(wait_until(Duration::from_secs(10), || peer
        .queries()
        .iter()
        .any(|q| param(&q.target, "cursor") == Some("c1"))));
    b.stop().unwrap();
    let before = peer.queries();
    let first = &before[0].target;
    assert_eq!(param(first, "cursor"), None, "{first}");
    let since = param(first, "since").unwrap().to_owned();
    assert!(before.iter().all(|q| q.replication), "Sbtp-Replication: 1");
    let b = Node::start(&data, "127.0.0.1:0", &pairs);
    assert!(wait_until(Duration::from_secs(10), || peer.queries().len()
        > before.len()));
    let after = peer.queries()[before.len()].target.clone();
    assert_eq!(param(&after, "cursor"), Some("c1"), "{after}");
    assert_eq!(param(&after, "since"), Some(since.as_str()), "{after}");
    drop(b);
}

/// Rule 9: `InvalidCursor` (a new index epoch of the peer) drops the cursor; the walk starts
/// again from the last complete page minus the margin, and the re-listed block is not fetched
/// again (rule 6).
#[test]
fn an_epoch_change_restarts_from_the_last_page() {
    let _g = serial();
    let (id, bytes) = block(b"epoch", 0);
    let resets = metrics::cursor_resets_total(0);
    // The first page hands out cursor c1, which the peer then refuses (a new index epoch).
    let first = Mutex::new(true);
    let peer = Peer::start(move |t| {
        if t.contains("/sbtp/v1/block/") {
            return Answer::ok(bytes.clone());
        }
        if param(t, "cursor") == Some("c1") {
            let mut a = Answer::status(400);
            a.body = br#"{"error":"InvalidCursor"}"#.to_vec();
            return a;
        }
        let mut f = first.lock().unwrap();
        let cursor = if *f { "c1" } else { "c2" };
        *f = false;
        Answer::page(&[id], cursor, false)
    });
    let url = peer.url();
    let started = now_ms();
    let b = Node::start(
        &tmp_dir("repl-epoch"),
        "127.0.0.1:0",
        &[("PEERS", &url), ("REPLICATION_RESYNC_MARGIN_MS", "0")],
    );
    // Q1 (no cursor) lists the block, which is fetched; Q2 (cursor c1) is refused with
    // InvalidCursor; Q3 has no cursor and `since` at the last complete page.
    assert!(wait_until(Duration::from_secs(15), || peer.queries().len() >= 3));
    let q = peer.queries();
    assert_eq!(param(&q[0].target, "cursor"), None);
    assert_eq!(param(&q[1].target, "cursor"), Some("c1"));
    assert_eq!(param(&q[2].target, "cursor"), None, "{}", q[2].target);
    let s0: u64 = param(&q[0].target, "since").unwrap().parse().unwrap();
    let s2: u64 = param(&q[2].target, "since").unwrap().parse().unwrap();
    assert!(
        s0 >= started.saturating_sub(1_000) && s2 > s0,
        "{started} {s0} {s2}"
    );
    assert!(metrics::cursor_resets_total(0) > resets);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(b.holds(&id));
    assert_eq!(peer.count(&format!("/sbtp/v1/block/{id}")), 1);
}

/// Rule 11: a `429` with `Retry-After` is not repeated before it has elapsed.
#[test]
fn retry_after_is_obeyed() {
    let _g = serial();
    let peer = Peer::start(|_| {
        let mut a = Answer::status(429);
        a.headers.push(("Retry-After", "3".to_owned()));
        a
    });
    let failed = metrics::failed_total(0, Failed::RateLimited);
    let _b = Node::start(
        &tmp_dir("repl-429"),
        "127.0.0.1:0",
        &[("PEERS", &peer.url())],
    );
    assert!(wait_until(Duration::from_secs(15), || peer.queries().len() >= 2));
    let q = peer.queries();
    let gap = q[1].at.duration_since(q[0].at);
    assert!(gap >= Duration::from_millis(2_900), "{gap:?}");
    assert!(metrics::failed_total(0, Failed::RateLimited) > failed);
}

/// Rules 4 and 7, ADR 0029: a hostile peer serves a block under another `block_id` (R1), bytes
/// that are not a block, a block from the future (P1) and a body over the block ceiling. Only
/// the valid block is stored; a skipped block is not fetched again in the walk.
#[test]
fn a_hostile_peer_cannot_store_wrong_or_oversized_blocks() {
    let _g = serial();
    let (good, good_b) = block(b"good", 0);
    let (claimed, _) = block(b"claimed", 0);
    let (other, other_b) = block(b"served instead", 0);
    let (junk, _) = block(b"junk id", 0);
    let (future, future_b) = block_at(b"future", 0, now_ms() + 86_400_000);
    let (big, _) = block(b"big", 0);
    let ids = [good, claimed, junk, future, big];
    let peer = Peer::start(move |t| {
        let is = |id: &BlockId| t.ends_with(&id.to_string());
        if !t.contains("/sbtp/v1/block/") {
            Answer::page(&ids, "c1", false)
        } else if is(&good) {
            Answer::ok(good_b.clone())
        } else if is(&claimed) {
            Answer::ok(other_b.clone())
        } else if is(&junk) {
            Answer::ok(b"not a block".to_vec())
        } else if is(&future) {
            Answer::ok(future_b.clone())
        } else {
            Answer::ok(vec![0; 70_000])
        }
    });
    let (invalid, too_large, future_n) = (
        metrics::skipped_total(0, Skip::Invalid),
        metrics::failed_total(0, Failed::TooLarge),
        metrics::skipped_total(0, Skip::Future),
    );
    let b = Node::start(
        &tmp_dir("repl-hostile"),
        "127.0.0.1:0",
        &[("PEERS", &peer.url())],
    );
    assert!(wait_until(Duration::from_secs(15), || b.holds(&good)));
    assert!(wait_until(Duration::from_secs(10), || peer
        .count(&big.to_string())
        >= 2));
    for id in [claimed, other, junk, future, big] {
        assert!(!b.holds(&id), "{id}");
    }
    assert_eq!(peer.count(&claimed.to_string()), 1);
    assert_eq!(peer.count(&junk.to_string()), 1);
    assert_eq!(peer.count(&future.to_string()), 1);
    assert_eq!(peer.count(&good.to_string()), 1);
    assert!(metrics::skipped_total(0, Skip::Invalid) - invalid >= 2);
    assert!(metrics::skipped_total(0, Skip::Future) > future_n);
    assert!(metrics::failed_total(0, Failed::TooLarge) > too_large);
    assert_eq!(b.listed(), vec![good.to_string()]);
}

/// Rule 6: a `block_id` below `min_pow_difficulty` is skipped without being fetched.
#[test]
fn ids_without_enough_pow_are_not_fetched() {
    let _g = serial();
    let low = (0u32..)
        .map(|n| block(format!("low {n}").as_bytes(), 0))
        .find(|(id, _)| id.leading_zero_bits() < 8)
        .unwrap();
    let high = block(b"high", 8);
    let (low_id, high_id) = (low.0, high.0);
    let (low_b, high_b) = (low.1, high.1);
    let pow = metrics::skipped_total(0, Skip::Pow);
    let peer = Peer::start(move |t| {
        if t.ends_with(&low_id.to_string()) {
            Answer::ok(low_b.clone())
        } else if t.ends_with(&high_id.to_string()) {
            Answer::ok(high_b.clone())
        } else {
            Answer::page(&[low_id, high_id], "c1", false)
        }
    });
    let b = Node::start(
        &tmp_dir("repl-pow"),
        "127.0.0.1:0",
        &[("PEERS", &peer.url()), ("MIN_POW_DIFFICULTY", "8")],
    );
    assert!(wait_until(Duration::from_secs(15), || b.holds(&high_id)));
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(peer.count(&low_id.to_string()), 0);
    assert!(!b.holds(&low_id));
    assert!(metrics::skipped_total(0, Skip::Pow) > pow);
    assert!(peer.seen().iter().all(|s| s.replication));
}

/// Rule 13: above the high-water mark replication stores nothing, and asks for nothing.
#[test]
fn replication_stops_above_the_high_water_mark() {
    let _g = serial();
    let (id, bytes) = block(b"not copied", 0);
    let peer = Peer::start(move |t| {
        if t.contains("/sbtp/v1/block/") {
            Answer::ok(bytes.clone())
        } else {
            Answer::page(&[id], "c1", false)
        }
    });
    // First filled by clients above 50 % of 4 MiB, without peers; then restarted with the peer.
    let data = tmp_dir("repl-full");
    let store = [
        ("MAX_STORE_BYTES", "4194304"),
        ("DEMAND_HIGH_WATER_PCT", "50"),
        ("DEMAND_LOW_WATER_PCT", "10"),
    ];
    let filler = Node::start(&data, "127.0.0.1:0", &store);
    for n in 0..40u32 {
        let mut payload = vec![0u8; 60_000];
        payload[..4].copy_from_slice(&n.to_be_bytes());
        let _ = filler.put(&block(&payload, 0).1);
    }
    filler.stop().unwrap();
    let url = peer.url();
    let mut pairs = store.to_vec();
    pairs.push(("PEERS", &url));
    let b = Node::start(&data, "127.0.0.1:0", &pairs);
    assert!(wait_until(Duration::from_secs(5), metrics::paused));
    std::thread::sleep(Duration::from_secs(2));
    assert!(peer.seen().is_empty(), "{:?}", peer.seen());
    assert!(!b.holds(&id));
    drop(b);
}

/// Rule 14, ADR 0030: a peer name that resolves to a loopback address is refused unless
/// `replication_allow_private`; a redirect is a failed request and is never followed.
#[test]
fn private_addresses_and_redirects_are_refused() {
    let _g = serial();
    let target = Peer::start(|_| Answer::page(&[], "c1", false));
    let port = target.addr.port();
    let refused = metrics::failed_total(0, Failed::Address);
    let named = format!("http://localhost:{port}");
    let b = Node::start(&tmp_dir("repl-ssrf"), "127.0.0.1:0", &[("PEERS", &named)]);
    assert!(wait_until(
        Duration::from_secs(10),
        || metrics::failed_total(0, Failed::Address) > refused
    ));
    std::thread::sleep(Duration::from_millis(500));
    assert!(target.seen().is_empty());
    drop(b);
    let b = Node::start(
        &tmp_dir("repl-ssrf-allowed"),
        "127.0.0.1:0",
        &[("PEERS", &named), ("REPLICATION_ALLOW_PRIVATE", "true")],
    );
    assert!(wait_until(Duration::from_secs(10), || !target
        .queries()
        .is_empty()));
    drop(b);

    let elsewhere = Peer::start(|_| Answer::page(&[], "c1", false));
    let location = format!("{}/sbtp/v1/query", elsewhere.url());
    let redirecting = Peer::start(move |_| {
        let mut a = Answer::status(301);
        a.headers.push(("Location", location.clone()));
        a
    });
    let redirects = metrics::failed_total(0, Failed::Redirect);
    let b = Node::start(
        &tmp_dir("repl-redirect"),
        "127.0.0.1:0",
        &[("PEERS", &redirecting.url())],
    );
    assert!(wait_until(
        Duration::from_secs(10),
        || metrics::failed_total(0, Failed::Redirect) > redirects
    ));
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(elsewhere.seen().is_empty());
    drop(b);
}

/// Rule 15: replication settings; rule 19: a `peer_ca_file` with no certificate stops the
/// start-up when a peer is `https`.
#[test]
fn replication_settings_are_checked_at_start_up() {
    let _g = serial();
    let bad = |pairs: &[(&str, &str)]| {
        Node::try_start(&tmp_dir("repl-bad"), "127.0.0.1:0", pairs).is_err()
    };
    assert!(bad(&[("PEERS", "http://relay.example")]));
    assert!(bad(&[("PEERS", "https://user@relay.example")]));
    assert!(bad(&[(
        "PEERS",
        "https://a.example,https://b.example,https://c.example,https://d.example,https://e.example"
    )]));
    assert!(bad(&[("PEERS", "https://a.example,https://A.example/")]));
    assert!(bad(&[
        ("PEERS", "https://a.example"),
        ("MIN_POW_DIFFICULTY", "17")
    ]));
    let dir = tmp_dir("repl-ca");
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("empty.pem");
    std::fs::write(&ca, b"").unwrap();
    assert!(bad(&[
        ("PEERS", "https://a.example"),
        ("PEER_CA_FILE", ca.to_str().unwrap())
    ]));
}
