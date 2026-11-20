//! End-to-end tests: the shipped `sbtp-relay` binary, started as a separate process with its
//! default settings (profile `small`, difficulty 16) on an ephemeral loopback port, driven over
//! real HTTP/1.1. Blocks are mined at the relay's own difficulty and signed with test keys from
//! public seeds.
//!
//! The per-feature tests (`blocks.rs`, `query.rs`, `http.rs`, ...) run the library in-process;
//! these check that the binary, its environment settings, its start-up order and its signal
//! handling put the same pieces together.
#![cfg(unix)]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{Response, connect, exchange, get as http_get, now_ms, put_block, tmp_dir};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};

/// The relay's default `min_pow_difficulty` (ADR 0019 point 1). The tests rely on the default and
/// read it back from `/info`.
const DIFFICULTY: u32 = 16;

/// A payload marker that must never appear in the relay's log (no block contents in logs).
const MARKER: &str = "e2e-payload-marker";

/// The relay binary as a child process. Stopped with `SIGTERM` on drop if still running.
struct RelayProcess {
    child: Option<Child>,
    addr: SocketAddr,
    data: PathBuf,
    log: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
}

impl RelayProcess {
    /// Starts the binary on `data` with only the listen address and the data directory set: every
    /// other setting is the built-in default. Waits for its `listening` line.
    fn start(data: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sbtp-relay"))
            .env_clear()
            .env("SBTP_RELAY_LISTEN", "127.0.0.1:0")
            .env("SBTP_RELAY_DATA_DIR", data)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the relay binary starts");
        let stderr = BufReader::new(child.stderr.take().unwrap());
        let log = Arc::new(Mutex::new(String::new()));
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let sink = Arc::clone(&log);
        // Drains the log for the whole run, so that the pipe never fills.
        let reader = std::thread::spawn(move || {
            for line in stderr.lines().map_while(Result::ok) {
                if line.contains("event=listening")
                    && let Some(a) = line.split("addr=").nth(1)
                    && let Ok(a) = a.trim().parse()
                {
                    let _ = addr_tx.send(a);
                }
                let mut l = sink.lock().unwrap();
                l.push_str(&line);
                l.push('\n');
            }
        });
        let Ok(addr) = addr_rx.recv_timeout(Duration::from_secs(30)) else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            panic!("no listening line:\n{}", log.lock().unwrap());
        };
        Self {
            child: Some(child),
            addr,
            data: data.to_path_buf(),
            log,
            reader: Some(reader),
        }
    }

    fn connect(&self) -> TcpStream {
        connect(self.addr)
    }

    /// Sends `SIGTERM` and waits for the exit; returns the status and the whole log.
    fn stop(mut self) -> (ExitStatus, String) {
        let status = self.terminate();
        (status, self.log.lock().unwrap().clone())
    }

    fn terminate(&mut self) -> ExitStatus {
        let mut child = self.child.take().expect("still running");
        let sent = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let status = child.wait().unwrap();
        if let Some(r) = self.reader.take() {
            r.join().unwrap();
        }
        status
    }
}

impl Drop for RelayProcess {
    /// Best effort and never panics, so that a test already unwinding cannot abort the binary:
    /// SIGTERM, then SIGKILL if the relay has not exited after 10 s (a hung drain fails the run
    /// instead of hanging it). The strict checks live in `stop()`.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
            if let Some(r) = self.reader.take() {
                let _ = r.join();
            }
        }
    }
}

/// Lowercase hexadecimal of a `block_id`.
fn hex(id: &BlockId) -> String {
    use std::fmt::Write;
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A block of the test key with public seed `[seed; 32]`, timestamped now, mined at `d`.
fn mined(seed: u8, payload: &[u8], parents: &[BlockId], d: u32) -> (Vec<u8>, BlockId) {
    let k = SigningKey::from_bytes(&[seed; 32]);
    let b = BlockBuilder::for_key(&k)
        .timestamp(now_ms())
        .parents(parents)
        .payload(payload)
        .build(&k, d)
        .unwrap();
    let id = sbtp_core::parse(&b).unwrap().block_id();
    (b, id)
}

fn error(r: &Response) -> String {
    r.json()["error"].as_str().unwrap().to_owned()
}

/// `(block_ids, cursor, more)` of a `/query` page.
fn page(c: &mut TcpStream, query: &str) -> (Vec<String>, String, bool) {
    let r = http_get(c, &format!("/sbtp/v1/query?{query}"), "");
    assert_eq!(
        r.status,
        200,
        "{query}: {}",
        String::from_utf8_lossy(&r.body)
    );
    let v = r.json();
    let ids = v["block_ids"].as_array().unwrap();
    let ids = ids.iter().map(|i| i.as_str().unwrap().to_owned()).collect();
    (
        ids,
        v["cursor"].as_str().unwrap().to_owned(),
        v["more"].as_bool().unwrap(),
    )
}

/// `/info` with the defaults, a block mined at the advertised difficulty stored then served
/// byte for byte, a duplicate `PUT`, an unknown block, and a `/query` walk over the children of
/// the root, one page at a time.
#[test]
fn publish_fetch_and_walk_through_the_binary() {
    let relay = RelayProcess::start(&tmp_dir("e2e-walk"));
    let mut c = relay.connect();

    let info = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!(info.status, 200);
    let info = info.json();
    assert_eq!(info["min_pow_difficulty"], DIFFICULTY);
    assert_eq!(info["max_future_ms"], 300_000);
    assert_eq!(info["max_query_limit"], 1000);
    let d = u32::try_from(info["min_pow_difficulty"].as_u64().unwrap()).unwrap();

    let (root, root_id) = mined(0x11, format!("root {MARKER}").as_bytes(), &[], d);
    let r = put_block(&mut c, &root);
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let path = format!("/sbtp/v1/block/{}", hex(&root_id));
    assert_eq!(r.header("location"), Some(path.as_str()));
    // ADR 0008: a duplicate is a success, `200`, never `409`.
    assert_eq!(put_block(&mut c, &root).status, 200);

    let r = http_get(&mut c, &path, "");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.body, root);
    // The recipient checks the identity and the signature (spec §3.4).
    sbtp_core::validate_requested(&r.body, 0, &root_id).unwrap();

    let (_, unknown) = mined(0x12, b"never sent", &[], 0);
    let r = http_get(&mut c, &format!("/sbtp/v1/block/{}", hex(&unknown)), "");
    assert_eq!((r.status, error(&r).as_str()), (404, "NotFound"));

    // Three children of the root, from two keys; read back one page at a time.
    let mut children = Vec::new();
    for (i, seed) in [0x21u8, 0x22, 0x21].into_iter().enumerate() {
        let (b, id) = mined(seed, format!("child {i}").as_bytes(), &[root_id], d);
        assert_eq!(put_block(&mut c, &b).status, 201);
        children.push(hex(&id));
    }
    let parent = format!("parent={}", hex(&root_id));
    let mut walked = Vec::new();
    let mut query = format!("{parent}&limit=1");
    loop {
        let (ids, cursor, more) = page(&mut c, &query);
        assert!(ids.len() <= 1);
        walked.extend(ids);
        if !more {
            break;
        }
        query = format!("{parent}&limit=1&cursor={cursor}");
    }
    // Acceptance order (spec §4, `/query`).
    assert_eq!(walked, children);
    // Every block, without a parent filter: the root first.
    let (all, _, more) = page(&mut c, "limit=10");
    assert!(!more);
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], hex(&root_id));

    let (status, log) = relay.stop();
    assert!(status.success(), "{status}\n{log}");
    assert!(log.contains("event=shutdown phase=index_closed"), "{log}");
    assert!(!log.contains(MARKER), "a payload reached the log:\n{log}");
}

/// Rejections at each pipeline step reachable from the network, none of which stores anything:
/// insufficient PoW, a bad signature, an oversized body, a block from the far future, and a
/// malformed body.
#[test]
fn rejected_blocks_are_not_stored() {
    let relay = RelayProcess::start(&tmp_dir("e2e-reject"));
    let mut c = relay.connect();

    // C1: below 16 leading zero bits.
    let weak = (0u8..=u8::MAX)
        .map(|n| mined(0x31, &[n], &[], 0))
        .find(|(_, id)| id.leading_zero_bits() < DIFFICULTY)
        .unwrap();
    let r = put_block(&mut c, &weak.0);
    assert_eq!((r.status, error(&r).as_str()), (400, "InsufficientPow"));

    // C3: the last signature byte flipped. The `block_id` does not cover the signature, so the
    // PoW still holds and the signature check is reached.
    let (mut forged, forged_id) = mined(0x32, b"forged", &[], DIFFICULTY);
    *forged.last_mut().unwrap() ^= 1;
    let r = put_block(&mut c, &forged);
    assert_eq!((r.status, error(&r).as_str()), (422, "InvalidSignature"));

    // P1: a timestamp beyond `max_future_ms` (ADR 0007).
    let k = SigningKey::from_bytes(&[0x33; 32]);
    let future = BlockBuilder::for_key(&k)
        .timestamp(now_ms() + 3_600_000)
        .payload(b"too early")
        .build(&k, DIFFICULTY)
        .unwrap();
    let future_id = sbtp_core::parse(&future).unwrap().block_id();
    let r = put_block(&mut c, &future);
    assert_eq!(
        (r.status, error(&r).as_str()),
        (400, "TimestampTooFarInFuture")
    );

    // Body limit: refused on `Content-Length` before any byte of the body is read.
    let r = exchange(
        &mut relay.connect(),
        &format!(
            "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            sbtp_core::layout::MAX_BLOCK_LEN + 1
        ),
    );
    assert_eq!((r.status, error(&r).as_str()), (413, "BodyTooLarge"));

    // F-checks: not a block at all.
    let r = put_block(&mut c, &[0u8; 200]);
    assert_eq!(r.status, 400);

    for id in [weak.1, forged_id, future_id] {
        let r = http_get(&mut c, &format!("/sbtp/v1/block/{}", hex(&id)), "");
        assert_eq!(r.status, 404);
    }
    let (ids, _, more) = page(&mut c, "limit=10");
    assert_eq!((ids.len(), more), (0, false));
    let stored = std::fs::read_dir(relay.data.join("blocks"))
        .unwrap()
        .map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap().count())
        .sum::<usize>();
    assert_eq!(stored, 0, "a rejected block reached the store");
}

/// A clean `SIGTERM` stop, then a second process on the same data directory: the block and the
/// cursor of the first run are still valid (spec §4, `/query`: a cursor survives a clean
/// restart).
#[test]
fn blocks_and_cursors_survive_a_clean_restart() {
    let data = tmp_dir("e2e-restart");
    let first = RelayProcess::start(&data);
    let mut c = first.connect();
    let (a, a_id) = mined(0x41, b"before restart", &[], DIFFICULTY);
    assert_eq!(put_block(&mut c, &a).status, 201);
    let (ids, cursor, _) = page(&mut c, "");
    assert_eq!(ids, [hex(&a_id)]);
    drop(c);
    let (status, log) = first.stop();
    assert!(status.success(), "{status}\n{log}");

    let second = RelayProcess::start(&data);
    let mut c = second.connect();
    let r = http_get(&mut c, &format!("/sbtp/v1/block/{}", hex(&a_id)), "");
    assert_eq!((r.status, r.body.as_slice()), (200, a.as_slice()));
    let (b, b_id) = mined(0x41, b"after restart", &[a_id], DIFFICULTY);
    assert_eq!(put_block(&mut c, &b).status, 201);
    let (ids, _, more) = page(&mut c, &format!("cursor={cursor}"));
    assert_eq!((ids, more), (vec![hex(&b_id)], false));
    let (status, log) = second.stop();
    assert!(status.success(), "{status}\n{log}");
}
