//! An index read failure on `/query` (ADR 0012 clarification K2; ADR 0021 clarifications X1, X3
//! and X4), over real HTTP with a failing index backend and the process logger on a captured
//! sink. One test: the logger is global to this process.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use common::{TestServer, get as http_get, put_block, settings, signed_block, tmp_dir};
use sbtp_core::BlockId;
use sbtp_relay::index::{FileState, IndexBackend, IndexError, Page, Position, RedbIndex};
use sbtp_relay::log::{self, LogConfig};
use sbtp_relay::metrics::{self, IndexReadOp};

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How `/query` pages fail: 0 they do not, 1 an I/O error (`EIO`), 2 a corrupt row.
static FAIL: AtomicU8 = AtomicU8::new(0);
const EIO: i32 = 5;

/// A redb index whose `query` fails as [`FAIL`] says; every other operation is redb's.
struct FailingQueries(RedbIndex);

impl IndexBackend for FailingQueries {
    type Error = IndexError;

    fn io_error(e: &IndexError) -> Option<&std::io::Error> {
        e.io_error()
    }
    fn restart_may_cure(e: &IndexError) -> bool {
        RedbIndex::restart_may_cure(e)
    }
    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self(RedbIndex::open(path, cache_bytes)?))
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
    fn query(&self, p: Option<&BlockId>, from: Position, n: usize) -> Result<Page, IndexError> {
        match FAIL.load(Ordering::SeqCst) {
            1 => Err(IndexError::Db(redb::Error::Io(
                std::io::Error::from_raw_os_error(EIO),
            ))),
            2 => Err(IndexError::CorruptRow),
            _ => self.0.query(p, from, n),
        }
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

#[test]
fn query_read_failure_is_500_and_logged() {
    let sink = Capture(Arc::new(Mutex::new(Vec::new())));
    assert!(
        log::install(Box::new(sink.clone())),
        "first use of the logger"
    );
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    log::global().configure(&LogConfig::from_settings(&s));
    let data = tmp_dir("index-read-failed");
    std::fs::create_dir_all(&data).unwrap();
    let index = Arc::new(FailingQueries::open(&data.join("index.redb"), 1 << 20).unwrap());
    let relay = TestServer::start_with(&s, Router::new(), &data, index);
    let mut c = relay.connect();
    for tag in [&b"one"[..], b"two"] {
        assert_eq!(put_block(&mut c, &signed_block(tag, &[])).status, 201);
    }
    let first = http_get(&mut c, "/sbtp/v1/query?limit=1", "");
    assert_eq!(first.status, 200);
    let cursor = first.json()["cursor"].as_str().unwrap().to_owned();
    let with_cursor = format!("/sbtp/v1/query?limit=1&cursor={cursor}");

    let before = metrics::index_read_errors_total(IndexReadOp::Query);
    for (n, mode) in [(1, 1), (2, 2), (3, 1)] {
        FAIL.store(mode, Ordering::SeqCst);
        let r = http_get(&mut c, &with_cursor, "");
        // K2 and X4: `500 Internal`, not cached, no detail, no `Retry-After`.
        assert_eq!(r.status, 500, "mode {mode}");
        assert_eq!(r.json(), serde_json::json!({"error": "Internal"}));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.header("retry-after"), None);
        // X3: every occurrence is counted, logged or suppressed.
        assert_eq!(
            metrics::index_read_errors_total(IndexReadOp::Query),
            before + n
        );
    }
    // K2 and X4: no state changed; the cursor is still recognised.
    FAIL.store(0, Ordering::SeqCst);
    let again = http_get(&mut c, &with_cursor, "");
    assert_eq!(
        again.status,
        200,
        "{}",
        String::from_utf8_lossy(&again.body)
    );
    assert_eq!(again.json()["block_ids"].as_array().unwrap().len(), 1);
    drop(c);
    drop(relay);

    log::flush();
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(" event=index_read_failed "))
        .collect();
    // X1: level `error`, `op=query`, the `errno` under the failure, throttled per `op` (rule 8):
    // one line for three failures. No cursor (rule 10), no message text.
    assert_eq!(lines.len(), 1, "{out}");
    assert!(
        lines[0].ends_with(&format!(
            " level=error event=index_read_failed op=query errno={EIO} suppressed=0"
        )),
        "{out}"
    );
    assert!(!out.contains(&cursor), "{out}");
}
