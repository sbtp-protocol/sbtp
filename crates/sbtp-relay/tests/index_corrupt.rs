//! A corrupt index row does not count toward the fatal exit of ADR 0018 rule 37 (security review
//! of relay milestone 1c-limits, L-1): any client that reaches the row could otherwise restart the
//! relay in a loop. Over real HTTP; were the failures counted, this test process would exit with
//! status 70.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;

use axum::Router;
use common::{TestServer, get as http_get, settings, tmp_dir};
use sbtp_core::BlockId;
use sbtp_relay::index::{FileState, IndexBackend, IndexError, Page, Position, RedbIndex};
use sbtp_relay::pool::FATAL_INDEX_FAILURES;

/// A redb index whose every `/query` page finds a corrupt row.
struct CorruptQueries(RedbIndex);

impl IndexBackend for CorruptQueries {
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
    fn query(&self, _: Option<&BlockId>, _: Position, _: usize) -> Result<Page, IndexError> {
        Err(IndexError::CorruptRow)
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
fn corrupt_row_failures_do_not_exit() {
    let s = settings(&[("RATE_QUERY_BURST", "1000")]);
    let data = tmp_dir("index-corrupt");
    std::fs::create_dir_all(&data).unwrap();
    let index =
        std::sync::Arc::new(CorruptQueries::open(&data.join("index.redb"), 1 << 20).unwrap());
    let relay = TestServer::start_with(&s, Router::new(), &data, index);
    let mut c = relay.connect();
    for _ in 0..2 * FATAL_INDEX_FAILURES {
        let r = http_get(&mut c, "/sbtp/v1/query", "");
        assert_eq!(r.status, 500);
        assert_eq!(r.json(), serde_json::json!({"error": "Internal"}));
    }
    // Still serving.
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
}
