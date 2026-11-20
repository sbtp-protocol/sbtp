//! The age-based sweeper (ADR 0013 rules 12 to 16; ADR 0019 rule 6; ADR 0021 rules 7, 35 and 41;
//! ADR 0023 rule 6; ADR 0043 rules 3 and 4; `architecture.md` §2, "Eviction").
//!
//! One background task ([`run`]) wakes every `sweep_interval_ms` and runs [`sweep_once`] on one
//! blocking thread (ADR 0018 rule 19: "a single background task"); it never runs on an async
//! worker, so request handling is never blocked by it. One run:
//!
//! 1. purges the quarantine (ADR 0023 rule 6), also when `block_ttl_ms = 0`;
//! 2. with eviction by age enabled, lists at most `sweep_batch` expired positions, oldest first:
//!    one `expired` job of the index reader queue (ADR 0018 rules 12 and 13, clarification M2),
//!    with the bound of `/query` ([`expiry_floor`]: expired iff `received_at + block_ttl_ms ≤
//!    now`). With `block_ttl_ms = 0` no job is submitted and nothing is deleted (ADR 0019 rule 6);
//! 3. for each listed block, under the `PUT` lock of its `block_id`: the cache entry, then the
//!    block file (ADR 0013 rule 15), unless the block was accepted again since the listing;
//! 4. removes the index entries of the processed positions, in one write job on the index writer.
//!
//! **Re-acceptance (ADR 0043 rule 4).** A `PUT` of an expired block gets `201` and a new position,
//! keeping the file (`blocks::Relay`). The sweeper must then not delete the file or the cache entry,
//! and removes only the entries of the expired position. Both run under the same per-`block_id`
//! lock, which serialises them. Every new acceptance (`201`) increments a counter of its lock
//! stripe under that lock. The sweeper reads the 64 counters before it lists a batch; for a block
//! whose stripe counter has moved by the time it holds the lock, it looks the block up again
//! (one `contains` job) and skips the file when the block now has another position. A block whose
//! counter has not moved has not been accepted since the listing: the listing already reflects
//! every acceptance made before it, since the acceptance indexes the block before it releases the
//! lock. A re-acceptance after the file was deleted finds no file and stores a new one (`201`);
//! its index insert replaces the old entry, so the sweeper's removal of the old position is a
//! no-op on it (`index::remove_entries` keeps an `ids` entry that points elsewhere).
//!
//! **Failures.** A run stops at the first failed file deletion; the positions already processed
//! still have their index entries removed. A failed listing or deletion is `sweep_failed` (error,
//! throttled, with `errno`); a failed removal is `index_write_failed` with `op=remove` (ADR 0021
//! rule 7). Both count `sweep_failures_total`. A job refused by a full queue or an expired wait is
//! load, not a failure: the run ends and the next one retries (ADR 0018 rule 13). The sweeper's
//! index calls never count toward the fatal exit (ADR 0018 clarification M6). The entries left by
//! a failure are phantoms (ADR 0013 rule 8), removed by a later run.
//!
//! **Supervision (ADR 0018 rule 37).** [`run`] returns only when told to stop, or when a run
//! panicked; the caller treats any other end as fatal (`crate::run`).
//!
//! `GET /block` keeps serving an expired block until its file is deleted (ADR 0013 rule 15 MAY):
//! the `GET` path does not read the index, so it keeps working while the index does not.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sbtp_core::BlockId;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::blocks::{ID_STRIPES, Relay, stripe};
use crate::index::{IndexBackend, Position};
use crate::log::{self, Event, Level, Throttle, Value};
use crate::metrics::{self, IndexOp};
use crate::query::expiry_floor;
use crate::store;

/// One listed batch and the acceptance counters read before it.
pub(crate) struct Listing {
    generations: [u64; ID_STRIPES],
    batch: Vec<(Position, BlockId)>,
}

/// Why a run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The `expired` job failed (`sweep_failed`).
    List(Option<u64>),
    /// A file deletion failed (`sweep_failed`).
    Delete(Option<u64>),
    /// The removal of the index entries failed (`index_write_failed`, `op=remove`).
    Remove(Option<u64>),
}

impl Failure {
    fn log(self) {
        static RUN_LOG: Throttle = Throttle::new();
        static REMOVE_LOG: Throttle = Throttle::new();
        metrics::sweep_failed();
        let (event, throttle, errno, mut fields) = match self {
            Self::List(n) | Self::Delete(n) => (Event::SweepFailed, &RUN_LOG, n, Vec::new()),
            Self::Remove(n) => {
                metrics::index_write_error(IndexOp::Remove);
                (
                    Event::IndexWriteFailed,
                    &REMOVE_LOG,
                    n,
                    vec![("op", Value::Str(IndexOp::Remove.name()))],
                )
            }
        };
        if let Some(n) = errno {
            fields.push(("errno", Value::Int(n)));
        }
        log::throttled(throttle, event, &fields, None);
    }
}

/// One run of the sweeper, on a blocking thread. Returns the number of index entries removed, or
/// `None` if the run stopped on a failure (logged and counted here).
pub fn sweep_once<I: IndexBackend + 'static>(relay: &Relay<I>, batch: usize) -> Option<u64> {
    let start = Instant::now();
    let now = (relay.clock())();
    // ADR 0023 rule 6: at every run, also with eviction by age disabled.
    if let Err(e) = relay.store().purge_quarantine(now) {
        store::log_store_failed(e.op, &e.error);
    }
    let (removed, failure) = match list(relay, batch, now) {
        Ok(Some(listing)) => apply(relay, listing),
        Ok(None) => (0, None),
        Err(f) => (0, Some(f)),
    };
    let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    metrics::sweep_done(removed, ms);
    if log::global().enabled(Level::Debug) {
        log::emit(
            Event::Sweep,
            &[
                ("removed", Value::Int(removed)),
                ("duration_ms", Value::Int(ms)),
            ],
        );
    }
    match failure {
        Some(f) => {
            f.log();
            None
        }
        None => Some(removed),
    }
}

/// Step 2: the acceptance counters, then one batch of expired positions. `Ok(None)` when eviction
/// by age is disabled or the reader queue refused the job.
pub(crate) fn list<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    batch: usize,
    now: u64,
) -> Result<Option<Listing>, Failure> {
    // ADR 0019 rule 6: no `expired` job, nothing deleted.
    let Some(ttl) = relay.block_ttl_ms() else {
        return Ok(None);
    };
    // Before the listing (module documentation).
    let generations = relay.accepted_generations();
    let floor = expiry_floor(Some(ttl), now);
    match relay
        .index()
        .read_blocking(move |i| i.expired(floor, batch))
    {
        Ok(Ok(batch)) => Ok(Some(Listing { generations, batch })),
        Ok(Err(e)) => Err(Failure::List(I::io_error(&e).and_then(log::errno))),
        Err(_) => Ok(None),
    }
}

/// Steps 3 and 4 for `listing`. Returns the entries removed and the failure that stopped the run.
pub(crate) fn apply<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    listing: Listing,
) -> (u64, Option<Failure>) {
    let mut done = Vec::with_capacity(listing.batch.len());
    let mut failure = None;
    for (at, id) in listing.batch {
        let _lock = relay.lock_id(&id);
        let before = listing.generations.get(stripe(&id)).copied();
        if before != Some(relay.accepted_generation(&id)) {
            // A block of this stripe was accepted since the listing: is it this one?
            match relay.index().read_blocking(move |i| i.contains(&id)) {
                // ADR 0043 rule 4: re-accepted at a new position. Its file, cache entry and new
                // entries stay; only the expired position goes.
                Ok(Ok(Some(now))) if now != at => {
                    done.push(at);
                    continue;
                }
                Ok(Ok(_)) => {}
                // Unknown: left for the next run, untouched.
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        match relay.evict_locked(&id) {
            Ok(_) => done.push(at),
            Err(e) => {
                failure = Some(Failure::Delete(log::errno(&e)));
                break;
            }
        }
    }
    relay.store().publish_gauges();
    if done.is_empty() {
        return (0, failure);
    }
    match relay.index().write_blocking(move |i| i.remove(&done)) {
        Ok(Ok(n)) => (u64::try_from(n).unwrap_or(u64::MAX), failure),
        Ok(Err(e)) => (
            0,
            failure.or(Some(Failure::Remove(I::io_error(&e).and_then(log::errno)))),
        ),
        // The writer refuses only while the relay stops: the entries stay as phantoms.
        Err(_) => (0, failure),
    }
}

/// The sweeper task: a run every `interval` (the first one `interval` after the start, the
/// start-up walk having just purged the quarantine), until `stop` changes or its sender is
/// dropped. A run that is still going when `stop` changes is waited for. Returns early only if
/// a run panicked, which the caller treats as the end of a supervised thread (ADR 0018 rule 37).
pub async fn run<I: IndexBackend + 'static>(
    relay: Arc<Relay<I>>,
    interval: Duration,
    batch: usize,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let r = Arc::clone(&relay);
        if tokio::task::spawn_blocking(move || sweep_once(&r, batch))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::{Method, StatusCode};

    use crate::blocks::{get_block, put_block};
    use crate::config::Settings;
    use crate::index::RedbIndex;
    use crate::pool::IndexPool;
    use crate::store::Store;

    const TTL: u64 = 60_000;
    const T0: u64 = 10_000_000;

    struct Fixture {
        relay: Arc<Relay<RedbIndex>>,
        dir: std::path::PathBuf,
        _pool: IndexPool<RedbIndex>,
    }

    fn fixture(name: &str, clock: fn() -> u64, extra: &[(&str, &str)]) -> Fixture {
        let dir = std::env::temp_dir().join(format!("sbtp-sweep-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut env = vec![
            ("SBTP_RELAY_BLOCK_TTL_MS".to_owned(), TTL.to_string()),
            ("SBTP_RELAY_MIN_POW_DIFFICULTY".to_owned(), "0".to_owned()),
        ];
        env.extend(
            extra
                .iter()
                .map(|(k, v)| (format!("SBTP_RELAY_{k}"), (*v).to_owned())),
        );
        let env = env
            .into_iter()
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        let settings = Settings::load(Vec::<std::ffi::OsString>::new(), env).unwrap();
        let index_file = dir.join("index.redb");
        let index = Arc::new(RedbIndex::open(&index_file, 1 << 20).unwrap());
        let store = Store::open(&dir, index_file, settings.max_store_bytes).unwrap();
        store::reconcile(&store, &*index).unwrap();
        let pool = IndexPool::start(&index, &settings).unwrap();
        let relay = Arc::new(Relay::new(&settings, store, pool.handle()).with_clock(clock));
        Fixture {
            relay,
            dir,
            _pool: pool,
        }
    }

    fn block(n: u8) -> (Vec<u8>, BlockId) {
        with_payload(&[n; 40])
    }

    fn with_payload(payload: &[u8]) -> (Vec<u8>, BlockId) {
        let k = sbtp_core::SigningKey::from_bytes(&[3; 32]);
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .payload(payload)
            .build(&k, 0)
            .unwrap();
        let id = sbtp_core::parse(&bytes).unwrap().block_id();
        (bytes, id)
    }

    async fn put(f: &Fixture, bytes: &[u8]) -> StatusCode {
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/sbtp/v1/block")
            .body(Body::from(bytes.to_vec()))
            .unwrap();
        put_block(State(Arc::clone(&f.relay)), req).await.status()
    }

    async fn get(f: &Fixture, id: &BlockId) -> StatusCode {
        let uri = format!("/sbtp/v1/block/{id}").parse().unwrap();
        get_block(
            State(Arc::clone(&f.relay)),
            uri,
            axum::http::HeaderMap::new(),
        )
        .await
        .status()
    }

    fn position(f: &Fixture, id: &BlockId) -> Option<Position> {
        let id = *id;
        f.relay
            .index()
            .read_blocking(move |i| i.contains(&id))
            .unwrap()
            .unwrap()
    }

    fn file(f: &Fixture, id: &BlockId) -> std::path::PathBuf {
        f.relay.store().path(id)
    }

    async fn sweep(f: &Fixture) -> Option<u64> {
        let r = Arc::clone(&f.relay);
        tokio::task::spawn_blocking(move || sweep_once(&r, 1_000))
            .await
            .unwrap()
    }

    /// ADR 0013 rules 12 and 15: a block expires at `received_at + ttl` exactly, not one
    /// millisecond before; the sweeper deletes the cache entry, the file and the entries, oldest
    /// first, within the batch; the quota is released; a deleted block is `404`.
    #[tokio::test]
    async fn expired_blocks_are_deleted_at_the_exact_millisecond() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("exact", now, &[]);
        let (a, ida) = block(1);
        let (b, idb) = block(2);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        NOW.store(T0 + 10, Ordering::SeqCst);
        assert_eq!(put(&f, &b).await, StatusCode::CREATED);
        let empty = f.relay.store().used_bytes();
        // Cached by a `GET`.
        assert_eq!(get(&f, &ida).await, StatusCode::OK);

        NOW.store(T0 + TTL - 1, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(0), "one millisecond before expiry");
        assert!(file(&f, &ida).exists());

        NOW.store(T0 + TTL, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(1));
        assert!(!file(&f, &ida).exists());
        assert!(file(&f, &idb).exists(), "not expired yet");
        assert_eq!(position(&f, &ida), None);
        assert_eq!(
            get(&f, &ida).await,
            StatusCode::NOT_FOUND,
            "cache entry gone"
        );
        assert!(f.relay.store().used_bytes() < empty, "quota released");
        assert_eq!(sweep(&f).await, Some(0), "idempotent");

        NOW.store(T0 + 10 + TTL, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(1));
        assert!(!file(&f, &idb).exists());
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// `sweep_batch` bounds one run; the oldest go first.
    #[tokio::test]
    async fn batch_bounds_a_run_oldest_first() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("batch", now, &[]);
        let mut ids = Vec::new();
        for n in 0..5u8 {
            NOW.store(T0 + u64::from(n), Ordering::SeqCst);
            let (b, id) = block(10 + n);
            assert_eq!(put(&f, &b).await, StatusCode::CREATED);
            ids.push(id);
        }
        NOW.store(T0 + 2 * TTL, Ordering::SeqCst);
        let r = Arc::clone(&f.relay);
        let removed = tokio::task::spawn_blocking(move || sweep_once(&r, 2))
            .await
            .unwrap();
        assert_eq!(removed, Some(2));
        let left: Vec<bool> = ids.iter().map(|id| file(&f, id).exists()).collect();
        assert_eq!(left, [false, false, true, true, true]);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// ADR 0019 rule 6: with `block_ttl_ms = 0` nothing expires, whatever the clock.
    #[tokio::test]
    async fn disabled_eviction_deletes_nothing() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("off", now, &[("BLOCK_TTL_MS", "0")]);
        let (a, ida) = block(3);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        NOW.store(u64::MAX / 2, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(0));
        assert!(file(&f, &ida).exists());
        assert_eq!(put(&f, &a).await, StatusCode::OK, "never expired");
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// ADR 0043 rules 2 to 4: before expiry a `PUT` is `200` and changes nothing; after expiry it
    /// is `201` with a new position, the file kept; a sweep after it deletes nothing of it.
    #[tokio::test]
    async fn reaccepted_block_survives_the_next_sweep() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("reaccept", now, &[]);
        let (a, ida) = block(4);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        let first = position(&f, &ida).unwrap();
        NOW.store(T0 + TTL - 1, Ordering::SeqCst);
        assert_eq!(put(&f, &a).await, StatusCode::OK, "no renewal");
        assert_eq!(position(&f, &ida), Some(first));
        NOW.store(T0 + TTL, Ordering::SeqCst);
        let used = f.relay.store().used_bytes();
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        let second = position(&f, &ida).unwrap();
        assert_eq!(second.received_at, T0 + TTL);
        assert_eq!(f.relay.store().used_bytes(), used, "the file is kept");
        assert_eq!(sweep(&f).await, Some(0));
        assert!(file(&f, &ida).exists());
        assert_eq!(get(&f, &ida).await, StatusCode::OK);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// ADR 0043 rule 4, the race: the sweeper lists the expired position, the block is accepted
    /// again before the sweeper takes its lock. The sweeper must keep the file, the cache entry
    /// and the new entries, and remove only the expired position. Another block of the same
    /// stripe, listed in the same batch, is still deleted.
    #[tokio::test]
    async fn reacceptance_between_listing_and_deletion_wins() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("race", now, &[]);
        let (a, ida) = block(5);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        // Another expired block in the same lock stripe as `a`.
        let (b, idb) = (0..10_000u32)
            .map(|n| with_payload(&n.to_be_bytes()))
            .find(|(_, id)| stripe(id) == stripe(&ida))
            .unwrap();
        assert_eq!(put(&f, &b).await, StatusCode::CREATED);
        NOW.store(T0 + TTL, Ordering::SeqCst);
        let listing = list(&f.relay, 1_000, now()).unwrap().unwrap();
        assert_eq!(listing.batch.len(), 2);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED, "re-accepted");
        assert_eq!(get(&f, &ida).await, StatusCode::OK); // cached
        let new = position(&f, &ida).unwrap();
        let r = Arc::clone(&f.relay);
        let (removed, failure) = tokio::task::spawn_blocking(move || apply(&r, listing))
            .await
            .unwrap();
        assert_eq!(failure, None);
        assert_eq!(removed, 1, "the old position of `a` was already replaced");
        assert!(file(&f, &ida).exists(), "re-accepted file kept");
        assert_eq!(position(&f, &ida), Some(new));
        assert!(!file(&f, &idb).exists(), "the other block is still swept");
        assert_eq!(position(&f, &idb), None);
        // The file is gone from under the cache too: `a` is still served, `b` is not.
        std::fs::remove_file(file(&f, &ida)).unwrap();
        assert_eq!(
            get(&f, &ida).await,
            StatusCode::OK,
            "cache entry of `a` kept"
        );
        assert_eq!(get(&f, &idb).await, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// ADR 0043 rule 3: a full relay still re-accepts an expired block whose file it holds:
    /// nothing is written, so the quota is not checked.
    #[tokio::test]
    async fn full_relay_reaccepts_a_held_expired_block() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("full", now, &[("MAX_STORE_BYTES", "4194304")]);
        let k = sbtp_core::SigningKey::from_bytes(&[4; 32]);
        let big = |n: u32| {
            sbtp_core::BlockBuilder::for_key(&k)
                .timestamp(u64::from(n))
                .payload(&vec![7; 60_000])
                .build(&k, 0)
                .unwrap()
        };
        let first = big(0);
        let id = sbtp_core::parse(&first).unwrap().block_id();
        assert_eq!(put(&f, &first).await, StatusCode::CREATED);
        let mut full = false;
        for n in 1..200 {
            match put(&f, &big(n)).await {
                StatusCode::CREATED => {}
                StatusCode::INSUFFICIENT_STORAGE => {
                    full = true;
                    break;
                }
                other => panic!("{other}"),
            }
        }
        assert!(full, "the store filled up");
        NOW.store(T0 + TTL, Ordering::SeqCst);
        assert_eq!(put(&f, &first).await, StatusCode::CREATED);
        assert_eq!(position(&f, &id).unwrap().received_at, T0 + TTL);
        let _ = std::fs::remove_dir_all(&f.dir);
    }
}
