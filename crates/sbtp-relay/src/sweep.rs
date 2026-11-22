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
//! every acceptance counted before it, since an acceptance increments the counter only after its
//! index insert has returned (security review 2026-11-20 M-1). An acceptance whose insert had not
//! committed when the listing ran increments the counter after the sweeper read it, so the
//! sweeper looks the block up again. A re-acceptance after the file was deleted finds no file and stores a new one (`201`);
//! its index insert replaces the old entry, so the sweeper's removal of the old position is a
//! no-op on it (`index::remove_entries` keeps an `ids` entry that points elsewhere).
//!
//! **Failures.** A failed file deletion skips that position for the rest of the run, which goes on
//! with the next ones (security review 2026-11-20 L-1: a deletion that keeps failing on the oldest
//! entry must not stop all eviction); its index entries stay. The positions processed still have
//! their index entries removed. A failed listing or deletion is `sweep_failed` (error, throttled,
//! with `errno` of the first failed deletion of the run), counted once per run; a failed removal is `index_write_failed` with `op=remove` (ADR 0021
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
//!
//! **Demand (ADR 0046).** The same task flushes the demand set ([`flush_demand`]) when it is
//! half full or an epoch ended (a request of [`crate::demand::Demand`]), at the start of every
//! run (rule 12), and once more at a clean shutdown (`crate::run`). After the age pass, a run
//! evicts by demand ([`demand_pass`], rules 5 to 8): when the admission total of the store is
//! above `demand_high_water_pct` of `max_store_bytes`, and until it is at or below
//! `demand_low_water_pct`, at most `sweep_batch` blocks per run, least recently demanded first,
//! only blocks whose `last_demand + 3 × E ≤ now`, never while rule 13 suspends it. Each candidate
//! is checked again under the `PUT` lock of its `block_id` (rule 22): not in the demand set, and
//! the index still holds it at the listed position with a `last_demand` within the bound, so a
//! `PUT` answered `200` (rule 14, recorded under the same lock) or a re-acceptance between the
//! listing and the deletion keeps the block. All flushes run on this task, so no flush is in
//! progress while a demand pass checks the set.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sbtp_core::BlockId;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::blocks::{ID_STRIPES, Relay, stripe};
use crate::demand::FLUSH_CHUNK;
use crate::index::{Candidate, IndexBackend, Position};
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
    /// A file deletion failed (`sweep_failed`); the first of the run.
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
    // ADR 0046 rule 12: at every run.
    flush_demand(relay);
    // ADR 0023 rule 6: at every run, also with eviction by age disabled.
    if let Err(e) = relay.store().purge_quarantine(now) {
        store::log_store_failed(e.op, &e.error);
    }
    let (aged, failure) = match list(relay, batch, now) {
        Ok(Some(listing)) => apply(relay, listing),
        Ok(None) => (0, None),
        Err(f) => (0, Some(f)),
    };
    let (demanded, demand_failure) = demand_pass(relay, batch, now);
    let removed = aged.saturating_add(demanded);
    let failure = failure.or(demand_failure);
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

/// Steps 3 and 4 for `listing`. Returns the entries removed and the first failure of the run.
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
            // Skipped for the rest of the run, entries kept: the next positions still go.
            Err(e) => {
                failure = failure.or(Some(Failure::Delete(log::errno(&e))));
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

/// What [`flush_demand`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Index entries moved forward (at most one per block per epoch).
    pub updates: u64,
    /// Demands lost: chunks the writer refused or failed to write.
    pub lost: u64,
}

/// ADR 0046 rule 12: moves the demand set into the index, [`FLUSH_CHUNK`] identifiers per write
/// job of the index writer, every identifier recorded at the epoch of the latest touch. A chunk
/// that the writer refuses or fails to write is lost (rule 13: counted, eviction suspended).
/// Runs on the sweeper task only, and once at shutdown after it has stopped.
pub fn flush_demand<I: IndexBackend + 'static>(relay: &Relay<I>) -> Flushed {
    let demand = relay.demand();
    let mut out = Flushed::default();
    if !demand.enabled() || demand.is_empty() {
        return out;
    }
    demand.begin_flush();
    let mut buf = Vec::with_capacity(FLUSH_CHUNK);
    while let Some(epoch) = demand.drain_chunk(&mut buf) {
        if buf.is_empty() {
            continue;
        }
        let chunk = std::mem::take(&mut buf);
        let n = chunk.len() as u64;
        let written = relay.index().write_blocking(move |i| {
            let r = i.record_demand(&chunk, epoch);
            (chunk, r)
        });
        match written {
            Ok((chunk, Ok(u))) => {
                out.updates = out.updates.saturating_add(u);
                buf = chunk;
            }
            Ok((chunk, Err(e))) => {
                crate::demand::write_failed(I::io_error(&e).and_then(log::errno));
                demand.lost(n, (relay.clock())());
                out.lost = out.lost.saturating_add(n);
                buf = chunk;
            }
            // The writer refuses only while the relay stops.
            Err(_) => {
                demand.lost(n, (relay.clock())());
                out.lost = out.lost.saturating_add(n);
                buf = Vec::with_capacity(FLUSH_CHUNK);
            }
        }
    }
    metrics::demand_flush(out.updates);
    out
}

/// One listed batch of demand candidates and the bound they were listed with.
pub(crate) struct DemandListing {
    bound: u64,
    candidates: Vec<Candidate>,
    /// Order entries skipped by the listing for a missing row (security review 2026-11-21, I-3).
    orphans: u64,
}

/// ADR 0046 rules 5, 7 and 13: whether a demand pass runs at `now` (not suspended, above the
/// high-water mark or still draining toward the low-water mark), then at most `batch` candidates
/// with `last_demand + 3 × E ≤ now`, least recently demanded first. `Ok(None)` when no pass runs
/// or the reader queue refused the job.
pub(crate) fn demand_list<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    batch: usize,
    now: u64,
) -> Result<Option<DemandListing>, Failure> {
    let demand = relay.demand();
    if !demand.enabled() {
        return Ok(None);
    }
    if let Ok(Ok(coldest)) = relay.index().read_blocking(I::coldest_demand) {
        metrics::set_demand_coldest_ms(coldest.unwrap_or(0));
    }
    // Rule 13: only demand eviction stops; age eviction, `PUT` and reads are unchanged.
    if demand.suspended(now) {
        return Ok(None);
    }
    let (high, low) = relay.watermarks();
    let total = relay.store().admission_total();
    if total > high {
        demand.set_draining(true);
    }
    if total <= low {
        demand.set_draining(false);
    }
    if !demand.draining() {
        return Ok(None);
    }
    // Rule 7. Before `3 × E` after the Unix epoch nothing can be a candidate.
    let Some(bound) = now.checked_sub(demand.epoch_ms().saturating_mul(3)) else {
        return Ok(Some(DemandListing {
            bound: 0,
            candidates: Vec::new(),
            orphans: 0,
        }));
    };
    match relay
        .index()
        .read_blocking(move |i| i.demand_candidates(bound, batch))
    {
        Ok(Ok(c)) => Ok(Some(DemandListing {
            bound,
            candidates: c.list,
            orphans: c.orphans,
        })),
        Ok(Err(e)) => Err(Failure::List(I::io_error(&e).and_then(log::errno))),
        // Load: the next run retries.
        Err(_) => Ok(None),
    }
}

/// ADR 0046 rules 8 and 22: deletes the listed candidates, least recently demanded first, until
/// the admission total is at or below the low-water mark. Each one is checked again under the
/// lock of its `block_id`: eviction not suspended since the listing (security review 2026-11-21,
/// L-2), not in the demand set, still indexed at the listed position, with a `last_demand` within
/// the bound. Then removes their index entries in one write job. Returns the entries removed and
/// the first failure.
///
/// When the index file and its reserve alone reach the low-water mark, deleting blocks can never
/// bring the total down to it: the pass deletes nothing and is stuck (`demand_stuck`,
/// `cause=index`, ADR 0046 clarification D6), rather than deleting every candidate.
pub(crate) fn demand_apply<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    listing: DemandListing,
) -> (u64, Option<Failure>) {
    let start = Instant::now();
    let (demand, store) = (relay.demand(), relay.store());
    let (_, low) = relay.watermarks();
    let clock = relay.clock();
    let DemandListing {
        bound,
        candidates,
        orphans,
    } = listing;
    let reserve_stuck = store.index_reserve_bytes() >= low;
    let todo = if reserve_stuck {
        &[][..]
    } else {
        &candidates[..]
    };
    let (mut done, mut bytes, mut failure) = (Vec::with_capacity(todo.len()), 0u64, None);
    for c in todo {
        if store.admission_total() <= low {
            break;
        }
        let id = c.id;
        let _lock = relay.lock_id(&id);
        // L-2: a demand lost since the listing (a `PUT` answered `200` whose demand write failed,
        // a full set) suspends eviction at once, for this candidate and the rest of the pass.
        if demand.suspended_at(clock()) {
            break;
        }
        // Rule 22: still a candidate at deletion time, the in-memory set included.
        if demand.contains(&id) {
            continue;
        }
        match relay.index().read_blocking(move |i| i.demand_state(&id)) {
            Ok(Ok(Some((at, last)))) if at == c.position && last <= bound => {}
            // Re-accepted, demanded since the listing, gone, or unknown: kept for this run.
            _ => continue,
        }
        match relay.evict_locked(&id) {
            Ok(freed) => {
                done.push(c.position);
                bytes = bytes.saturating_add(u64::from(c.len));
                // D6: a deletion that did not lower the stored total ends the run. A row whose
                // file was already gone deleted nothing: its entries go, the run goes on. Judged
                // on the quota bytes the deletion released, not on a total read before and after
                // it, which concurrent `PUT`s and index growth move (security review 2026-11-21
                // pre-push, L-1).
                if freed == Some(0) {
                    break;
                }
            }
            // Skipped for the rest of the run, entries kept.
            Err(e) => failure = failure.or(Some(Failure::Delete(log::errno(&e)))),
        }
    }
    store.publish_gauges();
    let blocks = done.len() as u64;
    let removed = if done.is_empty() {
        0
    } else {
        match relay.index().write_blocking(move |i| i.remove(&done)) {
            Ok(Ok(n)) => u64::try_from(n).unwrap_or(u64::MAX),
            Ok(Err(e)) => {
                failure = failure.or(Some(Failure::Remove(I::io_error(&e).and_then(log::errno))));
                0
            }
            // The writer refuses only while the relay stops: the entries stay as phantoms.
            Err(_) => 0,
        }
    };
    if store.admission_total() <= low {
        demand.set_draining(false);
    }
    metrics::demand_run(blocks, bytes);
    let orphans_field = ("orphans", Value::Int(orphans));
    if blocks > 0 {
        demand.set_stuck(false);
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut fields = vec![
            ("blocks", Value::Int(blocks)),
            ("bytes", Value::Int(bytes)),
            ("duration_ms", Value::Int(ms)),
        ];
        if orphans > 0 {
            fields.push(orphans_field);
        }
        log::emit(Event::DemandEvicted, &fields);
    } else if reserve_stuck {
        stuck(demand, "index", orphans);
    } else if candidates.is_empty() {
        // Rule 8: nothing to evict; new blocks get `507` until blocks become candidates.
        stuck(demand, "no_candidate", orphans);
    }
    (removed, failure)
}

/// A stuck demand pass (rule 8): counted, flagged for `Retry-After` (security review 2026-11-21,
/// L-4) and logged as `demand_stuck` with its `cause`, and `orphans` when the listing skipped
/// order entries without a row (I-3). Counts only, never a `block_id`.
fn stuck(demand: &crate::demand::Demand, cause: &'static str, orphans: u64) {
    static STUCK_LOG: Throttle = Throttle::new();
    metrics::demand_stuck();
    demand.set_stuck(true);
    let mut fields = vec![("cause", Value::Str(cause))];
    if orphans > 0 {
        fields.push(("orphans", Value::Int(orphans)));
    }
    log::throttled(&STUCK_LOG, Event::DemandStuck, &fields, None);
}

/// One demand pass: [`demand_list`], then [`demand_apply`].
pub(crate) fn demand_pass<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    batch: usize,
    now: u64,
) -> (u64, Option<Failure>) {
    match demand_list(relay, batch, now) {
        Ok(Some(listing)) => demand_apply(relay, listing),
        Ok(None) => (0, None),
        Err(f) => (0, Some(f)),
    }
}

/// The sweeper task: a run every `interval` (the first one `interval` after the start, the
/// start-up walk having just purged the quarantine), and a flush of the demand set when one is
/// requested (ADR 0046 rule 12), until `stop` changes or its sender is dropped. A run that is
/// still going when `stop` changes is waited for. Returns early only if a run panicked, which
/// the caller treats as the end of a supervised thread (ADR 0018 rule 37).
pub async fn run<I: IndexBackend + 'static>(
    relay: Arc<Relay<I>>,
    interval: Duration,
    batch: usize,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let r = Arc::clone(&relay);
        let job = tokio::select! {
            _ = tick.tick() => tokio::task::spawn_blocking(move || {
                sweep_once(&r, batch);
            }),
            () = relay.demand().flush_requested() => tokio::task::spawn_blocking(move || {
                flush_demand(&r);
            }),
            _ = stop.changed() => return,
        };
        if job.await.is_err() {
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
        index.configure_demand(settings.demand_epoch_ms).unwrap();
        store::reconcile(&store, &*index).unwrap();
        let pool = IndexPool::start(&index, &settings).unwrap();
        let relay = Arc::new(
            Relay::new(&settings, store, pool.handle())
                .unwrap()
                .with_clock(clock),
        );
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

    /// Security review 2026-11-20 M-1, ADR 0043 rule 4: a sweeper that lists while an acceptance
    /// of the block is between its start and its index insert sees the old, expired position.
    /// Once the `PUT` has its `201`, the sweeper must keep the block. Both acceptance paths that
    /// insert a new position: the re-acceptance of a held expired block, and a new file for a
    /// phantom entry whose file is gone.
    #[tokio::test]
    async fn listing_during_the_insert_of_an_acceptance_keeps_the_block() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("insert-race", now, &[]);
        let (a, ida) = block(6);
        let (b, idb) = block(7);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        NOW.store(T0 + 1, Ordering::SeqCst);
        assert_eq!(put(&f, &b).await, StatusCode::CREATED);
        // `a` expires first, then `b`; the file of `b` is lost, leaving a phantom entry.
        for (at, bytes, id, phantom) in [(T0 + TTL, &a, ida, false), (T0 + TTL + 1, &b, idb, true)]
        {
            NOW.store(at, Ordering::SeqCst);
            if phantom {
                std::fs::remove_file(file(&f, &id)).unwrap();
            }
            let slot = Arc::new(std::sync::Mutex::new(None));
            let (relay, out) = (Arc::downgrade(&f.relay), Arc::clone(&slot));
            f.relay.set_before_insert(move || {
                let relay = relay.upgrade().unwrap();
                *out.lock().unwrap() = Some(list(&relay, 1_000, now()).unwrap().unwrap());
            });
            assert_eq!(
                put(&f, bytes).await,
                StatusCode::CREATED,
                "phantom={phantom}"
            );
            let listing = slot.lock().unwrap().take().unwrap();
            assert_eq!(listing.batch.len(), 1);
            assert_eq!(listing.batch[0].1, id, "the old, expired position");
            let new = position(&f, &id).unwrap();
            assert_eq!(new.received_at, at);
            let r = Arc::clone(&f.relay);
            let (_, failure) = tokio::task::spawn_blocking(move || apply(&r, listing))
                .await
                .unwrap();
            assert_eq!(failure, None);
            assert!(
                file(&f, &id).exists(),
                "accepted file kept, phantom={phantom}"
            );
            assert_eq!(position(&f, &id), Some(new));
            assert_eq!(get(&f, &id).await, StatusCode::OK);
        }
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// Security review 2026-11-20 L-1: a deletion that fails on the oldest entry skips it for the
    /// run; the later positions are still swept, the failure is reported and counted, and the
    /// skipped block goes once its deletion succeeds.
    #[tokio::test]
    async fn failed_deletion_skips_the_position_and_the_run_goes_on() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("skip", now, &[]);
        let (a, ida) = block(8);
        let (b, idb) = block(9);
        assert_eq!(put(&f, &a).await, StatusCode::CREATED);
        NOW.store(T0 + 1, Ordering::SeqCst);
        assert_eq!(put(&f, &b).await, StatusCode::CREATED);
        // A directory under the final name of the oldest block: its deletion fails.
        std::fs::remove_file(file(&f, &ida)).unwrap();
        std::fs::create_dir(file(&f, &ida)).unwrap();
        NOW.store(T0 + 2 * TTL, Ordering::SeqCst);
        for _ in 0..2 {
            let (_, _, failures) = metrics::sweep_totals();
            assert_eq!(sweep(&f).await, None, "the failure is reported");
            assert!(metrics::sweep_totals().2 > failures, "and counted");
            assert!(file(&f, &ida).is_dir());
            assert!(position(&f, &ida).is_some(), "the failed position stays");
            assert!(!file(&f, &idb).exists(), "the next one is still swept");
            assert_eq!(position(&f, &idb), None);
        }
        std::fs::remove_dir(file(&f, &ida)).unwrap();
        assert_eq!(sweep(&f).await, Some(1));
        assert_eq!(position(&f, &ida), None);
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

/// ADR 0046: demand eviction, deterministic with the injectable clock (no sleeps). Every test has
/// its own clock, data directory and relay; metrics are process-wide, so counters are compared
/// with `>`, never for equality.
#[cfg(test)]
mod demand_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
    use axum::response::Response;

    use crate::blocks::{get_block, put_block};
    use crate::config::Settings;
    use crate::index::RedbIndex;
    use crate::pool::IndexPool;
    use crate::store::Store;

    use crate::demand::StartState;

    /// The smallest epoch (rule 24): 4 hours.
    const E: u64 = 14_400_000;
    /// Epoch-aligned start.
    const T0: u64 = 1_000 * E;

    struct Fixture {
        relay: Arc<Relay<RedbIndex>>,
        dir: std::path::PathBuf,
        _pool: IndexPool<RedbIndex>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn settings(extra: &[(&str, &str)]) -> Settings {
        let mut env = vec![
            ("SBTP_RELAY_MIN_POW_DIFFICULTY".to_owned(), "0".to_owned()),
            ("SBTP_RELAY_DEMAND_EPOCH_MS".to_owned(), E.to_string()),
            (
                "SBTP_RELAY_MAX_STORE_BYTES".to_owned(),
                "8388608".to_owned(),
            ),
            (
                "SBTP_RELAY_DEMAND_HIGH_WATER_PCT".to_owned(),
                "50".to_owned(),
            ),
            (
                "SBTP_RELAY_DEMAND_LOW_WATER_PCT".to_owned(),
                "10".to_owned(),
            ),
        ];
        env.extend(
            extra
                .iter()
                .map(|(k, v)| (format!("SBTP_RELAY_{k}"), (*v).to_owned())),
        );
        let env = env
            .into_iter()
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        Settings::load(Vec::<std::ffi::OsString>::new(), env).unwrap()
    }

    fn fixture(name: &str, clock: fn() -> u64, extra: &[(&str, &str)]) -> Fixture {
        fixture_sized(name, clock, extra, None)
    }

    /// With `index_len`, the store measures the index part on a stand-in file of that length
    /// instead of the redb file (the guard of ADR 0046 clarification D6).
    fn fixture_sized(
        name: &str,
        clock: fn() -> u64,
        extra: &[(&str, &str)],
        index_len: Option<u64>,
    ) -> Fixture {
        let dir = std::env::temp_dir().join(format!("sbtp-demand-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let settings = settings(extra);
        let index_file = dir.join("index.redb");
        let index = Arc::new(RedbIndex::open(&index_file, 1 << 20).unwrap());
        index.configure_demand(settings.demand_epoch_ms).unwrap();
        let measured = match index_len {
            Some(len) => {
                let stand_in = std::env::temp_dir()
                    .join(format!("sbtp-demand-{name}-{}.idx", std::process::id()));
                std::fs::File::create(&stand_in)
                    .unwrap()
                    .set_len(len)
                    .unwrap();
                stand_in
            }
            None => index_file,
        };
        let store = Store::open(&dir, measured, settings.max_store_bytes).unwrap();
        store::reconcile(&store, &*index).unwrap();
        let pool = IndexPool::start(&index, &settings).unwrap();
        let deny = Arc::new(crate::deny::Deny::open(&settings).unwrap());
        let relay = Arc::new(
            Relay::new(&settings, store, pool.handle())
                .unwrap()
                .with_clock(clock)
                .with_deny(deny),
        );
        Fixture {
            relay,
            dir,
            _pool: pool,
        }
    }

    /// ADR 0052 rule 15 (amends ADR 0046 rule 10): a `GET` answered `451`, with or without
    /// `If-None-Match`, is not a demand; the same block is a demand once the entry is lifted.
    #[tokio::test]
    async fn a_denied_read_is_not_demand() {
        fn now() -> u64 {
            T0
        }
        let list = std::env::temp_dir().join(format!("sbtp-deny-demand-{}", std::process::id()));
        std::fs::write(&list, "").unwrap();
        let f = fixture("deny", now, &[("DENY_FILE", list.to_str().unwrap())]);
        let (bytes, id) = block(1, 16, &[]);
        assert_eq!(put(&f, &bytes).await.status(), StatusCode::CREATED);
        std::fs::write(&list, format!("block {id}\n")).unwrap();
        assert_eq!(f.relay.deny().reload(), crate::deny::Reload::Loaded);
        for inm in [None, Some(format!("\"{id}\""))] {
            let r = get(&f, &id, inm.as_deref()).await;
            assert_eq!(r.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }
        assert!(!f.relay.demand().contains(&id), "a 451 is not demand");
        std::fs::write(&list, "").unwrap();
        assert_eq!(f.relay.deny().reload(), crate::deny::Reload::Loaded);
        assert_eq!(get(&f, &id, None).await.status(), StatusCode::OK);
        assert!(f.relay.demand().contains(&id));
        let _ = std::fs::remove_file(&list);
    }

    /// ADR 0054 rule 42: a block the deny list refuses when it is committed is never offered to
    /// the subscriptions, even when the list was loaded after the `PUT`'s own check.
    #[tokio::test]
    async fn a_block_denied_at_the_fan_out_is_never_offered() {
        fn now() -> u64 {
            T0
        }
        let list = std::env::temp_dir().join(format!("sbtp-deny-fanout-{}", std::process::id()));
        std::fs::write(&list, "").unwrap();
        let f = fixture(
            "deny-fanout",
            now,
            &[
                ("DENY_FILE", list.to_str().unwrap()),
                ("WS_ENABLED", "true"),
            ],
        );
        let hub = Arc::clone(f.relay.subscriptions().unwrap());
        let (a, ida) = block(1, 16, &[]);
        assert_eq!(put(&f, &a).await.status(), StatusCode::CREATED);
        assert_eq!(hub.drain_offered(), [ida]);
        let (b, idb) = block(2, 16, &[]);
        let relay = Arc::downgrade(&f.relay);
        let file = list.clone();
        // After the `PUT`'s deny check (rule 7 of ADR 0052), before its insert.
        f.relay.set_before_insert(move || {
            std::fs::write(&file, format!("block {idb}\n")).unwrap();
            let r = relay.upgrade().unwrap();
            assert_eq!(r.deny().reload(), crate::deny::Reload::Loaded);
        });
        assert_eq!(put(&f, &b).await.status(), StatusCode::CREATED);
        assert_eq!(hub.drain_offered(), Vec::<BlockId>::new(), "never offered");
        let _ = std::fs::remove_file(&list);
    }

    /// A block of `len` payload bytes, distinct per `n`, with `parents`.
    fn block(n: u32, len: usize, parents: &[BlockId]) -> (Vec<u8>, BlockId) {
        let k = sbtp_core::SigningKey::from_bytes(&[5; 32]);
        let mut payload = vec![0u8; len.max(4)];
        payload[..4].copy_from_slice(&n.to_be_bytes());
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .parents(parents)
            .payload(&payload)
            .build(&k, 0)
            .unwrap();
        let id = sbtp_core::parse(&bytes).unwrap().block_id();
        (bytes, id)
    }

    async fn put(f: &Fixture, bytes: &[u8]) -> Response {
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/sbtp/v1/block")
            .body(Body::from(bytes.to_vec()))
            .unwrap();
        put_block(State(Arc::clone(&f.relay)), req).await
    }

    async fn get(f: &Fixture, id: &BlockId, if_none_match: Option<&str>) -> Response {
        let uri = format!("/sbtp/v1/block/{id}").parse().unwrap();
        let mut h = HeaderMap::new();
        if let Some(v) = if_none_match {
            h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
        }
        get_block(State(Arc::clone(&f.relay)), uri, h).await
    }

    fn state(f: &Fixture, id: &BlockId) -> Option<(Position, u64)> {
        let id = *id;
        f.relay
            .index()
            .read_blocking(move |i| i.demand_state(&id))
            .unwrap()
            .unwrap()
    }

    fn held(f: &Fixture, id: &BlockId) -> bool {
        f.relay.store().path(id).exists()
    }

    async fn blocking<R: Send + 'static>(
        f: &Fixture,
        job: impl FnOnce(&Relay<RedbIndex>) -> R + Send + 'static,
    ) -> R {
        let r = Arc::clone(&f.relay);
        tokio::task::spawn_blocking(move || job(&r)).await.unwrap()
    }

    async fn sweep(f: &Fixture) -> Option<u64> {
        blocking(f, |r| sweep_once(r, 1_000)).await
    }

    /// Stores blocks of 60 kB from `first` at `at` until the admission total is above the
    /// high-water mark; returns them in acceptance order.
    async fn fill(f: &Fixture, first: u32, at: &AtomicU64) -> Vec<BlockId> {
        let (high, _) = f.relay.watermarks();
        let mut ids = Vec::new();
        let mut n = first;
        while f.relay.store().admission_total() <= high {
            at.fetch_add(1, Ordering::SeqCst);
            let (b, id) = block(n, 60_000, &[]);
            assert_eq!(put(f, &b).await.status(), StatusCode::CREATED, "block {n}");
            ids.push(id);
            n += 1;
            assert!(n < first + 200, "the high-water mark is reached");
        }
        ids
    }

    /// Rules 1 to 7 and 10: above the high-water mark, the blocks nobody requested for `3 × E`
    /// go, least recently demanded first (rule 6), down to the low-water mark; a block requested
    /// in the last `E`, by a `200` or a `304`, stays. Rules 15: the headers of a demand relay.
    #[tokio::test]
    async fn popular_blocks_survive_and_cold_blocks_go() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("popular", now, &[("DEMAND_LOW_WATER_PCT", "40")]);
        let ids = fill(&f, 0, &NOW).await;
        assert!(ids.len() >= 6, "{}", ids.len());
        // Three epochs later, every other block is requested: by a `200`, then by a `304` (a
        // shared cache revalidating).
        NOW.store(T0 + 3 * E, Ordering::SeqCst);
        for (k, id) in ids.iter().enumerate().filter(|(k, _)| k % 2 == 1) {
            let r = if k % 4 == 1 {
                get(&f, id, None).await
            } else {
                get(&f, id, Some(&format!("\"{id}\""))).await
            };
            assert!(
                matches!(r.status(), StatusCode::OK | StatusCode::NOT_MODIFIED),
                "{}",
                r.status()
            );
            // Rule 15 with `E` = 4 h: `S` = 7,200 s.
            assert_eq!(
                r.headers()[header::CACHE_CONTROL],
                "public, max-age=31536000, s-maxage=7200, immutable"
            );
            assert_eq!(
                r.headers()["cdn-cache-control"],
                "public, max-age=7200, must-revalidate"
            );
        }
        NOW.store(T0 + 3 * E + 1, Ordering::SeqCst);
        let evicted_before = metrics::demand_snapshot()[0].1;
        assert!(sweep(&f).await.unwrap() > 0);
        assert!(metrics::demand_snapshot()[0].1 > evicted_before);
        let popular: Vec<bool> = ids
            .iter()
            .skip(1)
            .step_by(2)
            .map(|id| held(&f, id))
            .collect();
        assert!(popular.iter().all(|h| *h), "{popular:?}");
        // Only cold blocks went, the oldest first: the deleted ones are a prefix of the cold ones.
        let cold: Vec<bool> = ids.iter().step_by(2).map(|id| held(&f, id)).collect();
        let gone = cold.iter().take_while(|h| !**h).count();
        assert!(gone > 0);
        assert!(cold[gone..].iter().all(|h| *h), "{cold:?}");
        // The run stopped at the low-water mark, before the last cold blocks (the index file,
        // which grows with the removals, makes the exact total after the run vary).
        let (high, _) = f.relay.watermarks();
        assert!(gone < cold.len(), "stopped at the low-water mark");
        assert!(f.relay.store().admission_total() < high);
        // An evicted block is gone from the index and answers `404`.
        assert_eq!(state(&f, &ids[0]), None);
        assert_eq!(get(&f, &ids[0], None).await.status(), StatusCode::NOT_FOUND);
    }

    /// Rule 7 at its exact millisecond: a block whose last demand is the epoch `T0` is not a
    /// candidate at `T0 + 3 × E − 1`, and is at `T0 + 3 × E`.
    #[tokio::test]
    async fn three_epochs_protect_to_the_millisecond() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("exact", now, &[]);
        let ids = fill(&f, 0, &NOW).await;
        assert_eq!(state(&f, &ids[0]).unwrap().1, T0);
        NOW.store(T0 + 3 * E - 1, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(0));
        assert!(ids.iter().all(|id| held(&f, id)));
        NOW.store(T0 + 3 * E, Ordering::SeqCst);
        assert!(sweep(&f).await.unwrap() > 0);
        assert!(!held(&f, &ids[0]));
    }

    /// Rule 13: a demand lost to a full set is counted and suspends demand eviction for `2 × E`;
    /// age eviction, reads and `PUT` are unchanged.
    #[tokio::test]
    async fn a_full_set_suspends_eviction_for_two_epochs() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("full-set", now, &[("DEMAND_TOUCH_MAX", "1024")]);
        let ids = fill(&f, 0, &NOW).await;
        let at = T0 + 3 * E;
        NOW.store(at, Ordering::SeqCst);
        // 1,024 other held blocks requested before a flush: stand-ins in the set.
        for n in 0..1_024u32 {
            let mut b = [9u8; 32];
            b[..4].copy_from_slice(&n.to_be_bytes());
            f.relay.demand().touch(&BlockId(b), at);
        }
        let lost = metrics::demand_lost_total();
        // One more distinct block requested: the set is full, the demand is lost.
        assert_eq!(get(&f, &ids[1], None).await.status(), StatusCode::OK);
        assert!(metrics::demand_lost_total() > lost);
        assert!(f.relay.demand().suspended(at));
        assert_eq!(f.relay.demand().suspended_until(), at + 2 * E);
        // Reads and writes go on.
        let (b, _) = block(10_000, 10, &[]);
        assert_eq!(put(&f, &b).await.status(), StatusCode::CREATED);
        // Every block is a candidate, but nothing goes until `at + 2 × E`.
        NOW.store(at + 2 * E - 1, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(0));
        assert!(ids.iter().all(|id| held(&f, id)));
        NOW.store(at + 2 * E, Ordering::SeqCst);
        assert!(sweep(&f).await.unwrap() > 0);
        assert!(!held(&f, &ids[0]));
    }

    /// Rule 13: a start after an unclean shutdown suspends for `2 × E`; a clean close does not
    /// and keeps `last_demand`.
    #[test]
    fn unclean_start_suspends_and_a_clean_restart_keeps_demand() {
        let dir = std::env::temp_dir().join(format!("sbtp-demand-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.redb");
        let id = BlockId([3; 32]);
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert!(!idx.unclean_start(), "a new index");
        idx.configure_demand(E).unwrap();
        idx.insert(&id, 100, &[], T0 + 5, crate::index::FileState::Created)
            .unwrap();
        assert_eq!(idx.record_demand(&[id], T0 + 3 * E).unwrap(), 1);
        idx.flush().unwrap();
        // Closed without the clean mark: a crash, as seen at the next open.
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert!(idx.unclean_start());
        idx.mark_clean(0).unwrap();
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert!(!idx.unclean_start(), "clean close");
        let (_, last) = idx.demand_state(&id).unwrap().unwrap();
        assert_eq!(last, T0 + 3 * E, "kept across a clean restart");
        idx.close().unwrap();
        // The relay side: suspended until `start + 2 × E`.
        let d = crate::demand::Demand::new(&settings(&[])).unwrap();
        d.unclean_start(T0);
        assert!(d.suspended(T0 + 2 * E - 1));
        assert!(!d.suspended(T0 + 2 * E));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR 0046 clarifications D1 and D2: the index records the `demand_eviction` setting of each
    /// start and, at a clean close, the suspension end; a crash leaves the last clean value, and
    /// the start case covers it.
    #[test]
    fn index_records_the_setting_and_the_suspension() {
        let dir = std::env::temp_dir().join(format!("sbtp-demand-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.redb");
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert_eq!(idx.suspended_until(), 0);
        assert_eq!(idx.record_demand_eviction(true).unwrap(), None);
        assert_eq!(idx.record_demand_eviction(true).unwrap(), Some(true));
        assert_eq!(idx.record_demand_eviction(false).unwrap(), Some(true));
        assert_eq!(idx.record_demand_eviction(true).unwrap(), Some(false));
        idx.mark_clean(T0 + 2 * E).unwrap();
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert!(!idx.unclean_start());
        assert_eq!(
            idx.suspended_until(),
            T0 + 2 * E,
            "survives a clean restart"
        );
        assert_eq!(idx.record_demand_eviction(true).unwrap(), Some(true));
        // A crash: no clean mark, the stored end is the one of the last clean close.
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert!(idx.unclean_start());
        assert_eq!(idx.suspended_until(), T0 + 2 * E);
        idx.close().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D1: a start without demand history (the migration ran, or `demand_eviction` was off at
    /// the previous start) suspends demand eviction for `2 × E`, to the millisecond; an
    /// on-to-on restart does not.
    #[tokio::test]
    async fn a_start_without_history_suspends_for_two_epochs() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let cases = [
            ("migrated", true, None, true),
            ("enabled", false, Some(false), true),
            ("on-on", false, Some(true), false),
        ];
        for (name, migrated, previous, suspends) in cases {
            NOW.store(T0, Ordering::SeqCst);
            let f = fixture(&format!("history-{name}"), now, &[]);
            let ids = fill(&f, 0, &NOW).await;
            let at = T0 + 3 * E;
            NOW.store(at, Ordering::SeqCst);
            let s = StartState {
                migrated,
                previous,
                ..StartState::default()
            };
            f.relay.demand().start(&s, at);
            assert_eq!(f.relay.demand().suspended(at), suspends, "{name}");
            if suspends {
                NOW.store(at + 2 * E - 1, Ordering::SeqCst);
                assert_eq!(sweep(&f).await, Some(0), "{name}");
                assert!(ids.iter().all(|id| held(&f, id)), "{name}");
                NOW.store(at + 2 * E, Ordering::SeqCst);
            }
            assert!(sweep(&f).await.unwrap() > 0, "{name}");
            assert!(!held(&f, &ids[0]), "{name}");
        }
    }

    /// D2: a suspension running at a clean close is restored at the next start (the index side
    /// is `index_records_the_setting_and_the_suspension`); a past end has no effect.
    #[tokio::test]
    async fn a_clean_restart_keeps_a_running_suspension() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("restored", now, &[]);
        let ids = fill(&f, 0, &NOW).await;
        let lost_at = T0 + 3 * E;
        NOW.store(lost_at + 3_600_000, Ordering::SeqCst);
        // The suspension end a clean close of the previous run wrote, then a restart an hour later.
        let s = StartState {
            previous: Some(true),
            suspended_until: lost_at + 2 * E,
            ..StartState::default()
        };
        f.relay.demand().start(&s, now());
        assert_eq!(sweep(&f).await, Some(0));
        assert!(ids.iter().all(|id| held(&f, id)));
        NOW.store(lost_at + 2 * E, Ordering::SeqCst);
        assert!(sweep(&f).await.unwrap() > 0);
        // A stored end in the past: nothing.
        let d = crate::demand::Demand::new(&settings(&[])).unwrap();
        d.start(
            &StartState {
                previous: Some(true),
                suspended_until: now() - 1,
                ..StartState::default()
            },
            now(),
        );
        assert!(!d.suspended(now()));
    }

    /// D3: a demand lost after the listing ends the pass before the next candidate.
    #[tokio::test]
    async fn a_loss_during_a_pass_stops_it() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("loss-in-pass", now, &[]);
        let ids = fill(&f, 0, &NOW).await;
        NOW.store(T0 + 3 * E, Ordering::SeqCst);
        let listing = blocking(&f, |r| demand_list(r, 1_000, now()).unwrap().unwrap()).await;
        assert_ne!(listing.candidates.len(), 0);
        // A `PUT` answered `200` whose demand write failed, between the listing and the deletion.
        f.relay.demand().lost(1, now());
        let (removed, failure) = blocking(&f, move |r| demand_apply(r, listing)).await;
        assert_eq!((removed, failure), (0, None));
        assert!(ids.iter().all(|id| held(&f, id)));
    }

    /// D5: a `507` carries `Retry-After` only while demand eviction is on, above the high-water
    /// mark, neither suspended nor stuck.
    #[tokio::test]
    async fn retry_after_on_507_only_when_room_can_come() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("retry-after", now, &[("MAX_STORE_BYTES", "4194304")]);
        let mut n = 0;
        let refused = loop {
            let (b, _) = block(n, 60_000, &[]);
            let r = put(&f, &b).await;
            if r.status() != StatusCode::CREATED {
                break b;
            }
            n += 1;
            assert!(n < 100, "the quota is reached");
        };
        let retry = |r: &Response| {
            r.headers()
                .get(header::RETRY_AFTER)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        let r = put(&f, &refused).await;
        assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(retry(&r).as_deref(), Some("60"));
        f.relay.demand().set_stuck(true);
        assert_eq!(retry(&put(&f, &refused).await), None, "stuck");
        f.relay.demand().set_stuck(false);
        f.relay.demand().lost(1, now());
        let r = put(&f, &refused).await;
        assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(retry(&r), None, "suspended");
        NOW.store(now() + 2 * E, Ordering::SeqCst);
        assert_eq!(
            retry(&put(&f, &refused).await).as_deref(),
            Some("60"),
            "the suspension ended"
        );
    }

    /// D6 and security review 2026-11-21 pre-push, L-1: `PUT`s accepted while the pass deletes
    /// (here, a block file written by the store right after each deletion, as a concurrent `PUT`
    /// of another block does) do not end the pass: only a deletion that released no quota bytes
    /// does. Before the fix, the pass stopped after its first deletion.
    #[tokio::test]
    async fn concurrent_puts_do_not_end_the_pass() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("concurrent-put", now, &[]);
        let ids = fill(&f, 0, &NOW).await;
        NOW.store(T0 + 10 * E, Ordering::SeqCst);
        let relay = Arc::clone(&f.relay);
        let written = Arc::new(AtomicU64::new(0));
        let w = Arc::clone(&written);
        f.relay.set_after_evict(move || {
            let n = w.fetch_add(1, Ordering::SeqCst);
            if n < 3 {
                let (bytes, _) = block(10_000 + u32::try_from(n).unwrap(), 60_000, &[]);
                let parsed = sbtp_core::parse(&bytes).unwrap();
                let valid = parsed.check_pow(0).unwrap().verify_signature().unwrap();
                assert!(matches!(
                    relay.store().write_new(&valid),
                    Ok(store::Stored::Created)
                ));
            }
        });
        let removed = sweep(&f).await.unwrap();
        assert!(written.load(Ordering::SeqCst) >= 3);
        assert!(
            removed > 3,
            "the pass went on after the concurrent writes: {removed}"
        );
        assert!(ids.iter().filter(|id| !held(&f, id)).count() > 3);
    }

    /// D6: when the index part alone is at or above the low-water mark, the sweeper deletes no
    /// candidate and the run is stuck; no `Retry-After` follows.
    #[tokio::test]
    async fn index_part_above_the_low_water_mark_is_stuck() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        // Low-water mark: 10 % of 8 MiB, 838,860 bytes; index part of a 500,000-byte index
        // file: 1,000,000 bytes.
        let f = fixture_sized("index-part", now, &[], Some(500_000));
        let (_, low) = f.relay.watermarks();
        assert!(f.relay.store().index_reserve_bytes() >= low);
        let ids = fill(&f, 0, &NOW).await;
        NOW.store(T0 + 10 * E, Ordering::SeqCst);
        let stuck = metrics::demand_snapshot()[3].1;
        assert_eq!(sweep(&f).await, Some(0));
        assert!(metrics::demand_snapshot()[3].1 > stuck);
        assert!(f.relay.demand().stuck());
        assert!(ids.iter().all(|id| held(&f, id)), "no candidate deleted");
        assert!(!f.relay.demand().retry_after_useful(now()));
    }

    /// ADR 0048 rule 18: a request carrying `Sbtp-Replication: 1` is answered `no-store` (both
    /// headers, `200` and `304`) and is not demand.
    #[tokio::test]
    async fn a_replication_request_is_not_demand() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        for demand in ["true", "false"] {
            let f = fixture(
                &format!("replication-{demand}"),
                now,
                &[("DEMAND_EVICTION", demand)],
            );
            let (a, ida) = block(1, 10, &[]);
            assert_eq!(put(&f, &a).await.status(), StatusCode::CREATED);
            for etag in [None, Some(format!("\"{ida}\""))] {
                let uri = format!("/sbtp/v1/block/{ida}").parse().unwrap();
                let mut h = HeaderMap::new();
                h.insert("sbtp-replication", HeaderValue::from_static("1"));
                if let Some(v) = &etag {
                    h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
                }
                let r = get_block(State(Arc::clone(&f.relay)), uri, h).await;
                assert!(matches!(
                    r.status(),
                    StatusCode::OK | StatusCode::NOT_MODIFIED
                ));
                assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store", "{demand}");
                assert_eq!(r.headers()["cdn-cache-control"], "no-store", "{demand}");
            }
            assert!(f.relay.demand().is_empty(), "not demand ({demand})");
            // Any other value is an ordinary read.
            let uri = format!("/sbtp/v1/block/{ida}").parse().unwrap();
            let mut h = HeaderMap::new();
            h.insert("sbtp-replication", HeaderValue::from_static("0"));
            let r = get_block(State(Arc::clone(&f.relay)), uri, h).await;
            assert_ne!(r.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    /// Rules 11 and 12: repeated requests in one epoch make at most one index update per block;
    /// a `304` counts; a `404` does not reach the set.
    #[tokio::test]
    async fn one_update_per_block_per_epoch() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("once", now, &[]);
        let (a, ida) = block(1, 10, &[]);
        assert_eq!(put(&f, &a).await.status(), StatusCode::CREATED);
        NOW.store(T0 + E + 7, Ordering::SeqCst);
        for _ in 0..5 {
            assert_eq!(get(&f, &ida, None).await.status(), StatusCode::OK);
        }
        let etag = format!("\"{ida}\"");
        let not_modified = metrics::block_not_modified_total();
        assert_eq!(
            get(&f, &ida, Some(&etag)).await.status(),
            StatusCode::NOT_MODIFIED
        );
        assert!(metrics::block_not_modified_total() > not_modified);
        assert_eq!(f.relay.demand().len(), 1);
        let missing = BlockId([0x44; 32]);
        assert_eq!(
            get(&f, &missing, None).await.status(),
            StatusCode::NOT_FOUND
        );
        assert!(!f.relay.demand().contains(&missing), "a 404 is not demand");
        let flushed = blocking(&f, flush_demand).await;
        assert_eq!(
            flushed,
            Flushed {
                updates: 1,
                lost: 0
            }
        );
        assert_eq!(state(&f, &ida).unwrap().1, T0 + E);
        // Again in the same epoch: nothing to update.
        assert_eq!(
            get(&f, &ida, Some(&etag)).await.status(),
            StatusCode::NOT_MODIFIED
        );
        assert_eq!(blocking(&f, flush_demand).await.updates, 0);
        // The next epoch moves it once more.
        NOW.store(T0 + 2 * E, Ordering::SeqCst);
        assert_eq!(get(&f, &ida, None).await.status(), StatusCode::OK);
        assert_eq!(blocking(&f, flush_demand).await.updates, 1);
        assert_eq!(state(&f, &ida).unwrap().1, T0 + 2 * E);
    }

    /// Rule 10: a `PUT` answered `200` is recorded by the writer before the response (rule 14);
    /// the acceptance of a child refreshes a held parent. Rule 22: `/query?parent=` of an
    /// evicted parent still lists its held children.
    #[tokio::test]
    async fn put_and_children_are_demand() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("children", now, &[]);
        let (p, idp) = block(1, 10, &[]);
        let (q, idq) = block(2, 10, &[]);
        assert_eq!(put(&f, &p).await.status(), StatusCode::CREATED);
        assert_eq!(put(&f, &q).await.status(), StatusCode::CREATED);
        NOW.store(T0 + E, Ordering::SeqCst);
        assert_eq!(put(&f, &q).await.status(), StatusCode::OK);
        assert_eq!(
            state(&f, &idq).unwrap().1,
            T0 + E,
            "recorded before the response"
        );
        assert!(f.relay.demand().is_empty(), "not through the set");
        NOW.store(T0 + 2 * E + 3, Ordering::SeqCst);
        let (c, idc) = block(3, 10, &[idp]);
        assert_eq!(put(&f, &c).await.status(), StatusCode::CREATED);
        assert_eq!(state(&f, &idp).unwrap().1, T0 + 2 * E, "parent refreshed");
        assert_eq!(state(&f, &idc).unwrap().1, T0 + 2 * E);
        // The child is read an epoch later; the parent goes by demand (filler blocks push the
        // store above the high-water mark), the child stays.
        NOW.store(T0 + 3 * E, Ordering::SeqCst);
        assert_eq!(get(&f, &idc, None).await.status(), StatusCode::OK);
        fill(&f, 100, &NOW).await;
        NOW.store(T0 + 5 * E + 3, Ordering::SeqCst);
        assert!(sweep(&f).await.unwrap() > 0);
        assert!(!held(&f, &idp));
        assert!(held(&f, &idc), "read at T0 + 3 E: protected until T0 + 6 E");
        let page = f
            .relay
            .index()
            .read_blocking(move |i| i.query(Some(&idp), Position::default(), 10))
            .unwrap()
            .unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.1).collect::<Vec<_>>(),
            vec![idc]
        );
    }

    /// Rule 22: a `PUT` answered `200` between the listing and the deletion keeps the block (its
    /// demand is recorded under the lock the sweeper takes); a `PUT` after a demand eviction is
    /// a new block, `201`, with a new position and `last_demand` of the current epoch.
    #[tokio::test]
    async fn put_racing_a_demand_eviction_and_reacceptance() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("race", now, &[]);
        let (a, ida) = block(1, 60_000, &[]);
        assert_eq!(put(&f, &a).await.status(), StatusCode::CREATED);
        let ids = fill(&f, 10, &NOW).await;
        NOW.store(T0 + 3 * E, Ordering::SeqCst);
        let listing = blocking(&f, |r| demand_list(r, 1_000, now()).unwrap().unwrap()).await;
        assert_eq!(listing.candidates[0].id, ida, "the oldest first");
        assert_eq!(put(&f, &a).await.status(), StatusCode::OK);
        let (_, failure) = blocking(&f, move |r| demand_apply(r, listing)).await;
        assert_eq!(failure, None);
        assert!(held(&f, &ida), "demanded since the listing");
        assert!(!held(&f, &ids[0]), "the next candidate goes");
        // Now `a` goes by demand, and comes back as a new block.
        let first = state(&f, &ida).unwrap().0;
        fill(&f, 500, &NOW).await;
        NOW.store(T0 + 7 * E, Ordering::SeqCst);
        assert!(sweep(&f).await.unwrap() > 0);
        assert!(!held(&f, &ida));
        assert_eq!(state(&f, &ida), None);
        NOW.store(T0 + 7 * E + 9, Ordering::SeqCst);
        assert_eq!(put(&f, &a).await.status(), StatusCode::CREATED);
        let (pos, last) = state(&f, &ida).unwrap();
        assert!(pos > first);
        assert_eq!(pos.received_at, T0 + 7 * E + 9);
        assert_eq!(last, T0 + 7 * E);
        assert_eq!(get(&f, &ida, None).await.status(), StatusCode::OK);
    }

    /// Rules 3 and 16: an archive relay (both evictions off) deletes nothing, sends the one-year
    /// headers and no `CDN-Cache-Control`, and records no demand.
    #[tokio::test]
    async fn archive_relay_deletes_nothing() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture(
            "archive",
            now,
            &[("DEMAND_EVICTION", "false"), ("BLOCK_TTL_MS", "0")],
        );
        let ids = fill(&f, 0, &NOW).await;
        NOW.store(T0 + 1_000 * E, Ordering::SeqCst);
        let r = get(&f, &ids[0], None).await;
        assert_eq!(
            r.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(r.headers().get("cdn-cache-control").is_none());
        let r = get(&f, &ids[0], Some(&format!("\"{}\"", ids[0]))).await;
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert!(r.headers().get("cdn-cache-control").is_none());
        assert!(f.relay.demand().is_empty());
        assert_eq!(sweep(&f).await, Some(0));
        assert!(ids.iter().all(|id| held(&f, id)));
    }

    /// Rule 8: above the high-water mark with no candidate, nothing is evicted and the run is
    /// counted as stuck.
    #[tokio::test]
    async fn nothing_evictable_is_stuck() {
        static NOW: AtomicU64 = AtomicU64::new(T0);
        fn now() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let f = fixture("stuck", now, &[]);
        let ids = fill(&f, 0, &NOW).await;
        let stuck = metrics::demand_snapshot()[3].1;
        NOW.store(T0 + E, Ordering::SeqCst);
        assert_eq!(sweep(&f).await, Some(0));
        assert!(metrics::demand_snapshot()[3].1 > stuck);
        assert!(ids.iter().all(|id| held(&f, id)));
    }
}
