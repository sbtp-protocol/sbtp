//! `PUT /sbtp/v1/block` and `GET /sbtp/v1/block/{block_id}` (spec §4; ADR 0003 rules 9 to 11,
//! ADR 0007, ADR 0008, ADR 0013 rules 7 to 9 and 18 to 21, ADR 0018 rules 18, 28 to 32, ADR 0023;
//! demand recording and shared-cache headers of ADR 0046 rules 10 to 16).

use std::collections::TryReserveError;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use http_body::Body as _;
use sbtp_core::layout::MAX_BLOCK_LEN;
use sbtp_core::{BlockId, BlockRef, PowChecked, Submitted, ValidatedBlock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::api::read_body;
use crate::cache::BlockCache;
use crate::client::Counts;
use crate::config::Settings;
use crate::demand::{Demand, epoch_start};
use crate::error::ApiError;
use crate::index::{FileState, IndexBackend, Position};
use crate::log::{self, Event, Level, Throttle, Value};
use crate::metrics::{self, Accepted, Damage, Refused, StorageFull, StoreOp};
use crate::pool::{IndexHandle, PoolError};
use crate::query::expiry_floor;
use crate::server::RequestClient;
use crate::store::{self, Cause, Quarantine, Store, StoreError, Stored, full_validation};

/// A bounded operation class of ADR 0018 rule 18: permits, then a queue of at most `max_queue`
/// waiters, each for at most `queue_timeout_ms`. Never an unbounded wait (rule 3).
#[derive(Debug)]
pub struct Class {
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_queue: usize,
    timeout: Duration,
    refused: Refused,
}

/// Leaves the queue on every exit path, cancellation included.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Class {
    /// `permits` permits and a queue of `max_queue` waiters.
    #[must_use]
    pub fn new(permits: u64, max_queue: u64, timeout: Duration, refused: Refused) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(usize::try_from(permits).unwrap_or(1))),
            waiting: AtomicUsize::new(0),
            max_queue: usize::try_from(max_queue).unwrap_or(0),
            timeout,
            refused,
        }
    }

    /// A permit, or `Err` (the caller answers `503`) when the queue is full or the wait expires.
    pub(crate) async fn acquire(&self) -> Result<OwnedSemaphorePermit, Refused> {
        if let Ok(p) = Arc::clone(&self.permits).try_acquire_owned() {
            return Ok(p);
        }
        let before = self.waiting.fetch_add(1, Ordering::Relaxed);
        let _waiting = Waiting(&self.waiting);
        if before >= self.max_queue {
            return Err(self.refused);
        }
        match tokio::time::timeout(self.timeout, Arc::clone(&self.permits).acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            _ => Err(self.refused),
        }
    }
}

/// Stripes of the per-`block_id` lock of the `PUT` pipeline. More than the largest sensible
/// `put_max_in_flight`, so that two different blocks rarely share one.
pub(crate) const ID_STRIPES: usize = 64;

/// The shared state of the block routes. `I` is the index backend (ADR 0013, "Index trait").
pub struct Relay<I> {
    store: Store,
    /// ADR 0018 rules 9 to 11: every index call of the `PUT` pipeline is a job of the index
    /// threads; the blocking thread that owns the `PUT` permit waits for it.
    index: IndexHandle<I>,
    cache: BlockCache,
    /// Serialises the `PUT`s of one `block_id` from the store lookup to the index insert, so that
    /// a repair (ADR 0013 rule 9) never indexes a block whose creator is about to index it with
    /// [`FileState::Created`], which would move its position (rule 6).
    ids: [Mutex<()>; ID_STRIPES],
    /// Per stripe, incremented under the stripe's lock each time a block of the stripe gets a new
    /// acceptance: a new file (`201`, or a damaged file replaced) or a re-acceptance of an expired
    /// block (ADR 0043 rule 3). Incremented only once the index insert of that acceptance has
    /// returned (security review 2026-11-20 M-1), so that a sweeper that read the old value lists
    /// after the insert committed, or sees the value move. The sweeper compares it with the value
    /// it read before listing a batch, and looks the block up again before deleting anything when
    /// it moved (ADR 0043 rule 4; see [`crate::sweep`]).
    accepted: [AtomicU64; ID_STRIPES],
    /// Per stripe, incremented by the sweeper after it deletes a block file. A `GET` miss that
    /// read the file before the deletion drops the cache entry it inserted when this moved during
    /// its read, so that a swept block is not kept in the cache ([`Relay::cache_loaded`]).
    evicted: [AtomicU64; ID_STRIPES],
    /// ADR 0013 rule 12, ADR 0019 rule 6: `None` when eviction by age is disabled.
    block_ttl_ms: Option<u64>,
    /// The relay clock in Unix milliseconds ([`log::unix_ms`]; a test clock in tests): P1,
    /// `received_at`, the expiry of a stored block, the sweeper and `/query`.
    clock: fn() -> u64,
    put: Class,
    put_per_client: Arc<Counts>,
    read: Class,
    min_pow: u32,
    max_future_ms: u64,
    body_timeout: Duration,
    retry_after_s: u64,
    /// ADR 0046 rules 9 to 14: the demand set and the suspension of demand eviction.
    demand: Demand,
    /// ADR 0046 rules 15 and 16: the `Cache-Control` of a `200` or `304` of `/block`, and the
    /// `CDN-Cache-Control` sent with it when demand eviction is on.
    cache_control: HeaderValue,
    cdn_cache_control: Option<HeaderValue>,
    /// ADR 0046 rule 5: the watermarks, in percent of `max_store_bytes`.
    high_water_pct: u64,
    low_water_pct: u64,
    /// ADR 0046 rule 8: `Retry-After` of a `507` above the high-water mark, `sweep_interval_ms`
    /// in seconds rounded up.
    sweep_retry_after_s: u64,
    /// Tests: run once by [`Relay::index_new`] just before its index insert, under the lock.
    #[cfg(test)]
    before_insert: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl<I: IndexBackend + 'static> Relay<I> {
    /// The block routes' state over an open store and index.
    ///
    /// # Errors
    ///
    /// The demand set of ADR 0046 rule 25 could not be allocated.
    pub fn new(s: &Settings, store: Store, index: IndexHandle<I>) -> Result<Self, TryReserveError> {
        let queue = Duration::from_millis(s.queue_timeout_ms);
        let demand = Demand::new(s)?;
        let (cache_control, cdn_cache_control) = cache_headers(&demand);
        Ok(Self {
            store,
            index,
            cache: BlockCache::new(usize::try_from(s.block_cache_bytes).unwrap_or(usize::MAX)),
            ids: [const { Mutex::new(()) }; ID_STRIPES],
            accepted: [const { AtomicU64::new(0) }; ID_STRIPES],
            evicted: [const { AtomicU64::new(0) }; ID_STRIPES],
            block_ttl_ms: s.block_ttl_ms,
            clock: log::unix_ms,
            put: Class::new(
                s.put_max_in_flight,
                s.put_max_queue,
                queue,
                Refused::PutQueue,
            ),
            put_per_client: Counts::new(
                u32::try_from(s.put_max_in_flight_per_client).unwrap_or(u32::MAX),
            ),
            read: Class::new(
                s.block_max_readers,
                s.block_max_queue,
                queue,
                Refused::BlockQueue,
            ),
            min_pow: s.min_pow_difficulty,
            max_future_ms: s.max_future_ms,
            body_timeout: Duration::from_millis(s.body_timeout_ms),
            retry_after_s: s.shed_retry_after_s,
            demand,
            cache_control,
            cdn_cache_control,
            high_water_pct: s.demand_high_water_pct,
            low_water_pct: s.demand_low_water_pct,
            sweep_retry_after_s: s.sweep_interval_ms.div_ceil(1_000),
            #[cfg(test)]
            before_insert: Mutex::new(None),
        })
    }

    /// The demand state (ADR 0046).
    #[must_use]
    pub fn demand(&self) -> &Demand {
        &self.demand
    }

    /// ADR 0046 rule 5: the high-water and low-water marks, in bytes of the admission total
    /// ([`Store::admission_total`]).
    pub(crate) fn watermarks(&self) -> (u64, u64) {
        let max = u128::from(self.store.max_bytes());
        let at = |pct: u64| u64::try_from(max * u128::from(pct) / 100).unwrap_or(u64::MAX);
        (at(self.high_water_pct), at(self.low_water_pct))
    }

    /// ADR 0046 rule 14: the demand of a `PUT` answered `200`, recorded by the index writer
    /// before the response, never through the set. Under the lock of `id`. A failed or refused
    /// write is a lost demand (rule 13).
    fn put_demand(&self, id: &BlockId) {
        if !self.demand.enabled() {
            return;
        }
        let now = (self.clock)();
        let (ids, at) = ([*id], epoch_start(now, self.demand.epoch_ms()));
        let written = self
            .index
            .write_blocking(move |i| i.record_demand(&ids, at));
        match written {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                crate::demand::write_failed(I::io_error(&e).and_then(log::errno));
                self.demand.lost(1, now);
            }
            Err(_) => self.demand.lost(1, now),
        }
    }

    /// Tests: `f` runs once, inside the next [`Relay::index_new`], just before its index insert.
    #[cfg(test)]
    pub(crate) fn set_before_insert(&self, f: impl FnOnce() + Send + 'static) {
        *self
            .before_insert
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(f));
    }

    /// Replaces the relay clock (tests: a controllable clock instead of [`log::unix_ms`]). The
    /// `/query` route built by [`crate::api::routes`] uses the same clock.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    /// The relay clock.
    #[must_use]
    pub fn clock(&self) -> fn() -> u64 {
        self.clock
    }

    /// The index handle, for the `/query` route.
    #[must_use]
    pub fn index(&self) -> &IndexHandle<I> {
        &self.index
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    pub(crate) fn block_ttl_ms(&self) -> Option<u64> {
        self.block_ttl_ms
    }

    /// The acceptance generation of every stripe, for the sweeper (see `accepted`).
    pub(crate) fn accepted_generations(&self) -> [u64; ID_STRIPES] {
        let mut out = [0; ID_STRIPES];
        for (o, a) in out.iter_mut().zip(&self.accepted) {
            *o = a.load(Ordering::SeqCst);
        }
        out
    }

    /// The acceptance generation of `id`'s stripe.
    pub(crate) fn accepted_generation(&self, id: &BlockId) -> u64 {
        self.accepted
            .get(stripe(id))
            .map_or(0, |a| a.load(Ordering::SeqCst))
    }

    /// Records a new acceptance of `id`. Called under the lock of `id`, after the index insert of
    /// the acceptance returned (see `accepted`).
    fn bump_accepted(&self, id: &BlockId) {
        if let Some(a) = self.accepted.get(stripe(id)) {
            a.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn evicted_generation(&self, id: &BlockId) -> u64 {
        self.evicted
            .get(stripe(id))
            .map_or(0, |a| a.load(Ordering::SeqCst))
    }

    /// The sweeper's deletion of one block, under the lock of `id` (ADR 0013 rule 15, first two
    /// steps): the cache entry, the file, then the cache entry again, so that a `GET` miss that
    /// read the file before the `unlink` cannot leave it cached ([`Relay::cache_loaded`]).
    /// Returns whether a file was there.
    pub(crate) fn evict_locked(&self, id: &BlockId) -> io::Result<bool> {
        self.cache.remove(id);
        let deleted = self.store.evict(id)?;
        if let Some(a) = self.evicted.get(stripe(id)) {
            a.fetch_add(1, Ordering::SeqCst);
        }
        self.cache.remove(id);
        Ok(deleted)
    }

    /// Caches the bytes of `id` that a `GET` miss loaded, unless the sweeper deleted a file of the
    /// stripe since `before` ([`Relay::evicted_generation`] read before the load): then the entry
    /// is dropped again. Either the sweeper's second cache removal comes after this insert, or its
    /// increment is visible here.
    fn cache_loaded(&self, id: &BlockId, bytes: Bytes, before: u64) {
        self.cache.insert(id, bytes);
        if self.evicted_generation(id) != before {
            self.cache.remove(id);
        }
    }

    /// Whether position `at` is expired at the relay clock (ADR 0013 rule 12: `received_at +
    /// block_ttl_ms ≤ now`, the bound of `/query`, [`expiry_floor`]).
    pub(crate) fn is_expired(&self, at: Position) -> bool {
        self.block_ttl_ms.is_some() && at < expiry_floor(self.block_ttl_ms, (self.clock)())
    }

    /// The lock of `id`'s stripe. A panic under it leaves no state to repair: poisoning is
    /// ignored.
    pub(crate) fn lock_id(&self, id: &BlockId) -> MutexGuard<'_, ()> {
        // The stripe is taken modulo the array length: the fallback is never used.
        let [first, ..] = &self.ids;
        self.ids
            .get(stripe(id))
            .unwrap_or(first)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn shed(&self, r: Refused, req_client: Option<&crate::client::ClientKey>) -> Response {
        static PUT_LOG: Throttle = Throttle::new();
        static READ_LOG: Throttle = Throttle::new();
        metrics::refused(r);
        let t = if r == Refused::PutQueue {
            &PUT_LOG
        } else {
            &READ_LOG
        };
        log::throttled(
            t,
            Event::Shed,
            &[("reason", Value::Str(r.reason()))],
            req_client,
        );
        ApiError::unavailable(self.retry_after_s).into_response()
    }

    /// Steps 1 to 5 of the `PUT` pipeline (spec §4), on a blocking thread. `seen` receives the
    /// `block_id` once C1 has computed it.
    fn process(&self, bytes: &[u8], seen: &mut Option<BlockId>) -> Result<Accepted, Rejection> {
        // spec §2.2 F1 to F9.
        let block = sbtp_core::parse(bytes).map_err(Rejection::Block)?;
        // P1 (ADR 0007 rules 3 and 8): after F9, before C1; the sum saturates.
        if block.timestamp() > (self.clock)().saturating_add(self.max_future_ms) {
            return Err(Rejection::Future);
        }
        // spec §2.2 C1; computes the `block_id`.
        let checked = block.check_pow(self.min_pow).map_err(Rejection::Block)?;
        let id = *checked.block_id();
        *seen = Some(id);
        // Held until the index insert: one `PUT` of a given block at a time.
        let _id = self.lock_id(&id);
        let result = self.decide(bytes, id, &block, checked);
        // ADR 0046 rules 10 and 14: a `PUT` answered `200` is a demand of the block. A `201`
        // records its demand in its index insert.
        if matches!(result, Ok(Accepted::Known)) {
            self.put_demand(&id);
        }
        result
    }

    /// Steps 4 and 5 of the `PUT` pipeline, under the lock of `id`.
    fn decide<'a>(
        &self,
        bytes: &[u8],
        id: BlockId,
        block: &BlockRef<'a>,
        checked: PowChecked<'a, Submitted>,
    ) -> Result<Accepted, Rejection> {
        // C2 and C3 of the submitted bytes, run at most once.
        let mut verified = None;
        let replaced = match self.settle(&id, block, checked, &mut verified)? {
            Settled::Known => return Ok(Accepted::Known),
            // ADR 0043 rule 3: an expired block is not held; the file is kept, the block gets a
            // new position. No quota check: nothing is written to the store.
            Settled::Reaccept => return self.index_new(&id, block),
            Settled::Create { replaced } => replaced,
        };
        // C2, C3 (ADR 0023 rule 8.6: the normal create path).
        verify_once(checked, &mut verified)?;
        let Some(valid) = verified else {
            return Err(Rejection::Internal);
        };
        match self.store.write_new(&valid) {
            Ok(Stored::Created) if replaced => {
                // ADR 0023 rule 8.7: the `block_id` was already accepted by this relay; an
                // existing index entry is kept, a missing one is added as an orphan. `200`. An
                // expired entry is not a holding (ADR 0043 rule 3): the block is new, `201`.
                metrics::store_replaced();
                match self.held(&id) {
                    Held::Unindexed => self.index_orphan(&id, block),
                    // Counts the acceptance after its insert.
                    Held::Expired => return self.index_new(&id, block),
                    Held::Live | Held::Unknown => self.store.publish_gauges(),
                }
                // A new file: an acceptance, counted once the index is settled (see `accepted`).
                self.bump_accepted(&id);
                Ok(Accepted::Known)
            }
            Ok(Stored::Created) => self.index_new(&id, block),
            // A file appeared under the final name since the lookup (ADR 0008 rule 6). It is
            // indexed only if it holds the bytes just verified (ADR 0023 rule 15).
            Ok(Stored::AlreadyPresent) => {
                if matches!(self.store.read(&id), Ok(Some(b)) if b == bytes) && self.unindexed(&id)
                {
                    self.index_orphan(&id, block);
                }
                Ok(Accepted::Known)
            }
            // ADR 0023 rule 8.6: no room; a damaged file stays in quarantine.
            Err(StoreError::Full) => Err(Rejection::Full(StorageFull::Quota)),
            Err(StoreError::NoSpace(r)) => Err(Rejection::Full(r)),
            Err(StoreError::Io(e)) => {
                store::log_store_failed(StoreOp::Write, &e);
                Err(Rejection::Internal)
            }
            // ADR 0023 rule 16: the file is under its final name, keeps its quota charge and is
            // not indexed: a valid orphan for the next `PUT` of the block or the start-up walk.
            Err(StoreError::Unsynced(e)) => {
                self.store.publish_gauges();
                store::log_store_failed(StoreOp::Sync, &e);
                Err(Rejection::Internal)
            }
        }
    }

    /// The index entries of a block that is new for the relay (`201`): a new file, or an expired
    /// block whose file is kept (ADR 0043 rule 3). [`FileState::Created`] replaces any older entry
    /// of `id` (ADR 0013 rule 13). Under the lock of `id`. Counts the acceptance once the insert
    /// has returned, whatever its result (security review 2026-11-20 M-1; see `accepted`).
    fn index_new(&self, id: &BlockId, block: &BlockRef<'_>) -> Result<Accepted, Rejection> {
        let len = u32::try_from(block.as_bytes().len()).unwrap_or(u32::MAX);
        #[cfg(test)]
        {
            let hook = self
                .before_insert
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(f) = hook {
                f();
            }
        }
        let inserted = self.insert(id, len, block.parents(), FileState::Created);
        self.bump_accepted(id);
        self.store.publish_gauges();
        // ADR 0018 rule 13: the writer queue is bounded by the `PUT` permits; a refusal leaves an
        // orphan, repaired by the next `PUT` of the block or at start-up.
        let inserted = inserted.map_err(Rejection::Shed)?;
        if let Err(e) = inserted {
            // An orphan: repaired by the next `PUT` of the block or at start-up (rule 9).
            index_write_failed::<I>(&e, None);
            // Security review I-3 and L-1: no room for the index entry is a full store.
            if let Some(r) = I::io_error(&e).and_then(store::no_space) {
                return Err(Rejection::Full(r));
            }
            return Err(Rejection::Internal);
        }
        if log::global().enabled(Level::Debug) {
            let hex = store::hex(id);
            log::emit(
                Event::BlockStored,
                &[
                    ("block", Value::Str(suffix(&hex))),
                    ("bytes", Value::Int(u64::from(len))),
                ],
            );
        }
        Ok(Accepted::New)
    }

    /// ADR 0023 rule 8, steps 1 to 5, under the lock of `id`: decides from the stored file
    /// whether the `PUT` is answered as known or goes on to the create path, after moving a
    /// damaged stored file to quarantine (`replaced`). `verified` receives C2 and C3 of the
    /// submitted bytes when they ran.
    fn settle<'a>(
        &self,
        id: &BlockId,
        block: &BlockRef<'a>,
        checked: PowChecked<'a, Submitted>,
        verified: &mut Option<ValidatedBlock<'a, Submitted>>,
    ) -> Result<Settled, Rejection> {
        // ADR 0023 rule 7: after a quarantine attempt that found the file changed, decide again
        // from the new state, once.
        let mut redecided = false;
        loop {
            // ADR 0023 rule 8.1.
            let stored = match self.store.read(id) {
                Ok(Some(stored)) => stored,
                // ADR 0013 rule 7, also after a move by another request (ADR 0023 rule 9).
                Ok(None) => return Ok(Settled::Create { replaced: false }),
                // ADR 0025 rule 6: a missing shard directory fails on the create path, which
                // reserves and releases the quota and logs `op=write`; it is never recreated.
                Err(e) if store::is_shard_error(&e) => {
                    return Ok(Settled::Create { replaced: false });
                }
                Err(e) => {
                    store::log_store_failed(StoreOp::Read, &e);
                    return Err(Rejection::Internal);
                }
            };
            // Rule 8.2, ADR 0003 rule 10: the signature check MAY be skipped only for identical
            // bytes. An orphan is indexed only after full validation (ADR 0023 rule 15).
            if stored == block.as_bytes() {
                let held = self.held(id);
                if matches!(held, Held::Unindexed | Held::Expired) {
                    // C2, C3 of the submitted bytes, which are the stored bytes; R1 holds since
                    // C1 computed `id` from them. A re-acceptance (ADR 0043 rule 3) is a `201`:
                    // its bytes are verified as for a new block.
                    if let Err(rejected) = verify_once(checked, verified) {
                        // Owner decision (security review I-6): the stored file fails C2 or C3;
                        // it is moved to quarantine and the `PUT` gets the signature failure.
                        self.quarantine_identical(id, &stored);
                        return Err(rejected);
                    }
                }
                match held {
                    Held::Unindexed => self.index_orphan(id, block),
                    Held::Expired => return Ok(Settled::Reaccept),
                    Held::Live | Held::Unknown => {}
                }
                return Ok(Settled::Known);
            }
            // Rule 8.3: the submitted bytes first, so that only a key holder reaches a second
            // verification.
            verify_once(checked, verified)?;
            // Rule 8.4: a stored file that passes full validation is kept (first write wins),
            // also when it is expired: ADR 0043 rule 3 lets the relay keep the file it holds.
            let Err(damage) = full_validation(&stored, id) else {
                match self.held(id) {
                    Held::Unindexed => self.index_orphan(id, block),
                    Held::Expired => return Ok(Settled::Reaccept),
                    Held::Live | Held::Unknown => {}
                }
                return Ok(Settled::Known);
            };
            // Rule 8.5.
            match self.store.quarantine(id, &stored) {
                Ok(Quarantine::Moved) => {
                    store::log_quarantined(Cause::Put, damage);
                    return Ok(Settled::Create { replaced: true });
                }
                Ok(Quarantine::MovedUnsynced(e)) => {
                    // The move may not survive a crash; the block is not written over it.
                    store::log_quarantined(Cause::Put, damage);
                    store::log_store_failed(StoreOp::Quarantine, &e);
                    return Err(Rejection::Internal);
                }
                Ok(Quarantine::Changed) if !redecided => redecided = true,
                // Security review I-1: only a local writer changes the file twice in a row.
                Ok(Quarantine::Changed) => {
                    store::log_store_failed(
                        StoreOp::Quarantine,
                        &io::Error::other("the stored file changed twice during the decision"),
                    );
                    return Err(Rejection::Internal);
                }
                // Never replaced on an I/O error (ADR 0023 decision 1).
                Err(e) => {
                    store::log_store_failed(e.op, &e.error);
                    return Err(Rejection::Internal);
                }
            }
        }
    }

    /// The `PUT` of bytes identical to an unindexed stored file that fails C2 or C3: the stored
    /// file is moved to quarantine (reason `signature`, cause `put`). Under the lock of `id`. A
    /// failed move is logged; the file is then left in place, unindexed, for the next `GET` miss.
    fn quarantine_identical(&self, id: &BlockId, stored: &[u8]) {
        match self.store.quarantine(id, stored) {
            Ok(Quarantine::Moved) => store::log_quarantined(Cause::Put, Damage::Signature),
            Ok(Quarantine::MovedUnsynced(e)) => {
                store::log_quarantined(Cause::Put, Damage::Signature);
                store::log_store_failed(StoreOp::Quarantine, &e);
            }
            // Only a local writer changes the file under the lock; the `GET` judges it again.
            Ok(Quarantine::Changed) => {}
            Err(e) => store::log_store_failed(e.op, &e.error),
        }
    }

    /// Whether `id` has no index entry, from a reader thread (ADR 0018 rules 9 and 11). The
    /// lookup only decides whether the orphan repair of ADR 0013 rule 9 runs (ADR 0018
    /// clarification M1): a failed lookup is logged and counted (ADR 0021 X2), a lookup refused
    /// by the reader queue is counted in `index_repairs_deferred_total` (X5, no event); both
    /// answer `false`, so the `PUT` still gets `200` and the orphan is repaired later. The failed
    /// lookup is `index_write_failed` with `op=insert`, `step=lookup`, not `index_read_failed`
    /// (ADR 0021 clarification X2).
    fn unindexed(&self, id: &BlockId) -> bool {
        matches!(self.held(id), Held::Unindexed)
    }

    /// The index entry of `id`, judged at the relay clock (see [`Relay::unindexed`] for the
    /// failure cases, which are [`Held::Unknown`] and leave the `PUT` at `200` as before). An
    /// entry whose position is expired is [`Held::Expired`]: the block is not held for `PUT`,
    /// whether or not the sweeper has deleted it yet (ADR 0043 rule 3).
    fn held(&self, id: &BlockId) -> Held {
        let id = *id;
        let found = self.index.read_blocking(move |i| i.contains(&id));
        if let Ok(r) = &found {
            self.index.record_read(r); // ADR 0018 rule 37
        }
        match found {
            Ok(Ok(None)) => Held::Unindexed,
            Ok(Ok(Some(at))) if self.is_expired(at) => Held::Expired,
            Ok(Ok(Some(_))) => Held::Live,
            Ok(Err(e)) => {
                index_write_failed::<I>(&e, Some("lookup"));
                Held::Unknown
            }
            Err(_) => {
                metrics::index_repair_deferred();
                Held::Unknown
            }
        }
    }

    /// One insert, run by the index writer thread (ADR 0018 rule 10) at the relay clock. The clock
    /// is read inside the write job, so that `received_at` is the time of the insert, not of the
    /// submission: a wait in the writer queue neither shortens the TTL of the entry nor places it
    /// before entries that a `since=` poller has already been given (ADR 0012 rule 7, ADR 0013
    /// rule 3). The writer runs its jobs in order, so readings follow the acceptance order.
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        state: FileState,
    ) -> Result<Result<Option<crate::index::Position>, I::Error>, Refused> {
        let (id, parents, clock) = (*id, parents.to_vec(), self.clock);
        let inserted = self
            .index
            .write_blocking(move |i| i.insert(&id, len, &parents, clock(), state))
            .map_err(|_: PoolError| Refused::IndexQueue);
        if let Ok(r) = &inserted {
            self.index.record_write(r); // ADR 0018 rule 37
        }
        inserted
    }

    /// ADR 0013 rule 9: a held block without index entry is indexed at the current time. Called
    /// under the lock of `id`, only once the stored file is known to pass full validation (ADR 0023
    /// rule 15). `block` is the submitted block, which may differ from the stored file in its 64
    /// signature bytes only: the `block_id` covers everything else (spec §3.1), so the length and
    /// the parents of the entry are those of the stored file. A failure is logged and counted; the
    /// `PUT` still gets `200`, since the block is held, and the orphan is repaired later.
    fn index_orphan(&self, id: &BlockId, block: &BlockRef<'_>) {
        let len = u32::try_from(block.as_bytes().len()).unwrap_or(u32::MAX);
        let inserted = self.insert(id, len, block.parents(), FileState::AlreadyHeld);
        self.store.publish_gauges();
        match inserted {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => index_write_failed::<I>(&e, None),
            // The writer queue is bounded by the `PUT` permits and refuses only while the relay
            // stops. The `PUT` still gets `200`: a skipped repair, not a `503` refusal (ADR 0018
            // clarification M1, ADR 0021 clarification X5). The orphan is repaired later.
            Err(_) => metrics::index_repair_deferred(),
        }
    }

    /// ADR 0023 rule 10, on a `GET` cache miss, inside the block-read permit: the stored block
    /// `id` after full validation (rule 1). A damaged file is moved to quarantine and answered as
    /// missing, also when the move fails (logged). `Err` is an I/O error while reading (`500`,
    /// rule 2).
    fn load(&self, id: &BlockId) -> Result<Option<Bytes>, ()> {
        // ADR 0023 rule 7: decide again once if the file changed under the lock.
        for _ in 0..2 {
            let read = self.store.read(id).map_err(|e| {
                store::log_store_failed(StoreOp::Read, &e);
            });
            let Some(bytes) = read? else {
                return Ok(None);
            };
            let Err(damage) = full_validation(&bytes, id) else {
                return Ok(Some(Bytes::from(bytes)));
            };
            // The lock of `id`, as on `PUT`, on this rare path only: a `PUT` of the block never
            // sees the final name emptied by this move halfway through its decision.
            let _id = self.lock_id(id);
            match self.store.quarantine(id, &bytes) {
                Ok(Quarantine::Moved) => store::log_quarantined(Cause::Get, damage),
                Ok(Quarantine::MovedUnsynced(e)) => {
                    store::log_quarantined(Cause::Get, damage);
                    store::log_store_failed(StoreOp::Quarantine, &e);
                }
                Ok(Quarantine::Changed) => continue,
                Err(e) => store::log_store_failed(e.op, &e.error),
            }
            return Ok(None);
        }
        Ok(None)
    }
}

/// The index entry of a stored block, at the relay clock.
enum Held {
    /// No entry: an orphan (ADR 0013 rule 9).
    Unindexed,
    /// An entry that has not expired.
    Live,
    /// An entry whose position is expired (ADR 0043 rule 3).
    Expired,
    /// The lookup failed or was refused; handled as [`Held::Live`].
    Unknown,
}

/// What the stored file of a `PUT` decided (ADR 0023 rule 8).
enum Settled {
    /// `200`, nothing more to write.
    Known,
    /// The stored file is valid but its entry is expired: `201`, a new position, the file kept
    /// (ADR 0043 rule 3).
    Reaccept,
    /// The create path; `replaced` when a damaged file was moved out of the final name.
    Create { replaced: bool },
}

/// C2 and C3 of `checked`, unless `done` already holds their result.
fn verify_once<'a>(
    checked: PowChecked<'a, Submitted>,
    done: &mut Option<ValidatedBlock<'a, Submitted>>,
) -> Result<(), Rejection> {
    if done.is_none() {
        *done = Some(checked.verify_signature().map_err(Rejection::Block)?);
    }
    Ok(())
}

/// A failed index insert, logged (`index_write_failed`, `op=insert`) and counted. `step` is
/// `Some("lookup")` when the lookup of a repair failed: the insert it guards could not run, so it
/// counts as a failed insert. One throttle per step, so that one cause cannot hide the other.
/// The fields are those of ADR 0021 rule 7: `op`, `step`, `errno`, `suppressed`.
fn index_write_failed<I: IndexBackend>(e: &I::Error, step: Option<&'static str>) {
    static INSERT_LOG: Throttle = Throttle::new();
    static LOOKUP_LOG: Throttle = Throttle::new();
    metrics::index_write_error(metrics::IndexOp::Insert);
    let mut fields = vec![("op", Value::Str("insert"))];
    if let Some(step) = step {
        fields.push(("step", Value::Str(step)));
    }
    if let Some(n) = I::io_error(e).and_then(log::errno) {
        fields.push(("errno", Value::Int(n)));
    }
    let t = if step.is_some() {
        &LOOKUP_LOG
    } else {
        &INSERT_LOG
    };
    log::throttled(t, Event::IndexWriteFailed, &fields, None);
}

/// The stripe of `id`'s lock: its last byte, the shard byte (ADR 0009), which PoW does not touch.
/// The leading bytes are forced to zero by C1 (spec §3.3) and would put every block on one stripe
/// (security review M-1).
pub(crate) fn stripe(id: &BlockId) -> usize {
    let [.., last] = *id.as_bytes();
    usize::from(last) % ID_STRIPES
}

/// The last 8 hexadecimal characters of a `block_id` (ADR 0021 rule 12).
fn suffix(hex: &str) -> &str {
    hex.get(hex.len().saturating_sub(8)..).unwrap_or("")
}

enum Rejection {
    Block(sbtp_core::Error),
    Future,
    Full(StorageFull),
    /// `503`: an index queue refused the job (ADR 0018 rules 13 and 30).
    Shed(Refused),
    Internal,
}

impl<I: IndexBackend + 'static> Relay<I> {
    /// The response to a failed `PUT` pipeline. `id` is the hexadecimal `block_id`, once known;
    /// `key` is the request's client key, for the `shed` event.
    fn reject(
        &self,
        rejection: &Rejection,
        id: Option<&str>,
        key: Option<&crate::client::ClientKey>,
    ) -> Response {
        static FULL_LOG: Throttle = Throttle::new();
        let e = match *rejection {
            Rejection::Block(ref e) => ApiError::rejected(e),
            Rejection::Future => ApiError::timestamp_too_far(),
            Rejection::Full(r) => {
                metrics::storage_full(r);
                log::throttled(
                    &FULL_LOG,
                    Event::StorageFull,
                    &[("reason", Value::Str(r.reason()))],
                    None,
                );
                // ADR 0046 rule 8 (MAY): above the high-water mark the next sweeper run makes
                // room, unless no block is a candidate (`demand_stuck`).
                let (high, _) = self.watermarks();
                if self.demand.enabled() && self.store.admission_total() > high {
                    return ApiError::storage_full_retry(self.sweep_retry_after_s).into_response();
                }
                return ApiError::storage_full().into_response();
            }
            Rejection::Internal => return ApiError::internal().into_response(),
            // ADR 0018 rule 30 and clarification M4: counted, logged, `shed_retry_after_s`.
            Rejection::Shed(r) => return self.shed(r, key),
        };
        if e.status() != StatusCode::INTERNAL_SERVER_ERROR {
            metrics::rejected(e.name());
            if log::global().enabled(Level::Debug) {
                let mut fields = vec![("error", Value::Str(e.name()))];
                if let Some(id) = id {
                    fields.push(("block", Value::Str(suffix(id))));
                }
                log::emit(Event::BlockRejected, &fields);
            }
        }
        e.into_response()
    }
}

/// `PUT /sbtp/v1/block`, in the order of ADR 0018 rule 28: step 4 (`Content-Length` over the body
/// limit: `413`), step 6 (per-client bound: `429`; `PUT` class: `503`), then the body under
/// `body_timeout_ms` and the pipeline of spec §4 on a blocking thread that owns both permits.
pub async fn put_block<I: IndexBackend + 'static>(
    State(relay): State<Arc<Relay<I>>>,
    req: Request,
) -> Response {
    static IN_FLIGHT_LOG: Throttle = Throttle::new();
    let key = req.extensions().get::<RequestClient>().and_then(|c| c.key);
    let body: Body = req.into_body();
    if body.size_hint().lower() > MAX_BLOCK_LEN as u64 {
        return ApiError::body_too_large().into_response();
    }
    let mut slot = None;
    if let Some(k) = key {
        slot = relay.put_per_client.try_acquire(k);
        if slot.is_none() {
            metrics::refused(Refused::PutInFlight);
            log::throttled(
                &IN_FLIGHT_LOG,
                Event::RateLimited,
                &[("class", Value::Str(Refused::PutInFlight.reason()))],
                Some(&k),
            );
            return ApiError::rate_limited(1).into_response();
        }
    }
    let permit = match relay.put.acquire().await {
        Ok(p) => p,
        Err(r) => return relay.shed(r, key.as_ref()),
    };
    let bytes = match read_body(body, MAX_BLOCK_LEN, relay.body_timeout).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let worker = Arc::clone(&relay);
    let done = tokio::task::spawn_blocking(move || {
        let _owned = (permit, slot);
        let mut id = None;
        let result = worker.process(&bytes, &mut id);
        (result, id.as_ref().map(store::hex))
    })
    .await;
    let (result, id) = match done {
        Ok(r) => r,
        Err(e) => return ApiError::from(e).into_response(),
    };
    match result {
        Ok(a) => {
            metrics::accepted(a);
            let mut r = Response::new(Body::empty());
            // ADR 0023 rule 13.
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if a == Accepted::New {
                *r.status_mut() = StatusCode::CREATED;
                if let Some(v) =
                    id.and_then(|id| HeaderValue::from_str(&format!("/sbtp/v1/block/{id}")).ok())
                {
                    r.headers_mut().insert(header::LOCATION, v);
                }
            }
            r
        }
        Err(rej) => relay.reject(&rej, id.as_deref(), key.as_ref()),
    }
}

/// `GET /sbtp/v1/block/{block_id}`. The identifier is read from the path as received, not
/// percent-decoded, and must be exactly 64 lowercase hexadecimal characters (spec §4, ADR 0012
/// rule 4). A cache hit takes no permit (ADR 0018 rule 18) and verifies nothing (ADR 0023 rule 11);
/// a miss takes a block-read permit, in which the file is fully validated (rule 10). axum routes
/// `HEAD` here too and drops the body: same pipeline, permit and headers (rule 13).
///
/// A `200` carries `ETag: "<block_id>"`, a strong validator: the bytes served for a `block_id` never
/// change (spec §3.4). A request whose `If-None-Match` matches it gets `304 Not Modified` with the
/// same validator and `Cache-Control`, and no body (RFC 9110 §13.1.2, §15.4.5), once the block is
/// known to be held: a block the relay no longer holds is `404`, whatever the condition.
pub async fn get_block<I: IndexBackend + 'static>(
    State(relay): State<Arc<Relay<I>>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(id) = uri
        .path()
        .strip_prefix("/sbtp/v1/block/")
        .and_then(store::parse_hex_id)
    else {
        return ApiError::invalid_parameter()
            .with_message("block_id must be 64 lowercase hexadecimal characters")
            .into_response();
    };
    if let Some(bytes) = relay.cache.get(&id) {
        return relay.block_response(bytes, &id, &headers);
    }
    let permit = match relay.read.acquire().await {
        Ok(p) => p,
        Err(r) => return relay.shed(r, None),
    };
    // Read before the file is: see `Relay::cache_loaded`.
    let evicted = relay.evicted_generation(&id);
    let worker = Arc::clone(&relay);
    let loaded = tokio::task::spawn_blocking(move || {
        let _owned = permit;
        worker.load(&id)
    })
    .await;
    match loaded {
        Ok(Ok(Some(bytes))) => {
            relay.cache_loaded(&id, bytes.clone(), evicted);
            relay.block_response(bytes, &id, &headers)
        }
        Ok(Ok(None)) => ApiError::not_found().into_response(),
        Ok(Err(())) => ApiError::internal().into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

impl<I: IndexBackend + 'static> Relay<I> {
    /// The `200` of a held block, or the `304` when `request` holds a matching `If-None-Match`.
    /// Either is a demand of the block (ADR 0046 rule 10), recorded in the demand set, never in
    /// the index (rule 12).
    fn block_response(&self, bytes: Bytes, id: &BlockId, request: &HeaderMap) -> Response {
        let r = block_response(
            bytes,
            id,
            request,
            &self.cache_control,
            self.cdn_cache_control.as_ref(),
        );
        self.demand.touch(id, (self.clock)());
        r
    }
}

/// ADR 0046 rules 15 and 16: the `Cache-Control` of a block response, and the
/// `CDN-Cache-Control` sent with it when demand eviction is on. `S = E / 2` seconds.
fn cache_headers(demand: &Demand) -> (HeaderValue, Option<HeaderValue>) {
    if !demand.enabled() {
        return (
            HeaderValue::from_static("public, max-age=31536000, immutable"),
            None,
        );
    }
    let shared = demand.shared_max_age_s();
    // Digits and ASCII only: always valid header values; the fallback is never used.
    let value =
        |v: String| HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static("no-store"));
    (
        value(format!(
            "public, max-age=31536000, s-maxage={shared}, immutable"
        )),
        Some(value(format!("public, max-age={shared}, must-revalidate"))),
    )
}

/// The `200` of a held block, or the `304` when `request` holds a matching `If-None-Match`, with
/// `cache_control` and, when given, `CDN-Cache-Control` (ADR 0046 rules 15 and 16).
fn block_response(
    bytes: Bytes,
    id: &BlockId,
    request: &HeaderMap,
    cache_control: &HeaderValue,
    cdn_cache_control: Option<&HeaderValue>,
) -> Response {
    let etag = format!("\"{}\"", store::hex(id));
    let mut r = if none_match(request, &etag) {
        metrics::block_not_modified();
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let mut r = Response::new(Body::from(bytes));
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        r
    };
    let h = r.headers_mut();
    // ADR 0012 rule 32, ADR 0023 rule 13: only bytes that passed full validation, or C2 and C3,
    // reach this point. ADR 0046 rules 15 and 16: with demand eviction on, shared caches keep it
    // at most `S` without revalidation; private caches keep the one-year lifetime.
    h.insert(header::CACHE_CONTROL, cache_control.clone());
    if let Some(cdn) = cdn_cache_control {
        h.insert(HeaderName::from_static("cdn-cache-control"), cdn.clone());
    }
    // 64 hexadecimal digits in quotes: always a valid header value.
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    r
}

/// Whether `If-None-Match` in `request` matches `etag` (RFC 9110 §13.1.2): `*`, or a listed
/// entity tag equal to it under the weak comparison this header uses (a `W/` prefix is ignored).
/// Every field line counts; a line that is not visible ASCII is ignored. Tags are split at commas:
/// a client tag that contains a comma can only fail to match, never match ours, which has none.
fn none_match(request: &HeaderMap, etag: &str) -> bool {
    request
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Security review M-1: ids that PoW makes equal in their leading bytes still spread over the
    /// stripes, by their last byte.
    #[test]
    fn stripe_uses_the_last_byte() {
        let id = |last: u8| {
            let mut b = [0u8; 32];
            b[31] = last;
            BlockId::from_bytes(b)
        };
        assert_ne!(stripe(&id(1)), stripe(&id(2)));
        for k in 0..=u8::MAX {
            assert_eq!(stripe(&id(k)), usize::from(k) % ID_STRIPES);
        }
    }

    /// RFC 9110 §13.1.2: `*`, the exact tag, its weak form, any element of a list or of a second
    /// field line match; another tag, an unquoted id, another case and no header do not.
    #[test]
    fn if_none_match_forms() {
        let etag = format!("\"{}\"", "ab".repeat(32));
        let check = |lines: &[&str]| {
            let mut h = HeaderMap::new();
            for l in lines {
                h.append(header::IF_NONE_MATCH, HeaderValue::from_str(l).unwrap());
            }
            none_match(&h, &etag)
        };
        assert!(check(&["*"]));
        assert!(check(&[&etag]));
        assert!(check(&[&format!("W/{etag}")]));
        assert!(check(&[&format!("\"x\", {etag} ,\"y\"")]));
        assert!(check(&["\"x\"", &etag]));
        assert!(!check(&[]));
        assert!(!check(&["\"x\""]));
        assert!(!check(&[&"ab".repeat(32)]), "unquoted");
        assert!(!check(&[&format!("\"{}\"", "AB".repeat(32))]), "case");
        assert!(!check(&["\"x,\""]));
    }

    /// ADR 0018 clarification M1: an orphan repair that the writer queue refuses (the relay is
    /// stopping) is a deferred repair, counted in `index_repairs_deferred_total`, not a `503`
    /// refusal in `http_refused_total{reason="index_queue"}`.
    #[test]
    fn refused_orphan_insert_is_a_deferred_repair() {
        use crate::index::RedbIndex;
        use crate::pool::IndexPool;
        let dir = std::env::temp_dir().join(format!("sbtp-blocks-orphan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings::load(Vec::<std::ffi::OsString>::new(), Vec::new()).unwrap();
        let index_file = dir.join("index.redb");
        let index = Arc::new(RedbIndex::open(&index_file, 1 << 20).unwrap());
        let pool = IndexPool::start(&index, &settings).unwrap();
        let store = Store::open(&dir, index_file, settings.max_store_bytes).unwrap();
        let relay = Relay::new(&settings, store, pool.handle()).unwrap();
        assert!(pool.shutdown().is_ok());
        let k = sbtp_core::SigningKey::from_bytes(&[9; 32]);
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .payload(b"orphan")
            .build(&k, 0)
            .unwrap();
        let block = sbtp_core::parse(&bytes).unwrap();
        let (deferred, refused) = (
            metrics::index_repairs_deferred_total(),
            metrics::refused_total(Refused::IndexQueue),
        );
        relay.index_orphan(&BlockId::from_bytes([7; 32]), &block);
        assert!(metrics::index_repairs_deferred_total() > deferred);
        assert_eq!(metrics::refused_total(Refused::IndexQueue), refused);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
