//! Demand recording for eviction by least recent demand (ADR 0046 rules 9 to 14, 21 and 25).
//!
//! The `GET`, `HEAD` and `PUT` paths never touch the index for demand: they insert the `block_id`
//! of a held block into [`Demand`], a set of at most `demand_touch_max` identifiers allocated once
//! at start-up. The sweeper task flushes it through the index writer when it is half full, when
//! an epoch ends, at every sweeper run and at a clean shutdown (rule 12), in chunks of
//! [`FLUSH_CHUNK`] identifiers so that a flush never copies the whole set.
//!
//! A demand that cannot be recorded (the set is full, or a flush failed) is lost: it is counted
//! (`demand_lost_total`) and demand eviction is suspended until `now + 2 × E` (rule 13). A start
//! after an unclean shutdown suspends it the same way. The suspension end is one integer in
//! memory; a later loss only moves it forward.
//!
//! The table is open addressing with linear probing over `2 × demand_touch_max` slots (rounded up
//! to a power of two), never resized, with removal by backward shift (no deletion marker), as the
//! limiter's table (`limiter.rs`, ADR 0027 clarification T2). Slots are hashed with the standard
//! `RandomState` (keyed `SipHash`): a client that grinds block identifiers cannot make them
//! collide. Only identifiers of blocks the relay holds and has just served or accepted reach it,
//! so a flood of unknown identifiers (`404`) never fills it (security review scope of rule 21).

use std::collections::TryReserveError;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sbtp_core::BlockId;
use tokio::sync::Notify;

use crate::config::Settings;
use crate::log::{self, Event, Throttle, Value};
use crate::metrics;

/// Identifiers taken from the set per index transaction of a flush. The flush buffer is the
/// only memory a flush adds: `FLUSH_CHUNK × 32` bytes.
pub const FLUSH_CHUNK: usize = 1_024;

/// The empty slot. No block has this identifier: it would need 256 leading zero bits of BLAKE3
/// output (spec §3.3), so [`Demand::touch`] ignores it.
const EMPTY: [u8; 32] = [0; 32];

/// The slots of a set of `max` identifiers: twice `max`, rounded up to a power of two.
fn slots_for(max: u64) -> u64 {
    max.max(1)
        .saturating_mul(2)
        .checked_next_power_of_two()
        .unwrap_or(u64::MAX)
}

/// ADR 0046 rule 25: the bytes of the demand set of `demand_touch_max = max` (32 bytes per slot,
/// allocated at start-up) plus one flush chunk. This is the layout of [`Demand`], not an estimate.
#[must_use]
pub fn memory_bytes(max: u64) -> u64 {
    slots_for(max)
        .saturating_mul(32)
        .saturating_add(FLUSH_CHUNK as u64 * 32)
}

/// A failed demand write (a flush chunk, or the demand of a `PUT` answered `200`): counted in
/// `index_write_errors_total{op="demand"}` and logged as `index_write_failed` with `op=demand`,
/// throttled (ADR 0021 rule 7). The caller counts the lost demands.
pub(crate) fn write_failed(errno: Option<u64>) {
    static LOG: Throttle = Throttle::new();
    metrics::index_write_error(metrics::IndexOp::Demand);
    let mut fields = vec![("op", Value::Str(metrics::IndexOp::Demand.name()))];
    if let Some(n) = errno {
        fields.push(("errno", Value::Int(n)));
    }
    log::throttled(&LOG, Event::IndexWriteFailed, &fields, None);
}

/// The start, in Unix milliseconds, of the epoch of length `epoch_ms` that holds `now` (rule 9).
#[must_use]
pub fn epoch_start(now: u64, epoch_ms: u64) -> u64 {
    now - now % epoch_ms.max(1)
}

/// The fixed-size table of identifiers.
#[derive(Debug)]
struct Table {
    slots: Vec<[u8; 32]>,
    len: usize,
    /// Most identifiers held: `demand_touch_max`.
    max: usize,
    /// The epoch start of the latest touch (rule 9). A flush records every identifier at it,
    /// which can only make `last_demand` later than the demand, never earlier.
    epoch: u64,
    /// Where the next flush chunk is taken from.
    cursor: usize,
    hasher: RandomState,
}

impl Table {
    fn with_room(max: usize) -> Result<Self, TryReserveError> {
        let n = usize::try_from(slots_for(max as u64)).unwrap_or(usize::MAX);
        let mut slots = Vec::new();
        slots.try_reserve_exact(n)?;
        slots.resize(n, EMPTY);
        Ok(Self {
            slots,
            len: 0,
            max,
            epoch: 0,
            cursor: 0,
            hasher: RandomState::new(),
        })
    }

    fn home(&self, id: &[u8; 32]) -> usize {
        let n = self.slots.len().max(1) as u64;
        usize::try_from(self.hasher.hash_one(id) % n).unwrap_or(0)
    }

    fn next(&self, i: usize) -> usize {
        if i + 1 >= self.slots.len() { 0 } else { i + 1 }
    }

    fn distance(&self, from: usize, to: usize) -> usize {
        if to >= from {
            to - from
        } else {
            to + self.slots.len() - from
        }
    }

    /// The slot of `id`, if present. Ends at the first empty slot: at least half are empty.
    fn find(&self, id: &[u8; 32]) -> Option<usize> {
        let mut i = self.home(id);
        loop {
            match self.slots.get(i)? {
                s if *s == EMPTY => return None,
                s if s == id => return Some(i),
                _ => i = self.next(i),
            }
        }
    }

    /// Inserts `id`, which is not present; `false` when `max` identifiers are held.
    fn insert(&mut self, id: [u8; 32]) -> bool {
        if self.len >= self.max || self.len >= self.slots.len() / 2 {
            return false;
        }
        let mut i = self.home(&id);
        loop {
            match self.slots.get_mut(i) {
                Some(slot) if *slot == EMPTY => {
                    *slot = id;
                    self.len += 1;
                    return true;
                }
                Some(_) => i = self.next(i),
                None => return false,
            }
        }
    }

    /// Empties slot `hole`, then moves back the identifiers of its cluster that the hole would
    /// make unreachable (backward shift). Identifiers only move to slots at or after `hole`
    /// within the cluster.
    fn remove_at(&mut self, mut hole: usize) {
        let Some(slot) = self.slots.get_mut(hole) else {
            return;
        };
        if *slot == EMPTY {
            return;
        }
        *slot = EMPTY;
        self.len -= 1;
        let mut j = self.next(hole);
        while let Some(k) = self.slots.get(j).copied() {
            if k == EMPTY {
                break;
            }
            let start = self.home(&k);
            if self.distance(start, j) >= self.distance(hole, j) {
                self.slots.swap(hole, j);
                hole = j;
            }
            j = self.next(j);
        }
    }

    /// Moves up to [`FLUSH_CHUNK`] identifiers into `out`, from the cursor on. Returns `false`
    /// once the cursor has passed the last slot: identifiers inserted behind it wait for the next
    /// flush.
    fn drain_chunk(&mut self, out: &mut Vec<BlockId>) -> bool {
        while out.len() < FLUSH_CHUNK {
            let Some(id) = self.slots.get(self.cursor).copied() else {
                return false;
            };
            if id == EMPTY {
                self.cursor += 1;
            } else {
                out.push(BlockId(id));
                // The backward shift may move an identifier into this slot: it is looked at
                // again before the cursor moves on.
                self.remove_at(self.cursor);
            }
        }
        true
    }
}

/// The demand state of a relay (ADR 0046 rules 9 to 14): the set, the suspension end, the
/// flush request and the hysteresis of the watermarks (rule 5).
#[derive(Debug)]
pub struct Demand {
    enabled: bool,
    epoch_ms: u64,
    table: Mutex<Table>,
    /// Rule 13: demand eviction does not run before this time (Unix milliseconds).
    suspended_until: AtomicU64,
    flush_requested: AtomicBool,
    flush: Notify,
    /// Rule 5: set when the store went above the high-water mark, cleared once at or below the
    /// low-water mark.
    draining: AtomicBool,
}

impl Demand {
    /// The demand state of `s`. With demand eviction off, the set holds nothing and nothing is
    /// recorded.
    ///
    /// # Errors
    ///
    /// The set could not be allocated: the relay does not start (as the limiter table, ADR 0027
    /// clarification T2).
    pub fn new(s: &Settings) -> Result<Self, TryReserveError> {
        let max = if s.demand_eviction {
            usize::try_from(s.demand_touch_max).unwrap_or(usize::MAX)
        } else {
            0
        };
        let table = if max == 0 {
            Table {
                slots: Vec::new(),
                len: 0,
                max: 0,
                epoch: 0,
                cursor: 0,
                hasher: RandomState::new(),
            }
        } else {
            Table::with_room(max)?
        };
        Ok(Self {
            enabled: s.demand_eviction,
            epoch_ms: s.demand_epoch_ms.max(1),
            table: Mutex::new(table),
            suspended_until: AtomicU64::new(0),
            flush_requested: AtomicBool::new(false),
            flush: Notify::new(),
            draining: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether demand eviction is on (`demand_eviction`).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The demand epoch `E`, in milliseconds.
    #[must_use]
    pub fn epoch_ms(&self) -> u64 {
        self.epoch_ms
    }

    /// Rule 15: the shared-cache lifetime `S = E / 2`, in seconds, rounded down.
    #[must_use]
    pub fn shared_max_age_s(&self) -> u64 {
        self.epoch_ms / 2 / 1_000
    }

    /// Rules 10 to 13: one demand of the held block `id` at `now`. Recorded once per flush
    /// window whatever the client; a full set loses it and suspends demand eviction.
    pub fn touch(&self, id: &BlockId, now: u64) {
        if !self.enabled || id.as_bytes() == &EMPTY {
            return;
        }
        let epoch = epoch_start(now, self.epoch_ms);
        let mut t = self.lock();
        let new_epoch = epoch > t.epoch;
        let had_entries = t.len > 0;
        if new_epoch {
            t.epoch = epoch;
        }
        let stored = t.find(id.as_bytes()).is_some() || t.insert(*id.as_bytes());
        let (len, max) = (t.len, t.max);
        drop(t);
        metrics::set_demand_touch_entries(len as u64);
        if !stored {
            self.lost(1, now);
            return;
        }
        // Rule 12: at half capacity, and when an epoch ended with identifiers of the last one.
        if len >= max / 2 || (new_epoch && had_entries) {
            self.request_flush();
        }
    }

    /// Whether `id` waits in the set (the re-check of rule 22).
    #[must_use]
    pub fn contains(&self, id: &BlockId) -> bool {
        self.enabled && self.lock().find(id.as_bytes()).is_some()
    }

    /// Identifiers in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Rule 13: `n` demands could not be recorded at `now`. Counted; demand eviction suspended
    /// until `now + 2 × E`.
    pub fn lost(&self, n: u64, now: u64) {
        metrics::demand_lost(n);
        self.suspend(now.saturating_add(self.epoch_ms.saturating_mul(2)), "lost");
    }

    /// Rule 13: a start after an unclean shutdown, at `now`.
    pub fn unclean_start(&self, now: u64) {
        if self.enabled {
            self.suspend(
                now.saturating_add(self.epoch_ms.saturating_mul(2)),
                "unclean_start",
            );
        }
    }

    fn suspend(&self, until: u64, cause: &'static str) {
        static LOG: Throttle = Throttle::new();
        let before = self.suspended_until.fetch_max(until, Ordering::SeqCst);
        metrics::set_demand_suspended(true);
        if until > before {
            log::throttled(
                &LOG,
                Event::DemandSuspended,
                &[
                    ("cause", Value::Str(cause)),
                    ("duration_ms", Value::Int(self.epoch_ms.saturating_mul(2))),
                ],
                None,
            );
        }
    }

    /// Whether rule 13 suspends demand eviction at `now`; sets the `demand_suspended` gauge.
    #[must_use]
    pub fn suspended(&self, now: u64) -> bool {
        let s = now < self.suspended_until.load(Ordering::SeqCst);
        metrics::set_demand_suspended(s);
        s
    }

    /// The end of the current suspension, Unix milliseconds (0: none yet).
    #[must_use]
    pub fn suspended_until(&self) -> u64 {
        self.suspended_until.load(Ordering::SeqCst)
    }

    fn request_flush(&self) {
        if !self.flush_requested.swap(true, Ordering::AcqRel) {
            self.flush.notify_one();
        }
    }

    /// Waits until a flush is requested (half capacity or end of an epoch).
    pub async fn flush_requested(&self) {
        self.flush.notified().await;
    }

    /// Starts a flush: clears the request and puts the cursor at the first slot.
    pub(crate) fn begin_flush(&self) {
        self.flush_requested.store(false, Ordering::Release);
        self.lock().cursor = 0;
    }

    /// Moves the next chunk of the flush into `out` (cleared first) and returns the epoch start
    /// to record it at; `None` once the flush has passed every slot and `out` is empty.
    pub(crate) fn drain_chunk(&self, out: &mut Vec<BlockId>) -> Option<u64> {
        out.clear();
        let mut t = self.lock();
        let more = t.drain_chunk(out);
        let (epoch, len) = (t.epoch, t.len);
        drop(t);
        metrics::set_demand_touch_entries(len as u64);
        (more || !out.is_empty()).then_some(epoch)
    }

    /// Rule 5: whether the sweeper is evicting toward the low-water mark.
    #[must_use]
    pub(crate) fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    pub(crate) fn set_draining(&self, on: bool) {
        self.draining.store(on, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn id(n: u32) -> BlockId {
        let mut b = [7u8; 32];
        b[..4].copy_from_slice(&n.to_be_bytes());
        BlockId(b)
    }

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let env = pairs
            .iter()
            .map(|(k, v)| (format!("SBTP_RELAY_{k}").into(), (*v).into()));
        Settings::load(Vec::<std::ffi::OsString>::new(), env).unwrap()
    }

    /// Rule 25 on `small`: 16,384 identifiers in 32,768 slots of 32 bytes, plus one chunk.
    #[test]
    fn memory_is_the_layout() {
        assert_eq!(memory_bytes(16_384), 32_768 * 32 + 32_768);
        assert_eq!(memory_bytes(1_024), 2_048 * 32 + 32_768);
        assert_eq!(memory_bytes(1_000), 2_048 * 32 + 32_768);
        let d = Demand::new(&settings(&[])).unwrap();
        assert_eq!(d.lock().slots.len(), 32_768);
        assert_eq!(d.lock().slots.capacity(), 32_768);
    }

    #[test]
    fn epochs_are_quantised() {
        assert_eq!(epoch_start(0, 10), 0);
        assert_eq!(epoch_start(9, 10), 0);
        assert_eq!(epoch_start(10, 10), 10);
        assert_eq!(epoch_start(u64::MAX, 10), u64::MAX - u64::MAX % 10);
    }

    /// Rule 11: one entry per block whatever the number of touches; rule 13: a full set loses
    /// the demand, counts it and suspends for `2 × E`; the table never grows.
    #[test]
    fn a_full_set_loses_and_suspends() {
        let d = Demand::new(&settings(&[("DEMAND_TOUCH_MAX", "1024")])).unwrap();
        let e = d.epoch_ms();
        let now = 10 * e;
        for _ in 0..3 {
            d.touch(&id(1), now);
        }
        assert_eq!(d.len(), 1);
        for n in 2..=1_024 {
            d.touch(&id(n), now);
        }
        assert_eq!(d.len(), 1_024);
        assert!(!d.suspended(now));
        let lost = metrics::demand_lost_total();
        d.touch(&id(1), now); // already held: not lost
        assert_eq!(metrics::demand_lost_total(), lost);
        d.touch(&id(5_000), now + 1);
        assert!(metrics::demand_lost_total() > lost);
        assert!(d.suspended(now + 1));
        assert!(d.suspended(now + 1 + 2 * e - 1));
        assert!(!d.suspended(now + 1 + 2 * e));
        assert_eq!(d.lock().slots.len(), 2_048);
    }

    /// A flush drains every identifier present at its start, in chunks, and leaves the table
    /// reachable for the rest (backward shift under removal at the cursor).
    #[test]
    fn flush_drains_every_identifier() {
        let d = Demand::new(&settings(&[("DEMAND_TOUCH_MAX", "4096")])).unwrap();
        let now = 3 * d.epoch_ms() + 5;
        for n in 0..3_000 {
            d.touch(&id(n), now);
        }
        d.begin_flush();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        while let Some(epoch) = d.drain_chunk(&mut out) {
            assert_eq!(epoch, 3 * d.epoch_ms());
            assert!(out.len() <= FLUSH_CHUNK);
            for i in &out {
                assert!(seen.insert(*i), "drained twice");
            }
        }
        assert_eq!(seen.len(), 3_000);
        assert!(d.is_empty());
        d.touch(&id(9), now);
        assert!(d.contains(&id(9)));
        assert!(!d.contains(&id(10)));
    }

    /// With demand eviction off nothing is recorded or allocated.
    #[test]
    fn off_records_nothing() {
        let d = Demand::new(&settings(&[("DEMAND_EVICTION", "false")])).unwrap();
        d.touch(&id(1), 1_000);
        assert!(d.is_empty());
        assert_eq!(d.lock().slots.capacity(), 0);
        d.unclean_start(0);
        assert!(!d.suspended(1));
    }
}
