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
//! after an unclean shutdown suspends it the same way, and so does a start with no demand history
//! (security review 2026-11-21, M-1): the first start after the upgrade that added the demand
//! tables or this record, and every start that turns `demand_eviction` from off to on, since
//! reads were not recorded while it was off. The suspension end is one integer in memory; a later
//! loss only moves it forward. A clean shutdown writes it to the index and the next start restores
//! it (L-1), so that a clean restart does not cancel a running suspension ([`StartState`]).
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

/// What the index says about the previous run, for the suspensions applied at start-up
/// ([`Demand::start`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartState {
    /// The previous run did not close the index cleanly (rule 13).
    pub unclean: bool,
    /// The start-up migration gave demand entries to at least one block (an index written before
    /// ADR 0046): their `last_demand` is an acceptance time, not a demand (M-1).
    pub migrated: bool,
    /// The `demand_eviction` setting of the previous start, `None` when none was recorded (M-1).
    pub previous: Option<bool>,
    /// The index holds no block: a new index has no demand to protect.
    pub empty: bool,
    /// The suspension end written at the last clean close, `0` when none (L-1).
    pub suspended_until: u64,
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
    /// The last demand pass was stuck (`demand_stuck`): it could not make room. Cleared by a pass
    /// that deletes a block, or once at or below the low-water mark (security review
    /// 2026-11-21, L-4).
    stuck: AtomicBool,
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
            stuck: AtomicBool::new(false),
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
        static LOG: Throttle = Throttle::new();
        metrics::demand_lost(n);
        if let Some(fields) = self.suspend(self.two_epochs(now), now, "lost") {
            log::throttled(&LOG, Event::DemandSuspended, &fields, None);
        }
    }

    /// Rule 13: a start after an unclean shutdown, at `now`.
    pub fn unclean_start(&self, now: u64) {
        self.start(
            &StartState {
                unclean: true,
                previous: Some(true),
                ..StartState::default()
            },
            now,
        );
    }

    /// The suspensions of a start at `now` (rule 13; security review 2026-11-21, M-1 and L-1),
    /// each logged once as `demand_suspended` with its `cause`: `unclean_start`; `no_history`
    /// (the migration ran, or no `demand_eviction` value was recorded, on an index that holds
    /// blocks); `enabled` (`demand_eviction` was off at the previous start); `restored` (the
    /// suspension written at the last clean close has not ended). Nothing with demand eviction
    /// off. The first three suspend until `now + 2 × E`: a demand made before this start may
    /// have gone unrecorded, and two epochs cover it (rule 13).
    pub fn start(&self, s: &StartState, now: u64) {
        if !self.enabled {
            return;
        }
        let two = self.two_epochs(now);
        let mut causes: Vec<(u64, &'static str)> = Vec::with_capacity(4);
        if s.unclean {
            causes.push((two, "unclean_start"));
        }
        if s.migrated || (s.previous.is_none() && !s.empty) {
            causes.push((two, "no_history"));
        } else if s.previous == Some(false) {
            causes.push((two, "enabled"));
        }
        // Security review 2026-11-21 pre-push, I-1: a stored end written while the wall clock was
        // far ahead is capped at two epochs from now; no single cause suspends for longer (D2).
        if s.suspended_until > now {
            causes.push((s.suspended_until.min(two), "restored"));
        }
        for (until, cause) in causes {
            // Once per start and cause: not throttled, so that every cause is seen.
            let _ = self.suspend(until, now, cause);
            log::emit(
                Event::DemandSuspended,
                &[
                    ("cause", Value::Str(cause)),
                    ("duration_ms", Value::Int(until.saturating_sub(now))),
                ],
            );
        }
    }

    fn two_epochs(&self, now: u64) -> u64 {
        now.saturating_add(self.epoch_ms.saturating_mul(2))
    }

    /// Moves the suspension end forward to `until`; the fields of the `demand_suspended` line
    /// when it moved.
    fn suspend(
        &self,
        until: u64,
        now: u64,
        cause: &'static str,
    ) -> Option<[(&'static str, Value<'static>); 2]> {
        let before = self.suspended_until.fetch_max(until, Ordering::SeqCst);
        metrics::set_demand_suspended(true);
        (until > before).then(|| {
            [
                ("cause", Value::Str(cause)),
                ("duration_ms", Value::Int(until.saturating_sub(now))),
            ]
        })
    }

    /// Whether rule 13 suspends demand eviction at `now`; sets the `demand_suspended` gauge.
    #[must_use]
    pub fn suspended(&self, now: u64) -> bool {
        let s = self.suspended_at(now);
        metrics::set_demand_suspended(s);
        s
    }

    /// Whether rule 13 suspends demand eviction at `now`: one atomic load, nothing else (the
    /// per-candidate check of a demand pass, security review 2026-11-21, L-2).
    #[must_use]
    pub fn suspended_at(&self, now: u64) -> bool {
        now < self.suspended_until.load(Ordering::SeqCst)
    }

    /// ADR 0046 rule 8 (MAY) as narrowed by security review 2026-11-21, L-4: a `507` carries
    /// `Retry-After` only while demand eviction is on, neither suspended at `now` nor stuck, so
    /// that the next sweeper run can make room. The caller also checks the high-water mark.
    #[must_use]
    pub fn retry_after_useful(&self, now: u64) -> bool {
        self.enabled && !self.suspended_at(now) && !self.stuck()
    }

    /// Whether the last demand pass was stuck.
    #[must_use]
    pub fn stuck(&self) -> bool {
        self.stuck.load(Ordering::Relaxed)
    }

    pub(crate) fn set_stuck(&self, on: bool) {
        self.stuck.store(on, Ordering::Relaxed);
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

    /// Sets the draining state; at or below the low-water mark (`false`), a stuck pass is over.
    pub(crate) fn set_draining(&self, on: bool) {
        self.draining.store(on, Ordering::Relaxed);
        if !on {
            self.set_stuck(false);
        }
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
        d.start(
            &StartState {
                previous: Some(false),
                suspended_until: 99,
                ..StartState::default()
            },
            0,
        );
        assert!(!d.suspended(1));
        assert!(!d.retry_after_useful(1));
    }

    /// Security review 2026-11-21, M-1 and L-1: the start-up suspensions, each `2 × E` from the
    /// start except a restored one, which keeps its end; none on a new index or a plain restart.
    #[test]
    fn start_suspensions() {
        let at = |s: StartState| {
            let d = Demand::new(&settings(&[])).unwrap();
            let e = d.epoch_ms();
            d.start(&s, 10 * e);
            (d.suspended_until(), e)
        };
        let base = StartState {
            previous: Some(true),
            ..StartState::default()
        };
        let (until, e) = at(base);
        assert_eq!(until, 0, "a plain restart");
        assert_eq!(
            at(StartState {
                previous: None,
                empty: true,
                ..base
            })
            .0,
            0,
            "a new index"
        );
        let two = 12 * e;
        for s in [
            StartState {
                unclean: true,
                ..base
            },
            StartState {
                migrated: true,
                ..base
            },
            StartState {
                previous: None,
                ..base
            },
            StartState {
                previous: None,
                migrated: true,
                empty: true,
                ..base
            },
            StartState {
                previous: Some(false),
                ..base
            },
            StartState {
                previous: Some(false),
                empty: true,
                ..base
            },
        ] {
            assert_eq!(at(s).0, two, "{s:?}");
        }
        // Restored: kept within two epochs of the start, ignored once ended.
        assert_eq!(
            at(StartState {
                suspended_until: 11 * e,
                ..base
            })
            .0,
            11 * e
        );
        // Pre-push review I-1: an end written under a wall clock far ahead (here, years) is
        // capped at two epochs from the start.
        for far in [13 * e, 10 * e + 1_000 * e, u64::MAX] {
            assert_eq!(
                at(StartState {
                    suspended_until: far,
                    ..base
                })
                .0,
                two,
                "{far}"
            );
        }
        assert_eq!(
            at(StartState {
                unclean: true,
                suspended_until: 11 * e,
                ..base
            })
            .0,
            two
        );
        assert_eq!(
            at(StartState {
                suspended_until: 10 * e,
                ..base
            })
            .0,
            0,
            "ended at the start"
        );
    }

    /// Security review 2026-11-21, L-4: `Retry-After` is useful only while demand eviction is
    /// neither suspended nor stuck.
    #[test]
    fn retry_after_only_when_room_can_come() {
        let d = Demand::new(&settings(&[])).unwrap();
        let e = d.epoch_ms();
        assert!(d.retry_after_useful(e));
        d.set_stuck(true);
        assert!(!d.retry_after_useful(e));
        d.set_stuck(false);
        d.lost(1, e);
        assert!(d.suspended_at(e) && !d.retry_after_useful(e));
        assert!(!d.retry_after_useful(3 * e - 1));
        assert!(d.retry_after_useful(3 * e));
    }
}
