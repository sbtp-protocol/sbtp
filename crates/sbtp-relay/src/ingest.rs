//! Ingest bounds against disk filling (ADR 0049): byte budgets per network group, always on, and
//! a global cap checked only while the store is at or above its low-water mark.
//!
//! Every bound is a token bucket counted in stored bytes (ADR 0013 rule 18, ADR 0025: the quota
//! cost of a block file). A bucket of rate `r` bytes per hour holds at most `r / 12` bytes (five
//! minutes) and starts full.
//!
//! - **Groups** (rules 1 to 5): the IPv6 /56 and /48, or the IPv4 /24, of the request's client key
//!   ([`ClientKey::groups`]). A `PUT` whose group bucket is at zero or below gets `429` before its
//!   body is read. Group buckets live in a second limiter table with the design of ADR 0027
//!   ([`KeyTable`] preallocated at start-up, order by full time, a full entry dropped first,
//!   O(log n)); when it is full of entries that are not full, a group not in it is neither checked
//!   nor charged (fail open): there is no shared overflow group.
//! - **Global cap** (rule 6): one bucket of rate `R`, checked at the storage step for a block that
//!   would be stored as new, only while the stored total is at or above the low-water mark; `503`
//!   with `Retry-After` of at most 300 s. Below the mark it still refills and is charged.
//!
//! No latch (rule 7): every refusal depends only on these buckets, which refill with time alone,
//! and on the stored total; nothing is persisted. No bucket ever goes below
//! `−put_max_in_flight × 70,000` bytes (rule 3). The buckets use a monotonic clock, so that a
//! step of the wall clock never stops a refill. Group keys live in memory only and are never
//! logged; no metric or event names a client or a network, and nothing about a writer's network
//! is stored with a block (rule 10).
//!
//! Levels are fixed-point: one byte is [`UNIT`] units (the milliseconds of one hour), and a bucket
//! of `r` bytes per hour gains `r` units per millisecond, so the arithmetic is exact in integers.

use std::collections::{BTreeSet, TryReserveError};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::client::ClientKey;
use crate::config::Settings;
use crate::limiter::KeyTable;
use crate::log::{self, Event, Throttle, Value};
use crate::metrics;

/// One byte, in units: the milliseconds of one hour.
const UNIT: i64 = 3_600_000;
/// ADR 0049 rule 3: the largest charge of one `PUT` counted by the floor of a bucket, in bytes.
const MAX_PUT_CHARGE: i64 = 70_000;
/// ADR 0049 rule 6: the largest `Retry-After` of a `503` of the global cap, in seconds.
pub const MAX_CAP_RETRY_AFTER_S: u64 = 300;

/// The rate, capacity and floor of one kind of bucket, in units.
#[derive(Clone, Copy, Debug)]
struct ByteRate {
    /// Bytes per hour, which is units per millisecond; at least 1.
    per_ms: i64,
    /// One twelfth of the hourly rate (rule 2).
    cap: i64,
    /// `−put_max_in_flight × 70,000` bytes (rule 3).
    floor: i64,
}

impl ByteRate {
    fn new(bytes_per_hour: u64, put_max_in_flight: u64) -> Self {
        let per_ms = i64::try_from(bytes_per_hour).unwrap_or(i64::MAX).max(1);
        let in_flight = i64::try_from(put_max_in_flight).unwrap_or(i64::MAX);
        Self {
            per_ms,
            cap: per_ms.saturating_mul(UNIT / 12),
            floor: in_flight
                .saturating_mul(MAX_PUT_CHARGE)
                .saturating_mul(UNIT)
                .saturating_neg(),
        }
    }

    /// `share` percent of `bytes_per_hour`.
    fn share(bytes_per_hour: u64, share_pct: u64, put_max_in_flight: u64) -> Self {
        let r = u128::from(bytes_per_hour) * u128::from(share_pct) / 100;
        Self::new(u64::try_from(r).unwrap_or(u64::MAX), put_max_in_flight)
    }
}

/// One byte bucket: its level in units and the clock of its last refill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bucket {
    level: i64,
    /// The ingest clock at the last refill, milliseconds.
    at: u64,
}

impl Bucket {
    /// A new bucket starts full (rule 2).
    fn full(r: &ByteRate, now: u64) -> Self {
        Self {
            level: r.cap,
            at: now,
        }
    }

    fn refill(&mut self, r: &ByteRate, now: u64) {
        let dt = i64::try_from(now.saturating_sub(self.at)).unwrap_or(i64::MAX);
        self.level = self
            .level
            .saturating_add(dt.saturating_mul(r.per_ms))
            .min(r.cap);
        self.at = self.at.max(now);
    }

    /// Rules 4 and 6: a bucket at zero or below refuses.
    fn open(&self) -> bool {
        self.level > 0
    }

    fn is_full(&self, r: &ByteRate) -> bool {
        self.level >= r.cap
    }

    /// The ingest clock at which the bucket is full, from the level left by the last change. A
    /// refill does not move it while the bucket is not full, so it is the entry's place in the
    /// order of full times (ADR 0027 rule 2).
    fn full_at(&self, r: &ByteRate) -> u64 {
        let deficit = u64::try_from(r.cap.saturating_sub(self.level)).unwrap_or(0);
        let per_ms = u64::try_from(r.per_ms).unwrap_or(1);
        self.at.saturating_add(deficit.div_ceil(per_ms))
    }

    /// Rules 4 and 6: the seconds until the bucket is back above zero, rounded up, at least 1.
    fn retry_after_s(&self, r: &ByteRate) -> u64 {
        let deficit = u64::try_from(self.level.saturating_neg()).unwrap_or(0);
        let per_ms = u64::try_from(r.per_ms).unwrap_or(1);
        // The first millisecond at which `level + t × per_ms > 0`.
        let ms = deficit / per_ms + 1;
        ms.div_ceil(1_000).max(1)
    }

    /// Rule 3: `bytes` stored, never below the floor.
    fn charge(&mut self, r: &ByteRate, bytes: u64) {
        let units = i64::try_from(bytes)
            .unwrap_or(i64::MAX)
            .saturating_mul(UNIT);
        self.level = self.level.saturating_sub(units).max(r.floor);
    }

    /// The level in whole bytes, 0 when at or below zero (the `ingest_bucket_bytes` gauge).
    fn bytes(&self) -> u64 {
        u64::try_from(self.level / UNIT).unwrap_or(0)
    }
}

/// The `level` label of `ingest_group_limited_total` (rule 16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupLevel {
    /// An IPv6 /56.
    V6_56,
    /// An IPv6 /48.
    V6_48,
    /// An IPv4 /24.
    V4_24,
}

impl GroupLevel {
    /// Every level, in the order of the counters.
    pub const ALL: [Self; 3] = [Self::V6_56, Self::V6_48, Self::V4_24];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::V6_56 => "v6_56",
            Self::V6_48 => "v6_48",
            Self::V4_24 => "v4_24",
        }
    }

    fn of(group: &ClientKey) -> Self {
        if group.is_ipv4() {
            Self::V4_24
        } else if group.prefix() == 56 {
            Self::V6_56
        } else {
            Self::V6_48
        }
    }
}

/// A `PUT` of a group whose bucket is at zero or below (rule 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupLimited {
    /// The seconds until every refusing bucket is back above zero.
    pub retry_after_s: u64,
    /// The level of the bucket that refuses longest.
    pub level: GroupLevel,
}

/// What a `PUT` is charged to, decided before its body is read and carried to its storage step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ticket {
    /// Rules 2 to 7 are off (`ingest_bytes_per_hour = 0`), or the client key is in
    /// `rate_limit_exempt` (rule 1): never charged, never refused.
    Exempt,
    /// Rule 9: a block stored by replication (ADR 0048) has its own budget and is neither charged
    /// nor refused here. HOOK(ADR 0048): the replication fetcher passes this ticket to the storage
    /// step; no code stores a replicated block yet.
    Replicated,
    /// A `PUT` from a client: charged to the global bucket and to the groups checked by rule 4.
    /// A group left unchecked by rule 5 (full table) is `None` and is not charged.
    Client {
        /// The groups checked, in the order of [`ClientKey::groups`].
        groups: [Option<ClientKey>; 2],
    },
}

/// The second limiter table (rule 5): one bucket per group.
#[derive(Debug)]
struct Groups {
    map: KeyTable<Bucket>,
    /// ADR 0027 rule 2: `(full time, group)` of every group of `map`.
    order: BTreeSet<(u64, ClientKey)>,
}

/// A run of `503`s of the global cap, for the `ingest_capped` and `ingest_cap_ended` events.
#[derive(Clone, Copy, Debug)]
struct Episode {
    since: u64,
    refused: u64,
}

#[derive(Debug)]
struct Global {
    bucket: Bucket,
    episode: Option<Episode>,
}

/// The ingest bounds of one relay (ADR 0049).
#[derive(Debug)]
pub struct Ingest {
    /// `ingest_bytes_per_hour > 0`.
    enabled: bool,
    /// The /48 and /24 groups (`ingest_group_share_pct`).
    wide: ByteRate,
    /// The /56 groups (`ingest_group56_share_pct`).
    narrow: ByteRate,
    /// The global bucket (`R`).
    total: ByteRate,
    max_groups: usize,
    ipv6_prefix: u8,
    groups: Mutex<Groups>,
    global: Mutex<Global>,
    /// Milliseconds of a monotonic clock ([`log::now_ms`]; a test clock in tests).
    clock: fn() -> u64,
}

/// A panic under a lock leaves consistent levels: poisoning is ignored.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Ingest {
    /// The ingest bounds of `s`. Every value is in range after [`Settings::load`].
    ///
    /// # Errors
    ///
    /// The group table could not be allocated for `ingest_group_max` entries (rule 5, ADR 0027
    /// clarification T2): the relay does not start.
    pub fn from_settings(s: &Settings) -> Result<Self, TryReserveError> {
        let r = s.ingest_bytes_per_hour;
        let enabled = r > 0;
        let max_groups = if enabled {
            usize::try_from(s.ingest_group_max).unwrap_or(usize::MAX)
        } else {
            0
        };
        let total = ByteRate::new(r, s.put_max_in_flight);
        let clock: fn() -> u64 = log::now_ms;
        Ok(Self {
            enabled,
            wide: ByteRate::share(r, s.ingest_group_share_pct, s.put_max_in_flight),
            narrow: ByteRate::share(r, s.ingest_group56_share_pct, s.put_max_in_flight),
            total,
            max_groups,
            ipv6_prefix: u8::try_from(s.client_ipv6_prefix).unwrap_or(64),
            groups: Mutex::new(Groups {
                map: KeyTable::with_room(max_groups)?,
                order: BTreeSet::new(),
            }),
            global: Mutex::new(Global {
                bucket: Bucket::full(&total, clock()),
                episode: None,
            }),
            clock,
        })
    }

    /// Replaces the ingest clock (tests: a controllable monotonic clock). Every bucket is full
    /// again at the new clock's current time.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        let total = self.total;
        let g = self
            .global
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        g.bucket = Bucket::full(&total, clock());
        self
    }

    /// Whether rules 2 to 7 are on.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn rate_of(&self, group: &ClientKey) -> &ByteRate {
        match GroupLevel::of(group) {
            GroupLevel::V6_56 => &self.narrow,
            GroupLevel::V6_48 | GroupLevel::V4_24 => &self.wide,
        }
    }

    /// Rule 5, ADR 0027 rules 1 to 3: refills the bucket of `group`, applies `f` to it and moves
    /// the entry in the order. A group not in the table enters it full, after dropping the entry
    /// with the earliest full time if the table is full and that entry is full. Returns the bucket
    /// after `f`, or `None` when the group could not enter (fail open).
    fn touch(
        &self,
        t: &mut Groups,
        group: ClientKey,
        now: u64,
        f: impl FnOnce(&mut Bucket),
    ) -> Option<Bucket> {
        let r = *self.rate_of(&group);
        if let Some(b) = t.map.get_mut(&group) {
            let before = b.full_at(&r);
            b.refill(&r, now);
            f(b);
            let after = b.full_at(&r);
            let out = *b;
            if before != after {
                t.order.remove(&(before, group));
                t.order.insert((after, group));
            }
            return Some(out);
        }
        if t.map.len() >= self.max_groups {
            match t.order.first() {
                Some(&(full, victim)) if full <= now => {
                    t.order.remove(&(full, victim));
                    t.map.remove(&victim);
                }
                _ => return None,
            }
        }
        let mut b = Bucket::full(&r, now);
        f(&mut b);
        // The map has room for `max_groups` entries, so the insert always stores the group.
        if !t.map.insert(group, b) {
            return None;
        }
        t.order.insert((b.full_at(&r), group));
        Some(b)
    }

    /// Rules 1, 4 and 5, before the body of a `PUT` is read: the ticket of the request with client
    /// key `key` (`None`: exempt), or the `429` of a group whose bucket is at zero or below. Only
    /// the requests of that group are refused.
    ///
    /// # Errors
    ///
    /// A group of the request has no bytes left.
    pub fn check_groups(&self, key: Option<ClientKey>) -> Result<Ticket, GroupLimited> {
        let Some(key) = key.filter(|_| self.enabled) else {
            return Ok(Ticket::Exempt);
        };
        let now = (self.clock)();
        let mut checked = [None; 2];
        let mut refused: Option<GroupLimited> = None;
        let mut unchecked = false;
        {
            let mut t = lock(&self.groups);
            for (slot, group) in checked.iter_mut().zip(key.groups(self.ipv6_prefix)) {
                let Some(group) = group else { continue };
                let Some(b) = self.touch(&mut t, group, now, |_| {}) else {
                    unchecked = true;
                    continue;
                };
                *slot = Some(group);
                if !b.open() {
                    let retry_after_s = b.retry_after_s(self.rate_of(&group));
                    if refused.is_none_or(|r| retry_after_s > r.retry_after_s) {
                        refused = Some(GroupLimited {
                            retry_after_s,
                            level: GroupLevel::of(&group),
                        });
                    }
                }
            }
            metrics::set_ingest_group_entries(t.map.len() as u64);
        }
        if unchecked {
            metrics::ingest_group_unchecked();
        }
        if let Some(r) = refused {
            metrics::ingest_group_limited(r.level);
            return Err(r);
        }
        Ok(Ticket::Client { groups: checked })
    }

    /// Rule 6, at the storage step of a block that would be stored as new, after validation and
    /// after the held check: `total` is the stored total and `low_water` the low-water mark, in
    /// bytes. Below the mark nothing is refused.
    ///
    /// # Errors
    ///
    /// The global bucket has no bytes left: the `Retry-After` of the `503`, 1 to 300 seconds.
    pub fn check_cap(&self, ticket: &Ticket, total: u64, low_water: u64) -> Result<(), u64> {
        if !self.enabled {
            return Ok(());
        }
        let now = (self.clock)();
        let mut g = lock(&self.global);
        g.bucket.refill(&self.total, now);
        self.end_episode(&mut g, now);
        let active = total >= low_water;
        metrics::set_ingest_cap(active, g.bucket.bytes());
        if !matches!(ticket, Ticket::Client { .. }) || !active || g.bucket.open() {
            return Ok(());
        }
        let retry_after_s = g
            .bucket
            .retry_after_s(&self.total)
            .min(MAX_CAP_RETRY_AFTER_S);
        metrics::ingest_capped();
        if let Some(e) = &mut g.episode {
            e.refused = e.refused.saturating_add(1);
        } else {
            static LOG: Throttle = Throttle::new();
            g.episode = Some(Episode {
                since: now,
                refused: 1,
            });
            log::throttled(
                &LOG,
                Event::IngestCapped,
                &[("retry_after_s", Value::Int(retry_after_s))],
                None,
            );
        }
        Err(retry_after_s)
    }

    /// `ingest_cap_ended`, once the global bucket holds a full charge again after a run of `503`s.
    fn end_episode(&self, g: &mut Global, now: u64) {
        static LOG: Throttle = Throttle::new();
        if let Some(e) = g.episode.filter(|_| g.bucket.is_full(&self.total)) {
            g.episode = None;
            log::throttled(
                &LOG,
                Event::IngestCapEnded,
                &[
                    ("refused", Value::Int(e.refused)),
                    ("duration_ms", Value::Int(now.saturating_sub(e.since))),
                ],
                None,
            );
        }
    }

    /// Rules 3 and 6: a block stored as new (`201`, a re-acceptance included) adds `bytes` to the
    /// stored total; charged once, to the global bucket and to each group of `ticket`. Called
    /// under the lock of the block's `block_id`, so that concurrent `PUT`s of one block charge it
    /// once. Exempt and replicated blocks are not charged.
    pub fn charge(&self, ticket: &Ticket, bytes: u64) {
        let Ticket::Client { groups } = ticket else {
            return;
        };
        if !self.enabled {
            return;
        }
        let now = (self.clock)();
        {
            let mut g = lock(&self.global);
            g.bucket.refill(&self.total, now);
            g.bucket.charge(&self.total, bytes);
            metrics::ingest_bytes(bytes, g.bucket.bytes());
        }
        let mut t = lock(&self.groups);
        for group in groups.iter().flatten() {
            let r = *self.rate_of(group);
            // A group whose entry was dropped since its check (it was full) enters again full.
            let _ = self.touch(&mut t, *group, now, |b| b.charge(&r, bytes));
        }
        metrics::set_ingest_group_entries(t.map.len() as u64);
    }

    /// Entries of the group table (tests).
    #[cfg(test)]
    fn entries(&self) -> usize {
        lock(&self.groups).map.len()
    }

    /// The group table is consistent (tests): every entry is in the order at its full time, and
    /// the order holds nothing else.
    #[cfg(test)]
    fn consistent(&self) -> bool {
        let t = lock(&self.groups);
        t.map.len() == t.order.len()
            && t.map
                .iter()
                .all(|(k, b)| t.order.contains(&(b.full_at(self.rate_of(k)), *k)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::client::ClientPolicy;

    const MIB: u64 = 1 << 20;
    /// The quota cost of a full-size block (`store::cost` of about 65 KB).
    const BIG: u64 = 69_760;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let env: Vec<(OsString, OsString)> = pairs
            .iter()
            .map(|(k, v)| (OsString::from(format!("SBTP_RELAY_{k}")), OsString::from(v)))
            .collect();
        Settings::load(Vec::<OsString>::new(), env).unwrap()
    }

    /// A clock per test: each test uses its own static.
    macro_rules! clock {
        ($name:ident) => {
            static $name: AtomicU64 = AtomicU64::new(1_000_000);
            fn now() -> u64 {
                $name.load(Ordering::SeqCst)
            }
            #[allow(dead_code)]
            fn advance(ms: u64) {
                $name.fetch_add(ms, Ordering::SeqCst);
            }
        };
    }

    fn key(s: &str) -> ClientKey {
        ClientPolicy::new(Vec::new(), Vec::new(), 64, 8)
            .key(s.parse().unwrap())
            .unwrap()
    }

    /// `small` defaults: `R` = 200 MiB/h, /48 and /24 at 50 MiB/h (capacity 4,369,066 bytes),
    /// /56 at 20 MiB/h (capacity 1,747,626 bytes).
    fn small(clock: fn() -> u64) -> Ingest {
        Ingest::from_settings(&settings(&[]))
            .unwrap()
            .with_clock(clock)
    }

    /// Stores blocks of `bytes` from `key` until its groups refuse; returns how many were
    /// accepted.
    fn fill(i: &Ingest, k: ClientKey, bytes: u64) -> u64 {
        let mut n = 0;
        while let Ok(t) = i.check_groups(Some(k)) {
            i.charge(&t, bytes);
            n += 1;
            assert!(n < 1_000_000);
        }
        n
    }

    /// Rule 2: the capacity is five minutes of the hourly rate; a new group starts full; rule 4:
    /// at zero or below it refuses, with the seconds until it is back above zero.
    #[test]
    fn group_budget_and_retry_after() {
        clock!(C);
        let i = small(now);
        let k = key("192.0.2.1");
        // 50 MiB/h / 12 = 4,369,066 bytes: 62 full-size blocks reach zero or below.
        assert_eq!(fill(&i, k, BIG), 63);
        let Err(r) = i.check_groups(Some(k)) else {
            panic!("refused")
        };
        assert_eq!(r.level, GroupLevel::V4_24);
        // The level is at most one block below zero: 69,760 bytes at 50 MiB/h is 4.8 s.
        assert!((1..=5).contains(&r.retry_after_s), "{r:?}");
        advance(r.retry_after_s * 1_000);
        assert!(
            i.check_groups(Some(k)).is_ok(),
            "refilled after Retry-After"
        );
        assert!(i.consistent());
    }

    /// Rules 1 and 4, the self-blocking guarantee: only the flooding network is refused. Another
    /// /24, another /48, and another /56 of the same /48 are served.
    #[test]
    fn only_the_flooding_network_is_refused() {
        clock!(C);
        let i = small(now);
        let flood = key("2001:db8:1:100::1");
        assert!(fill(&i, flood, BIG) > 0);
        let Err(r) = i.check_groups(Some(flood)) else {
            panic!()
        };
        // The /56 (20 MiB/h) is drained first.
        assert_eq!(r.level, GroupLevel::V6_56);
        // Another /64 of the same /56: the same group, refused.
        assert!(i.check_groups(Some(key("2001:db8:1:1ff::1"))).is_err());
        // Another /56 of the same /48: its own /56 is full; the /48 had 20 MiB/h of 50 taken.
        assert!(i.check_groups(Some(key("2001:db8:1:200::1"))).is_ok());
        assert!(i.check_groups(Some(key("2001:db8:2::1"))).is_ok());
        assert!(i.check_groups(Some(key("198.51.100.1"))).is_ok());
        // Many /56s of one /48 drain the /48 (50 MiB/h): then the whole /48 is refused.
        for n in 0..=255_u32 {
            let _ = fill(&i, key(&format!("2001:db8:1:{n:x}00::1")), BIG);
        }
        let Err(r) = i.check_groups(Some(key("2001:db8:1:ff00::1"))) else {
            panic!()
        };
        assert_eq!(r.level, GroupLevel::V6_48);
        assert!(i.check_groups(Some(key("2001:db8:2::1"))).is_ok());
        assert!(i.consistent());
    }

    /// The self-blocking guarantee: a normal load of many networks is never refused. A peak of
    /// five times the ADR's 1,000-writer average (21 MB/h), and a whole carrier NAT pool behind one
    /// IPv4 address at the same peak, for two hours.
    #[test]
    fn a_normal_multi_network_load_is_never_refused() {
        clock!(C);
        let i = small(now);
        // 1,000 writers on 100 networks, 2 KB blocks (quota cost 4,224 bytes), 250 blocks per
        // writer per day at the peak: about 2.9 blocks per second in all, one every 344 ms.
        let networks: Vec<ClientKey> = (0..100_u32)
            .map(|n| {
                if n % 2 == 0 {
                    key(&format!("10.{}.{}.1", n / 256, n % 256))
                } else {
                    key(&format!("2001:db8:{n:x}::1"))
                }
            })
            .collect();
        let nat = key("203.0.113.9");
        for step in 0..21_000_u64 {
            let k = networks[usize::try_from(step % 100).unwrap()];
            let t = i.check_groups(Some(k)).unwrap();
            assert_eq!(i.check_cap(&t, 0, 0), Ok(()), "step {step}");
            i.charge(&t, 4_224);
            // The NAT pool: all 1,000 writers' peak through one address, 2.9 blocks per second.
            let t = i.check_groups(Some(nat)).unwrap();
            assert_eq!(i.check_cap(&t, 0, 0), Ok(()), "nat step {step}");
            i.charge(&t, 4_224);
            advance(344);
        }
        assert!(i.consistent());
    }

    /// Rule 7, the self-blocking guarantee: nothing latches. Groups and the global bucket drained
    /// far below zero are open again after refill alone, with no other call.
    #[test]
    fn nothing_latches_after_refill() {
        clock!(C);
        let i = small(now);
        let k = key("192.0.2.1");
        // Concurrent `PUT`s that all passed their check, then all charge: the floor bounds the
        // level (rule 3).
        // 300 full-size blocks (20.9 MB) also drain the global bucket (16.7 MiB).
        let tickets: Vec<Ticket> = (0..300).map(|_| i.check_groups(Some(k)).unwrap()).collect();
        for t in &tickets {
            i.charge(t, BIG);
        }
        let floor: u64 = 4 * 70_000; // `put_max_in_flight` on `small`.
        let Err(r) = i.check_groups(Some(k)) else {
            panic!()
        };
        // From the floor at 50 MiB/h: 280,000 bytes take 19.2 s.
        assert_eq!(r.retry_after_s, (floor * 3_600).div_ceil(50 * MIB));
        let Err(cap) = i.check_cap(&tickets[0], 1, 0) else {
            panic!()
        };
        assert!(cap <= MAX_CAP_RETRY_AFTER_S);
        advance(r.retry_after_s * 1_000);
        assert!(i.check_groups(Some(k)).is_ok());
        advance(cap * 1_000);
        assert_eq!(i.check_cap(&tickets[0], 1, 0), Ok(()));
    }

    /// Rule 6: the cap is off below the low-water mark; at or above it, a drained bucket refuses
    /// with `Retry-After` of at most 300 s; below it again, nothing is refused. The bucket is still
    /// charged below the mark.
    #[test]
    fn the_cap_is_off_below_low_water() {
        clock!(C);
        let i = Ingest::from_settings(&settings(&[("INGEST_GROUP_SHARE_PCT", "100")]))
            .unwrap()
            .with_clock(now);
        let low = 800;
        // 200 MiB/h / 12 = 16.7 MiB of capacity; from many groups, below the mark.
        let mut n = 0_u32;
        loop {
            let t = i
                .check_groups(Some(key(&format!("10.{}.{}.1", n / 256, n % 256))))
                .unwrap();
            assert_eq!(i.check_cap(&t, low - 1, low), Ok(()));
            i.charge(&t, BIG);
            n += 1;
            if n > 300 {
                break;
            }
        }
        let t = i.check_groups(Some(key("192.0.2.1"))).unwrap();
        assert_eq!(i.check_cap(&t, low - 1, low), Ok(()), "below the mark");
        let Err(s) = i.check_cap(&t, low, low) else {
            panic!("at the mark")
        };
        assert!((1..=MAX_CAP_RETRY_AFTER_S).contains(&s), "{s}");
        assert_eq!(i.check_cap(&t, low - 1, low), Ok(()), "below again");
        // Exempt and replicated blocks are never refused (rules 1 and 9).
        assert_eq!(i.check_cap(&Ticket::Exempt, low, low), Ok(()));
        assert_eq!(i.check_cap(&Ticket::Replicated, low, low), Ok(()));
    }

    /// Rule 6: `Retry-After` of the global cap is at most 300 s, also from the floor of a slow
    /// bucket.
    #[test]
    fn cap_retry_after_is_at_most_300_s() {
        clock!(C);
        let i = Ingest::from_settings(&settings(&[
            ("INGEST_BYTES_PER_HOUR", "1048576"),
            ("INGEST_GROUP_SHARE_PCT", "100"),
            ("INGEST_GROUP56_SHARE_PCT", "100"),
        ]))
        .unwrap()
        .with_clock(now);
        let t = i.check_groups(Some(key("192.0.2.1"))).unwrap();
        for _ in 0..10 {
            i.charge(&t, BIG);
        }
        assert_eq!(i.check_cap(&t, 1, 0), Err(MAX_CAP_RETRY_AFTER_S));
    }

    /// Rule 5: a full table of entries that are not full lets an unknown group pass, unchecked
    /// and uncharged (fail open); a full entry is dropped first, at once.
    #[test]
    fn a_full_group_table_fails_open() {
        clock!(C);
        let i = Ingest::from_settings(&settings(&[("INGEST_GROUP_MAX", "64")]))
            .unwrap()
            .with_clock(now);
        for n in 0..64_u32 {
            let t = i.check_groups(Some(key(&format!("10.0.{n}.1")))).unwrap();
            i.charge(&t, 4_224);
        }
        assert_eq!(i.entries(), 64);
        let t = i.check_groups(Some(key("192.0.2.1"))).unwrap();
        assert_eq!(t, Ticket::Client { groups: [None; 2] });
        i.charge(&t, BIG);
        assert_eq!(i.entries(), 64);
        // IPv6: neither group enters.
        let t = i.check_groups(Some(key("2001:db8::1"))).unwrap();
        assert_eq!(t, Ticket::Client { groups: [None; 2] });
        // 4,224 bytes at 50 MiB/h are back in 291 ms: the first entry is full, dropped at once.
        advance(291);
        let t = i.check_groups(Some(key("192.0.2.1"))).unwrap();
        assert!(matches!(
            t,
            Ticket::Client {
                groups: [Some(_), None]
            }
        ));
        assert_eq!(i.entries(), 64);
        assert!(i.consistent());
    }

    /// Rule 1: exempt keys and `R = 0` are never charged nor refused; the overflow key has no
    /// group; with `client_ipv6_prefix = 48` only the /48 is used.
    #[test]
    fn exempt_off_and_prefix_rules() {
        clock!(C);
        let i = small(now);
        assert_eq!(i.check_groups(None), Ok(Ticket::Exempt));
        i.charge(&Ticket::Exempt, u64::MAX);
        i.charge(&Ticket::Replicated, u64::MAX);
        assert_eq!(i.check_cap(&Ticket::Exempt, 1, 0), Ok(()));
        let t = i.check_groups(Some(key("192.0.2.1"))).unwrap();
        assert_eq!(
            i.check_cap(&t, 1, 0),
            Ok(()),
            "exempt charges did not drain it"
        );
        assert_eq!(i.entries(), 1);

        let off = Ingest::from_settings(&settings(&[("INGEST_BYTES_PER_HOUR", "0")]))
            .unwrap()
            .with_clock(now);
        let k = key("192.0.2.1");
        for _ in 0..1_000 {
            let t = off.check_groups(Some(k)).unwrap();
            assert_eq!(t, Ticket::Exempt);
            off.charge(&t, BIG);
        }
        assert_eq!(off.check_cap(&Ticket::Exempt, 1, 0), Ok(()));

        assert_eq!(ClientKey::OVERFLOW.groups(64), [None, None]);
        let v6 = key("2001:db8:1:2::1");
        let [g56, g48] = v6.groups(64);
        assert_eq!((g56.unwrap().prefix(), g48.unwrap().prefix()), (56, 48));
        assert_eq!(
            v6.groups(56).map(|g| g.map(|g| g.prefix())),
            [Some(56), Some(48)]
        );
        assert_eq!(
            v6.groups(48).map(|g| g.map(|g| g.prefix())),
            [None, Some(48)]
        );
        let [g24, none] = key("192.0.2.200").groups(64);
        assert_eq!((g24, none), (key("192.0.2.1").groups(64)[0], None));
        assert_ne!(
            g24,
            Some(key("192.0.2.0")),
            "a /24 group is not the /32 client key"
        );
        // An IPv4-mapped IPv6 address is its IPv4 /24 (rule 1).
        assert_eq!(
            key("::ffff:192.0.2.7").groups(64),
            key("192.0.2.1").groups(64)
        );
    }

    /// Rule 15, ADR 0027 clarification T1: the estimate of one group entry in `config.rs` covers
    /// the map at most half full (two slots per entry, each with its occupancy) and two elements
    /// of the order of full times. A change of the types that outgrows it fails here.
    #[test]
    fn the_group_entry_estimate_covers_the_types() {
        use std::mem::size_of;
        let map_element = size_of::<(ClientKey, Bucket)>();
        assert_eq!(map_element, 40);
        let slot = size_of::<Option<(ClientKey, Bucket)>>();
        assert!(slot <= map_element + 1, "{slot}");
        let order_element = size_of::<(u64, ClientKey)>();
        let needed = 2 * (map_element + 1) + 2 * order_element;
        assert_eq!(needed, 146);
        let estimate = usize::try_from(crate::config::EST_GROUP_ENTRY).unwrap();
        assert!(estimate >= needed, "{estimate} < {needed}");
    }
}
