//! Per-client token buckets (ADR 0018 rules 21 and 29; ADR 0020 rules 22 to 24; ADR 0027).
//!
//! Each client key has one bucket per class (`block`, `query`, `put`). A bucket holds at most
//! `rate_<class>_burst` tokens and refills at `rate_<class>_per_min` tokens per minute; a request
//! takes one token of its class. The table holds at most `rate_limit_max_clients` keys: when it is
//! full, a key whose three buckets are full is dropped for the new key, and otherwise requests of
//! unknown keys share one overflow key with the allowance of a single client. State lives in
//! memory only; no address is logged here.
//!
//! ADR 0027: no operation passes over the table. Next to the map, the keys are ordered by their
//! full time (the time at which their three buckets are full again), so the earliest one is found
//! in O(log n). Keys with a unit in flight (ADR 0019 rule 31) are left out of that order: they are
//! never dropped.
//!
//! Levels are fixed-point: one token is [`UNIT`] units, and a bucket gains `per_min` units per
//! millisecond, so the arithmetic is exact in integers.

use std::collections::{BTreeSet, HashMap, TryReserveError};
use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use crate::client::ClientKey;
use crate::config::Settings;
use crate::server::RequestClass;

/// One token, in units: the milliseconds of one minute.
const UNIT: u64 = 60_000;

/// The rate of one class.
#[derive(Clone, Copy, Debug)]
struct Rate {
    per_min: u64,
    /// `burst × UNIT`.
    cap: u64,
}

/// The three buckets of one key, refilled together.
#[derive(Clone, Copy, Debug)]
struct Entry {
    level: [u64; 3],
    /// The limiter clock at the last refill, milliseconds.
    at: u64,
}

impl Entry {
    fn full(rates: &[Rate; 3], now: u64) -> Self {
        Self {
            level: rates.map(|r| r.cap),
            at: now,
        }
    }

    fn refill(&mut self, rates: &[Rate; 3], now: u64) {
        let dt = now.saturating_sub(self.at);
        for (level, r) in self.level.iter_mut().zip(rates) {
            *level = level
                .saturating_add(dt.saturating_mul(r.per_min))
                .min(r.cap);
        }
        self.at = self.at.max(now);
    }

    /// ADR 0027 rule 2: the limiter clock at which all three buckets are full, from the levels
    /// left by the last request. A refill does not change it while the key is not full, so it is
    /// the key's place in the order from one request to the next.
    fn full_at(&self, rates: &[Rate; 3]) -> u64 {
        let wait = self
            .level
            .iter()
            .zip(rates)
            .map(|(l, r)| r.cap.saturating_sub(*l).div_ceil(r.per_min.max(1)))
            .max()
            .unwrap_or(0);
        self.at.saturating_add(wait)
    }

    /// Takes one token of class `c`, or returns the `Retry-After` of ADR 0018 rule 29: the time
    /// until one token is available, in whole seconds, rounded up, at least 1.
    #[cfg(test)]
    fn take(&mut self, rates: &[Rate; 3], c: usize) -> Result<(), u64> {
        self.take_n(rates, c, 1)
    }

    /// Takes `tokens` tokens of class `c` (ADR 0051 rules 7 and 26), at least 1 and at most the
    /// burst, or none and returns the `Retry-After` until that many are available (ADR 0018
    /// rule 29), in whole seconds, rounded up, at least 1.
    fn take_n(&mut self, rates: &[Rate; 3], c: usize, tokens: u64) -> Result<(), u64> {
        let (Some(level), Some(rate)) = (self.level.get_mut(c), rates.get(c)) else {
            return Ok(());
        };
        let need = tokens.max(1).saturating_mul(UNIT).min(rate.cap.max(UNIT));
        if *level >= need {
            *level -= need;
            return Ok(());
        }
        let deficit = need - *level;
        let ms = deficit.div_ceil(rate.per_min.max(1));
        Err(ms.div_ceil(1_000).max(1))
    }
}

/// ADR 0027 clarification T2: the map of the limiter, allocated once for its bound and never
/// resized nor rehashed. Open addressing with linear probing over exactly two slots per key
/// (the table is at most half full, as clarification T1 counts it), and removal by backward
/// shift, which leaves no deletion marker: a removal moves at most the rest of its cluster, and
/// no operation ever passes over the table (ADR 0027 rule 1). The standard `HashMap` does not
/// meet T2 under the churn of rule 3: its deletion markers force a rehash in place or, when the
/// table holds more than half its capacity, a growth to twice its size during an insert.
///
/// Keys are hashed with the standard `RandomState` (`SipHash` with a random key), so a client
/// cannot choose keys that collide.
///
/// `V` is the entry of a key: the three buckets of a client key here, one byte bucket of a network
/// group in the second limiter table of ADR 0049 rule 5 ([`crate::ingest`]).
#[derive(Debug)]
pub(crate) struct KeyTable<V> {
    slots: Vec<Option<(ClientKey, V)>>,
    len: usize,
    hasher: RandomState,
}

impl<V: Copy> KeyTable<V> {
    /// Room for `max` keys: `2 × max` slots, allocated now.
    pub(crate) fn with_room(max: usize) -> Result<Self, TryReserveError> {
        let n = max.saturating_mul(2).max(2);
        let mut slots = Vec::new();
        slots.try_reserve_exact(n)?;
        slots.resize(n, None);
        Ok(Self {
            slots,
            len: 0,
            hasher: RandomState::new(),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The slot where the probe of `key` starts.
    fn home(&self, key: &ClientKey) -> usize {
        let n = self.slots.len() as u64;
        usize::try_from(self.hasher.hash_one(key) % n).unwrap_or(0)
    }

    fn next(&self, i: usize) -> usize {
        if i + 1 >= self.slots.len() { 0 } else { i + 1 }
    }

    /// Steps from `from` forward to `to`, around the end.
    fn distance(&self, from: usize, to: usize) -> usize {
        if to >= from {
            to - from
        } else {
            to + self.slots.len() - from
        }
    }

    /// The slot of `key`, if present. Ends at the first empty slot: at least half are empty.
    fn find(&self, key: &ClientKey) -> Option<usize> {
        let mut i = self.home(key);
        loop {
            match self.slots.get(i)? {
                None => return None,
                Some((k, _)) if k == key => return Some(i),
                Some(_) => i = self.next(i),
            }
        }
    }

    pub(crate) fn get(&self, key: &ClientKey) -> Option<&V> {
        let i = self.find(key)?;
        self.slots.get(i)?.as_ref().map(|(_, e)| e)
    }

    pub(crate) fn get_mut(&mut self, key: &ClientKey) -> Option<&mut V> {
        let i = self.find(key)?;
        self.slots.get_mut(i)?.as_mut().map(|(_, e)| e)
    }

    /// Inserts `key`, which is not present, and returns whether it was stored. The caller keeps
    /// `len` within `max` keys, so an empty slot is always found and this returns `true`; on a
    /// table already holding `max` keys (never reached, security review of 1c-limits, I-4) it
    /// stores nothing and returns `false`.
    #[must_use]
    pub(crate) fn insert(&mut self, key: ClientKey, e: V) -> bool {
        if self.len >= self.slots.len() / 2 {
            return false;
        }
        let mut i = self.home(&key);
        loop {
            match self.slots.get_mut(i) {
                Some(slot @ None) => {
                    *slot = Some((key, e));
                    self.len += 1;
                    return true;
                }
                Some(Some(_)) => i = self.next(i),
                None => return false,
            }
        }
    }

    /// Removes `key`, then moves back the keys of its cluster that the hole would make
    /// unreachable (backward shift), so that every key stays reachable from its home slot.
    pub(crate) fn remove(&mut self, key: &ClientKey) -> Option<V> {
        let mut hole = self.find(key)?;
        let (_, removed) = self.slots.get_mut(hole)?.take()?;
        self.len -= 1;
        let mut j = self.next(hole);
        while let Some(Some((k, _))) = self.slots.get(j) {
            // The key at `j` may fill the hole if the hole lies on its probe path, from its home
            // to `j`.
            let start = self.home(k);
            if self.distance(start, j) >= self.distance(hole, j) {
                self.slots.swap(hole, j);
                hole = j;
            }
            j = self.next(j);
        }
        Some(removed)
    }

    /// Every key and entry (tests).
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ClientKey, &V)> {
        self.slots.iter().flatten().map(|(k, e)| (k, e))
    }

    /// The number of slots (tests): it never changes after [`KeyTable::with_room`].
    #[cfg(test)]
    pub(crate) fn slots(&self) -> usize {
        self.slots.len()
    }
}

#[derive(Debug)]
struct Table {
    map: KeyTable<Entry>,
    /// ADR 0027 rule 2: `(full time, key)` of every key of `map` that has no unit in flight.
    order: BTreeSet<(u64, ClientKey)>,
    /// ADR 0019 rule 31, ADR 0027 rule 4: units in flight per key (connections of a direct peer,
    /// requests through a trusted peer), keys with a count above 0 only. A connection carries one
    /// counted unit at a time (counted at accept, or one HTTP/1.1 request in flight), so at most
    /// `max_connections` keys (ADR 0019 rule 31); a key may be here and not in `map`.
    pins: HashMap<ClientKey, u32>,
    overflow: Entry,
}

/// The token buckets of every client key.
#[derive(Debug)]
pub struct Limiter {
    rates: [Rate; 3],
    max_clients: usize,
    origin: Instant,
    table: Mutex<Table>,
}

/// The bucket index of a class.
fn slot(c: RequestClass) -> usize {
    match c {
        RequestClass::Block => 0,
        RequestClass::Query => 1,
        RequestClass::Put => 2,
    }
}

impl Limiter {
    /// The limiter of `s`. Every value is in range after [`Settings::load`].
    ///
    /// # Errors
    ///
    /// The map of the table could not be allocated for `rate_limit_max_clients` keys (ADR 0027
    /// clarification T2): the relay does not start.
    pub fn from_settings(s: &Settings) -> Result<Self, TryReserveError> {
        let rate = |per_min: u64, burst: u64| Rate {
            per_min,
            cap: burst.saturating_mul(UNIT),
        };
        Self::new(
            [
                rate(s.rate_block_per_min, s.rate_block_burst),
                rate(s.rate_query_per_min, s.rate_query_burst),
                rate(s.rate_put_per_min, s.rate_put_burst),
            ],
            usize::try_from(s.rate_limit_max_clients).unwrap_or(usize::MAX),
            usize::try_from(s.max_connections).unwrap_or(usize::MAX),
        )
    }

    /// ADR 0027 clarification T2: the map is allocated here, at start-up, for `max_clients` keys,
    /// so that an insert under the bound of ADR 0018 rule 21 never grows it and nothing rehashes
    /// it on the request path ([`KeyTable`]). The table of pins holds at most `max_pins` keys
    /// (ADR 0019 rule 31) and is reserved for them too (T2, MAY); it is a standard map, so its
    /// deletion markers may still make it rehash, or grow once to twice its size, at
    /// `max_connections` keys at most (counted twice by the pins term of T1). The order of full
    /// times grows one node at a time and needs no preallocation.
    fn new(rates: [Rate; 3], max_clients: usize, max_pins: usize) -> Result<Self, TryReserveError> {
        let map = KeyTable::with_room(max_clients)?;
        let mut pins = HashMap::new();
        pins.try_reserve(max_pins)?;
        Ok(Self {
            rates,
            max_clients,
            origin: Instant::now(),
            table: Mutex::new(Table {
                map,
                order: BTreeSet::new(),
                pins,
                overflow: Entry::full(&rates, 0),
            }),
        })
    }

    /// The slots of the map (tests): their number never changes after [`Self::new`].
    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.lock().map.slots()
    }

    /// A panic under the lock leaves consistent levels: poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Takes one token of `class` for `key` (ADR 0020 rule 22 (c)). Returns the key the request is
    /// attributed to: `key`, or [`ClientKey::OVERFLOW`] when the table is full of keys that are
    /// not full (ADR 0020 rule 24, ADR 0027 rule 3). Without a token, returns the `Retry-After` in
    /// seconds.
    ///
    /// # Errors
    ///
    /// The bucket is empty: the `Retry-After` of ADR 0018 rule 29.
    pub fn take(&self, key: ClientKey, class: RequestClass) -> Result<ClientKey, u64> {
        self.take_tokens(key, class, 1)
    }

    /// [`Limiter::take`] with the weight of the request (ADR 0051 rules 7 and 26): `tokens`
    /// tokens, at least 1 and capped at the burst of `class`, all or none.
    ///
    /// # Errors
    ///
    /// The bucket holds fewer: the `Retry-After` until it holds that many.
    pub fn take_tokens(
        &self,
        key: ClientKey,
        class: RequestClass,
        tokens: u64,
    ) -> Result<ClientKey, u64> {
        self.take_n_at(key, class, tokens, self.now())
    }

    #[cfg(test)]
    fn take_at(&self, key: ClientKey, class: RequestClass, now: u64) -> Result<ClientKey, u64> {
        self.take_n_at(key, class, 1, now)
    }

    /// ADR 0027 rules 1 to 4: one hash lookup and at most two changes of the order, O(log n).
    fn take_n_at(
        &self,
        key: ClientKey,
        class: RequestClass,
        tokens: u64,
        now: u64,
    ) -> Result<ClientKey, u64> {
        let (rates, c) = (&self.rates, slot(class));
        let mut guard = self.lock();
        let t = &mut *guard;
        if let Some(e) = t.map.get_mut(&key) {
            let before = e.full_at(rates);
            e.refill(rates, now);
            let taken = e.take_n(rates, c, tokens);
            let after = e.full_at(rates);
            // ADR 0027 rule 7: a request of a known key moves that key in the order.
            if before != after && !t.pins.contains_key(&key) {
                t.order.remove(&(before, key));
                t.order.insert((after, key));
            }
            return taken.map(|()| key);
        }
        // ADR 0027 rule 3: with a full table, the key with the earliest full time is dropped if
        // it is full, during this request. Keys with a unit in flight are not in the order, so
        // the one found is never one of them (rule 4).
        if t.map.len() >= self.max_clients {
            match t.order.first() {
                Some(&(full, victim)) if full <= now => {
                    t.order.remove(&(full, victim));
                    t.map.remove(&victim);
                }
                _ => {}
            }
        }
        if t.map.len() < self.max_clients {
            let mut e = Entry::full(rates, now);
            let taken = e.take_n(rates, c, tokens);
            let full_at = e.full_at(rates);
            // The map has room for `max_clients` keys, so the insert always stores the key
            // (review I-4). Were it ever refused, the key would stay out of the order too and the
            // request would use the overflow key: the table stays consistent.
            let stored = t.map.insert(key, e);
            debug_assert!(
                stored,
                "the limiter map has room for rate_limit_max_clients keys"
            );
            if stored {
                if !t.pins.contains_key(&key) {
                    t.order.insert((full_at, key));
                }
                return taken.map(|()| key);
            }
        }
        t.overflow.refill(rates, now);
        t.overflow
            .take_n(rates, c, tokens)
            .map(|()| ClientKey::OVERFLOW)
    }

    /// One more unit in flight for `key` (ADR 0019 rule 31): while its count is above 0, its
    /// entry is not dropped (ADR 0027 rule 4). Called by the per-client counts (`client::Counts`).
    pub fn pin(&self, key: ClientKey) {
        let mut guard = self.lock();
        let t = &mut *guard;
        let n = t.pins.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        if *n == 1
            && let Some(e) = t.map.get(&key)
        {
            t.order.remove(&(e.full_at(&self.rates), key));
        }
    }

    /// One unit fewer in flight for `key`; at 0 its entry may be dropped again once full.
    pub fn unpin(&self, key: ClientKey) {
        let mut guard = self.lock();
        let t = &mut *guard;
        match t.pins.get_mut(&key) {
            Some(n) if *n > 1 => *n -= 1,
            Some(_) => {
                t.pins.remove(&key);
                if let Some(e) = t.map.get(&key) {
                    t.order.insert((e.full_at(&self.rates), key));
                }
            }
            None => {}
        }
    }

    /// Keys in the table (tests).
    #[cfg(test)]
    fn keys(&self) -> usize {
        self.lock().map.len()
    }

    /// The table is consistent (tests): every key of the map is in the order at its full time,
    /// unless it has a unit in flight, and the order holds nothing else.
    #[cfg(test)]
    fn consistent(&self) -> bool {
        let t = self.lock();
        let unpinned = t
            .map
            .iter()
            .map(|(k, _)| k)
            .filter(|k| !t.pins.contains_key(k))
            .count();
        unpinned == t.order.len()
            && t.map.iter().all(|(k, e)| {
                t.pins.contains_key(k) || t.order.contains(&(e.full_at(&self.rates), *k))
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::client::ClientPolicy;
    use RequestClass::{Block, Put, Query};

    fn limiter(per_min: u64, burst: u64, max: usize) -> Limiter {
        let r = Rate {
            per_min,
            cap: burst * UNIT,
        };
        Limiter::new([r; 3], max, 32).unwrap()
    }

    fn key(s: &str) -> ClientKey {
        ClientPolicy::new(Vec::new(), Vec::new(), 64, 8)
            .key(s.parse().unwrap())
            .unwrap()
    }

    fn v4(i: u8) -> ClientKey {
        key(&format!("192.0.2.{i}"))
    }

    /// ADR 0051 rules 7 and 26: a weighted request takes all its tokens or none, at least 1 and
    /// at most the burst; the `Retry-After` is the wait for all of them.
    #[test]
    fn weighted_requests_take_all_or_nothing() {
        let l = limiter(60, 10, 64);
        let k = key("192.0.2.1");
        assert_eq!(l.take_n_at(k, Block, 4, 0), Ok(k));
        assert_eq!(l.take_n_at(k, Block, 0, 0), Ok(k), "at least one token");
        assert_eq!(l.take_n_at(k, Block, 6, 0), Err(1), "5 left, 6 asked");
        assert_eq!(
            l.take_n_at(k, Block, 5, 0),
            Ok(k),
            "the refusal took nothing"
        );
        // Empty; 60 per minute: 3 tokens in 3 s.
        assert_eq!(l.take_n_at(k, Block, 3, 0), Err(3));
        assert_eq!(l.take_n_at(k, Block, 3, 3_000), Ok(k));
        // A weight above the burst costs the whole burst, once full.
        let k2 = key("192.0.2.2");
        assert_eq!(l.take_n_at(k2, Block, 64, 0), Ok(k2));
        assert_eq!(l.take_n_at(k2, Block, 1, 0), Err(1));
        assert_eq!(l.take_n_at(k2, Block, 64, 0), Err(10));
        // Other buckets of the key are untouched.
        assert_eq!(l.take_n_at(k2, Query, 10, 0), Ok(k2));
    }

    /// Rule 21: the burst, then `429` with the time to the next token (rule 29); the bucket
    /// refills at `per_min`.
    #[test]
    fn burst_then_retry_after() {
        let l = limiter(300, 20, 64);
        let k = key("192.0.2.1");
        for _ in 0..20 {
            assert_eq!(l.take_at(k, Query, 0), Ok(k));
        }
        // 300 per minute: one token every 200 ms, so `Retry-After: 1`.
        assert_eq!(l.take_at(k, Query, 0), Err(1));
        assert_eq!(l.take_at(k, Query, 199), Err(1));
        assert_eq!(l.take_at(k, Query, 200), Ok(k));
        // 1 per minute: 60 s for a whole token, 30 s after half of it.
        let slow = limiter(1, 1, 64);
        assert_eq!(slow.take_at(k, Query, 0), Ok(k));
        assert_eq!(slow.take_at(k, Query, 0), Err(60));
        assert_eq!(slow.take_at(k, Query, 30_000), Err(30));
        assert_eq!(slow.take_at(k, Query, 59_001), Err(1), "rounded up");
        assert_eq!(slow.take_at(k, Query, 60_000), Ok(k));
        assert!(l.consistent() && slow.consistent());
    }

    /// The three classes of one key are separate buckets; keys are separate allowances; two
    /// IPv6 addresses of one /64 share one (rule 20).
    #[test]
    fn classes_and_keys_are_separate() {
        let l = limiter(1, 1, 64);
        let (a, b) = (key("192.0.2.1"), key("192.0.2.2"));
        assert!(l.take_at(a, Query, 0).is_ok());
        assert!(l.take_at(a, Query, 0).is_err());
        assert!(l.take_at(a, Block, 0).is_ok());
        assert!(l.take_at(a, Put, 0).is_ok());
        assert!(l.take_at(b, Query, 0).is_ok());
        let (v6, same) = (key("2001:db8::1"), key("2001:db8::ffff:2"));
        assert!(l.take_at(v6, Query, 0).is_ok());
        assert!(l.take_at(same, Query, 0).is_err(), "one /64, one bucket");
        assert!(l.consistent());
    }

    /// ADR 0027 rule 2: the full time is the latest of the three buckets, rounded up to the
    /// millisecond, and does not move while the key refills.
    #[test]
    fn full_time_of_three_buckets() {
        let rates = [
            Rate {
                per_min: 3_000,
                cap: 200 * UNIT,
            },
            Rate {
                per_min: 7,
                cap: 20 * UNIT,
            },
            Rate {
                per_min: 30,
                cap: 20 * UNIT,
            },
        ];
        let mut e = Entry::full(&rates, 1_000);
        assert_eq!(e.full_at(&rates), 1_000);
        e.take(&rates, 0).unwrap();
        assert_eq!(e.full_at(&rates), 1_020, "block: 20 ms per token");
        e.take(&rates, 1).unwrap();
        // 60,000 / 7 = 8,571.4 ms, rounded up.
        assert_eq!(e.full_at(&rates), 1_000 + 8_572);
        for now in [1_001, 1_020, 5_000, 9_571] {
            let mut r = e;
            r.refill(&rates, now);
            assert_eq!(r.full_at(&rates), 9_572, "at {now}");
        }
    }

    /// Rule 21 and ADR 0020 rule 24, ADR 0027 rule 3: a full table of keys that are not full
    /// sends unknown keys to the overflow key, which has the allowance of one client; full keys
    /// are dropped at once, with no waiting period.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn full_table_uses_the_overflow_key() {
        let l = limiter(60, 1, 2);
        let (a, b, c, d) = (v4(1), v4(2), v4(3), v4(4));
        assert_eq!(l.take_at(a, Query, 0), Ok(a));
        assert_eq!(l.take_at(b, Query, 0), Ok(b));
        assert_eq!(l.take_at(c, Query, 0), Ok(ClientKey::OVERFLOW));
        assert_eq!(
            l.take_at(d, Query, 0),
            Err(1),
            "the overflow key is one allowance"
        );
        assert_eq!(l.keys(), 2);
        // 60 per minute: `a` and `b` are full again at 1,000 ms, not before.
        // At 999 ms `c` is still sent to the overflow key, whose only token is spent (a new
        // entry would have full buckets).
        assert_eq!(l.take_at(c, Query, 999), Err(1));
        assert_eq!(l.take_at(c, Query, 1_000), Ok(c));
        assert_eq!(l.take_at(d, Query, 1_000), Ok(d));
        assert_eq!(l.keys(), 2);
        assert!(l.consistent());
        // `a` was dropped: it starts again with full buckets.
        assert_eq!(l.take_at(a, Query, 1_000), Ok(ClientKey::OVERFLOW));
    }

    /// ADR 0027 consequences: a full key is replaced at once, twice in the same millisecond; the
    /// one dropped is the one with the earliest full time.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn full_keys_are_replaced_at_once() {
        let l = limiter(60, 2, 3);
        let (a, b, c) = (v4(1), v4(2), v4(3));
        // `a` is full again at 1,000 ms, `b` at 2,000 ms, `c` at 1,500 ms.
        assert_eq!(l.take_at(a, Query, 0), Ok(a));
        assert_eq!(l.take_at(b, Query, 0), Ok(b));
        assert_eq!(l.take_at(b, Query, 0), Ok(b));
        assert_eq!(l.take_at(c, Query, 500), Ok(c));
        let (d, e, f) = (v4(4), v4(5), v4(6));
        assert_eq!(l.take_at(d, Query, 1_500), Ok(d), "replaces a");
        assert_eq!(l.take_at(e, Query, 1_500), Ok(e), "replaces c");
        assert_eq!(
            l.take_at(f, Query, 1_500),
            Ok(ClientKey::OVERFLOW),
            "b is not full"
        );
        assert_eq!(l.keys(), 3);
        assert!(l.consistent());
        // `b` was kept with its levels: its second token is still spent at 1,500 ms.
        assert_eq!(l.take_at(b, Query, 1_500), Ok(b));
        assert_eq!(l.take_at(b, Query, 1_500), Err(1));
    }

    /// ADR 0027 rule 4: a key one token short of full is not dropped, in any class.
    #[test]
    fn a_key_one_token_short_is_kept() {
        for class in [Block, Query, Put] {
            let (l, a) = (limiter(60, 3, 1), v4(1));
            assert_eq!(l.take_at(a, class, 0), Ok(a));
            // One millisecond short of the token.
            assert_eq!(l.take_at(v4(2), Query, 999), Ok(ClientKey::OVERFLOW));
            assert_eq!(l.take_at(v4(2), Query, 1_000), Ok(v4(2)));
            assert!(l.consistent());
        }
    }

    /// ADR 0027 rule 4, ADR 0019 rule 31: an entry with a unit in flight is not dropped, even
    /// full; once the unit ends, it is dropped at the next unknown key. A key pinned before it
    /// enters the table is kept out of the order from its first request.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn an_entry_in_flight_is_kept() {
        let l = limiter(60, 1, 2);
        let (a, b, c, d) = (v4(1), v4(2), v4(3), v4(4));
        assert_eq!(l.take_at(a, Query, 0), Ok(a));
        l.pin(a);
        l.pin(a);
        // `b` is pinned before its first request (a direct connection counted at accept).
        l.pin(b);
        assert_eq!(l.take_at(b, Query, 0), Ok(b));
        assert!(l.consistent());
        // The overflow key refills one token per second: one request per second on it.
        assert_eq!(l.take_at(c, Query, 10_000), Ok(ClientKey::OVERFLOW));
        l.unpin(a);
        assert_eq!(l.take_at(c, Query, 11_000), Ok(ClientKey::OVERFLOW));
        l.unpin(a);
        assert!(l.consistent());
        assert_eq!(l.take_at(c, Query, 11_000), Ok(c), "replaces a");
        // `b` is pinned and `c` is not full: `d` goes to the overflow key, spent at 11,000 ms.
        assert_eq!(l.take_at(d, Query, 11_500), Err(1));
        l.unpin(b);
        assert_eq!(l.take_at(d, Query, 11_500), Ok(d), "replaces b");
        assert!(l.consistent());
        // Unbalanced or unknown keys change nothing.
        l.unpin(v4(9));
        l.unpin(ClientKey::OVERFLOW);
        assert!(l.consistent());
    }

    /// ADR 0027 rule 4 (security review of 1c-b2, L-4): a key already in the table that takes a
    /// token while pinned stays out of the order, so it is not dropped once its new full time has
    /// passed; after its unpin it is in the order once, at that time.
    #[test]
    fn a_pinned_key_taking_a_token_stays_out_of_the_order() {
        let l = limiter(60, 1, 1);
        let (a, b) = (v4(1), v4(2));
        assert_eq!(l.take_at(a, Query, 0), Ok(a));
        l.pin(a);
        // Its full time moves from 1,000 to 6,000 ms.
        assert_eq!(l.take_at(a, Query, 5_000), Ok(a));
        assert!(l.consistent());
        assert_eq!(
            l.take_at(b, Query, 7_000),
            Ok(ClientKey::OVERFLOW),
            "a is pinned"
        );
        l.unpin(a);
        assert!(l.consistent());
        assert_eq!(l.take_at(b, Query, 8_000), Ok(b), "replaces a");
        assert!(l.consistent());
    }

    /// ADR 0019 rules 29 to 31: the counts of connections and requests pin their keys for as long
    /// as a unit is counted.
    #[test]
    fn counted_units_pin_their_keys() {
        let l = std::sync::Arc::new(limiter(60, 1, 1));
        let counts = crate::client::Counts::pinning(2, std::sync::Arc::clone(&l));
        let (a, b) = (v4(1), v4(2));
        let (one, two) = (counts.try_acquire(a), counts.try_acquire(a));
        assert!(one.is_some() && two.is_some() && counts.try_acquire(a).is_none());
        assert_eq!(l.take_at(a, Query, 0), Ok(a));
        assert_eq!(l.take_at(b, Query, 5_000), Ok(ClientKey::OVERFLOW));
        drop(one);
        assert_eq!(l.take_at(b, Query, 6_000), Ok(ClientKey::OVERFLOW));
        drop(two);
        assert_eq!(l.take_at(b, Query, 6_000), Ok(b), "replaces a");
        assert!(l.consistent());
    }

    /// ADR 0027 rule 1: the table stays at `max_clients` keys under many unknown keys, and the
    /// order stays in step with the map.
    #[test]
    fn many_keys_keep_the_bound() {
        let l = limiter(6_000, 1, 64);
        for i in 0..1_000_u32 {
            let k = key(&format!("10.0.{}.{}", i / 256, i % 256));
            let now = u64::from(i);
            assert!(l.take_at(k, Block, now).is_ok());
            if i % 7 == 0 {
                l.pin(k);
            }
            if i % 7 == 3 {
                l.unpin(key(&format!("10.0.{}.{}", (i - 3) / 256, (i - 3) % 256)));
            }
        }
        assert_eq!(l.keys(), 64);
        assert!(l.consistent());
    }

    /// ADR 0027 clarification T2: the map is allocated for `rate_limit_max_clients` keys before
    /// the relay listens and never grows: filling the table, replacing full keys and using the
    /// overflow key never change its number of slots, which is two per key.
    #[test]
    fn the_map_is_preallocated_and_never_grows() {
        let l = limiter(6_000, 1, 64);
        let cap = l.capacity();
        assert_eq!(cap, 128);
        for i in 0..10_000_u32 {
            let k = key(&format!(
                "10.{}.{}.{}",
                i / 65_536,
                (i / 256) % 256,
                i % 256
            ));
            // Every key is full again 10 ms after its token: some are replaced, others overflow.
            let _ = l.take_at(k, Block, u64::from(i / 8));
            assert_eq!(l.capacity(), cap, "request {i}");
        }
        assert_eq!(l.keys(), 64);
        assert!(l.consistent());
        // The three profiles allocate their table at start-up.
        for (max, pins) in [(4_096, 32), (32_768, 256), (262_144, 4_096)] {
            let r = Rate {
                per_min: 1,
                cap: UNIT,
            };
            let l = Limiter::new([r; 3], max, pins).unwrap();
            assert_eq!(l.capacity(), 2 * max, "{max}");
        }
    }

    /// ADR 0027 clarification T1: the estimate of one limiter entry in `config.rs` covers the map
    /// at most half full (two elements per key, each with its control byte) and two elements of
    /// the order of full times. A change of the limiter types that outgrows it fails here.
    #[test]
    fn the_entry_estimate_covers_the_limiter_types() {
        use std::mem::size_of;
        // A slot of [`KeyTable`]: the element and its occupancy, in one `Option`.
        let slot = size_of::<Option<(ClientKey, Entry)>>();
        assert!(slot <= size_of::<(ClientKey, Entry)>() + 1, "{slot}");
        let map_element = size_of::<(ClientKey, Entry)>();
        let order_element = size_of::<(u64, ClientKey)>();
        let needed = 2 * (map_element + 1) + 2 * order_element;
        let estimate = usize::try_from(crate::config::EST_LIMITER_ENTRY).unwrap();
        assert!(
            estimate >= needed,
            "EST_LIMITER_ENTRY = {estimate} < 2 x ({map_element} + 1) + 2 x {order_element} = {needed}"
        );
    }

    /// [`KeyTable`] against the standard map as a model: random inserts, lookups and removals over
    /// a small key space, so that clusters wrap around the end and backward shifts are frequent;
    /// every key stays reachable and the number of slots never changes.
    #[test]
    fn slots_match_a_model() {
        let mut slots = KeyTable::with_room(16).unwrap();
        let mut model: HashMap<ClientKey, Entry> = HashMap::new();
        // xorshift64: deterministic and dependency-free.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for step in 0..200_000_u64 {
            let k = v4(u8::try_from(rnd() % 40).unwrap());
            match rnd() % 3 {
                0 if model.len() < 16 && !model.contains_key(&k) => {
                    let e = Entry {
                        level: [step; 3],
                        at: step,
                    };
                    assert!(slots.insert(k, e));
                    model.insert(k, e);
                }
                1 => assert_eq!(
                    slots.remove(&k).map(|e| e.at),
                    model.remove(&k).map(|e| e.at)
                ),
                _ => {
                    if let Some(e) = slots.get_mut(&k) {
                        e.at += 1;
                    }
                    if let Some(e) = model.get_mut(&k) {
                        e.at += 1;
                    }
                }
            }
            assert_eq!(slots.len(), model.len(), "step {step}");
            assert_eq!(slots.slots(), 32);
            if step % 997 == 0 {
                for i in 0..40 {
                    let k = v4(i);
                    assert_eq!(slots.get(&k).map(|e| e.at), model.get(&k).map(|e| e.at));
                }
                assert_eq!(slots.iter().count(), model.len());
            }
        }
        // Full to the bound: one more insert is refused, never stored past half of the slots.
        let mut full = KeyTable::with_room(4).unwrap();
        for i in 0..5 {
            let stored = full.insert(v4(i), Entry::full(&[Rate { per_min: 1, cap: 1 }; 3], 0));
            assert_eq!(stored, i < 4, "{i}");
        }
        assert_eq!(full.len(), 4);
        assert!(full.get(&v4(4)).is_none());
    }
}
