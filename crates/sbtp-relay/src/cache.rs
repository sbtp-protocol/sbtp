//! Cache of hot blocks for `GET /sbtp/v1/block/{id}`, bounded in heap bytes (`block_cache_bytes`,
//! ADR 0018 rule 22): the least recently used blocks leave first. 0 disables it.
//!
//! Security review L-2: an entry is charged its block length plus [`ENTRY_OVERHEAD`]. The length
//! is the allocation: the store reads into a buffer whose capacity is its length
//! ([`crate::store::Store::read`]), and that buffer becomes the `Bytes` held here.
//!
//! A small strict LRU instead of `moka`: the bound is exact at every insert (no deferred
//! eviction), the order is plain LRU as ADR 0018 states, and no crate is added to the exposed
//! binary. Only blocks read from the store and checked (ADR 0003 rule 11) are inserted.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};

use axum::body::Bytes;
use sbtp_core::BlockId;

/// The heap bytes charged per entry on top of the block: a `HashMap` slot (key, `Bytes`, tick: 72
/// bytes, at most about 2.3 slots per entry between two resizes), its share of a `BTreeMap` node
/// (40-byte entries, nodes at least half full), the shared header `Bytes` allocates on the first
/// clone, and the allocator's rounding of these allocations and of the block's own. An upper
/// estimate, not a measure.
pub const ENTRY_OVERHEAD: usize = 384;

/// The heap bytes charged for a block of `len` bytes.
fn charge(len: usize) -> usize {
    len.saturating_add(ENTRY_OVERHEAD)
}

/// The cache. Every operation is O(log n) under one short lock; no I/O happens under it.
#[derive(Debug)]
pub struct BlockCache {
    capacity: usize,
    inner: Mutex<Lru>,
}

#[derive(Debug, Default)]
struct Lru {
    entries: HashMap<[u8; 32], (Bytes, u64)>,
    /// Use tick → key, oldest first.
    order: BTreeMap<u64, [u8; 32]>,
    tick: u64,
    bytes: usize,
}

impl BlockCache {
    /// A cache of at most `capacity` block bytes.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(Lru::default()),
        }
    }

    /// The cached bytes of `id`, marked as used.
    pub fn get(&self, id: &BlockId) -> Option<Bytes> {
        if self.capacity == 0 {
            return None;
        }
        let mut lru = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Lru {
            entries,
            order,
            tick,
            ..
        } = &mut *lru;
        let (bytes, used) = entries.get_mut(id.as_bytes())?;
        order.remove(used);
        *tick += 1;
        *used = *tick;
        order.insert(*tick, *id.as_bytes());
        Some(bytes.clone())
    }

    /// Inserts `bytes` under `id`, evicting the least recently used blocks to stay within the
    /// capacity. A block whose charge exceeds the capacity is not cached. `bytes` must own an
    /// allocation of its own length (module documentation).
    pub fn insert(&self, id: &BlockId, bytes: Bytes) {
        let cost = charge(bytes.len());
        if cost > self.capacity {
            return;
        }
        let mut lru = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((old, used)) = lru.entries.remove(id.as_bytes()) {
            lru.order.remove(&used);
            lru.bytes -= charge(old.len());
        }
        while lru.bytes + cost > self.capacity {
            let Some((_, key)) = lru.order.pop_first() else {
                break;
            };
            if let Some((old, _)) = lru.entries.remove(&key) {
                lru.bytes -= charge(old.len());
            }
        }
        lru.tick += 1;
        let tick = lru.tick;
        lru.bytes += cost;
        lru.order.insert(tick, *id.as_bytes());
        lru.entries.insert(*id.as_bytes(), (bytes, tick));
    }

    /// Heap bytes charged (block lengths plus [`ENTRY_OVERHEAD`] per entry).
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> BlockId {
        BlockId([b; 32])
    }

    #[test]
    fn evicts_least_recently_used_within_the_byte_bound() {
        let o = ENTRY_OVERHEAD;
        let c = BlockCache::new(300 + 3 * o);
        c.insert(&id(1), Bytes::from(vec![1; 100]));
        c.insert(&id(2), Bytes::from(vec![2; 100]));
        c.insert(&id(3), Bytes::from(vec![3; 100]));
        assert_eq!(c.bytes(), 300 + 3 * o, "each entry is charged its overhead");
        assert!(c.get(&id(1)).is_some()); // 2 is now the oldest
        c.insert(&id(4), Bytes::from(vec![4; 150]));
        assert!(c.get(&id(2)).is_none());
        assert!(c.get(&id(3)).is_none(), "150 bytes needed two evictions");
        assert!(c.get(&id(1)).is_some() && c.get(&id(4)).is_some());
        assert_eq!(c.bytes(), 250 + 2 * o);
        c.insert(&id(5), Bytes::from(vec![5; 300 + 2 * o + 1]));
        assert!(c.get(&id(5)).is_none(), "larger than the cache");
        c.insert(&id(1), Bytes::from(vec![1; 100])); // replace, not duplicate
        assert_eq!(c.bytes(), 250 + 2 * o);
    }

    /// Security review L-2: many small blocks cannot hold more heap than the bound says.
    #[test]
    fn overhead_bounds_the_number_of_entries() {
        let c = BlockCache::new(10 * (118 + ENTRY_OVERHEAD));
        for b in 0..=255u8 {
            c.insert(&id(b), Bytes::from(vec![b; 118]));
        }
        assert_eq!(c.bytes(), 10 * (118 + ENTRY_OVERHEAD));
        assert_eq!((0..=255u8).filter(|b| c.get(&id(*b)).is_some()).count(), 10);
    }

    #[test]
    fn zero_disables() {
        let c = BlockCache::new(0);
        c.insert(&id(1), Bytes::from_static(b""));
        assert!(c.get(&id(1)).is_none());
    }
}
