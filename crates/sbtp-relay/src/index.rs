//! Relay index on redb (ADR 0013 rules 1 to 5 and 22 to 24; `architecture.md` §2 "Index").
//!
//! Derived data only: block files are the source of truth (rule 1). Five tables:
//!
//! - `blocks`: position → `block_id` ‖ length (u32, big-endian) ‖ parents (32 bytes each);
//! - `ids`: `block_id` → position;
//! - `edges`: (parent, position) → child `block_id`;
//! - `demand`: position → `last_demand` (ADR 0046 rule 26), the start of the demand epoch in which
//!   the block was last demanded;
//! - `demand_order`: (`last_demand`, position) → `()`, the order of demand eviction (rule 6).
//!
//! The two demand tables are written in the transaction that writes the other entries of a block
//! and removed with them. An index written before ADR 0046 gets them at the first start
//! ([`IndexBackend::configure_demand`]). The `meta` table also records whether the index was
//! closed cleanly (`open`), the end of a demand-eviction suspension running at the last clean
//! close (`suspended_until`), and the `demand_eviction` setting of the last start
//! (`demand_eviction`), for the suspensions of ADR 0046 rule 13 (security review 2026-11-21, M-1
//! and L-1).
//!
//! Keys are 32-byte values taken from validated blocks; no path is built from them.
//!
//! # Operators: upgrading redb
//!
//! Before the first start of a relay built with a newer redb (4.4.0 to 4.6.0 on 2026-11-19, see
//! `docs/security/2026-11-18-redb-4.6-exception.md`), stop the relay and keep a copy of
//! `index.redb` **outside the data directory**, for example
//! `cp -p data/index.redb /var/backups/sbtp-relay/index.redb.redb-4.4.0`: the data directory is the
//! block store, which a rebuild scans, so no extra file belongs there. The index is derived data
//! and can be rebuilt from the block files (ADR 0013 rule 1), but the copy makes a
//! rollback to the previous release independent of redb's downgrade path, which upstream does not
//! test. Delete the copy once the new release has run cleanly.
//!
//! The migration check of that upgrade is `examples/index_migration.sh`.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbtp_core::BlockId;

use crate::log::{Event, Value};
use redb::{
    Builder, Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};

/// redb cache size proposed by ADR 0013 rule 24 (setting `index_cache_bytes`). The library default
/// is 1 GiB, which contradicts the RAM target: the relay MUST set it explicitly.
pub const DEFAULT_INDEX_CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Longest interval between two durable commits (ADR 0013 rule 10).
pub const DURABLE_COMMIT_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound of `limit` in [`IndexBackend::query`] and of `max` in [`IndexBackend::expired`]:
/// the largest `max_query_limit` of ADR 0012 rule 8. The index clamps to `1..=MAX_QUERY_LIMIT`
/// itself, so that a handler mistake cannot become a memory problem or a page without progress.
pub const MAX_QUERY_LIMIT: usize = 1_000;

type Id = [u8; 32];
const BLOCKS: TableDefinition<(u64, u32), &[u8]> = TableDefinition::new("blocks");
const IDS: TableDefinition<&Id, (u64, u32)> = TableDefinition::new("ids");
const EDGES: TableDefinition<(&Id, u64, u32), &Id> = TableDefinition::new("edges");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const DEMAND: TableDefinition<(u64, u32), u64> = TableDefinition::new("demand");
const DEMAND_ORDER: TableDefinition<(u64, u64, u32), ()> = TableDefinition::new("demand_order");
const EPOCH_KEY: &str = "epoch";
/// `1` once every block has its demand entries (ADR 0046 implementation plan, step 2).
const DEMAND_KEY: &str = "demand";
/// `1` while a relay has the index open, `0` after a clean close (ADR 0046 rule 13).
const OPEN_KEY: &str = "open";
/// The end, Unix milliseconds, of the demand-eviction suspension that was running at the last
/// clean close (security review 2026-11-21, L-1); `0` when none.
const SUSPENDED_KEY: &str = "suspended_until";
/// The `demand_eviction` setting of the last start, `0` or `1`; absent before the first start of
/// a relay that records it (security review 2026-11-21, M-1).
const DEMAND_ON_KEY: &str = "demand_eviction";
/// The migration logs its progress every this many transactions (security review 2026-11-21,
/// I-4): every 100,000 blocks.
const MIGRATION_LOG_EVERY: u64 = 10;
/// Order entries without a `blocks` row that one [`IndexBackend::demand_candidates`] listing
/// skips at most (security review 2026-11-21, I-3). They come only from corruption; the bound
/// keeps a listing's read transaction short whatever their number.
pub const ORPHAN_SCAN_MAX: u64 = 10_000;
/// The default demand epoch, 8 hours (ADR 0046 rule 24, D10), until [`IndexBackend::configure_demand`].
const DEFAULT_DEMAND_EPOCH_MS: u64 = 28_800_000;
/// Blocks given demand entries per transaction of the start-up migration.
const MIGRATION_BATCH: usize = 10_000;
/// Length of the fixed part of a `blocks` value: `block_id` and length.
const ROW_HEAD: usize = 36;

/// A position in the acceptance order: `(received_at, n)` (ADR 0013 rule 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    /// Relay clock at acceptance, Unix milliseconds.
    pub received_at: u64,
    /// Tie-breaker inside one millisecond.
    pub n: u32,
}

impl Position {
    /// First position with `received_at ≥ since` (`/query?since=`, ADR 0012 rule 7).
    #[must_use]
    pub const fn at(since: u64) -> Self {
        Self {
            received_at: since,
            n: 0,
        }
    }

    /// The position right after this one (cursor of a page, ADR 0012 rule 9).
    #[must_use]
    pub const fn next(self) -> Self {
        match self.n.checked_add(1) {
            Some(n) => Self {
                received_at: self.received_at,
                n,
            },
            None => Self::at(self.received_at.saturating_add(1)),
        }
    }

    /// The position of a block accepted at `now_ms` after `last` (ADR 0013 rule 3): positions
    /// strictly increase, and if the clock stepped back the last `received_at` is reused.
    #[must_use]
    pub const fn assign(last: Option<Self>, now_ms: u64) -> Self {
        match last {
            Some(last) if now_ms <= last.received_at => last.next(),
            _ => Self::at(now_ms),
        }
    }

    const fn key(self) -> (u64, u32) {
        (self.received_at, self.n)
    }

    const fn from_key((received_at, n): (u64, u32)) -> Self {
        Self { received_at, n }
    }
}

/// How the block being indexed reached the store (ADR 0013 rules 7, 9 and 13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    /// Its file was just created exclusively (the `201` case). Any index entry for the same
    /// `block_id` is stale (an eviction in progress, or a phantom left by a crash between file and
    /// index deletion, rule 8) and is replaced: the block is new for the relay (rule 13).
    Created,
    /// Its file was already held (the repair path of rule 9). An existing entry is kept.
    AlreadyHeld,
}

/// A block that demand eviction may delete (ADR 0046 rules 6 and 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The start of the epoch of its last demand.
    pub last_demand: u64,
    /// Its position.
    pub position: Position,
    /// Its `block_id`.
    pub id: BlockId,
    /// Its length in bytes.
    pub len: u32,
}

/// One listing of demand candidates (ADR 0046 rules 6 and 7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Candidates {
    /// The candidates, in increasing `(last_demand, position)`.
    pub list: Vec<Candidate>,
    /// Order entries skipped because their `blocks` row is missing (corruption), at most
    /// [`ORPHAN_SCAN_MAX`]; they do not count toward `max`.
    pub orphans: u64,
}

/// One page of `/query` (ADR 0012 rule 10), before JSON encoding.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// Entries in the order of the request: acceptance order with `asc`, newest first with
    /// `desc`.
    pub entries: Vec<(Position, BlockId)>,
    /// The gap the next page starts from (ADR 0051 rule 16): the position right after the last
    /// entry with `asc`, the position of the last (oldest) entry with `desc`; the gap the page
    /// started from when it is empty.
    pub next: Position,
    /// At least one more matching entry existed when the page was built.
    pub more: bool,
    /// With `fields=parents` (ADR 0051 rule 13): per entry, aligned with `entries`, its length
    /// and its Parents Hashes in header order. Empty otherwise.
    pub fields: Vec<EntryFields>,
}

/// The header data of one entry that `fields=parents` adds (ADR 0051 rule 13), from its
/// `blocks` row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryFields {
    /// The block's length in bytes.
    pub len: u32,
    /// Its Parents Hashes, in header order (0 to 8).
    pub parents: Vec<BlockId>,
}

/// The order of a `/query` walk (ADR 0051 rule 15): the relay's store order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Order {
    /// Oldest first (the default).
    #[default]
    Asc,
    /// Newest first.
    Desc,
}

/// One listing of a `/query` request: the children of `parent`, or every block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// The parent, `None` for every block.
    pub parent: Option<BlockId>,
    /// The gap the listing starts from (ADR 0051 rule 16), decoded; `None` for the start of the
    /// order (the oldest position with `asc`, the newest gap with `desc`).
    pub cursor: Option<Position>,
}

/// What one `/query` request reads (ADR 0051 rules 15 to 25).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryPlan {
    /// 1 to 32 listings, in request order.
    pub listings: Vec<Listing>,
    /// The order of every listing.
    pub order: Order,
    /// The first position any listing may return: the later of `since` and the expiry bound
    /// (ADR 0012 rule 9, ADR 0013 rule 14). With `asc` a listing starts at the later of it and
    /// its cursor; with `desc` it ends the walk (ADR 0051 rule 17).
    pub lower: Position,
    /// Entries per listing, clamped to `1..=MAX_QUERY_LIMIT`.
    pub limit: usize,
    /// `fields=parents`: fill [`Page::fields`] for the listing of every block (ADR 0051 rule
    /// 14: never with a parent).
    pub fields: bool,
}

/// The answer to a [`QueryPlan`]: one page per listing, in order, and `head`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct QueryAnswer {
    /// One page per listing.
    pub pages: Vec<Page>,
    /// ADR 0051 rule 18: the gap after the newest position the index held in this read
    /// transaction (any parent); `Position::default()` when it held none.
    pub head: Position,
}

/// Index errors: redb errors, plus a stored row that does not decode (corrupt index).
#[derive(Debug)]
pub enum IndexError {
    /// Any redb error.
    Db(redb::Error),
    /// A `blocks` row shorter than its fixed part or with a partial parent.
    CorruptRow,
}

impl core::fmt::Display for IndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "index: {e}"),
            Self::CorruptRow => f.write_str("index: corrupt row"),
        }
    }
}

impl std::error::Error for IndexError {}

impl IndexError {
    /// The operating-system error under this error, if any (ADR 0021 rules 7 and 37: the
    /// `errno` of `index_write_failed`; milestone 1c tells `ENOSPC` apart with it). redb 4.6.0
    /// has no `source()`: its `From` conversions turn `StorageError::Io` (alone, or inside
    /// `CommitError`, `TransactionError`, `TableError`...) into `Error::Io`, and a backend error
    /// into `Error::Backend`, which may box an `io::Error`.
    #[must_use]
    pub fn io_error(&self) -> Option<&std::io::Error> {
        match self {
            Self::Db(redb::Error::Io(e)) => Some(e),
            Self::Db(redb::Error::Backend(b)) => b.downcast_ref::<std::io::Error>(),
            _ => None,
        }
    }
}

impl<E: Into<redb::Error>> From<E> for IndexError {
    fn from(e: E) -> Self {
        Self::Db(e.into())
    }
}

/// What the relay needs from its index (ADR 0013 checklist, "Index trait"). Handlers depend on this
/// trait only, so that the backend can be replaced if the benchmark gate of ADR 0013 rule 23 fails.
/// [`RedbIndex`] is the only implementation.
pub trait IndexBackend: Send + Sync + Sized {
    /// Backend error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The operating-system error under `e`, if any (ADR 0021 rule 37). None by default.
    #[must_use]
    fn io_error(_: &Self::Error) -> Option<&std::io::Error> {
        None
    }

    /// Whether a restart of the relay may cure `e` (ADR 0018 rule 37, last bullet): only such
    /// failures count toward the fatal exit of `pool::FATAL_INDEX_FAILURES`. Every error by
    /// default.
    #[must_use]
    fn restart_may_cure(_: &Self::Error) -> bool {
        true
    }

    /// Opens or creates the index at `path` with a cache of `cache_bytes`, and recovers it after an
    /// unclean shutdown before returning: the index is ready when this returns (rule 11).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn open(path: &Path, cache_bytes: usize) -> Result<Self, Self::Error>;

    /// The epoch carried by cursors (rule 5).
    fn epoch(&self) -> u64;

    /// ADR 0024 rules 2 and 3: draws a new epoch from the operating system's random source,
    /// different from the current one, stores it and commits it durably before returning. Called
    /// by the start-up walk before its first orphan insert, before the index is shared with
    /// request handlers. Returns the new epoch, which [`IndexBackend::epoch`] then returns.
    ///
    /// # Errors
    ///
    /// Backend errors, or an error reading the random source. The epoch is then unchanged.
    fn renew_epoch(&self) -> Result<u64, Self::Error>;

    /// Indexes an accepted block and returns its position (rules 3, 4). With
    /// [`FileState::AlreadyHeld`], returns `None` and changes nothing if `id` is already indexed
    /// (rules 6, 9); with [`FileState::Created`], a stale entry for `id` is replaced (rule 13).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, Self::Error>;

    /// Makes every earlier insert durable (rule 10).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn flush(&self) -> Result<(), Self::Error>;

    /// Like [`IndexBackend::flush`], but only if a non-durable commit is pending. Returns whether
    /// it flushed. Called by the index writer thread (`pool`) every [`DURABLE_COMMIT_INTERVAL`], so
    /// that a quiet tail becomes durable (rule 10).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn flush_pending(&self) -> Result<bool, Self::Error>;

    /// The position of `id`, if indexed (rule 9).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, Self::Error>;

    /// One `asc` `/query` page from `from` (the later of `since` and the cursor, already raised
    /// to the expiry bound), by `parent` or over every block, at most `limit` entries (ADR 0012
    /// rules 6 to 14): [`IndexBackend::read_query`] with one listing. `limit` is clamped to
    /// `1..=MAX_QUERY_LIMIT`, so `more = true` always comes with at least one entry and a cursor
    /// that moved.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn query(
        &self,
        parent: Option<&BlockId>,
        from: Position,
        limit: usize,
    ) -> Result<Page, Self::Error> {
        let plan = QueryPlan {
            listings: vec![Listing {
                parent: parent.copied(),
                cursor: None,
            }],
            order: Order::Asc,
            lower: from,
            limit,
            fields: false,
        };
        Ok(self.read_query(&plan)?.pages.pop().unwrap_or_default())
    }

    /// Every listing of one `/query` request in one read transaction (ADR 0051 rules 15 to 25),
    /// with the `head` of that transaction (rule 18). `O(log n + limit)` per listing, forward or
    /// backward (rule 20). `plan.limit` is clamped to `1..=MAX_QUERY_LIMIT`.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn read_query(&self, plan: &QueryPlan) -> Result<QueryAnswer, Self::Error>;

    /// Up to `max` positions strictly before `before`, oldest first, each with the `block_id` it
    /// holds (rule 15: the sweeper deletes the cache entry and the file of that block). `max` is
    /// clamped to `1..=MAX_QUERY_LIMIT`.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, Self::Error>;

    /// Removes the entries of the blocks at `positions`; idempotent. Returns the number removed
    /// (rule 15).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn remove(&self, positions: &[Position]) -> Result<usize, Self::Error>;

    /// Number of indexed blocks.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn len(&self) -> Result<u64, Self::Error>;

    /// ADR 0046, at start-up before the index is shared: sets the demand epoch `epoch_ms` used to
    /// quantise `last_demand` on insert, and gives demand entries to every block that has none
    /// (an index written before ADR 0046), with `last_demand` its `received_at` quantised to its
    /// epoch. Returns the number of blocks given entries. A backend without demand entries does
    /// nothing (the default).
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn configure_demand(&self, _epoch_ms: u64) -> Result<u64, Self::Error> {
        Ok(0)
    }

    /// ADR 0046 rule 12: moves `last_demand` of each held block of `ids` forward to
    /// `epoch_start`, in one transaction. A block not indexed, or whose `last_demand` is already
    /// `epoch_start` or later, is skipped: at most one update per block per epoch. Returns the
    /// number of blocks updated.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn record_demand(&self, _ids: &[BlockId], _epoch_start: u64) -> Result<u64, Self::Error> {
        Ok(0)
    }

    /// ADR 0046 rules 6 and 7: up to `max` blocks with `last_demand ≤ bound`, in increasing order
    /// of `(last_demand, position)`. `max` is clamped to `1..=MAX_QUERY_LIMIT`. Order entries
    /// whose block row is missing are skipped and counted, without counting toward `max`, up to
    /// [`ORPHAN_SCAN_MAX`] of them (security review 2026-11-21, I-3). None by default.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn demand_candidates(&self, _bound: u64, _max: usize) -> Result<Candidates, Self::Error> {
        Ok(Candidates::default())
    }

    /// The position and `last_demand` of `id`, if indexed (the re-check of ADR 0046 rule 22).
    /// A block without a demand entry has `last_demand = u64::MAX`: never a candidate. `None` by
    /// default.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn demand_state(&self, _id: &BlockId) -> Result<Option<(Position, u64)>, Self::Error> {
        Ok(None)
    }

    /// The smallest `last_demand` of the index (the `demand_coldest_ms` gauge, ADR 0046 rule
    /// 29), `None` when empty or by default.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn coldest_demand(&self) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }

    /// `true` when no block is indexed.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.len()? == 0)
    }
}

struct WriterState {
    last: Option<Position>,
    last_durable: Instant,
    /// A non-durable commit happened since the last durable one.
    pending: bool,
}

/// The redb index. One writer assigns positions (ADR 0013 rule 3); readers run concurrently.
pub struct RedbIndex {
    db: Database,
    /// Changed only by [`IndexBackend::renew_epoch`], during the start-up walk (ADR 0024).
    epoch: AtomicU64,
    writer: Mutex<WriterState>,
    /// The demand epoch `E` (ADR 0046 rule 9), set by [`IndexBackend::configure_demand`].
    demand_epoch_ms: AtomicU64,
    /// The index was open, not closed cleanly, when this process opened it (ADR 0046 rule 13).
    unclean: bool,
    /// The suspension end recorded by the last clean close (security review 2026-11-21, L-1).
    suspended_until: u64,
}

impl IndexBackend for RedbIndex {
    type Error = IndexError;

    fn io_error(e: &IndexError) -> Option<&std::io::Error> {
        e.io_error()
    }

    /// A failure of redb itself; not a corrupt row, which a restart does not cure and which any
    /// client reaching the row could turn into a restart loop (security review of 1c-limits,
    /// L-1). A corrupt row is still logged and counted (ADR 0021 rule 37).
    fn restart_may_cure(e: &IndexError) -> bool {
        matches!(e, IndexError::Db(_))
    }

    /// Opens or creates the index at `path` with a redb cache of `cache_bytes` (rule 24). A new
    /// index draws a random epoch (rule 5). After an unclean shutdown redb repairs the file here.
    ///
    /// # Errors
    ///
    /// redb errors, or an error reading the system random source.
    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        let db = Builder::new().set_cache_size(cache_bytes).create(path)?;
        // The default durability (`Immediate`): the `open` mark is on disk before any request.
        let txn = db.begin_write()?;
        let (epoch, last, unclean, suspended_until) = {
            let mut meta = txn.open_table(META)?;
            let stored = meta.get(EPOCH_KEY)?.map(|g| g.value());
            let epoch = if let Some(epoch) = stored {
                epoch
            } else {
                let epoch = random_u64().map_err(|e| IndexError::Db(e.into()))?;
                meta.insert(EPOCH_KEY, epoch)?;
                epoch
            };
            // ADR 0046 rule 13: still marked open means the last run did not close it.
            let unclean = meta.get(OPEN_KEY)?.map(|g| g.value()) == Some(1);
            meta.insert(OPEN_KEY, 1)?;
            let suspended_until = meta.get(SUSPENDED_KEY)?.map_or(0, |g| g.value());
            txn.open_table(IDS)?;
            txn.open_table(EDGES)?;
            txn.open_table(DEMAND)?;
            txn.open_table(DEMAND_ORDER)?;
            let blocks = txn.open_table(BLOCKS)?;
            let last = blocks.last()?.map(|(k, _)| Position::from_key(k.value()));
            // A new index has nothing to migrate.
            if last.is_none() && meta.get(DEMAND_KEY)?.is_none() {
                meta.insert(DEMAND_KEY, 1)?;
            }
            (epoch, last, unclean, suspended_until)
        };
        txn.commit()?;
        Ok(Self {
            db,
            epoch: AtomicU64::new(epoch),
            writer: Mutex::new(WriterState {
                last,
                last_durable: Instant::now(),
                pending: false,
            }),
            demand_epoch_ms: AtomicU64::new(DEFAULT_DEMAND_EPOCH_MS),
            unclean,
            suspended_until,
        })
    }

    /// The epoch carried by cursors (rule 5).
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// ADR 0024 rules 2 and 3. The commit has redb's default durability (`Immediate`); it also
    /// makes every earlier non-durable commit durable.
    fn renew_epoch(&self) -> Result<u64, IndexError> {
        let mut w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = self.epoch.load(Ordering::Acquire);
        let random = || random_u64().map_err(|e| IndexError::Db(e.into()));
        let mut epoch = random()?;
        // Rule 2: never the previous epoch.
        while epoch == old {
            epoch = random()?;
        }
        let txn = self.db.begin_write()?;
        txn.open_table(META)?.insert(EPOCH_KEY, epoch)?;
        txn.commit()?;
        w.last_durable = Instant::now();
        w.pending = false;
        self.epoch.store(epoch, Ordering::Release);
        Ok(epoch)
    }

    /// Indexes an accepted block (rule 4): its position, `block_id`, length and one edge per parent.
    /// `now_ms` is the relay clock; if it stepped back, the last `received_at` is reused (rule 3).
    /// If `id` is already indexed: with [`FileState::AlreadyHeld`], returns `None` and changes
    /// nothing (rule 6); with [`FileState::Created`], removes the stale entry and indexes the block
    /// at a new position, in the same transaction (rule 13, security review F-2).
    ///
    /// Each insert is a non-durable commit; a durable commit follows at most every
    /// [`DURABLE_COMMIT_INTERVAL`] (rule 10). Call [`IndexBackend::flush`] at shutdown.
    ///
    /// # Errors
    ///
    /// redb errors. A panic of another writer poisons nothing: the state is only a position.
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, IndexError> {
        let mut w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pos = Position::assign(w.last, now_ms);
        let durable = w.last_durable.elapsed() >= DURABLE_COMMIT_INTERVAL;
        let mut txn = self.db.begin_write()?;
        if !durable {
            txn.set_durability(Durability::None)?;
        }
        {
            let id = id.as_bytes();
            let mut t = Tables::open(&txn)?;
            let existing = t.ids.get(id)?.map(|g| Position::from_key(g.value()));
            if let Some(old) = existing {
                if state == FileState::AlreadyHeld {
                    drop(t);
                    txn.abort()?;
                    return Ok(None);
                }
                t.remove_entries(old)?;
            }
            t.ids.insert(id, pos.key())?;
            let mut row = Vec::with_capacity(ROW_HEAD + 32 * parents.len());
            row.extend_from_slice(id);
            row.extend_from_slice(&len.to_be_bytes());
            // ADR 0046 rule 10: the acceptance is a demand of the block, and of each held parent.
            let demand = crate::demand::epoch_start(
                pos.received_at,
                self.demand_epoch_ms.load(Ordering::Relaxed),
            );
            for parent in parents {
                row.extend_from_slice(parent.as_bytes());
                t.edges
                    .insert((parent.as_bytes(), pos.received_at, pos.n), id)?;
                t.demand_forward(parent.as_bytes(), demand)?;
            }
            t.blocks.insert(pos.key(), row.as_slice())?;
            t.set_demand(pos, None, demand)?;
        }
        txn.commit()?;
        w.last = Some(pos);
        if durable {
            w.last_durable = Instant::now();
            w.pending = false;
        } else {
            w.pending = true;
        }
        Ok(Some(pos))
    }

    /// Makes every earlier commit durable (rule 10: at most every second, and at shutdown).
    ///
    /// # Errors
    ///
    /// redb errors.
    fn flush(&self) -> Result<(), IndexError> {
        let mut w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.db.begin_write()?.commit()?;
        w.last_durable = Instant::now();
        w.pending = false;
        Ok(())
    }

    fn flush_pending(&self) -> Result<bool, IndexError> {
        let mut w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !w.pending {
            return Ok(false);
        }
        self.db.begin_write()?.commit()?;
        w.last_durable = Instant::now();
        w.pending = false;
        Ok(true)
    }

    /// The position of `id`, if indexed (rule 9 repair check).
    ///
    /// # Errors
    ///
    /// redb errors.
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, IndexError> {
        let txn = self.db.begin_read()?;
        let ids = txn.open_table(IDS)?;
        Ok(ids
            .get(id.as_bytes())?
            .map(|g| Position::from_key(g.value())))
    }

    /// Every listing of one `/query` request (ADR 0012 rules 6 to 10, ADR 0051 rules 15 to 25)
    /// in one read transaction: the children of each `parent`, or every block, forward or
    /// backward, `O(log n + limit)` each (ADR 0012 rule 14, ADR 0051 rule 20), and `head`, from
    /// the last key of `blocks`. The caller passes `lower` already raised to the expiry bound
    /// (ADR 0013 rule 14).
    ///
    /// # Errors
    ///
    /// redb errors, `CorruptRow`.
    fn read_query(&self, plan: &QueryPlan) -> Result<QueryAnswer, IndexError> {
        let limit = plan.limit.clamp(1, MAX_QUERY_LIMIT);
        let desc = plan.order == Order::Desc;
        let txn = self.db.begin_read()?;
        let blocks = txn.open_table(BLOCKS)?;
        let head = blocks.last()?.map_or_else(Position::default, |(k, _)| {
            Position::from_key(k.value()).next()
        });
        let mut edges = None;
        let mut pages = Vec::with_capacity(plan.listings.len());
        for listing in &plan.listings {
            // ADR 0051 rules 16 and 17: `asc` reads forward from the later of the lower bound
            // and the cursor; `desc` reads backward from the cursor (the newest gap without one)
            // down to the lower bound. An empty interval reads nothing.
            let (from, upper) = if desc {
                (plan.lower, listing.cursor.unwrap_or(head))
            } else {
                (plan.lower.max(listing.cursor.unwrap_or_default()), head)
            };
            let mut entries = Vec::with_capacity(limit);
            let mut fields = Vec::new();
            let more = if desc && from >= upper {
                false
            } else if let Some(parent) = listing.parent.as_ref().map(BlockId::as_bytes) {
                let edges = match &mut edges {
                    Some(t) => t,
                    None => edges.insert(txn.open_table(EDGES)?),
                };
                let push = |k: &redb::AccessGuard<'_, (&Id, u64, u32)>,
                            v: &redb::AccessGuard<'_, &Id>| {
                    let (_, received_at, n) = k.value();
                    entries.push((Position { received_at, n }, BlockId(*v.value())));
                    Ok(())
                };
                let lo = (parent, from.received_at, from.n);
                if desc {
                    let hi = (parent, upper.received_at, upper.n);
                    walk(edges.range(lo..hi)?.rev(), limit, push)?
                } else {
                    walk(edges.range(lo..=(parent, u64::MAX, u32::MAX))?, limit, push)?
                }
            } else {
                let push = |k: &redb::AccessGuard<'_, (u64, u32)>,
                            v: &redb::AccessGuard<'_, &[u8]>| {
                    let row = v.value();
                    let id = row.get(..32).and_then(|b| Id::try_from(b).ok());
                    entries.push((
                        Position::from_key(k.value()),
                        BlockId(id.ok_or(IndexError::CorruptRow)?),
                    ));
                    if plan.fields {
                        fields.push(entry_fields(row)?);
                    }
                    Ok(())
                };
                if desc {
                    walk(blocks.range(from.key()..upper.key())?.rev(), limit, push)?
                } else {
                    walk(blocks.range(from.key()..)?, limit, push)?
                }
            };
            let next = match (desc, entries.last()) {
                (false, Some((p, _))) => p.next(),
                (false, None) => from,
                (true, Some((p, _))) => *p,
                (true, None) => upper,
            };
            pages.push(Page {
                entries,
                next,
                more,
                fields,
            });
        }
        Ok(QueryAnswer { pages, head })
    }

    /// Up to `max` positions strictly before `before`, oldest first (sweeper, rule 15).
    ///
    /// # Errors
    ///
    /// redb errors, `CorruptRow`.
    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, IndexError> {
        let txn = self.db.begin_read()?;
        let blocks = txn.open_table(BLOCKS)?;
        let max = max.clamp(1, MAX_QUERY_LIMIT);
        let mut out = Vec::with_capacity(max);
        for item in blocks.range(..before.key())?.take(max) {
            let (k, v) = item?;
            let id = v.value().get(..32).and_then(|b| Id::try_from(b).ok());
            out.push((
                Position::from_key(k.value()),
                BlockId(id.ok_or(IndexError::CorruptRow)?),
            ));
        }
        Ok(out)
    }

    /// Removes the entries of the blocks at `positions` in one durable transaction (rule 15, last
    /// step). Idempotent: a missing position is skipped. Returns the number removed.
    ///
    /// # Errors
    ///
    /// redb errors, `CorruptRow`.
    fn remove(&self, positions: &[Position]) -> Result<usize, IndexError> {
        let _w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let txn = self.db.begin_write()?;
        let mut removed = 0;
        {
            let mut t = Tables::open(&txn)?;
            for pos in positions {
                removed += usize::from(t.remove_entries(*pos)?);
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    /// Number of indexed blocks.
    ///
    /// # Errors
    ///
    /// redb errors.
    fn len(&self) -> Result<u64, IndexError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(BLOCKS)?.len()?)
    }

    /// Sets `E`, then, unless `meta` says it is done, gives demand entries to every block that has
    /// none, [`MIGRATION_BATCH`] blocks per durable transaction: an interrupted migration resumes
    /// at the next start, skipping the blocks already done. Marked done at the end.
    fn configure_demand(&self, epoch_ms: u64) -> Result<u64, IndexError> {
        let epoch_ms = epoch_ms.max(1);
        self.demand_epoch_ms.store(epoch_ms, Ordering::Relaxed);
        let _w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let done = self.db.begin_read()?.open_table(META)?.get(DEMAND_KEY)?;
        if done.is_some_and(|g| g.value() == 1) {
            return Ok(0);
        }
        // Security review 2026-11-21, I-4: counts and durations only, never a `block_id`.
        let started = Instant::now();
        let total = self.db.begin_read()?.open_table(BLOCKS)?.len()?;
        migration_line("start", &[("blocks", Value::Int(total))]);
        let mut filled = 0u64;
        let mut batches = 0u64;
        let mut from = Position::default();
        loop {
            let txn = self.db.begin_write()?;
            let more = {
                let mut t = Tables::open(&txn)?;
                let batch: Vec<Position> = t
                    .blocks
                    .range(from.key()..)?
                    .take(MIGRATION_BATCH)
                    .map(|r| r.map(|(k, _)| Position::from_key(k.value())))
                    .collect::<Result<_, _>>()?;
                for pos in &batch {
                    if t.demand.get(pos.key())?.is_none() {
                        let at = crate::demand::epoch_start(pos.received_at, epoch_ms);
                        t.set_demand(*pos, None, at)?;
                        filled += 1;
                    }
                }
                match batch.last() {
                    Some(last) if batch.len() == MIGRATION_BATCH => {
                        from = last.next();
                        true
                    }
                    _ => {
                        txn.open_table(META)?.insert(DEMAND_KEY, 1)?;
                        false
                    }
                }
            };
            txn.commit()?;
            batches += 1;
            if !more || batches.is_multiple_of(MIGRATION_LOG_EVERY) {
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                migration_line(
                    if more { "progress" } else { "end" },
                    &[
                        ("batches", Value::Int(batches)),
                        ("filled", Value::Int(filled)),
                        ("duration_ms", Value::Int(ms)),
                    ],
                );
            }
            if !more {
                return Ok(filled);
            }
        }
    }

    /// One transaction for `ids`, non-durable like an insert (rule 10 of ADR 0013): a crash
    /// before the next durable commit is an unclean start, which suspends demand eviction (ADR
    /// 0046 rule 13).
    fn record_demand(&self, ids: &[BlockId], epoch_start: u64) -> Result<u64, IndexError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let durable = w.last_durable.elapsed() >= DURABLE_COMMIT_INTERVAL;
        let mut txn = self.db.begin_write()?;
        if !durable {
            txn.set_durability(Durability::None)?;
        }
        let mut updated = 0;
        {
            let mut t = Tables::open(&txn)?;
            for id in ids {
                updated += u64::from(t.demand_forward(id.as_bytes(), epoch_start)?);
            }
        }
        txn.commit()?;
        if durable {
            w.last_durable = Instant::now();
            w.pending = false;
        } else {
            w.pending = true;
        }
        Ok(updated)
    }

    fn demand_candidates(&self, bound: u64, max: usize) -> Result<Candidates, IndexError> {
        let txn = self.db.begin_read()?;
        let order = txn.open_table(DEMAND_ORDER)?;
        let blocks = txn.open_table(BLOCKS)?;
        let max = max.clamp(1, MAX_QUERY_LIMIT);
        let mut out = Vec::with_capacity(max);
        let mut orphans = 0u64;
        for item in order.range(..=(bound, u64::MAX, u32::MAX))? {
            if out.len() >= max {
                break;
            }
            let (k, _) = item?;
            let (last_demand, received_at, n) = k.value();
            let position = Position { received_at, n };
            // Written in the same transaction as the row: a missing row (corruption) is not a
            // candidate. Skipped before counting, so that orphans at the head of the order
            // cannot fill the batch and stall every pass (security review 2026-11-21, I-3).
            let Some(row) = blocks.get(position.key())? else {
                orphans += 1;
                if orphans >= ORPHAN_SCAN_MAX {
                    break;
                }
                continue;
            };
            let row = row.value();
            let id = row.get(..32).and_then(|b| Id::try_from(b).ok());
            let len = row
                .get(32..ROW_HEAD)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes);
            let (Some(id), Some(len)) = (id, len) else {
                return Err(IndexError::CorruptRow);
            };
            out.push(Candidate {
                last_demand,
                position,
                id: BlockId(id),
                len,
            });
        }
        Ok(Candidates { list: out, orphans })
    }

    fn demand_state(&self, id: &BlockId) -> Result<Option<(Position, u64)>, IndexError> {
        let txn = self.db.begin_read()?;
        let ids = txn.open_table(IDS)?;
        let Some(pos) = ids
            .get(id.as_bytes())?
            .map(|g| Position::from_key(g.value()))
        else {
            return Ok(None);
        };
        let demand = txn.open_table(DEMAND)?;
        let last = demand.get(pos.key())?.map_or(u64::MAX, |g| g.value());
        Ok(Some((pos, last)))
    }

    fn coldest_demand(&self) -> Result<Option<u64>, IndexError> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .open_table(DEMAND_ORDER)?
            .first()?
            .map(|(k, _)| k.value().0))
    }
}

impl RedbIndex {
    /// Whether the index was still marked open when this process opened it: the previous run
    /// ended without a clean shutdown (ADR 0046 rule 13; ADR 0013 rule 9).
    #[must_use]
    pub fn unclean_start(&self) -> bool {
        self.unclean
    }

    /// The end, Unix milliseconds, of the demand-eviction suspension that was running when the
    /// index was last closed cleanly; `0` when none (security review 2026-11-21, L-1).
    #[must_use]
    pub fn suspended_until(&self) -> u64 {
        self.suspended_until
    }

    /// Records the `demand_eviction` setting of this start, durably, and returns the one of the
    /// previous start: `None` when none was recorded (an index written before this record, or a
    /// new index). Security review 2026-11-21, M-1: an off-to-on transition, or no record, means
    /// that the index holds no usable demand history.
    ///
    /// # Errors
    ///
    /// redb errors.
    pub fn record_demand_eviction(&self, on: bool) -> Result<Option<bool>, IndexError> {
        let _w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let txn = self.db.begin_write()?;
        let previous = {
            let mut meta = txn.open_table(META)?;
            let previous = meta.get(DEMAND_ON_KEY)?.map(|g| g.value() == 1);
            meta.insert(DEMAND_ON_KEY, u64::from(on))?;
            previous
        };
        txn.commit()?;
        Ok(previous)
    }

    /// Records a clean shutdown, durably: call once every write is done and durable, right before
    /// [`RedbIndex::close`]. An index closed without it is an unclean start at the next open.
    /// `suspended_until` is the end of the running demand-eviction suspension (`0` when none),
    /// restored at the next start so that a clean restart does not cancel it (security review
    /// 2026-11-21, L-1).
    ///
    /// # Errors
    ///
    /// redb errors.
    pub fn mark_clean(&self, suspended_until: u64) -> Result<(), IndexError> {
        let _w = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(SUSPENDED_KEY, suspended_until)?;
            meta.insert(OPEN_KEY, 0)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Closes the index at graceful shutdown and returns the error that dropping it would ignore
    /// (redb 4.5.0 `Database::close`). redb 4.6.0 also makes a pending non-durable commit durable
    /// here; the relay still calls [`IndexBackend::flush`] first, so that a failure to make the
    /// tail durable is reported apart from a failure to close the file.
    ///
    /// # Errors
    ///
    /// redb errors while closing the file, among them `TransactionInProgress` if a write
    /// transaction is still alive (the file is then closed when it ends, errors ignored).
    pub fn close(self) -> Result<(), IndexError> {
        self.db.close()?;
        Ok(())
    }

    /// The database, for the replication cursor table (ADR 0048 rule 8,
    /// `crate::replication::cursor`), which no other table refers to.
    #[cfg(feature = "replication")]
    pub(crate) fn database(&self) -> &Database {
        &self.db
    }
}

type Table<'t, K, V> = redb::Table<'t, K, V>;

/// The tables of one write transaction.
struct Tables<'t> {
    blocks: Table<'t, (u64, u32), &'static [u8]>,
    ids: Table<'t, &'static Id, (u64, u32)>,
    edges: Table<'t, (&'static Id, u64, u32), &'static Id>,
    demand: Table<'t, (u64, u32), u64>,
    order: Table<'t, (u64, u64, u32), ()>,
}

impl<'t> Tables<'t> {
    fn open(txn: &'t redb::WriteTransaction) -> Result<Self, IndexError> {
        Ok(Self {
            blocks: txn.open_table(BLOCKS)?,
            ids: txn.open_table(IDS)?,
            edges: txn.open_table(EDGES)?,
            demand: txn.open_table(DEMAND)?,
            order: txn.open_table(DEMAND_ORDER)?,
        })
    }

    /// Sets the demand entries of `pos` to `last` (ADR 0046 rule 26), replacing `old`.
    fn set_demand(&mut self, pos: Position, old: Option<u64>, last: u64) -> Result<(), IndexError> {
        if let Some(old) = old {
            self.order.remove((old, pos.received_at, pos.n))?;
        }
        self.demand.insert(pos.key(), last)?;
        self.order.insert((last, pos.received_at, pos.n), ())?;
        Ok(())
    }

    /// Moves `last_demand` of the indexed block `id` forward to `at` (ADR 0046 rule 11: never
    /// back). Returns whether an entry changed; an unknown block changes nothing.
    fn demand_forward(&mut self, id: &Id, at: u64) -> Result<bool, IndexError> {
        let Some(pos) = self.ids.get(id)?.map(|g| Position::from_key(g.value())) else {
            return Ok(false);
        };
        let old = self.demand.get(pos.key())?.map(|g| g.value());
        if old.is_some_and(|old| old >= at) {
            return Ok(false);
        }
        self.set_demand(pos, old, at)?;
        Ok(true)
    }

    /// Removes the `blocks` row at `pos`, its edges, its demand entries, and `ids[id]` if it still
    /// points at `pos` (a re-submission may own it at a newer position, rule 13). Edges in which
    /// the block is the parent belong to its children and stay (ADR 0046 rule 22). Returns
    /// whether a row existed.
    fn remove_entries(&mut self, pos: Position) -> Result<bool, IndexError> {
        if let Some(last) = self.demand.remove(pos.key())?.map(|g| g.value()) {
            self.order.remove((last, pos.received_at, pos.n))?;
        }
        let Some(row) = self.blocks.remove(pos.key())? else {
            return Ok(false);
        };
        let row = row.value();
        let (head, parents) = row
            .split_at_checked(ROW_HEAD)
            .ok_or(IndexError::CorruptRow)?;
        let id = head
            .get(..32)
            .and_then(|b| Id::try_from(b).ok())
            .ok_or(IndexError::CorruptRow)?;
        let (parents, rest) = parents.as_chunks::<32>();
        if !rest.is_empty() {
            return Err(IndexError::CorruptRow);
        }
        for parent in parents {
            self.edges.remove((parent, pos.received_at, pos.n))?;
        }
        if self.ids.get(&id)?.map(|g| g.value()) == Some(pos.key()) {
            self.ids.remove(&id)?;
        }
        Ok(true)
    }
}

/// One `demand_migration` line (security review 2026-11-21, I-4): `phase`, then `fields`.
/// Reads `range`, in the order it yields, into `push`: at most `limit` items. Returns whether
/// one more item existed (`more`, ADR 0012 rule 10).
fn walk<'a, K, V, R, F>(range: R, limit: usize, mut push: F) -> Result<bool, IndexError>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
    R: Iterator<
        Item = Result<(redb::AccessGuard<'a, K>, redb::AccessGuard<'a, V>), redb::StorageError>,
    >,
    F: FnMut(&redb::AccessGuard<'a, K>, &redb::AccessGuard<'a, V>) -> Result<(), IndexError>,
{
    for (n, item) in range.enumerate() {
        let (k, v) = item?;
        if n == limit {
            return Ok(true);
        }
        push(&k, &v)?;
    }
    Ok(false)
}

/// ADR 0051 rule 13: the length and the parents of a `blocks` row (`block_id` ‖ length ‖
/// parents, written by [`RedbIndex`]'s insert from a validated block).
fn entry_fields(row: &[u8]) -> Result<EntryFields, IndexError> {
    let len = row
        .get(32..ROW_HEAD)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .ok_or(IndexError::CorruptRow)?;
    let rest = row.get(ROW_HEAD..).ok_or(IndexError::CorruptRow)?;
    if rest.len() % 32 != 0 || rest.len() / 32 > usize::from(sbtp_core::layout::MAX_PARENTS) {
        return Err(IndexError::CorruptRow);
    }
    let parents = rest
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| BlockId(*c))
        .collect();
    Ok(EntryFields {
        len: u32::from_be_bytes(len),
        parents,
    })
}

fn migration_line(phase: &'static str, fields: &[(&'static str, Value<'_>)]) {
    let mut all = vec![("phase", Value::Str(phase))];
    all.extend_from_slice(fields);
    crate::log::emit(Event::DemandMigration, &all);
}

/// 64 random bits from the operating system (index epoch, rule 5).
fn random_u64() -> std::io::Result<u64> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::pool::IndexPool;
    use std::sync::Arc;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sbtp-index-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("index.redb")
    }

    fn id(b: u8) -> BlockId {
        BlockId([b; 32])
    }

    /// Insert of a block whose file was just created (the `201` case).
    fn put(idx: &RedbIndex, b: u8, parents: &[BlockId], now_ms: u64) -> Option<Position> {
        idx.insert(&id(b), 100, parents, now_ms, FileState::Created)
            .unwrap()
    }

    fn ids(page: &Page) -> Vec<BlockId> {
        page.entries.iter().map(|e| e.1).collect()
    }

    #[test]
    fn positions_increase_when_the_clock_steps_back() {
        let idx = RedbIndex::open(&tmp("clock"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let a = put(&idx, 1, &[], 1_000).unwrap();
        let b = put(&idx, 2, &[], 900).unwrap();
        let c = put(&idx, 3, &[], 1_000).unwrap();
        let d = put(&idx, 4, &[], 1_001).unwrap();
        let at = |received_at, n| Position { received_at, n };
        assert_eq!((a, b, c), (at(1_000, 0), at(1_000, 1), at(1_000, 2)));
        assert_eq!(d, Position::at(1_001));
    }

    #[test]
    fn repair_of_a_known_block_gets_no_position() {
        let idx = RedbIndex::open(&tmp("known"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let p = put(&idx, 1, &[id(9)], 10).unwrap();
        let again = idx.insert(&id(1), 100, &[id(9)], 20, FileState::AlreadyHeld);
        assert_eq!(again.unwrap(), None);
        assert_eq!(idx.len().unwrap(), 1);
        assert_eq!(idx.contains(&id(1)).unwrap(), Some(p));
        let page = idx.query(Some(&id(9)), Position::default(), 10).unwrap();
        assert_eq!(page.entries, vec![(p, id(1))]);
    }

    /// Security review F-2, first sequence: the sweeper has listed an expired block and deleted
    /// its file; the block is submitted again (new file, `201`) before the sweeper removes the
    /// index entries. The new acceptance must win: indexed at a new position, not evictable by the
    /// sweeper's pending batch, listed once.
    #[test]
    fn resubmission_during_a_sweep_supersedes_the_stale_entry() {
        let idx = RedbIndex::open(&tmp("resubmit"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let old = put(&idx, 1, &[id(9)], 10).unwrap();
        let batch = idx.expired(Position::at(20), 10).unwrap();
        assert_eq!(batch, vec![(old, id(1))]);
        let batch = [old];
        // The sweeper deletes the file here; the client re-submits.
        let new = put(&idx, 1, &[id(9)], 5_000).unwrap();
        assert!(new > old);
        assert_eq!(idx.remove(&batch).unwrap(), 0, "old row already superseded");
        assert_eq!(idx.contains(&id(1)).unwrap(), Some(new));
        assert_eq!(idx.len().unwrap(), 1);
        assert_eq!(idx.expired(Position::at(20), 10).unwrap(), vec![]);
        let page = idx.query(Some(&id(9)), Position::default(), 10).unwrap();
        assert_eq!(page.entries, vec![(new, id(1))]);
        assert_eq!(
            ids(&idx.query(None, Position::default(), 10).unwrap()),
            vec![id(1)]
        );
    }

    /// Security review F-2, second sequence: a crash between file deletion and index deletion
    /// leaves a phantom at an expired position (rule 8). A re-submission after restart must not be
    /// listed at the old position, where the next sweep would delete its fresh file.
    #[test]
    fn resubmission_over_a_crash_phantom_is_not_swept() {
        let path = tmp("phantom");
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let old = put(&idx, 1, &[id(9)], 10).unwrap();
        put(&idx, 2, &[], 11).unwrap();
        idx.flush().unwrap();
        drop(idx);
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let new = put(&idx, 1, &[id(9)], 5_000).unwrap();
        assert!(new > old);
        // Expiry bound between the old and the new acceptance: only block 2 is expired.
        let expired = idx.expired(Position::at(4_000), 10).unwrap();
        assert_eq!(expired, vec![(Position::at(11), id(2))]);
        assert_eq!(idx.contains(&id(1)).unwrap(), Some(new));
        let page = idx.query(Some(&id(9)), Position::default(), 10).unwrap();
        assert_eq!(page.entries, vec![(new, id(1))]);
    }

    #[test]
    fn query_pages_children_and_all_in_order() {
        let idx = RedbIndex::open(&tmp("query"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        for b in 1..=5u8 {
            let parents = if b % 2 == 1 {
                vec![id(100), id(200)]
            } else {
                vec![id(200)]
            };
            put(&idx, b, &parents, u64::from(b));
        }
        let p = idx.query(Some(&id(100)), Position::default(), 2).unwrap();
        assert_eq!(ids(&p), vec![id(1), id(3)]);
        assert!(p.more);
        let p = idx.query(Some(&id(100)), p.next, 2).unwrap();
        assert_eq!(ids(&p), vec![id(5)]);
        assert!(!p.more);
        let p = idx.query(None, Position::at(4), 10).unwrap();
        assert_eq!(ids(&p), vec![id(4), id(5)]);
        assert_eq!(
            idx.query(Some(&id(7)), Position::default(), 10).unwrap(),
            Page::default()
        );
    }

    /// Security review F-4: `limit = 0` must not give `more = true` with a cursor that does not
    /// move, and no `limit` may exceed `MAX_QUERY_LIMIT`.
    #[test]
    fn limit_is_clamped_and_always_makes_progress() {
        let idx = RedbIndex::open(&tmp("limit"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let total = u8::try_from(MAX_QUERY_LIMIT / 4 + 1).unwrap();
        for b in 1..=total {
            for k in 0..4u8 {
                let mut raw = [0u8; 32];
                raw[0] = b;
                raw[1] = k;
                raw[31] = 1; // never equal to `id(250)`
                let at = u64::from(b) * 10 + u64::from(k);
                idx.insert(&BlockId(raw), 100, &[id(250)], at, FileState::Created)
                    .unwrap();
            }
        }
        let n = idx.len().unwrap();
        assert!(n > MAX_QUERY_LIMIT as u64);
        for parent in [None, Some(&id(250))] {
            let p = idx.query(parent, Position::default(), 0).unwrap();
            assert_eq!(p.entries.len(), 1);
            assert!(p.more);
            assert!(p.next > Position::default());
            let p = idx.query(parent, Position::default(), usize::MAX).unwrap();
            assert_eq!(p.entries.len(), MAX_QUERY_LIMIT);
            assert!(p.more);
        }
        assert_eq!(idx.expired(Position::at(u64::MAX), 0).unwrap().len(), 1);
        assert_eq!(
            idx.expired(Position::at(u64::MAX), usize::MAX)
                .unwrap()
                .len(),
            MAX_QUERY_LIMIT
        );
    }

    #[test]
    fn remove_drops_every_entry_and_is_idempotent() {
        let path = tmp("remove");
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        for b in 1..=3u8 {
            put(&idx, b, &[id(100)], u64::from(b));
        }
        let old: Vec<Position> = idx
            .expired(Position::at(3), 10)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(old.len(), 2);
        assert_eq!(idx.remove(&old).unwrap(), 2);
        assert_eq!(idx.remove(&old).unwrap(), 0);
        assert_eq!(idx.contains(&id(1)).unwrap(), None);
        assert_eq!(idx.contains(&id(3)).unwrap(), Some(Position::at(3)));
        let page = idx.query(Some(&id(100)), Position::default(), 10).unwrap();
        assert_eq!(page.entries.len(), 1);
        let epoch = idx.epoch();
        idx.flush().unwrap();
        drop(idx);
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.epoch(), epoch);
        assert_eq!(idx.len().unwrap(), 1);
        // The writer resumes after the last stored position.
        let at = Position {
            received_at: 3,
            n: 1,
        };
        assert_eq!(put(&idx, 4, &[], 0), Some(at));
    }

    /// What `close` adds over `drop`: an error is returned, not swallowed. A live write
    /// transaction makes the close fail; the file still closes when it ends, and reopens intact.
    #[test]
    fn close_reports_a_live_write_transaction() {
        let path = tmp("close");
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        put(&idx, 1, &[id(100)], 1);
        idx.flush().unwrap();
        let txn = idx.db.begin_write().unwrap();
        let err = idx.close().unwrap_err();
        assert!(
            matches!(err, IndexError::Db(redb::Error::TransactionInProgress)),
            "{err}"
        );
        txn.abort().unwrap();
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.len().unwrap(), 1);
        idx.close().unwrap();
    }

    /// ADR 0046 rules 6, 7 and 26: candidates in increasing `(last_demand, position)`, bounded;
    /// `last_demand` only moves forward; removal drops the demand entries with the others; a
    /// child's insert refreshes its held parent.
    #[test]
    fn demand_order_and_entries() {
        let idx = RedbIndex::open(&tmp("demand"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let e = 1_000;
        idx.configure_demand(e).unwrap();
        let a = put(&idx, 1, &[], 10_500).unwrap();
        let b = put(&idx, 2, &[], 10_600).unwrap();
        let c = put(&idx, 3, &[], 12_100).unwrap();
        let ld = |b: u8| idx.demand_state(&id(b)).unwrap().unwrap().1;
        assert_eq!((ld(1), ld(2), ld(3)), (10_000, 10_000, 12_000), "quantised");
        let order = |bound| -> Vec<_> {
            idx.demand_candidates(bound, 10)
                .unwrap()
                .list
                .into_iter()
                .map(|c| (c.last_demand, c.position, c.id, c.len))
                .collect()
        };
        assert_eq!(
            order(11_999),
            vec![(10_000, a, id(1), 100), (10_000, b, id(2), 100)]
        );
        assert_eq!(order(12_000).len(), 3);
        assert_eq!(idx.demand_candidates(u64::MAX, 0).unwrap().list.len(), 1);
        // Forward only, once per epoch.
        assert_eq!(idx.record_demand(&[id(1), id(9)], 13_000).unwrap(), 1);
        assert_eq!(idx.record_demand(&[id(1)], 13_000).unwrap(), 0);
        assert_eq!(idx.record_demand(&[id(1)], 11_000).unwrap(), 0);
        assert_eq!(ld(1), 13_000);
        assert_eq!(
            order(12_999).iter().map(|c| c.2).collect::<Vec<_>>(),
            [id(2), id(3)]
        );
        // A child refreshes its held parent; an unknown parent changes nothing.
        put(&idx, 4, &[id(2), id(8)], 14_200).unwrap();
        assert_eq!(ld(2), 14_000);
        assert_eq!(idx.coldest_demand().unwrap(), Some(12_000));
        assert_eq!(idx.remove(&[c]).unwrap(), 1);
        assert_eq!(idx.demand_state(&id(3)).unwrap(), None);
        assert_eq!(idx.coldest_demand().unwrap(), Some(13_000));
        // A re-acceptance (`Created`) replaces the old entries, demand included.
        let again = put(&idx, 1, &[], 20_100).unwrap();
        assert_eq!(idx.demand_state(&id(1)).unwrap(), Some((again, 20_000)));
        assert_eq!(order(u64::MAX).len(), 3);
    }

    /// Security review 2026-11-21, I-3: order entries without a `blocks` row (corruption) at the
    /// head of the order are skipped and counted, without filling the batch; the scan of them is
    /// bounded by `ORPHAN_SCAN_MAX`.
    #[test]
    fn orphan_order_entries_do_not_stall_the_listing() {
        let idx = RedbIndex::open(&tmp("orphans"), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        idx.configure_demand(1_000).unwrap();
        let a = put(&idx, 1, &[], 10_500).unwrap();
        let b = put(&idx, 2, &[], 10_600).unwrap();
        let txn = idx.db.begin_write().unwrap();
        {
            let mut order = txn.open_table(DEMAND_ORDER).unwrap();
            for n in 0..25u32 {
                order.insert((0, 5, n), ()).unwrap();
            }
        }
        txn.commit().unwrap();
        let c = idx.demand_candidates(u64::MAX, 2).unwrap();
        assert_eq!(c.orphans, 25);
        assert_eq!(
            c.list.iter().map(|c| c.position).collect::<Vec<_>>(),
            [a, b]
        );
        let c = idx.demand_candidates(u64::MAX, 1).unwrap();
        assert_eq!((c.orphans, c.list.len()), (25, 1));
        // The bound: a listing past `ORPHAN_SCAN_MAX` orphans stops, with what it found.
        let txn = idx.db.begin_write().unwrap();
        {
            let mut order = txn.open_table(DEMAND_ORDER).unwrap();
            for n in 0..u32::try_from(ORPHAN_SCAN_MAX).unwrap() {
                order.insert((1, 6, n), ()).unwrap();
            }
        }
        txn.commit().unwrap();
        let c = idx.demand_candidates(u64::MAX, 10).unwrap();
        assert_eq!((c.orphans, c.list.len()), (ORPHAN_SCAN_MAX, 0));
    }

    /// ADR 0046 implementation plan, step 2: an index written before the demand tables gets them
    /// at the first start, `last_demand` its quantised `received_at`; once, then never again.
    #[test]
    fn demand_migration_fills_old_indexes_once() {
        let path = tmp("migrate");
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        for b in 1..=5u8 {
            put(&idx, b, &[], 1_000 * u64::from(b) + 7);
        }
        // What an index written before ADR 0046 looks like.
        let txn = idx.db.begin_write().unwrap();
        txn.delete_table(DEMAND).unwrap();
        txn.delete_table(DEMAND_ORDER).unwrap();
        txn.open_table(META).unwrap().remove(DEMAND_KEY).unwrap();
        txn.commit().unwrap();
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.demand_state(&id(2)).unwrap().unwrap().1, u64::MAX);
        assert_eq!(idx.configure_demand(2_000).unwrap(), 5);
        for b in 1..=5u8 {
            let at = 1_000 * u64::from(b) + 7;
            assert_eq!(
                idx.demand_state(&id(b)).unwrap().unwrap().1,
                at - at % 2_000
            );
        }
        assert_eq!(idx.demand_candidates(u64::MAX, 10).unwrap().list.len(), 5);
        assert_eq!(idx.configure_demand(2_000).unwrap(), 0, "done once");
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.configure_demand(2_000).unwrap(), 0);
    }

    /// ADR 0024 rules 2 and 3: a new epoch differs from the old one and is durable as soon as
    /// `renew_epoch` returns: a `SIGKILL` right after it (the crash between the epoch commit and
    /// the first orphan insert) leaves the new epoch. A reopen without renewal keeps the epoch.
    #[test]
    fn renewed_epoch_is_new_and_durable() {
        use std::io::BufRead;
        let path = tmp("epoch");
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let first = idx.epoch();
        idx.close().unwrap();
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.epoch(), first, "a reopen keeps the epoch");
        idx.close().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "index::tests::renew_epoch_child", "--nocapture"])
            .env(CHILD_PATH, &path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let out = std::io::BufReader::new(child.stdout.take().unwrap());
        let renewed: Option<u64> = out.lines().map_while(Result::ok).find_map(|l| {
            l.strip_prefix("RENEWED ")
                .and_then(|n| n.trim().parse().ok())
        });
        child.kill().unwrap(); // SIGKILL: no destructor, no flush
        child.wait().unwrap();
        let renewed = renewed.expect("child did not renew the epoch");
        assert_ne!(renewed, first);
        let idx = RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES).unwrap();
        assert_eq!(idx.epoch(), renewed);
    }

    /// Child side of `renewed_epoch_is_new_and_durable`: does nothing unless started by it.
    /// Renews the epoch, says `RENEWED <epoch>` (test protocol, not a log line), waits to be killed.
    #[test]
    #[allow(clippy::print_stdout)]
    fn renew_epoch_child() {
        let Ok(path) = std::env::var(CHILD_PATH) else {
            return;
        };
        let idx = RedbIndex::open(Path::new(&path), DEFAULT_INDEX_CACHE_BYTES).unwrap();
        let epoch = idx.renew_epoch().unwrap();
        println!("RENEWED {epoch}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    /// `IndexPool::shutdown` returns only once its threads hold no reference to the index.
    #[test]
    fn stopped_pool_releases_the_index() {
        let idx = Arc::new(RedbIndex::open(&tmp("stop"), DEFAULT_INDEX_CACHE_BYTES).unwrap());
        let pool = IndexPool::with(&idx, 2, 0, Duration::from_secs(1), 1).unwrap();
        for b in 1..=20u8 {
            put(&idx, b, &[], u64::from(b));
        }
        pool.shutdown().unwrap();
        Arc::try_unwrap(idx).ok().unwrap().close().unwrap();
    }

    /// ADR 0021 rule 37: the `errno` of an index failure, through the redb conversions.
    #[test]
    fn io_error_reaches_the_errno() {
        let enospc = || std::io::Error::from_raw_os_error(libc::ENOSPC);
        let errno = |e: &IndexError| e.io_error().and_then(std::io::Error::raw_os_error);
        let cases = [
            IndexError::from(redb::Error::Io(enospc())),
            IndexError::from(redb::StorageError::Io(enospc())),
            IndexError::from(redb::CommitError::Storage(redb::StorageError::Io(enospc()))),
            IndexError::from(redb::TransactionError::Storage(redb::StorageError::Io(
                enospc(),
            ))),
            IndexError::from(redb::Error::Backend(Box::new(enospc()))),
        ];
        for e in &cases {
            assert_eq!(errno(e), Some(libc::ENOSPC), "{e}");
        }
        assert_eq!(errno(&IndexError::CorruptRow), None);
        assert_eq!(
            errno(&IndexError::from(redb::Error::TransactionInProgress)),
            None
        );
    }

    const CHILD_PATH: &str = "SBTP_INDEX_TEST_CHILD_PATH";
    const CHILD_FLUSHER: &str = "SBTP_INDEX_TEST_CHILD_FLUSHER";
    const CHILD_INSERTS: u8 = 50;

    /// Child side of the quiet-tail tests: does nothing unless started by them. Inserts
    /// `CHILD_INSERTS` blocks, optionally runs the flusher, stays idle for more than
    /// `DURABLE_COMMIT_INTERVAL`, says `READY`, then waits to be killed.
    ///
    /// `READY` on standard output is a test protocol between this child process and
    /// `quiet_tail_survivors`, not a log line: the only print the relay lints allow, test only.
    #[test]
    #[allow(clippy::print_stdout)]
    fn quiet_tail_child() {
        let Ok(path) = std::env::var(CHILD_PATH) else {
            return;
        };
        let idx = Arc::new(RedbIndex::open(Path::new(&path), DEFAULT_INDEX_CACHE_BYTES).unwrap());
        // The writer thread of the pool flushes pending commits every `DURABLE_COMMIT_INTERVAL`.
        let _pool = std::env::var(CHILD_FLUSHER)
            .is_ok()
            .then(|| IndexPool::with(&idx, 1, 0, Duration::from_secs(1), 1).unwrap());
        for b in 1..=CHILD_INSERTS {
            put(&idx, b, &[id(200)], u64::from(b));
        }
        std::thread::sleep(DURABLE_COMMIT_INTERVAL + Duration::from_millis(700));
        println!("READY");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    /// Runs `quiet_tail_child` in a new process, kills it with `SIGKILL` once idle, reopens the
    /// index (crash repair) and returns the number of indexed blocks.
    fn quiet_tail_survivors(name: &str, flusher: bool) -> u64 {
        use std::io::BufRead;
        let path = tmp(name);
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "index::tests::quiet_tail_child", "--nocapture"])
            .env(CHILD_PATH, &path)
            .stdout(std::process::Stdio::piped());
        if flusher {
            cmd.env(CHILD_FLUSHER, "1");
        }
        let mut child = cmd.spawn().unwrap();
        let out = std::io::BufReader::new(child.stdout.take().unwrap());
        let ready = out
            .lines()
            .map_while(Result::ok)
            .any(|l| l.contains("READY"));
        child.kill().unwrap(); // SIGKILL: no destructor, no flush
        child.wait().unwrap();
        assert!(ready, "child did not reach READY");
        RedbIndex::open(&path, DEFAULT_INDEX_CACHE_BYTES)
            .unwrap()
            .len()
            .unwrap()
    }

    /// Security review F-3: with the flusher, entries become durable within the interval even
    /// when no insert follows.
    #[test]
    fn flusher_makes_a_quiet_tail_durable() {
        assert_eq!(
            quiet_tail_survivors("tail-flusher", true),
            u64::from(CHILD_INSERTS)
        );
    }

    /// Control for the test above: without the flusher the same sequence loses entries, so the
    /// test discriminates.
    #[test]
    fn without_flusher_a_quiet_tail_is_lost() {
        assert!(quiet_tail_survivors("tail-none", false) < u64::from(CHILD_INSERTS));
    }
}
