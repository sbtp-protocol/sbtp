//! redb upgrade check of the relay index (`docs/security/2026-11-18-redb-4.6-exception.md`,
//! condition 3). Driven by `index_migration.sh`, which builds this file twice: once in a checkout of
//! the commit before the bump (redb 4.4.0) and once in the current tree. Not shipped.
//!
//! ```text
//! index_migration write   <index.redb> <blocks>   # deterministic blocks, flush, clean close
//! index_migration load    <index.redb>            # inserts until killed; prints LOADING when mid-load
//! index_migration inspect <index.redb>            # opens (crash repair), prints the summary line
//! ```
//!
//! The summary line is
//! `rows=<n> epoch=<hex> last=<received_at>.<n> blocks=<hex> ids=<hex> edges=<hex> meta=<hex>`.
//! `inspect` first opens the index through `RedbIndex::open` (the relay's open, with crash repair),
//! closes it, then reads the file with plain redb and computes one FNV-1a 64 digest per table over
//! every key and every full value: `blocks` rows (`block_id`, length, parents), `ids`, `edges` and
//! `meta`. It also checks that the tables agree with each other (`ids` and `edges` derived from
//! `blocks`, `len()` and a full `/query` scan). It uses only APIs present in both redb versions
//! and in both trees. The table layout is repeated from `src/index.rs`, which keeps it private.
//!
//! The kill harness of `index_migration.sh` repeats the idea of `quiet_tail_survivors` in the
//! index unit tests (child process, `SIGKILL` once a marker is printed) instead of sharing it: the
//! process killed here is built from another commit. Not factored, on purpose.

#![allow(missing_docs, clippy::print_stdout, clippy::indexing_slicing)]

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use redb::{Builder, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use sbtp_core::BlockId;
use sbtp_relay::index::{
    DEFAULT_INDEX_CACHE_BYTES, FileState, IndexBackend, MAX_QUERY_LIMIT, Position, RedbIndex,
};
use sbtp_relay::pool::IndexPool;

/// Fixed clock origin: positions do not depend on the wall clock.
const BASE_MS: u64 = 1_763_500_000_000;
/// The load mode reports LOADING after this much loading: past at least one durable commit.
const LOAD_BEFORE_READY: Duration = Duration::from_millis(1_500);

fn id(i: u64) -> BlockId {
    let mut raw = [0xA5u8; 32];
    raw[..8].copy_from_slice(&(i + 1).to_be_bytes());
    BlockId(raw)
}

/// Block `i`: one parent (the previous block), two from the fifth on, four blocks per millisecond.
fn insert(idx: &RedbIndex, i: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut parents = Vec::new();
    if i > 0 {
        parents.push(id(i - 1));
    }
    if i >= 4 {
        parents.push(id(i / 2));
    }
    let len = 100 + u32::try_from(i % 900)?;
    idx.insert(&id(i), len, &parents, BASE_MS + i / 4, FileState::Created)?;
    Ok(())
}

type Id = [u8; 32];
const BLOCKS: TableDefinition<(u64, u32), &[u8]> = TableDefinition::new("blocks");
const IDS: TableDefinition<&Id, (u64, u32)> = TableDefinition::new("ids");
const EDGES: TableDefinition<(&Id, u64, u32), &Id> = TableDefinition::new("edges");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// FNV-1a 64.
struct Digest(u64);

impl Digest {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn feed(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

fn check(ok: bool, what: &str) -> Res<()> {
    if ok { Ok(()) } else { Err(what.into()) }
}

/// Positions in order, from a full `/query` scan through the relay API.
fn scan(idx: &RedbIndex) -> Res<Vec<(Position, BlockId)>> {
    let mut from = Position::default();
    let mut out = Vec::new();
    loop {
        let page = idx.query(None, from, MAX_QUERY_LIMIT)?;
        out.extend_from_slice(&page.entries);
        if !page.more {
            return Ok(out);
        }
        from = page.next;
    }
}

fn summary(path: &Path) -> Res<String> {
    // Through the relay: crash repair, epoch, `len()`, `/query`.
    let (epoch, len, scanned) = {
        let idx = RedbIndex::open(path, DEFAULT_INDEX_CACHE_BYTES)?;
        (idx.epoch(), idx.len()?, scan(&idx)?)
    };
    // Every table, read raw.
    let db = Builder::new()
        .set_cache_size(DEFAULT_INDEX_CACHE_BYTES)
        .open(path)?;
    let txn = db.begin_read()?;
    let (mut dblocks, mut dids, mut dedges, mut dmeta) =
        (Digest::new(), Digest::new(), Digest::new(), Digest::new());
    let ids_t = txn.open_table(IDS)?;
    let edges_t = txn.open_table(EDGES)?;
    let mut rows: u64 = 0;
    let mut parents_total: u64 = 0;
    let mut last = None;
    for item in txn.open_table(BLOCKS)?.iter()? {
        let (k, v) = item?;
        let (received_at, n) = k.value();
        let row = v.value();
        dblocks.feed(&received_at.to_be_bytes());
        dblocks.feed(&n.to_be_bytes());
        dblocks.feed(row);
        check(
            row.len() >= 36 && (row.len() - 36) % 32 == 0,
            "blocks: malformed row",
        )?;
        let id: Id = row[..32].try_into()?;
        let pos = Position { received_at, n };
        check(
            scanned.get(usize::try_from(rows)?) == Some(&(pos, BlockId(id))),
            "blocks: differs from the /query scan",
        )?;
        check(
            ids_t.get(&id)?.map(|g| g.value()) == Some((received_at, n)),
            "ids: missing or wrong entry for a block",
        )?;
        for parent in row[36..].as_chunks::<32>().0 {
            check(
                edges_t.get((parent, received_at, n))?.map(|g| *g.value()) == Some(id),
                "edges: missing or wrong edge for a parent",
            )?;
            parents_total += 1;
        }
        last = Some(pos);
        rows += 1;
    }
    for item in ids_t.iter()? {
        let (k, v) = item?;
        let (received_at, n) = v.value();
        dids.feed(k.value());
        dids.feed(&received_at.to_be_bytes());
        dids.feed(&n.to_be_bytes());
    }
    let mut edges: u64 = 0;
    for item in edges_t.iter()? {
        let (k, v) = item?;
        let (parent, received_at, n) = k.value();
        dedges.feed(parent);
        dedges.feed(&received_at.to_be_bytes());
        dedges.feed(&n.to_be_bytes());
        dedges.feed(v.value());
        edges += 1;
    }
    let mut stored_epoch = None;
    for item in txn.open_table(META)?.iter()? {
        let (k, v) = item?;
        dmeta.feed(k.value().as_bytes());
        dmeta.feed(&v.value().to_be_bytes());
        if k.value() == "epoch" {
            stored_epoch = Some(v.value());
        }
    }
    check(rows == len, "len() differs from the blocks table")?;
    check(
        rows == u64::try_from(scanned.len())?,
        "/query scan differs from the blocks table",
    )?;
    check(ids_t.len()? == rows, "ids: extra entries")?;
    check(edges == parents_total, "edges: extra entries")?;
    check(
        stored_epoch == Some(epoch),
        "meta: epoch differs from the relay's",
    )?;
    let last = last.map_or_else(|| "none".into(), |p| format!("{}.{}", p.received_at, p.n));
    Ok(format!(
        "rows={rows} epoch={epoch:016x} last={last} blocks={:016x} ids={:016x} edges={:016x} meta={:016x}",
        dblocks.0, dids.0, dedges.0, dmeta.0
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: index_migration write <index.redb> <blocks> | load <index.redb> | inspect <index.redb>";
    let (Some(mode), Some(path)) = (args.get(1), args.get(2)) else {
        return Err(usage.into());
    };
    let path = Path::new(path);
    match mode.as_str() {
        "write" => {
            let blocks: u64 = args.get(3).ok_or(usage)?.parse()?;
            let idx = RedbIndex::open(path, DEFAULT_INDEX_CACHE_BYTES)?;
            for i in 0..blocks {
                insert(&idx, i)?;
            }
            idx.flush()?;
            drop(idx); // clean close
            println!("{}", summary(path)?);
        }
        "load" => {
            let idx = Arc::new(RedbIndex::open(path, DEFAULT_INDEX_CACHE_BYTES)?);
            // The writer thread of the pool flushes pending commits every
            // `DURABLE_COMMIT_INTERVAL`, as in the relay; kept alive until the process is killed.
            let _pool = IndexPool::with(&idx, 1, 0, Duration::from_secs(1), 1)?;
            let start = Instant::now();
            let mut ready = false;
            for i in 0.. {
                insert(&idx, i)?;
                if !ready && start.elapsed() >= LOAD_BEFORE_READY {
                    println!("LOADING inserted={}", i + 1);
                    std::io::stdout().flush()?;
                    ready = true;
                }
            }
        }
        "inspect" => println!("{}", summary(path)?),
        _ => return Err(usage.into()),
    }
    Ok(())
}
