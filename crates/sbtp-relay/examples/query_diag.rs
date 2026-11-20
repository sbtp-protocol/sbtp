//! Diagnosis of the `/query` memory growth seen in step 2 of the ADR 0013 benchmark
//! (`docs/benchmarks/2026-11-18-query-memory-diagnosis.md`). Not a gate run, not shipped.
//!
//! ```text
//! query_diag load  <dataset> <work> blocks=N                  # redb index of the first N blocks
//! query_diag query <dataset> <work> [key=value ...]           # query load on that index
//! query_diag mem   <dataset> <work> blocks=N [key=value ...]  # load + queries, in-memory backend
//! ```
//!
//! Keys (defaults = the benchmark's step 2): `clients=8`, `cache_mib=4`, `limit=1000`, `pages=10`,
//! `queries=20000`, `max_readers=0` (0 = no bound on concurrent `query` calls). Half the queries
//! are by `parent`, half by `since`, as in the benchmark. Memory is measured from outside
//! (`/usr/bin/time -l`, `vmmap`, `heap`); the tool prints its pid and the resident size (`ps`)
//! after open and at the end.

#![allow(
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

#[allow(dead_code)]
#[path = "index_bench/common.rs"]
mod common;
#[allow(dead_code)]
#[path = "index_bench/dataset.rs"]
mod dataset;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Instant;

use common::{Mix, now_ms};
use sbtp_core::BlockId;
use sbtp_relay::index::{FileState, IndexBackend, MAX_QUERY_LIMIT, Page, Position, RedbIndex};

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Opts {
    blocks: u32,
    clients: u64,
    cache_mib: usize,
    limit: usize,
    pages: usize,
    queries: u64,
    max_readers: usize,
    churn_every: usize,
}

fn opts(args: &[&str]) -> R<Opts> {
    let mut o = Opts {
        blocks: 200_000,
        clients: 8,
        cache_mib: 4,
        limit: 1_000,
        pages: 10,
        queries: 20_000,
        max_readers: 0,
        churn_every: 0,
    };
    for a in args {
        let (k, v) = a.split_once('=').ok_or("expected key=value")?;
        match k {
            "blocks" => o.blocks = v.parse()?,
            "clients" => o.clients = v.parse()?,
            "cache_mib" => o.cache_mib = v.parse()?,
            "limit" => o.limit = v.parse()?,
            "pages" => o.pages = v.parse()?,
            "queries" => o.queries = v.parse()?,
            "max_readers" => o.max_readers = v.parse()?,
            "churn_every" => o.churn_every = v.parse()?,
            _ => return Err(format!("unknown key {k}").into()),
        }
    }
    Ok(o)
}

fn main() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let [cmd, ds, work, rest @ ..] = args.as_slice() else {
        return Err("usage: query_diag load|query|mem <dataset> <work> [key=value ...]".into());
    };
    let (ds, work, o) = (Path::new(ds), Path::new(work), opts(rest)?);
    println!("pid={} cmd={cmd}", std::process::id());
    match *cmd {
        "load" => {
            std::fs::create_dir_all(work)?;
            let idx = RedbIndex::open(&work.join("index.redb"), o.cache_mib << 20)?;
            let (t0, t1, loaded) = load(&idx, ds, o.blocks)?;
            idx.flush()?;
            std::fs::write(work.join("times"), format!("{t0} {t1} {loaded}"))?;
            rss("loaded")
        }
        "query" => {
            let idx = RedbIndex::open(&work.join("index.redb"), o.cache_mib << 20)?;
            let times = std::fs::read_to_string(work.join("times"))?;
            let t: Vec<u64> = times.split(' ').map(str::parse).collect::<Result<_, _>>()?;
            rss("opened")?;
            run_queries(&idx, ds, &o, t[0], t[1], t[2] as u32)
        }
        "mem" => {
            let idx = MemIndex {
                churn_every: o.churn_every,
                ..MemIndex::default()
            };
            let (t0, t1, loaded) = load(&idx, ds, o.blocks)?;
            rss("loaded")?;
            run_queries(&idx, ds, &o, t0, t1, loaded)
        }
        _ => Err(format!("unknown command {cmd}").into()),
    }
}

fn rss(label: &str) -> R<()> {
    println!("RSS {label} bytes={}", common::rss_bytes()?);
    std::io::stdout().flush()?;
    Ok(())
}

/// Single-threaded load of the first `n` blocks (the load is not under study here). Returns the
/// load interval and the number of blocks actually loaded (fewer than `n` if the data set ends).
fn load(idx: &impl IndexBackend, ds: &Path, n: u32) -> R<(u64, u64, u32)> {
    let mut r = BufReader::new(File::open(ds.join("blocks.bin"))?);
    let mut buf = Vec::new();
    let t0 = now_ms();
    let mut loaded = 0;
    while loaded < n && dataset::read_block(&mut r, &mut buf)? {
        let v = sbtp_core::validate_submitted(&buf, 0).map_err(|e| format!("{e:?}"))?;
        let len = u32::try_from(buf.len())?;
        idx.insert(
            v.block_id(),
            len,
            v.block().parents(),
            now_ms(),
            FileState::Created,
        )?
        .ok_or("duplicate block in data set")?;
        loaded += 1;
    }
    Ok((t0, now_ms(), loaded))
}

/// Counting semaphore bounding concurrent `query` calls (`max_readers`, the candidate bound).
struct Gate {
    max: usize,
    busy: Mutex<usize>,
    cv: Condvar,
}

impl Gate {
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        if self.max == 0 {
            return f();
        }
        let mut b = self
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *b >= self.max {
            b = self
                .cv
                .wait(b)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *b += 1;
        drop(b);
        let out = f();
        *self
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) -= 1;
        self.cv.notify_one();
        out
    }
}

fn run_queries(idx: &impl IndexBackend, ds: &Path, o: &Opts, t0: u64, t1: u64, n: u32) -> R<()> {
    let parents: Vec<BlockId> = dataset::read_sampled(ds)?
        .into_iter()
        .filter(|s| s.children.iter().all(|c| c.0 < n))
        .map(|s| s.parent)
        .collect();
    if parents.is_empty() || t1 < t0 {
        return Err("no parent to query".into());
    }
    let gate = Gate {
        max: o.max_readers,
        busy: Mutex::new(0),
        cv: Condvar::new(),
    };
    let t = Instant::now();
    let pages = std::thread::scope(|s| -> R<u64> {
        let workers: Vec<_> = (0..o.clients)
            .map(|c| {
                let (parents, gate) = (&parents, &gate);
                s.spawn(move || -> R<u64> {
                    let mut pages = 0;
                    for q in (c..o.queries).step_by(o.clients as usize) {
                        let (parent, mut from) = match common::mix(q, parents.len(), t0, t1) {
                            Mix::Parent(i) => (Some(parents[i]), Position::default()),
                            Mix::Since(since) => (None, Position::at(since)),
                        };
                        for _ in 0..o.pages {
                            let page = gate.run(|| idx.query(parent.as_ref(), from, o.limit))?;
                            pages += 1;
                            from = page.next;
                            if !page.more {
                                break;
                            }
                        }
                    }
                    Ok(pages)
                })
            })
            .collect();
        workers.into_iter().try_fold(0, |acc, w| {
            Ok(acc + w.join().map_err(|_| "client panicked")??)
        })
    })?;
    println!(
        "DONE queries={} pages={pages} secs={:.1}",
        o.queries,
        t.elapsed().as_secs_f64()
    );
    rss("end")
}

/// Trivial in-memory backend: the control that removes redb from the picture (bench only).
/// With `churn_every = k > 0`, each `query` also mimics a page cache: one 4 KiB buffer is
/// allocated per `k` entries returned and pushed into a shared FIFO of 4 MiB, whose oldest
/// buffers are freed by whichever client thread pushes next (the allocation pattern of redb's
/// read cache).
#[derive(Default)]
struct MemIndex {
    inner: RwLock<Mem>,
    churn_every: usize,
    cache: Mutex<VecDeque<Arc<[u8]>>>,
    /// Not durable: a memory index has no state across processes.
    epoch: AtomicU64,
}

static ZERO_PAGE: [u8; 4096] = [0; 4096];

#[derive(Default)]
struct Mem {
    last: Option<Position>,
    blocks: BTreeMap<Position, (BlockId, Vec<BlockId>)>,
    ids: HashMap<BlockId, Position>,
    edges: BTreeMap<(BlockId, Position), BlockId>,
}

impl Mem {
    /// Removes the block at `pos`, its edges, and `ids[id]` only if it still points at `pos` (a
    /// re-submission may own it at a newer position: ADR 0013 rule 13, as in `RedbIndex`).
    fn remove_at(&mut self, pos: Position) -> bool {
        let Some((id, parents)) = self.blocks.remove(&pos) else {
            return false;
        };
        for p in parents {
            self.edges.remove(&(p, pos));
        }
        if self.ids.get(&id) == Some(&pos) {
            self.ids.remove(&id);
        }
        true
    }
}

impl MemIndex {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Mem> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl IndexBackend for MemIndex {
    type Error = Infallible;

    fn open(_: &Path, _: usize) -> Result<Self, Infallible> {
        Ok(Self::default())
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Never called by this diagnosis (no start-up walk). ADR 0024 rule 2: always a new value.
    fn renew_epoch(&self) -> Result<u64, Infallible> {
        Ok(self.epoch.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
    }

    fn insert(
        &self,
        id: &BlockId,
        _len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, Infallible> {
        let mut m = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&old) = m.ids.get(id) {
            if state == FileState::AlreadyHeld {
                return Ok(None);
            }
            m.remove_at(old);
        }
        let pos = Position::assign(m.last, now_ms);
        m.last = Some(pos);
        m.ids.insert(*id, pos);
        for p in parents {
            m.edges.insert((*p, pos), *id);
        }
        m.blocks.insert(pos, (*id, parents.to_vec()));
        Ok(Some(pos))
    }

    fn flush(&self) -> Result<(), Infallible> {
        Ok(())
    }

    fn flush_pending(&self) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn contains(&self, id: &BlockId) -> Result<Option<Position>, Infallible> {
        Ok(self.read().ids.get(id).copied())
    }

    fn query(
        &self,
        parent: Option<&BlockId>,
        from: Position,
        limit: usize,
    ) -> Result<Page, Infallible> {
        let m = self.read();
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut entries = Vec::with_capacity(limit);
        let mut more = false;
        let mut push = |pos: Position, id: BlockId| {
            if entries.len() == limit {
                more = true;
                return false;
            }
            entries.push((pos, id));
            true
        };
        if let Some(p) = parent {
            let end = Position {
                received_at: u64::MAX,
                n: u32::MAX,
            };
            for (&(_, pos), &id) in m.edges.range((*p, from)..=(*p, end)) {
                if !push(pos, id) {
                    break;
                }
            }
        } else {
            for (&pos, (id, _)) in m.blocks.range(from..) {
                if !push(pos, *id) {
                    break;
                }
            }
        }
        drop(m);
        if let Some(n) = entries.len().checked_div(self.churn_every) {
            for _ in 0..n.max(1) {
                // Allocate and free outside the lock, concurrently across clients, as redb does.
                let page: Arc<[u8]> = Arc::from(&ZERO_PAGE[..]);
                let evicted = {
                    let mut cache = self
                        .cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    cache.push_back(page);
                    if cache.len() > 1024 {
                        cache.pop_front()
                    } else {
                        None
                    }
                };
                drop(evicted);
            }
        }
        let next = entries.last().map_or(from, |(p, _)| p.next());
        Ok(Page {
            entries,
            next,
            more,
        })
    }

    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, Infallible> {
        Ok(self
            .read()
            .blocks
            .range(..before)
            .take(max.clamp(1, MAX_QUERY_LIMIT))
            .map(|(p, (id, _))| (*p, *id))
            .collect())
    }

    fn remove(&self, positions: &[Position]) -> Result<usize, Infallible> {
        let mut m = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(positions.iter().filter(|pos| m.remove_at(**pos)).count())
    }

    fn len(&self) -> Result<u64, Infallible> {
        Ok(self.read().blocks.len() as u64)
    }
}
