//! ADR 0013 benchmark harness (gate of rule 23) for the redb index. Not shipped.
//!
//! ```text
//! index_bench gen <typical|adversarial> <dataset-dir>   # deterministic data set
//! index_bench run <dataset-dir> <work-dir>              # one run of the five steps
//! ```
//!
//! `run` starts one process per phase, as the protocol restarts the relay: `main` (steps 1 to 3),
//! `restart` (step 4), `load2` (killed with `SIGKILL` after `KILL_AFTER` accepted blocks) and
//! `recover` (step 5). Each process prints `MEASURE` lines: `VmHWM` (Linux, `/proc/self/status`) at
//! the end of every step, and the resident size at that instant (`ps`). On macOS the driver also
//! wraps each measured process in `/usr/bin/time -l` and prints its maximum resident set size.
//!
//! In process, without HTTP: 8 client threads call `validate_submitted` (difficulty 0) then
//! `IndexBackend::insert`, and `IndexBackend::query` for `/query`. Expected answers come from the data set
//! (`parents.bin`) and from an acceptance log written by the harness (`accept.log`, `pos.bin`),
//! never from the index under test.
//!
//! **Test key.** Every block is signed with the key derived from the public seed
//! `b"sbtp-relay-bench-public-test-key"` (`dataset.rs`). It is a published constant, not a secret:
//! a block signed with it proves nothing about its author and must never be trusted outside these
//! benchmarks.
//!
//! **Work directory.** `run` deletes and recreates `<work-dir>` only if it is absent, empty, or a
//! directory this tool created (it holds the marker file `.index_bench-work`). Anything else is
//! refused, so that a wrong path cannot delete unrelated data.

// Bench-only tool on its own fixed-size records, never on network input: plain indexing and lossy
// casts in statistics are acceptable here (they stay forbidden in the relay).
#![allow(
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::indexing_slicing
)]

mod common;
mod dataset;

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sbtp_core::BlockId;
use sbtp_relay::index::{DEFAULT_INDEX_CACHE_BYTES, FileState, IndexBackend, Position, RedbIndex};

use dataset::BLOCKS;

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Concurrent clients (steps 1, 2, 4, 5).
const CLIENTS: u64 = 8;
const LIMIT: usize = 1_000;
const MAX_PAGES: usize = 10;
/// Step 5: the second load is killed after this many accepted blocks (of 10,000).
const KILL_AFTER: u32 = 5_000;
/// Step 3: the oldest 10% of step 1 expire.
const EVICTED: u64 = BLOCKS as u64 / 10;
/// `block_ttl_ms` default (ADR 0013 rule 12), used for the expiry bound of step 2.
const DEFAULT_TTL_MS: u64 = 2_592_000_000;
/// `sweep_batch` default (ADR 0013 checklist).
const SWEEP_BATCH: usize = 1_000;
/// Acceptance log record: `received_at` u64, `n` u32, data set index u32, `block_id`.
const REC: usize = 48;
/// Latency histogram: 10 µs buckets up to 20 ms, then one overflow bucket.
const BUCKETS: usize = 2_001;

fn main() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["gen", kind, dir] => {
            let kind = dataset::Kind::parse(kind).ok_or("kind: typical or adversarial")?;
            Ok(dataset::generate(kind, Path::new(dir))?)
        }
        ["run", ds, work] => drive(Path::new(ds), Path::new(work)),
        ["phase", phase, ds, work] => phase_main(phase, Path::new(ds), Path::new(work)),
        _ => {
            Err("usage: index_bench gen <typical|adversarial> <dir> | run <dataset> <work>".into())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Driver

/// Marks a work directory as created by this tool (see the module documentation).
const WORK_MARKER: &str = ".index_bench-work";

/// Empties `work` if it is ours (marker present) or empty; refuses anything else.
fn prepare_work_dir(work: &Path) -> R<()> {
    match std::fs::symlink_metadata(work) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(m) if !m.is_dir() => {
            return Err(format!("{}: not a directory, refusing", work.display()).into());
        }
        Ok(_) => {
            let ours = std::fs::symlink_metadata(work.join(WORK_MARKER)).is_ok_and(|m| m.is_file());
            let empty = std::fs::read_dir(work)?.next().is_none();
            if !ours && !empty {
                return Err(format!(
                    "{}: not empty and not created by index_bench, refusing to delete it",
                    work.display()
                )
                .into());
            }
            std::fs::remove_dir_all(work)?;
        }
    }
    std::fs::create_dir_all(work)?;
    std::fs::write(work.join(WORK_MARKER), b"index_bench work directory\n")?;
    Ok(())
}

fn drive(ds: &Path, work: &Path) -> R<()> {
    prepare_work_dir(work)?;
    let exe = std::env::current_exe()?;
    measured(&exe, "main", ds, work)?;
    measured(&exe, "restart", ds, work)?;

    let mut child = Command::new(&exe)
        .args(["phase", "load2"])
        .arg(ds)
        .arg(work)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut killed = false;
    for line in BufReader::new(stdout).lines() {
        if line? == format!("accepted {KILL_AFTER}") {
            child.kill()?; // SIGKILL on Unix
            killed = true;
            break;
        }
    }
    let status = child.wait()?;
    println!(
        "MEASURE step=5 phase=load2 kill={} status={status}",
        if killed { "sigkill" } else { "missed" }
    );
    measured(&exe, "recover", ds, work)
}

/// Runs one phase as a new process; on macOS under `/usr/bin/time -l`.
fn measured(exe: &Path, phase: &str, ds: &Path, work: &Path) -> R<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/time");
        c.arg("-l").arg(exe);
        c
    } else {
        Command::new(exe)
    };
    let out = cmd
        .args(["phase", phase])
        .arg(ds)
        .arg(work)
        .stdout(Stdio::inherit())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr.lines() {
        for label in ["maximum resident set size", "peak memory footprint"] {
            if let Some(v) = line.trim().strip_suffix(label) {
                println!(
                    "MEASURE phase={phase} {}={}",
                    label.replace(' ', "_"),
                    v.trim()
                );
            }
        }
        if !line.contains("resident") && !line.contains("footprint") && line.contains("Error") {
            eprintln!("{line}");
        }
    }
    if !out.status.success() {
        eprint!("{stderr}");
        return Err(format!("phase {phase} failed: {}", out.status).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Phases

fn phase_main(phase: &str, ds: &Path, work: &Path) -> R<()> {
    let t0 = Instant::now();
    let idx = RedbIndex::open(&work.join("index.redb"), DEFAULT_INDEX_CACHE_BYTES)?;
    let startup = t0.elapsed();
    let sampled = dataset::read_sampled(ds)?;
    let floor_file = work.join("floor");
    match phase {
        "main" => {
            let t = Instant::now();
            let n = load(&idx, &ds.join("blocks.bin"), work, 0, false)?;
            idx.flush()?;
            let secs = t.elapsed().as_secs_f64();
            report(
                1,
                work,
                &format!("accepted={n} put_per_s={:.0}", f64::from(n) / secs),
            )?;

            let floor = Position::at(common::now_ms().saturating_sub(DEFAULT_TTL_MS));
            let s = queries(&idx, &sampled, work, 100_000, floor, false)?;
            report(2, work, &s.summary())?;

            // Step 3: `block_ttl_ms` such that the oldest 10% expire, then the sweeper.
            let log = Log::open(work)?;
            let cutoff = log.get(EVICTED - 1)?.ok_or("short log")?.pos.received_at;
            let floor = Position::at(cutoff + 1);
            let expected = log.lower_bound(floor)?;
            let t = Instant::now();
            let mut removed = 0u64;
            loop {
                let batch = idx.expired(floor, SWEEP_BATCH)?;
                if batch.is_empty() {
                    break;
                }
                let positions: Vec<Position> = batch.iter().map(|(p, _)| *p).collect();
                removed += idx.remove(&positions)? as u64;
            }
            let left = idx.len()?;
            let errors =
                u64::from(removed != expected) + u64::from(left != u64::from(n) - expected);
            std::fs::write(&floor_file, floor.received_at.to_string())?;
            report(
                3,
                work,
                &format!(
                    "ttl_ms={} expired={expected} removed={removed} left={left} sweep_s={:.2} errors={errors}",
                    common::now_ms() - cutoff,
                    t.elapsed().as_secs_f64()
                ),
            )?;
            idx.flush()?;
        }
        "restart" | "recover" => {
            let floor = Position::at(std::fs::read_to_string(&floor_file)?.trim().parse()?);
            let after_kill = phase == "recover";
            let mut s = queries(&idx, &sampled, work, 1_000, floor, after_kill)?;
            if after_kill {
                s.errors += check_step1(&idx, work, floor)?;
            }
            let step = if after_kill { 5 } else { 4 };
            let extra = format!("startup_ms={} {}", startup.as_millis(), s.summary());
            report(step, work, &extra)?;
            idx.flush()?;
        }
        "load2" => {
            load(&idx, &ds.join("blocks2.bin"), work, BLOCKS, true)?;
            idx.flush()?;
            println!("done");
        }
        _ => return Err(format!("unknown phase {phase}").into()),
    }
    Ok(())
}

fn report(step: u32, work: &Path, extra: &str) -> R<()> {
    let rss = common::rss_bytes()?;
    let vmhwm = common::vmhwm_bytes().map(|b| b.to_string());
    let redb = std::fs::metadata(work.join("index.redb"))?.len();
    println!(
        "MEASURE step={step} vmhwm_bytes={} rss_now_bytes={} redb_bytes={redb} {extra}",
        vmhwm.as_deref().unwrap_or("n/a"),
        rss
    );
    std::io::stdout().flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Acceptance log (expected answers)

struct Rec {
    pos: Position,
    idx: u32,
    id: BlockId,
}

struct Recorder {
    log: File,
    pos: File,
    accepted: u32,
}

impl Recorder {
    fn open(work: &Path) -> std::io::Result<Self> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(work.join("accept.log"))?;
        let pos = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(work.join("pos.bin"))?;
        Ok(Self {
            log,
            pos,
            accepted: 0,
        })
    }

    fn write(&mut self, pos: Position, idx: u32, id: &BlockId) -> std::io::Result<()> {
        let mut rec = [0u8; REC];
        rec[..8].copy_from_slice(&pos.received_at.to_be_bytes());
        rec[8..12].copy_from_slice(&pos.n.to_be_bytes());
        rec[12..16].copy_from_slice(&idx.to_be_bytes());
        rec[16..].copy_from_slice(id.as_bytes());
        self.log.write_all(&rec)?;
        self.pos.write_all_at(&rec[..12], u64::from(idx) * 12)?;
        self.accepted += 1;
        Ok(())
    }
}

struct Log {
    file: File,
    pos: File,
    len: u64,
}

/// Record `i` of a buffer filled by [`Log::read_into`].
fn rec_at(buf: &[u8], i: usize) -> Rec {
    let c = &buf[i * REC..(i + 1) * REC];
    let mut id = [0u8; 32];
    id.copy_from_slice(&c[16..]);
    let mut idx = [0u8; 4];
    idx.copy_from_slice(&c[12..16]);
    Rec {
        pos: decode_pos(c),
        idx: u32::from_be_bytes(idx),
        id: BlockId(id),
    }
}

fn decode_pos(b: &[u8]) -> Position {
    let mut r = [0u8; 8];
    r.copy_from_slice(&b[..8]);
    let mut n = [0u8; 4];
    n.copy_from_slice(&b[8..12]);
    Position {
        received_at: u64::from_be_bytes(r),
        n: u32::from_be_bytes(n),
    }
}

impl Log {
    fn open(work: &Path) -> std::io::Result<Self> {
        let file = File::open(work.join("accept.log"))?;
        let len = file.metadata()?.len() / REC as u64;
        Ok(Self {
            file,
            pos: File::open(work.join("pos.bin"))?,
            len,
        })
    }

    /// Reads up to `n` records from record `k` into `buf` (reused: the harness must not add
    /// allocator churn of its own to the measure). Returns the number read.
    fn read_into(&self, k: u64, n: u64, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let n = n.min(self.len.saturating_sub(k)) as usize;
        buf.resize(n * REC, 0);
        self.file.read_exact_at(buf, k * REC as u64)?;
        Ok(n)
    }

    /// Record `k`, if it exists.
    fn get(&self, k: u64) -> std::io::Result<Option<Rec>> {
        if k >= self.len {
            return Ok(None);
        }
        let mut b = [0u8; REC];
        self.file.read_exact_at(&mut b, k * REC as u64)?;
        Ok(Some(rec_at(&b, 0)))
    }

    /// First record at or after `p`.
    fn lower_bound(&self, p: Position) -> std::io::Result<u64> {
        let (mut lo, mut hi) = (0, self.len);
        while lo < hi {
            let mid = u64::midpoint(lo, hi);
            if self.get(mid)?.is_some_and(|r| r.pos < p) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Position recorded for data set index `idx`, if it was accepted.
    fn pos_of(&self, idx: u32) -> std::io::Result<Option<Position>> {
        let mut b = [0u8; 12];
        match self.pos.read_exact_at(&mut b, u64::from(idx) * 12) {
            Ok(()) if b != [0u8; 12] => Ok(Some(decode_pos(&b))),
            Ok(()) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Step 1 and the second load: `PUT` path up to the index

fn load(idx: &impl IndexBackend, file: &Path, work: &Path, first: u32, progress: bool) -> R<u32> {
    let reader = Mutex::new((BufReader::new(File::open(file)?), first));
    let rec = Mutex::new(Recorder::open(work)?);
    std::thread::scope(|s| {
        let workers: Vec<_> = (0..CLIENTS)
            .map(|_| {
                s.spawn(|| -> R<()> {
                    let mut buf = Vec::new();
                    loop {
                        let i = {
                            let mut g = reader.lock().map_err(|_| "poisoned")?;
                            if !dataset::read_block(&mut g.0, &mut buf)? {
                                return Ok(());
                            }
                            g.1 += 1;
                            g.1 - 1
                        };
                        // spec §4 PUT: validation (difficulty 0 per the protocol), then the index.
                        let v =
                            sbtp_core::validate_submitted(&buf, 0).map_err(|e| format!("{e:?}"))?;
                        let len = u32::try_from(buf.len())?;
                        let mut r = rec.lock().map_err(|_| "poisoned")?;
                        let pos = idx
                            .insert(
                                v.block_id(),
                                len,
                                v.block().parents(),
                                common::now_ms(),
                                FileState::Created,
                            )?
                            .ok_or("duplicate block in data set")?;
                        r.write(pos, i, v.block_id())?;
                        if progress && r.accepted % 500 == 0 {
                            println!("accepted {}", r.accepted);
                            std::io::stdout().flush()?;
                        }
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .try_for_each(|w| w.join().map_err(|_| "worker panicked")?)
    })?;
    Ok(rec.lock().map_err(|_| "poisoned")?.accepted)
}

// ---------------------------------------------------------------------------------------------
// Steps 2, 4, 5: `/query`

#[derive(Default)]
struct Stats {
    queries: u64,
    requests: u64,
    errors: u64,
    unlogged_tail: u64,
    hist: Vec<u32>,
    secs: f64,
    /// Per-client buffer for acceptance log reads.
    scratch: Vec<u8>,
}

impl Stats {
    fn merge(&mut self, o: &Self) {
        self.queries += o.queries;
        self.requests += o.requests;
        self.errors += o.errors;
        self.unlogged_tail += o.unlogged_tail;
        self.hist.resize(BUCKETS, 0);
        for (a, b) in self.hist.iter_mut().zip(&o.hist) {
            *a += b;
        }
    }

    fn record(&mut self, d: Duration) {
        self.hist.resize(BUCKETS, 0);
        let b = (d.as_micros() / 10).min(BUCKETS as u128 - 1) as usize;
        self.hist[b] += 1;
        self.requests += 1;
    }

    fn p99_us(&self) -> usize {
        let total: u64 = self.hist.iter().map(|&c| u64::from(c)).sum();
        let mut seen = 0;
        for (i, &c) in self.hist.iter().enumerate() {
            seen += u64::from(c);
            if seen * 100 >= total * 99 {
                return (i + 1) * 10;
            }
        }
        0
    }

    fn summary(&self) -> String {
        format!(
            "queries={} requests={} req_per_s={:.0} p99_us<={} unlogged_tail={} errors={}",
            self.queries,
            self.requests,
            self.requests as f64 / self.secs,
            self.p99_us(),
            self.unlogged_tail,
            self.errors
        )
    }
}

/// `count` queries from 8 clients: even ones by `parent` (drawn from `parents.bin`), odd ones by
/// `since` (uniform over the `received_at` of step 1). Each is followed for at most 10 pages.
/// `after_kill`: blocks of the second load MAY be missing (step 5).
fn queries(
    idx: &impl IndexBackend,
    sampled: &[dataset::Sampled],
    work: &Path,
    count: u64,
    floor: Position,
    after_kill: bool,
) -> R<Stats> {
    let log = Log::open(work)?;
    let first = log.get(0)?.ok_or("empty log")?.pos.received_at;
    let last = log
        .get(u64::from(BLOCKS) - 1)?
        .ok_or("short log")?
        .pos
        .received_at;
    let t = Instant::now();
    let mut total = std::thread::scope(|s| -> R<Stats> {
        let workers: Vec<_> = (0..CLIENTS)
            .map(|c| {
                let log = &log;
                s.spawn(move || -> R<Stats> {
                    let mut st = Stats::default();
                    for q in (c..count).step_by(CLIENTS as usize) {
                        let ok = match common::mix(q, sampled.len(), first, last) {
                            common::Mix::Parent(i) => {
                                parent_query(idx, log, &sampled[i], floor, after_kill, &mut st)?
                            }
                            common::Mix::Since(since) => {
                                since_query(idx, log, since, floor, after_kill, &mut st)?
                            }
                        };
                        st.queries += 1;
                        st.errors += u64::from(!ok);
                    }
                    Ok(st)
                })
            })
            .collect();
        let mut total = Stats::default();
        for w in workers {
            total.merge(&w.join().map_err(|_| "client panicked")??);
        }
        Ok(total)
    })?;
    total.secs = t.elapsed().as_secs_f64();
    Ok(total)
}

fn parent_query(
    idx: &impl IndexBackend,
    log: &Log,
    s: &dataset::Sampled,
    floor: Position,
    after_kill: bool,
    st: &mut Stats,
) -> R<bool> {
    // (position, id, optional), in acceptance order.
    let mut expected = Vec::new();
    for &(ci, cid) in &s.children {
        match log.pos_of(ci)? {
            Some(p) if p >= floor => {
                if ci < BLOCKS || after_kill {
                    expected.push((p, cid, ci >= BLOCKS));
                }
            }
            None if ci < BLOCKS => return Ok(false),
            Some(_) | None => {}
        }
    }
    expected.sort_by_key(|e| e.0);
    let mut k = 0;
    let mut cursor = floor;
    for _ in 0..MAX_PAGES {
        let t = Instant::now();
        let page = idx.query(Some(&s.parent), cursor, LIMIT)?;
        st.record(t.elapsed());
        for (pos, id) in &page.entries {
            while expected
                .get(k)
                .is_some_and(|e| e.2 && (e.0, e.1) != (*pos, *id))
            {
                k += 1;
            }
            if expected.get(k).is_none_or(|e| (e.0, e.1) != (*pos, *id)) {
                return Ok(false);
            }
            k += 1;
        }
        cursor = page.next;
        if !page.more {
            return Ok(expected.get(k..).unwrap_or(&[]).iter().all(|e| e.2));
        }
    }
    Ok(true)
}

fn since_query(
    idx: &impl IndexBackend,
    log: &Log,
    since: u64,
    floor: Position,
    after_kill: bool,
    st: &mut Stats,
) -> R<bool> {
    let mut cursor = Position::at(since).max(floor);
    let mut k = log.lower_bound(cursor)?;
    for _ in 0..MAX_PAGES {
        let t = Instant::now();
        let page = idx.query(None, cursor, LIMIT)?;
        st.record(t.elapsed());
        let n = log.read_into(k, page.entries.len() as u64, &mut st.scratch)?;
        for (i, (pos, id)) in page.entries.iter().enumerate() {
            match (i < n).then(|| rec_at(&st.scratch, i)) {
                Some(r) if (r.pos, r.id) == (*pos, *id) => {}
                // Killed between the index commit and the log write: one extra entry at most.
                None if after_kill && st.unlogged_tail == 0 && i + 1 == page.entries.len() => {
                    st.unlogged_tail += 1;
                }
                _ => return Ok(false),
            }
        }
        k += n as u64;
        cursor = page.next;
        if !page.more {
            // Every logged block of step 1 must have been listed; blocks of the second load MAY be
            // missing after the kill (a durable prefix of the acceptance order).
            return Ok(match log.get(k)? {
                None => true,
                Some(r) => after_kill && r.idx >= BLOCKS,
            });
        }
    }
    Ok(true)
}

/// Step 5: no block of step 1 is missing from the index, and no expired one is left.
fn check_step1(idx: &impl IndexBackend, work: &Path, floor: Position) -> R<u64> {
    let log = Log::open(work)?;
    let mut errors = 0;
    let mut buf = Vec::new();
    let mut k = 0;
    while k < u64::from(BLOCKS) {
        let n = log.read_into(k, 10_000, &mut buf)?;
        for i in 0..n {
            let r = rec_at(&buf, i);
            let want = (r.pos >= floor).then_some(r.pos);
            errors += u64::from(idx.contains(&r.id)? != want);
        }
        k += 10_000;
    }
    Ok(errors)
}
