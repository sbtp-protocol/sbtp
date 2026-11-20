//! The index component of ADR 0018 rules 9 to 13 and 37: `index_max_readers` dedicated reader
//! threads and one writer thread, created at start-up, which are the only threads of the relay
//! that call [`IndexBackend`] once the relay serves (rules 9 and 10; security review L-2 of
//! milestone 1c-a).
//!
//! Callers ([`IndexHandle`]) submit one job per index call (one `/query` page, one `contains`, one
//! insert) and wait for its reply; they never touch the index on their own thread (rule 11).
//!
//! - Readers share one queue of at most `index_max_queue` waiting jobs (rule 12). A job that finds
//!   the queue full is refused at once; a job carries a deadline `queue_timeout_ms` after it was
//!   queued, and a reader drops a job whose deadline has passed or whose requester is gone,
//!   without running it (rule 13). The deadline is a queue deadline (ADR 0018 clarification M3):
//!   each job has one atomic state, `Queued`, then `Taken` by a thread or `Abandoned` by its
//!   requester at the deadline, never both. A job that was taken runs to its end and its requester
//!   waits for it (bounded for a request by `request_timeout_ms`).
//! - The writer runs every write (insert, flush, the start-up walk) in submission order, and makes
//!   pending non-durable commits durable every [`DURABLE_COMMIT_INTERVAL`] (ADR 0013 rule 10). Its
//!   queue is bounded by `put_max_in_flight + 1`: every write caller holds a `PUT` permit (ADR 0018
//!   rule 18), so the bound is never reached in practice.
//! - Supervision (rule 37): a thread of the pool that ends while the relay is not stopping (a
//!   panic in the backend) makes the process exit with a non-zero status, so that the service
//!   manager restarts it. This is the one exception to "one panicking request must not stop the
//!   relay" (`[profile.release]` in the workspace `Cargo.toml`): a panic inside redb leaves its
//!   locks poisoned (security review 2026-11-18, F-7), so code run in an index job MUST NOT index
//!   slices or use unchecked arithmetic on request values (security review of 1c-b, I-1). A panic
//!   during shutdown is reported as a shutdown error (security review of 1c-b, L-1).
//! - Repeated index failures (rule 37, last bullet): [`FATAL_INDEX_FAILURES`] consecutive failed
//!   reads, or as many consecutive failed writes, make the process exit the same way, so that a
//!   backend left broken (for example by a panic inside redb, or a failed redb commit) is
//!   restarted instead of answering `500` forever. Callers report each outcome with
//!   [`IndexHandle::record_read`] or [`IndexHandle::record_write`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::config::Settings;
use crate::index::{DURABLE_COMMIT_INTERVAL, IndexBackend};
use crate::log::{self, Event, Throttle, Value};
use crate::metrics;

/// Exit status when a thread of the pool ends unexpectedly, or after [`FATAL_INDEX_FAILURES`]
/// consecutive index failures (`EX_SOFTWARE`).
pub(crate) const EXIT_THREAD_ENDED: i32 = 70;

/// ADR 0018 rule 37, last bullet: the fixed number of consecutive failed index calls of one
/// family after which the relay exits with status 70 and a `fatal` line, for the service manager
/// to restart it. There are two families, each with its own count (security review of 1c-limits,
/// M-1: in redb a broken writer leaves reads served from its cache, so one shared count would be
/// reset by every read and never reach the bound):
///
/// - **reads**: a `/query` page and the lookup of the `PUT` path (`unindexed`); reset only by a
///   successful read;
/// - **writes**: an insert of the `PUT` path (new block or orphan repair) and a periodic durable
///   commit; reset only by a successful write. A periodic commit with nothing pending changes
///   nothing.
///
/// What is counted is decided by [`IndexBackend::restart_may_cure`] and by this module:
///
/// - counted: a failure of the storage engine (for redb, [`crate::index::IndexError::Db`]);
/// - not counted: a corrupt row (`IndexError::CorruptRow`; review L-1), which a restart does not
///   cure and which would let any client that reaches the row restart the relay in a loop; a
///   failure whose operating-system error is `ENOSPC` or `EDQUOT` (the storage-full condition of
///   ADR 0013 rule 19 and ADR 0021 rule 37, `507`); a job refused by a full queue or an expired
///   wait, which is load, not a failure (rule 30).
/// - Known gap (review I-1, being clarified by the specification editor): redb reports only its first
///   write failure with its `errno`; once a write failed for lack of space, later calls fail with
///   `PreviousIo`, which carries none and IS counted. A full index file system therefore still
///   ends in exit 70 after [`FATAL_INDEX_FAILURES`] writes.
///
/// 32 is far above what a transient error produces in a row on a relay that serves, and small
/// enough that a broken backend is restarted within a few seconds of traffic.
pub const FATAL_INDEX_FAILURES: u32 = 32;

/// The states of a job (ADR 0018 clarification M3). `Queued` moves once, to `Taken` (a thread
/// runs it) or to `Abandoned` (its queue deadline passed): the two never both win.
const QUEUED: u8 = 0;
const TAKEN: u8 = 1;
const ABANDONED: u8 = 2;

/// Moves `state` from `Queued` to `to`; `false` if another party moved it first.
fn settle(state: &AtomicU8, to: u8) -> bool {
    state
        .compare_exchange(QUEUED, to, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Why [`IndexPool::shutdown`] failed.
#[derive(Debug)]
pub enum ShutdownError<E> {
    /// The final flush of the writer failed.
    Flush(E),
    /// A thread of the pool panicked while the relay was stopping (security review of 1c-b, L-1).
    Panicked(&'static str),
}

/// Why a job was not run (ADR 0018 rule 13). Both are answered `503 Unavailable` (rule 30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// The queue was full, or the relay is stopping: refused at once.
    Full,
    /// The deadline passed before a thread took the job, or the job was dropped without a reply.
    Expired,
}

/// One index call waiting for a thread.
trait Job<I>: Send {
    /// Takes the job for a run (`Queued` to `Taken`). `false` when its requester abandoned it,
    /// its deadline passed (the thread then marks it `Abandoned`) or its requester is gone: the
    /// job is dropped without running.
    fn take(&self, now: Instant) -> bool;
    /// Whether the job still waits for a thread: `Queued`, its requester present and its
    /// deadline not passed (a passed deadline marks it `Abandoned`). A job that is not live is
    /// settled: no thread will run it.
    fn live(&self, now: Instant) -> bool;
    /// Runs the call and sends its reply.
    fn run(self: Box<Self>, index: &I);
}

enum Reply<R> {
    /// An async caller (a handler), which may be cancelled.
    Async(oneshot::Sender<R>),
    /// A caller blocked on its own thread (the `PUT` pipeline, the start-up walk).
    Sync(mpsc::SyncSender<R>),
}

struct Call<F, R> {
    deadline: Option<Instant>,
    state: Arc<AtomicU8>,
    f: F,
    reply: Reply<R>,
}

impl<I, F, R> Job<I> for Call<F, R>
where
    F: FnOnce(&I) -> R + Send,
    R: Send,
{
    fn take(&self, now: Instant) -> bool {
        self.live(now) && settle(&self.state, TAKEN)
    }

    fn live(&self, now: Instant) -> bool {
        if self.state.load(Ordering::Acquire) != QUEUED {
            return false;
        }
        if matches!(&self.reply, Reply::Async(tx) if tx.is_closed()) {
            return false;
        }
        if self.deadline.is_some_and(|d| now >= d) {
            settle(&self.state, ABANDONED);
            return false;
        }
        true
    }

    fn run(self: Box<Self>, index: &I) {
        let r = (self.f)(index);
        match self.reply {
            Reply::Async(tx) => drop(tx.send(r)),
            Reply::Sync(tx) => drop(tx.send(r)),
        }
    }
}

/// What a thread does next.
enum Next<I> {
    Job(Box<dyn Job<I>>),
    /// The writer's flush period has elapsed with no job.
    Tick,
    Stop,
}

struct LaneState<I> {
    jobs: VecDeque<Box<dyn Job<I>>>,
    /// Threads of the lane waiting for a job.
    idle: usize,
    stop: bool,
}

/// A queue and the threads that take from it.
struct Lane<I> {
    state: Mutex<LaneState<I>>,
    wake: Condvar,
    max_queue: usize,
}

impl<I> Lane<I> {
    fn new(threads: usize, max_queue: usize) -> Self {
        Self {
            state: Mutex::new(LaneState {
                jobs: VecDeque::with_capacity(threads.saturating_add(max_queue)),
                idle: 0,
                stop: false,
            }),
            wake: Condvar::new(),
            max_queue,
        }
    }

    /// A panic under the lock leaves a consistent queue: poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, LaneState<I>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `job`, unless that would leave more than `max_queue` jobs waiting for a busy thread
    /// (ADR 0018 rule 12): a job is accepted when an idle thread will take it or the queue has
    /// room. Only live jobs count: when the queue looks full, the jobs that no thread will run
    /// (abandoned at their deadline, or whose requester is gone) are dropped first, so that dead
    /// work never refuses a live request. That purge is bounded by the queue length.
    fn push(&self, job: Box<dyn Job<I>>) -> Result<(), PoolError> {
        let mut s = self.lock();
        if s.stop {
            return Err(PoolError::Full);
        }
        let bound = s.idle.saturating_add(self.max_queue);
        if s.jobs.len() >= bound {
            let now = Instant::now();
            s.jobs.retain(|j| j.live(now));
            if s.jobs.len() >= bound {
                return Err(PoolError::Full);
            }
        }
        s.jobs.push_back(job);
        drop(s);
        self.wake.notify_one();
        Ok(())
    }

    /// The next job, in queue order; queued jobs are still taken after a stop. `tick`: return
    /// [`Next::Tick`] at that time if no job came.
    fn take(&self, tick: Option<Instant>) -> Next<I> {
        let mut s = self.lock();
        loop {
            if let Some(job) = s.jobs.pop_front() {
                return Next::Job(job);
            }
            if s.stop {
                return Next::Stop;
            }
            s.idle += 1;
            s = match tick {
                None => self.wake.wait(s).unwrap_or_else(PoisonError::into_inner),
                Some(t) => {
                    let left = t.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        s.idle -= 1;
                        return Next::Tick;
                    }
                    self.wake
                        .wait_timeout(s, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
            s.idle -= 1;
        }
    }

    fn stop(&self) {
        self.lock().stop = true;
        self.wake.notify_all();
    }
}

struct Shared<I> {
    readers: Lane<I>,
    writer: Lane<I>,
    /// `queue_timeout_ms`.
    timeout: Duration,
    /// The index epoch (ADR 0013 rule 5), refreshed by the writer after every write job.
    epoch: AtomicU64,
    /// Read jobs running now (tests: never above `index_max_readers`).
    running: AtomicUsize,
    /// Set before the threads are told to stop: an end of thread is then expected.
    stopping: AtomicBool,
    /// Consecutive failed index reads (rule 37), reset only by a successful read.
    read_failures: AtomicU32,
    /// Consecutive failed index writes (rule 37), reset only by a successful write.
    write_failures: AtomicU32,
}

/// The family of an index call, for the counts of rule 37 ([`FATAL_INDEX_FAILURES`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Read,
    Write,
}

impl<I> Shared<I> {
    fn count(&self, family: Family) -> &AtomicU32 {
        match family {
            Family::Read => &self.read_failures,
            Family::Write => &self.write_failures,
        }
    }

    /// Rule 37, last bullet: counts one outcome of `family`; at [`FATAL_INDEX_FAILURES`] in a row
    /// in either family, the process exits unless the relay is stopping (the stop then reports
    /// its own errors).
    fn record(&self, family: Family, ok: bool) {
        let count = self.count(family);
        if ok {
            count.store(0, Ordering::Relaxed);
            return;
        }
        let n = count.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if n >= FATAL_INDEX_FAILURES && !self.stopping.load(Ordering::Acquire) {
            // ADR 0021 rule 7: `fatal` carries `msg` only; ADR 0018 M6: it names the family.
            let msg = match family {
                Family::Read => "repeated index read failures",
                Family::Write => "repeated index write failures",
            };
            log::emit(Event::Fatal, &[("msg", Value::Str(msg))]);
            log::flush();
            std::process::exit(EXIT_THREAD_ENDED);
        }
    }
}

/// Whether `r` counts for rule 37: `Some(true)` a success, `Some(false)` a counted failure,
/// `None` a failure that is not counted ([`FATAL_INDEX_FAILURES`]).
fn outcome<I: IndexBackend, T>(r: &Result<T, I::Error>) -> Option<bool> {
    match r {
        Ok(_) => Some(true),
        Err(e) if !I::restart_may_cure(e) => None,
        Err(e) if I::io_error(e).and_then(crate::store::no_space).is_some() => None,
        Err(_) => Some(false),
    }
}

/// The index threads. Owned by the start-up code, which stops them with [`IndexPool::shutdown`];
/// dropping the pool also stops them.
pub struct IndexPool<I: IndexBackend> {
    shared: Arc<Shared<I>>,
    readers: Vec<JoinHandle<()>>,
    writer: Option<JoinHandle<Result<(), I::Error>>>,
}

/// A caller's access to the index: every call is a job run by a thread of the pool (ADR 0018
/// rule 11).
pub struct IndexHandle<I> {
    shared: Arc<Shared<I>>,
}

impl<I> Clone for IndexHandle<I> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<I: IndexBackend + 'static> IndexPool<I> {
    /// Starts the threads of `s`: `index_max_readers` readers with a queue of `index_max_queue`
    /// and a deadline of `queue_timeout_ms`, and the writer.
    ///
    /// # Errors
    ///
    /// A thread could not be started; the threads already started are stopped.
    pub fn start(index: &Arc<I>, s: &Settings) -> std::io::Result<Self> {
        let n = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        Self::with(
            index,
            n(s.index_max_readers).max(1),
            n(s.index_max_queue),
            Duration::from_millis(s.queue_timeout_ms),
            n(s.put_max_in_flight).saturating_add(1),
        )
    }

    /// [`Self::start`] with explicit bounds.
    ///
    /// # Errors
    ///
    /// A thread could not be started.
    pub fn with(
        index: &Arc<I>,
        readers: usize,
        max_queue: usize,
        timeout: Duration,
        writer_queue: usize,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            readers: Lane::new(readers, max_queue),
            writer: Lane::new(1, writer_queue),
            timeout,
            epoch: AtomicU64::new(index.epoch()),
            running: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            read_failures: AtomicU32::new(0),
            write_failures: AtomicU32::new(0),
        });
        let mut pool = Self {
            shared: Arc::clone(&shared),
            readers: Vec::with_capacity(readers),
            writer: None,
        };
        for k in 0..readers {
            let (shared, index) = (Arc::clone(&shared), Arc::clone(index));
            let t = std::thread::Builder::new()
                .name(format!("index-reader-{k}"))
                .spawn(move || read_loop(&shared, &*index))?;
            pool.readers.push(t);
        }
        let index = Arc::clone(index);
        let t = std::thread::Builder::new()
            .name("index-writer".into())
            .spawn(move || write_loop(&shared, &*index))?;
        pool.writer = Some(t);
        // Every reader waits for a job before callers can submit one, so that a queue of 0 does
        // not refuse the first jobs while the threads start.
        while pool.shared.readers.lock().idle < readers {
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(pool)
    }

    /// A handle for callers.
    #[must_use]
    pub fn handle(&self) -> IndexHandle<I> {
        IndexHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Stops the threads once their queued jobs are done, and waits for them. The writer makes
    /// every earlier insert durable before it ends (security review F-3). Once this returns, no
    /// thread of the pool holds the index.
    ///
    /// # Errors
    ///
    /// The final flush failed, or a thread panicked during the stop: supervision no longer exits
    /// the process once `stopping` is set, so the panic is reported here and the relay exits with
    /// an error and a `fatal` line (security review of 1c-b, L-1).
    pub fn shutdown(mut self) -> Result<(), ShutdownError<I::Error>> {
        self.stop()
    }
}

impl<I: IndexBackend> IndexPool<I> {
    fn stop(&mut self) -> Result<(), ShutdownError<I::Error>> {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.readers.stop();
        self.shared.writer.stop();
        let mut result = Ok(());
        for t in self.readers.drain(..) {
            if t.join().is_err() {
                result = Err(ShutdownError::Panicked("an index reader thread panicked"));
            }
        }
        let written = match self.writer.take().map(JoinHandle::join) {
            Some(Ok(flushed)) => flushed.map_err(ShutdownError::Flush),
            Some(Err(_)) => Err(ShutdownError::Panicked("the index writer thread panicked")),
            None => Ok(()),
        };
        written.and(result)
    }
}

impl<I: IndexBackend> Drop for IndexPool<I> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl<I: IndexBackend + 'static> IndexHandle<I> {
    /// ADR 0018 rule 37, last bullet: reports the result of one index read (a `/query` page, a
    /// lookup). [`FATAL_INDEX_FAILURES`] counted failures in a row end the process with status 70
    /// and a `fatal` line; only a successful read resets the count.
    pub fn record_read<T>(&self, r: &Result<T, I::Error>) {
        if let Some(ok) = outcome::<I, T>(r) {
            self.shared.record(Family::Read, ok);
        }
    }

    /// As [`Self::record_read`], for one index write (an insert); only a successful write
    /// resets the count of writes.
    pub fn record_write<T>(&self, r: &Result<T, I::Error>) {
        if let Some(ok) = outcome::<I, T>(r) {
            self.shared.record(Family::Write, ok);
        }
    }

    /// Consecutive failures counted so far, reads and writes (tests).
    #[cfg(test)]
    pub(crate) fn failures(&self) -> (u32, u32) {
        (
            self.shared.read_failures.load(Ordering::Relaxed),
            self.shared.write_failures.load(Ordering::Relaxed),
        )
    }

    /// The index epoch carried by cursors (ADR 0013 rule 5).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.shared.epoch.load(Ordering::Acquire)
    }

    /// Runs the read `f` on a reader thread and returns its result (ADR 0018 rules 9, 12 and 13).
    /// If this future is dropped, a reader drops the job without running it. A job taken by a
    /// reader before its queue deadline is waited for (clarification M3); the request deadline
    /// (`request_timeout_ms`, rule 25) bounds that wait.
    ///
    /// # Errors
    ///
    /// [`PoolError`]: the queue was full, or the deadline passed while the job was queued.
    pub async fn read<R, F>(&self, f: F) -> Result<R, PoolError>
    where
        F: FnOnce(&I) -> R + Send + 'static,
        R: Send + 'static,
    {
        let deadline = Instant::now() + self.shared.timeout;
        let state = Arc::new(AtomicU8::new(QUEUED));
        let (tx, mut rx) = oneshot::channel();
        self.shared.readers.push(Box::new(Call {
            deadline: Some(deadline),
            state: Arc::clone(&state),
            f,
            reply: Reply::Async(tx),
        }))?;
        match tokio::time::timeout_at(deadline.into(), &mut rx).await {
            Ok(r) => r.map_err(|_| PoolError::Expired),
            Err(_) if settle(&state, ABANDONED) => Err(PoolError::Expired),
            // Taken before the deadline: wait for it (M3).
            Err(_) => rx.await.map_err(|_| PoolError::Expired),
        }
    }

    /// [`Self::read`] for a caller on a blocking thread (the `PUT` pipeline).
    ///
    /// # Errors
    ///
    /// As [`Self::read`].
    pub fn read_blocking<R, F>(&self, f: F) -> Result<R, PoolError>
    where
        F: FnOnce(&I) -> R + Send + 'static,
        R: Send + 'static,
    {
        let deadline = Instant::now() + self.shared.timeout;
        let state = Arc::new(AtomicU8::new(QUEUED));
        let (tx, rx) = mpsc::sync_channel(1);
        self.shared.readers.push(Box::new(Call {
            deadline: Some(deadline),
            state: Arc::clone(&state),
            f,
            reply: Reply::Sync(tx),
        }))?;
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => Ok(r),
            Err(mpsc::RecvTimeoutError::Timeout) if !settle(&state, ABANDONED) => {
                // Taken before the deadline: wait for it (M3).
                rx.recv().map_err(|_| PoolError::Expired)
            }
            Err(_) => Err(PoolError::Expired),
        }
    }

    /// Runs the write `f` on the writer thread and waits for it, without a deadline: a write is
    /// never dropped once queued (ADR 0018 rule 10).
    ///
    /// # Errors
    ///
    /// [`PoolError::Full`] if the writer queue is full or the relay is stopping;
    /// [`PoolError::Expired`] if the writer ended without running it.
    pub fn write_blocking<R, F>(&self, f: F) -> Result<R, PoolError>
    where
        F: FnOnce(&I) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel(1);
        self.shared.writer.push(Box::new(Call {
            deadline: None,
            state: Arc::new(AtomicU8::new(QUEUED)),
            f,
            reply: Reply::Sync(tx),
        }))?;
        rx.recv().map_err(|_| PoolError::Expired)
    }

    /// Read jobs running now.
    #[must_use]
    pub fn running(&self) -> usize {
        self.shared.running.load(Ordering::Relaxed)
    }

    /// Jobs waiting in the reader queue (tests).
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.shared.readers.lock().jobs.len()
    }
}

/// Rule 37: ends the process if its thread ends while the relay is not stopping.
struct Supervised<'a>(&'a AtomicBool, &'static str);

impl Drop for Supervised<'_> {
    fn drop(&mut self) {
        if !self.0.load(Ordering::Acquire) {
            log::emit(Event::Fatal, &[("msg", Value::Str(self.1))]);
            log::flush();
            std::process::exit(EXIT_THREAD_ENDED);
        }
    }
}

fn read_loop<I: IndexBackend>(shared: &Shared<I>, index: &I) {
    let _supervised = Supervised(&shared.stopping, "an index reader thread ended");
    loop {
        match shared.readers.take(None) {
            Next::Job(job) if !job.take(Instant::now()) => drop(job),
            Next::Job(job) => {
                shared.running.fetch_add(1, Ordering::Relaxed);
                job.run(index);
                shared.running.fetch_sub(1, Ordering::Relaxed);
            }
            Next::Tick => {}
            Next::Stop => return,
        }
    }
}

/// The writer: jobs in order, a flush of pending commits every [`DURABLE_COMMIT_INTERVAL`] (ADR
/// 0013 rule 10, security review F-3), and a final flush when stopped.
fn write_loop<I: IndexBackend>(shared: &Shared<I>, index: &I) -> Result<(), I::Error> {
    let _supervised = Supervised(&shared.stopping, "the index writer thread ended");
    let mut tick = Instant::now() + DURABLE_COMMIT_INTERVAL;
    loop {
        match shared.writer.take(Some(tick)) {
            Next::Job(job) => {
                if job.take(Instant::now()) {
                    job.run(index);
                }
                shared.epoch.store(index.epoch(), Ordering::Release);
            }
            Next::Tick => {
                let flushed = index.flush_pending();
                if let Err(e) = &flushed {
                    flush_failed::<I>(e);
                }
                // Rule 37: a commit with nothing pending touched nothing and is not counted.
                if !matches!(flushed, Ok(false))
                    && let Some(ok) = outcome::<I, bool>(&flushed)
                {
                    shared.record(Family::Write, ok);
                }
                tick = Instant::now() + DURABLE_COMMIT_INTERVAL;
            }
            Next::Stop => return index.flush(),
        }
    }
}

/// ADR 0021 rules 8 and 37: a failed periodic flush, counted and throttled, with the fields of
/// rule 7 (`op`, `errno`, `suppressed`).
// HOOK(1c): the state `critical` after a failure for lack of space (ADR 0021 rule 37).
fn flush_failed<I: IndexBackend>(e: &I::Error) {
    static FLUSH_LOG: Throttle = Throttle::new();
    metrics::index_write_error(metrics::IndexOp::Flush);
    let mut fields = vec![("op", Value::Str("flush"))];
    if let Some(n) = I::io_error(e).and_then(log::errno) {
        fields.push(("errno", Value::Int(n)));
    }
    log::throttled(&FLUSH_LOG, Event::IndexWriteFailed, &fields, None);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::index::RedbIndex;

    fn pool(name: &str, readers: usize, queue: usize, timeout_ms: u64) -> IndexPool<RedbIndex> {
        let dir = std::env::temp_dir().join(format!("sbtp-pool-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = Arc::new(RedbIndex::open(&dir.join("index.redb"), 1 << 20).unwrap());
        IndexPool::with(&index, readers, queue, Duration::from_millis(timeout_ms), 4).unwrap()
    }

    /// Occupies the only reader until the returned sender is dropped.
    fn occupy(h: &IndexHandle<RedbIndex>) -> mpsc::Sender<()> {
        let (tx, rx) = mpsc::channel::<()>();
        let busy = h.clone();
        std::thread::spawn(move || {
            let _ = busy.read_blocking(move |_| rx.recv().is_ok());
        });
        while h.running() == 0 {
            std::thread::yield_now();
        }
        tx
    }

    /// Rules 12 and 13: with the reader busy, `index_max_queue` jobs wait; one more is refused at
    /// once.
    #[tokio::test]
    async fn queue_full_is_refused_at_once() {
        let p = pool("full", 1, 1, 10_000);
        let h = p.handle();
        let release = occupy(&h);
        assert_eq!(h.running(), 1);
        let queued = tokio::spawn({
            let h = h.clone();
            async move { h.read(RedbIndex::len).await }
        });
        while h.queued() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(h.read(RedbIndex::len).await, Err(PoolError::Full)));
        drop(release);
        assert!(matches!(queued.await.unwrap(), Ok(Ok(0))));
    }

    /// Rule 13: a job still queued at its deadline is refused at the deadline and never runs.
    #[tokio::test]
    async fn expired_job_never_runs() {
        let p = pool("expired", 1, 4, 50);
        let h = p.handle();
        let release = occupy(&h);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let r = h.read(move |_| flag.store(true, Ordering::SeqCst)).await;
        assert_eq!(r, Err(PoolError::Expired));
        drop(release);
        // A job queued after it runs, so the expired one has been taken and dropped.
        let later = pool_after(&h).await;
        assert_eq!(later, Ok(()));
        assert!(!ran.load(Ordering::SeqCst), "an expired job must not run");
    }

    async fn pool_after(h: &IndexHandle<RedbIndex>) -> Result<(), PoolError> {
        loop {
            match h.read(|_| ()).await {
                Err(PoolError::Full) => tokio::task::yield_now().await,
                r => return r,
            }
        }
    }

    /// Rule 12 bounds waiting jobs: jobs abandoned at their deadline or cancelled by their
    /// requester while every reader is busy no longer count, and a new job is accepted.
    #[tokio::test]
    async fn settled_jobs_do_not_fill_the_queue() {
        let p = pool("settled", 1, 2, 300);
        let h = p.handle();
        let release = occupy(&h);
        // One job abandoned at its deadline, one cancelled by its requester.
        assert_eq!(h.read(|_| ()).await, Err(PoolError::Expired));
        let cancelled = tokio::spawn({
            let h = h.clone();
            async move { h.read(|_| ()).await }
        });
        while h.queued() < 2 {
            tokio::task::yield_now().await;
        }
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(
            h.queued(),
            2,
            "the reader is busy: nothing popped the settled jobs"
        );
        let live = tokio::spawn({
            let h = h.clone();
            async move { h.read(|_| 5).await }
        });
        while h.queued() != 1 && !live.is_finished() {
            tokio::task::yield_now().await;
        }
        drop(release);
        assert_eq!(live.await.unwrap(), Ok(5));
    }

    /// Rule 13: a job whose requester is gone is dropped without running.
    #[tokio::test]
    async fn cancelled_job_never_runs() {
        let p = pool("cancelled", 1, 4, 10_000);
        let h = p.handle();
        let release = occupy(&h);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let task = tokio::spawn({
            let h = h.clone();
            async move { h.read(move |_| flag.store(true, Ordering::SeqCst)).await }
        });
        while h.queued() == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        drop(release);
        assert_eq!(pool_after(&h).await, Ok(()));
        assert!(!ran.load(Ordering::SeqCst), "a cancelled job must not run");
    }

    /// Rule 9: however many callers, at most `index_max_readers` read jobs run at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn running_reads_never_exceed_the_readers() {
        let p = pool("bounded", 2, 64, 10_000);
        let h = p.handle();
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let (h, peak) = (h.clone(), Arc::clone(&peak));
                let probe = h.clone();
                tokio::spawn(async move {
                    h.read(move |_| {
                        peak.fetch_max(probe.running(), Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(2));
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), Ok(()));
        }
        assert!((1..=2).contains(&peak.load(Ordering::SeqCst)));
    }

    /// Clarification M3: a job taken before its queue deadline is waited for, by both kinds of
    /// caller, and its result is returned instead of `503`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn taken_job_is_waited_for() {
        let p = pool("taken", 1, 0, 50);
        let h = p.handle();
        let slow = |_: &RedbIndex| {
            std::thread::sleep(Duration::from_millis(150));
            7
        };
        assert_eq!(h.read(slow).await, Ok(7));
        let blocking = h.clone();
        let r = tokio::task::spawn_blocking(move || blocking.read_blocking(slow)).await;
        assert_eq!(r.unwrap(), Ok(7));
    }

    /// Security review of 1c-b, L-1: a writer that panics once the stop has begun is reported by
    /// `shutdown`, not mapped to a clean stop.
    #[test]
    fn writer_panic_during_shutdown_is_an_error() {
        let p = pool("panic-stop", 1, 0, 1_000);
        let h = p.handle();
        let (go, wait) = mpsc::channel::<()>();
        let started = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&started);
        let writer = h.clone();
        let caller = std::thread::spawn(move || {
            writer.write_blocking(move |_| {
                flag.store(true, Ordering::SeqCst);
                let _ = wait.recv();
                std::panic::panic_any("a backend panic during the stop");
            })
        });
        while !started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let stopper = std::thread::spawn(move || p.shutdown());
        // The readers refuse jobs once the stop has begun, after `stopping` is set.
        while h.read_blocking(|_| ()).is_ok() {
            std::thread::yield_now();
        }
        drop(go);
        assert!(matches!(
            stopper.join().unwrap(),
            Err(ShutdownError::Panicked(_))
        ));
        assert_eq!(caller.join().unwrap(), Err(PoolError::Expired));
    }

    const CHILD_DIE: &str = "SBTP_POOL_TEST_CHILD_DIE";

    /// Child side of `dead_reader_exits_the_process`: does nothing unless started by it.
    #[test]
    fn dead_reader_child() {
        if std::env::var(CHILD_DIE).is_err() {
            return;
        }
        let p = pool("die", 1, 0, 1_000);
        let _ = p.handle().read_blocking(|_| {
            std::panic::panic_any("a backend panic");
        });
        std::thread::sleep(Duration::from_secs(30));
    }

    /// ADR 0018 rule 37: a reader thread that ends while the relay serves exits the process with
    /// status 70.
    #[test]
    fn dead_reader_exits_the_process() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "pool::tests::dead_reader_child", "--nocapture"])
            .env(CHILD_DIE, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(EXIT_THREAD_ENDED));
    }

    use crate::index::IndexError;

    /// A storage-engine failure (`EIO`): counted.
    fn broken() -> Result<(), IndexError> {
        Err(IndexError::Db(redb::Error::Io(
            std::io::Error::from_raw_os_error(libc::EIO),
        )))
    }

    fn no_space() -> Result<(), IndexError> {
        Err(IndexError::Db(redb::Error::Io(
            std::io::Error::from_raw_os_error(libc::ENOSPC),
        )))
    }

    const GOOD: Result<(), IndexError> = Ok(());

    /// ADR 0018 rule 37, last bullet: failures are counted in a row per family and a success of
    /// that family resets its count; a failure for lack of space and a corrupt row (review L-1)
    /// are not counted; below [`FATAL_INDEX_FAILURES`] the process keeps running.
    #[test]
    fn index_failures_are_counted_in_a_row_per_family() {
        let p = pool("failures", 1, 4, 1_000);
        let h = p.handle();
        for _ in 1..FATAL_INDEX_FAILURES {
            h.record_read(&broken());
            h.record_write(&broken());
        }
        let almost = FATAL_INDEX_FAILURES - 1;
        assert_eq!(h.failures(), (almost, almost));
        for _ in 0..100 {
            h.record_read(&no_space());
            h.record_write(&no_space());
            h.record_read(&Err::<(), _>(IndexError::CorruptRow));
            h.record_write(&Err::<(), _>(IndexError::CorruptRow));
        }
        assert_eq!(
            h.failures(),
            (almost, almost),
            "ENOSPC, CorruptRow: not counted"
        );
        // M-1: a success resets its own family only.
        h.record_read(&GOOD);
        assert_eq!(h.failures(), (0, almost));
        h.record_write(&GOOD);
        assert_eq!(h.failures(), (0, 0));
        // Through the public calls: a lookup that succeeds is a successful read.
        let id = sbtp_core::BlockId([3; 32]);
        let found = h.read_blocking(move |i| i.contains(&id)).unwrap();
        h.record_read(&broken());
        h.record_read(&found);
        assert_eq!(h.failures(), (0, 0));
        // After the stop, failures no longer end the process: the stop reports its own errors.
        let h2 = p.handle();
        assert!(p.shutdown().is_ok());
        for _ in 0..2 * FATAL_INDEX_FAILURES {
            h2.record_write(&broken());
        }
        assert!(h2.failures().1 >= FATAL_INDEX_FAILURES);
    }

    const CHILD_FAIL: &str = "SBTP_POOL_TEST_CHILD_FAIL";

    /// Child side of `failed_writes_between_good_reads_exit_the_process`: does nothing unless
    /// started by it.
    #[test]
    fn failed_writes_child() {
        if std::env::var(CHILD_FAIL).is_err() {
            return;
        }
        let p = pool("fail", 1, 4, 1_000);
        let h = p.handle();
        for _ in 0..FATAL_INDEX_FAILURES {
            h.record_read(&GOOD);
            h.record_write(&broken());
        }
        std::thread::sleep(Duration::from_secs(30));
    }

    /// ADR 0018 rule 37, last bullet (review M-1): a writer that fails [`FATAL_INDEX_FAILURES`]
    /// times in a row exits the process with status 70, even with a successful read between
    /// every two failed writes. The `fatal` line names the write family (ADR 0018 M6).
    #[test]
    fn failed_writes_between_good_reads_exit_the_process() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "pool::tests::failed_writes_child", "--nocapture"])
            .env(CHILD_FAIL, "1")
            .stdout(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(EXIT_THREAD_ENDED));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("repeated index write failures"), "{err}");
    }

    /// A redb index whose periodic durable commit does what [`FlakyFlush::mode`] says: 0 fails
    /// with `EIO`, 1 has nothing pending, 2 commits.
    struct FlakyFlush {
        inner: RedbIndex,
        mode: AtomicU8,
    }

    impl IndexBackend for FlakyFlush {
        type Error = IndexError;
        fn io_error(e: &IndexError) -> Option<&std::io::Error> {
            e.io_error()
        }
        fn restart_may_cure(e: &IndexError) -> bool {
            RedbIndex::restart_may_cure(e)
        }
        fn open(path: &std::path::Path, cache_bytes: usize) -> Result<Self, IndexError> {
            Ok(Self {
                inner: RedbIndex::open(path, cache_bytes)?,
                mode: AtomicU8::new(0),
            })
        }
        fn epoch(&self) -> u64 {
            self.inner.epoch()
        }
        fn renew_epoch(&self) -> Result<u64, IndexError> {
            self.inner.renew_epoch()
        }
        fn insert(
            &self,
            id: &sbtp_core::BlockId,
            len: u32,
            parents: &[sbtp_core::BlockId],
            now_ms: u64,
            state: crate::index::FileState,
        ) -> Result<Option<crate::index::Position>, IndexError> {
            self.inner.insert(id, len, parents, now_ms, state)
        }
        fn flush(&self) -> Result<(), IndexError> {
            self.inner.flush()
        }
        fn flush_pending(&self) -> Result<bool, IndexError> {
            match self.mode.load(Ordering::SeqCst) {
                0 => broken().map(|()| true),
                1 => Ok(false),
                _ => Ok(true),
            }
        }
        fn contains(
            &self,
            id: &sbtp_core::BlockId,
        ) -> Result<Option<crate::index::Position>, IndexError> {
            self.inner.contains(id)
        }
        fn query(
            &self,
            p: Option<&sbtp_core::BlockId>,
            from: crate::index::Position,
            n: usize,
        ) -> Result<crate::index::Page, IndexError> {
            self.inner.query(p, from, n)
        }
        fn expired(
            &self,
            before: crate::index::Position,
            max: usize,
        ) -> Result<Vec<(crate::index::Position, sbtp_core::BlockId)>, IndexError> {
            self.inner.expired(before, max)
        }
        fn remove(&self, positions: &[crate::index::Position]) -> Result<usize, IndexError> {
            self.inner.remove(positions)
        }
        fn len(&self) -> Result<u64, IndexError> {
            self.inner.len()
        }
    }

    /// Waits up to 5 s for `f`.
    fn eventually(mut f: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// ADR 0018 rule 37, last bullet: a failed periodic durable commit is a failed write; a commit
    /// with nothing pending changes nothing; a commit that succeeds resets the count of writes.
    #[test]
    fn periodic_commit_failures_are_counted_as_writes() {
        let dir = std::env::temp_dir().join(format!("sbtp-pool-flaky-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = Arc::new(FlakyFlush::open(&dir.join("index.redb"), 1 << 20).unwrap());
        let p = IndexPool::with(&index, 1, 4, Duration::from_secs(1), 4).unwrap();
        let h = p.handle();
        // One tick per `DURABLE_COMMIT_INTERVAL` (1 s): two failed commits in a row.
        assert!(eventually(|| h.failures().1 >= 2), "{:?}", h.failures());
        assert_eq!(h.failures().0, 0, "a commit is a write");
        index.mode.store(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100)); // a tick already running ends
        let held = h.failures().1;
        std::thread::sleep(DURABLE_COMMIT_INTERVAL * 2);
        assert_eq!(
            h.failures().1,
            held,
            "nothing pending: neither failure nor success"
        );
        index.mode.store(2, Ordering::SeqCst);
        assert!(eventually(|| h.failures().1 == 0), "{:?}", h.failures());
        assert!(p.shutdown().is_ok());
    }

    /// The writer runs writes in order and makes them durable at shutdown; a write after the stop
    /// is refused.
    #[test]
    fn writes_then_shutdown() {
        let p = pool("writes", 1, 0, 1_000);
        let h = p.handle();
        let id = sbtp_core::BlockId([9; 32]);
        let pos = h
            .write_blocking(move |i| i.insert(&id, 10, &[], 5, crate::index::FileState::Created))
            .unwrap()
            .unwrap();
        assert!(pos.is_some());
        assert_eq!(
            h.read_blocking(move |i| i.contains(&id)).unwrap().unwrap(),
            pos
        );
        assert!(p.shutdown().is_ok());
        assert_eq!(
            h.write_blocking(RedbIndex::flush).err(),
            Some(PoolError::Full)
        );
    }
}
