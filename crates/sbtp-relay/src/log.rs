//! The relay logger (ADR 0021 points 1 to 3, rules 9 and 13). In-house, no dependency.
//!
//! One event is one line on standard error, `key=value` text or JSON (rules 1 to 5). A call goes
//! through, in this order (rule 16): the level; the per-event [`Throttle`] of its call site; the
//! global token bucket (rule 18); a bounded queue of [`QUEUE_LINES`] lines read by one writer
//! thread that owns standard error (rule 21). A line dropped by the bucket or the queue is counted
//! per event, and a `log_dropped` summary reports the drops at most once per minute (rule 20). A
//! call never blocks a request: a full queue costs the line.
//!
//! Privacy (rule 10): call sites pass only values the relay produced, from fixed sets. Every string
//! value is escaped (rule 3), so that no byte can break a line or forge a field.

use std::cell::Cell;
use std::fmt::Write as _;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client::ClientKey;
use crate::config::Settings;

/// Rule 17: the largest line, line feed included.
pub const MAX_LINE: usize = 1024;
/// Rule 21: the queue between the callers and the writer thread, in lines.
pub const QUEUE_LINES: usize = 256;
/// Rule 20: the shortest time between two `log_dropped` lines.
pub const SUMMARY_PERIOD_MS: u64 = 60_000;
/// Rule 21: the longest wait to drain the queue at exit, and for a line outside the bucket.
pub const DRAIN: Duration = Duration::from_secs(1);
/// How often the writer thread checks the summary and `stats` timers while idle.
const TICK: Duration = Duration::from_secs(1);

macro_rules! choice {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident => $s:literal,)* }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($(#[$vm])* $v,)* }
        impl $name {
            /// Every value, in order.
            pub const ALL: &'static [Self] = &[$(Self::$v),*];
            /// The names of [`Self::ALL`], in order.
            pub const NAMES: &'static [&'static str] = &[$($s),*];
            /// The name in the settings and in the log.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self { $(Self::$v => $s,)* }
            }
            /// The value named `s`.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.name() == s)
            }
        }
    };
}

choice! {
    /// `log_level` and the level of a line (rule 6), lowest first.
    Level {
        /// One line per request or per block.
        Debug => "debug",
        /// Start-up, shutdown, state changes, periodic statistics. The default.
        Info => "info",
        /// A limit was reached, or a setting deserves attention.
        Warn => "warn",
        /// The relay lost data, a function or a write.
        Error => "error",
    }
}

choice! {
    /// `log_format` (rules 3 and 4).
    Format {
        /// `key=value` pairs. The default.
        Text => "text",
        /// One JSON object per line.
        Json => "json",
    }
}

choice! {
    /// `log_timestamp` (rule 5).
    Timestamp {
        /// RFC 3339, UTC, milliseconds. The default.
        Rfc3339 => "rfc3339",
        /// No `ts` field.
        None => "none",
    }
}

choice! {
    /// `log_client_tag` (rule 13).
    ClientTag {
        /// No client field. The default.
        Off => "off",
        /// A keyed hash of the client key, valid for one process run.
        Keyed => "keyed",
    }
}

/// How a line is bounded (rules 17 and 19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The start-up phase: outside the bucket, not cut.
    Startup,
    /// No client can cause it: outside the bucket, cut.
    Exempt,
    /// Through the bucket and cut.
    Bounded,
}

macro_rules! events {
    ($($v:ident => $s:literal, $level:ident, $kind:ident;)*) => {
        /// The fixed `event` vocabulary of ADR 0021 rule 7: one variant per row of its table, in
        /// the same order, then the rows of ADR 0023 rule 14, which amends it, then the row of
        /// ADR 0021 clarification X1 (tested against both ADRs). Renaming or removing one needs
        /// an ADR.
        #[allow(missing_docs)] // Each variant is documented by its row of the ADR table.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Event { $($v,)* }
        /// The number of events.
        pub const EVENTS: usize = [$($s),*].len();
        impl Event {
            /// Every event, in the order of the ADR table.
            pub const ALL: [Self; EVENTS] = [$(Self::$v),*];
            /// The `event` field.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self { $(Self::$v => $s,)* }
            }
            /// The level of the event; the first listed when the ADR lists several.
            #[must_use]
            pub fn level(self) -> Level {
                match self { $(Self::$v => Level::$level,)* }
            }
            fn kind(self) -> Kind {
                match self { $(Self::$v => Kind::$kind,)* }
            }
        }
    };
}

events! {
    Start => "start", Info, Startup;
    Setting => "setting", Info, Startup;
    Profile => "profile", Info, Startup;
    OpenFiles => "open_files", Info, Startup;
    MemoryBound => "memory_bound", Info, Startup;
    LogBound => "log_bound", Info, Startup;
    ConfigWarning => "config_warning", Warn, Startup;
    DataDir => "data_dir", Info, Startup;
    Listening => "listening", Info, Startup;
    MetricsListening => "metrics_listening", Info, Startup;
    AcceptFailed => "accept_failed", Warn, Bounded;
    ClientBound => "client_bound", Warn, Bounded;
    ForwardedInvalid => "forwarded_invalid", Warn, Bounded;
    RateLimited => "rate_limited", Warn, Bounded;
    Shed => "shed", Warn, Bounded;
    StorageFull => "storage_full", Warn, Bounded;
    DiskState => "disk_state", Info, Bounded;
    DiskCheckFailed => "disk_check_failed", Error, Bounded;
    IndexWriteFailed => "index_write_failed", Error, Bounded;
    StoreWriteFailed => "store_write_failed", Error, Bounded;
    Sweep => "sweep", Debug, Bounded;
    SweepFailed => "sweep_failed", Error, Bounded;
    BlockRejected => "block_rejected", Debug, Bounded;
    BlockStored => "block_stored", Debug, Bounded;
    Request => "request", Debug, Bounded;
    Panic => "panic", Error, Bounded;
    Stats => "stats", Info, Bounded;
    LogDropped => "log_dropped", Warn, Exempt;
    Shutdown => "shutdown", Info, Exempt;
    Fatal => "fatal", Error, Exempt;
    // ADR 0023 rule 14 (amends rule 7): its table, after the rows of this ADR.
    BlockQuarantined => "block_quarantined", Warn, Bounded;
    StoreReconciled => "store_reconciled", Info, Startup;
    // ADR 0021 clarification X1 (adds a row to rule 7): after the rows of ADR 0023.
    IndexReadFailed => "index_read_failed", Error, Bounded;
    // ADR 0046 rule 29 (adds three rows to rule 7; the ADR names them without a table, the
    // levels are this implementation's): after the row of X1.
    DemandEvicted => "demand_evicted", Info, Bounded;
    DemandStuck => "demand_stuck", Warn, Bounded;
    DemandSuspended => "demand_suspended", Warn, Bounded;
    // Security review 2026-11-21, I-4 (owner decision, ADR 0046 clarification): the progress of
    // the start-up migration of the demand tables, before the relay listens.
    DemandMigration => "demand_migration", Info, Startup;
}

/// A field value (rule 4: integers are numbers, flags are booleans as `truncated` of rule 17,
/// everything else is a string). A field always has the same type; a value that does not exist
/// leaves the field out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// A number the relay produced.
    Int(u64),
    /// A flag, `true` or `false` in both forms.
    Bool(bool),
    /// A string, escaped when written.
    Str(&'a str),
}

/// The `errno` field of an I/O error, if it has one.
#[must_use]
pub fn errno(e: &io::Error) -> Option<u64> {
    e.raw_os_error().map(|c| u64::from(c.unsigned_abs()))
}

/// The fields of a line, in order (rule 2).
pub type Fields<'a> = [(&'static str, Value<'a>)];

/// At most one line per [`Throttle::PERIOD_MS`] for an event that a remote peer can repeat
/// (rule 8; ADR 0020 rule 27). One instance per event name and per value of its `class`, `reason`
/// or `op` field. Lock-free: a suppressed event costs two atomic operations.
#[derive(Debug)]
pub struct Throttle {
    /// [`now_ms`] at the last line, or [`Throttle::NEVER`].
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

impl Throttle {
    /// Minimum time between two lines.
    pub const PERIOD_MS: u64 = 60_000;
    const NEVER: u64 = u64::MAX;

    /// A throttle that has written no line.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_ms: AtomicU64::new(Self::NEVER),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(n)` when a line may be written now, `n` being the events not logged since the last
    /// line; `None` otherwise.
    pub fn ready(&self) -> Option<u64> {
        self.ready_at(now_ms())
    }

    /// [`Self::ready`] at `now`, in milliseconds of a monotonic clock.
    pub fn ready_at(&self, now: u64) -> Option<u64> {
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == Self::NEVER || now.saturating_sub(last) >= Self::PERIOD_MS;
        // Of two threads that find the line due, one wins the exchange; the other is suppressed.
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Gives back a period claimed by [`Self::ready`] whose line was not written (the global
    /// bucket refused it): the next event may write, with this one counted as suppressed.
    pub fn undo(&self, suppressed: u64) {
        self.suppressed
            .fetch_add(suppressed.saturating_add(1), Ordering::Relaxed);
        self.last_ms.store(Self::NEVER, Ordering::Relaxed);
    }
}

/// The logger settings (ADR 0021 rule 46).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // Each field is the setting of the same name.
pub struct LogConfig {
    pub format: Format,
    pub level: Level,
    pub timestamp: Timestamp,
    pub client_tag: ClientTag,
    pub rate_per_min: u64,
    pub burst: u64,
    pub stats_interval_ms: u64,
}

impl Default for LogConfig {
    /// The built-in defaults, used until the settings are loaded.
    fn default() -> Self {
        Self {
            format: Format::Text,
            level: Level::Info,
            timestamp: Timestamp::Rfc3339,
            client_tag: ClientTag::Off,
            rate_per_min: 60,
            burst: 120,
            stats_interval_ms: 300_000,
        }
    }
}

impl LogConfig {
    /// The logger settings of `s`.
    #[must_use]
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            format: s.log_format,
            level: s.log_level,
            timestamp: s.log_timestamp,
            client_tag: s.log_client_tag,
            rate_per_min: s.log_rate_per_min,
            burst: s.log_burst,
            stats_interval_ms: s.stats_interval_ms,
        }
    }
}

/// Rule 18, in tokens × 60,000 so that a refill of `rate` tokens per minute is `rate` units per
/// millisecond.
#[derive(Debug)]
struct Bucket {
    rate: u64,
    burst: u64,
    units: u64,
    last_ms: u64,
}

const UNIT: u64 = 60_000;

impl Bucket {
    fn take(&mut self, now: u64, level: Level) -> bool {
        let elapsed = now.saturating_sub(self.last_ms);
        self.last_ms = self.last_ms.max(now);
        self.units = self
            .units
            .saturating_add(elapsed.saturating_mul(self.rate))
            .min(self.burst.saturating_mul(UNIT));
        // `debug` and `info` leave `burst / 4` tokens to `warn` and `error`.
        let floor = if level <= Level::Info {
            (self.burst / 4).saturating_mul(UNIT)
        } else {
            0
        };
        if self.units < UNIT.max(floor) {
            return false;
        }
        self.units -= UNIT;
        true
    }
}

/// Why a line was dropped (counter `log_lines_dropped_total`, label `cause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The global bucket had no token.
    Rate,
    /// The queue was full (the sink stopped reading).
    Queue,
}

/// A message to the writer thread.
#[derive(Debug)]
enum Msg {
    Line(Vec<u8>),
    Flush(mpsc::Sender<()>),
}

/// A monotonic clock in milliseconds (injected by the tests).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A logger: its settings, bucket, queue and counters. The relay uses one, [`global`].
pub struct Logger {
    level: AtomicU8,
    json: AtomicBool,
    timestamp: AtomicBool,
    client_tag: AtomicBool,
    stats_interval_ms: AtomicU64,
    bucket: Mutex<Bucket>,
    tx: SyncSender<Msg>,
    clock: Clock,
    dropped: [[AtomicU64; 2]; EVENTS],
    pending: [AtomicU64; EVENTS],
    last_summary_ms: AtomicU64,
    last_stats_ms: AtomicU64,
    /// Rule 21: the end of the one exit budget, set at the first wait of the exit.
    exit: OnceLock<Instant>,
}

impl Logger {
    /// A logger with the default settings and its queue, without a writer.
    fn new(clock: Clock) -> (Arc<Self>, Receiver<Msg>) {
        let (tx, rx) = mpsc::sync_channel(QUEUE_LINES);
        let now = clock();
        let d = LogConfig::default();
        let logger = Self {
            level: AtomicU8::new(0),
            json: AtomicBool::new(false),
            timestamp: AtomicBool::new(true),
            client_tag: AtomicBool::new(false),
            stats_interval_ms: AtomicU64::new(0),
            bucket: Mutex::new(Bucket {
                rate: d.rate_per_min,
                burst: d.burst,
                units: 0,
                last_ms: now,
            }),
            tx,
            clock,
            dropped: [const { [const { AtomicU64::new(0) }; 2] }; EVENTS],
            pending: [const { AtomicU64::new(0) }; EVENTS],
            last_summary_ms: AtomicU64::new(now),
            last_stats_ms: AtomicU64::new(now),
            exit: OnceLock::new(),
        };
        logger.configure(&d);
        (Arc::new(logger), rx)
    }

    /// A logger whose writer thread writes to `sink`. If the thread cannot start, every line is
    /// dropped and counted.
    #[must_use]
    pub fn start(sink: Box<dyn Write + Send>, clock: Clock) -> Arc<Self> {
        let (logger, rx) = Self::new(clock);
        let weak = Arc::downgrade(&logger);
        let _ = std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || write_loop(&rx, sink, &weak));
        logger
    }

    /// Applies `c`. The bucket starts full.
    pub fn configure(&self, c: &LogConfig) {
        let level = Level::ALL.iter().position(|l| *l == c.level).unwrap_or(1);
        self.level
            .store(u8::try_from(level).unwrap_or(1), Ordering::Relaxed);
        self.json.store(c.format == Format::Json, Ordering::Relaxed);
        self.timestamp
            .store(c.timestamp == Timestamp::Rfc3339, Ordering::Relaxed);
        self.client_tag
            .store(c.client_tag == ClientTag::Keyed, Ordering::Relaxed);
        self.stats_interval_ms
            .store(c.stats_interval_ms, Ordering::Relaxed);
        let mut b = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
        b.rate = c.rate_per_min;
        b.burst = c.burst;
        b.units = c.burst.saturating_mul(UNIT);
        b.last_ms = (self.clock)();
    }

    /// Whether a line of `level` is written (rule 6).
    #[must_use]
    pub fn enabled(&self, level: Level) -> bool {
        let min = Level::ALL
            .get(usize::from(self.level.load(Ordering::Relaxed)))
            .copied()
            .unwrap_or(Level::Info);
        level >= min
    }

    /// Writes `event` at `level` with `fields`, within the bounds of rules 16 to 21.
    pub fn log(&self, level: Level, event: Event, fields: &Fields<'_>) {
        self.write(level, event, fields, true, None);
    }

    /// [`Self::log`]; `bucket` false skips the bucket, `until` waits for room in the queue up to
    /// that instant. A start-up line waits at most [`DRAIN`]; every other line is sent with
    /// `try_send` and never waits, so that no runtime worker sleeps here (rule 21). `false` when
    /// the bucket refused the line.
    fn write(
        &self,
        level: Level,
        event: Event,
        fields: &Fields<'_>,
        bucket: bool,
        until: Option<Instant>,
    ) -> bool {
        let Some(line) = self.admit(level, event, fields, bucket) else {
            // Not enabled: nothing to give back. Enabled: the bucket refused it.
            return !self.enabled(level);
        };
        let until =
            until.or_else(|| (event.kind() == Kind::Startup).then(|| Instant::now() + DRAIN));
        let msg = Msg::Line(line);
        let sent = match until {
            Some(t) => self.send_until(msg, t),
            None => self.tx.try_send(msg).is_ok(),
        };
        // HOOK(1c-b): `log_lines_total{level}` for the `/metrics` listener, counted here.
        if !sent {
            self.count_drop(event, Cause::Queue);
        }
        true
    }

    /// The level, the bucket (unless `bucket` is false) and the rendering of a line.
    fn admit(
        &self,
        level: Level,
        event: Event,
        fields: &Fields<'_>,
        bucket: bool,
    ) -> Option<Vec<u8>> {
        if !self.enabled(level) {
            return None;
        }
        let kind = event.kind();
        if bucket && kind == Kind::Bounded {
            let now = (self.clock)();
            let taken = self
                .bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(now, level);
            if !taken {
                self.count_drop(event, Cause::Rate);
                return None;
            }
        }
        let ts = self
            .timestamp
            .load(Ordering::Relaxed)
            .then(|| rfc3339(SystemTime::now()));
        let json = self.json.load(Ordering::Relaxed);
        Some(render(
            json,
            ts.as_deref(),
            level,
            event,
            fields,
            kind != Kind::Startup,
        ))
    }

    /// Waits for room in the queue until `deadline`. Never called on a runtime worker: start-up
    /// lines, the exit flush and the line of an uncaught panic.
    fn send_until(&self, mut msg: Msg, deadline: Instant) -> bool {
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => return true,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = m;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn count_drop(&self, event: Event, cause: Cause) {
        let i = event as usize;
        if let Some(n) = self.dropped.get(i).and_then(|c| c.get(cause as usize)) {
            n.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(n) = self.pending.get(i) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Lines of `event` dropped for `cause` since start-up.
    #[must_use]
    pub fn dropped(&self, event: Event, cause: Cause) -> u64 {
        self.dropped
            .get(event as usize)
            .and_then(|c| c.get(cause as usize))
            .map_or(0, |n| n.load(Ordering::Relaxed))
    }

    /// Lines dropped since start-up, every event and cause.
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped
            .iter()
            .flatten()
            .map(|n| n.load(Ordering::Relaxed))
            .fold(0, u64::saturating_add)
    }

    /// The `client` field of rule 13, when `log_client_tag = "keyed"`: the first 8 hexadecimal
    /// characters of the BLAKE3 keyed hash of `key`, with the 32-byte key of [`client_tag_key`].
    /// No tag (the field is left out) if that key could not be drawn.
    #[must_use]
    pub fn client_tag(&self, key: &ClientKey) -> Option<String> {
        if !self.client_tag.load(Ordering::Relaxed) {
            return None;
        }
        let secret = client_tag_key().ok()?;
        Some(tag_hex(&blake3::keyed_hash(secret, &key.tag_input())))
    }

    /// The `log_dropped` summary (rule 20) and the `stats` line (rule 42), when due. Called by
    /// the writer thread at least once per [`TICK`].
    fn tick(&self) -> Vec<Vec<u8>> {
        let now = (self.clock)();
        let mut out = Vec::new();
        let last = self.last_summary_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= SUMMARY_PERIOD_MS
            && self.pending.iter().any(|n| n.load(Ordering::Relaxed) > 0)
        {
            self.last_summary_ms.store(now, Ordering::Relaxed);
            out.push(self.summary());
        }
        let interval = self.stats_interval_ms.load(Ordering::Relaxed);
        let last = self.last_stats_ms.load(Ordering::Relaxed);
        if interval > 0 && now.saturating_sub(last) >= interval {
            self.last_stats_ms.store(now, Ordering::Relaxed);
            let mut counters = crate::metrics::snapshot();
            counters.push(("log_dropped", self.dropped_total()));
            let fields: Vec<_> = counters
                .into_iter()
                .map(|(k, v)| (k, Value::Int(v)))
                .collect();
            out.extend(self.admit(Level::Info, Event::Stats, &fields, true));
        }
        out
    }

    /// `dropped`, then one field per event, largest first; what does not fit goes in `other`.
    fn summary(&self) -> Vec<u8> {
        let mut counts: Vec<(&'static str, u64)> = Event::ALL
            .iter()
            .zip(&self.pending)
            .map(|(e, n)| (e.name(), n.swap(0, Ordering::Relaxed)))
            .filter(|(_, n)| *n > 0)
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let total = counts.iter().map(|(_, n)| *n).fold(0, u64::saturating_add);
        let json = self.json.load(Ordering::Relaxed);
        let ts = self
            .timestamp
            .load(Ordering::Relaxed)
            .then(|| rfc3339(SystemTime::now()));
        let mut line = Vec::new();
        for k in (0..=counts.len()).rev() {
            let (shown, rest) = counts.split_at(k);
            let mut fields = vec![("dropped", Value::Int(total))];
            fields.extend(shown.iter().map(|(e, n)| (*e, Value::Int(*n))));
            if !rest.is_empty() {
                fields.push((
                    "other",
                    Value::Int(rest.iter().map(|(_, n)| *n).fold(0, u64::saturating_add)),
                ));
            }
            line = render(
                json,
                ts.as_deref(),
                Level::Warn,
                Event::LogDropped,
                &fields,
                false,
            );
            if line.len() <= MAX_LINE {
                break;
            }
        }
        line
    }

    /// Waits until the lines queued so far are written, at most until `deadline`.
    pub fn flush_until(&self, deadline: Instant) {
        let (ack, done) = mpsc::channel();
        if self.send_until(Msg::Flush(ack), deadline) {
            let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
    }

    /// Rule 21: drains the queue at exit within the one exit budget of [`DRAIN`], which starts
    /// at the first call; later calls share what is left.
    pub fn exit_flush(&self) {
        let deadline = *self.exit.get_or_init(|| Instant::now() + DRAIN);
        self.flush_until(deadline);
    }
}

/// Rule 13: the 32-byte key of the client tag, drawn from the operating system (`/dev/urandom`,
/// as the index epoch) at its first use, kept in memory only, never logged or written.
///
/// # Errors
///
/// The random source could not be read; the relay then refuses to start with the tag on.
pub(crate) fn client_tag_key() -> io::Result<&'static [u8; 32]> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(k);
    }
    let mut k = [0; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut k)?;
    Ok(KEY.get_or_init(|| k))
}

/// The first 8 hexadecimal characters of a hash.
fn tag_hex(h: &blake3::Hash) -> String {
    h.as_bytes().iter().take(4).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The writer thread: the only code that writes to the sink.
fn write_loop(rx: &Receiver<Msg>, mut sink: Box<dyn Write + Send>, logger: &Weak<Logger>) {
    loop {
        match rx.recv_timeout(TICK) {
            Ok(Msg::Line(line)) => {
                let _ = sink.write_all(&line);
            }
            Ok(Msg::Flush(ack)) => {
                let _ = sink.flush();
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if let Some(l) = logger.upgrade() {
            for line in l.tick() {
                let _ = sink.write_all(&line);
            }
        }
    }
}

/// Renders one line (rules 2 to 5). With `cut`, a line over [`MAX_LINE`] is cut at a character
/// boundary of a value and ends with `truncated=true` (rule 17); the result stays well-formed.
fn render(
    json: bool,
    ts: Option<&str>,
    level: Level,
    event: Event,
    fields: &Fields<'_>,
    cut: bool,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(3);
    if let Some(ts) = ts {
        head.push(("ts", Value::Str(ts)));
    }
    head.push(("level", Value::Str(level.name())));
    head.push(("event", Value::Str(event.name())));
    let all = || head.iter().chain(fields.iter());
    // Closing brace and line feed.
    let end = usize::from(json) + 1;
    let (mut s, mut truncated) = encode(json, all(), usize::MAX);
    if cut && s.len() + end > MAX_LINE {
        let suffix = if json { 17 } else { 15 };
        (s, truncated) = encode(json, all(), MAX_LINE - end - suffix);
    }
    if truncated {
        s.push_str(if json {
            ",\"truncated\":true"
        } else {
            " truncated=true"
        });
    }
    if json {
        s.push('}');
    }
    s.push('\n');
    s.into_bytes()
}

/// Encodes `fields` within `limit` bytes; `true` when something was left out.
fn encode<'a, 'b: 'a>(
    json: bool,
    fields: impl Iterator<Item = &'a (&'static str, Value<'b>)>,
    limit: usize,
) -> (String, bool) {
    let mut out = String::with_capacity(256);
    if json {
        out.push('{');
    }
    for (i, (key, value)) in fields.enumerate() {
        debug_assert!(valid_key(key), "{key}");
        let mark = out.len();
        if i > 0 {
            out.push(if json { ',' } else { ' ' });
        }
        if json {
            let _ = write!(out, "\"{key}\":");
        } else {
            let _ = write!(out, "{key}=");
        }
        let complete = match value {
            Value::Int(n) => {
                let _ = write!(out, "{n}");
                if out.len() > limit {
                    out.truncate(mark);
                }
                out.len() <= limit && out.len() > mark
            }
            Value::Bool(b) => {
                out.push_str(if *b { "true" } else { "false" });
                if out.len() > limit {
                    out.truncate(mark);
                }
                out.len() <= limit && out.len() > mark
            }
            Value::Str(v) if out.len() + 2 <= limit => push_str(&mut out, v, json, limit),
            Value::Str(_) => {
                out.truncate(mark);
                false
            }
        };
        if !complete {
            return (out, true);
        }
    }
    (out, false)
}

/// Rule 2: `[a-z][a-z0-9_]*`.
fn valid_key(k: &str) -> bool {
    let mut b = k.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Rule 3: a value written without quotes.
fn bare(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/@+-".contains(&b))
}

/// A character that rule 3 escapes, plus the C1 controls and U+2028 and U+2029, which some
/// readers take as line breaks.
fn is_control(c: char) -> bool {
    c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c) || c == '\u{2028}' || c == '\u{2029}'
}

/// Appends `s` as a value, escaped, without passing `limit` bytes; `false` if it was cut.
fn push_str(out: &mut String, s: &str, json: bool, limit: usize) -> bool {
    let quoted = json || !bare(s);
    let close = usize::from(quoted);
    if quoted {
        out.push('"');
    }
    let mut piece = String::with_capacity(16);
    let mut complete = true;
    for c in s.chars() {
        piece.clear();
        if quoted {
            escape(&mut piece, c, json);
        } else {
            piece.push(c);
        }
        if out.len() + piece.len() + close > limit {
            complete = false;
            break;
        }
        out.push_str(&piece);
    }
    if quoted {
        out.push('"');
    }
    complete
}

fn escape(out: &mut String, c: char, json: bool) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if is_control(c) && json => {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        }
        c if is_control(c) => {
            let mut buf = [0; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
        c => out.push(c),
    }
}

/// Rule 5: RFC 3339, UTC, milliseconds, suffix `Z`. A time before 1970 is written as the epoch.
#[must_use]
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm, unsigned form).
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

static START: OnceLock<Instant> = OnceLock::new();
static GLOBAL: OnceLock<Arc<Logger>> = OnceLock::new();

/// The wall clock as Unix time in milliseconds: the clock of block timestamps (spec §2.1, P1 of
/// ADR 0007), of `received_at` (ADR 0013 rule 2) and of quarantine names (ADR 0023 rule 4). `0`
/// before 1970. Not for durations or throttles: see [`now_ms`].
#[must_use]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Milliseconds since the first call, on a monotonic clock (throttles, durations). Not a Unix
/// time: see [`unix_ms`].
#[must_use]
pub fn now_ms() -> u64 {
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX - 1)
}

/// The process logger, writing to standard error; started at its first use.
#[must_use]
pub fn global() -> &'static Logger {
    GLOBAL.get_or_init(|| Logger::start(Box::new(io::stderr()), Arc::new(now_ms)))
}

/// Starts the process logger with `sink` instead of standard error (tests, embedding). `false`
/// if the logger was already started.
pub fn install(sink: Box<dyn Write + Send>) -> bool {
    let mut fresh = false;
    GLOBAL.get_or_init(|| {
        fresh = true;
        Logger::start(sink, Arc::new(now_ms))
    });
    fresh
}

/// Writes `event` at its level through [`global`].
pub fn emit(event: Event, fields: &Fields<'_>) {
    global().log(event.level(), event, fields);
}

/// Writes `event` at `level` through [`global`] (events with several levels).
pub fn emit_at(level: Level, event: Event, fields: &Fields<'_>) {
    global().log(level, event, fields);
}

/// Writes a throttled `event` (rule 8): through `t`, with `client` (rule 13) and `suppressed`
/// added before a `msg` field.
pub fn throttled(t: &Throttle, event: Event, fields: &Fields<'_>, client: Option<&ClientKey>) {
    let g = global();
    if !g.enabled(event.level()) {
        return;
    }
    let Some(n) = t.ready() else {
        return;
    };
    let tag = client.and_then(|k| g.client_tag(k));
    let mut all = fields.to_vec();
    let at = all
        .iter()
        .position(|(k, _)| *k == "msg")
        .unwrap_or(all.len());
    all.insert(at, ("suppressed", Value::Int(n)));
    if let Some(tag) = &tag {
        all.insert(at, ("client", Value::Str(tag)));
    }
    // Rule 16 orders the throttle before the bucket; a line the bucket refuses gives its
    // period back, so that the next occurrence is not hidden for a minute.
    if !g.write(event.level(), event, &all, true, None) {
        t.undo(n);
    }
}

/// Drains the queue of [`global`] at exit, within the exit budget (rule 21).
pub fn flush() {
    global().exit_flush();
}

thread_local! {
    /// Set while this thread polls a request inside the panic-catching layer.
    static CAUGHT: Cell<bool> = const { Cell::new(false) };
}

/// A request future polled inside `CatchPanicLayer` (`api`): a panic during its poll is caught
/// and answered `500`, and the hook knows it (rule 9).
pub struct Caught<F>(Pin<Box<F>>);

impl<F: Future> Caught<F> {
    /// Marks `f` as caught.
    pub fn new(f: F) -> Self {
        Self(Box::pin(f))
    }
}

impl<F: Future> Future for Caught<F> {
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        /// Restores the flag, also when the poll unwinds.
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                CAUGHT.with(|c| c.set(self.0));
            }
        }
        let _restore = Restore(CAUGHT.with(|c| c.replace(true)));
        self.0.as_mut().poll(cx)
    }
}

/// Security review L-2 (stricter option): only a literal message is logged; a formatted one may
/// hold request data (rule 10), so the line says `formatted=true` and keeps the location.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> Option<&'static str> {
    payload.downcast_ref::<&'static str>().copied()
}

static PANIC_CAUGHT: Throttle = Throttle::new();
static PANIC_UNCAUGHT: Throttle = Throttle::new();

/// Rule 9: replaces the default panic hook, which writes to standard error unthrottled, by the
/// `panic` event. The default hook does not run. Installed by the binary; a library user or a
/// test calls it when it wants this behaviour.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(on_panic));
}

/// A caught request panic is queued and throttled like any event; the `500` path counts it
/// (`error::panic_response`). Any other panic may end the thread or the process: it is counted
/// here, has its own throttle (an earlier caught panic does not hide it), skips the bucket, and
/// is written synchronously, bounded by [`DRAIN`].
fn on_panic(info: &std::panic::PanicHookInfo<'_>) {
    let location = info.location().map_or_else(
        || "unknown".to_owned(),
        |l| format!("{}:{}", l.file(), l.line()),
    );
    let mut fields = vec![("location", Value::Str(&location))];
    match panic_message(info.payload()) {
        Some(msg) => fields.push(("msg", Value::Str(msg))),
        None => fields.push(("formatted", Value::Bool(true))),
    }
    if CAUGHT.with(Cell::get) {
        throttled(&PANIC_CAUGHT, Event::Panic, &fields, None);
        return;
    }
    crate::metrics::panicked();
    let g = global();
    let Some(n) = PANIC_UNCAUGHT.ready() else {
        return;
    };
    let at = fields
        .iter()
        .position(|(k, _)| *k == "msg")
        .unwrap_or(fields.len());
    fields.insert(at, ("suppressed", Value::Int(n)));
    let deadline = Instant::now() + DRAIN;
    g.write(Level::Error, Event::Panic, &fields, false, Some(deadline));
    g.flush_until(deadline);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn test_logger(c: LogConfig) -> (Arc<Logger>, Receiver<Msg>, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000));
        let clock = Arc::clone(&t);
        let (l, rx) = Logger::new(Arc::new(move || clock.load(Ordering::Relaxed)));
        l.configure(&c);
        (l, rx, t)
    }

    fn quiet() -> LogConfig {
        LogConfig {
            timestamp: Timestamp::None,
            stats_interval_ms: 0,
            ..LogConfig::default()
        }
    }

    fn text(fields: &Fields<'_>) -> String {
        String::from_utf8(render(false, None, Level::Warn, Event::Shed, fields, true)).unwrap()
    }

    fn lines(rx: &Receiver<Msg>) -> Vec<String> {
        rx.try_iter()
            .filter_map(|m| match m {
                Msg::Line(l) => Some(String::from_utf8(l).unwrap()),
                Msg::Flush(_) => None,
            })
            .collect()
    }

    /// The `(event, level)` rows of each event table of `adr`, in order.
    fn event_tables(adr: &'static str) -> Vec<Vec<(&'static str, &'static str)>> {
        let mut tables = Vec::new();
        let mut lines = adr.lines();
        while lines.any(|l| l.contains("| `event` | Level |")) {
            let rows = lines
                .by_ref()
                .skip(1)
                .take_while(|l| l.trim_start().starts_with("| `"))
                .map(|l| {
                    let cols: Vec<&str> = l.split('|').map(str::trim).collect();
                    let level = cols[2].split(',').next().unwrap();
                    (cols[1].trim_matches('`'), level)
                })
                .collect();
            tables.push(rows);
        }
        tables
    }

    /// Rule 7: the enum is the table of the ADR, names, order and levels, followed by the table
    /// of ADR 0023 rule 14, which amends it, then the table of clarification X1 of ADR 0021.
    #[test]
    fn events_equal_the_adr_table() {
        let own = event_tables(include_str!(
            "../../../docs/decisions/0021-relay-observability-logs-metrics-disk-safety.md"
        ));
        assert_eq!(own.len(), 2, "rule 7 and clarification X1");
        let mut table = own[0].clone();
        let amended = event_tables(include_str!(
            "../../../docs/decisions/0023-relay-store-integrity.md"
        ));
        assert_eq!(amended.len(), 1);
        assert_eq!(amended[0].len(), 2, "ADR 0023 rule 14 adds two events");
        table.extend_from_slice(&amended[0]);
        assert_eq!(
            own[1],
            [("index_read_failed", "error")],
            "X1 adds one event"
        );
        table.extend_from_slice(&own[1]);
        // ADR 0046 rule 29 names three events without a level table: each must appear there.
        let adr0046 =
            include_str!("../../../docs/decisions/0046-keep-by-default-demand-eviction.md");
        let demand = [
            ("demand_evicted", "info"),
            ("demand_stuck", "warn"),
            ("demand_suspended", "warn"),
        ];
        for (name, _) in demand {
            assert!(adr0046.contains(&format!("`{name}`")), "{name}");
        }
        table.extend_from_slice(&demand);
        // Security review 2026-11-21, I-4: named by the ADR 0046 clarification written alongside
        // this change; checked against the ADR text once it is merged.
        table.push(("demand_migration", "info"));
        let ours: Vec<(&str, &str)> = Event::ALL
            .iter()
            .map(|e| (e.name(), e.level().name()))
            .collect();
        assert_eq!(ours, table);
    }

    /// Rule 3, with the forms an attacker would try: a line break, a forged field, quotes,
    /// backslashes, other controls, C1 controls and non-ASCII text.
    #[test]
    fn text_values_are_escaped() {
        let f = |v| text(&[("reason", Value::Str(v))]);
        assert_eq!(f("disk"), "level=warn event=shed reason=disk\n");
        assert_eq!(
            f("a/b:c@d+e-f_g.h"),
            "level=warn event=shed reason=a/b:c@d+e-f_g.h\n"
        );
        assert_eq!(
            f("x\nlevel=error event=fatal"),
            "level=warn event=shed reason=\"x\\nlevel=error event=fatal\"\n"
        );
        assert_eq!(
            f("a=1 b=\"2\" \\"),
            "level=warn event=shed reason=\"a=1 b=\\\"2\\\" \\\\\"\n"
        );
        assert_eq!(
            f("\r\t\0\x1b\x7f"),
            "level=warn event=shed reason=\"\\r\\t\\x00\\x1b\\x7f\"\n"
        );
        assert_eq!(
            f("\u{85}\u{2028}é"),
            "level=warn event=shed reason=\"\\xc2\\x85\\xe2\\x80\\xa8é\"\n"
        );
        assert_eq!(f(""), "level=warn event=shed reason=\"\"\n");
        for v in ["\n", "\r", "x\u{2029}y", "\u{85}"] {
            let line = f(v);
            assert_eq!(
                line.matches(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
                    .count(),
                1
            );
            assert!(line.ends_with('\n'));
        }
    }

    /// Rule 4: one object, the same keys in the same order; integers are numbers.
    #[test]
    fn json_lines_parse() {
        let line = render(
            true,
            Some("2026-11-19T14:03:07.123Z"),
            Level::Error,
            Event::Panic,
            &[
                ("location", Value::Str("a.rs:1")),
                ("suppressed", Value::Int(3)),
                ("msg", Value::Str("q\"\n\u{1}\u{2028}")),
            ],
            true,
        );
        let s = String::from_utf8(line).unwrap();
        assert_eq!(s.matches('\n').count(), 1);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(s.starts_with(
            "{\"ts\":\"2026-11-19T14:03:07.123Z\",\"level\":\"error\",\"event\":\"panic\",\
             \"location\":\"a.rs:1\",\"suppressed\":3,\"msg\":"
        ));
        assert_eq!(v["suppressed"], 3);
        assert_eq!(v["msg"], "q\"\n\u{1}\u{2028}");
    }

    #[test]
    fn rfc3339_fixed_instants() {
        let at = |s: u64, ms: u64| rfc3339(UNIX_EPOCH + Duration::from_millis(s * 1_000 + ms));
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1_709_164_800, 5), "2024-02-29T00:00:00.005Z");
        assert_eq!(at(1_767_225_599, 999), "2025-12-31T23:59:59.999Z");
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        assert_eq!(at(1_795_098_187, 123), "2026-11-19T14:23:07.123Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01T00:00:00.000Z"
        );
    }

    /// Rule 17: a long line is cut at a character boundary of a value, stays well formed and
    /// ends with `truncated=true`; a start-up line is not cut.
    #[test]
    fn long_lines_are_cut() {
        let long = "é\"x".repeat(600);
        for json in [false, true] {
            let fields = [("msg", Value::Str(&long))];
            let line = render(json, None, Level::Warn, Event::Shed, &fields, true);
            assert!(line.len() <= MAX_LINE, "{}", line.len());
            let s = String::from_utf8(line).unwrap();
            if json {
                let v: serde_json::Value = serde_json::from_str(&s).unwrap();
                assert_eq!(v["truncated"], true);
                assert!(long.starts_with(v["msg"].as_str().unwrap()));
            } else {
                assert!(s.ends_with("\" truncated=true\n"), "{s}");
            }
            let full = render(json, None, Level::Info, Event::Setting, &fields, false);
            assert!(full.len() > MAX_LINE);
        }
        // A field that does not fit at all is left out.
        let pad = "a".repeat(1_000);
        let s = text(&[("msg", Value::Str(&pad)), ("errno", Value::Int(u64::MAX))]);
        assert!(s.len() <= MAX_LINE && s.ends_with(" truncated=true\n"));
        // Exactly at the cap: not cut.
        let base = text(&[("msg", Value::Str(""))]).len() - 2;
        let fit = "a".repeat(MAX_LINE - base);
        let s = text(&[("msg", Value::Str(&fit))]);
        assert_eq!(s.len(), MAX_LINE);
        assert!(!s.contains("truncated"));
    }

    /// Rules 16, 18 and 20: a flood is bounded by the bucket, `warn` keeps its reserve, drops
    /// are counted and summarised once per minute, largest first.
    #[test]
    fn flood_is_bounded_and_summarised() {
        let (l, rx, clock) = test_logger(LogConfig {
            burst: 120,
            rate_per_min: 60,
            ..quiet()
        });
        for _ in 0..10_000 {
            l.log(Level::Debug, Event::Request, &[]);
        }
        assert!(!l.enabled(Level::Debug), "info by default");
        l.configure(&LogConfig {
            level: Level::Debug,
            ..quiet()
        });
        for _ in 0..10_000 {
            l.log(Level::Debug, Event::Request, &[("status", Value::Int(200))]);
        }
        // `info` and `debug` stop at a quarter of the burst.
        assert_eq!(lines(&rx).len(), 91);
        for _ in 0..100 {
            l.log(Level::Warn, Event::RateLimited, &[]);
        }
        assert_eq!(lines(&rx).len(), 29, "the reserve of warn and error");
        assert_eq!(l.dropped(Event::Request, Cause::Rate), 9_909);
        assert_eq!(l.dropped(Event::RateLimited, Cause::Rate), 71);
        // Outside the bucket: never dropped by it.
        l.log(
            Level::Info,
            Event::Shutdown,
            &[("phase", Value::Str("signal"))],
        );
        assert_eq!(lines(&rx).len(), 1);
        // One minute: 60 tokens back, and one summary.
        assert_eq!(l.tick().len(), 0, "no summary before the period");
        clock.fetch_add(SUMMARY_PERIOD_MS, Ordering::Relaxed);
        let t = l.tick();
        assert_eq!(t.len(), 1);
        assert_eq!(
            String::from_utf8(t[0].clone()).unwrap(),
            "level=warn event=log_dropped dropped=9980 request=9909 rate_limited=71\n"
        );
        assert_eq!(l.tick().len(), 0, "nothing new to report");
        l.log(Level::Debug, Event::Request, &[]);
        assert_eq!(lines(&rx).len(), 1, "the bucket refilled");
        l.count_drop(Event::Request, Cause::Queue);
        clock.fetch_add(1_000, Ordering::Relaxed);
        assert_eq!(l.tick().len(), 0, "at most once per period");
        assert_eq!(l.dropped_total(), 9_981);
    }

    /// Rule 20: events that do not fit are summed in `other`.
    #[test]
    fn summary_folds_into_other() {
        let (l, _rx, clock) = test_logger(LogConfig {
            format: Format::Json,
            ..quiet()
        });
        for (i, n) in l.pending.iter().enumerate() {
            n.store(u64::MAX / 2 - (EVENTS - i) as u64, Ordering::Relaxed);
        }
        clock.fetch_add(SUMMARY_PERIOD_MS, Ordering::Relaxed);
        let s = String::from_utf8(l.tick().remove(0)).unwrap();
        assert!(s.len() <= MAX_LINE);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("other").is_some() && v.get("truncated").is_none(),
            "{s}"
        );
        assert_eq!(v["dropped"], u64::MAX, "saturated");
        // Largest first: the last event of the table, then the one before.
        let head =
            "{\"level\":\"warn\",\"event\":\"log_dropped\",\"dropped\":18446744073709551615,";
        let [.., before, last] = Event::ALL;
        assert!(s.starts_with(&format!("{head}\"{}\":", last.name())), "{s}");
        let before = format!("\"{}\"", before.name());
        assert!(s.find(&before) < s.find("\"log_dropped\":"), "{s}");
    }

    /// Rule 42: the `stats` line every interval, with the counters.
    #[test]
    fn stats_line_is_periodic() {
        let (l, _rx, clock) = test_logger(LogConfig {
            stats_interval_ms: 300_000,
            ..quiet()
        });
        clock.fetch_add(299_999, Ordering::Relaxed);
        assert_eq!(l.tick().len(), 0);
        clock.fetch_add(1, Ordering::Relaxed);
        let s = String::from_utf8(l.tick().remove(0)).unwrap();
        assert!(s.starts_with("level=info event=stats requests_2xx="), "{s}");
        assert!(
            s.contains(" refused_429=") && s.ends_with(" log_dropped=0\n"),
            "{s}"
        );
    }

    /// Rule 21: with a sink that never returns, a caller does not wait; the queue holds 256
    /// lines and the rest are dropped and counted.
    #[test]
    fn a_blocked_sink_never_blocks_a_caller() {
        struct Blocked(Arc<std::sync::Barrier>);
        impl Write for Blocked {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0.wait(); // Never released: a full pipe.
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let l = Logger::start(
            Box::new(Blocked(Arc::new(std::sync::Barrier::new(2)))),
            Arc::new(|| 0),
        );
        l.configure(&LogConfig {
            burst: 3_000,
            rate_per_min: 6_000,
            ..quiet()
        });
        let start = Instant::now();
        for _ in 0..2_000 {
            l.log(Level::Error, Event::Panic, &[]);
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "{:?}",
            start.elapsed()
        );
        let queued = 2_000 - l.dropped(Event::Panic, Cause::Queue);
        // The writer holds one line, the queue the next 256.
        assert!(
            (QUEUE_LINES as u64..=QUEUE_LINES as u64 + 1).contains(&queued),
            "{queued}"
        );
        assert_eq!(l.dropped(Event::Panic, Cause::Rate), 0);
        // Rule 21, security review L-1: with the sink stalled, the exit lines never wait and
        // the exit flushes share one budget of `DRAIN`.
        let start = Instant::now();
        l.log(
            Level::Info,
            Event::Shutdown,
            &[("phase", Value::Str("signal"))],
        );
        l.log(
            Level::Warn,
            Event::Shutdown,
            &[("phase", Value::Str("deadline"))],
        );
        l.log(Level::Error, Event::Fatal, &[("msg", Value::Str("x"))]);
        assert!(start.elapsed() < Duration::from_millis(100));
        l.exit_flush();
        l.exit_flush();
        let spent = start.elapsed();
        assert!(
            spent >= DRAIN && spent < DRAIN + Duration::from_millis(300),
            "{spent:?}"
        );
    }

    /// Security review I-9: a line the bucket refuses gives back its throttle period.
    #[test]
    fn a_refused_line_gives_back_its_throttle() {
        let t = Throttle::new();
        let n = t.ready_at(0).unwrap();
        t.undo(n);
        assert_eq!(
            t.ready_at(1),
            Some(1),
            "free again, the refused one counted"
        );
    }

    /// Rule 9 with security review L-2: only a literal panic message is kept.
    #[test]
    fn only_literal_panic_messages_are_kept() {
        let literal: Box<dyn std::any::Any + Send> = Box::new("constant");
        let formatted: Box<dyn std::any::Any + Send> = Box::new(String::from("zz-input"));
        assert_eq!(panic_message(&*literal), Some("constant"));
        assert_eq!(panic_message(&*formatted), None);
        let line = render(
            true,
            None,
            Level::Error,
            Event::Panic,
            &[("formatted", Value::Bool(true)), ("errno", Value::Int(28))],
            true,
        );
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(
            (v["formatted"].as_bool(), v["errno"].as_u64()),
            (Some(true), Some(28))
        );
        assert_eq!(
            text(&[("formatted", Value::Bool(true))]),
            "level=warn event=shed formatted=true\n"
        );
    }

    #[test]
    fn throttle_reports_suppressed_events() {
        let t = Throttle::new();
        assert_eq!(t.ready_at(10), Some(0));
        assert_eq!(t.ready_at(20), None);
        assert_eq!(t.ready_at(30), None);
        assert_eq!(t.ready_at(10 + Throttle::PERIOD_MS), Some(2));
        assert_eq!(t.ready_at(20 + Throttle::PERIOD_MS), None);
    }

    #[test]
    fn client_tag_is_keyed_blake3() {
        let policy = crate::client::ClientPolicy::new(Vec::new(), Vec::new(), 64, 1);
        let k = policy.key("203.0.113.7".parse().unwrap()).unwrap();
        let (l, _rx, _) = test_logger(quiet());
        assert_eq!(l.client_tag(&k), None, "off by default");
        l.configure(&LogConfig {
            client_tag: ClientTag::Keyed,
            ..quiet()
        });
        let tag = l.client_tag(&k).unwrap();
        let want = blake3::keyed_hash(client_tag_key().unwrap(), &k.tag_input());
        assert_eq!(tag, want.to_hex()[..8]);
        assert!(tag.len() == 8 && tag.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(l.client_tag(&k).unwrap(), tag, "stable within the run");
        let other = policy.key("2001:db8::1".parse().unwrap()).unwrap();
        assert_ne!(l.client_tag(&other).unwrap(), tag);
    }

    #[test]
    fn keys_are_valid_and_choices_parse() {
        assert!(valid_key("index_write_failed") && valid_key("a1"));
        assert!(!valid_key("") && !valid_key("1a") && !valid_key("A") && !valid_key("a-b"));
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("WARN"), None);
        assert!(Level::Debug < Level::Info && Level::Warn < Level::Error);
        assert_eq!(Format::parse("json"), Some(Format::Json));
    }
}
