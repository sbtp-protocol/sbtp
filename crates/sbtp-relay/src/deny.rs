//! The operator deny list (ADR 0052; core spec §4, "Denied blocks"; `architecture.md` §2).
//!
//! The list names blocks by `block_id` and keys by the header's public key. It is local
//! configuration: read from `deny_file` at start-up, on `SIGHUP` and when the file changes
//! (device, inode, modification or change time, size; checked every `deny_reload_ms`), never
//! derived from anything the relay receives (rule 2). A file that changes while it is read is
//! discarded and read again (deny review L-1). An invalid file at start-up stops the start-up; an
//! invalid or missing file on reload keeps the previous list whole (rule 4).
//!
//! **Parser input bounds** (rule 3, for the security review). The file is read as a stream
//! through one buffer of [`READ_BUFFER`] bytes and one line buffer of at most
//! [`MAX_LINE_BYTES`] + 1 bytes: a line is never read past that, so a file without newlines
//! costs no more memory than a short one. The list itself is bounded by `deny_max_entries`
//! distinct entries (rule 21), allocated fallibly. A file that is not a regular file is refused
//! before it is read, and it is opened non-blocking, so a FIFO or a device cannot hang a reload.
//! Time is linear in the file's size; reloads run on a blocking thread, never on a request.
//! Nothing from a line reaches a log: an invalid file is reported by line number and a fixed
//! reason only (rule 20).
//!
//! **Checks** (rule 5): one hash lookup for the `block_id` and one for the key per checked
//! block, against an immutable [`List`] behind a read lock that is held only to clone an `Arc`.
//! A request uses the list current when its check runs, so a load applies to every request
//! that starts after it (rule 4).
//!
//! **Marking pass** (rules 9 and 14). After a load that adds a key or a `purge` entry, a
//! background task walks the held blocks in store order, `sweep_batch` per run, off the request
//! path. For each block under its `PUT` lock it reads the stored file's public key; a block of a
//! listed key with `hide` gets a mark in the index (`block_id` → key), which `/query` uses to
//! leave it out while the key stays listed; a block matched by a `purge` entry is deleted as an
//! eviction deletes (cache entry, file, index entries), without the demand protection. A mark
//! stores the key, so lifting a key lists its blocks again at once and a stale mark is harmless;
//! marks go with the block's index entries.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use sbtp_core::BlockId;
use sbtp_core::layout::{OFFSET_PUBKEY, PUBKEY_LEN};
use tokio::sync::{Notify, watch};
use tokio::time::MissedTickBehavior;

use crate::blocks::Relay;
use crate::config::{ConfigError, Settings};
use crate::index::{IndexBackend, Position};
use crate::log::{self, Event, Throttle, Value};
use crate::metrics;
use crate::store;

/// Rule 3: the longest valid line, in bytes, without its `\n`.
pub const MAX_LINE_BYTES: usize = 256;

/// The read buffer of the parser.
pub const READ_BUFFER: usize = 8_192;

/// The pause between two runs of the marking pass, so that a long pass leaves the index and the
/// disk to requests.
const PASS_PAUSE: Duration = Duration::from_millis(10);

/// The wait before a run of the marking pass that an index queue refused is tried again.
const PASS_RETRY: Duration = Duration::from_secs(1);

/// What an entry asks for (rule 14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Not served, not listed; the file and the index entries are kept (the default).
    Hide,
    /// Deleted by the marking pass as an eviction deletes.
    Purge,
}

/// How a block matched the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// Its `block_id` is listed.
    Block,
    /// Its public key is listed (and its `block_id` is not).
    Key,
}

impl Match {
    /// Whether the match is by key, for the `match` label of `denied_total`.
    #[must_use]
    pub fn is_key(self) -> bool {
        self == Self::Key
    }
}

/// Why a file is invalid (rule 3). Fixed texts: never the line's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The file is missing (rule 4: invalid on reload).
    Missing,
    /// The file could not be opened or read, or is not a regular file.
    Unreadable,
    /// A line is not UTF-8.
    NotUtf8,
    /// A line of more than [`MAX_LINE_BYTES`] bytes.
    LineTooLong,
    /// A line that is not empty, a comment or `<kind> <hex>[ <action>]`.
    UnknownToken,
    /// More than `deny_max_entries` distinct entries.
    TooManyEntries,
    /// One entry listed with two actions.
    ConflictingActions,
    /// The list could not be allocated.
    OutOfMemory,
}

impl Reason {
    /// The `reason` field of `deny_list_invalid`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::NotUtf8 => "not_utf8",
            Self::LineTooLong => "line_too_long",
            Self::UnknownToken => "unknown_token",
            Self::TooManyEntries => "too_many_entries",
            Self::ConflictingActions => "conflicting_actions",
            Self::OutOfMemory => "out_of_memory",
        }
    }
}

/// An invalid file: the 1-based line at fault (0 for the file as a whole) and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid {
    /// The line number, from 1; 0 when the file as a whole is at fault.
    pub line: u64,
    /// Why.
    pub reason: Reason,
}

/// One loaded list, immutable; a reload replaces it whole.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct List {
    blocks: HashMap<[u8; 32], Action>,
    keys: HashMap<[u8; 32], Action>,
}

impl List {
    /// Parses a deny file (rule 3) of at most `max_entries` distinct entries.
    ///
    /// # Errors
    ///
    /// The first invalid line, or a read error ([`Reason::Unreadable`]).
    pub fn parse(r: impl Read, max_entries: usize) -> Result<Self, Invalid> {
        let mut r = BufReader::with_capacity(READ_BUFFER, r);
        let mut line = Vec::with_capacity(MAX_LINE_BYTES + 1);
        let mut list = Self::default();
        let mut n: u64 = 0;
        loop {
            line.clear();
            n = n.saturating_add(1);
            let invalid = |reason| Invalid { line: n, reason };
            // At most one byte past the longest valid line, newline included.
            let read = (&mut r)
                .take(MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|_| invalid(Reason::Unreadable))?;
            if read == 0 {
                return Ok(list);
            }
            let text = line.strip_suffix(b"\n").unwrap_or(&line);
            if text.len() > MAX_LINE_BYTES {
                return Err(invalid(Reason::LineTooLong));
            }
            let text = std::str::from_utf8(text).map_err(|_| invalid(Reason::NotUtf8))?;
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let (kind, value, action) = parse_line(text).ok_or(invalid(Reason::UnknownToken))?;
            let total = list.blocks.len().saturating_add(list.keys.len());
            let map = if kind == Match::Block {
                &mut list.blocks
            } else {
                &mut list.keys
            };
            if let Some(&known) = map.get(&value) {
                // The same entry twice with one action counts once.
                if known != action {
                    return Err(invalid(Reason::ConflictingActions));
                }
                continue;
            }
            if total >= max_entries {
                return Err(invalid(Reason::TooManyEntries));
            }
            map.try_reserve(1)
                .map_err(|_| invalid(Reason::OutOfMemory))?;
            if let Entry::Vacant(v) = map.entry(value) {
                v.insert(action);
            }
        }
    }

    /// Whether the list has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.keys.is_empty()
    }

    /// Whether the list names a key.
    #[must_use]
    pub fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }

    /// The `blocks`, `keys` and `purge` counts of `deny_list_loaded`.
    #[must_use]
    pub fn counts(&self) -> (u64, u64, u64) {
        let purge = self
            .blocks
            .values()
            .chain(self.keys.values())
            .filter(|a| **a == Action::Purge)
            .count();
        (
            self.blocks.len() as u64,
            self.keys.len() as u64,
            purge as u64,
        )
    }

    /// Whether the block `id`, signed by `key` when known, is denied (rules 1 and 5): one lookup
    /// for the `block_id`, one for the key.
    #[must_use]
    pub fn check(&self, id: &BlockId, key: Option<&[u8; 32]>) -> Option<Match> {
        if self.blocks.contains_key(id.as_bytes()) {
            return Some(Match::Block);
        }
        key.filter(|k| self.keys.contains_key(*k))
            .map(|_| Match::Key)
    }

    /// Whether the block `id` is listed by its `block_id`.
    #[must_use]
    pub fn denies_id(&self, id: &BlockId) -> bool {
        self.blocks.contains_key(id.as_bytes())
    }

    /// Whether `key` is listed.
    #[must_use]
    pub fn denies_key(&self, key: &[u8; 32]) -> bool {
        self.keys.contains_key(key)
    }

    /// Rule 14: what the marking pass does with a held block: whether its key is listed, and
    /// whether an entry that matches it asks for `purge`.
    fn judge(&self, id: &BlockId, key: Option<&[u8; 32]>) -> (bool, bool) {
        let by_id = self.blocks.get(id.as_bytes());
        let by_key = key.and_then(|k| self.keys.get(k));
        let purge = by_id.into_iter().chain(by_key).any(|a| *a == Action::Purge);
        (by_key.is_some(), purge)
    }

    /// Rule 9: whether this list, loaded after `old`, needs a marking pass: it adds a key, or
    /// a `purge` entry. Every list with a key or a `purge` entry needs one at start-up.
    #[must_use]
    pub fn needs_pass(&self, old: Option<&Self>) -> bool {
        let added_key = self
            .keys
            .keys()
            .any(|k| old.is_none_or(|o| !o.keys.contains_key(k)));
        let added_purge = |new: &HashMap<[u8; 32], Action>, old: Option<&HashMap<_, _>>| {
            new.iter().any(|(k, a)| {
                *a == Action::Purge && old.and_then(|o| o.get(k)) != Some(&Action::Purge)
            })
        };
        added_key
            || added_purge(&self.blocks, old.map(|o| &o.blocks))
            || added_purge(&self.keys, old.map(|o| &o.keys))
    }

    /// Every listed key with `hide` or `purge`, for the operator command.
    pub fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.keys.keys()
    }
}

/// `<kind> <hex>[ <action>]`, single spaces, nothing else (rule 3).
fn parse_line(text: &str) -> Option<(Match, [u8; 32], Action)> {
    let mut tokens = text.split(' ');
    let kind = match tokens.next()? {
        "block" => Match::Block,
        "key" => Match::Key,
        _ => return None,
    };
    let value = store::decode_hex::<32>(tokens.next()?)?;
    let action = match tokens.next() {
        None | Some("hide") => Action::Hide,
        Some("purge") => Action::Purge,
        Some(_) => return None,
    };
    if tokens.next().is_some() {
        return None;
    }
    Some((kind, value, action))
}

/// The public key of a stored block's bytes (its header, spec §2.1).
#[must_use]
pub fn pubkey_of(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes
        .get(OFFSET_PUBKEY..OFFSET_PUBKEY + PUBKEY_LEN)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
}

/// What tells one state of the file from another: the device and inode (an `mv` into place),
/// the modification and change times (a time-preserving copy changes `ctime`) and the size
/// (deny review L-1). `None` when the file cannot be read, or when the last read must be done
/// again.
type Stamp = Option<FileStamp>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    mtime: Option<SystemTime>,
    /// `ctime` in seconds and nanoseconds; `(0, 0)` where it does not exist.
    ctime: (i64, i64),
    len: u64,
}

/// How many times the start-up load reads a file that changes while it is read, before giving
/// up, and the pause between two reads.
const SETTLE_TRIES: u32 = 5;
const SETTLE_PAUSE: Duration = Duration::from_millis(50);

/// The deny list of a relay: off, or the list loaded from `deny_file`.
#[derive(Debug, Default)]
pub struct Deny {
    path: Option<PathBuf>,
    max_entries: usize,
    reload_every: Duration,
    /// `None` when off.
    list: RwLock<Option<Arc<List>>>,
    /// The stamp of the last read attempt, so that an unchanged file is not read again.
    stamp: Mutex<Stamp>,
    /// Set by a load that needs a marking pass, taken by the pass.
    pass_wanted: AtomicBool,
    /// `SIGHUP` (or a test) asks for a reload.
    reload: Notify,
}

/// The outcome of [`Deny::reload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reload {
    /// A new list is in force.
    Loaded,
    /// The file is invalid or missing: the previous list stays in force.
    Invalid(Invalid),
    /// The file changed while it was read (deny review L-1): the result is discarded, the
    /// previous list stays in force, and the next poll reads the file again.
    Changed,
    /// The deny list is off.
    Off,
}

impl Deny {
    /// No deny list.
    #[must_use]
    pub fn off() -> Self {
        Self::default()
    }

    /// The deny list of `s`, loaded once (rule 4); off when `deny_file` is not set.
    ///
    /// # Errors
    ///
    /// The file is invalid or missing: `ConfigError::Invalid` naming `deny_file`, with the line
    /// number and a fixed reason, never the line's content.
    pub fn open(s: &Settings) -> Result<Self, ConfigError> {
        let Some(path) = s.deny_file.clone() else {
            return Ok(Self::off());
        };
        let deny = Self {
            path: Some(path),
            max_entries: usize::try_from(s.deny_max_entries).unwrap_or(usize::MAX),
            reload_every: Duration::from_millis(s.deny_reload_ms),
            ..Self::default()
        };
        for _ in 0..SETTLE_TRIES {
            match deny.reload() {
                Reload::Loaded | Reload::Off => return Ok(deny),
                Reload::Invalid(e) => {
                    return Err(ConfigError::Invalid {
                        setting: "deny_file",
                        reason: format!("invalid at line {}: {}", e.line, e.reason.name()),
                    });
                }
                Reload::Changed => std::thread::sleep(SETTLE_PAUSE),
            }
        }
        Err(ConfigError::Invalid {
            setting: "deny_file",
            reason: "the file kept changing while it was read".into(),
        })
    }

    /// Whether a deny list is applied (`deny_file` is set; `/info` `deny_list`, rule 11).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// The list in force, `None` when off.
    #[must_use]
    pub fn list(&self) -> Option<Arc<List>> {
        if !self.enabled() {
            return None;
        }
        self.list
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the block `id`, signed by `key` when known, is denied by the list in force.
    #[must_use]
    pub fn check(&self, id: &BlockId, key: Option<&[u8; 32]>) -> Option<Match> {
        self.list()?.check(id, key)
    }

    /// Asks the reload task for a reload (`SIGHUP`).
    pub fn request_reload(&self) {
        self.reload.notify_one();
    }

    /// Takes the request for a marking pass left by a load.
    pub fn take_pass(&self) -> bool {
        self.pass_wanted.swap(false, Ordering::AcqRel)
    }

    /// Whether the file's stamp ([`FileStamp`]) differs from the last read attempt.
    #[must_use]
    pub fn changed(&self) -> bool {
        let Some(path) = &self.path else {
            return false;
        };
        let now = stamp_of(std::fs::metadata(path).ok().as_ref());
        now != *self.stamp.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the file again (rule 4), on a blocking thread. A valid file replaces the list
    /// whole and is logged as `deny_list_loaded`; an invalid or missing one is refused whole,
    /// logged as `deny_list_invalid` (throttled), and the previous list stays in force.
    pub fn reload(&self) -> Reload {
        static INVALID_LOG: Throttle = Throttle::new();
        let Some(path) = &self.path else {
            return Reload::Off;
        };
        let (read, stamp) = read_file(path, self.max_entries);
        *self.stamp.lock().unwrap_or_else(PoisonError::into_inner) = stamp;
        let new = match read {
            Ok(Some(list)) => Arc::new(list),
            // Deny review L-1: half a rewrite is never applied; `stamp` is unset, so that the
            // next poll reads the file again.
            Ok(None) => return Reload::Changed,
            Err(e) => {
                log::throttled(
                    &INVALID_LOG,
                    Event::DenyListInvalid,
                    &[
                        ("line", Value::Int(e.line)),
                        ("reason", Value::Str(e.reason.name())),
                    ],
                    None,
                );
                return Reload::Invalid(e);
            }
        };
        let (blocks, keys, purge) = new.counts();
        let old = {
            let mut slot = self.list.write().unwrap_or_else(PoisonError::into_inner);
            slot.replace(Arc::clone(&new))
        };
        if new.needs_pass(old.as_deref()) {
            self.pass_wanted.store(true, Ordering::Release);
        }
        drop(old);
        metrics::set_deny_entries(blocks, keys);
        log::emit(
            Event::DenyListLoaded,
            &[
                ("blocks", Value::Int(blocks)),
                ("keys", Value::Int(keys)),
                ("purge", Value::Int(purge)),
            ],
        );
        Reload::Loaded
    }
}

fn stamp_of(m: Option<&std::fs::Metadata>) -> Stamp {
    m.map(|m| {
        #[cfg(unix)]
        let (dev, ino, ctime) = {
            use std::os::unix::fs::MetadataExt as _;
            (m.dev(), m.ino(), (m.ctime(), m.ctime_nsec()))
        };
        #[cfg(not(unix))]
        let (dev, ino, ctime) = (0, 0, (0, 0));
        FileStamp {
            dev,
            ino,
            mtime: m.modified().ok(),
            ctime,
            len: m.len(),
        }
    })
}

/// Opens `path` without blocking on a FIFO or a device, refuses anything but a regular file,
/// and parses it. Returns the stamp of the opened file. `Ok(None)` when the open file changed
/// while it was parsed (deny review L-1): an in-place rewrite caught half-way, whose stamp is
/// then `None`.
fn read_file(path: &Path, max_entries: usize) -> (Result<Option<List>, Invalid>, Stamp) {
    read_file_then(path, max_entries, || {})
}

/// [`read_file`], with `between` called between the parse and the second `fstat` (tests).
fn read_file_then(
    path: &Path,
    max_entries: usize,
    between: impl FnOnce(),
) -> (Result<Option<List>, Invalid>, Stamp) {
    let whole = |reason| Invalid { line: 0, reason };
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        open.custom_flags(libc::O_NONBLOCK);
    }
    let file = match open.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return (Err(whole(Reason::Missing)), None);
        }
        Err(_) => return (Err(whole(Reason::Unreadable)), None),
    };
    let meta = file.metadata().ok();
    let stamp = stamp_of(meta.as_ref());
    if !meta.is_some_and(|m| m.is_file()) {
        return (Err(whole(Reason::Unreadable)), stamp);
    }
    let parsed = match List::parse(&file, max_entries) {
        Ok(list) => list,
        Err(e) => return (Err(e), stamp),
    };
    between();
    // A rewrite in place that started or ended during the parse changes the size, the
    // modification or the change time of the open file.
    if stamp_of(file.metadata().ok().as_ref()) != stamp {
        return (Ok(None), None);
    }
    (Ok(Some(parsed)), stamp)
}

/// Where the marking pass is.
struct Pass {
    from: Position,
    pending: u64,
}

/// One run of the marking pass from `from`, at most `batch` held blocks, with `list`. Returns
/// the next position and the number of blocks walked, `None` as position when the walk is done;
/// `Err` when an index queue refused or a job failed (the run is tried again).
pub(crate) fn mark_once<I: IndexBackend + 'static>(
    relay: &Relay<I>,
    list: &List,
    from: Position,
    batch: usize,
) -> Result<(Option<Position>, u64), ()> {
    let Ok(Ok(page)) = relay
        .index()
        .read_blocking(move |i| i.query(None, from, batch))
    else {
        return Err(());
    };
    let walked = page.entries.len() as u64;
    let mut marks = Vec::new();
    let mut purged = Vec::new();
    for (at, id) in page.entries {
        let _lock = relay.lock_id(&id);
        // The stored file's key; a file that cannot be read is judged by its `block_id` only.
        let key = relay
            .store()
            .read(&id)
            .ok()
            .flatten()
            .and_then(|b| pubkey_of(&b));
        let (by_key, purge) = list.judge(&id, key.as_ref());
        if purge {
            // Rule 14: as an eviction deletes, regardless of ADR 0046 rule 7. A failed deletion
            // keeps the entries; the next pass tries again.
            if relay.evict_locked(&id).is_ok() {
                purged.push(at);
            }
        } else if let (true, Some(k)) = (by_key, key) {
            marks.push((id, k));
        }
    }
    relay.store().publish_gauges();
    if !marks.is_empty() {
        match relay.index().write_blocking(move |i| i.mark_denied(&marks)) {
            Ok(Ok(_)) => {}
            _ => return Err(()),
        }
    }
    if !purged.is_empty() {
        match relay.index().write_blocking(move |i| i.remove(&purged)) {
            Ok(Ok(_)) => {}
            _ => return Err(()),
        }
    }
    Ok((page.more.then_some(page.next), walked))
}

/// The whole marking pass with the list in force, run after run, on the calling thread (tests,
/// the operator command).
pub fn mark_all<I: IndexBackend + 'static>(relay: &Relay<I>, batch: usize) -> bool {
    let Some(list) = relay.deny().list() else {
        return true;
    };
    let mut from = Position::default();
    loop {
        match mark_once(relay, &list, from, batch) {
            Ok((Some(next), _)) => from = next,
            Ok((None, _)) => return true,
            Err(()) => return false,
        }
    }
}

/// The reload task (rule 4) and the marking pass (rules 9 and 14), until `stop` changes: a
/// reload on [`Deny::request_reload`] and when the file changed (every `deny_reload_ms`), a run
/// of the pass every [`PASS_PAUSE`] while one is due. Returns early only if a job panicked,
/// which the caller treats as the end of a supervised task (ADR 0018 rule 37).
pub async fn run<I: IndexBackend + 'static>(
    relay: Arc<Relay<I>>,
    batch: usize,
    mut stop: watch::Receiver<bool>,
) {
    let deny = Arc::clone(relay.deny_arc());
    let every = deny.reload_every.max(Duration::from_millis(1));
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut pass: Option<Pass> = None;
    loop {
        if deny.take_pass() {
            let r = Arc::clone(&relay);
            let len = tokio::task::spawn_blocking(move || {
                r.index()
                    .read_blocking(IndexBackend::len)
                    .ok()
                    .and_then(Result::ok)
            })
            .await;
            let Ok(len) = len else { return };
            pass = Some(Pass {
                from: Position::default(),
                pending: len.unwrap_or(0),
            });
        }
        metrics::set_deny_marking_pending(pass.as_ref().map_or(0, |p| p.pending));
        let pause = if pass.is_some() {
            PASS_PAUSE
        } else {
            Duration::MAX
        };
        let forced = tokio::select! {
            biased;
            _ = stop.changed() => return,
            () = deny.reload.notified() => Some(true),
            _ = tick.tick() => Some(false),
            () = sleep_or_never(pause) => None,
        };
        if let Some(forced) = forced {
            let d = Arc::clone(&deny);
            let job = tokio::task::spawn_blocking(move || {
                if forced || d.changed() {
                    d.reload();
                }
            });
            if job.await.is_err() {
                return;
            }
            continue;
        }
        let Some(p) = pass.as_mut() else { continue };
        let Some(list) = deny.list() else {
            pass = None;
            continue;
        };
        let (r, from) = (Arc::clone(&relay), p.from);
        let Ok(ran) = tokio::task::spawn_blocking(move || mark_once(&r, &list, from, batch)).await
        else {
            return;
        };
        match ran {
            Ok((Some(next), n)) => {
                p.from = next;
                p.pending = p.pending.saturating_sub(n);
            }
            Ok((None, _)) => pass = None,
            Err(()) => tokio::time::sleep(PASS_RETRY).await,
        }
    }
}

async fn sleep_or_never(d: Duration) {
    if d == Duration::MAX {
        std::future::pending::<()>().await;
    } else {
        tokio::time::sleep(d).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::format_collect)]
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn parse(text: &[u8], max: usize) -> Result<List, Invalid> {
        List::parse(text, max)
    }

    fn bad(text: &[u8], line: u64, reason: Reason) {
        assert_eq!(
            parse(text, 16).unwrap_err(),
            Invalid { line, reason },
            "{}",
            String::from_utf8_lossy(text)
        );
    }

    fn id(hex: &str) -> BlockId {
        store::parse_hex_id(hex).unwrap()
    }

    /// ADR 0052 rule 3: empty lines, comments, `block` and `key` entries, `hide` by default,
    /// `purge`, a missing final newline; a duplicate with one action counts once.
    #[test]
    fn valid_file_forms() {
        let text = format!("# operator list\n\nblock {A}\nkey {B} purge\nblock {A} hide\nkey {A}");
        let l = parse(text.as_bytes(), 3).unwrap();
        assert_eq!(l.counts(), (1, 2, 1));
        assert_eq!(l.check(&id(A), None), Some(Match::Block));
        assert_eq!(l.check(&id(B), None), None);
        let key_b = store::decode_hex::<32>(B).unwrap();
        assert_eq!(l.check(&id(B), Some(&key_b)), Some(Match::Key));
        // A block listed by id wins over its key on the match reported.
        assert_eq!(l.check(&id(A), Some(&key_b)), Some(Match::Block));
        assert!(parse(b"", 1).unwrap().is_empty());
    }

    /// ADR 0052 rule 3: every invalid form, with its line number and fixed reason.
    #[test]
    fn invalid_file_forms() {
        bad(
            format!("block {A} drop\n").as_bytes(),
            1,
            Reason::UnknownToken,
        );
        bad(format!("\nfile {A}\n").as_bytes(), 2, Reason::UnknownToken);
        bad(
            format!("block {}\n", A.to_uppercase()).as_bytes(),
            1,
            Reason::UnknownToken,
        );
        bad(
            format!("block {}\n", &A[..63]).as_bytes(),
            1,
            Reason::UnknownToken,
        );
        bad(format!("block  {A}\n").as_bytes(), 1, Reason::UnknownToken);
        bad(format!("block {A} \n").as_bytes(), 1, Reason::UnknownToken);
        bad(format!("block {A}\r\n").as_bytes(), 1, Reason::UnknownToken);
        bad(b" # comment\n", 1, Reason::UnknownToken);
        bad(
            format!("block {A} hide purge\n").as_bytes(),
            1,
            Reason::UnknownToken,
        );
        bad(b"block\n", 1, Reason::UnknownToken);
        bad(b" \n", 1, Reason::UnknownToken);
        bad(
            format!("block {A}\nblock {A} purge\n").as_bytes(),
            2,
            Reason::ConflictingActions,
        );
        bad(b"# \xff\xfe\n", 1, Reason::NotUtf8);
    }

    /// ADR 0052 rule 3: a line of 256 bytes is read, one of 257 is invalid, also as the last
    /// line without a newline and in a file with no newline at all (the read stops at 257
    /// bytes).
    #[test]
    fn line_length_bound() {
        let ok = format!("#{}\n", "x".repeat(MAX_LINE_BYTES - 1));
        assert!(parse(ok.as_bytes(), 1).is_ok());
        let long = format!("#{}", "x".repeat(MAX_LINE_BYTES));
        bad(format!("{long}\n").as_bytes(), 1, Reason::LineTooLong);
        bad(format!("\n{long}").as_bytes(), 2, Reason::LineTooLong);
        let huge = vec![b'#'; 10 * 1024 * 1024];
        bad(&huge, 1, Reason::LineTooLong);
    }

    /// ADR 0052 rules 3 and 21: `deny_max_entries` distinct entries; duplicates do not count, a
    /// block and a key with the same value are two entries.
    #[test]
    fn entry_bound() {
        let two = format!("block {A}\nblock {A}\nkey {A}\n");
        assert_eq!(parse(two.as_bytes(), 2).unwrap().counts(), (1, 1, 0));
        let over = |t: &[u8], max, line| {
            assert_eq!(
                parse(t, max).unwrap_err(),
                Invalid {
                    line,
                    reason: Reason::TooManyEntries
                }
            );
        };
        over(format!("{two}key {B}\n").as_bytes(), 2, 4);
        let many: String = (0..=255u8)
            .map(|n| format!("block {}\n", hex32(n)))
            .collect();
        assert_eq!(parse(many.as_bytes(), 256).unwrap().counts(), (256, 0, 0));
        over(many.as_bytes(), 255, 256);
    }

    fn hex32(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    /// ADR 0052 rule 9: a pass after a load that adds a key or a `purge` entry, not after one
    /// that only adds a block with `hide` or removes entries.
    #[test]
    fn pass_after_added_key_or_purge() {
        let l = |t: String| parse(t.as_bytes(), 16).unwrap();
        let blocks = l(format!("block {A}\n"));
        let keys = l(format!("key {B}\n"));
        assert!(!blocks.needs_pass(None));
        assert!(keys.needs_pass(None));
        assert!(!keys.needs_pass(Some(&keys)));
        assert!(!List::default().needs_pass(Some(&keys)));
        assert!(l(format!("block {A} purge\n")).needs_pass(Some(&blocks)));
        assert!(
            !l(format!("block {A} purge\n")).needs_pass(Some(&l(format!("block {A} purge\n"))))
        );
        assert!(l(format!("key {B} purge\n")).needs_pass(Some(&keys)));
        assert!(l(format!("key {A}\n")).needs_pass(Some(&keys)));
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sbtp-deny-{name}-{}-{}",
            std::process::id(),
            log::unix_ms()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d.join("deny.txt")
    }

    /// Deny review L-1: a file rewritten in place while it is parsed is discarded, with no
    /// stamp, so that the next poll reads it again.
    #[test]
    fn a_file_changed_during_the_parse_is_discarded() {
        let path = scratch("rewrite");
        std::fs::write(&path, format!("block {A}\n")).unwrap();
        let (read, stamp) = read_file_then(&path, 16, || {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(format!("block {B}\n").as_bytes()).unwrap();
        });
        assert_eq!((read, stamp), (Ok(None), None));
        let (read, stamp) = read_file(&path, 16);
        assert_eq!(read.unwrap().unwrap().counts(), (2, 0, 0));
        assert!(stamp.is_some());
    }

    /// Deny review L-1: a replacement with the same size and modification time, moved into
    /// place, is seen by the poll (the inode and `ctime` differ).
    #[test]
    fn a_same_size_same_time_replacement_is_seen() {
        let path = scratch("swap");
        std::fs::write(&path, format!("block {A}\n")).unwrap();
        let deny = Deny {
            path: Some(path.clone()),
            max_entries: 16,
            ..Deny::default()
        };
        assert_eq!(deny.reload(), Reload::Loaded);
        assert!(!deny.changed());
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let next = path.with_extension("new");
        std::fs::write(&next, format!("block {B}\n")).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&next)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        std::fs::rename(&next, &path).unwrap();
        assert!(deny.changed());
        assert_eq!(deny.reload(), Reload::Loaded);
        assert!(deny.check(&id(B), None).is_some());
    }

    /// The public key of a block is read from its header.
    #[test]
    fn pubkey_from_header() {
        let k = sbtp_core::SigningKey::from_bytes(&[3; 32]);
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .payload(b"k")
            .build(&k, 0)
            .unwrap();
        let block = sbtp_core::parse(&bytes).unwrap();
        assert_eq!(pubkey_of(&bytes).as_ref(), Some(block.pubkey()));
        assert_eq!(pubkey_of(&bytes[..40]), None);
    }
}
