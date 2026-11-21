//! Flat-file block store (ADR 0009; ADR 0013 rules 1, 7 to 9 and 18 to 21; ADR 0025).
//!
//! Layout (ADR 0025 rule 1): `<data_dir>/blocks/<hex(id[31])>/<hex(id)>.bin`. Every path is built
//! from a [`BlockId`] in lowercase hexadecimal, never from a string a client sent (no traversal).
//! The 256 shard directories are created by [`Store::open`], before any write; the write path never
//! creates or removes a directory (ADR 0025 rules 2 to 7).
//!
//! Write path (ADR 0013 rule 7): the bytes go to a temporary file under `<data_dir>/tmp/`, created
//! exclusively, written and `fsync`ed; the shard directory is checked to be a real directory, the
//! final name is then created exclusively with `link`, and the shard directory is `fsync`ed. `link`
//! fails if the final name exists, so a stored file is never replaced ("first write wins", spec
//! §3.4, ADR 0009) and a temporary file is never visible under a final name. The temporary name is
//! removed in every case.
//!
//! Security review L-4: `blocks/`, `tmp/`, `quarantine/` and the shard directories must be real
//! directories; a symbolic link or another kind of file there is refused, never followed.
//! Directories are created with mode `0700`, files with mode `0600`.
//!
//! Store integrity (ADR 0023): a file that fails full validation for its name ([`full_validation`])
//! is damaged. It is moved under one relay-wide lock to `<data_dir>/quarantine/` ([`Store::quarantine`]),
//! never served, and stays counted in the quota until it is purged (at most 64 files, 7 days).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, UNIX_EPOCH};

use sbtp_core::layout::MAX_BLOCK_LEN;
use sbtp_core::{BlockId, Requested, Submitted, ValidatedBlock};

use crate::index::{FileState, IndexBackend};
use crate::log::{self, Event, Value};
use crate::metrics::{self, Damage, StorageFull, StoreOp};

/// ADR 0023 rule 6: at most this many quarantined files (a constant, not a setting).
pub const QUARANTINE_MAX_FILES: usize = 64;

/// ADR 0023 rule 6: a quarantined file is deleted this long after its move (7 days).
pub const QUARANTINE_RETENTION_MS: u64 = 7 * 24 * 3_600 * 1_000;

/// File system block size used by the quota (ADR 0013 rule 18).
const QUOTA_BLOCK: u64 = 4_096;

/// ADR 0025 rule 10: the charge of one directory entry, per counted file (a constant).
pub const ENTRY_CHARGE: u64 = 128;

/// ADR 0025 rule 2: the shard directories `00` to `ff` under `blocks/`.
pub const SHARD_DIRS: u64 = 256;

/// ADR 0025 rule 9: one 4,096-byte block for each of `blocks/`, `tmp/`, `quarantine/` and the 256
/// shard directories, counted once (1,060,864 bytes).
pub const TREE_CHARGE: u64 = (SHARD_DIRS + 3) * QUOTA_BLOCK;

/// The smallest growth of the index file reserved before a write (see [`index_reserve`]).
const INDEX_GROWTH_FLOOR: u64 = 64 * 1_024;

/// The largest single growth of a redb file once it holds a full 4 GiB region: two regions.
const INDEX_GROWTH_CAP: u64 = 8 * 1_024 * 1_024 * 1_024;

/// What [`Store::write_new`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    /// The final file was created by this call (`201`, ADR 0008 rule 6).
    Created,
    /// A file with this `block_id` already existed; it is unchanged (`200`).
    AlreadyPresent,
}

/// Why a block was not stored.
#[derive(Debug)]
pub enum StoreError {
    /// The quota of ADR 0013 rule 18 would be exceeded (`507`, reason `quota`).
    Full,
    /// The operating system has no space left or a file-system quota is reached (`507`, reason
    /// `enospc` or `edquot`, see [`no_space`]). No partial file is left.
    NoSpace(StorageFull),
    /// Any other operating-system error. Nothing is left under the final name.
    Io(io::Error),
    /// The final name was created but its directory could not be `fsync`ed. ADR 0023 rule 16: the
    /// file stays under its final name (it may already be seen by another `PUT`), keeps its quota
    /// charge and is not indexed: a valid orphan, indexed by the next `PUT` of the block or the
    /// next start-up walk (ADR 0013 rule 9). `500`.
    Unsynced(io::Error),
}

/// The block store of one data directory.
#[derive(Debug)]
pub struct Store {
    blocks: PathBuf,
    /// The 256 shard directories, by trailing byte (ADR 0025 rule 2), built once.
    shards: Vec<PathBuf>,
    tmp: PathBuf,
    quarantine: PathBuf,
    index_file: PathBuf,
    max_bytes: u64,
    /// Quota bytes of the tree, the block files and the quarantined files (ADR 0023 rule 5, ADR
    /// 0025 rule 8), reservations in progress included. The index file is counted apart.
    used: AtomicU64,
    /// Directories created by [`Store::open`] at this start (ADR 0025 rule 17).
    dirs_created: u64,
    /// Distinguishes temporary files of concurrent writers.
    seq: AtomicU64,
    /// The `n` of quarantine names (ADR 0023 rule 4).
    qseq: AtomicU64,
    /// Quarantined files (the `quarantine_files` gauge).
    qfiles: AtomicU64,
    /// The quarantine lock of ADR 0023 rule 7: every move out of a final name and every purge.
    qlock: Mutex<()>,
}

/// What [`Store::quarantine`] did (ADR 0023 rule 7).
#[derive(Debug)]
pub enum Quarantine {
    /// The damaged file was moved and both directories were `fsync`ed.
    Moved,
    /// The file was moved, but a directory `fsync` failed: the move may not survive a crash (the
    /// file would then be found again under its final name and judged again).
    MovedUnsynced(io::Error),
    /// The final name no longer holds the bytes judged damaged; nothing was moved. The caller
    /// decides again from the new state, once.
    Changed,
}

/// A failed quarantine move or purge, with the `op` of `store_write_failed` (ADR 0023 rule 14).
#[derive(Debug)]
pub struct QuarantineError {
    /// [`StoreOp::Quarantine`] or [`StoreOp::Purge`].
    pub op: StoreOp,
    /// The operating-system error.
    pub error: io::Error,
}

/// Where a damaged file was found: the `cause` field of `block_quarantined` (ADR 0023 rule 14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A `GET` cache miss (rule 10).
    Get,
    /// A `PUT` of the same `block_id` (rule 8).
    Put,
    /// The start-up walk (rule 15).
    Startup,
}

impl Cause {
    /// The field value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Put => "put",
            Self::Startup => "startup",
        }
    }
}

/// ADR 0023 rule 1: full validation of a stored file for the `block_id` of its name: F1 to F9,
/// R1 against that name, C2 and C3. P1 and C1 are not re-checked (C1 is applied at difficulty 0,
/// which every `block_id` passes).
///
/// # Errors
///
/// The [`Damage`] of the first failing check.
pub fn full_validation<'a>(
    bytes: &'a [u8],
    id: &BlockId,
) -> Result<ValidatedBlock<'a, Requested>, Damage> {
    // spec §2.2 F1 to F9.
    let block = sbtp_core::parse(bytes).map_err(|_| Damage::Parse)?;
    // spec §2.2 R1 (ADR 0003 rule 11).
    let checked = block.check_requested_id(id).map_err(|_| Damage::Id)?;
    // spec §2.2 C2 and C3; C1 is not a property of the stored file (ADR 0023 rule 1).
    checked
        .check_pow(0)
        .and_then(sbtp_core::PowChecked::verify_signature)
        .map_err(|_| Damage::Signature)
}

/// Counts a file moved to quarantine and writes the throttled `block_quarantined` line (ADR 0023
/// rule 14; one throttle per `reason`). No `block` field: the quarantine name holds it.
pub fn log_quarantined(cause: Cause, d: Damage) {
    static LOGS: [log::Throttle; 3] = [const { log::Throttle::new() }; 3];
    metrics::store_quarantined(d);
    if let Some(t) = LOGS.get(d as usize) {
        log::throttled(
            t,
            Event::BlockQuarantined,
            &[
                ("cause", Value::Str(cause.name())),
                ("reason", Value::Str(d.name())),
            ],
            None,
        );
    }
}

/// A quarantine name `<64 hex>.<unix ms>.<n>` (ADR 0023 rule 4): its move time and `n`.
fn parse_quarantine_name(name: &str) -> Option<(u64, u64)> {
    let mut parts = name.split('.');
    let (hex, ms, n) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || parse_hex_id(hex).is_none() {
        return None;
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if !digits(ms) || !digits(n) {
        return None;
    }
    Some((ms.parse().ok()?, n.parse().ok()?))
}

/// A quarantined file found by a listing.
struct Quarantined {
    moved_ms: u64,
    n: u64,
    path: PathBuf,
    cost: u64,
}

/// The quota cost of a block file or a quarantined file of `len` bytes: its length rounded up to
/// 4,096 bytes, plus the entry charge (ADR 0025 rules 8, 10 and 12).
#[must_use]
pub fn cost(len: u64) -> u64 {
    len.div_ceil(QUOTA_BLOCK)
        .saturating_mul(QUOTA_BLOCK)
        .saturating_add(ENTRY_CHARGE)
}

/// The quota bytes reserved for the index file before a block is written (security review M-1):
/// the index entries of the block are written after its file, and redb grows its file by doubling
/// it (by one or two 4 GiB regions beyond the first region). The current size `index` is therefore
/// counted twice, at least `index` plus 64 KiB, and at most `index` plus 8 GiB. As long as every
/// write is admitted against this figure, block files plus index file stay within the quota.
#[must_use]
pub fn index_reserve(index: u64) -> u64 {
    index.saturating_add(index.clamp(INDEX_GROWTH_FLOOR, INDEX_GROWTH_CAP))
}

/// Whether `e` means that the file system has no room: `ENOSPC`, or `EDQUOT` (security review
/// L-1), both answered `507` (ADR 0013 rule 19).
#[must_use]
pub fn no_space(e: &io::Error) -> Option<StorageFull> {
    match e.raw_os_error() {
        Some(libc::ENOSPC) => Some(StorageFull::Enospc),
        Some(libc::EDQUOT) => Some(StorageFull::Edquot),
        _ => None,
    }
}

/// Lowercase hexadecimal of a `block_id` (ADR 0009 rule 2).
#[must_use]
pub fn hex(id: &BlockId) -> String {
    id.to_string()
}

/// Parses a `block_id` written as exactly 64 lowercase hexadecimal characters (ADR 0012 rule 4).
#[must_use]
pub fn parse_hex_id(s: &str) -> Option<BlockId> {
    decode_hex::<32>(s).map(BlockId)
}

/// Decodes exactly `2 × N` lowercase hexadecimal characters; anything else is `None`. The one
/// strict codec of the relay (`block_id` in URLs, `/query` cursors).
#[must_use]
pub fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (o, &[hi, lo]) in out.iter_mut().zip(s.as_chunks::<2>().0) {
        *o = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
}

/// Lowercase hexadecimal of `bytes`, the inverse of [`decode_hex`].
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(2 * bytes.len());
    push_hex(&mut out, bytes);
    // `push_hex` writes ASCII digits only: the conversion never fails.
    String::from_utf8(out).unwrap_or_default()
}

/// Appends `bytes` to `out` in lowercase hexadecimal: the one encoder of the relay, used by
/// [`encode_hex`] and by the `/query` page body, which writes into one buffer.
pub fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    // A nibble is below 16: the fallback is never used.
    let digit = |n: u8| DIGITS.get(usize::from(n)).copied().unwrap_or(b'0');
    for b in bytes {
        out.extend_from_slice(&[digit(b >> 4), digit(b & 0x0f)]);
    }
}

impl Store {
    /// Opens the store under `data_dir` (ADR 0025 rules 3 and 4): makes sure that `blocks/`,
    /// `tmp/`, `quarantine/` and the 256 shard directories are real directories, creating each
    /// missing one with mode `0700`, then `fsync`s `data_dir` once if one of the first three was
    /// created and `blocks/` once if a shard directory was. `index_file` counts towards the quota
    /// (ADR 0013 rule 18). The start-up walk [`reconcile`] (ADR 0023 rule 15) removes temporary
    /// files, sets the quota sum and the quarantine count; it must run before the first write.
    ///
    /// # Errors
    ///
    /// Operating-system errors; any of these names existing as anything but a real directory (a
    /// symbolic link included) is refused and stops the start-up (ADR 0025 rule 4, security
    /// review L-4).
    pub fn open(data_dir: &Path, index_file: PathBuf, max_bytes: u64) -> io::Result<Self> {
        let blocks = data_dir.join("blocks");
        let tmp = data_dir.join("tmp");
        let quarantine = data_dir.join("quarantine");
        let mut top = 0u64;
        for d in [&blocks, &tmp, &quarantine] {
            top += u64::from(ensure_dir(d)?);
        }
        if top > 0 {
            sync_dir(data_dir)?;
        }
        let shard_dirs: Vec<PathBuf> = (0..=u8::MAX)
            .map(|b| blocks.join(format!("{b:02x}")))
            .collect();
        let mut shards = 0u64;
        for d in &shard_dirs {
            shards += u64::from(ensure_dir(d)?);
        }
        if shards > 0 {
            sync_dir(&blocks)?;
        }
        let store = Self {
            blocks,
            shards: shard_dirs,
            tmp,
            quarantine,
            index_file,
            max_bytes,
            used: AtomicU64::new(TREE_CHARGE),
            dirs_created: top + shards,
            seq: AtomicU64::new(0),
            qseq: AtomicU64::new(0),
            qfiles: AtomicU64::new(0),
            qlock: Mutex::new(()),
        };
        store.publish(store.index_bytes());
        Ok(store)
    }

    /// ADR 0025 rule 1: one level, the trailing byte of the `block_id`.
    fn shard_dir(&self, id: &BlockId) -> &Path {
        let [.., last] = *id.as_bytes();
        // `shards` holds one path per byte value; the fallback is never used.
        self.shards
            .get(usize::from(last))
            .map_or(self.blocks.as_path(), PathBuf::as_path)
    }

    /// The path of a block file (ADR 0009 rule 2, amended by ADR 0025 rule 1).
    #[must_use]
    pub fn path(&self, id: &BlockId) -> PathBuf {
        self.shard_dir(id).join(format!("{}.bin", hex(id)))
    }

    /// Quota bytes of the tree, the block files and the quarantined files (ADR 0023 rule 5, ADR
    /// 0025 rule 8). The index file is not included.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    fn index_bytes(&self) -> u64 {
        fs::metadata(&self.index_file).map_or(0, |m| m.len())
    }

    /// The quota limit, `max_store_bytes`.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// The total a new block is admitted against (ADR 0013 rule 18; security review M-1): the
    /// quota bytes of the store plus the index file and the room reserved for its growth
    /// ([`index_reserve`]). The watermarks of demand eviction compare it with `max_store_bytes`
    /// (ADR 0046 rule 5), so that eviction makes room before `PUT`s get `507`.
    #[must_use]
    pub fn admission_total(&self) -> u64 {
        self.used_bytes().saturating_add(self.index_reserve_bytes())
    }

    /// The part of [`Store::admission_total`] that no block deletion reduces: the index file and
    /// its growth reserve ([`index_reserve`]; redb does not shrink its file). Security review
    /// 2026-11-21, I-2.
    #[must_use]
    pub fn index_reserve_bytes(&self) -> u64 {
        index_reserve(self.index_bytes())
    }

    fn publish(&self, index: u64) {
        metrics::set_store_bytes(self.used_bytes(), index);
    }

    /// Sets the `store_bytes` and `index_bytes` gauges from the current sizes. Called after an
    /// index insert, so that `index_bytes` includes it.
    pub fn publish_gauges(&self) {
        self.publish(self.index_bytes());
    }

    /// Reserves `cost` quota bytes, or fails with [`StoreError::Full`] (ADR 0013 rules 18, 19).
    /// `index` is the current size of the index file; room for its growth is reserved too
    /// ([`index_reserve`], security review M-1).
    fn reserve(&self, cost: u64, index: u64) -> Result<(), StoreError> {
        let index = index_reserve(index);
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let total = used.checked_add(cost).and_then(|u| u.checked_add(index));
            if total.is_none_or(|t| t > self.max_bytes) {
                return Err(StoreError::Full);
            }
            match self.used.compare_exchange_weak(
                used,
                used + cost,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(now) => used = now,
            }
        }
    }

    /// Returns quota bytes reserved by [`Store::reserve`], or the cost of a purged file. Saturates
    /// at zero: a file changed behind the relay's back cannot make the sum wrap.
    /// The sum never falls below the tree charge, which is always counted (ADR 0025 rule 9).
    fn release(&self, cost: u64) {
        let mut used = self.used.load(Ordering::Relaxed);
        while let Err(now) = self.used.compare_exchange_weak(
            used,
            used.saturating_sub(cost).max(TREE_CHARGE),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            used = now;
        }
    }

    /// Quarantined files.
    #[must_use]
    pub fn quarantine_files(&self) -> u64 {
        self.qfiles.load(Ordering::Relaxed)
    }

    fn set_quarantine_files(&self, n: u64) {
        self.qfiles.store(n, Ordering::Relaxed);
        metrics::set_quarantine_files(n);
    }

    /// ADR 0023 rule 7: moves the file of `id` to quarantine if it still holds `damaged`, the bytes
    /// the caller judged damaged. Under the quarantine lock: the final name is read again, the
    /// bound of rule 6 is applied (the oldest files are deleted first), then the file is moved
    /// (exclusive `link` to `quarantine/<hex>.<ms>.<n>`, then `unlink` of the final name, rule 4)
    /// and the quarantine and shard directories are `fsync`ed (rule 8.5). The quota sum does not
    /// change (rule 5). Counting and logging the move are the caller's ([`log_quarantined`]).
    ///
    /// # Errors
    ///
    /// [`QuarantineError`]: the read, the link or the unlink failed (nothing was moved), or the
    /// bound could not be applied (`op` [`StoreOp::Purge`], nothing was moved).
    pub fn quarantine(&self, id: &BlockId, damaged: &[u8]) -> Result<Quarantine, QuarantineError> {
        let q = |error| QuarantineError {
            op: StoreOp::Quarantine,
            error,
        };
        let _lock = self.qlock.lock().unwrap_or_else(PoisonError::into_inner);
        match self.read(id).map_err(q)? {
            Some(now) if now == damaged => {}
            _ => return Ok(Quarantine::Changed),
        }
        self.purge_locked(None, QUARANTINE_MAX_FILES.saturating_sub(1))?;
        let n = self.qseq.fetch_add(1, Ordering::Relaxed);
        let target = self
            .quarantine
            .join(format!("{}.{}.{n}", hex(id), log::unix_ms()));
        let path = self.path(id);
        // `link` never replaces an existing name (rule 4).
        fs::hard_link(&path, &target).map_err(q)?;
        if let Err(e) = fs::remove_file(&path) {
            let _ = fs::remove_file(&target);
            return Err(q(e));
        }
        self.set_quarantine_files(self.quarantine_files().saturating_add(1));
        match sync_dir(&self.quarantine).and_then(|()| sync_dir(self.shard_dir(id))) {
            Ok(()) => Ok(Quarantine::Moved),
            Err(e) => Ok(Quarantine::MovedUnsynced(e)),
        }
    }

    /// ADR 0023 rule 6, for the sweeper: deletes the quarantined files moved at least 7 days
    /// before `now_ms`, and the oldest files beyond 64. Returns the number deleted; each releases
    /// its quota cost (rule 5). Called by the sweeper at every run, even when `block_ttl_ms = 0`
    /// (rule 6).
    ///
    /// # Errors
    ///
    /// [`QuarantineError`] with `op` [`StoreOp::Purge`].
    pub fn purge_quarantine(&self, now_ms: u64) -> Result<u64, QuarantineError> {
        let _lock = self.qlock.lock().unwrap_or_else(PoisonError::into_inner);
        self.purge_locked(Some(now_ms), QUARANTINE_MAX_FILES)
    }

    /// Lists the quarantine; deletes the files expired at `now_ms` (if given), then the oldest
    /// until at most `keep` remain; sets the count. Entries that are not regular files with a
    /// quarantine name are skipped, never followed (rule 6). Called under the quarantine lock.
    fn purge_locked(&self, now_ms: Option<u64>, keep: usize) -> Result<u64, QuarantineError> {
        let p = |error| QuarantineError {
            op: StoreOp::Purge,
            error,
        };
        let mut files = self.list_quarantine().map_err(p)?;
        // Oldest first.
        files.sort_unstable_by_key(|f| (f.moved_ms, f.n));
        let expired = now_ms.map_or(0, |now| {
            files
                .iter()
                .take_while(|f| now.saturating_sub(f.moved_ms) >= QUARANTINE_RETENTION_MS)
                .count()
        });
        let excess = files.len().saturating_sub(keep);
        let doomed = expired.max(excess);
        let mut purged = 0u64;
        let mut failed = None;
        for f in files.iter().take(doomed) {
            match fs::remove_file(&f.path) {
                Ok(()) => {
                    self.release(f.cost);
                    purged += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => purged += 1,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        let left = u64::try_from(files.len())
            .unwrap_or(u64::MAX)
            .saturating_sub(purged);
        self.set_quarantine_files(left);
        if purged > 0 {
            self.publish(self.index_bytes());
        }
        match failed {
            Some(e) => Err(p(e)),
            None => Ok(purged),
        }
    }

    /// The regular files of `quarantine/` whose name is a quarantine name (rule 4).
    fn list_quarantine(&self) -> io::Result<Vec<Quarantined>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.quarantine)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some((moved_ms, n)) = name.to_str().and_then(parse_quarantine_name) else {
                continue;
            };
            // `DirEntry::metadata` does not follow a symbolic link.
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            out.push(Quarantined {
                moved_ms,
                n,
                path: entry.path(),
                cost: cost(meta.len()),
            });
        }
        Ok(out)
    }

    /// Stores a fully validated block (spec §3.4: the rule applies only to validated bytes), within
    /// the quota, without replacing an existing file. A block whose file is already held gets
    /// [`Stored::AlreadyPresent`] even when the quota is reached (ADR 0013 rule 20), but only if the
    /// final name is a regular file holding exactly these bytes; anything else there is
    /// [`StoreError::Full`]. The gauges are left to the caller on [`Stored::Created`]: it refreshes
    /// them after the index insert ([`Store::publish_gauges`]).
    ///
    /// # Errors
    ///
    /// [`StoreError`]. On [`StoreError::Unsynced`] the file is under its final name; on every
    /// other error nothing is left under the final name.
    pub fn write_new(&self, block: &ValidatedBlock<'_, Submitted>) -> Result<Stored, StoreError> {
        let bytes = block.block().as_bytes();
        let cost = cost(bytes.len() as u64);
        // Read once per write (security review L-3), for the reservation and for the gauge.
        let index = self.index_bytes();
        if let Err(e) = self.reserve(cost, index) {
            // A losing duplicate near the quota is still a known block (rule 20). `read` refuses
            // a symbolic link or a non-regular file.
            return match self.read(block.block_id()) {
                Ok(Some(held)) if held == bytes => Ok(Stored::AlreadyPresent),
                // ADR 0025 rule 6: a missing shard is an I/O error (`500`, `op=write`), whatever
                // the quota.
                Err(e) if is_shard_error(&e) => Err(StoreError::Io(e)),
                _ => Err(e),
            };
        }
        let result = self.write_inner(block.block_id(), bytes);
        match &result {
            Ok(Stored::Created) | Err(Linked(_)) => {}
            Ok(Stored::AlreadyPresent) | Err(NotLinked(_)) => self.release(cost),
        }
        if !matches!(result, Ok(Stored::Created)) {
            self.publish(index);
        }
        match result {
            Ok(s) => Ok(s),
            Err(Linked(e)) => Err(StoreError::Unsynced(e)),
            Err(NotLinked(e)) => Err(no_space(&e).map_or(StoreError::Io(e), StoreError::NoSpace)),
        }
    }

    fn write_inner(&self, id: &BlockId, bytes: &[u8]) -> Result<Stored, WriteError> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self.tmp.join(format!("{}.{n}.tmp", hex(id)));
        let written = new_file_options().open(&tmp).and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        });
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(NotLinked(e));
        }
        let dir = self.shard_dir(id);
        // ADR 0025 rules 5 and 6: never created here; missing or not a real directory is an I/O
        // error (`500`, `op=write`), the reservation is released by the caller.
        let linked = check_shard(dir).and_then(|()| fs::hard_link(&tmp, self.path(id)));
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => sync_dir(dir).map(|()| Stored::Created).map_err(Linked),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Stored::AlreadyPresent),
            Err(e) => Err(NotLinked(e)),
        }
    }

    /// The sweeper's deletion of the file of `id` (ADR 0013 rule 15): `unlink` of the final name,
    /// then its quota cost is released. Returns the quota bytes released, or `None` when no file
    /// was there; a missing file is not an error (the step is idempotent). A symbolic link or another non-regular entry under the
    /// final name is unlinked without being followed and releases nothing: only regular files are
    /// counted (`reconcile`). The shard directory is not `fsync`ed: a deletion lost in a crash
    /// leaves the file, which the start-up walk re-indexes from its modification time and the next
    /// sweep deletes again. The gauges are left to the caller ([`Store::publish_gauges`]).
    ///
    /// # Errors
    ///
    /// Operating-system errors; a shard directory that is missing or not a real directory (ADR
    /// 0025 rule 6, [`is_shard_error`]).
    pub fn evict(&self, id: &BlockId) -> io::Result<Option<u64>> {
        check_shard(self.shard_dir(id))?;
        let path = self.path(id);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
        let freed = if meta.is_file() { cost(meta.len()) } else { 0 };
        self.release(freed);
        Ok(Some(freed))
    }

    /// The stored bytes of `id`, or `None` if no file is held. At most `MAX_BLOCK_LEN + 1` bytes
    /// are read, so that an oversized file costs no more than a block. The buffer's capacity is
    /// its length (security review L-2), which the block cache relies on.
    ///
    /// # Errors
    ///
    /// Operating-system errors other than "not found" on the final name; a final name that is not
    /// a regular file (a symbolic link included) is an error, never followed (security review
    /// L-4). A shard directory that is missing or not a real directory is an error too (ADR 0025
    /// rule 6: the relay cannot tell whether it holds the block), see [`is_shard_error`].
    pub fn read(&self, id: &BlockId) -> io::Result<Option<Vec<u8>>> {
        check_shard(self.shard_dir(id))?;
        let file = match open_regular(&self.path(id)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let limit = MAX_BLOCK_LEN as u64 + 1;
        let len = file.metadata()?.len().min(limit);
        let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(MAX_BLOCK_LEN + 1));
        file.take(limit).read_to_end(&mut buf)?;
        // Only if the file changed length while it was read.
        buf.shrink_to_fit();
        Ok(Some(buf))
    }

    /// Calls `f(id, len, mtime_ms)` for every block file: one `read_dir` level under each shard
    /// directory (ADR 0025 rule 13). Names that are not a block file at its own shard, entries
    /// that are not regular files and subdirectories of a shard are skipped, never followed;
    /// nothing is collected in memory.
    ///
    /// # Errors
    ///
    /// Operating-system errors while listing.
    pub fn scan(&self, mut f: impl FnMut(BlockId, u64, u64)) -> io::Result<()> {
        for shard in fs::read_dir(&self.blocks)? {
            let shard = shard?;
            // `DirEntry::file_type` does not follow a symbolic link.
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for file in fs::read_dir(shard.path())? {
                let file = file?;
                let name = file.file_name();
                let Some(id) = name
                    .to_str()
                    .and_then(|n| n.strip_suffix(".bin"))
                    .and_then(parse_hex_id)
                else {
                    continue;
                };
                if self.path(&id) != file.path() {
                    continue;
                }
                // `DirEntry::metadata` does not follow a symbolic link.
                let meta = file.metadata()?;
                if !meta.is_file() {
                    continue;
                }
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                f(id, meta.len(), mtime);
            }
        }
        Ok(())
    }
}

fn not_a_dir() -> io::Error {
    io::Error::other("not a real directory (symbolic links are refused)")
}

/// The payload of the error of a shard directory that is missing or not a real directory: a type
/// of its own, so that no operating-system error (an `ENOTDIR` included) is taken for it.
#[derive(Debug)]
struct ShardMissing;

impl std::fmt::Display for ShardMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("shard directory missing or not a real directory")
    }
}

impl std::error::Error for ShardMissing {}

/// ADR 0025 rules 5 and 6: `dir`, a shard directory, is a real directory. Checked without
/// following a symbolic link and never created. Missing or of another kind is a
/// [`ShardMissing`] error ([`is_shard_error`]).
fn check_shard(dir: &Path) -> io::Result<()> {
    let bad = || io::Error::other(ShardMissing);
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(bad()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(bad()),
        Err(e) => Err(e),
    }
}

/// Whether `e`, from [`Store::read`], says that the shard directory of the block is missing or
/// not a real directory (ADR 0025 rule 6).
#[must_use]
pub fn is_shard_error(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<ShardMissing>().is_some())
}

/// Makes sure `path` is a real directory, creating it with mode `0700` if it does not exist;
/// returns whether this call created it. Anything else under that name, a symbolic link
/// included, is an error: it is never followed (security review L-4).
fn ensure_dir(path: &Path) -> io::Result<bool> {
    let check = |m: fs::Metadata| {
        if m.file_type().is_dir() {
            Ok(false)
        } else {
            Err(not_a_dir())
        }
    };
    match fs::symlink_metadata(path) {
        Ok(m) => check(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match dir_builder().create(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                check(fs::symlink_metadata(path)?)
            }
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// A directory builder with mode `0700` (security review L-4).
#[must_use]
pub fn dir_builder() -> fs::DirBuilder {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b
}

/// Exclusive creation of a new file with mode `0600`.
fn new_file_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

/// Opens `path` for reading without following a symbolic link at its last component and without
/// blocking on a FIFO; anything but a regular file is an error.
fn open_regular(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let f = o.open(path)?;
    if f.metadata()?.is_file() {
        Ok(f)
    } else {
        Err(io::Error::other("not a regular file"))
    }
}

/// Whether a failed write left a file under the final name (its quota bytes stay counted).
enum WriteError {
    Linked(io::Error),
    NotLinked(io::Error),
}
use WriteError::{Linked, NotLinked};

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

/// What [`reconcile`] found: the fields of `store_reconciled` (ADR 0023 rule 14).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Block files scanned.
    pub files: u64,
    /// Held blocks that had no index entry, passed full validation and were indexed.
    pub orphans: u64,
    /// Orphans that failed full validation and were moved to quarantine.
    pub quarantined: u64,
    /// Quarantined files deleted (retention and bound, ADR 0023 rule 6).
    pub purged: u64,
    /// Directories created by [`Store::open`] at this start (ADR 0025 rule 17).
    pub dirs_created: u64,
    /// The index got a new epoch before the first orphan was indexed (ADR 0024 rules 1 to 4, 11).
    pub epoch_renewed: bool,
    /// Duration of the walk.
    pub duration_ms: u64,
}

/// The start-up walk of ADR 0023 rule 15 (amending ADR 0013 rules 9 and 18), done once at every
/// start, before listening and before the first write:
///
/// 1. `tmp/`: temporary files left by a crash are deleted (rule 9).
/// 2. `quarantine/`: the quota sum starts at the tree charge (ADR 0025 rule 13) plus the
///    quarantined files; files older than 7 days and the oldest beyond 64 are deleted (rule 6).
/// 3. `blocks/`: the quota sum of the block files; every file without an index entry gets full
///    validation (rule 1), then is indexed with its modification time as `received_at` (ADR 0013
///    rule 9), capped at the current time (security review I-4), or moved to quarantine. Indexed
///    files are not read. Before the first orphan is indexed, the index gets a new epoch, durably
///    (ADR 0024 rules 1 to 4), so that cursors issued before an unclean shutdown are refused.
///
/// Ends with the `store_reconciled` line. The walk visits each file once; the number of files is
/// bounded by the quota, `max_store_bytes / 4,096` (rule 15).
///
/// # Errors
///
/// Listing or index errors stop the start-up. A file that cannot be read does not (security review
/// L-2): it is logged (`store_write_failed`, `op=read`), left unindexed in place and still counted
/// in the quota. Nor does a failed quarantine move: it is logged (`store_write_failed`,
/// `op=quarantine`) and the file is left unindexed in place.
pub fn reconcile<I: IndexBackend>(
    store: &Store,
    index: &I,
) -> Result<Reconciled, ReconcileError<I>> {
    let start = Instant::now();
    let mut out = Reconciled {
        dirs_created: store.dirs_created,
        ..Reconciled::default()
    };
    for entry in fs::read_dir(&store.tmp).map_err(ReconcileError::Io)? {
        let entry = entry.map_err(ReconcileError::Io)?;
        if entry.file_type().map_err(ReconcileError::Io)?.is_file() {
            fs::remove_file(entry.path()).map_err(ReconcileError::Io)?;
        }
    }
    // The running sum starts with the tree charge (ADR 0025 rule 13) and the quarantined files, so
    // that a purge during the walk releases a cost already counted.
    let quarantined = store.list_quarantine().map_err(ReconcileError::Io)?;
    let qbytes = quarantined
        .iter()
        .fold(TREE_CHARGE, |s, f| s.saturating_add(f.cost));
    store.used.store(qbytes, Ordering::Relaxed);
    out.purged = store
        .purge_quarantine(log::unix_ms())
        .map_err(|e| ReconcileError::Io(e.error))?;
    let mut failed: Option<ReconcileError<I>> = None;
    let now = log::unix_ms();
    store
        .scan(|id, len, mtime| {
            // Every file under a final name takes space, a damaged one included.
            store.used.fetch_add(cost(len), Ordering::Relaxed);
            if failed.is_some() {
                return;
            }
            out.files += 1;
            match index.contains(&id) {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(e) => {
                    failed = Some(ReconcileError::Index(e));
                    return;
                }
            }
            let bytes = match store.read(&id) {
                Ok(Some(b)) => b,
                Ok(None) => return,
                Err(e) => {
                    // Security review L-2: one unreadable file does not stop the start-up; a
                    // `GET` of it answers `500` (ADR 0023 rule 2).
                    log_store_failed(StoreOp::Read, &e);
                    return;
                }
            };
            // ADR 0023 rule 15: an orphan is indexed only after full validation.
            let damage = match full_validation(&bytes, &id) {
                Ok(valid) => {
                    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                    let parents = valid.block().parents();
                    // Security review I-4: a file time in the future would hold back every later
                    // position (ADR 0013 rule 3).
                    let at = mtime.min(now);
                    // ADR 0024 rules 1, 3 and 4: once per start, durable before the first orphan
                    // entry is written.
                    if !out.epoch_renewed {
                        if let Err(e) = index.renew_epoch() {
                            failed = Some(ReconcileError::Index(e));
                            return;
                        }
                        out.epoch_renewed = true;
                    }
                    match index.insert(&id, len, parents, at, FileState::AlreadyHeld) {
                        Ok(_) => out.orphans += 1,
                        Err(e) => failed = Some(ReconcileError::Index(e)),
                    }
                    return;
                }
                Err(d) => d,
            };
            match store.quarantine(&id, &bytes) {
                Ok(Quarantine::Moved) => {
                    out.quarantined += 1;
                    log_quarantined(Cause::Startup, damage);
                }
                Ok(Quarantine::MovedUnsynced(e)) => {
                    out.quarantined += 1;
                    log_quarantined(Cause::Startup, damage);
                    log_store_failed(StoreOp::Quarantine, &e);
                }
                // Nothing else writes during the walk; a local writer changed the file. It stays
                // unindexed; a `GET` judges it again.
                Ok(Quarantine::Changed) => {}
                Err(e) => log_store_failed(e.op, &e.error),
            }
        })
        .map_err(ReconcileError::Io)?;
    if let Some(e) = failed {
        return Err(e);
    }
    if out.orphans > 0 {
        // Durable before the relay listens.
        index.flush().map_err(ReconcileError::Index)?;
    }
    store.publish(store.index_bytes());
    out.duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    log::emit(
        Event::StoreReconciled,
        &[
            ("files", Value::Int(out.files)),
            ("orphans", Value::Int(out.orphans)),
            ("quarantined", Value::Int(out.quarantined)),
            ("purged", Value::Int(out.purged)),
            ("dirs_created", Value::Int(out.dirs_created)),
            ("epoch_renewed", Value::Bool(out.epoch_renewed)),
            ("duration_ms", Value::Int(out.duration_ms)),
        ],
    );
    Ok(out)
}

/// Why [`reconcile`] failed.
pub enum ReconcileError<I: IndexBackend> {
    /// Listing the store, or removing a temporary file.
    Io(io::Error),
    /// The index.
    Index(I::Error),
}

impl<I: IndexBackend> std::fmt::Debug for ReconcileError<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Io({e:?})"),
            Self::Index(e) => write!(f, "Index({e:?})"),
        }
    }
}

/// Logs and counts a store failure that is not a lack of space (ADR 0021 rule 7, throttled; one
/// throttle per operation, so that one cause cannot hide another). The event is
/// `store_write_failed`. The `op` field says which step failed: `write` (temporary file, shard,
/// link), `sync` (the shard directory after the link: the file is left as an orphan for the
/// start-up walk, ADR 0023 rule 16), `read` (the stored file of the block), `quarantine` (a move
/// to quarantine, or the `fsync` after it) and `purge` (deleting a quarantined file), ADR 0023
/// rule 14. The fields are those of ADR 0021 rule 7, in its order: `op`, `orphan`, `errno`,
/// `suppressed`.
pub fn log_store_failed(op: StoreOp, e: &io::Error) {
    static LOGS: [log::Throttle; StoreOp::COUNT] = [const { log::Throttle::new() }; StoreOp::COUNT];
    metrics::store_error(op);
    let mut fields = vec![("op", Value::Str(op.name()))];
    if op == StoreOp::Sync {
        fields.push(("orphan", Value::Bool(true)));
    }
    if let Some(n) = log::errno(e) {
        fields.push(("errno", Value::Int(n)));
    }
    if let Some(t) = LOGS.get(op as usize) {
        log::throttled(t, Event::StoreWriteFailed, &fields, None);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    /// Code review: only the relay's own shard error is a shard error, never an OS `ENOTDIR`.
    #[test]
    fn shard_errors_are_typed() {
        let dir = std::env::temp_dir().join(format!("sbtp-shard-typed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let e = check_shard(&dir).unwrap_err();
        assert!(is_shard_error(&e));
        for other in [
            io::Error::from_raw_os_error(libc::ENOTDIR),
            io::Error::new(io::ErrorKind::NotADirectory, "x"),
            io::Error::other("x"),
        ] {
            assert!(!is_shard_error(&other), "{other}");
        }
    }

    #[test]
    fn hex_codec_round_trips() {
        let raw = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode_hex(&raw), "000fa5ff");
        assert_eq!(decode_hex::<4>("000fa5ff"), Some(raw));
        assert_eq!(decode_hex::<4>("000FA5FF"), None);
        assert_eq!(decode_hex::<4>("000fa5f"), None);
    }

    #[test]
    fn hex_ids_are_strict() {
        let id = BlockId([0xab; 32]);
        assert_eq!(parse_hex_id(&hex(&id)), Some(id));
        assert_eq!(parse_hex_id(&"AB".repeat(32)), None, "uppercase");
        assert_eq!(parse_hex_id(&"ab".repeat(31)), None, "short");
        assert_eq!(parse_hex_id(&format!("{}0", "ab".repeat(32))), None, "long");
        assert_eq!(parse_hex_id(&format!("..{}", "ab".repeat(31))), None);
        assert_eq!(parse_hex_id(&format!("{}+0", "ab".repeat(31))), None);
        assert_eq!(
            parse_hex_id(&"é".repeat(32)),
            None,
            "non-ASCII of the same length"
        );
    }

    /// Security review L-1: `EDQUOT` is a full store, like `ENOSPC`.
    #[test]
    fn quota_errors_are_no_space() {
        let e = io::Error::from_raw_os_error;
        assert_eq!(no_space(&e(libc::ENOSPC)), Some(StorageFull::Enospc));
        assert_eq!(no_space(&e(libc::EDQUOT)), Some(StorageFull::Edquot));
        assert_eq!(no_space(&e(libc::EIO)), None);
        assert_eq!(no_space(&io::Error::other("x")), None);
    }

    /// ADR 0023 rule 4: only `<64 hex>.<ms>.<n>` is a quarantine name.
    #[test]
    fn quarantine_names_are_strict() {
        let h = "ab".repeat(32);
        assert_eq!(parse_quarantine_name(&format!("{h}.17.3")), Some((17, 3)));
        for bad in [
            format!("{h}.17"),
            format!("{h}.17.3.4"),
            format!("{h}.+17.3"),
            format!("{h}..3"),
            format!("{h}.17.x"),
            format!("{}.17.3", "AB".repeat(32)),
            format!("{h}.99999999999999999999.3"),
            "keep.txt".to_owned(),
        ] {
            assert_eq!(parse_quarantine_name(&bad), None, "{bad}");
        }
    }

    #[test]
    fn layout_uses_the_trailing_bytes() {
        let mut raw = [0u8; 32];
        raw[30] = 0xcd;
        raw[31] = 0xef;
        // ADR 0025 rule 9: 259 directories of 4,096 bytes.
        assert_eq!(TREE_CHARGE, 1_060_864);
        let store = Store {
            blocks: PathBuf::from("/d/blocks"),
            shards: (0..=u8::MAX)
                .map(|b| PathBuf::from(format!("/d/blocks/{b:02x}")))
                .collect(),
            tmp: PathBuf::from("/d/tmp"),
            quarantine: PathBuf::from("/d/quarantine"),
            index_file: PathBuf::from("/d/index.redb"),
            max_bytes: 0,
            used: AtomicU64::new(0),
            dirs_created: 0,
            seq: AtomicU64::new(0),
            qseq: AtomicU64::new(0),
            qfiles: AtomicU64::new(0),
            qlock: Mutex::new(()),
        };
        let id = BlockId(raw);
        assert_eq!(
            store.path(&id),
            PathBuf::from(format!("/d/blocks/ef/{}.bin", hex(&id)))
        );
        assert_eq!(
            (cost(0), cost(1), cost(4_096), cost(4_097)),
            (128, 4_224, 4_224, 8_320)
        );
    }
}
