//! The block store: one redb file. Every write is one fsynced transaction, so a block and its
//! position appear together or not at all (SPEC §5 `PUT`: stored atomically).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use redb::{Database, Error, ReadableDatabase, ReadableTable, TableDefinition};
use sbtp_core::{BlockId, ValidatedBlock};

use crate::limits::DenyList;

/// `block_id` → position.
const IDS: TableDefinition<[u8; 32], u64> = TableDefinition::new("ids");
/// position → (`block_id`, public key), in receipt order: listing and deny checks never read
/// block bytes (a 64-byte entry instead of up to 66 KB).
const LOG: TableDefinition<u64, ([u8; 32], [u8; 32])> = TableDefinition::new("log");
/// position → block bytes.
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
/// (parent, position) → (): the children of a parent, in position order.
const CHILDREN: TableDefinition<([u8; 32], u64), ()> = TableDefinition::new("children");
/// `relay_id` and the inode of the file it was drawn for.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Page cache of redb; its default (1 GiB) is far above what a lean relay should hold.
const CACHE_BYTES: usize = 32 << 20;
/// A page examines at most this many entries per block it may list, denied ones included: a
/// long denied run (the state after an abuse wave) otherwise made every request scan all of it.
const EXAMINED_PER_LISTED: usize = 4;

/// Result of [`Store::put`].
pub enum Put {
    /// Stored at this new position.
    Stored(u64),
    /// Already stored; nothing changed.
    Existing,
    /// New, but the store is over its quota.
    Full,
    /// The deny list names this block or its key (the spec §5 error name).
    Denied(&'static str),
}

/// One listed block of a [`Page`].
pub struct Item {
    pub position: u64,
    pub id: [u8; 32],
    /// `position ‖ block` (spec §6), when the page was read for `/subscribe`.
    pub frame: Option<Vec<u8>>,
}

/// A page of blocks in position order (SPEC §5 `/query`).
pub struct Page {
    pub items: Vec<Item>,
    /// The greatest position examined, listed or not, or the requested one.
    pub since: u64,
    /// Entries remain after the page.
    pub more: bool,
}

/// The store.
pub struct Store {
    db: Database,
    path: PathBuf,
    /// Serialises writes, deny-list swaps and the live broadcast that follows each write, so
    /// that live frames leave in position order and `served` never goes stale.
    write: Mutex<()>,
    deny: RwLock<Arc<DenyList>>,
    /// The greatest position ever given, denied blocks included.
    max: AtomicU64,
    /// spec §5 `/info` `last_position`, kept up to date instead of scanned per request.
    served: AtomicU64,
    /// spec §5 `/info`.
    pub relay_id: String,
}

fn corrupt() -> Error {
    Error::Corrupted("log entry without its block".into())
}

impl Store {
    /// Opens or creates `dir/relay.redb`, with the deny list in force.
    pub fn open(dir: &Path, deny: DenyList) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("relay.redb");
        let db = Database::builder()
            .set_cache_size(CACHE_BYTES)
            .create(&path)?;
        // spec §5 `/info`: a store restored from a backup or a copy draws a new `relay_id`.
        // A store cannot see its own rollback from inside its file, so three signals: a copy is
        // a new file (new inode); the sidecar, outside the database file, saw a greater position
        // (file restored in place); and the operator's `restored` marker, mandatory after a
        // volume or snapshot restore, which rolls the sidecar back too (deploy/README.md).
        let inode = std::fs::metadata(&path)?.ino().to_be_bytes();
        let (sidecar, marker) = (path.with_extension("position"), dir.join("restored"));
        let seen = std::fs::read_to_string(&sidecar).unwrap_or_default();
        let txn = db.begin_write()?;
        let (relay_id, max) = {
            txn.open_table(IDS)?;
            txn.open_table(BLOCKS)?;
            txn.open_table(CHILDREN)?;
            let max = txn.open_table(LOG)?.last()?.map_or(0, |(k, _)| k.value());
            let mut meta = txn.open_table(META)?;
            let same_file = meta.get("inode")?.is_some_and(|v| v.value() == inode);
            let kept = meta.get("relay_id")?.map(|v| v.value().to_vec());
            let kept = kept.and_then(|id| String::from_utf8(id).ok());
            let rolled_back = seen.split_once(' ').is_some_and(|(id, s)| {
                Some(id) == kept.as_deref() && s.parse().is_ok_and(|s: u64| s > max)
            });
            if let (Some(id), true, false) = (kept, same_file, rolled_back || marker.exists()) {
                (id, max)
            } else {
                let mut id = [0u8; 16];
                getrandom::fill(&mut id).map_err(|e| Error::Io(std::io::Error::other(e)))?;
                let id = format!("{:032x}", u128::from_be_bytes(id));
                meta.insert("relay_id", id.as_bytes())?;
                meta.insert("inode", inode.as_slice())?;
                (id, max)
            }
        };
        txn.commit()?;
        std::fs::write(&sidecar, format!("{relay_id} {max}"))?;
        // Absent in the usual case; a marker that cannot be removed only redraws again.
        let _ = std::fs::remove_file(&marker);
        let store = Self {
            db,
            path,
            write: Mutex::new(()),
            deny: RwLock::default(),
            max: AtomicU64::new(max),
            served: AtomicU64::new(0),
            relay_id,
        };
        store.set_deny(deny)?;
        Ok(store)
    }

    pub fn deny(&self) -> Arc<DenyList> {
        Arc::clone(&self.deny.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Puts `list` in force and recomputes `last_position` (once per reload, not per request).
    pub fn set_deny(&self, list: DenyList) -> Result<(), Error> {
        let _order = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        *self.deny.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(list);
        let deny = self.deny();
        let txn = self.db.begin_read()?;
        let mut served = 0;
        for entry in txn.open_table(LOG)?.range::<u64>(..)?.rev() {
            let (k, v) = entry?;
            let (id, key) = v.value();
            if deny.check(&id, &key).is_none() {
                served = k.value();
                break;
            }
        }
        self.served.store(served, SeqCst);
        Ok(())
    }

    /// The greatest position ever given, denied blocks included; `0` for an empty store.
    pub fn max_position(&self) -> u64 {
        self.max.load(SeqCst)
    }

    /// spec §5 `/info` `last_position`: the greatest position of a block still served.
    pub fn last_served(&self) -> u64 {
        self.served.load(SeqCst)
    }

    /// Stores a validated block unless it is denied, already there, or the file is over
    /// `quota` bytes. `then` runs after the commit, still under the write lock.
    pub fn put(
        &self,
        block: &ValidatedBlock<'_>,
        quota: u64,
        then: impl FnOnce(u64),
    ) -> Result<Put, Error> {
        let _order = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let (id, key) = (block.block_id().0, *block.block().pubkey());
        // spec §5 `PUT`: the deny list, then storage; under the lock, so that a reload cannot
        // fall between the check and `served`.
        if let Some(name) = self.deny().check(&id, &key) {
            return Ok(Put::Denied(name));
        }
        let txn = self.db.begin_write()?;
        let position = {
            let mut ids = txn.open_table(IDS)?;
            // spec §2: identity is the block_id alone; the bytes stored first are kept.
            if ids.get(id)?.is_some() {
                return Ok(Put::Existing);
            }
            // spec §7: the quota refuses new blocks only, after the duplicate check.
            if std::fs::metadata(&self.path)?.len() >= quota {
                return Ok(Put::Full);
            }
            // spec §5: from 1, above every position given before. A failed commit gives nothing.
            let position = self.max_position().checked_add(1).ok_or_else(corrupt)?;
            txn.open_table(LOG)?.insert(position, (id, key))?;
            txn.open_table(BLOCKS)?
                .insert(position, block.block().as_bytes())?;
            ids.insert(id, position)?;
            let mut children = txn.open_table(CHILDREN)?;
            for parent in block.block().parents() {
                children.insert((parent.0, position), ())?;
            }
            position
        };
        txn.commit()?;
        self.max.store(position, SeqCst);
        self.served.store(position, SeqCst);
        // The sidecar of `open`. Not fsynced: a lost write only weakens the rollback check, it
        // never draws a false one (the database is always at least as far as the sidecar).
        let sidecar = self.path.with_extension("position");
        let _ = std::fs::write(sidecar, format!("{} {position}", self.relay_id));
        then(position);
        Ok(Put::Stored(position))
    }

    /// The stored bytes of `id`, or the name of its denial.
    pub fn get(&self, id: &BlockId) -> Result<Option<Result<Vec<u8>, &'static str>>, Error> {
        let txn = self.db.begin_read()?;
        let Some(position) = txn.open_table(IDS)?.get(id.0)?.map(|v| v.value()) else {
            return Ok(None);
        };
        let (_, key) = txn
            .open_table(LOG)?
            .get(position)?
            .ok_or_else(corrupt)?
            .value();
        if let Some(name) = self.deny().check(&id.0, &key) {
            return Ok(Some(Err(name)));
        }
        let block = txn.open_table(BLOCKS)?.get(position)?.ok_or_else(corrupt)?;
        Ok(Some(Ok(block.value().to_vec())))
    }

    /// Blocks after `since`, children of `parent` if given, in position order, denied ones
    /// skipped: at most `limit` of them. With `frames`, frames are read too, and no more once
    /// that many bytes are read.
    pub fn page(
        &self,
        parent: Option<BlockId>,
        since: u64,
        limit: usize,
        frames: Option<usize>,
    ) -> Result<Page, Error> {
        let deny = self.deny();
        let txn = self.db.begin_read()?;
        let (log, blocks) = (txn.open_table(LOG)?, txn.open_table(BLOCKS)?);
        let children = txn.open_table(CHILDREN)?;
        let start = since.saturating_add(1);
        let entries: Box<dyn Iterator<Item = Result<_, Error>>> = match parent {
            None => Box::new(log.range(start..)?.map(|e| {
                let (k, v) = e?;
                Ok((k.value(), v.value()))
            })),
            Some(p) => Box::new(children.range((p.0, start)..=(p.0, u64::MAX))?.map(|e| {
                let position = e?.0.value().1;
                Ok((position, log.get(position)?.ok_or_else(corrupt)?.value()))
            })),
        };
        let mut page = Page {
            items: Vec::new(),
            since,
            more: false,
        };
        let (mut bytes, max_bytes) = (0usize, frames.unwrap_or(usize::MAX));
        let bound = limit.saturating_mul(EXAMINED_PER_LISTED);
        for (n, entry) in entries.enumerate() {
            let (position, (id, key)) = entry?;
            let denied = deny.check(&id, &key).is_some();
            // spec §5: `since` then names the last entry examined, so the client progresses.
            if n >= bound || (!denied && (page.items.len() >= limit || bytes >= max_bytes)) {
                page.more = true;
                break;
            }
            if !denied {
                let mut frame = None;
                if frames.is_some() {
                    let block = blocks.get(position)?.ok_or_else(corrupt)?;
                    bytes = bytes.saturating_add(block.value().len());
                    frame = Some([&position.to_be_bytes()[..], block.value()].concat());
                }
                page.items.push(Item {
                    position,
                    id,
                    frame,
                });
            }
            page.since = position;
        }
        Ok(page)
    }
}
