//! The block store: one redb file. Every write is one fsynced transaction, so a block and its
//! position appear together or not at all (SPEC §5 `PUT`: stored atomically).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use redb::{Database, Error, ReadableDatabase, ReadableTable, TableDefinition};
use sbtp_core::BlockId;

use crate::limits::DenyList;

/// `block_id` → position.
const IDS: TableDefinition<[u8; 32], u64> = TableDefinition::new("ids");
/// position → `block_id ‖ block bytes`, in receipt order: catch-up reads it sequentially.
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
/// (parent, position) → (): the children of a parent, in position order.
const CHILDREN: TableDefinition<([u8; 32], u64), ()> = TableDefinition::new("children");
/// `relay_id` and the inode of the file it was drawn for.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Page cache of redb; its default (1 GiB) is far above what a lean relay should hold.
const CACHE_BYTES: usize = 32 << 20;

/// Result of [`Store::put`].
pub enum Put {
    /// Stored at this new position.
    Stored(u64),
    /// Already stored; nothing changed.
    Existing,
    /// New, but the store is over its quota.
    Full,
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
    /// Matching blocks remain after the page.
    pub more: bool,
}

/// The store.
pub struct Store {
    db: Database,
    path: PathBuf,
    /// Serialises writes and the live broadcast that follows each one, so that live frames leave
    /// in position order.
    write: Mutex<()>,
    /// spec §5 `/info`.
    pub relay_id: String,
}

fn corrupt() -> Error {
    Error::Corrupted("log entry shorter than a block_id".into())
}

impl Store {
    /// Opens or creates `dir/relay.redb`.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("relay.redb");
        let db = Database::builder()
            .set_cache_size(CACHE_BYTES)
            .create(&path)?;
        // spec §5 `/info`: a store restored from a backup or a copy draws a new `relay_id`. A copy
        // is a new file, so a new inode: the id is redrawn whenever the inode differs.
        let inode = std::fs::metadata(&path)?.ino().to_be_bytes();
        let txn = db.begin_write()?;
        let relay_id = {
            txn.open_table(IDS)?;
            txn.open_table(LOG)?;
            txn.open_table(CHILDREN)?;
            let mut meta = txn.open_table(META)?;
            let same_file = meta.get("inode")?.is_some_and(|v| v.value() == inode);
            let kept = meta
                .get("relay_id")?
                .and_then(|v| <[u8; 16]>::try_from(v.value()).ok());
            if let Some(id) = kept.filter(|_| same_file) {
                id
            } else {
                let mut id = [0u8; 16];
                getrandom::fill(&mut id).map_err(|e| Error::Io(std::io::Error::other(e)))?;
                meta.insert("relay_id", id.as_slice())?;
                meta.insert("inode", inode.as_slice())?;
                id
            }
        };
        txn.commit()?;
        let relay_id = format!("{:032x}", u128::from_be_bytes(relay_id));
        let write = Mutex::new(());
        Ok(Self {
            db,
            path,
            write,
            relay_id,
        })
    }

    /// Stores a validated block unless it is already there or the file is over `quota` bytes.
    /// `then` runs after the commit, still under the write lock.
    pub fn put(
        &self,
        id: &BlockId,
        block: &sbtp_core::BlockRef<'_>,
        quota: u64,
        then: impl FnOnce(u64),
    ) -> Result<Put, Error> {
        let _order = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let txn = self.db.begin_write()?;
        let position = {
            let mut ids = txn.open_table(IDS)?;
            // spec §2: identity is the block_id alone; the bytes stored first are kept.
            if ids.get(id.0)?.is_some() {
                return Ok(Put::Existing);
            }
            // spec §7: the quota refuses new blocks only, after the duplicate check.
            if std::fs::metadata(&self.path)?.len() >= quota {
                return Ok(Put::Full);
            }
            let mut log = txn.open_table(LOG)?;
            // spec §5: from 1, above every position given before. A failed commit gives nothing.
            let position = log.last()?.map_or(0, |(k, _)| k.value()).saturating_add(1);
            log.insert(position, [&id.0[..], block.as_bytes()].concat().as_slice())?;
            ids.insert(id.0, position)?;
            let mut children = txn.open_table(CHILDREN)?;
            for parent in block.parents() {
                children.insert((parent.0, position), ())?;
            }
            position
        };
        txn.commit()?;
        then(position);
        Ok(Put::Stored(position))
    }

    /// The stored bytes of `id`.
    pub fn get(&self, id: &BlockId) -> Result<Option<Vec<u8>>, Error> {
        let txn = self.db.begin_read()?;
        let Some(position) = txn.open_table(IDS)?.get(id.0)?.map(|v| v.value()) else {
            return Ok(None);
        };
        let entry = txn.open_table(LOG)?.get(position)?.ok_or_else(corrupt)?;
        Ok(Some(split(entry.value())?.1.to_vec()))
    }

    /// The greatest position ever given, denied blocks included; `0` for an empty store.
    pub fn max_position(&self) -> Result<u64, Error> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(LOG)?.last()?.map_or(0, |(k, _)| k.value()))
    }

    /// spec §5 `/info` `last_position`: the greatest position of a block still served.
    pub fn last_served(&self, deny: &DenyList) -> Result<u64, Error> {
        let txn = self.db.begin_read()?;
        for entry in txn.open_table(LOG)?.range::<u64>(..)?.rev() {
            let (k, v) = entry?;
            let (id, block) = split(v.value())?;
            if deny.check(id, block).is_none() {
                return Ok(k.value());
            }
        }
        Ok(0)
    }

    /// Blocks after `since`, children of `parent` if given, in position order, denied ones
    /// skipped: at most `limit` of them, and no more once `max_bytes` of block bytes are listed.
    pub fn page(
        &self,
        parent: Option<&BlockId>,
        since: u64,
        limit: usize,
        max_bytes: usize,
        deny: &DenyList,
        frames: bool,
    ) -> Result<Page, Error> {
        let txn = self.db.begin_read()?;
        let log = txn.open_table(LOG)?;
        let children = txn.open_table(CHILDREN)?;
        let start = since.saturating_add(1);
        let entries: Box<dyn Iterator<Item = Result<(u64, _), Error>>> = match parent {
            None => Box::new(log.range(start..)?.map(|e| {
                let (k, v) = e?;
                Ok((k.value(), v))
            })),
            Some(p) => Box::new(children.range((p.0, start)..=(p.0, u64::MAX))?.map(|e| {
                let position = e?.0.value().1;
                Ok((position, log.get(position)?.ok_or_else(corrupt)?))
            })),
        };
        let mut page = Page {
            items: Vec::new(),
            since,
            more: false,
        };
        let mut bytes = 0usize;
        for entry in entries {
            let (position, value) = entry?;
            let (id, block) = split(value.value())?;
            let denied = deny.check(id, block).is_some();
            if page.items.len() >= limit || bytes >= max_bytes {
                if !denied {
                    page.more = true;
                    break;
                }
            } else if !denied {
                bytes = bytes.saturating_add(block.len());
                page.items.push(Item {
                    position,
                    id: *id,
                    frame: frames.then(|| [&position.to_be_bytes()[..], block].concat()),
                });
            }
            page.since = position;
        }
        Ok(page)
    }
}

/// A log value: `block_id ‖ block`.
fn split(value: &[u8]) -> Result<(&[u8; 32], &[u8]), Error> {
    value.split_first_chunk().ok_or_else(corrupt)
}
