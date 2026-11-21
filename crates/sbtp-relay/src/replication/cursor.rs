//! The durable walk of each peer (ADR 0048 rules 8 and 9): one row per peer in the index table
//! `replication_peers`, keyed by the normalised peer URL.
//!
//! Row: `flags` (1 byte; bit 0: `since` is set), `since` (u64, big-endian), `last_page_ms` (u64,
//! big-endian), then the cursor (0 to 128 bytes of `A-Z a-z 0-9 - _`). A row that does not have
//! this shape is read as no row: the peer starts again from `replication_start`, and the held
//! check makes that cheap (rule 6). The index is derived data: a rebuilt index has no row.
//!
//! Each write is its own transaction, with redb's default durability, run by the index writer
//! thread after the page it records: a crash before it walks the last page again (rule 8).

use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::index::{IndexError, RedbIndex};

const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("replication_peers");
const HEAD: usize = 17;

/// What the relay keeps of its walk of one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Walk {
    /// The `since` sent with every `/query` of the walk; `None` walks the full history.
    pub since: Option<u64>,
    /// The cursor of the last complete page; `None` before the first.
    pub cursor: Option<String>,
    /// The relay clock at the last complete page; `0` before the first (rule 9).
    pub last_page_ms: u64,
}

/// Whether `s` has the syntax of a cursor (core spec §4, `GET /sbtp/v1/query`).
#[must_use]
pub fn valid_cursor(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn encode(w: &Walk) -> Vec<u8> {
    let cursor = w.cursor.as_deref().unwrap_or("");
    let mut row = Vec::with_capacity(HEAD + cursor.len());
    row.push(u8::from(w.since.is_some()));
    row.extend_from_slice(&w.since.unwrap_or(0).to_be_bytes());
    row.extend_from_slice(&w.last_page_ms.to_be_bytes());
    row.extend_from_slice(cursor.as_bytes());
    row
}

fn decode(row: &[u8]) -> Option<Walk> {
    let (&flags, rest) = row.split_first()?;
    let since = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    let last_page_ms = u64::from_be_bytes(rest.get(8..16)?.try_into().ok()?);
    let cursor = std::str::from_utf8(rest.get(16..)?).ok()?;
    if flags > 1 || !(cursor.is_empty() || valid_cursor(cursor)) {
        return None;
    }
    Some(Walk {
        since: (flags == 1).then_some(since),
        cursor: (!cursor.is_empty()).then(|| cursor.to_owned()),
        last_page_ms,
    })
}

/// The cursor table, on the index backend.
pub trait CursorStore {
    /// The walk of `peer`, if a valid row exists.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn load_walk(&self, peer: &str) -> Result<Option<Walk>, IndexError>;

    /// Records the walk of `peer`, durably.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn save_walk(&self, peer: &str, walk: &Walk) -> Result<(), IndexError>;

    /// Removes the rows of the peers not in `keep` (rule 8, at start-up); returns how many.
    ///
    /// # Errors
    ///
    /// Backend errors.
    fn retain_walks(&self, keep: &[String]) -> Result<u64, IndexError>;
}

impl CursorStore for RedbIndex {
    fn load_walk(&self, peer: &str) -> Result<Option<Walk>, IndexError> {
        let txn = self.database().begin_read()?;
        let table = match txn.open_table(PEERS) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(peer)?.and_then(|g| decode(g.value())))
    }

    fn save_walk(&self, peer: &str, walk: &Walk) -> Result<(), IndexError> {
        let txn = self.database().begin_write()?;
        txn.open_table(PEERS)?
            .insert(peer, encode(walk).as_slice())?;
        txn.commit()?;
        Ok(())
    }

    fn retain_walks(&self, keep: &[String]) -> Result<u64, IndexError> {
        let txn = self.database().begin_write()?;
        let mut removed = 0;
        {
            let mut table = txn.open_table(PEERS)?;
            let mut gone = Vec::new();
            for row in table.iter()? {
                let (k, _) = row?;
                let k = k.value();
                if !keep.iter().any(|p| p == k) {
                    gone.push(k.to_owned());
                }
            }
            for k in gone {
                table.remove(k.as_str())?;
                removed += 1;
            }
        }
        txn.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::index::IndexBackend;

    #[test]
    fn rows_round_trip_and_bad_rows_are_none() {
        for w in [
            Walk::default(),
            Walk {
                since: Some(7),
                cursor: Some("k3_Zr0-AAAA".into()),
                last_page_ms: 9,
            },
        ] {
            assert_eq!(decode(&encode(&w)), Some(w));
        }
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[2; HEAD]), None);
        let mut bad = encode(&Walk::default());
        bad.extend_from_slice(b"a b");
        assert_eq!(decode(&bad), None);
        assert!(!valid_cursor(""));
        assert!(!valid_cursor(&"a".repeat(129)));
        assert!(valid_cursor(&"a".repeat(128)));
    }

    #[test]
    fn table_survives_reopen_and_retain_removes_others() {
        let dir = std::env::temp_dir().join(format!("sbtp-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.redb");
        let w = Walk {
            since: None,
            cursor: Some("abc".into()),
            last_page_ms: 5,
        };
        {
            let idx = RedbIndex::open(&path, 1 << 20).unwrap();
            assert_eq!(idx.load_walk("https://a.example").unwrap(), None);
            idx.save_walk("https://a.example", &w).unwrap();
            idx.save_walk("https://b.example", &w).unwrap();
            idx.close().unwrap();
        }
        let idx = RedbIndex::open(&path, 1 << 20).unwrap();
        assert_eq!(idx.load_walk("https://a.example").unwrap(), Some(w.clone()));
        assert_eq!(idx.retain_walks(&["https://a.example".into()]).unwrap(), 1);
        assert_eq!(idx.load_walk("https://b.example").unwrap(), None);
        assert_eq!(idx.load_walk("https://a.example").unwrap(), Some(w));
        idx.close().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
