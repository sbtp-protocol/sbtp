//! Local operator commands, run by the operator on the relay's host, never reachable from the
//! network.
//!
//! `sbtp-relay key-blocks <public-key-hex> [--config <path>]` (ADR 0052 rule 10): lists the
//! `block_id` of every block the relay holds whose header carries the public key, one lowercase
//! hex identifier per line on standard output, for a CDN purge. It reads the block headers in
//! the data directory read-only (the first 51 bytes of each file), so it works while the relay
//! runs and whether or not the key is already on the deny list. It creates nothing, opens no
//! index and writes no log line (ADR 0021): the key and the identifiers go to standard output
//! only. Errors are one fixed line on standard error, without the key.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use sbtp_core::layout::{OFFSET_PUBKEY, PUBKEY_LEN};

use crate::config::{ENV_PREFIX, Settings};
use crate::store;

/// The name of the subcommand.
pub const KEY_BLOCKS: &str = "key-blocks";

/// The exit code of a usage or configuration error.
pub const EXIT_USAGE: u8 = 2;
/// The exit code of an error while reading the store.
pub const EXIT_IO: u8 = 1;

const USAGE: &str = "usage: sbtp-relay key-blocks <public-key-hex> [--config <path>]";

/// Why the command failed: the exit code and one line for standard error.
#[derive(Debug, PartialEq, Eq)]
pub struct Failed {
    /// The process exit code.
    pub code: u8,
    /// The message, without the key.
    pub msg: String,
}

/// Runs `key-blocks` with `args` (after the subcommand) and the process environment `env`,
/// writing the identifiers to `out`. Returns how many were written.
///
/// # Errors
///
/// [`Failed`]: bad arguments or settings ([`EXIT_USAGE`]), or a read error on the store, or on
/// `out` ([`EXIT_IO`]).
pub fn key_blocks<A, E>(args: A, env: E, out: &mut impl Write) -> Result<u64, Failed>
where
    A: IntoIterator<Item = OsString>,
    E: IntoIterator<Item = (OsString, OsString)>,
{
    let usage = |msg: &str| Failed {
        code: EXIT_USAGE,
        msg: format!("{msg}; {USAGE}"),
    };
    let mut args = args.into_iter();
    let key = args
        .next()
        .and_then(|k| k.to_str().and_then(store::decode_hex::<32>))
        .ok_or_else(|| usage("the first argument must be a public key, 64 lowercase hex digits"))?;
    // The settings read only `SBTP_RELAY_*` variables.
    let env = env
        .into_iter()
        .filter(|(k, _)| k.to_str().is_some_and(|k| k.starts_with(ENV_PREFIX)));
    let settings = Settings::load(args, env).map_err(|e| usage(&e.to_string()))?;
    let blocks = settings.data_dir.join("blocks");
    let io_failed = |what: &str, e: &io::Error| Failed {
        code: EXIT_IO,
        msg: format!("{what}: {e}"),
    };
    // Never created: a missing store is an error, not an empty one.
    match fs::symlink_metadata(&blocks) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => {
            return Err(Failed {
                code: EXIT_IO,
                msg: "the block store is not a real directory".into(),
            });
        }
        Err(e) => return Err(io_failed("reading the block store", &e)),
    }
    let mut n = 0u64;
    let mut write_failed = None;
    store::scan_tree(&blocks, |id, path, _| {
        if write_failed.is_some() || header_key(path).as_ref() != Some(&key) {
            return;
        }
        match writeln!(out, "{}", store::hex(&id)) {
            Ok(()) => n += 1,
            Err(e) => write_failed = Some(e),
        }
    })
    .map_err(|e| io_failed("reading the block store", &e))?;
    if let Some(e) = write_failed.or_else(|| out.flush().err()) {
        return Err(io_failed("writing the list", &e));
    }
    Ok(n)
}

/// The public key in the header of the block file at `path` (spec §2.1), `None` when the file
/// cannot be opened as a regular file without following a link, or is shorter than the header.
fn header_key(path: &Path) -> Option<[u8; 32]> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let f: File = o.open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut head = [0u8; OFFSET_PUBKEY + PUBKEY_LEN];
    f.take(head.len() as u64).read_exact(&mut head).ok()?;
    crate::deny::pubkey_of(&head)
}
