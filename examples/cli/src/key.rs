//! The secret key file: the line `SBTP-ED25519-SECRET-KEY-V1`, then the 32-byte Ed25519 seed in
//! 64 lowercase hexadecimal characters. Unix only, as the relay binary.
//!
//! Threat model: the file protects the key as an unencrypted SSH key does, by permissions only.
//! It is created with mode `0600` and never replaced; one the group or others can access is
//! refused, as OpenSSH does. Anyone who reads the file, or runs code as this user, can sign as
//! this key. The key never goes on the command line, in the environment, on stdout or in an
//! error message. The heap buffers holding it are allocated at their final size and wiped on
//! drop, as is the `SigningKey`; stack copies made by the compiler cannot be guaranteed wiped.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use sbtp_core::SigningKey;
use zeroize::Zeroizing;

use crate::hex_into;

const HEADER: &str = "SBTP-ED25519-SECRET-KEY-V1";
/// Largest key file read: header, seed, line ends and some slack.
const MAX_LEN: usize = 256;

/// Writes a new key, drawn from the operating system, to a new file with mode `0600`. Refuses an
/// existing path, a symbolic link included (`create_new` is `O_EXCL`).
pub fn generate(path: &Path) -> Result<SigningKey, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| format!("no random source: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    let mut text = Zeroizing::new(String::with_capacity(MAX_LEN));
    text.push_str(HEADER);
    text.push('\n');
    hex_into(&mut text, key.as_bytes());
    text.push('\n');
    let mut options = std::fs::OpenOptions::new();
    let file = options.write(true).create_new(true).mode(0o600).open(path);
    let written = file.and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()));
    written.map_err(|e| format!("cannot create key file {}: {e}", path.display()))?;
    Ok(key)
}

/// Reads the key in `path`: a regular file, not a symbolic link, that only its owner can access.
pub fn read(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    let io = |e: std::io::Error| format!("cannot read key file {shown}: {e}");
    let file = std::fs::OpenOptions::new()
        .read(true)
        // The mode checked is the file's, not a link's; a FIFO must not block before `is_file`.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    let mode = meta.mode() & 0o777;
    if !meta.is_file() || mode & 0o077 != 0 {
        return Err(format!(
            "key file {shown} must be a regular file only its owner can access (mode {mode:04o}); \
             run `chmod 600 {shown}`"
        ));
    }
    // Sized so that `read_to_end` never reallocates and frees an unwiped copy.
    let mut text = Zeroizing::new(Vec::with_capacity(MAX_LEN.saturating_add(64)));
    file.take((MAX_LEN as u64).saturating_add(1))
        .read_to_end(&mut text)
        .map_err(io)?;
    let text = std::str::from_utf8(&text)
        .ok()
        .filter(|t| t.len() <= MAX_LEN);
    // Never quote the content.
    text.and_then(decode)
        .ok_or_else(|| format!("{shown} is not an SBTP secret key file"))
}

fn decode(text: &str) -> Option<SigningKey> {
    let mut lines = text.lines();
    let (header, hex) = (lines.next()?, lines.next()?.trim());
    let rest_empty = lines.all(|l| l.trim().is_empty());
    if header != HEADER || hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (byte, pair) in seed.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    rest_empty.then(|| SigningKey::from_bytes(&seed))
}
