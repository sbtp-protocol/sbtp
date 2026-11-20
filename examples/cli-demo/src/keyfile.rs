//! The secret key file.
//!
//! Format (text, two lines):
//!
//! ```text
//! SBTP-ED25519-SECRET-KEY-V1
//! <64 hexadecimal characters: the 32-byte Ed25519 seed (RFC 8032 secret key)>
//! ```
//!
//! Threat model. The file protects the key the way an unencrypted SSH key does: by file
//! permissions only. It is created with mode `0600` and never replaced; a key file readable by
//! the group or by others is refused, as OpenSSH does. Anyone who can read the file, or who runs
//! code as the same user, can sign as this key. The key never appears on the command line, in an
//! environment variable, on standard output or in an error message. The heap buffers the CLI
//! owns are wiped after use: the file text is read into one buffer allocated at its final size
//! (no reallocation leaves an unwiped copy), and the decoded seed and `SigningKey` are zeroized on
//! drop. Copies the compiler makes on the stack (return values, moves) cannot be guaranteed wiped.
//! Encryption at rest (passphrase) is out of scope of this demonstration CLI.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use sbtp_core::SigningKey;
use zeroize::Zeroizing;

use crate::fail::Fail;
use crate::hex;

/// First line of a key file.
pub const HEADER: &str = "SBTP-ED25519-SECRET-KEY-V1";

/// Largest key file read, in bytes: the header, the seed, line ends and a little slack.
const MAX_KEY_FILE_LEN: usize = 256;

/// The text of a key file holding `key`.
pub fn encode(key: &SigningKey) -> Zeroizing<String> {
    let seed = Zeroizing::new(key.to_bytes());
    let mut text = Zeroizing::new(String::with_capacity(HEADER.len() + 66));
    text.push_str(HEADER);
    text.push('\n');
    let hex = Zeroizing::new(hex::encode(seed.as_slice()));
    text.push_str(&hex);
    text.push('\n');
    text
}

/// Parses the text of a key file. The error never quotes the file content.
fn decode(text: &str) -> Result<SigningKey, &'static str> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("not an SBTP secret key file (bad first line)");
    }
    let seed = lines
        .next()
        .map(str::trim)
        .and_then(hex::decode::<32>)
        .map(Zeroizing::new)
        .ok_or("the second line is not 64 hexadecimal characters")?;
    if lines.any(|l| !l.trim().is_empty()) {
        return Err("unexpected content after the key");
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Draws a new key from the operating system's random source.
#[cfg(unix)]
pub fn generate() -> Result<SigningKey, Fail> {
    let mut seed = Zeroizing::new([0u8; 32]);
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(seed.as_mut_slice()))
        .map_err(|e| Fail::failed(format!("cannot read /dev/urandom: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Writes `key` to a new file `path` with mode `0600`. Refuses an existing path, a symbolic link
/// included.
#[cfg(unix)]
pub fn write_new(path: &Path, key: &SigningKey) -> Result<(), Fail> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Fail::failed(format!(
                    "{} already exists; refusing to overwrite a key file",
                    path.display()
                ))
            } else {
                Fail::failed(format!("cannot create {}: {e}", path.display()))
            }
        })?;
    let text = encode(key);
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| Fail::failed(format!("cannot write {}: {e}", path.display())))
}

/// Reads the key in `path`. Refuses anything but a regular file that only its owner can read
/// or write (mode `0600` or `0400`).
#[cfg(unix)]
pub fn read(path: &Path) -> Result<SigningKey, Fail> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        // Do not follow a symbolic link at the last component: the mode checked is the file's.
        // O_NONBLOCK: a FIFO planted at the path must not block `open` before the `is_file`
        // check below; it has no effect on reading a regular file.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Fail::failed(format!("cannot open key file {}: {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| Fail::failed(format!("cannot read key file {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(Fail::failed(format!(
            "key file {} is not a regular file",
            path.display()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Fail::failed(format!(
            "key file {} has mode {mode:04o}: it must be readable by its owner only; run `chmod 600 {}`",
            path.display(),
            path.display()
        )));
    }
    // Allocated once at the largest size read (`take` below), so that `read_to_end` never
    // reallocates and frees an unwiped copy of the seed (security review 2026-11-19, L-2). The
    // `+ 1` is the byte that detects a too-long file; the `+ 32` of slack keeps the buffer from
    // ever being full, so `read_to_end` neither grows it nor copies into its stack probe buffer.
    let mut text = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_LEN + 1 + 32));
    file.take(MAX_KEY_FILE_LEN as u64 + 1)
        .read_to_end(&mut text)
        .map_err(|e| Fail::failed(format!("cannot read key file {}: {e}", path.display())))?;
    if text.len() > MAX_KEY_FILE_LEN {
        return Err(Fail::failed(format!(
            "key file {} is too long to be an SBTP key file",
            path.display()
        )));
    }
    let text = std::str::from_utf8(&text).map_err(|_| {
        Fail::failed(format!(
            "key file {}: not an SBTP secret key file (not text)",
            path.display()
        ))
    })?;
    decode(text).map_err(|why| Fail::failed(format!("key file {}: {why}", path.display())))
}

#[cfg(not(unix))]
pub fn generate() -> Result<SigningKey, Fail> {
    Err(Fail::failed("key files are supported on Unix only"))
}

#[cfg(not(unix))]
pub fn write_new(_: &Path, _: &SigningKey) -> Result<(), Fail> {
    Err(Fail::failed("key files are supported on Unix only"))
}

#[cfg(not(unix))]
pub fn read(_: &Path) -> Result<SigningKey, Fail> {
    Err(Fail::failed("key files are supported on Unix only"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        // Test key from a public seed.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let text = encode(&key);
        assert!(text.starts_with(HEADER));
        assert_eq!(decode(&text).unwrap().to_bytes(), key.to_bytes());
    }

    #[test]
    fn decode_rejections_do_not_quote_the_content() {
        for bad in [
            "",
            "SBTP-ED25519-SECRET-KEY-V0\n0707\n",
            "SBTP-ED25519-SECRET-KEY-V1\nzz\n",
            "SBTP-ED25519-SECRET-KEY-V1\n0707070707070707070707070707070707070707070707070707070707070707\nmore\n",
        ] {
            let why = decode(bad).unwrap_err();
            assert!(!why.contains("0707"), "{why}");
        }
    }
}
