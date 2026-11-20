//! Output files (blocks, payloads): written all or nothing (security review 2026-11-19, L-3).
//!
//! Each file is first written in full to a new temporary file in the destination's directory,
//! created with `O_CREAT | O_EXCL | O_NOFOLLOW`, then put in place in one step:
//! - without `--force`, by `link(2)`, which fails if the destination exists (a symbolic link
//!   included) and never follows one: no check-then-create race;
//! - with `--force`, by `rename(2)`, which replaces the destination entry itself: a symbolic link
//!   at the destination is replaced, never followed, and its target is not touched.
//!
//! Several files given together (`get --out --payload-out`) are all staged before any is put in
//! place. If putting one in place fails, the ones already placed by `link` are removed again. With
//! `--force` a replaced file cannot be restored; the destinations are checked (not directories)
//! before the first rename to make that case rare.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::fail::Fail;

/// A temporary file holding the full content, not yet in place.
struct Staged {
    tmp: PathBuf,
    dest: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Gone already once it was linked and removed, or renamed: errors are expected.
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Writes every `(path, bytes)` pair, or none: see the module documentation.
///
/// # Errors
///
/// A [`Fail`] naming the path that could not be written; nothing new is left at any destination
/// (except, with `force`, a destination already renamed over).
pub fn write_all(files: &[(&Path, &[u8])], force: bool) -> Result<(), Fail> {
    let entries: Vec<PathBuf> = files.iter().map(|(path, _)| entry(path)).collect();
    for (i, (a, _)) in files.iter().enumerate() {
        let same = files
            .iter()
            .zip(&entries)
            .skip(i + 1)
            .find(|(_, e)| entries.get(i) == Some(*e));
        if let Some(((b, _), _)) = same {
            return Err(Fail::usage(format!(
                "{} and {} are the same file: give two different outputs",
                a.display(),
                b.display()
            )));
        }
    }
    for (path, _) in files {
        check_destination(path, force)?;
    }
    let staged = files
        .iter()
        .map(|(path, bytes)| stage(path, bytes))
        .collect::<Result<Vec<Staged>, Fail>>()?;
    place(&staged, force)
}

/// Puts every staged file in place, in order. Without `force`, a failure removes the
/// destinations already linked: this covers a destination created after [`check_destination`].
fn place(staged: &[Staged], force: bool) -> Result<(), Fail> {
    let mut placed: Vec<&Path> = Vec::new();
    for s in staged {
        let result = if force {
            std::fs::rename(&s.tmp, &s.dest)
        } else {
            std::fs::hard_link(&s.tmp, &s.dest)
        };
        if let Err(e) = result {
            if !force {
                for dest in &placed {
                    let _ = std::fs::remove_file(dest);
                }
            }
            return Err(place_fail(&s.dest, &e));
        }
        placed.push(&s.dest);
    }
    Ok(())
}

/// The directory entry `path` names: its canonical parent directory joined with its file name
/// (security review 2026-11-19, I-10). `a`, `./a`, `x/../a` and `link-to-dir/a` give one entry;
/// the file itself need not exist. A parent that cannot be resolved leaves the path as given
/// (staging then fails on it anyway).
fn entry(path: &Path) -> PathBuf {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match (std::fs::canonicalize(dir), path.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name),
        _ => path.to_path_buf(),
    }
}

/// Refuses a destination that exists without `force`, and a directory in any case.
fn check_destination(path: &Path, force: bool) -> Result<(), Fail> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            Err(Fail::failed(format!("{} is a directory", path.display())))
        }
        Ok(_) if !force => Err(exists(path)),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Fail::failed(format!("cannot use {}: {e}", path.display()))),
    }
}

/// Writes `bytes` to a new temporary file next to `dest` and syncs it.
fn stage(dest: &Path, bytes: &[u8]) -> Result<Staged, Fail> {
    static N: AtomicU32 = AtomicU32::new(0);
    let name = dest
        .file_name()
        .ok_or_else(|| Fail::usage(format!("{} is not a file path", dest.display())))?;
    let dir = dest
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = dir.join(tmp_name);
    let mut file = create_new(&tmp)
        .map_err(|e| Fail::failed(format!("cannot create {}: {e}", dest.display())))?;
    let staged = Staged {
        tmp,
        dest: dest.to_path_buf(),
    };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Fail::failed(format!("cannot write {}: {e}", dest.display())))?;
    Ok(staged)
}

#[cfg(unix)]
fn create_new(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn exists(path: &Path) -> Fail {
    Fail::failed(format!(
        "{} already exists; pass `--force` to replace it",
        path.display()
    ))
}

fn place_fail(path: &Path, e: &std::io::Error) -> Fail {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        exists(path)
    } else {
        Fail::failed(format!("cannot write {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cli-demo-output-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn writes_all_and_leaves_no_temporary_file() {
        let dir = tmp_dir("all");
        let (a, b) = (dir.join("a"), dir.join("b"));
        write_all(&[(&a, b"one"), (&b, b"two")], false).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"one");
        assert_eq!(std::fs::read(&b).unwrap(), b"two");
        assert_eq!(entries(&dir), ["a", "b"]);
    }

    #[test]
    fn nothing_written_when_one_output_exists() {
        let dir = tmp_dir("none");
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&b, b"old").unwrap();
        assert!(write_all(&[(&a, b"one"), (&b, b"two")], false).is_err());
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"old");
        assert_eq!(entries(&dir), ["b"]);
        assert!(write_all(&[(&a, b"x"), (&a, b"y")], true).is_err());
        assert!(!a.exists());
    }

    /// L-5: the pre-check bypassed (the second destination appears after it), the first file
    /// already linked is removed when the second `link` fails.
    #[test]
    fn placement_failure_removes_the_files_already_placed() {
        let dir = tmp_dir("rollback");
        let (a, b) = (dir.join("a"), dir.join("b"));
        let staged = vec![stage(&a, b"one").unwrap(), stage(&b, b"two").unwrap()];
        std::fs::write(&b, b"raced").unwrap();
        let fail = place(&staged, false).unwrap_err();
        assert!(fail.message.contains("already exists"), "{}", fail.message);
        assert!(!a.exists(), "the first output was left in place");
        assert_eq!(std::fs::read(&b).unwrap(), b"raced");
        drop(staged);
        assert_eq!(entries(&dir), ["b"]);
    }

    /// I-10: one file under two spellings is refused, with and without `--force`.
    #[cfg(unix)]
    #[test]
    fn same_file_under_two_spellings_is_refused() {
        let dir = tmp_dir("same");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::os::unix::fs::symlink(dir.join("sub"), dir.join("alias")).unwrap();
        let a = dir.join("sub").join("a");
        for other in [
            dir.join("sub").join(".").join("a"),
            dir.join("sub").join("..").join("sub").join("a"),
            dir.join("alias").join("a"),
        ] {
            for force in [false, true] {
                let fail = write_all(&[(&a, b"block"), (&other, b"payload")], force).unwrap_err();
                assert!(fail.message.contains("same file"), "{}", fail.message);
                assert!(!a.exists(), "{}", other.display());
            }
        }
        assert_eq!(entries(&dir.join("sub")), Vec::<String>::new());
        // Distinct entries are still accepted, a symlinked name included.
        write_all(
            &[(&a, b"block"), (&dir.join("alias").join("b"), b"payload")],
            false,
        )
        .unwrap();
        assert_eq!(entries(&dir.join("sub")), ["a", "b"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let dir = tmp_dir("symlink");
        let target = dir.join("target");
        std::fs::write(&target, b"precious").unwrap();
        let link = dir.join("out");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Without --force: refused.
        assert!(write_all(&[(&link, b"block")], false).is_err());
        // With --force: the link itself is replaced, the target is untouched.
        write_all(&[(&link, b"block")], true).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");
        assert!(!std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"block");
        assert_eq!(entries(&dir), ["out", "target"]);
    }
}
