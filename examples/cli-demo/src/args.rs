//! Command-line parsing. Hand-written to keep the dependency graph small: a handful of subcommands
//! with `--name value`, `--name=value`, switches and positional arguments.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::fail::Fail;

/// How one option of a subcommand is written.
#[derive(Clone, Copy)]
pub enum Kind {
    /// Takes a value; at most once.
    Value,
    /// Takes a value; may be repeated, in order.
    Repeated,
    /// No value.
    Switch,
}

/// The options and positional arguments given to one subcommand.
#[derive(Debug, Default)]
pub struct Parsed {
    values: Vec<(&'static str, OsString)>,
    switches: Vec<&'static str>,
    positionals: Vec<OsString>,
}

/// Parses `args` (after the subcommand name) against `spec`, a list of `(long name, kind)`.
/// `--help` and `-h` are recognised by the caller before this runs.
///
/// # Errors
///
/// A usage [`Fail`] for an unknown option, a missing value, a repeated single-valued option or a
/// value given to a switch.
pub fn parse(args: &[OsString], spec: &[(&'static str, Kind)]) -> Result<Parsed, Fail> {
    let mut parsed = Parsed::default();
    let mut iter = args.iter();
    let mut only_positionals = false;
    while let Some(arg) = iter.next() {
        let text = arg.to_str();
        if only_positionals || !text.is_some_and(|t| t.starts_with("--")) {
            if !only_positionals && text.is_some_and(|t| t.starts_with('-') && t.len() > 1) {
                return Err(Fail::usage(format!(
                    "unknown option `{}`",
                    arg.to_string_lossy()
                )));
            }
            parsed.positionals.push(arg.clone());
            continue;
        }
        let text = text.unwrap_or_default();
        if text == "--" {
            only_positionals = true;
            continue;
        }
        let body = text.trim_start_matches("--");
        let (name, inline) = match body.split_once('=') {
            Some((name, value)) => (name, Some(OsString::from(value))),
            None => (body, None),
        };
        let Some((name, kind)) = spec.iter().find(|(n, _)| *n == name).copied() else {
            return Err(Fail::usage(format!("unknown option `--{name}`")));
        };
        match kind {
            Kind::Switch => {
                if inline.is_some() {
                    return Err(Fail::usage(format!("`--{name}` takes no value")));
                }
                if !parsed.switches.contains(&name) {
                    parsed.switches.push(name);
                }
            }
            Kind::Value | Kind::Repeated => {
                let value = match inline {
                    Some(v) => v,
                    None => iter
                        .next()
                        .cloned()
                        .ok_or_else(|| Fail::usage(format!("`--{name}` needs a value")))?,
                };
                if matches!(kind, Kind::Value) && parsed.values.iter().any(|(n, _)| *n == name) {
                    return Err(Fail::usage(format!("`--{name}` given more than once")));
                }
                parsed.values.push((name, value));
            }
        }
    }
    Ok(parsed)
}

impl Parsed {
    /// The value of a single-valued option.
    pub fn value(&self, name: &str) -> Option<&OsStr> {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_os_str())
    }

    /// Every value of a repeated option, in order.
    pub fn values(&self, name: &str) -> Vec<&OsStr> {
        self.values
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.as_os_str())
            .collect()
    }

    /// Whether a switch was given.
    pub fn switch(&self, name: &str) -> bool {
        self.switches.contains(&name)
    }

    /// A required path option.
    pub fn required_path(&self, name: &str) -> Result<PathBuf, Fail> {
        self.value(name)
            .map(PathBuf::from)
            .ok_or_else(|| Fail::usage(format!("`--{name} <FILE>` is required")))
    }

    /// An optional path option.
    pub fn path(&self, name: &str) -> Option<PathBuf> {
        self.value(name).map(PathBuf::from)
    }

    /// An optional UTF-8 option.
    pub fn text(&self, name: &str) -> Result<Option<&str>, Fail> {
        self.value(name)
            .map(|v| {
                v.to_str()
                    .ok_or_else(|| Fail::usage(format!("`--{name}`: the value is not UTF-8")))
            })
            .transpose()
    }

    /// An optional decimal integer option.
    pub fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, Fail> {
        self.text(name)?
            .map(|t| {
                t.parse::<T>().map_err(|_| {
                    Fail::usage(format!("`--{name}`: `{t}` is not a valid decimal number"))
                })
            })
            .transpose()
    }

    /// Every positional argument, in order.
    pub fn all_positionals(&self) -> &[OsString] {
        &self.positionals
    }

    /// Exactly `n` positional arguments, or a usage error naming `what`.
    pub fn positionals(&self, n: usize, what: &str) -> Result<&[OsString], Fail> {
        match self.positionals.len().cmp(&n) {
            std::cmp::Ordering::Equal => Ok(&self.positionals),
            std::cmp::Ordering::Less => Err(Fail::usage(format!("missing argument {what}"))),
            std::cmp::Ordering::Greater => {
                let extra = self
                    .positionals
                    .get(n)
                    .map(|a| a.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Err(Fail::usage(format!("unexpected argument `{extra}`")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    const SPEC: &[(&str, Kind)] = &[
        ("out", Kind::Value),
        ("parent", Kind::Repeated),
        ("force", Kind::Switch),
    ];

    #[test]
    fn values_switches_and_positionals() {
        let p = parse(
            &os(&[
                "--out",
                "a",
                "--parent=x",
                "--parent",
                "y",
                "--force",
                "file",
            ]),
            SPEC,
        )
        .unwrap();
        assert_eq!(p.value("out"), Some(OsStr::new("a")));
        assert_eq!(p.values("parent"), vec![OsStr::new("x"), OsStr::new("y")]);
        assert!(p.switch("force"));
        assert_eq!(p.positionals(1, "<FILE>").unwrap(), &os(&["file"])[..]);
    }

    #[test]
    fn rejections() {
        assert!(parse(&os(&["--nope"]), SPEC).is_err());
        assert!(parse(&os(&["-x"]), SPEC).is_err());
        assert!(parse(&os(&["--out"]), SPEC).is_err());
        assert!(parse(&os(&["--out", "a", "--out", "b"]), SPEC).is_err());
        assert!(parse(&os(&["--force=yes"]), SPEC).is_err());
        let p = parse(&os(&["a", "b"]), SPEC).unwrap();
        assert!(p.positionals(1, "<FILE>").is_err());
        assert!(p.positionals(3, "<FILE>").is_err());
    }

    #[test]
    fn double_dash_ends_options() {
        let p = parse(&os(&["--", "--out"]), SPEC).unwrap();
        assert_eq!(p.positionals(1, "<FILE>").unwrap(), &os(&["--out"])[..]);
    }
}
