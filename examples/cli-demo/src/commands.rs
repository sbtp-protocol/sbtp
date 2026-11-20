//! The subcommands. Every layer 0 operation goes through `sbtp-core`: building, mining, signing,
//! parsing and validating blocks.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sbtp_core::layout::{MAX_BLOCK_LEN, MAX_PAYLOAD_LEN};
use sbtp_core::{
    BlockBuilder, BlockId, BlockRef, BuildError, DEFAULT_MAX_ATTEMPTS, mine, sign_block,
    validate_requested, validate_submitted,
};

use crate::args::{Kind, Parsed, parse as parse_args};
use crate::fail::{Fail, untrusted};
use crate::relay::{Relay, Stored};
use crate::walk::{self, Event, Filter, Policy, Walker};
use crate::{hex, keyfile, output};

/// Highest difficulty `mine` accepts from a relay's `/info` without `--difficulty`: about
/// 2^24 hashes, a few seconds. A relay announcing more is refused rather than obeyed
/// (`BlockBuilder` documents the same concern for hostile relays).
const MAX_RELAY_DIFFICULTY: u32 = 24;

/// `keygen --out <FILE>`.
pub fn keygen(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("out", Kind::Value)])?;
    p.positionals(0, "")?;
    let out = p.required_path("out")?;
    let key = keyfile::generate()?;
    keyfile::write_new(&out, &key)?;
    eprintln!("Secret key written to {} (mode 0600).", out.display());
    println!("{}", hex::encode(key.verifying_key().as_bytes()));
    Ok(())
}

/// `pubkey --key <FILE>`.
pub fn pubkey(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("key", Kind::Value)])?;
    p.positionals(0, "")?;
    let key = keyfile::read(&p.required_path("key")?)?;
    println!("{}", hex::encode(key.verifying_key().as_bytes()));
    Ok(())
}

/// `mine --key <FILE> --out <FILE> [--payload <FILE>] [--parent <ID>]... (--difficulty <D> |
/// --relay <URL>) [--timestamp <MS>] [--force]`.
pub fn mine_block(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(
        args,
        &[
            ("key", Kind::Value),
            ("out", Kind::Value),
            ("payload", Kind::Value),
            ("parent", Kind::Repeated),
            ("difficulty", Kind::Value),
            ("relay", Kind::Value),
            ("timestamp", Kind::Value),
            ("force", Kind::Switch),
        ],
    )?;
    p.positionals(0, "")?;
    let key_path = p.required_path("key")?;
    let out = p.required_path("out")?;
    let parents = p
        .values("parent")
        .into_iter()
        .map(|v| {
            v.to_str().and_then(hex::block_id).ok_or_else(|| {
                Fail::usage(format!(
                    "`--parent {}`: expected a block_id of 64 hexadecimal characters",
                    untrusted(&v.to_string_lossy(), 80)
                ))
            })
        })
        .collect::<Result<Vec<BlockId>, Fail>>()?;
    let payload = match p.path("payload") {
        Some(path) => read_bounded(&path, MAX_PAYLOAD_LEN, "payload")?,
        None => Vec::new(),
    };
    let difficulty = target_difficulty(p.number::<u32>("difficulty")?, p.text("relay")?)?;
    let timestamp = match p.number::<u64>("timestamp")? {
        Some(t) => t,
        None => now_ms()?,
    };
    let key = keyfile::read(&key_path)?;

    let mut block = BlockBuilder::for_key(&key)
        .timestamp(timestamp)
        .parents(&parents)
        .payload(&payload)
        .build_unsigned()
        .map_err(build_fail)?;
    let started = Instant::now();
    // spec §3.3: increment the nonce from 0 until the block_id has `difficulty` leading zeros.
    let budget = if difficulty > 26 {
        u64::MAX
    } else {
        DEFAULT_MAX_ATTEMPTS
    };
    let (nonce, id) = mine(&mut block, difficulty, budget).map_err(build_fail)?;
    let elapsed = started.elapsed();
    // spec §3.2: sign SIG_PREFIX ‖ block_id, after mining (the nonce is covered by block_id).
    let signed = sign_block(&mut block, &key).map_err(build_fail)?;
    debug_assert_eq!(signed, id);
    // Self-check before writing: the block must pass the validation a relay applies.
    validate_submitted(&block, difficulty).map_err(|e| {
        Fail::failed(format!(
            "internal error: the mined block fails validation: {}",
            e.name()
        ))
    })?;
    output::write_all(&[(&out, &block)], p.switch("force"))?;
    eprintln!(
        "Mined at difficulty {difficulty} in {} ms ({} attempts); {} bytes written to {}.",
        elapsed.as_millis(),
        nonce.saturating_add(1),
        block.len(),
        out.display()
    );
    println!("{id}");
    Ok(())
}

/// The difficulty to mine at: `--difficulty`, or the relay's `min_pow_difficulty` (spec §4: a
/// sender SHOULD read `/info` before mining), capped at [`MAX_RELAY_DIFFICULTY`].
fn target_difficulty(difficulty: Option<u32>, relay: Option<&str>) -> Result<u32, Fail> {
    match (difficulty, relay) {
        (Some(_), Some(_)) => Err(Fail::usage(
            "give `--difficulty` or `--relay`, not both (`--relay` reads the difficulty from the \
             relay's /sbtp/v1/info)",
        )),
        (Some(d), None) if d > sbtp_core::MAX_DIFFICULTY => Err(Fail::usage(format!(
            "`--difficulty {d}`: the maximum is {}",
            sbtp_core::MAX_DIFFICULTY
        ))),
        (Some(d), None) => Ok(d),
        (None, Some(url)) => {
            let relay = Relay::new(url)?;
            let d = relay.info()?.min_pow_difficulty;
            eprintln!("Relay {} requires difficulty {d}.", relay.base());
            if d > MAX_RELAY_DIFFICULTY {
                return Err(Fail::refused(format!(
                    "relay {} requires difficulty {d}, above the {MAX_RELAY_DIFFICULTY} this CLI \
                     accepts from a relay; pass `--difficulty {d}` explicitly to mine anyway",
                    relay.base()
                )));
            }
            Ok(d)
        }
        (None, None) => Err(Fail::usage(
            "give the target difficulty with `--difficulty <D>`, or `--relay <URL>` to use the \
             relay's",
        )),
    }
}

/// `inspect <FILE> [--difficulty <D>]`: full local validation, then a summary.
pub fn inspect(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("difficulty", Kind::Value)])?;
    let file = p.positionals(1, "<BLOCK_FILE>")?;
    let path = file.first().map_or(Path::new(""), Path::new);
    let difficulty = p.number::<u32>("difficulty")?.unwrap_or(0);
    let bytes = read_bounded(path, MAX_BLOCK_LEN, "block")?;
    let validated = validate_submitted(&bytes, difficulty).map_err(|e| {
        Fail::invalid(format!(
            "{} is not a valid block: {} ({e})",
            path.display(),
            e.name()
        ))
    })?;
    print_summary(validated.block(), validated.block_id(), difficulty);
    Ok(())
}

/// `publish --relay <URL> <BLOCK_FILE>`.
pub fn publish(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("relay", Kind::Value)])?;
    let file = p.positionals(1, "<BLOCK_FILE>")?;
    let path = file.first().map_or(Path::new(""), Path::new);
    let relay = Relay::new(
        p.text("relay")?
            .ok_or_else(|| Fail::usage("`--relay <URL>` is required"))?,
    )?;
    let bytes = read_bounded(path, MAX_BLOCK_LEN, "block")?;
    // Catch a broken file before the network; the relay applies its own difficulty (C1) and
    // timestamp policy (P1), so only format and signature are checked here.
    let id = *validate_submitted(&bytes, 0)
        .map_err(|e| {
            Fail::invalid(format!(
                "{} is not a valid block: {} ({e}); not sent",
                path.display(),
                e.name()
            ))
        })?
        .block_id();
    match relay.put_block(&bytes)? {
        Stored::Created => eprintln!("201 Created: relay {} stored the block.", relay.base()),
        Stored::AlreadyStored => {
            eprintln!("200 OK: relay {} already held this block.", relay.base());
        }
    }
    println!("{id}");
    Ok(())
}

/// `get --relay <URL> <BLOCK_ID> [--out <FILE>] [--payload-out <FILE>] [--difficulty <D>]
/// [--force]`.
pub fn get(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(
        args,
        &[
            ("relay", Kind::Value),
            ("out", Kind::Value),
            ("payload-out", Kind::Value),
            ("difficulty", Kind::Value),
            ("force", Kind::Switch),
        ],
    )?;
    let positional = p.positionals(1, "<BLOCK_ID>")?;
    let id_text = positional
        .first()
        .and_then(|a| a.to_str())
        .unwrap_or_default();
    let id = hex::block_id(id_text).ok_or_else(|| {
        Fail::usage(format!(
            "`{}`: expected a block_id of 64 hexadecimal characters",
            untrusted(id_text, 80)
        ))
    })?;
    let relay = Relay::new(
        p.text("relay")?
            .ok_or_else(|| Fail::usage("`--relay <URL>` is required"))?,
    )?;
    // ADR 0026 rules 1 to 3: a local floor, 0 by default, never taken from the relay's /info.
    let difficulty = p.number::<u32>("difficulty")?.unwrap_or(0);
    if difficulty > sbtp_core::MAX_DIFFICULTY {
        return Err(Fail::usage(format!(
            "`--difficulty {difficulty}`: the maximum is {}",
            sbtp_core::MAX_DIFFICULTY
        )));
    }
    let bytes = relay.get_block(&id)?;
    // spec §3.4 "Receipt": recompute the block_id, compare with the requested one (R1), then
    // full validation (F1 to F9, C1 with the recipient's own difficulty, C2, C3) before any
    // storage or use.
    let validated = validate_requested(&bytes, difficulty, &id)
        .map_err(|e| receipt_fail(&relay, &id, &bytes, &e))?;
    // Both outputs or neither (security review 2026-11-19, L-3).
    let out = p.path("out");
    let payload_out = p.path("payload-out");
    let mut files: Vec<(&Path, &[u8])> = Vec::new();
    if let Some(path) = &out {
        files.push((path, &bytes));
    }
    if let Some(path) = &payload_out {
        files.push((path, validated.block().payload()));
    }
    output::write_all(&files, p.switch("force"))?;
    if let Some(path) = &out {
        eprintln!("Block written to {}.", path.display());
    }
    if let Some(path) = &payload_out {
        eprintln!("Payload written to {}.", path.display());
    }
    print_summary(validated.block(), validated.block_id(), difficulty);
    Ok(())
}

/// The failure of the receipt check of `get`. A block that fails only C1 at the local floor
/// (`--difficulty` above 0) is refused by this client's policy; it does not show that the relay
/// served an invalid block (ADR 0026 rule 4). `validate_requested` checks C1 before C2 and C3, so
/// the block is checked again at `d = 0` to tell the two cases apart.
fn receipt_fail(relay: &Relay, id: &BlockId, bytes: &[u8], e: &sbtp_core::Error) -> Fail {
    if let sbtp_core::Error::InsufficientPow { required, actual } = *e {
        match validate_requested(bytes, 0, id) {
            Ok(_) => {
                return Fail::invalid(format!(
                    "the block {id} from relay {} is valid, but below the local floor: its \
                     block_id has {actual} leading zero bits, `--difficulty {required}` asks for \
                     at least {required}. This is this client's policy, not a fault of the \
                     relay. Nothing written.",
                    relay.base()
                ));
            }
            Err(other) => return invalid_from_relay(relay, id, &other),
        }
    }
    invalid_from_relay(relay, id, e)
}

fn invalid_from_relay(relay: &Relay, id: &BlockId, e: &sbtp_core::Error) -> Fail {
    Fail::invalid(format!(
        "relay {} sent an invalid block for {id}: {} ({e}); nothing written",
        relay.base(),
        e.name()
    ))
}

/// Default polling interval of `query --follow`, in seconds.
const DEFAULT_FOLLOW_INTERVAL_S: u64 = 10;
/// Longest polling interval of `query --follow`, in seconds.
const MAX_FOLLOW_INTERVAL_S: u64 = 3600;

/// `query --relay <URL> [--parent <ID>] [--since <MS>] [--limit <N>] [--cursor <C>]
/// [--follow [--interval <S>]]`: walks `/query` with cursors (ADR 0012 rule 12) and prints each
/// `block_id` once.
pub fn query(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(
        args,
        &[
            ("relay", Kind::Value),
            ("parent", Kind::Value),
            ("since", Kind::Value),
            ("limit", Kind::Value),
            ("cursor", Kind::Value),
            ("follow", Kind::Switch),
            ("interval", Kind::Value),
        ],
    )?;
    p.positionals(0, "")?;
    let relay = Relay::new(
        p.text("relay")?
            .ok_or_else(|| Fail::usage("`--relay <URL>` is required"))?,
    )?;
    let (filter, cursor) = query_filter(&p)?;
    let follow = p.switch("follow");
    let interval = match p.number::<u64>("interval")? {
        Some(_) if !follow => return Err(Fail::usage("`--interval` needs `--follow`")),
        Some(s) if s == 0 || s > MAX_FOLLOW_INTERVAL_S => {
            return Err(Fail::usage(format!(
                "`--interval {s}`: give 1 to {MAX_FOLLOW_INTERVAL_S} seconds"
            )));
        }
        Some(s) => s,
        None => DEFAULT_FOLLOW_INTERVAL_S,
    };

    let mut walker = Walker::new(&relay, filter, cursor, Policy::default());
    let mut first = true;
    loop {
        let mut closed = false;
        let result = walker.walk(
            &mut std::thread::sleep,
            &mut walk::jitter_source,
            &mut |event| on_walk_event(&relay, event, &mut closed),
        );
        if closed {
            // The reader of standard output went away (`| head`): a normal end.
            return Ok(());
        }
        let summary = result.map_err(|mut fail| {
            if let Some(c) = walker.cursor() {
                // The cursor is within the rule 5 alphabet: safe to show as is.
                fail.message = format!("{}\nResume later with `--cursor {c}`.", fail.message);
            }
            fail
        })?;
        if first {
            let restarts = match summary.restarts {
                0 => String::new(),
                n => format!(", {n} restart(s) after InvalidCursor"),
            };
            eprintln!(
                "{} block_id(s) in {} page(s){restarts}.",
                summary.new_ids, summary.pages
            );
            if let Some(c) = walker.cursor() {
                eprintln!("cursor: {c}");
                if !follow {
                    eprintln!("Poll for blocks stored since with `--cursor {c}`.");
                }
            }
            first = false;
        }
        if !follow {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

/// The filters and starting cursor of `query`, checked.
fn query_filter(p: &Parsed) -> Result<(Filter, Option<String>), Fail> {
    let parent = p
        .text("parent")?
        .map(|t| {
            hex::block_id(t).ok_or_else(|| {
                Fail::usage(format!(
                    "`--parent {}`: expected a block_id of 64 hexadecimal characters",
                    untrusted(t, 80)
                ))
            })
        })
        .transpose()?;
    let since = p.number::<u64>("since")?;
    let limit = p.number::<u32>("limit")?;
    if limit == Some(0) {
        return Err(Fail::usage("`--limit` is at least 1"));
    }
    let cursor = p.text("cursor")?;
    if let Some(c) = cursor {
        // ADR 0012 rule 5: a value outside this syntax would get InvalidParameter (K1).
        if !walk::is_cursor_syntax(c) {
            return Err(Fail::usage(format!(
                "`--cursor {}`: a cursor is 1 to 128 characters of A-Z a-z 0-9 - _, copied \
                 from an earlier `query` of the same relay",
                untrusted(c, 40)
            )));
        }
    }
    Ok((
        Filter {
            parent,
            since,
            limit,
        },
        cursor.map(str::to_owned),
    ))
}

/// Prints one walk event: identifiers to standard output, notices to standard error.
fn on_walk_event(relay: &Relay, event: Event<'_>, closed: &mut bool) -> Result<(), Fail> {
    match event {
        Event::Id(id) => {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{id}")
                .and_then(|()| out.flush())
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        *closed = true;
                    }
                    Fail::failed(format!("cannot write to standard output: {e}"))
                })
        }
        Event::Restart { first_output } => {
            let dedup = if first_output {
                // The rejected cursor came from `--cursor` (security review 2026-11-19 query,
                // I-1): this run has printed nothing it could hide.
                "The listing starts again from the beginning: identifiers printed by earlier \
                 runs will be printed again."
            } else {
                "Identifiers already printed by this run are not printed again."
            };
            eprintln!(
                "Relay {} no longer recognises the cursor (InvalidCursor; it may have restarted \
                 after a crash): walking again from the start. {dedup}",
                relay.base()
            );
            Ok(())
        }
        Event::Wait {
            status,
            delay,
            retry_after,
        } => {
            let why = if retry_after { " (Retry-After)" } else { "" };
            eprintln!(
                "Relay {} answered {status}; keeping the cursor, retrying in {:.1} s{why}.",
                relay.base(),
                delay.as_secs_f64()
            );
            Ok(())
        }
    }
}

/// `info --relay <URL>`.
pub fn info(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("relay", Kind::Value)])?;
    p.positionals(0, "")?;
    let relay = Relay::new(
        p.text("relay")?
            .ok_or_else(|| Fail::usage("`--relay <URL>` is required"))?,
    )?;
    let info = relay.info()?;
    println!("min_pow_difficulty: {}", info.min_pow_difficulty);
    println!("max_future_ms:      {}", info.max_future_ms);
    Ok(())
}

/// The fields of a validated block, one per line. The payload is shown as escaped text (UTF-8)
/// or as hexadecimal, never as raw bytes.
fn print_summary(block: &BlockRef<'_>, id: &BlockId, difficulty: u32) {
    println!("block_id:   {id}");
    println!("valid:      yes (format, strict Ed25519 signature, proof of work >= {difficulty})");
    println!("pow:        {} leading zero bits", id.leading_zero_bits());
    println!("version:    {}", block.version());
    println!("timestamp:  {} ms", block.timestamp());
    println!("nonce:      {}", block.nonce());
    println!("pubkey:     {}", hex::encode(block.pubkey()));
    println!("parents:    {}", block.parents().len());
    for parent in block.parents() {
        println!("  - {parent}");
    }
    let payload = block.payload();
    println!("payload:    {} bytes", payload.len());
    if !payload.is_empty() {
        const PREVIEW: usize = 64;
        if let Ok(text) = std::str::from_utf8(payload) {
            println!("  text:     \"{}\"", untrusted(text, PREVIEW));
        } else {
            let head = payload
                .get(..PREVIEW.min(payload.len()))
                .unwrap_or_default();
            let more = if payload.len() > PREVIEW { "…" } else { "" };
            println!("  hex:      {}{more}", hex::encode(head));
        }
    }
}

/// Reads at most `max` bytes of `path`; refuses a longer file.
fn read_bounded(path: &Path, max: usize, what: &str) -> Result<Vec<u8>, Fail> {
    let file = File::open(path)
        .map_err(|e| Fail::failed(format!("cannot open {what} file {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Fail::failed(format!("cannot read {what} file {}: {e}", path.display())))?;
    if bytes.len() > max {
        return Err(Fail::failed(format!(
            "{what} file {} is longer than {max} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn now_ms() -> Result<u64, Fail> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Fail::failed("the system clock is before 1970; pass `--timestamp <MS>`"))?;
    u64::try_from(since.as_millis())
        .map_err(|_| Fail::failed("the system clock is out of range; pass `--timestamp <MS>`"))
}

fn build_fail(e: BuildError) -> Fail {
    match e {
        BuildError::TooManyParents { .. }
        | BuildError::DuplicateParent { .. }
        | BuildError::PayloadTooLong { .. }
        | BuildError::DifficultyTooHigh { .. } => {
            Fail::usage(format!("cannot build the block: {e}"))
        }
        BuildError::PowNotFound => Fail::failed(format!(
            "cannot mine the block: {e} within the attempt budget; lower the difficulty"
        )),
        _ => Fail::failed(format!("cannot build the block: {e}")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn build_mine_sign_through_core() {
        // Test key from a public seed.
        let key = sbtp_core::SigningKey::from_bytes(&[1u8; 32]);
        let mut block = BlockBuilder::for_key(&key)
            .payload(b"hello")
            .build_unsigned()
            .unwrap();
        let (_, id) = mine(&mut block, 8, DEFAULT_MAX_ATTEMPTS).unwrap();
        assert_eq!(sign_block(&mut block, &key).unwrap(), id);
        let parsed = sbtp_core::parse(&block).unwrap();
        assert_eq!(parsed.payload(), b"hello");
        assert!(validate_requested(&block, 8, &id).is_ok());
    }
}
