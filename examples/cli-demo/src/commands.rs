//! The subcommands. Every layer 0 operation goes through `sbtp-core`: building, mining, signing,
//! parsing and validating blocks.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sbtp_core::layout::{MAX_BLOCK_LEN, MAX_PAYLOAD_LEN};
use sbtp_core::{
    BlockBuilder, BlockId, BlockRef, BuildError, Requested, ValidatedBlock, default_max_attempts,
    mine, sign_block, validate_requested, validate_submitted,
};

use crate::args::{Kind, Parsed, parse as parse_args};
use crate::fail::{self, Fail, untrusted};
use crate::relay::{MAX_BATCH_IDS, READ_API, Relay, Stored};
use crate::walk::{self, Event, Filter, Policy, Walker};
use crate::{hex, keyfile, output};

/// Highest difficulty `mine` accepts from a relay's `/info` without `--difficulty`: about
/// 2^24 hashes, a few seconds. A relay announcing more is refused rather than obeyed
/// (`BlockBuilder` documents the same concern for hostile relays).
const MAX_RELAY_DIFFICULTY: u32 = 24;

/// Most relays one command uses (`--relay` repeated or a comma list). Every per-relay bound (request
/// deadline, body ceilings, walk) is multiplied by at most this.
const MAX_RELAYS: usize = 8;

/// The relays of `--relay`, repeated and/or comma-separated, in order, without duplicates (same
/// base URL). `None` when the option is absent.
fn relay_list(p: &Parsed) -> Result<Option<Vec<Relay>>, Fail> {
    let mut relays: Vec<Relay> = Vec::new();
    for value in p.values("relay") {
        let text = value
            .to_str()
            .ok_or_else(|| Fail::usage("`--relay`: the value is not UTF-8"))?;
        for url in text.split(',').map(str::trim) {
            if url.is_empty() {
                return Err(Fail::usage(
                    "`--relay`: an empty URL in the list (separate URLs with one comma)",
                ));
            }
            let relay = Relay::new(url)?;
            if !relays.iter().any(|r| r.base() == relay.base()) {
                relays.push(relay);
            }
        }
    }
    if relays.len() > MAX_RELAYS {
        return Err(Fail::usage(format!(
            "{} relays given; this client uses at most {MAX_RELAYS}",
            relays.len()
        )));
    }
    Ok(if relays.is_empty() {
        None
    } else {
        Some(relays)
    })
}

/// [`relay_list`], required.
fn required_relays(p: &Parsed) -> Result<Vec<Relay>, Fail> {
    relay_list(p)?.ok_or_else(|| Fail::usage("`--relay <URL>` is required"))
}

/// The failures of some relays, when the command still succeeds on others.
fn warn_all(failures: &[Fail]) {
    for f in failures {
        eprintln!("warning: {f}");
    }
}

/// One failure for several relays that all failed: every message, and an exit status that says
/// the most: 4 when a relay served an invalid block (a relay fault worth noticing), else the
/// status they share, else 1. With one relay, its failure unchanged.
fn all_failed(what: &str, mut failures: Vec<Fail>) -> Fail {
    if failures.len() == 1
        && let Some(only) = failures.pop()
    {
        return only;
    }
    let code = if failures.iter().any(|f| f.code == fail::EXIT_INVALID) {
        fail::EXIT_INVALID
    } else {
        match failures.first().map(|f| f.code) {
            Some(c) if failures.iter().all(|f| f.code == c) => c,
            _ => fail::EXIT_FAILURE,
        }
    };
    let mut message = format!("{what} on any relay:");
    for f in &failures {
        message.push_str("\n- ");
        message.push_str(&f.message.replace('\n', "\n  "));
    }
    Fail { code, message }
}

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
            ("relay", Kind::Repeated),
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
    let explicit = p.number::<u32>("difficulty")?;
    let difficulty = target_difficulty(explicit, relay_list(&p)?.as_deref())?;
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
    // An explicit `--difficulty` is the user's own choice: no attempt bound. A difficulty read from a
    // relay is bounded by the default budget (spec §4, "Client bounds"), which is counted in hashed
    // bytes so that the time bound does not depend on the block's size.
    let budget = if explicit.is_some() {
        u64::MAX
    } else {
        default_max_attempts(block.len())
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

/// The difficulty to mine at: `--difficulty`, or the relays' `min_pow_difficulty` (spec §4: a
/// sender SHOULD read `/info` before mining). With several relays the block is mined once, at the
/// highest difficulty among them; a relay asking for more than [`MAX_RELAY_DIFFICULTY`] is left out
/// (ADR 0029 rule 13: no mining for it), and a relay whose `/info` fails sets nothing. Refused when
/// no relay gives a usable difficulty. A difficulty read from relays is raised to the network
/// difficulty `D_NET` (ADR 0045 rule 5), so that the block can be copied to any relay of the
/// network; an explicit `--difficulty` is used as given.
fn target_difficulty(difficulty: Option<u32>, relays: Option<&[Relay]>) -> Result<u32, Fail> {
    match (difficulty, relays) {
        (Some(_), Some(_)) => Err(Fail::usage(
            "give `--difficulty` or `--relay`, not both (`--relay` reads the difficulty from the \
             relay's /sbtp/v1/info)",
        )),
        (Some(d), None) if d > sbtp_core::MAX_DIFFICULTY => Err(Fail::usage(format!(
            "`--difficulty {d}`: the maximum is {}",
            sbtp_core::MAX_DIFFICULTY
        ))),
        (Some(d), None) => Ok(d),
        (None, Some(relays)) => {
            let several = relays.len() > 1;
            let mut failures = Vec::new();
            let mut chosen: Option<u32> = None;
            for relay in relays {
                let d = match relay.info() {
                    Ok(info) => info.min_pow_difficulty,
                    Err(f) => {
                        failures.push(f);
                        continue;
                    }
                };
                eprintln!("Relay {} requires difficulty {d}.", relay.base());
                if d > MAX_RELAY_DIFFICULTY {
                    let f = Fail::refused(format!(
                        "relay {} requires difficulty {d}, above the {MAX_RELAY_DIFFICULTY} this \
                         CLI accepts from a relay; pass `--difficulty {d}` explicitly to mine anyway",
                        relay.base()
                    ));
                    failures.push(f);
                    continue;
                }
                chosen = Some(chosen.map_or(d, |c| c.max(d)));
            }
            match chosen {
                Some(d) => {
                    warn_all(&failures);
                    // ADR 0045 rule 5: never below `D_NET`. `D_NET` is below the cap of ADR 0029
                    // rule 13, which applies to the values read from relays.
                    let net = sbtp_core::NETWORK_POW_DIFFICULTY;
                    let mined = d.max(net);
                    if mined > d {
                        eprintln!(
                            "Mining at difficulty {mined}, the network difficulty, so that every \
                             relay of the network accepts the block."
                        );
                    } else if several {
                        eprintln!("Mining once at difficulty {d}, the highest of these relays.");
                    }
                    Ok(mined)
                }
                None => Err(all_failed("no usable difficulty", failures)),
            }
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

/// `publish --relay <URL>... <BLOCK_FILE>`: one `PUT` per relay, in parallel. The block is
/// published when at least one relay answered `200` or `201`.
pub fn publish(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("relay", Kind::Repeated)])?;
    let file = p.positionals(1, "<BLOCK_FILE>")?;
    let path = file.first().map_or(Path::new(""), Path::new);
    let relays = required_relays(&p)?;
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
    let outcomes: Vec<Result<Stored, Fail>> = std::thread::scope(|scope| {
        let handles: Vec<_> = relays
            .iter()
            .map(|relay| scope.spawn(|| relay.put_block(&bytes)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    Err(Fail::failed("internal error: a request thread panicked"))
                })
            })
            .collect()
    });
    let mut failures = Vec::new();
    let mut failed_on = Vec::new();
    for (relay, outcome) in relays.iter().zip(outcomes) {
        match outcome {
            Ok(Stored::Created) => {
                eprintln!("201 Created: relay {} stored the block.", relay.base());
            }
            Ok(Stored::AlreadyStored) => {
                eprintln!("200 OK: relay {} already held this block.", relay.base());
            }
            Err(f) => {
                failed_on.push(relay.base().to_owned());
                failures.push(f);
            }
        }
    }
    if failures.len() == relays.len() {
        return Err(all_failed("the block was not stored", failures));
    }
    warn_all(&failures);
    if !failed_on.is_empty() {
        eprintln!(
            "Published on {} of {} relays. To retry the others (PUT is idempotent): \
             cli-demo publish --relay {} {}",
            relays.len() - failed_on.len(),
            relays.len(),
            failed_on.join(","),
            path.display()
        );
    }
    println!("{id}");
    Ok(())
}

/// Most block ids one `get` takes.
const MAX_GET_IDS: usize = 1024;

/// A `<BLOCK_ID>` argument.
fn block_id_arg(arg: &std::ffi::OsStr) -> Result<BlockId, Fail> {
    let text = arg.to_str().unwrap_or_default();
    hex::block_id(text).ok_or_else(|| {
        Fail::usage(format!(
            "`{}`: expected a block_id of 64 hexadecimal characters",
            untrusted(text, 80)
        ))
    })
}

/// `get --relay <URL>... <BLOCK_ID>... [--out <FILE>] [--payload-out <FILE>] [--out-dir <DIR>]
/// [--difficulty <D>] [--force]`: asks the relays in order and keeps the first block that passes
/// the receipt rule. Several ids: see [`get_many`].
pub fn get(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(
        args,
        &[
            ("relay", Kind::Repeated),
            ("out", Kind::Value),
            ("payload-out", Kind::Value),
            ("out-dir", Kind::Value),
            ("difficulty", Kind::Value),
            ("force", Kind::Switch),
        ],
    )?;
    let positional = p.all_positionals();
    if positional.is_empty() {
        return Err(Fail::usage("missing argument <BLOCK_ID>"));
    }
    if positional.len() > MAX_GET_IDS {
        return Err(Fail::usage(format!(
            "{} block ids given; `get` takes at most {MAX_GET_IDS}",
            positional.len()
        )));
    }
    let mut ids: Vec<BlockId> = Vec::with_capacity(positional.len());
    for arg in positional {
        let id = block_id_arg(arg)?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let relays = required_relays(&p)?;
    // ADR 0026 rules 1 to 3: a local floor, 0 by default, never taken from the relay's /info.
    let difficulty = p.number::<u32>("difficulty")?.unwrap_or(0);
    if difficulty > sbtp_core::MAX_DIFFICULTY {
        return Err(Fail::usage(format!(
            "`--difficulty {difficulty}`: the maximum is {}",
            sbtp_core::MAX_DIFFICULTY
        )));
    }
    let [id] = ids[..] else {
        return get_many(&p, &relays, &ids, difficulty);
    };
    if p.value("out-dir").is_some() {
        return get_many(&p, &relays, &ids, difficulty);
    }
    let several = relays.len() > 1;
    let mut failures = Vec::new();
    // Failover: a 404, a failed request, a refusal or an invalid block moves on to the next relay.
    // No relay is trusted: each answer goes through the receipt rule.
    for relay in &relays {
        let bytes = match relay.get_block(&id) {
            Ok(bytes) => bytes,
            Err(f) => {
                failures.push(f);
                continue;
            }
        };
        // spec §3.4 "Receipt": recompute the block_id, compare with the requested one (R1), then
        // full validation (F1 to F9, C1 with the recipient's own difficulty, C2, C3) before any
        // storage or use.
        match validate_requested(&bytes, difficulty, &id) {
            Ok(validated) => {
                warn_all(&failures);
                if several {
                    eprintln!("Served by relay {}.", relay.base());
                }
                return write_fetched(&p, &bytes, &validated, difficulty);
            }
            Err(e) => {
                let (f, local_floor) = receipt_fail(relay, &id, &bytes, &e);
                // The PoW of a block is a property of its block_id: every relay would fail the
                // local floor the same way, so none is asked further.
                if local_floor {
                    return Err(f);
                }
                failures.push(f);
            }
        }
    }
    Err(all_failed(
        &format!("no valid block {id} was served"),
        failures,
    ))
}

/// The outputs of `get` for a block that passed the receipt rule: both files or neither (security
/// review 2026-11-19, L-3), then the summary.
fn write_fetched(
    p: &Parsed,
    bytes: &[u8],
    validated: &ValidatedBlock<'_, Requested>,
    difficulty: u32,
) -> Result<(), Fail> {
    let out = p.path("out");
    let payload_out = p.path("payload-out");
    let mut files: Vec<(&Path, &[u8])> = Vec::new();
    if let Some(path) = &out {
        files.push((path, bytes));
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
/// the block is checked again at `d = 0` to tell the two cases apart. The flag is true for the
/// local floor.
fn receipt_fail(relay: &Relay, id: &BlockId, bytes: &[u8], e: &sbtp_core::Error) -> (Fail, bool) {
    if let sbtp_core::Error::InsufficientPow { required, actual } = *e {
        match validate_requested(bytes, 0, id) {
            Ok(_) => {
                let f = Fail::invalid(format!(
                    "the block {id} from relay {} is valid, but below the local floor: its \
                     block_id has {actual} leading zero bits, `--difficulty {required}` asks for \
                     at least {required}. This is this client's policy, not a fault of the \
                     relay. Nothing written.",
                    relay.base()
                ));
                return (f, true);
            }
            Err(other) => return (invalid_from_relay(relay, id, &other), false),
        }
    }
    (invalid_from_relay(relay, id, e), false)
}

/// One block of `get_many` and what the relays asked so far answered for it.
struct Wanted {
    id: BlockId,
    /// Bytes that passed the receipt rule (spec §3.4) for `id`.
    bytes: Option<Vec<u8>>,
    /// Below the local floor: no other relay is asked (its PoW is a property of its `block_id`).
    refused: Option<Fail>,
    /// One message per relay that did not serve it.
    tried: Vec<String>,
    /// A relay served bytes that failed validation for it.
    invalid: bool,
}

impl Wanted {
    fn pending(&self) -> bool {
        self.bytes.is_none() && self.refused.is_none()
    }

    /// The receipt rule on bytes a relay served for this block (spec §3.4: R1 against the id
    /// asked, then full validation at the local floor).
    fn receive(&mut self, relay: &Relay, bytes: Vec<u8>, difficulty: u32) {
        match validate_requested(&bytes, difficulty, &self.id) {
            Ok(_) => self.bytes = Some(bytes),
            Err(e) => {
                let (f, local_floor) = receipt_fail(relay, &self.id, &bytes, &e);
                if local_floor {
                    self.refused = Some(f);
                } else {
                    self.invalid = true;
                    self.tried.push(f.message);
                }
            }
        }
    }
}

/// `get` with several block ids (or `--out-dir`): the relays are asked in order for the blocks
/// still missing. A relay whose `/info` says `read_api >= 2` gets batches of 256 identifiers
/// (`POST /sbtp/v1/blocks`, ADR 0051); every other relay, or one whose `/info` fails, gets one
/// `GET /sbtp/v1/block` per block, as with one id. Each block is checked against the id asked
/// (R1) and fully validated, whatever relay served it. The blocks fetched are printed (and written
/// to `--out-dir`); the command fails if one is missing.
fn get_many(p: &Parsed, relays: &[Relay], ids: &[BlockId], difficulty: u32) -> Result<(), Fail> {
    if p.value("out").is_some() || p.value("payload-out").is_some() {
        return Err(Fail::usage(
            "with several block ids, give `--out-dir <DIR>` (one <BLOCK_ID>.sbtp file per block); \
             `--out` and `--payload-out` take one block",
        ));
    }
    let mut wanted: Vec<Wanted> = ids
        .iter()
        .map(|id| Wanted {
            id: *id,
            bytes: None,
            refused: None,
            tried: Vec::new(),
            invalid: false,
        })
        .collect();
    for relay in relays {
        let pending: Vec<usize> = (0..wanted.len())
            .filter(|i| wanted.get(*i).is_some_and(Wanted::pending))
            .collect();
        if pending.is_empty() {
            break;
        }
        // ADR 0051 rule 31: a batch only to a relay that announces read_api 2.
        let batch = relay.info().is_ok_and(|i| i.read_api >= READ_API);
        if batch {
            batch_from(relay, &mut wanted, &pending, difficulty);
        } else {
            for i in pending {
                let Some(w) = wanted.get_mut(i) else { continue };
                match relay.get_block(&w.id) {
                    Ok(bytes) => w.receive(relay, bytes, difficulty),
                    Err(f) => w.tried.push(f.message),
                }
            }
        }
        let served = wanted.iter().filter(|w| w.bytes.is_some()).count();
        if relays.len() > 1 {
            eprintln!(
                "Relay {} asked ({}); {served} of {} block(s) fetched so far.",
                relay.base(),
                if batch {
                    "POST /sbtp/v1/blocks"
                } else {
                    "GET /sbtp/v1/block"
                },
                wanted.len()
            );
        }
    }

    let fetched: Vec<(&BlockId, &[u8])> = wanted
        .iter()
        .filter_map(|w| w.bytes.as_deref().map(|b| (&w.id, b)))
        .collect();
    if let Some(dir) = p.path("out-dir") {
        let paths: Vec<std::path::PathBuf> = fetched
            .iter()
            .map(|(id, _)| dir.join(format!("{id}.sbtp")))
            .collect();
        let files: Vec<(&Path, &[u8])> = paths
            .iter()
            .zip(&fetched)
            .map(|(path, (_, b))| (path.as_path(), *b))
            .collect();
        output::write_all(&files, p.switch("force"))?;
        eprintln!("{} block(s) written to {}.", files.len(), dir.display());
    }
    for (n, (id, bytes)) in fetched.iter().enumerate() {
        if n > 0 {
            println!();
        }
        if let Ok(v) = validate_requested(bytes, difficulty, id) {
            print_summary(v.block(), v.block_id(), difficulty);
        }
    }
    let missing: Vec<&Wanted> = wanted.iter().filter(|w| w.bytes.is_none()).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "{} of {} block(s) not fetched:",
        missing.len(),
        wanted.len()
    );
    for w in &missing {
        let _ = write!(message, "\n- {}:", w.id);
        if let Some(f) = &w.refused {
            let _ = write!(message, "\n  {}", f.message.replace('\n', "\n  "));
        }
        for t in &w.tried {
            let _ = write!(message, "\n  {}", t.replace('\n', "\n  "));
        }
    }
    let code = if missing.iter().any(|w| w.invalid || w.refused.is_some()) {
        fail::EXIT_INVALID
    } else {
        fail::EXIT_FAILURE
    };
    Err(Fail { code, message })
}

/// Asks `relay` (`read_api >= 2`) for the blocks at `pending` with `POST /sbtp/v1/blocks`, 256 at
/// most per request. A record of length 0: not served by this relay. A prefix (ADR 0051 rule 3):
/// the rest is asked again (each `200` holds at least one record, so this ends). A failed request,
/// a body over 1 MiB, a record above `MAX_BLOCK_LEN` or a body ending inside a record ends this
/// relay: the blocks not answered go to the next one; complete records before a truncation are used.
fn batch_from(relay: &Relay, wanted: &mut [Wanted], pending: &[usize], difficulty: u32) {
    for chunk in pending.chunks(MAX_BATCH_IDS) {
        let mut rest: &[usize] = chunk;
        while !rest.is_empty() {
            let ask: Vec<BlockId> = rest
                .iter()
                .filter_map(|i| wanted.get(*i).map(|w| w.id))
                .collect();
            let failed = |wanted: &mut [Wanted], rest: &[usize], why: &str| {
                for i in rest {
                    if let Some(w) = wanted.get_mut(*i) {
                        w.tried.push(why.to_owned());
                    }
                }
            };
            match relay.post_blocks(&ask) {
                Err(f) => {
                    failed(wanted, rest, &f.message);
                    return;
                }
                Ok(batch) => {
                    let n = batch.records.len();
                    for (i, record) in rest.iter().zip(batch.records) {
                        let Some(w) = wanted.get_mut(*i) else {
                            continue;
                        };
                        match record {
                            None => w.tried.push(format!(
                                "relay {} does not serve it (length 0 in POST /sbtp/v1/blocks); \
                                 it may have evicted it",
                                relay.base()
                            )),
                            Some(bytes) => w.receive(relay, bytes, difficulty),
                        }
                    }
                    rest = rest.get(n..).unwrap_or_default();
                    if batch.truncated {
                        failed(
                            wanted,
                            rest,
                            &format!(
                                "relay {} sent a POST /sbtp/v1/blocks body that ends inside a \
                                 record (a failed request)",
                                relay.base()
                            ),
                        );
                        return;
                    }
                }
            }
        }
    }
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

/// `query --relay <URL>... [--parent <ID>] [--since <MS>] [--limit <N>] [--cursor <C>]...
/// [--follow [--interval <S>]]`: walks `/query` with cursors (ADR 0012 rule 12) on each relay, one
/// after the other, each with its own cursor, and prints each `block_id` once over all of them.
pub fn query(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(
        args,
        &[
            ("relay", Kind::Repeated),
            ("parent", Kind::Repeated),
            ("since", Kind::Value),
            ("limit", Kind::Value),
            ("cursor", Kind::Repeated),
            ("follow", Kind::Switch),
            ("interval", Kind::Value),
            ("desc", Kind::Switch),
            ("fields", Kind::Value),
        ],
    )?;
    p.positionals(0, "")?;
    let relays = required_relays(&p)?;
    let parents = query_parents(&p, relays.len())?;
    let filter = query_options(&p, &parents)?;
    if parents.len() > 1 {
        return query_grouped(&relays, &parents, &filter);
    }
    query_walk(&p, &relays, &filter)
}

/// The filter of `query`, after the checks of the options of ADR 0051 (`--desc`, `--fields`,
/// several `--parent`) against each other and against `--follow` and `--cursor`. With several
/// parents the filter has no `parent`: they are listed by [`query_grouped`].
fn query_options(p: &Parsed, parents: &[(BlockId, Option<String>)]) -> Result<Filter, Fail> {
    let desc = p.switch("desc");
    let fields = match p.text("fields")? {
        None => false,
        Some("parents") => true,
        Some(other) => {
            return Err(Fail::usage(format!(
                "`--fields {}`: the only value is `parents`",
                untrusted(other, 40)
            )));
        }
    };
    if fields && !parents.is_empty() {
        return Err(Fail::usage(
            "`--fields parents` lists relay-wide only: it is not combined with `--parent` (ADR \
             0051 rule 14)",
        ));
    }
    if p.switch("follow") && (desc || parents.len() > 1) {
        return Err(Fail::usage(
            "`--follow` polls one ascending listing: it is not combined with `--desc` or several \
             `--parent`. Poll later with the `head` printed (`--cursor <HEAD>`)",
        ));
    }
    if parents.len() > 1 {
        if !p.values("cursor").is_empty() {
            return Err(Fail::usage(
                "with several `--parent`, give each parent's cursor as `--parent <ID>.<CURSOR>`, \
                 as printed by an earlier `query`",
            ));
        }
        return query_filter(p, None, desc, false);
    }
    if let Some((_, Some(_))) = parents.first() {
        return Err(Fail::usage(
            "`--parent <ID>.<CURSOR>` is for several parents; with one, give `--cursor <CURSOR>`",
        ));
    }
    query_filter(p, parents.first().map(|(id, _)| *id), desc, fields)
}

/// `query` with at most one `--parent`: one walk per relay, each with its own cursor.
fn query_walk(p: &Parsed, relays: &[Relay], filter: &Filter) -> Result<(), Fail> {
    let cursors = query_cursors(p, relays)?;
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

    let several = relays.len() > 1;
    // The deduplication bound is shared: what this process remembers does not grow with the number
    // of relays. Each walker keeps its own set (its restarts and its no-progress check are its own);
    // `printed` deduplicates across relays and is not needed for one.
    let policy = Policy {
        max_seen: (walk::MAX_SEEN / relays.len()).max(1),
        ..Policy::default()
    };
    let mut walkers: Vec<Walker<&Relay>> = relays
        .iter()
        .zip(cursors)
        .map(|(relay, cursor)| Walker::new(relay, filter.clone(), cursor, policy))
        .collect();
    let mut printed: Option<Printed> = several.then(|| Printed::new(walk::MAX_SEEN));
    // A walk that failed is terminal for its relay (a fatal refusal, a Retry-After above the
    // maximum, no progress, the dedupe bound): that relay is not asked again in this run, so that
    // `--follow` never repeats a request early and the dedupe sets stop growing (security review
    // 2026-11-21, M-1). The command ends when every relay is retired.
    let mut retired = vec![false; relays.len()];
    let mut retired_failures = Vec::new();
    if filter.needs_read_api() {
        retire_without_read_api(relays, &mut retired, &mut retired_failures)?;
    }
    let mut first = true;
    loop {
        let mut failures = Vec::new();
        for i in 0..relays.len() {
            let (Some(relay), Some(walker)) = (relays.get(i), walkers.get_mut(i)) else {
                continue;
            };
            if retired.get(i).copied().unwrap_or(true) {
                continue;
            }
            let mut closed = false;
            let result = walker.walk(
                &mut std::thread::sleep,
                &mut walk::jitter_source,
                &mut |event| on_walk_event(relay, event, printed.as_mut(), &mut closed),
            );
            if closed {
                // The reader of standard output went away (`| head`): a normal end.
                return Ok(());
            }
            match result {
                Ok(summary) if first => walk_summary(relay, several, &summary),
                Ok(_) => {}
                Err(fail) if printed.as_ref().is_some_and(|p| p.full) => {
                    // The bound over all relays: the whole command stops, with every cursor.
                    print_cursors(relays, &walkers, false);
                    return Err(fail);
                }
                Err(mut fail) => {
                    resume_hint(&mut fail, relay, walker.cursor(), several, follow);
                    if let Some(r) = retired.get_mut(i) {
                        *r = true;
                    }
                    failures.push(Fail {
                        code: fail.code,
                        message: fail.message.clone(),
                    });
                    retired_failures.push(fail);
                }
            }
        }
        if retired.iter().all(|r| *r) {
            return Err(all_failed("the listing failed", retired_failures));
        }
        warn_all(&failures);
        if first {
            print_cursors(relays, &walkers, follow);
            first = false;
        }
        if !follow {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

/// The counts of a relay's first walk, on standard error.
fn walk_summary(relay: &Relay, several: bool, summary: &walk::Summary) {
    let restarts = match summary.restarts {
        0 => String::new(),
        n => format!(", {n} restart(s) after InvalidCursor"),
    };
    let from = if several {
        format!("relay {}: ", relay.base())
    } else {
        String::new()
    };
    eprintln!(
        "{from}{} block_id(s) in {} page(s){restarts}.",
        summary.new_ids, summary.pages
    );
}

/// Adds to the failure of a relay's walk the cursor to resume from and, under `--follow` with
/// several relays, that the relay is retired.
fn resume_hint(fail: &mut Fail, relay: &Relay, cursor: Option<&str>, several: bool, follow: bool) {
    if let Some(c) = cursor {
        // The cursor is within the rule 5 alphabet: safe to show as is.
        let resume = if several {
            format!("{}={c}", relay.base())
        } else {
            c.to_owned()
        };
        fail.message = format!("{}\nResume later with `--cursor {resume}`.", fail.message);
    }
    if follow && several {
        fail.message
            .push_str("\nThis relay is not polled again in this run.");
    }
}

/// The `block_id`s printed by one `query` over several relays, with a bound of their own: what this
/// process remembers does not depend on what the relays send (spec §4 "Client bounds"; security
/// review 2026-11-21, M-1).
struct Printed {
    seen: HashSet<BlockId>,
    max: usize,
    /// The bound was reached: the command stops.
    full: bool,
}

impl Printed {
    fn new(max: usize) -> Self {
        Self {
            seen: HashSet::new(),
            max,
            full: false,
        }
    }

    /// Whether `id` is new, to be printed. Past `max` distinct identifiers, an error that ends the
    /// command.
    fn admit(&mut self, id: &BlockId) -> Result<bool, Fail> {
        if self.seen.contains(id) {
            return Ok(false);
        }
        if self.seen.len() >= self.max {
            self.full = true;
            return Err(Fail::failed(format!(
                "more than {} distinct block_ids over all relays in one run, the most this client \
                 remembers to avoid printing one twice; narrow the listing with `--parent` or \
                 `--since`",
                self.max
            )));
        }
        self.seen.insert(*id);
        Ok(true)
    }
}

/// The cursors to resume from, on standard error. With several relays each is tied to its relay:
/// `<RELAY_URL>=<CURSOR>`, so that a cursor is never sent to a relay that did not issue it.
///
/// With `--desc` (ADR 0051 rules 16 to 19) the cursor continues the newest-first listing further
/// back (with `--desc --cursor`), and `head` is printed too: an ascending poll from it lists
/// exactly the blocks stored since the walk began, so it is the one offered for polling.
fn print_cursors(relays: &[Relay], walkers: &[Walker<&Relay>], follow: bool) {
    let poll_from = |w: &Walker<&Relay>| -> Option<String> {
        if w.is_desc() {
            w.head().map(str::to_owned)
        } else {
            w.cursor().map(str::to_owned)
        }
    };
    if let [_] = relays {
        let Some(walker) = walkers.first() else {
            return;
        };
        if let Some(c) = walker.cursor() {
            eprintln!("cursor: {c}");
        }
        if walker.is_desc()
            && let Some(h) = walker.head()
        {
            eprintln!("head: {h}");
        }
        if let (Some(c), false) = (poll_from(walker), follow) {
            eprintln!("Poll for blocks stored since with `--cursor {c}`.");
        }
        return;
    }
    let mut resume = Vec::new();
    for (relay, walker) in relays.iter().zip(walkers) {
        if let Some(c) = walker.cursor() {
            eprintln!("cursor: {}={c}", relay.base());
        }
        if walker.is_desc()
            && let Some(h) = walker.head()
        {
            eprintln!("head: {}={h}", relay.base());
        }
        if let Some(c) = poll_from(walker) {
            resume.push(format!("--cursor {}={c}", relay.base()));
        }
    }
    if !follow && !resume.is_empty() {
        eprintln!(
            "Poll for blocks stored since with the same --relay list and {}.",
            resume.join(" ")
        );
    }
}

/// `query --parent` given 2 to 32 times (ADR 0051 rules 21 to 29), on each relay in turn.
///
/// - A relay whose `/info` says `read_api >= 2`: grouped requests, each parent with its own
///   cursor (`--parent <ID>.<CURSOR>`), until every listing ends with `more = false`.
/// - Any other relay: one plain walk per parent, as before; `--desc` cannot be honoured there and
///   the relay is skipped with a warning.
///
/// Standard output: `<PARENT> <CHILD>`, one per line, each pair once over all relays. Standard
/// error: per parent, whether its listing is complete on that relay (rule 28; only a complete
/// listing says that a block is absent, rule 29) and its cursor as `cursor: <ID>.<CURSOR>`; then
/// `head` for the grouped relays.
fn query_grouped(
    relays: &[Relay],
    parents: &[(BlockId, Option<String>)],
    filter: &Filter,
) -> Result<(), Fail> {
    let several = relays.len() > 1;
    let policy = Policy {
        max_seen: (walk::MAX_SEEN / relays.len()).max(1),
        ..Policy::default()
    };
    let mut printed: HashSet<(BlockId, BlockId)> = HashSet::new();
    let mut failures = Vec::new();
    let mut served = 0usize;
    for relay in relays {
        let grouped = match relay.info() {
            Ok(info) => info.read_api >= READ_API,
            Err(f) => {
                failures.push(f);
                continue;
            }
        };
        if !grouped && filter.desc {
            failures.push(read_api_fail(relay, "`--desc`"));
            continue;
        }
        let mut closed = false;
        let (result, listings, head) = walk_parents(
            relay,
            grouped,
            parents,
            filter,
            policy,
            &mut printed,
            &mut closed,
        );
        if closed {
            return Ok(());
        }
        print_listings(relay, several, &listings, head.as_deref());
        match result {
            Ok(()) => served = served.saturating_add(1),
            Err(f) => failures.push(f),
        }
    }
    if served == 0 {
        return Err(all_failed("the listing failed", failures));
    }
    warn_all(&failures);
    if !several {
        eprintln!(
            "Continue each listing with the `--parent <ID>.<CURSOR>` values above; poll for new \
             children of every parent with `--parent <ID>.<HEAD>`."
        );
    }
    Ok(())
}

/// The listing of one parent on one relay, for the summary of `query` with several `--parent`.
struct ParentSummary {
    parent: BlockId,
    cursor: Option<String>,
    complete: bool,
    emitted: u64,
}

/// Prints `<PARENT> <CHILD>` once per run (`printed`, bounded by `MAX_SEEN` pairs).
fn print_pair(
    printed: &mut HashSet<(BlockId, BlockId)>,
    parent: &BlockId,
    id: &BlockId,
    closed: &mut bool,
) -> Result<(), Fail> {
    if printed.contains(&(*parent, *id)) {
        return Ok(());
    }
    if printed.len() >= walk::MAX_SEEN {
        return Err(Fail::failed(format!(
            "more than {} distinct parent and child pairs in one run",
            walk::MAX_SEEN
        )));
    }
    printed.insert((*parent, *id));
    let mut out = std::io::stdout().lock();
    writeln!(out, "{parent} {id}")
        .and_then(|()| out.flush())
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                *closed = true;
            }
            Fail::failed(format!("cannot write to standard output: {e}"))
        })
}

/// Lists `parents` on `relay`: grouped requests when it has the read API (`grouped`), else one
/// plain ascending walk per parent, exactly as with one parent. Returns the outcome, one summary
/// per parent reached, and the grouped walk's `head`.
fn walk_parents(
    relay: &Relay,
    grouped: bool,
    parents: &[(BlockId, Option<String>)],
    filter: &Filter,
    policy: Policy,
    printed: &mut HashSet<(BlockId, BlockId)>,
    closed: &mut bool,
) -> (Result<(), Fail>, Vec<ParentSummary>, Option<String>) {
    if grouped {
        let mut gw = walk::GroupWalker::new(relay, filter.clone(), parents.to_vec(), policy);
        let r = gw.walk(
            &mut std::thread::sleep,
            &mut walk::jitter_source,
            &mut |event| match event {
                walk::GroupEvent::Child { parent, id } => print_pair(printed, parent, id, closed),
                walk::GroupEvent::Restart => {
                    eprintln!(
                        "Relay {} no longer recognises the cursors (InvalidCursor): listing every \
                         parent again from the start.",
                        relay.base()
                    );
                    Ok(())
                }
                walk::GroupEvent::Wait { status, delay, .. } => {
                    eprintln!(
                        "Relay {} answered {status}; retrying in {:.1} s.",
                        relay.base(),
                        delay.as_secs_f64()
                    );
                    Ok(())
                }
            },
        );
        let listings = gw
            .listings()
            .iter()
            .map(|l| ParentSummary {
                parent: l.parent,
                cursor: l.cursor.clone(),
                complete: l.complete,
                emitted: l.emitted,
            })
            .collect();
        return (r.map(|_| ()), listings, gw.head().map(str::to_owned));
    }
    let mut listings = Vec::new();
    for (parent, cursor) in parents {
        let single = Filter {
            parent: Some(*parent),
            ..filter.clone()
        };
        let mut walker = Walker::new(relay, single, cursor.clone(), policy);
        let mut emitted = 0u64;
        let w = walker.walk(
            &mut std::thread::sleep,
            &mut walk::jitter_source,
            &mut |event| match event {
                Event::Id(id, _) => {
                    emitted = emitted.saturating_add(1);
                    print_pair(printed, parent, id, closed)
                }
                other => on_walk_event(relay, other, None, closed),
            },
        );
        listings.push(ParentSummary {
            parent: *parent,
            cursor: walker.cursor().map(str::to_owned),
            complete: w.is_ok(),
            emitted,
        });
        if let Err(f) = w {
            return (Err(f), listings, None);
        }
    }
    (Ok(()), listings, None)
}

/// Per parent: its count, whether its listing is complete (ADR 0051 rule 28) and its cursor as
/// `<ID>.<CURSOR>`; then `head`. Prefixed by the relay with several relays.
fn print_listings(relay: &Relay, several: bool, listings: &[ParentSummary], head: Option<&str>) {
    let (from, tag) = if several {
        (
            format!("relay {}: ", relay.base()),
            format!("{}=", relay.base()),
        )
    } else {
        (String::new(), String::new())
    };
    for l in listings {
        let state = if l.complete {
            "complete"
        } else {
            "INCOMPLETE: do not derive the absence of a block from it"
        };
        eprintln!(
            "{from}parent {}: {} child(ren), {state}.",
            l.parent, l.emitted
        );
        if let Some(c) = &l.cursor {
            eprintln!("cursor: {tag}{}.{c}", l.parent);
        }
    }
    if let Some(h) = head {
        eprintln!("head: {tag}{h}");
    }
}

/// ADR 0051 rule 31: `order` and `fields` go only to a relay that announces `read_api` 2. Any other
/// relay is retired from this run, with a warning; the command fails when none is left.
fn retire_without_read_api(
    relays: &[Relay],
    retired: &mut [bool],
    retired_failures: &mut Vec<Fail>,
) -> Result<(), Fail> {
    let mut skipped = Vec::new();
    for (i, relay) in relays.iter().enumerate() {
        if let Err(fail) = require_read_api(relay, "`--desc` and `--fields`") {
            if let Some(r) = retired.get_mut(i) {
                *r = true;
            }
            skipped.push(Fail {
                code: fail.code,
                message: fail.message.clone(),
            });
            retired_failures.push(fail);
        }
    }
    if retired.iter().all(|r| *r) {
        return Err(all_failed(
            "the listing failed",
            std::mem::take(retired_failures),
        ));
    }
    warn_all(&skipped);
    Ok(())
}

/// The failure for a relay that does not announce `read_api >= 2` (ADR 0051 rule 31).
fn read_api_fail(relay: &Relay, what: &str) -> Fail {
    Fail::refused(format!(
        "relay {} does not announce read_api 2 in /sbtp/v1/info (ADR 0051): {what} need it; \
         not asked",
        relay.base()
    ))
}

/// `Ok` when `relay`'s `/info` says `read_api >= 2`; the failure otherwise.
fn require_read_api(relay: &Relay, what: &str) -> Result<(), Fail> {
    if relay.info()?.read_api >= READ_API {
        Ok(())
    } else {
        Err(read_api_fail(relay, what))
    }
}

/// The `--parent` values of `query`: 1 to 32 distinct block ids, each `<ID>` or `<ID>.<CURSOR>`
/// (ADR 0051 rule 21). A per-parent cursor is only accepted with one relay: a cursor belongs to
/// the relay that issued it.
fn query_parents(p: &Parsed, relays: usize) -> Result<Vec<(BlockId, Option<String>)>, Fail> {
    let values = p.values("parent");
    if values.len() > walk::MAX_PARENTS {
        return Err(Fail::usage(format!(
            "{} `--parent` given; one request takes at most {} (ADR 0051 rule 21)",
            values.len(),
            walk::MAX_PARENTS
        )));
    }
    let mut out: Vec<(BlockId, Option<String>)> = Vec::new();
    for v in values {
        let t = v
            .to_str()
            .ok_or_else(|| Fail::usage("`--parent`: the value is not UTF-8"))?;
        let (id_text, cursor) = match t.split_once('.') {
            Some((i, c)) => (i, Some(checked_cursor(c)?.to_owned())),
            None => (t, None),
        };
        let id = hex::block_id(id_text).ok_or_else(|| {
            Fail::usage(format!(
                "`--parent {}`: expected a block_id of 64 hexadecimal characters, optionally \
                 followed by `.<CURSOR>`",
                untrusted(t, 80)
            ))
        })?;
        if out.iter().any(|(o, _)| *o == id) {
            return Err(Fail::usage(format!("`--parent {id}` given twice")));
        }
        if cursor.is_some() && relays > 1 {
            return Err(Fail::usage(
                "`--parent <ID>.<CURSOR>` takes one relay: a cursor is only valid on the relay \
                 that issued it",
            ));
        }
        out.push((id, cursor));
    }
    Ok(out)
}

/// The starting cursor of each relay, in the order of `relays`. With one relay `--cursor <C>` (at
/// most once); with several, each `--cursor <RELAY_URL>=<CURSOR>` names its relay, since a cursor
/// is only valid on the relay that issued it (ADR 0012, ADR 0024).
fn query_cursors(p: &Parsed, relays: &[Relay]) -> Result<Vec<Option<String>>, Fail> {
    let values = p.values("cursor");
    let mut cursors: Vec<Option<String>> = vec![None; relays.len()];
    if relays.len() == 1 {
        if values.len() > 1 {
            return Err(Fail::usage("`--cursor` given more than once"));
        }
        if let (Some(v), Some(slot)) = (values.first(), cursors.first_mut()) {
            *slot = Some(checked_cursor(text(v)?)?.to_owned());
        }
        return Ok(cursors);
    }
    for v in values {
        let v = text(v)?;
        let Some((url, cursor)) = v.rsplit_once('=') else {
            return Err(Fail::usage(format!(
                "`--cursor {}`: with several relays, give `--cursor <RELAY_URL>=<CURSOR>`, as \
                 printed by an earlier `query`",
                untrusted(v, 60)
            )));
        };
        let base = Relay::new(url)?;
        let Some(i) = relays.iter().position(|r| r.base() == base.base()) else {
            return Err(Fail::usage(format!(
                "`--cursor`: relay {} is not in the --relay list",
                untrusted(url, 100)
            )));
        };
        let slot = cursors
            .get_mut(i)
            .ok_or_else(|| Fail::failed("internal error: relay index"))?;
        if slot.is_some() {
            return Err(Fail::usage(format!(
                "`--cursor`: two cursors for relay {}",
                base.base()
            )));
        }
        *slot = Some(checked_cursor(cursor)?.to_owned());
    }
    Ok(cursors)
}

/// A `--cursor` value as text.
fn text(v: &std::ffi::OsStr) -> Result<&str, Fail> {
    v.to_str()
        .ok_or_else(|| Fail::usage("`--cursor`: the value is not UTF-8"))
}

/// A `--cursor` value within the syntax of ADR 0012 rule 5: a value outside it would get
/// `InvalidParameter` (K1).
fn checked_cursor(c: &str) -> Result<&str, Fail> {
    if walk::is_cursor_syntax(c) {
        Ok(c)
    } else {
        Err(Fail::usage(format!(
            "`--cursor {}`: a cursor is 1 to 128 characters of A-Z a-z 0-9 - _, copied from an \
             earlier `query` of the same relay",
            untrusted(c, 40)
        )))
    }
}

/// The filters of `query`, checked.
fn query_filter(
    p: &Parsed,
    parent: Option<BlockId>,
    desc: bool,
    fields: bool,
) -> Result<Filter, Fail> {
    let since = p.number::<u64>("since")?;
    let limit = p.number::<u32>("limit")?;
    if limit == Some(0) {
        return Err(Fail::usage("`--limit` is at least 1"));
    }
    Ok(Filter {
        parent,
        since,
        limit,
        desc,
        fields,
    })
}

/// Prints one walk event: identifiers to standard output, notices to standard error. `printed`
/// deduplicates across relays (`None` with one relay: the walker already does).
fn on_walk_event(
    relay: &Relay,
    event: Event<'_>,
    printed: Option<&mut Printed>,
    closed: &mut bool,
) -> Result<(), Fail> {
    match event {
        Event::Id(id, hint) => {
            // spec §4 `/query`: a client MUST deduplicate by block_id, over every relay it reads.
            if let Some(set) = printed
                && !set.admit(id)?
            {
                return Ok(());
            }
            // `fields=parents` (ADR 0051 rule 13): the length and parents from the relay's
            // index, hints only until the block is fetched and verified.
            let line = match hint {
                None => id.to_string(),
                Some(h) => {
                    let parents: Vec<String> = h.parents.iter().map(BlockId::to_string).collect();
                    format!("{id} len={} parents={}", h.len, parents.join(","))
                }
            };
            let mut out = std::io::stdout().lock();
            writeln!(out, "{line}")
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

/// `info --relay <URL>...`.
pub fn info(args: &[OsString]) -> Result<(), Fail> {
    let p = parse_args(args, &[("relay", Kind::Repeated)])?;
    p.positionals(0, "")?;
    let relays = required_relays(&p)?;
    let several = relays.len() > 1;
    let mut failures = Vec::new();
    for relay in &relays {
        match relay.info() {
            Ok(info) => {
                if several {
                    println!("relay:              {}", relay.base());
                }
                println!("min_pow_difficulty: {}", info.min_pow_difficulty);
                println!("max_future_ms:      {}", info.max_future_ms);
            }
            Err(f) => {
                failures.push(f);
            }
        }
    }
    if failures.len() == relays.len() {
        return Err(all_failed("/info failed", failures));
    }
    warn_all(&failures);
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
            "cannot mine the block: {e} within the default attempt budget; pass `--difficulty <D>` explicitly to mine without a bound"
        )),
        _ => Fail::failed(format!("cannot build the block: {e}")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// The set of printed identifiers has a bound of its own (security review 2026-11-21, M-1).
    #[test]
    fn printed_ids_are_bounded() {
        let mut p = Printed::new(2);
        let id = |n: u8| BlockId::from_bytes([n; 32]);
        assert!(p.admit(&id(1)).unwrap());
        assert!(!p.admit(&id(1)).unwrap());
        assert!(p.admit(&id(2)).unwrap());
        assert!(!p.full);
        // Already printed: still fine at the bound; a third distinct one ends the command.
        assert!(!p.admit(&id(2)).unwrap());
        let fail = p.admit(&id(3)).unwrap_err();
        assert!(p.full && fail.message.contains("more than 2 distinct"));
        assert_eq!(p.seen.len(), 2);
    }

    /// The exit status of a command that failed on every relay.
    #[test]
    fn all_failed_status() {
        let one = all_failed("x", vec![Fail::refused("only")]);
        assert_eq!(
            (one.code, one.message.as_str()),
            (fail::EXIT_REFUSED, "only")
        );
        let same = all_failed("x", vec![Fail::refused("a"), Fail::refused("b\nc")]);
        assert_eq!(same.code, fail::EXIT_REFUSED);
        assert_eq!(same.message, "x on any relay:\n- a\n- b\n  c");
        let mixed = all_failed("x", vec![Fail::refused("a"), Fail::failed("b")]);
        assert_eq!(mixed.code, fail::EXIT_FAILURE);
        let invalid = all_failed("x", vec![Fail::failed("a"), Fail::invalid("b")]);
        assert_eq!(invalid.code, fail::EXIT_INVALID);
    }

    #[test]
    fn build_mine_sign_through_core() {
        // Test key from a public seed.
        let key = sbtp_core::SigningKey::from_bytes(&[1u8; 32]);
        let mut block = BlockBuilder::for_key(&key)
            .payload(b"hello")
            .build_unsigned()
            .unwrap();
        let (_, id) = mine(&mut block, 8, sbtp_core::DEFAULT_MAX_ATTEMPTS).unwrap();
        assert_eq!(sign_block(&mut block, &key).unwrap(), id);
        let parsed = sbtp_core::parse(&block).unwrap();
        assert_eq!(parsed.payload(), b"hello");
        assert!(validate_requested(&block, 8, &id).is_ok());
    }
}
