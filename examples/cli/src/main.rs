//! `sbtp`: the SBTP v1 command-line client (SPEC.md §4 to §7): keygen, publish, get.
//! Listing (`/query`) is left to an HTTP tool: its JSON needs no client, unlike mining,
//! signing and validation.

mod key;
mod relay;

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sbtp_core::{BlockId, UnsignedBlock, validate_requested};

use relay::Relay;

const USAGE: &str = "\
sbtp keygen KEY_FILE
    Write a new secret key to KEY_FILE (mode 0600, never overwritten); print
    the public key.
sbtp publish URL KEY_FILE [--parent BLOCK_ID]... < PAYLOAD
    Mine the payload (stdin, at most 65,535 bytes) with up to 8 parents at the
    relay's min_pow_difficulty, sign, PUT; print `BLOCK_ID stored` (new) or
    `BLOCK_ID already-stored`.
sbtp get URL BLOCK_ID [--raw]
    Fetch the block, validate it (SPEC section 4, id included); print a summary
    or, with --raw, the block bytes.
URL is https://HOST[:PORT] (or http:// for a local relay). List blocks with any
HTTP tool: GET URL/sbtp/v1/query?since=0 (JSON). Exit status 1 on any failure.
";

/// Appends lowercase hexadecimal; never reallocates when `out` has the room.
pub fn hex_into(out: &mut String, bytes: &[u8]) {
    let digits = bytes.iter().flat_map(|b| [b >> 4, b & 15]);
    out.extend(digits.filter_map(|n| char::from_digit(n.into(), 16)));
}

fn block_id(text: &str) -> Result<BlockId, String> {
    text.parse()
        .map_err(|_| format!("`{text}` is not a block id"))
}

fn out(write: impl FnOnce(&mut std::io::StdoutLock) -> std::io::Result<()>) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    let written = write(&mut stdout).and_then(|()| stdout.flush());
    written.map_err(|e| format!("cannot write to stdout: {e}"))
}

fn keygen(path: &str) -> Result<(), String> {
    let key = key::generate(Path::new(path))?;
    let mut public = String::with_capacity(64);
    hex_into(&mut public, key.verifying_key().as_bytes());
    out(|o| writeln!(o, "{public}"))
}

fn publish(url: &str, key_file: &str, rest: &[&str]) -> Result<(), String> {
    let parents = rest.chunks(2).map(|pair| match *pair {
        ["--parent", id] => block_id(id),
        _ => Err(format!(
            "unexpected `{}`; see `sbtp --help`",
            pair.join(" ")
        )),
    });
    let parents = parents.collect::<Result<Vec<_>, _>>()?;
    let (relay, key) = (Relay::new(url), key::read(Path::new(key_file))?);
    let mut payload = Vec::new();
    let read = std::io::stdin().take(65_536).read_to_end(&mut payload);
    read.map_err(|e| format!("cannot read the payload: {e}"))?;
    let pow = relay.min_pow_difficulty()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut block = UnsignedBlock {
        timestamp: u64::try_from(now.as_millis()).unwrap_or(u64::MAX),
        nonce: 0,
        pubkey: key.verifying_key().to_bytes(),
        parents: &parents,
        payload: &payload,
    };
    eprintln!("mining at difficulty {pow}");
    let id = block
        .mine(pow, u64::MAX)
        .map_err(|e| format!("cannot build the block: {e}"))?;
    let signed = block
        .sign(&key)
        .map_err(|e| format!("cannot sign the block: {e}"))?;
    let status = relay.put(&signed)?;
    out(|o| writeln!(o, "{id} {status}"))
}

fn get(url: &str, id: &str, raw: bool) -> Result<(), String> {
    let id = block_id(id)?;
    let bytes = Relay::new(url).block(&id)?;
    // spec §4: F1 to F9, R1, then C1 with the client's own difficulty (0: it has none), C2, C3.
    let valid = validate_requested(&bytes, 0, &id).map_err(|e| format!("{id}: {}", e.name()))?;
    if raw {
        return out(|o| o.write_all(&bytes));
    }
    let (block, mut author) = (valid.block(), String::with_capacity(64));
    hex_into(&mut author, block.pubkey());
    // Untrusted bytes: escaped, and at most 200 shown.
    let (time, payload) = (block.timestamp(), block.payload());
    let shown = payload.get(..200).unwrap_or(payload).escape_ascii();
    out(|o| {
        writeln!(o, "block_id  {id}\nauthor    {author}\ntimestamp {time}")?;
        for parent in block.parents() {
            writeln!(o, "parent    {parent}")?;
        }
        writeln!(o, "payload   {} bytes: \"{shown}\"", payload.len())
    })
}

fn run(args: &[&str]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|a| ["help", "--help", "-h"].contains(a)) {
        return out(|o| o.write_all(USAGE.as_bytes()));
    }
    match *args {
        ["keygen", path] => keygen(path),
        ["publish", url, key_file, ref rest @ ..] => publish(url, key_file, rest),
        ["get", url, id] => get(url, id, false),
        ["get", url, id, "--raw"] => get(url, id, true),
        _ => Err("unrecognised command line; see `sbtp --help`".into()),
    }
}

fn main() -> ExitCode {
    // Lossy: a non-UTF-8 path then names no file, and opening it says so.
    let args = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned());
    let args: Vec<String> = args.collect();
    if let Err(message) = run(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
        eprintln!("sbtp: {message}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
