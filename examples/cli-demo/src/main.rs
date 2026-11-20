//! SBTP demonstration CLI: generate a key, build, mine and sign a block, publish it to a relay and
//! fetch it back, fully verified. Every layer 0 operation goes through `sbtp-core`.
//!
//! Run `cli-demo --help` for usage.

mod args;
mod commands;
mod fail;
mod hex;
mod keyfile;
mod output;
mod relay;
mod walk;

use std::ffi::OsString;
use std::process::ExitCode;

use fail::Fail;

const HELP: &str = "\
cli-demo: SBTP demonstration client (Signed Block Transport Protocol, layer 0 v0.2-draft)

USAGE:
    cli-demo <COMMAND> [OPTIONS]
    cli-demo <COMMAND> --help

COMMANDS:
    keygen    Generate an Ed25519 key pair into a new file (mode 0600)
    pubkey    Print the public key of a key file
    mine      Build a block, mine its proof of work and sign it
    inspect   Validate a block file locally and print its fields
    publish   Send a block file to a relay (PUT /sbtp/v1/block)
    get       Fetch a block from a relay, verify it fully, print or save it
    query     List the block_ids a relay holds, or the children of a block (GET /sbtp/v1/query)
    info      Print a relay's settings (GET /sbtp/v1/info)

QUICK START (against a local relay, `cargo run -p sbtp-relay`):
    cli-demo keygen --out alice.key
    echo 'hello' > hello.txt
    cli-demo mine --key alice.key --payload hello.txt --relay http://127.0.0.1:8080 --out hello.sbtp
    cli-demo publish --relay http://127.0.0.1:8080 hello.sbtp
    cli-demo get --relay http://127.0.0.1:8080 <BLOCK_ID>
    cli-demo query --relay http://127.0.0.1:8080 --parent <BLOCK_ID>

OUTPUT:
    Results (public key, block_id, block fields) go to standard output; progress and errors go
    to standard error. A secret key is never printed.

EXIT STATUS:
    0  success
    1  I/O, network or local failure
    2  command-line usage error
    3  the relay refused the request (its error name and message are shown)
    4  the block was not accepted by this client, without saying who is at fault: it failed
       validation (local file, or the relay's answer), or it is valid but below the local
       floor of `get --difficulty`. To tell the two apart, run `get` again without
       --difficulty: status 0 then means the first refusal was the local floor

KEY FILES:
    A key file holds the Ed25519 secret key in clear, protected by file permissions only, like an
    unencrypted SSH key. `keygen` creates it with mode 0600 and never overwrites a file; every
    command refuses a key file readable by the group or others. A key is never read from the
    command line or the environment.

NETWORK:
    This build speaks plain HTTP only (no TLS): use a local relay or an SSH tunnel. Proxies from
    the environment are not used. Requests time out after 30 seconds.
";

const HELP_KEYGEN: &str = "\
cli-demo keygen: generate an Ed25519 key pair

USAGE:
    cli-demo keygen --out <FILE>

Writes the secret key to the new file <FILE> with mode 0600 (an existing file, symbolic link
included, is never replaced) and prints the public key (64 hexadecimal characters).

OPTIONS:
    --out <FILE>    Key file to create (required)
";

const HELP_PUBKEY: &str = "\
cli-demo pubkey: print the public key of a key file

USAGE:
    cli-demo pubkey --key <FILE>

OPTIONS:
    --key <FILE>    Key file, mode 0600 or 0400 (required)
";

const HELP_MINE: &str = "\
cli-demo mine: build a block, mine its proof of work, sign it

USAGE:
    cli-demo mine --key <FILE> --out <FILE> (--difficulty <D> | --relay <URL>)
                  [--payload <FILE>] [--parent <BLOCK_ID>]... [--timestamp <MS>] [--force]

Builds the block (spec §2), increments its nonce from 0 until the block_id has at least D leading
zero bits (spec §3.3), signs SIG_PREFIX || block_id with the key (spec §3.2), checks the result
with the same validation a relay applies, and writes the raw block to --out. Prints the block_id.

OPTIONS:
    --key <FILE>            Key file, mode 0600 or 0400 (required)
    --out <FILE>            Block file to create (required)
    --difficulty <D>        Proof-of-work difficulty, 0 to 256 (16 is the relay default; each
                            extra bit doubles the expected time)
    --relay <URL>           Read the difficulty from this relay's /sbtp/v1/info instead; a relay
                            asking for more than 24 is refused (use --difficulty to override)
    --payload <FILE>        Payload, at most 65,535 bytes (default: empty)
    --parent <BLOCK_ID>     A parent block_id, 64 hexadecimal characters; repeat for up to 8
                            parents, in order
    --timestamp <MS>        Timestamp in Unix milliseconds (default: now). A relay refuses a
                            timestamp too far in the future (max_future_ms in /info)
    --force                 Replace --out if it exists
";

const HELP_INSPECT: &str = "\
cli-demo inspect: validate a block file locally and print its fields

USAGE:
    cli-demo inspect [--difficulty <D>] <BLOCK_FILE>

Applies the full validation of spec §2.2 (format F1-F9, proof of work C1, public key and strict
Ed25519 signature C2-C3). The payload is shown as escaped text or hexadecimal, never raw.

OPTIONS:
    --difficulty <D>    Required proof-of-work difficulty (default: 0, any)
";

const HELP_PUBLISH: &str = "\
cli-demo publish: send a block to a relay

USAGE:
    cli-demo publish --relay <URL> <BLOCK_FILE>

Validates the block locally (format and signature), then sends PUT /sbtp/v1/block. 201 Created
(newly stored) and 200 OK (already stored) are both success. On a refusal, prints the status and
the relay's {error, message}; after 429, 502, 503 or 504, wait for the Retry-After shown, if
any, before retrying (ADR 0012 K3). Prints the block_id.

OPTIONS:
    --relay <URL>   Relay base URL, such as http://127.0.0.1:8080 (required)
";

const HELP_GET: &str = "\
cli-demo get: fetch a block from a relay and verify it

USAGE:
    cli-demo get --relay <URL> [--out <FILE>] [--payload-out <FILE>] [--difficulty <D>]
                 [--force] <BLOCK_ID>

Sends GET /sbtp/v1/block/<BLOCK_ID>, then, before writing or printing anything, recomputes the
block_id and checks it equals <BLOCK_ID> (R1) and applies the full validation (spec §3.4). A 404
means the relay does not hold the block; it may have evicted it.

OPTIONS:
    --relay <URL>           Relay base URL, such as http://127.0.0.1:8080 (required)
    --out <FILE>            Write the raw block to this new file
    --payload-out <FILE>    Write the payload to this new file
    --difficulty <D>        Local proof-of-work floor, 0 to 256 (default: 0, any). It is this
                            client's own anti-spam filter, independent of the relay: the
                            min_pow_difficulty of /info only applies to what the relay
                            accepts with PUT, and is never read here. A block below the floor
                            is refused as local policy, not reported as a relay fault
    --force                 Replace the output files if they exist
";

const HELP_QUERY: &str = "\
cli-demo query: list block_ids held by a relay

USAGE:
    cli-demo query --relay <URL> [--parent <BLOCK_ID>] [--since <MS>] [--limit <N>]
                   [--cursor <CURSOR>] [--follow [--interval <S>]]

Walks GET /sbtp/v1/query page by page, following the returned cursor until the relay has no
more, and prints each block_id once, one per line, in the relay's storage order. The order is
local to this relay: do not derive anything from it. Each block_id is a hint only: fetch and
verify the block with `get`. Progress and the final cursor go to standard error; keep the
cursor and pass it with --cursor later to list only the blocks stored since.

Each block_id is printed once per run: deduplication holds within one process only, up to
1,000,000 distinct block_ids (the run stops past that, with a cursor to resume; narrow the
listing with --parent or --since). A consumer that polls with --cursor across runs must
deduplicate itself.

If the relay no longer recognises the cursor (400 InvalidCursor, for example after a crash
of the relay), the walk starts again from the beginning with the same filters. Identifiers
already printed by this run are not printed again; when the rejected cursor is the one given
with --cursor, the whole listing is printed again. On 500, 502, 503, 504 or 429 the cursor is
kept and the request repeated after Retry-After, or after an exponential back-off from 1
second (6 retries at most); a Retry-After over 300 seconds or not in seconds stops the walk.
Any other refusal, InvalidParameter included, stops the walk, as does a relay that keeps
sending pages with nothing new.

OPTIONS:
    --relay <URL>           Relay base URL, such as http://127.0.0.1:8080 (required)
    --parent <BLOCK_ID>     Only the children of this block (the relay need not hold it)
    --since <MS>            Only blocks the relay stored at or after this Unix time in
                            milliseconds, by the relay's clock (not the block Timestamp)
    --limit <N>             Page size, at least 1 (default: 100; the relay lowers a value
                            above its max_query_limit)
    --cursor <CURSOR>       Start after this cursor, printed by an earlier `query` of the
                            same relay
    --follow                After the walk, poll for new blocks until interrupted
    --interval <S>          Seconds between polls with --follow, 1 to 3600 (default: 10)
";

const HELP_INFO: &str = "\
cli-demo info: print a relay's settings

USAGE:
    cli-demo info --relay <URL>

Prints min_pow_difficulty and max_future_ms from GET /sbtp/v1/info.

OPTIONS:
    --relay <URL>   Relay base URL, such as http://127.0.0.1:8080 (required)
";

type Command = fn(&[OsString]) -> Result<(), Fail>;

/// The subcommand table: name, handler, help text.
const COMMANDS: &[(&str, Command, &str)] = &[
    ("keygen", commands::keygen, HELP_KEYGEN),
    ("pubkey", commands::pubkey, HELP_PUBKEY),
    ("mine", commands::mine_block, HELP_MINE),
    ("inspect", commands::inspect, HELP_INSPECT),
    ("publish", commands::publish, HELP_PUBLISH),
    ("get", commands::get, HELP_GET),
    ("query", commands::query, HELP_QUERY),
    ("info", commands::info, HELP_INFO),
];

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail) => {
            eprintln!("error: {fail}");
            if fail.code == fail::EXIT_USAGE {
                eprintln!("Run `cli-demo --help` for usage.");
            }
            ExitCode::from(fail.code)
        }
    }
}

fn run(args: &[OsString]) -> Result<(), Fail> {
    let Some((first, rest)) = args.split_first() else {
        print!("{HELP}");
        return Err(Fail::usage("no command given"));
    };
    let name = first.to_str().unwrap_or_default();
    if matches!(name, "--help" | "-h" | "help") {
        print!("{HELP}");
        return Ok(());
    }
    if matches!(name, "--version" | "-V") {
        println!("cli-demo {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let Some((_, command, help)) = COMMANDS.iter().find(|(n, _, _)| *n == name) else {
        return Err(Fail::usage(format!(
            "unknown command `{}`",
            fail::untrusted(&first.to_string_lossy(), 40)
        )));
    };
    // `--help` anywhere before a `--` shows the command's help and runs nothing.
    if rest
        .iter()
        .take_while(|a| a.to_str() != Some("--"))
        .any(|a| matches!(a.to_str(), Some("--help" | "-h")))
    {
        print!("{help}");
        return Ok(());
    }
    command(rest)
}
