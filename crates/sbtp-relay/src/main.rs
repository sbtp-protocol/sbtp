//! SBTP dumb relay. Specification: `docs/spec/sbtp-core-v0.2.md` §4 and `docs/spec/architecture.md` §2.
//!
//! Usage: `sbtp-relay [--config <path>]`. Settings: ADR 0018 rule 6 (defaults, then the TOML file,
//! then `SBTP_RELAY_*` environment variables). Status: relay milestone 1c-b (see the library).
//!
//! Operator command: `sbtp-relay key-blocks <public-key-hex> [--config <path>]` lists the held
//! blocks of a key on standard output ([`sbtp_relay::operator`], ADR 0052 rule 10).
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::io::Write as _;
use std::process::ExitCode;

use sbtp_relay::log::{self, Event, Value};
use sbtp_relay::operator;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.peek().is_some_and(|a| a == operator::KEY_BLOCKS) {
        args.next();
        // No logger: the command writes to standard output only (ADR 0052 rule 10).
        let mut out = std::io::stdout().lock();
        return match operator::key_blocks(args, std::env::vars_os(), &mut out) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "sbtp-relay key-blocks: {}", e.msg);
                ExitCode::from(e.code)
            }
        };
    }
    // ADR 0021 rule 9: panics go through the logger and its bounds; the default hook never runs.
    log::install_panic_hook();
    let result = sbtp_relay::run(
        sbtp_core::self_test,
        args,
        std::env::vars_os(),
        sbtp_relay::signals,
        |_| {},
    );
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let msg = e.to_string();
            log::emit(Event::Fatal, &[("msg", Value::Str(&msg))]);
            ExitCode::FAILURE
        }
    };
    // ADR 0021 rule 21: drain the queue, for at most one second.
    log::flush();
    code
}
