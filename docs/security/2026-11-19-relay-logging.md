# Security review: relay logger and counters (ADR 0021, milestone 1b part)

- Date: 2026-11-19
- Scope: branch `feat/relay-adr0021-logging`, commits `80e7c6d` and `92115ea`, read as
  `git diff main...92115ea` (14 files, +2,354 −193). Main at `0f47bd8`.
- Reference: ADR 0021 (accepted), ADRs 0018, 0019, 0020.
- Method: reading of the diff; a scratch copy (`git archive 92115ea`, outside the repository) for the
  existing suite, `clippy`, attack tests added in the scratch copy only, and two runs of the debug binary
  (hostile requests; standard error on a pipe that nobody reads). Nothing was checked out or modified in
  the repository except this file.

## Verdict

**Mergeable.** No critical, high or medium finding. Three low findings, none blocking; L-2 should be
decided by the owner before the milestone 1b handlers start to parse client data. No client-controlled
byte reaches a log line today, the volume bound holds, the request path does not block on a stalled
sink, and no crate enters the graph.

| Id | Severity | Subject | Blocking |
|---|---|---|---|
| L-1 | low | Exit takes up to about 5 s, not 1 s, when standard error is stalled | no |
| L-2 | low | The panic `msg` is the only free-text path that could carry client data (rule 9 against rule 10) | no, decide before the 1b handlers |
| L-3 | low | In JSON mode the `start` line and an early `fatal` line are text | no |
| I-1 to I-9 | info | See below | no |

## Findings

### L-1 (low): a stalled sink delays exit by one second per exempt line, not one second in total

- Where: `crates/sbtp-relay/src/log.rs` lines 436 to 440 and 481 to 496 (`send_patient`), 608 to 614
  (`flush`); callers `server.rs` (`shutdown` `signal`, then `drained`/`deadline`/`forced`), `lib.rs`
  (`index_closed`), `main.rs` (`fatal`, `log::flush`).
- Scenario: standard error is a pipe whose reader stopped (a stalled logging driver, rule 21). The queue
  is full. At `SIGTERM`, each line outside the bucket waits `DRAIN` (1 s) for room, then the final
  `flush` waits 1 s more. Measured on the debug binary with a full pipe: exit 4.05 s after `SIGTERM`
  (`signal`, `drained`, `index_closed`, flush). With a `fatal` line: about 5 s. ADR 0021 rule 21 says
  "At exit the relay drains the queue for at most 1 second".
- Second effect: the two `shutdown` lines of `server::serve` are written from an async function with
  `std::thread::sleep` in a loop. With a stalled sink they hold a runtime worker for up to 1 s each, and
  `stopping_tx.send(true)` is sent 1 s late. Only at shutdown, only with a stalled sink.
- Gain for an attacker: none directly. A remote client cannot stall the sink. The total stays bounded
  (about 5 s) and under any supervisor stop timeout.
- Fix: one exit budget shared by the exempt lines and the flush (a deadline stored at the first wait;
  later lines use `try_send` once it has passed), or make the `shutdown` lines `try_send` and keep the
  wait for `fatal` and the flush only. Otherwise amend the sentence of rule 21 to "1 second per line
  outside the bucket, about 5 seconds in total".

### L-2 (low): the panic message is logged as produced, and a panic payload may hold anything

- Where: `log.rs` lines 908 to 929 (`on_panic`); ADR 0021 rule 9 (logs `msg`) against rule 10 ("never
  logged, at any level").
- Scenario: a handler or a dependency panics with a formatted message that embeds input
  (`expect` on an error whose `Debug` holds the value, `panic!("... {value}")`). The message goes to the
  `panic` line at `error`, so with the default settings. It is escaped and cut to 1,024 bytes, so it
  cannot forge a line or a field; the concern is privacy only (an address, a header value, block bytes).
- Reach today: none found. The only route is `/info`; no code of this branch formats client data into a
  panic; the workspace lints warn on `unwrap` and indexing; overflow panics have constant messages. The
  privacy test (`tests/logging.rs`) panics with a constant string, so it would not catch a regression.
  The exposure grows with the `PUT` and `/query` handlers of milestone 1b.
- Fix (owner's choice, the ADR accepted the message):
  1. write `msg` only when the payload is a `&'static str` (a literal: it cannot hold input); for a
     `String` payload (formatted) write a fixed text such as `formatted message withheld` at `info`,
     and the real message only at `log_level = "debug"`. `location` is kept in both cases and is
     usually enough to find the fault; or
  2. keep the code and add to the privacy test a handler that panics with a formatted marker, with the
     rule "no panic message formats request data" stated in `CLAUDE.md` for the 1b handlers.
- Related, info: `render` (lines 682 to 686) encodes the whole line once before it encodes it again with
  the limit. A very long value is fully escaped first (up to 6 bytes per input byte in JSON). The throttle
  runs before, so this is at most once per minute per throttle, and only the panic payload could be
  large. Pass the limit on the first pass when `cut` is true.

### L-3 (low): JSON mode still writes text for the first line and for an early `fatal`

- Where: `lib.rs` lines 90 to 98 (`start` before `Settings::load`), `main.rs` (`fatal` on a
  configuration error).
- Scenario: `log_format = "json"`. Confirmed on the binary: line 1 is
  `ts=... level=info event=start name=sbtp-relay version=0.1.0`, every later line is JSON. A
  configuration error gives two text lines. A collector that parses strictly rejects one line per start,
  and may miss the `fatal` line, which is the one an operator alerts on.
- Injection: none. `start` has constant content; the early `fatal` message echoes operator input
  (the invalid value) and is escaped.
- Fix: write `start` after `configure` (it stays the first line), and for a failure before the settings
  are loaded read `SBTP_RELAY_LOG_FORMAT` alone before formatting `fatal`; or state in the deployment
  documentation that a JSON consumer must accept text lines for `start` and early `fatal`.

### Info

- **I-1, writer thread loss is silent.** If the `log-writer` thread cannot be spawned or panics, every
  later line is dropped and counted, but no `log_dropped` or `stats` line can be written (the writer
  writes them). Tested with a sink that panics: no deadlock, 1,000 calls plus an exempt line plus a
  flush return in 2 ms. No realistic panic path was found in the writer (`metrics::snapshot` and
  `Logger::dropped_total` use `.sum()`, which panics on overflow under `overflow-checks = true`, but
  needs 2^64 events). Suggest `saturating_add` folds, as `summary` already does, and exposing the state
  on `/metrics` in 1c.
- **I-2, panic `location` holds build paths.** For a panic in a dependency it is the absolute path of
  the registry on the build machine (home directory name). The same strings are already in the binary.
  Use `--remap-path-prefix` (or `trim-paths` when stable) for release builds.
- **I-3, `client_tag_key()` is `pub`.** `log.rs` line 623 returns the 32-byte key to any caller of the
  library. It is never logged, formatted or written (checked: no `Debug` on `Logger`, the static is
  private to the function). `pub(crate)` is enough for `lib.rs` and removes the only way out of the
  module. The key is not zeroized; it lives for the whole process, so this changes nothing.
- **I-4, 8 hexadecimal characters are acceptable.** The tag only links lines of one run. Without the
  key, 32 bits cannot be turned back into an address; collisions (even odds near 77,000 distinct clients
  in one run) only blur a correlation, which favours privacy. Residual: a local process that can read
  the log and connect from a trusted loopback address (the default `trusted_proxies`) can test "is tag T
  the address A" by sending `X-Forwarded-For: A`, at about one line per minute per throttle. This is
  inherent to a pseudonymous tag, already warned (`client_tag_keyed`, `trusted_loopback`).
- **I-5, Unicode format characters are not escaped** (U+202E, U+200B, U+FEFF). They can only come from
  operating system error text, a path or a setting, never from a client. C0, DEL, C1, U+2028 and U+2029
  are escaped, which is more than rule 3 asks.
- **I-6, requests refused by hyper before routing** (malformed request line, `400`) reach neither
  `observe` nor a counter. A flood of them is invisible in `http_requests_total`. For 1c.
- **I-7, write errors on the sink are ignored and not counted** (`EPIPE` after the reader closed). Lines
  are lost without a trace. Acceptable; a counter in 1c would show it.
- **I-8, the reserve of rule 18 is read as strict:** a `debug` or `info` line passes with exactly
  `log_burst / 4` tokens and leaves one fewer. One token of difference, harmless.
- **I-9, a throttled line that the bucket then refuses loses its `suppressed` count** (the throttle slot
  is spent before the bucket). The drop is counted in `log_dropped`. With the reserve, at most 9
  throttles write `warn` or `error` lines, so the bucket does not refuse them in practice.

## What was checked and holds

**1. Log injection: none found.**
- Every string value goes through `push_str`/`escape`. Keys are `&'static str` from the code; no key and
  no event name comes from input. A value with `=`, a space, a quote or a backslash is quoted and
  escaped in text; JSON escapes all controls as `\uXXXX`.
- Non-UTF-8 bytes cannot reach the sink: values are `&str` (paths go through `display()`).
- Truncation works on whole characters and whole escape sequences (`piece` is appended or not at all), and
  the closing quote is always written. Attack tests in the scratch copy: 60,000 random lines per format
  built from CR, LF, NUL, ESC, DEL, C1, U+2028, quotes, backslashes, `=`, forged `truncated=true` and
  forged JSON members; every escape unit repeated 1,200 times at 40 offsets, with and without `ts`; 200
  integer fields; a value starting at each offset from 900 to 1,010. Every line: at most 1,024 bytes, one
  line feed, valid for a strict text parser and for `serde_json`, keys equal to the expected prefix, and
  `truncated` last when present.
- Binary run with a request path holding `%0Alevel=error`, an invalid method, a non-UTF-8 path and
  hostile `X-Forwarded-For` values: no marker in any line; `route=other method=GET`.

**2. Volume bounds: effective.**
- Order level, throttle, bucket, queue as rule 16. Nine throttle instances cover every `warn` and `error`
  event a peer can cause, including the panic hook.
- Bounded events use `try_send`. With a sink that never returns, 200,000 calls of 5,000-byte values took
  1.0 s in a debug build, all counted (`rate` 196,899, `queue` 2,844, 256 queued). Binary with a full
  pipe: 1,500 of 1,500 requests answered, 16 ms for the last one, RSS 7 MB.
- No unbounded allocation from a remote client: 256 lines of at most 1,024 bytes; per-event tables are
  fixed arrays; `fields.to_vec()` runs after the throttle.
- `log_dropped`: at most one per 60 s, written by the writer thread only, shrunk to 1,024 bytes with
  `other`.
- Worst case: `(120 + 60 × 1,440 + 1,440) × 1,024 = 90,071,040` bytes per day for `small`; the binary
  logs `log_bound bytes_per_day=90071040`. The `stats` line and the `panic` line pay a token. Lines
  outside the bucket have call sites only at start-up and exit.

**3. Privacy.** No address, header value, received path, query string, body byte, cursor or key is passed
to any call site, at any level. Error texts logged: `io::Error` of `accept`, the redb flush error, the
start-up error (operator input, allowed by rule 11). The one open path is the panic payload (L-2). Client
tag: keyed BLAKE3 over family, prefix length and address; key from `/dev/urandom`; start-up refuses
(`fatal`, exit 1) before `configure` when the key cannot be read, and `client_tag` returns no tag rather
than an unkeyed one. The failure path was read, not run.

**4. Panic hook.** Throttled by `PANIC_LOG` (one line per 60 s; counted every time). It takes no lock
except the bucket mutex, held only around saturating arithmetic that cannot panic, and recovered from
poisoning; it never writes to standard error itself, so it cannot deadlock on the writer. A panic in
the writer or during the flush makes `flush` return at once (disconnected channel). The second panic
within 60 s logs nothing (test `privacy_events_and_panics`). Theoretical only: a panic inside the
first initialisation of the global logger would re-enter `OnceLock`; no panic path exists there. A
panic during unwinding aborts the process with a message from the standard library, outside the logger,
once per process.

**5. Counters.** Fixed arrays of `AtomicU64` indexed by enums with `get`; labels are constants. `Route`
comes from axum's matched template; `method` is one of six names or `other`; status classes are 2xx,
4xx, 5xx. Atomic additions wrap and cannot panic. `connections_open` is decremented once per increment,
in the same task.

**6. Choices where the ADR was silent: all safe.** `config_warning code=trusted_loopback` (fixed code,
text without input); `forwarded_invalid` with `reason` `unreadable` or `absent` (fixed values, one
throttle each, a field added as rule 7 allows; the header value is not logged); `stats` field names
(constants) and throttle keys (one static per event and class); the strict reading of the reserve (I-8);
`start` and early `fatal` in the default format (not unsafe; L-3 for consumers).

**7. Supply chain.** `crates/sbtp-relay/Cargo.toml` adds `blake3.workspace = true` only; `Cargo.lock`
gains one dependency line under `sbtp-relay` and no package. The shipped graph has 83 packages, as on
`main` (ADR 0021 facts table). No change to the workspace manifest, `deny.toml` or CI files.
`cargo deny --offline check`: advisories, bans, licenses and sources ok. Existing suite on the scratch
copy: 85 tests pass; `cargo clippy -p sbtp-relay --all-targets -- -D warnings` clean.
`#![deny(clippy::print_stdout, clippy::print_stderr)]` in the library and the binary; the only remaining
print is the test-only `READY` protocol in `index.rs`.

## Not checked

- Linux behaviour: all runs were on macOS (`open_files_unchecked` path). Pipe atomicity, journald and
  Docker sinks, `/proc/self/limits`, and `/dev/urandom` in a minimal container were not exercised.
- The failure of the key draw (no way to inject it without a chroot); read only.
- The release profile (`opt-level = "s"`, LTO); only debug builds were run.
- A 24-hour volume measurement; the bound is computed and was observed over seconds only.
- Events with no call site yet (`block_rejected`, `block_stored`, `sweep*`, `storage_full`, `disk_*`,
  `store_write_failed`, `metrics_listening`): the `block` suffix of rule 12 and the `/metrics` listener
  belong to the next reviews.
- What dependencies (hyper, tokio, redb) may write to standard error on their own, and the content of
  their panic messages.
- `cargo audit` was not run; `cargo deny` ran offline against the local advisory database.
