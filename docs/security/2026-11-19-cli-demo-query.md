# Security and correctness review: `cli-demo query` and `get --difficulty` (combined pass)

- Date: 2026-11-19.
- Scope: branch `feat/cli-demo-query` at `22458f7`, read as `git diff main...feat/cli-demo-query`
  (`main` at `9f4da35`; 5 files, +1,452 −23): `examples/cli-demo/src/{commands,main,relay,walk}.rs`,
  `examples/cli-demo/tests/e2e.rs`. No manifest or lockfile change: no supply-chain review needed.
- References: spec `sbtp-core-v0.2.md` §3.3, §3.4, §4 (`/query`, "Errors", "Admission control");
  ADR 0012 rules 5 to 14, 29, 30 and clarifications K1, K2; ADR 0024 rules 7 and 8; ADR 0026. The
  author's description of the change was not used.
- Method: reading of the diff and of the unchanged helpers it relies on (`read_limited`,
  `error_body`, `untrusted`, `hex::block_id`, `Relay::new` agent settings, `validate_requested`
  check order in `sbtp-core`). In the worktree: `cargo test -p cli-demo` (36 unit + 17 e2e, all
  pass), `cargo clippy -p cli-demo --all-targets -- -D warnings` (clean), `cargo fmt --all --check`
  (clean). No repository file outside this report was modified.

## Verdict

**Mergeable.** No blocking and no medium finding. The four low findings are robustness and
conformance-of-messages issues in a demonstration CLI against a relay the user chooses; none gives a
hostile relay anything beyond making the CLI loop, use memory or wait, all of which the user can
interrupt. L-1 (the give-up path advertises the rejected cursor) is a one-line fix worth doing before
merge; the others can be done now or tracked.

What holds:

- Every relay byte is bounded: `/query` 200 bodies at 128 KiB (`relay.rs:239`), error bodies at
  16 KiB, 30 s end-to-end deadline per request, no redirect followed, no environment proxy. The JSON
  is parsed into `serde_json::Value` (recursion limit 128, no stack exhaustion).
- `parse_page` (`relay.rs:333`) rejects a page with more identifiers than the `limit` asked for (capped
  at 1,000, ADR 0012 rule 8), any identifier that is not exactly 64 **lowercase** hex characters, a
  missing or out-of-syntax `cursor` (ADR 0012 rule 5 / K1), and a non-boolean `more`. Unknown members
  are ignored (rule 10).
- The cursor is validated against the rule 5 alphabet both from the relay and from `--cursor`, so it
  is URL-safe and terminal-safe when interpolated into the URL (`query_url`) and into messages. The
  `parent` is re-encoded through `BlockId`'s lowercase `Display`. No relay text reaches the terminal
  without `untrusted()`; the error name used for classification is compared, never printed raw.
- Classification (`classify`, `relay.rs:317`) decides on the status first (spec §4 "Errors"): only
  `400` + exact `InvalidCursor` restarts; `400` with any other or no name, and every other non-listed
  status (3xx, 404, 408, 501...), is fatal (K1); `429/500/502/503/504` keep the cursor (K2).
- Walk loop (`walk.rs:172`): restart drops the cursor and keeps the filters (ADR 0024 rule 8);
  `InvalidCursor` on a cursor-less request is fatal instead of looping; restarts per walk capped at 3,
  consecutive transient failures per page at 6, `Retry-After` obeyed exactly up to 300 s and the walk
  ends rather than repeat early beyond that; back-off from 1 s, doubling, capped at 60 s, jitter up to
  +50 %, no overflow (`1 << attempt.min(30)`, saturating). Deduplication by `block_id` across pages,
  restarts and `--follow` polls (spec §4, ADR 0012 rule 13).
- `get --difficulty` (ADR 0026): default 0, `/info` never read; `receipt_fail` re-runs
  `validate_requested` at `d = 0` only when the error is `InsufficientPow`. Since `sbtp-core` checks
  F1-F9, R1, C1, then C2/C3, a block that fails C1 at the floor and also C2/C3 is still reported as an
  invalid block from the relay; only a block that passes everything at `d = 0` gets the "local floor"
  message (rule 4). The re-validation costs one extra signature check on an already-failed path:
  negligible.
- Tests discriminate what they claim: the scripted `PageSource` panics on an unscripted request, so
  any extra restart or retry fails the unit tests; the e2e InvalidParameter test relies on the closed
  port turning a forbidden third request into exit 1 instead of 3; the K2 test checks both the repeated
  cursor and an elapsed time of at least 1 s; the floor test checks that a C3 failure behind a C1
  failure is still reported as a relay fault, so it would catch a `receipt_fail` that always blamed
  local policy.

## Findings

### L-1 (low): giving up after repeated `InvalidCursor` advertises the rejected cursor

- `examples/cli-demo/src/walk.rs:214-220` and `examples/cli-demo/src/commands.rs:347-353`.
- Scenario: a relay rejects the cursor of the walk more than `max_restarts` (3) times, or a relay with
  a fresh epoch keeps rejecting. `walk` returns the "giving up" error **without** clearing
  `self.cursor`, which still holds the cursor the relay just rejected. `query` then appends
  ``Resume later with `--cursor <rejected>` ``. The user (or a script) following the advice sends the
  rejected cursor again, against ADR 0024 rule 8 ("It MUST NOT retry the rejected cursor"). Effect: one
  more `InvalidCursor` and a restart, no data loss; hence low.
- `restarts_are_bounded` (`walk.rs:456`) does not assert the cursor after the failure, so the tests do
  not catch it.
- Fix: set `self.cursor = None` before returning the give-up error (the rejected cursor is dead in any
  case), and assert `walker.cursor() == None` in `restarts_are_bounded`.

### L-2 (low): a hostile relay can keep a walk running forever without the "no progress" guard firing

- `examples/cli-demo/src/walk.rs:185-195`.
- The guard only catches an empty page with `more: true` **and** the same cursor as the request.
  Scenarios with an attacker-controlled relay:
  1. empty pages with `more: true` and alternating cursors (`a`, `b`, `a`...): infinite requests, no
     output, no event on stderr, so the user sees a silent hang (each request is fast, so the 30 s
     deadline never fires);
  2. pages that only repeat already-emitted identifiers with fresh cursors: same effect, the
     identifiers are swallowed by deduplication;
  3. an endless stream of fresh identifiers: indistinguishable from a huge relay (see L-3).
- An honest relay never produces 1 or 2 outside a restart: a cursor returns "exactly the matching
  blocks that this response and its predecessors did not return" (ADR 0012 rule 10), and `more: true`
  means at least one more matching block existed, which a `limit ≥ 1` page would have contained (only
  an eviction race can produce one empty `more: true` page).
- Fix: count consecutive `200` pages that emit no new identifier; stop after a small bound (for example
  16) when no restart happened in the walk, or after `seen.len() / page_limit + 16` pages after a
  restart (when re-served identifiers are expected). One unit test with alternating cursors.

### L-3 (low): the deduplication set grows without bound

- `examples/cli-demo/src/walk.rs:142`, `:198`.
- `seen` keeps every identifier emitted by the process, across every `--follow` poll. Roughly 40-50
  bytes per identifier with `HashSet` overhead. A hostile relay serving 1,000 fresh identifiers per
  page grows it by about 45 KB per request; on loopback or a fast link that is hundreds of MB per
  minute. An honest mirror relay with 10 million blocks costs about 450 MB for a full listing.
- Effect: memory exhaustion of the user's own CLI process, interruptible with Ctrl-C. Not exploitable
  beyond that.
- Fix (any of): cap `seen` (for example 1,000,000 entries) and stop with a message that suggests
  `--parent`/`--since`; or keep only the identifiers emitted since the last restart plus the current
  walk, since an honest relay only re-serves identifiers after `InvalidCursor` or a re-store after
  eviction (rule 12, third guarantee). Document the bound in `HELP_QUERY`.

### L-4 (low): an unparseable `Retry-After` falls back to a 1 s back-off and repeats early

- `examples/cli-demo/src/relay.rs:324`.
- Scenario: a `429` or `503` comes from a reverse proxy (the deployment the spec assumes for a public
  `sbtp-relay`) with `Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`, or from a relay with a value that
  does not fit `u64` or has a fraction (`1.5`). `classify` maps it to `None`, the walk backs off 1 s,
  2 s... and repeats before the time the server asked for. Spec §4 "Admission control" and ADR 0012
  rule 30: "A client MUST NOT repeat the request before `Retry-After` has elapsed". The HTTP-date form
  is a SHOULD NOT on the relay side (rule 29), not a licence for the client to ignore it.
- Effect: a few early repeats against a server that is shedding load; bounded by `max_retries`. No
  security impact on the user.
- Fix: distinguish "absent" from "present but unparseable". For the latter, either stop the walk with
  the same message as an over-long `Retry-After` (simplest, and the user sees the raw value through
  `untrusted`), or back off at `backoff_cap` (60 s). Add the case to `query_failures_are_classified`
  (today the date test only asserts `retry_after: None`, which encodes the early repeat as expected
  behaviour).

### I-1 (info): "identifiers already printed are not printed again" is wrong for a rejected `--cursor`

- `examples/cli-demo/src/commands.rs:433-437`, and the same sentence in `HELP_QUERY`
  (`main.rs`).
- When the **starting** `--cursor` is rejected (`invalid_starting_cursor_restarts`), the process has
  printed nothing yet; the restart prints the full listing again, including every identifier that the
  earlier run (which produced the cursor) already printed. The behaviour is correct (ADR 0024 rule 8),
  the message is not. A consumer polling with `--cursor` must deduplicate itself.
- Fix: in that case say "the listing starts again from the beginning; identifiers from earlier runs
  will be printed again", and state in `HELP_QUERY` that deduplication holds within one process only.

### I-2 (info): `get --difficulty` range not checked, and checked after the network request

- `examples/cli-demo/src/commands.rs:238`.
- The new help says "0 to 256", but `--difficulty 1000` is accepted; the block is fetched, fails C1,
  passes at `d = 0`, and the user gets "below the local floor ... asks for at least 1000". `mine`
  already rejects values above `MAX_DIFFICULTY`. Not a security issue.
- Fix: reject `> sbtp_core::MAX_DIFFICULTY` as a usage error before `get_block`.

### I-3 (info): local-floor refusal and relay fault share exit code 4

- `examples/cli-demo/src/commands.rs:271-281`.
- ADR 0026 rule 4 is about not *reporting* the floor refusal as a relay fault; the message complies.
  A script, however, cannot tell the two apart by exit code. Acceptable for a demo; consider a distinct
  code if scripts are expected to act on it.

### I-4 (info): minor inaccuracies

- `relay.rs:242`: the over-size message says "(70 KiB)" while the cap is 128 KiB. Harmless, but it
  reads as if a 100 KiB page would be accepted by nothing; say "larger than 128 KiB; a valid page is
  under 70 KiB".
- A network failure mid-walk (`Io`, timeout, closed connection) is fatal (`relay.rs:235`, `:240`).
  Spec §4 allows one immediate retry then back-off; being fatal is conservative and conformant (MAY),
  and the resume cursor is printed. Fine as is.
- `eprintln!` panics if standard error is closed or a broken pipe (`2>&1 | head`); the stdout
  `BrokenPipe` case is handled, the stderr one is not. Pre-existing pattern across the CLI; exit 101
  instead of a clean end, no other effect.

## Not checked

- Behaviour against a real reverse proxy (Caddy, nginx) in front of `sbtp-relay`: proxy-generated
  `502/504` bodies and `Retry-After` formats were reasoned about, not observed.
- `--follow` over long durations (hours) and real memory use of `seen`; the figures in L-3 are
  estimates, not measurements.
- No fuzzing of `parse_page`; it delegates to `serde_json` and simple predicates, so the residual risk
  is low.
- `ureq` 3.5.1 internals were not re-read for this pass (no version change since the
  `2026-11-19-cli-demo.md` review, which covered body limits, redirects, proxy and timeouts).
- Windows behaviour (pipe semantics, terminal escaping) was not exercised; tests ran on macOS.
