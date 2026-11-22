# Security review: relay hardening 2 (`feat/relay-hardening-2`)

- Date: 2026-11-22
- Scope: `git diff main...feat/relay-hardening-2` (8 commits, `crates/sbtp-relay`, `deploy/README.md`).
- Reference: ADR 0052 (deny list; rule 10, the operator command), ADR 0050 rule 22 (credentials),
  ADR 0021 (logs), ADR 0051 clarification B10; earlier reports
  `docs/security/2026-11-21-relay-deny-list.md` and `docs/security/2026-11-21-relay-object-mirror.md`.
- Reviewer: security-auditor, independent (diff and spec; the author's conclusions were not used).

## Verdict

**Mergeable.** No blocking, high or medium finding. Two low findings (L-1 the `key-blocks` scan
aborts on a file deleted during the walk and leaves a partial list; L-2 the remaining unwiped
credential copies of mirror L-2) and eight info points. Under the review policy these go to the
roadmap; no re-review is needed. L-1 is a small fix and worth doing before an operator relies on
the command for a CDN purge.

## Checks run

On a temporary worktree of `feat/relay-hardening-2` at `334a0c2`:

| Check | Result |
|---|---|
| `cargo test -p sbtp-relay` | pass: every unit and integration test binary green (180 unit tests; `deny` 14, `e2e` 7, ...) |
| `cargo test -p sbtp-relay --features object-store` | pass except one flaky test, most likely pre-existing: `mirror::every_block_is_copied_once_and_the_cursor_survives_a_restart` failed once in four runs (I-8); the other three runs were green (187 unit tests, `e2e` 8, `mirror` 7) |
| `cargo test --workspace` | other crates green as far as observed; the first run's output was cut by my own pipe and the disk then filled up (see "Not checked"). The branch changes only `sbtp-relay`, which ran in full above |
| `cargo clippy -p sbtp-relay --all-targets --features object-store -- -D warnings` | clean |
| `cargo deny --offline check` | `advisories ok, bans ok, licenses ok, sources ok` (local advisory database) |
| `Cargo.toml` / `Cargo.lock` | unchanged by the branch: no new dependency |

## Earlier findings: claimed fixes

| Finding | Claim | Status |
|---|---|---|
| deny I-1 | `SIGHUP` handler installed at the start, whatever the settings; ignored without `deny_file` | **Fixed.** `guard_hangup()` (`lib.rs:125`, `:609`) registers tokio's process-wide handler right after the early log format, before the self-test, the settings, the store and the deny file. tokio's handler replaces the default action for the life of the process, so a `SIGHUP` in the window until `spawn_hangup` is swallowed. `spawn_hangup` (`lib.rs:538`, `:631`) now runs unconditionally and, without `deny_file`, logs a throttled `config_warning code=sighup_ignored` with fixed fields only. Tested end to end (`e2e.rs`, `sighup_without_a_deny_file_is_ignored`). See I-3 for a harmless side effect. |
| deny L-1 | Stamp holds dev, inode, mtime, ctime, size; re-`fstat` after the parse | **Fixed.** `FileStamp` (`deny.rs`), taken from `fstat` of the opened file and compared again after the parse (`deny.rs:619`); a mismatch returns `Reload::Changed` with the stamp unset, so the next poll reads again; start-up retries 5 times then refuses. `changed()` follows symlinks like the open does, so a ConfigMap-style symlink swap is seen through the inode. Both scenarios of the original finding are tested. The optional "two stable ticks" step was not done; see I-2 for the residual. |
| deny L-2 | Mark before deletion; a gone file is judged by its mark | **Fixed.** `mark_once` (`deny.rs:653`) reads the existing marks (`denied_keys`, one read transaction) when the list has keys, takes the key from the file or else from the mark, writes marks for every key match, `purge` included (`deny.rs:697`), and only then deletes. A failed deletion keeps the mark (block stays out of `/query`) and schedules a new pass after `PURGE_RETRY` (300 s). Both scenarios are tested (`a_purge_interrupted_after_the_deletion_is_finished`, `a_failed_purge_deletion_keeps_the_block_unlisted`). Between the marking loop and the deletion loop the per-id lock is released; a concurrent `PUT` of that block is refused as denied, so nothing is lost. |
| deny L-3 | Pre-sizing with `try_reserve` | **Fixed.** `count_entries` does a first bounded read with the same line buffer, capped at `deny_max_entries`; `parse_sized` calls `try_reserve` on both maps before the parse and returns `OutOfMemory` on failure. The count is a hint only (tested with smaller and larger hints); a file changed between the two reads is caught by the L-1 re-`fstat`. The second read doubles the I/O of a reload, which is local and bounded. |
| mirror L-2 | Only the three named variables kept, wiped on drop; session-token header sensitive | **Fixed for what was claimed; partly open overall** (see L-2). `WipedEnv` (`lib.rs:275`) holds the start-up environment and zeroizes every value on drop (including on the error paths of `self_test` and `Settings::load`); `keep` moves out only the names from `Settings::credential_vars()` (none while `mirror_endpoint` is unset) and wipes the rest immediately; `Settings::load` sees only `SBTP_RELAY_*` copies, which by rule 22 never hold credentials (a `*_ref` starting with `SBTP_RELAY_` is refused). The `x-amz-security-token` header is marked sensitive. Still open from the original finding: `hmac` without its `zeroize` feature, and the per-request `HeaderValue` copies. `deploy/README.md` now documents the process-environment residual and `LimitCORE=0`. |
| mirror L-4 | `mirror_unverified_total`; `mirror_*` on the `stats` line | **Fixed.** A non-`200` answer, or no answer, of the verification `GET` after a `412` counts in `mirror_unverified`; the ten `mirror_*` fields are appended to the `stats` snapshot once the copy runs (`ON` flag), with `mirror_failed` summed over classes. Tested (`a_claimed_object_the_public_url_lacks_is_unverified`). The fields are counters only; no host, key or path. |
| deny I-7 (the brief says "mirror I-7") | `*_ref` lines log `unused` when the copy is off | **Fixed.** `config.rs` returns `unused` for the three `*_ref` names while `mirror_endpoint` is unset; tested end to end with a pasted value that never reaches the log. Note: this was finding I-7 of the **deny-list** report; I-7 of the mirror report (the lag recount) is untouched, which is fine (no fix was needed). |

## New code

### `sbtp-relay key-blocks <public-key-hex> [--config <path>]` (ADR 0052 rule 10)

What holds:

- **Dispatch.** `main.rs` recognises the subcommand only as the first argument, before the panic
  hook and the logger: the command writes no log line (ADR 0021) and opens no index (so no redb
  lock contention with a running relay). The relay path is unchanged otherwise.
- **Arguments.** The key must be exactly 64 lowercase hex digits (`store::decode_hex::<32>`);
  anything else exits 2 with a fixed message that does not repeat it. The rest goes to the
  relay's own `parse_args` (`--config <path>` once, nothing else). Only `SBTP_RELAY_*` variables
  are read; no credential is read or copied.
- **Read-only, offline.** It creates nothing: a missing `blocks` directory is an error, a
  `blocks` that is a symlink is refused (`symlink_metadata`). It contacts no network endpoint.
- **Walk.** `store::scan_tree` (shared with `Store::scan`, refactor checked to be behaviour
  preserving) skips non-directory shards without following links, accepts only names that parse
  as `<64 hex>.bin`, rebuilds the expected path from the identifier and skips any file not at its
  own shard, and skips non-regular files from `lstat`. Path traversal from the store is not
  possible: the path is rebuilt from a parsed identifier.
- **Header read.** `header_key` opens with `O_NOFOLLOW | O_NONBLOCK` (a symlink swapped in after
  the `lstat` fails to open; a FIFO does not block), re-checks `is_file` on the open descriptor,
  and reads at most 51 bytes (`OFFSET_PUBKEY + PUBKEY_LEN`) through `take` and `read_exact`; a
  short file yields `None`. No panic path: `pubkey_of` uses `get`.
- **While the relay runs.** Block files are written to `tmp/` and renamed into place, so a file is
  never seen half written under its final name. A file deleted before it is opened is skipped
  (`header_key` returns `None`), but see L-1 for a deletion between `readdir` and `lstat`.
- **Output.** Identifiers go to standard output only, one per line; a write error (closed pipe)
  stops with exit 1. Errors go to standard error and never include the key. The key is a public
  key, so even its appearance would not be a secret leak, but ADR 0052 rule 20 keeps it out of the
  relay log, and it is (tested: `!log.contains(&key)`).
- **`--config` and `data_dir`.** Both are operator input on the operator's own host; the command
  has no privilege of its own (no setuid), so pointing it at another path gains nothing the caller
  does not already have. See I-7 for a stderr detail when run with elevated rights.

### B10 test (`tests/deny.rs`, `a_walk_always_advances_past_denied_blocks`)

It walks a store with runs of denied blocks (by key and by `block_id`) at `limit=1`, ascending,
descending per parent, the shared listing and a grouped two-parent request with per-parent
cursors, and asserts at every step that no page has no identifier, `more = true` and the cursor it
was asked from, and that each walk ends (100 steps). The ungrouped walks also assert the exact
non-denied content. This discriminates the B10 criterion: a relay that returned its starting gap
on an all-denied page would fail the assertion. The grouped walk does not check the final content
(only progress and termination); that is enough for B10.

## Findings

### L-1 (low): `key-blocks` aborts on a block deleted during the walk and leaves a partial list with exit 1

- `crates/sbtp-relay/src/store.rs:744` (`fs::read_dir(shard.path())?`) and `:764`
  (`file.metadata()?`); used by `operator.rs` through `scan_tree`; `deploy/README.md:407`.
- Scenario: the operator runs `sbtp-relay key-blocks <key> > key-blocks.txt` on a running relay
  with demand eviction, `block_ttl_ms`, or a `purge` pass in progress. A block file that is listed
  by `readdir` and deleted before its `lstat` makes `DirEntry::metadata` fail with `ENOENT`; the
  `?` ends the whole walk. Standard output already holds the identifiers found so far, the process
  exits 1 with `reading the block store: No such file or directory` on standard error. The README
  command does not check the exit status, so an operator who does not notice the message purges
  only part of the key's blocks from the CDN; the rest stays cached for up to a year. The same
  race can hit any file, not only the key's, so the larger and busier the store, the likelier.
  `Store::scan` has the same `?`, but it runs at start-up when the relay is the only writer.
- Fix (code, no ADR):
  1. In `scan_tree`, treat `io::ErrorKind::NotFound` from `file.metadata()` and from
     `fs::read_dir(shard.path())` as "skip this entry"; keep other errors fatal.
  2. In `deploy/README.md`, write to a temporary file and keep it only on success, for example
     `sbtp-relay key-blocks <key> > key-blocks.tmp && mv key-blocks.tmp key-blocks.txt`, and say
     that a non-zero exit means the list is incomplete.
  3. A test that deletes a block file between two `scan_tree` callbacks.

### L-2 (low): remaining unwiped credential copies (mirror L-2, part not claimed)

- `Cargo.toml:77` (`hmac = { version = "=0.13.0", default-features = false }`);
  `crates/sbtp-relay/src/mirror/mod.rs` (request builder, `Authorization` and
  `x-amz-security-token` `HeaderValue`s).
- The keyed HMAC state of the SigV4 derivation is not wiped, because `hmac` is built without its
  `zeroize` feature. The per-request header values are `Bytes` copies freed unwiped
  (`set_sensitive` only affects `Debug` and HPACK, not memory). As in the original finding, this
  matters only to an attacker who can already read the relay's memory, who can read
  `/proc/<pid>/environ` as well; defence in depth.
- Fix: enable `hmac`'s `zeroize` feature in `[workspace.dependencies]` (`hmac 0.13.0` declares
  `zeroize = ["digest/zeroize"]`; `zeroize` is already in the graph, so no new package; confirm with
  `cargo tree` and `cargo deny check`). Accept the `HeaderValue` copies and record them in the
  roadmap: hyper owns that memory.

### I-1 (info): rule 10 says "after the marking pass", which is too late for a `purge` key

- ADR 0052 rule 10; `operator.rs`; `deploy/README.md` ("Copies the relay cannot reach").
- After a `purge` pass the files are gone; `key-blocks` then prints nothing and exits 0, which
  reads like "nothing to purge from the CDN". The README gives the right order (load `hide` or
  nothing, run `key-blocks`, purge the CDN, then switch to `purge`), and the marks would still hold
  the identifiers, but the command does not read the index.
- Fix: report to `spec-architect` a wording clarification of rule 10 ("before a `purge` entry is
  loaded" rather than "after the marking pass"). Optionally, when `deny_file` lists the key with
  `purge`, print one fixed warning line on standard error.

### I-2 (info): deny L-1 residual: a rewrite that pauses at a line boundary is still applied

- `deny.rs:582-622`.
- A writer that has truncated and written a prefix ending on a newline, then pauses past the whole
  parse, leaves the stamp equal at both `fstat` calls; the prefix is applied until the writer
  resumes and the next poll (`deny_reload_ms`). The re-`fstat` closes the common case (the write
  continues during the parse). The README tells operators to `mv` a complete file into place,
  which avoids it entirely.
- Fix: none needed. If wanted later, apply a poll-triggered reload only once the stamp is equal
  on two consecutive ticks (`SIGHUP` stays immediate).

### I-3 (info): a `SIGHUP` received during start-up is delivered once to `spawn_hangup`

- `lib.rs:609-620` and `:631`.
- tokio's process-wide handler records a signal that arrives while no runtime drives it; the
  listener created later by `spawn_hangup` then sees it once. Effect: one extra deny reload
  (idempotent) or one `sighup_ignored` line. Harmless.
- Fix: none.

### I-4 (info): `key-blocks` usage errors carry the relay's usage text

- `config.rs:2070`, reached through `operator.rs` (`Settings::load`).
- `sbtp-relay key-blocks <key> x` prints `unexpected argument `x`; usage: sbtp-relay [--config
  <path>]; usage: sbtp-relay key-blocks ...`. It repeats the operator's own argument on standard
  error, not in the log. Cosmetic.
- Fix: map `ConfigError::Args` to the command's own fixed usage line in `operator.rs`.

### I-5 (info): `key-blocks` trusts the file name and the header bytes

- `operator.rs:103`.
- The identifier comes from the file name and the key from bytes 19 to 50, without a full block
  validation or a check that the content hashes to the name. A damaged or planted file in the
  store lists a wrong identifier; the effect is an extra CDN purge, never a missed one. Only the
  relay's user can write there. Opening a device node in the store (with `O_NONBLOCK`) is likewise
  limited to that user.
- Fix: none; this is the right trade for a fast scan that reads 51 bytes per file.

### I-6 (info): `WipedEnv` covers the start-up vector, not the `SBTP_RELAY_*` copies or the process environment

- `lib.rs:135-145`.
- The `SBTP_RELAY_*` values cloned for `Settings::load` are not wiped; rule 22 forbids
  credentials there, so nothing secret is copied. The process environment block remains, as the
  README now says.
- Fix: none.

### I-7 (info): a `--config` pointed at another file may echo a fragment of it on standard error

- `config.rs:799-803` (TOML parse error text), reached by `key-blocks` and by the relay itself.
- A TOML parse error displays the offending line. Run as the relay's user (as the README says),
  this reveals nothing the caller cannot read. Run with `sudo` against an arbitrary path, it would
  print a line of that file, which the caller could read with `sudo` anyway.
- Fix: none; keep "run it as the relay's user" in the README.

### I-8 (info): a mirror test is flaky (restart re-sends a copied block)

- `crates/sbtp-relay/tests/mirror.rs:410`, `every_block_is_copied_once_and_the_cursor_survives_a_restart`.
- It failed once in four runs (`puts_of == 2` for one block): after `halt`, the restart sent a
  block that had already been copied. The branch does not touch the mirror cursor or window, so
  this is the known behaviour of mirror I-4 (the cursor is not saved at shutdown; progress since
  the last save is re-sent and ends as `412`), surfacing as a timing race in a test that assumes
  the drained-window save happened before `halt`. Safe (a re-sent block is a `412`), but a flaky
  test erodes CI signal.
- Fix: save the cursor once when `stop` fires (mirror I-4), or make the test wait for the saved
  cursor before `halt`.

## What was checked and holds

- No `unsafe`, no `unwrap`/indexing on file or network input in the new code (tests aside); no
  new dependency, `Cargo.lock` unchanged.
- No secret, key or token added to logs: the new `config_warning` carries fixed strings; the
  `stats` additions are counters; `key-blocks` writes no log line.
- The SIGHUP change cannot stop the relay: the handler is installed before any slow start-up step
  and the listener is spawned whatever the settings.
- The marking pass still releases nothing early: marks before deletions, removals only for
  completed deletions, retries bounded by `PASS_RETRY` and `PURGE_RETRY`.
- The deny-file reader keeps its earlier bounds (one bounded line buffer, `deny_max_entries`) in
  both the counting and the parsing read.

## Not checked

- Linux-specific behaviour was reasoned about, not run: tests ran on macOS (APFS); `ctime`
  nanoseconds, `O_NOFOLLOW` and `DirEntry::metadata` semantics are the same on Linux, and the
  container image was not built.
- The `docker exec ... key-blocks` path in the image (user, environment) was not exercised.
- The tokio signal-registry behaviour of I-1 and I-3 rests on tokio's documented caveats and its
  source design, not on a test that sends `SIGHUP` during the start-up window.
- No remote endpoint was contacted; crates.io data was not rechecked (no dependency changed).
- `gitleaks` was not run.
- `cargo test --workspace` did not complete: my first run piped its output through `head`, which
  cut it, and the volume then ran out of space (117 MB free; my scratch build directory took
  5.2 GB, which I deleted). I reran only `sbtp-relay`, in both builds. The other crates are not
  touched by the branch.
- My first `cargo deny check` (without `--offline`) tried to fetch the RustSec advisory database
  from GitHub (a `git fetch`) and the fetch failed. The result above is from
  `cargo deny --offline check` on the local copy, which may be a few days old.
- I did not confirm on `main` that I-8 is pre-existing (no disk space for a second build); the
  conclusion rests on the diff not touching the mirror cursor.
