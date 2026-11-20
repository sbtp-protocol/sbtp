# Security and correctness review: relay milestone 1c, limits (`feat/relay-m1c-limits`)

- Date: 2026-11-19
- Reviewer: security reviewer (combined security and correctness pass)
- Scope: `git diff main...feat/relay-m1c-limits` (commits `6da4169`, `0224e2e`; 10 files under
  `crates/sbtp-relay/`, about +720/-70). No dependency change (`Cargo.toml`, `Cargo.lock` untouched).
- References: ADR 0027 (rules 1 to 7, clarifications T1, T2, T3), ADR 0018 (rules 21, 28, 29, 35, 37,
  clarification M5), ADR 0019 rule 31, ADR 0020 rules 23 to 25, ADR 0021 rules 7 and 37,
  `docs/spec/sbtp-core-v0.2.md` §4.
- Automated checks run in the worktree: `cargo test -p sbtp-relay` (all suites green, 197 tests),
  `cargo clippy -p sbtp-relay --all-targets -- -D warnings` (clean), `cargo fmt --all --check` (clean).

## Verdict

**Mergeable after M-1 is fixed.** No finding gives a remote client a new capability against a healthy
relay. M-1 is a conformance gap in ADR 0018 rule 37 (the fatal exit is not reached in the main failure
mode it exists for); it is not exploitable but should be fixed before the merge, with a short re-review
of the fix. L-1 and the info points can follow.

## Findings

### M-1 (medium): any successful index call resets the failure streak, so a broken writer is never fatal under read traffic

- Files: `crates/sbtp-relay/src/pool.rs:274` (`Shared::record`), callers
  `crates/sbtp-relay/src/blocks.rs:376` (lookup in `unindexed`), `blocks.rs:409` (insert),
  `crates/sbtp-relay/src/query.rs:316` (`/query` page), `pool.rs:603` (periodic commit).
- Rule: ADR 0018 rule 37, last bullet: repeated index failures MUST be fatal after a fixed number of
  consecutive failures. The module comment (`pool.rs`, rule 37 bullet) names the target case: "a
  backend left broken (for example by a panic inside redb) is restarted instead of answering `500`
  forever".
- Problem: one global counter, reset to 0 by a success of any kind (read or write). In redb 4.6.0 the
  realistic "broken backend" is write-side:
  - a failed commit invalidates the allocator state; every later write transaction fails with
    `StorageError::Corrupted("... reopen the database to repair it")` (`redb-4.6.0/src/db.rs:1023`
    onwards). A restart is exactly the cure;
  - a failed file write latches `io_failed`, so later file accesses fail with `PreviousIo`, but page
    reads served from the read cache or write buffer return `Ok` without checking the latch
    (`redb-4.6.0/src/tree_store/page_store/cached_file.rs:696-722`).
  Reads therefore keep succeeding while every insert fails.
- Scenario: the index writer is broken as above. Each new `PUT` fails its insert (count 1), but any
  `/query` page, any re-`PUT` of a stored block (lookup in `unindexed`) or any `GET` that runs a
  lookup succeeds from cache and resets the count to 0. On a relay with ordinary mixed traffic the
  count never reaches 32: the relay answers `500` to every new block forever, which is what rule 37
  is meant to prevent. Any client (or ordinary traffic) also keeps it alive this way, though that gives
  an attacker nothing beyond the existing outage.
- Fix: count per family. For example two counters, `write_failures` (insert, periodic commit, the
  rule-9 orphan insert) reset only by a successful write, and `read_failures` (lookup, `/query` page)
  reset only by a successful read; exit when either reaches `FATAL_INDEX_FAILURES`. Document the
  families next to the constant. Add a test that interleaves one successful read with one failed write
  32 times and expects exit status 70 (the existing child-process pattern works), and a test of the
  periodic-commit path, which no test covers today.

### L-1 (low): `CorruptRow` counts toward the fatal exit, so one corrupt index row lets any client trigger a restart loop

- Files: `crates/sbtp-relay/src/pool.rs:297` (`outcome`), `crates/sbtp-relay/src/query.rs:316`,
  `crates/sbtp-relay/src/index.rs:528` (`/query` over `blocks` returns `CorruptRow`).
- Precondition: a `blocks` row is malformed (written by the relay itself, under redb checksums, so
  unlikely). No client input can produce a redb error or `CorruptRow` on a sound index: I checked that
  every range built in `query` is ordered (`from <= (u64::MAX, u32::MAX)`) and that pool refusals
  (`PoolError`: full queue, expired wait) are not counted.
- Scenario: with one such row, any client sends 32 unfiltered `GET /sbtp/v1/query` from the start (or
  past the row). The query bucket allows 20 per key, so two keys, a /64, or the overflow key are
  enough. The relay exits with status 70, restarts (start-up walk included), and the corruption is
  still there, so the same 32 requests take it down again. Before this branch the same row gave `500`
  on one page and the rest of the relay kept serving. The branch turns a local fault into an
  availability lever that anyone can pull.
- Fix: do not count `CorruptRow`, for the reason given for `ENOSPC` (a restart does not cure it), or
  count only `IndexError::Db`. Keep logging and counting it in metrics (ADR 0021 rule 37).

### I-1 (info): after the first `ENOSPC` on the index, later errors are `PreviousIo` and do count

- Files: `crates/sbtp-relay/src/pool.rs:297`, `crates/sbtp-relay/src/store.rs:242` (`no_space`).
- redb latches the first write failure. Only that first error carries `ENOSPC`; the following ones are
  `StorageError::PreviousIo` with no errno. They are counted, so a full index partition still ends in
  exit 70 after 32 calls, contrary to the comment on `FATAL_INDEX_FAILURES` ("a failure for lack of
  space ... is not counted"). In practice this is the better behaviour, because redb needs a reopen to
  recover once space is freed. Related, and not new on this branch: those later `PUT` errors are
  answered `500`, not `507`. Recommend that the specification editor states the intended outcome together with
  the pending `critical` state (`HOOK(1c)`, ADR 0021 rule 37), then align the comment.

### I-2 (info): the preallocated map is resident from start-up, not "as keys arrive"

- File: `crates/sbtp-relay/src/limiter.rs:117` (`slots.resize(n, None)`).
- `resize` writes every slot, so all of `2 x max x 56` bytes is touched at start-up: 112 bytes per key,
  0.4 MiB `small`, 3.5 MiB `standard`, 28 MiB `large`, 1.75 GiB at the maximum of
  `rate_limit_max_clients` (about a second of start-up at that size). This stays within the T1 term
  (192 bytes per key). The T2 sentence "resident memory grows as keys arrive" is descriptive, not
  normative. Touching the memory up front also makes an overcommitted host fail at start-up rather
  than later. No change needed; at most reword the T2 note.

### I-3 (info): little margin left in the T1 estimate in the worst B-tree case

- File: `crates/sbtp-relay/src/limiter.rs:720` (`the_entry_estimate_covers_the_limiter_types`).
- Measured types: `ClientKey` 18 bytes, `Entry` 32, slot `Option<(ClientKey, Entry)>` 56 (niche, no
  extra byte), order element 32. The test's formula is the one T1 prescribes: `2 x 57 + 2 x 32 = 178 <=
  192`. A `BTreeSet` leaf holds 11 elements in about 368 bytes and can drop to 5, which is about 74
  bytes per element plus internal nodes. In the worst case the real cost is therefore 112 + about 80,
  close to 192. Typical occupancy is far better, and the Linux gate measure replaces the estimate
  (ADR 0018 rule 35). Worth checking at the gate, nothing to change now.

### I-4 (info): `KeyTable::insert` drops silently when there is no room

- File: `crates/sbtp-relay/src/limiter.rs:172`.
- If it were ever reached, the key would be in `order` but not in `map`. It cannot be reached:
  `take_at` inserts only while `len < max_clients`, and the table has `2 x max_clients` slots. A
  `debug_assert!` or a `bool` return checked by the caller would make the invariant explicit without
  adding a panic on release builds.

### I-5 (info): pins table may still rehash in place under churn

- File: `crates/sbtp-relay/src/limiter.rs:287`.
- The table is a standard `HashMap` reserved for `max_connections` keys. Its deletion markers can force
  an in-place rehash, O(`max_connections`) under the limiter mutex, amortised: below a millisecond at
  65,535. This is allowed by T2 ("MAY preallocate") and documented in the code. No action.

## Verified and holds

- **ADR 0027 T2, `KeyTable`.** Allocated with `try_reserve_exact` in `ConnLimits::from_settings`,
  before the bind (`lib.rs`); a failure is `StartError::Io(OutOfMemory)` and the relay does not
  listen. The `Vec` has no growth path. Load is at most 1/2, so every probe ends at an empty slot.
  Backward-shift deletion uses the correct condition: the hole lies on the probe path from the key's
  home to `j`, `distance(home, j) >= distance(hole, j)`, with wrap-around. There are no tombstones and
  no pass over the table. No `unsafe`, no `[]` indexing, and no arithmetic that can overflow:
  `i + 1 < len`, `to + len - from` with `to < from <= len`, `len -= 1` only after a successful take.
  The hash is std `RandomState` (SipHash with a per-process random key), so remote clients cannot aim
  collisions. The expected probe length is about 1.5 / 2.5, and the longest cluster is logarithmic
  with high probability. `slots_match_a_model` is a good discriminating test: 40 keys over 32 slots,
  200,000 random operations, wrap-around clusters, compared with `HashMap`.
- **T1.** `EST_LIMITER_ENTRY = 192`. The `size_of` test implements the T1 formula, and the profile
  bounds in `startup.rs` equal the T1 table exactly (13,665,748 / 100,972,368 / 1,224,232,608).
- **T3.** Pinned keys stay out of the order (new pinned key, pin, unpin); the victim is popped only if
  `full <= now`.
- **M5** (`config.rs:984`). Checked after all sources are merged, with `saturating_mul`. The message
  names both settings and their effective values. Tests cover env, file overridden by env, the
  profiles, both ends of the range, and the range check taking precedence.
- **Buckets, ADR 0018 rules 21, 28, 29; ADR 0020 rules 23 to 25.** Every class takes its token in
  `admit` (step 3), before the router, before any `404`/`405`/`413` and before the body is read. The
  HTTP test sends `PUT` with `Content-Length: 70000` and no body and gets `429`. That discriminates
  the order: a relay that read the body would time out, and one that checked the length first would
  answer `413`. Preflights and unknown paths cost a `block` token. Exempt keys skip the limiter. The
  test helper raises the `block`/`put` bursts so that other suites are not throttled; the bucket tests
  set their own.
- **Fatal exit, remote reachability.** Only `IndexError::Db` and `CorruptRow` are counted, and neither
  can be produced by client input on a sound index (see L-1). `PoolError` is not counted. No exit
  happens once `stopping` is set. The `fatal` line carries `msg` only (ADR 0021 rule 7) and is flushed
  before `exit(70)`. Exiting while the writer runs loses at most the non-durable tail (≤ 1 s), as the
  existing thread-supervision exit already does.

## Not checked

- Real failure injection into redb. The cache-hit and latching behaviour behind M-1 and I-1 comes from
  reading the redb 4.6.0 source, not from a run.
- The Linux memory gate (resident set at the profiles and at the maximum of `rate_limit_max_clients`)
  and the latency of a 16,777,216-key table.
- `cargo deny check`: not run, because no dependency changed.

## Re-review (fix commit `f65bc86`)

- Date: 2026-11-19
- Scope: `git show f65bc86` (7 files under `crates/sbtp-relay/`, +372/-82), read in the worktree at
  that commit. No dependency change.
- Checks run: `cargo test -p sbtp-relay` (all suites green, including the four new or rewritten
  pool tests and `tests/index_corrupt.rs`), `cargo test -p sbtp-relay --release --lib limiter`
  (green, `debug_assert!` compiled out), `cargo clippy -p sbtp-relay --all-targets -- -D warnings`
  (clean).

### M-1: fixed

- `Shared` now holds `read_failures` and `write_failures`; `record(family, ok)` resets only the
  count of its own family and exits when either reaches `FATAL_INDEX_FAILURES`
  (`pool.rs`, `Shared::record`).
- Every index call site made while serving is classified, and correctly:

  | Call site | Index call | Family |
  |---|---|---|
  | `query.rs:317` `/query` page | `query` (reader thread) | read |
  | `blocks.rs:377` `unindexed` | `contains` (reader thread) | read |
  | `blocks.rs:410` `insert`, used by the new-block path and by `index_orphan` (rule 9) | `insert` (writer) | write |
  | `pool.rs:648` periodic tick | `flush_pending` (writer) | write; `Ok(false)` neutral |

  Not counted, and rightly so: the start-up walk (`lib.rs:150`, a failure there aborts the start)
  and the shutdown `flush` (reported by `shutdown`). There are no retention call sites
  (`expired`/`remove`) on this branch yet; when they arrive they belong to the write family.
- Can a client reset the write count while the writer is broken? I looked for a write that returns
  `Ok` without committing. `RedbIndex::insert` returns `Ok(None)` after `abort` when an
  `AlreadyHeld` id is already indexed, but that path is only reached after `unindexed` saw no entry,
  so a client cannot steer it (only a benign race). In redb 4.6.0 a failed commit invalidates the
  allocator state, and `begin_write_holding` (`db.rs:2020-2030`) then refuses every later write
  transaction, non-durable ones included. A broken writer therefore fails every insert and every
  tick, and nothing in the write family can succeed and reset the count.
- Tests discriminate: `failed_writes_between_good_reads_exit_the_process` alternates
  `record_read(Ok)` and `record_write(EIO)` 32 times in a child process and expects status 70. With
  the old shared counter the child would sleep 30 s and exit 0, so the test fails.
  `periodic_commit_failures_are_counted_as_writes` fails if the tick were recorded as a read
  (`failures().1` would stay 0) or if `Ok(false)` were counted either way. The unit test checks that
  each family's reset is independent.

### L-1: fixed

- `IndexBackend::restart_may_cure` (default `true`) is consulted first in `outcome`; `RedbIndex`
  returns `true` only for `IndexError::Db`, so `CorruptRow` is never counted. It is still logged and
  counted in metrics by the callers (`index_read_failed`, `index_write_failed`), which did not change.
- `tests/index_corrupt.rs` serves 64 corrupt-row `/query` pages over HTTP, then `/info`. It runs in
  its own test binary, so if `CorruptRow` were counted the process would exit with 70 and the test
  would fail. The wrapper delegates `restart_may_cure` to `RedbIndex`, so the production
  classification is what gets tested, not a test-only override. `tests/index_read.rs` was aligned in
  the same way.
- Remote reachability after the fix: on a sound index, no client input produces `IndexError::Db` in
  either family (ranges ordered, row sizes bounded by the 64 KiB block limit, pool refusals not
  counted). A client can still reset the **read** count with successful reads, but only while reads
  actually work, which is the intended semantics.

### I-4: fixed

- `KeyTable::insert` returns `bool` (`#[must_use]`). The only caller (`Limiter::take_at`) asserts it
  in debug builds. In release builds a refusal (unreachable: the caller checks
  `map.len() < max_clients` against a table of `2 x max_clients` slots, and `insert` refuses only at
  `len >= slots / 2`) leaves the key out of both `map` and `order` and charges the overflow bucket.
  The table stays consistent and nothing panics. The unit test asserts that the fifth insert into a
  4-key table returns `false`.

### New observations

- **Info, residual of L-1 at page level.** A redb page-checksum failure surfaces as
  `IndexError::Db(StorageError::Corrupted)` and is counted. A client reaching such a page could
  therefore force exit 70. The precondition is on-disk corruption under redb's checksums (a local
  fault, not client-reachable on a sound disk). Exit 70 is an unclean shutdown, so redb repairs on
  reopen; if the page cannot be repaired, the start fails instead of looping. No action now; worth one
  line in the I-1 clarification for the specification editor.
- **Info.** The default `restart_may_cure = true` is conservative (unknown errors count). Only
  `RedbIndex` is a production backend, so this is fine.

### Still open (deliberately)

- I-1 (`PreviousIo` after a first `ENOSPC` is counted) and the threshold 32: unchanged, now
  documented as a known gap on `FATAL_INDEX_FAILURES`, pending the specification editor. If a client could
  fill the index file system, this would become a restart lever. Today the store budget
  (`max_store_bytes`) is what prevents that, so the clarification should state the intended outcome.
- I-2, I-3, I-5: no action, as before.

### Verdict

**M-1, L-1 and I-4 are fixed; no new finding of medium or higher. Mergeable.** Not checked again:
real failure injection into redb (the claim that writes stay broken after a failed commit comes from
reading the redb 4.6.0 source), and the Linux memory gate.
