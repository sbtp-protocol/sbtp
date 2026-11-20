# Security review: relay index on redb, milestone 0 (2026-11-18)

Scope: `git diff b2e8483..0e7f038` (branch `diag/relay-query-memory`, commits `6547aff`, `9cc8d96`,
`576330e`, `0e7f038`): `crates/sbtp-relay/src/index.rs`, `main.rs`, the two example tools, the release
profile, `redb = "=4.4.0"` and 37 new crates in `Cargo.lock`. Independent review from the diff, the ADRs
(0009, 0012, 0013, 0014, 0017), the crate sources in the local registry and crates.io, not from the author's
conclusions. All file and line references are at commit `0e7f038`.

**Verdict: OK to merge as milestone 0.** No critical or high finding in the merged code: there is no
handler, the binary listens on loopback and serves one placeholder route. Four findings (F-1 to F-4) MUST be
fixed, and re-reviewed, before the milestone that adds the `PUT` and `/query` handlers is merged; none of
them is exploitable today. The memory finding (F-1) stays open and gates any Internet exposure.

| # | Severity | Summary | When |
|---|---|---|---|
| F-1 | high (open, not reachable yet) | Memory growth under concurrent reads: the proposed bound is under-tested and placed too high | before milestone 1 merges; gates exposure |
| F-2 | medium | `insert` refuses a re-submitted block while a stale entry exists: unevictable orphan, or a fresh block deleted by the sweeper | before the `PUT` handler |
| F-3 | medium | Durability depends on a later insert, and `flush` is unreachable: an idle relay never makes its last entries durable | before the `PUT` handler |
| F-4 | low | `query` and `expired` trust the caller for `limit`; `limit = 0` yields `more = true` with an unchanged cursor | with the `/query` handler |
| F-5 | low | redb 4.4.0 lacks recovery fixes shipped in 4.5.0 and 4.6.0 | bump on or after 2026-11-27 |
| F-6 | low | Position pinned by a clock that once ran ahead; cursor order after a crash | milestone 1 |
| F-7 | low | Release profile: what a panic does once handlers exist | milestone 1 |
| F-8 | info | Supply chain, tooling, defaults | no action or housekeeping |

## What was checked

| Check | Result |
|---|---|
| `cargo test -p sbtp-relay --offline --locked` (on the branch) | 4 passed. |
| `cargo clippy -p sbtp-relay --all-targets --offline --locked -- -D warnings` | clean. |
| `cargo deny --offline check` | advisories ok, bans ok, licenses ok, sources ok (advisory database fetched today). |
| OSV query for `redb` | no advisory. |
| `Cargo.lock` | 37 packages added, none changed or removed; every source is the crates.io registry. For all 37: checksum equals the crates.io checksum, not yanked. SHA-256 of the cached `.crate` recomputed for redb, smallvec, mio, mime, tokio and log: equal to the lockfile. |
| Age | Youngest: `log` 0.4.35 (2026-10-30, 19 days), `smallvec` 1.16.4 (2026-10-23, 26 days), `tokio` 1.54.1 (28 days), `redb` 4.4.0 (2026-10-13, 36 days), `mio` 1.2.4 (46 days). All over 14 days. |
| Three pinned-back crates | `mime` 0.3.17 (0.3.18 is 13 days old), `mio` 1.2.4 (1.2.5 is 5 days old), `smallvec` 1.16.4 (1.16.5 is 12 days old, 1.16.6 is from today): each pin is the newest version that satisfies the rule. `mime`: no `unsafe`, no build script. |
| `smallvec` 1.16.4 | First 1.x release published by a new individual owner (`alejandro-vaz`; earlier ones by `jdm`, `emilio`, `mbrubeck`). Downloaded 1.16.3 and diffed: `src/` is identical, only the version and the dev lockfile differ. Fine. See F-8. |
| Build scripts among the new crates | `redb`, `httparse`, `parking_lot_core` only. Read all three: they print `cargo:` directives; `httparse` runs `rustc --version`. No network, no file write. Proc-macro: `tokio-macros` only (no `fs`, `net`, `process` or `env` use in its source). |
| redb tarball extras | `AGENTS.md`, `CLAUDE.md`, `justfile`, `scripts/podman-sandbox.sh`, `.cargo/config.toml`, container files. Read as data. `AGENTS.md` holds contributor instructions for agents working in the redb repository (run `just test`, commit trailers); nothing hostile, and nothing was followed. None of these files is referenced by `build.rs`, by `include!`/`include_str!` or by the manifest; Cargo ignores a dependency's `.cargo/config.toml`. They do not affect the build. |
| redb `unsafe` (54 occurrences, 6 files) | See below. Nothing reachable with attacker-chosen lengths or offsets. |
| Release build of `0e7f038` (exported to a scratch directory) | `cargo build --release --offline --locked -p sbtp-relay`: no example target compiled; the binary (1,547,040 bytes on macOS arm64) contains neither the test seed nor any `index_bench` / `query_diag` string. Every crate, dependencies included, is compiled with `-C overflow-checks=on`. |
| `vector-gen` guard | `cargo build --release -p sbtp-core --features vector-gen` still fails with the `compile_error!` of `sbtp-core/src/lib.rs:33`. The relay release graph has `ed25519-dalek` with `fast, zeroize` only (`cargo tree -e features`). |
| Index behaviour | A scratch probe (outside the repository) linked against the branch: edge positions, the re-submission case, and four `SIGKILL` runs. Results under F-2, F-3, F-4 and "Crash recovery". |

### redb 4.4.0 `unsafe`

| File | Compiled in the relay (Linux x86-64 musl) | Assessment |
|---|---|---|
| `sync.rs` (10) | No: the spin locks exist only under `cfg(redb_no_std)` or `test`; the std build re-exports `std::sync`. | Not in the binary. |
| `file_backend/optimized.rs` (2) | No: `pread`/`pwrite` wrappers under `cfg(target_os = "wasi")`. | Not in the binary. |
| `file_backend/range_lock.rs` (7) | Partly: `fcntl` open-file-description locks and one `mem::zeroed()` of `struct flock`. The Windows half is not compiled. | FFI on the database file with constant ranges checked by `checked_range`. No block data involved. |
| `transactions.rs:141`, `multimap_btree.rs:524,601` | Yes. | Pointer casts from `[u8]` to `#[repr(transparent)]` wrappers over `[u8]` (`PageListMut`, `DynamicCollection`, `UntypedDynamicCollection`). Sound by layout; no length or offset is derived from data. The relay uses no multimap table. |
| `tree_store/page_store/xxh3.rs` (32) | Yes: the AVX2 path, selected by `is_x86_feature_detected!`; NEON on aarch64. | Page checksums. The kernels assert `data.len() >= 64` and `secret.len() >= 64` before the unaligned loads, and callers slice with checked indexing. `scramble_accumulators_avx2` has no assert but always receives a 64-byte slice of a fixed 192-byte secret. Page content is partly sender-chosen (ids, parents); lengths are not. |

Senders control key and value bytes (32-byte identifiers), never a length, an offset or a page number.
The relay opens only the file it wrote; a crafted database file is out of scope and stays so as long as
`SBTP_RELAY_DATA` is not writable by another party.

## Findings

### F-1 (high, open): the bound on concurrent index reads is not yet a sufficient mitigation

`docs/benchmarks/2026-11-18-query-memory-diagnosis.md`. Up to 2.6 GB RSS with 8 concurrent query clients;
proposed fix: a `tokio::sync::Semaphore` of 2 (`index_max_readers`) in the `/query` handler.

Scenario if it reproduces on the shipped target: any client opens a handful of connections, pages through
`/query?limit=1000` and drives the relay from 10 MB to gigabytes; the host OOM-kills it. No PoW is needed
for reads.

The diagnosis itself is careful and its evidence (live heap 6 to 15 MB, 97% fragmentation, flat RSS under
`MallocSpaceEfficient=1`) supports "allocator retention, not a leak in redb". The mitigation is weaker
than the diagnosis:

1. **The trigger is not identified** (the report says so), and the data contradict "concurrency level" as
   the variable: 4 client threads stayed bounded in 4 runs of 4, but 8 threads behind a bound of 4 grew in
   3 runs of 3. The number and identity of the threads that allocate and free pages matters, not only how
   many run at once.
2. **The tested configuration is not the one proposed.** `query_diag` uses 8 fixed threads behind a
   condition-variable gate (`query_diag.rs:157-188`). The relay would run `query` on tokio's blocking
   pool, where a semaphore of 2 still spreads the work over many threads (the pool grows up to 512 and is
   shared with file I/O). Cross-thread frees then involve far more than 8 threads.
3. **Sample size.** The growth is stochastic (3 clients: 2 runs of 3). "Bound of 2 holds" rests on 3 runs
   of 8 seconds. A relay runs for weeks.
4. **Placement.** A semaphore in the `/query` handler leaves the other read paths unbounded: `contains`
   (the `PUT` of an already held block, ADR 0013 rule 9, which a client can repeat for free), `expired`,
   `len`, and the page reads of the writer. A later handler can also forget it.
5. **Cancellation.** A blocking task is not cancelled when its request is dropped. If the permit lives in
   the handler future, a client that resets its connections releases permits while the queries still run:
   the bound is bypassed by exactly the hostile client.
6. **Queue.** Waiters behind 2 permits are unbounded unless something else caps them.

Recommended fix:

- Enforce the bound **below the `IndexBackend` callers**, not in a handler: a fixed set of
  `index_max_readers` dedicated reader threads fed by a bounded queue, used by every read path. The thread
  count then equals the bound by construction, which is the configuration the diagnosis measured as safe,
  and no cancellation can exceed it. If a semaphore is kept, use `acquire_owned` and move the permit into
  the blocking closure.
- When the queue is full or a wait exceeds a short timeout: `503` `Unavailable` with `Retry-After` (ADR
  0012 rule 17), never an unbounded wait.
- Keep the permit for the index call only (it already returns an owned `Page`; the read transaction ends
  inside `query`, `index.rs:361-398`). Never hold it while writing the response.
- Around it, for `/query` as a whole: the per-IP limiter before any index work; a global in-flight cap
  with load shedding; a connection cap; a header-read timeout and a total request timeout; `limit`
  clamped to `max_query_limit` (F-4).
- Backstop outside the process: a memory limit on the unit or container (`MemoryMax=`), so that the worst
  case is a restart of the relay and not an OOM on the host.

What the Linux musl check must confirm, before milestone 1 merges:

1. `VmHWM` with no bound, 8 and 32 client threads, on the 8-parent adversarial index: does mallocng grow
   at all?
2. The same through the real path: HTTP, tokio blocking pool or the dedicated readers, not `query_diag`
   alone (ADR 0017 rule 2 already makes the in-process figure informative).
3. Enough samples for a stochastic effect: at least 30 runs per setting and one soak of 30 minutes or
   more, with `VmRSS` sampled, not only the high-water mark at the end.
4. A mixed load: `PUT`, `/query` and the sweeper together, and repeated `PUT` of held blocks (`contains`).
5. A connection-reset storm: clients that abandon requests, to prove the bound survives cancellation.
6. Throughput and p99 under the chosen bound, and CPU contention of mallocng with many threads.
7. A statement that only the musl build is supported, or the same check on glibc: glibc's per-thread
   arenas are the classic case of this retention pattern.

If musl shows growth that the bound does not remove, the backend decision returns to the owner (ADR 0013
rule 23); an alternative allocator is a new dependency and needs its own review.

### F-2 (medium): a re-submitted block cannot supersede a stale index entry

`index.rs:296-300` (the early return of `insert`) against `index.rs:451-454` (the comment in `remove`).

`insert` returns `None` whenever `ids[id]` exists. ADR 0013 rule 15 deletes the block file before the
index entries, and rule 13 says a block submitted again after eviction is a new block with a new position.
`insert` cannot express that: while the old entry exists, the new acceptance gets no position. The state
that the comment at line 451 guards against ("a later re-submission may own `ids[id]` at a newer
position") can never be produced by this code.

Reproduced with the probe: `insert(id, t=1000)` → position; `insert(id, t=5,000,000)` → `None`;
`remove([old])` → 1; `contains(id)` → `None`.

Scenarios once the `PUT` handler and the sweeper exist:

- **Unevictable orphan.** The sweeper deletes the file of an expired block; before it removes the index
  entries of its batch, a client re-submits the block (expiry is predictable from `/query` order and
  `block_ttl_ms`). The exclusive creation succeeds (`201`), `insert` returns `None`, then the sweeper
  removes the old entries. The file is held, has no index entry, is invisible to `/query` and is never
  swept, because the sweeper walks positions. Repeated, this fills `max_store_bytes` with blocks that never
  expire: `507` for everyone until a manual `reindex`. Each block costs one PoW, paid once.
- **Fresh block deleted.** After a crash between file deletion and index deletion (a phantom, rule 8), a
  re-submission gets `201` but stays listed at its old, expired position. The next sweep deletes the new
  file within one interval.

Fix: give the writer a way to say "this file was just created". For example
`insert(id, len, parents, now_ms, created: bool)`: when `created` is true and `ids[id]` exists, remove the
stale position (its `blocks` row and edges) and insert the new one in the same transaction. Keep the
current behaviour for the repair path of rule 9. Add the two scenarios above as tests; the ADR 0013
checklist lists them only from the file side.

### F-3 (medium): the last index entries are durable only if another insert follows

`index.rs:288-292` and `314-316`; `main.rs:37-38`.

A commit is durable only when an insert arrives at least one second after the previous durable commit.
Nothing makes the tail durable when traffic stops, and `flush` is unreachable: `axum::serve` has no
graceful shutdown, so `SIGTERM` ends the process before `main.rs:38`.

Reproduced: 50 inserts, 3 seconds idle, `SIGKILL`, reopen → `len` = 0. Every entry was lost, not "the last
second" of ADR 0013 rule 10. The block files would survive, so this creates orphans (rule 9), and the
reconciliation that repairs them does not exist yet. Every normal stop is also an unclean shutdown, so
every start pays the redb repair.

Fix: a periodic task that calls `flush` when a non-durable commit is pending (every
`DURABLE_COMMIT_INTERVAL`); `with_graceful_shutdown` on `SIGTERM`/`SIGINT`, then `flush`. Run `insert`,
`remove` and `flush` on blocking threads: they hold a `std::sync::Mutex` across disk I/O and `fsync`.

### F-4 (low): `limit` and `max` are trusted

`index.rs:362-390` and `405-412`.

`query` caps only the initial capacity (`limit.min(1024)`); the entries vector grows to `limit`. With an
unclamped `limit` a single request copies the whole table into memory. `limit = 0` returns no entry,
`more = true` and `next = from`: a client that follows `more` loops forever. `expired(_, usize::MAX)`
returns every expired position. ADR 0012 rule 8 puts the clamp and the `limit=0` rejection in the handler,
which is correct, but nothing in this layer enforces it.

Fix: clamp in the index as well (a `MAX_QUERY_LIMIT` constant of 1,000 and a non-zero type or an early
return for 0), so that a handler mistake cannot become a memory problem.

Checked and fine: any `(u64, u32)` start position is safe, `u64::MAX`/`u32::MAX` included (no panic, empty
page); the parent range is never inverted; `Position::next` uses checked and saturating arithmetic; a
duplicate parent yields one edge; row decoding uses `get`, `split_at_checked` and `as_chunks` and returns
`CorruptRow`. No `unwrap`, indexing or unchecked arithmetic on any input path of `index.rs`.

### F-5 (low): redb 4.4.0 is behind two releases with recovery fixes

`Cargo.toml:38`. The pin follows the two-week rule correctly. According to the upstream changelog
(fetched from the redb repository, to be re-read when bumping): 4.5.0 turns a panic on a malformed
allocator state at `open()` into `StorageError::Corrupted`; 4.6.0 fixes a repair that could fall back to a
commit slot with a failed checksum and open a damaged database as empty, and a read at close time that
could see a later commit. The relay kills and repairs this file by design (benchmark step 5), so these
paths matter more here than in most uses. An index that silently opens empty is recoverable (rule 1) but
would hide every held block until a rebuild.

Fix: move to 4.6.0 on or after 2026-11-27, with a diff review of 4.4.0 → 4.6.0, before the relay is
exposed. Single maintainer (`cberner`), 463,418 downloads for this version: acceptable for derived data,
and a reason to keep `IndexBackend` as the only coupling.

### F-6 (low): time handling in positions

- `index.rs:284-287`. If the relay clock was ever ahead (bad RTC, operator error), `last.received_at`
  stays ahead after the correction and survives restarts (`index.rs:244`). Every new block then gets that
  future `received_at` until real time catches up: such blocks outlive `block_ttl_ms` by the size of the
  jump, and `since=now` returns nothing new. The opposite case (clock behind at boot, before NTP) gives
  positions near zero, and those blocks expire at the first sweep. Fix: at start-up and on insert, log and
  refuse (`503`) when `last.received_at` exceeds the clock by more than a small tolerance; start the relay
  after time synchronisation.
- After a crash, positions handed out in cursors may no longer exist, and reconciliation (rule 9) may
  re-insert blocks at positions below a cursor a client still holds; that client never sees them (ADR 0012
  rule 12). Simplest fix: draw a new epoch after an unclean shutdown, so that old cursors get
  `InvalidCursor`. ADR 0017 rule 18 already allows an epoch change. This needs a decision from
  the specification editor, since ADR 0012 rule 9 says a cursor survives a restart.
- `Position::next` at `(u64::MAX, u32::MAX)` returns `(u64::MAX, 0)`, which is lower. Unreachable through
  `insert` with a sane clock; harmless in `query` (the page is empty there). No fix needed; a comment would
  do.

### F-7 (low): release profile and panics

`Cargo.toml:49-56`. `overflow-checks = true` is a sound choice and applies to every crate of the build.
`panic` stays `unwind`, as ADR 0013 requires. Consequences to handle in milestone 1:

- A panic in a handler unwinds its connection task: the client sees a closed connection, not a `500`, and
  nothing is logged by default. Add `tower_http::catch_panic::CatchPanicLayer` mapped to the `Internal`
  error body, and count panics.
- A panic in `spawn_blocking` surfaces as a `JoinError`: map it, never `unwrap` it.
- A panic on a thread the runtime does not own (dedicated index readers, the sweeper) kills that thread
  silently. Supervise them and exit the process if one dies.
- The index mutex recovers from poisoning (`index.rs:280-283`), which is correct: its state is written
  only after a successful commit. redb's internal locks use `lock().unwrap()`: after a panic inside redb
  every later call may panic too. Treat repeated index failures as fatal and let the supervisor restart
  the relay, instead of serving `500` forever.
- Dependencies now panic on an overflow that used to wrap in release builds. This is the intended effect;
  it turns a silent wrong value into a failed request. The Linux gate must be measured with this flag
  (binary size and throughput change slightly).
- `strip = true` removes symbols: panic backtraces in production logs are addresses only. Keep the
  unstripped artefact of each release.
- The `vector-gen` guard keys on `debug_assertions`. It holds for this profile (verified). It would be
  silently defeated by a profile that sets `debug-assertions = true`; do not add one.

### F-8 (info)

- **Tooling stays out of the binary.** `examples/index_bench` and `examples/query_diag.rs` are example
  targets; `cargo build --release -p sbtp-relay` does not compile them (verified in the build log and in
  the binary). They add no dependency.
- **Test key.** `index_bench/dataset.rs:23-24`: `KEY_SEED = *b"sbtp-relay-bench-public-test-key"`, a public
  ASCII constant with the comment "Never a real key". It is documented in the source only. Add one line to
  the benchmark documentation so that nobody mistakes blocks signed with it for anything else.
- **`index_bench run <dataset> <work>`** deletes `<work>` recursively if it exists (`main.rs:83`). A typo
  deletes a directory. Refuse a non-empty directory that the tool did not create (marker file).
- **`smallvec`.** New individual publisher since 1.16.4 on a crate with hundreds of millions of
  downloads. 1.16.4 is clean (identical source to 1.16.3). Diff the source at the next bump instead of
  trusting the version number.
- **`tokio` features.** `full` links `process`, `fs`, `signal`, `io-std` into an exposed binary
  (`Cargo.toml:32`). Narrow to what the relay uses (`rt-multi-thread`, `net`, `macros`, `sync`, `time`,
  `signal`) when the handlers land.
- **Defaults.** Loopback by default (`main.rs:17`): good. `SBTP_RELAY_LISTEN=0.0.0.0:…` is accepted
  silently: log a warning. `SBTP_RELAY_DATA` defaults to a relative `data` (`main.rs:18`): the index lands
  in whatever the working directory is. The index file is created with the process umask; it holds public
  data only. The placeholder route prints the epoch, which cursors make public anyway.
- **Paths.** No path is built from block data anywhere in the diff.
- **Unit tests** use predictable names under the temp directory (`index.rs:486-491`). Test-only; harmless.

## Crash recovery (observed)

Three runs of continuous inserts (two parents per block) killed with `SIGKILL` after 3 seconds, then
reopened: the index opened in 186 to 294 ms at 135 MB; `blocks` and `ids` agreed for every listed entry
(76,985, 146,695 and 221,951 entries); about one second of acknowledged inserts was lost each time, as
ADR 0013 rule 10 allows. The writer resumes from the last stored position (`index.rs:244`). "First write
wins" holds inside the index: the duplicate check and the insert share one write transaction under the
writer mutex, so two concurrent inserts of one identifier cannot both get a position.

## Not checked

- No run on Linux or musl: every memory figure and the recovery runs above are macOS arm64. `fsync`
  semantics differ (macOS does not force the drive cache); power-loss behaviour was not tested, only
  `SIGKILL`.
- redb was reviewed for its `unsafe` blocks, its build script and its packaging, not line by line (about
  2,600 lines contain an `assert!`, `unwrap` or `panic!`). Its B-tree and repair logic are trusted on the
  strength of upstream fuzzing and tests.
- The changelog entries of redb 4.5.0 and 4.6.0 were read through a summary, not from the source diff.
- `mio`, `tokio`, `hyper`, `axum` and the other new HTTP crates: checksum, age, yank status, build scripts
  and publishers only. No source audit. They carry `unsafe` (176 occurrences in `mio`, 83 in `smallvec`).
- `index_bench/main.rs` and `query_diag.rs` were read for process spawning, file deletion and the
  concurrency gate, not for the correctness of their measurements.
- The memory diagnosis was evaluated from its report and the tool's source; its runs were not repeated.
- Quota accounting, the sweeper, reconciliation, the cursor encoding and every handler: not written yet.
- The fuzz workspace (`cargo deny --manifest-path fuzz/Cargo.toml check`) is untouched by this diff and
  was not re-run.
