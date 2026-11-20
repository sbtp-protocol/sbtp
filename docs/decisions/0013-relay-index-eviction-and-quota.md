# 0013: Relay index, TTL eviction and storage quota

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0014 (adversarial data set uses the format maximum of 8 parents); 0017 (benchmark protocol clarifications); 0021 (rule 19: disk-space watermark); 0023 (rules 9 and 18: reconciliation at every start with full validation of orphans; quota counts quarantined files; its clarifications of 2026-11-21 also cover rules 9 and 19); 0024 (rule 5: new epoch when the start-up walk indexes an orphan); 0025 (rule 18: tree and entry charges); 0043 (rule 13: an expired block is not held for `PUT` and is a new block, `201`, even before the sweep; rule 15: the sweeper deletes nothing of a block re-accepted after expiry)
- Date: 2026-11-18
- Questions: Q-12 (resolved; chunk storage stays under Q-21)
- Depends on: ADR 0012 (`/query` order, cursor, error names); ADR 0003 rule 9, ADR 0008 rule 6 and
  ADR 0009 (exclusive creation, flat files) are unchanged
- Impact: `docs/spec/architecture.md` §2 (storage, new "Index", "Eviction" and "Quota" parts); spec §4
  (`PUT`: `507`; `/info`: `block_ttl_ms`); `sbtp-relay` (index, sweeper, quota, start-up); workspace
  dependencies (redb, conditional on the benchmark) and `rust-version` of `sbtp-relay`; no `sbtp-core` change; no layer 0 test vector

## Context

`/query?parent=` and `since=` (spec §4, ADR 0012) need an index that flat files do not give. ADR 0009
settled the file layout and left three points of Q-12 open: the `parent → children` index and the time
index, the eviction sweeper, and what a relay does when its storage is full.

Forces:

- The relay reads header fields only (Parents Hashes, PubKey, Timestamp). It never parses a payload.
- Targets: under 15 MB of RAM, a binary of about 5 MB (`architecture.md` §3). The relay is exposed to the
  Internet without authentication.
- No external database. `architecture.md` §2 describes flat files and an LRU cache; an embedded store
  needs a justification.
- Storage is "first write wins" by exclusive creation (ADR 0009, security review B-6). A block file and
  an index entry cannot be written in one atomic step, whatever the index is.
- `architecture.md` §2 says "TTL eviction of blocks not requested recently or at the end of their
  lifetime" and no mechanism exists: an explicit sweeper is needed (Q-12).
- A sender chooses the parents of its block. One block can name 15 parents that exist nowhere. Each
  costs one index entry: the index grows up to 15 times faster than the number of blocks, at the price
  of one proof of work.

### Library facts checked on 2026-11-18

redb, from Context7 (`/cberner/redb`: upstream docs and `docs/design.md`) and the crates.io API:

| Fact | Source |
|---|---|
| Pure Rust, copy-on-write B-trees, ACID, one file. Page size 4,096 bytes, not configurable in release builds. | Context7, configuration reference |
| `Builder::set_cache_size(bytes)`; the default cache is 1 GiB. | Context7, `Builder` |
| `Durability::Immediate` (default): persistent when `commit` returns. `Durability::None`: not persistent until a later `Immediate` commit. | Context7, `Durability` |
| After an unclean shutdown, opening the file runs a repair. A full repair walks every tree to rebuild the allocator state. With `WriteTransaction::set_quick_repair(true)` the repair is immediate and commits are slower. | Context7, `docs/design.md` "Database repair" |
| `Database::compact(&mut self)` shrinks the file; refused while a transaction is open. | Context7, `Database::compact` |
| Multimap tables exist (`MultimapTableDefinition`). | Context7 |
| Latest release 4.6.0 (2026-11-13). 4.5.0: 2026-11-05. 4.4.0: 2026-10-13. All 4.x declare `rust-version = 1.90`. 2.6.4 (2026-10-02) declares 1.85. | crates.io API |
| Non-optional dependency of 4.6.0: `libc` only (Linux, Apple, WASI). License MIT OR Apache-2.0. 16.5 million downloads. | crates.io API |

Not checked: the effect of redb on the binary size; the resident memory of a process with a small cache;
whether the facts above hold for the 2.6 line (the fetched docs describe the current line).

Every figure in bytes per block below is an estimate from record sizes. None was measured.

## Decision

Rules 1 to 21 do not depend on the index backend. Rules 22 to 26 set the backend.

### Index: content and positions

1. **Derived data.** Block files (ADR 0009) are the only source of truth. The index is derived from them
   and from the reception times. A relay MUST be able to rebuild it from the block files alone. The index
   format is internal to a relay and is not part of the protocol.
2. **Acceptance.** A block is accepted when the exclusive creation of its file succeeds (the `201` case of
   ADR 0008). The relay then assigns it `received_at`, its clock as a Unix time in milliseconds, and a
   position.
3. **Positions.** A position is the pair `(received_at, n)`, `n` breaking ties inside one millisecond.
   Positions are strictly increasing in acceptance order. `received_at` never decreases: if the clock
   steps back, the relay reuses the last `received_at`. One writer assigns positions and publishes index
   entries in position order: no entry may become visible at a position lower than one already visible.
4. **Entries.** For each accepted block the index holds: its position, its `block_id`, its length, and
   one edge `(parent, position) → block_id` per parent, read from the Parents Hashes field. The relay
   reads nothing after the Parents Hashes field. A parent does not need to be held or known.
5. **Epoch.** An index carries a random 64-bit epoch, drawn when the index is created or rebuilt. A
   `/query` cursor (ADR 0012 rule 9) encodes the epoch and a position. A cursor with another epoch gets
   `InvalidCursor`.
6. **Known block.** A `PUT` of a block already held (`200`, ADR 0008) assigns no position and changes no
   entry.

### Write path and crash consistency

7. A new block is processed in this order: validation (spec §4); quota check (rules 18 to 20); block file
   written to a temporary file, flushed to disk (`fsync`), then created exclusively under its final name;
   index entries; response `201`.
8. **Phantoms are tolerated.** The index MAY hold an entry for a block the relay no longer holds. A
   client already handles a `404` after `/query` (ADR 0012 rule 13). The sweeper removes such entries.
9. **Orphans are repaired.** A held block with no index entry is invisible to `/query`. A relay MUST
   repair it: when a `PUT` finds the block already held and not indexed, it adds the entries (position
   from the current time); and after an unclean shutdown, the relay MUST reconcile the block files
   written since the last durable index state with the index, using the file modification time as
   `received_at`.
10. The index MAY be made durable in batches (at most 1 second apart, and at shutdown) and not on every
    `PUT`. A power loss can then lose index entries of the last second; rule 9 restores them.
11. Until the index is ready at start-up, `/query` and `PUT` get `503` (`Unavailable`) with
    `Retry-After`. `GET /block` and `/info` do not need the index and SHOULD be served.

### Eviction

12. **By age.** A relay setting `block_ttl_ms` gives the lifetime of a block. A block expires when
    `received_at + block_ttl_ms ≤ now`. Default: 2,592,000,000 (30 days). Eviction does not depend on
    reads: a `GET` writes no state.
13. **No extension.** A `PUT` of a held block (`200`) does not extend its lifetime. After eviction the
    block can be submitted again; it is then a new block for the relay (`201`, new position).
14. **Queries.** `/query` MUST NOT list an expired block. The relay applies the expiry bound when it
    builds a response; it does not wait for the sweeper.
15. **Sweeper.** A periodic task (default: every 60 seconds) removes expired blocks, oldest first, with
    a bounded amount of work per run. For each block, in this order: drop it from the LRU cache; delete
    the block file; delete its index entries. A crash between two steps leaves a phantom (rule 8) and the
    next run finishes the work. `GET /block` MAY still serve an expired block until its file is deleted.
16. **Archive relays.** Eviction by age can be disabled (`block_ttl_ms` unset). `/info` then publishes
    `"block_ttl_ms": null`. Such a relay never deletes a block and answers `507` when full (rule 19).
17. Eviction is local. It creates no tombstone, sends no notification and is not a deletion mechanism:
    other relays and clients keep the block.

### Quota

18. **Setting.** `max_store_bytes` bounds the disk space of a relay: the sum, over block files, of the
    file length rounded up to 4,096 bytes, plus the size of the index. Default: 1 GiB. The relay keeps the
    sum up to date and checks it before writing; it does not wait for the file system to fail.
19. **Full.** When a new block does not fit, the relay answers `507 Insufficient Storage` with the error
    `StorageFull` and writes nothing. If `block_ttl_ms` is set it MAY send `Retry-After`. A write error of
    the operating system for lack of space (`ENOSPC`) or of quota (`EDQUOT`) gets the same answer and
    leaves no partial file. (ADR 0023, clarifications)
20. **Order.** The quota check comes after validation and applies to new blocks only: a valid block
    already held still gets `200` (ADR 0008 rule 3), and an invalid block still gets its own error.
21. **Reads continue.** A full relay serves `GET /block`, `/query` and `/info` normally. It MUST NOT evict
    unexpired blocks to make room.

### Index backend (conditional)

22. The index backend is redb, an embedded key-value store in one file next to the block files. It holds
    the `parent → children` edges and the reception-time order used by `since` and by cursors (rule 4).
    Blocks stay in flat files (ADR 0009).
23. Rule 22 holds **provided the benchmark below passes**. The benchmark is the first task of Phase 2. If
    it passes, redb is the definitive index backend of `sbtp-relay`. If it fails, the decision returns to
    the project owner; this ADR does not choose a fallback.
24. The relay MUST set the redb cache size explicitly (`Builder::set_cache_size`; proposed value: 4 MiB).
    The library default is 1 GiB.
25. `crates/sbtp-relay/Cargo.toml` declares `rust-version = "1.90"`, which redb 4.x requires. The
    workspace value (1.85) is unchanged for `sbtp-core`, `sbtp-wasm` and `cli-demo`.
26. The redb version is pinned exactly in `[workspace.dependencies]` and MUST be at least two weeks old
    when it is added (`CLAUDE.md`, dependency rules). On 2026-11-18 that is 4.4.0; 4.5.0 qualifies on
    2026-11-19 and 4.6.0 on 2026-11-27.

### Benchmark protocol (gate of rule 23)

**Subject.** The `sbtp-relay` binary with the redb index, the flat-file store, the LRU cache at its default
size and every other setting at its default, except `min_pow_difficulty = 0` and the two limits that would
stop the load (`max_store_bytes`, rate limits), which are raised. The code path is the real one: blocks
enter through the `PUT` handler, in process or over loopback HTTP.

**Build.** `cargo build --release -p sbtp-relay --locked`, target `x86_64-unknown-linux-musl`, with the
release profile committed in the workspace `Cargo.toml`. No release profile exists today: committing one
is the first step, and the gate applies to that profile, the one that ships. Proposed:
`opt-level = "s"`, `lto = true`, `codegen-units = 1`, `strip = true`. `panic = "abort"` MUST NOT be used
to pass the gate: one panicking request must not stop the relay.

**Environment.** Linux x86-64, ext4 or XFS on an SSD, no swap, no other load. The report gives the kernel,
the file system, the `rustc` version, the redb version and the commit hash.

**Data sets.** Generated by a deterministic generator (fixed seed, public test key), committed with the
benchmark. Blocks are valid (signature included), with a 200-byte payload.

| Data set | Blocks | Parents |
|---|---|---|
| Typical | 1,000,000 | 20% with 0 parents, 50% with 1, 30% with 2 (1.1 on average). Each parent is drawn among the 10,000 most recent earlier blocks. |
| Adversarial | 1,000,000 | 15 per block, each a distinct random 32-byte value that is not a stored block (15,000,000 edges). |

**Procedure**, once per data set, on an empty data directory:

1. Load: `PUT` the 1,000,000 blocks with 8 concurrent clients.
2. Query: 100,000 `/query` requests with 8 concurrent clients: half with a `parent` drawn from the data
   set and `limit=1000`, half with no `parent`, a random `since` and `limit=1000`; each followed to
   `more = false` for at most 10 pages.
3. Evict: set `block_ttl_ms` so that the oldest 10% of blocks are expired; run the sweeper to completion.
4. Restart after a clean stop; repeat 1,000 queries.
5. Kill with `SIGKILL` during a second load of 10,000 blocks; restart; wait for readiness; repeat 1,000
   queries.

**Measures.**

| Measure | How |
|---|---|
| Binary size | Size in bytes of `target/x86_64-unknown-linux-musl/release/sbtp-relay`, as produced by the build above, with no further processing. |
| Peak memory | `VmHWM` of the relay process (`/proc/<pid>/status`), read at the end of each of the five steps; each restart is a new process and is read separately. |
| Informative, not gating | Size of the redb file and of the block directory; `PUT` and `/query` throughput; `/query` latency at the 99th percentile; start-up time in steps 4 and 5; binary size of the same build without redb. |

Each data set is run three times. The worst value of the three runs counts.

**Pass criteria.** All of the following:

| Criterion | Threshold |
|---|---|
| Binary size | under 5,000,000 bytes |
| Peak memory, typical data set, every step | at most 12 MiB (12,582,912 bytes) |
| Peak memory, adversarial data set, every step | at most 12 MiB |
| Correctness | every query of steps 2, 4 and 5 returns the expected identifiers; no block of step 1 is missing from the index after step 5 |

"Well under 15 MB" is read here as 12 MiB, 80% of the target. **Confirmed by the project owner on
2026-11-18, before the benchmark ran, together with the 5,000,000-byte binary limit and the release profile
above.** These figures MUST NOT be changed after the results are known.

**Report.** the implementer returns the table of measures for the six runs, the profile used and the
verdict. The maintainer records the verdict in this ADR's index line and in the open questions (not published).

## Choices made and their alternatives

Decided by the project owner on 2026-11-18.

### Index backend

**Decided: redb, conditional on the benchmark** (rules 22 to 26).

Assumptions for the figures: 1.5 parents per block on average; 30% of blocks have at least one child;
"adversarial" means 15 distinct parents per block. Every figure is an estimate; the benchmark replaces
the redb column with measures.

| | Append-only log, index in memory | Embedded store, redb (adopted, conditional) | One index file per parent |
|---|---|---|---|
| Mechanism | One record per accepted block appended to a segmented log (position, `block_id`, length, parents, checksum). At start-up the log is read and a `parent → positions` map is built in memory. | Three tables in one file: `position → block`, `block_id → position`, `(parent, position) → block_id`. Range reads serve `/query` directly. | A file `index/<shard>/<parent>.idx` of fixed 44-byte records, plus the log of the first option for queries without `parent`. |
| RAM per held block | About 100 bytes typical (about 12 per edge, about 120 per distinct parent, about 40 for the set of `block_id` values that rule 9 needs). About 2 KB adversarial. Grows without bound unless capped. | None per block. Bounded by the cache size setting. | None. |
| Disk per held block | About 110 bytes. | About 200 bytes of rows; 300 to 400 with B-tree overhead. About 1.7 KB adversarial. | About 60 bytes of records, but one file system block and one inode per distinct parent: about 1.3 KB typical, about 65 KB adversarial. |
| Start-up | Reads the whole log: about 110 MB and 1 to 3 seconds per million blocks. | Constant after a clean stop. After a crash: full repair proportional to the file, or immediate with quick repair at the price of slower commits. | Constant. |
| Crash consistency | Only the last record can be torn; it is dropped. Any other bad record forces a rebuild from block files. Recovery code is ours to write and test. | Transactions: the entries of one block (up to 17 rows) and of one eviction are atomic. Rules 8 to 10 still apply between files and store. | Appends to up to 15 files per block, not atomic together; a torn tail per file. |
| Eviction | Drops a prefix of the log (whole segments) and a prefix of each list. | Range delete on positions, then the edges of each block, in one transaction. | Rewrites up to 15 files per evicted block, or leaves stale records. |
| Memory bound under attack | Needs its own cap (`max_index_bytes`). At a 6 MiB cap, about 3,000 adversarial blocks fill the index and every later `PUT` gets `507` until blocks expire. | The disk quota is the only bound; the amplification stays under 50% of the block's own disk cost. | Disk amplification of about 15 for a minimal block. |
| Dependencies | None. | `redb` (pure Rust; `libc` only). 4.x needs Rust 1.90. | None. |
| `/query` cost | Map lookup, binary search in a list, then up to `limit` records read from the log. | B-tree range read: `O(log n + limit)`. | One file read from an offset; cursor seek by binary search. |

Why redb:

- The RAM target is the hard constraint. An in-memory index cannot hold it beyond about 60,000 typical
  blocks (6 MiB of index), nor under the 15-parent attack. redb keeps memory independent of the number of
  blocks, which the benchmark verifies.
- With a log, the project writes and maintains a small storage engine (segments, checksums, torn-tail
  handling, memory accounting) inside a service exposed to the Internet.
- redb keeps what "zero-DB" was protecting: no database server, blocks as plain files readable with
  `ls`. The redb file holds derived data only; deleting it costs a rebuild (rule 1), never a block.

Costs accepted: one more crate in an exposed binary (rule 26); Rust 1.90 for `sbtp-relay` (rule 25); a
library default that contradicts the RAM target (rule 24).

If the benchmark fails, the material for the owner's next decision is in this table: the append-only log
with a memory cap is the option that needs no dependency; redb 2.6.4 (Rust 1.85) and a smaller cache are
variants of the adopted option. None is pre-selected (rule 23).

### Eviction criterion

**Decided: by age since acceptance; default 30 days; configurable; can be disabled for archive relays**
(rules 12 to 17).

| | Age since acceptance (adopted) | Least recently requested |
|---|---|---|
| State written on a read | None. | A timestamp per block, in memory or on disk (`atime` is unreliable and often disabled). |
| Index consistency | The expired set is a prefix of the acceptance order. | Entries leave from anywhere. |
| Popular old blocks (a long-lived root block) | Evicted like the others. | Kept. |
| Attack | None specific. | A script keeps its own blocks alive for free by reading them. |

The cost is real: a relay with a TTL forgets a long-lived root block after 30 days unless someone submits it
again after expiry, and rule 13 gives no way to renew it before. Who keeps long-lived blocks available
(archive relays, re-publication by clients, renewal on `PUT`) is Q-24.

### Behaviour when full

**Decided: refuse new blocks; no early eviction** (rules 19 to 21).

| | Refuse new blocks (adopted) | Evict the oldest blocks early |
|---|---|---|
| Flood by a sender with cheap PoW | Writes are refused until blocks expire. History is kept. | The flood replaces the whole history of the relay. |
| Operator signal | `507` rate in the logs. | Silent. |

Loss of write availability is recoverable; loss of the stored history is not. A per-IP rate limit and a
higher `min_pow_difficulty` are the operator's levers.

### Status code when full

**Decided: `507 Insufficient Storage`** (rule 19).

| | `507 Insufficient Storage` (adopted) | `503 Service Unavailable` |
|---|---|---|
| Meaning | The server cannot store the representation needed to complete the request (RFC 4918 §11.5). Exact. | The server cannot handle the request for now. Generic. |
| Scope perceived | This write. Reads are unaffected, which is the case. | The whole service. Proxies and health checks can take the relay out of rotation, reads included. |
| Client support | Registered status; a client that does not know it treats it as `500` (RFC 9110 §15). The error name `StorageFull` removes the doubt. | Universal, with `Retry-After`. |

`503` stays for a relay that is starting, stopping or overloaded (ADR 0012 rule 17).

## Consequences

- **`/query`.** Rules 2 to 5 give ADR 0012 its order, its cursor and its `since`. These rules rely on
  the acceptance order adopted by ADR 0012: eviction by age removes a prefix of that order.
- **Durability.** A `201` means the block file was flushed to disk and created under its final name. It
  does not promise that the relay keeps the block: eviction exists. The directory entry is not flushed on
  every `PUT`; a power loss can lose blocks of the last seconds, which become phantoms (rule 8).
- **Corrupt files.** Flushing before the exclusive creation (rule 7) avoids a final file with missing
  bytes after a power loss. Without it, a truncated file would hold its `block_id` forever under "first
  write wins".
- **File system overhead.** A block file uses at least one file system block, 4 KiB on common
  configurations, whatever its length. A relay of one million small blocks uses about 4 GiB, not the sum
  of the lengths. Rule 18 counts it that way.
- **Restored backups.** The reconciliation of rule 9 and a full rebuild take `received_at` from file
  modification times. A restore that resets them extends lifetimes by up to one TTL.
- **Concurrency.** A `PUT` that gets `200` just before the sweeper deletes the block tells the client the
  relay held it at that instant, nothing more.
- **Security.**
  - The index is fed by header bytes chosen by senders. Its growth per block is bounded (15 edges) and
    counted in the quota (rule 18).
  - Index keys are 32-byte values taken from validated blocks; no path is built from them.
  - A full relay still runs the whole validation pipeline for each `PUT`. Rejecting earlier would break
    ADR 0008 rule 3 and save little: the per-IP limiter acts before the body is read.
- **`sbtp-core`.** No change. The relay needs the parents and the length of a validated block, which the
  public API already exposes.
- **Chunks.** Not covered. If relays store chunks, their quota and eviction are decided with Q-21.
- **Compatibility.** No relay is deployed.

### Checklist for the implementer

- [ ] First task: the benchmark of rule 23, exactly as the protocol states (release profile committed
      first, generator and harness committed, six runs). Report the table and the verdict to the
      maintainer. Stop if it fails: the backend decision returns to the owner.
- [ ] `Index` trait: `insert(block_id, len, parents, received_at) -> position`, `contains(block_id)`,
      `children(parent, from, limit)`, `all(from, limit)`, `position_at(since)`, `expired(before, max)`,
      `remove(position)`. Handlers depend on the trait only.
- [ ] Single index writer (task or mutex) that assigns positions and enforces rule 3, the clock-step
      case included (test with an injected clock that goes back).
- [ ] Write path of rule 7: temporary file in the data volume, `fsync`, exclusive creation (`link` or
      `create_new`), index insert, `201`. Temporary files are removed on every error path and at
      start-up.
- [ ] Rule 9: on "already held", `contains` check and repair; clean-shutdown marker; reconciliation after
      an unclean shutdown, in the background, with bounded memory.
- [ ] Rule 11: readiness flag; `503` + `Retry-After` for `/query` and `PUT` until the index is ready.
- [ ] Sweeper: interval and batch size as settings; order of rule 15; idempotent on a missing file;
      never blocks the async runtime (blocking pool).
- [ ] Expiry bound applied in `/query` (rule 14), tested without running the sweeper.
- [ ] Quota: counter of rule 18 kept atomically (reserve, then write, release on failure); check after
      validation; `507` + `StorageFull`; `ENOSPC` mapped to `507`; held block still `200` when full.
- [ ] Settings with defaults: `block_ttl_ms` (30 days; unset disables), `max_store_bytes` (1 GiB),
      `sweep_interval_ms` (60,000), `sweep_batch` (1,000), `index_cache_bytes` (4 MiB).
- [ ] redb: add it to `[workspace.dependencies]` with an exact version at least two weeks old (rule 26),
      after the crates.io check of `CLAUDE.md`; `rust-version = "1.90"` in the relay crate (rule 25);
      `cargo deny check`; explicit `set_cache_size` and a test that fails if it is not set (rule 24);
      `Durability::None` per block with an `Immediate` commit at most every second and at shutdown;
      decide on quick repair from the start-up times of the benchmark.
- [ ] Rebuild command (`sbtp-relay reindex`): walks the block files, checks that each file name equals
      the `block_id` of its bytes, writes a new index with a new epoch.
- [ ] Tests: crash between file creation and index insert (orphan repaired by the next `PUT` and by
      reconciliation); crash between file deletion and index delete (phantom removed); expiry at the exact
      millisecond; `block_ttl_ms` unset never deletes; quota at the exact byte; 15 distinct unknown
      parents counted; cursor stable across a restart, rejected after `reindex`.
- [ ] Security review of the index, the sweeper and the quota (hostile input reaches all
      three).

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-12 | `parent → children` and time index (content, positions, consistency rules, redb backend subject to the benchmark of rule 23); eviction sweeper and its criterion; disabling eviction; quota behaviour and status code. | The verdict of the benchmark. Chunk storage is part of Q-21. |
| Q-08 | Supplies the order, the cursor epoch and `received_at` used by ADR 0012; `507` for `PUT`. | See ADR 0012. |
| Q-24 (new) | Nothing. | Availability of long-lived blocks on relays with a TTL. |

## Rejected alternatives

- **No index: scan the block files for each query.** Unbounded cost per request; contradicts ADR 0012
  rule 14.
- **Blocks inside the embedded store.** Excluded by ADR 0009: the owner keeps flat files. It would also
  put the source of truth in a format that needs a tool to read.
- **SQLite.** C code and a build script in an exposed binary; conflicts with the dependency rules
  (`CLAUDE.md`) and with a static, `unsafe`-free build. Not evaluated further.
- **Other embedded stores (LSM trees).** Background compaction threads and write buffers work against a
  15 MB target. Not evaluated further.
- **In-memory index with no log (rebuild from block files at each start).** One file open per block at
  each start: minutes per million blocks, and `received_at` reduced to file times.
- **Index keyed by a truncated hash of the parent.** Saves memory with an in-memory index, but needs a keyed hash, a
  verification read per result and a new entry in the registry of spec §3.5 if BLAKE3 is used.
- **Lifetime renewed by a `PUT` of a held block.** Lets anyone pin content on a relay for the price of
  one request per TTL, and moves entries inside the acceptance order. Deferred to Q-24.
- **`413` or `429` when full.** `413` is about the size of this request; `429` is about the sender's
  rate. Neither says that the relay is full.
- **Eviction "by the file system".** Does not exist (Q-12, finding).

## Spec change

Applied on 2026-11-18, on the owner's decision relayed by the maintainer, together with the spec
change of ADR 0012.

### `docs/spec/architecture.md` §2

**Title.** `## 2. Internal design of a dumb relay (zero-DB)` becomes
`## 2. Internal design of a dumb relay (no external database)`.

**"Content-addressed storage".** Replace the last three bullets (LRU cache, TTL eviction, `[Q-12]`) with:

```markdown
- The block is written to a temporary file, flushed to disk, then created under its final name.
- In-memory LRU cache (`moka`) for hot blocks, bounded in bytes.

### Index
- Block files are the only source of truth. The index is derived data: a relay MUST be able to rebuild it
  from the block files. Its format is internal to a relay.
- When a relay stores a new block, it records `received_at` (its clock, Unix milliseconds) and assigns a
  position `(received_at, n)`. Positions strictly increase in storage order; `received_at` never
  decreases.
- For each stored block the index holds its position, its `block_id`, its length and one edge
  `(parent, position) → block_id` per parent. Parents are read from the header. The relay reads nothing
  after the Parents Hashes field.
- The index MAY list a block that the relay no longer holds; a stored block missing from the index MUST
  be repaired (on the next `PUT` of that block, and after an unclean shutdown).
- Backend: an embedded key-value store (redb) in one file next to the block files, with an explicit
  cache size. This choice is conditional on the benchmark of ADR 0013 (binary under 5 MB, memory well
  under 15 MB at one million blocks); if the benchmark fails, the backend is decided again. (ADR 0013)

### Eviction
- A block expires when `received_at + block_ttl_ms ≤ now`. `block_ttl_ms` is a relay setting (default: 30
  days), published by `/info`. Eviction does not depend on reads, and a `PUT` of a stored block does not
  extend its lifetime.
- `/query` never lists an expired block. A sweeper deletes expired blocks periodically, oldest first:
  cache entry, block file, then index entries.
- A relay MAY disable eviction (archive relay); `/info` then publishes `"block_ttl_ms": null`.
- Eviction is local to a relay and is not a deletion mechanism. (ADR 0013)

### Quota
- `max_store_bytes` bounds the block files (each counted in 4,096-byte units) plus the index.
- A new block that does not fit gets `507 Insufficient Storage`. The relay does not evict unexpired
  blocks to make room, and keeps serving reads. (ADR 0013)
```

**§3, tier 2 row.** No change.

### `docs/spec/sbtp-core-v0.2.md` §4

**`PUT /sbtp/v1/block`, "Responses".** Add after the `422` line:

```markdown
  - `507 Insufficient Storage`: the block is valid and new, and the relay has no room for it
    (`StorageFull`). Nothing is stored. A valid block already stored still gets `200`.
  - `503 Service Unavailable`: the relay is starting, stopping or shedding load (`Unavailable`).
```

**`PUT /sbtp/v1/block`, processing list.** Replace item 5 with:

```markdown
  5. storage addressed by the `block_id`, without replacing a block already present (§3.4), within the
     relay's storage quota.
```

**`GET /sbtp/v1/block/{block_id}`.** Add a bullet:

```markdown
- A relay MAY evict blocks (`block_ttl_ms`, `/info`). A `404` does not mean that the block does not
  exist.
```

**`GET /sbtp/v1/info`.** The `block_ttl_ms` member and its bullet are in the spec change of ADR 0012.
