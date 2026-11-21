# Security review: relay operator deny list (ADR 0052), with fixes L-1 and L-3

- Date: 2026-11-21
- Branch: `feat/relay-deny-list` (`git diff main...feat/relay-deny-list`, 24 files, about 2,250
  lines, `crates/sbtp-relay` and `deploy/README.md`)
- References: ADR 0052 (accepted); core spec §4 (`PUT` pipeline, `GET /block`, `POST /blocks`,
  `/query`, Errors, "Denied blocks"); `architecture.md` §2; ADR 0021 (logs and privacy); ADR 0018
  rule 35 (memory bound); ADRs 0048 and 0050 (replication and archive copy);
  `docs/security/2026-11-21-relay-object-mirror.md` (L-1, L-3)
- Reviewer: security-auditor, independent (diff and spec only)

## Verdict

**Mergeable.** No finding is blocking or high. A denied block is not served, batched, replicated,
uploaded or served from the cache on any route I traced, with any header combination. Every `451`
carries `Cache-Control: no-store` and `CDN-Cache-Control: no-store`. An invalid or missing file
never empties the list. Nothing from a line or an entry reaches a log, a metric label or an error
body.

One medium finding (M-1) is in the operator documentation: the CDN purge procedure for a key entry
does not work once the marking pass has run, and the operator command of rule 10 is missing.
Fixing the README text is enough to merge; the command can go to the roadmap. The low findings go
to the roadmap ("Relay hardening (parked)").

| Id | Severity | Title |
|---|---|---|
| M-1 | medium | The key-entry CDN purge procedure fails after marking; the operator command of rule 10 is missing |
| L-1 | low | A valid prefix of a file being rewritten in place lifts entries until the next poll; the stamp ignores the inode |
| L-2 | low | A `purge` by key that fails halfway leaves index entries that are never marked or removed |
| L-3 | low | The reload peak is about 6 % above the ADR's `2 × N × 80` estimate |
| I-1 | info | `SIGHUP` still terminates a relay without `deny_file`, and any relay before the handler is installed |
| I-2 | info | Response timing tells a block match from a key match on a read |
| I-3 | info | `DeniedKey` is visible to anyone who holds one public block of the key (by design) |
| I-4 | info | A `PUT` that passed the check just before a load can be stored and listed after the pass |
| I-5 | info | The marking pass reads every block file in full, at every start-up with a key or `purge` entry |
| I-6 | info | The deny file is opened (symlinks followed, devices opened) before the regular-file check |
| I-7 | info | L-1 residual: `*_ref` values are still logged when the archive copy is off |

## Checks run

Run in the worktree, nothing contacted remotely:

- `cargo test --workspace`: pass (615 tests, 0 failed)
- `cargo test -p sbtp-relay --features object-store`: pass (349 tests in 20 binaries, 0 failed)
- `cargo clippy --workspace --all-targets -- -D warnings`, and the same with
  `-p sbtp-relay --features object-store`: clean
- `cargo deny check`: `advisories ok, bans ok, licenses ok, sources ok` (duplicate-version warnings only)

No dependency was added. The parser uses `libc::O_NONBLOCK`, and `libc` was already in the
dependency graph.

## Findings

### M-1 (medium): the key-entry CDN purge procedure fails after marking; the operator command of rule 10 is missing

- `deploy/README.md`, "Operator deny list", "Copies the relay cannot reach", first sub-bullet.
  `crates/sbtp-relay/src/deny.rs:280-283` (`List::keys`, "for the operator command") has no
  caller.
- ADR 0052 rule 10 says that for a key "`sbtp-relay` offers a local operator command that lists the
  held `block_id` values of that key after the marking pass, for the purge". The branch does not
  ship it. The README says so and tells the operator to "list the blocks with `/query` and keep
  those whose header carries the key".
- Scenario: an operator adds `key <k>` and reloads. The marking pass marks the key's blocks, and
  `/query` stops listing them, which is rule 9 working as intended. The operator then follows the
  README: `/query` no longer returns any block of that key, and fetching them gives `451`. The
  operator finds nothing to purge. Every `200` of those blocks that the CDN already holds stays
  public for up to a year (`max-age=31536000, immutable`, ADR 0046 rule 16). The denied content
  keeps being served, and the operator believes the procedure succeeded. With `purge`, the bytes
  are also gone locally, so the operator cannot rebuild the list afterwards.
- Fix:
  1. Before merging (documentation only): state the order. List the blocks of the key before
     loading the entry, through `/query` plus a `GET` of each block to read bytes 19 to 50. Or load
     the key with `hide` first, collect the list, purge the CDN, and only then switch to `purge`.
  2. Roadmap: implement the command. The `denied` index table already maps `block_id` to key for
     every `hide` match, so the command is a read-only scan of that table, filtered by key. It
     should print to stdout only, never to the log (ADR 0021). For `purge`, write the mark before
     the deletion (see L-2) and print the list before the pass removes it, or document the
     "`hide` first" sequence as the only supported one.

### L-1 (low): a valid prefix of a file being rewritten in place lifts entries until the next poll; the stamp ignores the inode

- `deny.rs:410-418` (`changed`), `:467-495` (`stamp_of`, `read_file`).
- The poll reloads when `(mtime, size)` of the path differs from the last attempt. It reads the
  stamp from `fstat` at open, before the parse. An empty file, or a prefix that ends at a line
  boundary, is a valid list (rule 11: "including none").
- Scenario: the operator or a tool rewrites the file in place (`cat new > deny.txt`, an editor that
  truncates and writes, a generator script that streams its output). A poll that falls between the
  truncation and the end of the write loads an empty or shorter list. The missing entries are lifted
  until the next poll (up to `deny_reload_ms`, 10 s by default). During that window a denied block is
  served with `200` and `Cache-Control: public, max-age=31536000, immutable`, so a CDN or browser can
  keep it for a year. The window is small, but the result is the same as a lift the operator never
  asked for. Separately, a replacement with the same size and the same modification time is never
  picked up by polling. This happens when one 64-character identifier is swapped for another and the
  time is preserved (`cp -p`, `rsync -t`, `tar x`), or within one timestamp tick on a coarse
  filesystem. Only a `SIGHUP` reloads it then.
- Mitigations already present: `deploy/README.md` tells operators to write to a temporary file and
  `mv` it into place. A partial last line (no newline yet) is invalid and keeps the old list.
- Fix (in the code; no ADR needed):
  1. After the parse, `fstat` the open file again. If its size or modification time changed, discard
     the result and leave the stored stamp unset, so that the next tick reads the file again.
  2. Add the device, the inode and `ctime` to `Stamp` (`std::os::unix::fs::MetadataExt`), so that an
     `mv` or a time-preserving copy is always seen.
  3. Optionally, for poll-triggered reloads only, apply a file only once its stamp is the same on two
     consecutive ticks. `SIGHUP` stays immediate.

### L-2 (low): a `purge` by key that fails halfway leaves index entries that are never marked or removed

- `deny.rs:521-553` (`mark_once`).
- The run deletes each purged file under its lock (`evict_locked`). It removes the index entries for
  the whole run afterwards (`i.remove(&purged)`), and writes marks only for `hide` matches. When a
  run is tried again, it judges each block by the key read from its file.
- Scenarios:
  - The index writer refuses the removal (queue full under load), or the process stops between the
    deletions and the removal. The run is tried again from the same position, or the pass starts
    again at the next start-up. The files are gone, so the key is unknown (`key = None`). `judge`
    sees no key match, and the entries are neither removed nor marked. They stay in `/query` while
    the key entry is in force. That contradicts rule 9 ("omitted once the marking pass has reached
    it"). On a relay without `block_ttl_ms` the entries stay forever, because start-up
    reconciliation does not drop index entries whose file is missing.
  - `evict_locked` returns an error (`EACCES`, `EIO`). The block is neither purged nor marked, so it
    stays listed. The comment "the next pass tries again" holds only if a later load or restart
    starts a pass.
- Impact: no bytes are served. A fetch gets `404`, or `451` while the file is still there. A
  `block_id` of denied content stays in listings, and publishers re-submit after the `404` and get
  `451 DeniedKey`. Limited, hence low.
- Fix: write the mark (`block_id` → key) for every key match, `purge` included, in `mark_denied`
  **before** deleting the files. Change `judge` to use the mark's key when the file cannot be read.
  A run that is tried again, or the start-up pass, then finds the key, calls `evict_locked` (which
  returns `Ok(None)` for a missing file) and removes the entries. A failed deletion keeps a mark, so
  the block is at least not listed. The mark goes with the index entries, as it does today.

### L-3 (low): the reload peak is about 6 % above the ADR's `2 × N × 80` estimate

- `deny.rs:152-200` (`List::parse`), `config.rs` (`EST_DENY_ENTRY = 80`).
- A `HashMap<[u8; 32], Action>` slot is 33 bytes plus one control byte. A table holding `N = 2^k`
  entries has `2N` buckets, so it takes `68 N` bytes. The map grows one `try_reserve(1)` at a time.
  At its last growth, the old table (`34 N`) and the new one (`68 N`) are alive together, while the
  previous list (`68 N`) is still in force. That makes `170 N` against the `160 N` of the estimate.
  For `small` (`N = 2,048`, all entries of one kind), the peak is 348,160 bytes against 327,680
  bytes, 20,480 over. The 20,000,000-byte budget still holds with every function on (about
  19,030,000). On `large` the overshoot is about 10.5 MB, against a term of 167.8 MB.
- In-flight requests hold the previous `Arc<List>` only for one check or one index job, so at most
  two lists are alive outside a `SIGHUP` storm, which only the local operator can cause.
- Fix (code): remove the growth transient. Count the entry lines in a first read (capped at
  `deny_max_entries`), then build each map with `HashMap::try_with_capacity`; the capacity is only a
  hint, so a file that changes between the two reads is still handled correctly. Or use one map keyed
  by `(kind, value)` with the exact capacity. Either keeps the ADR figure; no ADR change.

### I-1 (info): `SIGHUP` still terminates a relay without `deny_file`, and any relay before the handler is installed

- `lib.rs` (`spawn_hangup`, called only when the deny list is enabled, after the listener starts).
- `systemctl reload`, set up as the README suggests, stops a relay without `deny_file`, or one still
  reconciling its store at start-up, because the default `SIGHUP` action is to terminate the
  process. That is an availability problem, not a security one.
- Fix: install the handler early and unconditionally; ignore the signal when the deny list is off.
  Or add a README line saying not to configure `ExecReload` without `deny_file`.

### I-2 (info): response timing tells a block match from a key match on a read

- `blocks.rs` (`fetch`): a listed `block_id` returns before any permit, read or validation. A key
  match comes after the cache lookup, or after the file read and full validation on a miss.
- Rule 6 says a read MUST NOT state whether the match is by block or by key. The latency does,
  given enough samples. Rule 7 already accepts that a key-level denial can be inferred by reading
  several of the key's blocks, so this adds nothing worth the cost, except for a key with a single
  block.
- No change recommended. Mention it in the ADR's "Privacy" consequence if it is revised.

### I-3 (info): `DeniedKey` is visible to anyone who holds one public block of the key

- Any reader who holds a public block of the key, not only the key's owner, can `PUT` it back and
  read `Denied` or `DeniedKey`. This is the documented trade-off of rule 7 and owner decision 2. The
  check follows C3 as specified (`blocks.rs:453-459`), and a forged signature gets `422` (tested).

### I-4 (info): a `PUT` that passed the check just before a load can be stored and listed after the pass

- `blocks.rs:453-460`: the check runs before the lock of `id` and the index insert. If a load that
  adds a key lands between the check and the insert, and the marking pass has already walked past
  the end of the store, the block is stored and listed, though not served (reads check the list).
  The window is milliseconds. Rule 4 binds requests that start after the load. No change needed.

### I-5 (info): the marking pass reads every block file in full, at every start-up with a key or `purge` entry

- `deny.rs:524-529` reads up to 65,909 bytes per block to get 32 bytes of header. `needs_pass(None)`
  is true at every start-up when the list holds a key or a `purge` entry, and a list with only
  `block … purge` entries also triggers a full walk. That is cost, not exposure.
- Possible improvements: read only the first 51 bytes; purge `block` entries by direct lookup; keep
  a persisted digest of the last fully marked list, to skip the pass at start-up.

### I-6 (info): the deny file is opened (symlinks followed, devices opened) before the regular-file check

- `deny.rs:473-495`. The file is opened with `O_NONBLOCK` and then `fstat`-ed, so a FIFO, a
  directory or a device is refused without blocking a reload. A symlink to a regular file is
  accepted, which is useful with configuration management. Opening a device node can have side
  effects on some drivers. The path is operator-controlled, so this is not exploitable from the
  network.
- Optional: `stat` the path first and skip `open` when it is not a regular file, keeping the `fstat`
  check after the open.

### I-7 (info): L-1 residual: `*_ref` values are still logged when the archive copy is off

- `mirror/mod.rs:289`: `prepare` returns `None` before resolving the credentials when
  `mirror_endpoint` is unset. A value pasted into `mirror_access_key_ref` on a relay with the copy
  off is therefore still written in its `setting` line. Negligible: without an endpoint the operator
  is not configuring the copy.
- Optional: resolve the `*_ref` names whenever any of them differs from its default, or log a `*_ref`
  value only once its variable has been found.

## What was checked and holds

**Parser (`deny.rs`)**
- Bounds: one 8,192-byte read buffer and one line of at most 257 bytes (`take(257)` before
  `read_until`). A 10 MiB file with no newline is refused after 257 bytes (tested). Entries are
  bounded by `deny_max_entries` before insertion and allocated with `try_reserve`. The line counter
  saturates. Time is linear in the file size and runs on a blocking thread.
- Invalid UTF-8, `\r\n`, double or trailing spaces, uppercase hex, short hex, a leading space, extra
  tokens, an unknown action and conflicting actions all fail with a fixed reason and a line number.
  A duplicate with the same action counts once. There is no `unwrap`, no indexing and no arithmetic
  that can overflow on file content.
- FIFO, directory and device paths are refused (`Unreadable`) after a non-blocking open.
- An invalid or missing file at start-up stops the start-up with
  `invalid at line N: <reason>` (tested, including that no line content appears). On reload the
  previous `Arc<List>` stays in force (tested with three invalid forms and a deleted file). A missing
  file is invalid. The stamp of a failed attempt is recorded, so an unchanged invalid file is not
  re-read and re-logged on every tick.

**Reload races**
- `SIGHUP`, the poll and the marking pass run in one task, one after another. `Notify::notify_one`
  stores a permit, so a `SIGHUP` that arrives during a reload or a run is not lost. No two reloads
  run at once.
- Each request takes the list once (`fetch`, `process`, the `/query` plan, the replication held
  check, `read_for_copy`) and uses that same list for the whole decision. The swap is one
  `RwLock` write of an `Arc`. No request sees half a list.
- A load that adds a key or a `purge` entry restarts the pass from the start. A load that adds
  neither lets a running pass go on, with the new list for each run.

**Enforcement on every route**
- `GET` and `HEAD`: a listed `block_id` gets `451` before the cache, the permit or the file read,
  held or not. A key match is checked on cache hits and on misses. A denied miss is not cached.
  `block_response`, the only producer of `200` and `304`, is reached only on `Fetched::Served`, so
  `If-None-Match` (a matching ETag and `*`) and `Sbtp-Replication: 1` give `451` (tested).
- `POST /blocks`: every record, the first one included, goes through `fetch`. A denied block is a
  `length = 0` record and is not demand (tested).
- `PUT`: after F1 to F9, P1, C1 and R1, then C2 and C3 (`verify_signature`), then `451`. Nothing is
  stored, held or not. `Denied` wins over `DeniedKey`. The replication store path uses the same
  `process` and maps the result to a `denied` skip.
- `/query`: entries are dropped after the walk, so the cursor and `more` stay those of the walk and
  the work stays `O(log n + limit)`. The `fields` vector is filtered in step with the entries. A
  listed `block_id` is dropped at once; a key match is dropped through the `denied` marks table,
  read only when the list holds a key. Children of a denied parent are still listed (tested for
  `asc`, `desc`, `fields=parents`, `parent=` and an empty page with `more = true`).
- Replication: a listed `block_id` is skipped before the fetch; a fetched block of a listed key is
  discarded by `process`; a peer's `451` is a skip (`Skip::Denied`) and adds nothing to the local
  list.
- Archive copy: `read_for_copy` refuses by `block_id` before any read and by key on cache hits and
  misses. The block counts as done (`mirror_denied_total`) and is never uploaded (tested against the
  S3 stub).
- Demand: a `451` records no demand (tested in `sweep.rs`).
- Every `451` carries `Cache-Control: no-store` and `CDN-Cache-Control: no-store`, set in
  `ApiError::into_response` for that status, so `HEAD` and `PUT` get them too. The message is one
  fixed text for both error names.
- `/info` publishes `"deny_list": true` only when `deny_file` is set, and says nothing about the
  entries.

**Marking pass and `purge`**
- Each block is judged under its `PUT` lock. A `purge` goes through `evict_locked` (cache, file,
  cache again, eviction generation), so a concurrent `GET` miss cannot re-cache it. In any case
  every read gets `451` as soon as the `purge` entry is loaded, before the deletion: a block is never
  served once its deletion is requested.
- Marks are written in one transaction under the index writer lock, only for blocks still in `ids`.
  They are removed together with the `ids` entry in `Tables::remove`, and are re-checked against the
  list in force on every listing, so a stale mark after a lift is harmless. A lifted `hide` entry
  serves and lists the block again at once, at its original position (tested). A lifted `purge`
  entry followed by a `PUT` gives `201` at a new position (tested). For the cases that break this,
  see L-2.

**Logs and metrics**
- `deny_list_loaded` carries counts only; `deny_list_invalid` carries a line number and a fixed
  reason, and is throttled. The `setting` line logs the path. Denied requests are counted, never
  logged; the `request` debug line carries the route template and the status only, with no client
  tag. The end-to-end `SIGHUP` test checks that neither the key nor the `block_id` appears in the
  process log.
- `denied_total{route, match}`, `deny_entries{kind}` and `deny_marking_pending` use fixed labels.
  Their slots are reached through `get()`, never by indexing.

**Memory bound**
- The term `2 × deny_max_entries × 80` is counted only when `deny_file` is set. The "every function
  on" test checks 19,009,458 bytes with the two terms this relay does not implement yet, under
  20,000,000. For the reload peak, see L-3.

**L-1 and L-3 of the archive-copy review**
- L-1: `prepare_mirror` (credential resolution) now runs before `log_settings`. The `mirror` line
  moved to `announce`, after the `setting` lines. A binary test checks, for each of the three refs,
  that a pasted value appears in no log line and that nothing is opened. Fixed. For the residual
  case, see I-7.
- L-3: `Loaded::Changed` replaces `Absent` when the quarantine loop runs out. `read_for_copy` maps it
  to `Copied::Retry` (`LOCAL_RETRY` back-off, never counted as missed); `GET` still answers `404`.
  The unit test drives both decisions with a concurrent writer. Fixed.

**Panics on input**
- No `unwrap`, `expect` or unchecked indexing in the new non-test code paths. `pubkey_of` uses
  `get()`, and the metric arrays use `get()`. The `drop_denied` counters are `u64` increments
  bounded by the page size.

## Not checked

- Read-through (ADR 0050 rules 15 to 19, ADR 0052 rule 19): not implemented in this relay; only the
  `fallback` metric label exists. To review when it lands.
- The operator command of rule 10 (absent, M-1) and the client side of rules 12 and 13 (web client,
  `cli-demo`, SDK: stage 3, not in this branch).
- Behaviour on Windows (the `O_NONBLOCK` open and `SIGHUP` are Unix-only; `spawn_hangup` is a no-op
  there).
- The deny file on network filesystems, where a hung read stalls the reload task and the marking
  pass, but not requests.
- A fuzz run of `List::parse`: the parser is small and its bounds were checked by reading the code
  and the tests, not by fuzzing.
- CDN behaviour towards `CDN-Cache-Control: no-store` on a `451`, which depends on the provider.
