# 0025: One shard level created at start-up; directories in the storage quota

- Status: accepted (by the project owner, 2026-11-19), with the recommended choice on the three "Choices for the project owner" (`500` on a missing shard directory, minimum `max_store_bytes` 4 MiB, `E` = 128 as a constant)
- Date: 2026-11-19
- Questions: Q-31
- Review: `docs/security/2026-11-21-relay-m1b.md`, finding I-7; `docs/security/2026-11-21-relay-m1b-adr0023.md`,
  L-3 (clarification C1 of ADR 0023)
- Owner direction (2026-11-19): the two-level layout of the first draft is rejected; one level of 256
  directories, all created at start-up, a fixed tree charge and a fixed per-entry charge.
- Amends:
  - ADR 0009 rule 2 (one shard level instead of two) and its consequence "Distribution" (256 directories
    instead of 65,536); ADR 0009 rules 1, 3 and 4 are unchanged.
  - ADR 0013 rule 18 (the quota sum gains a tree charge and a per-entry charge).
  - ADR 0019 rule 4 (the lower bound of `max_store_bytes` rises from 1,048,576 to 4,194,304).
  - ADR 0023 rule 5 (the quarantine and the start-up walk use the same costs) and rule 14 (one field
    added to `store_reconciled`).
  - Clarifies, without changing its text: ADR 0021 rule 36 (the inode warning stays an upper bound of the
    relay's own inode use); ADR 0023 rule 15 (its walk bound `max_store_bytes / 4,096` stays true).
- Depends on: ADR 0009; ADR 0013 rules 7, 18 to 21; ADR 0019 rule 4; ADR 0021 rules 30 to 36; ADR 0023
  rules 2 to 8, 14 to 16 and clarification C1; security review L-4 (real directories only)
- Impact: `docs/spec/architecture.md` §2 "Content-addressed storage" and "Quota" (see "Spec change", applied on
  2026-11-19); `sbtp-relay` (`store.rs`, `config.rs`, `log`, tests); no change to
  `docs/spec/sbtp-core-v0.2.md`; no `sbtp-core` change; no test vector

## Context

`max_store_bytes` (ADR 0013 rule 18, amended by ADR 0023 rule 5) counts block files and quarantined files,
each rounded up to 4,096 bytes, and the index file. Directories are not counted. The layout of ADR 0009
rule 2 has two levels of one byte: up to 256 first-level and 65,536 leaf directories, created on demand by
the write path. The security review of milestone 1b measured 538 directories for 347 files (I-7).

The first draft of this ADR kept two levels and charged 4,096 bytes per directory. That costs up to
65,792 × 4,096 = 269,484,032 bytes (257 MiB), a quarter of the default quota, and needs reservation and
release logic for directories created concurrently on the write path. The project owner rejected it.

Figures used below. File-system figures are estimates from the on-disk formats, from memory, not
measured on this project:

- A block file name is 68 characters (`<64 hex>.bin`).
- **ext4.** A linear directory entry is an 8-byte header plus the name, aligned to 4 bytes: 76 bytes.
  An indexed directory (htree) keeps entries in leaf blocks that split in half when full; under uniform
  hash inserts the average fill is about 70%, so about 110 bytes of directory per entry. Just after a
  split a leaf is half full: about 152 bytes per entry in that leaf. A directory does not shrink when
  entries are removed; their space is reused by later entries.
- **XFS.** A data entry is 8 + 1 + 68 + 1 + 2 bytes aligned to 8: 80 bytes, in data blocks filled by
  free-space lookup (close to full), plus an 8-byte hash entry in leaf blocks that split (about 70%
  fill): about 95 bytes per entry. A small directory is held inside its inode.
- One new directory takes one 4,096-byte block on a common file system. Each file and each directory
  takes one inode.

ADR 0021 already refuses new blocks with `507` under 4,096 free inodes, under `min_free_disk_bytes` of free
space, or on a read-only file system. The relay is correct when the disk runs out before the quota. What
is wrong is the quota: it promises a bound it does not keep.

Facts about the code at `f29e239` (`crates/sbtp-relay/src/store.rs`):

- `Store::open` creates `blocks/`, `tmp/` and `quarantine/` with `ensure_dir` (mode `0700`, real
  directories only) and does not `fsync` `data_dir`.
- `shard_dir` joins `id[31]` then `id[30]`. `write_inner` calls `ensure_shard`, which creates each missing
  level and `fsync`s its parent, then `link`s the temporary file.
- `read` returns "not held" when a shard level is missing.
- `scan` walks two levels; `reconcile` sets the sum to the quarantined files, then adds `cost(len)` per
  block file; `cost` is the length rounded up to 4,096 bytes.
- No code removes a shard directory.

## Decision

### Layout (amends ADR 0009 rule 2)

1. **One level.** With `id` the 32 bytes of the `block_id` and `hex` in lowercase, a block file is

   ```
   <data_dir>/blocks/<hex(id[31])>/<hex(id[0..32])>.bin
   ```

   Example for the `block_id` `0000a3…17cdef`: `blocks/ef/0000a3…17cdef.bin`. The shard key stays the
   trailing byte of the `block_id` (ADR 0009 rule 1): the proof of work sets the leading bits to zero.
2. **Fixed set.** The shard directories are exactly the 256 names `00` to `ff` under `blocks/`.

### Creation at start-up

3. **Before any `PUT`.** At every start, before the start-up walk (ADR 0023 rule 15) and before the relay
   listens, the relay makes sure that `blocks/`, `tmp/`, `quarantine/` and the 256 shard directories
   exist as real directories. It creates each missing one with mode `0700`. After creating any of them it
   `fsync`s its parent: `data_dir` for `blocks/`, `tmp/` and `quarantine/`; `blocks/` for a shard
   directory. One `fsync` per parent is enough after all creations under it.
4. **Wrong kind.** An entry under one of these names that is not a real directory (a symbolic link
   included) stops the start-up with an error. It is never followed (security review L-4).
5. **No creation on the write path.** `PUT` never creates a directory. Before the `link`, the relay checks
   that the shard directory is a real directory, without following a symbolic link.
6. **Missing at run time.** A shard directory that is missing or is not a real directory while the relay
   runs is a store integrity problem, an I/O error in the sense of ADR 0023 rule 2:
   - `PUT` of a new block: `500` (`Internal`), `store_write_failed` with `op=write`, the reservation is
     released, nothing is created under a final name, the directory is not recreated.
   - `GET` cache miss: `500` (`Internal`), `store_write_failed` with `op=read`. Not `404`: the relay
     cannot tell whether it holds the block.
   - The next start recreates a missing directory (rule 3). Index entries of files lost with it are
     phantoms (ADR 0013 rule 8).
7. **No removal.** The relay MUST NOT remove a shard directory, nor `blocks/`, `tmp/` or `quarantine/`.
   The sweeper and the quarantine purge remove files only.

### What the quota counts (amends ADR 0013 rule 18 and ADR 0023 rule 5)

8. **Sum.** The quota sum is
   `T + Σ (round_up(len, 4,096) + E) + size of the index file`,
   where the sum runs over the block files under final names and the quarantined files, `len` is the file
   length, `T` is the tree charge (rule 9) and `E` the entry charge (rule 10). The reservation before a
   write (ADR 0013 rule 7) uses the same cost for the new file, with the index growth reserve unchanged.
9. **Tree charge.** `T = 259 × 4,096 = 1,060,864` bytes: one 4,096-byte block for each of `blocks/`,
   `tmp/`, `quarantine/` and the 256 shard directories. It is counted once, whether the directories are
   empty or not. `data_dir` itself is the operator's and is not counted.
10. **Entry charge.** `E = 128` bytes per counted file, a constant. It covers the growth of the directory
    that holds the entry beyond its first block. 128 is above the estimated average of about 110 bytes on
    ext4 and about 95 bytes on XFS. A change of `E` requires an ADR.
11. **`tmp/`.** A temporary file is not counted separately. It exists only during a write whose
    reservation already covers the bytes and the final entry, and it shares its inode with the final file
    after the `link`. At most `put_max_in_flight` temporary entries exist at once; their directory growth
    beyond the first block of `tmp/` is left to `min_free_disk_bytes`.
12. **`quarantine/`.** A quarantined file costs `round_up(len, 4,096) + E`, as under its final name. A move
    to quarantine does not change the running sum (ADR 0023 rule 5); a purge releases that cost.
13. **Start-up walk.** The walk starts the sum at `T`, adds the quarantined files, then adds
    `round_up(len, 4,096) + E` for each block file it counts. It counts the same files as today: regular
    files whose name is a block file at its own shard path. Entries that are neither a real directory nor
    a regular file are skipped, never followed; a subdirectory inside a shard directory is skipped and not
    counted. The walk does not measure directories.
14. **Not counted.** The growth of `tmp/` (rule 11); directory space left after entries are removed
    (ext4 directories do not shrink); file system metadata (inode tables, journal, extent blocks). These
    are covered by `min_free_disk_bytes` (ADR 0021 rule 30).

### Files and inodes

15. **No file-count setting.** The relay has no bound on the number of files besides `max_store_bytes`.
    A block is never empty, so each file the relay writes costs at least 4,096 + 128 bytes. Under
    `data_dir` the relay creates at most 259 directories and `(max_store_bytes − T) / 4,224` files, plus
    the index file and at most `put_max_in_flight` temporary files. ADR 0021 rule 33 (`507` under 4,096
    free inodes) covers inodes used by other processes. The start-up warning of ADR 0021 rule 36, which
    compares free inodes with `(max_store_bytes − bytes already stored) / 4,096`, stays an upper bound.

### Minimum quota (amends ADR 0019 rule 4)

16. The range of `max_store_bytes` becomes 4,194,304 to `2^63 − 1`. Under the old lower bound of
    1,048,576 the tree charge alone exceeds the quota and every new block gets `507`.

### Observability (amends ADR 0023 rule 14)

17. `store_reconciled` gains the field `dirs_created`: the number of directories created by rule 3 at this
    start. It is 259 at the first start and 0 at a normal restart. A non-zero value on a store that held
    blocks shows that a directory was removed while the relay was stopped. A `507` caused by the tree or
    entry charge has the reason `quota`, like any other quota refusal. No new event, counter or reason.
    The `store_bytes` gauge includes `T` and the entry charges.

## Consequences

- **The quota holds for current entries.** On a file system with 4,096-byte blocks, what the relay writes
  under `data_dir` stays within `max_store_bytes` while directories grow by no more than about 128 bytes
  per entry, which holds on average on ext4 and XFS (estimates). Two residues are outside the quota:
  - ext4 leaves just after a split use up to about 152 bytes per entry, under 0.6% of the charge of a
    minimum-size block;
  - a directory does not shrink after eviction. After a peak of minimum-size blocks, the unreused part is
    at most about 254,000 × 110 bytes ≈ 28 MB on a 1 GiB store, under 3% of the quota, and it is reused
    by later entries in the same directory.
  Both are left to `min_free_disk_bytes`.
- **Capacity at the default quota.** A 1 GiB store of minimum-size blocks (one 4,096-byte unit each)
  holds `(1,073,741,824 − 1,060,864) / 4,224` = 253,949 blocks, the index file not included, against
  262,144 with no directory accounting and about 199,475 under the rejected two-level draft. Tree and
  entry charges together are 33,566,336 bytes, 3.1% of the quota. With blocks of the maximum size
  (65,909 bytes, 69,632 bytes rounded up) the same quota holds 15,376 blocks.
- **Minimum quota.** 4,194,304 bytes hold at most `(4,194,304 − 1,060,864 − 65,536) / 4,224` = 726
  minimum-size blocks, less the size of the index file (the 65,536 bytes are the smallest index
  reserve).
- **Directory sizes.** Blocks spread uniformly over 256 directories for any `d ≤ 248`. About 1,000
  entries per directory at 1 GiB of minimum-size blocks, about 100,000 at 100 GiB. ext4 (htree, on by
  default) and XFS index large directories, so a lookup by name costs no more than in a small one. Only
  tools that list a directory (`ls`, backup, `rsync`) slow down, and only on very large relays. A future
  ADR may add a second level for archive relays; it would change the path function and the walk only.
- **Start-up.** At most 259 `mkdir` calls and two `fsync`s at the first start, 259 `lstat` calls at
  each later start. No directory work on the write path.
- **Write path.** Simpler than in 1b: one `lstat` of the shard directory before the `link`, no creation,
  no `fsync` of a parent, no race between two `PUT`s creating the same directory.
- **Security.** The relay's own disk use, inodes included, is a function of `max_store_bytes` again, up
  to the residues above. A sender that grinds nonces into one directory (ADR 0009, "Targeted
  directories") makes that directory larger, not the store: each entry is charged `E` wherever it lands.
  A zero-length file left by a local writer now costs 128 bytes in the sum instead of 0 (clarification
  C1 of ADR 0023); the walk still visits every file. Rule 5 keeps the L-4 property on the write path:
  the relay never writes through a symbolic link in place of a shard directory.
- **ADR 0023 rule 15.** Its bound `max_store_bytes / 4,096` files stays true, since each counted file now
  costs 4,224 bytes or more. No text change.
- **ADR 0021 context.** Its context table describes the two-level layout as it was when ADR 0021 was
  written. It is context, not a rule; it is not amended.
- **Measurement.** The Q-31 measurement of directory sizes on ext4 and XFS was not run in milestone 1b.
  The rules do not depend on it. If a measurement in 1c shows an average above 128 bytes per entry, `E`
  is changed by a new ADR.
- **Compatibility.** No relay is deployed; no on-disk migration. A development store written by 1b (two
  levels) is not supported: its files sit in subdirectories of shard directories, are skipped by the walk
  and are not counted. Such a store is deleted before 1c runs.

### Code (the implementer, milestone 1c)

`crates/sbtp-relay/src/store.rs`, at `f29e239`:

- Module documentation (line 3): the layout of rule 1.
- Constants: `ENTRY_CHARGE = 128`; `SHARD_DIRS = 256`; `TREE_CHARGE = (SHARD_DIRS + 3) * QUOTA_BLOCK`.
- `cost` (line 205): `round_up(len, 4,096) + ENTRY_CHARGE`. Its callers (`list_quarantine` line 487,
  `write_new` line 506, `reconcile` line 790) then follow rules 8, 12 and 13 without other change.
- `Store::open` (line 265): after the three `ensure_dir` calls, `fsync` `data_dir` if one was created;
  create the 256 shard directories with `ensure_dir`, then `fsync` `blocks/` once if one was created;
  return or record the number created (rule 17). An existing entry of the wrong kind is an error (rule 4,
  already the behaviour of `ensure_dir`).
- `shard_dir` (line 288): one `join` of `id[31]`.
- `write_inner` (lines 543 to 546): replace `ensure_shard` by a check that `dir` is a real directory
  (`symlink_metadata`, no creation); "not found" and "not a directory" are `NotLinked` errors, hence
  `500` and a released reservation. Remove `ensure_shard` (lines 555 to 567).
- `read` (lines 578 to 588): check one level; a missing shard directory is an error (`500`), not
  `Ok(None)` (rule 6).
- `scan` (lines 608 to 647): one `read_dir` level under each shard directory; skip subdirectories.
- `reconcile` (line 781): start the sum at `TREE_CHARGE + qbytes`; `Reconciled` and `store_reconciled`
  gain `dirs_created`.
- `crates/sbtp-relay/src/config.rs` line 89: lower bound of `max_store_bytes` to 4,194,304.

Tests to change:

- Path helpers with two levels: `tests/blocks.rs` line 80, `tests/integrity.rs` line 58,
  `tests/logging.rs` line 141; unit test `layout_uses_the_trailing_bytes` (`store.rs` line 960): path
  `/d/blocks/ef/<hex>.bin` and costs `(cost(0), cost(1), cost(4_096), cost(4_097))` =
  `(128, 4_224, 4_224, 8_320)`.
- `tests/blocks.rs` `disk_use` (line 640): add `TREE_CHARGE`; `cost` already includes `E`.
- `tests/blocks.rs` `quota_gives_507` (line 339) uses a quota of 1,048,576, below the new minimum; and
  `quota_includes_index_growth` (line 665) uses 1,572,864 and 1,835,008, calibrated on a redb doubling
  near block 203. Both need new quotas at or above 4,194,304; the second needs a new calibration.
- `tests/blocks.rs` lines 895 to 910 (shard directory that is a symbolic link): the body runs only
  `if !shard.exists()`, which is never true once all shard directories exist at start-up. It MUST be
  rewritten to remove the shard directory and put the link in its place, otherwise it passes without
  testing anything.
- `tests/startup.rs` line 433: the range test of `max_store_bytes` (`1048575` refused, `1048576`
  accepted) moves to `4194303` and `4194304`.

Tests to add: the first start creates 259 directories with mode `0700` and logs `dirs_created=259`; a
restart logs 0; a shard directory that is a file or a symbolic link stops the start-up; the first block
in an empty store brings the sum to `T + 4,224` plus the index; a restart recomputes the same sum; a
quarantine move leaves the sum unchanged and a purge releases `round_up(len) + 128`; with a shard
directory removed while running, `PUT` gets `500`, creates nothing, leaves the sum unchanged and does not
recreate the directory, and `GET` of a block in it gets `500`; the next start recreates it
(`dirs_created=1`); the relay never removes a shard directory after the sweeper empties it.

## Choices for the project owner

All three accepted as recommended by the project owner on 2026-11-19.

1. **`GET` with a missing shard directory (rule 6).** Recommended: `500`, consistent with ADR 0023 rule 2
   and visible to the operator. Alternative: `404`, which hides a damaged store behind an ordinary miss.
2. **Minimum quota (rule 16).** Recommended: raise the lower bound to 4,194,304. Alternative: keep
   1,048,576 and let such a relay answer `507` to every block, as ADR 0019 point 2 accepts for an index
   larger than the quota. A setting that can never store a block has no use.
3. **`E = 128` (rule 10).** Recommended as a constant now, revisited by ADR if the 1c measurement shows
   an average above it.

## Rejected alternatives

- **Two levels, directories charged at 4,096 bytes each (first draft).** Up to 257 MiB of overhead, about
  24% of a 1 GiB store of minimum-size blocks, and the write path needs to reserve a charge for missing
  directories and release it when another `PUT` created the directory first. Rejected by the project
  owner.
- **Document only.** Keep the quota as is and state that directories are outside it. The quota would
  stay wrong, which is what Q-31 reports.
- **Measure directory sizes (`st_size` or `st_blocks`).** Exact on one file system at one moment, but a
  directory grows after it is measured, values differ between file systems, and the relay would need to
  stat directories again to keep the sum. A fixed charge is simple, portable and conservative on
  average.
- **Remove empty shard directories in the sweeper.** Races with a `PUT` that is about to `link` into the
  directory; fixing the race needs a lock or a retry loop on the write path. With 256 directories
  created at start-up there is nothing to gain.
- **One level, created on demand.** Keeps a creation and its race on the write path, and a charge that
  depends on which directories exist. Pre-creating 256 directories costs about 1 MiB once.
- **Tree charge only, no entry charge.** Under-counts as soon as directories grow beyond one block:
  about 53 entries per directory on ext4, about 13,600 files in all.
- **A `max_store_files` setting.** Rule 15 already bounds the relay's files by the quota; a second
  setting would add a choice for operators without adding safety.

## Spec change

Applied on 2026-11-19. No change to `docs/spec/sbtp-core-v0.2.md`.

**`docs/spec/architecture.md`, §2 "Content-addressed storage".** Replace the code block with:

````markdown
```
/data/blocks/
└── ef/                      last byte of the block_id (hex), one of 256 directories
    └── 0000a3…17cdef.bin
```
````

and add, after the first bullet:

> - The 256 shard directories are created at start-up, before the relay accepts blocks. A relay never
>   creates a shard directory on the write path and never removes one. (ADR 0025)

**§2 "Quota".** Replace the first bullet with:

> - `max_store_bytes` bounds the block files and quarantined files (each counted in 4,096-byte units
>   plus 128 bytes for its directory entry), a fixed charge of 1,060,864 bytes for the directories, and
>   the index. File system metadata and directory space left after removals are left to the free-space
>   margin. (ADRs 0013, 0023 and 0025)

**On acceptance**, following `docs/decisions/README.md`: ADR 0009 gets "Amended by: 0025 (rule 2 and the
'Distribution' consequence: one shard level of 256 directories created at start-up)"; ADR 0013 gets
"0025 (rule 18: tree and entry charges)"; ADR 0019 gets "0025 (rule 4: lower bound of
`max_store_bytes`)"; ADR 0023 gets "0025 (rules 5 and 14: costs in the quarantine and the walk,
`dirs_created`)". The index rows of 0009, 0013, 0019 and 0023 read "accepted, amended by …, 0025".
ADR 0009's "Spec change" section is historical and is not edited.
