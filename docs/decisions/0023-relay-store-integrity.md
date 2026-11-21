# 0023: Relay store integrity: damaged files, signature check on read, cache policy

- Status: accepted (by the project owner, 2026-11-21), with the recommended choice on rules 14 to 18
- Amended by: 0024 (rule 14: `epoch_renewed`); 0025 (rules 5 and 14: costs in the quarantine and the walk, `dirs_created`); 0046 (rule 13: `Cache-Control` of a block response when demand eviction is on; rule 18: `Retry-After` on `507` MAY be sent only while demand eviction is on, not suspended and not stuck, clarification D5)
- Date: 2026-11-19
- Questions: none
- Review: `docs/security/2026-11-21-relay-m1b.md`, finding L-1, design questions (b) and (c); also L-3,
  I-4, I-5
- Amends: ADR 0013 rules 9 and 18; ADR 0018 rule 18 (block-read class, signature bound); ADR 0021
  rules 7 and 41 (vocabulary, counters). Applies ADR 0003 rules 9 to 11 and spec §3.4 as written.
- Impact: spec §3.4 and §4 (`GET /block`, errors); `sbtp-relay` (`blocks.rs`, `store.rs`, `cache.rs`,
  `metrics`, `log`); no test vector of `docs/test-vectors/` changes

## Context

The `block_id` does not cover the signature (spec §3.4). In milestone 1b (`c341c2d`) the relay checks a
stored file on read with parse and R1 only. A file damaged on disk is then permanent: with a damaged body,
`GET` gives `404` and `PUT` of the valid block gives `200` while the file stays; with a damaged signature,
`GET` serves invalid bytes with `Cache-Control: … immutable`. Only disk corruption or a local writer
produces this. Spec §3.4 limits "first write wins" to fully validated bytes, so a stored file that fails
full validation is not protected by it.

The security review recommended no signature check on `GET`. The project owner decided otherwise
(decision 2 below): a relay that announces `immutable` to every cache on the path must have verified what
it announces.

## Decisions of the project owner

1. **Quarantine and replace.** A stored file that fails full validation is moved to a quarantine area
   inside `data_dir`. It is replaced only inside a `PUT` permit, only after the submitted bytes passed F1
   to F9, P1, C1, C2 and C3, and never on an I/O error.
2. **Signature check on read.** On a `GET` cache miss the relay verifies the file before serving it,
   inside the block-read permit. The cache holds only verified bytes. A file that fails is quarantined
   and answered `404`.
3. **Cache policy.** `Cache-Control: public, max-age=31536000, immutable` is sent only for verified bytes.

The rules below make these decisions normative. Rules 14 to 18 settle the smaller 1b questions; each
states the recommended choice. The project owner accepted those choices on 2026-11-21.

## Decision

### Full validation of a stored file

1. A stored file passes **full validation** for the `block_id` of its name when it passes F1 to F9 (§2.2),
   R1 against that name, and C2 and C3. P1 and C1 are not re-checked: P1 is a policy at receipt, and C1
   depends on the `block_id` only, which R1 fixes.
2. A file that fails full validation is **damaged**. A damaged file is not a stored block for spec §3.4
   and ADR 0003 rule 9. An I/O error while reading a file is not a validation failure: it gives `500`
   (`Internal`) and changes nothing.

### Quarantine area

3. **Place.** `data_dir/quarantine/`, created at start-up with `blocks/` and `tmp/`, on the same file
   system. It is never served, and no path under it is derived from client bytes.
4. **Name.** `<64 hexadecimal characters of the final name>.<unix ms of the move>.<n>`, `n` a process
   counter. A move MUST NOT replace an existing file (exclusive `link` then `unlink`, or a no-replace
   rename).
5. **Size.** A quarantined file stays counted in `max_store_bytes` (ADR 0013 rule 18, amended): the sum
   covers block files and quarantined files. A move does not change the running sum; a purge releases the
   cost of the file purged. The start-up walk (rule 15) recomputes the sum from file lengths.
6. **Bound and retention.** At most 64 quarantined files (a constant, not a setting). A move that would
   exceed 64 first deletes the oldest. A quarantined file is deleted 7 days after its move, by the
   start-up walk and by the sweeper. The sweeper runs for this purpose even when `block_ttl_ms = 0`.
   Entries that are not regular files are skipped, never followed.
7. **Quarantine lock.** Every move out of a final name (rules 8 and 10) holds one relay-wide lock. Under
   the lock the relay reads the final name again and moves the file only if its bytes equal the bytes it
   judged damaged. Otherwise it releases the lock and decides again from the new state, once. The
   operation is rare; the lock bounds nothing else.

### `PUT` of a block whose stored file is damaged

8. Under the `PUT` permit, after F1 to F9, P1 and C1:
   1. Read the final name. I/O error: `500`. Absent: normal path (ADR 0013 rule 7).
   2. Bytes identical to the body: `200` (ADR 0003 rule 10 shortcut, unchanged).
   3. Bytes differ: verify the submitted bytes (C2, C3); failure gives `422`, nothing changes. The stored
      file is checked only after this step, so only a key holder reaches a second verification.
   4. Full validation of the stored file. It passes: `200`, nothing changes (first write wins).
   5. It fails: under the lock (rule 7), move it to quarantine, then `fsync` the quarantine directory
      and the shard directory.
   6. Normal create path: quota reservation, temporary file, `fsync`, exclusive `link`, `fsync` of the
      shard, unlink of the temporary name. `AlreadyExists` (a concurrent `PUT` won): `200`. No room:
      `507`; the damaged file stays in quarantine.
   7. Index: an existing entry is kept as is (it was derived from the validated bytes). With no entry,
      the relay indexes the block as an orphan (ADR 0013 rule 9). Answer `200`: the `block_id` was
      already accepted by this relay, so no new position is assigned.
9. **Crash safety.** Before the move: the damaged file is still in place and is detected again. Between
   the move and the `link`: the final name is absent and the index entry is a phantom (ADR 0013 rule 8);
   the next `PUT` stores the block by the normal path. After the `link`: the file is complete (it was
   `fsync`ed before the `link`). A temporary file left behind is removed at start-up. No state needs a
   journal.

### `GET` cache miss

10. Under the block-read permit: read the file, apply full validation (rule 1), then insert it into the
    cache and serve it. A damaged file is moved to quarantine (rule 7) and answered `404` (`NotFound`).
    If the move fails, the answer is still `404` and the failure is logged (rule 16). The index entry,
    if any, becomes a phantom.
11. A cache hit serves the cached bytes and verifies nothing: only fully validated bytes enter the cache,
    from this rule or from a `201`/`200` path whose bytes passed C2 and C3.
12. **Cost (ADR 0018 rule 18, amended).** One verification is about 40 µs of CPU (BLAKE3 over at most
    65,909 bytes and one strict Ed25519 verification). It runs only on a cache miss and only inside a
    block-read permit, so at most `block_max_readers` run at once, plus at most `put_max_in_flight` in
    `PUT` permits and one in the start-up walk. The bound of ADR 0018 rule 18 becomes: "No signature is
    verified outside a `PUT` permit, a block-read permit or the start-up walk." Queue, timeout and `503`
    of the class are unchanged. At the default of 4 permits the class uses at most 4 cores for about
    40 µs per miss on top of the file read it already covers.

### Cache policy

13. `Cache-Control`:

    | Response | `Cache-Control` |
    |---|---|
    | `GET /block` `200` | `public, max-age=31536000, immutable`. Only bytes that passed rule 1 or C2 and C3 are served, so every `200` carries it. |
    | `HEAD /block` | The headers `GET` would send, no body (RFC 9110 §9.3.2). Same pipeline, permit and verification. `HEAD` stays outside the protocol interface (ADR 0012); a client MUST NOT rely on it. |
    | `404`, `429`, `503`, `507`, every other `4xx` and `5xx` | `no-store` (ADR 0012 rule 32). A `404` MUST NOT be cached: the block can be stored later. |
    | `PUT` `200`, `201` | `no-store`. |

### 1b questions settled

14. **(a) Events and counters (ADR 0021 rules 7 and 41, amended).** Minimal set:

    | `event` | Level | Fields | When |
    |---|---|---|---|
    | `block_quarantined` | warn | `cause` (`get`, `put`, `startup`), `reason` (`parse`, `id`, `signature`), `suppressed` | A file was moved to quarantine. No `block` field: ADR 0021 rule 12 keeps `block_id`s out of `warn`; the quarantine file name holds it. |
    | `store_reconciled` | info | `files`, `orphans`, `quarantined`, `purged`, `duration_ms` | Once, at the end of the start-up walk (review L-3). |

    `store_write_failed` field `op` takes the values `read`, `write`, `sync` (milestone 1b), `quarantine` and `purge`. Counters:
    `store_quarantined_total` (label `reason`), `store_replaced_total` (no label), gauge
    `quarantine_files`. They count files moved, not requests: a second `GET` of the same id finds no file
    and adds nothing (review I-5). The 1b counter `store_corrupt` is replaced by
    `store_quarantined_total`. **Recommended:** no `block_known` event; `blocks_accepted_total{result=
    "known"}` already counts it.
15. **(e) Start-up walk. Recommended: a full walk at each start, done once.** One walk over `tmp/`
    (delete), `quarantine/` (sum, purge, bound) and `blocks/` (sum; for each file without an index
    entry, full validation, then index or quarantine). Indexed files are not read. For files the relay
    wrote, the walk is bounded by `max_store_bytes / 4,096` files (clarification C1). It replaces the two
    walks of 1b (quota sum and reconciliation).
    ADR 0013 rule 9 is amended: the relay reconciles at every start, and an orphan is indexed only after
    full validation, including on the `PUT` path even when the identical-bytes shortcut applied.
16. **Directory `fsync` failure after the `link`.** **Recommended:** `500` (`Internal`), the file is kept
    under its final name, its quota charge is kept, no index entry is written, and `store_write_failed`
    is logged. The file is a valid orphan, indexed by the next `PUT` of the block or the next start-up
    walk (ADR 0013 rule 9). The client retries and gets `200`.
17. **(g) Empty id.** **Recommended:** `GET /sbtp/v1/block/` is `404` (`NotFound`), with the JSON error
    body and `no-store`. The path has no `block_id` segment, so the `400` rule of spec §4 does not apply.
18. **(h) `Retry-After` on `507`.** **Recommended:** not sent by the reference relay. The relay cannot
    predict when room frees: eviction depends on `block_ttl_ms` and the sweeper interval, and the store
    may stay full for days. A client tries another relay. ADR 0013 rule 19 keeps its `MAY` for other
    implementations.

## Consequences

- **Security.** A damaged file is never served, never answered `200` as a held block, and never cached
  with `immutable`. A valid stored file is never displaced: replacement requires the stored file to fail
  a deterministic check, and first write wins holds for validated bytes. Remote clients cannot trigger a
  move of a valid file.
- **Cost.** One verification per cache miss, bounded by `block_max_readers`. The start-up walk verifies
  orphans only.
- **Behaviour.** `/query` can list a block whose file was quarantined; `GET` then gives `404`, as after
  an eviction (ADR 0012 rule 13). A replacement answers `200`, not `201`.
- **Remaining case.** A `PUT` byte-identical to a file damaged in its signature gets `200` under the ADR
  0003 rule 10 shortcut when the file has an index entry; the next `GET` miss quarantines the file. When
  the file has no index entry, the `PUT` verifies C2 and C3 and quarantines the file on failure
  (clarification C6).
- **Code (the implementer).** `blocks.rs`: `load` adds C2/C3 and quarantine; `process` gains the
  sequence of rule 8; `repair` indexes only after full validation. `store.rs`: `quarantine/`, the lock,
  move, purge and bound; one start-up walk; quota sum over both areas. `cache.rs`: unchanged (inserts
  already follow the check). Error responses gain `no-store`. Tests: damaged body and damaged signature,
  each for `GET` (`404`, counter, file moved) and `PUT` (`200`, then `GET` `200` with valid bytes); racing
  repairs give one file; crash between move and `link`; bound of 64 and retention; `HEAD`; `no-store` on
  `404`, `429`, `503`, `507`.

## Clarifications (2026-11-21, after review)

Approved by the project owner after the security review of the implementation (`8f019da`). They record
behaviour. They change no decision above.

- **C1. Rule 15 walk bound.** The bound `max_store_bytes / 4,096` files holds for files the relay wrote.
  It is not enforced for entries written by a local writer: a zero-length file costs 0 in the quota sum.
  Inode and directory costs stay with Q-31 (milestone 1c).
- **C2. Rule 7, second change.** If the re-decision finds the file changed again, `PUT` answers `500`
  (`Internal`) and logs it; `GET` answers `404`. Only a local writer produces this.
- **C3. Directory `fsync` failure after a quarantine move.** `PUT` answers `500` and does not create the
  block over the move; the retry takes the normal path. `GET` answers `404`. The start-up walk logs and
  continues. The failure is logged as `store_write_failed` with `op=quarantine`.
- **C4. `PUT` after a quarantine by `GET` or the walk.** A `PUT` that finds the final name absent because
  a `GET` or the walk already quarantined the file takes the normal path: `201` and a new position, as for
  a phantom entry (rule 9). Only a replacement made by the `PUT` itself answers `200` (rule 8.7).
- **C5. Rule 8.4.** When the stored file passes full validation and has no index entry, the relay indexes
  it as an orphan (ADR 0013 rule 9). Existing positions never move.
- **C6. `PUT` identical to a stored file with no index entry.** The relay verifies C2 and C3, because it
  cannot index without full validation (rule 15). On failure it answers `422` and quarantines the stored
  file (`cause=put`, `reason=signature`). The ADR 0003 rule 10 shortcut for an indexed file (verification
  skipped, `200`) is unchanged.
- **C7. Unreadable orphan at start-up.** An I/O error on an orphan file during the start-up walk does not
  stop start-up. The relay logs it, leaves the file in place unindexed and continues. Listing and index
  errors still stop start-up.
- **C8. Orphan position.** At start-up, the position of an orphan comes from the file mtime, capped at the
  current time.

## Rejected alternatives

- **No signature check on `GET`** (review answer b). The relay would announce `immutable` for bytes it
  did not verify, and a damaged signature would spread to every cache on the path.
- **Unlink instead of quarantine.** Simpler, but leaves the operator nothing to inspect after a disk
  fault.
- **Quarantine outside the quota.** An unbounded second store; the 64-file bound and the quota together
  keep disk use a function of the settings.
- **Durable clean-shutdown marker instead of a full walk.** The quota sum needs a walk at each start
  anyway (ADR 0013 rule 18 counts file lengths), and a marker is a second source of truth beside the
  files (ADR 0013 rule 1).
- **Roll back by unlinking after a failed directory `fsync`.** The unlink needs the same `fsync` that
  just failed, and a concurrent `PUT` may already have received `200` for that file (review I-4).
- **Replace before quarantine (write over the final name).** Breaks the exclusive `link` that makes two
  writers give one winner.

## Spec change

Applied on acceptance (2026-11-21). `docs/spec/sbtp-core-v0.2.md`:

- §3.4, "Storage", append: "A stored file that fails full validation for its `block_id` is not a stored
  block. A relay MUST NOT serve it and MAY replace it with bytes that pass full validation."
- §4, `GET /sbtp/v1/block/{block_id}`, replace the `Cache-Control` line with: "A relay MUST serve only
  bytes that pass full validation (§2.2) and R1 for the requested `block_id`. A stored file that fails
  gets `404` (`NotFound`). A `200` response SHOULD carry `Cache-Control: public, max-age=31536000,
  immutable`."
- §4, "Errors", append: "Error responses carry `Cache-Control: no-store`. (ADR 0012, ADR 0023)"
