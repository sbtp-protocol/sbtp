# 0024: Cursor validity after an unclean shutdown: a new index epoch when the start-up walk indexes an orphan

- Status: accepted (by the project owner, 2026-11-19)
- Date: 2026-11-19
- Questions: Q-27
- Review: `docs/security/2026-11-18-relay-index.md`, finding F-6 (second point)
- Amends: ADR 0012 rule 9 (a cursor survives a restart unless the epoch changed); ADR 0013
  rule 5 (a second case in which the epoch is drawn); ADR 0023 rule 14 (one field added to
  `store_reconciled`)
- Depends on: ADR 0013 rules 3, 5, 9 and 10 (positions, epoch, orphans, batched durability); ADR 0023
  rule 15 and clarification C8 (one start-up walk; orphan position from the file time)
- Impact: spec §4 (`/query`, `cursor` bullet; see "Spec change", applied on 2026-11-19); `sbtp-relay` (`index.rs`:
  epoch renewal; `store.rs`: `reconcile`; the `/query` handler of milestone 1c); clients (`cli-demo`,
  `sbtp-wasm`, web client: handling of `InvalidCursor`); no `sbtp-core` change; no test vector

## Context

ADR 0013 rule 10 lets the index become durable in batches, at most 1 second apart. Index entries are
visible to `/query` as soon as their commit returns, before they are durable. A client can therefore
hold a cursor at a position whose entry a power loss or a `SIGKILL` erases.

After such a crash the index restarts from its last durable state, with last position `L`. The files of
the lost entries are still on disk (ADR 0013 rule 7 writes and `fsync`s the file before the index), so
the start-up walk (ADR 0023 rule 15) finds them as orphans and indexes them at positions above `L`
(`Position::assign` in `index.rs`). A client whose cursor lies above `L` never sees the orphans placed
between `L` and its cursor. This breaks the walk guarantee of ADR 0012 rule 12. ADR 0012 rule 9 says a
cursor "survives a restart".

Facts about the code at `f29e239` that the decision relies on:

- The epoch is a 64-bit random value stored in the `meta` table of `index.redb`, drawn only when the
  table has none (`RedbIndex::open`).
- `reconcile` (`store.rs`) runs before the relay listens. It indexes each orphan with
  `FileState::AlreadyHeld` at `min(mtime, now)`, and makes the index durable at the end if it indexed at
  least one orphan. An insert can itself be durable when the last durable commit is older than 1 second.
- Outside the start-up walk, an orphan is indexed only by a `PUT` (ADR 0013 rule 9), at the current time.
  Its position is then above every position visible since the start, hence above every cursor issued
  since the start.
- The `/query` handler and the cursor encoding are milestone 1c work (`api.rs`, `HOOK(1c)`).

## Decision

### When the epoch changes

1. **Trigger.** When the start-up walk (ADR 0023 rule 15) indexes at least one orphan, the relay MUST give
   the index a new epoch. No other start-up event changes the epoch, except the creation or rebuild of the
   index (ADR 0013 rule 5).
2. **Value.** The new epoch is 64 bits from the operating system's random source. It MUST differ from the
   previous epoch; the relay draws again if it does not.
3. **Order.** The new epoch MUST be durable (redb `Durability::Immediate`) before the first orphan entry
   of the walk is written. A crash during the walk then leaves either the old epoch with no orphan
   indexed, or the new epoch. The relay serves no `/query` until the walk has ended (ADR 0013 rule 11).
4. **Once per start.** The epoch changes at most once per start, whatever the number of orphans.
5. **Runtime repair.** The repair of an orphan by a `PUT` (ADR 0013 rule 9) does not change the epoch.

### What a client sees

6. **Clean restart.** After a clean shutdown (index made durable at stop, ADR 0013 rule 10) the walk
   finds no orphan written by the relay: cursors keep working.
7. **Unclean restart.** After a start that changed the epoch, every cursor issued before it gets `400`
   with the error `InvalidCursor` (ADR 0012 rules 9 and 17). Nothing else changes for a client: `PUT`,
   `GET /block` and `/info` behave as before.
8. **Client rule.** A client MUST accept `InvalidCursor` on any `/query` request, including in the middle
   of a walk. It then starts the walk again without a cursor, and deduplicates by `block_id` (ADR 0012
   rule 13). It MUST NOT retry the rejected cursor. It MAY bound the new walk with `since`; only a walk
   without `since` is guaranteed to return every held block.

### Amended rules

9. **ADR 0012 rule 9** reads: "… it does not expire with time, and it survives a restart, except a restart
   after which the relay changed the epoch of its index (ADR 0013 rule 5, ADR 0024). … A cursor that the
   relay does not recognise (another relay, index rebuilt, new epoch, malformed) gets `400`
   `InvalidCursor`; the client starts again without a cursor."
10. **ADR 0013 rule 5** gains: "The epoch is also drawn again when the start-up walk indexes an orphan
    (ADR 0024)."
11. **ADR 0023 rule 14.** `store_reconciled` gains the field `epoch_renewed` (`true` or `false`). No new
    event and no new counter.

## Consequences

- **Correctness.** Every cursor that could point above a lost entry is refused. A refused cursor costs a
  client one new walk; a stale cursor accepted would cost it blocks it never sees. The guarantee of ADR
  0012 rule 12 then holds within one epoch.
- **Why orphans are the right trigger.** An entry visible before a crash and lost by it leaves its file
  on disk, so the walk sees an orphan. The trigger also covers an index restored from an older copy (the
  upgrade note in `index.rs`): the files written since the copy are orphans. It needs no shutdown marker
  and no state beside the index.
- **Extra resets.** An orphan can also exist after a clean shutdown: a directory `fsync` failure after
  the `link` (ADR 0023 rule 16), an index insert that failed for lack of space (ADR 0021 rule 37), or a
  file placed by a local writer. These starts also change the epoch. They are rare, and the cost is one
  new walk per client.
- **Residual case, accepted.** If every lost entry's file is also gone before the restart (quarantined or
  removed by a local writer) and the clock at restart is behind the lost positions, blocks stored after
  the restart can take positions below a stale cursor that stays valid. This needs a crash, the loss of
  files written in the last second, and a clock step back across the restart. It is not handled.
- **Cost for clients.** A child walk (`parent=`) is a few pages. A mirror that lists the whole store
  walks it again: at the default quota, at most about 262,144 identifiers, about 17.6 MB in 263 pages
  of 1,000. Informative: a mirror that records the `Date` header of its last complete page can restart
  with a `since` slightly before it and accept the small risk of a relay clock step.
- **Benchmark.** ADR 0017 rule 18 already allows the epoch to change at step 5. Unchanged.
- **Code (the implementer, milestone 1c).**
  - `index.rs`: `IndexBackend` gains a method that draws, stores and durably commits a new epoch
    (rules 2 and 3). `RedbIndex::epoch` becomes readable after that call; the walk runs before the
    index is shared with request handlers, so an atomic or a `&mut` call before sharing is enough.
  - `store.rs`, `reconcile`: call it once, before the first orphan `insert` (rule 3); set
    `epoch_renewed` in `store_reconciled`.
  - The `/query` handler of 1c: compare the cursor epoch with the current one (ADR 0013 rule 5).
  - Tests: clean stop then restart, old cursor accepted; `SIGKILL` during a load with orphans found,
    old cursor gets `400` `InvalidCursor`; restart with no orphan keeps the epoch; a crash injected
    between the epoch commit and the first orphan insert leaves a new epoch at the next start; a
    restored older `index.redb` changes the epoch.
- **Clients (the implementer).** `cli-demo` and the web client restart a walk on `InvalidCursor`
  (rule 8).
- **Compatibility.** No relay is deployed. No format and no test vector changes.

## Rejected alternatives

- **Reconcile only at positions above every cursor issued.** The relay would need a durable record of
  the highest position it handed out, written before each `/query` response: an index write per read,
  against "a `GET` writes no state" (ADR 0013 rule 12) and the cost bound of ADR 0012 rule 14.
- **Index orphans at the start-up time instead of the file time.** Puts orphans above old cursors
  without an epoch change, but only if the clock at restart is ahead of every position issued before
  the crash. A clock behind at boot (F-6, first point) breaks it silently. It also changes `since` for
  those blocks and extends their lifetime by the downtime.
- **Durable clean-shutdown flag in the index.** Detects every unclean shutdown, including the residual
  case, but misses an index restored from a copy taken while the relay was stopped, so the orphan
  trigger is needed anyway. It adds a second trigger for a case that needs three coincident faults.
- **Make every index commit durable.** Removes the lost-entry window, at the cost of one `fsync` per
  `PUT`. ADR 0013 rule 10 chose batches for throughput; this ADR does not revisit it.
- **A new epoch at every start.** Simple, but breaks every client's cursor at each upgrade or planned
  restart, which is the common case.
- **Publish the epoch or a reset time in `/info`.** A client learns of a reset from `InvalidCursor`
  already. A new member is unnecessary.

## Spec change

Applied on 2026-11-19.

`docs/spec/sbtp-core-v0.2.md`, §4, `GET /sbtp/v1/query`, response, `cursor` bullet. Replace "A cursor is
valid with any `parent` and `since`, and survives a relay restart." with:

> A cursor is valid with any `parent` and `since`. It survives a clean restart of the relay. After an
> unclean shutdown the relay MAY refuse every earlier cursor with `400` (`InvalidCursor`). A client MUST
> accept `InvalidCursor` on any request; it then walks again without a cursor and deduplicates by
> `block_id`. (ADR 0012, ADR 0024)

`docs/spec/architecture.md`, §2 "Index", append to the bullet on repair:

> When the start-up reconciliation indexes a block that was missing from the index, the relay draws a new
> index epoch, so that cursors issued before the crash are refused rather than skip blocks. (ADR 0024)
