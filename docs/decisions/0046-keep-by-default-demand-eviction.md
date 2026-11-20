# 0046: Relays keep by default; eviction under disk pressure by least recent demand

- Status: proposed
- Date: 2026-11-20
- Questions: none open; owner direction of 2026-11-20 (relays keep what they receive; a relay with
  little disk drops what is not, or no longer, requested). Chunks wait on Q-21
- Amends:
  - ADR 0013 rule 12 (default of `block_ttl_ms`; "Eviction does not depend on reads"), rule 16 (what an
    archive relay is) and rule 21 ("MUST NOT evict unexpired blocks to make room");
  - ADR 0019 rule 4 (default of `block_ttl_ms`), rule 37 (one profile row) and rule 38 (policy
    settings);
  - ADR 0018 rule 35 (one more term in the memory bound);
  - ADR 0021 rule 41 (counters and gauges);
  - ADR 0043 rule 1 (definition of an archive relay; the default `block_ttl_ms` is no longer 30 days).
  Nothing else in these ADRs changes
- Depends on: ADR 0013 rules 8, 13, 14, 15 and 18; ADR 0023 rule 13 (`Cache-Control`); ADR 0024
  (cursors); ADR 0043 rules 3 to 5
- Impact: core spec §4 (`GET /block`, `/info`); `architecture.md` §2 ("Eviction", "Quota");
  `sbtp-relay` (settings, index tables, read path, sweeper, metrics); no wire format change, no test
  vector

## Context

Today a relay evicts every block 30 days after it accepted it, whether or not anyone reads it, and a full
relay answers `507` and never makes room (ADR 0013 rules 12 and 21). ADR 0043 then relies on archive
relays and re-publication to keep long-lived blocks.

The owner's direction: a relay node keeps what it receives (clients are not relays and keep what they
choose). A relay with little disk needs to make room, and what goes first is what nobody requests, for
example the parts of a large item that are no longer downloaded.

Facts the design relies on:

- A relay reads header fields only. It cannot tell a container root from a leaf, nor group the chunks
  of one item.
- A `200` of `GET /block` carries `Cache-Control: public, max-age=31536000, immutable`; a `404` carries
  `no-store` (ADR 0023 rule 13). A CDN in front of a relay serves hits from its edges.
- `GET /block` does not touch the index today (ADR 0013 rule 11). The index has one writer.
- The `small` profile's computed worst case is 13,018,580 bytes against a 15 MB target (ADR 0019
  rule 37); about 2 MB are left.

## Decision

### Default posture

1. **Keep.** The default of `block_ttl_ms` in `sbtp-relay` becomes `0` (no eviction by age). Eviction by
   age stays a setting that an operator MAY choose (range of ADR 0019 rule 4, unchanged).
2. **Demand eviction on by default.** A relay MAY evict blocks by demand under rules 3 to 16. In
   `sbtp-relay` it is on by default (`demand_eviction = true`): a default relay keeps everything until its
   store reaches the high-water mark, then drops the blocks requested least recently.
3. **Archive relay.** An archive relay is a relay with eviction by age off and demand eviction off. It
   never deletes a block and answers `507` when full (ADR 0013 rule 19). ADR 0043 rule 1 reads "a relay
   with `"block_ttl_ms": null` and `"demand_eviction": false`" instead of "a relay with
   `"block_ttl_ms": null`".
4. **`/info`.** A relay publishes `"demand_eviction": true` when it evicts by demand. A client MUST read
   an absent member as `false`.

### Eviction under disk pressure

5. **Trigger.** The sweeper (ADR 0013 rule 15) runs demand eviction when the stored total (ADR 0013
   rule 18, ADR 0025) is above `demand_high_water_pct` of `max_store_bytes`. It evicts until the total is
   at or below `demand_low_water_pct`, in runs of at most `sweep_batch` blocks.
6. **Order.** Candidates are taken in increasing order of `(last_demand, position)`: the block requested
   least recently first; among equals, the oldest position first.
7. **Protection.** A relay MUST NOT evict by demand a block whose `last_demand` falls in the current or
   the previous demand epoch (rule 9). A new block therefore stays at least one full epoch.
8. **No eviction on the write path.** A `PUT` never evicts. A new block that does not fit gets `507`
   `StorageFull` as today (ADR 0013 rules 19 and 20). When demand eviction is on and the store is above
   the high-water mark, the relay MAY send `Retry-After` (seconds of `sweep_interval_ms`, rounded up).
   When no block is a candidate under rule 7, the sweeper evicts nothing and logs `demand_stuck`; new
   blocks get `507` until the next epoch makes candidates.

### What counts as demand

9. **Epoch.** `demand_epoch_ms` cuts time into epochs. `last_demand` is the start, in Unix milliseconds,
   of the last epoch in which the block was demanded. It is stored as a time, not an epoch number, so a
   change of `demand_epoch_ms` keeps the stored order.
10. **Demand events.** Each of the following sets a block's `last_demand` to the current epoch:
    - its acceptance (`201`), so a block nobody has read yet is not the first to go;
    - a `GET` or `HEAD` of `/block` answered `200` or `304`;
    - a `PUT` of it answered `200` (a re-submission, ADR 0043 rule 5);
    - the acceptance of a block that names it in its Parents Hashes field, for each held parent (at most
      8, ADR 0014). This is the only header-level DAG fact used; see rule 15.
    A `/query` listing is not demand.
11. **One count per block per epoch.** A relay MUST count at most one demand per block per epoch,
    whatever the client. Demand only moves `last_demand` forward; there is no counter. This bounds every
    client, and stores no client identity next to a block.

### Recording demand (write amplification)

12. **In memory, then in batches.** The `GET`, `HEAD` and `PUT` paths do not touch the index. They insert
    the `block_id` into a bounded in-memory set of the current epoch (`demand_touch_max` entries). The
    single index writer flushes the set in one transaction when it is full, when an epoch ends, every
    `sweep_interval_ms`, and at a clean shutdown. A flush skips a block not held and a block whose stored
    `last_demand` is already the current epoch: at most one index update per block per epoch.
13. **When the set is full** and a flush is in progress, a new demand is dropped and counted
    (`demand_dropped_total`). A dropped demand makes a block look one epoch colder; it never deletes
    anything by itself. Exception: the demand of a `PUT` answered `200` is never dropped; when the set is
    full, the index writer records it before the response (it is under the `put` rate limits).
14. **Crash.** Demands not yet flushed are lost by a crash. The affected blocks look one epoch colder.
    Nothing else depends on them.

### Problems stated explicitly

15. **DAG integrity.** Rule 10 refreshes a parent each time a child is accepted, so a root with active
    children stays warm. A block with held children is not otherwise protected: anyone can mint a child
    of any block, so absolute protection would let anyone pin the whole store and turn every new block
    into a `507`. A dormant root can be evicted before or with its dormant children. The availability of
    long-lived blocks is guaranteed by archive relays and by re-publication on `404` (ADR 0043 rules 1
    and 5), not by a relay with demand eviction. A client handles a missing parent as pending
    (ADR 0043 rule 6).
16. **CDN in front of a relay.** Edge hits never reach the origin: the origin sees one request per edge
    per edge cache lifetime. Popular blocks therefore look colder at the origin than they are. This is
    accepted:
    - while an edge holds a block, the origin copy is not what serves it; when edges miss, the miss
      reaches the origin and counts as demand;
    - when the origin has evicted a block and an edge misses, the `404` is not cached (`no-store`), and
      the client falls back to another relay or an archive and MAY re-submit (ADR 0043 rule 5);
    - an operator behind a CDN who wants the origin to keep popular blocks sets a larger quota or turns
      demand eviction off. `Cache-Control` of a `200` is unchanged: the bytes are immutable.
17. **Gaming.** One `GET` per block per epoch keeps a block warm; filling the store with new blocks
    pushes cold blocks out. Both are accepted. Reads cannot make a block colder. Writes cost one proof
    of work each (ADR 0045) and are under the `put` rate limits. Demand eviction is local: it is not a
    deletion or censorship mechanism, and other relays and archives keep their copies (ADR 0013
    rule 17).

### Interactions

18. **Deletion.** A demand eviction deletes in the sweeper's order: cache entry, block file, then the
    block's own index entries (position, `block_id`, its edges to its parents) and its demand entries.
    Edges in which the evicted block is the parent belong to its children and stay: `/query?parent=`
    still lists held children of an evicted block. A crash between steps leaves a phantom (ADR 0013
    rule 8).
19. **`/query` and cursors.** An evicted block disappears from `/query` once its index entries are
    removed; before that, a client may get a `404` for a listed block (ADR 0012 rule 13). Removing
    positions does not invalidate a cursor and does not draw a new epoch (ADR 0024): a walk lists what
    is still held.
20. **Re-acceptance.** A `PUT` of an evicted block is a new block: `201`, new `received_at`, new
    position, `last_demand` of the current epoch (ADR 0013 rule 13). The sweeper serialises a demand
    eviction and a `PUT` of the same `block_id` as for expiry (ADR 0043 rule 4) and re-checks, at
    deletion time, that the block is still a candidate, the in-memory set included. A `PUT` answered `200`
    is therefore never followed by a demand eviction of that block within the next epoch.
21. **Age and demand together.** A relay with both enabled evicts a block at its expiry by age or earlier
    by demand, whichever comes first. Demand never changes `received_at` or the expiry of ADR 0013
    rule 12.

### Chunks

22. **Scope.** This ADR covers blocks. Chunks (ADR 0010) are not served by relays yet; their transport,
    admission and storage are Q-21. When Q-21 is decided, it SHOULD reuse rules 5 to 14 per chunk under
    the same quota. A relay cannot group the chunks of one item: each chunk ages by its own requests,
    so an item that is no longer downloaded loses its chunks one by one, and a partly downloaded item
    loses its unread chunks first.

### Settings and metrics

23. **Settings** (environment variables `SBTP_RELAY_<NAME>`, as in ADR 0019):

    | Setting | Default | Range | Why |
    |---|---|---|---|
    | `block_ttl_ms` | 0 (was 2,592,000,000) | unchanged: 0, or 60,000 to 315,360,000,000 | Rule 1. |
    | `demand_eviction` | `true` | `true`, `false` | Rule 2. Off on an archive relay. |
    | `demand_high_water_pct` | 90 | 50 to 99 | Leaves room for the `PUT`s that arrive between two sweeper runs. |
    | `demand_low_water_pct` | 80 | 10 to `demand_high_water_pct − 1` | A gap avoids a run on every new block. Equal or higher stops the start-up. |
    | `demand_epoch_ms` | 86,400,000 (1 day) | 3,600,000 (1 hour) to 2,592,000,000 (30 days) | One index update per block per epoch at most. Shorter costs more writes; rule 7 makes it the minimum stay. |
    | `demand_touch_max` | profile: 16,384 / 131,072 / 1,048,576 | 1,024 to 16,777,216 | Set by the profile (`small` / `standard` / `large`). |

    `demand_eviction`, the two watermarks and `demand_epoch_ms` are policy settings and are not set by a
    profile (ADR 0019 rule 38). `demand_touch_max` is a profile row (ADR 0019 rule 37). The settings are
    validated even when `demand_eviction` is `false`, as `sweep_*` are with `block_ttl_ms = 0`.
24. **Memory.** The set costs at most `demand_touch_max × 48` bytes (estimate: 32-byte identifier plus
    table overhead; not measured), added to the bound of ADR 0018 rule 35: 786,432 bytes on `small`
    (worst case 13,805,012 bytes, under 15 MB), 6 MiB on `standard`, 48 MiB on `large`.
25. **Index.** Two entries per held block: `position → last_demand` and `(last_demand, position) → ()`.
    They count in the index size and therefore in the quota (ADR 0013 rule 18). Estimate: about 60 bytes
    per block, not measured.
26. **Metrics** (prefix `sbtp_relay_`, ADR 0021 rule 41):

    | Name | Kind | Labels |
    |---|---|---|
    | `demand_evicted_blocks_total`, `demand_evicted_bytes_total` | counter | none |
    | `demand_runs_total`, `demand_stuck_total` | counter | none |
    | `demand_flushes_total`, `demand_flush_updates_total` | counter | none |
    | `demand_dropped_total` | counter | none |
    | `demand_touch_entries` | gauge | none |
    | `demand_coldest_ms` | gauge (`last_demand` of the next candidate, 0 when none) | none |

    Events: `demand_evicted` (one line per run: blocks, bytes, duration) and `demand_stuck` (rate-capped,
    ADR 0021). No event names a `block_id` or a client.

## Consequences

- **Network.** By default a relay is a long-lived source until its disk is near full, and the blocks it
  drops are those nobody asked for in the last epochs. Archive relays remain the guarantee.
- **Privacy.** The index now records, per block, the day it was last requested. No client identity is
  stored with it (rule 11). Someone with the disk learns which blocks were read on which day, not by
  whom. An operator who does not want this turns demand eviction off.
- **Cost.** Reads stay O(1) and off the index: one insert into a bounded set. Index writes are at most
  one per block per epoch plus one per accepted block. A client that enumerates every block by `GET`
  costs at most one update per held block per epoch, under the `block` rate limit.
- **Compatibility.** Nothing is released. A relay that does not implement this ADR is a relay without
  demand eviction (rule 4).

## Implementation plan (relay-engineer)

1. `config.rs`: `block_ttl_ms` default 0; the five settings of rule 23, ranges, the low < high check,
   the `demand_touch_max` profile row; `/info` member `demand_eviction`.
2. `index.rs`: tables `demand` (`position → u64`) and `demand_order` (`(u64, position) → ()`); written in
   the same transaction as the other entries on insert, removed with them; a start-up step that fills
   both for blocks that have none (`last_demand = received_at` quantised to its epoch); a `candidates`
   read job bounded by `sweep_batch`.
3. A `DemandSet` (bounded set of `block_id`, current epoch start) shared by `api.rs` (`GET`, `HEAD`,
   `PUT` `200`) and the `PUT` `201` path (the block and its held parents). Flush job on the index writer.
4. `sweep.rs`: after the age pass, a demand pass when above the high-water mark; re-check at deletion
   under the per-`block_id` serialisation of ADR 0043 rule 4, including the in-memory set; `demand_stuck`.
5. `metrics.rs`, `log.rs`: rule 26. The memory bound logged at start-up includes rule 24.
6. Tests: the order of rule 6; the protection of rule 7; low and high water; `507` and `Retry-After`
   with nothing evictable; one update per block per epoch under repeated `GET`s; a full set drops and
   counts; a parent refreshed by a child; a `PUT` `200` racing a demand eviction; re-acceptance after
   eviction gets `201`; `/query?parent=` of an evicted parent still lists its children; restart keeps
   `last_demand`; an archive relay (both off) deletes nothing.
7. `deploy/README.md`: archive relay settings; the CDN note of rule 16.

**Security-auditor review** before merge: the bound of the demand set and the `GET` hot path (no index
access, no unbounded growth under an identifier flood); the race of rule 20; the start-up migration on a
large index (time bound, interruption); write-flood eviction of cold blocks (rule 17) against the
`small` profile; that logs and metrics carry no `block_id` or client key.

## Spec change on acceptance

Core spec §4, `GET /sbtp/v1/block/{block_id}`, the bullet "A relay MAY evict blocks…" replaced by:

> - A relay MAY evict blocks, by age (`block_ttl_ms`) or by demand (`demand_eviction`), both published by
>   `/info`. A `404` does not mean that the block does not exist. (ADR 0013, ADR 0046)

Core spec §4, `GET /sbtp/v1/info`: in the example, `"block_ttl_ms": null` and add
`"demand_eviction": true`; add the bullet:

> - `demand_eviction`: boolean; `true` when the relay evicts the blocks requested least recently once
>   its store is near full (`architecture.md` §2, "Eviction"). A client MUST read an absent member as
>   `false`. (ADR 0046)

`architecture.md` §2, "Eviction", replaced by:

> ### Eviction
> - A relay keeps what it receives. Eviction by age is a setting: a block expires when
>   `received_at + block_ttl_ms ≤ now`; `sbtp-relay` disables it by default (`block_ttl_ms = 0`, `/info`
>   `null`). A `PUT` of a held, unexpired block does not extend its lifetime. From its expiry a block is
>   not held for `PUT`: a `PUT` of it is a new block (`201`, new `received_at`), even before the sweeper
>   has deleted it, and the sweeper then deletes nothing of it. (ADRs 0013, 0043, 0046)
> - Eviction by demand: when the store is above a high-water mark of the quota, the sweeper evicts the
>   blocks requested least recently until it is at a low-water mark. Demand is its acceptance, a `GET`
>   answered `200` or `304`, a `PUT` answered `200`, and the acceptance of a child; at most one per block
>   per epoch, whatever the client. A block demanded in the current or the previous epoch is not
>   evicted. A `PUT` never evicts. (ADR 0046)
> - `/query` never lists an expired block. Evicted blocks leave `/query` when the sweeper removes them:
>   cache entry, block file, then index entries. Edges of their children stay.
> - An archive relay disables both; it never deletes a block. (ADRs 0019, 0046)
> - Eviction is local to a relay and is not a deletion mechanism. (ADR 0013)
> - Long-lived blocks are kept available by archive relays and by clients that submit them again after
>   a `404` or an expiry; a `PUT` never renews a block before it expires. (ADR 0043)

`architecture.md` §2, "Quota", second bullet replaced by:

> - A new block that does not fit gets `507 Insufficient Storage`. A `PUT` never evicts to make room;
>   only the sweeper evicts, by age or by demand. A full relay keeps serving reads. (ADRs 0013, 0046)

## Rejected alternatives

- **Keep 30 days by age as the default.** Contrary to the owner's direction; it deletes popular and
  unpopular blocks alike and keeps every relay dependent on re-publication.
- **Default `demand_eviction = false`.** A default relay with a small disk would answer `507` to every new
  block once full and stop being useful to the network. An archive is a deliberate choice; it is one
  setting away.
- **Counting reads (frequency, LFU).** Needs a counter per block, and a per-client bound on counts needs
  a table of client keys per block: memory, writes, and a record of who read what. Recency per epoch
  needs neither.
- **Updating the index on every `GET`.** One write per read, through the single index writer, on the
  hot path. Rule 12 bounds it to one per block per epoch, off the request path.
- **Protecting every block that has held children.** Anyone can mint a child of any block; the store
  could be pinned whole (rule 15).
- **Evicting on the `PUT` path to admit the new block.** It lets a write flood choose, request by
  request, what goes, and adds deletions to the latency of a `PUT`.
- **Triggering on low free disk space (ADR 0021) as well as on the quota.** Another process filling the
  disk would make the relay delete its store. Free space below the watermark keeps giving `507`.
