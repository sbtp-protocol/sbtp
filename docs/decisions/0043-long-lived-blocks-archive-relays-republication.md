# 0043: Long-lived blocks: archive relays, re-publication, and a `PUT` of an expired block

- Status: accepted (2026-11-20, owner)
- Amended by: 0046 (rule 1: definition of an archive relay; the default `block_ttl_ms` is no longer 30 days); 0052 (rule 5: a re-submission follows a `404`
  to a single `GET` or `HEAD`, never a `length = 0` batch record alone, and never a `451`)
- Date: 2026-11-20
- Questions: Q-24
- Amends: ADR 0013 rules 13 and 15 (what "after eviction" means for a `PUT`, and what the
  sweeper may delete); `l2-grammar.md` §5.5, re-submission of the current key block. Nothing else in
  ADR 0013 changes
- Depends on: ADR 0008 (`200` / `201`), ADR 0013 (positions, expiry, sweeper), ADR 0019 (archive relay),
  ADR 0029 (client bounds)
- Impact: core spec §4 `PUT` responses; `architecture.md` §2 "Eviction"; `l2-grammar.md` §5.5;
  `sbtp-relay` (`PUT` path and sweeper); clients (re-publication); no wire format change, no vector change

## Context

A relay evicts a block `block_ttl_ms` after it accepted it (default 30 days). It cannot tell a block that
every later block depends on (a container root, a key block) from a short-lived one: it never parses a
payload. After expiry, later blocks name a parent that the relay no longer lists.

ADR 0013 rule 13 says a `PUT` of a held block does not extend its lifetime, and that "after eviction" the
block is new again (`201`). It does not say what happens between expiry and the sweeper's deletion. The
reference relay answers `200` in that window and keeps the old `received_at`: the block stays hidden from
`/query` until the sweeper deletes it, and the client was told it is stored.

## Decision

1. **Archive relays.** The long-lived source of a graph is a relay with `"block_ttl_ms": null`
   (ADR 0019), or a graph gateway with `"retention_ms": null` for reads (ADR 0041). An application that
   needs blocks to outlive relay TTLs SHOULD name at least one archive relay in its configuration, run
   by its operator or by another party it trusts for availability. Availability is a deployment
   property; the protocol does not guarantee it.
2. **No renewal.** A `PUT` of a block that the relay holds and that has not expired gets `200` and
   changes nothing: no new `received_at`, no new position (ADR 0013 rules 6 and 13, unchanged).
3. **An expired block is not held.** From the instant `received_at + block_ttl_ms ≤ now`, a relay MUST
   treat the block as not held for `PUT`, whether or not the sweeper has deleted its file or its index
   entries. A `PUT` of that block that passes validation MUST be processed as a new block: `201`, a new
   `received_at` and a new position, listed again by `/query`. The relay MAY keep the file it already
   holds instead of writing the received bytes: both carry the same `block_id` (core spec §3.4). Such a
   `PUT` MUST NOT get `507` because of the quota when the file is still held.
4. **Sweeper.** After a `PUT` under rule 3, the sweeper MUST NOT delete the block file, its cache entry
   or its new index entries; it removes only the entries of the expired position. A relay MUST order the
   sweeper's deletion of a block and a re-acceptance of that block so that a `201` is never followed by
   the deletion of that block before its new expiry, except by a crash, which rule 9 of ADR 0013 then
   repairs on the next `PUT`.
5. **Re-publication.** A client or super-peer that needs a block to stay available on a relay with a TTL
   keeps a validated copy and submits the same bytes again:
   - when a `GET` of the block gets `404` from that relay;
   - on a schedule: no earlier than its last `201` for that block from that relay plus that relay's
     `block_ttl_ms`. An earlier `PUT` is a no-op (rule 2). A `200` at that time means the relay's
     clock or `received_at` differs; the client retries later with backoff.
   It applies this to the blocks it authored and, when it needs them, to the blocks they depend on
   (container roots, key blocks, the parents it resolves through). It MUST NOT re-sign or alter a block.
   The number of blocks it keeps and re-submits per period is bounded by its own settings (core spec §4
   "Client bounds").
6. **Gap.** Between expiry and re-submission, a relay with a TTL neither lists nor guarantees the
   block. Clients read such blocks from an archive relay, a gateway or a peer. A client MUST handle a
   missing parent as pending (`l2-grammar.md` §4.1), not as an error.
7. **Pinning by third parties.** Anyone who holds the bytes of a block can re-submit it after each
   expiry: no key and no new proof of work is needed. This is not prevented. Its cost to a relay is at
   most one write per block per `block_ttl_ms`, under the rate limits and the quota; an operator who
   wants less of it lowers `block_ttl_ms` or the quota.

## Consequences

- **Relay (rule for `sbtp-relay`).** On `PUT`, a block whose stored position is expired at the relay's
  clock is handled as new: `201`, new position, `Location`. The sweeper checks, at the time it deletes,
  that the block has no unexpired position; deletion and re-acceptance of one `block_id` are serialised
  (for example both through the single index writer). Tests: a `PUT` after expiry and before the sweep
  gets `201` and is listed by `/query`; a sweep that runs after that `PUT` deletes no file; a `PUT`
  before expiry gets `200` and is not listed again; a full relay accepts the re-submission of an
  expired block whose file is still present.
- **Clients.** Re-publication needs no new API. A client records, per relay, the time of its last `201`
  for the blocks it keeps alive. `cli-demo` needs nothing; the web client and any super-peer implement
  rule 5 when they hold long-lived blocks.
- **Key blocks.** The rule of `l2-grammar.md` §5.5 "submit again before the shortest `block_ttl_ms`"
  was a no-op under rule 2. It now follows rule 5.
- **Indexers.** A re-accepted block appears again in `/query` and gateway feeds. They already
  deduplicate by `block_id` (core spec §4).
- **Compatibility.** Nothing is released. The relay change is behaviour on an edge case of
  ADR 0013 that it did not define.

## Spec change on acceptance

Core spec §4, `PUT /sbtp/v1/block`, responses:

> - `201 Created`: the block is valid and the relay did not hold it, or held it expired (see
>   `architecture.md` §2, "Eviction"); the relay stored it with a new reception time. …
> - `200 OK`: the block is valid and the relay holds it, not expired. The stored bytes are not replaced
>   and its lifetime is not extended (§3.4). …

`architecture.md` §2, "Eviction", first bullet replaced by:

> - A block expires when `received_at + block_ttl_ms ≤ now`. `block_ttl_ms` is a relay setting (default:
>   30 days), published by `/info`. Eviction does not depend on reads. A `PUT` of a held, unexpired block
>   does not extend its lifetime. From its expiry a block is not held for `PUT`: a `PUT` of it is a new
>   block (`201`, new `received_at`), even before the sweeper has deleted it, and the sweeper then deletes
>   nothing of it. (ADR 0043)

and one bullet added:

> - Long-lived blocks are kept available by archive relays and by clients that submit them again after
>   expiry; a `PUT` never renews a block before it expires. (ADR 0043)

`l2-grammar.md` §5.5, the re-submission bullet replaced by:

> - A client MUST submit its current key block again (the same bytes) to each relay with a TTL once it
>   has expired there (`architecture.md` §2, "Eviction"), or rotate at that interval. (ADR 0043)

## Rejected alternatives

- **Renewal on `PUT`** (a `200` resets `received_at`). It closes the gap of rule 6, but turns every
  replayed `PUT` into an index write and a new feed entry, which any client can trigger on any public
  block as often as the rate limit allows. It also does not stop pinning: it only removes the gap.
- **Lifetime that depends on unexpired children.** Anyone can mint a child of any block, so pinning
  gets cheaper, and expiry would need an index join per block, outside the sweeper's bounded work.
- **Keep `200` for an expired block until the sweep.** The current behaviour: the client is told the
  block is stored while `/query` hides it, and re-publication fails silently for up to one sweep
  period, or longer when the sweeper is behind.
- **A relay-level pin list set by the operator.** Possible as a local feature, but it is relay internals
  and needs no protocol rule; an archive relay serves the same need.
