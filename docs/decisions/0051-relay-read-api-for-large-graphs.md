# 0051: Relay read API for large graphs: batch fetch, parent ids, newest first, several parents

- Status: accepted (by the project owner, 2026-11-21), as proposed, with the owner choices recorded in
  "Decisions of the project owner": batch weight `⌈N/4⌉`; a `POST` batch route; `/info` `read_api: 2`;
  `fields=parents` refused with `parent` for now; gateway newest first by ingestion order. A
  non-normative section "Fast first catch-up" is added at acceptance; it adds no rule
- Amended by: 0052 (rule 2: a denied block is a `length = 0` record; such a record alone never triggers
  a re-submission); 0052 clarification L1, accepted 2026-11-21 (clarification B4: a page whose entries were all denied
  returns the cursor of the entries it read, not the gap it started from)
- Clarification B10, proposed (2026-11-21), raised by the first TypeScript client (ADR 0053
  clarification S15): a page with no identifier and `more = true` never returns the cursor it was
  asked from; a client MAY treat one that does as a relay fault
- Date: 2026-11-21
- Questions: Q-23 (requirements recorded, rule 30; not decided); Q-64 (partially resolved: omission,
  rules 36 to 38); opens Q-74, Q-75, Q-76 and Q-77
- Amends: ADR 0012 rules 5, 6, 9, 10 and 12 (new parameters, order, cursor as a gap,
  `head`, grouped response); ADR 0018 rule 21 (request weight in the `query` and `block` buckets);
  ADR 0029 rule 4 (one more body ceiling); ADR 0041 rules 11, 17 and 18 (gateway order, several
  targets, counts, per-node completeness); CORS of core spec §4 (`POST`). Nothing else in these ADRs
  changes
- Clarifications: B1 to B9 (2026-11-21, after implementation and security review): no declared
  length, rounding of `N`, time budget, empty `desc` page, failed records, minimum bursts (amends
  ADR 0018 rule 22 and ADR 0019 rule 4), metrics (amends ADR 0021 rule 41), hints and completeness
  over several relays, shared cache rule
- Depends on: ADR 0012 (`/query`), ADR 0013 (positions, index), ADR 0018 and 0027 (admission), ADR 0023
  (served bytes are validated), ADR 0024 (epochs), ADR 0029 (client bounds), ADR 0041 (gateway),
  ADR 0046 (demand), ADR 0048 (`Sbtp-Replication`)
- Impact: core spec §4 (`/query`, new `POST /sbtp/v1/blocks`, `/info`, CORS, admission control, client
  bounds); `graph-access.md` §3; `sbtp-relay` (`query.rs`, `index.rs`, `blocks.rs`, `server.rs`,
  `limiter.rs`); clients (`cli-demo`, `sbtp-wasm`, web client); new relay API vector set `relay-v1/`
  (planned, not frozen); no wire format change, no layer 0 vector

## Context

Two measurements by an application client against a relay built from current `main`:

- **A view** ("the 25 newest children of X, and their children", a 35-block graph): about 70 relay
  requests and 7.6 s. `/query?parent=` lists oldest first, so reaching the newest children means paging
  through all of them; one request lists one parent; nothing but paging to the end says a listing is
  complete. Serial round trips dominate, not relay CPU (informative VM figures: 19,000 to 23,000
  `/query` per second, p99 under 1 ms).
- **A cold start** (a 23,000-block graph): a per-parent walk took 22,824 `/query`. A relay-wide walk
  (no `parent`, with a cursor) took 23 `/query` but 22,807 `GET /block`; at the `small` `block` bucket
  (3,000 per minute) that is 7.6 minutes. On a relay shared by several applications the follower also
  fetches blocks it then discards.

A walk the client must bound is also a correctness problem: a block that changes what a reader should
see (a retraction, a moderation block) and is stored after the bound is never seen.

A warm follower, with its own index fed by a cursor, needs neither newest-first nor several parents.
Those mainly help clients without an index, and spot checks. The cold-start win comes from batch fetch
and parent ids. The rules below are in that priority order.

## Decision

### Batch fetch: `POST /sbtp/v1/blocks`

1. **Request.** `POST /sbtp/v1/blocks`, `Content-Type: application/octet-stream`, body = 1 to 256
   distinct `block_id` values, 32 raw bytes each, concatenated (at most 8,192 bytes). A body that is
   empty, not a multiple of 32 bytes or holds a duplicate gets `400` (`InvalidParameter`). A body over
   8,192 bytes gets `413` (`BodyTooLarge`) before it is read. `POST` is used because 256 identifiers in
   hexadecimal (17,408 bytes) do not fit `max_header_bytes` (16,384 by default, ADR 0018). The request
   changes nothing on the relay; it is safe to repeat.
2. **Response framing.** `200`, `Content-Type: application/octet-stream`, `Cache-Control: no-store`.
   The body is a sequence of records, one per requested identifier, in request order:
   `length (u32, big-endian) ‖ length bytes`. The bytes are the block exactly as stored. `length = 0`
   means the relay does not serve that block (not held, evicted, damaged: what `GET /block` would
   answer with `404`). No block is shorter than its header, so `0` is unambiguous. A `length` above
   65,909 makes the response a failed request.
3. **Prefix.** The relay MAY end the body after any complete record: at the byte ceiling (rule 4), at
   its time budget, or under load. The records then cover a prefix of the request; the client requests
   the rest again. A `200` holds at least one record.
4. **Ceiling.** The relay MUST NOT start a record that would bring the body above 1,048,576 bytes. The
   first record always fits (65,913 bytes at most). Clients apply 1,048,576 as the body ceiling of this
   route (ADR 0029).
5. **Served bytes.** Each record follows the rules of `GET /block` (ADR 0023): only bytes that pass full
   validation and R1 for the requested `block_id`; otherwise `length = 0`. A relay MUST NOT hold more
   than one block of a batch in memory beyond its HTTP send buffer: records are read and written one
   after the other, each as one job of the block reader threads, so a batch cannot hold readers longer
   than single requests would and the memory term of ADR 0018 rule 35 stays one block per connection.
6. **Recipient.** The client checks each non-empty record as a requested block (§3.4, R1 against the
   identifier at that position). A body that ends inside a record is a failed request; the complete
   records before it MAY be used, since each is checked on its own.
7. **Weight.** The request takes `⌈N / 4⌉` tokens of the `block` bucket, `N` being `Content-Length / 32`
   (64 tokens when `Content-Length` is absent), capped at `rate_block_burst`, at admission and before
   the body is read (ADR 0018 rule 21). Records not sent because of rule 3 are not refunded.
8. **Demand.** Each record served with a block counts as a demand of that block, at most once per
   epoch (ADR 0046 rules 10 and 11). A record with `length = 0` is not demand.
9. **Replication.** A request with `Sbtp-Replication: 1` counts no demand (ADR 0048); its response
   already carries `Cache-Control: no-store` and MUST also carry `CDN-Cache-Control: no-store`. A
   replicating relay MAY fetch by batch.
10. **No conditional form.** A client does not request a block it holds; `If-None-Match` does not
    apply. A relay ignores it on this route.
11. **CORS.** A preflight from an allowed origin gets `Access-Control-Allow-Methods: GET, PUT, POST`.
12. **Single or batch.** `GET /block/{id}` stays the cacheable form: a shared cache or CDN serves a
    popular block without reaching the relay, and the client's bucket is not charged. A batch always
    reaches the relay. A client SHOULD use single `GET`s, over HTTP/2 when available, for the blocks of
    a view that other readers also fetch, and SHOULD use batches for walks, cold starts, back-fills and
    any fetch of more than about 32 blocks. A `read_only` URL (ADR 0050) has no batch route.

### Parent ids and lengths in `/query`

13. **`fields=parents`.** Optional `/query` parameter, single value `parents`. The response then
    carries, beside `block_ids` and aligned with it, `parents` (for each block, its Parents Hashes in
    header order, 0 to 8 `block_id` strings) and `lens` (each block's length in bytes). Both are header
    data the relay already indexes: the relay stays payload-blind. A client uses them to skip blocks
    it does not need and to pack batches under the ceiling of rule 4. They are hints: a block's own
    header is authoritative once fetched (§3.4).
14. **Bounds.** With `fields=parents` the page size is `min(limit, max_query_limit, 200)`. Worst case
    per entry: 67 bytes of identifier, 538 of parents, 6 of length; 200 entries are 122,200 bytes, under
    the 131,072-byte ceiling of `/query` (ADR 0029), which does not change. `fields` MUST NOT be
    combined with `parent` (`400` `InvalidParameter`): the parent index holds child identifiers only, so
    the extra members would need one more lookup per entry and break the `O(log n + limit)` bound.
    Without `parent` the members come from the same index row. (Q-75)

### Order: newest first

15. **`order`.** Optional, `asc` (default) or `desc`. Any other value gets `400` (`InvalidParameter`).
    `desc` lists matching blocks newest first in the relay's store order (`received_at`, then position).
16. **Cursor as a gap.** A cursor names a gap between two positions of the store order. With `asc` a
    page holds matching blocks after the gap; with `desc`, before it. Every cursor is valid in both
    orders, with any `parent`, `since` and `fields`. An `asc` page returns the gap after its last
    entry (as today); a `desc` page returns the gap before its last (oldest) entry. A `desc` request
    without a cursor starts at the newest position. The encoding of existing cursors does not change.
17. **`since` and expiry.** With `desc`, `since` and the relay's expiry bound (ADR 0013 rule 14) are
    the lower end of the walk: the walk ends with `more = false` there.
18. **`head`.** Every `/query` response carries `head`, a cursor for the gap after the newest position
    the index held when the response was built (any parent). An `asc` request from `head` returns
    exactly the matching blocks stored after the response was built. `head` discloses the time of the
    relay's latest acceptance; a walk with no `parent` already discloses it.
19. **Guarantees, per relay.** A `desc` walk returns every matching block stored before its first
    response's `head` and still held when its page is built. A block stored during the walk, or evicted
    and stored again (new position, ADR 0046 rule 22), is after that `head` and appears in an `asc`
    poll from it. Eviction removes positions and invalidates no cursor (ADR 0024).
20. **Cost.** `O(log n + limit)` in both orders (ordered range read, forward or backward, plus one
    read of the last position for `head`).

### Several parents per request

21. **Parameter.** `parent` MAY appear 1 to 32 times, with distinct identifiers; a 33rd or a repeated
    identifier gets `400` (`InvalidParameter`). When it appears two or more times, each value is
    `<block_id>` or `<block_id>.<cursor>` (a per-parent cursor; `.` is outside the cursor alphabet and
    needs no percent-encoding). A per-parent cursor overrides `cursor` for that parent; `cursor`
    applies to the others. With a single `parent` the `.<cursor>` form is malformed.
22. **Why 32.** It covers a page of 25 to 30 items plus its root in one request. The request line stays
    within `max_header_bytes`: 32 × (`parent=` 7 + 64 + 1 + 128 + `&` 1) = 6,432 bytes at the longest cursors. The
    response stays within the `/query` ceiling (rule 24). The index work is 32 range reads plus at most
    1,000 entries.
23. **Per-parent limit.** `limit` applies to each parent, lowered to `max(1, ⌊max_query_limit / N⌋)`
    for `N` parents. The total is at most `max(N, max_query_limit)` ≤ 1,000 entries.
24. **Grouped response.** With two or more `parent`:

    ```json
    {
      "parents": [
        {"parent": "9e02…", "block_ids": ["77ab…"], "cursor": "…", "more": false},
        {"parent": "4c1f…", "block_ids": [], "cursor": "…", "more": false}
      ],
      "head": "…"
    }
    ```

    One entry per requested parent, in request order, each with the members and meaning of a
    single-parent response. Worst case: 32 × 246 bytes of envelope (128-character cursors), 1,000 × 67
    bytes of identifiers and 152 bytes outside the list, 75,024 bytes in all, under 131,072. With one
    `parent`, or none, the response keeps its current shape, plus `head`.
25. **One job.** A grouped request is one index read transaction and one job of the reader threads.
26. **Weight.** A `/query` request takes `⌈N / 8⌉` tokens of the `query` bucket (`N` the number of
    `parent` values, 1 when absent), capped at `rate_query_burst`, at admission. The relay counts the
    `parent=` pairs of the raw query string, bounded by the request line.
27. **Cursors are not bound to a parent.** A cursor is a position (ADR 0012 rule 9); using the cursor
    of one parent for another starts that listing at the same gap, as `since` would. It grants nothing.
    One unrecognised cursor makes the whole request `400` (`InvalidCursor`): an epoch change
    invalidates every cursor at once (ADR 0024).

### Completeness

28. **Complete listing.** A listing of one parent is complete when its `more` is `false`: it holds
    every matching block the relay held, not expired, between the cursor sent (or the start of the
    order) and the end of the walk in its direction, when the page was built. Together with `head` the
    client knows the relay's children of that parent up to `head`.
29. **Absence.** A client that derives state from the absence of a block (no retraction, no moderation
    block, no newer version) MUST derive it only from complete listings, and MUST NOT present a listing
    that ended with `more = true` as complete. To stay complete cheaply it keeps `head` and, on each
    view, polls the shown parents `asc` from it in one grouped request (32 parents per request). It
    lists `desc` again when it has no `head` (new session, `InvalidCursor`). A parent with more children
    than the client's walk bound stays incomplete on that relay; a gateway that indexes by verb
    (rule 33) is the way to read it.

### Subscription by parent set (requirement for Q-23)

30. The WebSocket ADR (Q-23) MUST offer a subscription to new children of a parent set: at most 32
    parents per subscription, identifiers only (optionally with rule 13's members), starting from a
    cursor such as `head`, delivered in store order with the parent of each identifier; after a
    disconnect the client resumes with `/query` `asc` from its last delivered gap, with no hole. A
    subscription is admitted with the weight of rule 26, and the number per connection is bounded. This
    ADR specifies no transport.

### Discovery

31. **`/info` `read_api`.** Integer. A relay that implements every rule of this ADR publishes `2`; an
    absent member reads as `1`. A client MUST NOT send `POST /blocks`, `fields`, `order`, a repeated
    `parent` or a per-parent cursor to a relay without `read_api ≥ 2`. The bounds (256 identifiers,
    1 MiB, 32 parents, 200 entries with `fields`) are fixed by the protocol, not relay settings.

### Graph gateway (amends ADR 0041)

32. **Order (rule 11).** Gateway lists are in ingestion order; `order=desc` lists newest ingested first
    on `/children` and `/feed`, with cursors as gaps (rule 16). The `Timestamp` field is chosen by the
    author and is not an order the gateway offers.
33. **Children (rule 17).** `/children/{target}` gains `order` and a member `count`: the number of
    entries for `(target, rel)` the gateway holds, from a counter kept at ingestion (`O(1)`). A form
    with several targets, `GET /sbtp-graph/v1/children?target=<t>[.<cursor>]&…` (1 to 32 targets),
    returns the grouped shape of rule 24 with `children` in place of `block_ids` and `count` per entry.
    Limit per target as in rule 23 with `max_limit`; body ceiling unchanged (262,144 bytes).
34. **Subgraph (rule 18).** `order` (default `desc`) chooses which children `dir=in` follows under
    `max_children_per_node`. The response gains `incomplete`: the nodes whose children were cut by that
    cap. `truncated` keeps its meaning. A client completes an `incomplete` node with `/children`.
35. **Federation.** Several gateways MAY read the same relays. A client MAY use one, or merge several:
    it takes the union of their listings, deduplicates by `block_id`, verifies every block (§3.4) and
    keeps one cursor per gateway. Counts are claims of one gateway; a client does not add them.
36. **Omission.** A gateway cannot forge a block, but it can omit one. No cheap standard construction
    proves to a client that a gateway's listing is complete. A signature by the gateway proves only
    what it claimed. A commitment is checkable only against a party that commits to the same set, and
    relays hold different sets (eviction, replication delay), so a mismatch would be the normal case,
    not evidence. A per-parent count or fingerprint published by relays would add up to 8 index writes
    per accepted block and still not converge between relays; it is not adopted. The honest answer is
    cross-checking against a second source.
37. **Spot-check rule.** A client that derives state from absence (rule 29) from gateway data SHOULD,
    on each view, list the shown targets on one relay it chose independently of the gateway, `desc`,
    grouped, with a small per-parent limit (for example 8): one request per 32 targets. A block the
    relay lists and the gateway still omits on a repeated request after a delay (its ingestion lag) is
    an omission. The client then stops using that gateway for absence-derived state, falls back to
    relays, and MAY report the evidence (the two responses and the block). This catches recent
    omissions; an old one is found only by a full walk, which a client MAY run in the background at a
    low rate.
38. **Later.** If relays expose range fingerprints for set reconciliation (Q-11, Negentropy-style), a
    fingerprint over the children of a parent becomes available at no extra write cost, and rule 36 is
    revisited. Signed gateway answers, for accountability, stay with Q-64.

## Consequences

### Expected request counts

- **The view (35 blocks).** Today about 70 requests. With this ADR: `desc` on X (1), then a grouped
  query for its 25 children and a batch of those 25 blocks in parallel (2), then a batch of the
  grandchildren (1): **4 requests in 3 serial round trips**, plus 1 grouped follow-up if a child has
  more than 40 children. Tokens: 5 `query`, about 10 `block`. With single `GET`s over HTTP/2 through a
  CDN instead of batches: 2 to 3 `/query` plus 35 `GET`, about 7 round trips at 8 in flight, but CDN
  hits reach no relay and cost no token. A refresh: 1 grouped `asc` poll from `head` (26 parents) and
  at most 1 batch.
- **The cold start (22,807 blocks, `small` profile).** Walk with `fields=parents`: 115 `/query`
  pages, about 19 s at 300 per minute after a burst of 20. Fetch: 90 batches, `⌈N/4⌉` → 5,702 tokens,
  `(5,702 − 200) / 3,000` ≈ **1.8 minutes**, against 7.6 minutes today; the two run in parallel. With
  `⌈N/2⌉` it would be 3.7 minutes. Blocks skipped thanks to `parents` lower it proportionally. On the
  `standard` profile (12,000 per minute, burst 600) about 26 s. An operator that serves followers raises the
  bucket or lists them in `rate_limit_exempt`.

### Weights (rules 7 and 26)

- **Batch, per block.** A single `GET` on a cache miss costs about 100 µs of relay CPU: about 45 µs of
  per-request work (HTTP, admission, response; the `/query` figure of 19,000 to 23,000 per second) and
  about 55 µs of file read and Ed25519 check (ADR 0023). In a batch the per-request part is shared:
  about 55 µs per block on a miss, a few µs on a cache hit. Cost-neutral would be `⌈N/2⌉`. `⌈N/4⌉`
  gives one client key at most 12,000 block reads per minute on `small`, about 200 per second, or 1 %
  of one core: the bucket is a per-client allowance, not the CPU guard. Bandwidth per token stays
  under the single `GET` worst case: 1 MiB / 64 tokens = 16 KiB, against 65,909 bytes. The divisor
  is checked by measurement (Q-74).
- **Grouped query.** Per-request work dominates a range read; one grouped request replaces up to 32
  requests and their round trips with one reader job. `⌈N/8⌉` charges 4 tokens at 32 parents; a page
  view costs 5 `query` tokens instead of 26. Checked by measurement (Q-74).

### Implementation

Two stages, `sbtp-relay` (relay-engineer), `read_api: 2` published only when both are done.

1. **Cold start (first).** `POST /sbtp/v1/blocks`: body parse, weight at admission from
   `Content-Length`, streamed body over block reader jobs, demand recording, `Sbtp-Replication`,
   CORS `POST`; `fields=parents` from the `blocks` row (it already holds length and parents).
   About 2 to 2.5 days with tests.
2. **Index-less clients.** `order=desc` (redb `Range` is double-ended in 4.6.0: `.rev()` on the
   existing ranges of `query`), `head` (last key of `blocks`), grouped requests (`parent` parser,
   per-parent cursors, one read transaction, grouped body writer, weight). About 2 days.
3. Clients (wasm-engineer): web client and `cli-demo` use batches and `fields`, then `desc`, grouped
   polls and `head`. About 2 days.
4. `graph-access.md` §3 (rules 32 to 37); `sbtp-gateway` is not built yet and starts from the amended
   rules.

### Security review (security-auditor)

- Amplification: worst-case relay work and bytes per token for a batch (256 identifiers, 1 MiB, rule
  3 prefix, slow reader holding a connection within `request_timeout_ms`) and for a grouped query (32
  range reads); weight computed before the body is read, absent `Content-Length`, chunked bodies.
- Memory: one block per batch in flight (rule 5); the rule 35 bound unchanged.
- Parsing: the `<block_id>.<cursor>` form, duplicates, a 33rd `parent`, `fields` with `parent`,
  binary request body; record framing on the client (length above 65,909, truncated record).
- Cursors: a cursor used across parents or orders grants nothing (rule 27); forged cursors within the
  current epoch are equivalent to `since`; `head` disclosure.
- Demand: a batch cannot count more than one demand per block per epoch; replication requests count
  none.
- `fields=parents` from a hostile relay can only make a client skip a block, which omitting it from
  the listing already allows.

### Compatibility

Nothing is released. Old relays answer `400` to the new parameters and `404` or `405` to the new
route; clients read `read_api` first (rule 31). Existing cursors and single-parent responses keep
their encoding and shape; `head` is an added member, which clients already ignore when unknown.

## Decisions of the project owner (2026-11-21)

1. **Accepted as proposed.**
2. **Batch weight `⌈N / 4⌉`** `block` tokens (rule 7), not the cost-neutral `⌈N / 2⌉`. The divisor is
   checked by measurement before a public relay publishes `read_api: 2` (Q-74).
3. **Batch route `POST /sbtp/v1/blocks`** with a raw binary body (rule 1), not a `GET` with identifiers
   in the query string.
4. **Discovery by `/info` `read_api: 2`** (rule 31).
5. **`fields=parents` is refused with `parent`** for now (rule 14); revisited if a client needs it
   (Q-75).
6. **Gateway lists newest first by ingestion order** (rule 32), never by the `Timestamp` field.
7. **Fast first catch-up.** A cold start of 1.8 minutes on `small` is too long for a first start. The
   section below records how a client starts from a snapshot and a bucket mirror (ADR 0050) with the
   rules already in force. It is non-normative and adds no rule. One point would need a rule and is
   left to the owner (Q-76); a shared snapshot format is Q-77.

## Fast first catch-up (non-normative)

Nothing in this section is a new rule. It combines ADR 0050 (bucket mirror), this ADR (`head`, `asc`
from a cursor, batches) and core spec §3.4 and §4.

**Sources, by role.**

- **Snapshot.** A set of validated blocks, cut from one relay `R` by a producer that walked `R` to
  `more = false`, with a resume point: the relay URL of `R`, the `head` of its last response, and the
  `Date` header of that response (the relay's clock). A snapshot is not a protocol object: its format,
  host and refresh are the producer's (a common format is Q-77). One static object behind a CDN is one cacheable `GET`, with no
  relay rate limit. It is not placed under `/sbtp/v1/`, whose layout is fixed (ADR 0050 rule 1).
- **Bucket mirror** (ADR 0050). A read-only relay URL served through a CDN: single `GET /block`, each
  object `public, max-age=31536000, immutable`, so a CDN serves popular blocks from its edge and the
  origin relay sees no request and charges no token. It has no `/query`: identifiers come from a relay
  or from the snapshot. It lags the writer by its uploader.
- **Relay batch route** (rules 1 to 12). For gaps (identifiers the bucket did not serve) and for recent
  blocks, which the bucket may not hold yet.
- **Relay `/query`.** Identifiers only. Resuming from the snapshot's `head` lists exactly the blocks `R`
  stored after the cut (rule 18): nothing is walked twice.

Every block, from every source, the snapshot included, goes through the receipt rule (§3.4: full
validation and R1 against the requested or listed `block_id`). A snapshot is an untrusted source like a
relay; the client bounds of core spec §4 apply to it.

**Order for a client.**

1. Load the snapshot (bundled with the program or one `GET`); validate each block as it arrives, in a
   background worker; store within the storage budget. Show the current view from it.
2. Read `/info` of the relays in the list (`read_api`, `read_only`).
3. Resume on `R`: `/query` with no `parent`, `asc`, from the snapshot's `head`, to `more = false`; keep
   the last `head`. On another relay, or after `InvalidCursor` on `R` (ADR 0024), use `since` = the
   snapshot's `Date` minus a margin (the relay's clock on `R`; on another relay the margin also covers
   its replication delay) and deduplicate by `block_id`; only the margin is walked again.
   `fields=parents` is used when the client skips blocks it does not need; without it a page holds up to
   1,000 identifiers.
4. Fetch the blocks of the current view first: single `GET`s, which shared caches serve (rule 12).
5. Fetch the rest of the delta. A delta of a few batches goes to the relay batch route directly. A
   larger one goes first to the bucket by single `GET`; the identifiers it does not serve (any status
   other than `200` or `304`, ADR 0050 rule 5) go to the relay batch route.
6. Stay current with a grouped `asc` poll from `head` for the shown parents (rule 29) and a batch for
   what it lists.

**Completeness.** The producer's walk of `R` to `more = false` is a complete listing of what `R` held
at the cut; the `asc` walk from `head` to `more = false` extends it to the new `head` (rules 28 and 29).
State derived from absence is therefore as complete as a full walk of `R`, without the walk. Blocks
that `R` did not hold are found as on any relay: on another relay of the list.

**Cold-start estimate.** For the 22,807-block graph of the context, with an assumed average block of
1.5 KiB (about 35 MB; not measured):

| Path | Bound by | Estimate |
|---|---|---|
| Today: per-block `GET`, `small` `block` bucket | relay rate limit | 7.6 min |
| This ADR: `/query` with `fields` and relay batches, `small` | relay rate limit | 1.8 min |
| Bucket through a CDN, no snapshot, at most 8 requests in flight, 30 ms round trip | latency | about 85 s |
| Snapshot, one `GET` through a CDN, then a small delta | bandwidth | 35 MB / link rate + delta |

With a snapshot, the start is bandwidth-bound: about 28 s at 10 Mbit/s, 6 s at 50 Mbit/s, 3 s at
100 Mbit/s. Validation runs in parallel with the download: about 100 µs per block in a browser (an
estimate: BLAKE3, PoW check and one Ed25519 verification in WebAssembly), about 2.3 s on one core for
the whole graph. The delta after a recent snapshot costs a few seconds: for 2,000 blocks, 2 `/query`
pages and 8 batches (500 `block` tokens, about 6 s on `small` after the burst of 200), or the same
blocks from the bucket at 8 in flight in about 7.5 s. The delta grows with the age of the snapshot, so
a producer refreshes it on a schedule that keeps the delta to a few batches.

**The point that would need a rule (Q-76).** Without a snapshot, the bucket path is latency-bound
because a client SHOULD keep at most 8 requests in flight per relay (core spec §4, "Admission
control"), and a bucket URL is a relay URL in a relay list (ADR 0050 rule 4). That bound protects a
relay's per-client in-flight allowance (ADR 0019); a static bucket behind a CDN has none. With 64
streams over HTTP/2 the same fetch would take about 11 s and be bandwidth-bound on links under about
25 Mbit/s. Exempting `read_only` URLs from the 8-request bound is a change of core spec §4 and is not
made here. The recommended order (snapshot first) does not depend on it.

## Spec change on acceptance

Applied on acceptance (2026-11-21). In `graph-access.md` the gateway order rule is in §3.2 (not §3.1);
the several-target form of `/children` became §3.9, before the new §3.10. The `/query` text also notes
that `parent` is exempt from the "repeated parameter" rule and that the client check of `limit` holds
per parent in a grouped response. Core spec §4 also gains the non-normative subsection "Fast first
catch-up".

Core spec §4:

1. **New subsection after `GET /sbtp/v1/block/{block_id}`:**

   > ### `POST /sbtp/v1/blocks`
   >
   > - Batch read. Body: 1 to 256 distinct `block_id` values, 32 raw bytes each, concatenated,
   >   `Content-Type: application/octet-stream`. An empty body, a length that is not a multiple of 32
   >   or a duplicate gets `400` (`InvalidParameter`); a body over 8,192 bytes gets `413`
   >   (`BodyTooLarge`) before it is read. The request changes nothing and is safe to repeat.
   > - Response: `200`, `application/octet-stream`, `Cache-Control: no-store`. One record per
   >   requested identifier, in request order: `length` (u32, big-endian) then `length` bytes of the
   >   block. `length = 0`: the block is not served. The relay serves only bytes it would serve with
   >   `GET /block` and MAY end the body after any complete record (at least one); the client requests
   >   the rest again. A relay MUST NOT start a record that brings the body above 1,048,576 bytes.
   > - The recipient checks each record as a requested block (§3.4, R1 against the identifier at that
   >   position). A `length` above 65,909 makes the response a failed request. A body that ends inside
   >   a record is a failed request; the complete records before it MAY be used.
   > - Each served block counts as demand once per epoch, except with `Sbtp-Replication: 1`, which also
   >   gets `CDN-Cache-Control: no-store`. `If-None-Match` does not apply.
   > - `GET /block` is the cacheable form. A client SHOULD use it for the blocks of a view and SHOULD
   >   use batches for walks and bulk fetches. (ADR 0051)

2. **`/query` title** becomes `GET /sbtp/v1/query?parent=&since=&limit=&cursor=&order=&fields=`, and
   the parameter list gains:

   > - `parent` MAY be repeated, 1 to 32 distinct values; then each value is `<block_id>` or
   >   `<block_id>.<cursor>`, a per-parent cursor that overrides `cursor`. `limit` applies per parent,
   >   lowered to `max(1, ⌊max_query_limit / N⌋)` for `N` parents.
   > - `order`: `asc` (default) or `desc` (newest first).
   > - `fields`: `parents`. Adds `parents` and `lens` aligned with `block_ids`; the page is at most 200
   >   entries. Not allowed with `parent`.

   "Order" becomes:

   > - Order: the relay's store order, oldest first with `asc`, newest first with `desc`. A cursor
   >   names a gap in that order and is valid in both orders: `asc` returns blocks after it, `desc`
   >   before it. `since` and the expiry bound end a `desc` walk. A client MUST NOT derive application
   >   state from the order.

   The response gains:

   > - `head`: always present, a cursor for the gap after the newest position held when the response
   >   was built. `asc` from `head` returns exactly the matching blocks stored since.
   > - With two or more `parent`, the body is `{ "parents": [ {"parent", "block_ids", "cursor",
   >   "more"} … ], "head" }`, one entry per requested parent in request order.
   > - A listing is complete when its `more` is `false`. A client that derives state from the absence
   >   of a block MUST use only complete listings, and keeps `head` to poll the shown parents.

3. **`/info`** gains `read_api` (rule 31). **CORS**: methods `GET, PUT, POST`. **Admission control**:
   "A `/query` request takes `⌈N/8⌉` tokens of its bucket (`N` parents, 1 when absent) and a batch
   `⌈N/4⌉` (`N` identifiers), capped at the burst." **Client bounds**: ceiling of `POST /blocks`
   1,048,576 bytes.
4. **WebSocket**: one sentence: "The WebSocket ADR (Q-23) offers a subscription by parent set (ADR
   0051 rule 30)."

`graph-access.md` §3.1 (order), §3.6 (`order`, `count`, several targets), §3.7 (`order`, `incomplete`),
and a new §3.10 "Several gateways and omission" (rules 35 to 38). ADR 0041 gets "Amended by: 0051
(rules 11, 17, 18)" under its status; ADRs 0012, 0018 and 0029 get the same line.

## Test vectors (plan, not frozen)

A new set `docs/test-vectors/relay-v1/`, generated by an `sbtp-relay` test helper from blocks signed
with the public seeds of `v1/`. Cursors are opaque and relay-specific, so vectors never contain a
cursor value: scenarios reference "the cursor of response k, parent j" symbolically.

- `query-params.json`: query strings → accepted or `InvalidParameter`: `order` values, `fields` values,
  `fields` with `parent`, 32 and 33 `parent`, a repeated identifier, `<id>.<cursor>` with one and two
  parents, an empty or 129-character per-parent cursor, `.` in `cursor=`.
- `query-scenarios/`: a fixture store (blocks inserted in a fixed order with given parents), then a
  sequence of requests and expected `block_ids`, `more` and `parents`/`lens` per response:
  `asc` and `desc` walks of one parent at `limit` 1, 2 and 3; a switch of order on the same cursor;
  `desc` with `since`; `asc` from `head` after inserts; grouped requests with per-parent and shared
  cursors and the lowered per-parent limit; an expired lower bound.
- `blocks-batch/`: request bodies → status, and fixture → expected records (lengths, held and missing
  identifiers, request order); a body of 33 bytes, 0 bytes, a duplicate; the prefix rule is checked by
  structure only (a response that is a prefix of the full answer).
- `weights.json`: `N` → tokens for both buckets.

They are frozen only after this ADR is accepted, implemented and reviewed.

## Rejected alternatives

- **`GET /blocks?id=…`.** 256 identifiers do not fit `max_header_bytes`; a 128-identifier `GET` would
  be cacheable only for that exact list, which a CDN rarely sees twice.
- **Multipart response.** A boundary parser on untrusted input and a larger framing overhead; length
  prefixes are simpler and match the binary block format.
- **Blocks inline in `/query`.** Mixes JSON and binary and breaks the `/query` ceiling.
- **One combined cursor for several parents.** It forces one merged walk: a parent with many children
  starves the others, and no listing is complete until the whole union is. 32 positions do not fit 128
  characters.
- **Weight `N` for grouped queries.** 26 tokens for a page view exceeds the default burst of 20; the
  grouped form would be unusable.
- **`fields` with `parent`.** An extra lookup per entry; revisit with measurements (Q-75).
- **Order by the `Timestamp` field.** Chosen by authors, so a block could be placed at the top at
  will; store order is the relay's own.
- **Signed gateway checkpoints, relay per-parent counts or fingerprints.** See rule 36.

## Clarifications (2026-11-21)

Arising from the implementation and its security review (`docs/security/2026-11-21-read-api-0051.md`).
B1 to B5 state normatively what the reference relay does where the rules above left a choice. B6 is a
rule recommended by the project owner after review finding L-1. B7 lists the metrics. B8 is a client
rule from review findings M-1 and L-2. B9 is a deployment rule. They are applied to core spec §4.

- **B1. No declared length (rules 1 and 7).** A `POST /sbtp/v1/blocks` request without
  `Content-Length`, or with any `Transfer-Encoding` (with or without `Content-Length`), is charged 64
  `block` tokens at admission (rule 7, capped at the burst). If admitted, it gets `400`
  (`InvalidParameter`) with `Connection: close`, and the relay closes the connection before it reads
  any byte of the body. A `Content-Length` that is not a decimal integer is treated as absent.
- **B2. Rounding of `N` (rule 7).** `N` is `⌈Content-Length / 32⌉`, and the weight `⌈N / 4⌉` is at
  least 1 token. A body that is empty or not a multiple of 32 bytes is therefore charged before its
  `400`: no refusal of this route is free. A `Content-Length` above 8,192 is charged the burst
  (saturating arithmetic) and gets `413` before the body is read.
- **B3. Time budget (rule 3).** The time budget of a batch is half of the relay's request time limit
  (`request_timeout_ms` for `sbtp-relay`, ADR 0018 rule 22), counted from the start of the request. A
  relay MUST NOT start a record once the budget is spent; the body then ends after the last complete
  record. The other half leaves time to write that record before the request deadline (ADR 0018
  rule 25).
- **B4. Empty `desc` page (rule 16).** A `desc` page with no entry returns as its `cursor` the gap it
  started from: the cursor sent (per-parent or shared), or `head` when the request had no cursor for
  that listing. The cursor of an empty page is never absent and never moves the walk: an `asc`
  request from it lists the matching blocks after that gap (rule 16). A page that read entries and
  had all of them removed by a deny list is not an empty page in this sense: it returns the cursor of
  the entries it read (ADR 0052 clarification L1, accepted 2026-11-21).
- **B5. Failed records (rules 2, 3 and 5).** The first record decides the status: when it cannot be
  read, the relay answers as `GET /block` would (`503` when its block readers are busy, `500` on an
  I/O error), with no batch body. A later record that cannot be read (I/O error, read refused under
  load) ends the body before that record, as a prefix of rule 3; the client requests the rest again.
  `length = 0` means only that the relay does not serve that block (rule 2). A relay MUST NOT use
  `length = 0` for an error.
- **B6. Minimum bursts (rules 7 and 26; owner recommendation after review L-1).** The weights are
  capped at the burst so that a request is always admissible from a full bucket. A burst below the
  largest weight would sell more than the intended ratio: with a `block` burst `b < 64`, a 256-id
  batch costs `b` tokens. A relay MUST refuse at start-up a `block` bucket burst below 64 and a
  `query` bucket burst below 4 (`rate_block_burst` and `rate_query_burst` for `sbtp-relay`; ADR 0018
  rule 22 and ADR 0019 rule 4: the ranges become 64 to 1,000,000 and 4 to 1,000,000). A batch then
  buys at most 4 blocks per token, and a grouped query at most 8 parents per token. Every profile of
  ADR 0019 rule 37 is above both minimums; no default changes.
- **B7. Metrics (ADR 0021 rule 41).** The set of rule 41 gains, with the prefix `sbtp_relay_`:

  | Name | Kind | Labels |
  |---|---|---|
  | `batch_requests_total` | counter | none; batches answered `200` |
  | `batch_records_total` | counter | `result` (`served`, `missing`) |
  | `batch_cut_total` | counter | `reason` (`ceiling`, `budget`, `busy`, `failed`): bodies ended before the last requested record, by cause (rule 4, B3, B5) |

  The `route` label of `http_requests_total` gains the value `/sbtp/v1/blocks`. The labels come from
  fixed sets (ADR 0021 rule 39).
- **B8. Several relays (rules 13, 28 and 29; review M-1 and L-2).**
  - A client that merges `fields=parents` hints from several relays MUST take, for each `block_id`,
    the union of the parents the relays list. A hint can only add a fetch; the fetched header decides
    what the block is (rule 13, §3.4). With a first-wins merge, one relay could hide a block that
    another relay lists with its true parents.
  - A listing over several relays is complete only when every relay of the client's list was asked
    and returned a complete listing (rule 28). A relay skipped because it does not publish
    `read_api` ≥ 2, and was not asked with the single-parent form instead, counts as not asked: the
    listing is not complete (rule 29). A client MAY instead present completeness per relay.
- **B9. Shared caches (rule 12).** A batch response carries `Cache-Control: no-store` and MUST NOT be
  stored by a shared cache. An operator rule that caches blocks at a CDN or reverse proxy MUST match
  the path prefix `/sbtp/v1/block/` with its trailing slash (and `GET`), never `/sbtp/v1/block*`,
  which would also match `/sbtp/v1/blocks`.

Spec change (applied with these clarifications): core spec §4, `POST /sbtp/v1/blocks` (B1, B2, B3, B5,
B9), `/query` (B4, B8), "Admission control" (B2, B6). ADR 0019 and ADR 0021 get an "Amended by" entry;
the ADR 0018 entry for 0051 gains rule 22.

## Clarification B10 (2026-11-21, proposed)

Raised by the first TypeScript client (ADR 0053 clarification S15). It strengthens the wording "so
that a walk always advances" of ADR 0052 clarification L1 and fixes the client's reaction.

- **B10. A walk advances (rules 16 and 28, B4, ADR 0052 L1).** A relay MUST NOT answer a request
  that carried cursor `C` for a listing (the shared `cursor`, or a per-parent cursor) with a page of
  that listing that holds no identifier, has `more = true` and returns `C` as its `cursor`. B4 and
  ADR 0052 L1 already give every page a cursor that moves the walk: an empty page that read no entry
  returns its starting gap only with nothing left in its direction, and a page whose entries were all
  removed returns the cursor of the entries it read. A client that receives such a page MAY treat it
  as a relay fault: it ends the walk on that relay as incomplete, keeps `C`, counts the page as a
  failed request of ADR 0029 rule 16, and MAY continue later from `C` as a poll. It MUST NOT present
  that listing as complete (rule 29).

  *Reason:* without B10, a client cannot tell a relay that stalls a walk (by fault or on purpose)
  from one that makes progress through denied or expired entries, and a walk bounded only by pages
  could spend its whole bound on one cursor.

Spec change on acceptance: core spec §4, `GET /sbtp/v1/query`, after the bullet that ends "so that a
walk always advances. (ADR 0052, clarification L1)":

> - A relay MUST NOT answer a request that carried a cursor for a listing with a page of that listing
>   that holds no identifier, has `more = true` and returns the same cursor. A client MAY treat such a
>   page as a fault of that relay: the listing ends incomplete there. (ADR 0051, clarification B10)

Relay conformance: `sbtp-relay` is to be checked against B10 (`relay-v1/` gains a case where a run of
denied entries longer than `limit` is walked in both orders); `client-v1/` gains a case where a
scripted relay returns the same cursor with `more = true` and no identifier.
