# 0046: Relays keep by default; eviction under disk pressure by least recent demand

- Status: proposed
- Date: 2026-11-20
- Revised: 2026-11-20, owner review: demand hidden by shared caches is recovered, not accepted
  (rules 7, 12 to 17, 24 to 28)
- Questions: none open; owner direction of 2026-11-20 (relays keep what they receive; a relay with
  little disk drops what is not, or no longer, requested). Chunks wait on Q-21
- Amends:
  - ADR 0013 rule 12 (default of `block_ttl_ms`; "Eviction does not depend on reads"), rule 16 (what an
    archive relay is) and rule 21 ("MUST NOT evict unexpired blocks to make room");
  - ADR 0023 rule 13 (`Cache-Control` of a block response when demand eviction is on);
  - ADR 0019 rule 4 (default of `block_ttl_ms`), rule 37 (one profile row) and rule 38 (policy
    settings);
  - ADR 0018 rule 35 (one more term in the memory bound);
  - ADR 0021 rule 41 (counters and gauges);
  - ADR 0043 rule 1 (definition of an archive relay; the default `block_ttl_ms` is no longer 30 days).
  Nothing else in these ADRs changes
- Depends on: ADR 0013 rules 8, 13, 14, 15 and 18; ADR 0024 (cursors); ADR 0043 rules 3 to 5;
  ADR 0044 (client address behind a CDN)
- Impact: core spec §4 (`GET /block`, `/info`); `architecture.md` §2 ("Eviction", "Quota");
  `sbtp-relay` (settings, index tables, read path, response headers, sweeper, metrics);
  `deploy/README.md` (CDN cache rule); no wire format change, no test vector

## Context

Today a relay evicts every block 30 days after it accepted it, whether or not anyone reads it, and a full
relay answers `507` and never makes room (ADR 0013 rules 12 and 21). ADR 0043 then relies on archive
relays and re-publication to keep long-lived blocks.

The owner's direction: a relay node keeps what it receives (clients are not relays and keep what they
choose). A relay with little disk needs to make room, and what goes first is what nobody requests, for
example the parts of a large item that are no longer downloaded. Demand MUST be measured reliably, also
behind a shared cache (CDN), within the relay's resource bounds.

Facts the design relies on:

- A relay reads header fields only. It cannot tell a container root from a leaf, nor group the chunks
  of one item.
- A `200` of `GET /block` carries `Cache-Control: public, max-age=31536000, immutable` and
  `ETag: "<block_id>"`; a request whose `If-None-Match` matches gets `304` with no body (core spec §4).
  A `404` carries `no-store` (ADR 0023 rule 13). With a one-year shared lifetime, a CDN serves a block
  from its edges for up to a year and the origin sees none of those requests.
- In `sbtp-relay` (`crates/sbtp-relay/src/blocks.rs`, `get_block` and `block_response`), a `304` is
  decided after the block is known to be held: on a hit of the in-memory block cache, with no I/O; on a
  miss, after a block-read permit, a file read and full validation, as for a `200`, without sending the
  body.
- `GET /block` does not touch the index (ADR 0013 rule 11). The index has one writer.
- The `small` profile's computed worst case is 13,018,580 bytes against a 15 MB target (ADR 0019
  rule 37).

### Shared cache behaviour checked on 2026-11-20

From the Cloudflare documentation (`cloudflare/cloudflare-docs`, through Context7). These facts are
documented; none was tested on a zone.

| Fact | Source page |
|---|---|
| Precedence for Cloudflare's cache decision: `Cloudflare-CDN-Cache-Control` > `CDN-Cache-Control` > `Cache-Control`. With `CDN-Cache-Control` present, `Cache-Control` is passed on unchanged and does not affect Cloudflare's decision; `CDN-Cache-Control` is passed downstream. | `cache/concepts/cdn-cache-control` |
| `s-maxage` sets the shared-cache lifetime and implies `proxy-revalidate`: no stale content without revalidation. | `cache/concepts/cache-control` |
| An expired entry is revalidated with a conditional request using the origin's `ETag` or `Last-Modified`; on `304` Cloudflare keeps the entry and sets a new lifetime. Without a validator it fetches the full response. | `cache/guides/invalidate-cache`, `cache/concepts/revalidation` |
| With Tiered Cache, a lower tier revalidates with its upper tier. Smart Tiered Cache funnels misses through one upper tier; it is available on the Free plan. Origins behind anycast cloud networks may fall back to several upper tiers. | `cache/how-to/tiered-cache`, `reference-architecture/architectures/cdn`, changelog 2026-04-17 |
| Eviction before expiry is LRU and not configurable; the next request is then a miss to the origin. | `cache/concepts/retention-vs-freshness` |
| A path without a listed file extension (such as `/sbtp/v1/block/<hex>`) is not cached unless a Cache Rule marks it "Eligible for cache". | `cache/concepts/default-cache-behavior` |
| A Cache Rule with Edge TTL "Ignore cache-control header and use this TTL" overrides `s-maxage` and the origin headers. A Cache Response Rule that sets `Cache-Control` overrides `CDN-Cache-Control`. Origin Cache Control is always on for Free, Pro and Business. | `cache/concepts/cache-control`, `cache/concepts/cdn-cache-control`, `cache/how-to/cache-rules/settings` |
| The minimum Edge Cache TTL that a rule can set on the Free plan is 2 hours. | `cache/how-to/edge-browser-cache-ttl` |
| Cloudflare turns a strong `ETag` into a weak one unless "Respect Strong ETags" is on. | `cache/how-to/cache-rules/settings` |

Not verified: whether an origin lifetime below 2 hours is honoured on the Free plan (rule 23 keeps the
shared lifetime at 2 hours or more); whether `CF-Connecting-IP` on a request from an upper tier carries
the visitor's address (rule 28 does not depend on it); whether Cloudflare serves a stale entry when the
origin answers a revalidation with `429` or `503` (rule 26).

## Decision

### Default posture

1. **Keep.** The default of `block_ttl_ms` in `sbtp-relay` becomes `0` (no eviction by age). Eviction by
   age stays a setting that an operator MAY choose (range of ADR 0019 rule 4, unchanged).
2. **Demand eviction on by default.** A relay MAY evict blocks by demand under rules 3 to 22. In
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
7. **Protection.** With `E = demand_epoch_ms`, a block is a candidate only when
   `last_demand + 3 × E ≤ now`. Under rules 9, 23 and 24 this guarantees: **a block requested at least
   once in the last `E`, directly or through at most two shared caches in series, is never evicted by
   demand.** Derivation: the origin sees that request, or a revalidation for it, at most `2 × E/2 = E`
   before it was made (rule 24); `last_demand` is the start of that epoch, at most `E` earlier; so
   `last_demand > now − 3 × E`. A new block stays at least `3 × E`.
8. **No eviction on the write path.** A `PUT` never evicts. A new block that does not fit gets `507`
   `StorageFull` as today (ADR 0013 rules 19 and 20). When demand eviction is on and the store is above
   the high-water mark, the relay MAY send `Retry-After` (seconds of `sweep_interval_ms`, rounded up).
   When no block is a candidate, the sweeper evicts nothing and logs `demand_stuck`; new blocks get
   `507` until blocks become candidates.

### What counts as demand

9. **Epoch.** `last_demand` is the start, in Unix milliseconds, of the epoch of length `E` in which the
   block was last demanded. It is stored as a time, not an epoch number, so a change of `E` keeps the
   stored order.
10. **Demand events.** Each of the following sets a block's `last_demand` to the current epoch:
    - its acceptance (`201`), so a block nobody has read yet is not the first to go;
    - a `GET` or `HEAD` of `/block` answered `200` or `304`, whether served from the block cache or from
      the file; a conditional request from a shared cache is one of them;
    - a `PUT` of it answered `200` (a re-submission, ADR 0043 rule 5);
    - the acceptance of a block that names it in its Parents Hashes field, for each held parent (at most
      8, ADR 0014). This is the only header-level DAG fact used; see rule 19.
    A `/query` listing is not demand. A request refused (`429`, `503`) or answered `404` is not demand.
11. **One count per block per epoch.** A relay MUST count at most one demand per block per epoch,
    whatever the client. Demand only moves `last_demand` forward; there is no counter. This bounds every
    client, and stores no client identity next to a block.

### Recording demand

12. **In memory, then in batches.** The `GET`, `HEAD` and `PUT` paths do not touch the index. They insert
    the `block_id` into a bounded in-memory set (`demand_touch_max` entries). The single index writer
    flushes the set in one transaction when it is half full, when an epoch ends, every
    `sweep_interval_ms`, and at a clean shutdown. A flush skips a block not held and a block whose stored
    `last_demand` is already the current epoch: at most one index update per block per epoch.
13. **No silent loss.** A demand is lost when the set is full, or when the relay stops without a clean
    shutdown before a flush. A relay MUST NOT evict by demand while a lost demand could be the one that
    protects a block under rule 7:
    - when the set is full, the demand is not recorded, `demand_lost_total` is incremented, and demand
      eviction is suspended until `now + 2 × E`;
    - after a start that follows an unclean shutdown (the index was not closed cleanly, ADR 0013 rule 9),
      demand eviction is suspended until `start + 2 × E`.
    A suspension stops demand eviction only: age eviction, `PUT` and reads are unchanged, and a full
    store answers `507`. The suspension end is kept in memory and set again by the next loss or unclean
    start. Proof: caches validated by the lost origin request at `t_o` serve visitors for at most
    `2 × S = E` after it (rule 17); rule 7 owes each of those requests protection for `E`, so until
    `t_o + 2 × E` at the latest, which the suspension covers.
14. **The `PUT` exception.** The demand of a `PUT` answered `200` is never lost to a full set: the index
    writer records it before the response (it is under the `put` rate limits).

### Shared caches

15. **Lifetime in shared caches.** A relay with demand eviction on MUST NOT let a shared cache keep a
    block response longer than `S = E / 2` (in seconds, rounded down) without revalidation. It sends, on
    every `200` and `304` of `GET` and `HEAD /block`:

    ```text
    Cache-Control: public, max-age=31536000, s-maxage=<S>, immutable
    CDN-Cache-Control: public, max-age=<S>, must-revalidate
    ETag: "<block_id>"
    ```

    `max-age` and `immutable` keep the one-year lifetime for private (browser) caches. `s-maxage`
    (RFC 9111 §5.2.2.10) and `CDN-Cache-Control` (RFC 9213) bound shared caches. The relay computes the
    values from its setting; the operator configures nothing on the relay.
16. **Archive and age-only relays.** With demand eviction off, the relay sends
    `Cache-Control: public, max-age=31536000, immutable` and no `CDN-Cache-Control`, as today.
17. **Revalidation is demand.** A shared cache that holds a block revalidates it with `If-None-Match`
    once its entry is older than `S` and the block is requested again; the relay answers `304` (no body)
    and counts it (rule 10). An entry evicted early by the cache gives a miss, which is a `200` and also
    counts. Each cache between the client and the relay adds at most `S` of delay before the origin sees
    a request. Rule 7 holds for up to two caches in series (an edge and one upper tier). A deployment
    with more tiers in series MUST NOT be placed in front of a relay with demand eviction on, or the
    operator turns demand eviction off.
18. **Deployment.** A cache rule that overrides the origin lifetime of `/sbtp/v1/block/*` (a fixed edge
    TTL that ignores the origin headers, or a response rule that rewrites `Cache-Control`) breaks
    rule 15. `deploy/README.md` states it (see "Implementation plan"). Bypassing the cache for
    `/sbtp/v1/*` is also correct: every request then reaches the relay.
19. **What stays outside.** A copy kept by a client application (IndexedDB, files) or by a private
    browser cache serves one user without a network request; demand counts network fetches, not
    views. A gateway or mirror that keeps its own copy is another holder, not a cache: its readers do
    not reach the relay.

### DAG integrity, gaming and interactions

20. **DAG integrity.** Rule 10 refreshes a parent each time a child is accepted, so a root with active
    children stays warm. A block with held children is not otherwise protected: anyone can mint a child
    of any block, so absolute protection would let anyone pin the whole store and turn every new block
    into a `507`. A dormant root can be evicted before or with its dormant children. The availability of
    long-lived blocks is guaranteed by archive relays and by re-publication on `404` (ADR 0043 rules 1
    and 5), not by a relay with demand eviction. A client handles a missing parent as pending
    (ADR 0043 rule 6).
21. **Gaming.** One `GET` per block per epoch keeps a block warm; filling the store with new blocks
    pushes cold blocks out. Both are accepted. Reads cannot make a block colder. Writes cost one proof
    of work each (ADR 0045) and are under the `put` rate limits. Demand eviction is local: it is not a
    deletion or censorship mechanism, and other relays and archives keep their copies (ADR 0013
    rule 17). A client that fills the demand set to suspend eviction (rule 13) must make the relay
    serve `demand_touch_max / 2` distinct held blocks faster than the writer flushes them, under the
    `block` rate limit; the effect is a `507` on new blocks, never the loss of a block.
22. **Deletion, `/query`, cursors, re-acceptance.**
    - A demand eviction deletes in the sweeper's order: cache entry, block file, then the block's own
      index entries (position, `block_id`, its edges to its parents) and its demand entries. Edges in
      which the evicted block is the parent belong to its children and stay: `/query?parent=` still
      lists held children of an evicted block. A crash between steps leaves a phantom (ADR 0013 rule 8).
    - An evicted block disappears from `/query` once its index entries are removed; before that, a client
      may get a `404` for a listed block (ADR 0012 rule 13). Removing positions does not invalidate a
      cursor and does not draw a new epoch (ADR 0024).
    - A `PUT` of an evicted block is a new block: `201`, new `received_at`, new position, `last_demand`
      of the current epoch (ADR 0013 rule 13). The sweeper serialises a demand eviction and a `PUT` of
      the same `block_id` as for expiry (ADR 0043 rule 4) and re-checks, at deletion time, that the
      block is still a candidate, the in-memory set included.
    - With both enabled, a block goes at its expiry by age or earlier by demand, whichever comes first.
      Demand never changes `received_at` or the expiry of ADR 0013 rule 12.

### Chunks

23. **Scope.** This ADR covers blocks. Chunks (ADR 0010) are not served by relays yet; their transport,
    admission and storage are Q-21. When Q-21 is decided, it SHOULD reuse rules 5 to 18 per chunk under
    the same quota. A relay cannot group the chunks of one item: each chunk ages by its own requests,
    so an item that is no longer downloaded loses its chunks one by one, and a partly downloaded item
    loses its unread chunks first.

### Settings, memory and metrics

24. **Settings** (environment variables `SBTP_RELAY_<NAME>`, as in ADR 0019):

    | Setting | Default | Range | Why |
    |---|---|---|---|
    | `block_ttl_ms` | 0 (was 2,592,000,000) | unchanged: 0, or 60,000 to 315,360,000,000 | Rule 1. |
    | `demand_eviction` | `true` | `true`, `false` | Rule 2. Off on an archive relay. |
    | `demand_high_water_pct` | 90 | 50 to 99 | Leaves room for the `PUT`s that arrive between two sweeper runs. |
    | `demand_low_water_pct` | 80 | 10 to `demand_high_water_pct − 1` | A gap avoids a run on every new block. Equal or higher stops the start-up. |
    | `demand_epoch_ms` (`E`) | 86,400,000 (1 day) | 14,400,000 (4 hours) to 2,592,000,000 (30 days) | One index update per block per epoch at most. The lower bound keeps `S = E/2` at 2 hours or more, the shortest edge lifetime documented for the cheapest CDN plan checked. Minimum stay of a block: `3 × E`. |
    | `demand_touch_max` | profile: 16,384 / 131,072 / 1,048,576 | 1,024 to 16,777,216 | Set by the profile (`small` / `standard` / `large`). |

    `demand_eviction`, the two watermarks and `demand_epoch_ms` are policy settings and are not set by a
    profile (ADR 0019 rule 38). `demand_touch_max` is a profile row (ADR 0019 rule 37). The settings are
    validated even when `demand_eviction` is `false`, as `sweep_*` are with `block_ttl_ms = 0`.
25. **Memory.** The set costs at most `demand_touch_max × 48` bytes (estimate: 32-byte identifier plus
    table overhead; not measured), added to the bound of ADR 0018 rule 35: 786,432 bytes on `small`
    (worst case 13,805,012 bytes, 1,194,988 bytes under 15 MB), 6 MiB on `standard`, 48 MiB on `large`.
    The suspension state of rule 13 is one integer.
26. **Index.** Two entries per held block: `position → last_demand` and `(last_demand, position) → ()`.
    They count in the index size and therefore in the quota (ADR 0013 rule 18). Estimate: about 60 bytes
    per block, not measured.
27. **Origin load of rule 15.** `N` is the number of blocks requested at least once per `S`, `U` the
    number of cache locations that contact the relay. A block causes at most `E / S = 2` origin requests
    per cache location per epoch; with the default `E` of one day, at most `2 × N × U` per day. A `304`
    carries no body: about 300 bytes of response headers, plus a request of the same order. Estimates,
    not measured:

    | `N` | `U = 1` (one upper tier) | `U = 20` (no tiered cache, 20 edges per block) |
    |---|---|---|
    | 10,000 | 20,000 / day, 0.23 / s, 12 MB / day | 400,000 / day, 4.6 / s, 240 MB / day |
    | 100,000 | 200,000 / day, 2.3 / s, 120 MB / day | 4,000,000 / day, 46 / s, 2.4 GB / day |
    | 1,000,000 | 2,000,000 / day, 23 / s, 1.2 GB / day | 40,000,000 / day, 463 / s, 24 GB / day |

    Bytes count request and response at 600 bytes per exchange. Cost per `304`: on a block-cache hit, a
    header comparison; on a miss, one block-read permit, one file read of at most 65,909 bytes and full
    validation (one BLAKE3 hash and one Ed25519 verification, of the order of 0.1 ms of CPU, not
    measured): about 0.2% of one core at 23 / s and 5% at 463 / s. No index access on the request path.
    Index writes from flushes: at most `N_epoch` per epoch (`N_epoch` the blocks requested in the
    epoch), 11.6 / s at one million. A deployment behind a CDN SHOULD enable a single upper tier
    (tiered cache) to stay in the `U = 1` column.
28. **Rate limiter.** Revalidations are `block` requests of the client key the relay derives
    (ADR 0018 rule 20, ADR 0044). Each one stands for a visitor request that found an expired entry, so
    it adds no request that the visitor would not have sent without the cache. When the key is the
    visitor's address (`client_ip_header` or a correct `X-Forwarded-For`), the limiter sees what it sees
    without a CDN. When every request of one cache location arrives under one key (the header is not
    set, or a tier does not forward the visitor's address), that key carries `2 × N` requests per day:
    the `small` `block` allowance (3,000 per minute) covers up to 2.16 million blocks at `U = 1`,
    `standard` 4.32 million and `large` 8.64 million. A revalidation refused with `429` or `503` is
    not demand (rule 10); the cache retries on the next visitor request, which is counted then. An
    operator behind a CDN sets `client_ip_header` (ADR 0044) and SHOULD NOT exempt CDN ranges from
    the limiter: they carry every customer of the CDN.
29. **Metrics** (prefix `sbtp_relay_`, ADR 0021 rule 41):

    | Name | Kind | Labels |
    |---|---|---|
    | `demand_evicted_blocks_total`, `demand_evicted_bytes_total` | counter | none |
    | `demand_runs_total`, `demand_stuck_total` | counter | none |
    | `demand_flushes_total`, `demand_flush_updates_total` | counter | none |
    | `demand_lost_total` | counter | none |
    | `demand_suspended` | gauge (1 while rule 13 suspends eviction) | none |
    | `demand_touch_entries` | gauge | none |
    | `demand_coldest_ms` | gauge (`last_demand` of the next candidate, 0 when none) | none |
    | `block_not_modified_total` | counter (`304` answers of `/block`) | none |

    Events: `demand_evicted` (one line per run: blocks, bytes, duration), `demand_stuck` and
    `demand_suspended` (rate-capped, ADR 0021). No event names a `block_id` or a client.

## Consequences

- **Network.** By default a relay is a long-lived source until its disk is near full, and the blocks it
  drops are those nobody fetched over the network, directly or through a cache, for at least `E`, and
  that the origin has not seen for at least `2 × E`. Archive relays remain the guarantee.
- **CDN offload.** Browsers keep the one-year lifetime. Shared caches keep serving bodies; they ask the
  origin at most twice a day per block per cache location, and get `304` without a body.
- **Privacy.** The index now records, per block, the epoch in which it was last requested. No client
  identity is stored with it (rule 11). Someone with the disk learns which blocks were read in which
  epoch, not by whom. An operator who does not want this turns demand eviction off.
- **Cost.** Reads stay O(1) and off the index: one insert into a bounded set. Index writes are at most
  one per block per epoch plus one per accepted block. Rule 27 gives the origin load of rule 15.
- **Compatibility.** Nothing is released. A relay that does not implement this ADR is a relay without
  demand eviction (rule 4) and keeps the one-year shared lifetime.

## Implementation plan (relay-engineer)

1. `config.rs`: `block_ttl_ms` default 0; the settings of rule 24, ranges, the low < high check, the
   `demand_touch_max` profile row; `/info` member `demand_eviction`.
2. `index.rs`: tables `demand` (`position → u64`) and `demand_order` (`(u64, position) → ()`); written in
   the same transaction as the other entries on insert, removed with them; a start-up step that fills
   both for blocks that have none (`last_demand = received_at` quantised to its epoch); a `candidates`
   read job bounded by `sweep_batch`, with the `3 × E` bound of rule 7.
3. A `DemandSet` (bounded set of `block_id`, current epoch start, suspension end) shared by `blocks.rs`
   (`get_block` after `block_response` decides `200` or `304`; `put_block` on `200` and `201`, the block
   and its held parents). Flush job on the index writer at half capacity; rule 13 on overflow and after
   an unclean start; rule 14 for `PUT` `200`.
4. `blocks.rs`, `block_response`: the headers of rules 15 and 16 from the settings, on `200` and `304`.
5. `sweep.rs`: after the age pass, a demand pass when above the high-water mark and not suspended;
   re-check at deletion under the per-`block_id` serialisation of ADR 0043 rule 4, including the
   in-memory set; `demand_stuck`.
6. `metrics.rs`, `log.rs`: rule 29. The memory bound logged at start-up includes rule 25.
7. Tests: the order of rule 6; the `3 × E` bound of rule 7 at its exact millisecond; low and high
   water; `507` and `Retry-After` with nothing evictable; one update per block per epoch under repeated
   `GET`s; a `304` counts; a `404`, `429` or `503` does not; a full set suspends eviction for `2 × E` and
   counts; an unclean start suspends for `2 × E`; a clean restart does not and keeps `last_demand`; a parent
   refreshed by a child; a `PUT` `200` racing a demand eviction; re-acceptance after eviction gets
   `201`; `/query?parent=` of an evicted parent still lists its children; the response headers of
   rules 15 and 16 with demand eviction on and off; an archive relay (both off) deletes nothing.
8. `deploy/README.md`, Cloudflare section: replace "Cache rule bypass on `/sbtp/v1/*`, explicitly" by:

   > - Cache rules on `/sbtp/v1/*`. Either bypass the cache for the whole path (every request reaches
   >   the relay), or:
   >   - bypass for every path except `GET /sbtp/v1/block/*`;
   >   - for `/sbtp/v1/block/*`: "Eligible for cache"; Edge TTL "Use cache-control header if present,
   >     bypass cache if not"; Browser TTL "Respect origin". Never "Ignore cache-control header and use
   >     this TTL", and no Cache Response Rule that sets `Cache-Control` on this path: either one
   >     overrides the lifetime that the relay sets for demand eviction (ADR 0046 rule 15);
   >   - Tiered Cache with Smart Topology on, so that one upper tier contacts the relay.
   >   - `client_ip_header = "CF-Connecting-IP"` on the relay (ADR 0044).

**Security-auditor review** before merge: the bound of the demand set and the `GET` hot path (no index
access, no unbounded growth under an identifier flood); the suspension of rule 13 as a lever to force
`507` (rule 21); the race of rule 22; the start-up migration on a large index (time bound,
interruption); write-flood eviction of cold blocks (rule 21) against the `small` profile; the response
headers of rule 15 (no shared lifetime above `S`, unchanged `immutable` for private caches); that logs
and metrics carry no `block_id` or client key.

## Spec change on acceptance

Core spec §4, `GET /sbtp/v1/block/{block_id}`, the `Cache-Control` sentence ("A `200` response SHOULD
carry `Cache-Control: public, max-age=31536000, immutable`.") replaced by:

> A `200` response SHOULD carry `Cache-Control: public, max-age=31536000, immutable`. A relay that
> evicts by demand MUST instead bound shared caches to half its demand epoch `S`, on every `200` and
> `304`: `Cache-Control: public, max-age=31536000, s-maxage=<S>, immutable` and
> `CDN-Cache-Control: public, max-age=<S>, must-revalidate` (RFC 9213), with the `ETag`, so that a shared
> cache revalidates each requested block at least once per `S`. (ADR 0023, ADR 0046)

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
>   per epoch `E`, whatever the client. A block whose last demand is less than `3 × E` old is not
>   evicted. A lost demand suspends eviction by demand for `2 × E`. A `PUT` never evicts. (ADR 0046)
> - A relay that evicts by demand bounds shared caches to `E / 2` with `s-maxage` and
>   `CDN-Cache-Control`, so that a block requested through a cache is revalidated, and counted, at least
>   once per `E / 2`. (ADR 0046)
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
- **Accept that a CDN hides demand.** Popular blocks served from edges for a year would look cold at the
  origin and be evicted first. Rejected by the owner.
- **Read the CDN's logs or analytics to recover demand.** Vendor-specific, delayed, often a paid feature,
  and it puts per-request records on the relay host.
- **A shared lifetime of `E`.** With two tiers, the origin can see a request up to `2 × E` late; the
  protection window would grow to `4 × E`. `E / 2` costs one more `304` per block per epoch and keeps
  `3 × E`.
- **`stale-while-revalidate` for shared caches.** The cache would serve stale and revalidate in the
  background; `s-maxage` disables it on the cache checked, and the gain is latency, not accuracy.
- **Answer a `304` from the file's existence only (no read, no validation).** Cheaper on a cache miss,
  but it confirms a block that may be damaged (ADR 0023). The measured need is small (rule 27); it can
  be decided later with figures.
- **Drop demands when the set is full.** A block requested only in that window could then be evicted
  while still in demand. Rule 13 suspends eviction instead.
- **Counting reads (frequency, LFU).** Needs a counter per block, and a per-client bound on counts needs
  a table of client keys per block: memory, writes, and a record of who read what. Recency per epoch
  needs neither.
- **Updating the index on every `GET`.** One write per read, through the single index writer, on the
  hot path. Rule 12 bounds it to one per block per epoch, off the request path.
- **Protecting every block that has held children.** Anyone can mint a child of any block; the store
  could be pinned whole (rule 20).
- **Evicting on the `PUT` path to admit the new block.** It lets a write flood choose, request by
  request, what goes, and adds deletions to the latency of a `PUT`.
- **Triggering on low free disk space (ADR 0021) as well as on the quota.** Another process filling the
  disk would make the relay delete its store. Free space below the watermark keeps giving `507`.
