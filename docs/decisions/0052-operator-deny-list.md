# 0052: Operator deny list: blocks and keys a relay does not serve or store

- Status: accepted (by the project owner, 2026-11-21), as proposed, with the owner choices recorded in
  "Decisions of the project owner": `451` with `Denied` for every ground; `DeniedKey` on `PUT`; default
  action `hide`, `purge` per entry; a denied block is never re-sent automatically; `/info`
  `"deny_list": true`; `deny_max_entries` 2,048 / 65,536 / 1,048,576
- Amended: 2026-11-21, accepted by the project owner on 2026-11-21 (Q-83): rule 12, last bullet, a
  cross-reference to ADR 0047 amendment D1 (a `451` to a presence check of a block the relay had
  acknowledged changes its availability, not its delivery state)
- Clarifications: L1 to L3 (2026-11-21, after the implementation of `sbtp-relay`; accepted by the project owner, 2026-11-21): L1, the
  cursor of a page that the list emptied (rule 9, an exception to ADR 0051 clarification B4); L2, the
  `/info` member is `true` or absent (rule 11); L3, the line format of `deny_file` (rules 3 and 21).
  No wire format change
- Date: 2026-11-21
- Questions: opens Q-80 (keeping the bytes of a denied block as evidence) and Q-81 (public notice and
  appeal of a denial)
- Amends: ADR 0018 rule 35 (one memory term); ADR 0019 rules 37 and 38 (profile row and policy
  settings); ADR 0021 rules 7 and 41 (events, counters); ADR 0043 rule 5 (what triggers a re-submission);
  ADR 0046 rule 10 (a `451` is not demand); ADR 0047 rules 3 and 5 (a denial is final and is not
  re-sent automatically); ADR 0048 rules 6 and 7 (replication skips denied blocks); ADR 0050 rules 7,
  16 and 19 (the archive copy and read-through skip denied blocks); ADR 0051 rule 2 (a denied block is
  a `length = 0` record). Nothing else in these ADRs changes
- Depends on: ADR 0012 (errors, `/query`), ADR 0013 (index, positions), ADR 0021 (privacy of logs),
  ADR 0023 (served bytes), ADR 0029 (client bounds), ADR 0041 (graph gateway), ADR 0043, ADR 0046,
  ADR 0047, ADR 0048, ADR 0050, ADR 0051
- Impact: core spec §4 (introduction, `PUT`, `GET /block`, `POST /blocks`, `/info`, `/query`, errors,
  "Several relays", a new part "Denied blocks"); `architecture.md` §2 (validation pipeline, eviction,
  replication, archive copy); `graph-access.md` §3.2 (a gateway and a `451`);
  `sbtp-relay` (deny list, reload, checks on every route, marking pass, settings, metrics);
  `deploy/README.md` (file, reload, CDN purge, bucket removal); clients (outcome `denied`); client
  conformance cases; no wire format change, no block test vector

## Context

A relay that serves public content can receive a demand to stop serving a block, on a legal ground or
for abuse. Nothing in the specification lets an operator do that in a way clients understand:

- A relay could answer `404`. Clients read `404` as "not held here". A publisher that keeps a block
  available re-submits the same bytes when a `GET` gets `404` (ADR 0043 rule 5); a client may also
  count a `GET` `200` as an acknowledgement and run presence checks (ADR 0047 rule 1). A relay that
  hides a block behind `404` and refuses its `PUT` would get it again, forever, from every holder.
- A relay could delete the file. It comes back with the next `PUT`, the next replication walk or the
  next read-through fetch (ADR 0048, ADR 0050).
- Copies outside the relay process stay: a bucket written by the archive copy that is never deleted
  from (ADR 0050 rule 11), a CDN that keeps `200` responses up to one year (ADR 0046 rule 16), replicas
  run by other operators.

The relay does not parse payloads (§4). It can act only on what layer 0 gives: the `block_id` and the
header's public key. Blocks are immutable: a denied block cannot be altered, only not served.

## Decision

### The list

1. **Entries.** A relay MAY apply a **deny list** set by its operator. An entry names either:
   - a **block**, by its `block_id`; or
   - a **key**, by the 32-byte Ed25519 public key of the header (§2): every block signed by that key,
     held now or received later.

   A block is **denied** when its `block_id` is listed, or its public key is listed. The relay does not
   interpret payloads to build or apply the list (§4: a dumb relay); a list by content (hashes of
   files carried inside payloads, words) is out of scope.
2. **Configuration, not protocol.** The list is local configuration of one relay. It is not published,
   not exchanged between relays and not derived from anything the relay receives (rule 17). The
   protocol fixes only what a client observes.
3. **Format of `sbtp-relay`.** The setting `deny_file` names a UTF-8 text file. Each line is empty, a
   comment starting with `#`, or `<kind> <hex>[ <action>]`: `kind` is `block` or `key`, `hex` is 64
   lowercase hexadecimal characters, `action` is `hide` (the default) or `purge` (rule 14). A line of
   more than 256 bytes, an unknown token, more than `deny_max_entries` entries, or one entry listed with
   two actions makes the file invalid. The same entry listed twice with one action counts once. Other
   implementations SHOULD accept this format, so that an operator can move a list between them.
4. **Reload.** The relay reads the file at start-up, on `SIGHUP`, and when its modification time or
   size changes (checked every `deny_reload_ms`). An invalid file at start-up stops the start-up with a
   `config_error`. An invalid file on reload is refused as a whole: the previous list stays in force,
   and the relay logs `deny_list_invalid` (rule 20). A relay never falls back to an empty list because
   a file is invalid or missing; a missing file on reload is invalid. A loaded list applies to every
   request that starts after the load.
5. **Bounds.** Lookups are by exact match in memory: one lookup for the `block_id` and one for the key
   per block checked, `O(1)`. `deny_max_entries` bounds the list (rule 21).

### What a client observes

6. **Status.** For a denied block the relay answers **`451 Unavailable For Legal Reasons`** (RFC 7725)
   with the error body of §4, on every route that names the block:
   - `GET` and `HEAD /sbtp/v1/block/{id}`: `451`, error name `Denied`, whatever the request's
     `If-None-Match` (a denied block is never answered `304`, §4 already ties `304` to a block the relay
     would serve with `200`), whether the bytes are held, cached or not held at all, and whether or not
     the request carries `Sbtp-Replication: 1`;
   - `PUT /sbtp/v1/block`: rule 7;
   - `POST /sbtp/v1/blocks`: rule 8;
   - `/query`: rule 9.

   The status says only that this relay's operator does not serve the block. The relay MUST NOT state
   the ground, the party that asked, or whether the match is by block or by key on a read. The error
   `message`, when present, is a fixed text that does not depend on the entry. RFC 7725 §3 asks for an
   explanation of the legal demand in the body; this version gives none, and leaves the place for one to
   a later ADR (rule 23). A denial on an abuse ground uses the same status: a second status for it would
   tell every reader which ground applies.
7. **`PUT`.** The deny check is a step of the `PUT` pipeline after C3 and before storage (§4, new
   step 5; storage becomes step 6). A block that passes F1 to F9, P1, C1, C2 and C3 and is denied gets
   `451` and is not stored, whether or not the relay holds its bytes; it never gets `200` or `201`. The
   error name is `Denied` when the `block_id` is listed, `DeniedKey` when the key is listed (and the
   `block_id` is not). Because the check follows C3, only a holder of a validly signed block of that
   key reaches it; anyone can already infer a key-level denial by reading several of that key's blocks,
   so `DeniedKey` adds little, and it lets a publisher stop mining blocks that the relay will refuse
   (rule 12). A block that fails an earlier check gets that check's answer.
8. **Batch fetch.** In `POST /sbtp/v1/blocks`, a denied block is a `length = 0` record, as any block
   not served. The record format does not change (ADR 0051 rule 2). A `length = 0` record is never by
   itself a reason to re-submit (rule 13).
9. **Listings.** `/query` MUST NOT list a denied block, with or without `parent`, `fields` or `order`.
   - A block listed by `block_id` is omitted from the first page built after the load: the listing
     checks each identifier against the list.
   - A block denied by key is omitted once the relay's **marking pass** has reached it: after a load
     that adds a key or a `purge` entry, the relay walks its held blocks in bounded runs, off the
     request path, and records which are denied (for `sbtp-relay`, a table of the index; rule 14 for
     `purge`). Until then a listing MAY still return it, and a fetch of it gets `451`. A block received
     later is refused at `PUT` (rule 7) or skipped (rules 17 to 19) and never listed.
   - A page MAY therefore hold fewer than `limit` identifiers, and `more` MAY be `true` when only denied
     blocks remain; the next page is then empty with `more = false`. Cursors are unchanged. The work of
     a request stays `O(log n + limit)`. A page whose entries were all denied returns the cursor of
     the entries it read, not the gap it started from (clarification L1).
   - Edges in which a denied block is the parent belong to its children: `/query?parent=` still lists
     the children that are not denied (as after an eviction, ADR 0046 rule 22).
10. **Caching.** A `451` is an error response and carries `Cache-Control: no-store` (§4, Errors), and
    also `CDN-Cache-Control: no-store`: a lifted denial takes effect at the next request, and no shared
    cache keeps a response the operator may withdraw. The cost of a denied block that is requested often
    is one lookup per request, under the rate limits.
    A relay cannot withdraw a `200` that a shared cache or a browser already holds (up to one year on an
    archive relay, `S` on a relay with demand eviction, ADR 0046 rules 15 and 16). An operator who
    denies a block SHOULD purge `/sbtp/v1/block/{id}` from the CDN it runs in front of the relay; for a
    key, `sbtp-relay` offers a local operator command that lists the held `block_id` values of that key
    after the marking pass, for the purge. Private caches are out of reach.
11. **`/info`.** A relay that applies a deny list publishes `"deny_list": true`: the setting `deny_file`
    is set, whatever the number of entries, including none. A client MUST read an absent member as
    `false`; a relay without a deny list omits the member (clarification L2). The member says that
    `451` can occur; it says nothing about the entries. A relay MUST NOT
    publish the entries, their number or their grounds in `/info`.

### What a client does

12. **On `451`.** A conforming client:
    - **reads**: handles the block as not served by that relay and MAY ask another relay, as after a
      `404`. A `451` from one relay says nothing about the block's validity or about other relays. A
      client MUST NOT treat it as proof that the block does not exist or is invalid;
    - **publishes**: sets the delivery state of that block for that relay to `refused` (ADR 0047 rule 3:
      a final refusal) and continues with the other relays of its list. It MUST NOT send that block to
      that relay again automatically: not on a schedule, not after a `404` or a `length = 0` record from
      that relay, not under ADR 0043 rule 5 or ADR 0047 rule 5. A user action MAY send it again;
    - after `DeniedKey`, MUST NOT send to that relay automatically any other block signed by that key,
      new blocks included, until the user acts. It MAY still publish them to other relays;
    - MUST NOT create a new block automatically because of a `451` (re-signing, re-mining or altering
      the payload to obtain another `block_id`);
    - applies the same rules to a `451` from a `GET` or `HEAD` of a block it publishes or keeps
      available: it records the denial and does not re-submit. When that relay had acknowledged the
      block, its delivery state stays `acknowledged` and the block's availability on that relay
      becomes `refused`; the relay no longer counts as holding the block for ADR 0047 rule 2, and the
      second bound of ADR 0047 rule 4 does not restart (ADR 0047 amendment D1, accepted 2026-11-21).

    A client keeps, per relay, the `block_id` values (and the keys of `DeniedKey`) it saw denied, within
    its storage bounds (ADR 0029 rule 12). Dropping a record only lets the client send the block once
    more and get `451` again.
13. **Re-submission trigger.** A re-submission under ADR 0043 rule 5 follows a `404` to a single
    `GET` or `HEAD /sbtp/v1/block/{id}` from that relay. A `length = 0` record of a batch is not a
    trigger on its own: the client confirms with a single `GET` first, so that a denied block, which
    gets `451` there, is never re-sent.

### Storage and lifting

14. **Actions.** Per entry, the operator chooses:
    - `hide` (default): the relay keeps the file and its index entries, and does not serve or list the
      block. The block is not demand (rule 15) and is evicted in the normal course (age, demand) like
      any block; an archive relay keeps it. Lifting the entry serves it again at its original
      position.
    - `purge`: the marking pass deletes the block as an eviction does (ADR 0046 rule 22: cache entry,
      file, index entries), regardless of the protection of ADR 0046 rule 7. Lifting the entry does not
      bring it back: a later `PUT` stores it as a new block (`201`, new position).

    Lifting an entry (removing it and reloading) ends the `451` at once. A block that reappears at its
    original position is not seen by a client walking from a cursor already past it; a lifted block is
    not announced.
15. **Not demand.** A request answered `451` is not a demand event (ADR 0046 rule 10, which lists the
    `200` and `304` answers only). A denied block held under `hide` counts in the quota.
16. **Evidence.** This ADR gives the relay no function to keep the bytes of a denied block beyond
    `hide`, and no function to export them. Whether an operator must keep them, for how long, and out of
    public reach, depends on the legal ground and the jurisdiction (Q-80). An operator who needs a copy
    makes it before a `purge`, for example by a `GET` of the block before the entry is loaded.

### Other functions of the relay

17. **Replication (ADR 0048).** A relay MUST NOT fetch, store or serve a block on its own deny list:
    - at the held check (rule 6), a listed `block_id` is skipped without a fetch and counted (`denied`);
    - a fetched block whose key is listed is discarded after validation and counted (`denied`);
    - a `451` from a peer is a skip, like a `404` (rule 7), counted by reason `denied`, and not retried
      in that walk.
    A relay MUST NOT add an entry to its own list because a peer answered `451`, or because a peer's
    `/info` says `deny_list: true`. A denial does not propagate: each operator decides its own list.
18. **Archive copy (ADR 0050).** The uploader does not upload a denied block. It treats it as done, so
    the cursor passes it, and counts it (`mirror_denied_total`). A block lifted after the cursor passed
    it is not uploaded; the operator MAY reset the cursor. The relay never deletes from a bucket
    (ADR 0050 rule 11, unchanged): removing an object already uploaded is an operator task with
    credentials the relay does not hold, as repair is (ADR 0050 rule 14). After that removal the bucket
    answers `403` or `404`, which a reader handles as "not here" (ADR 0050 rule 5). A read-only relay
    URL cannot answer `451`; no client sends it a `PUT`, so there is no re-submission loop.
19. **Read-through (ADR 0050 rules 15 to 19).** On a local miss for a block whose `block_id` is listed,
    the relay answers `451` without asking any source. A fetched block whose key is listed is not
    served and not kept; the relay answers `451` and counts it (`fallback_fetches_total`, result
    `denied`). A `451` from a source is a source that does not serve the block: the relay tries the
    next one, and answers `404` when none serves it. A relay never answers `451` because a source did.
20. **Logs and metrics (ADR 0021).** The rules of ADR 0021 rule 10 apply unchanged: a public key is
    never logged, and a `block_id` never at `info` or above. The deny list adds:
    - events `deny_list_loaded` (counts `blocks`, `keys`, `purge`) and `deny_list_invalid` (line
      number and a fixed reason, never the line's content), rate-capped;
    - no event per denied request: a denied request is counted, not logged. It carries no client tag,
      even with `log_client_tag = "keyed"`: the relay does not record who asked for or sent a denied
      block;
    - counters `denied_total` (labels `route`: `put`, `get`, `batch`, `query`, `replication`,
      `fallback`, `mirror`; `match`: `block`, `key`) and gauges `deny_entries` (label `kind`) and
      `deny_marking_pending` (blocks the marking pass has not reached).
    The file holds identifiers of denied content. `deploy/README.md` advises mode `0600`, owned by the
    relay's service account. A `setting` event logs the path of `deny_file`, never its content.
21. **Settings and memory.**

    | Setting | Default | Range | Kind |
    |---|---|---|---|
    | `deny_file` | empty (off) | path | policy |
    | `deny_max_entries` | 2,048 / 65,536 / 1,048,576 | 1 to 16,777,216 | profile row |
    | `deny_reload_ms` | 10,000 | 1,000 to 3,600,000 | policy |

    Memory term of ADR 0018 rule 35, estimate, counted only when `deny_file` is set:
    `2 × deny_max_entries × 80` (a 32-byte entry and its kind in a table at most half full, two lists
    during a reload). `small`: 327,680 bytes. With ADR 0050 as amended (amendment U3, accepted
    2026-11-21: 18,681,778 bytes with every function on), `small` with every function on is
    19,009,458 bytes, 990,542 bytes under the 20,000,000-byte budget of ADR 0048 rule 3, item 2. The marking pass uses the sweeper's
    bounded runs (`sweep_batch`) and adds no term.

### Graph gateway and later work

22. **Graph gateway (ADR 0041).** A gateway that reads a relay handles a `451` as a block not served:
    it does not show it, and it does not fetch it from elsewhere to serve it in that relay's place. A
    gateway's own deny list is out of scope.
23. **Room for later decisions.** This ADR defines no public notice, no appeal route and no legal
    status of the operator or of the relay. A later ADR MAY add, without changing the rules above:
    a reference to a public notice on a `451` (for example the `Link` relation `blocked-by` of RFC 7725
    §4, or an error body member); an `/info` member naming the operator's policy page; an appeal or
    counter-notice route; lists shared between operators, subscribed to explicitly (Q-81). A client MUST
    already ignore members and headers it does not know (§4).

## Consequences

- **Network.** A relay operator can stop serving a block or a key on its relay without breaking
  clients: readers go to other relays, publishers stop sending it there and continue elsewhere. Other
  relays are not affected; a denial on one relay is not a denial on the network.
- **Integrity.** Unchanged. The list removes blocks from what one relay serves; it never makes a client
  accept or reject a block's validity. A missing parent is pending (`l2-grammar.md` §4.1), as after an
  eviction.
- **Privacy.** A `451` tells a reader that this relay's operator does not serve the block, nothing more.
  The relay keeps no record of who asked for or sent a denied block. `/info` reveals only that a list is
  applied. Copies in shared caches, buckets and replicas are out of the relay's reach (rules 10, 18).
- **Cost.** Two in-memory lookups per checked block; a bounded marking pass after a load that adds a
  key or a `purge`. No index read on the `GET` path for a block denied by `block_id`.
- **Compatibility.** `451` is new to the relay interface; `deny_list` is a new optional `/info`
  member. A client written before this ADR already treats a `451` to a `PUT` as a final refusal
  (ADR 0047 rule 3, "any other `4xx`") and a `451` to a `GET` as a failed read; it does not re-submit on
  a `451`, only on a `404`. Nothing is released.
- **Client conformance (ADR 0053, accepted 2026-11-21).** The outcome `denied` of ADR 0053 rule 14 maps to a
  `451` on any route; `client-v1/` gains the cases of rules 12 and 13.

## Implementation plan

| Stage | Work | Owner | Effort |
|---|---|---|---|
| 1 | Settings and file parser (rules 3, 4, 21), reload by `SIGHUP` and modification time, checks on `GET`, `HEAD`, `PUT` (after C3), `POST /blocks`, `/query` (rules 6 to 9), headers (rule 10), `/info` member, marking pass and `purge` (rules 9 and 14), metrics and events (rule 20); tests: each route with a block entry and a key entry, `If-None-Match` gives `451`, reload with an invalid file keeps the old list, lifting with `hide` serves again, `purge` then `PUT` after lifting gives `201` | relay-engineer | 2 days |
| 2 | Replication, archive copy and read-through skips (rules 17 to 19), with the existing stubs | relay-engineer | 1 day |
| 3 | Client outcome `denied` (rules 12 and 13) in the web client, `cli-demo` and the client SDK; `deploy/README.md` (file mode, reload, CDN purge, bucket removal) | wasm-engineer, relay-engineer | 1 day |

**Security-auditor review:** the parser on a hostile file (long lines, huge counts, invalid UTF-8); no
entry, key or `block_id` in logs, metrics labels or error messages; an invalid or missing file never
empties the list; no route serves a denied block from the block cache; `451` before `304`; the deny step
after C3 on `PUT`; the read-through never fetches a listed `block_id`; the memory bound.

## Decisions of the project owner (2026-11-21)

1. **One status for every ground.** A denied block gets `451` with the error name `Denied`, whatever
   the ground, legal or abuse (rule 6). `410 Gone` is rejected (see "Rejected alternatives").
2. **`DeniedKey` on `PUT`.** A `PUT` of a block whose public key is listed gets `451` with `DeniedKey`
   (rule 7). Reads never say whether the match is by block or by key.
3. **Actions.** The default action is `hide`; `purge` is chosen per entry (rule 14).
4. **No automatic re-send.** A client never sends a denied block to the relay that denied it again
   automatically; only a user action does (rule 12). Periodic re-submission is rejected.
5. **`/info`.** A relay that applies a deny list publishes `"deny_list": true` (rule 11).
6. **Bound.** `deny_max_entries` is 2,048 on `small`, 65,536 on `standard` and 1,048,576 on `large`
   (rule 21).

## Spec change on acceptance

Applied on acceptance (2026-11-21).

Core spec §4, introduction: the relay stores the block without interpreting it "unless its operator
denies it (see "Denied blocks")".

Core spec §4, `PUT /sbtp/v1/block`, processing: a new step after the Ed25519 signature:

> 5. deny list: a block the relay's operator denies is not stored (see "Denied blocks");
> 6. storage addressed by the `block_id`, […]

and a new response:

> - `451 Unavailable For Legal Reasons`: the block is valid and the relay's operator denies it
>   (`Denied`, or `DeniedKey` when its public key is denied). Nothing is stored. A denied block never
>   gets `200` or `201`. (ADR 0052)

`GET /sbtp/v1/block/{block_id}`, a bullet after the `404` bullet:

> - `451 Unavailable For Legal Reasons` (`Denied`): the relay's operator denies the block. The relay
>   answers it whether or not it holds the bytes, and never answers `304` for it. (ADR 0052)

`POST /sbtp/v1/blocks`, after "`length = 0`: the block is not served":

> A denied block is a `length = 0` record. (ADR 0052)

`GET /sbtp/v1/info`, a new bullet after `read_api`:

> - `deny_list`: boolean; `true` when the relay applies a deny list of its operator, whatever its
>   entries. A client MUST read an absent member as `false`. (ADR 0052)

`/query`, a new bullet after "A request with no match gets `200`":

> - A relay MUST NOT list a block it denies by `block_id`. A block denied by its public key MAY be
>   listed until the relay has marked it, and gets `451` on a fetch. A page MAY hold fewer than `limit`
>   identifiers, and `more` MAY be `true` when only denied blocks remain. (ADR 0052)

Errors, names: add `Denied`, `DeniedKey` (`451`).

"Several relays (non-normative)", the bullet on `PUT` idempotence: a block refused or not reached MAY be
sent again later, "except a block the relay denied (see "Denied blocks")".

A new part after "Redirects":

> ### Denied blocks
>
> - A relay MAY apply a deny list set by its operator, by `block_id` or by the public key of the
>   header. It does not interpret payloads to apply it. The list is local configuration; it is not
>   published or exchanged.
> - For a denied block the relay answers `451` with `Cache-Control: no-store` and
>   `CDN-Cache-Control: no-store`, on `GET`, `HEAD` and `PUT`, and serves it as `length = 0` in a
>   batch. It does not state the ground, the requester or, on a read, whether the match is by block or
>   by key.
> - A client handles a `451` to a read as a block not served by that relay and MAY ask another relay.
>   It MUST NOT treat it as proof that the block is invalid or absent elsewhere.
> - A client that receives `451` for a block it publishes treats it as a final refusal by that relay,
>   continues with its other relays, and MUST NOT send that block to that relay again automatically.
>   After `DeniedKey` it MUST NOT send any block signed by that key to that relay automatically. A user
>   action MAY. A client MUST NOT create a new block automatically because of a `451`.
> - A re-submission after a missing block follows a `404` to a single `GET` or `HEAD`, never a
>   `length = 0` batch record alone.
> - A relay MUST NOT fetch, store or serve a block it denies through replication, read-through or any
>   other function, and MUST NOT deny a block because another relay or source denies it.
> - A deny list does not reach copies outside the relay: shared caches, object stores, other relays,
>   clients. (ADR 0052)

`architecture.md` §2, "Validation pipeline": the deny step after the signature. "Eviction": a bullet

> - An operator deny list (ADR 0052) is not eviction: a denied block is not served or listed; with
>   `purge` it is deleted as an eviction deletes, without the demand protection. (ADR 0052)

"Replication" and "Archive copy and read-through": one bullet each stating rules 17 to 19. The bullet
on long-lived blocks: clients submit them again after a `404` "to a single `GET` or `HEAD`, never after
a `451`".

`graph-access.md` §3.2, a new bullet after "Shared relay rules":

> - **Denied blocks.** A gateway handles a `451` from a relay as a block that relay does not serve. It
>   does not show it, and it does not fetch it from another source to serve it in that relay's place.
>   (ADR 0052)

## Rejected alternatives

- **`404` for a denied block.** Publishers re-submit on `404` (ADR 0043 rule 5); presence checks never
  end; a reader cannot tell an eviction from a denial, and the operator's refusal of each `PUT` costs a
  full validation every time.
- **`410 Gone`.** It states that the resource is gone for good, which a lifted denial contradicts, and
  it is heuristically cacheable and commonly cached for long by CDNs; HTTP tooling and crawlers drop a
  `410` URL. It also does not name the refusal as a decision.
- **`403 Forbidden`.** An object store answers `403` for a missing key (ADR 0050 rule 5) and proxies and
  firewalls emit it for their own reasons; a client could not tell a denial from either.
- **A second status for abuse grounds (`451` for legal demands only).** It tells every reader which
  ground applies to each block.
- **A marker in listings** (`"denied": true` next to an identifier). It publishes the identifiers of
  denied blocks to anyone who lists a parent, and points readers to where else to look for them.
- **A per-record status in the batch format** (a reserved `length` value). A change of the record
  format that clients written for ADR 0051 reject as a failed response (`length` above 65,909); rule 13
  gives the same result with one `GET`.
- **A short `max-age` on `451`.** It shields the origin from repeated reads of a denied block, but a
  lifted denial would then stay visible for that time; the lookup is cheap.
- **Periodic re-submission after a denial** (for example once every 30 days, to heal a lifted denial).
  With `hide` as the default, lifting is lossless and needs no re-submission; with `purge`, the operator
  chose to drop the bytes. A periodic retry would cost every denied block's holders a `PUT` per period.
- **Propagation of denials between relays** (a `451` from a peer, or a shared list fetched by URL). A
  relay would then enforce decisions it did not make, and one list could remove a block from every
  relay that follows it. Explicit subscription to a shared list is left to Q-81.
- **Logging denied requests with a client tag.** It makes the relay a record of who asked for or sent
  what; ADR 0021 already keeps addresses out of relay logs.
- **A built-in evidence store** (bytes kept out of eviction and out of public reach). Its need, duration
  and legal basis depend on the ground and the jurisdiction (Q-80); `hide` keeps the bytes in the
  normal course meanwhile.
- **Denial by content** (hashes of payload data, keyword filters). The relay does not parse payloads;
  that belongs to layers above, which can apply their own lists before showing a block.

## Clarifications (2026-11-21)

After the implementation of `sbtp-relay`. Accepted by the project owner, 2026-11-21.

- **L1. A page that the list emptied (rule 9).** Accepted 2026-11-21. The relay builds a page from the index, then removes
  the denied identifiers from it. The page's `cursor` is the cursor of the entries it read, before the
  removal: with `asc`, the gap after the last entry read; with `desc`, the gap before the oldest entry
  read. This holds when every entry read was denied and `block_ids` is empty. ADR 0051 clarification
  B4 (an empty `desc` page returns the gap it started from) applies only to a page that read no entry.
  Without this exception, a `desc` walk over a run of at least `limit` denied blocks would receive the
  same cursor again and never end. A client sees an empty page with `more = true` and an advanced
  cursor, and continues the walk as for any page (rule 9).
- **L2. `/info` (rule 11).** Accepted 2026-11-21. The member `deny_list` is either `true` or absent. A relay without a deny
  list omits it; `sbtp-relay` never publishes `false`. A client reads `false` and an absent member
  alike.
- **L3. Line format of `deny_file` (rules 3 and 21).** Accepted 2026-11-21. Operator-facing, not wire. `sbtp-relay` reads
  the file strictly:
  - Lines are separated by `\n` (LF). The last line MAY end without `\n`. A line is at most 256 bytes,
    the `\n` not included.
  - The file is UTF-8 as a whole, comment lines included.
  - A line is empty (zero bytes), a comment (`#` in the first column, then any text), or an entry:
    `block <hex>`, `key <hex>`, optionally followed by ` hide` or ` purge`. `<hex>` is 64 lowercase
    hexadecimal characters. Fields are separated by exactly one space.
  - Anything else makes the whole file invalid (rule 4): a CR before the `\n` (CRLF line ends),
    leading or trailing whitespace, a tab, two spaces between fields, a line of only whitespace, a
    `#` after whitespace, upper-case hexadecimal, an unknown kind or action, a fourth field.
  - An entry is its kind and its value: `block X` and `key X` are two entries. The same entry twice
    with one action counts once; with two actions it makes the file invalid. `deny_max_entries`
    counts distinct entries (rule 21).
  - An invalid file is reported by line number and a fixed reason (`deny_list_invalid`, rule 20); the
    line's content is never logged.
