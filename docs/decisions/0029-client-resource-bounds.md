# 0029: Client resource bounds against an untrusted relay

- Status: accepted (by the project owner, 2026-11-19)
- Amended by: 0030 (rule 15, a `3xx` is a failed request); 0047 (rule 12: an own block stays protected until every relay of the list acknowledges it or is no longer pending, within bounds; eviction order of the local store)
- Date: 2026-11-19
- Questions: Q-26, client part only (partially resolved). The peer-exchange part stays open, post-MVP
- Amends: ADR 0012 rules 10, 14, 16 and 20 (response body ceilings; the members a relay MAY
  add count toward them) and rule 30 (a `Retry-After` that is not in seconds; a client's maximum wait).
  Nothing else in ADR 0012 changes. ADR 0018 is not amended: it bounds the relay, this ADR bounds the
  client
- Depends on: ADR 0003 (§3.4 receipt rule), ADR 0012 (`/query`, error body, `/info`, `Retry-After`;
  clarifications K1 and K3), ADR 0014 (`MAX_BLOCK_LEN` = 65,909), ADR 0024 (rule 8: `InvalidCursor`
  restarts a walk), ADR 0026 (difficulty applied on receipt: a local setting, never taken from `/info`)
- Does not decide: Q-28 (default difficulty; this ADR only requires that a sender has a maximum for a
  difficulty it reads from `/info`); redirects (Q-37; `cli-demo` follows none, ADR 0028 rule 52)
- Impact: spec §4 (response ceilings in `/info`, `/query` and "Errors"; one sentence in "Admission
  control"; new subsection "Client bounds"; see "Spec change", applied 2026-11-19); `examples/cli-demo` (already
  conforms at `b3c6b48`, see Consequences); `sbtp-wasm` and `web/` (Phase 3 web client); `sbtp-relay`
  (tests that assert the ceilings; no behaviour change expected); no `sbtp-core` change; no layer 0 test
  vector

## Context

ADR 0018 bounds what a relay spends. Nothing in the spec bounds a client. Q-26 lists what a relay that a
client does not trust can do to it, within the letter of spec §4:

- answer `/query` with `more = true` without end, or with identifiers of blocks that do not exist;
- send a body of any size: `/info`, `/query` and error bodies may carry members the client does not
  know, with no upper bound, and a reverse proxy may compress them;
- publish `min_pow_difficulty = 256` to a sender that mines at the relay's value, or send a
  `Retry-After` of several years;
- serve a valid DAG that is very deep or very wide. Blocks are cheap to mine at the default difficulty
  (about 11 ms at `d = 16`, ADR 0019), so this needs no relay misbehaviour: any publisher can build it;
- drip a response one byte at a time.

Spec §3.4 makes a client validate every block it fetches, with a difficulty of its own (ADR 0026). It
does not limit how many blocks the client fetches, keeps or walks.

`cli-demo query` (on `main`) already applies several bounds as implementation choices: a 131,072-byte
`/query` body limit, page checks, at most 1,000,000 identifiers per walk, a `Retry-After` maximum of
300 seconds, a 30-second request deadline, and no redirects. The web client needs the same. A third-party
client must know which of these a relay may rely on.

The Phase 3 web client runs in a browser tab: a few hundred MiB of memory at best, a storage quota set
by the browser, one main thread. It reads relays it does not operate.

Two constraints from `CLAUDE.md` frame the answer:

- **Spec only for what is shared.** A bound that one side can choose alone is an implementation detail.
  It is not a protocol value. The rule of ADR 0018, "the limits are local settings", is the starting
  point.
- **The MVP.** Decide what the web client needs before it reads a public relay, nothing more.

A bound becomes a protocol rule in two cases only:

1. both sides must agree on it, or they fail to interoperate. This is the case of a response size: a
   client that refuses a body a conforming relay may send breaks; a relay that sends more than every
   client accepts breaks too;
2. the protocol must say that a conforming client bounds something, because a hostile relay can
   otherwise exhaust it within the rules. The value stays local.

## Decision

### Scope

1. A **client** is any program that sends requests to the relay interface of spec §4: `cli-demo`, the
   web client, an application PWA, an indexer or a super-peer when it reads another relay. A client treats
   every relay, every reverse proxy in front of it and every static mirror as untrusted.
2. **Principle.** The memory, storage and time a client spends because of one relay are a function of the
   client's settings, not of what the relay sends. At a bound the client stops, keeps what it has
   validated, and reports a partial result. Reaching a bound is not a protocol error.
3. **Out of scope.** Peer exchange between clients (WebRTC, layer 1, Q-11, Q-21): connections and
   requests accepted per peer, bytes served per peer, concurrent transfers, refusal signalling outside
   HTTP. It is post-MVP and stays open under Q-26.

### Shared rule: response body ceilings

4. **Ceilings.** The body of a response on `/sbtp/v1/` is at most:

   | Response | Ceiling (bytes) | Origin |
   |---|---|---|
   | `200` of `GET /sbtp/v1/block/{block_id}` | 65,909 | `MAX_BLOCK_LEN` (ADR 0014). A longer body fails F2 anyway. |
   | `200` of `GET /sbtp/v1/query` | 131,072 | ADR 0012 rule 14 gives under 70 KiB without added members. |
   | `200` of `GET /sbtp/v1/info` | 16,384 | |
   | Any `4xx` or `5xx` | 16,384 | |

   The ceiling applies to the body after removal of any content coding (`Content-Encoding`), that is to
   the bytes the client parses.
5. **Relay side.** A relay, a reverse proxy configured for it and a static mirror MUST NOT send a body
   above its ceiling. The members a relay MAY add to `/query`, `/info` and error bodies (ADR 0012 rules
   10, 16 and 20) count toward the ceiling.
6. **Client side.** A client MUST accept every body at or under its ceiling. It MUST stop reading a body
   when its decoded length exceeds the ceiling, and MUST NOT read more than the ceiling plus one byte to
   find out. A `2xx` body above its ceiling is a failed request (rule 15). An error body above its
   ceiling is an unparseable error body: the client decides on the status code alone (spec §4, "Errors").
   A client MAY use a lower bound for an error body, since it may ignore that body.

### Client rules: what a client MUST bound

The values in rules 7 to 14 are client settings. The protocol requires the bound, not its value. Rule
16 gives non-normative starting values.

7. **Request deadline.** Every request MUST have a total time limit that covers the connection, the
   response head and the whole body. An idle-read timeout alone is not enough: a relay can send one byte
   per period without end. On expiry the request has failed (rule 15).
8. **`/query` response checks.** A client MUST treat a `200` response of `/query` as a failed request
   (rule 15) when:
   - it is not a JSON object, or `block_ids` is not an array, `cursor` not a string or `more` not a
     boolean;
   - `block_ids` holds more identifiers than the `limit` the client sent (100 when it sent none);
   - an identifier is not exactly 64 lowercase hexadecimal characters;
   - `cursor` is not 1 to 128 characters of `A-Z a-z 0-9 - _` (the syntax a relay MUST issue, ADR 0012
     clarification K1).

   The client MUST NOT use any identifier of such a response. A duplicate identifier is not a failure;
   the client deduplicates it (ADR 0012 rule 13).
9. **Walk bound.** A client MUST bound the number of pages, or of identifiers, it takes from one relay in
   one walk of `/query` (ADR 0012 rule 12). When it reaches the bound with `more = true`, it stops the
   walk, keeps the last cursor, and MAY continue later from it as a poll. A page with `more = true` may
   hold fewer than `limit` identifiers, none included; a client MUST NOT treat this as an error, and the
   page counts toward the bound. A restart after `InvalidCursor` (ADR 0024 rule 8) counts toward the same
   bound.
10. **Fetch bound.** The identifiers of a `/query` response are hints (ADR 0012 rule 13). A client MUST
    bound the number of blocks it fetches because of them, and the number of `GET /block` requests it
    has in flight per relay (spec §4 already asks for at most 8). A `404` counts toward the bound.
11. **Traversal bound.** A walk of the DAG from a block, through its parents or through its children,
    MUST be bounded by a number of blocks visited. A client MUST record the visited `block_id` values and
    visit each at most once: with up to 8 parents per block (ADR 0014), the number of paths through a
    valid DAG grows exponentially with its depth, while the number of blocks does not. A traversal MUST
    NOT use recursion whose depth depends on the DAG. At the bound the client shows a partial view.
12. **Memory and local storage.** A client MUST bound the blocks it holds in memory and in local storage
    (IndexedDB, OPFS, files) by its own settings. When it drops blocks to stay within its storage budget,
    it MUST NOT drop the user's private keys, nor a block the user created that no relay has yet
    acknowledged with `200` or `201`. Blocks fetched from relays are dropped first.
13. **Values published by `/info`.**
    - A client MUST treat an `/info` response as a failed request (rule 15) when `min_pow_difficulty` is
      not an integer from 0 to 256, or `max_future_ms` is not a non-negative integer that fits in a u64.
      Other members are checked only when the client uses them; a member out of its range is then
      treated as absent.
    - `min_pow_difficulty` serves a sender, before a `PUT`. The difficulty a client applies to a block it
      fetches is its own setting and never comes from `/info` (ADR 0026 rules 1 to 3). This ADR does not
      change that.
    - A sender that takes its mining difficulty from a relay's `/info` MUST have a maximum it accepts
      that way. When `min_pow_difficulty` is above it, the sender does not mine for that relay and
      reports it. A difficulty the user gives explicitly is not bound by this rule. The default of this
      maximum depends on Q-28 and is not set here.
14. **`Retry-After`.** This rule covers every status that may carry the header: `429`, `503`, and the
    `502` and `504` of a proxy (ADR 0012 clarification K3). A `Retry-After` that is not a `delay-seconds`
    value (RFC 9110 §10.2.3) gives the client no delay: the client either backs off as spec §4 says for a
    response without the header, or gives up the operation on that relay. A client MAY set a maximum
    wait. When `Retry-After` exceeds it, the client MAY give up the operation on that relay and use
    another one. It still MUST NOT repeat the request to that relay before `Retry-After` has elapsed.

### Failed requests and faulty relays

15. **Failed request.** A response that fails rule 6, 8 or 13, or a request that exceeds its deadline
    (rule 7), is treated like a network failure: nothing from it is used. The client MAY repeat the
    request after the back-off of spec §4, or MAY end the operation. A walk that ends this way keeps its
    last valid cursor. A block that fails the receipt rule of spec §3.4 is discarded and never stored.
16. **Guidance (non-normative).** Starting values for an interactive view in a browser: a request
    deadline of 30 seconds; at most 10,000 identifiers per walk; at most 1,000 blocks visited per
    traversal; a maximum `Retry-After` wait of 300 seconds. A command-line or indexing client may use
    larger walk bounds (`cli-demo` uses 1,000,000 identifiers). A client SHOULD count, per relay, the
    failed requests of rule 15 and the blocks that failed §3.4, and MAY stop using a relay that exceeds a
    threshold of its choice. A block that fails only the client's own difficulty floor is not counted:
    it does not show a relay fault (ADR 0026 rule 4). A client SHOULD tell the user when a view is
    partial because of a bound.

### What is left to implementations

17. The value of every bound of rules 7 to 14; the data structures (cache, LRU, visited set); what a
    client drops first among fetched blocks; the polling interval; whether a bound counts pages or
    identifiers; the number of consecutive retries (ADR 0012 clarification K3); the per-relay failure
    threshold; the user interface of a partial view. None of these is a protocol value. A change to them
    needs no ADR.

### Amended rules

18. **ADR 0012 rules 10, 16 and 20.** Each "A relay MAY add members" gains: "within the body ceiling of
    ADR 0029 rule 4".
19. **ADR 0012 rule 14.** Gains: "The body of a `/query` response, added members included, is at most
    131,072 bytes (ADR 0029)."
20. **ADR 0012 rule 30.** Gains: "A `Retry-After` that is not a `delay-seconds` value gives no delay: the
    client backs off as without it, or gives up the operation on that relay. A client MAY give up on a
    relay whose `Retry-After` exceeds its maximum wait (ADR 0029 rule 14)."

## Consequences

- **Interoperability.** One new shared fact: four body ceilings. `sbtp-relay` already conforms: its
  `/query` body is under 70 KiB, its `/info` and error bodies are a few hundred bytes, and it adds no
  member. A relay that adds members later has a budget of about 58 KiB on `/query` and 16 KiB elsewhere.
- **`cli-demo` at `b3c6b48` already conforms**, with no code change (`examples/cli-demo/src/relay.rs`,
  `walk.rs`, `commands.rs`):
  - rules 4 to 6: `MAX_BLOCK_LEN` for `get`, `MAX_QUERY_LEN` = 131,072 for `/query`, `MAX_JSON_LEN` =
    16,384 for `/info` and error bodies; `read_limited` reads at most the limit plus one byte. `ureq` is
    built without default features, so it does not decode content codings and the counted bytes are the
    parsed bytes;
  - rule 7: `timeout_global` of 30 seconds;
  - rule 8: `parse_page` checks the shape, the `limit` (`page_limit`, 100 by default, at most 1,000),
    the identifiers and the cursor syntax;
  - rule 9: `max_seen` (1,000,000 identifiers, the walk stops with a resume cursor), bounded restarts
    and retries;
  - rules 10 and 11: `query` prints identifiers and fetches no block; `get` fetches one; there is no
    traversal;
  - rule 13: `parse_info` checks both members; `MAX_RELAY_DIFFICULTY` = 24 bounds a difficulty read from
    `/info`, and an explicit `--difficulty` is not bound; `get` takes its difficulty from
    `--difficulty`, never from `/info` (ADR 0026);
  - rule 14: a `Retry-After` above 300 seconds or not in seconds ends the walk.

  Its help text MAY cite this ADR once it is accepted.
- **Web client.** It implements rules 4 to 15. It is the first client with a DAG traversal (rule 11) and
  a persistent store (rule 12).
- **Browser.** `fetch()` has no body size limit. The web client reads the body as a stream and counts
  bytes after decoding (rule 6); `Content-Length` is a hint only, since a proxy may omit it or compress.
  The deadline of rule 7 is an `AbortSignal` that covers the body read, not only the response head.
- **Security.** A hostile relay can no longer cost a conforming client more than its settings allow: no
  unbounded body, walk, fetch list, traversal, wait or mining effort. It can still waste a client's bound
  in each poll and serve invalid blocks that cost one verification each; both are bounded by rules 9 and
  10. It can withhold blocks; that is availability (Q-24), not resource use.
- **Storage eviction.** Rule 12 protects the user's keys and unpublished blocks from a relay that floods
  the local store. The rest of the eviction policy is the client's.
- **Tests.** Client tests against a hostile mock relay: a body at the ceiling (accepted) and one byte
  above (refused) for each of the four responses, compressed included where the HTTP stack decodes;
  `more = true` forever (the walk stops at its bound and keeps the cursor); a page with more identifiers
  than `limit`, a malformed identifier, a malformed cursor; `min_pow_difficulty` 257, and a value above
  the sender's maximum; `Retry-After` as a date and as a very large number; a body sent one byte per
  second (deadline); a diamond-shaped DAG of depth 40 (visited set). Relay tests that assert each body
  stays under its ceiling at `max_query_limit = 1000`. These are crate tests, not frozen test vectors.
- **Compatibility.** No wire format change, no layer 0 test vector, no frozen vector affected.

## Rejected alternatives

- **Every bound local, no shared rule.** Leaves the response size undefined: a client choosing 16 KiB
  for `/query` fails against a conforming relay at `limit = 1000`, and a relay adding members has no
  limit to respect. The ceilings are the one part both sides must know.
- **Normative values for the client bounds (walk, traversal, storage).** They depend on the device and
  on the view; a phone tab and an indexer need different values. A fixed value adds nothing to
  interoperability.
- **A `/query` ceiling of exactly 70 KiB.** Leaves no room for the members a relay MAY add, and makes
  the cursor length and every envelope byte a compatibility issue.
- **Publishing the ceilings in `/info`.** A client would have to trust a relay to tell it how much it
  may send, which is the problem. Fixed ceilings need no discovery.
- **Treating a short or empty page with `more = true` as a faulty relay.** A conforming relay may
  produce one (expired entries are skipped, ADR 0013 rule 14). The walk bound already ends the loop.
- **Treating a `Retry-After` that is not in seconds as absent, always.** `cli-demo` ends the walk
  instead, which is at least as safe. Both are allowed.
- **A client MUST honour any `Retry-After`, with no maximum.** Lets one relay stall an operation the
  client can complete elsewhere. The client still never repeats the request early.
- **A maximum difficulty for every block a client mines.** An explicit choice of the user is not an
  attack; only a value read from an unauthenticated `/info` needs a bound.
- **Deciding peer bounds now.** No peer exchange exists before the end of Phase 4; its transport and
  refusal signalling are not chosen (Q-11, Q-21).

## Spec change

Applied on acceptance (2026-11-19). In `docs/spec/sbtp-core-v0.2.md` §4:

1. **`GET /sbtp/v1/info`**, the line "A relay MAY add members. A client MUST ignore members it does not
   know. …" becomes: "A relay MAY add members; the body is at most 16,384 bytes. A client MUST ignore
   members it does not know. …"
2. **`GET /sbtp/v1/query`**, after "A relay MUST serve a request with work in `O(log n + limit)`.", add:
   "The response body is at most 131,072 bytes, members added by the relay included. (ADR 0029)"
3. **Errors**, after the first bullet, add: "- An error body is at most 16,384 bytes. (ADR 0029)"
4. **Admission control**, the bullet "A client MUST NOT repeat the request before `Retry-After` has
   elapsed. …" gains: "A `Retry-After` that is not a number of seconds gives no delay: the client backs
   off as without it, or gives up the operation on that relay. A client MAY give up on a relay whose
   `Retry-After` exceeds its maximum wait; it still does not repeat the request to it earlier."
5. New subsection after "Admission control":

   ```markdown
   ### Client bounds

   - A client treats every relay, proxy and mirror as untrusted. What it spends because of one relay
     (memory, storage, time, mining effort) depends on its own settings, not on what the relay sends.
     The values are client settings; the protocol requires the bounds. (ADR 0029)
   - Body ceilings, after removal of any content coding: `GET /block` 65,909 bytes; `/query` 131,072;
     `/info` 16,384; any `4xx` or `5xx` 16,384. A relay MUST NOT exceed them. A client MUST accept a
     body at or under its ceiling and MUST stop reading at the ceiling plus one byte. A `2xx` body above
     its ceiling is a failed request; an error body above it is unparseable.
   - Every request has a total time limit that covers the whole body.
   - A `/query` response is a failed request when it is not the object of this section, holds more
     identifiers than the `limit` sent, or holds a malformed identifier or cursor. None of its
     identifiers is used.
   - A client MUST bound the pages or identifiers of one walk, the blocks it fetches from hints, the
     blocks visited in one DAG traversal (each `block_id` at most once) and the blocks it keeps in
     memory and in local storage. At a bound it stops and keeps what it has validated; this is not an
     error. A page with `more = true` may be short or empty.
   - When it drops blocks to stay within its storage budget, a client MUST NOT drop the user's private
     keys, nor a block the user created that no relay has acknowledged with `200` or `201`.
   - An `/info` response whose `min_pow_difficulty` is not an integer from 0 to 256, or whose
     `max_future_ms` is not a non-negative u64, is a failed request. A sender that mines at the
     difficulty a relay publishes has a maximum it accepts that way; above it, it does not mine for that
     relay. The difficulty applied on receipt is the client's own (§3.3).
   - A failed request is treated like a network failure: nothing from it is used. The client backs off
     before repeating it, or ends the operation.
   - Peer-to-peer bounds are not specified in this version. `[Q-26]`
   ```

No change to §1 to §3 or §5. No change to `architecture.md` (its "Admission control" section describes
the relay).
