# 0054: Relay subscriptions over WebSocket

- Status: accepted (by the project owner, 2026-11-21), with the owner choices recorded in "Decisions of
  the project owner": binary delivery frames with JSON control messages; off by default
  (`ws_enabled = false`); a subscription share of at most half of `max_connections` and 4 / 8 / 16
  connections per client by profile; `ws_max_age_ms` of one hour; no relay-side catch-up from a `from`
  cursor
- Date: 2026-11-21
- Questions: Q-23 (resolved; submission over WebSocket is decided "not offered", rule 40); opens Q-84
  and Q-85; gives Q-65 (push delivery of a gateway feed) the shape to follow, without deciding it
- Amends: ADR 0012 rule 3 (a WebSocket route is now specified); ADR 0018 rules 22 (settings), 28
  (admission of an upgrade) and 35 (memory terms); ADR 0019 rules 29 and 30 (an upgraded connection
  leaves the per-client connection count), 37 and 38 (profile rows and policy settings) and 42 (what
  the reverse proxy forwards); ADR 0021 rule 41 (counters); ADR 0048 rule 3, item 2 (new total of the
  `small` bound with every function on); ADR 0053 API shape (`follow`). Nothing else in these ADRs
  changes
- Depends on: ADR 0012 (`/query`, errors), ADR 0013 (store order, positions), ADR 0018, ADR 0019,
  ADR 0020, ADR 0027 and ADR 0044 (admission, client key), ADR 0021 (privacy of logs), ADR 0024 (cursor
  epochs), ADR 0028 (TLS term), ADR 0046 (demand), ADR 0048 (replication), ADR 0049 (network groups),
  ADR 0050 (`read_only`), ADR 0051 (cursors as gaps, `head`, grouped weight, rule 30), ADR 0052 (deny
  list), ADR 0053 (client SDK)
- Impact: core spec §4 (the "WebSocket" part replaced by a route `GET /sbtp/v1/subscribe`, `/info`,
  admission control, client bounds); `architecture.md` §2 (admission control, a new part
  "Subscriptions"); `graph-access.md` §3 (pointer for Q-65); `sbtp-relay` (upgrade, fan-out,
  settings, metrics, memory bound); client SDK (`follow`); relay API vector set `relay-v1/` and
  client cases `client-v1/` (new cases, not frozen); a new frame vector set `subscribe-v1/`
  (planned); no wire format change of blocks, no layer 0 vector

## Context

The relay interface has no push. A client learns of new blocks only by polling `/query` with a cursor
(ADR 0012 rule 12, ADR 0051 "Completeness"). In practice:

- a server-side follower polls the relay-wide listing every 2 seconds;
- a browser polls each parent it shows every 5 to 60 seconds, with back-off, in grouped requests of up
  to 32 parents (ADR 0051 rule 26).

Every application with live views pays this cost, and most of these responses are empty pages. Each one
is still an index read under the `query` class, the class shed first (ADR 0018 rule 32).

Requirements already fixed:

- ADR 0051 rule 30: a subscription to new children of a parent set, at most 32 parents, identifiers
  only (optionally with the members of `fields=parents`), starting from a cursor such as `head`,
  delivered in store order with the parent of each identifier, resumable with `/query` `asc` from the
  last delivered gap with no hole, admitted with the grouped-query weight, and a bounded number per
  connection.
- A relay-wide subscription for indexers, with the same delivery and completeness semantics.
- A gap or a restart is signalled; the client resumes with `/query` from its last cursor.

The facts of this relay that shape the transport:

- `sbtp-relay` serves HTTP/1.1 only (ADR 0018 rule 27, ADR 0019 point 6), directly with built-in TLS
  (ADR 0028) or behind a reverse proxy that MAY offer HTTP/2 and HTTP/3 to clients.
- `small` has 32 connection slots and 8 per client (ADR 0019 rule 37).
- The `small` bound with every function on is 19,009,458 bytes, 990,542 bytes under the 20,000,000-byte
  budget (ADR 0052 rule 21, ADR 0048 rule 3, item 2). The default bound (every function off) is
  14,910,996 bytes, under the 15,000,000-byte target (ADR 0048 rule 3).
- Cursors name gaps in store order and are valid with any `parent`, `since`, `order` and `fields`
  (ADR 0051); `head` names the gap after the newest position.

The owner's preference (2026-11-21) is WebSocket. "Rejected alternatives" weighs it against
Server-Sent Events (SSE) and long polling with the facts above.

## Decision

### Route, upgrade and version

1. **Route.** `GET /sbtp/v1/subscribe` under the relay URL (ADR 0030), upgraded to a WebSocket
   connection (RFC 6455, version 13). The WebSocket URL is the relay URL with `https` replaced by `wss`
   (and `http` by `ws`), followed by `/sbtp/v1/subscribe`. No query parameter is defined; a request
   with a query string gets `400` (`InvalidParameter`).
2. **Subprotocol.** The client MUST offer the subprotocol `sbtp.subscribe.v1` in
   `Sec-WebSocket-Protocol`. The relay MUST select it in its `101` response. A request that does not
   offer it, or that is not a valid WebSocket upgrade (method, `Upgrade`, `Connection`,
   `Sec-WebSocket-Key`), gets `400` (`InvalidParameter`); a `Sec-WebSocket-Version` other than 13 gets
   `400` (`InvalidParameter`) with `Sec-WebSocket-Version: 13` (RFC 6455 §4.4). A client that gets a
   `101` without the subprotocol selected MUST close the connection and treat the attempt as failed.
   Other methods on the route get `405`. Error responses carry the JSON error body and
   `Cache-Control: no-store` (core spec §4, "Errors").
3. **The HTTP version.** The protocol depends on WebSocket semantics only. `sbtp-relay` accepts the
   HTTP/1.1 upgrade. A reverse proxy MAY accept WebSocket over HTTP/2 (RFC 8441) or HTTP/3 (RFC 9220)
   from clients and use the HTTP/1.1 upgrade towards the relay.
4. **No cookies, no authentication, no Origin check.** The rule of core spec §4 "CORS" holds: no
   cookie and no HTTP authentication on `/sbtp/v1/`. The relay does not refuse an upgrade because of
   its `Origin`; `cors_allow_origins` does not apply to the upgrade, as it is not access control.
5. **Discovery.** `/info` gains an optional member `subscribe`:

   ```json
   "subscribe": { "versions": [1], "max_subscriptions": 4, "tick_ms": 30000 }
   ```

   - `versions`: array of subscription protocol versions; this ADR defines `1`, which is
     `sbtp.subscribe.v1`. A later version gets the subprotocol `sbtp.subscribe.v<N>`, and the client
     offers the versions it implements in its preference order.
   - `max_subscriptions`: integer from 1 to 64, the subscriptions one connection may hold (rule 26).
   - `tick_ms`: integer from 5,000 to 120,000, the longest time the relay leaves a connection without
     a message (rule 31).
   - A relay MUST NOT publish `subscribe` unless it publishes `read_api` ≥ 2, and MUST NOT publish it
     with `read_only: true` (ADR 0050). A relay that does not publish it MUST NOT serve the route: the
     route then gets `404` (`NotFound`).
   - A client MUST read an absent member, or a member that is not an object of this shape, as "no
     subscriptions", and MUST NOT open the route then. It ignores unknown members of the object.
   - A client MUST NOT open the route on a relay whose `versions` holds no version it implements.

### Messages

6. **Directions and frame types.** Client to relay: text frames only, each one JSON object (rule 7). A
   binary frame from the client closes the connection with code 1003. Relay to client: text frames
   for control messages (rule 8) and binary frames for deliveries (rule 9). The order of frames on one
   connection is the order in which the relay sends them, whatever their type.
7. **Client messages.** UTF-8 JSON (RFC 8259), at most 4,096 bytes per message, one of:

   ```json
   { "op": "subscribe", "sub": 7, "parents": ["<64 hex>", "…"], "fields": "parents" }
   { "op": "subscribe", "sub": 8, "all": true }
   { "op": "unsubscribe", "sub": 7 }
   ```

   - `sub`: integer from 1 to 4,294,967,295, chosen by the client, unique among the open
     subscriptions of the connection.
   - `parents`: 1 to 32 distinct `block_id` values, 64 lowercase hexadecimal characters each. `all`:
     the value `true`, the relay-wide subscription. A `subscribe` carries exactly one of the two.
   - `fields`: optional, the value `parents` (rule 9).
   - A message larger than 4,096 bytes closes the connection with code 1009. A text frame that is not
     a JSON object closes it with code 1007. A JSON object with an unknown `op`, an unknown member, a
     missing or malformed member, a duplicate `sub`, or an `unsubscribe` of a `sub` that is not open
     gets an `error` with `InvalidParameter` (rule 8); the connection stays open.
8. **Relay control messages.** UTF-8 JSON objects, at most 1,024 bytes each:

   ```json
   { "op": "subscribed", "sub": 7, "start": "<cursor>" }
   { "op": "unsubscribed", "sub": 7 }
   { "op": "gap", "sub": 7, "cursor": "<cursor>" }
   { "op": "tick", "cursor": "<cursor>" }
   { "op": "error", "sub": 7, "error": "RateLimited", "retry_after": 2, "message": "…" }
   ```

   - Every cursor is a `/query` cursor of the relay (syntax of core spec §4, at most 128 characters).
   - `error`: `sub` is present when the error concerns one `subscribe` or `unsubscribe`. `error` is one
     of the names of core spec §4, "Errors": `InvalidParameter`, `RateLimited` (with `retry_after`, a
     whole number of seconds, at least 1), `Unavailable`. `message` follows the rules of the error body
     (at most 200 characters, for humans only). No new error name is defined.
   - A client MUST ignore unknown members and text messages with an unknown `op`, and MUST ignore a
     binary frame whose first byte is not a type it knows.
9. **Delivery frame.** Binary, all integers big-endian (ADR 0001), at most 65,536 bytes:

   | Offset | Size | Field |
   |---|---|---|
   | 0 | 1 | type: `0x01` (delivery) |
   | 1 | 4 | `sub` (u32) |
   | 5 | 1 | flags: bit 0 = `fields` (each entry carries parents and length); bit 1 = `mask` (each entry carries a match mask); other bits 0 |
   | 6 | 1 | `c`, cursor length, 1 to 128 |
   | 7 | `c` | cursor, ASCII, syntax of a `/query` cursor |
   | 7 + `c` | 2 | `n`, entry count, at least 1 (u16) |
   | 9 + `c` | … | `n` entries |

   Each entry, in this order:
   - `block_id`: 32 bytes;
   - if `mask`: 4 bytes (u32); bit `i` (bit 0 the least significant) is set when the block lists the
     `i`-th value of the subscription's `parents` (in the order of the `subscribe` message) among its
     Parents Hashes. At least one bit is set, and no bit at or above the number of parents;
   - if `fields`: 1 byte `p` (0 to 8), then `p` × 32 bytes of Parents Hashes in header order, then the
     block's length in bytes (u32, 1 to 65,909).

   `mask` is set exactly for a parent subscription, `fields` exactly when the `subscribe` asked for
   them. The cursor names the gap after the last entry of the frame, in store order. The frame ends
   exactly after its `n`-th entry.
10. **A malformed relay frame.** A client MUST treat as failed a delivery frame that breaks rule 9 (a
    length, count, flag, mask or field out of range, a truncated entry, trailing bytes, a cursor out
    of syntax, a frame over 65,536 bytes, a `sub` it has not subscribed and not just unsubscribed), a
    control message over 1,024 bytes, or one that is not a JSON object. It uses nothing from that
    frame, closes the connection with code 1002, and continues as after any close (rule 21). A client
    MUST stop reading a message at its bound plus one byte.

### Subscriptions

11. **What a subscription matches.** A parent subscription matches every block that lists at least one
    of its parents among its Parents Hashes. The relay-wide subscription matches every block. The
    relay does not need to hold a parent.
12. **What enters a subscription.** A block is delivered when it takes a new position in the relay's
    store order after the subscription's start: a `PUT` answered `201`, a block stored by replication
    (ADR 0048) or by read-through (ADR 0050). A `PUT` answered `200` delivers nothing. A block
    re-submitted after expiry takes a new position (ADR 0043) and is delivered again. The set
    delivered is the set that `/query` `asc` from `start` with the same filter would list.
13. **Visibility.** The relay MUST NOT deliver a `block_id` before `/query` lists it and
    `GET /sbtp/v1/block/{block_id}` serves it.
14. **Start.** On a valid `subscribe` the relay registers the subscription and answers `subscribed`
    with `start`: a cursor for the gap after the last position the relay had evaluated for delivery
    when it registered the subscription. Every matching block stored after `start` is delivered, in a
    delivery frame or covered by a `gap` (rule 18). The `subscribed` message precedes every frame of
    that subscription. The relay reads no index to start a subscription.
15. **Catch-up is the client's.** The relay does not deliver blocks stored before `start`. A client
    that holds a cursor `C` older than `start` (for example the `head` of its last `/query`) walks
    `/query` `asc` from `C` with the same filter until `more = false`, after it receives `subscribed`,
    and deduplicates the walk and the deliveries by `block_id`. It MAY skip the walk when `start` is
    the same string as `C`.
16. **Order.** The entries of one subscription are delivered in store order, oldest first, each at most
    once between two gaps. There is no order between subscriptions. A block that matches several
    subscriptions of one connection is delivered once to each. A client MUST NOT derive application
    state from the order (core spec §4, `/query`).
17. **Unsubscribe.** On `unsubscribe` the relay removes the subscription and answers `unsubscribed`.
    No frame of that `sub` follows `unsubscribed`; a client ignores a frame of a `sub` it has
    unsubscribed and for which it has not yet received `unsubscribed`. There is no message that
    changes a subscription: a client that changes the parents it follows subscribes the new set, then
    unsubscribes the old one, and deduplicates.

### Gaps, overflow, restarts and cursors

18. **Overflow.** The relay bounds the bytes queued for sending on each connection (rule 29). When a
    delivery does not fit, the relay drops it and every later delivery of that subscription until it
    can queue a `gap` message for it. The `gap` carries the cursor of the last frame of that
    subscription that it queued, or `start` when there was none. The relay MUST send the `gap` before
    any later frame of that subscription, and then continues delivery live. It MUST NOT hold more than
    its bound to avoid a gap. The same applies to every subscription of the relay when its internal
    fan-out falls behind (rule 34).
19. **What a gap means.** After a `gap`, the client walks `/query` `asc` from the gap's cursor, with the
    subscription's filter (grouped when several parents), until `more = false`, and deduplicates with
    the deliveries that follow. Until that walk ends, the subscription is incomplete.
20. **Slow consumer.** A relay MAY close a connection whose subscriptions keep overflowing, or whose
    queue stays full for 2 × `tick_ms`, with code 1008. It never queues without bound.
21. **Any close.** Subscriptions do not survive their connection; the relay keeps nothing of them
    after a close. After any close (any code, or a lost transport), the client resumes each
    subscription from its resume point (rule 22) with `/query` `asc` as in rule 19, and MAY open a new
    connection and subscribe again (rule 15). It reconnects with exponential back-off and jitter,
    starting at 1 second, and obeys `Retry-After` on a refused upgrade (core spec §4, "Admission
    control"). After code 1002, 1003, 1007, 1008 or 1009 it SHOULD NOT reconnect automatically before
    its longest back-off and SHOULD poll instead.
22. **Resume point.** The resume point of a subscription is, of the cursors received for it, the one
    received last: `start`, the cursor of each delivery frame, the cursor of a `gap`, and the cursor
    of a `tick` (rule 31) received while no gap of that subscription is unresolved. These are `/query`
    cursors: they are valid with any `parent`, `order` and `fields`, survive a clean restart and are
    subject to `InvalidCursor` after an unclean shutdown (ADR 0024). A walk that gets
    `InvalidCursor` follows the existing rule: walk again without a cursor and deduplicate by
    `block_id` (core spec §4, `/query`).
23. **Shutdown.** A relay that stops closes each connection with code 1001. A client reads 1001 as
    rule 21 and reconnects with back-off and jitter: every client of the relay sees it at once.
24. **Completeness.** A parent set followed by subscription is complete at a resume point when the
    connection is open, the catch-up walk of rule 15 and every walk of rule 19 ended with
    `more = false`, and no gap is unresolved. This is the condition of ADR 0051 "Completeness" for
    the polled case, with the subscription in place of polling from `head`. Over several relays the
    rule of core spec §4 holds: complete only when every relay of the list is complete.

### Admission and limits

25. **Upgrade admission.** The upgrade request goes through ADR 0018 rule 28:
    1. connection accepted under `max_connections`;
    2. head read under `header_timeout_ms` and `max_header_bytes`;
    3. client key (ADR 0018 rule 20, ADR 0020, ADR 0044: from the peer, `X-Forwarded-For` or
       `client_ip_header`) and one `query` token: `429`;
    4. head checks of rules 1 and 2 (`400`, `404`, `405`);
    5. readiness: `503`;
    6. the subscription class: the client key already holds `ws_max_connections_per_client`
       subscription connections, or its network group (rule 28) its share: `429` `RateLimited` with
       `Retry-After` (at least 30 seconds); the relay holds `ws_max_connections`: `503` `Unavailable`
       with `Retry-After: shed_retry_after_s`;
    7. `101 Switching Protocols`.

    The client key of a connection is fixed at its upgrade. A key in `rate_limit_exempt` skips step 6
    for the per-client and group bounds, not for `ws_max_connections`.
26. **Subscribe admission.** Each `subscribe` takes `⌈N/8⌉` tokens of the client key's `query` bucket
    (`N` the number of entries of `parents`, at least 1; 4 for `all`), capped at the burst, before it is
    checked, as a `/query` with `N` parents (ADR 0051 rule 26 and clarification B2). Without the tokens
    it gets `error` `RateLimited` with `retry_after`, and nothing is registered. A connection holds at
    most `ws_max_subscriptions` subscriptions, the value of `/info` `max_subscriptions`; one more gets
    `error` `InvalidParameter`. `unsubscribe` takes no token.
27. **Connection counting.** A subscription connection counts in `max_connections` for its whole
    life, and at most `ws_max_connections` connections are subscription connections. From its `101`
    it no longer counts in `max_connections_per_client` (ADR 0019 rule 29) nor as a request in flight
    (ADR 0019 rule 30); it counts in `ws_max_connections_per_client` of its client key instead. Its
    count lives with the limiter state: an entry with a count above 0 is not dropped by the bound of
    `rate_limit_max_clients`, and connections attributed to the overflow key share one count (ADR 0019
    rule 31, ADR 0027).
28. **Network groups.** A network group (ADR 0049: an IPv6 /48, an IPv4 /24; a level not shorter than
    `client_ipv6_prefix` is skipped) holds at most `⌈ws_max_connections × ws_group_share_pct / 100⌉`
    subscription connections.
29. **Per-connection memory.** The relay MUST set explicitly the WebSocket codec's read buffer, write
    buffer, maximum message and maximum frame sizes. It accepts client messages of at most 4,096 bytes
    and queues at most `WS_SEND_BYTES` (65,536 bytes, a constant) for sending on one connection,
    delivery frames, control messages and the frame in progress included. The per-connection total
    (read buffer, largest client message, send queue) MUST NOT exceed the per-connection term of
    ADR 0018 rule 35 (`max_header_bytes + largest response`, 88,064 bytes with the defaults); when an
    operator's settings make it exceed, the excess times `ws_max_connections` is added to the bound.
    With TLS on, a subscription connection is a TLS connection already counted by ADR 0028 rule 36.
30. **Settings.** Added to the table of ADR 0018 rule 22, validated as ADR 0018 rules 6 and 7 and
    ADR 0019 rule 36:

    | Setting | Default | Range | Kind |
    |---|---|---|---|
    | `ws_enabled` | `false` | boolean | policy |
    | `ws_max_connections` | 16 / 128 / 2,048 | 1 to `⌊max_connections / 2⌋` | profile row |
    | `ws_max_connections_per_client` | 4 / 8 / 16 | 1 to `ws_max_connections` | profile row |
    | `ws_max_subscriptions` | 4 / 8 / 8 | 1 to 64 | profile row |
    | `ws_group_share_pct` | 25 | 1 to 100 | policy |
    | `ws_ping_interval_ms` | 30,000 | 5,000 to 120,000 | policy |
    | `ws_max_age_ms` | 3,600,000 | 60,000 to 86,400,000 | policy |

    A value outside its range, or `ws_max_connections > ⌊max_connections / 2⌋`, stops the start-up
    with `config_error`. With `ws_enabled = false` the relay serves no route of this ADR, publishes no
    `subscribe` member and adds no memory term.

### Timers

31. **Ticks and pings.** Every `ws_ping_interval_ms` the relay sends a WebSocket ping on each
    subscription connection and, when it sent nothing else on it during that interval, a `tick`. The
    `tick` cursor names the gap after the last position the relay had evaluated for that connection.
    The relay MUST NOT send a `tick` while a `gap` of that connection is pending, nor before the frames
    of every position up to the tick's. `/info` `tick_ms` is `ws_ping_interval_ms`.
32. **Liveness.** The relay closes a connection, with code 1001 or without a close frame, when no pong
    or other frame arrives within `ws_ping_interval_ms` after a ping. A client considers a connection
    dead when it receives nothing for 3 × `tick_ms`, and then proceeds as rule 21. A browser client
    cannot see pings; ticks are its liveness signal.
33. **Idle and age.** A connection with no open subscription for `idle_timeout_ms` (ADR 0018 rule 26)
    is closed with code 1000. A connection is closed with code 1000 at `ws_max_age_ms`, so that slots
    turn over (ADR 0019 point 10); the client proceeds as rule 21. `request_timeout_ms` ends at the
    `101`. `max_requests_per_connection` and `max_connection_age_ms` do not apply after the `101`.

### Fan-out and memory bound

34. **Fan-out.** The relay evaluates new positions for delivery in store order, after the index commit
    (rule 13), off the index writer's path: the writer never waits for a subscriber. The queue between
    the writer and the fan-out holds at most 256 entries. When it is full, the relay drops the new
    entries and every open subscription gets a `gap` (rule 18). Matching costs one lookup per Parents
    Hash of the block (at most 8) in a table keyed by parent, plus the relay-wide subscriptions: no
    index read and no block read.
35. **Memory terms of ADR 0018 rule 35**, estimates, added only when `ws_enabled` is `true`:

    ```
    + ws_max_connections × ws_max_subscriptions × 5,184     (subscription registry)
    + 256 × 320                                             (fan-out queue)
    + ws_max_connections × 128                              (network group counts)
    ```

    5,184 bytes per subscription: 32 parent entries of 128 bytes (a 32-byte key and a reference in a
    table at most half full) and 1,088 bytes of subscription state (its parent list and counters).
    320 bytes per queued entry: the `block_id`, the position, up to 8 Parents Hashes and the length.
    The connection term already covers the buffers of rule 29. The 60-second `VmHWM` runs replace the
    estimates (ADR 0048 rule 3, item 2).

    | Profile | Subscription term |
    |---|---|
    | `small` | 16 × 4 × 5,184 + 81,920 + 2,048 = 415,744 bytes |
    | `standard` | 128 × 8 × 5,184 + 81,920 + 16,384 = 5,406,720 bytes |
    | `large` | 2,048 × 8 × 5,184 + 81,920 + 262,144 = 85,278,720 bytes |

    `small` with every function on: 19,009,458 + 415,744 = 19,425,202 bytes, 574,798 bytes under the
    20,000,000-byte budget. The default bound (`ws_enabled = false`) is unchanged: 14,910,996 bytes.

### Privacy and logs

36. **What the relay learns.** For the life of a connection, the relay holds the parent sets that one
    client key follows, and sees each change. Polling reveals the same sets at each request; a
    subscription holds them continuously, for up to `ws_max_age_ms`, and links the changes of one
    connection. The relay-wide subscription reveals no parent. A relay MUST keep subscription state
    in memory only, MUST NOT write it to disk, and forgets it at the close. Reducing what a
    subscription reveals is left open (Q-85).
37. **Logs.** ADR 0021 applies. A parent, a cursor, a `sub` value or any other content of a client
    message is never logged, at any level. No line is written per connection or per message at `info`
    or above. At `debug`, the events `ws_open` and `ws_close` MAY carry counts, durations and the close
    code, and the client tag of ADR 0021 rule 13 when it is on.
38. **Counters** (ADR 0021 rule 41, labels from fixed sets only): `ws_connections_open` (gauge),
    `ws_subscriptions_open` (gauge, label `kind`: `parents`, `all`), `ws_frames_sent_total`,
    `ws_entries_sent_total`, `ws_gaps_total` (label `cause`: `queue`, `fanout`), `ws_closed_total`
    (label `code`: `1000`, `1001`, `1002`, `1003`, `1007`, `1008`, `1009`, `1011`, `none`). Refused
    upgrades count in `http_refused_total` with the reasons `ws_client`, `ws_group` and `ws_full`.

### Interactions

39. **Demand eviction (ADR 0046).** A subscription, a delivery and a `tick` are not demand. A subscribed
    parent is not protected from eviction. The `GET` or batch that follows a delivery is demand as
    usual.
40. **Submission.** This version offers no submission over the connection. `PUT /sbtp/v1/block` stays
    the only write, with its pipeline, status codes and admission.
41. **Replication (ADR 0048).** There is no feed for peers. A replicating relay MAY use the relay-wide
    subscription of a peer as a signal to poll that peer earlier; it then sends `Sbtp-Replication: 1`
    on the upgrade, still fetches through its replication path and never treats a delivery as a
    block. `sbtp-relay` keeps polling every `replication_poll_ms` in this version (Q-84).
42. **Deny list (ADR 0052).** The relay MUST NOT deliver a block it denies, by `block_id` or by public
    key, at the time of the fan-out; the header is in hand, so the key check costs nothing. A block
    denied later is not withdrawn: its fetch gets `451`.
43. **Read-only URLs (ADR 0050).** A `read_only` URL has no subscription route (rule 5). An archive
    relay that is not `read_only` MAY offer subscriptions.
44. **Client SDK (ADR 0053).** `follow(parents, from)` uses a subscription when the relay publishes
    `subscribe` with a version it implements and the transport allows WebSocket; otherwise, and after a
    refused upgrade, it polls as today. Both feed the same stream with the same completeness report.
    The SDK holds at most one subscription connection per relay, spreads its parent sets over the
    subscriptions of that connection, and falls back to polling for a set the relay refuses.

### Reverse proxy and CDN

45. **Function required.** ADR 0019 rule 42 is amended: when `ws_enabled` is `true`, the reverse proxy
    MUST forward the WebSocket upgrade on `/sbtp/v1/subscribe` (the `Upgrade` and `Connection` fields
    towards the relay), MUST keep an upgraded connection open while frames flow at least every
    `ws_ping_interval_ms`, and MUST NOT apply to that route a rule that clears the `Connection` field
    for keep-alive pooling.
46. **Client address.** The client key comes from the upgrade request, under the rules of
    `trusted_proxies`, `X-Forwarded-For` and `client_ip_header` (ADR 0020, ADR 0044). A CDN in front
    passes the upgrade where its operator enables WebSocket; it does not cache it. Its own idle
    timeout for upgraded connections MUST be longer than `ws_ping_interval_ms`.
47. **Caching.** A shared cache MUST NOT store a response of this route. A cache rule for blocks still
    matches `/sbtp/v1/block/` with its trailing slash (ADR 0051 clarification B9), which does not match
    `/sbtp/v1/subscribe`.

## Consequences

### Expected load

| Case | Polling today | Subscription |
|---|---|---|
| Server-side follower, relay-wide | 30 `/query` per minute, each one index read, mostly empty | 1 upgrade, 4 tokens, one frame per batch of new blocks, a `tick` every 30 s |
| Browser view of 32 parents, poll every 5 s | 12 grouped `/query` per minute (48 tokens) | 1 upgrade and 4 tokens per view change, then frames only when children arrive |
| Connection slots | about one keep-alive connection per active client (5 s polling under a 30 s idle timeout) | one subscription connection per client, plus HTTP connections for fetches |

The index work of empty pages disappears. Slot use is about the same as polling with keep-alive; the
subscription share (half of `max_connections`) keeps the other half for HTTP.

### Implementation

- `sbtp-relay`: the upgrade route behind `ws_enabled`; a fan-out task fed by the index writer after
  commit; the registry keyed by parent; per-connection send queue with gap state; ticks, pings, idle
  and age timers; admission (step 6 of rule 25, counts of rules 27 and 28); settings, profile rows,
  memory terms and counters; close with 1001 at shutdown. The WebSocket codec comes from a new
  dependency or from a feature of an existing one (for example the WebSocket feature of the HTTP
  framework, which pulls a WebSocket codec and SHA-1 for the handshake only). It goes through the
  supply-chain rules and `security-auditor` as any parser of network input.
- Client SDK: a subscription state machine in the sans-I/O core (resume points, gap and catch-up walks,
  completeness); a browser WebSocket adapter in TypeScript; an optional adapter for the Rust crate,
  behind a feature.
- No change to `sbtp-core` or `sbtp-l2`.

### Security

- Push removes no bound: every pushed identifier is a hint; the client fetches and validates each block
  (§3.4), as with `/query`.
- A hostile client holds at most `ws_max_connections_per_client` connections, `ws_max_subscriptions`
  subscriptions on each and 32 parents on each, all paid in `query` tokens; its group holds at most its
  share. The relay's memory is bounded by rules 29 and 35 whatever the client reads or does not read.
- Cross-site pages can open subscription connections from a visitor's browser, as they can send
  `fetch` requests today: the data is public and no credential is involved. The per-client bound
  applies.
- Amplification is bounded by the ingest bounds (ADR 0049): each stored block is delivered at most once
  per matching subscription.

### Compatibility

Additive. A relay without the member keeps working with every client; a client without WebSocket
support polls. ADR 0012 rule 3 is replaced: the route of this ADR is the only WebSocket endpoint under
`/sbtp/v1/`, and only when `/info` publishes `subscribe`.

## Decisions of the project owner (2026-11-21)

1. **Delivery encoding.** Deliveries are binary frames and control messages are JSON text (rules 6
   to 9). A delivery is 2.1 to 2.2 times smaller than hexadecimal JSON (32 bytes per identifier
   against about 70; 297 bytes against about 640 with `fields`) and is read without a JSON parser.
   JSON text for everything, with hexadecimal identifiers as in `/query`, is rejected: one encoding,
   easier to inspect, but more bytes and a JSON parse per frame.
2. **Default.** `ws_enabled` is `false` by default; an operator enables subscriptions (rule 30). The
   15 MB default target of `small` holds: with the function on, 14,910,996 + 415,744 = 15,326,740 bytes
   would exceed it. Subscriptions on by default, with the 15 MB target raised or `small` rows lowered,
   is rejected.
3. **Share and per-client bound.** Subscription connections take at most half of `max_connections`
   (16 of 32 on `small`), and `ws_max_connections_per_client` is 4 / 8 / 16 on `small` / `standard` /
   `large` (rule 30).
4. **Connection age.** `ws_max_age_ms` is one hour (rule 33). A shorter age turns slots over faster and
   costs one catch-up walk per reconnect.
5. **Catch-up by the relay.** Not offered: the relay starts a subscription at `start` and the client
   walks `/query` (rule 15). A `from` cursor with a relay-side catch-up stays rejected (see "Rejected
   alternatives").

## Spec change on acceptance

**Core spec §4, "WebSocket"** is replaced by a part `### GET /sbtp/v1/subscribe (WebSocket)`:

> - Optional. A relay that publishes `subscribe` in `/info` serves it; another relay answers `404`
>   (`NotFound`). A relay without `read_api` ≥ 2, or with `read_only`, MUST NOT publish it.
> - A WebSocket upgrade (RFC 6455, version 13) of `GET /sbtp/v1/subscribe` under the relay URL; `wss`
>   for `https`. The client offers the subprotocol `sbtp.subscribe.v1` and the relay selects it. An
>   invalid upgrade, a query string or a missing subprotocol gets `400` (`InvalidParameter`); a
>   `Sec-WebSocket-Version` other than 13 also gets `Sec-WebSocket-Version: 13`. A `101` without the
>   subprotocol is a failed request. No cookie, no authentication; `Origin` is not checked. The
>   protocol does not depend on the HTTP version that carries the upgrade.
> - Client to relay: text frames, one JSON object each, at most 4,096 bytes: `subscribe` (`sub` 1 to
>   2^32 − 1, unique on the connection; `parents`, 1 to 32 distinct `block_id` values, or `all: true`;
>   optional `fields: "parents"`) and `unsubscribe` (`sub`). A binary frame closes with 1003, a frame
>   that is not a JSON object with 1007, a larger message with 1009. A malformed or refused message gets
>   `error`; the connection stays open.
> - Relay to client: text control messages, JSON, at most 1,024 bytes: `subscribed` (`sub`, `start`),
>   `unsubscribed` (`sub`), `gap` (`sub`, `cursor`), `tick` (`cursor`), `error` (`sub` when it applies,
>   `error`: `InvalidParameter`, `RateLimited` with `retry_after` in seconds, or `Unavailable`;
>   optional `message`). Binary delivery frames, big-endian, at most 65,536 bytes: type `0x01`, `sub`
>   (u32), flags (bit 0 `fields`, bit 1 `mask`), cursor length (1 to 128) and cursor, entry count
>   (u16, at least 1), then per entry the `block_id` (32 bytes), a match mask (u32, bit `i` for the
>   `i`-th parent of the subscription) for a parent subscription, and with `fields` the parent count
>   (0 to 8), the Parents Hashes in header order and the length (u32). Every cursor is a `/query`
>   cursor. A client ignores unknown members, unknown `op` values and unknown frame types.
> - A subscription delivers, in store order, each block that takes a new position after `start`
>   (`201`, replication, read-through) and matches it: one of its parents in Parents Hashes, or every
>   block for `all`. The set is what `/query` `asc` from `start` with the same filter lists. A block is
>   delivered only once `/query` lists it and `GET /block` serves it, never when the relay denies it,
>   and never from before `start`: a client with an older cursor walks `/query` `asc` from it to
>   `more = false` after `subscribed`, and deduplicates.
> - When the relay cannot queue a delivery it drops it and later ones of that subscription, then sends
>   `gap` with the cursor of the last frame it queued for it (or `start`) before any later frame. The
>   client walks `/query` `asc` from that cursor to `more = false`. The relay MAY close a connection that
>   keeps overflowing (1008). Subscriptions end with their connection; after any close the client walks
>   from each subscription's resume point (the last cursor received for it: `start`, frame, `gap`, or
>   `tick` while no gap is unresolved) and MAY subscribe again with back-off. `InvalidCursor` on that
>   walk follows the `/query` rule. A relay that stops closes with 1001.
> - A followed set is complete when the connection is open, every catch-up walk ended with
>   `more = false` and no gap is unresolved.
> - The relay sends a `tick` when it sent nothing for `tick_ms`, and pings. A client treats a connection
>   with nothing received for 3 × `tick_ms` as closed. A connection with no subscription for the idle
>   time of the relay, or older than its maximum age, is closed with 1000.
> - Admission: the upgrade takes one `query` token; each `subscribe` takes `⌈N/8⌉` `query` tokens (`N`
>   parents; 4 for `all`). A relay bounds subscription connections in total, per client and per network
>   group, and subscriptions per connection (`max_subscriptions`). An upgrade over a per-client or
>   group bound gets `429` with `Retry-After`; over the total, `503`. A relay bounds the bytes it queues
>   per connection.
> - A subscription, a delivery and a `tick` are not demand (ADR 0046). There is no submission over the
>   connection. A replicating relay that subscribes sends `Sbtp-Replication: 1`. A shared cache MUST NOT
>   store a response of this route.
> - (ADR 0051, ADR 0054)

**Core spec §4, `/info`**, a new member after `deny_list`:

> - `subscribe`: object `{ "versions": [1], "max_subscriptions": n, "tick_ms": t }`, present when the
>   relay serves `GET /sbtp/v1/subscribe`. `max_subscriptions` from 1 to 64, `tick_ms` from 5,000 to
>   120,000. A client MUST read an absent or malformed member as "no subscriptions" and MUST NOT open the
>   route then, nor when `versions` holds no version it implements. (ADR 0054)

**Core spec §4, "Admission control"**, one bullet:

> - A subscription connection (`GET /sbtp/v1/subscribe`) counts in the relay's connection cap and, from
>   its upgrade, in a per-client bound of subscription connections instead of the per-client
>   connection bound. Its client key is the one of its upgrade request. (ADR 0054)

**Core spec §4, "Client bounds"**, one bullet:

> - A subscription client MUST bound its subscriptions per relay, MUST stop reading a message at its
>   bound plus one byte (65,536 bytes for a delivery frame, 1,024 for a control message), and MUST treat
>   a frame that breaks the frame layout as failed: nothing from it is used and it closes with 1002.
>   Every delivered identifier is a hint: the client fetches and validates the block (§3.4). (ADR 0054)

**Core spec §4, "Several relays (non-normative)"**, one bullet:

> - A client that follows the same parents on several relays holds one subscription connection per
>   relay that offers it and polls the others; it deduplicates by `block_id` and keeps one resume point
>   per relay. (ADR 0054)

**`architecture.md` §2**, a new part `### Subscriptions` after "Admission control":

> - Optional (`ws_enabled`, off by default). One fan-out task, fed by the index writer after commit
>   through a queue of 256 entries, matches each new position against a table keyed by parent and the
>   relay-wide subscriptions. No index or block read; the writer never waits for a subscriber.
> - Each connection queues at most 65,536 bytes; an overflow becomes a `gap`, never memory. The memory
>   terms are added to the computed bound only when the function is on; `small` with every function on
>   stays under 20 MB. Subscription state lives in memory only and is never logged. (ADR 0054)

and in "Admission control", the bullet on `max_connections_per_client` gains: "A subscription
connection counts in `ws_max_connections_per_client` instead, from its upgrade. (ADR 0054)"

**`graph-access.md` §3**, the sentence on push delivery reads: "Push delivery `[Q-65]` follows the
shape of the relay's subscriptions (core spec §4, `GET /sbtp/v1/subscribe`)."

## Test vectors (plan, not frozen)

- `subscribe-v1/`: delivery frames as hexadecimal with their decoding: one relay-wide entry, a parent
  subscription with a mask, `fields` with 0 and 8 parents, the largest frame. Negative frames, each
  discriminating one criterion: count above the entries present, trailing byte, `p` = 9, length 0 and
  65,910, mask 0, mask bit at the number of parents, unknown flag bit, cursor length 0 and 129, cursor
  with a character out of syntax, frame of 65,537 bytes, `mask` set on a relay-wide subscription.
- `relay-v1/`: upgrade refusals (`400` without subprotocol, with a query string, version 8; `404` when
  off; `429` at the per-client bound; `503` at the total); `subscribe` errors (33 parents, duplicate,
  upper-case hex, `parents` with `all`, unknown member, over `max_subscriptions`, no tokens); a block
  stored after `start` is delivered and one stored before it is not; a `200` re-`PUT` delivers nothing;
  a denied block is not delivered; overflow gives one `gap` whose cursor, walked with `/query`, returns
  every dropped block; close 1001 at shutdown.
- `client-v1/`: `follow` with a subscription: catch-up walk from an older `head`; gap then walk; close
  then resume from the tick cursor; refused upgrade falls back to polling; malformed frame closes with
  1002 and nothing from it is used.

## Rejected alternatives

### Server-Sent Events (SSE)

SSE (`text/event-stream`, one long `GET` per stream) was weighed point by point.

| Fact | Favours | Why |
|---|---|---|
| HTTP/1.1 only at the relay | WebSocket, partly | A browser opens about 6 HTTP/1.1 connections per origin, SSE streams included; WebSocket connections are not counted in that limit. This bites when browsers reach `sbtp-relay` directly (built-in TLS, ADR 0028). Behind a proxy that serves HTTP/2, SSE streams are multiplexed and the cap does not apply; the relay still holds one HTTP/1.1 connection per stream towards the proxy. |
| Changing what a client follows | WebSocket | A client changes its parent sets as it navigates. SSE fixes the filter in the request: each change is a new stream (a new request, token and relay connection), or a side channel (`POST` to a session) that makes the relay keep sessions addressed by an identifier, which is state and a capability to protect. WebSocket changes subscriptions on one connection. |
| Connections at the relay | WebSocket | `small` has 32 slots and 8 per client. One WebSocket connection carries up to `max_subscriptions` sets; SSE needs one stream per set, or one stream re-opened on each change. |
| Frame format | WebSocket | Binary frames carry raw 32-byte identifiers, as `POST /blocks`; SSE is UTF-8 text, so identifiers are hexadecimal and about twice the bytes. Compression of an event stream by a proxy is possible but interacts with buffering. |
| CDN in front | Neither | Common CDNs pass a WebSocket upgrade when enabled and pass long responses; neither is cached. An SSE stream is exposed to response buffering by a proxy or CDN, which delays events until a buffer fills, unless buffering is turned off for the route. |
| Plain HTTP proxies | SSE | SSE is an ordinary `GET` response: it passes forward proxies and proxies that strip `Upgrade`, and needs no proxy rule. WebSocket needs the proxy to forward the upgrade (rule 45); some networks block it. |
| Resume | SSE | SSE reconnects by itself and sends `Last-Event-ID`, which maps directly to a cursor. WebSocket has no built-in resume; rules 21 and 22 define it, and the client walks `/query`. |
| Tooling | SSE | An SSE stream can be read with a plain HTTP client; WebSocket needs a WebSocket client. |

The deciding facts are the dynamic sets on one connection and the connection budget of a small relay;
binary frames add to them. SSE is the stronger choice where proxies block upgrades; there, a client
loses nothing but latency, since it polls as today (rule 44).

### Long polling (`/query` with a wait parameter)

A `/query` that waits up to a bound for the first new match. Stateless and plain HTTP, it reuses cursors
as they are. Rejected: each waiting request holds a connection slot and a `query` permit for its whole
wait, under the class shed first; a change of set cancels and re-sends the request; the browser
HTTP/1.1 cap applies as to SSE. It also changes the cost model of `/query` (ADR 0012 rule 14).

### Relay-side catch-up from a client cursor

`subscribe` with a `from` cursor, the relay first replaying from it. Rejected: it puts an unbounded index
walk on the push path, which this ADR keeps free of index reads (rule 14), and duplicates what `/query`
already does under its own admission and bounds. The client walk costs one grouped request in the usual
case.

### Submission over WebSocket

`PUT` frames with acknowledgements carrying the error names. Rejected for this version: it duplicates the
`PUT` pipeline, its status codes, its body and time bounds and its per-client bounds over a second
transport, for a saving of one request per block. Publication is not the cost this ADR addresses.

### Filters by public key or by kind

A relay never parses payloads, so a filter by kind is excluded. A filter by public key is header-level
and possible, but nothing requires it yet, and it reveals a set of followed authors, which is more than
a parent set. Not in version 1.

### A separate port or listener for subscriptions

Its own connection pool would not take slots from HTTP. Rejected: a second listener to expose, proxy and
secure, and a second TLS configuration. The share of rule 27 gives the same protection on one listener.

### Pushing block bytes

Rejected: rule 30 of ADR 0051 asks for identifiers only. Block bytes would bypass the block cache, demand
counting and the CDN, and make a frame up to 65,909 bytes per entry.
