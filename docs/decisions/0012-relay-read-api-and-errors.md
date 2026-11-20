# 0012: Relay read API and errors (MVP): `/query`, error body, `/info`, CORS, rate-limit signalling

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0014 (the 66,133-byte body limit reads as `MAX_BLOCK_LEN` = 65,909); 0018 (`RequestTimeout` and
  `408`; error body of HTTP-layer responses; HTTP/1.1 only in milestone 1); 0019 (wording of rule 2:
  proxy-neutral); 0024 (rule 9: a cursor does not survive a restart after which the epoch changed); 0028
  (rule 2: `sbtp-relay` terminates TLS when configured to); 0029 (rules 10, 14, 16 and 20: response body
  ceilings, added members included; rule 30: a `Retry-After` not in seconds, a client's maximum wait)
- Clarifications: 2026-11-19, after relay milestone 1c-a (K1, K2), and after `cli-demo query` (K3: `502`
  and `504` retried like `503`), accepted by the project owner, 2026-11-19
- Date: 2026-11-18
- Questions: Q-08 (resolved, except the WebSocket protocol, moved to Q-23)
- Extends: ADR 0007 rule 11 (`/info` members; nothing is removed or changed)
- Depends on: ADR 0013 (acceptance position, `received_at`, index) for the ordering of `/query`
- Impact: spec §4 (title, intro, `PUT` responses, `GET /block`, `/info`, `/query`, WebSocket, new "Errors",
  "CORS", "Rate limiting" and "Transport" subsections); `sbtp-relay` (handlers, rejections, CORS layer,
  limiter); clients (`cli-demo`, `sbtp-wasm`, web client); no `sbtp-core` change; no layer 0 test vector

## Context

Phase 2 cannot start while Q-08 is partially resolved. ADR 0007 defined `GET /sbtp/v1/info`; ADR 0008
defined the status codes of `PUT`. Four points remain (the open questions (not published), Q-08):

- `/query`: response format and pagination;
- the error body: a client cannot tell which check failed behind a `400` (ADR 0007, "Interoperability");
- HTTP/3: in the relay or at a reverse proxy;
- the WebSocket protocol.

Two more points are needed by the first clients and are not written anywhere: the CORS policy (the PWA
reads relays from a browser, `architecture.md` §3 tier 1) and the signalling of rate limits (ADR 0007
leaves rate limiting to the relay but a client must know how to react).

Constraints: the relay never parses a payload; it reads header fields only. Every response is bounded.
The relay targets under 15 MB of RAM.

### Library facts checked on 2026-11-18

Source: Context7 (`/tokio-rs/axum`, `/tower-rs/tower-http`), which serves the upstream sources and docs.
The workspace pins `axum = "0.8.9"` and `tower-http = "0.7.1"`; the implementer MUST confirm each fact
against those exact versions on docs.rs before relying on it.

| Fact | Source |
|---|---|
| The `Bytes` extractor wraps the body in `http_body_util::Limited` with the limit of `DefaultBodyLimit`; the default is 2,097,152 bytes. `Limited` counts the frames actually read, so the limit holds without a `Content-Length` header. | `axum-core/src/ext_traits/request.rs`, `axum/src/docs/extract.md` |
| `DefaultBodyLimit::max(n)` replaces the default for a router or a route. | `axum-core/src/extract/default_body_limit.rs` |
| A body over the limit makes `Bytes` fail with `BytesRejection` → `LengthLimitError`, status `413`, body `Failed to buffer the request body` (plain text). | `axum-core/src/extract/rejection.rs` |
| `tower_http::limit::RequestBodyLimitLayer::new(n)` answers `413` without calling the handler when `Content-Length` exceeds `n`. Needs the `limit` feature. | docs.rs `tower_http::limit` |
| `CorsLayer::new()` sends no CORS header. `CorsLayer::permissive()` allows any origin, method and header and exposes any header. | docs.rs `tower_http::cors` |
| `CorsLayer` has `allow_origin`, `allow_methods`, `allow_headers`, `expose_headers`, `max_age`. `Layer::layer` panics when credentials are combined with a wildcard; `CorsLayer::validate()` returns the same error as a `Result`. | docs.rs `tower_http::cors`, `CorsConfigurationError` |

Not checked: the status code `CorsLayer` gives to a preflight response; the Cargo feature names of
`tower-http` 0.7.1 (`cors`, `limit` in the fetched docs); any per-IP rate limiting crate.

## Decision

### Transport

1. The relay interface is defined on HTTP semantics (RFC 9110). It does not depend on an HTTP version.
2. `sbtp-relay` serves HTTP/1.1 and MAY serve HTTP/2. It does not implement HTTP/3 or TLS. A public relay
   MUST be reachable over HTTPS; TLS, HTTP/2 and HTTP/3 are terminated by a reverse proxy (Caddy).
3. This version specifies no WebSocket endpoint. A relay MUST NOT expose one under `/sbtp/v1/` until an
   ADR specifies it (Q-23). Clients discover new blocks by polling `/query` with a cursor (rule 12).

### Identifiers in URLs

4. A `block_id` in a path or a query string is exactly 64 lowercase hexadecimal characters. Any other
   value gets `400` with the error `InvalidParameter`. This applies to `GET /sbtp/v1/block/{block_id}`
   and to the `parent` parameter.

### `GET /sbtp/v1/query`

5. **Parameters.** All are optional.

   | Parameter | Syntax | Meaning |
   |---|---|---|
   | `parent` | `block_id` (rule 4) | Only blocks whose Parents Hashes field contains this value. |
   | `since` | decimal u64, digits only | Only blocks with `received_at ≥ since` (rule 7). |
   | `limit` | decimal integer ≥ 1 | Maximum number of identifiers in the response. Default: 100. |
   | `cursor` | 1 to 128 characters of `A-Z a-z 0-9 - _` | Position returned by a previous response of the same relay. |

   A parameter that is unknown, repeated or malformed gets `400` `InvalidParameter`. A relay MUST NOT
   ignore a parameter it does not know: a later filter must not be dropped silently.
6. **Order.** A relay returns identifiers in its acceptance order: the order in which it stored the blocks
   (ADR 0013 rules 2 to 4). The order is total and stable on one relay. It differs between relays.
7. **`since`.** `received_at` is the Unix time in milliseconds, read from the relay's clock, at which the
   relay stored the block. It is not the Timestamp field of the header. `since` is a starting point for a
   client with no cursor ("the last 24 hours"); a client that already holds a cursor uses the cursor.
8. **`limit`.** Each relay has a setting `max_query_limit`, from 1 to 1,000, default 1,000, published by
   `/info`. A `limit` greater than `max_query_limit` is lowered to it; this is not an error. `limit=0`
   gets `400` `InvalidParameter`.
9. **`cursor`.** A cursor is opaque. A client MUST NOT build or interpret one. A cursor is a position in
   the acceptance order of the relay that issued it: it stays valid for any value of `parent` and `since`,
   it does not expire with time, and it survives a restart. With both `since` and `cursor`, the response
   starts at the later of the two positions. A cursor that the relay does not recognise (another relay,
   index rebuilt, malformed) gets `400` `InvalidCursor`; the client starts again without a cursor.
10. **Response.** `200 OK`, `Content-Type: application/json`, `Cache-Control: no-store`, and a JSON object
    with exactly these members:

    ```json
    {
      "block_ids": ["0000a3…17cdef", "00007b…90aa01"],
      "cursor": "k3_Zr0AAAAEAAAAq",
      "more": true
    }
    ```

    - `block_ids`: array of 0 to `limit` `block_id` values (64 lowercase hexadecimal characters), in
      acceptance order, each at most once.
    - `cursor`: always present. A later request with the same `parent` and this cursor returns exactly the
      matching blocks that this response and its predecessors did not return.
    - `more`: `true` if at least one more matching block existed when the response was built.

    A relay MAY add members. A client MUST ignore members it does not know.
11. **No match.** An unknown `parent`, a `parent` with no child, or a `since` in the future gets `200` with
    an empty `block_ids` and `"more": false`. A relay MUST NOT answer `404` to `/query`. A relay lists the
    children it holds whether or not it holds the parent (stateless validation, spec §2.2).
12. **Walking and polling.** To read every child of a block, a client requests
    `?parent=<id>&limit=<n>`, then repeats with the returned `cursor` until `more` is `false`. It keeps the
    last cursor and repeats the request later to get the children stored since. Guarantees on one relay:
    - a walk returns every matching block stored before its first request and still held when its page is
      built;
    - a block stored during a walk appears later in the same walk or in the next poll;
    - a block evicted and stored again gets a new position and can be returned again.
13. **Client rules.** A client MUST deduplicate by `block_id`. It MUST NOT derive application state from
    the order of a response: the order is local to a relay. It MUST treat each identifier as a hint: the
    block is fetched and validated as spec §3.4 requires, and the fetch can return `404` (eviction,
    ADR 0013).
14. **Cost bound.** A relay MUST serve a request with work in `O(log n + limit)`, `n` being the number of
    indexed entries. No combination of parameters may cause a scan of the store. A response body is under
    70 KiB (1,000 identifiers of 67 bytes plus the envelope).
15. **With neither `parent` nor `since`.** The request lists every block the relay holds, page by page.
    It is allowed: mirrors and super-peers need it until Q-11 is decided.

### Error body

16. Every response with a `4xx` or `5xx` status produced by a relay MUST carry
    `Content-Type: application/json` and a JSON object:

    ```json
    { "error": "InsufficientPow", "message": "block_id has 12 leading zero bits, 16 required" }
    ```

    - `error` (required): one name from the table of rule 17. Names are case-sensitive and never change
      meaning.
    - `message` (optional): text for a human, at most 200 characters. A client MUST NOT parse it. It MUST
      NOT contain block bytes, file paths or internal error text.
    - A relay MAY add members. A client MUST ignore members it does not know.
17. Error names. The block validation names are the variants of ADR 0004.

    | Status | `error` | Condition |
    |---|---|---|
    | `400` | `TooShort`, `TooLong`, `BadMagic`, `UnsupportedVersion`, `TooManyParents`, `Truncated`, `TrailingBytes`, `DuplicateParent` | `PUT`: checks F1 to F9 (spec §2.2). |
    | `400` | `TimestampTooFarInFuture` | `PUT`: policy check P1 (ADR 0007). |
    | `400` | `InsufficientPow` | `PUT`: check C1. |
    | `422` | `InvalidPublicKey`, `InvalidSignature` | `PUT`: checks C2, C3. |
    | `413` | `BodyTooLarge` | `PUT`: body over the transport limit (ADR 0008 rule 8). Distinct from `TooLong` (F2). |
    | `400` | `InvalidParameter` | Malformed `block_id`, unknown, repeated or malformed query parameter. |
    | `400` | `InvalidCursor` | `/query`: cursor not recognised (rule 9). |
    | `404` | `NotFound` | `GET /block/{block_id}`: block not held. Unknown path. |
    | `405` | `MethodNotAllowed` | Method not defined for the path. The relay sends `Allow`. |
    | `429` | `RateLimited` | Rate limit reached (rules 29 to 31). |
    | `500` | `Internal` | Relay fault. No detail is disclosed. |
    | `503` | `Unavailable` | Relay starting, stopping or shedding load. `Retry-After` SHOULD be sent. |
    | `507` | `StorageFull` | `PUT`: the relay cannot store a new block (ADR 0013). |

    `BlockIdMismatch` (R1) is a recipient-side check and never appears in a relay response. A new name
    goes through an ADR.
18. A client MUST decide on the status code first and use `error` to refine. A reverse proxy or a CDN can
    answer in the relay's place (`502`, `504`, its own `429`) with another body: a client MUST accept a
    missing or unparseable error body.
19. A `2xx` response of `PUT` has no body (ADR 0008 rule 5 is unchanged).

### `GET /sbtp/v1/info`

20. The two members of ADR 0007 rule 11 are unchanged. A relay MUST also publish:

    ```json
    {
      "min_pow_difficulty": 16,
      "max_future_ms": 300000,
      "block_versions": [1],
      "max_query_limit": 1000,
      "block_ttl_ms": 2592000000
    }
    ```

    - `block_versions`: array of the Version field values the relay accepts (check F4).
    - `max_query_limit`: integer from 1 to 1,000 (rule 8).
    - `block_ttl_ms`: integer, or `null` when the relay does not evict by age (ADR 0013 rules 12 to 17).
21. A relay MAY publish `software`, a free string such as `"sbtp-relay/0.1.0"`. It MUST be possible to
    turn it off: a version string helps an attacker pick an exploit.
22. A client MUST accept the absence of any member other than the two of ADR 0007 (older relay, static
    mirror). The rule "a client MUST ignore members it does not know" stays.

### CORS

23. **Setting.** A relay has a setting `cors_allow_origins`: either the single value `*`, or a list of
    origins (`scheme://host[:port]`, compared byte for byte with the `Origin` request header). Default:
    `*`. An empty list is allowed and disables cross-origin access from browsers.
24. **Default (`*`).** Every response, errors included, carries `Access-Control-Allow-Origin: *`.
25. **Allow-list.** When the request has an `Origin` header that is in the list, the response carries
    `Access-Control-Allow-Origin: <that origin>`. Otherwise the response carries no
    `Access-Control-Allow-Origin`. In both cases the response carries `Vary: Origin`. The relay still
    processes the request: the allow-list tells browsers which pages may read responses; it is not
    access control, and a client that is not a browser is unaffected. An operator who needs access
    control uses the network (firewall, proxy authentication), outside this specification.
26. **No credentials.** Whatever the setting, a relay MUST NOT send `Access-Control-Allow-Credentials`,
    and MUST NOT use cookies, HTTP authentication or any other ambient credential on `/sbtp/v1/`.
27. **Preflight.** A relay MUST answer a CORS preflight (`OPTIONS`) from an allowed origin with a `2xx`
    status and:

    ```
    Access-Control-Allow-Methods: GET, PUT
    Access-Control-Allow-Headers: Content-Type
    Access-Control-Max-Age: 86400
    ```

    It MUST send `Access-Control-Expose-Headers: Location, Retry-After` on actual responses to an allowed
    origin: neither header is readable by a script otherwise.
28. **Where.** The CORS headers are produced by the relay, not by the reverse proxy. An operator MUST NOT
    add them a second time at the proxy (a duplicated `Access-Control-Allow-Origin` is invalid).

### Rate-limit signalling

29. A relay that refuses a request because of a rate limit MUST answer `429 Too Many Requests` with the
    error `RateLimited` and SHOULD send `Retry-After` as a number of seconds (the `delay-seconds` form of
    RFC 9110 §10.2.3, not a date). The refusal happens before the body is read.
30. A client MUST NOT repeat the request before `Retry-After` has elapsed. Without `Retry-After`, it
    SHOULD back off exponentially with jitter, starting at 1 second. The same rule applies to `503`.
31. The limits themselves (per IP, per key, algorithm, values) are relay implementation choices
    (ADR 0007). They are not published by `/info` in this version.

### Caching

32. A `200` response of `GET /sbtp/v1/block/{block_id}` SHOULD carry
    `Cache-Control: public, max-age=31536000, immutable`: a `block_id` never designates another block
    (spec §3.4). Error responses and `/query` responses carry `Cache-Control: no-store`.

## Choices made and their alternatives

Decided by the project owner on 2026-11-18. The rules above state the choices; this section records what
they were weighed against.

### Order of `/query` and meaning of `since`

**Decided: acceptance order; `since` is the relay's reception time** (rules 6 and 7).

| | Acceptance order (adopted) | Timestamp order |
|---|---|---|
| Order | Position assigned by the relay when it stores the block. | `(Timestamp, block_id)` from the header. |
| `since` | Relay reception time. | Header Timestamp. |
| Polling with a cursor | Complete: a new block is always after every cursor already issued. | Incomplete: a block accepted later with an earlier Timestamp falls behind the cursor and is never seen. Nothing bounds back-dating (ADR 0007 rule 10). |
| Same order on every relay | No. | Yes, for the same set of blocks. |
| Index | Append-only; eviction by age removes a prefix. | Ordered structure per parent and one global; eviction by age removes entries anywhere. |

Without WebSocket, polling is the only way to follow a thread; it has to be complete. With Timestamp
order, a sender hides a block from every polling client by back-dating it by one second. Layer 2 order is
defined by the DAG and by layer 2 rules, not by a relay response (rule 13).

### Response format of `/query`

**Decided: JSON** (rule 10).

| | JSON (adopted) | Compact binary |
|---|---|---|
| Size for 1,000 identifiers | about 67 KiB; hexadecimal compresses well at the proxy. | 32 KiB plus a trailer for the cursor. |
| Browser client | `fetch().json()`. | Manual slicing; a second framing to specify and test. |
| Consistent with | `/info`, error body. | Blocks. |

A binary form can be added later under content negotiation (`Accept: application/octet-stream`) without
breaking JSON clients. Until then a relay ignores `Accept`.

### Error body

**Decided: the object `{error, message}`** (rule 16). Alternative: RFC 9457
(`application/problem+json`). It requires a `type` URI per error under a domain the project does not own
yet, and three more members that no client needs. The object of rule 16 can be extended into a problem
document later (unknown members are ignored).

### CORS

**Decided: `*` without credentials by default, and a relay setting `cors_allow_origins` that holds an
allow-list of origins** (rules 23 to 28).

- Why `*` is the default. The interface has no credential and every block is public (Q-17), so a
  cross-origin read discloses nothing that a direct request does not. A fixed list as the default would
  break third-party clients, which is the point of an open protocol.
- What the default implies. Any web page can make a visitor's browser read or write a relay that the
  browser can reach, a relay on `localhost` or on a LAN included.
- What the allow-list is for. An operator of a private or LAN relay restricts which web origins can read
  it from a browser. It does not stop a request from being sent or processed (rule 25).
- Background, not a guarantee. Some browsers restrict requests from public pages to private network
  addresses (Private Network Access: a preflight carrying `Access-Control-Request-Private-Network`). A
  relay does not answer that preflight header, so such browsers may block a public page from reaching a
  LAN relay even with `*`. The behaviour varies between browsers and versions and has changed over time.
  A relay MUST NOT be treated as private because of it, nor because of its network position.

### WebSocket

**Decided: out of the MVP, tracked as Q-23** (rule 3). Specifying frames, filters, acknowledgements and
back-pressure before a first client exists would be guesswork, and each open subscription costs memory in
a 15 MB relay. Polling with a cursor is bounded and stateless. Direction for the future ADR: a
subscription takes the `/query` filters and a cursor, and delivers `block_id` values only; a submitted
frame is acknowledged with the error names of rule 17; subscriptions per connection and per IP are capped.

## Out of the MVP

- **WebSocket** submission and subscription: Q-23, dedicated ADR.
- **HTTP/3 and TLS in the relay process**: left to the reverse proxy (rule 2).
- **P2P synchronisation** (spec §5): Q-11. `/query` with no `parent` (rule 15) is the interim way to copy
  a relay.
- **Other filters** (`pubkey`, Timestamp range), **batch `GET`**, **`HEAD`**, **binary `/query`**,
  **publication of rate limits in `/info`**. Each needs an index or a framing that the MVP does not have.
- **Chunk endpoints**: Q-21.

## Consequences

- **Clients.** One loop serves both the initial walk and the polling (rule 12). A client can now tell a
  format error from a policy rejection: after `InsufficientPow` or `TimestampTooFarInFuture` it reads
  `/info` again (ADR 0007 rule 12); after a format error it does not retry.
- **Information disclosed.** The error name tells which check failed. Every check is a public,
  deterministic function of the submitted bytes and of published settings: it gives no oracle. `message`
  is constrained by rule 16.
- **Order and layer 2.** Two relays return the same children in different orders. Layer 2 state resolution
  (votes, tombstones) already has to be order-independent, since blocks arrive out of order.
- **Relay clock.** `since` and `received_at` use the relay clock, like P1. A clock step backwards must not
  reorder positions (ADR 0013 rule 3).
- **Static mirrors (tier 3).** A mirror can serve `GET /block` and a fixed `/info`. It cannot serve
  `/query` with cursors unless it pre-computes pages; this ADR does not define that.
- **Security.**
  - Every parameter is length-bounded and validated before any index access. A storage path is never
    built from a query string (rule 4, the implementer rules).
  - The per-IP limiter needs the client address. Behind Caddy, it comes from `X-Forwarded-For`; the relay
    MUST trust that header only when the peer is the configured proxy, otherwise any client can evade or
    poison the limiter. The limiter state MUST be bounded in memory.
  - `Cache-Control: immutable` on blocks lets a CDN keep a block after the relay evicted it. This is
    consistent with content addressing; it is not a deletion mechanism (there is none in layer 0).
- **`sbtp-core`.** No change. The error names reuse its variant names; the relay maps variants to names
  with an exhaustive `match`, so a new variant fails to compile until it is mapped.
- **Compatibility.** No relay is deployed.

### Checklist for the implementer

- [ ] `tower-http`: enable the features for CORS and body limit in `[workspace.dependencies]`; confirm
      their names for 0.7.1 on docs.rs.
- [ ] `PUT`: `DefaultBodyLimit::max(66_133)` on the route, plus `RequestBodyLimitLayer::new(66_133)` to
      refuse early on `Content-Length`. Tests: 66,133 bytes parsed, 66,134 bytes `413`, both with and
      without `Content-Length` (chunked).
- [ ] Map every extractor rejection (`BytesRejection`, `QueryRejection`, `PathRejection`) and the router
      fallbacks (`404`, `405`) to the JSON error body. No plain-text framework body may reach a client.
- [ ] Error type of the relay: one variant per row of rule 17; exhaustive `match` from `sbtp_core::Error`;
      P1 maps to `TimestampTooFarInFuture`.
- [ ] `/query` handler: strict parameter parser (rules 4, 5, 8), clamp of `limit`, cursor codec, response
      of rule 10, `Cache-Control: no-store`.
- [ ] Cursor: opaque token that carries the index epoch and a position (ADR 0013 rule 5); constant-size
      decode; unknown epoch gives `InvalidCursor`.
- [ ] `/info`: add `block_versions`, `max_query_limit`, `block_ttl_ms`; `software` behind a setting.
- [ ] CORS: setting `cors_allow_origins` (default `*`; a list is validated at start-up as
      `scheme://host[:port]`). `CorsLayer::new()` with explicit `allow_origin` (wildcard or list; confirm
      the list form and its `Vary: Origin` behaviour on docs.rs for 0.7.1), `allow_methods([GET, PUT])`,
      `allow_headers([CONTENT_TYPE])`, `expose_headers([LOCATION, RETRY_AFTER])`, `max_age(86400 s)`. Do
      not use `permissive()`. Call `validate()` at start-up. Put the layer outermost so that `413`, `429`
      and `503` responses carry the headers.
- [ ] Rate limiter: before body read; `429` + `Retry-After` in seconds; bounded map; trusted-proxy
      setting for `X-Forwarded-For`. Any new crate follows the dependency rules of `CLAUDE.md`.
- [ ] `GET /block`: `400 InvalidParameter` on a malformed identifier before any path is built;
      `Cache-Control` of rule 32.
- [ ] No WebSocket route. Remove "WS" from the crate description until Q-23 is decided.
- [ ] Integration tests: one per row of rule 17; walk of 2,500 children with `limit=1000` (three pages,
      `more` false on the last); poll after the walk returns only new children; unknown parent gives `200`
      and an empty list; unknown parameter gives `400`; cursor from another epoch gives `400`;
      preflight and exposed headers; `Retry-After` readable on `429`; with an allow-list: listed origin
      echoed with `Vary: Origin`, unlisted origin gets no `Access-Control-Allow-Origin` and the request is
      still processed; no `Access-Control-Allow-Credentials` in either mode.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-08 | `/query` format, order, pagination and limits; error body; `/info` members; CORS; rate-limit signalling; HTTP versions. | WebSocket protocol, moved to Q-23. |
| Q-07 | Nothing new. `since` does not use the header Timestamp. | Unchanged (layer 2). |
| Q-11 | Nothing. Rule 15 gives an interim full listing. | Unchanged. |

## Clarifications (2026-11-19, after relay milestone 1c-a)

Recorded by the specification editor after relay milestone 1c-a, accepted by the project owner, 2026-11-19. They state
how rules 5, 9 and 17 (rule 9 as amended by ADR 0024) read together, and what a client sees when `/query`
fails inside the relay. They change no decision above and describe what `sbtp-relay` does at `8c42d95`.

- **K1. Malformed cursor versus unrecognised cursor.** Rule 5 and rule 9 both use the word "malformed".
  They read as follows.
  - A `cursor` value outside the syntax of rule 5 (empty, longer than 128 characters, or with a character
    outside `A-Z a-z 0-9 - _`) is a malformed parameter: `400` `InvalidParameter` (rule 5).
  - A `cursor` value within that syntax that the relay did not issue for its current index epoch gets
    `400` `InvalidCursor` (rule 9). This includes a value of another length or alphabet than the
    relay's own encoding: a cursor is opaque (rule 9), so only the relay that issued it can judge it, and
    the word "malformed" in rule 9 means "not a cursor of this relay's encoding".
  - A relay MUST issue cursors that match the syntax of rule 5. A client that sends back a cursor
    exactly as received therefore never gets `InvalidParameter` for it.
  - Client behaviour: on `InvalidCursor`, the client restarts the walk without a cursor (rule 9, ADR
    0024 rule 8). On `InvalidParameter`, the request is wrong on the client side (or was altered on the
    way); the client MUST NOT repeat it unchanged and MUST NOT treat it as a reason to restart a walk.
  - The check order is the one of `sbtp-relay`: all parameters are checked against rule 5 first, then
    the cursor is decoded. A request with a malformed `limit` and an unrecognised cursor gets
    `InvalidParameter`.
- **K2. Index read failure on `/query`.** When the relay cannot read its index to build a page (an
  I/O or database error, or a corrupt row), the response is `500` `Internal` (rule 17), with
  `Cache-Control: no-store` (rule 32) and no detail in `message`. It is not `503`: `503` means a limit,
  start-up or shutdown, and a read failure can persist. The failure does not invalidate any cursor:
  only `InvalidCursor` does. A client keeps its cursor and repeats the request later, backing off
  exponentially with jitter from 1 second, as for a `503` without `Retry-After` (spec §4, "Admission
  control"). The event that the relay logs is defined in ADR 0021, clarification of 2026-11-19.

## Clarification (2026-11-19, after `cli-demo query`)

Recorded by the specification editor after the `cli-demo query` merge (`a27ce6e`), accepted by the project
owner, 2026-11-19. It follows the combined review `docs/security/2026-11-19-cli-demo-query.md`. It
states how rule 18 and spec §4 "Admission control" read together for the status codes that a proxy
sends. It changes no decision above and describes what `cli-demo` does at `a27ce6e`.

- **K3. `502` and `504` are retried like `503`.** A relay does not produce `502` or `504`: rule 17
  has no name for them. They come from a reverse proxy, a gateway or a CDN in front of the relay (rule
  18), which could not reach the relay or did not get its answer in time. The condition is transient
  in the same way as a `503`. A client:
  - keeps its cursor, and keeps the blocks it could not publish;
  - MUST NOT repeat the request before `Retry-After` has elapsed when the response carries it, and
    otherwise SHOULD back off exponentially with jitter from 1 second (spec §4, "Admission control");
  - MUST NOT treat it as `InvalidCursor` and MUST NOT restart a walk because of it;
  - MAY bound the number of consecutive retries and then stop, reporting the cursor it holds.

  Every request of this interface is safe to repeat (spec §4), so the retry has no side effect. A
  `502` or `504` body is not a relay error body: rule 18 applies (decide on the status code; accept a
  missing or unparseable body).

## Rejected alternatives

- **`POST /query` with a JSON filter** (roadmap, earlier draft). Not cacheable, needs a preflight, and
  invites a query language. The spec already uses `GET`.
- **Offset pagination (`offset=`, `page=`).** Unstable under insertion and eviction; cost grows with the
  offset.
- **`404` for an unknown parent.** A relay can hold children of a block it does not hold; "unknown" and
  "no child" are the same answer for a client.
- **Returning header fields (Timestamp, PubKey) with each identifier.** A client cannot trust them without
  fetching and validating the block. It doubles the response size.
- **Rejecting a `limit` above the cap with `400`.** Forces a client to read `/info` before its first
  query for no benefit.
- **Ignoring unknown query parameters.** A client that sends a future filter would get unfiltered results
  with no signal.
- **`Retry-After` as an HTTP date.** Depends on clock agreement between client and relay.
- **Fixed list of origins with no wildcard default.** Breaks third-party clients; kept as an operator
  setting (rule 23).
- **Answering Private Network Access preflights (`Access-Control-Allow-Private-Network`).** The mechanism
  is not stable across browsers. Revisit if a LAN relay use case needs it.
- **CORS at the reverse proxy only.** A relay run without Caddy, and the integration tests, would have no
  CORS; the policy would not be testable in this repository.

## Spec change

Applied to `docs/spec/sbtp-core-v0.2.md` on 2026-11-18, on the owner's decision relayed by the
maintainer, together with the spec change of ADR 0013.

**§4, title.** `## 4. Dumb relay interface (HTTP/3 and WebSocket)` becomes
`## 4. Dumb relay interface (HTTP)`.

**§4, intro.** Replace the sentence ``Points of this interface not specified yet: `[Q-08]`.`` with:

```markdown
The interface is defined on HTTP semantics (RFC 9110) and does not depend on an HTTP version. A public
relay MUST be reachable over HTTPS. TLS, HTTP/2 and HTTP/3 MAY be terminated by a reverse proxy.

A `block_id` in a path or a query string is exactly 64 lowercase hexadecimal characters; any other value
gets `400` (`InvalidParameter`). (ADR 0012)
```

**§4, `PUT /sbtp/v1/block`.** Replace the `400`, `413` and `422` lines of "Responses" with:

```markdown
  - `400 Bad Request`: F1 to F9, P1, C1. Every failure of the binary analysis gets `400`, F2 included if
    it is reached despite the body limit. Error names: the §2.2 error of the failed check; P1 is
    `TimestampTooFarInFuture`.
  - `413 Content Too Large`: body longer than the body limit, rejected before any parsing. Error name:
    `BodyTooLarge`.
  - `422 Unprocessable Entity`: C2 (`InvalidPublicKey`), C3 (`InvalidSignature`).
  - `429 Too Many Requests`: rate limit, see "Rate limiting".
```

**§4, `GET /sbtp/v1/block/{block_id}`.** Replace the second bullet with:

```markdown
- `200 OK`; `404 Not Found` (`NotFound`) when the relay does not hold the block; `400 Bad Request`
  (`InvalidParameter`) when the identifier is malformed.
- A `200` response SHOULD carry `Cache-Control: public, max-age=31536000, immutable`.
```

**§4, `GET /sbtp/v1/info`.** Replace the JSON example and add three bullets after `max_future_ms`:

````markdown
  ```json
  {
    "min_pow_difficulty": 16,
    "max_future_ms": 300000,
    "block_versions": [1],
    "max_query_limit": 1000,
    "block_ttl_ms": 2592000000
  }
  ```

- `block_versions`: array of the Version field values the relay accepts (F4).
- `max_query_limit`: integer from 1 to 1,000, the largest page of `/query`.
- `block_ttl_ms`: integer in milliseconds, or `null` when the relay does not evict by age.
- A relay MAY publish `software` (free string). A client MUST accept the absence of any member other than
  `min_pow_difficulty` and `max_future_ms`. (ADR 0007, ADR 0012)
````

**§4, `/query`.** Replace the whole subsection with:

````markdown
### `GET /sbtp/v1/query?parent={block_id}&since={ms}&limit={n}&cursor={cursor}`

- Discovery of blocks, and of children in the DAG. All parameters are optional. A parameter that is
  unknown, repeated or malformed gets `400` (`InvalidParameter`).
  - `parent`: only blocks whose Parents Hashes field contains this `block_id`. The relay does not need to
    hold the parent.
  - `since`: decimal u64. Only blocks that the relay stored at or after this Unix time in milliseconds,
    by the relay's clock. This is not the Timestamp field.
  - `limit`: integer ≥ 1, default 100. A value above the relay's `max_query_limit` (§4, `/info`) is
    lowered to it.
  - `cursor`: opaque value, 1 to 128 characters of `A-Z a-z 0-9 - _`, taken from a previous response of
    the same relay. An unrecognised cursor gets `400` (`InvalidCursor`).
- Order: the order in which the relay stored the blocks. It is stable on one relay and differs between
  relays. A client MUST NOT derive application state from it.
- Response: `200 OK`, `application/json`, `Cache-Control: no-store`:

  ```json
  { "block_ids": ["0000a3…17cdef"], "cursor": "k3_Zr0AAAAEAAAAq", "more": false }
  ```

  - `block_ids`: 0 to `limit` identifiers in order, each at most once.
  - `cursor`: always present. The same request with this cursor returns the matching blocks not returned
    so far. A cursor is valid with any `parent` and `since`, and survives a relay restart.
  - `more`: `true` if at least one more matching block existed when the response was built.
- A request with no match gets `200` and an empty `block_ids`, an unknown `parent` included. A relay MUST
  NOT answer `404`.
- To read all children of a block, a client repeats the request with the returned `cursor` until `more`
  is `false`. Repeating it later returns the children stored since. A client MUST deduplicate by
  `block_id` and MUST fetch and validate each block (§3.4); the fetch can return `404`.
- A relay MUST serve a request with work in `O(log n + limit)`. (ADR 0012, ADR 0013)
````

**§4, WebSocket.** Replace the whole subsection with:

```markdown
### WebSocket

Not specified in this version. A relay MUST NOT expose a WebSocket endpoint under `/sbtp/v1/`. Clients
poll `/query` with a cursor. `[Q-23]`
```

**§4.** Add after the WebSocket subsection:

````markdown
### Errors

- Every `4xx` and `5xx` response produced by a relay carries `Content-Type: application/json` and a JSON
  object `{ "error": "<name>", "message": "<text>" }`. `error` is required. `message` is optional, at
  most 200 characters, for humans only; it MUST NOT contain block bytes, paths or internal error text.
- Names: the §2.2 error names for F1 to F9, C1, C2 and C3; `TimestampTooFarInFuture` (P1);
  `BodyTooLarge` (`413`); `InvalidParameter`, `InvalidCursor` (`400`); `NotFound` (`404`);
  `MethodNotAllowed` (`405`); `RateLimited` (`429`); `Internal` (`500`); `Unavailable` (`503`);
  `StorageFull` (`507`).
- A client decides on the status code first. It MUST accept a missing or unparseable error body (a proxy
  can answer in the relay's place) and MUST ignore members it does not know. (ADR 0012)

### CORS

- A relay setting `cors_allow_origins` holds `*` (default) or a list of origins.
  - With `*`, every response carries `Access-Control-Allow-Origin: *`.
  - With a list, a response to a request whose `Origin` is in the list carries
    `Access-Control-Allow-Origin: <that origin>`; any other response carries no
    `Access-Control-Allow-Origin`. Every response carries `Vary: Origin`. The relay still processes the
    request: the list is not access control.
- A relay MUST NOT send `Access-Control-Allow-Credentials` and MUST NOT use cookies or HTTP
  authentication on `/sbtp/v1/`.
- Responses to an allowed origin carry `Access-Control-Expose-Headers: Location, Retry-After`. A preflight
  from an allowed origin gets a `2xx` with `Access-Control-Allow-Methods: GET, PUT`,
  `Access-Control-Allow-Headers: Content-Type` and `Access-Control-Max-Age: 86400`. (ADR 0012)

### Rate limiting

- A relay that refuses a request because of a rate limit answers `429 Too Many Requests` (`RateLimited`)
  before reading the body, and SHOULD send `Retry-After` in seconds.
- A client MUST NOT repeat the request before `Retry-After` has elapsed. Without the header, it SHOULD
  back off exponentially with jitter. The same applies to `503`.
- The limits are local settings of each relay. (ADR 0007, ADR 0012)
````

No change to `docs/spec/architecture.md` from this ADR.
