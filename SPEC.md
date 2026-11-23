# SBTP v1: Signed Block Transport Protocol

Status: draft. This page is the whole normative specification. MUST, MUST NOT, SHOULD and MAY are used as
in RFC 2119. The frozen vectors in `docs/test-vectors/v1/` are part of it: an implementation MUST give
the result each vector expects.

## 1. Block format

A block is one byte string. Every integer longer than one byte is big-endian. `N` is the number of
parents, `P` the payload length.

| Offset | Size | Field | Content |
|---|---|---|---|
| 0 | 2 | Magic | `0x53 0x42` ("SB"). |
| 2 | 1 | Version | `0x01`. |
| 3 | 8 | Timestamp | u64, Unix time in milliseconds, set by the author. Not checked by layer 0. |
| 11 | 8 | Nonce | u64, free value for the proof of work. |
| 19 | 32 | PubKey | Author's Ed25519 public key. |
| 51 | 1 | Parents Count | `N`, 0 to 8. |
| 52 | 32·N | Parents | `block_id` of each parent, contiguous. |
| 52 + 32·N | 2 | Payload Len | `P`, u16, 0 to 65,535. |
| 54 + 32·N | P | Payload | Opaque bytes. |
| 54 + 32·N + P | 64 | Signature | Ed25519 signature (§3). |

- Total length is `118 + 32·N + P`: from 118 bytes to 65,909 bytes (`MAX_BLOCK_LEN`).
- Parent order is significant and kept. A parent is 32 opaque bytes: it may be unknown, or all zeros.
- The payload is never interpreted by layer 0 or by a relay.

## 2. Block identifier

```
block_id = BLAKE3.derive_key(context = "SBTP 2026-11-18 block_id v1", key_material = block[0 .. 54 + 32·N + P])
```

- 32-byte output, BLAKE3 key derivation mode. The input is the whole block except the 64 signature bytes.
- The context is the 27 ASCII bytes `53 42 54 50 20 32 30 32 36 2d 31 31 2d 31 38 20 62 6c 6f 63 6b 5f 69
  64 20 76 31`, with no terminator. Plain BLAKE3 hashing gives a different value and is wrong.
- In text (URLs, JSON), a `block_id` is exactly 64 lowercase hexadecimal characters.
- A block is identified by its `block_id` alone. Two valid byte strings with the same `block_id` differ
  only in their signature. An implementation MUST NOT identify or deduplicate blocks by a hash of the full
  bytes, and MUST NOT make any state depend on the signature bytes.

## 3. Signature and proof of work

The author signs `M = SIG_PREFIX ‖ block_id` (49 bytes) with pure Ed25519 (RFC 8032 §5.1, no prehash, no
context). `SIG_PREFIX` is the 17 ASCII bytes `SBTP-v1-block-sig`
(`53 42 54 50 2d 76 31 2d 62 6c 6f 63 6b 2d 73 69 67`). An author SHOULD sign deterministically (RFC 8032
§5.1.6). A key MUST NOT sign any other message that starts with `SIG_PREFIX`.

Verification is strict. Let `A` be PubKey, `R` the first 32 signature bytes, `S` the last 32 (little-endian
integer), `L = 2^252 + 27742317777372353535851937790883648493`. The signature is invalid if any of:

| # | Condition | Error |
|---|---|---|
| V1 | `A` is not a canonical point encoding (RFC 8032 §5.1.3): `y ≥ 2^255 − 19`, or `y` not on the curve, or `x = 0` with the sign bit set. | `InvalidPublicKey` |
| V2 | `A` is of small order (`[8]A` is the identity). | `InvalidPublicKey` |
| V3 | `S ≥ L`. | `InvalidSignature` |
| V4 | `R` does not decode to a curve point. | `InvalidSignature` |
| V5 | `R` is of small order. | `InvalidSignature` |
| V6 | The canonical encoding of `[S]B − [k]A` differs from `R` byte for byte, with `k = SHA-512(R ‖ A ‖ M) mod L` (`R` and `A` as received, digest read little-endian). | `InvalidSignature` |

V6 is the cofactorless equation. The cofactored equation and batch verification MUST NOT be used. A
mixed-order `A` that passes V1, V2 and V6 is valid (vector `valid_mixed_order_pubkey`).

Proof of work: with difficulty `d` (0 to 256), the `block_id` read as a 256-bit big-endian integer MUST be
below `2^(256 − d)`, that is, have at least `d` leading zero bits. The author varies Nonce until it does.
Validation takes `d` as a parameter; it reads no clock and no other state.

## 4. Validation

Checks run in this order; the first failure gives the error. A decoder MUST NOT read a byte before it
has checked that the buffer holds it. `len` is the buffer length.

| # | Rejection condition | Error |
|---|---|---|
| F1 | `len < 118` | `TooShort` |
| F2 | `len > 65,909` | `TooLong` |
| F3 | Magic is not `0x53 0x42` | `BadMagic` |
| F4 | Version is not `0x01` | `UnsupportedVersion` |
| F5 | `N > 8` | `TooManyParents` |
| F6 | `len < 118 + 32·N` | `Truncated` |
| F7 | `len < 118 + 32·N + P` | `Truncated` |
| F8 | `len > 118 + 32·N + P` | `TrailingBytes` |
| F9 | Two parents are equal, at any positions | `DuplicateParent` |
| R1 | Only for a block fetched by identifier: the computed `block_id` differs from the requested one | `BlockIdMismatch` |
| P1 | Only on a relay, for `PUT`: Timestamp `> now + max_future_ms` (relay clock, `/info`) | `TimestampTooFarInFuture` |
| C1 | Proof of work below `d` (§3) | `InsufficientPow` |
| C2 | V1 or V2 fails | `InvalidPublicKey` |
| C3 | Any of V3 to V6 fails | `InvalidSignature` |

- A vector's `params.difficulty` is `d`; `params.requested_block_id`, when not `null`, enables R1.
- On receipt of a block fetched by identifier, a client MUST apply F1 to F9, R1, then C1 with its own `d`
  (`0` if it has none, never the serving relay's) and C2, C3, before it stores or uses the block.

## 5. Relay HTTP API

A relay checks the envelope (§4) and never reads the payload. It is reached under a base URL; a public
relay is served over HTTPS (TLS MAY be terminated by a reverse proxy). Every response carries
`Access-Control-Allow-Origin: *` and `Access-Control-Expose-Headers: Location, Retry-After`. A relay MUST
NOT answer with a redirect; a client MUST NOT follow one.

**Positions.** A relay gives each block it stores for the first time a position: a u64, at least 1,
strictly greater than every position it gave before, never reused, kept across restarts. Positions MAY
have gaps, and a position is never renumbered: a block denied after it was stored leaves a gap. A relay
MUST make positions visible in increasing order: once a reader sees position `q`, no block with a lower
position appears later. Positions are local to one store of one relay, named by `relay_id` (§5,
`/info`). Position `0` means "before the first block".
A store restored or copied under a new `relay_id` MUST keep the relative order of the blocks it carries
over (a re-import replays them in position order). A position is one relay's receipt order, not a consensus
or a proof of time: an application that orders blocks by position trusts that relay for the order.

**Retention.** A relay never evicts a block it has stored: it keeps serving it unless the operator
denies it (`451`).

**Errors.** Every `4xx` and `5xx` from the relay has `Content-Type: application/json`, `Cache-Control:
no-store` and the body `{ "error": "<name>", "message": "<text>" }`; `message` is optional, at most 200
characters, and never holds block bytes. A client decides on the status code first and MUST accept a
missing or unparseable body (a proxy may answer instead of the relay).

### `PUT /sbtp/v1/block`

Body: the raw block, `Content-Type: application/octet-stream`. The relay rejects a body over 65,909 bytes
before reading it, then runs §4 (F1 to F9, P1, C1, C2, C3), then the deny list, then stores the block
atomically.

| Status | Meaning |
|---|---|
| `201 Created` | Valid and new: stored at a new position. SHOULD carry `Location: /sbtp/v1/block/{block_id}`. |
| `200 OK` | Valid and already stored. The stored bytes are kept; no new position. |
| `400` | F1 to F9, P1 or C1 failed. Error name from §4. |
| `408` | `RequestTimeout`: the body did not arrive in time. |
| `413` | `BodyTooLarge`: body over 65,909 bytes. |
| `422` | `InvalidPublicKey` (C2) or `InvalidSignature` (C3). |
| `429` | `RateLimited`, with `Retry-After` (§7). |
| `451` | `Denied` or `DeniedKey`: the operator denies this block or this key. Nothing is stored. |
| `503` | `Unavailable`: the relay is at a global limit, starting or stopping. |
| `507` | `StorageFull`: valid and new, but over the disk quota. Nothing is stored. |

A client MUST treat `200` and `201` as the same success. `PUT` is idempotent.

### `GET /sbtp/v1/block/{block_id}`

`200` with the stored bytes as `application/octet-stream` and `Cache-Control: public, max-age=31536000,
immutable`; `404` `NotFound`; `400` `InvalidParameter` for a malformed identifier; `451` `Denied`. A relay
MUST serve only bytes that pass §4 for that `block_id`. A `404` means this relay never stored the block
(retention, §5); it says nothing about other relays.

### `GET /sbtp/v1/query`

Lists stored blocks in position order, oldest first. Parameters, all optional:

- `parent`: one `block_id`; only blocks that have it among their Parents. Without it, every block.
- `since`: a position, decimal, at most 20 digits (default `0`); only blocks with a greater position. A
  value above 2^64 − 1 is `InvalidParameter`.
- `limit`: integer, at least 1, default 100; a value above `max_query_limit` is lowered to it.

An unknown, repeated or malformed parameter gets `400` `InvalidParameter`. A position greater than every
position the relay has given (denied blocks included) gets `400` `InvalidPosition`, never an empty page: the client resumes from `0` and
deduplicates by `block_id`. Response `200`, `application/json`, `Cache-Control: no-store`:

```json
{ "block_ids": ["5965bbc7…4f046d47"], "positions": ["1040"], "since": "1042", "more": false }
```

- `block_ids`: 0 to `limit` identifiers, in position order, none listed twice.
- `positions`: decimal strings, the position of each listed block, same length and order as `block_ids`
  (so strictly increasing). A response whose arrays differ in length is a relay error.
- `since`: decimal string, the greatest position the relay examined for this page, listed or not (it may
  be a gap or a denied block), or the requested position when it examined none. The next request sends
  it as `since` to get the blocks after the page.
- `more`: `true` when matching blocks remained after the page. When `more` is `true`, `since` is greater
  than the requested position, so a client always progresses, even on an empty page.
- The body is at most 131,072 bytes.
- An unknown `parent` gets `200` with an empty list. A denied block is not listed. Every identifier is a
  hint: the client fetches and validates the block (§4), and drops it if it does not carry the requested
  `parent`. A response whose `since` is lower than the requested one is a relay error.

### `GET /sbtp/v1/info`

`200`, `application/json`, at most 16,384 bytes:

```json
{ "relay_id": "9f2c…e41a", "min_pow_difficulty": 16, "max_future_ms": 300000, "block_versions": [1],
  "max_query_limit": 1000, "max_subscriptions_per_ip": 4, "last_position": "1042" }
```

- `relay_id`: 32 lowercase hexadecimal characters, 16 random bytes drawn when the relay's store is
  created and kept as long as that store lives. A store restored from a backup or a copy MUST draw a new
  `relay_id`. A client that sees a `relay_id` other than the one its
  positions came from MUST drop those positions, resume from `0` and deduplicate by `block_id`.
- `min_pow_difficulty`: `d` of C1 on `PUT`, 0 to 256. An author SHOULD read it before mining.
- `max_future_ms`: the P1 margin, in milliseconds.
- `block_versions`: accepted Version values; read as `[1]` when absent.
- `max_query_limit`: largest `/query` page, 1 to 1,000.
- `max_subscriptions_per_ip`: concurrent `/subscribe` connections allowed per client address; absent
  when the relay does not serve `/subscribe`.
- `last_position`: decimal string, the greatest position of a block the relay still serves (a denied
  block does not count), `"0"` when it serves none. Every position in this specification is a decimal
  string in JSON, never a JSON number.

A client MUST accept the absence of any member other than `relay_id`, `min_pow_difficulty` and
`max_future_ms`, and MUST ignore members it does not know. A relay MAY change its values at any time.

## 6. `GET /sbtp/v1/subscribe` (WebSocket)

A WebSocket upgrade (RFC 6455) of `GET /sbtp/v1/subscribe?since=<position>[&parent=<block_id>]` (`wss`
under `https`). `since` is required and has the `/query` meaning; `parent` is optional, at most one. A
connection carries exactly one subscription. Without `parent` it covers every block of the relay.

- Refusals, as plain HTTP before the upgrade: `400` `InvalidParameter` (malformed upgrade or parameter),
  `400` `InvalidPosition` (`since` beyond every position given, as for `/query`), `429` `RateLimited` with `Retry-After` (over
  `max_subscriptions_per_ip`), `503` `Unavailable` (over the relay's total).
- Relay to client: one binary frame per block, `position` (u64, big-endian, 8 bytes) followed by the
  block bytes, 126 to 65,917 bytes in all. The relay sends, in position order, every matching block with a
  position greater than `since`, the ones already stored first, then each new one. A block is sent only
  once `GET /block` serves it. A denied block is never sent.
- Client to relay: no data frames. A client data frame closes the connection with `1003`.
- The client validates each block itself (§4, without R1) and keeps the last position it
  received. It MUST drop a block that does not carry the requested `parent` among its Parents.
- A frame whose position is not greater than both `since` and the previous frame's position is a relay
  error: the client closes the connection and falls back to `/query` with back-off.
- **Catch-up, then live.** While it sends blocks already stored, the relay reads them from its store
  only as fast as the client takes them (TCP flow control): a slow client is never closed for slowness
  during catch-up, so one connection can sync a whole relay. Once caught up, the relay bounds what it
  queues per connection, and a client that reads new blocks too slowly is closed with `4000`. The
  maximum connection age still applies; the client then reconnects from its last position.
- The relay sends WebSocket pings and closes a connection that does not answer. There is no gap or tick
  message. A browser client cannot see pings; one that needs to tell a quiet stream from a dead one MAY
  compare its last position with `last_position` from `/info` from time to time.
- Close codes: `1000` idle timeout or maximum age; `1001` relay stopping; `1003` client sent data;
  `1011` relay error; `4000` client too slow.
- After any close, the client reconnects with `since` set to its last position, backing off
  exponentially, or walks `/query` from it. A browser cannot see why an upgrade was refused: after a
  failed upgrade, a client reads `/info` (`relay_id`, `last_position`) before it retries. Completeness comes from `since`, not from the stream.

## 7. Relay limits

A client MUST expect, on any relay:

- block size: at most 65,909 bytes, checked before the body is read (`413`); a body read timeout (`408`);
- proof of work: at least `min_pow_difficulty` (`400` `InsufficientPow`);
- rate limits per client address (an IPv6 /64 is one address) and a cap on concurrent connections; an
  operator MAY give higher limits, for requests and connections, to client addresses it lists (for
  example a gateway that publishes for many users): `429`
  `RateLimited` with `Retry-After` in seconds. A client MUST NOT repeat the request before `Retry-After`
  has elapsed; without it, it backs off exponentially with jitter, starting at 1 second;
- a global disk quota: `507` `StorageFull` for new blocks, with no eviction; blocks already stored still
  get `200`;
- an operator deny list by `block_id` or public key: `451`. A client MUST NOT resend a denied block to
  that relay automatically, and MUST NOT read a `451` as proof that the block is invalid elsewhere. A
  denial is never announced: an index that must honour an operator's removals re-checks a block with
  `GET /block`, where `451` signals the removal.

Every request is safe to repeat. A `502`, `503` or `504` is transient: the client keeps its position and
its unpublished blocks and retries later.
