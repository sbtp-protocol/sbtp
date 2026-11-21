# SBTP: Signed Block Transport Protocol, layer 0 specification (v0.2-draft)

> **Status:** normative draft. **This file is authoritative.**
> A `[Q-xx]` marker flags a point that is not specified yet: it cannot be implemented until a later
> version of this specification settles it. Some decision records are not published; the specification
> is self-contained and normative on its own.
> Protocol name: *Signed Block Transport Protocol*, acronym SBTP (ADR 0005).

The words MUST, MUST NOT, SHOULD and MAY have the meaning given in RFC 2119.

## 1. Goal and philosophy

SBTP is a universal, decentralised binary transport layer that is neutral with respect to the application
domain. It structures data exchange networks as a directed acyclic graph (DAG).

Founding principles:

- **Stateless.** A relay processes each block atomically and independently. It does not know the
  application semantics and keeps no session to validate it.
- **Application-agnostic.** The payload is an opaque byte sequence. SBTP guarantees integrity,
  authenticity and causality without interpreting the data.
- **Zero-copy binary transport.** The binary layout allows reading directly from the received buffer
  (*buffer slicing*), with no allocation or copy to route or store.
- **Content addressing.** Each block has a unique, immutable identity derived from its content.
- **Decentralised DAG.** Each block references zero, one or several parents by their hash. This forms
  a causal graph with no central ordering authority.

## 2. Block binary format

| Field | Size | Type | Description |
|---|---|---|---|
| Magic | 2 | `0x53 0x42` | "SB" in ASCII. |
| Version | 1 | u8 | `0x01` for v0.2-draft. |
| Timestamp | 8 | u64 big-endian | Unix timestamp **in milliseconds**. Not interpreted by layer 0 validation (§2.2). |
| Nonce | 8 | u64 big-endian | Free value for the proof of work. Not interpreted by a validator. |
| PubKey | 32 | bytes | Sender's Ed25519 public key. |
| Parents Count | 1 | u8 | Number N of parents, from 0 to 8. Values 9 to 255 are reserved (§2.2). |
| Parents Hashes | 32 × N | bytes | BLAKE3 `block_id` of the direct parents, contiguous. |
| Payload Len | 2 | u16 big-endian | Payload size, at most 65,535 bytes. Larger objects are carried as chunks outside the block (ADR 0010). |
| Payload | variable | bytes | Opaque application data. |
| Signature | 64 | bytes | Ed25519 signature (§3.2). |

Every integer field longer than one byte MUST be encoded as big-endian (network order). (ADR 0001)

Block size: from 118 bytes (0 parents, empty payload) to 65,909 bytes (8 parents, max payload).
These constants are implemented in `crates/sbtp-core/src/layout.rs`.

### 2.1 Zero-copy reading

1. **Fixed header.** The first 52 bytes (magic, version, timestamp, nonce, pubkey, parents count)
   have fixed offsets and are read without decoding.
2. **Computed dynamic offsets.**
   - `Offset(Payload Len) = 52 + 32·N`
   - `Offset(Payload) = 52 + 32·N + 2`
   - `Offset(Signature) = Offset(Payload) + Payload Len`
3. **No re-serialisation.** The received block (epoll, io_uring, WebSocket) is read in place: the public
   key and parents are views over the buffer.

### 2.2 Format validation

A block that passes the checks below is well-formed. Format validity is the same for every implementation:
no check depends on a local configuration. The checks MUST be done in this order; the first one that fails
determines the error. A decoder MUST NOT read a byte before checking that the buffer contains it. `len` is
the buffer length, `N` the Parents Count field, `P` the Payload Len field.

| Order | Rejection condition | Error |
|---|---|---|
| F1 | `len < 118`. | `TooShort` |
| F2 | `len > 65,909`. | `TooLong` |
| F3 | Magic differs from `0x53 0x42`. | `BadMagic` |
| F4 | Version differs from `0x01`. | `UnsupportedVersion` |
| F5 | `N > 8`. | `TooManyParents` |
| F6 | `len < 118 + 32·N`. | `Truncated` |
| F7 | `len < 118 + 32·N + P`. | `Truncated` |
| F8 | `len > 118 + 32·N + P`. | `TrailingBytes` |
| F9 | Two identical parent hashes, at any positions. | `DuplicateParent` |

- **Parent limit.** A block MUST have from 0 to 8 parents. An implementation MUST NOT make this limit
  configurable. Raising it requires a new value of the Version field.
- **Parent order.** It is significant and kept. A decoder MUST NOT require sorting or reorder.
- **Well-formed cases.** A decoder MUST NOT reject on format grounds: `N = 0`; `P = 0`; a parent unknown to
  it; a parent of any value, zero included; any value of Timestamp or Nonce; any payload content.

After the format, validation MUST continue in this order:

| Order | Rejection condition | Error |
|---|---|---|
| C1 | Insufficient proof of work (§3.3). | `InsufficientPow` |
| C2 | Invalid PubKey (§3.2, V1 and V2). | `InvalidPublicKey` |
| C3 | Invalid signature (§3.2, V3 to V6). | `InvalidSignature` |

For a block received in response to a request by identifier (§3.4), one check, R1, is added between F9 and C1:
the computed `block_id` MUST equal the requested identifier, otherwise `BlockIdMismatch`.

A relay adds one policy check, P1, between F9 and C1, on submitted blocks only: the Timestamp MUST NOT be
greater than `now + max_future_ms` (§4, `GET /sbtp/v1/info`). P1 depends on the relay's clock and
settings. It is not a format rule, and `sbtp-core` does not implement it. (ADR 0007)

Every new rejection rule goes through an ADR. (ADR 0004, ADR 0014)

## 3. Identifier and cryptographic primitives

### 3.1 `block_id`

```
block_id = BLAKE3_derive_key( BLOCK_ID_CONTEXT, fixed_header ‖ parents_hashes ‖ payload_len ‖ payload )
```

The `block_id` MUST be computed with the BLAKE3 key derivation mode (`derive_key`), 32-byte output. The
input (`key_material`) covers the whole block except the 64 signature bytes, that is
`block[0 .. Offset(Signature)]`.

`BLOCK_ID_CONTEXT` is the 27-byte ASCII string, with no terminator:

```
SBTP 2026-11-18 block_id v1
53 42 54 50 20 32 30 32 36 2d 31 31 2d 31 38 20 62 6c 6f 63 6b 5f 69 64 20 76 31
```

This string is bound to the Version field `0x01`. It MUST NOT be used for any other purpose. Every new value
of the Version field MUST define new strings. (ADR 0002)

### 3.2 Signature

- Algorithm: pure Ed25519 (RFC 8032 §5.1), with no prehashing and no context parameter.
- Signed message: `M = SIG_PREFIX ‖ block_id` (49 bytes). `SIG_PREFIX` is the 17-byte ASCII string, with
  no terminator:

  ```
  SBTP-v1-block-sig
  53 42 54 50 2d 76 31 2d 62 6c 6f 63 6b 2d 73 69 67
  ```

- Signature: `Signature = Ed25519_Sign(sk, M)`. An SBTP key MUST NOT sign a message that starts with
  `SIG_PREFIX` and is not a block signature message. (ADR 0002)
- Verification: strict and mandatory. Let `A` be the PubKey field, `R` the first 32 bytes of the signature
  and `S` the last 32 (little-endian integer, RFC 8032). A verifier MUST reject the block if any of the
  following conditions is true:

  | # | Rejection condition |
  |---|---|
  | V1 | `A` is not the canonical encoding of a point on the curve (RFC 8032 §5.1.3 decoding). Rejected: `y ≥ 2^255 − 19`; `y` not on the curve; `x = 0` with the sign bit set to 1. |
  | V2 | `A` is of small order (`[8]A` is the identity element). |
  | V3 | `S ≥ L`, with `L = 2^252 + 27742317777372353535851937790883648493`. |
  | V4 | `R` does not decode to a point on the curve. |
  | V5 | `R` is of small order. |
  | V6 | The canonical encoding of `[S]B − [k]A` differs from `R` byte for byte, with `k = SHA-512(R ‖ A ‖ M) mod L`. |

  In V6, `R` and `A` enter SHA-512 as received; the digest is read as a 512-bit little-endian integer, then
  reduced modulo `L`. V6 is the cofactorless equation; the cofactored equation MUST NOT be used. Batch
  verification MUST NOT be used to validate a block.
- A sender SHOULD sign deterministically (RFC 8032 §5.1.6) and SHOULD NOT publish two different signatures
  for the same `block_id`. A layer MUST NOT make any state depend on the signature bytes (sorting, random
  selection, deduplication). (ADR 0003)

### 3.3 Proof of work (anti-spam)

- The `block_id` MUST have at least `d` leading zero bits, that is, read as a 256-bit big-endian
  integer, `block_id < 2^(256 − d)`.
- The sender increments `Nonce` until the difficulty is reached.
- The relay checks it in O(1) on the `block_id` it computes anyway, with no shared state.
- The minimum difficulty `d` is a setting of each relay (`min_pow_difficulty`, 0 to 256), published by
  `GET /sbtp/v1/info` (§4). An implementation of validation takes `d` as a parameter and MUST NOT read
  a clock or any ambient state. (ADR 0007)
- The network difficulty `D_NET` is 16. A relay SHOULD set `min_pow_difficulty = D_NET`. A relay that
  takes part in replication MUST NOT set it above `D_NET`; it MAY set it below. A sender that wants its
  block to be accepted by every such relay mines at `D_NET` or above. `D_NET` changes only by a
  revision of this specification; a relay never re-checks C1 on a block it holds. (ADR 0045)
- The recipient of a block requested by its identifier (§3.4) applies C1 with a difficulty `d` of its
  own, independent of any relay, and `d = 0` when it has none. It MUST NOT take `d` from the `/info` of
  the relay that served the block. A block that fails only a recipient's own `d > 0` is refused by that
  recipient's policy; it does not show that the relay served an invalid block. (ADR 0026)

### 3.4 Block identity

A block is identified by its `block_id` alone. The `block_id` does not cover the signature: two valid byte
sequences with the same `block_id` are the same block and can differ only in their 64 signature bytes. Under
the strict verification of §3.2, only the holder of the private key can produce such a variant.

- **Storage.** It is idempotent, "first write wins" rule: a valid block whose `block_id` is already stored
  MUST NOT replace the stored bytes. The rule applies only to fully validated bytes. A stored file that
  fails full validation for its `block_id` is not a stored block. A relay MUST NOT serve it and MAY replace
  it with bytes that pass full validation. (ADR 0023)
- **Replayed block.** If the `block_id` is already stored and the received bytes are identical to the stored
  bytes, signature verification MAY be skipped. If the bytes differ, it MUST be done.
- **Receipt.** Every recipient of a block requested by its identifier (client, peer, cache) MUST, before any
  storage or use: recompute the `block_id` of the received bytes; reject the block if this `block_id`
  differs from the requested identifier (`BlockIdMismatch`); apply full validation (§2.2), criteria V1 to V6
  included, C1 with the recipient's own difficulty (§3.3).
- **Full bytes.** An implementation MUST NOT identify, deduplicate or reference a block by a hash of its full
  bytes. Two relays may return different bytes for the same `block_id`. (ADR 0003)

### 3.5 Registry of domain separation strings

| String | Use | Version |
|---|---|---|
| `SBTP 2026-11-18 block_id v1` | BLAKE3 `derive_key` context of the `block_id` (§3.1) | `0x01` |
| `SBTP-v1-block-sig` | prefix of the signed message (§3.2) | `0x01` |
| (none: BLAKE3 `hash` mode) | `chunk_id` of a layer 1 chunk (ADR 0010) | not bound to Version |
| `SBTP 2026-11-20 sbtp.enc v1` | HPKE `info` of every layer 2 seal (ADR 0016) | layer 2 |
| `SBTP-v1-sealed-sig` | prefix of the Ed25519 signature inside a sealed payload (ADR 0016) | layer 2 |
| `SBTP 2026-11-20 enc_key directory v1` | BLAKE3 `derive_key` context, encryption key directory tag (ADR 0016) | layer 2 |

- Every new use of BLAKE3 or Ed25519 in this specification, all layers included, MUST use a distinct string and add it to
  this table. One exception: the `chunk_id` of a layer 1 chunk is the standard BLAKE3 hash of the chunk
  bytes (`hash` mode, 32-byte output, no string). The `hash` mode is reserved to this use: no other SBTP
  use may hash in this mode, and layer 0 MUST NOT use it. The `chunk_id` does not depend on the Version
  field. (ADR 0002, amended by ADR 0010)
- A `chunk_id` and a `block_id` come from two BLAKE3 modes (`hash` and `derive_key`), which BLAKE3
  separates internally. The separation does not rely on the content or the structure of the hashed bytes:
  a chunk may contain any bytes, those of a block included.
- Every new value of the Version field MUST define new strings.
- **Reserved prefixes.** This table lists the strings of this specification only; it is the list of
  ADR 0002 rule 12. The prefixes `SBTP ` and `SBTP-` of a domain separation string (a BLAKE3
  `derive_key` context, a signature prefix, an HPKE `info`) are reserved for this specification. A
  layer 2 application uses its own context strings and documents them in its own specification. An
  application string MUST NOT start with a reserved prefix and MUST NOT be a prefix of a string of this
  table. Application strings are not registered here. Likewise the kind prefix `sbtp.` is reserved for
  the kinds of this specification (`l2-grammar.md` §1.3).
- A layer 2 tag (ADR 0016, `l2-grammar.md` §5.4) is a `derive_key` output carried as a header parent value. It is not a
  `block_id` and is well-formed like any parent (§2.2); relays treat it as any parent.
- A signature prefix MUST NOT be a prefix of another. A published string never changes and is never reused.
  (ADR 0002)

## 4. Dumb relay interface (HTTP)

A dumb relay validates only binary conformance, its timestamp policy, the PoW and the signature, then
stores the block without interpreting it, unless its operator denies it (see "Denied blocks").

The interface is defined on HTTP semantics (RFC 9110) and does not depend on an HTTP version. A public
relay MUST be reachable over HTTPS. TLS, HTTP/2 and HTTP/3 MAY be terminated by a reverse proxy.

The protocol does not depend on a proxy. The reference relay `sbtp-relay` serves HTTP/1.1. It
terminates TLS when its operator configures a certificate (ADR 0028); otherwise a public
`sbtp-relay` is placed behind a reverse proxy that terminates TLS and buffers request heads (for
example Caddy, nginx or HAProxy). This is a deployment requirement of that program only.
(ADR 0012, ADR 0019, ADR 0028)

A `block_id` in a path or a query string is exactly 64 lowercase hexadecimal characters; any other value
gets `400` (`InvalidParameter`). (ADR 0012)

A relay is reached at the relay URL its operator publishes: scheme, host, optional port and optional
path prefix. The routes of this section are under it. (ADR 0030)

### `PUT /sbtp/v1/block`

- `Content-Type: application/octet-stream`, body = raw binary block.
- Body limit: a relay MUST limit the request body to 65,909 bytes (`MAX_BLOCK_LEN`) at the transport
  level. A longer body gets `413 Content Too Large` before any parsing.
- Processing, in this order (cheapest to most expensive):
  1. format: checks F1 to F9 (§2.2);
  2. timestamp policy: check P1 (§2.2);
  3. PoW difficulty on the `block_id`: check C1;
  4. Ed25519 signature: checks C2 and C3;
  5. deny list: a block the relay's operator denies is not stored (see "Denied blocks");
  6. storage addressed by the `block_id`, without replacing a block already present (§3.4), within the
     relay's storage quota.
- Responses:
  - `201 Created`: the block is valid and the relay did not hold it, or held it expired (see
    `architecture.md` §2, "Eviction"); the relay stored it with a new reception time. The relay SHOULD
    send `Location: /sbtp/v1/block/{block_id}` (lowercase hexadecimal).
  - `200 OK`: the block is valid and the relay holds it, not expired. The stored bytes are not replaced
    and its lifetime is not extended (§3.4). A relay MUST NOT answer `409` in this case.
  - `400 Bad Request`: F1 to F9, P1, C1. Every failure of the binary analysis gets `400`, F2 included if
    it is reached despite the body limit. Error names: the §2.2 error of the failed check; P1 is
    `TimestampTooFarInFuture`.
  - `413 Content Too Large`: body longer than the body limit, rejected before any parsing. Error name:
    `BodyTooLarge`.
  - `408 Request Timeout`: the body did not arrive within the relay's time limit (`RequestTimeout`). The
    relay closes the connection.
  - `422 Unprocessable Entity`: C2 (`InvalidPublicKey`), C3 (`InvalidSignature`).
  - `429 Too Many Requests`: this client is over its allowance, see "Admission control".
  - `507 Insufficient Storage`: the block is valid and new, and the relay has no room for it
    (`StorageFull`). Nothing is stored. A valid block that the relay holds, not expired, still gets
    `200`. An expired block whose file the relay still holds MUST NOT get `507` because of the quota.
  - `503 Service Unavailable`: the relay is starting, stopping or at one of its own limits
    (`Unavailable`), see "Admission control".
  - `451 Unavailable For Legal Reasons`: the block is valid and the relay's operator denies it
    (`Denied`, or `DeniedKey` when its public key is denied). Nothing is stored. A denied block never
    gets `200` or `201`. (ADR 0052)
- A client MUST treat `200` and `201` as the same success. When concurrent requests carry the same new
  `block_id`, at most one gets `201`. (ADR 0004, ADR 0007, ADR 0008, ADR 0012, ADR 0013, ADR 0018,
  ADR 0043)

### `GET /sbtp/v1/block/{block_id}`

- Response: full block as `application/octet-stream`.
- `200 OK`; `404 Not Found` (`NotFound`) when the relay does not hold the block; `400 Bad Request`
  (`InvalidParameter`) when the identifier is malformed.
- A relay MUST serve only bytes that pass full validation (§2.2) and R1 for the requested `block_id`. A
  stored file that fails gets `404` (`NotFound`). A `200` response SHOULD carry `Cache-Control: public,
  max-age=31536000, immutable`. A relay that evicts by demand MUST instead bound shared caches to half
  its demand epoch `S`, on every `200` and `304`: `Cache-Control: public, max-age=31536000,
  s-maxage=<S>, immutable` and `CDN-Cache-Control: public, max-age=<S>, must-revalidate` (RFC 9213),
  with the `ETag`, so that a shared cache revalidates each requested block at least once per `S`.
  (ADR 0023, ADR 0046)
- A `200` response MAY carry `ETag: "<block_id>"` (lowercase hexadecimal, a strong validator). A relay
  that sends it answers a request whose `If-None-Match` matches it (RFC 9110 §13.1.2) with `304 Not
  Modified`, the same `ETag` and `Cache-Control` and no body, and only for a block it would serve with
  `200`.
- A relay MAY evict blocks, by age (`block_ttl_ms`) or by demand (`demand_eviction`), both published by
  `/info`. A `404` does not mean that the block does not exist. (ADR 0013, ADR 0046)
- `451 Unavailable For Legal Reasons` (`Denied`): the relay's operator denies the block. The relay
  answers it whether or not it holds the bytes, and never answers `304` for it. (ADR 0052)
- A relay that copies blocks from another relay sends `Sbtp-Replication: 1` on its requests. A relay
  that evicts by demand MUST NOT count such a `GET` or `HEAD` as demand and MUST answer it with
  `Cache-Control: no-store` and `CDN-Cache-Control: no-store`; another relay SHOULD answer it with
  the same headers. (ADR 0048)
- The recipient MUST check that the received block carries the requested `block_id` and validate it
  (§3.4). The `min_pow_difficulty` of `/info` applies to `PUT` only (§3.3).

### `POST /sbtp/v1/blocks`

- Batch read. Body: 1 to 256 distinct `block_id` values, 32 raw bytes each, concatenated,
  `Content-Type: application/octet-stream`. An empty body, a length that is not a multiple of 32 or a
  duplicate gets `400` (`InvalidParameter`); a body over 8,192 bytes gets `413` (`BodyTooLarge`) before
  it is read. The request changes nothing and is safe to repeat.
- A request without `Content-Length`, or with any `Transfer-Encoding`, is charged 64 tokens at
  admission (see "Admission control"), then gets `400` (`InvalidParameter`) with `Connection: close`;
  the relay closes the connection before it reads the body. (ADR 0051, clarification B1)
- Response: `200`, `application/octet-stream`, `Cache-Control: no-store`. One record per requested
  identifier, in request order: `length` (u32, big-endian) then `length` bytes of the block.
  `length = 0`: the block is not served. A denied block is a `length = 0` record (ADR 0052). The relay
  serves only bytes it would serve with `GET /block`
  and MAY end the body after any complete record (at least one); the client requests the rest again. A
  relay MUST NOT start a record that brings the body above 1,048,576 bytes, nor once half of its
  request time limit has passed. (ADR 0051, clarification B3)
- When the first record cannot be read, the relay answers as `GET /block` would (`503` when busy,
  `500` on an I/O error). A later record that cannot be read ends the body before it. `length = 0`
  means only that the block is not served, never an error. (ADR 0051, clarification B5)
- The recipient checks each record as a requested block (§3.4, R1 against the identifier at that
  position). A `length` above 65,909 makes the response a failed request. A body that ends inside a
  record is a failed request; the complete records before it MAY be used.
- Each served block counts as demand once per epoch, except with `Sbtp-Replication: 1`, which also gets
  `CDN-Cache-Control: no-store`. `If-None-Match` does not apply.
- `GET /block` is the cacheable form. A client SHOULD use it for the blocks of a view and SHOULD use
  batches for walks and bulk fetches. A `read_only` URL has no batch route. (ADR 0051)
- A shared cache MUST NOT store a batch response. A cache rule for blocks in front of a relay MUST
  match the prefix `/sbtp/v1/block/` with its trailing slash, so that it never matches
  `/sbtp/v1/blocks`. (ADR 0051, clarification B9)

### `GET /sbtp/v1/info`

- Response: `200 OK`, `application/json`, a JSON object with at least:

  ```json
  {
    "min_pow_difficulty": 16,
    "max_future_ms": 300000,
    "block_versions": [1],
    "max_query_limit": 1000,
    "block_ttl_ms": null,
    "demand_eviction": true
  }
  ```

- `min_pow_difficulty`: integer from 0 to 256, the difficulty `d` of check C1 (§3.3).
- `max_future_ms`: integer, in milliseconds. The relay rejects a submitted block whose Timestamp is greater
  than its clock plus this value (P1). Default: 300,000.
- `block_versions`: array of the Version field values the relay accepts (F4).
- `max_query_limit`: integer from 1 to 1,000, the largest page of `/query`.
- `block_ttl_ms`: integer in milliseconds, or `null` when the relay does not evict by age. A relay never
  publishes `0`.
- `demand_eviction`: boolean; `true` when the relay evicts the blocks requested least recently once
  its store is near full (`architecture.md` §2, "Eviction"). A client MUST read an absent member as
  `false`. (ADR 0046)
- `read_only`: boolean; `true` when the URL serves `GET /sbtp/v1/block/{block_id}` and `/info` only,
  for example a bucket of static objects. A client MUST NOT send `PUT` or `/query` to it. For
  `GET /block` on such a URL, any status other than `200` or `304` means that the block is not served
  there. A client MUST read an absent member as `false`. (ADR 0050)
- `read_api`: integer; `2` when the relay implements `POST /sbtp/v1/blocks` and the `/query`
  parameters `order`, `fields` and repeated `parent` with the `head` member. A client MUST read an
  absent member as `1`, and MUST NOT send `POST /blocks`, `order`, `fields`, a repeated `parent` or a
  per-parent cursor to a relay without `read_api` ≥ 2. The bounds of these routes (256 identifiers,
  1,048,576 bytes, 32 parents, 200 entries with `fields`) are fixed by the protocol. (ADR 0051)
- `deny_list`: boolean; `true` when the relay applies a deny list of its operator, whatever its
  entries. A client MUST read an absent member as `false`. (ADR 0052)
- A relay MAY publish `software` (free string). `sbtp-relay` does not publish it. (ADR 0019)
- A relay MAY publish `graph_gateway`, the URL of a graph gateway that its operator runs over this
  relay (`graph-access.md` §3, §5). It is a hint, not a guarantee. (ADR 0040)
- A relay MAY publish `relays`, a relay list (at most 16 relay URLs, each under the rules of a relay
  hint) chosen by its operator. It is a hint. A client reads an absent member as an empty list and
  does not send the user's own traffic to a listed relay unless the user chose it. (ADR 0048)
- A client MUST accept the absence of any member other than `min_pow_difficulty` and `max_future_ms`.
  (ADR 0007, ADR 0012)
- A relay MAY add members; the body is at most 16,384 bytes. A client MUST ignore members it does not
  know. A relay MAY change its settings at any time. A sender SHOULD read `/info` before mining.
  (ADR 0007, ADR 0029)

### `GET /sbtp/v1/query?parent=&since=&limit=&cursor=&order=&fields=`

- Discovery of blocks, and of children in the DAG. All parameters are optional. A parameter that is
  unknown, repeated (other than `parent`) or malformed gets `400` (`InvalidParameter`).
  - `parent`: only blocks whose Parents Hashes field contains this `block_id`. The relay does not need to
    hold the parent.
  - `since`: decimal u64. Only blocks that the relay stored at or after this Unix time in milliseconds,
    by the relay's clock. This is not the Timestamp field.
  - `limit`: integer ≥ 1, default 100. A value above the relay's `max_query_limit` (§4, `/info`) is
    lowered to it.
  - `cursor`: opaque value, 1 to 128 characters of `A-Z a-z 0-9 - _`, taken from a previous response of
    the same relay. A value outside this syntax is malformed (`InvalidParameter`). A value within it
    that the relay did not issue for its current index epoch gets `400` (`InvalidCursor`), whatever its
    length or alphabet. A relay MUST issue cursors within this syntax. (ADR 0012, clarification K1)
  - `parent` MAY be repeated, 1 to 32 distinct values; then each value is `<block_id>` or
    `<block_id>.<cursor>`, a per-parent cursor that overrides `cursor`. `limit` applies per parent,
    lowered to `max(1, ⌊max_query_limit / N⌋)` for `N` parents. A 33rd or a repeated value, or the
    `.<cursor>` form with a single `parent`, gets `400` (`InvalidParameter`).
  - `order`: `asc` (default) or `desc` (newest first).
  - `fields`: `parents`. Adds `parents` (for each block, its Parents Hashes in header order) and `lens`
    (its length in bytes), aligned with `block_ids`; the page is at most 200 entries. Not allowed with
    `parent` (`400` `InvalidParameter`). They are hints: a block's own header is authoritative once
    fetched (§3.4). (ADR 0051)
- Order: the relay's store order, oldest first with `asc`, newest first with `desc`. It is stable on one
  relay and differs between relays. A cursor names a gap in that order and is valid in both orders:
  `asc` returns blocks after it, `desc` before it. `since` and the expiry bound end a `desc` walk. A
  client MUST NOT derive application state from the order. (ADR 0051)
- Response: `200 OK`, `application/json`, `Cache-Control: no-store`:

  ```json
  { "block_ids": ["0000a3…17cdef"], "cursor": "k3_Zr0AAAAEAAAAq", "more": false }
  ```

  - `block_ids`: 0 to `limit` identifiers in order, each at most once.
  - `cursor`: always present. The same request with this cursor returns the matching blocks not returned
    so far. A cursor is valid with any `parent`, `since`, `order` and `fields`. It survives a clean restart of the relay. After an
    unclean shutdown the relay MAY refuse every earlier cursor with `400` (`InvalidCursor`). A client MUST
    accept `InvalidCursor` on any request; it then walks again without a cursor and deduplicates by
    `block_id`. (ADR 0012, ADR 0024)
  - `more`: `true` if at least one more matching block existed when the response was built.
  - `head`: always present, a cursor for the gap after the newest position held when the response was
    built. `asc` from `head` returns exactly the matching blocks stored since. (ADR 0051)
  - An empty `desc` page returns as `cursor` the gap it started from: the cursor sent, or `head` when
    the request had no cursor for that listing. (ADR 0051, clarification B4)
- With two or more `parent`, the body is `{ "parents": [ {"parent", "block_ids", "cursor", "more"} … ],
  "head" }`, one entry per requested parent in request order, each with the meaning of a single-parent
  response. A grouped request is one index read. (ADR 0051)
- A listing is complete when its `more` is `false`. A client that derives state from the absence of a
  block MUST use only complete listings, MUST NOT present a listing that ended with `more = true` as
  complete, and keeps `head` to poll the shown parents. (ADR 0051)
- Over several relays, a listing is complete only when every relay of the client's list was asked and
  returned a complete listing. A relay skipped because it lacks `read_api` ≥ 2 counts as not asked. A
  client that merges `fields` hints from several relays MUST take, for each `block_id`, the union of
  the parents they list: a hint can only add a fetch. (ADR 0051, clarification B8)
- A request with no match gets `200` and an empty `block_ids`, an unknown `parent` included. A relay MUST
  NOT answer `404`.
- A relay MUST NOT list a block it denies by `block_id`. A block denied by its public key MAY be
  listed until the relay has marked it, and gets `451` on a fetch. A page MAY hold fewer than `limit`
  identifiers, and `more` MAY be `true` when only denied blocks remain. (ADR 0052)
- To read all children of a block, a client repeats the request with the returned `cursor` until `more`
  is `false`. Repeating it later returns the children stored since. A client MUST deduplicate by
  `block_id` and MUST fetch and validate each block (§3.4); the fetch can return `404`.
- A relay MUST serve a request with work in `O(log n + limit)`, in both orders. (ADR 0012, ADR 0013) The response body
  is at most 131,072 bytes, members added by the relay included. (ADR 0029)
- A relay that cannot read its index to build a page answers `500` (`Internal`). This invalidates no
  cursor: only `InvalidCursor` does. The client keeps its cursor and retries later with exponential
  backoff (see "Admission control"). (ADR 0012, clarification K2)

### WebSocket

Not specified in this version. A relay MUST NOT expose a WebSocket endpoint under `/sbtp/v1/`. Clients
poll `/query` with a cursor. The WebSocket ADR offers a subscription by parent set (ADR 0051 rule 30).
`[Q-23]`

### Errors

- Every `4xx` and `5xx` response produced by a relay carries `Content-Type: application/json` and a JSON
  object `{ "error": "<name>", "message": "<text>" }`. `error` is required. `message` is optional, at
  most 200 characters, for humans only; it MUST NOT contain block bytes, paths or internal error text.
- An error body is at most 16,384 bytes. (ADR 0029)
- Names: the §2.2 error names for F1 to F9, C1, C2 and C3; `TimestampTooFarInFuture` (P1);
  `BodyTooLarge` (`413`); `InvalidParameter`, `InvalidCursor` (`400`); `NotFound` (`404`);
  `MethodNotAllowed` (`405`); `RequestTimeout` (`408`); `RateLimited` (`429`); `Internal` (`500`);
  `Unavailable` (`503`); `StorageFull` (`507`); `Denied`, `DeniedKey` (`451`, ADR 0052).
- A request that is not valid HTTP, or whose headers are too large, MAY be answered by the HTTP layer of
  the relay without this body. (ADR 0018)
- Error responses carry `Cache-Control: no-store`. (ADR 0012, ADR 0023)
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
  from an allowed origin gets a `2xx` with `Access-Control-Allow-Methods: GET, PUT, POST`,
  `Access-Control-Allow-Headers: Content-Type` and `Access-Control-Max-Age: 86400`. (ADR 0012)

### Redirects

- A relay, and a proxy or mirror serving its relay URL, MUST NOT answer a request under `/sbtp/v1/`
  with a `3xx` status, a preflight included. The exception is `304 Not Modified` to a conditional
  request the client sent.
- A client MUST NOT follow a redirect. A `3xx` response, other than such a `304`, is a failed request
  (see "Client bounds"): its `Location` and its body are not used. A client SHOULD NOT repeat the
  request automatically and SHOULD report that the relay URL redirects.
- A browser client sets `redirect: "manual"` (recommended: an `opaqueredirect` response shows the
  redirect) or `redirect: "error"` on every `fetch()` to a relay. Other clients turn off the
  redirect following of their HTTP library.
- A redirect on another origin, such as a proxy that sends plain HTTP on port 80 to `https`, is
  outside this interface. A client still does not follow it.
- A relay that moves announces its new URL out of band; a reverse proxy at the old URL MAY forward to
  it. (ADR 0028, ADR 0030)

### Denied blocks

- A relay MAY apply a deny list set by its operator, by `block_id` or by the public key of the
  header. It does not interpret payloads to apply it. The list is local configuration; it is not
  published or exchanged.
- For a denied block the relay answers `451` with `Cache-Control: no-store` and
  `CDN-Cache-Control: no-store`, on `GET`, `HEAD` and `PUT`, and serves it as `length = 0` in a
  batch. It does not state the ground, the requester or, on a read, whether the match is by block or
  by key.
- A client handles a `451` to a read as a block not served by that relay and MAY ask another relay.
  It MUST NOT treat it as proof that the block is invalid or absent elsewhere.
- A client that receives `451` for a block it publishes treats it as a final refusal by that relay,
  continues with its other relays, and MUST NOT send that block to that relay again automatically.
  When that relay had already acknowledged the block, the `451` changes the block's availability on
  that relay, not its delivery: see "Client bounds".
  After `DeniedKey` it MUST NOT send any block signed by that key to that relay automatically. A user
  action MAY. A client MUST NOT create a new block automatically because of a `451`.
- A re-submission after a missing block follows a `404` to a single `GET` or `HEAD`, never a
  `length = 0` batch record alone.
- A relay MUST NOT fetch, store or serve a block it denies through replication, read-through or any
  other function, and MUST NOT deny a block because another relay or source denies it.
- A deny list does not reach copies outside the relay: shared caches, object stores, other relays,
  clients. (ADR 0052)

### Admission control

- A relay bounds what it spends: connections, requests per client, concurrent operations and the
  duration of a request. The limits are local settings of each relay and are not published by `/info`.
- `429 Too Many Requests` (`RateLimited`): this client is over its own allowance, in requests per period
  or in requests in flight. The relay answers before reading the body and SHOULD send `Retry-After` in
  seconds. A relay counts clients by address; an IPv6 /64, or the users of one shared address, are one
  client. A client SHOULD keep at most 8 requests in flight per relay. A `/query` request takes
  `⌈N/8⌉` tokens of its bucket (`N` parents, 1 when absent) and a batch `⌈N/4⌉` (`N` identifiers,
  `⌈Content-Length / 32⌉`; at least 1 token, so that a `400` is never free), capped at the burst, at
  admission. A relay MUST refuse at start-up a burst below 64 for batches and below 4 for `/query`, so
  that the cap never buys more than 4 blocks or 8 parents per token. (ADR 0051, clarifications B2
  and B6) A relay MAY also bound the bytes
  stored per hour from a network prefix (an IPv6 /56 or /48, an IPv4 /24); a `PUT` over that bound gets
  `429` before its body is read. (ADR 0049)
- `503 Service Unavailable` (`Unavailable`): the relay is at one of its own limits, starting or
  stopping. The refusal does not depend on the client. The relay SHOULD send `Retry-After` in seconds.
  A relay whose store is near full MAY bound the bytes it stores per hour from all clients together; a
  new block over that bound gets `503` with `Retry-After`, and a block the relay holds still gets `200`.
  (ADR 0049)
- `408 Request Timeout` (`RequestTimeout`): the request body did not arrive in time.
- A relay MAY close a connection without a response: when it is idle or too slow, when the client holds
  too many connections, or after a number of requests or a duration. A response MAY carry
  `Connection: close`. (ADR 0019)
- A client MUST NOT repeat the request before `Retry-After` has elapsed. Without the header, it SHOULD
  back off exponentially with jitter, starting at 1 second. After `408` or a closed connection it MAY
  retry once at once, then backs off. Every request of this interface is safe to repeat (`PUT` is
  idempotent). A `Retry-After` that is not a number of seconds gives no delay: the client backs off as
  without it, or gives up the operation on that relay. A client MAY give up on a relay whose
  `Retry-After` exceeds its maximum wait; it still does not repeat the request to it earlier. (ADR 0029)
- A `502` or `504` comes from a proxy or gateway in front of the relay, not from the relay. A client
  handles it as a `503`: it keeps its cursor and the blocks it could not publish, obeys `Retry-After`
  when present and otherwise backs off as above. It does not restart a walk. (ADR 0012, clarification
  K3)
- A relay under load refuses `/query` and `PUT` before `GET /block`. A client SHOULD keep its cursor and
  the blocks it could not publish, and retry. (ADR 0007, ADR 0012, ADR 0018)

### Client bounds

- A client treats every relay, proxy and mirror as untrusted. What it spends because of one relay
  (memory, storage, time, mining effort) depends on its own settings, not on what the relay sends.
  The values are client settings; the protocol requires the bounds. (ADR 0029)
- Body ceilings, after removal of any content coding: `GET /block` 65,909 bytes; `POST /blocks`
  1,048,576; `/query` 131,072; `/info` 16,384; any `4xx` or `5xx` 16,384. A relay MUST NOT exceed them. A client MUST accept a
  body at or under its ceiling and MUST stop reading at the ceiling plus one byte. A `2xx` body above
  its ceiling is a failed request; an error body above it is unparseable.
- Every request has a total time limit that covers the whole body.
- A `/query` response is a failed request when it is not the object defined under `GET /sbtp/v1/query`, holds more
  identifiers than the `limit` sent (per parent in a grouped response), or holds a malformed identifier or cursor. None of its
  identifiers is used.
- A client MUST bound the pages or identifiers of one walk, the blocks it fetches from hints, the
  blocks visited in one DAG traversal (each `block_id` at most once) and the blocks it keeps in
  memory and in local storage. At a bound it stops and keeps what it has validated; this is not an
  error. A page with `more = true` may be short or empty.
- When it drops blocks to stay within its storage budget, a client MUST NOT drop the user's private
  keys, nor a protected block the user created. Such a block is protected while no relay of the
  client's relay list has acknowledged it with `200` or `201`, or while one has and another relay of
  the list is still pending for it. It drops blocks fetched from relays first, then own blocks that
  are not protected. Only to store a new own block, it MAY drop a block of the second kind, oldest
  first acknowledgement first. (ADR 0029, ADR 0047)
- A relay that acknowledged a block and later answers `451` to a `GET` or `HEAD` of it stays
  acknowledged, but no longer counts as holding the block for this protection, nor as pending for it.
  The bounded time since the block's first acknowledgement does not restart. (ADR 0047, ADR 0052)
- A relay stops being pending for a block when it acknowledges it; when it refuses it with an answer
  that does not change on a repeat (`400` other than `TimestampTooFarInFuture`, `413`, `422`, a
  `3xx`, another `4xx` other than `408` and `429`); when the client has made a bounded number of
  attempts to it over at least a bounded time; when a bounded time has passed since the block's first
  acknowledgement; or when the user removes it from the list. A request not sent because of a
  back-off is not an attempt. The bounds are client settings. (ADR 0047)
- A relay added to the list is pending for every block protected at that moment. Acknowledgements
  by a relay removed from the list no longer count. (ADR 0047)
- An `/info` response whose `min_pow_difficulty` is not an integer from 0 to 256, or whose
  `max_future_ms` is not a non-negative u64, is a failed request. A sender that mines at the
  difficulty a relay publishes has a maximum it accepts that way; above it, it does not mine for that
  relay. The difficulty applied on receipt is the client's own (§3.3).
- A failed request is treated like a network failure: nothing from it is used. The client backs off
  before repeating it, or ends the operation. A `3xx` response is a failed request that is not
  repeated (see "Redirects"). (ADR 0029, ADR 0030)
- Peer-to-peer bounds are not specified in this version. `[Q-26]`

### Several relays (non-normative)

Nothing in this subsection is a new rule. It is guidance for a client that uses several relays, and
follows from §3.3, §3.4 and the subsections above.

- A block is the same block on every relay: it is identified by its `block_id` (§3.4). A client merges
  `/query` results from several relays and deduplicates them by `block_id`, never by the full bytes.
- Every block, from every relay, goes through the receipt rule (§3.4). A block that fails it is
  discarded and the block MAY be requested from another relay. A block that fails only the client's own
  difficulty floor fails it on every relay: its proof of work depends on its `block_id` alone (§3.3).
- A cursor is only valid on the relay that issued it (`GET /sbtp/v1/query`). A client keeps one cursor
  per relay and never sends a cursor to another relay.
- A sender that mines once for several relays mines at `D_NET` or at the highest
  `min_pow_difficulty` among them, whichever is higher, each read within its maximum (see "Client
  bounds"); it does not mine for a relay above that maximum. (ADR 0045)
- `PUT` is idempotent: a block refused or not reached on one relay MAY be sent again to it later,
  except a block the relay denied (see "Denied blocks"). The
  client keeps it until each relay of its list has acknowledged it or is no longer pending for it (see
  "Client bounds").
- The bounds of "Client bounds" hold per relay; the number of relays is a client setting, so the total
  stays a function of the client's settings. `Retry-After` and the back-off apply to the relay that
  sent them.

### Fast first catch-up (non-normative)

Nothing in this subsection is a new rule. It is guidance for a client's first start on a large graph,
and follows from the subsections above. Estimates are in ADR 0051, "Fast first catch-up".

- **Snapshot first.** A client MAY start from a snapshot: blocks cut from one relay walked to
  `more = false`, with a resume point (that relay's URL, the `head` of its last response and the `Date`
  of that response). A snapshot is not a protocol object; its format and host are its producer's. One
  static object behind a CDN is one cacheable `GET`, with no relay rate limit. Every block in it goes
  through the receipt rule (§3.4), like a block from a relay.
- **Resume, do not walk again.** `/query` with no `parent`, `asc`, from the snapshot's `head` lists
  exactly the blocks that relay stored after the cut. On another relay, or after `InvalidCursor`, the
  client uses `since` with a margin and deduplicates by `block_id`.
- **Bulk from a bucket mirror.** A `read_only` URL behind a CDN (`/info`) serves `GET /block` with
  immutable caching: single requests, served from the CDN edge, with no relay allowance spent. It has no
  `/query`; identifiers come from a relay or the snapshot.
- **Batches for gaps and recent blocks.** Identifiers that the bucket did not serve, and blocks too
  recent for it, go to `POST /sbtp/v1/blocks` on a relay with `read_api` ≥ 2.
- **Order.** Snapshot; `/info` of each relay; `asc` from `head`; the blocks of the current view by single
  `GET`; the rest of the delta from the bucket, then by batch; then grouped `asc` polls from `head`.

### Client implementations (non-normative)

Nothing in this subsection is a new rule. The project maintains a TypeScript client library (and
later a Rust one, `sbtp-client`) that implements the client rules of this section: transport rules,
`/info` and capability gating, walks, batch fetch, admission, completeness, publication, delivery
state of own blocks and re-submission. Client libraries are conforming implementations, not part of
this specification; where one differs from this specification, the specification applies. The client
conformance cases are in `docs/test-vectors/` (`client-v1/`) and MAY be run by any client.
(ADR 0053)

## 5. P2P synchronisation and gossip

```
Node A                                  Node B
  | --- 1. Digest handshake ----------->|  Bloom filter or range-based reconciliation
  |<-- 2. Missing hashes ---------------|  delta computation
  | --- 3. Targeted GETs (batched) ---->|
  |<-- 4. Raw binary blocks ------------|  validation then insertion into the local DAG
```

The first stage is pull replication between relays (`architecture.md` §2, "Replication"): a relay is
a client of the peers its operator chooses and walks their `/query` with a cursor. Set reconciliation
replaces the walk later and keeps the same peer model `[Q-11]`. Client nodes exchange relay lists
first; peer-to-peer serving over WebRTC is opt-in and specified later `[Q-26]`. (ADR 0048)

1. **Digest exchange** over a time window, either: a Bloom filter with a controlled false-positive
   rate, or *range-based set reconciliation* over a time-based Merkle tree. `[Q-11]`
2. **Delta computation**: the exact set of missing `block_id` values.
3. **Targeted retrieval**: `GET /sbtp/v1/block/{block_id}` in batches from the peers that hold them.
4. **Integration and gossip**: each received block is checked against the requested identifier, validated
   independently (§3.4), stored, then its `block_id` is announced to adjacent peers.

Out of scope for the MVP (phases 1 to 4): P2P synchronisation is specified here to guide the design,
but is not planned before the end of Phase 4.
