# Overall architecture and relay model

> The layer numbering and names below are normative (ADR 0006).

## 1. The three layers

| Layer | Name | Components | Role |
|---|---|---|---|
| **0** | SBTP Core | binary blocks, BLAKE3, Ed25519, PoW, DAG, relay interface | Transport and validation of atomic blocks. Crates `sbtp-core`, `sbtp-relay`. |
| **1** | Media / Chunks P2P | 256 KiB chunks, manifests, WebRTC Data Channels | Distribution of large objects and media streams. (ADR 0010) |
| **2** | Application | client interpretation, tombstones, rolling indexes | Semantics, cryptographic moderation, discoverability. Shared grammar and sealed envelope: `l2-grammar.md`. Applications are specified and implemented outside this repository (ADR 0038). |

**Separation rule:** layer 0 imposes no business rule, no schema, no moderation. Everything that
interprets a payload lives in layer 2, on the client or indexer side. A relay never parses a payload.

### Layer 0
Each block is identified by its BLAKE3 digest and signed with Ed25519. The PoW regulates emission. The
topology is a DAG, with no linear chain and no global consensus.

### Layer 1
Files and streams are split into chunks of **256 KiB** (262,144 bytes); the last chunk of an object may be
shorter. A chunk is a raw byte sequence outside the SBTP envelope: no header, no signature, no proof of
work. It is identified by its `chunk_id`, the standard BLAKE3 hash of its bytes (`hash` mode, 32 bytes;
`sbtp-core-v0.2.md` §3.5), and a recipient MUST check it before any use. A manifest, carried in the
payload of a signed SBTP block, lists the `chunk_id` values of the object in order. Authorship comes from
the manifest block only. Lightweight relays help set up WebRTC Data Channels between peers for
high-throughput transfer. Transport and admission of chunks: `[Q-21]`. (ADR 0010)

### Layer 2
Clients interpret the DAG to build application views. Every application shares one payload grammar
and one sealed envelope (`l2-grammar.md`); applications are specified and implemented outside this
repository (ADR 0038). A payload declares the meaning of each header parent through typed edges (ADR
0015). An author retracts its own blocks with a signed tombstone; moderation relies on signed blocks
published by keys the user chooses to trust (verb `moderates`), not on physical deletion. Signed rolling
indexes give the recent state without walking the whole history. Programs read the graph without scraping
pages through the `sbtp:` URI, the JSON block view and an optional graph gateway (`graph-access.md`).

Blocks are public by default. Layer 2 adds a sealed envelope (`sbtp.enc`, HPKE RFC 9180) for payloads
addressed to chosen recipients. A sealed block is an ordinary layer 0 block signed by a one-time key, whose
single parent is a delivery tag that recipients find with `/query?parent=`; relays need no change and
still never parse a payload.
The header (PubKey, Timestamp, parents, length) and the IP addresses seen by relays are not hidden.
(ADR 0016; `l2-grammar.md` §5)

## 2. Internal design of a dumb relay (no external database)

### Ingestion
Direct reading of the network buffer, parsing by offsets (O(1)), no copy.

### Validation pipeline
1. Format: overall size, offsets, magic bytes.
2. Timestamp policy: Timestamp against the relay clock plus the configured window (ADR 0007).
3. PoW: digest difficulty against the configured threshold.
4. Ed25519: signature against the public key in the header.

On the first failure, the block is rejected without allocating any persistent resource.

### Content-addressed storage
```
/data/blocks/
└── ef/                      last byte of the block_id (hex), one of 256 directories
    └── 0000a3…17cdef.bin
```
- Raw binary files, named by the full `block_id` (lowercase hex). A relay MUST derive the shard
  directories from the trailing bytes of the `block_id`, never from the leading bytes: the proof of work
  sets the leading bits to zero. The layout is internal to a relay and is not part of the protocol.
  (ADR 0009)
- The 256 shard directories are created at start-up, before the relay accepts blocks. A relay never
  creates a shard directory on the write path and never removes one. (ADR 0025)
- The final file is created exclusively, so that "first write wins" holds under concurrency
  (`sbtp-core-v0.2.md` §3.4).
- The block is written to a temporary file, flushed to disk, then created under its final name.
- In-memory LRU cache (`moka`) for hot blocks, bounded in bytes.

### Index
- Block files are the only source of truth. The index is derived data: a relay MUST be able to rebuild it
  from the block files. Its format is internal to a relay.
- When a relay stores a new block, it records `received_at` (its clock, Unix milliseconds) and assigns a
  position `(received_at, n)`. Positions strictly increase in storage order; `received_at` never
  decreases.
- For each stored block the index holds its position, its `block_id`, its length and one edge
  `(parent, position) → block_id` per parent. Parents are read from the header. The relay reads nothing
  after the Parents Hashes field.
- The index MAY list a block that the relay no longer holds; a stored block missing from the index MUST
  be repaired (on the next `PUT` of that block, and after an unclean shutdown). When the start-up
  reconciliation indexes a block that was missing from the index, the relay draws a new index epoch, so
  that cursors issued before the crash are refused rather than skip blocks. (ADR 0024)
- Backend: an embedded key-value store (redb) in one file next to the block files, with an explicit
  cache size. This choice is conditional on the benchmark of ADR 0013 (binary under 5 MB, memory well
  under 15 MB at one million blocks); if the benchmark fails, the backend is decided again. The benchmark
  runs the relay binary itself, over loopback HTTP. (ADR 0013, protocol clarified by ADR 0017)

### Eviction
- A relay keeps what it receives. Eviction by age is a setting: a block expires when
  `received_at + block_ttl_ms ≤ now`; `sbtp-relay` disables it by default (`block_ttl_ms = 0`, `/info`
  `null`). A `PUT` of a held, unexpired block does not extend its lifetime. From its expiry a block is
  not held for `PUT`: a `PUT` of it is a new block (`201`, new `received_at`), even before the sweeper
  has deleted it, and the sweeper then deletes nothing of it. (ADRs 0013, 0043, 0046)
- Eviction by demand: when the store is above a high-water mark of the quota, the sweeper evicts the
  blocks requested least recently until it is at a low-water mark. Demand is its acceptance, a `GET`
  answered `200` or `304`, a `PUT` answered `200`, and the acceptance of a child; at most one per block
  per epoch `E`, whatever the client. A block whose last demand is less than `3 × E` old is not
  evicted. A lost demand suspends eviction by demand for `2 × E`, as do an unclean stop, a first start
  without demand history and a change of `demand_eviction` from off to on. A `PUT` never evicts.
  (ADR 0046)
- A relay that evicts by demand bounds shared caches to `E / 2` with `s-maxage` and
  `CDN-Cache-Control`, so that a block requested through a cache is revalidated, and counted, at least
  once per `E / 2`. (ADR 0046)
- `/query` never lists an expired block. Evicted blocks leave `/query` when the sweeper removes them:
  cache entry, block file, then index entries. Edges of their children stay.
- An archive relay disables both; it never deletes a block. (ADRs 0019, 0046)
- Eviction is local to a relay and is not a deletion mechanism. (ADR 0013)
- Long-lived blocks are kept available by archive relays and by clients that submit them again after
  a `404` or an expiry; a `PUT` never renews a block before it expires. (ADR 0043)

### Quota
- `max_store_bytes` bounds the block files and quarantined files (each counted in 4,096-byte units
  plus 128 bytes for its directory entry), a fixed charge of 1,060,864 bytes for the directories, and
  the index. File system metadata and directory space left after removals are left to the free-space
  margin. (ADRs 0013, 0023 and 0025)
- A new block that does not fit gets `507 Insufficient Storage`. A `PUT` never evicts to make room;
  only the sweeper evicts, by age or by demand. A full relay keeps serving reads. (ADRs 0013, 0046)

### Replication
- A relay MAY copy blocks from peers that its operator lists in `peers` (relay URLs, `https` only).
  It walks each peer's `/query` with a cursor kept per peer, skips the blocks it holds and those below
  its `min_pow_difficulty`, fetches the others with `GET`, validates each as a `PUT` body (F1 to F9,
  P1, C1, C2, C3) and R1, and stores it as an accepted block. It never re-mines, re-signs or alters a
  block, never follows a redirect and never adds a peer from what it receives. (ADRs 0045, 0048)
- Replication is off by default (`peers` empty). It runs within its own bounds per profile, obeys
  the peer's `Retry-After`, and stores nothing while the store is above the high-water mark. A
  replicating relay does not set `min_pow_difficulty` above `D_NET`. (ADR 0048)
- A copy is not a read: replication requests carry `Sbtp-Replication: 1`, and a source that evicts
  by demand does not count them as demand (core spec §4, `GET /sbtp/v1/block/{block_id}`).
  (ADR 0048)
- A mirror outside the relay MAY copy blocks by a `PUT` of the same bytes instead. It never re-mines,
  re-signs or alters a block. A block below the target's `min_pow_difficulty` is skipped for that
  target and counted; it is not an error of the source. (ADR 0045)
- When `D_NET` is raised, clients mine at the new value from its announcement and relays raise their
  floor at its effective date. Blocks mined earlier stay where they are held. (ADR 0045)

### Admission control
- Every request has a cost bounded by constants and settings: time, memory and index work.
- Every operation that reads the index, reads or writes a block file, buffers a request body or verifies
  a signature runs under a bound: a number of permits and a bounded queue. No code path reaches the
  index, the block files or the blocking pool outside these bounds.
- At a bound the relay refuses with `429` (this client is over its allowance) or `503` (the relay is at
  one of its own limits). It does not wait without a time limit and keeps no unbounded queue.
- The peak memory of the relay process is a function of its settings, not of the number or the behaviour
  of clients. The relay computes the bound from its settings and logs it at start-up: caches, plus
  connections, `PUT` bodies in flight, read working sets and limiter entries, each at its maximum.
- Index reads run on a fixed set of dedicated threads (`index_max_readers`) and index writes on one
  dedicated writer thread. No other thread touches the index.
- A connection is new, reading a request head, serving a request, or idle between two requests. One
  time limit applies to each phase (`header_timeout_ms` for the first two, `request_timeout_ms`,
  `idle_timeout_ms`). A new connection that sends nothing is closed at `header_timeout_ms`. (ADR 0019)
- One client holds at most `max_connections_per_client` connections, or requests in flight when it
  comes through a trusted proxy. (ADR 0019)
- Behind trusted proxies, the client address comes from `X-Forwarded-For`, or, when the operator
  sets `client_ip_header`, from that single-value header written by a CDN. Either source is read only
  from a peer in `trusted_proxies`. (ADR 0020, ADR 0044)
- A `profile` setting (`small`, `standard`, `large`) gives coherent values to the resource limits. Each
  setting overrides it. The 15 MB worst-case memory target applies to `small` with the default
  settings (server TLS and replication off); with replication on and TLS off, the bound of `small` is
  16 MB. (ADR 0019, ADR 0028, ADR 0048)
- The relay listens on one address (`listen`, default `127.0.0.1:8080`) and keeps its blocks and index
  under `data_dir`. It serves HTTP/1.1 only, over TLS when `tls_mode` is `files` (TLS 1.3, ALPN
  `http/1.1`). With TLS on, a handshake takes a per-client token and completes within
  `header_timeout_ms`. (ADR 0019, ADR 0028)
- The limits are local settings of a relay, not protocol values. (ADR 0018, ADR 0019)

## 3. Target runtimes

| Tier | Runtime | Role |
|---|---|---|
| 1 | Zero-install PWA (WASM, OPFS, IndexedDB, WebRTC) | Universal access. Discovery through relay lists; P2P serving while the tab is open is a later, opt-in stage (ADR 0048). |
| 2 | Self-hosted micro-relays (one Rust image under 5 MB compressed, < 15 MB RAM with the default profile `small` and the default settings) | Backbone. Built-in TLS and replication are compiled in and off until configured (ADR 0028, ADR 0048). Either with built-in TLS (one binary, ADR 0028), or behind a reverse proxy that terminates TLS and buffers request heads (Caddy, nginx, HAProxy). |
| 3 | Object storage / CDN (S3, R2, Pages) | Static mirrors, near-zero cost. |
| 4 | Desktop / mobile daemon | Super-peers: 24/7 seeding, indexing; MAY run a graph gateway (`graph-access.md` §3). |

Browser extensions are not a primary target (installation friction, Manifest V3, not available on mobile).
