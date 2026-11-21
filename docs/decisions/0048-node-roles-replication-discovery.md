# 0048: Node roles, pull replication in the relay, relay lists, and a size budget

- Status: accepted (by the project owner, 2026-11-21), with the owner choices recorded in
  "Decisions of the project owner": a copy is not a read (rule 18); a new peer starts at `now`, `all`
  for archive relays (rule 9); the signed bootstrap list in a later ADR (rule 23); one published image
  with every network feature compiled in and off by default at run time, no code downloaded at run
  time (rule 3); server TLS of ADR 0028 off by default at run time (Q-70)
- Amended by: owner decision of 2026-11-21 on the size and memory budget, recorded with ADR 0050
  (rule 3, item 2: binary under 8 MB, image under 5 MB compressed, `small` under 15 MB with the default
  settings and under 20 MB with every function on, core `.wasm` under 200 KB gzip with MLS code in a
  separate module; replaces the 16 MB bound of `small` with replication on; the ADR 0013 binary gate
  becomes 8 MB and an image gate of 5 MB compressed is added; resolves Q-70 and Q-72; "Decisions of the
  project owner", item 7); 0050 (rule 18: a relay makes no fallback fetch for a request that carries
  `Sbtp-Replication: 1`); 0050 amendment U3 (rule 3, item 2: the `small` bound with every function on
  is 18,681,778 bytes, 1,318,222 bytes of margin)
- Date: 2026-11-21
- Questions: Q-11 (first stage only: the peer model; set reconciliation stays open), Q-26 (peer bounds
  staged, not decided), Q-68 (format and constraints fixed here; signer and freshness split out)
- Amends: ADR 0013 pass criteria and ADR 0017 (by the owner decision of item 7: binary gate 8 MB, image
  gate 5 MB compressed); ADR 0018 rule 35 (one term in the memory bound); ADR 0019 rules 37 and 38
  (profile rows and policy settings) and rule 39 (memory targets of `small`: 15 MB with the default
  settings, 20 MB with every function on); ADR 0021 rule 41
  (counters); ADR 0028 rule 1 (the published artefact also compiles in `replication`; server TLS
  stays off at run time unless its certificate settings are given) and rule 36 (memory target: with TLS
  on, `small` is under the 20 MB bound with every function on);
  ADR 0046 rules 10 and 15 (a request carrying `Sbtp-Replication: 1` is not demand and is answered
  `no-store`; rules 17 and 18 below). Nothing else in these ADRs changes
- Depends on: ADR 0024 (cursors and epochs), ADR 0028 (rustls, ring, OS roots), ADR 0029 (client
  bounds), ADR 0030 (no redirects), ADR 0040 rules 4 and 17 (hints, `/.well-known/sbtp`), ADR 0043,
  ADR 0045 (network difficulty), ADR 0046 (keeping, demand eviction)
- Impact: `architecture.md` §2 and §3; core spec §4 (`/info`, `GET /block`) and §5; `sbtp-relay`
  (default feature `replication`, settings, index table, metrics); `deploy/Dockerfile` (one image,
  every feature compiled in); CI (size and memory budget job); web client and `cli-demo` (read relay
  lists); no wire format change, no test vector

## Context

The data graph exists: signed, content-addressed blocks in a DAG. The network does not: each relay is
an island, and a block is on a relay only if a client sent it there. Relays now keep by default
(ADR 0046) and share one difficulty (ADR 0045), so copying blocks between relays works.

The owner's direction of 2026-11-21: SBTP is a network of nodes. Relays copy blocks from each other,
inside the relay program, off by default. Clients are nodes too, with a small budget. The relay stays
small: today the image is about 2 MB compressed, the binary is static, the computed memory bound of
`small` is 14,747,092 bytes with ADR 0046 as built, and the WASM module is 79 KB gzip.

## Decision

### Node roles

1. **Roles.** A node has one of three roles. A role is not a protocol field: a client reads it from the
   relay's `/info` (`block_ttl_ms`, `demand_eviction`).

   | Role | Keeps | Serves | Announces |
   |---|---|---|---|
   | **Archive relay** | Every block it accepts; never deletes; `507` when full. | The full relay interface. | `/info` with `"block_ttl_ms": null` and `"demand_eviction": false`; MAY publish `relays` (rule 21). |
   | **Keeping relay** (the default) | Every block until the store reaches the high-water mark, then drops the least recently demanded (ADR 0046). A relay that evicts by age is a variant. | The full relay interface. | `/info` with `"demand_eviction": true`; MAY publish `relays`. |
   | **Client node** (browser tab, CLI, app) | What the user and application choose, within its client bounds (ADR 0029). Never the user's keys or protected own blocks (ADR 0047). | Nothing in stage 1. Stage 2: cached blocks and chunks to peers over WebRTC, opt-in (rule 27). | Nothing on the network in stage 1. It keeps a local relay list (rule 20). |

   On a relay the role is configuration: it follows from `block_ttl_ms`, `demand_eviction`, `peers`
   and `replication_start` (rule 15), with one program and one image (rule 3). This ADR adds no
   `role` setting. A later ADR MAY add one, including a value `auto` that derives settings from the
   disk and memory available; such a value MUST NOT download or load code (rule 3, item 5).
2. **Replication is orthogonal.** Either relay role MAY replicate (rules 4 to 19). A relay that
   replicates MUST NOT set `min_pow_difficulty` above `D_NET` (ADR 0045 rule 3).

### Lightness

3. **Budget and features.**
   1. **One published image.** The published `sbtp-relay` image and binary are built with every
      network feature compiled in: `replication` (rules 4 to 19) and `tls` (ADR 0028). Both are
      default Cargo features. Every function of this ADR is **off by default at run time** and is
      enabled by configuration only: replication by a non-empty `peers`, `/info` `relays` by a
      non-empty `announce_relays`. Server TLS stays off unless its certificate settings are given
      (`tls_mode = "files"`, `tls_cert_file`, `tls_key_file`; ADR 0028 rules 2, 6 and 57, unchanged).
      With the default settings the published relay behaves as a relay without this ADR, except for
      the answer of rule 18. The Cargo features remain for an operator who builds a smaller binary
      (`--no-default-features`, then the features wanted); such a build is not published, and CI
      builds and tests it (ADR 0028 rule 1). A setting that needs a feature absent from the build stops
      the start-up with `config_error` (it is never ignored).
   2. **Budget** (owner decision of 2026-11-21, item 7, replacing the 16 MB bound of `small` with
      replication on and the WASM limit of 100,000 bytes). CI checks a budget on every pull request, on
      the one published image. A pull request that exceeds a limit fails.

      | Measure | Limit | How CI measures it |
      |---|---|---|
      | Relay image, compressed, every feature compiled in | < 5,000,000 bytes | Build with `deploy/Dockerfile` (`docker buildx build --output type=oci,dest=…`, gzip layers); sum of the layer `size` fields of the image manifest, base layers included. This is what a registry stores and a host pulls. |
      | Relay binary | < 8,000,000 bytes | `stat` of `/out/sbtp-relay` from the `export` stage of the same build (release profile, static, stripped). |
      | Relay memory, `small`, default settings | < 15,000,000 bytes | (a) A test asserts `memory_bound_bytes()` of the `small` profile with the default settings (`peers` empty, TLS off). (b) A Linux job starts the relay with `small` and the default settings, runs a fixed load of `PUT`, `GET` and `/query` for 60 seconds, and reads `VmHWM` from `/proc/<pid>/status`. |
      | Relay memory, `small`, every function on | < 20,000,000 bytes | (a) The same test with every function the build can run turned on: server TLS (`tls_mode = "files"`), replication (`peers` not empty; the bound counts `replication_max_peers` peers, rule 16), the archive copy and read-through of ADR 0050 (`mirror_endpoint` set, `fallback_sources` not empty), and each later function as its ADR adds it (sync, streaming, chunks, OHTTP). (b) The same job with TLS on, one peer (a second relay in the job) and a local S3-compatible server as mirror and fallback source, the load running while replication and the uploader run. |
      | Core WASM module | < 200,000 bytes gzip | The `sbtp-wasm` release pipeline of `crates/sbtp-wasm/README.md` (wasm-bindgen, then `wasm-opt`), then `gzip -9 -c sbtp_wasm_bg.wasm | wc -c`. Any MLS (group encryption) code is in a separate module, loaded on demand, with its own budget set by the ADR that adds it; it is not counted here. |

      The job writes the figures and their change against `main` to the job summary.

      **Memory with the functions on.** The owner accepts about 1 MB of memory per enabled outbound
      function rather than a smaller block cache or smaller `small` rows. Each function's terms are added
      to the bound of ADR 0018 rule 35 only when the function is on. With the default settings every
      function of this ADR and of ADR 0050 is off, and the 15 MB target of ADR 0019 rule 39 applies:
      14,910,996 bytes computed with ADR 0049. With every function on, the computed `small` bound is
      18,681,778 bytes: the default bound, plus server TLS (ADR 0028 rule 36, 2,228,224), replication
      (rule 16, 723,077) and ADR 0050 rule 27 (819,481, the root store counted once). The 1,318,222 bytes
      under 20,000,000 are what later functions have (updated by ADR 0050 U3; was 18,188,451 bytes,
      326,154 for ADR 0050 and 1,811,549 bytes of margin); each later ADR states its terms and the new total.
      The 60-second `VmHWM` runs replace the estimates. The packaged unit keeps `MemoryMax=128M` for
      `small` (ADR 0019 rule 37).

      The ADR 0013 benchmark (one million blocks) stays the release gate; the 60-second runs are the
      per-PR check. Its binary threshold becomes 8,000,000 bytes, the same as the per-PR limit, and it
      gains an image threshold of 5,000,000 bytes compressed, measured as above (owner decision of
      2026-11-21, item 7, Q-70; set before the gate has run, so the pre-registration rule of ADR 0013
      holds). The binary that ships has every feature compiled in.
   3. Every function has bounds per profile (`small`, `standard`, `large`, ADR 0019 rule 37) and its
      memory is a term of the bound of ADR 0018 rule 35.
   4. The relay never embeds a TURN server or any media relay. Help with WebRTC signalling is a later
      stage (rule 26), behind its own feature.
   5. **No code loaded at run time.** The relay never downloads, loads or runs code at run time: no
      plugin, no dynamic library, no script from a peer, a relay list or a URL. A function that is not
      compiled in is absent. Every function the published image can run went through the reviewed and
      pinned build (`Cargo.lock`, `cargo deny`).

### Pull replication

4. **Model.** A relay with replication on is a client of each of its peers. It walks the peer's
   `/query?since=&cursor=` and fetches with `GET /sbtp/v1/block/{id}` the blocks it does not hold. It
   validates each fetched block as a `PUT` body: F1 to F9, P1 with its own `max_future_ms`, C1 at its own
   `min_pow_difficulty`, C2, C3, and R1 for the requested `block_id`. It stores a valid block through the
   same storage step as a `PUT` (core spec §4, step 5), not by an HTTP request to itself. It never
   parses a payload.
5. **Peers.** `peers` is a list of relay URLs (rule 20) set by the operator. Default: empty, which turns
   replication off. A relay MUST NOT add a peer from anything it receives: not from a peer's `/info`, a
   relay list, a hint or a request. Automatic peering is out of scope for this stage.
6. **Held check first.** For each listed `block_id`, the relay looks it up in its own index (one read,
   O(log n)) and does not fetch a block it holds, not expired. It also does not fetch a `block_id` with
   fewer leading zero bits than its `min_pow_difficulty`: the proof of work depends on the identifier
   alone (§3.3). Such a block is skipped and counted (ADR 0045 rule 6). It is never re-mined.
7. **Skips.** A block that fails validation, a `404`, or a block that fails P1 is skipped and counted
   by reason. A skipped block is not retried in this walk. A peer that sends 16 invalid blocks in one
   round ends that round and backs off (rule 11). None of these is an error of the local relay.
8. **Cursor per peer.** The relay keeps one cursor per peer, durably, in an index table
   (`peer URL → cursor, since`). The index writer writes it in the transaction that stores the last
   block of a page, or alone when the page stored nothing. After a crash the relay walks the last page
   again; the held check (rule 6) makes that cheap. The index is derived data: when it is rebuilt, the
   table is empty and rule 9 applies. Rows of peers no longer configured are removed at start-up.
9. **Start and peer epochs.** A peer without a cursor is walked from `replication_start`: `now` (the
   default: `since` = the time the peer was first seen, minus `replication_resync_margin_ms`) or `all`
   (no `since`, the full history; the setting for an archive relay). On `400` `InvalidCursor` (a new index epoch of
   the peer, ADR 0024), the relay drops the cursor and walks again from `since` = the local time of its
   last complete page of that peer, minus `replication_resync_margin_ms`. The margin covers clock
   differences between relays; re-listed blocks cost one index read each (rule 6).
10. **Bounds.** Settings of rule 15. All peers together share `replication_max_in_flight` requests and
    `replication_blocks_per_min` and `replication_bytes_per_hour`, served round robin so that one peer
    cannot take another's share. A peer connection is open only while a request to it runs or is about
    to; at most `replication_max_in_flight` connections are open. Each request applies the ceilings
    and checks of ADR 0029 (bodies of 65,909 and 131,072 bytes, the `/query` shape) and a total time
    limit, `replication_request_timeout_ms`. A walk that is caught up (`more = false`) waits
    `replication_poll_ms` before the next `/query` of that peer.
11. **The peer's limits.** The relay follows the client rules of core spec §4, "Admission control",
    toward each peer: it never repeats a request before `Retry-After`, backs off exponentially with
    jitter from 1 second without it, handles `502` and `504` as `503`, and keeps its cursor. It waits at
    most `replication_max_backoff_s` before trying the peer again; it never gives up a peer for good.
    Its defaults stay below the `small` allowances of a peer (rule 15), so a default peer never answers
    `429` to it.
12. **Local admission.** Replication is not under the local rate limiter (it is not a client). Its
    storage step takes the same permits as a `PUT` (`put_max_in_flight`, the index writer queue), at
    most `replication_max_in_flight` at a time; when none is free it waits for one within
    `queue_timeout_ms`, then retries in the next round. Client `PUT`s are never refused because of
    replication beyond that share.
13. **Store pressure.** Replication stores nothing while the stored total (ADR 0013 rule 18) is above
    `demand_high_water_pct` of `max_store_bytes` (90 % when demand eviction is off). It pauses, logs
    `replication_paused` (rate-capped) and resumes when the sweeper brings the total below the mark. The
    room above the mark stays for client `PUT`s. A paused relay keeps its cursors: it does not skip
    what it did not store.
14. **No redirects, no SSRF.** A peer URL MUST be an absolute `https` URL without userinfo, query or
    fragment (`http` is allowed for a loopback host only, for tests). The relay MUST NOT follow a
    redirect: a `3xx` is a failed request (ADR 0030), counted, and the peer backs off. It never sends a
    request to a URL it did not read from its own configuration. By default it refuses to connect to a
    resolved address that is loopback, private (RFC 1918, RFC 4193), link-local (cloud metadata
    addresses included), unspecified or multicast, unless the peer host is that literal address or
    `replication_allow_private = true`. DNS is resolved per connection.
15. **Settings** (environment variables `SBTP_RELAY_<NAME>`, ADR 0019). Profile rows (ADR 0019
    rule 37):

    | Setting | `small` | `standard` | `large` | Range |
    |---|---|---|---|---|
    | `replication_max_peers` | 4 | 16 | 64 | 1 to 256 |
    | `replication_max_in_flight` | 1 | 4 | 16 | 1 to 64 |
    | `replication_blocks_per_min` | 600 | 3,000 | 12,000 | 1 to 1,000,000 |
    | `replication_bytes_per_hour` | 268,435,456 (256 MiB) | 2 GiB | 16 GiB | 1 MiB to 1 TiB |

    Policy settings (not set by a profile, ADR 0019 rule 38): `peers` (empty; at most
    `replication_max_peers` entries, more stops the start-up), `replication_start` (`now` or `all`,
    default `now`), `replication_poll_ms` (10,000; 1,000 to 3,600,000), `replication_request_timeout_ms`
    (30,000; 1,000 to 300,000), `replication_max_backoff_s` (3,600; 1 to 86,400),
    `replication_resync_margin_ms` (3,600,000; 0 to 86,400,000), `replication_allow_private` (`false`),
    `peer_ca_file` (none: the operating system store, rule 19). The `small` defaults are under a
    `small` peer's `block` allowance (3,000 per minute) and, with one `/query` per page of up to 1,000
    identifiers, far under its `query` allowance (300 per minute).
16. **Memory.** New terms of ADR 0018 rule 35, estimates, not measured:

    ```
    + replication_max_in_flight × (131,072 + 65,909 + 32,000 + 90,000)   (query body, block,
                                                                          identifiers, TLS and HTTP state)
    + 400,000                                                             (root store, loaded once)
    + replication_max_peers × 1,024                                       (peer state)
    ```

    `small`: 318,981 + 400,000 + 4,096 = 723,077 bytes. On top of the ADR 0046 bound as built
    (14,747,092 bytes, ADR 0046 clarification D7) it gives 15,470,169 bytes: above the 15 MB target of
    the default settings, which does not apply with replication on. The terms count only when the
    feature is compiled and `peers` is not empty. With replication on, `small` is held to the 20 MB
    bound with every function on (rule 3, item 2, as amended by the owner on 2026-11-21; the proposed
    16 MB bound is replaced).

### What a replicated block counts as

17. **On the replica.** A stored replicated block is an acceptance in every respect: new
    `received_at` and position, listed by `/query`, counted in the quota, `last_demand` of the current
    epoch, and its held parents refreshed (ADR 0046 rule 10). It is protected for `3 × E` like any new
    block, then ages by local demand. A keeping relay is therefore a recent window of what its peers
    hold, plus what its own clients read.
18. **On the source: a copy is not a read.** A replica sends `Sbtp-Replication: 1` on each
    `GET /block` and `/query`. A relay that evicts by demand MUST NOT count a `GET` or `HEAD` of
    `/block` carrying it as demand (ADR 0046 rule 10), and MUST answer it with
    `Cache-Control: no-store` and `CDN-Cache-Control: no-store` in place of the headers of ADR 0046
    rule 15, so that no shared cache keeps an entry filled by a request the origin did not count
    (ADR 0046 rule 7 would no longer hold). A relay without demand eviction has no demand to skip and
    SHOULD answer it with the same `no-store` headers; `sbtp-relay` does so in every mode. The header
    can only make a request count less; a client that sends it falsely only stops its own reads from
    keeping blocks warm. A response served to a replica from a shared cache is fine: it neither
    reaches nor misleads the origin.
19. **Outbound TLS.** The client side uses the crates of ADR 0028: `rustls` (provider `ring`, TLS 1.3
    only, as on the server side, no `dangerous` API, hostname checked), `tokio-rustls`, `rustls-native-certs`
    for the operating system store, and hyper's low-level HTTP/1.1 client (`hyper` feature `client`,
    `hyper::client::conn::http1`: no pool, no redirect following). `peer_ca_file` (PEM) replaces the
    OS store when set. `webpki-roots` is not used: its CDLA-Permissive-2.0 licence is not in the
    `deny.toml` allow list, and a compiled-in root set changes only with a rebuild. The distroless
    runtime image carries `/etc/ssl/certs`; a host without a store needs `peer_ca_file`. A store that
    loads no root stops the start-up when `peers` is not empty.

### Discovery

20. **Relay list format.** One format is used everywhere a list of relays appears: the relay's
    `peers`, a client's relay list, the `relays` member of `/.well-known/sbtp` (ADR 0040 rule 17), the
    `relays` member of `/info` (rule 21) and the future signed bootstrap list (rule 23). A **relay
    list** is a JSON array (a TOML array in the relay's settings) of **relay URLs**, each a string under
    the rules of a relay hint (ADR 0040 rule 4: absolute `https`, no userinfo, query or fragment), at
    most 16 entries, without duplicates after the normalisation of RFC 3986 §6.2.2 and §6.2.3. A list
    carries no metadata: what a relay keeps, its difficulty and its gateway come from its own `/info`,
    which stays current where a list goes stale.
21. **Published by a relay.** A relay MAY publish `"relays": [...]` in `/info`, a relay list chosen by
    its operator in the setting `announce_relays` (default empty: the member is absent). It is not
    derived from `peers`: an operator may replicate from a relay it does not want to announce. It is
    a hint (ADR 0040 rule 4). It reveals the operator's choices, nothing about users.
22. **Use by clients.** A client node keeps a local relay list: configured relays, the bootstrap list
    when one exists, and relays learned from `/info` `relays`, `/.well-known/sbtp` and URI hints, all
    within its client bounds. Learned relays are candidates. A client MAY use one for public reads; it
    uses a relay for the user's own traffic (publishing, polling the delivery tags of sealed messages)
    only when the user or the application's configuration chose it, because every relay it contacts
    sees its address and what it asks for. A learned relay never replaces a configured one.
23. **Signed bootstrap list (Q-68).** Its content is a relay list (rule 20). Its signer, key custody and
    rotation (with Q-38), carrier, freshness rule and inclusion criteria are decided by a later ADR,
    before the list is published. The recommended direction for it: a signed SBTP block of an `sbtp.*`
    kind whose body is the list, signed by a project key held offline whose public key ships with the
    clients, with a `supersedes` chain and a maximum age; inclusion requires `min_pow_difficulty` at or
    below `D_NET` and a reachable relay. Until then no client depends on a bootstrap list.

### Client nodes, staged

24. **Stage 1, now.** Relay lists only (rules 20 to 22). A client node serves nothing.
25. **Later stages are not specified here.** Each needs its own ADR. Peer bounds (Q-26), chunk transport
    (Q-21) and the signalling transport (Q-23, WebSocket) come first.
26. **Stage 2 outline.** A client node serves the blocks and chunks it already caches to other client
    nodes over WebRTC data channels. Relays MAY help with signalling: opaque, size-bounded, short-lived
    messages, never stored, behind their own feature and bounds. Every block and chunk received from a
    peer is validated as from a relay (§3.4, ADR 0010). Set reconciliation (Q-11) reuses the peer
    model of rules 5 to 14: operator- or user-chosen peers, a cursor or digest per peer, the same
    bounds and skip rules.
27. **Privacy default.** A WebRTC connection shows each side's IP address to the other. Peer serving
    and peer fetching are therefore **off by default** and turned on by the user, who is told that
    peers then see their address. A user MAY configure a TURN server of their choice
    (`iceTransportPolicy: "relay"`) to hide the address from peers; the TURN operator still sees it.
    SBTP provides no TURN server (rule 3, item 4).

## Consequences

- **Network.** Two operators that list each other in `peers` hold the same blocks within one poll
  interval, bounded by the store pressure rule. Loops are harmless: a block is the same block on every
  relay (§3.4), so a block that comes back from a peer is found held by rule 6 and costs one listing
  entry and one index read; nothing is fetched or stored twice.
- **Abusive peer.** A peer can only send blocks that pass the local pipeline, each with its proof of
  work, within `replication_blocks_per_min`, `replication_bytes_per_hour`, its round-robin share and
  the high-water pause. The worst it does is fill the replica's window with valid blocks that age out
  by demand. The operator removes the peer; metrics per peer show it.
- **Size.** One published image. `replication` adds `rustls-native-certs` and hyper's client code to
  what `tls` (ADR 0028) compiles in (`rustls`, `ring`, `tokio-rustls`); both together are of the order
  of 1 MB of binary (estimate). None of it runs while the settings leave it off. The CI job of rule 3
  gives the real figure.
- **Memory.** `small` keeps its 15 MB target with the default settings. An operator who turns
  functions on in `small` accepts about 1 MB per outbound function, within 20 MB with every function on
  (rule 3, item 2, owner decision of 2026-11-21).
- **Privacy.** A replica's address is seen by its peers, like any client's. Replication copies public
  and sealed blocks alike; it does not change what a relay already sees. `/info` `relays` reveals only
  the operator's choices.
- **Security.** The relay gains an outbound client. Its targets are fixed by the operator; it reads
  bounded bodies and stores only what its own validation accepts.
- **Compatibility.** Nothing is released. A relay without this ADR ignores `Sbtp-Replication` and
  publishes no `relays`; a client reads an absent `relays` as an empty list.

## Implementation plan

| Stage | Work | Owner | Effort (rough) | Security review |
|---|---|---|---|---|
| 0 | CI budget job of rule 3 (image, binary, memory bound tests with the defaults and with every function on, 60 s `VmHWM` runs with the defaults and with every function on, core WASM gzip); one image, built with every feature compiled in | relay-engineer | 1 day | No |
| 1 | Feature `replication` (a default feature): settings and checks (rules 5, 14, 15), outbound client (rule 19), walker with held check, PoW pre-check and skips (rules 6, 7), cursor table (rules 8, 9), bounds and back-off (rules 10 to 13), memory terms (rule 16), metrics and events; tests with two in-process relays: loop, restart mid-page, peer `InvalidCursor`, `429` with `Retry-After`, `3xx`, oversize body, invalid blocks, high-water pause, private address refused | relay-engineer | 4 to 6 days | **Yes**, before merge |
| 2 | `/info` `relays` and `announce_relays` (rule 21); web client and `cli-demo` read `/info` `relays` and `/.well-known/sbtp` into their relay list (rules 20, 22) | relay-engineer, wasm-engineer | 1 day | No |
| 3 | `Sbtp-Replication` on the source (rule 18): not demand, `no-store` in every mode | relay-engineer | 0.5 day | With ADR 0046 |
| Later | Bootstrap list ADR (Q-68); RBSR (Q-11); WebSocket (Q-23); WebRTC peers (Q-26, Q-21) | spec-architect first | | Each |

**Security-auditor review of stage 1:** the new dependencies and their features (no `aws-lc-rs`, no
`dangerous`, no `webpki-roots`); certificate and hostname verification; redirect and SSRF rules,
including DNS that changes between checks; every body read bounded before allocation; the storage path
shared with `PUT` (no check skipped, R1 applied); the cursor table under a crash; a hostile peer
(endless `more = true`, slow bodies, invalid blocks, valid-block flood) against the `small` bound; logs
and metrics name peers by index, never by client data.

**Metrics** (prefix `sbtp_relay_`, label `peer` = position of the peer in `peers`, so the set is
bounded and the URL is not repeated): `replication_blocks_stored_total`, `replication_bytes_total`,
`replication_skipped_total` (label `reason`: `held`, `pow`, `invalid`, `not_found`, `future`),
`replication_requests_failed_total` (label `status`), `replication_paused` (gauge),
`replication_cursor_resets_total`. Events: `replication_peer_backoff`, `replication_paused`,
`replication_cursor_reset` (rate-capped, ADR 0021).

## Decisions of the project owner (2026-11-21)

1. **A copy is not a read.** Replication downloads carry `Sbtp-Replication: 1`, are answered
   `no-store` and do not count as demand (rule 18).
2. **Start point.** A new peer starts at `now` by default; `all` is the setting for archive relays
   (rule 9).
3. **Signed bootstrap list.** Split into a later ADR (rule 23); Q-68 stays open.
4. **One published image.** Two images and plugins downloaded at run time are rejected. The one image
   compiles in every network feature; everything is off by default at run time and enabled by
   configuration. Cargo features remain for minimal builds. The node role is configuration (rules 1
   and 3).
5. **Memory with replication on.** `small` with replication on gets its own bound, 16,000,000 bytes;
   the `small` replication rows do not shrink (rule 3, item 2). *Replaced by item 7.*
6. **Q-70, server TLS.** ADR 0028 is amended: `tls` is compiled into the published image and server
   TLS is inactive unless its certificate settings are given (rule 3, item 1). This was already the
   run-time default of ADR 0028 rules 2 and 4 (`tls_mode = "off"`); the feature stays a default
   feature.

7. **Size and memory budget (2026-11-21, with ADR 0050; replaces item 5 and the 16 MB bound of
   rule 3).** About 1 MB per enabled outbound function is accepted rather than a smaller block cache.
   The budgets, checked in CI (rule 3, item 2):
   - relay binary under 8 MB;
   - published image under 5 MB compressed (the single image, every feature compiled in);
   - `small` worst case under 15 MB with the default settings;
   - `small` worst case under 20 MB with every function on (replication, object store, server TLS, and
     later sync, streaming, chunks, OHTTP);
   - core `.wasm` under 200 KB gzip; any MLS (group encryption) code in a separate module loaded on
     demand, budgeted on its own.

   The ADR 0013 binary gate (ADR 0017) becomes 8 MB, and the gate gains the 5 MB compressed image
   threshold. This resolves Q-70 (with item 6) and Q-72.

## Spec change on acceptance

Applied on acceptance (2026-11-21). The "Replication" part of `architecture.md` §2 written for
ADR 0045 is replaced in place by the text below.

`architecture.md`, §2 "Replication":

> ### Replication
> - A relay MAY copy blocks from peers that its operator lists in `peers` (relay URLs, `https` only).
>   It walks each peer's `/query` with a cursor kept per peer, skips the blocks it holds and those below
>   its `min_pow_difficulty`, fetches the others with `GET`, validates each as a `PUT` body (F1 to F9,
>   P1, C1, C2, C3) and R1, and stores it as an accepted block. It never re-mines, re-signs or alters a
>   block, never follows a redirect and never adds a peer from what it receives. (ADRs 0045, 0048)
> - Replication is off by default (`peers` empty). It runs within its own bounds per profile, obeys
>   the peer's `Retry-After`, and stores nothing while the store is above the high-water mark. A
>   replicating relay does not set `min_pow_difficulty` above `D_NET`. (ADR 0048)
> - A copy is not a read: replication requests carry `Sbtp-Replication: 1`, and a source that evicts
>   by demand does not count them as demand (core spec §4, `GET /sbtp/v1/block/{block_id}`).
>   (ADR 0048)
> - A mirror outside the relay MAY copy blocks by a `PUT` of the same bytes instead. It never
>   re-mines, re-signs or alters a block. A block below the target's `min_pow_difficulty` is skipped
>   for that target and counted; it is not an error of the source. (ADR 0045)
> - When `D_NET` is raised, clients mine at the new value from its announcement and relays raise their
>   floor at its effective date. Blocks mined earlier stay where they are held. (ADR 0045)

`architecture.md` §2, "Admission control", the bullet on `profile`, last sentence replaced by: "The
15 MB worst-case memory target applies to `small` with the default settings (server TLS and
replication off); with replication on and TLS off, the bound of `small` is 16 MB. (ADR 0019, ADR 0028,
ADR 0048)" *Replaced by item 7 (2026-11-21): "The worst-case memory of `small` is under 15 MB with the
default settings and under 20 MB with every function on. (ADR 0019, ADR 0028, ADR 0048, ADR 0050)"*

`architecture.md` §3, tier 1 row, role column: "Universal access. Discovery through relay lists; P2P
serving while the tab is open is a later, opt-in stage (ADR 0048)."

`architecture.md` §3, tier 2 row: runtime column "Self-hosted micro-relays (one Rust image under 5 MB
compressed, < 15 MB RAM with the default profile `small` and the default settings)"; role column
starts with "Backbone. Built-in TLS and replication are compiled in and off until configured
(ADR 0028, ADR 0048)."

Core spec §4, `GET /sbtp/v1/block/{block_id}`, new bullet:

> - A relay that copies blocks from another relay sends `Sbtp-Replication: 1` on its requests. A relay
>   that evicts by demand MUST NOT count such a `GET` or `HEAD` as demand and MUST answer it with
>   `Cache-Control: no-store` and `CDN-Cache-Control: no-store`; another relay SHOULD answer it with
>   the same headers. (ADR 0048)

Core spec §4, `GET /sbtp/v1/info`, new bullet:

> - A relay MAY publish `relays`, a relay list (at most 16 relay URLs, each under the rules of a relay
>   hint) chosen by its operator. It is a hint. A client reads an absent member as an empty list and
>   does not send the user's own traffic to a listed relay unless the user chose it. (ADR 0048)

Core spec §5, after the diagram, new paragraph:

> The first stage is pull replication between relays (`architecture.md` §2, "Replication"): a relay is
> a client of the peers its operator chooses and walks their `/query` with a cursor. Set reconciliation
> replaces the walk later and keeps the same peer model `[Q-11]`. Client nodes exchange relay lists
> first; peer-to-peer serving over WebRTC is opt-in and specified later `[Q-26]`. (ADR 0048)

## Rejected alternatives

- **A separate replication program** (mirror by `PUT`). One more process to run and secure, and each
  copy pays the local rate limiter and a second validation over loopback. It stays possible for anyone
  (ADR 0045 rule 6), but it is not the reference path.
- **Push replication** (the source `PUT`s to its peers). The source would need a client per peer and a
  queue per peer that a slow peer makes grow; with pull, the slow side paces itself.
- **Automatic peering from announced lists.** Lets any relay steer others' outbound traffic and fill
  their stores; it needs a trust and reputation model this stage does not have.
- **Two published images** (a default image and a `replication` image; the proposed text). Rejected by
  the owner: two artefacts to build, test and document, and an operator who must choose an image
  before knowing which function it needs. One image with every function off at run time keeps the
  default behaviour and the size budget of rule 3.
- **Plugins downloaded at run time.** Rejected by the owner: code fetched by a running relay bypasses
  the reviewed and pinned build, a supply-chain path (rule 3, item 5).
- **`webpki-roots`.** Licence outside the allow list and roots fixed at build time; the OS store is in
  the image and `peer_ca_file` covers the rest.
- **Count replica fetches as demand on the source.** A new replica's first walk would mark every block
  of a full source as demanded and stall its demand eviction for `3 × E` (`demand_stuck`, `507` for
  clients). An honest replica should not do this; a hostile client still can (ADR 0046 rule 21).
- **Metadata in relay lists** (role, difficulty). Stale as soon as an operator changes a setting; `/info`
  is the current source and is no less trusted than a list entry.
- **Derive `/info` `relays` from `peers`.** Leaks peers an operator wants to keep private.
- **Decide the bootstrap signer now.** It needs the project key custody and succession rules (Q-38),
  and there is no relay to list yet.
- **Peer serving on by default in browsers.** Shows every user's IP address to strangers; privacy is an
  MVP requirement.
