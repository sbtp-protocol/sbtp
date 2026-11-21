# 0050: Archive copy to S3-compatible object storage, and read-through fallback from read-only sources

- Status: accepted (by the project owner, 2026-11-21), as proposed, with the owner choices recorded in
  "Decisions of the project owner": the `/info` member `read_only` (a core spec change);
  `fallback_sources` as a separate setting; `fallback_keep` on by default; one writer per bucket
  recommended. Rule 27 (memory) is replaced by the owner's budget decision: the outbound terms are added
  to the bound, and the block cache keeps its default
- Date: 2026-11-21
- Questions: Q-72 (opened here; resolved by the owner's budget decision, rule 27), Q-73 (opened:
  verification and repair of a shared bucket; stays open)
- Amends: ADR 0018 rule 35 (the outbound terms of rule 27 are added to the bound when a function is
  on); ADR 0019 rules 37 and 38 (profile rows and policy settings); ADR 0021 rule 41 (counters);
  ADR 0048 rule 18 (gains rule 17 below). The owner's budget decision recorded in rule 27 also amends
  ADR 0048 rule 3, item 2 (recorded there). Nothing else in these ADRs changes
- Depends on: ADR 0010 (chunks, out of scope), ADR 0023 (integrity of served bytes), ADR 0029 (client
  bounds), ADR 0030 (no redirects), ADR 0040 (relay URLs, hints), ADR 0043 (re-acceptance), ADR 0045,
  ADR 0046 (demand eviction), ADR 0047 (final refusals), ADR 0048 (outbound client, relay lists, URL
  rules), ADR 0049 (ingest budget)
- Impact: core spec §4 (`/info` `read_only`); `architecture.md` §2 ("Archive copy", "Read-through");
  `sbtp-relay` (feature `object-store`, uploader, fallback fetcher, settings, metrics); `deploy/README.md`
  (bucket policy, CORS, credentials); no wire format change, no test vector

## Context

Blocks are immutable and content-addressed (§3.4): a block's bytes never change, and the `block_id`
names them. That fits object storage (S3, R2, MinIO and others), which is cheap, durable and served
well by CDNs. Owner direction of 2026-11-21, "option A": an archive relay MAY also write each accepted
block to a bucket, under a path a client derives from the `block_id`, so that the bucket's public URL
works as a read-only relay for `GET /block`. The relay's own storage is unchanged; the bucket is an
extra copy. Second owner direction of the same day: one bucket, written by one operator's relay, can be
read by **several relays** as a fallback on a local miss, not only by clients.

Facts checked on 2026-11-21 (Context7: AWS S3 user guide and API reference; Cloudflare R2
documentation):

- S3 `PutObject` with `If-None-Match: *` writes only if the key is absent, else `412 Precondition
  Failed`; a concurrent conflict gives `409 ConditionalRequestConflict`, after which the upload may be
  retried. Since 2024-11-25 a bucket policy can require the header (condition key `s3:if-none-match`).
- R2 `PutObject` supports `If-None-Match: *` atomically ("create-once"): at most one of concurrent
  writers succeeds, the others get `412`. An R2 bucket's region is `auto`; `us-east-1` aliases to it.
- On S3, a `GET` of a missing key returns `403` to a reader without `s3:ListBucket`, not `404`.

## Decision

### Layout and the read-only relay URL

1. **Object key.** The block with identifier `id` (64 lowercase hexadecimal characters) is the object
   `{mirror_prefix}sbtp/v1/block/{id}`. `mirror_prefix` is empty or ends with `/`.
2. **Read-only relay.** A URL under which these objects are served read-only (a public bucket URL, or a
   CDN in front of it) is a **read-only relay URL**: `GET {URL}/sbtp/v1/block/{id}` returns the block.
   It serves no `/query` and accepts no `PUT`.
3. **`/info` of a read-only relay.** The writer puts one object `{mirror_prefix}sbtp/v1/info`
   (`application/json`, `Cache-Control: public, max-age=3600`):

   ```json
   {"min_pow_difficulty": 16, "max_future_ms": 300000, "block_versions": [1],
    "block_ttl_ms": null, "demand_eviction": false, "read_only": true}
   ```

   `min_pow_difficulty` is `D_NET` (ADR 0045); it describes the blocks a client can expect, since a
   read-only relay accepts none. Core spec §4 gains the member `read_only` (spec change below): when
   `true`, a client MUST NOT send `PUT` or `/query` to that URL; an absent member is `false`. The relay
   writes this object at start-up when its content differs from what it last wrote (kept in `META`).
   It is the only object the relay ever overwrites.
4. **No metadata in relay lists.** A read-only relay URL is an ordinary entry of any relay list
   (ADR 0048 rule 20): a client's list, `/info` `relays`, `/.well-known/sbtp`. No marker is added to the
   format; a client learns `read_only` from that URL's `/info`, as it learns every other property. A
   client that cannot read `/info` there may still use the URL for `GET /block`. A `PUT` sent to a
   bucket gets a `4xx`, a final refusal for ADR 0047.
5. **Reading.** A client validates every block from a read-only relay as from any relay (§3.4: full
   validation and R1). For `GET /block` on a read-only relay, any status other than `200` or `304`
   means "not here" (S3 answers `403` for a missing key); the client tries another relay. A bucket's
   error body is not JSON; ADR 0029 ceilings apply. A read-only relay's `ETag` is the store's own, not
   the `block_id`; a client gives it no meaning.

### Upload (archive copy)

6. **Scope.** A relay with `mirror_endpoint` set uploads every block it stores (from `PUT`, replication
   or read-through rule 15) to the bucket. The relay's local storage, quota and eviction are unchanged.
   Default: off.
7. **Off the request path.** No `PUT` waits for the bucket. The uploader walks the relay's own index by
   position (ADR 0013), from a durable cursor in `META` (`mirror_cursor`), in pages of 64 positions;
   without a cursor it starts at the first position (the whole local history). The backlog is the set
   of positions after the cursor: it lives on the relay's disk already and costs no memory. The cursor
   is advanced, durably, after every block of a page is done.
8. **Request.** For each block, the uploader reads the file through the read path of ADR 0023 (full
   validation and R1; a damaged file is not uploaded, it is counted and skipped) and sends a path-style
   (default) or virtual-hosted `PUT` signed with AWS Signature Version 4, with:
   - `If-None-Match: *`;
   - `Content-Type: application/octet-stream`;
   - `Cache-Control: public, max-age=31536000, immutable`;
   - `x-amz-content-sha256`: the SHA-256 of the body (signed payload), and `Content-Length`.
9. **Outcomes.**
   - `200`: done. `412`: the key exists; done (first write wins). If `mirror_public_url` is set, the
     uploader then fetches the object from it once, validates it, and on failure counts
     `mirror_poisoned_total` and logs `mirror_poisoned` with the `block_id` (a public identifier). It
     never deletes.
   - `409`, `429`, `5xx`, a timeout or a connection error: retry the same block after exponential
     back-off with jitter from 1 s to `mirror_max_backoff_s`. The cursor does not move.
   - Any other `4xx` (bad credentials, missing bucket, policy) and any `3xx` (ADR 0030): a failed
     request, `mirror_failed` (rate-capped, ADR 0021), back-off at the maximum. The cursor does not
     move: a configuration error never skips a block.
   - A block no longer held when its turn comes (evicted) is skipped and counted
     (`mirror_missed_total`).
10. **Bucket down.** The uploader keeps retrying with back-off; client `PUT`s are not affected. With
    demand eviction, a block is protected for `3 × E` after its acceptance (ADR 0046 rule 7), so a block
    is lost to the bucket only after an outage of at least `3 × E` (3 days by default); with
    `block_ttl_ms` set, after an outage of that duration. An archive relay evicts nothing and loses
    nothing. Operators alert on `mirror_lag_ms` (rule 20).
11. **Never deletes.** The relay MUST NOT send `DELETE` or any request other than `PUT` (and the `GET` of
    rule 9) to the bucket. Eviction is local only. A bucket with an expiry rule is not an archive and
    its operator MUST NOT publish `"block_ttl_ms": null` for it (the relay's `mirror_info = false` then
    turns rule 3 off).
12. **Demand does not apply to a bucket.** Nothing is evicted from a bucket, so there is nothing to
    measure: the one-year `immutable` lifetime of ADR 0046 rule 16 (archive relays) is right for it.
    Reads served from a bucket or its CDN do not reach the relay and do not count as demand there; a
    block popular only through the bucket may be evicted locally, and the bucket still serves it.

### Several writers on one bucket

13. **One writer per bucket is RECOMMENDED.** With `If-None-Match: *`, the first bytes written under a key
    stay. A writer that uploads wrong bytes under a `block_id` poisons that key: every reader rejects
    them (R1 and full validation), and no honest writer can replace them. Readers validate, so poisoning
    makes a block unavailable from that bucket; it never makes anyone accept a wrong block. Several
    writers on one bucket SHOULD be mutually trusted relays, each with its own put-only credentials.
14. **Repair** is an operator task with credentials the relay does not hold: list or check the keys,
    validate each object, delete those that fail (Q-73). The relay's part is detection (rule 9).

### Read-through fallback

15. **Setting.** `fallback_sources` is a relay list (ADR 0048 rule 20, at most 16 URLs) of sources the
    relay MAY read from on a local miss: read-only relay URLs or ordinary relays. Default: empty (off).
    It is a separate setting, not a marker in `peers`: a source is read per block on demand, a peer is
    walked. URLs follow ADR 0048 rule 14 (absolute `https`, `http` for a loopback host only; no redirect
    followed; loopback, private, link-local, unspecified and multicast addresses refused unless the host
    is that literal address or `fallback_allow_private = true`; DNS resolved per connection). No
    credentials are sent: a source is public.
16. **Fetch.** On `GET` or `HEAD /sbtp/v1/block/{id}` for a block the relay does not hold (absent,
    expired or evicted), and when the request does not carry `Sbtp-Replication: 1` (rule 17), the relay
    asks the sources in list order, at most one at a time per request, and takes the first `200`. It
    validates the body as a received block: full validation and R1 (§3.4). On success it serves it as a
    `200` with the headers of its own policy; on failure of every source it answers `404` `NotFound`,
    as before. A local block is always served from local storage: a source never replaces it.
    Bounds (rule 19): `fallback_max_in_flight` fetches at once across all requests (a request that finds
    none free gets `404` at once, not a wait), `fallback_per_min` fetches per minute across all clients,
    `fallback_timeout_ms` for the whole fetch, the `/block` body ceiling of ADR 0029 (65,909 bytes).
    A fetch is a `block` request of the client for the local rate limiter (ADR 0018 rule 21), as the
    `GET` already is.
17. **No chains.** Every fallback request carries `Sbtp-Replication: 1` (ADR 0048 rule 18). A relay MUST
    NOT make a fallback fetch for a request that carries it. Two relays that list each other therefore
    forward at most once.
18. **Negative cache.** A `block_id` that no source served is kept in a bounded set of
    `fallback_negative_max` entries for `fallback_negative_ttl_ms`; while it is there, a miss on it gets
    `404` without a fetch. When the set is full, the oldest entry is replaced. The per-minute bound of
    rule 16 holds whatever the set contains: a client asking for random identifiers costs the sources at
    most `fallback_per_min` requests per minute from this relay.
19. **Keeping a copy.** With `fallback_keep = true` (default), a fetched block that also passes C1 at the
    relay's `min_pow_difficulty` and P1 (as replication, ADR 0048 rule 4) is stored through the storage
    step of a `PUT`. It is then an acceptance in every respect, as a replicated block (ADR 0048 rule 17):
    new `received_at` and position (a re-acceptance under ADR 0043 when it was expired or evicted),
    listed by `/query` from then on, `last_demand` of the current epoch, counted in the quota. It is
    charged to the global ingest bucket of ADR 0049 rule 6, and it is not stored (only served) when that
    bucket would refuse a new block from a `PUT`, or the stored total is above the high-water mark
    (ADR 0048 rule 13). A block that is
    only served is not listed by `/query` and is a demand event for nothing (it is not held). With
    `fallback_keep = false`, nothing fetched is stored.
20. **What listing needs.** A source gives no `/query`. A block reached through read-through appears in
    the reading relay's `/query` only when rule 19 stored it; a client that walks the graph from that
    relay finds the children it holds. Listing a bucket's content needs a relay that holds the index:
    the writer, or a replica of it (ADR 0048).

### What this gives a small relay

21. With an archive bucket among its `fallback_sources`, a small keeping relay can evict cold blocks
    (ADR 0046) without its clients losing them: a later `GET` is served from the bucket and, by rule 19,
    the block is warm again. This also bounds the harm of a write flood (ADR 0049, security review M-2):
    cold blocks a flood pushes out remain readable through the relay, as long as the bucket holds them.

### Configuration, secrets and footprint

22. **Credentials are never settings.** The access key identifier, the secret key and an optional
    session token are read from environment variables whose **names** are the settings
    `mirror_access_key_ref`, `mirror_secret_key_ref` and `mirror_session_token_ref`. A setting holds a
    variable name, never a key: a value outside `^[A-Z_][A-Z0-9_]{0,63}$`, or starting with
    `SBTP_RELAY_` (the settings namespace, ADR 0019), stops the start-up with a `config_error` that does
    not repeat the value. A referenced variable that is unset or empty stops the start-up when
    `mirror_endpoint` is set. Credentials are read once at start-up (rotation is a restart), kept in
    memory only, zeroed on drop, and never logged, published in `setting` events, metrics or errors.
23. **Endpoint rules.** `mirror_endpoint` follows rule 15's URL rules (same `mirror_allow_private`
    switch). TLS uses the outbound client of ADR 0048 rule 19 (rustls, ring, TLS 1.3, operating system
    roots or `peer_ca_file`). Every response body from the endpoint is read up to 16,384 bytes and
    discarded; only the status is logged.
24. **Least privilege** (guidance in `deploy/README.md`): the relay's credentials allow `PutObject` on
    `{mirror_prefix}sbtp/v1/*` of one bucket and nothing else (no `GetObject`, `ListBucket` or
    `DeleteObject`); on S3, a bucket policy denies a `PutObject` under `sbtp/v1/block/` without
    `If-None-Match` (`s3:if-none-match`); public read on `{mirror_prefix}sbtp/v1/*` only; credentials
    with an expiry where the provider supports it. Where a provider has no put-only grant (R2 API
    tokens are read-write per bucket), use a token scoped to that one bucket and say so. The bucket
    and its CDN MUST NOT answer `/sbtp/v1/` with a `3xx` (ADR 0030); its CORS allows `GET` and `HEAD`
    from any origin, without credentials.
25. **Dependencies.** No AWS SDK and no general S3 crate. Signature Version 4 is implemented in
    `sbtp-relay` (canonical request, string to sign, signing key derivation, a few hundred lines) on
    `sha2` (already in `Cargo.lock`) and `hmac` from the same RustCrypto family (one new small crate,
    under the two-week and `cargo deny` rules; otherwise HMAC by RFC 2104 over `sha2`, tested with the
    RFC 4231 vectors). Tests use the published SigV4 examples of the provider documentation. HTTP and
    TLS reuse the outbound stack of ADR 0048 (`hyper` client, `tokio-rustls`, `rustls-native-certs`).
26. **Build.** One Cargo feature, `object-store`, not a default feature of the crate, covers rules 6 to
    20. The published image is built with it (owner direction: one image; every function off at run
    time). Estimated cost over a build that already has the outbound TLS client of ADR 0048: under
    150 KB of binary, under 100 KB compressed in the image; without it, the TLS stack adds about 1 MB
    (ADR 0048 estimate). The CI budget job of ADR 0048 rule 3 (binary < 8,000,000 bytes, image
    < 5,000,000 bytes compressed) measures the image with every feature on.
27. **Memory** (owner decision of 2026-11-21, replacing the proposed text, which took these terms from
    `block_cache_bytes`). New terms of ADR 0018 rule 35, estimates: per upload or fetch in flight,
    65,909 (block) + 90,000 (TLS and HTTP state); the root store, 400,000, counted once and shared with
    replication when both are on; the uploader's page, 64 × 32; the negative cache,
    `fallback_negative_max × 48`. The terms count only when the feature is compiled and the function is
    on (`mirror_endpoint` set, `fallback_sources` not empty); they are **added to the bound**. The block
    cache keeps its default (`block_cache_bytes`, 2 MiB on `small`) whether these functions are on or
    off. On `small` with both functions on (one upload, one fetch, 256 negative entries):
    2 × 155,909 + 400,000 + 2,048 + 12,288 = 726,154 bytes alone, 326,154 bytes when replication is
    also on (the root store is already counted).

    The owner accepts about 1 MB per enabled outbound function rather than a smaller block cache. The
    budget of ADR 0048 rule 3, item 2 (as amended on 2026-11-21) applies: `small` with the default
    settings stays under 15,000,000 bytes (these functions are off by default); `small` with every
    function on stays under 20,000,000 bytes. Computed on `small`: the default bound with ADR 0049,
    14,910,996 bytes; plus server TLS (ADR 0028 rule 36, 2,228,224), replication (ADR 0048 rule 16,
    723,077) and this ADR (326,154): 18,188,451 bytes, 1,811,549 bytes under 20,000,000. That margin is
    what later functions (sync, streaming, chunks, OHTTP) have; each later ADR states its terms and the
    new total.

### Settings and metrics

28. **Settings** (environment variables `SBTP_RELAY_<NAME>`).

    | Setting | Default | Range | Kind |
    |---|---|---|---|
    | `mirror_endpoint` | empty (off) | absolute `https` URL of the S3 API | policy |
    | `mirror_bucket` | empty | 3 to 63 characters, `[a-z0-9.-]` | policy |
    | `mirror_region` | `us-east-1` | 1 to 32 characters, `[a-z0-9-]` (`auto` for R2) | policy |
    | `mirror_prefix` | empty | at most 256 characters, `[A-Za-z0-9/._-]`, ends with `/` | policy |
    | `mirror_url_style` | `path` | `path`, `virtual` | policy |
    | `mirror_access_key_ref`, `mirror_secret_key_ref` | `SBTP_MIRROR_ACCESS_KEY_ID`, `SBTP_MIRROR_SECRET_ACCESS_KEY` | variable names (rule 22) | policy |
    | `mirror_session_token_ref` | empty (none) | variable name | policy |
    | `mirror_info` | `true` | `true`, `false` | policy |
    | `mirror_public_url` | empty | read-only relay URL | policy |
    | `mirror_max_in_flight` | 1 / 4 / 8 | 1 to 64 | profile row |
    | `mirror_request_timeout_ms` | 30,000 | 1,000 to 300,000 | policy |
    | `mirror_max_backoff_s` | 3,600 | 1 to 86,400 | policy |
    | `mirror_allow_private` | `false` | `true`, `false` | policy |
    | `fallback_sources` | empty (off) | relay list, at most 16 | policy |
    | `fallback_max_in_flight` | 1 / 4 / 16 | 1 to 256 | profile row |
    | `fallback_per_min` | 60 / 600 / 6,000 | 1 to 1,000,000 | profile row |
    | `fallback_timeout_ms` | 5,000 | 500 to 60,000 | policy |
    | `fallback_negative_max` | 256 / 4,096 / 65,536 | 0 to 1,048,576 | profile row |
    | `fallback_negative_ttl_ms` | 60,000 | 1,000 to 3,600,000 | policy |
    | `fallback_keep` | `true` | `true`, `false` | policy |
    | `fallback_allow_private` | `false` | `true`, `false` | policy |

    A `mirror_*` or `fallback_*` setting other than its default in a build without `object-store` stops
    the start-up (ADR 0048 rule 3.1). `mirror_endpoint` set without `mirror_bucket` stops it.
29. **Metrics** (prefix `sbtp_relay_`): `mirror_uploaded_total`, `mirror_existing_total` (`412`),
    `mirror_failed_total` (label `status`: the HTTP status class or `network`), `mirror_missed_total`,
    `mirror_damaged_total`, `mirror_poisoned_total`, `mirror_lag_blocks` and `mirror_lag_ms` (gauges:
    positions after the cursor, and the age of the oldest of them); `fallback_fetches_total` (label
    `result`: `served`, `kept`, `not_found`, `invalid`, `timeout`, `limited`), `fallback_negative_hits_total`.
    Labels never carry a URL, a key or a client. Events: `mirror_failed`, `mirror_poisoned`,
    `fallback_source_failed` (rate-capped). Alert on `mirror_lag_ms` above `demand_epoch_ms` and on any
    `mirror_poisoned_total`.

## Consequences

- **Network.** A bucket and its CDN serve old blocks at a cost and scale a relay process does not reach,
  and several small relays can lean on one archive bucket. Discovery is unchanged: a read-only relay URL
  is a relay URL.
- **Integrity.** Unchanged: every reader validates every block. The worst a bucket or a writer can do is
  make a block unavailable from that bucket.
- **Privacy.** A read-through fetch tells the source which `block_id` a client of the relay asked for,
  not who asked; the relay's address is all the source sees. A bucket's CDN sees its readers, as any
  relay does. The writer stores nothing about clients in the bucket.
- **Cost.** No change on the `PUT` path. A local miss with fallback on adds one bounded outbound request.
  Index reads of the uploader: one page per 64 blocks.
- **Compatibility.** `read_only` is a new optional `/info` member; older clients ignore it and get a
  `4xx` on a `PUT` to a bucket.

## Implementation plan

| Stage | Work | Owner | Effort |
|---|---|---|---|
| 1 | Settings and checks (rules 22, 23, 28), SigV4 signer with provider test vectors, uploader (rules 6 to 11), `/info` object (rule 3), metrics; tests against a local S3-compatible server in CI (MinIO, pinned image digest) and an in-process stub for `412`, `409`, `403`, `3xx`, slow and oversize bodies | relay-engineer | 3 to 4 days |
| 2 | Read-through (rules 15 to 20): fetcher, bounds, negative cache, `Sbtp-Replication` on requests and the no-chain rule, keep path with ADR 0049 charge; tests with two in-process relays and a stub source serving a wrong body, a `302`, a slow body | relay-engineer | 2 days |
| 3 | `deploy/README.md`: bucket policies (S3, R2, MinIO), CORS, CDN, credentials through the service manager's secret mechanism, rotation by restart; web client and `cli-demo` read `read_only` | relay-engineer, wasm-engineer | 0.5 day |

**Security-auditor review (before merge of each stage):** no secret in settings, logs, events, metrics,
`config_error` text or panics; zeroing of credentials; the SigV4 implementation (canonical encoding of
keys and headers, signed payload hash); SSRF: endpoint and source URLs from configuration only,
private-address refusal with DNS that changes between checks, no redirect; every response body bounded
before allocation; the uploader's backlog lives on disk and its memory is constant; the no-chain rule;
fetch bounds and the negative cache against a client asking for random identifiers; a hostile source
(wrong body, `200` with a valid block for another id, slow body); the keep path takes no check the
`PUT` path has; the `small` bound with every function on (rule 27).

## Decisions of the project owner (2026-11-21)

1. **Accepted as proposed**, including the `/info` member `read_only` (core spec §4, a change of the
   relay interface; rule 3).
2. **`fallback_sources` is a separate setting**, not a marker in `peers` (rule 15).
3. **`fallback_keep` is on by default** (rule 19).
4. **One writer per bucket is recommended** (rule 13).
5. **Memory and size budget.** The proposed rule 27 (outbound terms taken from the block cache) is
   replaced: about 1 MB per enabled outbound function is accepted, and the block cache keeps its
   default. The budgets, checked in CI on every pull request, are recorded in ADR 0048 rule 3, item 2:
   binary under 8 MB; published image (the single image, every feature compiled in) under 5 MB
   compressed; `small` worst case under 15 MB with the default settings and under 20 MB with every
   function on; core `.wasm` under 200 KB gzip, with any MLS (group encryption) code in a separate
   module loaded on demand and budgeted on its own. This replaces the 16 MB bound of `small` with
   replication on (ADR 0048) and resolves Q-72.

## Spec change on acceptance

Applied on acceptance (2026-11-21).

Core spec §4, `GET /sbtp/v1/info`, new bullet after `demand_eviction`:

> - `read_only`: boolean; `true` when the URL serves `GET /sbtp/v1/block/{block_id}` and `/info` only,
>   for example a bucket of static objects. A client MUST NOT send `PUT` or `/query` to it. For
>   `GET /block` on such a URL, any status other than `200` or `304` means that the block is not served
>   there. A client MUST read an absent member as `false`. (ADR 0050)

`architecture.md` §2, new part after "Replication":

> ### Archive copy and read-through
> - A relay MAY copy every block it stores to an object store under `sbtp/v1/block/{block_id}`, with a
>   write that never replaces an existing object, and never deletes from it. The store's public URL is a
>   read-only relay URL: `GET /block` and a static `/info` with `read_only: true`. (ADR 0050)
> - A relay MAY read a block it does not hold from operator-chosen sources (read-only or full relays),
>   within fixed bounds, validate it as any received block and serve it; it MAY then store it as an
>   accepted block. A source never replaces a local block, and a relay never forwards a fallback
>   request it received from another relay. (ADR 0050)

## Rejected alternatives

- **Option B: the bucket as the primary block store.** Every cache miss and every `/query` follow-up
  would cost a network round trip and a billed request; store integrity (ADR 0023: quarantine, start-up
  walk), the quota (ADR 0025) and eviction assume local files; eviction would need delete rights,
  which defeats the put-only credentials; the relay would stop serving when the provider is down.
  Revisit only with a measured need.
- **Option C: a FUSE mount (s3fs and similar).** No atomic rename or reliable `fsync`, latency on every
  file operation, privileges for FUSE in a container, and the same mismatch with ADR 0023 and 0025.
- **An in-memory upload queue fed by the `PUT` path.** It needs a drop policy when the bucket is down
  and costs memory per pending block; the index walk of rule 7 costs neither.
- **The AWS SDK or a general S3 crate.** Tens of crates and megabytes of binary for one signed `PUT`.
- **`/.well-known/sbtp` in the bucket as the description.** RFC 8615 places it at the origin root,
  which a bucket under a prefix or a shared CDN host does not control, and it describes a site, not a
  relay URL. The static `/info` of rule 3 sits under the relay URL itself.
- **A "read-only" marker in the relay list format.** ADR 0048 rule 20 keeps lists free of metadata
  that goes stale; `/info` carries it.
- **Unconditional `PUT`.** A retry or a second writer would rewrite objects that a CDN already serves.
- **Credentials as settings.** A settings file would then hold a secret.
