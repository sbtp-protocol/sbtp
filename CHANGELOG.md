# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Two things are versioned separately:

- **the protocol**: the layer 0 wire format (the Version byte, currently `0x01`) and its interoperability
  vector sets (`docs/test-vectors/v1/`). A published vector set never changes; a format change creates a
  new set and a new Version value;
- **the crates** (`sbtp-core`, `sbtp-relay`, …), which follow [Semantic Versioning](https://semver.org/).

Nothing has been released yet: everything below is unreleased.

## [Unreleased]

Initial public version. Pre-release software: no version is supported for production use yet.

### Protocol (layer 0, Version `0x01`)

- Signed block format: big-endian header, 0 to 8 parents, payload of up to 65,535 bytes, blocks of 118 to
  65,909 bytes; `block_id` = BLAKE3 with domain separation; strict Ed25519 verification (no batch
  verification); proof of work over the `block_id`; a fixed validation order (format, PoW, signature).
- 82 frozen interoperability vectors in `docs/test-vectors/v1/`, positive and negative, each negative
  vector isolating one rejection rule; Ed25519 cases cross-checked against a second implementation.
- Relay API: `PUT /sbtp/v1/block`, `GET /sbtp/v1/block/{block_id}` (immutable, cacheable),
  `GET /sbtp/v1/query` with cursors, `GET /sbtp/v1/info`.
- Operator deny list (ADR 0052, spec only so far): `451` with `Denied` / `DeniedKey`, `no-store`, denied
  blocks omitted from `/query` and returned as empty records in batches, `/info` `deny_list`; publishers
  never re-send a denied block automatically.
- Client implementations (ADR 0053, non-normative): boundary of a client library, shared conformance cases
  (`client-v1/`, planned), packaging and release policy for first-party packages.

### Layer 2

- Generic grammar `{v, kind, edges, body}` in a deterministic CBOR profile, typed edges and a verb
  registry, the `sbtp.manifest` kind for media chunks, and the sealed envelope (`sbtp.enc`, `sbtp.enc_key`,
  HPKE; specified, not implemented yet) in `docs/spec/l2-grammar.md`. Application kinds are defined by
  each application.

### Added

- `sbtp-core`: `no_std` zero-copy decoder and builder, signing, verification, proof of work; fuzz targets.
- `sbtp-relay`: dumb relay with content-addressed flat-file storage, an index with eviction and quota,
  resource limits and admission control, structured logs and metrics, store integrity checks;
  distroless container image and reverse-proxy guidance in `deploy/`.
- `sbtp-l2`: validation of the layer 2 grammar.
- `sbtp-seal`: sealed envelope of the layer 2 grammar (`l2-grammar.md` §5): HPKE base mode seal and open
  (single-shot, X25519/HKDF-SHA256/ChaCha20Poly1305), padding to the fixed buckets, strict inner
  signature, directory and application tags; `no_std` + `alloc`, `wasm32`. Security review:
  `docs/security/2026-11-21-sbtp-seal.md` (mergeable; L-2 fixed, other low and info findings tracked).
- `sbtp-relay`: archive copy to S3-compatible object storage (ADR 0050 stage 1, `object-store` feature,
  off by default): conditional `PUT` (`If-None-Match: *`) under `sbtp/v1/block/{id}`, never deletes,
  durable cursor with a window of 256 positions, SigV4 with the `hmac` crate, a static `/info` object with
  `read_only`; 4 lanes on `small` (amendments U1-U3). Measurements: `docs/benchmarks/2026-11-21-mirror-measurements.md`.
  Security review: `docs/security/2026-11-21-relay-object-mirror.md` (mergeable; low findings tracked).
- `sbtp-relay`, ADR 0051 stage 1 (read API for large graphs): `POST /sbtp/v1/blocks`, a batch read
  of 1 to 256 raw identifiers (body of at most 8,192 bytes with `Content-Length`; chunked or
  unannounced bodies get `400` and the connection closed), answered `no-store` with one
  length-prefixed record per identifier in request order (`0` when not served), streamed one block
  at a time through the read path of `GET /block`, ending after a complete record at 1 MiB, at
  half of `request_timeout_ms` or when a later read is refused; it costs `⌈N / 4⌉` `block` tokens
  at admission (64 without `Content-Length`, capped at the burst), counts each served block as
  demand once per epoch, none with `Sbtp-Replication: 1` (which also gets `CDN-Cache-Control:
  no-store`); CORS allows `POST`. `/query?fields=parents` adds `parents` and `lens` aligned with
  `block_ids`, pages of at most 200, refused with `parent`. Counters `batch_requests_total`,
  `batch_records_total{result}` and `batch_cut_total{reason}`; the route label
  `/sbtp/v1/blocks`.
- `sbtp-relay`, ADR 0051 stage 2: `/query?order=desc` (newest first, redb backward ranges; a
  cursor names a gap and is valid in both orders; `since` and the expiry bound end a `desc` walk);
  `head` in every `/query` response; `parent` repeated up to 32 times with per-parent cursors
  `<block_id>.<cursor>`, the per-parent limit `max(1, ⌊max_query_limit / N⌋)`, one read
  transaction and one reader job, the grouped body `{"head", "parents": [{"block_ids", "cursor",
  "more", "parent"}]}`, and a weight of `⌈N / 8⌉` `query` tokens. `/info` publishes
  `read_api: 2`.
- `sbtp-core`: the inner signature of a sealed payload (`l2-grammar.md` §5.3): typed builder
  `sealed_sig_message` (into a caller buffer, no allocation), `sign_sealed`, and `verify_sealed` with the
  strict criteria V1 to V6 (`SealedSigError`); the layer 2 registry constants `SEALED_HPKE_INFO`,
  `SEALED_SIG_PREFIX` and `ENC_KEY_DIRECTORY_CONTEXT` (spec §3.5).
- `sbtp-wasm`: WebAssembly bindings; `examples/cli-demo`: keygen, mine, sign, publish, query; `web/`:
  minimal browser client.
- Several relays in the clients, with automatic failover. `cli-demo`: `--relay` is repeatable or a
  comma list (at most 8) for `mine`, `publish`, `get`, `query` and `info`. `mine` mines once at the
  highest `/info` difficulty (each bounded by 24); `publish` sends to every relay in parallel and
  succeeds when one stores the block; `get` asks the relays in order and keeps the first block that
  passes the receipt rule; `query` prints each `block_id` once over all relays, with one cursor per
  relay (`--cursor <RELAY_URL>=<CURSOR>`). A command fails only when it fails on every relay. The web
  client keeps a relay list in its local settings, publishes to all relays, reads with failover,
  merges `/query` walks with per-relay cursors, leaves a failing relay aside with a back-off, and
  sends an own block again to the relays it failed on. Every block is validated whatever relay served
  it. Spec §4 gains a non-normative "Several relays" subsection; no rule changes.
- CI (`.github/workflows/`, `docs/ci.md`): the `CONTRIBUTING.md` checks on every push and pull request
  to `main`; a relay image built by CI and pushed to `ghcr.io/sbtp-protocol/sbtp-relay` on `relay-v*`
  tags, deployed by digest. Actions pinned by commit SHA, read-only token outside the image job.
- CI job `budgets` (ADR 0048 budgets): the static musl relay binary under 8,000,000 bytes, the relay
  image under 5,000,000 bytes compressed (also checked in `relay-image.yml` before the push), the
  computed `small` memory bound under 15,000,000 bytes with the defaults and 20,000,000 with every
  function on, and the core WASM under 200,000 bytes gzip (an upper bound from the cargo output,
  `web/wasm-budget.py`). No new tool is installed.
- `sbtp-relay`: ingest bounds against disk filling (ADR 0049). Stored bytes per hour are bounded per
  network group, always: an IPv6 /56 (10 % of `ingest_bytes_per_hour`), an IPv6 /48 or an IPv4 /24
  (25 %); a group over its budget gets `429` with `Retry-After` before its body is read, and only that
  group is refused. Group buckets live in a second limiter table of `ingest_group_max` entries (ADR
  0027 design, fail open when full, no shared overflow group). Above the low-water mark, a global
  cap of `ingest_bytes_per_hour` (200 MiB on `small`) answers `503` with `Retry-After` of at most
  300 s to new blocks; held blocks still get `200`. Nothing latches and no network origin is stored
  with a block. New settings `ingest_bytes_per_hour`, `ingest_group_max` (profile rows),
  `ingest_group_share_pct`, `ingest_group56_share_pct`; new counters and gauges `ingest_*`, events
  `ingest_capped` and `ingest_cap_ended`; `deploy/README.md` gains the ingest section, a CDN edge
  rule and the alerts of ADR 0049 rule 12. Computed `small` memory bound: 14,910,996 bytes.
- `sbtp-relay`: pull replication built into the relay (ADR 0048 stage 1), default Cargo feature
  `replication`, off at run time unless `peers` is set. Per peer the relay walks `/query` with a
  cursor kept in a new index table (`replication_peers`), skips held blocks and identifiers below
  `min_pow_difficulty` without fetching them, fetches the others with `Sbtp-Replication: 1`,
  validates each as a `PUT` body plus R1 and stores it through the `PUT` storage step (never charged
  to the ADR 0049 ingest bounds). `InvalidCursor` restarts the walk from the last complete page
  minus `replication_resync_margin_ms`. Bounds: `replication_max_in_flight`,
  `replication_blocks_per_min`, `replication_bytes_per_hour` (profile rows), round robin turns,
  ADR 0029 body ceilings, a total time limit, the peer's `Retry-After`, exponential back-off, a
  pause above the high-water mark. Outbound HTTP/1.1 with hyper's low-level client; TLS 1.3 with
  rustls and `ring` against the operating system store (`rustls-native-certs`) or `peer_ca_file`; no redirect followed; resolved private, loopback and link-local
  addresses refused unless `replication_allow_private`. New settings `peers`, `replication_start`,
  `replication_allow_private`, `peer_ca_file`, `replication_max_peers`,
  `replication_max_in_flight`, `replication_blocks_per_min`, `replication_bytes_per_hour`,
  `replication_poll_ms`, `replication_request_timeout_ms`, `replication_max_backoff_s`,
  `replication_resync_margin_ms`; counters `replication_*`; events `replication`,
  `replication_peer_backoff`, `replication_paused`, `replication_cursor_reset`. New dependencies:
  `rustls` 0.23.46, `tokio-rustls` 0.26.6, `rustls-native-certs` 0.8.5 and the hyper feature
  `client`; through them `ring` 0.17.14, `rustls-webpki` 0.103.16, `rustls-pki-types` 1.15.1,
  `untrusted` 0.9.0, `want` 0.3.2, `try-lock` 0.2.5, and per platform `openssl-probe` 0.2.2
  (Linux), `security-framework` 3.7.0, `security-framework-sys` 2.17.0, `core-foundation` 0.10.1
  (macOS), `schannel` 0.1.30 (Windows). Computed `small` memory bound with replication on:
  15,634,073 bytes, under the 20 MB budget of every function on. `deploy/README.md` gains a
  "Replication" section.
- Clients: the relay read API of ADR 0051, used only with a relay whose `/info` says `read_api: 2`
  (rule 31); any other relay gets exactly the requests of before. Web client: batch fetch
  (`POST /sbtp/v1/blocks`, length-prefixed records each checked by R1 against the id at its
  position and fully validated; `length = 0` and invalid records go to the next relay, a prefix is
  asked again, a record above 65,909 bytes or a body over 1 MiB is a failed request, the complete
  records before a truncation are kept), packed under 256 ids and 1 MiB from `fields=parents`
  lengths; single GETs stay the form for up to 32 blocks of a view, batches above that and for
  walks and cold starts. A batch of N ids counts N in the operation's 800-request bound. The view
  of a block (`src/view.js`) lists the 25 newest children (`order=desc`, `head` kept), the children
  of those items in grouped requests (32 parents each, per-parent cursors, `more` as the
  completeness signal: an item's replies are shown as complete only when every relay asked gave a
  complete listing), and "Refresh the view" polls the root and the shown items `asc` from `head` in
  one grouped request per 32. "Descendants" is a cold start: one relay-wide `fields=parents` walk,
  then batches of the descendants only. Ancestors are fetched one level at a time, in batches. A
  35-block view takes 38 requests against a fake relay (1 `/info`, 2 `/query`, 35 cacheable GETs),
  5 with batches; a refresh with nothing new takes 1. `cli-demo`: `get` takes up to 1,024 ids
  (batches of 256 with failover, `--out-dir`); `query` gains `--desc` (prints `head`), a
  repeatable `--parent` (2 to 32, `<ID>.<CURSOR>`, prints `<PARENT> <CHILD>` with per-parent
  completeness and cursors; one plain walk per parent on an older relay) and `--fields parents`
  (prints length and parents). No new dependency; no change to `sbtp-core` or `sbtp-wasm`.

### Changed (from a deep review of `sbtp-core` and `sbtp-l2`)

- **Breaking:** the default mining budget of `BlockBuilder::build` is counted in bytes compressed
  (`DEFAULT_MINING_BUDGET_BYTES`, `default_max_attempts`), so its time bound no longer grows with the
  payload; nonce exhaustion is the distinct, sticky `BuildError::NonceSpaceExhausted`.
- **Breaking:** `sbtp-l2` validates the registry verbs `tagged` and `tallies` and the structure of
  `sbtp.enc` and `sbtp.enc_key` (padding lengths, ciphertext length, key fields); `KindRow` declares its
  repeatable verbs per row (`repeatable`), and a required verb appears exactly once.
- **Breaking:** `sbtp-l2` implements ADR 0039. An `sbtp.enc_key` MUST carry its `tagged` edge as `p: 0`
  (`L2Error::EncKeyTagPosition`) and, with 2 parents, `supersedes` as `p: 1`
  (`L2Error::EncKeySupersedesPosition`); a key block with swapped positions, or with an extension or
  unknown causal verb as its second parent, is now invalid. The edge set of `sbtp.enc` is closed
  (`KindRow::closed`): an extra extension or unknown edge fails with `EdgeMultiplicity` instead of
  `EncCiphertextLen`. The set of valid `sbtp.enc` payloads does not change.

### Changed (relay hardening)

- `sbtp-relay`: `GET /sbtp/v1/info` carries `Cache-Control: no-store`, so that a CDN in front of the
  relay never serves settings from before a restart.
- `sbtp-relay`: `GET /sbtp/v1/block/{block_id}` sends `ETag: "<block_id>"` and answers a matching
  `If-None-Match` (a list, a weak tag or `*`) with `304 Not Modified`, for a block it holds. Spec §4
  gains the corresponding `MAY`.
- `sbtp-relay`: the age-based sweeper runs every `sweep_interval_ms` on one blocking thread:
  quarantine purge, then at most `sweep_batch` expired blocks, oldest first (cache entry, file, index
  entries), with `sweep` / `sweep_failed` log events and the `sweeps`, `sweep_removed` and
  `sweep_failures` counters. A `PUT` of an expired block, swept or not, is `201` with a new position
  and is listed by `/query` again; the held file is kept, so a full relay still accepts it, and the
  sweeper never deletes a block accepted again after it listed it (ADR 0043). `GET` still serves an
  expired block until the sweeper deletes it.
- `sbtp-relay`: `client_ip_header` (`SBTP_RELAY_CLIENT_IP_HEADER`, off by default): behind a CDN
  that writes one client address into a header (`CF-Connecting-IP`), the relay keys clients by that
  header on connections from `trusted_proxies`, instead of `X-Forwarded-For`; any other form falls
  back to the proxy's address; the value is never logged (ADR 0044). `deploy/README.md` states the
  conditions and the cross-tenant risk.
- `deploy/`: what the relay and its reverse proxy log about clients, recommended retention (none, or
  at most 7 days, for any log that holds addresses), and how to drop or mask addresses in Caddy and
  Traefik access logs.
- Network PoW difficulty `D_NET` = 16 (ADR 0045): `sbtp_core::NETWORK_POW_DIFFICULTY`; the default
  of the relay's `min_pow_difficulty` reads it, and a value above it logs the `config_warning`
  `pow_above_network`. `cli-demo` `mine` and the web client mine at `max(D_NET, highest /info
  difficulty)` (the /info cap of 24 still applies); an explicit difficulty is used as given.
- **Breaking (defaults):** `sbtp-relay` keeps what it receives (ADR 0046): `block_ttl_ms` defaults
  to 0 (no eviction by age; `/info` `null`) and demand eviction is on (`demand_eviction`,
  `demand_high_water_pct` 90, `demand_low_water_pct` 80, `demand_epoch_ms` 8 hours,
  `demand_touch_max` 16,384 / 131,072 / 1,048,576 by profile). Above the high-water mark the
  sweeper deletes the blocks requested least recently (a `200` or `304` of `GET` or `HEAD`, a
  `PUT` answered `200`, an acceptance, the acceptance of a child), never one demanded within
  `3 × E`, down to the low-water mark; a lost demand or an unclean restart suspends it for `2 × E`.
  Demand is kept in a fixed-size set off the request path and written to the index at most once
  per block per epoch (two new index tables, filled at the first start of an older index). With
  demand eviction on, block responses carry `s-maxage` and `CDN-Cache-Control` of `E / 2`; a `507`
  above the high-water mark carries `Retry-After`. `/info` gains `demand_eviction`. New counters,
  gauges and the `demand_evicted`, `demand_stuck` and `demand_suspended` events. An archive relay
  is `demand_eviction = false` with `block_ttl_ms = 0`. `deploy/README.md`: retention modes and the
  Cloudflare cache rules. The `small` profile's computed memory bound is 14,747,092 bytes.
- **Breaking (defaults):** `sbtp-relay` `demand_epoch_ms` defaults to 28,800,000 (8 hours) instead
  of 86,400,000 (1 day); range unchanged, 4 hours to 30 days (owner decision, ADR 0046
  clarification D10). With the default, block responses carry `s-maxage=14400` and
  `CDN-Cache-Control: public, max-age=14400, must-revalidate` (was 43,200), a block is protected for
  at least 24 hours (was 3 days), a demand suspension lasts 16 hours (was 2 days), and a shared cache
  revalidates a requested block up to 6 times a day per cache location (was 2). Set
  `demand_epoch_ms = 86400000` to keep the former behaviour.
- Web client: an own block stays protected in the local store until every relay of the list
  acknowledges it, within a bound (ADR 0047). Each own block keeps a delivery state per relay
  (pending, acknowledged, refused, given up) with its attempt count, first attempt and first
  acknowledgement, replacing `acked` and the truncated `failedOn`. A `PUT` answer is transient (the
  relay stays pending: no response, timeout, `408`, `429`, `5xx` including `507`, `400
  TimestampTooFarInFuture`) or final (refused: any other `400` including `InsufficientPow`, `413`,
  `422`, a `3xx`, any other `4xx`); a request not sent because of a back-off is not an attempt.
  A pending relay is given up after 5 attempts and 24 hours since the first, and in any case 7 days
  after the block's first acknowledgement (`bounds.js`); a block no relay acknowledged keeps its
  protection. Removing a relay deletes its states (a block only it held is protected again and sent
  to the others); an added relay is pending only for the blocks protected then. Eviction: fetched
  blocks, then unprotected own blocks, then, only for a new own block, partly delivered ones (oldest
  first acknowledgement first). A new "Undeliverable own blocks" section lists the blocks no relay
  holds or is pending for, with add a relay, export and delete. Stored records are rewritten on the
  first start, with no IndexedDB version change.

### Fixed

- Security review 2026-11-21 of the relay read API (`docs/security/2026-11-21-read-api-0051.md`):
  - web client cold start: the `fields=parents` hints of several relays are merged as a union of the
    claimed parents (and the largest claimed length) per block, so a hostile relay listed first can no
    longer hide a block that another relay lists by claiming `parents: []` (M-1);
  - web client view: a relay skipped for lacking `read_api: 2` counts as incomplete for every item, so
    "replies N (complete)" is no longer shown when an older relay was never asked (L-2);
  - `sbtp-relay`: `rate_block_burst` below 64 and `rate_query_burst` below 4 are refused at start-up
    with a constraint error, so the capped weights of ADR 0051 rule 21 cannot serve more than 4 blocks
    (or 8 parents) per token (L-1);
  - web client and `cli-demo get`: a `POST /sbtp/v1/blocks` refused with `400`, `404`, `405`, `411`
    or `413`, or answered with a broken body, falls back to single `GET`s on the same relay instead of
    failing the ids; the web client remembers it per relay for the session (I-1);
  - `sbtp-relay`: a refused `peers` URL is shown with everything from `//` to its last `@` hidden, so a
    password holding `/`, `?` or `#` is hidden too, and with its position in the list (I-2).
- Pre-push security review 2026-11-21 of replication and ingest bounds
  (`docs/security/2026-11-21-replication-ingest-pre-push.md`), `sbtp-relay`:
  - the byte budget of a network group (ADR 0049) is checked once the `PUT` permit is held, still
    before the body is read: `PUT`s waiting in the queue no longer pass it uncharged, which let one
    group store about 5 times its share (M-1);
  - with `peers` set, `max_blocking_threads` defaults to (and must be at least)
    `block_max_readers + put_max_in_flight + 2 + replication_max_in_flight + 1`: the DNS lookups and
    cursor writes of replication no longer take the blocking threads of `GET` and `PUT` (L-1);
  - the global ingest cap is checked after the signature: a bad signature gets `422`, not `503`,
    while the cap is active (ADR 0049 rule 6, L-2);
  - replication refuses peer addresses in `64:ff9b:1::/48`, `192.0.0.0/24` and `198.18.0.0/15`, and
    judges 6to4 and Teredo addresses by the IPv4 addresses they embed (I-1);
  - a peer URL with userinfo is refused without printing the userinfo back (I-2).
- Pre-push security review 2026-11-21 (`docs/security/2026-11-21-pre-push-eviction-fixes-web-0047.md`):
  - `sbtp-relay`: a demand pass no longer ends after one deletion when `PUT`s or index growth move
    the admission total during it; a deletion ends the pass only when it released no quota bytes
    (L-1);
  - `sbtp-relay`: a suspension restored at start-up is capped at `2 × E` from the start, so that an
    end written under a wall clock far ahead cannot suspend demand eviction for years (I-1);
  - web client: a relay-supplied error name keeps only `[A-Za-z0-9_-]` before it is stored or
    shown (I-2);
  - `deploy/README.md`: the `no_history` cause also covers the one-off suspension of a relay
    upgraded from the previous build (I-5).
- `sbtp-relay`, demand eviction (security review 2026-11-21, ADR 0046 clarifications D1 to D6):
  - a start with no demand history (first start after the upgrade, an index rebuilt from the block
    files) and every change of `demand_eviction` from off to on now suspend demand eviction for
    `2 × E` (`demand_suspended cause=no_history` or `cause=enabled`); the setting of each start is
    recorded in the index metadata. A new empty data directory is not suspended (M-1);
  - a running suspension is written to the index at a clean stop and restored at the next start
    (`cause=restored`) (L-1);
  - each candidate of a demand pass checks the suspension again under its lock: a demand lost
    during the pass ends it (L-2);
  - a drain ended by its deadline or by a second signal no longer marks the index clean (L-3);
  - `507` carries `Retry-After` only while demand eviction is on, neither suspended nor stuck;
    otherwise none (L-4, amends ADR 0023 rule 18);
  - when the index part alone reaches the low-water mark, the sweeper deletes nothing and logs
    `demand_stuck cause=index`; a run also ends when a deletion did not lower the stored total (I-2);
  - order entries without an index row no longer fill a candidate listing and stall it: they are
    skipped and counted (`orphans` field), at most 10,000 per listing (I-3);
  - the start-up migration of the demand tables logs `demand_migration` lines (start, every
    100,000 blocks, end), with counts and durations only (I-4).
- `sbtp-relay`: a `GET` or `HEAD` of `/block` carrying `Sbtp-Replication: 1` is answered
  `Cache-Control: no-store` and `CDN-Cache-Control: no-store` in every mode and is not counted as
  demand (ADR 0048 rule 18).
- `deploy/README.md`: the CDN purge to make after turning demand eviction on, the start-up
  suspension causes, and an "Alerts" section.
- `sbtp-relay`: the sweeper could delete a block that had just been answered `201` when it listed
  the expired position while the acceptance's index insert was still being written (pre-push review
  2026-11-20 M-1, ADR 0043 rule 4). An acceptance now counts itself only after its index insert
  returns.
- `sbtp-relay`: a file deletion that keeps failing (for example a directory under a block's final
  name) no longer stops eviction by age: the sweeper skips that position for the run and goes on
  with the next ones, still logging `sweep_failed` and counting `sweep_failures` (review L-1).
- `cli-demo query --follow` with several relays no longer polls a relay whose walk failed (a fatal
  refusal, a `Retry-After` above 300 s, no progress, the dedupe bound): that relay is retired for
  the run, and the command ends when every relay is retired. The `block_id`s printed over all relays
  have a bound of their own (1,000,000). (Security review 2026-11-21, M-1.)
- Web client: a relay's `Retry-After` is checked again before each `GET` of a failover, and a
  success already in flight no longer lifts it; merged `/query` ids are taken round-robin across the
  relays, so the first relay cannot fill the view. (Security review 2026-11-21, L-1, L-2.)

### Security

- Independent security reviews of the decoder, the cryptography, the relay and the clients are in
  `docs/security/`.
