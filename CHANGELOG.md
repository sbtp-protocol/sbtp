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
  `demand_high_water_pct` 90, `demand_low_water_pct` 80, `demand_epoch_ms` one day,
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
