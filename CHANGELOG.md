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
- `sbtp-wasm`: WebAssembly bindings; `examples/cli-demo`: keygen, mine, sign, publish, query; `web/`:
  minimal browser client.

### Changed (from a deep review of `sbtp-core` and `sbtp-l2`)

- **Breaking:** the default mining budget of `BlockBuilder::build` is counted in bytes compressed
  (`DEFAULT_MINING_BUDGET_BYTES`, `default_max_attempts`), so its time bound no longer grows with the
  payload; nonce exhaustion is the distinct, sticky `BuildError::NonceSpaceExhausted`.
- **Breaking:** `sbtp-l2` validates the registry verbs `tagged` and `tallies` and the structure of
  `sbtp.enc` and `sbtp.enc_key` (padding lengths, ciphertext length, key fields); `KindRow` declares its
  repeatable verbs per row (`repeatable`), and a required verb appears exactly once.

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

### Security

- Independent security reviews of the decoder, the cryptography, the relay and the clients are in
  `docs/security/`.
