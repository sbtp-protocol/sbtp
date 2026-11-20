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

### Security

- Independent security reviews of the decoder, the cryptography, the relay and the clients are in
  `docs/security/`.
