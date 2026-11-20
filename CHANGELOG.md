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

### Security

- Independent security reviews of the decoder, the cryptography, the relay and the clients are in
  `docs/security/`.
