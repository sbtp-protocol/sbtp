# SBTP: Signed Block Transport Protocol

SBTP is a binary, decentralised, application-neutral transport layer. Each block is:

- **content-addressed**: its `block_id` is a BLAKE3 hash (domain-separated `derive_key` mode);
- **signed**: Ed25519, with strict verification;
- **spam-protected**: a local proof of work on the `block_id`;
- **linked to its parents**: up to 8 parents per block, forming a directed acyclic graph (DAG) with no
  central authority.

"Dumb" relays validate and store blocks without ever reading their payload. All application semantics live
in the clients. The repository provides the layer 0 format and its validation, a dumb relay, a WebAssembly
runtime, and a generic layer 2 grammar (typed edges, `sbtp.*` kinds, a sealed envelope) on which
applications define their own kinds. Applications are specified and implemented outside this repository.

> **Status: pre-release.** The layer 0 format and its interoperability vectors are settled internally but
> not yet published; the relay is in progress. Nothing is production-ready. See [Status](#status).

## Status

| Component | State |
|---|---|
| Layer 0 specification | Settled by 16 accepted ADRs ([`docs/decisions/`](docs/decisions/)) |
| `sbtp-core` | Implemented: zero-copy decoder, `block_id`, PoW, strict Ed25519, self-test; 116 tests, fuzzed, reviewed |
| Interoperability vectors | 82 vectors in [`docs/test-vectors/v1/`](docs/test-vectors/) (unpublished; frozen on first publication) |
| `sbtp-relay` | Implemented: HTTP API, flat-file store, redb index, age-based sweeper; container image `ghcr.io/sbtp-protocol/sbtp-relay` (from `relay-v0.1.0`) |
| `sbtp-wasm`, CLI | Implemented: WASM bindings, `cli-demo`, minimal web client |
| Layer 2 grammar | Specified ([`docs/spec/l2-grammar.md`](docs/spec/l2-grammar.md)); `sbtp-l2` validates it |
| Graph access | Specified ([`docs/spec/graph-access.md`](docs/spec/graph-access.md)): `sbtp:` URI, JSON view, optional gateway, MCP server; not implemented yet |

Changes: [`CHANGELOG.md`](CHANGELOG.md).

## Layout

```
crates/sbtp-core     layer 0: binary format, block_id, signature, PoW (no_std, no unsafe)
crates/sbtp-relay    dumb HTTP relay, content-addressed storage, index
crates/sbtp-wasm     WebAssembly bindings for the browser
examples/cli-demo    CLI: generate a key, mine, sign, publish
fuzz/                cargo-fuzz targets (standalone workspace)
docs/                specification, decisions, vectors, security reviews, benchmarks (see docs/README.md)
```

## Getting started

Prerequisites: Rust stable via rustup (`rust-toolchain.toml` installs `clippy`, `rustfmt` and the
`wasm32-unknown-unknown` target), and [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny).

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo build -p sbtp-wasm --target wasm32-unknown-unknown
cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --check   # vectors intact
```

Fuzzing needs nightly and `cargo-fuzz`: see [`fuzz/README.md`](fuzz/README.md).

## Block format (layer 0, version `0x01`)

```
magic(2) version(1) timestamp(8) nonce(8) pubkey(32) parents_count(1)
parents(32×N, N ≤ 8) payload_len(2) payload(≤ 65,535) signature(64)
```

All integers big-endian. A block is 118 to 65,909 bytes. Full specification:
[`docs/spec/sbtp-core-v0.2.md`](docs/spec/sbtp-core-v0.2.md).

## Contributing and security

- How the project works (spec first, ADRs, review policy, supply-chain rules):
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md).

## License

At your option: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
