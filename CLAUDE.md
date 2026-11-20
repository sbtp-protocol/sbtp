# SBTP: Signed Block Transport Protocol

Binary transport protocol for signed blocks (BLAKE3, Ed25519, proof of work) organised as a DAG, with a
dumb relay, a WASM runtime and a generic layer 2 grammar for applications.
Stack: Rust (Cargo workspace, edition 2024), WebAssembly. License MIT OR Apache-2.0.

Contributor rules are in `CONTRIBUTING.md`; this file summarises them for coding assistants.

## Where things are

| Path | Contents |
|---|---|
| `docs/spec/sbtp-core-v0.2.md` | **Normative layer 0 spec** (binary format, crypto, relay API). |
| `docs/spec/architecture.md` | The layers, relay design, runtimes. |
| `docs/spec/l2-grammar.md` | Layer 2 grammar (`{v, kind, edges, body}`), `sbtp.*` kinds, sealed envelope. |
| `docs/spec/graph-access.md` | `sbtp:` URI, JSON block view, optional graph gateway API, MCP server, discovery. |
| `docs/decisions/` | Published architecture decision records. |
| `docs/test-vectors/` | Interoperability vectors. A published vector set never changes. |
| `crates/sbtp-core` | Layer 0, `no_std`, no `unsafe`. |
| `crates/sbtp-relay` | Dumb relay (axum, tokio). |
| `crates/sbtp-l2` | Generic layer 2 grammar validation. |
| `crates/sbtp-wasm` | `wasm-bindgen` bindings. |
| `examples/cli-demo` | CLI: keygen, mine, sign, publish. |

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p sbtp-core --no-default-features            # checks no_std
cargo build -p sbtp-wasm --target wasm32-unknown-unknown
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --check   # frozen vectors intact
```

## Rules

- **Spec first.** A change to the wire format, a validation rule, the relay API or the layer 2 grammar
  starts as a decision record and a spec change, then vectors, then code. An ambiguity found while coding
  is reported, never resolved silently in code.
- `sbtp-core`: `#![no_std]` outside the `std` feature, `unsafe` forbidden, **no `panic`, `unwrap` or
  unchecked indexing on network input**: everything goes through `Result` and `get()`. Zero-copy with
  `zerocopy` fixed-endianness types.
- Validation errors are enum variants, one per spec rule, each tested; a `// spec §x.y` reference next to
  the code that implements a rule.
- Everything in the repository is in English; RFC 2119 keywords (MUST, SHOULD, MAY).
- **Supply chain:** dependencies only through `[workspace.dependencies]` with explicit versions and the
  committed `Cargo.lock`; no `git` dependency, no `path` outside the repository, no crate published less
  than two weeks ago, no `build.rs` that downloads or executes anything. Only test keys derived from public
  seeds; no key or token in the repository or in logs.
