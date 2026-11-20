# Contributing to SBTP

Thank you for your interest. This document explains how the project works.

## Language

Everything in the repository is written in **English**: code, comments, rustdoc, specifications, ADRs,
reports, commit messages and pull request descriptions. Normative text uses the RFC 2119 keywords (MUST,
MUST NOT, SHOULD, SHOULD NOT, MAY).

## Specification first

1. A change to the wire format, a validation rule, the relay API or a layer 2 grammar rule starts as an
   **ADR** in [`docs/decisions/`](docs/decisions/) (template in its README), with status "proposed".
2. The project owner accepts it; only then is the specification updated, then the test vectors, then the
   code.
3. An ambiguity found while coding is reported as an issue, never resolved silently in code.
4. An accepted ADR is never rewritten: a later ADR amends or supersedes it.

## Before every commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p sbtp-core --no-default-features
cargo build -p sbtp-wasm --target wasm32-unknown-unknown
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
cargo run -p sbtp-core --features vector-gen --example gen_vectors -- --check
```

## Code rules (layer 0)

- `sbtp-core` is `no_std` outside the `std` feature; `unsafe` is forbidden in every crate of the workspace.
- No panic on network input: no `unwrap`, `expect`, unchecked indexing or unchecked arithmetic on data that
  has not been validated.
- One error variant per specification rule, each with its own test; a `// spec §x.y` reference next to the
  code that implements a rule.

## Reviews

Reviews are done per milestone branch (ideally under about 1,500 lines of diff), not per commit:

- a **security review** before merging anything that touches the decoder, cryptography, network-exposed
  relay code, key storage or dependencies, and at the end of every phase;
- a **correctness review** before every merge of code into `main`;
- a **spec conformance check** at the end of every phase and before freezing vectors;
- **test vectors** are never merged or published before the security review confirms that every negative
  vector discriminates the criterion it targets. A published vector set never changes.

## Dependencies

- Only through `[workspace.dependencies]`, with explicit versions; `Cargo.lock` is committed; crates.io only
  (no `git` or out-of-tree `path` dependencies).
- **Two-week rule:** no crate version published less than 14 days ago, transitive dependencies included
  (`cargo update -p <name> --precise <older>` to pin back). A new cryptography crate requires a security
  review.
- No `build.rs` that downloads or executes anything.
- JavaScript tooling (`interop/`, later `web/`): pnpm, exact versions, committed lockfile, the same two-week
  rule, and install scripts disabled next to every `package.json` (`ignoreScripts: true` in
  `pnpm-workspace.yaml` for pnpm 11+, plus `ignore-scripts=true` in `.npmrc` for npm).

## Commits and branches

- Branches: `feat/<crate>-<topic>`, merged into `main` with a merge commit after review.
- Commit messages: imperative summary line in English, then what and why. Never commit secrets: tests and
  vectors use only keys derived from documented public seeds.
