# Security review: `feat/core-hardening` (2026-11-18)

Scope: `git diff main..feat/core-hardening` (commits `c10cccf`, `4ff71ff`). Independent review from the diff,
the registry and the spec/ADR rules, not from the author's conclusions.

**Verdict: OK to merge.** No blocking finding. Two low/info points, neither required before the merge.

## What was checked

| Check | Result |
|---|---|
| Files changed | 6, all additions: `crates/sbtp-core/tests/validation.rs` and `interop/noble/*`. `crates/sbtp-core/src`, `Cargo.toml`, `Cargo.lock` identical to main. |
| `docs/test-vectors/v1/` | Byte-identical to main (`git diff --quiet`, 82 files). |
| Lockfile integrity | `sha512-criDgRlnUA09hchYrTy/JUWPIEap5rZxQe6wDWzRx51oWWpDRcUpuNzlgPxDJaOK6AsW9c0wKcj3rKRv6t+bPQ==` equals the registry `dist.integrity` of `@noble/ed25519@3.2.0` and the SHA-512 of the tarball downloaded and hashed separately. |
| Installed code | `node_modules/@noble/ed25519` in the worktree is identical (`diff -r`) to the unpacked registry tarball. |
| Package metadata | No `dependencies`, `optionalDependencies`, `peerDependencies`, `bin` or `gypfile`; scripts are `test`, `build`, `check`, `format`, `benchmark*` only (no install lifecycle script). Maintainer `paulmillr`, published 2026-08-27 by GitHub Actions, 83 days old. |
| Package content | 6 files (`index.js`, `index.ts`, `index.d.ts`, README, LICENSE, `package.json`). No `child_process`, `fs`, `fetch`, `eval`, `Function(`, dynamic `import(` or `process.env` in `index.js`. |
| `node_modules` ignored | `interop/noble/.gitignore:1`, confirmed with `git check-ignore`; not tracked. |
| `check-vectors.mjs` | Imports `readFileSync`, `readdirSync`, `createHash`, `path`, `url` and noble only. No write API, no network, no subprocess. Worktree clean after a run. |
| Script results | 82 vectors, 67 signature-checked, 15 format-only skipped, 0 inconsistencies. Strict mode: 9 divergences (8 `c3_v5_only_r_*` and `c3_v6_cofactored_only`), all "noble accepts, sbtp-core rejects". ZIP-215: 19. Matches the README. |
| noble behaviour | Read in `index.js` 3.2.0: small-order check on `A` only, in strict mode only (l.687); no small-order check on `R`; final equation `RkA.subtract(SB).clearCofactor().is0()` (l.694), cofactored in both modes. The README table and its conclusion are accurate. |
| Tests | `cargo test -p sbtp-core --test validation --offline`: 86 passed, the 6 new ones included. |

## Findings

### Low: the supply-chain rules do not cover npm (`CLAUDE.md` l.112-123, `CONTRIBUTING.md` l.56-62)

The rules are written for crates only (`[workspace.dependencies]`, crates.io, `cargo deny`). The noble check
respects their intent (exact version, committed lockfile with integrity, `--ignore-scripts`, 83 days old
against a 14-day minimum, no transitive dependency), and committing the lockfile is the right choice: it is
what pins the tarball hash. But nothing states it, and `cargo deny` will never see this directory.

Fix (can follow the merge): one sentence in `CONTRIBUTING.md` extending the rules to `interop/` tooling
(exact version, committed lockfile, `--frozen-lockfile --ignore-scripts`, two-week rule, never imported by
shipped code). Phase 3 will bring npm into the PWA, so the rule will be needed anyway.

### Info: `check-vectors.mjs` `parseBlock` does not bound-check (l.45-55)

A truncated `block_hex` gives `undefined` offsets and throws or reports "block layout does not add up".
Input is the repository's own vectors and the script is not shipped: harmless, no fix needed.

### Info: 2 of the 6 new tests are coverage-driven

`display_messages_carry_the_error_fields` and `build_and_self_test_errors_display` pin `Display` strings.
They are not tautological (expected strings are literals, not derived from the code under test), but they
protect wording, not security behaviour. The other four assert real behaviour: error propagation through
`write_unsigned` / `build_unsigned` / `build`, `KeyMismatch`, `mine` and `sign_block` refusing a short buffer
and leaving it unchanged, C1 reported after R1 passes with exact `required` / `actual`, `BlockId`
conversions. In `mine_and_sign_refuse_a_malformed_buffer` the "unchanged" assertion is weak (an all-zero
buffer rejected on length alone), which is acceptable for what it claims.

## Conclusion for Phase 3

Confirmed: `@noble/ed25519` in either mode accepts signatures that every relay rejects (V5 unchecked,
cofactored equation). The browser must verify through `sbtp-wasm`, as ADR 0003 requires. noble must not be
used as the verifier in the PWA, even with `zip215: false`.

## Not checked

- No source audit of noble beyond the `verify` / `Point.fromBytes` paths and a pattern scan of `index.js`.
- The README claim that strict mode allows `S = 0` (`arange(s, 1, N)`) was not verified.
- npm provenance attestation of the tarball was not verified (hash and publisher only).
- `cargo deny check`, `cargo clippy` and the fuzz targets were not run: the library and `Cargo.lock` are
  unchanged.
- Whether the coverage figures quoted in commit `4ff71ff` are accurate (`cargo-llvm-cov` not run).
