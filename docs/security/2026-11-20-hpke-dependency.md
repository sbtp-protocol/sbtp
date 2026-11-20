# Supply-chain review: `hpke` 0.15.1 for the sealed envelope (ADR 0016)

- Review date: 2026-11-20. Reviewer: security auditor.
- Scope: the dependency `hpke = "=0.15.1"` with `default-features = false` and the features `x25519`,
  `chacha`, `alloc`, and every crate it adds to `Cargo.lock`. Intended use: ADR 0016 rule 1 (HPKE
  `mode_base`, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, single-shot API) in a future
  `crates/sbtp-seal` (`no_std` + `alloc`, `wasm32-unknown-unknown`).
- Method: `hpke` was not in `[workspace.dependencies]` nor in `Cargo.lock`. A throwaway member crate
  depending on it was added in the review worktree to resolve the graph, then removed; `Cargo.lock` was
  restored byte for byte. Commands: `cargo fetch`, `cargo tree -e normal,features --target
  wasm32-unknown-unknown`, `cargo deny check`, `cargo update --dry-run` at a raised `rust-version`, a
  native and wasm32 build, one native seal/open round-trip test. crates.io API for dates, licences,
  owners and `rust_version`. Sources read from the cargo registry cache.
- Commit: only the `[workspace.dependencies]` line (with its conditions in a comment). No member uses it
  yet, so `Cargo.lock` is unchanged; the lock entries are created by the `sbtp-seal` PR, under the
  conditions below.

## Verdict

**Accept with conditions.** `hpke` 0.15.1 and its transitive set are the expected, well-known
RustCrypto and dalek crates, all crates.io, all permissively licensed, no `build.rs` anywhere, one
procedural macro (`zeroize_derive`, RustCrypto, read: no I/O, no process, no `include_*`). No duplicate
version is introduced. But resolving it **today, with the declared MSRV 1.85, locks a vulnerable crate**
(`ctutils` 0.4.2, RUSTSEC-2026-0385, `cargo deny check` fails) and one crate younger than two weeks
(`inout` 0.2.6). Both are fixed by the resolution order and pins below; with them, `cargo deny check` is
green and the code builds natively and for `wasm32-unknown-unknown`.

### Conditions (blocking for the `sbtp-seal` PR)

1. **Raise the workspace `rust-version` to `1.90` first, in its own commit, before resolving `hpke`.**
   The real floor of the locked graph is 1.90 (`redb` 4.6.0); `hpke` 0.15.1 and `ctutils` >= 0.4.3 need
   1.87; `proptest` 1.12.0 needs 1.88. Resolver 3 is MSRV-aware: at the declared 1.85 it picks
   `ctutils` 0.4.2 (finding F-1).
2. **`ctutils` MUST be >= 0.4.4 in `Cargo.lock`; use 0.4.8** (published 2026-11-02, 18 days,
   checksum `261af4dc7a06ea8a527a8717d8cbba3417530d6ea14e1edb3de6b67806be474f`). At MSRV 1.90 the
   resolver picks it by itself.
3. **`inout` MUST stay at 0.2.5** (`cargo update -p inout --precise 0.2.5`, 2026-10-19, checksum
   `3b5cf4372d022092674a83b8febf5865f7a573cc0c5baec5e49c879b6a20978f`) if the PR is resolved before
   2026-11-21. From 2026-11-21, 0.2.6 is 14 days old and SHOULD be taken instead (finding F-2).
4. **The lock diff of the PR MUST contain exactly these 13 new packages and nothing else moving**
   (besides the new `sbtp-seal` entry and the new feature edges listed in "Graph"): `aead` 0.6.1,
   `chacha20poly1305` 0.11.0, `cipher` 0.5.2, `cmov` 0.5.4, `ctutils` 0.4.8, `hkdf` 0.13.0, `hmac`
   0.13.0, `hpke` 0.15.1 (checksum `8f512e325a1a71bf3273fb9b7fc9e5d96dac136fb4a95d0e6637001b12ea3e09`),
   `inout` 0.2.5 (or 0.2.6 after 2026-11-21), `poly1305` 0.9.1, `universal-hash` 0.6.1,
   `x25519-dalek` 3.0.0, `zeroize_derive` 1.5.0. `cargo deny check` green in the same PR.
5. **`sbtp-seal` uses only the single-shot API in `mode_base`** (`single_shot_seal_with_rng`,
   `single_shot_open`) with the suite fixed by type parameters, never `hpke::danger` (an unstable,
   not-feature-gated streaming module) and never `Serializable::write_exact` on a buffer whose length
   comes from input (it `assert!`s; use `to_bytes()`).
6. **Known-answer test**: `sbtp-seal` MUST carry the RFC 9180 Appendix A.2 vector
   (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode) as a test, through
   the deterministic `derive_keypair` / a seeded RNG in tests only. The published `hpke` crate excludes
   its own `test-vectors/`, so its KATs cannot be run from the tarball.

### Exact line for `[workspace.dependencies]`

```toml
hpke = { version = "=0.15.1", default-features = false, features = ["x25519", "chacha", "alloc"] }
```

MSRV to declare: **`rust-version = "1.90"`** (workspace). The lowest value that `hpke` alone forces is
1.87; 1.90 is what the existing lock already needs.

## Findings

### F-1 (high, blocking; trivial to fix): resolving at MSRV 1.85 locks `ctutils` 0.4.2, RUSTSEC-2026-0385

- Where: `Cargo.lock` after adding `hpke`; root cause `Cargo.toml` line 14 (`rust-version = "1.85"`)
  together with `resolver = "3"`.
- Facts: `hmac` 0.13 enables the `mac` feature of `digest` 0.11.3, which pulls `ctutils`. `ctutils`
  0.4.3 and later declare `rust-version = 1.87`; the MSRV-aware resolver therefore falls back to 0.4.2.
  RUSTSEC-2026-0385 ("Non-constant-time mask generation and `u128` comparisons"): before 0.4.4 the
  `Choice` mask functions could compile to a branch, and `u128` constant-time comparisons branched on
  **32-bit targets**. `wasm32-unknown-unknown`, the web target of `sbtp-seal`, is a 32-bit target.
- Scenario: `universal-hash` 0.6.1 verifies the Poly1305 tag with `ct_eq` from `ctutils`
  (`universal-hash-0.6.1/src/lib.rs:137`). A branch in that comparison is a timing side channel on tag
  verification. Practical exploitability over the network is low (the client opens blocks it fetched,
  one try per key, no oracle returned to the sender), but it is exactly the property the crate exists
  to provide, and `cargo deny check` fails, so the PR could not merge anyway.
- Note: `ctutils` also enters the graph of `ed25519-dalek` through feature unification on `digest`.
- Fix: conditions 1 and 2. Verified: at `rust-version = "1.90"`, `cargo update --dry-run` picks
  `ctutils` 0.4.8, and `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`.

### F-2 (medium, process): `inout` 0.2.6 is 13 days old

- `inout` 0.2.6 was published 2026-11-07 (13 days): it breaks the two-week rule of `CONTRIBUTING.md`.
  Without a pin, the resolver takes it (it is MSRV 1.85).
- What 0.2.6 changes (diff of the tarballs read): a Stacked/Tree Borrows fix in
  `InOutBufReserved::split_reserved` and `into_padded_blocks` (`src/reserved.rs`), i.e. aliasing
  undefined behaviour visible under Miri. `into_padded_blocks` is behind the `block-padding` feature,
  which is not enabled; `split_reserved` has no caller in `aead`, `cipher`, `chacha20`,
  `chacha20poly1305`, `poly1305`, `universal-hash` or `hpke`. The ChaCha20Poly1305 path does not reach
  the fixed code, so 0.2.5 is safe for this use.
- 0.2.3 was yanked and 0.2.4 to 0.2.6 followed within three weeks (all soundness or bounds fixes in the
  padded/reserved buffers). This is active hardening by RustCrypto, not a red flag, but it argues for
  keeping the pin exact and taking 0.2.6 once eligible.
- Fix: condition 3. No owner exception is needed: waiting one day, or pinning 0.2.5, both satisfy the
  rule.

### F-3 (low): `poly1305` state is not wiped on drop

- `poly1305` 0.9.1 zeroizes its state only with its `zeroize` feature
  (`poly1305-0.9.1/src/lib.rs:122-129`); `chacha20poly1305`'s `zeroize` feature (enabled by `hpke`)
  forwards to `chacha20` but not to `poly1305`. The one-time Poly1305 key (derived per message from the
  ChaCha20 key) can stay in freed memory.
- Impact: low. The key is single-use and an attacker who reads process memory already has better
  targets (the X25519 private key, the plaintext). Zeroization is best-effort in WASM anyway.
- Fix (optional): `sbtp-seal` MAY add `poly1305 = { version = "0.9.1", default-features = false,
  features = ["zeroize"] }` as a direct dependency to unify the feature. Not required for acceptance.

### F-4 (low): RNG adapter panics on entropy failure

- `hpke` takes `&mut impl rand_core::CryptoRng` (infallible, `rand_core` 0.10). With the workspace
  `getrandom` 0.4.3, the working adapter is `hpke::rand_core::UnwrapErr(getrandom::SysRng)`, which
  needs the `getrandom` feature `sys_rng` and **panics** if the OS or Web Crypto source fails. Verified
  in the throwaway crate: seal and open round-trip natively, wrong `aad` is rejected, and the same code
  builds for `wasm32-unknown-unknown` with `wasm_js`.
- Impact: availability only (a panic in WASM aborts the call), never a weak key. Acceptable, but the
  `sbtp-seal` reviewer should decide whether to probe entropy with `getrandom::fill` first and return an
  error instead of panicking. Never substitute a seeded RNG outside tests (ADR 0016).

### F-5 (info): `hpke` is a single-owner crate without a paid audit

- crates.io owner of `hpke`: `rozbb` only (also publisher of `x25519-dalek` 3.0.0). The upstream README
  states no formal audit beyond Cloudflare's review of 0.8. 0.15.1 published 2026-10-28 (23 days), not
  yanked, about 0.3 M downloads for this version. Everything below it is RustCrypto (team-owned,
  `newpavlov`, `tarcieri`) or dalek (`isislovecruft` plus team).
- Risk: bus factor and a compromised-publisher scenario for one crate. Mitigated by the exact pin, the
  committed lock checksum, and this review. Re-review on every bump (exact pin means any bump is a PR).

### F-6 (info): properties checked and found correct

- RFC 9180 §7.1.4 all-zero check: `hpke-0.15.1/src/dhkex/x25519.rs:150-159` rejects an all-zero DH
  output with `ct_eq` on both encap and decap (ADR 0016 rule 4 is met by the library).
- Hostile input does not panic in the paths `sbtp-seal` will use: `PublicKey::from_bytes` and
  `PrivateKey::from_bytes` check the length and return `IncorrectInputLength`; `open` uses
  `checked_sub` for the tag length (`aead.rs:332-335`). Only `write_exact` asserts (condition 5).
- Private keys: `PrivateKey` wraps `x25519_dalek::StaticSecret` (zeroize on drop), has no `Debug`, and
  its `PartialEq` is constant time. DH outputs and the key schedule buffers are zeroized
  (`kem/dhkem.rs`), `AeadKey`, `AeadNonce` and `ExporterSecret` zeroize on drop. Deserialised X25519
  keys are clamped (0.15.0 change).
- Tag check: `chacha20poly1305` verifies the tag before decryption with `ct_eq`
  (`chacha20poly1305-0.11.0/src/cipher.rs:89-90`), which is where F-1 matters.
- `unsafe`: none in `hpke`, `aead`, `cipher`, `chacha20poly1305`, `hkdf`, `hmac`, `universal-hash`,
  `x25519-dalek`; `aead`, `cipher`, `ctutils` and `universal-hash` `forbid(unsafe_code)`. `unsafe` is
  confined to `cmov` (inline `asm!` for constant-time selects on native targets, portable code on
  wasm32), `poly1305` (AVX2 backend, x86 only; the soft backend is used on aarch64 and wasm32) and
  `inout` (raw-pointer in/out buffers). All three are RustCrypto and widely used.
- `no_std`: every new crate is `#![no_std]`; `hpke` has no `std` feature and, with these features, no
  `getrandom` dependency (the caller passes the RNG).
- Licences: all `MIT OR Apache-2.0` except `x25519-dalek` (BSD-3-Clause); all allowed by `deny.toml`.
- Sources and bans: crates.io only, no git; `curve25519-dalek` reused at 5.0.0 without
  `legacy_compatibility`; no `build.rs` in any new crate (`build = false` in every manifest).

## Graph

New packages (13): `aead` 0.6.1 (2026-06-17), `chacha20poly1305` 0.11.0 (2026-06-28), `cipher` 0.5.2
(2026-05-19), `cmov` 0.5.4 (2026-05-28), `ctutils` 0.4.8 (2026-11-02), `hkdf` 0.13.0 (2026-03-30),
`hmac` 0.13.0 (2026-03-29), `hpke` 0.15.1 (2026-10-28), `inout` 0.2.5 (2026-10-19), `poly1305` 0.9.1
(2026-07-08), `universal-hash` 0.6.1 (2026-02-27), `x25519-dalek` 3.0.0 (2026-07-06), `zeroize_derive`
1.5.0 (2026-06-12). All older than 14 days with the pins above. Compared with the list expected in ADR
0016, `cmov` and `ctutils` are additional.

Reused at the locked version, no duplicate: `chacha20` 0.10.2 (gains the `cipher` and `zeroize`
features), `curve25519-dalek` 5.0.0, `digest` 0.11.3 (gains `mac`, hence `ctutils`), `sha2` 0.11.0,
`rand_core` 0.10.1, `subtle` 2.6.1, `zeroize` 1.9.1 (gains `zeroize_derive`), `hybrid-array`,
`crypto-common`, `block-buffer`, `typenum`. The only `cargo deny` duplicate warning (`syn` 2 and 3) was
already there.

## Not checked

- A build with the 1.87 or 1.90 toolchain: only stable 1.100 is installed; the MSRV figures come from
  the crates' declared `rust-version`.
- A real `no_std` target (no bare-metal target installed); `no_std` is inferred from the crate
  attributes and the `wasm32-unknown-unknown` build.
- RFC 9180 known-answer tests (excluded from the `hpke` tarball; condition 6).
- Constant-time behaviour of the generated WASM under a JIT (V8, SpiderMonkey): not verifiable here;
  constant time in the browser is best-effort for every library.
- A line-by-line review of `hpke`'s key schedule and of `cmov`'s `asm!` blocks; the review covered the
  paths named above, the 0.2.5/0.2.6 `inout` diff and the `zeroize_derive` macro.
- `cargo audit` (not installed); `cargo deny check advisories` uses the same RustSec database.
