# Security review: `sbtp-wasm` bindings (combined pass)

- Date: 2026-11-19.
- Scope: branch `feat/wasm-bindings` at `22f1d58`, read as `git diff main...feat/wasm-bindings`
  (10 files, +1,386 −7): `crates/sbtp-wasm/src/{lib,api,error,key}.rs`,
  `crates/sbtp-wasm/tests/{vectors,pow_timing}.rs`, `crates/sbtp-wasm/{Cargo.toml,README.md}`,
  workspace `Cargo.toml`, `Cargo.lock`.
- References: spec `sbtp-core-v0.2.md` §2.2, §3.2 to §3.4; ADR 0003 (rules 15, 16); `architecture.md`
  (runtimes); the roadmap (not published) Phase 3 (browsers verify only through `sbtp-wasm`; signing may use a
  non-extractable Web Crypto key); `CLAUDE.md` code conventions and supply-chain rules. The author's
  conclusions were not used.
- Method: reading of the diff; reading of the relevant upstream sources in the local registry
  (`js-sys` 0.3.107 typed-array copy helpers and feature gates, `getrandom` 0.4.3 backend selection
  and `wasm_js` backend, `wasm-bindgen` 0.2.130 `build.rs` and exported-object borrow/free runtime,
  `ed25519-dalek` 3.0.0 `SigningKey`/`ExpandedSecretKey` drop); crates.io API for the three crates;
  parsing of the release `.wasm` import, export and custom sections (small read-only Python script).
  No repository file outside this report was modified. macOS, rustc 1.100.0.

## Verdict

**Mergeable. No blocking, high or medium finding.** Four low findings, to be tracked in the roadmap;
L-1 and L-2 are cheap and are best fixed before the web client starts calling the bindings.

What holds:
- No protocol rule is reimplemented: parsing, `block_id`, PoW, signing and strict verification are
  `sbtp-core` calls. `authenticated === true` is produced only by `validate_submitted_block` and
  `validate_requested_block`, after `sbtp-core` returned `Ok`; `parseBlock` always yields `false`.
  `BlockInfo` has no constructor or setter exported to JS.
- `validateRequested` applies F1-F9, R1, C1, C2, C3 in the §3.4 order (delegated to
  `sbtp_core::validate_requested`). Error names are the `sbtp-core` `Error::name()` strings; the 82
  frozen v1 vectors replay through the binding API with the same verdict, name, `block_id` and signed
  message (`tests/vectors.rs`).
- The external-signature path is sound: `signingMessage` returns exactly `SIG_PREFIX ‖ block_id`
  (domain-separated, §3.2); `attachSignature` re-runs full C2/C3 strict verification (V1-V6) on the
  result before returning it, so a wrong-key, wrong-message or non-canonical signature is refused.
  PoW is deliberately not checked there (documented).
- Every byte argument is length-checked before it is copied into WASM memory (`block_in`,
  `exact_in`, parents ≤ 256, payload ≤ `MAX_PAYLOAD_LEN`): per-call allocation is bounded by about
  64 KiB. No `unwrap`, unchecked indexing or arithmetic on input in the crate; the only panic sites
  are js-sys length assertions, reachable only by JS code that lies about `length` (I-1), never by
  data.
- Key handling: no `Debug`/`Display`/error/log path shows the seed; `SigningKey` zeroizes on drop
  (dalek `zeroize` feature, `impl Drop for SigningKey`), and so does the per-signature
  `ExpandedSecretKey`; `generate` fails closed (`EntropyUnavailable`, no fallback, seed never used on
  failure); `exportSeed` copies straight from a `Zeroizing` buffer into a new JS array (no unwiped
  heap copy).
- Entropy: `getrandom` 0.4.3 selects the `wasm_js` backend from the feature alone
  (`src/backends.rs:172`), which calls `globalThis.crypto.getRandomValues` through a `catch` import;
  natively it uses the OS source. A wasm32 build without a backend is a compile error, so there is no
  silent weak RNG.
- No `unsafe-eval`: `js-sys` is built with no features (checked in the build fingerprint). The release
  module imports exactly: `getRandomValues`, `Uint8Array` constructor/`length`/`set`/
  `prototype.set.call`, `Error` constructor and `name` setter, and wasm-bindgen runtime shims. The
  `eval` / `Function` descriptors that appear as strings in `__wasm_bindgen_unstable` are declarations
  of the whole `js-sys` extern block (cfg'd-out items included, as for the two `getRandomValues`
  variants); they are not imported and the CLI emits no glue for them.

| Id | Severity | Subject |
|---|---|---|
| L-1 | low | JS number coercion: `difficulty` `undefined`/`NaN`/non-number silently becomes 0 (C1 disabled); `maxAttempts` `undefined` becomes 0 (endless mining loop) |
| L-2 | low | A non-`Uint8Array` argument (`undefined`, `null`) throws through WASM frames without running destructors: a `DemoSigningKey` used in that call can never be freed or wiped |
| L-3 | low | ADR 0003 rule 16 not enforced by the module: `selfTest()` is opt-in |
| L-4 | low | Seed copies on the WASM shadow stack (linear memory) are not wiped; the doc claims every intermediate copy is |
| I-1 to I-7 | info | See below |

Checks run: `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets -- -D warnings`
clean; `cargo test --workspace` 393 passed, 0 failed (`sbtp-wasm`: 14 unit, 1 vector replay, 1
ignored timing test); `cargo build -p sbtp-wasm --target wasm32-unknown-unknown --release` green;
`cargo deny check` and `cargo deny --manifest-path fuzz/Cargo.toml check`: advisories, bans,
licenses, sources ok.

## Supply chain

Verified on crates.io (API, 2026-11-19):

| Crate | Version | Published | Age | Yanked | Downloads (version) | `build.rs` | Proc macro | Features used |
|---|---|---|---|---|---|---|---|---|
| `wasm-bindgen` | 0.2.130 | 2026-10-30 | 20 days | no | 9.4 M | yes: emits cfgs (`wbg_diagnostic`, `wbg_reference_types`) and an emscripten-only link arg; no I/O, no network, no process spawn | `wasm-bindgen-macro` (already in graph via web-sys) | `default` (`std`) |
| `js-sys` | 0.3.107 | 2026-10-30 | 20 days | no | 8.7 M | none | none | none (`default-features = false`: no `std`, no `unsafe-eval`) |
| `getrandom` | 0.4.3 | 2026-06-17 | 5 months | no | 245 M | yes: msan cfg only | none | `wasm_js` (pulls `wasm-bindgen`; `js-sys` only with `target_feature = "atomics"`) |

- All three pass the two-week rule and were already in `Cargo.lock` on `main` (same versions and
  checksums; the lockfile diff only adds dependency edges). `published_by` is `null` for all three,
  consistent with trusted publishing from CI.
- `wasm_js` is a workspace-level feature on `getrandom`: it has no effect off OS-less wasm targets
  (target-gated dependencies), so the native relay, CLI and tests are unchanged.
- `serde_json` and `ed25519-dalek` are dev-dependencies only, both already in the graph.

## Findings

### L-1 (low): JS number coercion silently disables C1 or loops mining forever

- Location: `crates/sbtp-wasm/src/lib.rs:112` (`validate_submitted_js`, `difficulty: u32`), `:125`
  (`validate_requested_js`), `:198-199` (`mine_slice_js`, `difficulty`, `max_attempts`).
- Scenario: a `u32` parameter reaches WASM through the WebAssembly JS API `ToInt32` conversion; the
  release glue does no type check. `validateSubmitted(bytes)` (argument forgotten),
  `validateSubmitted(bytes, info.min_pow_difficulty)` with a misspelled or missing member, a string
  that is not numeric, `NaN`, or `2 ** 32` all yield `difficulty = 0`: C1 passes for any block, with
  `authenticated === true` and no error. Spec §3.4 requires the recipient to apply C1 with its own
  difficulty. Likewise `mineSlice(block, d)` without `maxAttempts` gives 0 attempts, so the README's
  `while (mineSlice(...) === undefined)` loop never ends. Negative numbers wrap to `2^32 − 1`, which
  fails closed (`InsufficientPow` / `DifficultyTooHigh`).
- Impact: a client with this bug accepts PoW-less blocks from a hostile relay or peer (signature still
  enforced; ADR 0029 client bounds still apply), or hangs a worker. Requires a client bug, hence low.
- Fix: take the numeric arguments as `f64` (or `JsValue`) and reject anything that is not a finite
  integer in range: `difficulty` 0 to 256 (`DifficultyTooHigh` above, `InvalidArgument` otherwise),
  `maxAttempts` ≥ 1. Add one JS-side test once a `wasm-bindgen-test` runner exists.

### L-2 (low): exceptions through WASM frames leak the key's borrow; `free()` cannot wipe it

- Location: `crates/sbtp-wasm/src/lib.rs:56-68` (`js_len`, `block_in`), `:270`
  (`DemoSigningKey::sign_block_js`); upstream `wasm-bindgen` 0.2.130 `src/rt/mod.rs:520-549`.
- Scenario: `key.signBlock(undefined)` (for example the result of a failed build passed on). wasm-bindgen
  does not type-check `&Uint8Array` parameters; `js_len` calls the `length` import, which throws a
  `TypeError` on `undefined`/`null`. wasm32 is `panic = "abort"` without exception handling, so the JS
  exception unwinds the WASM frames without running Rust destructors. For a `&self` method, wasm-bindgen
  holds an `RcRef` anchor that incremented the object's strong count; it is never dropped. A later
  `key.free()` (`allow_delayed = 0`) then sees a non-unique `Rc` and throws, and the `SigningKey` is
  never dropped, so the seed is never zeroized, contrary to the README ("wipes the key on `free()`").
  Every other entry point leaks at most its argument buffers.
- Impact: the secret outlives `free()` in linear memory. Within the documented threat model (any page
  script can read WASM memory while the key is live), the gain for an attacker is small: it only
  widens the exposure window. Low.
- Fix: take byte arguments as `&JsValue` and convert with `dyn_ref::<Uint8Array>()` (an `instanceof`
  check that cannot throw), returning a named error (`InvalidArgument`) for anything else. This also
  makes the error name stable for `undefined`/`null`, which today surface as a bare `TypeError`.

### L-3 (low): ADR 0003 rule 16 is opt-in in the WASM module

- Location: `crates/sbtp-wasm/src/lib.rs:90` (`self_test_js`), README "API".
- Scenario: rule 16 says the `S + L` vector "MUST be run by every shipped binary". The module exports
  `selfTest()` and documents calling it, but nothing forces it: a client that forgets gets a verifier
  whose rule-15 status was never checked in this build. The native vector replay covers the workspace
  feature set, and `cargo deny` bans the feature, so the practical risk is low.
- Fix: run `run_self_test()` from a `#[wasm_bindgen(start)]` function returning
  `Result<(), JsValue>`: `init()` then rejects on failure, and no export is usable on a bad build.
  Keep `selfTest()` as an explicit re-check if useful.

### L-4 (low): seed copies on the shadow stack are not wiped; documentation overstates it

- Location: `crates/sbtp-wasm/src/lib.rs:72-80` (`exact_in` returns the seed array by value),
  `:252` (`from_seed_js`), `crates/sbtp-wasm/src/key.rs:50-74` (`generate` moves the key into its
  `Rc` box, `seed()` goes through `SigningKey::to_bytes()` by value); `key.rs` module doc ("every
  intermediate copy of the seed made by this crate is a `Zeroizing` buffer").
- Scenario: values returned by value or moved (`[u8; 32]` results, `SigningKey` into the wasm-bindgen
  `Rc`) are written to the shadow stack, which lives in linear memory, and are not wiped; they persist
  until the stack region is overwritten. After `free()`, a script that dumps `memory.buffer` may still
  find seed bytes.
- Impact: same reasoning as L-2: only the window after `free()` widens. Same class as the CLI review's
  L-2 (2026-11-19).
- Fix: fill the seed in place (`exact_into(&mut Zeroizing<[u8; 32]>)` instead of returning
  `[u8; N]`); for `exportSeed`, build the JS array from `self.inner.as_bytes()` if dalek exposes a
  borrow. Moves of `SigningKey` itself cannot be fully controlled in Rust: reword the doc as best
  effort ("heap copies made by this crate are wiped; transient stack copies may remain").

## Information

- **I-1. js-sys `to_vec` trusts `length` read up to three times.** `Uint8Array::to_vec`
  (`js-sys` `src/lib.rs:15321`) sizes the `Vec` from one `length` read, then `raw_copy_to_ptr` builds
  a slice from a second read before `copy_to` asserts a third. An object with an own `length` getter
  (constructible only by JS code, never by JSON or `structuredClone`) can make it write past the
  allocation in linear memory. Not a security boundary: that code already holds `memory`. The comments
  at `lib.rs:78` and `:203` ("cannot hit its length assertion") hold only for genuine typed arrays.
  With the L-2 fix, prefer `let mut v = vec![0; len]; bytes.copy_to(&mut v)`: `set` throws
  `RangeError` on a longer source and the assertion traps on a mismatch, both fail closed.
- **I-2. Threat model in `key.rs` and the README is accurate**, with one addition worth making: a
  non-extractable Web Crypto key prevents exfiltration, not use. A script running in the page can
  still have it sign arbitrary SBTP blocks while it runs. The web client should sign only the output
  of `signingMessage` (always `SIG_PREFIX`-prefixed, so domain separation holds) and dedicate that key
  to SBTP. Key storage (IndexedDB, `CryptoKey` structured clone) is for the web-client review.
- **I-3. `BlockInfo` lives in WASM memory.** Each instance copies the payload (≤ 64 KiB) into linear
  memory until `free()` or finalization, and linear memory never shrinks. A client validating many
  blocks should call `info.free()` (or the bindings could later return plain JS objects). Also,
  `authenticated` is a convenience flag, not a capability: page code can forge objects with
  `__wrap` or by writing memory.
- **I-4. CSP for the web client:** these bindings need `'wasm-unsafe-eval'` in `script-src` (to
  compile the module) but not `'unsafe-eval'`.
- **I-5. Release profile:** `overflow-checks = true` and `strip = true` verified on the built module
  (561,433 bytes): no `name` section, the only custom section is `__wasm_bindgen_unstable` (needed by
  the CLI, removed by it). Panics trap (`panic = "abort"`); wasm-bindgen 0.2.130 exports
  `__instance_terminated`, whose behaviour after a trap was not verified.
- **I-6. Error-name list:** `BufferTooSmall` and `PowNotFound` are mapped in `error.rs:81-83` but
  unreachable from JS (`build_unsigned` allocates; `PowNotFound` becomes `undefined`). Harmless; the
  documented list is correct for what JS can observe.
- **I-7. No JS-side test.** Marshalling, the JS `Error.name`, argument coercion (L-1) and exception
  behaviour (L-2) are untested; the crate's own docs say so. Add a `wasm-bindgen-test` (Node) smoke
  test when the wasm-bindgen CLI is set up.

## Not checked

- The generated JS glue: the wasm-bindgen CLI is not installed. L-1 and L-2 rely on the WebAssembly JS
  API conversion rules (`ToInt32`, exceptions crossing WASM frames) and on reading the wasm-bindgen
  0.2.130 runtime, not on a reproduction in a JS engine.
- Behaviour in browsers and Node (FinalizationRegistry timing, `crypto.getRandomValues` availability,
  Web Crypto Ed25519 support).
- The `wasm-bindgen-macro` / `-macro-support` proc-macro code beyond the exported-object borrow and
  free paths; the crate owners list on crates.io (only version metadata was fetched).
- The web client, its key storage and CSP (Phase 3, separate review).
