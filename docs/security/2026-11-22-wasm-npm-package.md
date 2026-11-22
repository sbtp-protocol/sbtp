# Security review: npm package `@sbtp/wasm` (branch `feat/wasm-npm-package`)

- Date: 2026-11-22
- Scope: `git diff main...feat/wasm-npm-package` (20 files, about 1,100 lines): `crates/sbtp-wasm/npm/`
  (manifest, README, `node.js`, `build.sh`, `check.sh`, `tools.mjs`, `smoke.sh`, `smoke.mjs`),
  `SigningMessage` (`crates/sbtp-wasm/src/message.rs`, `seal.rs`, `lib.rs`), web client
  `signingMessageBytes`, CI job `npm-package`, draft workflow `release-npm.yml`.
- Against: ADR 0053 rules 26 to 45, ADR 0055 E1.
- Verdict: **mergeable**. No blocking finding and no high finding. M-1 concerns the disabled release
  draft and must be resolved before publication is enabled.

## Findings

### M-1 (medium, before enabling the release): rule 37 is enforced by a file the tagged commit controls

- Where: `.github/workflows/release-npm.yml`, step "Tag, version and main"
  (`git merge-base --is-ancestor "$GITHUB_SHA" origin/main`).
- Scenario: with the `push: tags` trigger enabled, the workflow that runs is the copy in the tagged
  commit. Someone with tag-push rights (a maintainer, or a stolen token with `contents: write`) tags a
  side commit whose `release-npm.yml` drops the check. The environment's deployment policy
  ("tags `wasm-v*`") accepts the tag. npm trusted publishing matches the workflow file name and the
  environment, not the branch. Only the required reviewer stands between that commit and a published
  version with valid provenance.
- Fix (choose one):
  - (a) Publish from `main` itself: `workflow_dispatch` on `main` with the version as input,
    environment `npm-release` restricted to the branch `main`, and the tag created or checked by the
    workflow. The workflow file is then always the reviewed one on `main`.
  - (b) Keep tags, but state in the workflow header that the check only guards against mistakes.
    Make the reviewer's approval explicitly include "commit is on `main`", and keep the consumer-side
    commit check of rule 38.

### L-1 (low): the contents check and npm read different archives

- Where: `crates/sbtp-wasm/npm/check.sh:35-44` (`tar -tzf`, `tar -tvzf`).
- Scenario (tested): a tarball with the 8 expected entries, then one zero block, then an entry
  `package/hidden.js`. `check.sh` passes: bsdtar, and probably GNU tar, stops at the lone zero block.
  `npm install --offline` of that file extracts `hidden.js` (node-tar continues). A second gzip
  member holding a second archive was not extracted by npm. Today the checked tarball is the one
  `npm pack` wrote in the same job, so this only matters if the check is relied on against a hostile
  tarball.
- Fix: walk the archive in `tools.mjs` with Node's `zlib`, the way node-tar does. Accept only ustar
  regular-file headers whose names are on the expected list, each exactly once. Require every byte
  after the first zero block to be zero, and reject a multi-member gzip stream.

### L-2 (low): the manifest and copied-file checks are deny-lists

- Where: `crates/sbtp-wasm/npm/tools.mjs:85-108`; the path scan in `check.sh:53-65`.
- Scenario (tested, each passed `check.sh`):
  - `directories.bin` set to `"."` (npm can turn it into `bin` at publish time);
  - `publishConfig` with another `registry` and `tag`;
  - `exports["."].node`, `main` and `browser` redirected;
  - `os`, `workspaces`, `overrides`, `imports` and `engines` changed;
  - a `node.js` that imports `node:child_process` and runs a command on import.

  Rule 35 is met (file list, no install script), but any key or code the check does not name gets
  through. Size is only bounded for the `.wasm`.
- Fix: `package.json`, `node.js`, `README.md` and both licences are copied verbatim, so compare them
  byte-for-byte (`cmp`) with the repository copies. If the manifest may later be rewritten, use an
  exact allow-list of top-level keys and deep-equality on `exports`, `publishConfig`, `engines` and
  `sideEffects`. Bound the tarball's total size. The glue `sbtp_wasm.js` stays checked by the
  reproducible build (rebuild and compare).

### L-3 (low): `SigningMessage` is an API shape, not a capability; the rustdoc overstates it

- Where: `crates/sbtp-wasm/src/message.rs:1-8` and `:36-38`; `crates/sbtp-wasm/README.md`
  ("Signing messages"); `crates/sbtp-wasm/npm/smoke.mjs:79-80`.
- Scenario (tested in Node on the built package):
  - `new SigningMessage()` and `Object.create(SigningMessage.prototype)` pass `instanceof`. Reading
    `bytes` then throws "null pointer passed to rust", so no bytes come out.
  - `SigningMessage.__wrap(ptr)`, the static glue method that the smoke test explicitly allows, wraps
    any pointer. `__wrap(l2Payload.__wbg_ptr).bytes` returned the payload's kind string, and the object
    passed `instanceof`.
  - `init()` returns the module's `memory`. Overwriting a real message's bytes in it made `bytes`
    return 49 `A` characters, with `kind` still `"block"`.

  E1 is met: no function offered by the package passes caller bytes to a signer. But "a signer that
  checks `instanceof` never signs bytes its caller chose" holds only against misuse, not against code
  running in the same realm (which can also call the signer on the key handle directly, as the README
  says).
- Fix: reword the rustdoc and README to "against API misuse; code in the same realm can forge one".
  Recommend that signers also check the shape of the bytes: kind `"block"` means exactly 49 bytes
  starting with `SBTP-v1-block-sig`; kind `"sealed"` means at least 114 bytes starting with
  `SBTP-v1-sealed-sig`.

### I-1 (info): `SigningMessage.bytes` leaves an unwiped copy in the WASM heap

- Where: `message.rs` `bytes()` (`self.bytes.to_vec()`).
- Measured: the occurrences in linear memory of a marker inside a sealed `msg` went 2 → 3 on
  `pending.message`, 3 → 4 on `.bytes`, and 4 → 3 on `free()`. The `Zeroizing` copy is wiped. The
  temporary `Vec` that `bytes()` hands to the glue is freed without being wiped. The README's "freed
  heap buffers (best effort)" covers this; the rustdoc of `SigningMessage` suggests only the JS copies
  remain.
- Fix: return `js_sys::Uint8Array::from(&self.bytes[..])`, which copies straight to JS with no
  temporary heap buffer, or state the residue in the rustdoc.

### I-2 (info): build isolation and the reproducibility claim

- Verified: two builds of `ed41b87` from different paths on one machine, one path containing a space,
  gave the same SHA-256 (`e118b475…c7c664`) and the same integrity string. A cross-OS rebuild (macOS
  against the Linux CI) was not verified.
- Not controlled by `build.sh:39-75`:
  - `RUSTC_WRAPPER` and `build.rustc-wrapper`;
  - `.cargo/config.toml` in parent directories or in `CARGO_HOME`;
  - the reused `target/npm/cargo`;
  - ignored files, which `git status --porcelain` omits.

  A `--allow-dirty` build gets the same tarball name as a clean one. CI uses a fresh runner, so this
  concerns workstation builds and the "build of one commit" wording.
- Fix:
  - `unset RUSTC_WRAPPER` and set `CARGO_BUILD_RUSTC_WRAPPER=`;
  - fail if a `.cargo/config*` exists above `$root`;
  - name dirty tarballs `sbtp-wasm-<version>-dirty.tgz`;
  - publish the expected `.wasm` SHA-256 with each release (Q-79).

### I-3 (info): release workflow details

- `run: sh …/smoke.sh "dist-npm/${{ steps.build.outputs.tarball }}"` interpolates a step output
  into the script. It cannot be injected (the name is checked by `build.sh` against a semver version),
  but pass it through `env:` as the publish job does.
- `tarball="$(cd dist-npm && ls sbtp-wasm-*.tgz)"` assumes exactly one file: fail if not.
- Add `--registry https://registry.npmjs.org/` to `npm publish`, so the manifest's `publishConfig`
  cannot redirect it.
- The rest holds:
  - workflow permissions `{}` at the top, `contents: read` for the build job, `id-token: write` in
    the publish job only;
  - no checkout in the publish job;
  - the artifact's SHA-256 re-checked with `sha256sum --check --strict`;
  - `--provenance --ignore-scripts`.

### I-4 (info): web client signing path

- `web/src/keys.js:28` and `:76` are the only calls to `crypto.subtle.sign`. Both sign
  `signingMessageBytes(block)`, which builds the message in WASM from the block and frees the
  `SigningMessage`; no caller bytes reach the signer. The web client has no sealed signing path yet.
- When it adopts `sealPrepare`, add one helper that takes a `SealPending` and checks
  `message.kind === "sealed"` and the prefix and length, as in L-3. No generic `sign(bytes)` helper
  should exist.

### I-5 (info): `wasm-bindgen-cli` is built from crates.io in CI

- Where: the `npm-package` job of `ci.yml`; the `build` job of `release-npm.yml`.
- `cargo install --locked` pins the tool's dependency tree and cargo checks the registry checksums.
  But the tool's build scripts and proc macros run on the runner, it writes the shipped glue, and
  `cargo deny` of this workspace does not cover it. This is the same pattern as cargo-deny, and there
  is no secret in that job.
- Optional: compare the glue against a rebuild elsewhere (I-2).

### I-6 (info): shell pipelines without `pipefail`

- `build.sh` and `check.sh` are POSIX `sh` (dash in CI) without `pipefail`. Each pipeline fails safe
  through a later comparison, with two exceptions:
  - the per-file path scan (`check.sh:57`): a failing `tar -xO` yields no hits and the file passes;
  - the budget (`check.sh:67-69`): a failing extraction counts 0 bytes.

  The file-list check runs first and makes both unreachable in practice.
- Fix: extract each file once to a variable or a temporary file and test the extraction's exit status.

## What was checked and holds

- **Manifest:**
  - no `scripts`, dependencies or `bin`;
  - `exports` has `types` first, then `node` → `node.js`, then `default` → `sbtp_wasm.js`;
  - `sideEffects` is `["./node.js"]`;
  - `publishConfig` has `access: public` and `provenance: true`;
  - the packed `package.json`, `node.js` and `README.md` are byte-identical to the repository copies.
- **Tarball:**
  - exactly 8 regular files, mode 0644, uid and gid 0, fixed timestamps;
  - no user name, host name or absolute path. Registry paths are remapped to
    `registry/index.crates.io-<standard hash>/…` and the toolchain paths are `/rustc/<hash>/…`;
  - the `.wasm` has no custom section after `wasm-opt` (no name, producers or target_features);
  - the glue has no URL and only the standard `fetch` of the module.
- **`node.js`:** reads `new URL("./sbtp_wasm_bg.wasm", import.meta.url)`, which is the package's own
  directory and takes no input, and instantiates synchronously before re-exporting.
- **`build.sh`:**
  - refuses a dirty tree;
  - checks the versions of rustc, the wasm-bindgen CLI against `Cargo.lock`, wasm-opt, node and npm;
  - checks the module's feature set;
  - runs `npm pack` with scripts disabled and empty user and global npm configuration;
  - cross-checks the integrity string npm reports;
  - downloads nothing.
- **Path remapping:** `CARGO_ENCODED_RUSTFLAGS` keeps paths with spaces intact. A remap that misses
  fails safe through the path scan.
- **CI job `npm-package`:**
  - `contents: read`, `persist-credentials: false`, `pull_request` (not `pull_request_target`), no
    secret, no new action;
  - Node.js and binaryen are fetched over HTTPS only, then checked with `sha256sum --check --strict`
    under `set -euo pipefail`. An empty or wrong pin fails.
- **Release draft:**
  - no automatic trigger;
  - both jobs are guarded by `vars.NPM_PUBLISH_ENABLED == 'true'` and a `wasm-v*` tag ref;
  - a fork or a pull request cannot reach the publish job. There is no PR trigger, a fork PR that
    adds one gets no `id-token: write`, and the environment policy and the trusted-publisher
    environment block refs outside the environment;
  - an untagged dispatch skips both jobs.
- **`SigningMessage`:**
  - no constructor, factory or `From` impl (a crate-private `new`);
  - the `.d.ts` has a `private constructor` plus a `unique symbol` brand kept out of the exports by
    `export {}`, so a `Uint8Array` or an object literal does not type-check;
  - `Debug` shows only the kind and the length (tested);
  - the held copy is `Zeroizing` and is wiped on `free()` (measured).
- **Tests run:**
  - `build.sh`, with its `check.sh`, passed;
  - `smoke.sh` passed;
  - `node --test web/tests/*.test.mjs`: 71 passed, 1 skipped;
  - `cargo test --workspace`: all passed except one relay test that ran while the disk was full
    (the relay is not touched by this branch).

## Not checked

- The pinned SHA-256 values of the Node.js and binaryen archives, and the two new action SHAs (no
  network access).
- A Linux build compared with the macOS build.
- How GNU tar handles the lone-zero-block archive.
- Whether npm turns `directories.bin` into `bin` at publish time.
- The `.d.ts` brand under `tsc` (no compiler available). Checked afterwards by the client library
  repository with TypeScript 6.0.3 in strict mode: the brand rejects a plain `Uint8Array` and a
  structural look-alike as intended. That check also found that `sbtp_wasm.d.ts` needs the DOM lib
  (`RequestInfo`, `BufferSource`, the `WebAssembly` namespace in the `init` types) to compile.
- `cargo deny check` (advisory fetch failed), `cargo clippy` and `gitleaks dir` (not run: disk full).

## Re-review (2026-11-22)

- Scope: `git diff f7152f0..b118bc3` (7 commits), against the findings above, ADR 0053 and ADR 0055 E1.
- Verdict: **mergeable**. Every finding in scope is closed. The fixes add no finding above low.

### Status of the findings

| Finding | Status | Evidence |
|---|---|---|
| M-1 | Closed | `release-npm.yml` has only a `workflow_dispatch` trigger. Every job checks `github.ref == 'refs/heads/main'`. `publish` runs in the `npm-release` environment, which owner setup step 3 restricts to `main`. The tag is checked in `build` and created in `tag` on `GITHUB_SHA`. `release-workflow.test.mjs` fixes all of this. |
| L-1 | Closed | `check.sh` no longer uses `tar(1)`; it reads the archive through `tools.mjs readPackage` only. That walker accepts one gzip member with `FLG = 0`, a valid CRC-32 and ISIZE, and nothing after it. It then accepts only ustar type `0` headers with a valid checksum and mode 0644, whose names are on the exact list, each once. Every byte after the first zero block must be zero. The original lone-zero-block case is tested and refused. |
| L-2 | Closed | `package.json`, `node.js`, `README.md` and both licences are compared with `cmp` against the repository copies. The tarball is bounded at 300,000 bytes and the unpacked files at 1,000,000. `tamper.test.mjs` replays every tampering from L-2, including whitespace-only manifest changes: 17 of 17 are refused. |
| L-3 | Closed | The rustdoc of `message.rs`, the crate README and the npm README now say "against API misuse, not against code in the same JavaScript realm", and give the shape checks. `smoke.mjs` signs only after checking kind, length and prefix, and asserts that an `Object.create` forgery is refused. |
| I-1 | Closed | `bytes()` returns `js_sys::Uint8Array::from(&self.bytes[..])`: a view on the held bytes is copied into a new JS array, with no temporary `Vec`. `smoke.mjs` checks that reading `bytes` adds no copy of `msg` to linear memory, and that test passed. |
| I-2 | Mostly closed | `build.sh` clears `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTC` and the `CARGO_BUILD_*` forms. It refuses any `.cargo/config*` above the checkout or in `CARGO_HOME`, and names a dirty build `-dirty.tgz` (`check.sh` accepts both names; `release-npm.yml` requires the clean one). Still open, info only: ignored files are not detected (`git status --porcelain` omits them); `target/npm/cargo` is reused; other `CARGO_*` environment variables (for example `CARGO_PROFILE_RELEASE_*`) still apply. The rebuild-and-compare check of Q-79 covers all three. |
| I-3 | Closed | The tarball name reaches `smoke.sh` through `env:`, and the build fails unless there is exactly one `sbtp-wasm-$VERSION.tgz`. `npm publish` names `--registry https://registry.npmjs.org/`. A test asserts that no `${{ }}` expression appears inside a `run:` script. |

The other findings were outside this re-review. I-4 and I-5 are unchanged. I-6 is partly reduced: `cmp` fails safe on an empty extraction. The per-file path scan still passes on a failed `tar-cat`, but `tar-list` has already validated the same file, so that case cannot occur in practice.

### New code checked

**Release workflow, `tag` job (`contents: write`).**

- It runs no checkout and no third-party action. It makes one `gh api` POST of `refs/tags/$TAG` on `GITHUB_SHA`.
- `TAG` comes from the `build` output, which is `wasm-v` followed by a version that matched `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$` and equals `package.json`. The input reaches the shell only through `env:`.
- `tag` needs `publish`. If `publish` is skipped or rejected, no tag is created.

**A dispatch from another ref.**

- A dispatch on a branch other than `main` runs that branch's copy of the workflow, so its `if:` guards can be removed. `publish` is still stopped by the environment's deployment branch policy, and the npm trusted publisher requires the environment name. A dispatch on a tag ref is stopped the same way (no tag pattern in the policy).
- That branch copy can declare a `contents: write` job, but anyone who can push a branch can already do so in any workflow. The `tag` job adds no capability.
- What protects publication is therefore owner setup step 3, not the `if:` guards. The workflow header says so.

**New finding N-1 (low, before enabling the release): the tag ruleset of step 4 blocks update and deletion, not creation.**

- Scenario: someone with write access, or a stolen token with `contents: write`, creates `wasm-v<next>` on another commit before the release.
- Effect: the release `build` job fails ("tag exists on X, not on GITHUB_SHA"). This is a detectable denial of service. Nothing wrong is published, because provenance names the real commit and `refs/heads/main`.
- Consumers who follow the npm README compare the provenance commit with the tag, so a pre-created tag makes them see a mismatch and refuse the version. That is the intended outcome.
- Fix (optional): in step 4, also restrict creation of `wasm-v*`, with GitHub Actions as the only bypass actor. Or accept the risk, since the failure is loud.

**Tar and gzip walker (`tools.mjs readPackage`).**

- Crash and resource use:
  - Every failure is a thrown `Error`. `main` catches it and exits 1, so `check.sh` fails closed.
  - Decompressed output is capped at 2,000,000 bytes (`maxOutputLength`), so a gzip bomb stops (tested).
  - The stream must be whole 512-byte blocks, every read is bounds-checked (`start + size` and `end + 8`), and each iteration advances by at least 512 bytes. There is no infinite loop or out-of-range read.
- Parsing bypasses:
  - Base-256 sizes and non-octal or space-padded fields are refused.
  - PAX (`x`, `g`), GNU (`L`, `K`), link, directory and old-style `\0` type headers are refused.
  - The GNU `ustar  \0` magic is refused.
- Parity with node-tar:
  - node-tar reads the ustar prefix over 155 or 130 bytes, depending on byte 475. Both stop at the first NUL, so for any name this walker accepts, the two give the same path.
  - Names must match `package/<file>` exactly, so no normalisation difference (`./`, `//`, a different first component that `strip: 1` would hide) gets through.
- No bypass found. The walker is stricter than node-tar everywhere, so a future `npm pack` that writes PAX headers (long names) would fail the check. That is the safe direction.

**`.d.ts` alias trick and the `SigningMessage` brand.**

Read on the shipped `sbtp_wasm.d.ts` of the rebuilt tarball (no `tsc`).

- The aliases are seven non-exported `type` declarations. Each is a conditional on `typeof globalThis`, or a structural ES-lib type. They are used only in `InitInput`, `SyncInitInput`, `InitOutput.memory` and `InitOutput.__wbindgen_externrefs`, and none of them refers to `SigningMessage`.
- The brand is unchanged:
  - `declare const signingMessageBrand: unique symbol`;
  - an `interface SigningMessage` with `readonly [signingMessageBrand]: true`, merged with `export class SigningMessage { private constructor(); ... }`;
  - `export {}`, which keeps the symbol and the aliases out of the module's exports.
- The aliases cannot weaken the brand. They widen or narrow only the `init` input types: `never` when a global is absent, and the global's own instance type (or `any`-derived) when present.
- The real gain is that a consumer without the DOM lib no longer needs `skipLibCheck`, which would hide every other error of the file.
- `dtsFix` requires each wasm-bindgen line to occur exactly once, so a wasm-bindgen upgrade fails the build instead of silently shipping DOM names again.

**N-2 (info).** `dtsCheck` counts the brand parts in the raw text, comments included. A brand that survived only inside a comment would pass. The input is the pinned wasm-bindgen output, not attacker input, so this only guards against regressions. The fix is optional: count on the comment-stripped `code`.

**N-3 (info, disk hygiene).** `build.sh` writes `$root/target/npm/` (about 160 MB here) and ignores `CARGO_TARGET_DIR`, so each worktree that builds the package gets its own `target/`. The fix is optional: base `stage` and `cargo_target` on `${CARGO_TARGET_DIR:-$root/target}/npm`, as `web/build.sh` now does.

**`web/build.sh`.** It uses the same `--remap-path-prefix` pair as `build.sh`, its own target directory under `CARGO_TARGET_DIR`, and a final scan that fails if `$HOME`, the checkout or `CARGO_HOME` appears in `web/pkg`. There is no security concern.

### Tests run

- `node --test crates/sbtp-wasm/npm/*.test.mjs`: 20 passed, 17 skipped (no tarball given), 0 failed.
- `build.sh` on `b118bc3`: the contents check passed. The tarball is 146,765 bytes (340,340 unpacked) and the module is 122,348 bytes gzip -9. SHA-256 `b909a024f73a74459ea83c3536694af997f6c92c2abf3fd62527a3e7e652cd7a`.
- `tamper.test.mjs` with that tarball: 17 passed, 0 failed.
- `smoke.sh` with that tarball: passed. This includes the forged-object refusal and the I-1 heap-copy check.

### Not checked

- The `.d.ts` under `tsc`, with and without the DOM lib, and with `@types/node` (no compiler available). The reading above is a code review only.
- The release workflow on GitHub: whether the environment policy rejects a non-`main` dispatch as described, whether `gh api` with the job token can create a tag under the planned ruleset, and the pinned SHAs (no network access).
- That node-tar's current header parser matches the behaviour described above (read from memory of its source, not from the vendored version).
- `cargo deny`, `cargo clippy` and `cargo test --workspace`: the Rust changes are limited to `message.rs`, and the build and the smoke test exercise it.
