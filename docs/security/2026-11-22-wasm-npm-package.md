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
