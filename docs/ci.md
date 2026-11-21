# Continuous integration

Two GitHub Actions workflows, in `.github/workflows/`.

| Workflow | Runs on | What it does | Token permissions |
|---|---|---|---|
| `ci.yml` | push and pull request to `main` | The `CONTRIBUTING.md` checks: `fmt`, `clippy -D warnings`, tests, the `no_std` build, the wasm32 build, the frozen-vector check (job `check`); `cargo deny` on the workspace and on `fuzz/` (job `deny`); the ADR 0048 budgets (job `budgets`: relay binary, relay image, `small` memory bound, core WASM) | `contents: read` |
| `relay-image.yml` | push of a `relay-v*` tag; manual dispatch from `main` | Builds `deploy/Dockerfile` for `linux/amd64`, smoke-tests the image, checks its compressed size against the ADR 0048 budget, pushes it to `ghcr.io/sbtp-protocol/sbtp-relay`, writes the digest to the job summary, and attests its build provenance once the repository is public | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` (that job only) |

## Hardening rules

Every change to a workflow keeps these:

- **Actions pinned by full commit SHA**, with the version in a comment. Only `actions/*` and
  `docker/*` official actions; anything else is a plain shell step. To update one, resolve the tag
  on the official repository and check that the commit is on its default branch (a SHA from a fork
  is reachable through the parent repository's URL too):

  ```bash
  gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.type + " " + .object.sha'
  # type "tag" (annotated): dereference it
  gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha
  # "behind" or "identical": the commit is in the default branch's history
  gh api repos/<owner>/<repo>/compare/<default-branch>...<commit-sha> --jq .status
  ```

  The two-week rule of `CONTRIBUTING.md` applies to action releases and to `cargo-deny` too.
- **Least privilege.** The workflow-level token is `contents: read` (a private repository cannot
  be checked out with less). Write grants are given per job, and only `relay-image.yml` has them.
- **No credential left on disk:** `persist-credentials: false` on every checkout.
- **Nothing untrusted runs with privileges.** No `pull_request_target`, no `workflow_run`, no
  secret in a job that a pull request triggers. A value an outsider can choose (a branch or tag
  name, a title) never appears as `${{ ... }}` inside a `run:` script: it goes through `env:` and
  is quoted, and the tag name is checked against a strict pattern before use.
- **No cache.** Nothing one run writes is executed by a later run. This costs build time (see
  "Minutes") and closes the cache-poisoning path; revisit only with `actions/cache` keyed on
  `Cargo.lock` and written from `main` only.
- **Toolchain.** The runner's preinstalled rustup installs what `rust-toolchain.toml` names; no
  `curl | sh`. `cargo-deny` is built from crates.io with `--locked` at a pinned version
  (`CARGO_DENY_VERSION` in `ci.yml`).
- **Image build.** The runner's own Docker daemon builds the image (`docker` driver of BuildKit),
  so no BuildKit image is pulled by tag. The base images are pinned by digest in
  `deploy/Dockerfile`.
- **Timeouts and concurrency** on every job: a superseded CI run on the same pull request is
  cancelled; an image run is never cancelled half-way through a push.

## Budgets (job `budgets`)

The budgets of ADR 0048, each printed by its step before it is compared:

| Budget | Measured on | How |
|---|---|---|
| Relay binary below 8,000,000 bytes | `x86_64-unknown-linux-musl` release binary from the `export` stage of `deploy/Dockerfile` | `stat` |
| Relay image below 5,000,000 bytes compressed | the image of `deploy/Dockerfile` | `deploy/image-size.sh`: every layer of `docker save` gzip-compressed at level 6 (what a push stores) plus the configuration; also run in `relay-image.yml` before the push |
| `small` memory bound below 15,000,000 bytes (defaults) and 20,000,000 bytes (every function on) | the computed bound of ADR 0018 rule 35 | `crates/sbtp-relay/tests/startup.rs` (`small_profile_*`); a new function adds its row to `FUNCTIONS` there |
| Core WASM below 200,000 bytes gzip | `cargo build -p sbtp-wasm --target wasm32-unknown-unknown --release` | `web/wasm-budget.py`: the module without its custom sections, gzip -9 |

The WASM figure is an upper bound of what `web/build.sh` ships (`web/pkg/sbtp_wasm_bg.wasm`):
wasm-bindgen and `wasm-opt -Os` only remove code from it. Measuring the shipped file would need
the wasm-bindgen CLI and binaryen on the runner, two more toolchains to pin and verify, one of them
a prebuilt binary download; the bound needs neither. On 2026-11-21 the bound was 116,735 bytes
for a shipped 78,512 bytes (factor 1.5). If the bound ever nears the budget while the shipped file
does not, install wasm-bindgen-cli with `cargo install --locked` at the `Cargo.lock` version, as
cargo-deny is, and measure `web/build.sh` instead.

## Limits and follow-ups

- **Toolchain version.** `rust-toolchain.toml` pins an exact version (`1.99.1`), so a new Rust
  release or clippy lint never fails an unchanged commit. Raise it in one commit together with the
  builder image of `deploy/Dockerfile` (`rust:1.99-alpine`, pinned by digest), so that CI and the
  release image build with the same compiler.
- **Advisories.** `cargo deny check` fetches the RustSec database at each run, so a new advisory
  fails CI on unchanged code. That is intended.
- **Provenance.** Each pushed image gets a GitHub build provenance attestation (Sigstore,
  keyless), stored with the image in GHCR:
  `gh attestation verify oci://ghcr.io/sbtp-protocol/sbtp-relay@<digest> -R sbtp-protocol/sbtp`.
  Attestations need a public repository on the Free plan, so the step is skipped if the
  repository is ever private.
- **Later release steps** (roadmap, "Repository"): reproducible musl builds checked by a second
  build (`SOURCE_DATE_EPOCH`, byte comparison), cosign keyless signing, SLSA provenance level 3,
  a `linux/arm64` image (native arm64 runner rather than QEMU), the digest in the release notes.
- **Minutes.** Without a cache, a CI run builds the workspace and `cargo-deny` from scratch in two
  parallel jobs. Standard GitHub-hosted runners are free for public repositories; this only
  matters if the repository becomes private again.

## Organisation and repository settings

- Actions permissions: allow only actions from `actions/*` and `docker/*` (organisation or
  repository settings, Actions, General, "Allow select actions"), and require actions to be
  pinned to a full-length commit SHA.
- Workflow permissions: the default `GITHUB_TOKEN` is read-only; "Allow GitHub Actions to create
  and approve pull requests" is off.
- Pull requests from outside collaborators: require approval before workflows run.
- The `protect-main` ruleset requires the `CI` checks (`check`, `deny`) to pass before a merge.
  `budgets` (check name `budgets (binary, image, memory, wasm)`) is to be added to it once it has
  passed on `main`.
