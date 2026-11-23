# Security review: v1 CI workflows and relay container image (2026-11-23)

**Verdict: safe to run.** No finding blocks the first run. Fix M-1 (the README's verification
command) before an operator relies on provenance, and apply M-2 (protect `v1`) on GitHub before
or right after the first run.

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 2 |
| Low | 6 |
| Info | 7 |

## Scope and method

Reviewed `git diff 803fb2e..HEAD` on `feat/ci-image-v1` (commits `4e6dee1`, `3792fc4`):
`.github/workflows/ci.yml`, `.github/workflows/relay-image.yml`, `deploy/Dockerfile`,
`deploy/Dockerfile.dockerignore`, `deploy/image-size.sh`, `deploy/README.md`, checked against
`crates/sbtp-relay/src`. Read-only checks:

- Repository settings through `gh api` (rulesets, environments, Actions permissions, the GHCR
  package).
- Each action tag resolved upstream and compared with its pin. The nested `uses:` of composite
  actions.
- The base image digests resolved against Docker Hub and gcr.io.
- cargo-deny release dates on crates.io.
- redb 4.6.0 file growth, read in the local registry source.
- One local native (arm64) `docker build` of `deploy/Dockerfile`. I inspected the build context
  and the image config, then ran the image read-only without capabilities. I also tested the
  `restored` marker and `docker cp` on a stopped container. Images, volume and build cache were
  removed afterwards.

## Triggers and permissions (summary)

| Event | Workflow / job | Token grants |
|---|---|---|
| `push` to `v1`/`main`, `pull_request` to `v1`/`main` (forks included) | `CI` / `check`, `deny` | `contents: read` |
| `push` of a `relay-v*` tag | `Relay image` / `image` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` |
| `workflow_dispatch` (write access needed), job runs only on `refs/heads/v1`, `refs/heads/main` | `Relay image` / `image` | same |

- Neither workflow has `pull_request_target`, `workflow_run`, `issue_comment` or another
  trigger that runs fork code with a write token. A fork pull request gets a read-only token, no
  secrets and no OIDC token. Fork pull requests also need approval for every outside contributor
  (`approval_policy: all_external_contributors`). A fork therefore cannot reach `packages: write`,
  `id-token: write` or `attestations: write`.
- The `protect-relay-tags` ruleset is active. It restricts creation, update and deletion of
  `refs/tags/relay-v*`, and only organisation admins can bypass it. A collaborator with plain
  write access cannot start the tag path.
- Repository Actions policy: `allowed_actions: selected`, meaning GitHub-owned actions plus
  `docker/login-action@*` and `docker/build-push-action@*`. `sha_pinning_required: true`. The
  default workflow token is read-only, and Actions cannot approve pull requests. These settings
  are good.
- No environment exists (`environments: []`).

## Findings

### M-1 (medium): the documented provenance check proves the repository, not the workflow, ref or commit

`deploy/README.md:103-107` and the job summary (`relay-image.yml:195`) give:

```sh
gh attestation verify oci://ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest> -R sbtp-protocol/sbtp
```

The README then says: "It succeeds only if the image was built by this repository's workflow
from the commit it names." That is not what `-R` checks. It only checks that the signing
certificate belongs to *some* workflow run in `sbtp-protocol/sbtp`.

**Scenario.** An attacker gets a token with write access to the repository. This is the
October 2026 pattern: a stolen token or session. The attacker pushes any branch with a modified
workflow that has `packages: write` and `id-token: write`. That workflow builds a backdoored
image and pushes it to `ghcr.io/sbtp-protocol/sbtp-relay`. The package is linked to the
repository, so every workflow in it has write access. The workflow then attests the image. The
attacker can also re-point a mutable tag such as `0.2.0`. The README command passes for that
digest, and the operator deploys it "verified".

The tag ruleset and the `if:` guard do not help here. Both live in files the attacker's own
branch replaces.

**Fix** (in the README and the job summary). Pin the signer workflow, the source ref and the
source commit:

```sh
gh attestation verify oci://ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest> \
  --repo sbtp-protocol/sbtp \
  --signer-workflow sbtp-protocol/sbtp/.github/workflows/relay-image.yml \
  --source-ref refs/tags/relay-v<version> \
  --source-digest <commit sha you reviewed> \
  --deny-self-hosted-runners
```

For a dispatch build, use `--source-ref refs/heads/v1` (or `main`). Rewrite the claim to say
what is checked: signed by `relay-image.yml` running on the given ref and commit, on a
GitHub-hosted runner. Only the `--source-ref` of a protected tag (or of a protected branch,
see M-2) ties the build to a reviewed history. A tag is preferable, because creating one needs
admin rights.

### M-2 (medium): `v1` has no protection against force-push or deletion

`gh api repos/sbtp-protocol/sbtp/rulesets`: `protect-main` covers only `~DEFAULT_BRANCH`
(`main`), with `non_fast_forward` and `deletion`. Classic branch protection on `v1` returns
`404`. `v1` is where the work happens, and this diff makes it a publishing source: a dispatch
on `v1` pushes and attests an image.

**Scenario.** Force-pushed loaders were the October 2026 technique. Someone with a token that
has `contents: write` (but not admin) rewrites `v1`. The next dispatch, or the orchestrator's
next merge, then builds and attests the rewritten history. M-1's `--source-ref refs/heads/v1`
would still pass. A ruleset would stop a non-admin token. An admin token can lift any ruleset,
so admin credentials stay the root of trust.

**Fix (GitHub setting).** Add `refs/heads/v1` to `protect-main`, or create a second ruleset
with `non_fast_forward` and `deletion`, no bypass. Prefer tags over dispatch for images an
operator will run.

### L-1 (low): the required status checks on `main` no longer match the job names

The `require-ci` ruleset requires three checks:

- `fmt, clippy, test, no_std, wasm32, vectors`
- `cargo deny (workspace and fuzz)`
- `budgets (binary, image, memory, wasm)`

The new `ci.yml` names its job `fmt, clippy, test, no_std, wasm32` (`ci.yml:33`) and has no
budgets job. Once `v1` replaces `main`, no pull request into `main` can satisfy the ruleset
without an admin bypass. Repeated bypasses are a bad habit, and a bypass is also how an
unreviewed commit would land.

**Fix.** Update the ruleset to the new job names when `v1` is merged, or keep the old job
names.

### L-2 (low): an image can be published from a commit that CI did not pass

`relay-image.yml` does not depend on `CI`. A dispatch on `v1`, or a tag on any commit, builds
and pushes after only the smoke test. A commit with failing tests or a failing `cargo deny`
(for example a new RustSec advisory) can therefore become an attested image.

**Fix.** Pick one:

- run `cargo test -p sbtp-relay --locked` and `cargo deny check` in the image job before the
  push;
- or check that the commit's `CI` run succeeded (`gh api .../commits/$GITHUB_SHA/check-runs`)
  and fail otherwise;
- or keep it as a release-procedure rule: tag only a commit with green CI.

### L-3 (low): `/data` is mode 0755, not 0700 as the Dockerfile and README state

`deploy/Dockerfile:28,38-40` runs `chmod 0700 /out/data`, then
`COPY --from=build --chown=65532:65532 /out/data /data`. `COPY` of a directory copies its
*contents*, so `/data` is created with the default mode. A locally built image shows
`drwxr-xr-x 65532 65532 /data`, and a fresh named volume inherits that mode.

The impact is minimal. The relay is the only process in the container, the stored blocks are
public data, and Docker's volume root on the host is root-only. The finding is that the claim
is wrong.

**Fix.** Use `COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data`, which the
builtin BuildKit frontend supports without a `# syntax=` line. Alternatively, drop the "mode
0700" claim from the Dockerfile comment and the README.

### L-4 (low): the disk quota counts redb's file length, which grows in large steps

`store.rs:194` refuses new blocks once `metadata(relay.redb).len() >= quota`. redb 4.6.0
(`page_manager.rs` `grow`, `MAX_USABLE_REGION_SPACE` = 4 GiB, 4 KiB pages) grows the file in
large steps. It doubles the file until the first 4 GiB region, then adds a whole 4 GiB region
at a time. The apparent length therefore jumps from 4 GiB to 8 GiB in one step.

- With the README's example (`SBTP_MAX_STORE_BYTES=5368709120` on a 6 GB volume), and with the
  8 GiB default, new blocks get `507` at about 4 GiB of real data. That is less than the
  operator set.
- The extension is a sparse `set_len`, so the disk does not fill. But a backup through
  `docker cp`, `tar` or a plain `cp` can materialise the holes, giving an 8 GiB file that does
  not fit back on the 6 GB volume.
- The relay comment "filled the 8 GiB quota in 43 minutes" (`lib.rs:76`) overstates the real
  capacity by about 2x.

This is not attacker-controlled beyond what the PUT budgets already allow. I derived it from
the source, not from a fill test.

**Fix.** Pick one:

- set redb's region size (`Builder::set_region_size`, for example 64 MiB) so that the file
  grows in small steps;
- or measure used space instead of the file length.

Then confirm with a fill test. In the README, tell operators to restore with a sparse-aware
copy (`cp --sparse=always`, `tar -S`).

### L-5 (low): the container run example leaves the proxy wiring implicit

The `docker run` example (`README.md:126-130`) sets `SBTP_CLIENT_IP_HEADER=x-real-ip` but
publishes no port and joins no network. The nginx example proxies to `http://127.0.0.1:8080`.
An operator who connects the two with the usual `-p 8080:8080` exposes the plain-HTTP relay on
every host interface. Docker's published ports also bypass host firewalls such as ufw.

Any client on that interface can then set `X-Real-IP` itself and rotate through fake
addresses. That defeats the per-client rate, concurrency, subscription and PUT-byte limits.
The global caps and the quota still hold. The README says "never publish it on a public
interface" but gives no safe command.

**Fix.** Show the two safe forms:

- `-p 127.0.0.1:8080:8080` with a proxy on the host;
- a user-defined network shared with a proxy container, with no `-p`.

Also state that the published port bypasses host firewall rules.

### L-6 (low): the restore steps for a container are incomplete

The backup side (`docker cp` from the stopped container) works. I tested it, and the
`restored` marker correctly redraws `relay_id` and is removed. The README does not say how to
put data back into a volume of an image with no shell. `docker cp` *into* a container writes
files owned by root, or by the host uid with `-a`. The relay, as uid 65532, then cannot open
`relay.redb` for writing and refuses to start. This fails closed, but it will confuse an
operator under pressure.

**Fix.** Document a restore that works, for example:

```sh
docker run --rm -v sbtp-data:/data -v "$PWD/sbtp-data-backup:/b:ro" --user 0 <any image with sh> \
  sh -c 'cp -a /b/. /data/ && chown -R 65532:65532 /data && touch /data/restored'
```

You can also restore through the volume's host path, with `chown 65532:65532`.

### I-1 (info): what the `if:` guard, the tag regex and an environment actually protect

The ref guard (`relay-image.yml:36-38`) and the strict `relay-v` regex (`:66`) hold for this
file as committed. They stop an accidental dispatch from a feature branch and a malformed tag
name from reaching `tags:` and `labels:`. They do not stop a writer, who can run any workflow
file on any branch with any `permissions:`.

An environment with required reviewers is **not needed now**:

- the job uses no secret, only `GITHUB_TOKEN`;
- the only reviewer would be the same single account;
- a modified workflow on another branch would simply not reference the environment.

The controls that matter are M-1 (verification pinned to workflow, ref and commit), M-2, the
tag ruleset, and the owner account's own hygiene (hardware key, short-lived fine-grained
tokens). Add an environment with required reviewers and a tag-only deployment policy as soon
as the job needs a real secret.

### I-2 (info): action pins are correct and old enough

Each tag resolves upstream to a lightweight tag on the pinned commit, and each is the latest
release.

| Action | Pin | Tag | Released |
|---|---|---|---|
| `actions/checkout` | `3d3c42e5…90b1` | v7.0.1 | 2026-07-20 |
| `docker/build-push-action` | `c3c9e263…b0dc` | v7.4.0 | 2026-09-15 |
| `docker/login-action` | `8aa5831f…f550` | v4.8.0 | 2026-11-05 (18 days) |
| `actions/attest-build-provenance` | `4d101475…04dd8` | v4.2.2 | 2026-08-06 |

`attest-build-provenance` is a composite action. Its only nested action is
`actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1`, pinned by SHA. The other
three are `node24` actions with bundled `dist/`. `persist-credentials: false` is set on every
checkout. No `${{ }}` expression reaches a `run:` script: refs, digest, tags and visibility go
through `env`, and the tag name is validated before use. `docker/login-action` runs after the
smoke test, so the freshly built image never runs with registry credentials on the runner.

### I-3 (info): base image digests match their tags

On 2026-11-23:

- `rust:1.99-alpine`, `rust:1.99.1-alpine` and `rust:1.99.1-alpine3.24` all resolve to
  `sha256:44819b27…9383`;
- `gcr.io/distroless/static-debian12:nonroot` resolves to `sha256:afa5c872…7ab`.

Both are multi-platform index digests, as the Dockerfile says. `rust-toolchain.toml` pins
1.99.1, the same version. Nothing refreshes these pins (no Dependabot or Renovate), so plan a
manual refresh, for example per release, with the same two-week rule.

### I-4 (info): build-time downloads and their trust paths

- **Docker build.** The only network fetch beyond the two base images is crates from crates.io,
  checked against the `Cargo.lock` checksums under `--locked`. There is no `apk add`, no `curl`
  and no `# syntax=` frontend. `rust-toolchain.toml` is left out of the build context, so
  rustup downloads nothing in the build. The crate build scripts (`blake3` through `cc`) run
  inside the BuildKit sandbox, which never sees the runner's token or OIDC variables.
- **CI toolchain.** `rustup toolchain install` fetches 1.99.1 from `static.rust-lang.org` over
  TLS and checks the SHA-256 values of the channel manifest. rustup does not enforce the
  manifest's signature, so trust rests on TLS and the Rust infrastructure. This is acceptable.
- **cargo-deny.** `cargo install cargo-deny --version 0.20.2 --locked` builds a version
  published on 2026-07-09 by the usual publisher. Its dependencies come from crates.io with
  their checksums, under its own lock file. 0.21.0 and 0.22.0 are under two weeks old, so the
  pin is right. The build, and the advisory database fetched from GitHub, run in a job with a
  read-only token and no secret, and nothing is cached. A compromise there could fail or fake
  a CI result but could not reach a credential.

The build is not bit-for-bit reproducible, and nothing claims it is. Provenance is the control.

### I-5 (info): build context and image

The `Dockerfile.dockerignore` allowlist keeps only `Cargo.toml`, `Cargo.lock`, `crates/` and
`examples/`, minus `target`, `*.key`, `*.pem` and `.env*`. I confirmed it in the local build:
the build stage holds only manifests and `.rs` files, with no `.git`, docs, keys or data. Only
the static binary and `/data` reach the final image.

The image config, confirmed on the local build:

- `User 65532:65532`;
- `Entrypoint ["/usr/local/bin/sbtp-relay"]`;
- `SBTP_LISTEN=0.0.0.0:8080`, `SBTP_DATA_DIR=/data`;
- `VOLUME /data`.

Behaviour of the local build:

- `docker exec … sh` fails, so the image has no shell.
- It starts under `--read-only --cap-drop ALL --security-opt no-new-privileges` and answers
  `/sbtp/v1/info`.
- It logs the expected header warning, and logs no client IP, key or payload.
- It exits 0 on SIGTERM.

The response headers include `access-control-allow-origin: *` and `cache-control: no-store`.
That suits a public read API holding public data with no credentials.

On local builds only: an untracked key file under `crates/` or `examples/` with an unusual name
would enter the build stage and the local build cache, but not the image. A CI checkout is
clean.

### I-6 (info): the pushed image is a second build, not the smoke-tested image

`Build and push` rebuilds with labels and reuses the cached layers from the same daemon. The
binary layer is therefore the one that was tested, but the pushed manifest is not the one that
was smoke-tested. This is acceptable. An alternative is to apply the labels in the first build
and push the tested image as it is.

### I-7 (info, outside this diff): the `npm-release` environment referenced on `main` does not exist

`main` carries `release-npm.yml`. Its header says the job runs in the environment `npm-release`
"with required reviewers". The repository has no environments. GitHub creates a missing
environment *without protection rules* the first time a job references it. Create
`npm-release` with required reviewers and a `main`-only deployment policy before that workflow
is ever dispatched, or remove the workflow if v1 drops it.

## README claims checked against `crates/sbtp-relay/src`

| Claim | Result |
|---|---|
| Variables, defaults: `SBTP_LISTEN` `127.0.0.1:8080` (`main.rs:16`), `SBTP_DATA_DIR` `data`, `SBTP_MIN_POW_DIFFICULTY` 16, `SBTP_MAX_STORE_BYTES` 8 GiB, `SBTP_CLIENT_IP_HEADER`, `SBTP_LISTED_ADDRESSES` (comma-separated, ×16) | Correct (`lib.rs:84-131`). Unknown variables are ignored: correct. |
| Last entry of the header; bare address, `ip:port` or `[v6]:port`; fallback to the peer | Consistent with `http.rs:120-128` (last header value, last comma-separated entry). |
| Startup warning: header on a non-loopback listener, or no header on a loopback one | Correct (`lib.rs:183-187`), seen in the local run. |
| 8 requests in flight and 4 subscriptions per client; ping every 20 s | Correct (`REQUESTS_PER_CLIENT`, `MAX_SUBSCRIPTIONS_PER_IP`, idle timeout 60 s pinged at a third). |
| `client_max_body_size 65909` | Matches `MAX_BLOCK_LEN` (`http.rs:164-171`). |
| Deny list: reloaded within 2 s; a parse error at start stops the relay | Correct (`deny_reload`, `lib.rs:177-178`). |
| `relay.position` written after each new block; new `relay_id` on a new inode, a sidecar ahead of the store, or `restored`; the marker is deleted | Correct (`store.rs:82-125, 211-215`), and the marker was tested on the local image. |
| Quota: `507` for new blocks, existing blocks still served, no eviction | Correct in behaviour (`store.rs:194`, `http.rs:212`). Capacity is lower than set, see L-4. |
| `/data` mode 0700 | Wrong, see L-3. |
| Restore in a container | Incomplete, see L-6. |
| `gh attestation verify … -R` "succeeds only if built by this repository's workflow from the commit it names" | Overstated, see M-1. |

## Not checked

- **An actual GitHub run**, which I was asked not to start. Two things stay unchecked:
  - whether `build-push-action` with the runner's default `docker` driver exposes a `digest`
    output, and on which manifest. The runner's Docker version decides between the classic and
    the containerd image store;
  - whether `gh attestation verify` passes end to end on that digest.

  Earlier v0.2 runs did push attestations to this package (`sha256-…` referrer tags), which
  suggests the path works.
- **The linux/amd64 build.** I built natively on arm64 only.
- The contents of each action's bundled `dist/` and of cargo-deny's dependency tree (beyond
  pins, dates and publisher).
- **A fill test** to confirm L-4's growth steps on a real volume.
- The organisation-level settings beyond Actions permissions, and the owner account's 2FA and
  token inventory.

## Cleanup

During this review I created a local image (`sbtp-audit-relay:local`, plus a build-stage tag),
pulled `alpine:3`, and created a container, a volume `sbtp-audit-data` and a scratch backup
copy. I removed all of them. I pruned the build cache, 24 entries, all created by this build:
1.78 GB freed. I ran no cargo build in the worktree, so there is no `target/` to clean.
