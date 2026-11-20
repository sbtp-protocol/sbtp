# Pre-push security review: `d336800..main` (2026-11-20)

Scope: every commit on local `main` since `d336800` (last commit on `origin/main`), 24 commits, 67
files. Code reviewed directly, not the authors' summaries. Toolchain: Rust 1.99.1 (pinned).

## Verdict

**OK to push.** No critical, high or blocking finding. One medium finding (M-1, a race that can
delete a just re-accepted block, against the MUST of ADR 0043 rule 4) is a correctness defect with
no attacker gain and no exposure; the fix is one moved line. Fix it in the next relay change, before
the sweeper runs on a relay that receives republications at volume.

| ID | Severity | Where | Summary |
|---|---|---|---|
| M-1 | medium | `crates/sbtp-relay/src/blocks.rs:296-297`, `:320-322`; `src/sweep.rs:145`, `:164-181` | Acceptance counter bumped before the index insert: the sweeper can delete a block it just saw `201` |
| L-1 | low | `crates/sbtp-relay/src/sweep.rs:181-186` | One persistent deletion failure at the head of the expiry order stops all eviction |
| L-2 | low | `.github/workflows/relay-image.yml:13-15`, `:36` | Any account with push rights can publish a `relay-v*` image from any commit |
| I-1 | info | `docs/ci.md`, "Limits and follow-ups" | States that `rust-toolchain.toml` names `stable`; it now pins `1.99.1` |
| I-2 | info | `fuzz/fuzz_targets/decode_block.rs` | The target barely explores the decoder (coverage 53 after 101 M runs) |
| I-3 | info | `Cargo.toml` (`hpke` line) | Not in `Cargo.lock` yet; the review's lock conditions apply when the first crate uses it |

## Findings

### M-1 (medium): a re-accepted block can be deleted by a concurrent sweep

**Where.** `blocks.rs:296-297` (`Settled::Reaccept`: `bump_accepted` then `index_new`) and
`blocks.rs:320-322` (`Stored::Created`: same order). The sweeper reads the counters without the lock
(`sweep.rs:145`), then lists (`:149`), then per block compares the counter under the lock
(`:166-167`).

**Why it breaks.** The module documentation (`sweep.rs:24-26`) relies on "the acceptance indexes the
block before it releases the lock", so an unchanged counter would mean the listing already reflects
every acceptance. That holds for the lock release, but the counter is incremented **before** the
insert, not after it. Interleaving:

1. `PUT` of expired block X takes the stripe lock, `bump_accepted` (stripe counter = n+1);
2. the sweeper reads the counters (n+1) and runs `expired`: the read transaction does not see the
   insert yet, so it lists X at its old, expired position;
3. the `PUT`'s insert commits X at a new position; the lock is released; the client gets `201`;
4. the sweeper takes the lock, sees n+1 = n+1, skips the `contains` re-check, and `evict_locked`
   deletes the cache entry and the file; `remove(old position)` is a no-op.

**Effect.** A `201` followed by deletion of that block before its new expiry (ADR 0043 rule 4 MUST).
The index keeps a live entry whose file is gone: `/query` lists the block, `GET` answers `404`, until
the next `PUT` of the block (which finds no file and stores it again) or its new expiry. The same
applies on the `Stored::Created` path when the old entry outlived its file (a phantom after a failed
run). The window is the duration of the index write job (a redb commit, milliseconds) and needs a
sweep to start inside it; it grows with republication volume (archive relays, ADR 0043 rule 5).

**Exploitability.** None worth the name: the only blocks at risk are expired ones, which the sweeper
would delete anyway, and the effect heals on the next `PUT`. An attacker gains nothing over what
expiry already does. The harm is a silent loss of a block an honest republisher was told was stored.

**Fix.** Increment the counter after the insert returns (whatever its result), still under the lock,
on both paths (and on the `replaced` / `Held::Expired` path at `:308-315`). Then an increment the
sweeper did not see (read at step 2) belongs to an insert that committed before the listing began,
and any later acceptance moves the counter. Add a test that bumps, lists, then inserts (or one with a
slowed writer job) to cover the interleaving; the current race test
(`reacceptance_between_listing_and_deletion_wins`) only covers an acceptance that completes entirely
after the listing.

### L-1 (low): head-of-line stall of the sweeper

`apply` stops at the first failed deletion (`sweep.rs:181-186`), by design. The failed block stays the
oldest entry, so every following run lists it first and fails on it again: eviction by age stops for
the whole relay, and the store fills up until `507`. Triggers are local only: a directory or an
unreadable entry under a final name, a missing or replaced shard directory (`check_shard`), a
permission change. No network input reaches them. `sweep_failed` is logged (throttled) and counted,
so an operator who alerts on `sweep_failures_total` sees it.

Fix (optional): on a deletion error, skip that position for the rest of the run and continue with the
others, or keep a small in-memory skip set; keep the failure log.

### L-2 (low): who can publish a release image

`relay-image.yml` runs on any `relay-v*` tag push, with `packages: write`, using the workflow file of
the tagged commit. An account with push rights (or a stolen token with `contents: write`) can tag any
commit, including one on an unmerged branch with a modified workflow, and push
`ghcr.io/sbtp-protocol/sbtp-relay:<version>`. The tag pattern check (`:64`) is correct and stops
injection through the ref name, but it does not restrict who tags or what. Deployment by digest
(`deploy/README.md`) and the provenance attestation (which names the source commit) limit the
damage. Recommended: a tag ruleset on `relay-v*` restricting creation, update and deletion to the
owner, and optionally a protected `release` environment with a required reviewer on the `image` job.

### I-1 (info): `docs/ci.md` is stale on the toolchain

"Limits and follow-ups" says `rust-toolchain.toml` names `stable` and suggests pinning; commit
`7a9f637` pinned `1.99.1`. Update the paragraph (and keep the Docker builder `rust:1.99-alpine` and
the toolchain file moving together).

### I-2 (info): `decode_block` fuzzing is shallow

A 3-minute run did 101 M executions with coverage 53 and a corpus of 3 inputs: the target rarely gets
past the first format checks. Pre-existing, not introduced by this range. Seed the corpus from
`docs/test-vectors/` (valid blocks and each rejection vector) so mutations start from well-formed
headers. `validate_l2` looked healthy (6.6 M runs, dictionary built, no crash).

### I-3 (info): `hpke` workspace line

`hpke = "=0.15.1"` with `default-features = false` is declared but used by no crate, so it is not in
`Cargo.lock` and `cargo deny` does not see it yet. The conditions of
`docs/security/2026-11-20-hpke-dependency.md` (`ctutils >= 0.4.4`, `inout` pin until 2026-11-21) must
be checked on the commit that adds the first user. Nothing to do now.

## Checked and fine

**Sweeper and re-acceptance (ADR 0013, ADR 0043).**
- Expiry bound identical in the sweeper (`expired(floor)` = `range(..floor)`), `/query` and
  `Relay::is_expired` (`at < expiry_floor`): expired at `received_at + ttl <= now` exactly; tested at
  the millisecond. `block_ttl_ms = 0` submits no job and deletes nothing.
- Deletion and re-acceptance share the per-`block_id` stripe lock; the sweeper re-checks `contains`
  when the stripe counter moved and then removes only the expired position (M-1 aside).
  `remove_entries` keeps an `ids` entry that points elsewhere; a `Created` insert removes the old
  entry, so the later removal of the old position is a no-op.
- Re-acceptance writes nothing and checks no quota (ADR 0043 rule 3), runs C2/C3 on the submitted
  bytes, and a `Created` insert replaces the old entry, so repeated re-PUTs do not grow the index.
- `Store::evict`: `symlink_metadata` then `remove_file`, so a symlink is unlinked, never followed,
  and only a regular file releases quota; `NotFound` at either step is idempotent; `release`
  saturates and never goes below the tree charge. No path is built from input other than the
  validated 32-byte id.
- Cache: `evict_locked` removes the entry before and after the unlink and bumps the evicted counter;
  `cache_loaded` drops an entry inserted by a `GET` whose load overlapped a deletion (SeqCst on both
  sides). A false drop for another block of the stripe only costs a cache miss.
- No deadlock: the sweeper and `PUT` hold a stripe lock while waiting for index jobs, and the index
  threads take no stripe lock. Supervision: a panicked run ends `sweep::run`, which `serve` turns into
  a `fatal` line and exit 70; on shutdown the sweeper is stopped and its run awaited.
  `sweep_interval_ms` has a minimum of 1000, so `tokio::time::interval` cannot get a zero period.
- `expired` now decodes the `block_id` with `get(..32)` and returns `CorruptRow` instead of panicking.

**`client_ip_header` (ADR 0044).**
- Read only under `Admission::Proxied`, which exists only for peers in `trusted_proxies`; a direct
  peer's key is fixed at accept and no header is read for it.
- With the setting on, the guard arm precedes the `X-Forwarded-For` arm, and nothing else in the
  relay reads `X-Forwarded-For` (`forwarded_client` is its only reader).
- `header_client`: exactly one field line, visible ASCII plus SP/HTAB only, trimmed, parsed by
  `IpAddr::from_str` (rejects ports, brackets, lists, zone ids, leading-zero IPv4), IPv4-mapped
  normalised before the `trusted_proxies` check. Fallback is the proxy's exact key, never a refusal
  and never a key of its own.
- Setting: token characters only, 1 to 64 bytes, lowercased, `X-Forwarded-For` and `Forwarded`
  refused at start-up; start-up warning names the header.
- Logs: the fallback warning carries only `reason=client_ip_header` and, when `log_client_tag =
  keyed`, the keyed hash of the proxy key; the integration test asserts that no header value or
  address appears in any line. Note: with the default `trusted_proxies` (loopback), any local
  process can set the header, as it can `X-Forwarded-For`; the existing loopback warning covers it.

**HTTP.** `ETag: "<hex block_id>"` is a correct strong validator (bytes per id never change);
`If-None-Match` parsing handles `*`, lists, multiple lines and `W/` with no indexing, and cannot
match a tag with a comma; `304` carries `ETag` and `Cache-Control` and no body, and is sent only
for a held block (a cache hit or a validated load). Serving an expired, not yet swept block is the
MAY of ADR 0013 rule 15. `/info` has `Cache-Control: no-store`.

**`sbtp-core` sealed inner signature.** The message layout is
`SBTP-v1-sealed-sig (18) ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519 ‖ msg`, exactly
`l2-grammar.md` §5.3; fixed length 114, tested field by field. The output slice comes from
`get_mut(..n)` with a checked length, and every `split_at_mut` / `copy_from_slice` is on a slice
whose length is exact by construction: no panic. `SealedSigMessage` has a private field and a single
constructor, so `sign_sealed` / `verify_sealed` cannot sign or verify arbitrary bytes. Verification
is V1/V2 through the existing `check_public_key`, then `verify_strict` (S < L, R decodes, R not small
order, encoded-R comparison), no batch. Domain separation: the block message is
`SBTP-v1-block-sig ‖ block_id` (49 bytes); the sealed prefix differs at byte 8 (`s` / `b`), neither is
a prefix of the other, and all five registry strings are distinct (tested). No secret handling
beyond borrowing a `SigningKey`.

**`sbtp-l2` (ADR 0039).** `check_enc_key_positions` uses iterators and enum comparisons only;
with the no-duplicate-`p` coverage rule, a root key block is exactly `tagged p:0` (+ non-causal) and
an update exactly `tagged p:0, supersedes p:1`. `sbtp.enc` row is closed (`check_row` rejects any
non-registry verb). The `EncCiphertextLen` check stays as defence in depth. No new indexing.

**CI.** Every action pinned by 40-character SHA with a version comment; workflow-level
`contents: read`, write grants only on the image job; `persist-credentials: false`; no
`pull_request_target`, no `workflow_run`, no cache; `${{ }}` appears in `run:` nowhere (refs, sha and
digest go through `env:`); tag regex anchored, version captured from `BASH_REMATCH`; digest checked
against `^sha256:[0-9a-f]{64}$` before use; image built by the runner's daemon (no BuildKit image by
tag), base images pinned by digest in `deploy/Dockerfile`; smoke test runs read-only, no capabilities,
loopback port, checks the uid. `cargo install cargo-deny --version 0.20.2 --locked`. Attestation via
`actions/attest-build-provenance` (GitHub-owned, allowed by the stated policy).

**Deploy docs.** The `client_ip_header` section states both deployment conditions and the
cross-tenant risk with a correct mitigation (per-zone Authenticated Origin Pulls verified by the
proxy, or a Tunnel). Caddy: no access log without a `log` directive; `roll_keep_for` default 2160h
(90 days); `format filter` with `delete` / `ip_mask` and the canonical header name `Cf-Connecting-Ip`
are valid. Traefik field names (`ClientAddr`, `ClientHost`, `ClientPort`, headers `defaultmode=drop`)
are correct. Pull by digest, public package, classic PAT `read:packages` with expiry only if private:
accurate.

**Toolchain and MSRV.** MSRV 1.90 everywhere, toolchain pinned 1.99.1; the MSRV-lint changes
(`is_multiple_of`, `as_chunks`) are behaviour-preserving (`split_parents` still checks the length and
the parent count before allocating).

## Commands run

- `cargo test --workspace`: pass (29 test suites including doc tests, 0 failures).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo deny check` and `cargo deny --manifest-path fuzz/Cargo.toml check`: advisories, bans,
  licenses, sources ok.
- `cargo +nightly fuzz run validate_l2 -- -max_total_time=180`: 6.6 M runs, no crash.
- `cargo +nightly fuzz run decode_block -- -max_total_time=180`: 101 M runs, no crash (see I-2).

## Not checked

- The GitHub repository and organisation settings (allowed actions, default token, approval for
  outside contributors, `protect-main`, tag rules): taken as stated, not verified.
- That each pinned action SHA is the commit of the stated tag on the official repository: the
  `gh api` lookup failed from this machine (404), so the SHAs were not re-resolved.
- The image build and push themselves (no run of `relay-image.yml`); the GHCR package visibility.
- ADRs 0040 to 0042 and `docs/spec/graph-access.md` (gateway API, MCP server): spec only, no code in
  this range; not reviewed for design-level risk.
- M-1 was established by reading the code; no test was written to reproduce the interleaving (this
  review does not modify code).
