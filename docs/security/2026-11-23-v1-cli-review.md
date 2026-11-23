# Security and correctness review: v1 command-line client

- Date: 2026-11-23
- Scope: `git diff a4e377d..HEAD` on branch `feat/cli-v1` (`examples/cli/`, `Cargo.toml`, `Cargo.lock`,
  `deny.toml`), against `SPEC.md` §4 to §7 and the CLI budget in `PRINCIPLES.md`.
- Threat model: a developer or operator tool that holds an unencrypted Ed25519 secret key file on disk
  and talks to relays that may be hostile, over HTTPS (rustls, webpki-roots) or plain HTTP.

## Verdict: blocking

The code is in good shape. Key handling, the hostile-relay bounds and the TLS configuration hold up,
and I found no high-severity issue. The one blocking point is about the supply chain, not the code:
three crates in `Cargo.lock` are younger than the repository's two-week minimum (M-1). It takes one
`cargo update --precise` per crate to fix, or it goes away by itself on 2026-11-26. After that fix the
branch is mergeable; the low and info findings can go to the roadmap.

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 1 |
| Low | 4 |
| Info | 8 |

Automated checks run in this worktree: `cargo fmt --all --check` clean;
`cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace` all green
(CLI: 7 tests); `cargo deny --offline check`: advisories, bans, licenses and sources ok (advisory
database dated 2026-11-23). CLI size: 290 lines (`grep -vcE '^\s*$|^\s*//'` over `examples/cli/src`),
within the 300-line budget. `slice::as_chunks` (key.rs:81) needs Rust 1.88, which is the workspace MSRV.

## Medium

### M-1: three new crates are younger than two weeks

- Files: `Cargo.lock` (entries `rustls-webpki`, `rustls-pki-types`, `webpki-roots`); the comment in
  `Cargo.toml` above `ureq`.
- Facts (crates.io, checked 2026-11-23):

  | Crate | Locked | Published | Age | Older version |
  |---|---|---|---|---|
  | rustls-webpki | 0.103.17 | 2026-11-12 | 11 days | 0.103.16, 2026-10-20 |
  | rustls-pki-types | 1.16.0 | 2026-11-10 | 13 days | 1.15.1, 2026-07-23 |
  | webpki-roots | 1.0.12 | 2026-11-10 | 13 days | 1.0.11, 2026-10-23 |

  The `Cargo.toml` comment says these are "the versions v0.2's CLI used, all in its Cargo.lock". That is
  wrong for these three: the `main` lockfile has `rustls-webpki 0.103.16` and
  `rustls-pki-types 1.15.1`, and no `webpki-roots`. `cargo deny` does not check age, so nothing caught it.
- Real risk: low. All three come from the rustls organisation (owners `ctz`, `djc`,
  `github:rustls:publishers`) and have millions of downloads. `webpki-roots 1.0.12` changes data only
  (it removes Buypass, Certigna and some DigiCert/QuoVadis roots), and `rustls-webpki 0.103.17` only
  adds accessors (SPKI, SCT). Still, this is the rule that exists to block a freshly compromised
  release, and the repository treats it as a hard rule.
- Fix (any one of these):
  1. Pin to older versions:
     `cargo update -p rustls-webpki --precise 0.103.16`, `cargo update -p rustls-pki-types --precise 1.15.1`,
     `cargo update -p webpki-roots --precise 1.0.11`. 0.103.16 still contains the RUSTSEC-2026-0382 fix
     (distrusted emSign intermediates), so nothing security-relevant is lost. `webpki-roots 1.0.11`
     brings back the roots that 1.0.12 removed; that is acceptable for a short time.
  2. Wait: pki-types and roots reach 14 days on 2026-11-24, webpki on 2026-11-26.
  3. Have the owner record an explicit exception for `webpki-roots` (data-only root removal).

  Whichever you choose, correct the `Cargo.toml` comment.

## Low

### L-1: `http://` to a non-loopback host is accepted silently

- File: `examples/cli/src/relay.rs:26-37`; the usage text in `main.rs:28` says "http:// for a local
  relay", but nothing enforces it.
- Scenario: `sbtp publish http://relay.example ...` on a hostile network. An on-path attacker cannot
  forge or alter a fetched block, because `get` checks R1 and the signature. It can, however, answer
  `201` to a `PUT` it never forwards, so the CLI prints `stored` for a block that is stored nowhere. It
  can also set `min_pow_difficulty` (see L-2), and it sees the payload and the public key in clear. The
  secret key never travels, and payloads are public by design, so the impact is limited to false
  success reports, wasted CPU and observation.
- Fix: refuse `http://` unless the host is a loopback address or `localhost`. If remote plain HTTP must
  stay possible, at least print a one-line warning on stderr.

### L-2: a hostile `/info` can make the CLI mine for many hours

- File: `relay.rs:16` (`MAX_MINED_DIFFICULTY = 32`), `main.rs:81-83` (`mine(pow, u64::MAX)`).
- Scenario: a relay answers `min_pow_difficulty: 32` and the user publishes a 64 KiB payload.
  `UnsignedBlock::block_id` re-hashes the whole block for every nonce, so the expected work is
  2^32 × 64 KiB, about 280 TB of BLAKE3. On one core that takes from many hours to about a day. The
  user sees `mining at difficulty 32` and can interrupt with Ctrl-C, so this costs CPU and is not a
  compromise.
- Fix: bound the expected work instead of the difficulty alone, for example refuse when
  `2^d × block_len` exceeds a fixed budget, or lower the cap to around 24 to 28. Note for `sbtp-core`
  (outside this scope): the hash state for the fixed part of the block could be computed once and
  reused, instead of hashing the payload again for every nonce.

### L-3: the hostile-relay claims have no tests

- File: `examples/cli/tests/cli.rs`.
- The tests cover the happy path, a `451`, one `429` with `Retry-After: 1`, a `301` and the key-file
  checks. Nothing tests the defences against a lying relay:
  - `GET` returning another valid block (R1 `BlockIdMismatch`);
  - a block with a corrupted signature (C3);
  - a `200` body over 65,909 bytes;
  - an `/info` value above 32;
  - `Retry-After` above 300 (reported without waiting);
  - `HTTPS_PROXY` or `http_proxy` set, and ignored.

  From reading the code, all of these are handled correctly today. A refactor that removed one would
  still pass the suite.
- Fix: add these cases to the existing `canned()` server; each is a few lines.

### L-4: `get --raw` writes untrusted bytes to a terminal

- File: `main.rs:96-98`.
- Scenario: a block author puts terminal escape sequences in a payload, and a user runs
  `sbtp get URL ID --raw` without redirecting stdout. The sequences reach the terminal (title change,
  screen clear; on some terminal emulators, worse). The summary mode escapes the payload correctly;
  only `--raw` is exposed. The user asked for raw bytes, hence low.
- Fix: refuse `--raw` when `std::io::stdout().is_terminal()` and suggest redirecting to a file.

## Info

- **I-1, no owner check on the key file** (`key.rs:52-59`). The mode is checked but `st_uid` is not,
  whereas OpenSSH also requires the file to be owned by the current user. This only matters when the
  CLI runs as root on another user's file.
- **I-2, partial key file on failure** (`key.rs:36-38`). If the write or `sync_all` fails (disk full),
  a partial file is left behind. A later `keygen` then refuses with "File exists", and `read` rejects
  the file, which is safe. The directory is not fsynced. A message saying "remove the partial file"
  would help.
- **I-3, stale comments.** The workspace `Cargo.toml` says "No default features: no TLS (rustls, ring,
  webpki-roots), no gzip, no JSON" while the features are `["rustls"]`, which pulls in exactly those.
  `examples/cli/Cargo.toml` lists "query" in its description, but the CLI has no query command. The
  "v0.2 versions" claim is covered in M-1.
- **I-4, retry bounds** (`relay.rs:42-73`). The worst case is five waits of 300 s, about 25 minutes, if
  a relay answers `429` with `Retry-After: 300` every time. That is bounded and visible on stderr. A
  `Retry-After` in HTTP-date form is ignored and falls back to back-off; SPEC §7 defines seconds only,
  so this conforms. `PUT` is idempotent (SPEC §5), so retrying it is safe. A `451` is not retried
  (tested).
- **I-5, proxies are ignored** (`.proxy(None)`). This is deliberate and good: no traffic is silently
  sent through a proxy taken from the environment. A user behind a mandatory proxy cannot use the CLI;
  one line in the usage text would say so.
- **I-6, transport error text on stderr** (`relay.rs:53`). `relay unreachable: {e}` prints ureq's
  error. The `http` crate rejects header values with control characters (so no ESC), and httparse
  errors are fixed strings. A TLS name-mismatch error may quote certificate names, which a CA has
  validated. The risk is negligible.
- **I-7, supply-chain notes (positive).**
  - Ages:
    - `ureq 3.5.1` and `ureq-proto 0.7.1`: 2026-11-02 (21 days; owners `algesten`, `jsha`).
    - `utf8-zero 0.8.1`: 2026-02.
    - `base64 0.23.1`: 2026-08.
    - `rustls 0.23.46`: 2026-10-14.
    - `ring 0.17.14`: 2025-03 (owner `briansmith`).
    - `untrusted 0.9.0`: 2021.
    - `getrandom 0.2.17`: 2026-01.

    All of these are at least two weeks old.
  - None of the new crates is a procedural macro.
  - `ring`'s `build.rs` compiles the bundled C and assembly through `cc`, from the pregenerated
    sources in the package. It runs `nasm` only for a Windows build from a git checkout, and downloads
    nothing.
  - `rustls`'s `build.rs` only emits a cfg on nightly.
  - TLS checked in the ureq 3.5.1 source:
    - provider: `ring`, since no TLS config provider or process default is set;
    - roots: `RootCerts::WebPki`;
    - `disable_verification` defaults to `false` and is not set;
    - versions: rustls' TLS 1.2 and 1.3.
  - Redirects: with `max_redirects(0)`, a 3xx response is returned as is and no error is raised
    (`run.rs`, `max_redirects_do_error` is false when the limit is 0). The `301` test confirms it.
  - `deny.toml`: ISC is a permissive license and fits the allow list. The CDLA-Permissive-2.0
    exception is scoped to `webpki-roots` alone, which is correct.
- **I-8, Unix only.** `key.rs` uses `std::os::unix` unconditionally, and `libc` is a `cfg(unix)`
  dependency, so `cargo build --workspace` fails on Windows. The module docs state this is intended.

## Confirmed sound (no finding)

- **Key creation:**
  - `create_new` (`O_CREAT | O_EXCL`) with mode `0600`. The umask can only narrow it.
  - Existing files and symbolic links, dangling ones included, are refused (tested).
  - The seed comes from `getrandom::fill` (the OS CSPRNG).
- **Key reading:**
  - `O_NOFOLLOW | O_NONBLOCK`, then `fstat` on the open descriptor, so there is no window between the
    check and the use.
  - A FIFO or device is rejected by `is_file` without blocking.
  - The size is bounded (257 bytes read, into a buffer of 320).
  - The content is never quoted in errors (tested).
- **Zeroization:**
  - The seed and the file text are in `Zeroizing` buffers, pre-sized so they do not reallocate.
  - `SigningKey` is `ZeroizeOnDrop` (ed25519-dalek `zeroize` feature).
  - The secret is never in argv, the environment, stdout or stderr; `keygen` prints only the public key
    (tested).
- **Response bounds:**
  - 16 KiB for `/info` and error bodies, 65,909 bytes for a block.
  - Headers: ureq's 64 KiB default.
  - A 30 s global timeout per request, which bounds a slow-drip relay.
  - An oversized `200` is an error; an oversized error body is dropped (SPEC §5: decide on the status).
- **Validation of fetched blocks:** `validate_requested(&bytes, 0, &id)` runs F1 to F9, R1, C1 with the
  client's own `d = 0`, then C2 and C3, before anything is printed. This matches SPEC §4, last bullet.
- **Output escaping:**
  - Relay error names are reduced to ASCII letters and digits, 64 at most.
  - The summary payload goes through `escape_ascii`, which escapes control characters and non-ASCII
    bytes (tested with ESC).
  - IDs and keys are printed as hex.
- **Panics on hostile input:** I found none. `mul_f64` takes a factor in [1, 2] over at most 32 s, the
  `get` calls are checked, and `Duration::from_secs(u64)` cannot overflow.

## Not checked

- Behaviour against a real public relay over HTTPS. Only the code path and the ureq source were read;
  I made no TLS connection.
- The full `rustls`, `ring` and `rustls-webpki` sources (unsafe code, C and assembly): I relied on their
  reputation, the advisory database and their build scripts.
- What actually remains in memory after drop (stack copies, the allocator). The module docs say this
  cannot be guaranteed.
- Windows and other non-macOS Unix builds. The tests ran on macOS (aarch64) only.
- Whether the exact `webpki-roots` 1.0.11 and `rustls-pki-types` 1.15.1 combination resolves. It is
  probable: `main`'s lockfile used pki-types 1.15.1 with rustls 0.23.46, and ureq requires
  `>= 1.11.0`. It was not run, because changing `Cargo.lock` is outside this review's scope.
