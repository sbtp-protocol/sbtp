# Security review: relay archive copy to object storage (ADR 0050 stage 1)

- Branch: `feat/relay-object-mirror`, reviewed at `e7f867d`.
- Scope: `git diff main...e7f867d`, excluding `crates/sbtp-relay/examples/mirror_bench.rs` and
  `docs/benchmarks/`; the shipped code under `crates/sbtp-relay/src/` (`mirror/mod.rs`,
  `mirror/sigv4.rs`, `config.rs`, `replication/http.rs`, `replication/mod.rs`, `blocks.rs`,
  `index.rs`, `log.rs`, `lib.rs`); `Cargo.toml`, `Cargo.lock`, `crates/sbtp-relay/Cargo.toml`;
  `.github/workflows/`, `deploy/Dockerfile`, `deploy/README.md`.
- Spec: ADR 0050 with amendments U1 to U3 (accepted 2026-11-21); the relay parts of
  `docs/spec/sbtp-core-v0.2.md` and `docs/spec/architecture.md`; ADRs 0018, 0021 and 0048 where 0050
  amends them.
- Reviewed independently from the diff and the spec.

## Verdict

**Mergeable.** No blocking, high or medium finding. The archive copy is off unless
`mirror_endpoint` is set, sends only `PUT` (plus the verification `GET` of rule 9), never follows a
redirect, bounds every response, and cannot be crashed or made to grow memory by a hostile store.
The cursor logic is correct: it never passes a block that is not done, and a restart only re-sends
blocks that end as `412`. The low findings below are hardening and go to the roadmap.

## Checks run

| Check | Result |
|---|---|
| `cargo test -p sbtp-relay --features object-store --locked` | all suites pass, 0 failed |
| `cargo clippy -p sbtp-relay --all-targets --features object-store --locked -- -D warnings` | clean |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo tree -i hmac` / `-i sha2` (feature `object-store`) | `hmac 0.13.0`, `sha2 0.11.0`; no new package in `Cargo.lock` (the diff adds three dependency edges of `sbtp-relay` only) |

## Findings

Ranked by severity. None blocks the merge.

### L-1 (low): an access key identifier written in a `*_ref` setting is logged before the start-up stops

- `crates/sbtp-relay/src/lib.rs:140` (`log_settings`) runs before `:144` (`prepare_mirror`);
  `crates/sbtp-relay/src/config.rs:1051-1055` logs the `*_ref` values in the `setting` lines.
- Scenario: an operator pastes the access key identifier itself into `mirror_access_key_ref`
  instead of a variable name. AWS-style identifiers (`AKIA` followed by 16 uppercase letters and
  digits) match `^[A-Z_][A-Z0-9_]{0,63}$`, so `parse_var_name` accepts them. The `setting` line then
  logs the identifier as `value=...`, and only afterwards does `Mirror::prepare` stop the start-up
  because no such variable exists. The identifier ends up in the logs and in whatever ships them.
  The secret key and session tokens contain lowercase letters, `/` or `+`, so they fail the shape
  check and are never logged. The identifier alone does not authenticate anything, but it names the
  account and the key, so it is still worth keeping out of logs.
- Fix: resolve the credentials (`prepare_mirror`) before `log_settings`, so that a ref that names
  no variable stops the start-up before any `setting` line is written. Optionally, log a `*_ref`
  value only once the variable it names has been found. Add a test with an `AKIA...`-shaped value
  that asserts the value is in no emitted line.

### L-2 (low): copies of the credentials outlive their use, unwiped

- `crates/sbtp-relay/src/lib.rs:132` (`env.clone()`), `:145` (`drop(env_kept)`);
  `crates/sbtp-relay/src/main.rs:17` (`std::env::vars_os()`); `mirror/mod.rs:185-194`.
- Rule 22 says credentials are "zeroed on drop". `Credentials` is zeroed on drop, but other
  copies are not:
  - the start-up environment vector and its clone `env_kept` (every variable, not only the three
    credentials) are freed without being wiped;
  - the `Authorization` and `x-amz-security-token` `HeaderValue`s (`mirror/mod.rs:853-875`) are
    `Bytes` copies that are freed unwiped after each request;
  - `hmac` is built without its `zeroize` feature, so the keyed HMAC state is not wiped.

  The process environment block itself still holds the values for the life of the process. It is
  readable by the same user and by root (`/proc/<pid>/environ`), and with `unsafe_code = "forbid"`
  and edition 2024 (`remove_var` is `unsafe`) it cannot be cleared.
- Effect: the heap copies matter only to an attacker who can already read the relay's memory, and
  that attacker can read `/proc/<pid>/environ` anyway. So this is defence in depth, not an
  exposure.
- Fix:
  - Filter `env_kept` down to the three referenced names before cloning, and wipe those
    `OsString`s after use (`into_encoded_bytes()` into a `Zeroizing<Vec<u8>>`).
  - State in `deploy/README.md` that the variables stay in the process environment, and that only
    the relay user and root should be able to read `/proc/<pid>/environ`. A `*_file` variant of the
    refs (read from a file, then wiped) would remove the environment copy; that is a later ADR
    question, not this merge.
  - Mark the session-token header sensitive (`set_sensitive(true)`), as `Authorization` already is.

### L-3 (low): a held block can be skipped when the quarantine retry loop runs out

- `crates/sbtp-relay/src/blocks.rs:805-829`: after two `Quarantine::Changed` rounds `load` returns
  `Loaded::Absent`; `read_for_copy` maps it to `Copied::Absent`, and the uploader treats that as
  final (`mirror_missed_total`, done).
- Scenario: a damaged file is being replaced by a concurrent `PUT` of the same block twice in a
  row while the uploader reads it. The block is held, but it is never copied to the bucket. For
  `GET` the old behaviour (`404`, the client tries again) was harmless; for the uploader the result
  is permanent. This needs a damaged file plus a precise race, so it is very rare, but it is a
  silent gap in an archive.
- Fix: return a distinct outcome when the loop runs out (for example `Loaded::Changed`) and map it
  to `Copied::Retry` in `read_for_copy`, keeping `Fetched::Missing` for `GET`.

### L-4 (low): a store that claims success without storing leaves gaps that nothing counts

- `mirror/mod.rs:630-639` and `:650-675`.
- Scenario: a broken or hostile S3-compatible store (or a CDN in front of the public URL) answers
  `2xx` or `412` to every `PUT` without keeping the object. Every block counts as `uploaded` or
  `existing` and the cursor moves on. With `mirror_public_url` set, the check after a `412` sees a
  `403` or `404` and, per rule 9, counts nothing ("a failed fetch proves nothing"). The archive can
  then be empty while every counter looks healthy. This is consistent with ADR 0050, since the
  store is trusted to store, and the bucket is an extra copy, not the primary one. Two more things
  make it worse today:
  - the `mirror_*` counters are not exported yet (`deploy/README.md`: "once `/metrics` exists");
  - `mirror_poisoned` is only a rate-capped log event.
- Fix (implementation detail, no ADR needed):
  - Count a non-`200` answer of the verification `GET` in its own counter, for example
    `mirror_unverified_total`, kept separate from `mirror_poisoned_total`.
  - Put the `mirror_*` counters on the `stats` line until `/metrics` exists.

### I-1 (info): malformed credential bytes look like a store refusal

- `mirror/mod.rs:867-877`.
- An access key or session token holding a byte that is not valid in a header value (a pasted
  newline, for example) makes the `Request` builder fail. `put` returns
  `Put::Refused(Class::Client)`, so the relay counts `4xx` and retries hourly forever, without
  saying what is wrong.
- Fix: in `Mirror::prepare`, check that each credential is visible ASCII (`0x21..=0x7e`) and fail
  with a `ConfigError` that names the setting, without the value.

### I-2 (info): SigV4 header canonicalisation trims but does not collapse inner spaces

- `mirror/sigv4.rs` (`authorization`).
- Rule: SigV4 canonicalisation collapses sequential spaces inside a header value. Every signed
  value today is either fixed by the code or a hexadecimal, date, host or token string without
  spaces, so the canonical form is correct. A future signed header with inner spaces would get a
  `403`, not a security issue.
- Other SigV4 points checked, all correct:
  - Path encoding is single, as S3 expects.
  - `%` is refused in endpoint paths, and the prefix and bucket character sets are validated, so
    nothing can be injected or double-encoded.
  - The request URI and the canonical URI are built by the same function.
  - `host` is sent explicitly (hyper's low-level client adds none).
  - `If-None-Match` and `x-amz-security-token` are signed.
  - The scope date comes from `x-amz-date`.
  - The RFC 4231 vectors and the published S3 GET and PUT examples pass.
- Fix: collapse runs of spaces in `authorization`, or document that a signed value must not
  contain them.

### I-3 (info): the verification `GET` opens a new TLS connection for every `412`

- `mirror/mod.rs:654` (`let mut conn = None`).
- Scenario: after a restart, or when a relay that lost its data directory walks its whole history
  again against a populated bucket, every block costs a `PUT` plus a fresh TLS handshake to the
  public URL. The cost is bounded by `mirror_max_in_flight` and by the timeouts, and it is not
  memory.
- Fix: keep one verification connection per lane, as for the `PUT`.

### I-4 (info): the cursor is not saved at shutdown

- `mirror/mod.rs:349-355`.
- At stop, the walk is dropped, so progress since the last save (fewer than 64 positions, plus
  whatever finished inside the window) is sent again after the restart. Those blocks end as `412`
  and trigger the I-3 `GET`s. This is safe, because the saved cursor is never ahead of the true
  one, but it is wasted work.
- Fix: optionally save the cursor once when `stop` fires.

### I-5 (info): `peer_ca_file` replaces the operating system roots for the mirror too

- `replication/mod.rs` (`client_config`).
- An operator who sets `peer_ca_file` to a private CA for replication peers also limits the mirror
  endpoint and the public URL to that CA. The failure is closed (TLS errors, retried), so it is not
  a weakness. It could push an operator to add public roots to a file meant to be narrow.
- Fix: document it in the "Archive copy" section of `deploy/README.md`.

### I-6 (info): `replication::client_config` is now public

- It is public only for the bench example. It has no side effect beyond reading `peer_ca_file`, and
  it keeps the hardened configuration: TLS 1.3 only, `ring`, WebPKI hostname verification,
  resumption disabled, ALPN `http/1.1`. No concern.
- Fix (optional): `#[doc(hidden)]`.

### I-7 (info): the lag recount scans up to 1,000,000 index rows every 30 seconds

- `index.rs` (`count_from`).
- With a large backlog, one read transaction walks up to `LAG_CAP` rows on an index reader every
  `LAG_EVERY`. That costs CPU and holds a redb read snapshot briefly; it is not attacker-driven
  beyond normal ingest.
- Fix: none needed for the MVP; a lower cap is an option.

### I-8 (info): the AWS documentation example key pair in the tests

- `mirror/sigv4.rs` tests and `tests/mirror.rs`.
- `AKIAIOSFODNN7EXAMPLE` and its secret are the public documentation examples, not credentials.
  This is correct; just confirm that the pre-push `gitleaks git` run stays clean (its default rules
  allowlist `...EXAMPLE` keys).

## What was checked and found sound

**Credentials (rule 22)**
- They are read only from the variables named by the settings.
- Names are validated against `^[A-Z_][A-Z0-9_]{0,63}$`, and a name starting with `SBTP_RELAY_` is
  refused. The value is never repeated in an error (tested).
- A named variable that is unset or empty stops the start-up before the data directory is created
  (tested).
- `Credentials` has a redacting `Debug` and is zeroed on drop.
- The signing key derivation wipes its intermediate keys.
- `Authorization` is marked sensitive.
- The endpoint URL is logged as `set`; userinfo in a URL is refused and redacted.
- No credential reaches the metrics, the `mirror` start-up line or `mirror_failed` (status class and
  delay only).

**Outbound network**
- Hostnames are resolved per connection, and each address is checked against the private-address
  rule unless `mirror_allow_private` is set. That switch triggers a start-up warning.
- The connection goes to the address that was checked, so DNS rebinding cannot reach an unchecked
  address. IP literals are the operator's choice.
- `http` is accepted for a loopback host only, and a virtual-hosted name under a loopback endpoint
  is refused.
- No redirect is ever followed: a `3xx` is refused at the maximum back-off.
- The whole exchange is bounded by `mirror_request_timeout_ms`, DNS and TLS included.
- Response heads are bounded by hyper (16 KiB, 64 fields). Bodies are read up to 16 KiB and
  discarded; a body announced larger fails without allocating.
- The verification `GET` is bounded by `MAX_BLOCK_LEN` and rejects content codings.

**Behaviour against a hostile store**
- No status, header or body is turned into a duration (`Retry-After` is not used), so the store
  cannot cause an `Instant` overflow or a busy loop.
- `classify` covers every status: `1xx` and statuses above 599 are retried as `5xx`.
- Nothing panics on store input. Validating the bytes from the public URL goes through
  `sbtp-core`'s `full_validation`, which is panic-free and fuzzed.
- A lane that panicked stops the relay (ADR 0018 rule 37), as for replication.
- The uploader sends only `PUT`, plus the rule 9 `GET` to the public URL. Block `PUT`s carry
  `If-None-Match: *`; only `/info` is written unconditionally (rule 3).
- After a `412`, the poisoned-object check validates the public copy and only counts and logs.

**Window and cursor**
- The window is bounded at 256 slots (96 bytes each, guarded by a `size_of` test) plus one page.
  Lanes are bounded by `mirror_max_in_flight`, so the state stays bounded whatever the store
  answers.
- A failing block waits out its back-off in the window, not in a lane.
- The cursor is the lowest slot not done, or `page.next` once the window drains. Index positions
  strictly increase, even when the clock steps back. Files are written before their index entry,
  so a new block is never inserted behind the cursor and a block never appears in the index before
  its file exists.
- The cursor is saved durably at least once per 64 positions and when the window drains. A save
  that fails keeps the older, safe value.
- After a restart, only blocks that were done past the saved cursor are re-sent, and they end as
  `412`.
- No block is skipped on a failure; only `expired`, `absent` and `damaged` count as done, as
  rule 9 says (see L-3 for one exception).

**`/info` object**
- Its members are the constants and settings already public through a relay's own `/info`:
  `D_NET`, `max_future_ms`, block versions, `null` TTL, `demand_eviction: false`,
  `read_only: true`. No host, path, key or internal state.
- The `META` digest covers the target URL, the key and the body, and is stored as a `u64`.

**Configuration**
- The bucket, region and prefix character sets are validated. The prefix refuses empty, `.` and
  `..` segments.
- `mirror_*` settings given without the `object-store` feature stop the start-up unless they equal
  their defaults.
- The blocking-thread floor and the memory bound count the mirror.

**CI and image**
- The two new CI steps run `clippy` and the tests with `--features object-store` under the
  existing `permissions: contents: read`, with no secret and no `pull_request_target`.
- Every action is pinned by SHA, and the workflow's actions are unchanged.
- `deploy/Dockerfile` only adds `--features object-store` to the existing `--locked` release build.

**Supply chain**
- `hmac 0.13.0` (exact pin) and `sha2 0.11.0` were already in `Cargo.lock`, through `hkdf` and
  `ed25519-dalek`. `hmac` was reviewed in `docs/security/2026-11-20-hpke-dependency.md`.
- Both are built without default features, so this branch adds no new package.
- `zeroize` is already in the graph.
- `cargo deny check` is green.

## Not checked

- **No real S3-compatible endpoint was contacted** (as instructed). These were not verified against
  a provider:
  - SigV4 acceptance (it rests on the published examples and the fake store of `tests/mirror.rs`);
  - each provider's handling of `If-None-Match: *`: a store that ignores the header overwrites, but
    with content-addressed keys an overwrite carries the same bytes, except from a hostile writer,
    which the bucket policy of `deploy/README.md` covers on S3;
  - virtual-hosted TLS names for buckets with dots.
- **crates.io publication dates and maintainers were not rechecked online**, because no remote
  contact was allowed. I relied on `Cargo.lock` showing no new package and on the 2026-11-20
  dependency review.
- `crates/sbtp-relay/examples/mirror_bench.rs` and `docs/benchmarks/` were excluded by scope.
- No fuzzing of the uploader's response handling beyond the existing `read_bounded` and status
  tests.
- I did not run the Docker image build or `gitleaks`.
