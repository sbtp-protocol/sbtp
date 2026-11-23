# Security and correctness review: SBTP v1 core, relay, fuzz target and dependencies

- Date: 2026-11-23. Reviewer: security auditor (independent; read the diff and `SPEC.md`/`PRINCIPLES.md`,
  not the authors' conclusions).
- Scope: branch `v1` at `2de0f13`, the whole code diff `bd0c4a5..2de0f13`: `crates/sbtp-core`,
  `crates/sbtp-relay`, `fuzz/`, `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock`, `deny.toml`,
  `rust-toolchain.toml`.
- Threat model: a public relay behind a TLS reverse proxy, reachable by anonymous clients; clients that
  rely on `sbtp-core` to verify blocks fetched from untrusted relays. The relay is an MVP demonstrator,
  findings are ranked by what an anonymous attacker can actually do to a publicly reachable relay.

## Verdict

**Blocking before the first public relay: H-1.** Everything else is mergeable; M-1 to M-5 should be fixed
before a relay is exposed (each is a small change in the relay code, none needs a spec change).

`sbtp-core` has no finding above info: the decoder is panic-free and bounds-checked, the validation order
is the spec's, and the strict Ed25519 path maps one to one to V1–V6.

| Severity | Count |
|---|---|
| High | 1 |
| Medium | 5 |
| Low | 7 |
| Info | 8 |

## Checks run

| Check | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | 53 passed, 1 ignored (benchmark) |
| `cargo build -p sbtp-core --no-default-features` | builds (`no_std`) |
| `cargo deny --offline check` (advisory DB updated 2026-11-23 10:36) | advisories, bans, licenses, sources ok |
| `cargo deny --offline --manifest-path fuzz/Cargo.toml check` | ok |
| `cargo +nightly fuzz run decode_block` (120 s, dictionary, default `max_len`) | 2.66 M runs, no crash, no oracle failure |
| `Cargo.lock` against `legacy/v0.2:Cargo.lock` | every crate identical (name, version, checksum) except 4 new ones, see I-4 |
| `redb 4.6.0` checksum | `096b1dd5ec053c9c2a5a26a93aafeadf73ebcb710ea54dc3151f17a8e20535ef`, equal to the approved exception |
| Scratch probes (outside the repository, against the relay library; see H-1 and L-1) | results quoted in the findings |

## High

### H-1. Denied blocks are skipped without bound: `/info`, `/query` and `/subscribe` cost grows with every denied run

- Location: `crates/sbtp-relay/src/store.rs:163-173` (`last_served`), `store.rs:206-224` (`page`, the
  `if page.items.len() >= limit ...` branch and the `else if !denied` branch); callers
  `http.rs:285-291` (`/query`), `http.rs:307` (`/info`), `subscribe.rs:116-123` (catch-up).
- Scenario: the deny list is the operator's answer to spam, so a long run of denied blocks is the
  expected state after an abuse wave. `page()` only counts *listed* blocks against `limit` and
  `max_bytes`; a denied entry is examined, its full value (id and up to 65,909 block bytes) read to check
  the key, and the scan continues. `last_served()` walks back from the tail across every denied block.
  Neither has a bound on entries examined.
  1. Attacker publishes N blocks under key K (or the operator denies an ordinary spammer's key).
  2. Operator denies `key K`.
  3. Any client: `GET /sbtp/v1/query?since=<just before the run>&limit=1`, or `GET /sbtp/v1/info` while
     the run is at the tail, or `/subscribe?since=0`. Each request scans the whole run in one blocking
     task, holding a redb read transaction.
- Measured (scratch probe, release build, Apple Silicon, warm page cache): 3,000 denied 60 KB blocks
  (180 MB): `/info` 0.9 ms → 57 ms, `/query?since=0&limit=1` 0.9 ms → 27 ms, about 26 ms of CPU per
  `/info`. Linear in N: the 8 GiB default quota holds about 130,000 maximum-size blocks, that is about
  2.5 s of CPU and 8 GB read per request. At the default 50 requests/s per client address, one client
  keeps dozens of cores busy and the 512-thread blocking pool, shared with `PUT` and `GET`, saturates:
  the relay stops serving everyone. The operator's only remedy (denying more) makes it worse, and the
  spec forbids eviction.
- Fix: bound the work per request by entries *examined*, not entries listed. `page()` stops after, say,
  `4 × limit` (or a fixed 4,096) examined entries and returns `since` = last examined with `more = true`
  (the spec already allows a page that advances `since` with few or no ids; `more = true` with an empty
  page is fine as long as `since` moved). `last_served()` needs either a bound plus a cached value
  recomputed on deny-list reload and on each store, or a stored "last served" counter updated in
  `put` and on reload. Also see M-1: the deny check should not have to read block bytes at all.
  Add a test with a denied run longer than the bound.

## Medium

### M-1. `/query` and every deny check read full block bytes to list 32-byte ids

- Location: `store.rs:16` (`LOG` value is `block_id ‖ block`), `store.rs:206-209`, `limits.rs:147-154`.
- Scenario: to list ids, `/query` iterates `LOG` and reads each value, because the deny check needs the
  public key at bytes 19..51. `GET /sbtp/v1/query?since=0&limit=1000` over 1,000 large blocks reads
  about 66 MB to return about 90 KB. Measured: 18.8 ms per request (0.9 ms for `limit=1`). At 50
  requests/s one client address costs about one core and 3 GB/s of store reads; a few /64 prefixes
  (cheap in IPv6) cost the whole machine. Cost per request is bounded, so medium, but it is a large
  amplification on the cheapest endpoint.
- Fix: keep the block bytes in their own table (`position → block`, or `block_id → block`) and make the
  listing table `position → (block_id, pubkey)` (64 bytes). `/query`, `/info` and the deny checks then
  never touch block bytes; the subscribe catch-up reads bytes only for blocks it sends. This is also the
  natural base for the H-1 fix.

### M-2. One client address fills the disk quota for good in under an hour

- Location: `lib.rs:81-87` (`min_pow_difficulty: 16`, `max_store_bytes: 8 GiB`, `rate_per_sec: 50`,
  `rate_burst: 200`), `http.rs:101-119` (one token per request whatever the route), `store.rs:127`.
- Scenario: the same token bucket covers `GET` and `PUT`. A client sends 50 maximum-size `PUT`s per
  second: 3.3 MB/s, 8 GiB in about 43 minutes. Proof of work at 16 bits is about 65,000 attempts per
  block. The Nonce sits in the first 1 KiB BLAKE3 chunk, so a miner that caches the chaining values of
  the other chunks (the `blake3` crate exposes them in its `hazmat` module) pays one chunk and a few
  parent compressions per attempt whatever the block size: a fraction of one core at 50 blocks/s. Even a
  naive miner (rehashing 65 KB per attempt) fills the quota for a few dozen core-hours of rented CPU. With
  several /64 prefixes it is minutes. After that every new block gets `507` forever (spec §5, §7: no eviction), and denying the
  attacker's key does not free space (H-1 even makes it costlier). The public relay is dead for writes
  until the operator adds disk.
- Fix (implementation detail, no spec change: `429` and `Retry-After` already exist): a separate,
  much smaller `PUT` budget per client, counted in bytes (for example 64 KiB/s with a few MiB of burst),
  plus an aggregate budget per IPv6 /48 (or /56) so that one allocation is not 65,536 clients. Consider a
  default difficulty that grows with block size, or simply a higher default. Write the attack next to the
  rule (PRINCIPLES rule 3).

### M-3. A malformed deny list at startup lifts every denial

- Location: `crates/sbtp-relay/src/lib.rs:177-180`.
- Scenario: `DenyList::load` rejects the whole file on one bad line, which during a reload correctly keeps
  the previous list (`limits.rs:113`, "a typo never lifts a denial"). At startup the same error, or an
  unreadable file (permissions after a restore), logs a warning and starts with an **empty** list.
  Operator adds a line with a typo, the relay restarts (deploy, crash, reboot): every block the operator
  removed for legal reasons is served again (`200`) and listed, with only a `warn` line in the log.
- Fix: refuse to start (`run` returns the error) when `deny.txt` exists and does not parse or cannot be
  read. A missing file stays an empty list. Add the test.

### M-4. Default deployment behind a proxy puts every client in one bucket

- Location: `lib.rs:41`, `lib.rs:83` (`client_ip_header: None`), `http.rs:122-134`, `main.rs:16`
  (loopback by default).
- Scenario: the documented deployment is "loopback behind a reverse proxy", and by default the relay keys
  every limit on the TCP peer, which is then the proxy. All users share one client address: 8 requests
  in flight (`REQUESTS_PER_CLIENT`), 4 subscriptions (`MAX_SUBSCRIPTIONS_PER_IP`) and 50 requests/s for
  the whole relay. One browser tab or one attacker holding 8 slow requests or 4 WebSockets locks everybody
  out with `429`. Nothing warns the operator. Related, low on its own: the header value must be a bare IP;
  `Forwarded: for=...`, `ip:port` or `[v6]:port` silently fall back to the peer (same collapse), and if the
  operator sets `SBTP_LISTEN=0.0.0.0` with the header configured, a direct client spoofs its address.
- Fix: when `client_ip_header` is unset and the peer is a loopback address, log one prominent warning at
  the first request (or refuse to start when `SBTP_LISTEN` is loopback and no header is set, with an
  explicit opt-out). Count a request whose configured header is missing or unparseable as one shared
  "unknown" key with a small budget rather than as the proxy. Document the exact proxy configuration
  (header overwritten or appended by the proxy, last entry used).

### M-5. The `relay_id` inode heuristic misses in-place restores: positions are reused under the same `relay_id`

- Location: `store.rs:75-97`.
- Scenario (correctness, not attacker-driven): spec §5 says a store restored from a backup MUST draw a new
  `relay_id`, and positions are never reused. The relay redraws only when the file's inode changes. A
  volume snapshot rollback (ZFS, LVM, cloud disk snapshot), `cp backup.redb relay.redb` over the existing
  file, `rsync --inplace`, or a delete-and-copy on a filesystem that reuses the freed inode number (ext4
  often does) all keep the inode. The restored store keeps the old `relay_id` with a lower last position.
  A client that had reached position 1,100 on a store restored at 1,000 first gets `InvalidPosition`
  (fine), but as soon as 100 new blocks arrive its `since=1100` is valid again and it silently skips
  positions 1,001 to 1,100, which now name other blocks. Completeness, the property `since` exists for,
  is lost without any signal. The opposite error (inode changes on some network or FUSE filesystems at
  each mount) only costs a full resync and is harmless.
- Fix: a store cannot detect its own rollback from inside the file. Make restore an explicit operator
  action: a `--new-relay-id` / `SBTP_NEW_RELAY_ID=1` switch, documented as mandatory after any restore,
  or a sidecar `relay_id` file outside the backed-up data directory compared with the one in `META`.
  Keep the inode check as a safety net. Document the procedure in the operator notes.

## Low

### L-1. A WebSocket frame cancels the in-flight catch-up read and leaves it running

- Location: `subscribe.rs:150-178` (`select!` with `feed.next()`), `subscribe.rs:116-123`, `http.rs:52-62`.
- Scenario: `feed.next()` awaits a `spawn_blocking` page read. Any client frame (an unsolicited pong is
  legal) or a ping tick wins the `select!`, drops the future and detaches the blocking task, which reads
  the page to completion and throws it away; the next loop spawns a new one. Probe: 4 connections
  flooding about 1.2 M pongs in 4 s during a 300-block catch-up showed no measurable extra CPU and no
  `/info` latency change, because a page (at most 256 KiB) reads in well under a millisecond. Low today;
  combined with H-1 each cancellation would leave a multi-second scan running.
- Fix: keep the pending `JoinHandle` in `Feed` and poll it again on the next call instead of respawning,
  and cap the client frames accepted per second (close with `1003` or `1008` above a few per second).

### L-2. Global request slots are held during the 10 s body read; the relay relies on the proxy for connection and header limits

- Location: `http.rs:101-119`, `http.rs:164-169`, `lib.rs:69-71`; axum `serve` sets no hyper timer, so no
  header read timeout and no connection cap.
- Scenario: 32 IPv6 /64 prefixes × 8 slow `PUT` bodies hold all 256 global slots for 10 s each, and the
  relay answers `503` to everyone. Behind a proxy that buffers request bodies (nginx's default) the relay
  never sees a slow body, and the proxy also bounds idle connections and slow heads, which `lib.rs:4-6`
  already states.
- Fix: write the required proxy settings down next to the deployment notes (request buffering on, header
  and body timeouts, connection limit per client). Optionally, take the global slot only after the body
  is read.

### L-3. The global subscription cap is cheap to exhaust over IPv6

- Location: `lib.rs:88` (`max_subscriptions: 256`), `lib.rs:67`, `subscribe.rs:48-55`.
- Scenario: 64 /64 prefixes (one /58) × 4 connections that answer pings hold all 256 subscriptions for
  `max_age` (1 h), renewed at will: every other client gets `503` on `/subscribe` and falls back to
  `/query` polling (which still works). Spec-conformant, and the fallback exists.
- Fix: also count subscriptions per /48, and keep a few slots for clients that have none.

### L-4. Rate-limiter table: a spray of addresses makes every new client pay an O(65,536) scan, or a `429`

- Location: `limits.rs:51-57`.
- Scenario: once 65,536 keys are tracked, every request from a new key runs `retain` over the whole map
  under the global mutex; if the entries are all fresh (an attacker with a /48 touching each /64 every
  4 s, about 16,000 requests/s), every new legitimate client gets `429`. Expensive for the attacker, hence
  low.
- Fix: evict in amortised fashion (for example drop the oldest bucket, or sweep once per second from a
  timer), and aggregate per /48 for the tracking bound.

### L-5. A client still draining its last catch-up page can be closed with `4000`

- Location: `subscribe.rs:94-100`, `subscribe.rs:127-134`, `subscribe.rs:173`.
- Scenario: `live` becomes `true` as soon as the final catch-up page is read, while its frames (up to 128
  blocks or 256 KiB) are still in `buffer`. A burst of more than `live_queue` (128) new blocks during that
  drain gives `Lagged` → `4000`, and a send stall in that window is also treated as live slowness; spec §6
  says catch-up is never closed for slowness. The client reconnects from its last position, so nothing is
  lost.
- Fix: set `live` only once the buffer is empty, and on `Lagged` before that point drop the receiver and
  return to catch-up instead of closing.

### L-6. Log flooding under load

- Location: `http.rs:199` (`warn` for every refused block once the quota is reached), `http.rs:203`
  (`info` for every stored block).
- Scenario: combined with M-2, a full relay writes one warning per `PUT` (50/s per client address) to
  stderr forever; journald or the container log driver then grows disk usage the quota does not count.
- Fix: log the quota state change once (and periodically), not per request; consider `debug` for
  "block stored".

### L-7. Test gaps on the rules that guard a public relay

- No test for: startup with a malformed deny list (M-3); the per-client concurrency `429` and the global
  `503` request cap; a denied run longer than a page (H-1); `/subscribe` and the deny list (catch-up and
  live); close code `1011`; `relay_id` after an in-place restore (M-5).
- `deny_list_reloads_without_restart` depends on `(mtime, len)` change detection: two different files of
  the same length written within the filesystem's timestamp granularity are not seen. Fine on APFS and
  ext4 (nanoseconds); a flake source on coarser filesystems. The relay has the same blind spot in
  production (an operator replacing one hex id by another of the same length in under a second).
- The timing tests (`idle_client_and_max_age_close_with_1000`, `slow_live_consumer_is_closed_with_4000`)
  have comfortable margins; none failed or looked load-sensitive in this run. Temporary directories are
  all `tempfile::TempDir`, removed on drop.

## Info

- **I-1. `sbtp-core` decoder and validation: no finding.** `parse` checks F1 to F9 in spec order, never
  reads before checking the length (`zerocopy` `ref_from_prefix`, `split_at_checked`, `get`), the only
  arithmetic is `block_len`, bounded at 73,813. `block_id` is BLAKE3 `derive_key` with the 27-byte
  context over `bytes[..len-64]`. R1 runs before C1; P1 sits between F9 and C1; PoW (one hash) runs before
  the signature (one scalar multiplication). The fuzz target's oracles (agreement of the entry points,
  re-encoding, R1, re-signing) are good; the default `max_len` of a quick run does not reach F2, use the
  `-max_len=66200` of `fuzz/README.md` for longer runs.
- **I-2. Strict Ed25519 maps to V1–V6.** V1: `VerifyingKey::from_bytes` (decompression) plus recompression
  and byte comparison, which rejects `y ≥ p` and `x = 0` with the sign bit. V2: `is_weak`. In
  `ed25519-dalek 3.0.0` `verify_strict`: V3 `Scalar::from_canonical_bytes` (`legacy_compatibility` off,
  and banned in `deny.toml`; `cargo tree -e features` confirms only `fast`, `zeroize`, `digest`,
  `precomputed-tables`), V4 decompression of `R`, V5 `R.is_small_order()`, V6 the cofactorless equation
  with `k` hashed over `R` and `A` as received (`key.compressed`), compared with `R` byte for byte. No
  batch. Domain separation: `SIG_PREFIX ‖ block_id`, and the only signing entry point signs exactly that.
- **I-3. API misuse surface is acceptable.** `BlockRef` and `PowChecked` expose unauthenticated fields;
  both are documented as such and only `ValidatedBlock` is authenticated (no public constructor). P1 is a
  separate call that a relay could forget; the relay does call it. `validate_requested` documents that
  the difficulty is the client's own.
- **I-4. Supply chain.** Every crate in `Cargo.lock` and `fuzz/Cargo.lock` is from crates.io and, except
  four, identical in version and checksum to the reviewed v0.2 lock. New: `tracing-subscriber 0.3.23`
  (2026-03-13, `hds`), `thread_local 1.1.10` (2026-07-10, `Amanieu`), `sharded-slab 0.1.7` (2023-10-04,
  `hawkw`), `lazy_static 1.5.1` (2026-10-01). All are older than two weeks, none has a `build.rs` or a
  proc-macro. `lazy_static 1.5.1` was published by `rust-lang-owner` after two years of releases by
  individuals: that is the rust-lang organisation's publishing account (the crate moved there), seven
  weeks old, two `unsafe` lines; acceptable, noted because a publisher change is the signal to watch.
  `tracing-subscriber` features are `fmt` and `std` only (no `env-filter`, no `ansi`).
- **I-5. `redb =4.6.0` exception.** Checksum equal to the approved one; exact pin; default features; no
  `set_concurrency_mode`; default durability. 4.6.0 is still under two weeks old (published 2026-11-13),
  so the exception is still needed until 2026-11-27. Conditions 3 and 4 (upgrade from a 4.4.0 index) are
  moot for a fresh v1 store; condition 5 (kill and recovery on the deployment CPU architecture) is not
  covered by any v1 test and should be run once before the first public relay.
- **I-6. Position overflow.** `store.rs:132` uses `saturating_add(1)`: at `u64::MAX` the next block would
  overwrite the last log entry. Unreachable in practice; `checked_add` with an error would make the
  invariant explicit for free.
- **I-7. No CI on `v1`.** Every check above is manual. When CI returns: actions pinned by SHA, read-only
  `permissions`, no `pull_request_target`, `cargo deny check` and the vector tests required.
- **I-8. Logging is clean.** No payload, no client address, no key is logged; block ids and positions are
  logged at `info`. `CLAUDE.md` still mentions `gen_vectors --check` with a `vector-gen` feature that v1
  does not have; the frozen vectors are checked by `tests/vectors.rs` (82 vectors, count asserted).

## Not checked

- `crates/sbtp-wasm`, the CLI and any browser client: not on this branch.
- Behaviour behind a real reverse proxy (body buffering, header rewriting, WebSocket proxying).
- redb crash recovery (`kill -9` during writes) and behaviour on a full disk; Linux and x86_64.
- Long fuzz runs (only 120 s with the default input length) and fuzzing of the relay's HTTP and
  WebSocket parsing.
- Source review of axum, hyper, tungstenite and tokio beyond the paths used (serve defaults, upgrade,
  `to_bytes`); they are unchanged from v0.2.
- The `relay_id` behaviour on network and FUSE filesystems (inode stability), argued from documentation,
  not tested.
- Load and throughput beyond the scratch probes quoted above.
