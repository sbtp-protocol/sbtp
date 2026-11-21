# Security review: pull replication, ingest bounds, epoch default, CI budgets (pre-push)

- Date: 2026-11-21
- Scope: local `main` (`32ca29e`) against `origin/main` (`d3c60dd`): ADR 0048 stage 1 (pull
  replication), ADR 0049 (ingest bounds), ADR 0046 D10 (default epoch 8 h), pre-push fixes `e5a41ad`,
  the CI `budgets` job, `deploy/image-size.sh`, `web/wasm-budget.py`, `relay-image.yml`.
- Rules: ADR 0046, 0048, 0049 as accepted in `docs/decisions/`.

## Verdict

**OK to push.** Nothing critical, high or blocking. One medium finding (M-1) breaks the per-group
bound of ADR 0049 by about 5x. The global cap still holds above the low-water mark, so the relay
stays bounded and M-1 is not a blocker. The fix is one line moved and a test, so it is worth putting
into the image you are about to publish. The rest is low or info.

## Checks run

| Check | Result |
|---|---|
| `cargo test --workspace` | all pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo deny check` (advisory DB fetched 2026-11-21) | `advisories ok, bans ok, licenses ok, sources ok`; warnings: duplicate `getrandom`, `syn`, `windows-sys`; one unused licence allowance and one unused exception |
| `cargo +nightly fuzz run decode_block`, 180 s, seeded with 410 `--fuzz-seeds` | 2,081,393 runs, no crash (`sbtp-core` is unchanged in this range) |

## Findings

### M-1 (medium): group budgets let through about 5 times their share, because the check comes before the permit queue

- `crates/sbtp-relay/src/blocks.rs:1017` (`check_groups`) runs before `relay.put.acquire()` at `:1034`.
- `crates/sbtp-relay/src/ingest.rs:134`: `charge` clamps the level at `floor = −put_max_in_flight × 70,000`.

ADR 0049 rule 3 sets the floor on the assumption that only the `PUT`s already in flight have passed
the check and are still uncharged. The check runs before the permit, so every request waiting in the
`put` queue has also passed it. That is `put_max_in_flight + put_max_queue` requests at once:
4 + 16 = 20 on `small`, 16 + 64 on `standard`. When they are all charged, the clamp writes off
whatever goes past the floor.

Scenario on `small`, from one /24:
1. The group share is 25 % of 200 MiB/h, about 14.6 bytes/ms.
2. The attacker uses about 10 addresses in the /24 (`put_max_in_flight_per_client = 2`). It keeps 20
   full-size `PUT`s waiting each time the bucket goes just above zero.
3. All 20 pass the check. All 20 are stored and charged 1.4 MB, clamped at −280 KB.
4. The bucket is back above zero about 19 s later, and the next round starts.

Result: about 260 MB/h from one /24, against a 52 MB/h share. That is more than the whole
`R = 200 MiB/h`. Below the low-water mark nothing else limits it, so the ADR figure "one /48 writes at
most 50 MiB/h from any fill level" does not hold. Above the mark, the global cap (`check_cap` at the
storage step) is correct: only `put_max_in_flight` blocks can sit between check and charge, which
matches the floor. So disk filling stays bounded at `R` per hour.

Fix, either of:
- **Preferred:** call `check_groups` right after `relay.put.acquire()` and before `read_body`. The body
  is still unread (rule 4 holds), and at most `put_max_in_flight` requests are then uncharged, which is
  what the floor assumes. A refused group gives its permit back at once.
- Or set the floor to `−(put_max_in_flight + put_max_queue) × 70,000`. This changes rule 3's figure, so
  it needs an ADR clarification.

Test to add: 20 concurrent `PUT`s from one /24 with the bucket just above zero. After the burst, the
bytes stored minus the bytes charged must stay within `put_max_in_flight × 70,000`.

### L-1 (low): the blocking thread pool does not count replication

- `crates/sbtp-relay/src/config.rs:719`: `blocking_floor = block_max_readers + put_max_in_flight + 2`.
- Replication's blocking work:
  - `tokio::net::lookup_host` (`replication/http.rs:196`) calls `getaddrinfo` on a blocking thread.
  - `save_walk` and `retain` (`replication/mod.rs:652`, `:378`) wait on the index writer from a
    blocking thread.

Scenario: a peer whose DNS answers slowly keeps up to `replication_max_in_flight` blocking threads
busy. On `standard` that is 4, more than the 2 spare threads. A peer can also be broken without being
hostile: its operator controls its DNS. Cancelling the request at the timeout does not free a thread
stuck in `getaddrinfo`. `GET /block` and `PUT` blocking jobs then wait in tokio's unbounded queue.

Effect: added latency, no crash, no bypass. On `small` (`in_flight = 1`) it is contained.

Fix: when `peers` is set, add `replication_max_in_flight + 1` to `blocking_floor`, and update the ADR
0018 rule 35 memory term to match.

### L-2 (low): the global cap is checked before signature verification, not after it

- `crates/sbtp-relay/src/blocks.rs:501` (`check_cap`) comes before `verify_once` (C2, C3) at `:504`.
  The comment at `:496` says "after validation".
- ADR 0049 rule 6 says the cap is checked after validation.

Scenario: while the cap is active, a block with a bad signature gets `503` with `Retry-After`. Under
the rule it should get `400`. A client retries a block it should drop.

There is no security effect. The cap is only charged on `201`, and checking earlier saves an Ed25519
verification under load. Fix: either move `check_cap` after `verify_once`, or reword rule 6 and the
comment to "after C1 and the held check".

### I-1 (info): the default-deny address list has gaps

`crates/sbtp-relay/src/peers.rs:236-273` refuses these by default:
- IPv4: loopback, RFC 1918, link-local, RFC 6598, 0/8, 240/4, multicast, broadcast.
- IPv6: loopback, `fc00::/7`, `fe80::/10`, `fec0::/10`, IPv4-mapped, `64:ff9b::/96` and `::/96`.

Not refused:
- `64:ff9b:1::/48` (RFC 8215, local-use NAT64): on a host with a local NAT64 it reaches private IPv4.
- `192.0.0.0/24`.
- `198.18.0.0/15`.
- `2002::/16` (6to4) and `2001::/32` (Teredo) that embed a private IPv4 address.

Each needs an unusual network on the relay host, and only names the operator configured are
resolved. Fix: add `64:ff9b:1::/48`, `192.0.0.0/24` and `198.18.0.0/15`, and judge `2002::/16` by
its embedded address.

### I-2 (info): a rejected peer URL is printed back in full, including userinfo

`crates/sbtp-relay/src/peers.rs:38`: `bad()` puts the whole input into the error. For
`https://user:secret@relay`, the start-up error shows the password in the operator's own log. Fix:
leave the authority out of the error when it contains `@`.

### I-3 (info): a peer can choose its own back-off and its own resets

- Any `Retry-After` is honoured up to 30 days (`replication/mod.rs:565`), even past
  `replication_max_backoff_s`.
- An endless `InvalidCursor` costs one `/query` and one cursor write per second for that peer
  (`:435`, paced by `QUERY_INTERVAL`).

Both only affect the peer that sends them. This is as designed.

## Confirmed correct

**ADR 0048, replication HTTP client** (`replication/http.rs`):
- Head bounds: 16 KiB, 64 fields, 64 KiB read buffer, set on hyper's builder and tested.
- Body bounds: an announced `Content-Length` over the ceiling is refused before any byte is read; a
  streamed body stops at the ceiling; a truncated body fails.
- `3xx` is never followed, and its body is not read.
- Any content coding other than `identity` is refused.
- One timeout covers DNS, TCP, TLS, head and body.
- A connection lives only for one turn, and it is dropped after any failure.

**ADR 0048, SSRF:**
- DNS is resolved per connection, at most 8 addresses are tried, each is checked, and the connection
  goes to the checked `SocketAddr`. A name that changes between two lookups cannot reach an unchecked
  address.
- IPv4-mapped and `64:ff9b::/96` addresses are judged by the IPv4 address they carry.
- Literal IPs written by the operator are allowed, as rule 14 says.
- `http` is accepted only for a loopback host.
- No URL comes from the network: only fixed paths, a 64-hex id, a numeric `since`, and a cursor
  limited to `[A-Za-z0-9_-]{1,128}`, so no `&` or CRLF can be injected.
- `PeerUrl` rejects userinfo, query, fragment, `%`, `.`/`..` segments and numeric-looking host names.

**ADR 0048, TLS:**
- rustls with the `ring` provider, TLS 1.3 only, `Resumption::disabled()`, ALPN `http/1.1`.
- Hostnames are checked by the WebPKI verifier.
- `peer_ca_file` is read up to 4 MiB and replaces the system store.
- `rustls-native-certs` reads `SSL_CERT_FILE` and `SSL_CERT_DIR`. That is operator environment, and
  whoever controls it already controls the relay.
- With no root loaded, the relay refuses to start.
- The distroless runtime image ships a CA bundle.

**ADR 0048, cursor and storage:**
- Cursor table: each write is its own redb transaction with default durability, made after the
  page's blocks are stored. Block files are `fsync`ed, and a durable commit also makes earlier
  non-durable index commits durable. A crash replays the last page, which is cheap because already
  held blocks are skipped.
- R1 (`blocks.rs:416`): checked right after C1, so a block for a different id is `Invalid`. 16
  invalid blocks end the round with a back-off.
- An oversized body is `TooLarge`, which is a back-off. Future blocks are skipped.
- Endless `more = true` is paced by `QUERY_INTERVAL`, the block and byte buckets, the high-water pause
  and the 64-fetch turn.
- The arithmetic in the scheduler and buckets is saturating or bounded. No panic path reachable from
  peer input was found.
- `Ticket::Replicated` is neither charged nor capped (`ingest.rs:420`, `:468`), and a copy records no
  demand.
- Logs name a peer by its position only, and the settings line logs the peer count.

**ADR 0049, ingest bounds:**
- No latch: monotonic clock, refill depends only on time, nothing is persisted.
- The negative floor is enforced. See M-1 for how many requests can be in flight against it.
- Groups come from the resolved client key (ADR 0044 `client_ip_header` or `trusted_proxies`).
  IPv4-mapped addresses are normalised. The overflow key has no group.
- The group table fails open when full, as rule 5 says, and the global cap still applies.
- Each block is charged once, under the `block_id` lock, on `201` only.
- Held blocks get `200` before the cap is checked.
- No address appears in logs, metrics labels or on disk.

**ADR 0046 D10:**
- The default is 28,800,000 ms (8 h). `last_demand` is stored as a time, not an epoch number, so
  changing the epoch does not corrupt the index.
- The rule 27 and 28 figures are consistent: `6 × N` revalidations per key per day. The `small` block
  allowance of 3,000 per minute covers 720,000 blocks at `U = 1`.
- The tripled `304` load is a cost (about 6.9/s at 100,000 blocks with one upper tier), not a risk.

**Pre-push fixes `e5a41ad`:**
- L-1: `Store::evict` returns the bytes it released, and a demand pass stops only on `Some(0)`.
- I-1: a restored suspension is capped at now + 2 × E.
- I-2: `errorName` keeps only `[A-Za-z0-9_-]{0,64}`. There is no `innerHTML` sink in `web/src`.

**Supply chain:**
- Every new crate was published before the two-week cutoff (2026-11-07). The newest is
  `openssl-probe` 0.2.2, published 2026-10-26.
- Publishers are the usual maintainers: ctz/djc (rustls family), briansmith (ring, untrusted),
  seanmonstar (want, try-lock), kornelski (security-framework).
- No proc-macro. Only two crates have a `build.rs`:
  - `ring`: compiles its bundled C and assembly. NASM is used only on Windows.
  - `rustls`: one nightly `cfg` line.
- rustls 0.23.46 and rustls-webpki 0.103.16 are the patched versions for RUSTSEC-2026-0285 and
  -0346 to -0349, and for RUSTSEC-2026-0382.
- Everything comes from the registry, there is no git source, and `Cargo.lock` is committed.

**CI:**
- `ci.yml` triggers on `push` and `pull_request` only (no `pull_request_target`), with
  `contents: read` at top level.
- The new `budgets` job uses only `actions/checkout`, pinned by SHA with `persist-credentials: false`.
  It needs no secret and installs no tool. The Dockerfile base images are pinned by digest.
- `image-size.sh` and `wasm-budget.py` only read files the job built itself, and Python runs with `-I`.
- `relay-image.yml` adds one read-only step before the GHCR login.

## Not checked

- The live deployment: whether the public relay behind the CDN sets `client_ip_header` and
  `trusted_proxies` correctly. Without them, every client is one group (ADR 0049, Consequences) and
  one key for the limiter (ADR 0046 rule 28). This needs checking on the host before the new image is
  rolled out.
- The CDN's edge rate limits for `PUT` (ADR 0049 rule 11).
- TLS against a real `https` peer. The tests use loopback `http`, so certificate validation was not
  exercised end to end here.
- hyper and rustls internals beyond their public options, and the source of `ring`'s C and assembly.
- Whether the relay-image workflow is green on GitHub. No push was made.
- M-1 was found by reading the code. No concurrent load test was run, because the review is read-only.
