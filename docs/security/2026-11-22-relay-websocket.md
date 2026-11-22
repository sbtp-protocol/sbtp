# Security review: relay subscriptions over WebSocket (ADR 0054)

- Review date: 2026-11-22. Reviewer: security auditor (independent: diff and spec only).
- Scope: `git diff feat/relay-hardening-2...feat/relay-websocket` (3 commits: `1ea5c8a`, `8a4f8ae`,
  `6bb199b`): `crates/sbtp-relay/src/subscribe/` (new), the integration in `server.rs`, `api.rs`,
  `blocks.rs`, `config.rs`, `metrics.rs`, `mirror/mod.rs`, `sweep.rs`, the tests
  `tests/subscribe.rs` and `tests/startup.rs`, `deploy/README.md`, `Cargo.toml` and `Cargo.lock`.
  The hardening branch below it is reviewed separately.
- Reference: ADR 0054 (rules 1 to 47); core spec §4 `GET /sbtp/v1/subscribe`; `architecture.md` §2
  "Subscriptions"; ADRs 0018 and 0027 (admission, limiter), 0021 (logs), 0052 (deny list).
- Commands, on a detached worktree at `6bb199b`: `cargo test --workspace` (all green),
  `cargo clippy --workspace --all-targets -- -D warnings` (green), `cargo deny check`
  (`advisories ok, bans ok, licenses ok, sources ok`), `cargo tree -d`. With `object-store`, only the
  targeted tests `startup::small_profile*` and `mirror::tests::the_read_only_info_has_no_subscribe_member`
  (green); the full `object-store` suite could not be built (disk full on the review machine).
  Dependency sources read from the local cargo registry cache; publication dates from the local
  index cache (`pubtime`). No remote endpoint was contacted other than what `cargo deny check` does
  for its advisory database.

## Verdict

**Mergeable.** No blocking or high finding. The upgrade path, admission, memory bounds, the deny-list
rule and the privacy rules hold against the spec. One **medium** finding (M-1: the age, liveness and
slow-consumer timers are not evaluated while a connection's queue stays non-empty) should be fixed,
with a short re-review, before a relay is exposed publicly with `ws_enabled = true`; the function is
off by default, so merging does not expose it. The low findings go to the roadmap ("Relay hardening
(parked)"); L-4 and L-8 are spec ambiguities for `spec-architect`.

## Findings

### M-1 (medium): timers are skipped while the send queue is non-empty

- File: `crates/sbtp-relay/src/subscribe/session.rs`, lines 113 to 150 (the send branch of the loop)
  and 151 to 165 (where `age_at`, `idle_at`, `pong_due`, `ping_at` and `slow_at` are evaluated).
- What happens: each turn of the loop pops one queued item, sends it (bounded by
  `2 × ws_ping_interval_ms` per item) and `continue`s. The deadlines are evaluated only when the queue
  is empty. A connection whose queue never empties is therefore never closed at `ws_max_age_ms`
  (rule 33), never closed with 1008 for a queue that stays full (rule 20), and gets no ping.
- Scenario: a client subscribes `all` (or a busy parent set) and reads slowly enough that every single
  send completes within 60 s but the queue never drains, for example 1 KiB/s. On a relay with steady
  ingest, or with the client's own `PUT`s feeding its subscription, the connection lives past one hour
  indefinitely, keeps a 64 KiB queue full and receives a `gap` after another. The slot turnover the
  1-hour age exists for (ADR 0019 point 10) is defeated, and the 1008 defence of rule 20 never fires.
  Impact is bounded: memory stays within `WS_SEND_BYTES`, and an attacker could hold its share of
  slots by reconnecting anyway, so this is a spec conformance gap under adversarial load, not an
  exhaustion.
- Fix: evaluate `age_at` and `slow_at` (from `overflow_since`) at the top of every turn, before popping,
  and race the send against `sleep_until(min(age_at, slow_at))` as well as `stopping.changed()`. Add a
  unit-level test of the loop's deadline choice (a 60 s integration test at the lowest
  `ws_max_age_ms` is acceptable too). The doc comment of `a_slow_consumer_gets_a_gap` claims 1008 is
  covered, but nothing asserts it (I-7).

### L-1 (low): a reply to a client message can be lost, so a frame can precede its `subscribed`

- File: `crates/sbtp-relay/src/subscribe/session.rs`, lines 151 to 153 (`can_read`) and 235 to 238
  (`reply`); `crates/sbtp-relay/src/subscribe/mod.rs`, lines 572 and 593 (the result of `q.push` is
  ignored).
- Scenario: `can_read` is computed when the queue is empty; while the session waits in `recv`, the
  fan-out (another worker thread) can fill the queue with deliveries for the connection's other
  subscriptions. The next client message is then handled with less than `MAX_CONTROL` bytes of room:
  `subscribed`, `unsubscribed` or `error` is dropped silently. For `subscribe` the subscription is
  registered anyway, so its first delivery frame reaches the client with no `subscribed` before it
  (rule 14 MUST). A conforming client treats a frame of an unknown `sub` as malformed (rule 10),
  closes with 1002 and backs off to polling; a lost `error` leaves a client waiting for an answer.
  Self-inflicted and rare, but on a busy relay with an `all` subscription on the same connection it
  is reachable.
- Fix: reserve `MAX_CONTROL` bytes for replies: deliveries and gaps may use only
  `WS_SEND_BYTES - MAX_CONTROL`, and the session reads only while the reserve is free (one reply per
  message read). Make `Hub::subscribe` register only if `subscribed` was queued.

### L-2 (low): the fan-out task starts at the first upgrade, not at start-up

- File: `crates/sbtp-relay/src/subscribe/mod.rs`, line 703 (`hub.start()` in `upgrade`);
  `crates/sbtp-relay/src/blocks.rs`, `Relay::new` (the start-up `head`, `unwrap_or_default` on error).
- Scenario: until the first subscription connection, nothing reads the fan-out channel. After 256
  accepted blocks it is full and every later offer records a drop. The first subscriber then gets
  `start` = the `head` of process start-up and, immediately, a `fanout` gap with that cursor, plus up
  to 256 stale deliveries: its client walks `/query` from the relay's start (days or weeks of blocks,
  paid with its own `query` tokens), and `ws_gaps_fanout` increases on a healthy relay, which is the
  alert `deploy/README.md` recommends. If the start-up `head` read fails, `start` becomes the cursor of
  the default position, and the walk covers the whole store.
- Fix: start the fan-out task when the runtime starts (in `serve`, when `ws_enabled`), so that entries
  with no subscription are evaluated and discarded as they come; on a failed `head` read, stop the
  start-up (or disable the function) rather than starting from position 0.

### L-3 (low): shutdown can be held past the drain deadline by a client that does not read

- File: `crates/sbtp-relay/src/subscribe/session.rs`, line 204 (ping send).
- Scenario: the ping is sent under `timeout(2 × ws_ping_interval_ms, ...)` without racing
  `stopping.changed()` (the item send at line 130 does race it). A client that does not read, whose
  TCP and codec buffers are full when the relay stops, keeps its session in that send for up to 60 s,
  longer than `request_timeout_ms + RESPONSE_GRACE`. The drain ends as `Deadline`, the stop is not
  clean, and the next start suspends demand eviction (ADR 0046 rule 13). One hostile connection is
  enough to make shutdowns unclean.
- Fix: race the ping send with `stopping.changed()` (return `End::Drop`), as the item send does, or
  skip the ping while the codec still holds unwritten bytes.

### L-4 (low, spec ambiguity): an orphan repaired by a `PUT` answered `200` is never delivered

- File: `crates/sbtp-relay/src/blocks.rs`, `index_orphan` (line 895) and `insert_new` (line 854).
- Scenario: a held block without index entry (after an index write refused while stopping, or an
  index error) is indexed by the next `PUT` of it, answered `200`, with `FileState::AlreadyHeld` at
  the current time: a new position after every open `start`. `/query asc` from `start` lists it, but
  only `insert_new` offers to the fan-out, so no delivery and no `gap` cover it. A client that follows
  rule 24 reports its set complete while missing a block `/query` lists. Rule 12 says both "a `PUT`
  answered `200` delivers nothing" and "the set delivered is the set that `/query` `asc` from `start`
  would list": the two conflict in exactly this case.
- Fix: report to `spec-architect`. The simple resolution is "every insert that takes a new position
  is delivered", which in code means offering the result of `index_orphan`'s insert too (with the
  deny check); the start-up reconcile runs before the `head` is read and needs nothing.

### L-5 (low): the deny check runs at commit time, not at fan-out time

- File: `crates/sbtp-relay/src/blocks.rs`, line 871; `crates/sbtp-relay/src/subscribe/mod.rs`,
  `evaluate` (line 425).
- Scenario: rule 42 asks for the check "at the time of the fan-out". The code checks on the writer
  thread right after the commit, which covers a list loaded between the `PUT`'s own check and the
  insert (tested). A list loaded after the offer and before `evaluate` (up to 256 queued entries plus
  one batch, normally milliseconds, longer when the fan-out lags) still lets the block be pushed. The
  push is only a hint: the fetch gets `451`.
- Fix: carry the public key in `Entry` and check again in `evaluate` (EST_FANOUT_ENTRY becomes about
  352 bytes), or record in the code that the commit time is the fan-out time for rule 42 and accept
  the window.

### L-6 (low): the send-queue bound counts payload bytes, not memory

- File: `crates/sbtp-relay/src/subscribe/mod.rs`, `Queue::push` (line 211).
- Scenario: `bytes` counts each item's length only. A client that subscribes `all` and never reads,
  on a relay that ingests one block per fan-out batch, fills its queue with one-entry frames of 81
  bytes: about 809 items, each with a 32-byte `VecDeque` slot and an allocation rounded up with its
  allocator header, roughly 40 to 50 KB per connection above `WS_SEND_BYTES`. Sixteen such
  connections on `small` add about 0.7 to 0.8 MB, more than the 574,798 bytes of headroom of `small`
  with every function on (ADR 0054 rule 35). Bounded, and the 60-second `VmHWM` runs replace the
  estimate, but the estimate is optimistic under an adversarial pattern.
- Fix: charge a per-item overhead (`len + 64`) in `bytes`, or coalesce consecutive deliveries of one
  subscription into the frame at the tail of the queue.

### L-7 (low, spec ambiguity): the resume point after a `gap` can skip the dropped range

- Not in this diff (client side), found while checking the `gap` cursor: ADR 0054 rule 22 makes the
  resume point "the one received last" among `start`, frame cursors, `gap` cursors and ticks. After a
  `gap`, the relay continues live delivery, so a frame cursor newer than the dropped range arrives
  before the client's catch-up walk of rule 19 ends. If the connection closes then, resuming from that
  frame cursor (rule 21) skips the dropped blocks. "Received while no gap of that subscription is
  unresolved" reads as qualifying only the tick.
- Fix: report to `spec-architect`: while a gap is unresolved, the resume point stays at the oldest
  unresolved gap's cursor; the SDK state machine and a `client-v1/` case should pin it.

### L-8 (low): the network group of a key equal to its /48 is not skipped

- File: `crates/sbtp-relay/src/subscribe/mod.rs`, line 731.
- Scenario: rule 28 skips a group level "not shorter than `client_ipv6_prefix`". The filter keeps a
  group whose prefix is `<=` the key's: with `client_ipv6_prefix = 48`, the group is the key itself
  and the group share applies on top of `ws_max_connections_per_client`. With a low
  `ws_group_share_pct` a client gets the group share instead of its per-client bound. The call also
  passes a fixed 64 to `groups` instead of the setting (harmless with the `<=` filter, but surprising).
- Fix: use `<` and pass `client_ipv6_prefix`; add a test with `client_ipv6_prefix = 48`.

### Info

- **I-1: dependencies.** See "Dependencies" below: all 22 packages pass (crates.io, at least 14 days,
  known maintainers, permissive licences, no `build.rs` beyond `rustc` probes and one file copy on
  wasm targets that the relay never builds). No version of an existing package moves.
- **I-2: `tungstenite` as a direct dependency is needed in normal builds**, not only in tests:
  `session.rs` line 87 downcasts the read error to `tungstenite::Error` to choose 1009, 1007 or 1002.
  The downcast works only while the workspace version equals the one axum's `tokio-tungstenite` uses;
  if they diverge, the build still succeeds and every violation silently ends without a close code.
  `protocol_violations_close_the_connection` catches that. Keep it; add to the `Cargo.toml` comment
  that the version MUST equal axum's, and check `cargo tree -d` lists a single `tungstenite` when
  axum is updated (`multiple-versions` is only `warn`).
- **I-3: `HEAD` on the route.** axum's `get` also serves `HEAD`; `RequestClass::of` charges it a
  `block` token, and it ends as `400` (axum's `MethodNotGet`) after step 6 rather than `405`. Rule 2
  allows `400` for an invalid upgrade method; harmless. Add `HEAD` to the class match or answer `405`.
- **I-4: a client-initiated close is not answered.** On `Message::Close` the session drops the socket
  without flushing the codec's automatic close reply, so the client sees an abnormal closure. Cosmetic.
- **I-5: duplicate JSON members.** `serde_json` keeps the last value of a duplicated member, so
  `{"op":"subscribe","op":"unsubscribe",...}` is accepted. The spec is silent; no security impact.
- **I-6: privacy holds.** No log line in `subscribe/` at any level; error messages are fixed texts;
  metric labels come from fixed sets (an unknown peer close code counts as `none`); subscription state
  lives in memory only and is dropped with the connection (`remove_conn`). Rules 36 to 38 hold.
- **I-7: test gap.** `a_slow_consumer_gets_a_gap` documents 1008 but does not assert it; see M-1.
- **I-8: fan-out CPU.** `evaluate` holds the registry lock on a runtime worker for O(entries × matching
  subscriptions) per batch, builds frames even for subscriptions whose queue cannot take them, and
  keeps a transient `matched` map of up to about 16 MB on `large` (16,384 subscriptions × 64 entries
  × 16 bytes), outside the rule 35 estimate. On `small` it is about 64 KB. Skip frame building when a
  gap is owed and the queue is full; consider sharing the frame body between `all` subscriptions.
- **I-9: group share.** With `ws_group_share_pct = 25`, four network groups (four IPv4 /24s, or four
  IPv6 /48s, which tunnel brokers hand out for free) fill `ws_max_connections` on every profile. Other
  clients then get `503` and fall back to polling (rule 44); the HTTP half of `max_connections` is
  untouched. This is the ADR's design; worth a sentence in `deploy/README.md`.
- **I-10: the fan-out task and the hub form a cycle** (the task holds `Arc<Hub>`, the hub holds the
  channel's sender), so the task ends only when the runtime is dropped. That is what the binary does at
  the end of `serve`; a leak only for an embedding that keeps the runtime.
- **I-11: entries before `start` after a fan-out overflow.** After the drop is processed,
  `reg.next` jumps past the dropped position while older entries are still in the channel; a
  subscription registered in between receives those older entries (rule 15 says none from before
  `start`). Duplicates only, which the client deduplicates. Keeping the start position in `Sub` and
  skipping older entries fixes it.

## What holds

- **Upgrade path (rules 1, 2, 25).** The query string, `Upgrade`, `Connection`, `Sec-WebSocket-Key`,
  `Sec-WebSocket-Version: 13` (with the header on the `400`) and subprotocol checks run before
  axum's extractor, with the JSON error body; header tokens are split on commas, trimmed and compared
  case-insensitively; invalid UTF-8 header values are treated as absent. `405` keeps the JSON body
  through `json_405`. The route exists only with `ws_enabled` (`404` otherwise); `/info` publishes
  `subscribe` only then, never on the read-only bucket. `Connection: close` is no longer added to a
  `101`. The upgrade is charged one `query` token by the existing middleware, before the head checks.
- **Admission (rules 25 to 28).** Per-client (pinning the limiter entry, overflow key shared), then
  group, then total; `429` with `Retry-After: 30`, `503` with `shed_retry_after_s`; slots are RAII
  guards, released on every early return and when the session ends; an exempt key skips the client
  and group bounds and the `subscribe` tokens, never the total. The direct peer's per-client
  connection slot is released at the `101` and the `max_connections` permit is kept until the
  session's `oneshot` fires, also when the upgrade never completes (the callback and its guards are
  dropped). Proxied clients get their key from `X-Forwarded-For` or `client_ip_header` on the upgrade
  request. Slowloris on the handshake is the existing `header_timeout_ms`; after the `101`, idle,
  ping and age close a silent connection.
- **Codec limits (rule 29).** Read buffer 8,192, write buffer 0, maximum write buffer 65,600 (a full
  65,536-byte frame plus its 10-byte header fits), message and frame 4,096. In tungstenite 0.29.0 the
  frame length is checked against `max_frame_size` before any reservation, fragments are accumulated
  under `max_message_size`, unmasked client frames are refused, and only one automatic pong is kept:
  no allocation driven by a declared length. Oversized maps to 1009, invalid UTF-8 to 1007, protocol
  errors to 1002, a binary frame to 1003, a non-object to 1007.
- **Memory.** The per-connection queue never exceeds `WS_SEND_BYTES` of payload (L-6 for overhead);
  the session reads only when its queue is empty, so a client cannot queue replies faster than it
  reads them; the fan-out channel is bounded at 256 and overflow becomes gaps; the registry is
  bounded by `ws_max_connections × ws_max_subscriptions × 32` parent entries. The `small` figure
  19,425,202 bytes is asserted.
- **Correctness.** Offers happen on the single index writer, after the commit, in store order, never
  waiting; only new positions are offered (`201`, replication through `process`, re-acceptance after
  expiry); a `200` re-`PUT` offers nothing (except L-4). The `gap` cursor is the cursor of the last
  frame queued (or `start`) and is queued before any later frame of its subscription; every dropped
  delivery, from the queue or from the channel, lies after that cursor, so a walk from it loses
  nothing (verified by `a_slow_consumer_gets_a_gap` with `/query`). Masks set exactly the matched
  parents' bits; ticks are withheld while a gap is owed.
- **Robustness.** No `unwrap`, `expect`, panic or unchecked indexing outside tests in `subscribe/`
  (clippy `indexing_slicing` and `unwrap_used` are on); lock order is always registry then queue; one
  task per connection plus one fan-out task, all ending with the connection or the runtime.

## Dependencies

All from crates.io (`cargo deny check` sources ok), dates from the local index cache, none yanked
there. Maintainers from the crates' repositories as known to the reviewer, not re-checked online.

| Crate | Version | Published | Licence | `build.rs` | Notes |
|---|---|---|---|---|---|
| tungstenite | 0.29.0 | 2026-03-17 | MIT OR Apache-2.0 | none | snapview; `unsafe` only in UTF-8 and mask helpers; `rand` used for client masking only |
| tokio-tungstenite | 0.29.0 | 2026-03-17 | MIT | none | snapview |
| sha1 | 0.10.7 | 2026-07-10 | MIT OR Apache-2.0 | none | RustCrypto; handshake accept key only, not a security primitive here |
| digest, block-buffer, crypto-common | 0.10.7, 0.10.4, 0.1.7 | 2023-05-19, 2023-03-09, 2025-11-12 | MIT OR Apache-2.0 | none | RustCrypto, older majors beside 0.11 / 0.12 / 0.2 |
| generic-array | 0.14.7 | 2023-03-28 | MIT | `rustc` version probe through `version_check` | |
| version_check | 0.9.5 | 2024-07-25 | MIT/Apache-2.0 | none | build dependency only |
| cpufeatures | 0.2.17 | 2025-01-25 | MIT OR Apache-2.0 | none | RustCrypto, beside 0.3.1 |
| base64 | 0.22.1 | 2024-04-30 | MIT OR Apache-2.0 | none | beside 0.23.1 (cli-demo's `ureq`) |
| data-encoding | 2.11.1 | 2026-08-03 | MIT | none | |
| rand, rand_chacha, rand_core | 0.9.5, 0.9.0, 0.9.5 | 2026-07-11, 2025-01-27, 2026-01-13 | MIT OR Apache-2.0 | none | rust-random; `rand_core` beside 0.10.1 |
| ppv-lite86 | 0.2.21 | 2025-03-09 | MIT OR Apache-2.0 | none | |
| getrandom | 0.3.4 | 2025-10-14 | MIT OR Apache-2.0 | runs `rustc -vV` on Windows targets only | beside 0.2.17 and 0.4.3 |
| r-efi | 5.3.0 | 2025-06-17 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | none | UEFI targets only |
| wasip2, wit-bindgen | 1.0.4+wasi-0.2.12, 0.57.1 | 2026-06-12, 2026-04-17 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | `wit-bindgen`: copies a prebuilt `libwit_bindgen_cabi.a` on wasm targets | `wasm32-wasip2` only; never built for the relay nor for `sbtp-wasm` (`wasm32-unknown-unknown` does not reach `getrandom` 0.3) |
| futures-sink | 0.3.34 | 2026-08-11 | MIT OR Apache-2.0 | none | rust-lang futures |
| thiserror, thiserror-impl | 2.0.21 | 2026-09-23 | MIT OR Apache-2.0 | `thiserror`: compiles a probe with `rustc`, writes into `OUT_DIR` | dtolnay; `thiserror-impl` is a procedural macro (code generation only) |

The newest is 60 days old. The duplicates this adds (`base64`, `block-buffer`, `cpufeatures`,
`crypto-common`, `digest`, `getrandom`, `rand_core`, `r-efi`) are older majors pulled by the
WebSocket stack beside the newer ones of the dalek and HPKE graph; they cost compile time and binary
size, not security, and go away when axum moves to a `tokio-tungstenite` on `sha1` 0.11 and `rand`
0.10. Nothing to do now.

## Not checked

- Maintainer lists and download counts on crates.io, and yanked status after the local index cache's
  last refresh (no network).
- The full `cargo test -p sbtp-relay --features object-store` suite (the review machine ran out of
  disk); only the targeted tests above.
- Real reverse proxies and CDNs in front (WebSocket over HTTP/2 or HTTP/3, idle timeouts, `Connection`
  rewriting), browser clients, and TLS (not in the relay yet).
- Load and `VmHWM` measurements of the memory terms (rule 35), and fuzzing of the client-message
  parser (it is `serde_json` with a 4,096-byte bound and a fixed member list).
- The client SDK side of ADR 0054 (`follow`, resume points), apart from the spec note L-7.

## Re-review (2026-11-22)

- Scope: the six fix commits after the rebase on `main` `1f76b1c`, `git diff 36d62c7..124f188 --
  crates/sbtp-relay` (`64738ac` M-1, `8555066` L-3, `c9d80e8` L-8, `bd7963f` L-2, `9665cc2` L-6,
  `124f188` L-1); range confirmed with `git log`. The findings L-4, L-5 and L-7 are not addressed by
  these commits and are not re-reviewed here.
- Commands, in the branch worktree at `124f188`: `cargo test -p sbtp-relay` (green),
  `cargo test -p sbtp-relay --features object-store` (green, the full suite this time),
  `cargo clippy -p sbtp-relay --all-targets --all-features -- -D warnings` (green),
  `cargo deny --offline check` (`advisories ok, bans ok, licenses ok, sources ok`). The cancellation
  behaviour of a send was checked against the `tokio-tungstenite` 0.29.0 and `axum` 0.8.9 sources in
  the local cargo registry. No remote endpoint was contacted.

### Status of the findings

| Finding | Status | Notes |
|---|---|---|
| M-1 | **Closed** | Every loop turn checks the age, idle and 1008 deadlines before popping an item, and every item send is raced against the earliest of them. On the read path the wake time includes the same deadline. The ping send is bounded by its own `2 × tick_ms` timeout. The 1008 clock stops only once the queue is empty and no gap is owed, so a client that flushes a gap now and then under steady traffic keeps its clock running; `a_slow_reader_under_steady_traffic_gets_1008` covers that case. One edge case remains (L-9 below). |
| L-1 | **Closed** | Deliveries, gaps and ticks are bounded by `WS_SEND_BYTES - REPLY_RESERVE`; replies may use the whole bound. A client message is read only on the empty-queue path with `can_read()`, the session reads one message per turn, and each message yields at most one reply, so the reply always fits. `subscribe` queues `subscribed` before registering, all under the `reg` lock, so no fan-out batch can come in between. The lock order (`reg` then `q`) matches `evaluate` and `unsubscribe`. There is no deadlock and no starvation of replies: replies are FIFO in the same queue. The test checks that the largest frame of one batch fits outside the reserve, so a delivery can never be refused for good. |
| L-2 | **Closed** | `hub.start()` runs in `serve` after the listener is bound and before the accept loop serves, and `upgrade` no longer starts it. A failed `head` read now fails start-up (`NewError::Head`, then `StartError::Io`) instead of starting from position 0, and the index pool is still shut down on that path. Entries committed between the `head` read and `start()` (replication is spawned earlier in `serve`) wait in the 256-entry channel, so no gap is expected. See I-12 and I-13 for test coverage. |
| L-3 | **Closed** | The ping send is raced against `stopping.changed()` like an item send. Not tested (I-13). |
| L-6 | **Closed** | Each item is charged its heap capacity (after `shrink_to_fit`) plus `ITEM_OVERHEAD = 2 × size_of::<Out>() + 32`. Per item, the real cost is at most two ring-buffer slots (a `VecDeque` grows by doubling and keeps its capacity, so its capacity stays below about twice the largest item count the bound allows), the payload, and at most 31 bytes of glibc header and rounding (a 32-byte minimum chunk for tiny payloads). That stays within the charge for any payload length, including frames smaller than the 81-byte delivery used in the test, because the charge grows with the payload and the overhead is a fixed upper bound. The charge is computed once, after `shrink`, and the same `cost()` is released when the item leaves the queue, so the accounting is consistent. The codec's write buffer (`max_write_buffer_size`) is a separate term, unchanged. See I-14 for other allocators. |
| L-8 | **Closed** | `group_of` passes `client_ipv6_prefix` (validated to 32..=64, so the `unwrap_or(64)` cannot be reached) and uses `<`. Tested with a prefix of 48. |

### New findings

#### L-9 (low): a deadline that interrupts the last send can skip the 1008 close

- File: `crates/sbtp-relay/src/subscribe/session.rs`, lines 171 to 188 (the `None` arm after
  `sleep_until(ending)`).
- Scenario: the 1008 deadline (`slow_at`) fires while the session is sending the last queued item,
  for example the queued `gap` itself, with no other gap owed. `release()` then finds the queue empty
  with no gap owed and clears `overflow_since`. At the next turn `ended()` sees no `slow_at`, so the
  connection that rule 20 says to close with 1008 stays open. It is closed later only by a new
  overflow, by the item or ping send timeout (`2 × tick_ms`), or by the maximum age, so this is
  bounded. Second effect: in `tokio-tungstenite` 0.29, a cancelled send drops its message if it is
  cancelled in `poll_ready`, which happens only when an earlier cancelled send left `ready = false`.
  After two such interruptions without a close, a delivery or `gap` frame can be lost with no `gap`
  reported, which breaks the delivery contract of rule 34 for that client. Only the slow client
  itself is affected, and the timing is narrow. There is no cross-client impact and nothing for an
  attacker to gain.
- Fix: when the deadline arm wins, close at once using the deadlines read at the top of the turn,
  for example `None => return ended(Instant::now(), age_at, idle_at, slow_at).unwrap_or(End::Close(1008))`,
  instead of calling `release` and continuing. A cancelled send is never reused after that.

#### Info

- **I-10** (pre-existing, author's note): the session reads client messages only on the
  empty-queue path. Under steady traffic, an `unsubscribe` or a close frame from the client is not
  read until its queue drains. Liveness (rule 32) is also judged only there. This does not let a
  client stay connected without bound. A client that never answers pings and keeps its queue
  non-empty either reads TCP (each send completes) or does not (a send times out after
  `2 × tick_ms`, and the session is dropped). If it reads more slowly than the traffic arrives, it
  overflows and gets 1008. In every case the maximum age closes it, now that M-1 checks the age on
  every turn. Only the client's own subscription is affected. A pong that arrives while the queue is
  busy is read before the liveness timeout is judged, because `recv` comes before `sleep_until` in
  the biased `select!`, so a busy but live client is not closed with 1001 for that reason.
- **I-11**: the ping send is not raced against the age or idle deadlines, only against shutdown. A
  connection can outlive `ws_max_age_ms` by at most `2 × ws_ping_interval_ms`. This is bounded.
  Nothing to do unless the age becomes a hard guarantee.
- **I-12**: the start-up error drops the cause (`"index read failed"`). If the index reader already
  logs `index_read_failed`, this is harmless; otherwise, carry the index error kind into
  `StartError` so that an operator can tell a corrupt index from an I/O error.
- **I-13** (test coverage, author's notes): there is no test for L-3 or for the failed-head branch.
  The L-2 integration test passes on the old code because `tests/common/mod.rs` calls `hub.start()`
  itself rather than going through `sbtp_relay::run`/`serve`. A regression that removes the call
  from `serve` would therefore not be caught. A startup test through `run` that opens a subscription
  after more than 256 accepted blocks, and checks that no `fanout` gap is reported, would pin it.
- **I-14**: `ALLOC_SLACK = 32` is argued for glibc. musl's mallocng and jemalloc have different size
  classes. jemalloc rounds 81 bytes up to 96, which is still within the slack. If the image changes
  allocator, re-check the constant or measure `VmHWM` as rule 35 already plans.

### Verdict of the re-review

**Mergeable.** M-1 and L-1, L-2, L-3, L-6 and L-8 are closed. The fixes introduce one low finding
(L-9, a skipped 1008 close in a narrow timing window, harmful only to the slow client itself) and
info notes. None is blocking. L-9 is a one-line fix and can be made before the merge or parked in
"Relay hardening (parked)" with the info items.
