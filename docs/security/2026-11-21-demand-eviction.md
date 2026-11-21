# Security review: network PoW difficulty (ADR 0045) and demand eviction (ADR 0046)

- Date: 2026-11-21
- Scope: `git diff 0c47d4c..12c0dc7` (merge of the ADR 0045 and ADR 0046 implementation on local
  `main`). Rules: `docs/decisions/0045-network-pow-difficulty.md`,
  `docs/decisions/0046-keep-by-default-demand-eviction.md`.
- Exposure: `crates/sbtp-relay` is network-exposed; a public relay runs behind Cloudflare with the
  cache bypassed on `/sbtp/v1/*` (deploy README before this change).
- Checks run: `cargo test --workspace` (all green), `cargo clippy --workspace --all-targets -- -D
  warnings` (clean). No dependency, `Cargo.lock`, `deny.toml` or CI change in the range.

## Verdict

**OK to push, with fixes before a release.** Nothing is blocking. The demand set, the hot path, the
race re-check and the headers hold. Two medium points are design gaps rather than coding bugs: the
first start of demand eviction with no demand history (M-1), and the write-flood exposure that ADR
0046 rule 21 accepts but that the `block_ttl_ms = 0` default makes more lasting (M-2). Both need an
owner decision; under the spec-first rule M-1 goes to an ADR clarification, not to a silent code
change. The low findings are narrow windows where rule 13 ("MUST NOT evict while a lost demand
could protect a block") is not quite kept.

## Findings

### M-1 (medium): demand eviction starts with no demand history after the upgrade or after `demand_eviction` goes from `false` to `true`

- `crates/sbtp-relay/src/index.rs:730-779` (`configure_demand`), `index.rs:446` (unclean mark),
  `crates/sbtp-relay/src/lib.rs:144-145`.
- Scenario A (upgrade): an index written before ADR 0046 gets `last_demand = epoch_start(received_at)`
  for every block. The index has no `open` key yet, so this first start counts as clean and nothing
  is suspended. If the store is above 90 % (or reaches it), the first sweeper run evicts in order of
  acceptance, not of demand. A block that was read every day until the upgrade is treated as last
  demanded when it was accepted, and is evicted at once if it was accepted at least `3 × E` ago.
- Scenario B (transition): with `demand_eviction = false`, the relay records no `GET` demand
  (`Demand::touch` returns early) and sends the one-year shared `Cache-Control`. When an operator
  turns it on, `last_demand` reflects only acceptances and children. Reads from the "off" period are
  invisible. Worse, a CDN that cached responses under the old one-year `s`-lifetime keeps serving
  them for up to a year without revalidating, so the origin never sees that demand. This is exactly
  the "a CDN hides demand" case the owner rejected.
- Impact: popular blocks are evicted first. This is local and recoverable through re-publication and
  archive relays, so it is not data loss for the network. Today's public relay bypasses the
  Cloudflare cache, so only scenario A applies to it, and only if its store is near the high-water
  mark when it is upgraded.
- The ADR's implementation plan asks for "`received_at` quantised", so the code follows the text.
  The gap is in the ADR: rule 13 covers demands that were *lost*, not demands that were *never
  recorded*.
- Fix (ADR clarification first): treat "no demand history" as a lost demand. Either set
  `last_demand` to the current epoch for every block during the migration, or suspend for `2 × E`
  after it. Persist the last `demand_eviction` value in `META`, and on an off-to-on transition do the
  same as for the migration. In `deploy/README.md`, require a purge of `/sbtp/v1/block/*` on the CDN
  when turning demand eviction on for a relay that used to serve the one-year shared lifetime.

### M-2 (medium, accepted by ADR 0046 rule 21; for the owner): a write flood evicts cold blocks on `small`, then pins the store

- `crates/sbtp-relay/src/config.rs:95` (`block_ttl_ms` default 0), `:97` (1 GiB), `:99` and `:125-126`
  (`sweep_batch` 1,000, `rate_put_per_min` 30, burst 20); `crates/sbtp-relay/src/sweep.rs:291-410`.
- Figures for the defaults (`small`, estimates). A full-size block costs about 70 KB of quota. One
  client key can write about 2.1 MB per minute, so filling 1 GiB takes about 8 hours from one key,
  or about 5 minutes from 100 keys (100 IPv6 /64s from one /48). The proof of work at 16 costs
  milliseconds. The sweeper evicts at most 1,000 blocks per 60 s, about 66 MB per minute at full
  size, so about 32 or more flooding keys outpace it, and everyone else gets `507` while it does.
- What the attacker can evict: every block whose last demand is at least `3 × E` old (3 to 4 days
  by default), coldest first. Anything requested in the last `E`, and every block accepted in the
  last `3 × E`, survives (verified: `sweep.rs:319`, `index.rs:811-842`, tests
  `three_epochs_protect_to_the_millisecond` and `popular_blocks_survive_and_cold_blocks_go`). By
  warming every other cold block first (one `GET` each, listed through `/query`), the attacker can
  also choose which cold block goes.
- What changed compared with before: with a 30-day TTL and no demand eviction, a flood gave `507`
  until the junk expired, and no legitimate block was deleted. Now cold legitimate blocks are
  deleted. The junk also never expires as long as the attacker keeps it warm, which costs about
  16,000 `GET`s per day for 1 GiB, well inside the `block` allowance. A single relay can therefore be
  kept write-full indefinitely and cheaply.
- Not a bug: rule 21 accepts it, and reads and other relays are unaffected. Recommended: a public
  relay sets a `block_ttl_ms` as an outer bound, or alerts on `demand_evicted_blocks_total` and
  `storage_full_total`. Record a per-client storage share as an open question for a later ADR.

### L-1 (low): a clean restart cancels a running suspension

- `crates/sbtp-relay/src/demand.rs:210-211, 340-355`; `crates/sbtp-relay/src/lib.rs:195`.
- Scenario: a demand is lost at `t0` (the set was full, or a flush failed), so eviction is suspended
  until `t0 + 2E`. The operator restarts cleanly at `t0 + 1 h`. The index is marked clean, the
  suspension, which lived only in memory, is gone, and the block whose demand was lost can be
  evicted before `t0 + 2E`. The proof of rule 13 does not hold across a restart. The ADR says
  "kept in memory", so this is again a spec gap.
- Fix: write `suspended_until` into `META` in `mark_clean` and restore it at open. Alternatively, do
  not mark the index clean while a suspension is running.

### L-2 (low): a demand pass does not stop when a loss suspends eviction during the pass

- `crates/sbtp-relay/src/sweep.rs:304` (checked once per run), loop `sweep.rs:351-374`;
  `crates/sbtp-relay/src/blocks.rs:206-223` (`put_demand`).
- Scenario: a pass lists up to 1,000 candidates. While it runs, a `PUT` answered `200` for candidate X
  fails its demand write (rule 14 loss), or a `GET` of X finds the set full. Eviction is now
  suspended, but the loop does not look again. It takes X's lock, finds X absent from the set and its
  index `last_demand` still old, and deletes it. A client has just been told `200` (or served the
  block) and the block is gone. This is the case rule 13 forbids with a MUST. The window is short and
  needs an index write failure or a full set, so it cannot be aimed at a chosen block in a useful
  way.
- Fix: check `demand.suspended(clock())` (one atomic load) at the top of each iteration in
  `demand_apply`.

### L-3 (low): a forced or timed-out drain is marked clean although demands can still arrive after the last flush

- `crates/sbtp-relay/src/server.rs:382-396` (`serve` returns `Ok` on the `deadline` and `forced`
  phases, and leaves connection tasks running until the runtime is dropped);
  `crates/sbtp-relay/src/lib.rs:349-356, 195`.
- Scenario: `SIGTERM` is followed by a second signal, or the drain deadline passes. Handlers still in
  flight call `Demand::touch` concurrently with, or after, the final `flush_demand`. Identifiers added
  behind the flush cursor or after it are dropped with the process without being counted as lost,
  and the index is marked clean, so the next start does not suspend. In effect, one or a few demands
  are lost silently.
- Fix: treat `deadline` and `forced` as not clean (return a value from `server::serve`), or close
  the demand set before the final flush (later touches are counted as lost) and require it to be
  empty afterwards.

### L-4 (low): `Retry-After` on `507`: conflict on paper with ADR 0023 rule 18, and sent when no room is coming

- `crates/sbtp-relay/src/blocks.rs:811-816`; `crates/sbtp-relay/src/error.rs:96-98` (the doc comment
  still says "No `Retry-After`").
- ADR 0046 rule 8 (MAY) is later and accepted, so the behaviour is allowed. However, ADR 0046's
  "Amends" list does not name ADR 0023 rule 18 ("not sent by the reference relay"), so the two
  records contradict each other as written.
- The header is also sent while rule 13 suspends eviction (up to `2 × E`) and after `demand_stuck`.
  In both cases the sweeper frees nothing in `sweep_interval_ms`, so the header invites clients to
  retry every minute instead of going to another relay, which is the concern behind ADR 0023 rule
  18. The added load is bounded by the `put` limits, so the harm is small.
- Fix: add "ADR 0023 rule 18" to the Amends list of ADR 0046 and update `error.rs:96-98`. Send
  `Retry-After` only when eviction is not suspended and the last run was not stuck.

### Info

- **I-1. A `GET` racing the deletion.** `blocks.rs:967` touches after the response is built, outside
  the `block_id` lock. A child insert refreshes its parent under the child's lock (`index.rs:557`).
  If `demand_apply` checks X just before such a touch or refresh, X is deleted at the instant it was
  served or gained a child. This race is inherent to a lock-free read path. The block had been cold
  for `3 × E` until that moment. Accept it.
- **I-2. The admission total includes `index_reserve` (about twice the index file), which eviction
  never reduces** (redb does not shrink its file): `store.rs:391-394`, `sweep.rs:352, 390`. If the
  reserve alone ever exceeded the low-water mark, each run would keep deleting candidates until none
  were left. With blocks charged at least 4 KiB each this looks out of reach, but the index size per
  block is not measured. Cheap guard: end the draining state when a run deletes files and the total
  does not fall.
- **I-3. `demand_candidates` (`index.rs:817`)** applies `take(max)` before skipping order entries
  that have no row. Orphan order entries could only come from corruption, but `sweep_batch` of them
  would keep the pass stuck at the head. Skip them before counting.
- **I-4. The migration** (`index.rs:730-779`) is bounded and resumable: 10,000 blocks per durable
  transaction, already-filled blocks skipped. A crash part-way through is an unclean start (the
  `open` key is written durably at open), so eviction is suspended. Verified by reading the code and
  by `demand_migration_fills_old_indexes_once`. It runs before the relay listens and logs nothing
  about its progress. Log the count and duration, so that a supervisor restart loop on a large index
  can be diagnosed.
- **I-5. Memory.** The layout bound is `memory_bytes(16,384) = 1,081,344` bytes: 32 bytes for each
  of 2 × `max` slots, plus one flush chunk. The ADR's estimate was 786,432. The computed `small`
  worst case is 14,747,092 bytes, 252,908 bytes under 15 MB, and is checked by
  `small_profile_memory_bound_is_under_15_mb`. The figures in ADR 0046 rule 25 (13,805,012) are
  stale; update them with the next ADR touch. There is no growth path: the table is allocated once,
  `insert` refuses at `max`, and the load is at most 50 %, so `find` always ends. Only one flush
  buffer is live at a time.
- **I-6. Privacy with demand eviction off.** `touch` and `put_demand` record nothing, and the tables
  only hold acceptance times and child acceptances, which the index already reveals through
  `received_at` and the edges. What stays is the read data from an earlier period with eviction on.
  Acceptable, and documented in `deploy/README.md`.
- **I-7. The JavaScript copy of `D_NET`** (`web/src/relay.js`) is pinned at 16 by
  `web/tests/checks.test.mjs`. A future change has to touch both.

## Author's decisions, judged

- **Watermarks compared with the `PUT` admission total.** Correct. Eviction makes room before `PUT`s
  get `507` (see I-2 for the one degenerate case).
- **Parent refresh inside the child's insert.** Fine. It costs at most 8 extra demand updates per
  insert, skipped when the parent is already at the current epoch, so it cannot be amplified. See I-1
  for the race.
- **Set entries recorded at the epoch of the latest touch.** Safe. It can only move `last_demand`
  later, never earlier.
- **Flush in transactions of 1,024 entries.** Fine. The writer queue is `put_max_in_flight + 1` and
  the sweeper is its only writer without a `PUT` permit, so a chunk is never refused under load. A
  failed chunk is counted and suspends eviction.
- **Clean mark only on full success.** Correct direction. L-3 is the case where "success" is too
  broad, and L-1 the case where it is enough to lose state.
- **Tables maintained with demand eviction off.** Acceptable for privacy (I-6). Combined with M-1,
  the data they hold is misleading at an off-to-on transition.

## Verified without finding

- **Demand set** (`demand.rs`): the bound is fixed and allocated once (`try_reserve_exact`). Slots
  are hashed with keyed SipHash (`RandomState`), so a ground `block_id` gives no control over
  probing. The empty slot is unreachable for a real block (`EMPTY` needs 256 zero bits). Removal by
  backward shift is correct, and `drain_chunk` looks again at the cursor slot after a shift; the
  tests drain all 3,000 identifiers exactly once.
- **`GET` hot path:** one short lock, no index access. Only identifiers the relay held and served
  reach the set, so a flood of `404`s cannot fill it.
- **Race re-check in `demand_apply`:** it runs under the `block_id` lock and checks three things:
  not in the set, same position, `last_demand ≤ bound`.
  - A `PUT` answered `200` records its demand in the index under the same lock before replying
    (`blocks.rs:368-374`).
  - A re-acceptance moves the block to a new position, so the check skips it.
  - A `PUT` that falls between the file deletion and the batched index removal takes the create path
    (the file is gone). Its insert replaces the stale entries, and the later `remove(P1)` is
    idempotent and leaves `ids[X]` alone when it points elsewhere (`index.rs:957-984`).
  - The earlier M-1 fix (bump after insert) is not involved, because the demand path reads the index
    under the lock instead of using generations.
  - All flushes run on the sweeper task, so none is in progress while a pass checks the set.
- **Suspension lever (rule 21):** to fill the set, an attacker must serve `demand_touch_max / 2` =
  8,192 distinct held blocks within one writer delay, under the `block` limit of 50 per second per
  key. The worst moment is during a long sweeper run, when the flush request waits; that needs on the
  order of 100 keys. The result is `507` on new blocks, never deletion, and M-2 already gives the
  same result more cheaply. Low as designed.
- **Headers:** `S = E/2` is at least 7,200 s within the settings range. `Cache-Control` with
  `s-maxage=S` and `immutable`, plus `CDN-Cache-Control` with `max-age=S` and `must-revalidate`, are
  sent on both `200` and `304`. With eviction off, the one-year header is sent and
  `CDN-Cache-Control` is absent. Tests: `crates/sbtp-relay/tests/blocks.rs:100`, `sweep.rs:1048,
  1327`. `If-None-Match` uses the weak comparison, so Cloudflare's weakened ETags still get `304`.
- **Logs and metrics:** `demand_evicted`, `demand_stuck` and `demand_suspended` carry counts,
  durations and a cause only. The new gauges hold counts and one timestamp (`demand_coldest_ms`). No
  `block_id` or client key appears anywhere.
- **ADR 0045:** the default `min_pow_difficulty` reads `sbtp_core::NETWORK_POW_DIFFICULTY`, and
  `pow_above_network` warns above 16. The CLI and the web client mine at `max(16, highest /info)`, a
  value read from `/info` is still capped at 24 (ADR 0029 rule 13), and an explicit difficulty is used
  as given. A hostile `/info` cannot push the client above the cap.
- **Configuration:** `low < high` is enforced, and `parse_bool` accepts only `true` or `false`.

## Not checked

- Cloudflare's real behaviour (documented facts only): whether `CDN-Cache-Control` and `s-maxage`
  are honoured below 2 h on the Free plan, whether stale entries are served on a `429` or `503`
  revalidation, and whether tiered topology really puts at most two caches in series.
- redb file growth steps and the index bytes per block (I-2, M-1 sizing). There was no measurement
  on a large index, including the migration time.
- No fuzzing or load test of the demand set under contention on the `large` profile.
- The mirror tool of ADR 0045 rule 6 is not in this range.
