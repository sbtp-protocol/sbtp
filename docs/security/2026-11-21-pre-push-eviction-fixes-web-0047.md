# Security review: demand-eviction fixes (ADR 0046 D1-D6), web client ADR 0047, deploy README

Date: 2026-11-21. Range: `origin/main` (7caedba) to `main` (dd70e56), code under `crates`, `web`,
`deploy`. Spec and ADR text are used as rules only.

## Verdict

**OK to push.** No critical, high or medium finding. One low finding (L-1, a liveness regression of
the D6 "deletion did not lower the total" check under concurrent writes) is worth a small follow-up
fix; it is not exploitable beyond what a write flood already achieves (ADR 0046 D8, ADR 0049) and it
heals itself. The rest is informational.

Checks run on `main`:

- `cargo test --workspace`: all green (relay unit 137, integration suites green, 1 timing test
  ignored by design).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `web/build.sh` and `node --test tests/*.test.mjs`: 54 pass, 1 skipped (end-to-end test that needs
  `SBTP_RELAY`).

## Findings

### L-1 (low): the D6 end-of-run check compares `admission_total`, which concurrent `PUT`s move

`crates/sbtp-relay/src/sweep.rs:393` and `:400`.

```rust
let before = store.admission_total();
match relay.evict_locked(&id) {
    Ok(deleted) => {
        ...
        if deleted && store.admission_total() >= before {
            break;
        }
```

`admission_total()` is `used_bytes()` plus the index part, and the index part is a fresh
`fs::metadata` of the redb file. Between the two reads, `PUT`s of other block ids are accepted
(the sweeper holds only the lock of this id) and the index writer commits, which grows `used` and
can grow the redb file (its reserve counts the growth up to twice). Scenario: a relay above the
high-water mark with a steady write rate (no attacker needed; a flood makes it certain). A `PUT`
whose accounting lands inside the window of one deletion makes `after >= before`, and the pass ends
after that deletion. At a few hundred `PUT`/s the pass ends after a handful of deletions; eviction
falls to a few blocks per `sweep_interval_ms`, the store climbs to `max_store_bytes`, and new
blocks get `507`, still with `Retry-After` (the pass was not stuck), which is the misleading hint
D5 meant to remove. When writes stop, the next passes drain normally.

Effect: availability of `PUT` on a busy demand-eviction relay; no data loss, no protection lost.
The intent of D6 ("a deletion that did not lower the stored total") is about the block part only.

Fix: compare `store.used_bytes()` before and after the deletion (or check that `evict` reported a
non-zero freed size), and keep `admission_total()` for the low-water loop condition. A test with a
concurrent `PUT` between listing and deletion would pin it.

### I-1 (info): a restored `suspended_until` is not capped

`crates/sbtp-relay/src/demand.rs:392`. The stored end is absolute wall-clock time. A loss recorded
while the clock was wrong far forward (bad NTP, manual date), then a clean stop, restores a
suspension that can last years. Safe direction (nothing is deleted), visible in `duration_ms` and
in the new `demand_suspended` alert of `deploy/README.md`. Optional fix: restore
`min(stored, now + 2 × E)`, which D2 allows in substance since no single cause lasts longer.

### I-2 (info): a relay-supplied error name can carry line breaks into the page

`web/src/relay.js:138` keeps up to 64 characters of the relay's `error` string as is;
`web/src/delivery.js:66` stores it in the delivery record, and `describeDelivery` and `perRelay`
join lines with `\n` into a `<pre>`. Everything goes through `textContent` (`app.js` `say`,
`showStranded`), so there is **no XSS**, and the CSP (`default-src 'none'; script-src 'self'
'wasm-unsafe-eval'`) holds. A hostile relay can only fake a line such as
`https://other-relay: acknowledged` in the text output; the stored states and the eviction decisions
do not depend on the string (only `TimestampTooFarInFuture` on `400` is matched, exactly). Optional
fix: keep `[A-Za-z0-9_-]` only in `errorName`.

### I-3 (info): a fetched copy that becomes own bypasses `storeMaxPending`

`web/src/store.js:70`. The `existing && own && !existing.own` branch adds 1 to `pending` without
the cap check that the new-block path has. Pre-existing behaviour, kept by this change. It needs the
user to sign a block whose id is already stored as fetched, so it is bounded by the user's own
blocks; not attacker-reachable. Optional: apply the same check.

### I-4 (info): orphan order entries at the head stall every pass for good

`crates/sbtp-relay/src/index.rs:880`. With at least `ORPHAN_SCAN_MAX` (10,000) orphan entries
before the first real candidate, every listing returns no candidate and every pass is `demand_stuck
cause=no_candidate` with `orphans=10000`. The bound does what I-3 asked (short read transactions);
the stall is corruption-only, logged, and the README says to look at `demand_stuck`. A distinct
cause (`orphans`) would point the operator to an index rebuild faster.

### I-5 (info): `no_history` wording in `deploy/README.md`

`deploy/README.md:129` says the cause applies to "the first start after the upgrade that added
demand tracking". It also applies to the first start of this build on an index already migrated by
`origin/main` (no `demand_eviction` record yet, `previous = None`, index not empty): every relay
running the current `origin/main` with demand eviction on gets a one-time `2 × E` suspension when it
upgrades. Correct and conservative (the code comment in `demand.rs` says so), but an operator should
expect it. Suggest "the first start after an upgrade that added demand tracking or this record".

### I-6 (info): multi-tab `pending` drift is transient

Between a list change saved in tab B and the `storage` event reaching tab A, a `recordPublish` in A
computes its `pending` delta against A's old list. IndexedDB serialises the transactions, and A's
`setRelays` (triggered by the event through `announceRelays`) recomputes the totals from scratch
right after, so the drift lasts milliseconds. If `localStorage` is unavailable, each tab keeps its
own list and the last `setRelays` wins; the 200 cap may be off by the difference until the next list
change or reload. Not worth more.

## What was checked and found sound

**Relay (ADR 0046 D1-D6, I-3, I-4).**

- D1: `demand_start` (`lib.rs`) reads the unclean mark and the stored end, runs the migration, then
  records `demand_eviction` durably, before the pool and the listener. Field order matters and is
  right: a migration that fails or crashes leaves no record, so the next start sees `previous =
  None` and suspends (`no_history`) even if the migration then reports `filled = 0`. `empty` is
  computed after the reconcile walk, so a rebuilt index with files is suspended and a new empty one
  is not. Off-to-on suspends; on-to-on does not.
- D2: `mark_clean(until)` writes `suspended_until` and `open = 0` in one transaction; the value is
  read after `serve` returns, which includes the final flush, so a loss in that flush is either in
  the value or makes the stop unclean.
- D3: `suspended_at` is checked under the id lock for every candidate; a `PUT` `200` whose demand
  write fails calls `lost` under the same lock (`blocks.rs` `put_demand`).
- D4: `server::serve` returns `Drain`; only `Drained` plus `durable.is_ok()` plus a flush with no
  loss writes the clean mark. `Deadline` and `Forced` leave the index marked open.
- D5: `retry_after_useful` requires on, not suspended, not stuck; the high-water check stays in the
  caller. `stuck` is set by both stuck causes and cleared by a deleting pass or at the low-water mark.
- D6 guard: `index_reserve_bytes() >= low` deletes nothing and reports `cause=index` (see L-1 for the
  second half of D6).
- I-3: the orphan scan is bounded and orphans no longer count toward `max`. I-4: migration lines
  carry counts and durations only, no `block_id`.
- `Sbtp-Replication: 1`: handled only in `Relay::block_response`, after routing, the read semaphore
  and any rate limiting, so it bypasses none of them. It removes demand recording and makes the
  response `no-store` for both headers (`200` and `304`, demand on and off). Abuse value: a client
  can only decline to protect a block it reads, which it could do by not reading. On a CDN miss the
  `no-store` answer is not cached, so it cannot poison or pin a cache entry; on a hit the CDN answers
  from its entry, which was counted when stored. Only a CDN rule that overrides origin cache headers
  (edge TTL "ignore origin") would cache it, and such a rule already breaks rule 16 for every
  response; the README does not suggest one. Exact match on `1`; other values are ordinary reads.

**Web client (ADR 0047).**

- Bounds against a hostile relay: `settle` is a pure function evaluated at read time in every
  decision (`protection`, `deliveryTargets`, `planEviction`, `retryPlan`), so no stored state has to
  be refreshed for a bound to apply. Once one relay of the list acknowledged, a pending relay is
  given up after 5 attempts and 24 h, and in any case 7 days after the first acknowledgement. The
  7-day bound does not depend on attempts, so a relay that forces `backing-off` (huge `Retry-After`)
  or keeps the client aborting cannot extend it. Unknown statuses, unknown error names and malformed
  answers are `transient` (counted); other `4xx` and `3xx` are final. A relay can never move an
  acknowledged entry back to pending while it stays in the list. A block no relay acknowledged stays
  protected, as designed, under the 200 cap.
- `totals.pending` counts `UNACKNOWLEDGED` own blocks, which depends on the list but not on time, so
  the running count is stable between list changes. `put`, `recordPublish` (before/after delta),
  `delete`, `clearFetched` and `setRelays` (full recompute) are consistent; eviction never drops an
  `UNACKNOWLEDGED` block, and step 3 drops only `PARTIAL` blocks, which are not in the count.
- `eviction.js`: fetched, then delivered own, then (own incoming only) partial by oldest first
  acknowledgement; never unacknowledged.
- Migration: `acked = false` maps to pending everywhere; `acked = true` was already evictable, so the
  mapping loses no protection. Until `setRelays` rewrites a record, the on-the-fly `ackedAt = now`
  only delays the 7-day bound. An old cached tab writing the old fields next to a new record errs on
  the protective side (old code treats a record without `acked` as pending).
- Export: `Blob` with `application/octet-stream`, `download` attribute, hex id as file name, bytes
  re-validated with `verifySubmitted` first, URL revoked after 10 s; no CSP relaxation was needed.
- No new `innerHTML`-style sink in `web/src`.

**`deploy/README.md`.** Causes, alert signals and stats fields match the code (`refused_507`,
`demand_evicted`, `demand_lost`, `demand_suspended` exist in `metrics.rs`). The Cloudflare purge
order (restart with demand eviction on first, then purge within `2 × E`) matches D1 and is correct.
Only I-5 above.

## Not checked

- Behaviour against a real Cloudflare zone (purge by prefix availability, handling of `no-store`
  with the account's actual cache rules).
- The browser runtime: the web tests run in Node with a fake IndexedDB (`tests/fake-idb.mjs`); real
  `storage` event delivery, Blob downloads under the CSP and quota behaviour were not exercised.
- Long-running load: L-1 is from reading the code, not from a measurement.
- `cargo deny check` and `cargo audit` were not run (no dependency change in this range).
