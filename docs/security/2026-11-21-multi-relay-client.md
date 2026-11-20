# Security review: multi-relay publish and read with failover (web client, cli-demo)

- Date of the review: 2026-11-21.
- Scope: merge `2b30c5b` on local `main` (branch commit `d9c4579`), read as
  `git diff 13f2ec2..2b30c5b -- web examples/cli-demo docs/spec` (13 files, +1,703 -200).
- References: spec `sbtp-core-v0.2.md` §3.4 and §4 ("Admission control", "Client bounds", the new
  non-normative "Several relays"); ADR 0026; ADR 0029 (rules 10, 13 to 16).
- Method: reading of the diff and of the code it calls (`web/src/walk.js`, `relay.js`, `http.js`,
  `wasm.js`; `examples/cli-demo/src/walk.rs`; `sbtp-core` `validate_requested`). `cargo test -p cli-demo`
  (41 unit + 20 e2e, all pass); `web/build.sh` then `node --test tests/*.test.mjs` (39 pass, 1 skipped:
  the end-to-end test needs `SBTP_RELAY`). No dependency, `Cargo.lock` or CI file changed, so
  `cargo deny` was not re-run for this review.

## Verdict

**OK to push with one fix recommended first (M-1).** No critical or high finding. The properties that
matter most hold: every fetched block goes through `validateRequested` / `validate_requested` (R1, then
C1 at the client's own floor, then C2 and C3) whatever relay served it; an invalid block is never stored
or printed; the receipt floor is never taken from `/info`; mining uses the highest `/info` difficulty
capped at 24; a cursor never reaches a relay other than the one that issued it. M-1 is a regression of
an existing bound in a long-running mode of the CLI, and a spec MUST; it is small to fix.

| Id | Severity | Subject | Blocking |
|---|---|---|---|
| M-1 | medium | CLI `query --follow` with several relays keeps polling a relay whose walk failed: ignores a long `Retry-After`, and the dedupe sets grow without bound | fix before push recommended; not a hold |
| L-1 | low | Web `fetchOne` uses a snapshot of `available()`: a concurrent worker can contact a relay inside its `Retry-After` | no |
| L-2 | low | Web `walkAll` merges in list order with one 200-id budget: the first relay can fill the whole view (and with bogus ids, exhaust the GET budget) | no |
| I-1 to I-6 | info | See below | no |

## Findings

### M-1 (medium): `query --follow` re-walks a failed relay every interval

`examples/cli-demo/src/commands.rs:536-590`. With several relays, a walker whose `walk()` returned an
error is only reported as a warning (`failures`, line 579 exits only when *every* relay failed in the
same round), and the next `--follow` round, `interval` seconds later (1 to 3600, default 10), calls
`walk()` on it again. Before this change a single-relay failure ended the command, so these paths were
terminal; now they are not.

Two consequences:

1. **Retry-After not obeyed (spec §4 "Admission control": "A client MAY give up on a relay whose
   `Retry-After` exceeds its maximum wait; it still does not repeat the request to it earlier").**
   Scenario: relay B answers `503` with `Retry-After: 3600`. `Walker::walk` (`walk.rs:316-324`) gives up
   because 3600 s is above `max_retry_after` (300 s). The command continues on relay A, and 10 s later
   sends B the same request again, then again every interval. The same holds for any fatal refusal of
   B (a `4xx`, `InvalidCursor` without a cursor, no progress): B is polled for the life of the process.
   The cost to B is one request (up to seven with transient retries) per client per interval: a
   protocol violation more than a real flood, but exactly the case the spec rule exists for.
2. **The memory bound of the dedupe sets no longer holds over time.** `max_seen` is split
   (`commands.rs:524`, `MAX_SEEN / n`), and `take_page` (`walk.rs:218-233`) inserts the whole page
   *before* checking `seen.len() > max_seen`. When a relay's walker passes its share it fails, but the
   next round walks it again from its cursor, inserts one more page into its `seen` and into the shared
   `printed` set (`commands.rs:532`, which has no bound of its own), and fails again. Scenario: a hostile
   relay in the list serves endless distinct fake `block_id`s; once its share (125,000 with 8 relays) is
   reached, each round adds up to one page (`--limit`, at most the relay's `max_query_limit`) to both
   sets, forever, as long as one other relay is healthy. Growth is bounded per unit of time by the
   user's `--limit` and `--interval` (for example 100 ids per 10 s, about 1 MB per hour for both sets),
   so this is a slow leak, not a crash on demand; but it removes the bound the author relied on
   ("dedupe set split between relays plus the shared printed set"). Within one round the total is
   bounded (sum of shares plus one page per relay, times two for `printed`), which is fine.

Fix: retire a walker for the rest of the run after a terminal failure (`max_seen` exceeded, fatal
refusal, `Retry-After` above the maximum, no progress), and end the command when every walker is
retired. If a retired relay with a long `Retry-After` should come back, keep a per-relay `not_before`
instant and skip it until then. Add an e2e test with two relays where one answers `503 Retry-After:
3600` under `--follow`, and a unit test that a failed walker is not called again.

### L-1 (low): `fetchOne` can contact a relay inside its `Retry-After`

`web/src/relays.js:249-257`. `candidates = set.available()` is computed once, then each candidate is
asked in turn with `await`. `fetchBlocksFrom` runs up to 4 workers on the same `RelaySet`. Scenario:
worker 1 is waiting for relay A's 404 on id X; meanwhile worker 2 gets `429 Retry-After: 30` from relay
B, which sets `B.until`. Worker 1 then moves on to B for X, within the 30 s. Worker 1's later ids
re-read `available()` and skip B, so the excess is at most about one GET per other worker (3) per
`Retry-After` received, beyond requests already in flight (unavoidable). The same snapshot shape exists
in `walkAll` (`relays.js:342`) but each walk only talks to its own relay, and `walk.js` obeys a
`Retry-After` from that relay itself, so there it does not matter.

Fix: in the loop, `if (set.waitMs(e) > 0) { tried.push({ base: e.base, backingOff: true }); continue; }`
before the GET, and a test with two workers where one receives a `Retry-After`.

### L-2 (low): the first relay can fill the merged view

`web/src/relays.js:357-370` with `web/src/app.js:259-261`. `onList` walks each relay up to 200 ids
(`perRelayMaxIds`) and merges in the user's order up to 200 in all (`maxTotalIds`). Relay 1 alone can
therefore take the whole budget, and the other relays contribute nothing. Scenario: relay 1 is hostile
(or simply large) and lists 200 ids. If they are bogus, every id gets a 404 from every relay;
`fetchBlocksFrom` spends up to 8 GETs per id and stops at its 800-GET budget after about 100 ids, and
the page shows "0 fetched, partial view": the honest relays' blocks are hidden. Nothing is unbounded and
no invalid data is accepted; this is availability only, the user can reorder or remove the relay, and
with one relay the situation was the same before. The CLI is not affected (it prints every relay's ids
in turn).

Fix (optional): merge round-robin across relays, or give each relay a share of `maxTotalIds`
(`ceil(maxTotalIds / n)`) before handing leftover room to the others.

### Info

- **I-1. Relay health is lost on save and reload** (`web/src/app.js:38`, documented in `relays.js:70`).
  A new `RelaySet` forgets every `until`, so a `Retry-After` received before is not obeyed after the user
  saves the list or reloads. User-initiated, one request per relay; acceptable for a demo client.
- **I-2. Relays that refuse a block permanently are retried on every click.** `publishAll` puts every
  non-acknowledging relay, a non-transient `4xx` included (for example a relay whose difficulty is above
  the block's), into `failed`, hence `failedOn` (`store.js` `recordPublish`); for a block no relay has
  acknowledged, `retryTargets` (`relays.js:379-384`) targets every relay, those skipped for difficulty
  above 24 included. Each "Publish pending blocks" click re-sends them. Bounded per click
  (`storeMaxPending` blocks, at most 8 PUTs each) and `failedOn` is capped at 16 deduplicated bases; only
  wasted requests. Optionally keep only transient failures in `failedOn`.
- **I-3. One success clears a relay's fault count** (`relays.js:101-105`). A relay alternating a valid
  and an invalid block never reaches the back-off threshold. The operation bound (800 GETs, every block
  validated) still holds, so it only costs validation work.
- **I-4. Relay list in `localStorage`** (`web/src/settings.js`). The list is re-checked on load
  (`parseRelayList`: `checkRelayUrl`, https or loopback http only, at most 8, at most 2,048 characters
  each; a bad value falls back to the default). A same-origin script could rewrite it, but such a script
  can already use the non-extractable signing key and read IndexedDB, so the list adds no capability.
  The CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline script) and the use of `textContent` for
  every relay-controlled string (no `innerHTML` in `web/src`) leave no XSS route in this change.
  `connect-src https:` is broad but pre-existing and needed for user-chosen relays.
- **I-5. One relay sets the mining cost for all.** `publishDifficulty` and the CLI `target_difficulty`
  mine at the highest `/info` value, each capped at 24 (ADR 0029 rule 13); a relay above 24 is left out,
  not mined for. A hostile relay can thus force difficulty 24 on every publish (seconds to tens of
  seconds of local CPU), as a single relay already could. By design; the page and the CLI show the
  difficulty used.
- **I-6. CLI walks relays one after the other.** A relay that answers slowly or with in-bound
  `Retry-After` values (up to 300 s, 6 retries) delays the listing of the others in each round.
  Availability only.

## Checked and found sound

- **Retry-After on the web paths.** `publishAll` checks `waitMs` per relay (`relays.js:209`);
  `publishDifficulty` asks `/info` only of available relays, and a relay that answered `/info` with a
  `Retry-After` is then skipped by `publishAll` as "backing-off"; the `/info` button checks `waitMs`
  (`app.js`, `main`); `onRepublish` goes through `publishAll`; `walkAll` asks only available relays and
  `walk.js` sleeps for an in-bound `Retry-After` or ends the walk, after which `set.fail` records it.
  `fail()` applies a `Retry-After` whether or not the error counts as a fault. Only L-1 escapes.
- **Fault attribution (`isRelayFault`).** Every outcome is recorded on the entry that produced it; no
  path blames relay A for relay B's bytes. A 404 and a non-transient `4xx` are not faults; an abort is
  never one. A hostile relay cannot cause the "refused" short-circuit for another relay's block:
  `validate_requested` checks R1 before C1 (`crates/sbtp-core/src/verify.rs:254-257`), so
  `InsufficientPow` only arises for bytes whose `block_id` is the requested one, a property of the id
  itself. Redirects are refused (`http.js`, `redirect` errors), so a relay cannot point the client at
  another relay's URL.
- **Validation and storage.** `onList` stores only `got.blocks` (validated by `verifyFetched` with
  `LIMITS.receiptDifficulty`); `onAncestors` stores only after `fetchOne` returned `ok`; local blocks are
  re-checked with `receive`. The CLI `get` validates each relay's answer before `write_fetched`. The
  receipt floor never comes from `/info` (ADR 0026).
- **Overall bounds (web).** At most 8 relays (`parseRelayList`, `RelaySet` constructor); 200 ids merged;
  200 blocks fetched; 800 GETs per list operation and per ancestors traversal (shared `budget`); 4 GETs in
  flight in all; walks bounded per relay; `failedOn` at most 16 entries; `retryPlan` at most
  `storeMaxPending` blocks per click.
- **CLI cursors.** `query_cursors` (`commands.rs:574-614`) splits at the last `=`, which is correct
  because the cursor alphabet has no `=`; the URL part is canonicalised with `Relay::new` and must match
  a `--relay` base; a second cursor for the same relay is refused; each cursor is placed at its relay's
  index and zipped with that relay's walker. A cursor cannot reach another relay. With one relay a
  `URL=CURSOR` value fails the cursor syntax check.
- **CLI publish.** At most 8 scoped threads, one per relay; a panicked thread becomes a failure; the
  retry hint prints only canonical bases and the local path.

## Not checked

- The web client in a real browser against several live relays (the end-to-end test was skipped, no
  `SBTP_RELAY`); browser-specific behaviour of concurrent fetches and connection limits.
- The CLI against a real relay sending `Retry-After` under `--follow` (M-1 is from reading the code, not
  reproduced).
- `cargo deny` and `cargo clippy` were not re-run: no dependency, lock file or CI change in the scope.
