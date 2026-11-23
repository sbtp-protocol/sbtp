# Fixes-only re-review: SBTP v1 relay (H-1, M-1 to M-5, L-1, L-7)

- Date: 2026-11-23. Reviewer: security auditor (independent; read the diff, `SPEC.md` §5 to §7,
  `PRINCIPLES.md` and the original report, not the authors' conclusions).
- Scope: branch `feat/relay-v1-fixes`, diff `81bbd18..HEAD` (3 commits): `crates/sbtp-relay/src`,
  `crates/sbtp-relay/tests`, `deploy/README.md`. Original findings:
  `docs/security/2026-11-23-v1-core-relay-review.md`.

## Verdict

**Mergeable before first public relay.** H-1 is closed and re-measured; M-1 and M-3 are closed;
M-2, M-4 and M-5 are closed for the scenarios of the original report, with residual risk that the
deployment notes now state. No new high or medium finding. R-L-1 (the `/48` budget is drained by a
single `/64`) is a two-line fix and should be done before the relay is exposed; the other new
findings are low or info and go to the roadmap.

Relay budget: 998 code lines (`cat crates/sbtp-relay/src/*.rs | grep -vcE '^\s*$|^\s*//'`), under
1,000. No dependency change (`Cargo.toml` and `Cargo.lock` untouched).

## Checks run

| Check | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | 59 passed, 1 ignored (benchmark) |
| `cargo deny --offline check` | advisories, bans, licenses, sources ok |
| Scratch probe (outside the repository, release build, Apple Silicon, warm cache; store seeded directly in the new table layout, relay driven over loopback HTTP and WebSocket) | figures below |

## Original findings

| ID | Status | Basis |
|---|---|---|
| H-1 | **Closed** | Re-measured, see below. |
| M-1 | **Closed** | Re-measured, see below. |
| M-2 | **Closed** for one client address; residual low (R-L-1, R-I-5) | Code review and probe. |
| M-3 | **Closed** | Code review; test `unreadable_or_malformed_deny_list_refuses_to_start`. |
| M-4 | **Partially closed** | Warning and documentation done; a missing header still falls back to the proxy. |
| M-5 | **Closed with an operator step** | Sidecar detects an in-place file restore; directory or volume rollbacks rely on the documented `restored` marker. |
| L-1 | **Closed** for the detached-scan scenario; frame-rate cap not done | Code review. |
| L-7 | **Mostly closed** | Tests added for M-3, the `429`/`503` caps, a long denied run, deny list in catch-up and live, `relay_id` after restore. Still untested: close code `1011`, the live-path deny filter (a block denied after it was queued). |

### H-1: closed

`store.rs:269-292`: `page()` now stops after `limit × 4` entries examined, denied ones included, and
returns `since` = last examined with `more = true`. `/info` reads an `AtomicU64` (`served`) updated
in `put` and recomputed by `set_deny` once per reload and at startup (`store.rs:143-159`), both
under the write lock. The deny check reads the 64-byte `LOG` entry, never block bytes.

Measured, one served block, a denied run of N blocks by one key, one more block (denied for the
`/info` case, served for the subscribe case):

| | Before (original report, N = 3,000 × 60 KB) | After, N = 3,000 × 60 KB | After, N = 200,000 × small |
|---|---|---|---|
| `GET /info` | 57 ms | 0.33 ms | 0.33 ms |
| `GET /query?since=1&limit=1` | 27 ms | 0.25 ms (`since` 5, `more` true) | 0.25 ms |
| `GET /query?since=1&limit=1000` | (not measured) | 0.68 ms | 0.83 ms (`since` 4001, `more` true) |
| `/subscribe?since=0`, catch-up through the run | (linear, full bytes) | 0.5 ms | 33 ms per connection |
| Startup (`set_deny` scans back over the denied tail) | | 18 ms | 50 ms |

Per-request cost of `/info` and `/query` no longer depends on the run. Subscribe catch-up still
walks the whole run once per connection (inherent: the client asked for everything), at about
165 ns per denied entry; see R-L-2.

### M-1: closed

`LOG` is now `position → (block_id, pubkey)`, block bytes are in `BLOCKS`. Measured on 1,000 served
60 KB blocks: `/query?since=0&limit=1000` **1.24 ms** (was 18.8 ms), `limit=1` 0.45 ms.

### M-2: closed for one client address

`http.rs:177-181`: a per-client budget of 32 KiB/s (4 MiB burst) and a per-/48 budget 8× larger, in
body bytes, valid or not, before any CPU is spent. One address now needs about three days to fill the
8 GiB default quota, one /48 about nine hours. A botnet or many /48s still fill the disk eventually
(no eviction by spec); that is the residual risk of any quota without eviction, and the deny list
plus more disk remain the operator's answer. See R-L-1 for a defect in how the two budgets combine.

### M-3: closed

`lib.rs:178`: a deny list that exists but does not read or parse makes `run` fail; a missing file is
an empty list (`limits.rs:133-136`). Reload behaviour is unchanged (previous list kept).

### M-4: partially closed

Done: a startup warning when the header is set on a non-loopback listener or unset on a loopback one
(`lib.rs:182-187`); `ip:port` and `[v6]:port` parsed (`http.rs:128-131`); proxy settings documented
with an nginx example that overwrites the header (`deploy/README.md`). Not done: a request whose
configured header is missing or unparseable still counts as the proxy's address
(`http.rs:133`), so one proxy route that forgets `proxy_set_header` (a common slip on the WebSocket
location) collapses every client of that route into one bucket. With the new PUT budget the collapse
is sharper: 32 KiB/s of `PUT` for the whole relay. Low on its own now that the warning and the notes
exist; the original recommendation (a separate, small "unknown" key) still stands.

### M-5: closed with an operator step

`store.rs:94-124`: three signals redraw `relay_id`: a new inode, a sidecar `relay.position` showing a
greater position than the store (file restored in place: the original scenario of `cp` or
`rsync --inplace` over `relay.redb`, tested), and an operator marker file `restored`. The sidecar is
written after the commit and never fsynced; a lost or torn write only weakens the check, it cannot
cause a false redraw (the database is always at least as far as the sidecar). Checked for harm: a
marker that cannot be deleted redraws at every start (clients resync from `0`, not a safety issue); a
sidecar from another store is ignored (id mismatch); positions continue after the restored maximum
under the new id, as the spec allows.

Residual false negative: the sidecar lives inside the data directory, so restoring the **whole
directory in place** (`cp -a backup/. data/`, `rsync --inplace -a`, a snapshot rollback) rolls it back
too and nothing is detected unless the operator creates `restored`. `deploy/README.md` states this as
mandatory. The original recommendation was a sidecar outside the backed-up directory; keeping it
inside is acceptable for the MVP given the documented step, but a relay operator who restores the
directory and forgets the marker silently reuses positions. Low; consider an optional
`SBTP_POSITION_FILE` outside the data directory later.

### L-1: closed for the detached scan

`subscribe.rs:120-123`: the catch-up `JoinHandle` is kept in `Feed::read` and polled again after a
cancelled `next()`; it is set back to `None` in the same synchronous step that consumes the result,
so a completed handle is never polled twice (which would panic) and `last` cannot move while a read
is pending. A handle left pending when the session ends finishes one bounded page and is dropped.
The suggested cap on client frames per second was not added; with H-1 bounded it is no longer
needed.

## New findings

No new high or medium finding.

### R-L-1. One `/64` drains the whole `/48` `PUT` budget: the two buckets are charged independently

- Location: `crates/sbtp-relay/src/http.rs:180-181`.
- Code: `let wide = relay.put_bytes_wide.check(key.wide(), …); (relay.put_bytes.check(key, …).and(wide))`.
  Both buckets are charged on every call. A client over its own 32 KiB/s budget still takes bytes from
  its /48's bucket on each refused attempt, so the per-client cap does not bound its share of the /48.
- Scenario (probe): one `/64` sends 700 junk 65,000-byte bodies (no proof of work needed: the budget
  is charged before validation). 64 are processed, 636 get `429`, and the /48 bucket is empty. A
  neighbour `/64` in the same /48 then gets **`429` on its very first `PUT`**; another /48 is
  unaffected. Sustained at the default 50 requests/s (about 3 MB/s of upload), the attacker keeps
  every other client of its /48 unable to publish, at zero CPU cost to itself. Who shares a /48:
  mobile carriers and VPS hosts hand out single /64s from shared /48s; the code comment itself
  assumes up to 256 `/56` customers per /48.
- Related: when the /48 bucket refuses, the per-client bucket was still charged, so an honest
  neighbour loses its own budget on each refused try (bounded if it honours `Retry-After`). A non-listed
  neighbour's request also clamps the shared /48 bucket of a listed gateway down to the unlisted burst
  (`limits.rs:75`, `.min(burst)` with the caller's factor).
- Severity: low. Writes only, temporary, scoped to one /48; even with the fix a `/56` holder has 256
  `/64` keys and can drain its /48 (the inherent trade-off of an aggregate budget).
- Fix: check the per-client bucket first and charge the /48 bucket only when it passed (and, if the
  /48 refuses, refund or accept the per-client charge). Better: charge the /48 bucket only for blocks
  that pass validation and are new (the disk-filling concern), so a lock-out of neighbours costs the
  attacker proof of work; the per-client byte budget before validation still bounds junk.

### R-L-2. Subscribe catch-up over a denied run is not paced and costs O(run) per connection

- Location: `subscribe.rs:120-138`, `store.rs:269-277`.
- Scenario: pages of a denied run carry no frames, so TCP flow control never slows the loop; each
  connection reads `LOG` back-to-back until it passes the run. Measured: 33 ms of blocking work per
  connection for 200,000 denied entries (about 165 ns per entry). An attacker that first stored a
  very large run (millions of small blocks, hours of work under the new budgets) and had it denied can
  keep 4 subscriptions per `/64` cycling, each costing roughly a core for the run's length. Bounded by
  the 4-per-address and 256-global subscription caps and by the request rate; far cheaper per entry
  than before the fix (the old code read 60 KB per denied entry). Low.
- Fix (when it matters): count examined entries per connection and, after a few empty pages in a
  row, sleep briefly (for example 10 ms per 4,096 denied entries examined), or keep a per-relay
  "skip index" of denied ranges rebuilt in `set_deny`.

### R-L-3. A whole-directory in-place restore without the marker reuses positions under the same `relay_id`

See M-5 above: residual of the chosen design, documented. Listed here so that it is tracked.

### R-I-1. `more = true` without any matching block left

`store.rs:274`: when the examined bound is hit inside a denied run that reaches the end of the log,
the page says `more = true` although no matching block remains (the tests show `since=4&limit=1 →
since 8, more true` over a run of denied entries). SPEC §5 defines `more` as "`true` when matching
blocks remained after the page"; its second sentence ("so a client always progresses, even on an
empty page") anticipates the behaviour, and the cost is one extra request. Conformant in spirit; a
one-clause spec clarification ("or when the relay stopped examining early") would remove the
ambiguity for third-party clients. `since` is always greater than the requested position when
`more` is true (the bound is at least 4 entries).

### R-I-2. `/query` can list position `p` before `InvalidPosition` accepts `since = p`

`store.rs:209-211`: the commit makes position `p` visible to readers before `max` is stored;
`check_position` now reads only `max` (`http.rs:280-284`). A client that sees `p` in a `/query` page
and sends `since=p` within that window gets `InvalidPosition` and resyncs from `0`. The window is a
few instructions unless the writer thread is descheduled; a full HTTP round trip has to fit in it.
Fix if ever seen: on `since > max`, re-read the last `LOG` key in a read transaction before refusing.

### R-I-3. The new table layout cannot open a store written by `81bbd18`

`LOG` changed value type; redb refuses the table (`TableTypeMismatch`) and the relay does not start.
A safe failure (no corruption, no silent misread), and no v1 relay has been deployed. Note it in the
changelog; a store from before this branch must be re-imported.

### R-I-4. `set_deny` holds the write lock for a scan back over the denied tail

`store.rs:143-159`: 50 ms for a 200,000-entry denied tail; a store filled with millions of minimum-size
blocks that are then denied would block `PUT` for seconds at each reload and at startup. Reloads
are rare and operator-driven. Fine for the MVP.

### R-I-5. Three rate-limiter maps now share the O(65,536) eviction of L-4

`put_bytes` and `put_bytes_wide` reuse `RateLimiter`; the L-4 behaviour (full `retain` scan under the
mutex once 65,536 keys are tracked) now applies to each. Unchanged severity; fix together with L-4.

### R-I-6. Things checked and found fine

- No new panic on network input: header parsing (`str::parse`, `SocketAddr`), `ClientKey::wide`
  (shift by a constant), `bytes.len() as f64`, `Retry-After` arithmetic, `item.frame.get(8..)`; I-6
  of the original report is fixed (`checked_add` on the position).
- Store atomicity: `LOG`, `BLOCKS`, `IDS` and `CHILDREN` are written in one redb write transaction;
  `max` and `served` change only after a successful commit, under the write mutex; `set_deny` swaps the
  list and recomputes `served` under the same mutex, so a `PUT` cannot fall between the deny check and
  `served`. Restart recomputes both from the store.
- `last_position` excludes denied blocks after a reload (tested); `InvalidPosition` counts denied
  positions (`max`).
- Shutdown waits for subscribers with `acquire_many` under a 1 s timeout, equivalent to before.
- The deny check order in `PUT` is still §4, then the deny list, then storage.

## Not checked

- Behaviour behind a real reverse proxy (the nginx example was read, not run).
- redb crash recovery with the new layout (`kill -9` during writes), full disk, Linux and x86_64;
  sidecar behaviour on network or FUSE filesystems.
- Catch-up cost with a denied run of millions of entries (extrapolated from 200,000).
- Everything outside `crates/sbtp-relay` and `deploy/` (no change there on this branch).
