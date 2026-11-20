# 0027: Cost bound of the rate-limiter table: no pass over the table, a full key found by its full time

- Status: accepted (project owner, 2026-11-19)
- Date: 2026-11-19
- Questions: Q-33
- Amends: ADR 0018 rule 21 ("Bounded state" bullet) and rule 35 (what the limiter entry
  estimate covers; 192 bytes by clarification T1). By clarification T1, also the worst-case figures of
  ADR 0019 rule 37, of the header of ADR 0020 and of ADR 0021 rule 45. ADR 0019 rule 31 and ADR 0020
  rule 24 are unchanged
- Depends on: ADR 0018 rules 1, 21, 22 (range of `rate_limit_max_clients`), 32 and 35; ADR 0019 rule 31
  (an entry with an in-flight count above 0 is never dropped); ADR 0020 rules 22 and 24
- Impact: `sbtp-relay` (`limiter.rs`); no spec change; no `sbtp-core` change; no test vector
- Clarifications: 2026-11-19, after relay milestone 1c-b2 (T1: limiter entry estimate 192 bytes and
  recomputed bounds; T2: limiter map preallocated; T3: pinned keys and the order; with ADR 0018
  clarification M5: `rate_limit_max_clients >= 2 × max_connections`), accepted by the project owner,
  2026-11-19. 2026-11-19, after relay milestone 1c limits (T4: the map never resizes or rehashes,
  preallocation alone does not ensure it; T5: when the memory of the map becomes resident),
  accepted by the project owner, 2026-11-19

## Context

ADR 0018 rule 21 bounds the limiter table at `rate_limit_max_clients` keys and says: "A key whose three
buckets are full is dropped first. When the table is full of active keys, requests from unknown keys
share one overflow key." It gives no cost bound for finding a key whose buckets are full.

Facts:

- Dropping a key whose three buckets are full loses nothing: a new key starts with full buckets
  (rule 21). Dropping any other key would give its client a fresh allowance.
- The range of `rate_limit_max_clients` is 64 to 16,777,216 (rule 22); the default is 4,096.
- At 52f8a7b, `sbtp-relay` finds full keys with one pass over the whole table under the limiter mutex,
  at most once per second, when an unknown key arrives and the table is full. Between two passes,
  unknown keys use the overflow key even if full keys exist. Every request of every class takes that
  mutex.
- The cost of the pass is linear in the table size. It is negligible at 4,096 keys. The security
  review of 1c-b (`docs/security/2026-11-19-relay-m1c-b.md`, L-4) estimates at least 100 ms per pass at
  16,777,216 keys: every request, `/info` and cached `GET /block` included, would wait for it once per
  second. Rule 1 asks for a cost bounded by settings; rule 32 asks that `/info` and cached reads be
  refused only by the connection cap and the token bucket.
- A key's buckets refill deterministically. From its levels at its last request, the time at which all
  three are full again (its **full time**) is known at that moment and does not change until its next
  request.
- The exact rule has a security value. To keep the table full against new clients, an attacker must keep
  each of its keys short of a full bucket. With the default `block` bucket (200 tokens, 3,000 per
  minute) a key is full again 20 ms after one request. An approximate rule that treats a key as active
  for longer lowers that cost.

Options:

| Option | Cost per request | Exact? | Assessment |
|---|---|---|---|
| A. Periodic full pass (52f8a7b) | linear, once per second, under the mutex | no (1 s window) | Stall of 100 ms or more at the maximum. |
| B. Lower maximum (for example 1,048,576) | linear, smaller | no | Still linear; a pass at 1,048,576 keys is several ms under the mutex; restricts operators. |
| C. Sharded table, one pass per shard | linear in a shard | no | Shorter lock hold; same total work; more code. |
| D. Bounded probe (examine at most K keys from a rotating cursor) | O(K) | no | Simple. May miss a full key; result depends on probe order. |
| E. Keys ordered by full time | O(log n) | yes | The key with the earliest full time is a full key if any key is full. Keeps the text of rule 21. Some memory per entry. |

## Decision

1. **Cost bound.** The work of the limiter for one request MUST be bounded by a constant or by a
   logarithm of `rate_limit_max_clients`. No operation of the limiter passes over the whole table, on
   the request path or under a lock that requests take.
2. **Full time.** For each key, the limiter knows the time at which all three of its buckets will be
   full, computed from the levels left by its last request and the rates of rule 21. A key is **full**
   when its full time is not later than now.
3. **Unknown key, full table.** When a request comes from a key that is not in the table and the table
   holds `rate_limit_max_clients` keys:
   - if some key in the table is full, the relay MUST drop one full key and admit the new key in its
     place, during that request;
   - otherwise the request uses the overflow key (ADR 0018 rule 21, ADR 0020 rule 24).
   There is no waiting period between two admissions.
4. **Never dropped.** A key that is not full MUST NOT be dropped. An entry whose in-flight count is above
   0 MUST NOT be dropped (ADR 0019 rule 31), whatever its full time.
5. **Memory.** The estimate of one limiter entry in ADR 0018 rule 35 (100 bytes) covers the entry and its
   place in the order of rule 2. The Linux gate measure replaces it, as rule 35 already says.
6. **Range unchanged.** `rate_limit_max_clients` keeps its range (64 to 16,777,216) and its default
   (4,096). Under rule 1, its cost is memory only, which rule 35 counts and the relay logs at start-up.
7. **Implementation note (not normative).** An ordered map keyed by (full time, key), or a binary heap
   with positions, satisfies rules 1 to 3 with the standard library only. A request of a known key moves
   that key in the order: O(log n).

## Consequences

- **`sbtp-relay` (the implementer).** `limiter.rs`: remove `SWEEP_MS` and the `retain` pass; keep, next
  to the map, an order of keys by full time (for example `BTreeMap<(u64, ClientKey), ()>`), updated on
  every take; on an unknown key with a full table, pop the first key of the order if its full time is not
  later than now and its in-flight count is 0. Tests: a full key is replaced at once, twice in the same
  millisecond; a key one token short is not dropped; an entry with a request in flight is not dropped;
  the overflow key is used only when no key is full. The per-entry size and the start-up bound of rule
  35 are recomputed.
- **Performance.** Every request pays one reordering of its key (about 24 levels at the maximum, 12 at
  the default) under the existing mutex. No stall.
- **Security.** The attack cost of filling the table is the one rule 21 intended: keys must be kept short
  of a full bucket. Fixes review finding L-4.
- **Compatibility.** No protocol change: the limiter is a local behaviour of a relay (ADR 0018 rule 5).
  No change to `/info`, to status codes or to `Retry-After`.
- **Test vectors.** None.

## Clarifications (2026-11-19, after relay milestone 1c-b2)

Recorded by the specification editor after relay milestone 1c-b2 (`feat/relay-m1c-b2`, merged at `db1dffe`),
accepted by the project owner, 2026-11-19. They follow the security review of the branch
(`docs/security/2026-11-19-relay-m1c-b2.md`, L-1 to L-3). They add no setting and no status code. T1
replaces an estimate and the figures computed from it; T2 states how rule 1 applies to the growth of
the map; T3 states how rules 3 and 4 read together. The start-up constraint that goes with them is ADR
0018 clarification M5.

- **T1. Limiter entry estimate: 192 bytes.** The estimate of one limiter entry in rule 5 and in ADR
  0018 rule 35 is 192 bytes, not 100. It covers the entry in the map at most half full (two buckets
  per key, each with its control byte) and two elements of the order of rule 2 (B-tree nodes about
  half full). The review measured 168 to 178 bytes per entry with the types of `sbtp-relay` at
  `db1dffe`; 192 leaves a margin.
  - `sbtp-relay` MUST have a unit test that fails when the estimate is below
    `2 × (size of one map element + 1) + 2 × (size of one order element)`, computed with `size_of` on
    the types the limiter uses. A change of those types that outgrows the estimate then fails the
    build of the tests.
  - The Linux gate measure still replaces the estimate (ADR 0018 rule 35).
  - Figures recomputed with 192 bytes. They include the two per-client tables of ADR 0019 rule 31 and
    the pins of rule 4, counted together as `4 × max_connections × 64` bytes, as `sbtp-relay` does
    (review I-2: conservative), and the log queue of ADR 0021 rule 45 (262,144 bytes). They replace
    the worst-case row of ADR 0019 rule 37, the figures in the header of ADR 0020, and the figures of
    ADR 0021 rule 45:

    | Bound of ADR 0018 rule 35, from its estimates, `index_max_readers = 2` | `small` | `standard` | `large` |
    |---|---|---|---|
    | Terms of ADR 0019 rule 37 only (was 13,018,580 / 97,630,032 / 1,198,804,640) | 13,395,412 | 100,644,688 | 1,222,921,888 |
    | With the per-client tables and the pins | 13,403,604 | 100,710,224 | 1,223,970,464 |
    | With the log queue, `/metrics` off (logged at start-up) | 13,665,748 (13.0 MiB) | 100,972,368 (96.3 MiB) | 1,224,232,608 (1,167.5 MiB) |
    | With `/metrics` on (+131,072) | 13,796,820 | 101,103,440 | 1,224,363,680 |

    The difference from the old figures is `92 × rate_limit_max_clients` (376,832, 3,014,656 and
    24,117,248 bytes) plus the pins term (4,096, 32,768 and 524,288 bytes), which the earlier figures
    did not show. `small` stays under its 15 MB target with TLS off (ADR 0019 rule 39, ADR 0028 rule
    36). The memory limits of the packaged unit (128 MiB, 512 MiB, 2 GiB) are unchanged.
  - At the maximum of `rate_limit_max_clients` (16,777,216) the limiter term is 3,221,225,472 bytes
    (3 GiB). The relay logs it like every other term.
  - Note (not normative). The figure of two buckets per key holds exactly when the map is
    preallocated (T2) for a power of two keys, which the default and the three profiles are. For
    other values a hash map with power-of-two bucket counts can reserve up to 16/7 buckets per key,
    about 194 bytes per entry with today's types, within 2 % of the estimate.
- **T2. The limiter map is preallocated.** At start-up, before it listens, the relay MUST allocate the
  map of the limiter for `rate_limit_max_clients` keys. The map MUST NOT grow, and so MUST NOT
  rehash, on the request path: with the bound of ADR 0018 rule 21 an insert never needs more room.
  This is how rule 1 applies to the map: an amortised growth to the bound does not meet it.
  - The order of rule 2 grows by one node at a time; an insert or a removal is `O(log n)` and moves no
    other element. It needs no preallocation.
  - The table of pins (rule 4) holds at most `max_connections` keys (ADR 0019 rule 31). The relay MAY
    preallocate it for `max_connections` keys; its memory is in the pins term of T1.
  - The memory is counted by the limiter term of ADR 0018 rule 35 (T1). A preallocated map reserves it
    at start-up; resident memory grows as keys arrive. If the allocation fails, the relay does not
    start.
- **T3. Pinned keys are kept out of the order.** A key whose in-flight count is above 0 (rule 4, ADR
  0019 rule 31) is not in the order of rule 2. It goes back into the order, with its full time, when
  its count returns to 0. Therefore:
  - every key in the order may be dropped once it is full, and the first key of the order is the full
    key with the earliest full time, if any key in the order is full;
  - on an unknown key with a full table, the relay drops the first key of the order if its full time
    is not later than now, with no further check; otherwise it uses the overflow key;
  - in rule 3, "some key in the table is full" reads "some key that rule 4 allows to drop is full". A
    full key with a unit in flight is never dropped; when only such keys are full, the request uses the
    overflow key.

  The Consequences above read accordingly: "pop the first key of the order if its full time is not
  later than now" (the in-flight count of a key in the order is always 0). This is what `sbtp-relay`
  does at `db1dffe`.

## Clarifications (2026-11-19, after relay milestone 1c limits)

Proposed by the specification editor after the branch `feat/relay-m1c-limits`. Status: accepted by the
project owner, 2026-11-19. They follow the implementation of T2 and the security review
`docs/security/2026-11-19-relay-m1c-limits.md` (I-2, I-5). They add no setting. T4 replaces the
second and third sentences of T2 and the note at the end of T1; T5 replaces the last bullet of T2.

- **T4. The map never resizes or rehashes; preallocation alone does not ensure it.** T2 reads: "The
  map MUST NOT resize or rehash on the request path, whatever the sequence of inserts and removals
  within the bound of ADR 0018 rule 21. An amortised growth or rehash does not meet rule 1."
  - The sentence "with the bound of ADR 0018 rule 21 an insert never needs more room" is withdrawn.
    It holds for the number of keys, not for every hash map. A hash map that marks removed slots
    (tombstones) counts them against its capacity: under a churn of removals and inserts that never
    exceeds the bound, it rehashes in place or doubles. This was reproduced with a standard
    `HashMap` reserved for the bound. Preallocation is necessary; it is not sufficient.
  - The relay MUST use a structure that, by construction, never resizes or rehashes under the bound.
    Two examples, not normative: open addressing at a fixed capacity with backward-shift deletion
    (no tombstones), which `sbtp-relay` uses with exactly two slots per key; or a fixed array of
    entries with a free list and a separate fixed index. A standard hash map meets T2 only if its
    documentation guarantees that it does not rehash under this pattern, which the standard library
    of Rust does not.
  - The load of the table MUST stay low enough that every lookup ends: with two slots per key it is
    at most one half.
  - The hash keyed per process (SipHash with a random key in `sbtp-relay`) stays required, so that a
    remote client cannot aim collisions at one cluster.
  - The note at the end of T1 is replaced: "The figure of two slots per key is the table of
    `sbtp-relay`: a fixed table of `2 × rate_limit_max_clients` slots, for any value of the setting.
    The size test of T1 stays as written; its `+ 1` per slot is a control byte that this table does
    not have, so the test over-counts by 2 bytes per key." The 16/7 figure applied to a standard hash
    map, which T4 excludes.
  - The table of pins (rule 4) is bounded by `max_connections`, not by `rate_limit_max_clients`. It
    SHOULD use the same fixed structure. A standard hash map reserved for `max_connections` keys is
    accepted: its in-place rehash under churn costs `O(max_connections)` under the limiter mutex,
    amortised, which a setting bounds (at most 65,535 keys, under 1 ms by review I-5). This is the one
    exception to rule 1 and it is stated here so that it is not read as an oversight.
  - *Alternatives considered.* Keep the T2 text: it implies that a reserved standard map complies,
    which is false. Name one structure normatively: over-specifies a local behaviour (ADR 0018 rule
    5). Reserve a standard map for a multiple of the bound: lowers the rate of rehashes, does not
    remove them.
- **T5. When the memory of the map becomes resident.** The last bullet of T2 reads: "The memory is
  counted by the limiter term of ADR 0018 rule 35 (T1). The relay reserves it at start-up, before it
  listens. If the allocation fails, the relay does not start."
  - The phrase "resident memory grows as keys arrive" is withdrawn. An implementation MAY write every
    slot at start-up or leave its pages untouched until used. Both stay within the limiter term of
    T1.
  - Writing every slot at start-up is RECOMMENDED: on a host that overcommits memory, a shortage then
    stops the relay at start-up and not under load, and the resident set from the first request is
    the one the gate of ADR 0018 measures.
  - `sbtp-relay` writes every slot at start-up: 112 bytes per key with its types (two slots of 56
    bytes). That is 0.4 MiB for `small`, 3.5 MiB for `standard`, 28 MiB for `large`, and 1.75 GiB at
    the maximum of `rate_limit_max_clients` (16,777,216), where it adds about one second to the
    start-up. This is accepted. The relay logs the limiter term at start-up (ADR 0018 rule 35); at the
    maximum, that term (3 GiB by T1) exceeds the memory limit of the packaged `large` unit (2 GiB), and
    it is the operator's choice to raise both.
  - *Alternatives considered.* Require lazy pages (allocate zeroed memory and never write it at
    start-up): the shortage moves to the request path on an overcommitted host, and the slot type
    would need an all-zero empty state. Require writing every slot: excludes a valid lazy design for
    no interoperability gain. Lower the maximum of `rate_limit_max_clients` because of the start-up
    time: rule 6 keeps the range, and one second at the extreme is acceptable.

## Rejected alternatives

- **A periodic full pass** (option A): a linear stall under the lock every request takes.
- **A lower maximum alone** (option B): still linear, and removes a choice from operators for no gain once
  the cost is logarithmic.
- **A sharded table** (option C): shortens the lock but keeps linear work; the order of rule 2 is simpler.
- **A bounded probe** (option D): may send an unknown key to the overflow key while full keys exist,
  which lowers the cost of filling the table; acceptable as a fallback only if option E proves too
  costly in memory at the gate.
- **Dropping the least recently used key**: may give a fresh allowance to a client whose buckets are not
  full.

## Spec change

None. `docs/spec/sbtp-core-v0.2.md` does not describe the limiter table. Applied on acceptance: ADR 0018 gets
"Amended by: ... 0027 (rule 21: cost bound of the limiter table; rule 35: entry estimate)" and its index
row reads "accepted, amended by 0019, 0020, 0021, 0023 and 0027".
