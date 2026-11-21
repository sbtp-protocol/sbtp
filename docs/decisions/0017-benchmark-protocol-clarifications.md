# 0017: Clarifications of the ADR 0013 benchmark protocol

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0048 (owner decision of 2026-11-21 on the size budget, Q-70: the binary threshold of
  ADR 0013 becomes 8,000,000 bytes and the gate gains an image threshold of 5,000,000 bytes compressed;
  the memory thresholds are unchanged; set before the gate has run)
- Date: 2026-11-18
- Questions: Q-12 (the benchmark verdict is still pending; this ADR does not give it)
- Amends, if accepted: ADR 0013, section "Benchmark protocol" only (subject, procedure steps 2 to 5,
  peak memory measure). Rules 1 to 26 of ADR 0013, its thresholds and ADR 0014 rules 14 to 17 are
  unchanged
- Impact: `sbtp-relay` (one benchmark-only control for the expiry bound, see rule 4); the benchmark
  harness and generator (the implementer); `docs/benchmarks/linux-gate-vm-spec.md` (no change needed);
  no spec change; no `sbtp-core` change; no test vector

## Context

The first run of the ADR 0013 benchmark (`docs/benchmarks/2026-11-18-redb-macos-informative.md`) was made
on macOS with an in-process harness and gave no verdict. the implementer reported seven points where the
protocol can be read in more than one way. Each reading gives different figures or a different pass
condition.

The gate exists to check that the relay that ships stays under its memory and size targets in the worst
case the format allows. Where two readings are possible, this ADR takes the one closer to the real relay
and the one that does not lower the measured peak.

These rules are fixed before the Linux gating run. They MUST NOT be changed after its results are known
(ADR 0013, pre-registration). The thresholds are not touched: binary under 5,000,000 bytes, peak memory
at most 12 MiB.

## Decision

### Subject

1. The benchmark subject is the `sbtp-relay` binary produced by the gating build, run as its own process.
   Blocks enter through `PUT /sbtp/v1/block` and queries through `GET /sbtp/v1/query`, over loopback
   HTTP, from a separate load-generator process. The flat-file store (ADR 0009) and the moka cache at its
   default size are in the path. The words "in process or" of ADR 0013 are withdrawn for the gate.
2. A harness that calls the index or the validation in process is informative only. Its figures MUST NOT
   be used for the verdict, in either direction.
3. The memory of the load generator is not measured. The generator MUST NOT run inside the relay process.

### Expiry bound in steps 3 to 5

4. Step 3 fixes one absolute expiry bound `B`, in milliseconds. From step 3 to the end of step 5 a block
   is expired if and only if `received_at ≤ B`. `B` does not move with the clock. The relay evaluates it
   in the code that implements ADR 0013 rule 12, where `B` takes the place of `now − block_ttl_ms`.
5. `B` is given to the relay by a benchmark-only control. It MUST be off by default, MUST NOT be
   reachable from the network and MUST be a run-time control of the gated binary, not a compile-time
   feature: the binary measured is the binary that ships. The report describes it.
6. `B` MUST be applied to the process that ran steps 1 and 2, without a restart. The processes of steps 4
   and 5 start with the same `B`.
7. **Meaning of "10%".** Let `r` be the `received_at` of the 100,000th block in acceptance order. Then
   `B = r`. The expired set `E` is every step-1 block with `received_at ≤ r`. When several positions
   share the millisecond `r`, all of them are in `E`: `E` holds at least 100,000 blocks. The report gives
   the size of `E`.
8. The harness finds `r` and `E` through `/query` (`since` is inclusive, ADR 0012 rule 7) or by reading
   the index; the report says which.
9. Step 3 ends when the file and the index entries of every block of `E` are deleted. The sweeper period
   MAY be lowered to 1 second for the benchmark; its work bound per run stays at its default.

### Queries

10. **Reference order.** After step 1 the harness lists the whole relay once (`/query` with neither
    `parent` nor `since`, followed to the end). The list MUST be a permutation of the 1,000,000 generated
    identifiers, and the blocks of each client MUST appear in the order that client sent them. This list
    is the reference order. Expected responses are computed from it, from the generator's parent table
    and, in steps 4 and 5, with `E` removed.
11. **`since`.** For each query with no `parent`, `since` is drawn uniformly among the integer
    milliseconds of `[t0, t1]`, where `t0` is read by the harness just before the first `PUT` of step 1
    and `t1` just after its last response. The harness and the relay share the host clock. The draw
    comes from the seeded generator. Steps 4 and 5 use the same interval.
12. **`parent` in queries.** Typical data set: drawn uniformly among the 1,000,000 block identifiers; a
    block with no child gets the expected empty list. Adversarial data set: drawn uniformly among the
    8,000,000 parent values; each has exactly one child.

### Parent sampling in the data sets

13. Blocks are numbered `0` to `999,999` in generation order. Block `i` is sent by client `i mod 8`; each
    client sends its blocks in increasing `i`, one at a time. The header Timestamps are fixed by the
    generator and lie in the past.
14. **Typical.** The number of parents `k` of block `i` is drawn with probabilities 20% (0), 50% (1) and
    30% (2), then lowered to `i` if `i < k`. The `k` parents are drawn uniformly, without replacement,
    among the blocks numbered `max(0, i − 10,000)` to `i − 1`. "Most recent earlier" refers to generation
    order, not to acceptance order: a child may reach the relay before its parent (ADR 0013 rule 4).
15. **Adversarial.** Each block has 8 parents (ADR 0014 rule 14). Each parent is 32 bytes taken from the
    seeded generator's stream. The generator MUST check that the 8 values of a block are distinct. No
    value is the identifier of a generated block.
16. The 10,000 blocks of the second load (step 5) are numbered `1,000,000` to `1,009,999` and follow the
    same rules.

### Kill point of step 5

17. The harness sends `SIGKILL` to the relay as soon as it has received the 5,000th `201` response of the
    second load, counted over the 8 clients. It does not wait for requests in flight and sends nothing
    after the signal. The report gives the number of `201` responses received.
18. **Durable-prefix tolerance.** After the restart and readiness:
    - every step-1 block outside `E` MUST be held and listed by `/query`;
    - every second-load block acknowledged by `201` before the signal MUST be held and listed exactly
      once (ADR 0013 rules 7 and 9);
    - a second-load block that was not acknowledged MAY be present or absent; if present it MUST be valid
      and listed exactly once; if absent, `GET` returns `404`;
    - second-load blocks MAY appear in any order among themselves, after every step-1 block. The epoch
      MAY have changed; the harness does not reuse a cursor across the restart.
19. The 1,000 queries of step 5 are checked on their step-1 identifiers against rule 10, and on their
    second-load identifiers against rule 18.

### Measures

20. **The killed process is measured.** The harness reads its `VmHWM` when the 5,000th `201` arrives,
    immediately before sending `SIGKILL`. This reading is gating. `/proc/<pid>/status` no longer exists
    after the signal.
21. **Processes.** One run has four relay processes: A (steps 1, 2 and 3), B (step 4), C (second load of
    step 5, killed), D (restart of step 5). Steps are not split into more processes: a relay in
    production loads, serves and sweeps in one process, and a restart would hide memory kept from an
    earlier step.
22. **`VmHWM` is cumulative** over the life of a process. The reading at the end of step 2 covers steps 1
    and 2; the reading at the end of step 3 covers steps 1 to 3. This is accepted. The gate applies to
    every reading: three for A, one for B, one for C (rule 20), one for D. `/proc/<pid>/clear_refs` MUST
    NOT be written. Every reading is taken while the process is alive, before any stop signal.
23. Per-step peaks MAY be reported from periodic samples of `VmRSS`. They are informative.
24. **Binary size.** The gating figure is the size of
    `target/x86_64-unknown-linux-musl/release/sbtp-relay` from the gating build (ADR 0013, "Measures").
    The macOS figures of 2026-11-18 (1,497,440 bytes, aarch64 Mach-O) are informative.

## Consequences

- **`sbtp-relay`.** The relay needs the control of rules 4 to 6. It is the only code the benchmark adds
  to the gated binary. Its exact form (for example a local file read by the sweeper) is
  the implementer's choice within rule 5. security reviews it with Phase 2: a control that
  expires blocks must not be reachable by a remote sender.
- **Step 3 without rule 4 cannot be checked.** With a bound that follows the clock, a sweep lasting
  longer than the load expires the whole data set; the macOS sweep took up to 695 seconds, the typical
  load a few minutes.
- **Memory figures are the conservative ones.** Process A carries its allocator state from the load into
  the queries and the sweep. A reading above 12 MiB at the end of step 1 fails the gate even if steps 2
  and 3 use less.
- **Correctness is checkable from outside the process.** Rules 10 and 18 need the public API and the
  generator only.
- **Earlier runs.** The macOS runs stay informative and are not re-read under these rules.
- **Compatibility and security of the protocol.** None: no format, API or spec rule changes.
- **On acceptance.** ADR 0013 gets the line "Amended by: 0017 (benchmark protocol: subject, steps 2 to
  5, peak memory measure)" next to its 0014 amendment; its body is not edited.

## Rejected alternatives

- **In-process harness as the gate.** Skips the HTTP stack, the block files and moka, which hold memory
  in the shipped relay. It was the cause of the undetermined first run.
- **Expiry bound that follows the clock, with `block_ttl_ms` recomputed at each restart.** The bound
  still moves during a step; the expected responses depend on elapsed time.
- **A compile-time benchmark feature for the bound.** The measured binary would differ from the shipped
  one.
- **One process per step.** Gives per-step figures, but each process starts with an empty heap: it
  understates the peak of a long-lived relay.
- **Resetting the high-water mark between steps.** Changes nothing in the process, but replaces six
  simple readings by a procedure that a missed reset silently invalidates.
- **Not measuring the killed process.** It is a relay under write load; leaving it out removes one of
  the two loaded phases of step 5.
- **Kill at a random instant.** Not reproducible across the three runs.
- **Requiring unacknowledged blocks to be absent, or present.** Neither follows from ADR 0013: the file
  may be created before the response is sent (rule 7).

## Spec change

None. `docs/spec/` is not concerned: the benchmark protocol lives in ADR 0013.
