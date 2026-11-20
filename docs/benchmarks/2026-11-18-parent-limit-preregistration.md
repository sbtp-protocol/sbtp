# Pre-registration: index cost at 15 versus 8 parents (ADR 0013 benchmark)

- Written: 2026-11-18, before any 8-parent measurement exists. The commit that adds this file is the
  timestamp of record; the 8-parent results must come in a later commit.
- Related: ADR 0013 (benchmark protocol), ADR 0014 (parent limit lowered from 15 to 8).

## Chronology (stated honestly)

1. The project owner lowered the parent limit from 15 to 8 on design grounds (layer 2 payloads rarely need
   more than 3 to 5 parents; each parent is an index entry an attacker obtains for one proof of work).
   The decision was taken while the 15-parent benchmark was still running and before its verdict.
2. The 15-parent adversarial runs (ADR 0013 protocol as written at the time) are kept to completion and
   reported as they are. They document the worst-case cost of the old format; they corroborate the
   decision, they do not justify it after the fact.
3. The 8-parent adversarial runs use the same machine, the same binary build and the same protocol, with
   only the number of fake parents per block changed (ADR 0014).

## Predictions for the 8-parent adversarial data set, relative to 15 parents

Assumption: the index cost is roughly linear in the number of `parent → child` edges (15,000,000 edges at
15 parents, 8,000,000 at 8).

| Quantity | Prediction |
|---|---|
| Step 1 insert rate (blocks/s) | about 1.9x higher (15/8), within a factor 1.5 to 2.5 |
| Index file size after step 1 | about 0.55x (8/15), within 0.4 to 0.7 |
| Step 3 sweep time | about 0.55x, within 0.4 to 0.8 |
| Peak memory (every step) | roughly unchanged (bounded by the redb cache and the process, not by data volume), within ±25% |
| Query throughput and p99 (steps 2, 4, 5) | better or equal |
| Correctness | identical (no error, no missing block) |

A result outside these ranges is reported as a deviation and explained, not hidden.

## Known confounder

During the 15-parent runs another, unrelated benchmark (Docker) was running on the same machine for part of
the time (at least during adversarial run 2). It affects wall-clock timings, not per-process peak memory.
The 8-parent runs are made with no other heavy job running, and the report says so; timing comparisons with
the 15-parent runs carry this caveat.
