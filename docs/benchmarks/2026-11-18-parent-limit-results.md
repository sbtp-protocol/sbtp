# Results: index cost at 15 versus 8 parents (informative macOS runs)

- Pre-registration: `2026-11-18-parent-limit-preregistration.md` (commit `a33c017`, 18:27, before any 8-parent
  measurement). This file was written after the runs and does not modify it.
- 15-parent runs: `2026-11-18-redb-macos-informative.md` (commit `5ed731d`).
- 8-parent runs: branch `feat/relay-redb-bench`, commit `9cc8d96` (rebased on `b2e8483`, `IndexBackend` trait,
  generator using `MAX_PARENTS`). Harness SHA-256 `7d3778cdc1bf3ecc37d5fa7157d14ae6f18f86cafe6cf2d379629298ccc80670`.
  Same settings, driver and measurement method as the 15-parent runs (ADR 0017 not applied on purpose).
- **Not the ADR 0013 gate** (ADR 0017 rule 2: an in-process harness is informative only).
- Machine state: no other heavy job at the start. Background: the Docker VM (about 25% of one core) and Chrome;
  the BlockBlock and Defender agents reached 47–73% CPU while reacting to the benchmark's own I/O. Timings
  are affected, per-process peak memory is not.

## Comparison with the predictions

| Quantity | Predicted (8 vs 15) | Measured | Verdict |
|---|---|---|---|
| Step 1 insert rate | ×1.5 to ×2.5 | 649 → 1,612 blocks/s, ×2.48 | within range (top edge) |
| Index file after step 1 | ×0.4 to ×0.7 | 4,294,971,392 → 2,155,876,352 bytes, ×0.502 | within range |
| Step 3 sweep time | ×0.4 to ×0.8 | 646.7 → 68.5 s, ×0.106 | **deviation** (faster than predicted) |
| Peak memory | roughly unchanged, ±25% | steps 1–3 process worst 80,986,112 → 2,626,797,568 bytes (×32) | **deviation** (much higher) |
| Query throughput and p99 | better or equal | 5 to 10x the throughput, p99 under 3 ms | within range |
| Correctness | identical | 0 errors in every run | within range |

Not predicted: start-up after `SIGKILL` dropped from 32–77 s to 1.4–5.1 s.

## 8-parent runs: maximum RSS in bytes per process

| Run | Steps 1–3 | Step 4 | Step 5 | Errors |
|---|---|---|---|---|
| adversarial8-1 | 416,055,296 | 13,975,552 | 93,634,560 | 0 |
| adversarial8-2 | 714,964,992 | 11,878,400 | 25,165,824 | 0 |
| adversarial8-3 | 2,626,797,568 | 10,682,368 | 26,607,616 | 0 |

Peak memory footprint of the steps 1–3 process: 286.5 MB, 561.3 MB, 3,422.2 MB (anonymous memory, not
file-backed pages). End-of-step RSS falls back to 14.7–58.9 MB after step 3: the growth happens during the
step-2 concurrent `/query` load (8 clients, `limit=1000`, up to 10 pages).

## Interpretation

- **Deviation 1, sweep.** The cost is not linear in edges. Hypothesis (unverified): the 4 GiB 15-parent file
  no longer fitted in the OS page cache, so deletes became disk reads; the 2 GiB file fits.
- **Deviation 2, memory.** The prediction assumed memory bounded by the redb cache and the process; that is
  wrong on this platform. Step-2 growth does not track data volume or query rate in a simple way (typical
  runs: 26 MB / 750 MB / 30 MB; 15-parent adversarial: 18–26 MB; 8-parent adversarial: 0.4–1.8 GB at
  the end of step 2). Cause unknown. Candidates: redb's read path under 8 concurrent readers with a full
  4 MiB cache, the harness itself, or the macOS allocator under high-rate concurrent churn.
- **Risk.** If concurrent `/query` load can drive a relay to gigabytes on Linux too, it is a memory-exhaustion
  (denial-of-service) vector. It must be diagnosed before relay milestone 1 and before the Linux gate.
- The decision to lower the limit to 8 (ADR 0014) is corroborated on insert rate, index size, sweep time,
  query latency and crash recovery. It was taken before these results.
