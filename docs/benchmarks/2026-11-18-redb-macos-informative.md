# redb index benchmark, macOS run (informative, NOT the ADR 0013 gate)

- Date: 2026-11-18. Branch `feat/relay-redb-bench`, commit `5ed731d` (not merged at the time of writing).
- **Verdict for ADR 0013 rule 23: NOT DETERMINED.** The gating protocol requires Linux x86-64 (ext4/XFS,
  no swap), a `x86_64-unknown-linux-musl` build, `VmHWM` from `/proc`, and the real relay (`PUT` handler,
  flat-file store, moka). This run used macOS 26 on aarch64/APFS, `/usr/bin/time -l` maximum RSS, and an
  in-process harness (8 client threads → `validate_submitted` → `Index::insert` / `Index::query`), without
  handlers, block files or moka. The maintainer's brief scoped handlers out, which conflicted with the
  protocol; the engineer reported the conflict instead of reinterpreting it.
- Format at the time: 15 parents maximum (adversarial data set: 15 fake parents per block). ADR 0014 later
  lowered the limit to 8; see `2026-11-18-parent-limit-preregistration.md`.
- Settings: redb 4.4.0, cache 4 MiB, one write transaction per block with `Durability::None` and an
  `Immediate` commit at least every 1 s, quick repair off, sweeper batch 1,000, difficulty 0, release profile
  (`opt-level="s"`, `lto`, `codegen-units=1`, `strip`). No tuning between runs.
- Confounder: an unrelated Docker benchmark ran on the same machine during part of the runs (at least
  adversarial-2). It affects timings, not per-process peak memory.

## Maximum RSS (bytes, `/usr/bin/time -l`, one process per phase)

| Run | Steps 1–3 | Step 4 | Step 5 | Correctness errors |
|---|---|---|---|---|
| typical-1 | 33,439,744 | 14,336,000 | 36,339,712 | 0 |
| typical-2 | 751,714,304 | 11,517,952 | 14,155,776 | 0 |
| typical-3 | 31,965,184 | 11,419,648 | 45,596,672 | 0 |
| adversarial-1 | 43,843,584 | 9,666,560 | 19,578,880 | 0 |
| adversarial-2 | 80,986,112 | 9,633,792 | 13,549,568 | 0 |
| adversarial-3 | 53,198,848 | 9,568,256 | 9,699,328 | 0 |

All above the 12 MiB threshold in steps 1–3 and 5. An exploratory `vmmap` diagnosis at a step-2 peak showed
6.4 MB of live allocations for 64.6 MB resident in the default malloc zone (91% fragmentation): most of the
macOS peak is memory the allocator keeps after it is freed. The typical-2 spike (750 MB) is unexplained.
Only the Linux musl run can decide.

## Other measurements (informative)

| | Typical (1 parent) | Adversarial (15 fake parents) |
|---|---|---|
| Insert rate | 4,440–8,414 blocks/s | 623–673 blocks/s |
| Step-2 queries | 18,859–23,056 req/s, p99 ≤ 0.5–1.0 ms | 1,002–2,665 req/s, p99 ≤ 7.6–14.4 ms |
| Sweep (100,000 expired) | 9.9–13.7 s | 572–695 s |
| Start-up after clean stop | 6–18 ms | 6 ms |
| Start-up after `SIGKILL` | 286–360 ms | 32.3–77.4 s (full repair) |
| redb file after load | 539 MB | 4,294,971,392 bytes (stopped at exactly 4 GiB + 4 KiB), 2.46 GB after clean stop |
| Wall time per run | 2.7–4.4 min | 44–87 min |

Binary (aarch64 Mach-O, release profile): 1,497,440 bytes with tokio, axum, redb and sbtp-core validation
linked (818,672 without redb and the index). Not the gating figure.

## Open points raised by this run

- Index size larger than the block data (539 MB of index for 355 MB of blocks, typical): investigate page
  usage with per-block transactions.
- The 4 GiB + 4 KiB stop of the adversarial redb file.
- Recovery up to 77 s after a crash (ADR 0013 rule 11: `503` until ready); quick-repair decision pending.
- Protocol ambiguities 2–7 reported by the implementer (expiry clock in steps 3–5, `since` distribution,
  parent sampling, kill point, measurement of the killed process, `VmHWM` cumulative granularity): to be
  settled in ADR 0013 before the gating run. Settled by ADR 0017 (accepted 2026-11-18); ADR 0017 rule 2
  confirms that an in-process harness such as this one is informative only.
