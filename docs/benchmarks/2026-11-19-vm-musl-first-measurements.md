# First measurements on the Linux benchmark VM (musl build, informative, NOT the ADR 0013 gate)

- Date: 2026-11-19. Author: implementer. Commit measured: `main` at
  `cdc4670f13b7b0275412701de458621b50335965`, transferred as a git bundle; the clone's HEAD was checked
  against that hash.
- Status: **informative**. These runs use the in-process `query_diag` tool, not the real relay over HTTP,
  so ADR 0017 rule 2 applies: no gate verdict is drawn from them.
- Question answered: does the `x86_64-unknown-linux-musl` build show the `/query` memory growth seen on
  macOS (`2026-11-18-query-memory-diagnosis.md`)? **No.**

## Conclusion

- **musl does not show the macOS growth.** Under the reproduction conditions (8 clients, no bound), `VmHWM`
  is 6,900–6,972 KiB (6.7–6.8 MiB) in 5 runs of 5. On macOS the same load reached 415–873 MiB max RSS.
  Every one of the 20 runs stayed under 7 MiB, whatever the client count or bound.
- **On musl the bound changes nothing for memory.** With `index_max_readers` 2 the peak is 0.2–0.3 MiB
  lower and the run is 40% slower (22.8–23.7 s against 16.1–16.8 s). A bound of 4 matches the unbounded
  runs, at the same memory and the same time. The semaphore keeps its value as a portable limit on
  concurrent work (diagnosis, "Proposed bound", point 1), not as a memory fix on Linux.
- **A cost appears instead.** About 1.19 million minor page faults per run, the same with 1 or 8 clients,
  and system time is 44–49% of CPU time. This fits an allocator that hands freed pages back to the kernel
  and touches them again, which would be the mirror of libmalloc keeping them. It is a hypothesis:
  `strace` and `perf` were not run.

## Environment

- VM: Debian 13, 4 vCPU pinned (Xeon E5-2690, AVX, no AVX2 or AVX-512), 7.8 GiB RAM, no swap, ext4. User
  `bench`, no sudo. Rust 1.100.0 (rustc `0ef1bc386` 2026-11-09, cargo `3acc79c0c` 2026-11-05),
  targets `x86_64-unknown-linux-gnu` (host) and `x86_64-unknown-linux-musl`.
- Shared virtualisation host with other workloads, on spinning disks. The VM had booted one minute
  before the session started. Load averages around each step are shown below. Timings are informative only.
- Crates: `cargo fetch --locked` for `main` and for `afe1911` (the redb 4.4.0 lockfile the migration
  script needs, fetched from a temporary `git archive` that was then removed). Every later step ran
  offline.

## Build

`cargo build --release --locked --target x86_64-unknown-linux-musl -p sbtp-relay --examples --bins`:
succeeded in 52.9 s. Load average went from 0.05 to 1.80.

| Binary (release profile) | Size (bytes) |
|---|---|
| `sbtp-relay` | 2,740,752 |
| `sbtp-relay` after a manual `strip` of a copy (not shipped) | 2,200,488 |
| `examples/query_diag` | 1,844,240 |
| `examples/index_bench` | 1,920,832 |

`file sbtp-relay`: `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked,
BuildID[sha1]=1db87489a3f0156515cc0527c8df6bc56fdd71ab, not stripped`.

**Odd:** the workspace sets `strip = true` for release, but the musl binary still has `.symtab`
(4,631 entries, 0x1b180 bytes) and `.strtab` (0x68c5a bytes). A plain `strip` removes 540,264 bytes
(20%). Both sizes are well under the 5 MB target.

## Tests (host gnu target)

- `cargo test --workspace --locked`: **165 passed, 0 failed, 0 ignored** (50.5 s). Load average went from
  1.29 to 2.76.

  | Test binary | Passed |
  |---|---|
  | `sbtp-core` unit tests | 21 |
  | `sbtp-core` `tests/properties.rs` | 8 |
  | `sbtp-core` `tests/validation.rs` | 86 |
  | `sbtp-core` `tests/vectors.rs` | 7 |
  | `sbtp-relay` unit tests | 17 |
  | `sbtp-relay` `tests/http.rs` | 19 |
  | `sbtp-relay` `tests/startup.rs` | 7 |
  | `cli-demo`, `sbtp-relay` main, `sbtp-wasm`, the doc-tests | 0 each |

- Run one at a time with `--exact`, all ok: `index::tests::flusher_makes_a_quiet_tail_durable` (1.75 s),
  `index::tests::without_flusher_a_quiet_tail_is_lost` (1.75 s) and
  `index::tests::close_reports_a_live_write_transaction` (0.01 s).
- `sbtp-core` `--test vectors`: 7 of 7 ok (`every_vector_validates_exactly_as_expected`,
  `self_test_constants_are_the_frozen_vectors`, `vectors_cover_every_error_variant`,
  `isolating_vectors_discriminate_v2_and_v5`, `required_cases_are_present`, `boundary_sizes`,
  `json_reader_handles_escapes`).
- `crates/sbtp-relay/examples/index_migration.sh`: compares old tree `afe1911` on redb 4.4.0 with new tree
  `cdc4670` on redb 4.6.0, 20,000 blocks. **7 of 7 PASS**, exit 0 (1 min 30 s, load average 1.69 to 1.97):
  - Clean shutdown: the file reopens on 4.4, opens on the new version, reopens on it, and is downgraded
    back. Every summary is `rows=20000 epoch=57b775bbcccd9bfe last=1763500004999.3`, with identical
    digests.
  - `kill -9` mid-load (`inserted=1076`): the new version opens and reopens the file, and the downgrade
    works. Each summary equals the one from the 4.4 repair: `rows=1076 epoch=ac81a7537621343a
    last=1763500000268.3`, with identical digests.
  - Cargo printed only manifest warnings about unused workspace dependencies (`moka`, `thiserror`,
    `tower-http`, `wasm-bindgen`) in both trees.

## Memory measurement (`query_diag`, musl release build)

### Method

- Data set: `index_bench gen adversarial` (8 fake parents per block, `MAX_PARENTS` = 8), 38.6 s, 555 MiB.
- Index: `query_diag load <ds> <work> blocks=200000`, run once. It took 1 min 47 s, max RSS 8,704 KiB,
  `RSS loaded` 7,168,000 bytes. `index.redb` is 549,892,096 bytes.
- Each measured run is a new process, `query_diag query <ds> <work> [keys]`, with the tool's defaults:
  redb cache 4 MiB, `limit=1000`, 10 pages per query, 20,000 queries. Every run served 107,546 pages, the
  same count as on macOS.
- Measures:
  - `VmHWM` comes from `/proc/<pid>/status`, sampled every 20 ms until the process exits. `VmHWM` never
    decreases, so the last sample is the peak, except for growth in the last 20 ms. The tool itself does
    not print `VmHWM`, only `ps` RSS at open and at the end.
  - `/usr/bin/time -v` gives the maximum resident set size.
- The page cache was warm: 0 major faults in every query run, so disk speed does not enter.
- No tuning between runs. The sets ran in the order a, b, c, d, five runs each, back to back.

### Results (KiB; one value per process)

| Set | Settings | VmHWM per run | `time -v` max RSS per run | Wall time (s) |
|---|---|---|---|---|
| a | 8 clients, no bound | 6,916 / 6,932 / 6,972 / 6,924 / 6,900 | 6,916 / 6,932 / 6,972 / 6,924 / 6,900 | 16.4 / 16.6 / 16.6 / 16.1 / 16.8 |
| b | 8 clients, `max_readers=2` | 6,764 / 6,656 / 6,688 / 6,612 / 6,708 | 6,764 / 6,656 / 6,688 / 6,612 / 6,708 | 22.8 / 23.7 / 23.3 / 23.3 / 23.5 |
| c | 8 clients, `max_readers=4` | 6,920 / 6,908 / 6,896 / 6,960 / 6,948 | 6,920 / 6,908 / 6,896 / 6,960 / 6,948 | 16.7 / 16.1 / 15.9 / 16.0 / 16.8 |
| d | 1 client (baseline) | 6,392 / 6,308 / 6,288 / 6,304 / 6,364 | 6,284 / 6,260 / 6,300 / 6,184 / 6,276 | 32.3 / 31.7 / 33.1 / 32.2 / 32.1 |

- RSS right after open: 1.46–1.56 MB in every run. At the end: 6.44–6.89 MB.
- Every peak sits between 6.0 and 6.9 MiB: under the bounded macOS figures (8.5–9.0 MiB) and under the
  12 MiB threshold of ADR 0013. The relay itself is not included here.

### CPU and page faults (from `time -v`)

| Set | User (s) | System (s) | CPU | Minor faults | Voluntary context switches |
|---|---|---|---|---|---|
| a | 25.6–26.7 | 24.2–25.0 | 306–308% | 1,191,458–1,191,596 | 367,338–373,282 |
| b | 22.9–23.8 | 21.4–22.4 | 192–194% | 1,190,839–1,190,945 | 237,225–256,379 |
| c | 25.0–26.7 | 23.2–25.1 | 303–307% | 1,191,837–1,191,962 | 353,305–364,243 |
| d | 17.4–18.2 | 14.1–15.2 | 99% | 1,190,408–1,190,413 | 22–24 |

- The minor-fault count is the same in every set, about 11 faults per page served, so it depends on the
  work, not on the concurrency. The one-time load had 610,351.
- 8 clients use about 3 of the 4 vCPUs. The throughput gain from 1 to 8 clients is about 2x, not 8x. The
  high voluntary context switch count suggests contention, which was not investigated.

### Node load around the runs (`/proc/loadavg`, 1/5/15 min)

| Point | Load average |
|---|---|
| Before set a (09:24:05 UTC) | 0.81 / 1.14 / 0.65 |
| After set a, before set b (09:25:28) | 3.14 / 1.80 / 0.93 |
| After set b, before set c (09:27:25) | 2.35 / 1.94 / 1.08 |
| After set c, before set d (09:28:46) | 3.58 / 2.44 / 1.33 |
| After set d (09:31:28) | 1.29 / 1.89 / 1.29 |

The VM's load average counts its own runs: 3 busy threads in sets a and c, 1 in set d. The figures are
the VM's own, as seen by the guest. Other tenants of the host are not visible from inside the VM.

## Anything odd

1. `strip = true` leaves a symbol table in the musl binary (see Build). Worth checking how the profile
   option interacts with the musl target before the image is built. The size is not at risk.
2. In set d, `VmHWM` is 24–120 KiB higher than `time -v` max RSS. In sets a–c the two are equal. The gap is
   small and does not change any conclusion. It is unexplained.
3. System time is high (44–49% of CPU) and there are about 1.19 million minor faults per run (see CPU and
   page faults). The allocator explanation is unverified.
4. The home directory of `bench` contains `.sudo_as_admin_successful`, although the user is described as
   having no sudo. It is probably left over from provisioning. Not tested: `sudo` was not run.
5. With Rust 1.100, test executables sit under `target/debug/build/<crate>/<hash>/out/`, not
   `target/debug/deps/`. Scripts that look up test binaries by path should be checked.

## What remains

- The gate run itself (ADR 0013, ADR 0017): the real relay binary over loopback HTTP, driven by a separate
  load-generator process. These figures do not replace it.
- If the fault and system-time cost matters for the gate's throughput figures, profile it with
  `perf stat -e page-faults` or `strace -c` on the VM.
- Left on the VM: `~/sbtp` (clone), `~/bench` (data set, 200k index, run logs), `~/sbtp-main.bundle`,
  `~/vm-measure.sh`, `~/test-workspace.log`, `~/migration.log`. No process is left running.
