# Diagnosis: memory growth under concurrent `/query` (ADR 0013 benchmark, step 2)

- Date: 2026-11-18. Author: implementer. Branch `diag/relay-query-memory`.
- Status: diagnosis on macOS. Not a gate run; no protocol or threshold changed.
- Subject: the step-2 growth reported in `2026-11-18-parent-limit-results.md` (up to 2.6 GB RSS and
  3.4 GB peak footprint with 8 concurrent `/query` clients on the 8-parent adversarial data set).

## Conclusion

**The memory is not held by redb or by the index. It is freed memory that the macOS allocator
(libmalloc, default mode) keeps resident after redb's concurrent read workload.**

- At the peak, live heap allocations are 6 to 15 MB. The resident memory is free, empty regions of the
  malloc "small" zone (97% fragmentation).
- The same binary, on the same index, with the same 8 clients, stays at **10 MB max RSS** when libmalloc
  runs in its space-efficient mode (`MallocSpaceEfficient=1`). Nothing else changes.
- redb's read cache keeps to its budget: about 1,000 live 4 KiB page buffers (4 MiB) at the peak.

**The trigger is specific to redb's read path.** A plain 4 KiB allocate-and-free churn, simulated
without redb, does not reproduce the growth. The exact allocation sequence that triggers the retention
was not identified.

## Method

- **Tool:** `crates/sbtp-relay/examples/query_diag.rs`, release profile of the workspace, built at the
  commit of this file.
- **Data:** the 8-parent adversarial data set (`index_bench gen adversarial`, `MAX_PARENTS` = 8), first
  200,000 blocks.
- **Index:** a redb index loaded once (`query_diag load`, 14.2 MiB max RSS during the load). Every
  measured run is a new process that opens this index and runs only the query load (`query_diag query`).
  Start-up RSS is 2.4–2.5 MiB.
- **Query load:** the mix of step 2 of the benchmark. Half the queries are by `parent` (fake parents of
  the data set), half by `since` (uniform over the load interval). Each is followed for up to 10 pages.
- **Defaults:** 8 client threads, redb cache 4 MiB, `limit=1000`, 10 pages per query, 20,000 queries
  (about 107,000 pages, 5–9 s). One variable changes per row.
- **Measures:** `/usr/bin/time -l` (maximum resident set size, peak memory footprint). At the peak:
  `vmmap -summary`, `heap -s`, and `malloc_history -allBySize` under `MallocStackLogging=1`.
- **Machine:** macOS 26.6.2, Apple M-series with 4 performance and 4 efficiency cores, 24 GiB RAM,
  APFS on an SSD. Background: Docker VM, Chrome, endpoint security agents.

## Runs

Max RSS and peak footprint are in MiB. Each value is one process.

| Variable | Setting | Max RSS per run | Peak footprint per run | Time (s) |
|---|---|---|---|---|
| Reproduction | defaults | 722.4, 872.5, 414.9 | 519.3, 475.8, 155.5 | 8.1, 6.9, 4.9 |
| Backend (a) | in-memory `IndexBackend` (BTreeMap), 20,000 queries | 284.2, 284.4 (data baseline 256.9, 255.8) | 293.2, 293.8 | 0.5, 0.4 |
| Backend (a) | in-memory, 300,000 queries (1.6 million pages) | 284.8 (baseline 263.3) | 293.9 | 5.3 |
| Backend (a) + churn | in-memory, one 4 KiB `Arc<[u8]>` per 10 entries into a shared 4 MiB FIFO, 100,000 queries | 274.8, 274.9 | 298.8, 299.2 | 19.5, 24.4 |
| Backend (a) + churn | same, one buffer per entry | 274.9, 274.8 | 299.2, 298.8 | 145.2, 146.9 |
| Backend (a) + churn | one per 10 entries, allocated and freed outside the lock | 281.8, 287.6 | 306.1, 314.5 | 23.3, 20.2 |
| Clients (b) | 1 | 8.3, 8.4, 8.3, 8.3 | 7.3 (all four) | 11.8–17.8 |
| Clients (b) | 2 | 8.4 (all four) | 7.3–7.4 | 11.2–19.0 |
| Clients (b) | 3 | 18.1, 202.5, 158.6 | 16.0, 202.0, 151.9 | 5.8–7.9 |
| Clients (b) | 4 | 8.7, 9.0, 8.8, 9.0 | 7.7 (all four) | 7.3–7.7 |
| Clients (b) | 5 | 1,035.8 | 1,019.4 | 8.6 |
| Clients (b) | 6 | 28.8 | 21.6 | 8.4 |
| Clients (b) | 7 | 664.1 | 473.1 | 7.6 |
| Clients (b) | 16 | 763.7 | 510.3 | 7.9 |
| redb cache (c) | 1 MiB | 183.0, 66.2 | 133.6, 64.9 | 4.8, 4.7 |
| redb cache (c) | 16 MiB | 833.5, 285.0 | 553.1, 171.6 | 5.1, 4.3 |
| Page size (d) | `limit=100`, 10 pages (about 10x less data read) | 17.7, 19.1 | 16.5, 17.9 | 0.6, 0.6 |
| Page size (d) | `limit=100`, 100 pages (same data volume as the defaults) | 1,157.2, 715.1, 780.5 | 1,046.3, 614.6, 766.4 | 8.1, 6.8, 6.4 |
| Pages per query (d) | 1 page of `limit=1000` | 173.3, 124.3 | 138.4, 123.3 | 0.5, 0.6 |
| Allocator | `MallocSpaceEfficient=1`, defaults otherwise | 9.6, 9.6, 9.5 | 6.9, 7.3, 6.9 | 8.3, 8.6, 8.6 |
| Bound (5) | at most 1 concurrent `query` call, 8 clients | 8.6, 8.5, 8.5 | 7.5, 7.4, 7.5 | 12.9, 12.5, 15.1 |
| Bound (5) | at most 2 concurrent `query` calls, 8 clients | 8.8, 8.8, 9.0 | 7.7, 7.8, 8.0 | 8.9, 8.1, 8.3 |
| Bound (5) | at most 4 concurrent `query` calls, 8 clients | 1,060.7, 742.8, 888.0 | 832.9, 528.4, 1,045.0 | 6.9, 5.2, 6.6 |

- **Variability.** The growth is stochastic. It depends on how threads land on CPUs, not only on how
  many there are: 3 clients grew in 2 runs of 3, while 4 clients stayed bounded in 4 runs of 4.
- **(e) Read transaction lifetime** (one per page against one per query) was not tested. The
  space-efficient run removes the growth with one read transaction per page unchanged, so transaction
  handling is not the cause.

## Evidence at the peak

**`heap -s`** while RSS was above 300 MB (8 clients, 40,000 queries; RSS later reached 843 MiB):

```text
All zones: 2008 nodes malloced - Sizes: ... 5KB[1063] 2.5KB[94] ... 512[97] ...
All zones: 2008 nodes (6085152 bytes)
```

Live heap: 5.8 MiB. The 1,063 blocks of "5KB" are redb's 4 KiB page buffers (`Arc<[u8]>` of 4,096
bytes plus its header, in a 4.5 KiB small-zone slot): the 4 MiB cache plus pages in flight.

**`vmmap -summary`** at the same instant:

```text
Physical footprint:         163.0M
MALLOC_SMALL                      56.0M    27.5M    26.7M     272K ...   14
MALLOC_SMALL (empty)             380.0M    69.7M    69.6M    63.3M ...   95
DefaultMallocZone_0x104998000     442.2M      99.2M      98.3M      63.6M       2003      5918K     156.1M     97%     116
```

The default zone holds 5.9 MB allocated against 98.3 MB resident and 63.6 MB compressed, with 97%
fragmentation. Most of it sits in 95 empty small regions.

**`malloc_history -allBySize`** under `MallocStackLogging=1`, with the process stopped at 105 MB RSS.
Live allocations total about 15 MB. The largest groups are:

- 8.7 MB in 11 allocations from start-up;
- 1,003 page buffers (5.1 MB) on the client threads.

That run ended at 840 MB RSS.

## redb 4.4.0 source

Read-only reading of `src/tree_store/page_store/cached_file.rs`:

- **Misses allocate.** `PagedCachedFile::read` allocates a new zero-filled `Arc<[u8]>` of the page size
  on every miss (`read_direct_into_arc`, `zero_filled_arc`: one allocation per miss).
- **Evicted pages are freed by another thread.** The page is inserted into one of 131 read-cache
  stripes (`offset % 131`). When the total exceeds the budget, one page is evicted from the same stripe.
  The evicted page is freed when its last `Arc` is dropped, by whichever reader thread held it last,
  often not the one that allocated it.
- **The cache keeps to its budget.** Read cache plus write buffer stay at or under `max_cache_size`
  (soft limit, "one page" of slack per concurrent miss). This matches the roughly 1,000 live page
  buffers counted by `heap`.

So redb's per-miss allocations explain the allocation and free traffic, but redb does not retain the
pages: the retained memory is free memory inside libmalloc. The pattern that triggers it is concurrent
4 KiB allocations and cross-thread frees from 3 or more threads. The simulated churn above did not
reproduce it, so some feature of redb's traffic not modelled here also matters: the interleaving with
other allocations of the read path, or the timing. This part is a hypothesis.

## Proposed bound

1. **Bound concurrent index reads to 2** (relay setting `index_max_readers`, default 2). In relay
   milestone 1, the `/query` handler acquires a `tokio::sync::Semaphore` permit before it calls
   `IndexBackend::query` on the blocking pool. The permit is held for one page.
   - Measured effect on the reproduction (8 clients, defaults): max RSS 8.8–9.0 MiB in 3 runs of 3,
     against 415–873 MiB without the bound.
   - Cost: 8.1–8.9 s for the 20,000 queries, against 4.9–8.1 s.
   - A bound of 4 does not hold. A bound of 1 holds but costs more (12.5–15.1 s).
   - The semaphore is also a portable limit on concurrent work per relay. It is worth keeping even if
     Linux shows no growth.
2. **Not proposed:**
   - Changing the redb cache size: 1 MiB and 16 MiB both grow.
   - A cap on bytes per `/query`: at equal volume, `limit=100` grows as much as `limit=1000`.
   - An alternative global allocator such as mimalloc: a new dependency, not added. It is an option to
     report to the owner if Linux shows the same growth.
3. **macOS only:** `MallocSpaceEfficient=1` bounds the process with no code change (9.5–9.6 MiB, same
   throughput). It is useful for development measurements and irrelevant to the shipped musl binary.

## What Linux must confirm

The gate binary is `x86_64-unknown-linux-musl`, which uses musl's mallocng, not libmalloc.

1. Run `query_diag query` with the defaults (8 clients, no bound) and read `VmHWM`. If it stays near the
   bounded figures (under about 15 MiB), the growth is macOS-specific. The semaphore then remains a
   defence-in-depth limit, not a fix.
2. If musl shows growth, repeat with `max_readers=2` and `max_readers=4` to find the bound on Linux.
3. Record the throughput cost of the bound on the gate machine, so that the setting can be chosen there.
4. The gate run itself (ADR 0013, ADR 0017) must use the real relay over HTTP. The figures in this file
   are informative only (ADR 0017 rule 2).
