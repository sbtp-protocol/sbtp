# Archive copy and replication: size, memory and performance (informative)

- Date: 2026-11-21. Branch `feat/relay-object-mirror` (ADR 0050 stage 1).
- Status: **informative**. Not the ADR 0013 gate: the machine is an Apple Silicon laptop (macOS, 8
  cores, APFS), not the Linux gate VM, and the binaries are the host `aarch64-apple-darwin` build, not
  the shipped `x86_64` musl build.
- Harness: `crates/sbtp-relay/examples/mirror_bench.rs` (needs `--features object-store`). It follows
  the subject rules of ADR 0017 (rules 1 to 3): the relay binary runs as its own process and is driven
  over loopback HTTP by the harness, whose memory is not measured. The S3-compatible store is a fake
  in the harness process, on loopback (it checks every SigV4 signature and honours
  `If-None-Match: *`), with added latency and injected failures. No network, no container.

## Conclusions

1. **The archive copy does not back-pressure ingest.** Client `PUT` p50/p99 stay at 20–23 ms / 34–40
   ms whatever the store does: no mirror, a fast store, 200 ms per request, a 10 s burst of `503`, or
   one `PUT` in three failing. The relay's `PUT` latency on this machine is dominated by the durable
   write (APFS `fsync`), not by the mirror.
2. **Binary cost of `object-store`: +115,904 bytes** over the default build (+54,646 gzip), under the
   150 KB estimate of ADR 0050 rule 26.
3. **Memory cost: about +0.5 MiB resident** at idle and +0.1 to +0.4 MiB at peak with the mirror on
   (macOS RSS). The uploader holds at most `mirror_max_in_flight` blocks at once; its peak did not grow
   with a backlog of 5,000 blocks or with a store answering in 200 ms.
4. **Uploader throughput is bounded by `mirror_max_in_flight / store latency`, and below that by a
   per-page barrier.** See "Possible problems" 1 and 2: the `small` default (1 lane) copies at most
   about 28 blocks/s against a store 20 ms away and 15 blocks/s at 50 ms.
5. **SigV4 signing is cheap:** 2.6–3.2 µs per request plus the payload SHA-256 (1.4 µs at 1 KiB,
   24 µs at 64 KiB).

## Sizes

Release profile, `cargo build --release --locked -p sbtp-relay --bin sbtp-relay`, host target
(`aarch64-apple-darwin`). `object-store` implies `replication` (it reuses its outbound client), so
"`object-store` only" is not a build; `object-store` is "all".

| Features | Binary (bytes) | gzip -9 (bytes) |
|---|---|---|
| none (`--no-default-features`) | 2,425,408 | 1,167,410 |
| `replication` (default) | 3,520,224 | 1,805,159 |
| `object-store` (= all; the image's build) | 3,636,128 | 1,859,805 |

The container image was not built: the distroless runtime base of `deploy/Dockerfile` is not in the
local image store and pulling it was out of scope. The CI `budgets` job builds the image with the
Dockerfile's features (`object-store`) and checks the 8,000,000-byte binary and 5,000,000-byte
compressed image budgets.

## Client-facing load, memory and CPU

Each run: a fresh relay, `small` profile, 5,000 blocks of 1,024 payload bytes (1,142 bytes on the
wire), `PUT` from 4 keep-alive clients as fast as the relay answers, then 5,000 `GET`s spread over the
set, then the wait for the copy. Settings changed from `small`, because every connection comes from
one loopback client key: the per-client rates lifted to 1,000,000/min, `ingest_bytes_per_hour = 0`,
`put_max_in_flight_per_client = 4`, `min_pow_difficulty = 0` (the check costs the same; only mining
would differ). Three runs of each; values are run 1 / run 2 / run 3. RSS is `ps` sampled every
100 ms (macOS has no `VmHWM`), so a peak shorter than 100 ms can be missed.

| Scenario | PUT/s | PUT p50 (ms) | PUT p99 (ms) | Idle RSS (KiB) | Peak RSS (KiB, max of 3) | Relay CPU (s) |
|---|---|---|---|---|---|---|
| binary without features, mirror off | 180/184/187 | 22.0/21.5/20.9 | 37.0/36.3/35.2 | 5,584/5,600/5,536 | 12,640 | 16.0/16.2/14.4 |
| default binary, mirror off | 177/185/191 | 22.2/21.3/20.7 | 37.2/35.8/35.9 | 10,352/10,336/10,272 | 17,408 | 15.9/16.5/14.3 |
| `object-store` binary, mirror off | 178/184/183 | 22.0/21.5/21.6 | 37.4/36.5/36.0 | 10,208/10,208/10,192 | 17,392 | 15.5/16.4/15.5 |
| mirror on, 1 lane, store 0 ms | 154/184/193 | 21.5/21.2/20.4 | 92.9/37.7/34.3 | 10,784/10,768/10,704 | 17,392 | 15.9/16.4/15.8 |
| mirror on, 4 lanes, store 20 ms | 187/185/189 | 21.1/21.3/20.9 | 36.0/36.3/35.8 | 10,768/10,752/10,720 | 17,520 | 17.0/16.9/17.2 |
| mirror on, 8 lanes, store 20 ms | 189/192/194 | 20.7/20.5/20.2 | 36.9/34.3/35.0 | 10,800/10,768/10,752 | 17,120 | 16.2/16.0/16.0 |
| mirror on, 4 lanes, store 200 ms | 185/183/185 | 21.1/21.7/21.4 | 36.1/35.1/35.3 | 10,896/10,816/10,848 | 17,776 | 17.7/20.0/19.6 |
| 4 lanes, 20 ms, `503` from 2 s to 12 s | 180/187/183 | 21.8/21.1/21.5 | 37.7/35.2/35.9 | 10,752/10,768/10,752 | 17,744 | 18.6/18.0/19.6 |
| 4 lanes, 20 ms, every 3rd `PUT` `503` | 184/185/183 | 21.2/21.3/21.7 | 37.1/35.8/35.9 | 10,752/10,832/10,816 | 17,824 | 16.7/18.9/17.9 |
| replication on (2 relays), mirror off | 172/171/169 | 22.8/23.0/23.1 | 40.1/38.9/41.1 | 10,928/10,896/10,928 | 17,488 | 15.9/15.8/16.6 |
| replication on + mirror 4 lanes, 20 ms | 173/172/165 | 22.7/22.7/23.3 | 39.9/39.3/47.8 | 11,072/11,056/11,152 | 17,712 | 18.6/18.3/17.6 |

- The one high p99 (92.9 ms, mirror 1 lane, run 1) did not repeat; its runs 2 and 3 match the
  baseline.
- `GET` (5,000 per run): p50 1.2–1.5 ms and p99 1.9–5.1 ms with the mirror off; p50 0.26–0.43 ms in
  most runs with a busy uploader. The faster `GET`s with more background work are unexplained; a
  plausible cause is macOS core and frequency scheduling of a busier process. Not investigated.
- Relay CPU is about 3 ms per accepted block on this machine with or without the mirror; the mirror
  adds 0.1–0.9 ms per block (more with failures and slow stores, which keep connections and timers
  busy longer).
- With replication on, the peer held every block 48–63 s after the `GET` phase (`small`:
  `replication_max_in_flight = 1`, poll every second, no rate bound for the test).

## Uploader throughput (backlog drain)

`--backlog`: the 5,000 blocks are stored by a relay without the mirror, which then restarts with it;
the rate is first to last arrival at the store. One run each.

| Lanes | Store latency | Blocks/s | MB/s | Drain time (s) | Relay CPU (s) | Peak RSS (KiB) |
|---|---|---|---|---|---|---|
| 1 | 0 ms | 224 | 0.26 | 22.4 | 4.3 | 12,128 |
| 1 | 20 ms | 28 | 0.03 | 177.7 | 6.3 | 12,064 |
| 1 | 50 ms | 15 | 0.02 | not done in 300 s (4,587) | 5.5 | 12,080 |
| 4 | 0 ms | 2,222 | 2.54 | 2.4 | 1.6 | 12,352 |
| 4 | 20 ms | 116 | 0.13 | 43.4 | 4.9 | 12,384 |
| 4 | 50 ms | 62 | 0.07 | 81.5 | 5.1 | 12,432 |
| 8 | 0 ms | 2,782 | 3.18 | 1.9 | 1.5 | 12,656 |
| 8 | 20 ms | 224 | 0.26 | 22.5 | 4.4 | 12,688 |
| 8 | 50 ms | 120 | 0.14 | 42.0 | 4.7 | 12,736 |
| 1 | 0 ms, 64,000-byte payloads (2,000 blocks) | 167 | 10.9 | 12.0 | 2.5 | 11,696 |
| 4 | 0 ms, 64,000-byte payloads | 1,987 | 129.4 | 1.1 | 0.65 | 12,432 |
| 8 | 0 ms, 64,000-byte payloads | 2,423 | 157.8 | 0.9 | 0.50 | 12,496 |

## Lag under sustained ingest

3,000 blocks paced at 100 blocks/s for 30 s, store 20 ms. Lag is the time from the client's `201` to
the object's arrival at the store.

| Lanes | Lag p50 (ms) | Lag p99 (ms) | Lag max (ms) | Copy rate (blocks/s) | Drained after last `201` (s) | Client PUT p50/p99 (ms) |
|---|---|---|---|---|---|---|
| 1 | 33,273 | 61,133 | 61,697 | 33 | 61.7 | 9.8 / 21.8 |
| 4 | 121 | 943 | 1,001 | 103 | 0.1 | 10.3 / 19.4 |
| 8 | 34 | 812 | 985 | 103 | 0.0 | 10.9 / 20.6 |

When the uploader keeps up, its lag is bounded by its 2-second idle poll (`IDLE` in
`src/mirror/mod.rs`): p99 just under 1 s, max about 2 s in the unpaced runs.

## A slow or failing store

From the client-facing table:

- 200 ms per request, 4 lanes: the copy runs at 19 blocks/s and ends 237 s after the last `201`;
  client latency unchanged.
- `503` for 10 s: every lane backs off (1, 2, 4, 8 s, jittered) and recovers after the window; the copy
  ends 25–36 s after the last `201` instead of 14–15 s; 16–17 extra `PUT`s.
- One `PUT` in three answered `503`: the copy falls to 7 blocks/s and only 2,318–2,366 of 5,000 blocks
  were copied after 300 s. Client latency unchanged.

## SigV4 signing cost

`mirror_bench sigv4`, 20,000 iterations, the headers the uploader signs for a block.

| Body | SHA-256 of the payload (µs) | `authorization()` (µs) | Total per `PUT` (µs) |
|---|---|---|---|
| 1,024 bytes | 1.44 | 3.17 | 4.61 |
| 16,384 bytes | 6.42 | 2.62 | 9.04 |
| 65,000 bytes | 24.01 | 2.62 | 26.62 |

At the 2,782 blocks/s of the fastest drain, signing is about 1.3% of one core.

## Possible problems

1. **The `small` default of one lane copies slowly against a distant store.** With 1 lane the copy
   rate is about 1 / (store latency + about 15 ms of local work per block on this machine): 28
   blocks/s at 20 ms, 15 at 50 ms. A relay that accepts more than that for long builds a backlog that
   only drains when ingest slows. Not a memory risk (the backlog is the index, not RAM), but the
   archive lags. Operators of a busy relay should raise `mirror_max_in_flight`; the profile rows
   (1/4/8) look right for `standard` and `large`. **Since changed:** `small` has 4 lanes, after
   the MinIO runs above.
2. **A page barrier.** The cursor moves once every block of a 64-block page is done, so one slow or
   failing block holds its page's other lanes idle. With 4 lanes at 20 ms the drain reaches 116
   blocks/s against an ideal near 160; at 0 ms, 4 lanes are ten times faster than 1 (2,222 against 224
   blocks/s), which suggests per-block local work that the lanes overlap. Not investigated further.
   **Since changed:** the lanes take blocks from a window of four pages from the cursor, which is the
   oldest block not yet done; a failing block waits out its back-off in the window, not in a lane.
   Re-measured (same laptop, fake store, backlog of 2,000 blocks, 4 lanes, 20 ms): 120 blocks/s.
3. **A store that fails part of the requests collapses the copy rate.** With one `PUT` in three
   answered `503`, each failure sleeps its lane for 0.5 to 1 s (more on a repeat failure), and the
   page barrier makes the other lanes wait for it: 7 blocks/s. This is the ADR 0050 rule 9 back-off
   working as written, against a store that is shedding load; worth knowing when a provider throttles
   with `503 SlowDown`. Client traffic is not affected. **After the window change** (backlog of 2,000
   blocks, 4 lanes, 20 ms, every third block `PUT` answered `503`): 12 blocks/s with the default
   `mirror_max_backoff_s` (one hour), and, in the integration test (300 blocks, no added latency,
   `mirror_max_backoff_s = 1`), 51.6 blocks/s against 9.4 before. With the one-hour cap the rate
   stays low: rule 9 doubles a block's back-off at each failure, the block with the longest run
   of failures holds the cursor, and the window can only get four pages past it. A simulation of
   the lanes gives the same picture: about 8 blocks/s with a two-page window, 12 with four, 14 with
   sixteen, against 43, 66 and 104 with a 1 s cap. Only a change of the back-off itself (for
   example, a per-block exponent that stops growing while the store answers other `PUT`s with
   `2xx`) would lift it; that is rule 9, not an internal detail.
4. **macOS resident size with the outbound TLS client.** Any build with `replication` starts at about
   10.2 MiB resident against 5.5 MiB without, although no TLS connection is made. A plausible cause is
   the macOS system frameworks the native trust store links (their pages are counted in RSS). The
   shipped build is static musl on Linux; the Linux gate VM is the place to check. The peaks here
   (12.5–17.8 MiB) are macOS figures and say nothing about the ADR 0013 thresholds.
5. **Per-block CPU** of about 3 ms on this machine for an accepted block, mirror off, is mostly the
   durable write path on APFS; it is not affected by the mirror.

## MinIO (LAN, single node)

A single-node MinIO on the LAN, TLS, path-style, with the commands of "Remote runs" below. These
runs **predate** two later changes on this branch: `mirror_max_in_flight` on `small` raised from 1
to 4, and the uploader's window that lets the other lanes go on while one block is in back-off
(see "Possible problems" 2 and 3). Run 1 is the relay with ingest paced at 50 blocks/s; run 2 is
`s3put`, the uploader's `PUT` sent straight to the store; run 3 is a backlog drain.

| Run | Phase | Requests | p50 | p99 | Max | Throughput |
|---|---|---|---|---|---|---|
| 1 | relay at 50/s, in_flight 1 (6,000 blocks) | client PUT 6,000 × 201 | 8.5 ms | 17 ms | | upload lag p50 66 s, p99 119 s |
| 1 | relay at 50/s, in_flight 4 | client PUT | 9.7 ms | 19 ms | | lag p50 319 ms, p99 730 ms |
| 1 | relay at 50/s, in_flight 8 | client PUT | 10.0 ms | 17 ms | | lag p50 318 ms, p99 494 ms |
| 1 | RSS peak, in_flight 1 / 4 / 8 | | | | | 21.7 / 24.4 / 24.5 MiB |
| 2 | s3put, 1 lane, 3,000 blocks | 200 | 36 ms | 77 ms | 166 ms | 25/s |
| 2 | s3put, 4 lanes, 6,000 blocks at 100/s | 200 | 37 ms | 81 ms | 372 ms | 100/s |
| 2 | rerun of the same 6,000 blocks | 6,000 × 412 | 35 ms | 81 ms | 499 ms | 100/s |
| 3 | backlog drain, 8 lanes, 6,000 blocks (47.7 MB) | | | | | 37.6 s, 160 blocks/s, 1.27 MB/s, relay CPU 3.0 s, RSS 20 MiB, `mirror_failed` 0 |

- The store answers a `412` in the same time as a `201`: a rerun of a copied range costs as many
  round trips as the first copy.
- One lane copies about 25 blocks/s (1 / 36 ms plus local work), below the 50 blocks/s of ingest,
  so the lag of run 1 grew for the whole run; 4 lanes kept it under 1 s. This is why `small` now
  has 4 lanes.
- The store's disk peaked at 13 % utilisation: the uploader, not the store, was the bottleneck.
- The first `PUT` of the session (5.3 s) was a local firewall prompt and is excluded as warm-up.
- In run 1, each sub-run logged one `mirror_failed` line: the bucket policy covered only
  `sbtp/v1/block/*`, so the `/info` `PUT` got `403`. Block uploads were not affected.
  `deploy/README.md` now shows a policy that covers both keys.
- RSS is the macOS figure of the relay process (see "Possible problems" 4).

## Remote runs

The harness drives a real endpoint as follows. The endpoint and the credentials come only from
environment variables, the rest from flags; neither the endpoint nor a credential is ever printed
or written to a file.

- MinIO: `SBTP_MIRROR_BENCH_MINIO_ENDPOINT`, `SBTP_MIRROR_BENCH_MINIO_ACCESS_KEY_ID`,
  `SBTP_MIRROR_BENCH_MINIO_SECRET_ACCESS_KEY`.
- S3-compatible provider: `SBTP_MIRROR_BENCH_S3_ENDPOINT`, `SBTP_MIRROR_BENCH_S3_ACCESS_KEY_ID`,
  `SBTP_MIRROR_BENCH_S3_SECRET_ACCESS_KEY`.

Build once:

```sh
cargo build --release --locked -p sbtp-relay --features object-store --bin sbtp-relay --example mirror_bench
```

With `T="--target minio --bucket <bucket> --region us-east-1 --url-style path --allow-private"`
(`--target s3 --region auto`, without `--allow-private`, for a provider) and the three variables in the
environment of the command only:

```sh
B=target/release/examples/mirror_bench; REL=target/release/sbtp-relay
# Uploader throughput and lag under sustained ingest, client-facing latency while it runs.
$B run --relay $REL --work <scratch> $T --mirror remote --in-flight 4 --blocks 6000 --payload-mix \
  --rate 50 --max-rate 150 --max-puts 6000 --probe-every 20 --max-heads 1000 --drain-timeout-s 120
# Burst: the uploader alone on a stored backlog, 8 lanes.
$B run --relay $REL --work <scratch> $T --mirror remote --backlog --in-flight 8 --blocks 6000 \
  --payload-mix --max-puts 6000 --max-rate 150 --probe-every 50 --drain-timeout-s 120
# The store's PUT latency distribution, then the same blocks again (expect 412).
$B s3put $T --blocks 6000 --payload-mix --rate 100 --max-rate 150 --max-puts 6000 --in-flight 4 \
  --save-blocks <scratch>/blocks.bin
$B s3put $T --load-blocks <scratch>/blocks.bin --rate 100 --max-rate 150 --max-puts 6000 --in-flight 4
```

A block count above `--max-puts` is refused (default 200); `--rate` is capped at `--max-rate`
(default 10/s). Each block is one bucket `PUT` plus its retries, plus one `PUT` of `/info`, plus at
most `--max-heads` signed `HEAD` probes. The guards of the file's documentation stop a run on a
store p99 above 1 s, on `5xx`/`507` answers or on relay `mirror_failed` lines. `fake-s3` runs the
fake store alone so that these commands can be tried offline first (`..._ENDPOINT` set to its
printed `http://127.0.0.1:<port>`, bucket `bench`).
