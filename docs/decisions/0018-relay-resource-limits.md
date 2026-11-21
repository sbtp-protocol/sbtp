# 0018: Relay resource limits (admission control)

- Status: accepted (by the project owner, 2026-11-19), with owner decision: the 15 MB memory target is a
  worst-case bound, so the default of `max_connections` is 32
- Amended by: 0019 (rules 6, 8, 22, 26 and 28: key set, defaults, new-connection timer, per-client bound;
  profiles); 0020 (rules 20, 21 and 22: reading of `X-Forwarded-For`, class of unrouted requests and preflights, CIDR validation); 0021 (rules 6, 22 and 35: logging and disk settings, memory bound); 0023 (rule 18: a signature is also verified in a block-read permit and in the start-up walk); 0027 (rule 21: cost bound of the limiter table; rule 35: entry estimate, 192 bytes by its clarification T1); 0028 (rule 21: a fourth bucket, `tls`; rule 22: TLS settings and constraint; rule 28: steps 1a to 1c with TLS on; rule 35: TLS term); 0040 (rule 6: key set, `info_graph_gateway`); 0044 (rule 6: key set, `client_ip_header`; rule 20: the client address can come from `client_ip_header`); 0046 (rule 35: demand set term in the memory bound); 0048 (rule 35: replication terms); 0049 (rule 35: ingest group table term); 0050 (rule 35: archive copy and read-through terms, added when those functions are on); 0051 (rule 21: request weight, `⌈N/4⌉` `block` tokens for a batch of `N` identifiers and `⌈N/8⌉` `query` tokens for `N` parents, capped at the burst, at admission; rule 22, by its clarification B6: `rate_block_burst` 64 to 1,000,000 and `rate_query_burst` 4 to 1,000,000); 0052 (rule 35: deny list term `2 × deny_max_entries × 80`, counted only when `deny_file` is set)
- Clarifications: 2026-11-19, after relay milestone 1c-b (M1 to M4: index lookups of the `PUT` path,
  start-up walk, started jobs, `Retry-After`), accepted by the project owner, 2026-11-19. Rule 21 (limiter
  table cost): ADR 0027, accepted. 2026-11-19, after relay milestone 1c-b2 (M5: start-up constraint
  `rate_limit_max_clients >= 2 × max_connections`), accepted by the project owner, 2026-11-19.
  2026-11-19, after relay milestone 1c limits (M6: which index failures count toward the fatal exit
  of rule 37), accepted by the project owner, 2026-11-19
- Date: 2026-11-18
- Questions: none resolved. Opens Q-26 (client-side and P2P peer bounds) and Q-27 (cursor validity after
  an unclean shutdown). Carries out the rate-limiting task that ADR 0007 and ADR 0012 rule 31 left to
  the relay implementation
- Amends, if accepted: ADR 0012 rule 17 (adds the error name `RequestTimeout`, status `408`) and rule 16
  (exception for responses produced by the HTTP layer before any relay code runs). Nothing else in
  ADR 0012 changes. ADR 0013 and ADR 0017 are not amended
- Depends on: ADR 0008 (body limit, `413`), ADR 0012 (`/query` cap, `429`, `503`, error body), ADR 0013
  (index, sweeper, quota, `507`, benchmark gate), ADR 0014 (`MAX_BLOCK_LEN` = 65,909), ADR 0017 (gate
  protocol)
- Impact: spec §4 (new "Admission control" subsection, `408`, wording of `429` and `503`; see "Spec
  change", not applied); `sbtp-relay` (settings, connection loop, limiter, index reader pool, bounded
  operations, supervision); `deploy/` (memory limit on the unit and the container); workspace
  dependencies (`tower-http` features, possibly `hyper-util` as a direct dependency); no `sbtp-core`
  change; no layer 0 test vector

## Context

A relay is exposed to the Internet without authentication. Reads need no proof of work. Until now
nothing bounds how many requests a relay serves at once, how long a request may last, or how much memory
the open connections may hold. The relay's memory and CPU use therefore depend on what clients do.

The project owner's requirement (2026-11-18): each node operator sets the parallelism and the limits of
its own node. The principle agreed between the owner and the maintainer is **admission control**:

- every request has a bounded cost;
- the number of concurrent operations is bounded;
- beyond the bounds the relay refuses (`429` or `503`, with `Retry-After`) instead of consuming resources.

Relay memory must depend on the relay's settings, not on client behaviour.

Two inputs make this concrete:

- **Memory diagnosis** (`docs/benchmarks/2026-11-18-query-memory-diagnosis.md`, branch
  `diag/relay-query-memory`). Up to 2.6 GB of resident memory under 8 concurrent `/query` clients on
  macOS. The memory is freed memory kept by libmalloc after redb's concurrent reads; live heap was 6 to
  15 MB. With at most 2 concurrent index reads the process stayed near 9 MiB; with 4 it did not. The
  trigger was not identified. The shipped binary uses musl's allocator, which was not measured.
- **Security review of the relay index** (`docs/security/2026-11-18-relay-index.md`, finding F-1, high,
  gates any Internet exposure). A semaphore in the `/query` handler is not a sufficient bound: the
  measured configuration had 8 fixed threads, not tokio's blocking pool; the number and identity of the
  threads that touch the index matters; a permit held by the handler is released when the client resets
  the connection while the read still runs; `contains`, `expired` and the writer were left unbounded; the
  waiters were unbounded.

Limits that already exist and stay as they are: the body limit and `413` (ADR 0008 rules 7 and 8, value
from ADR 0014), `min_pow_difficulty` and `max_future_ms` (ADR 0007), `max_query_limit`, `429`, `503` and
`Retry-After` (ADR 0012), `block_ttl_ms`, `max_store_bytes`, `507`, the sweeper settings and
`index_cache_bytes` (ADR 0013).

**Scope.** The `sbtp-relay` server program: a self-hosted micro-relay (target: a VPS with 1 to 2 vCPU and
1 GB of RAM, or a Raspberry Pi), a managed relay with higher values, and a future desktop super-peer
daemon that embeds the relay logic with the same settings. Out of scope: PWA and browser clients, static
mirrors, client-side bounds and peer-to-peer limits (Q-26).

### Library facts checked on 2026-11-18

The workspace pins `axum = "0.8.9"`, `tower-http = "0.7.1"`, `tokio = "1.54.1"`; branch
`diag/relay-query-memory` pins `redb = "=4.4.0"`. `hyper`, `hyper-util` and `tower` are not in
`Cargo.lock` on `main` yet: the versions below are the latest on docs.rs, and the implementer MUST
confirm each fact against the versions that `Cargo.lock` resolves.

| Fact | Source |
|---|---|
| `axum::serve` "is intentionally simple and doesn't support any configuration"; for more control, hyper or hyper-util is used directly. `axum::serve::ListenerExt` has one method, `tap_io`. There is no connection limit and no timeout setting in `axum::serve` 0.8.9. | docs.rs `axum/0.8.9`, `fn.serve`, `serve::ListenerExt` |
| axum treats every routed service as always ready and drives readiness inside the response future. Its docs say to avoid middleware that relies on backpressure inside a router, and to "load shed so requests are dropped quickly and don't keep piling up". A middleware error that is not `Infallible` needs `HandleErrorLayer`. | docs.rs `axum/0.8.9`, `middleware`, "Routing to services/middleware and backpressure" |
| `tower::limit` (`ConcurrencyLimitLayer`, `GlobalConcurrencyLimitLayer`, `RateLimitLayer`; feature `limit`) and `tower::load_shed` (`LoadShedLayer`, "sheds load when the inner service isn't ready"; feature `load-shed`) exist in tower 0.5.3. `RateLimitLayer` is not keyed by client. | docs.rs `tower/0.5.3`, `limit`, `load_shed` |
| `tower_http::timeout` (feature `timeout`): `TimeoutLayer::with_status_code(status, duration)` returns a response with an empty body and the given status; `TimeoutLayer::new` is deprecated since 0.6.7 and answers `408`. `RequestBodyTimeoutLayer` and `ResponseBodyTimeoutLayer` apply a timeout to a body. `RequestBodyDeadlineLayer` and `ResponseBodyDeadlineLayer` enforce "a hard time limit on the whole transfer". | docs.rs `tower-http/0.7.1`, `timeout` |
| `tower_http::catch_panic::CatchPanicLayer` (feature `catch-panic`) converts a panic into a `500` response; `CatchPanicLayer::custom` takes a function that builds the response. | docs.rs `tower-http/0.7.1`, `catch_panic` |
| hyper HTTP/1 server builder: `header_read_timeout` (default 30 seconds; needs a timer set with `timer`, panics without one; the connection is closed on expiry); `max_buf_size` (default about 400 KB, minimum 8,192); `max_headers` (default 100; `431` beyond). No idle keep-alive timeout is documented on that page. | docs.rs `hyper/1.12.0`, `server::conn::http1::Builder` |
| hyper HTTP/2 server builder: `max_concurrent_streams` (default 200), `max_header_list_size` (default 16 KB), `max_send_buf_size` (about 400 KB per stream). | docs.rs `hyper/1.12.0`, `server::conn::http2::Builder` |
| `hyper_util::server::conn::auto::Builder` exposes `http1()`, `http2()`, `http1_only()`, `serve_connection`. | docs.rs `hyper-util/0.1.21` |
| tokio runtime builder: `worker_threads` defaults to the number of cores; `max_blocking_threads` defaults to 512; a blocking task beyond the limit is queued and "the queue does not apply any backpressure, it could potentially grow unbounded"; idle blocking threads exit after 10 seconds; thread stacks default to 2 MiB. | docs.rs `tokio/1.54.1`, `runtime::Builder` |
| A `spawn_blocking` task "cannot be aborted" once it runs. For long-lived blocking work the docs say to "prefer a dedicated thread". | docs.rs `tokio/1.54.1`, `task::spawn_blocking` |
| `tokio::sync::Semaphore` is fair (permits in request order), has `try_acquire` and `acquire_owned`, and sets no bound on the number of waiters. `mpsc::channel(n)` has a fixed capacity and `try_send` fails when it is reached. `oneshot::Sender::is_closed` returns true once the receiver is dropped; `send` is synchronous. | docs.rs `tokio/1.54.1`, `sync` |
| redb `Builder::set_cache_size(bytes)`; default 1 GiB. redb has one writer and several concurrent readers (MVCC). | docs.rs `redb/4.4.0`, `Builder`; Context7 `/cberner/redb`, `docs/design.md` |
| systemd `MemoryMax=`: "If memory usage cannot be contained under the limit, out-of-memory killer is invoked inside the unit." | freedesktop.org, `systemd.resource-control` |

Not checked: whether hyper's `header_read_timeout` also bounds the wait for the next request on an idle
keep-alive connection; the exact response hyper sends for a malformed request or oversized headers;
`hyper_util::server::graceful`; `Receiver::blocking_recv`; the default size and weigher of moka; any
per-client rate-limiting crate (none is required by this ADR); the upstream protocol that Caddy speaks to
a plain-HTTP backend by default.

Every memory figure in bytes per connection or per request below is an estimate from buffer sizes. None
was measured.

## Decision

### Principles

1. **Bounded cost.** Every request MUST have a cost bounded by constants and settings: time (rules 23
   to 27), memory (rule 35) and index work (ADR 0012 rule 14).
2. **Bounded concurrency.** Every operation that reads the index, reads or writes a block file, buffers
   a request body or verifies a signature MUST run under one of the bounds of rules 9 to 18. No code path
   may reach the index, the block files or the blocking pool outside these bounds.
3. **Refuse, do not absorb.** At a bound the relay refuses with `429` or `503` (rules 28 to 32). It MUST
   NOT wait without a time limit and MUST NOT keep an unbounded queue.
4. **Settings decide.** The peak memory of the relay process MUST be a function of its settings (rule
   35), not of the number or the behaviour of clients.
5. **One set of settings.** The limits below are local settings of a relay. They are not protocol
   values. A daemon that embeds the relay logic uses the same names and rules.

### Configuration

6. **Sources and precedence**, lowest to highest: built-in default; configuration file; environment
   variable. The file is given by `--config <path>` or `SBTP_RELAY_CONFIG`; with neither, no file is
   read. The file is a flat TOML table whose keys are the setting names of this ADR and of ADRs 0007,
   0012 and 0013. The environment variable of a setting is `SBTP_RELAY_` followed by its name in upper
   case (`SBTP_RELAY_MAX_CONNECTIONS`). A list is a TOML array in the file and a comma-separated string
   in the environment.
7. **Validation at start-up.** An unknown key, a value of the wrong type, a value outside its range or a
   broken constraint between settings (rule 22) MUST stop the relay before it listens, with a message
   that names the setting. The relay MUST NOT clamp or ignore a bad value. It logs the effective value of
   every setting once at start-up. None of these settings is a secret.
8. **Changes.** Settings are read at start-up. Changing one needs a restart. The built-in defaults are
   the "small VPS" column of the profile table.

### Index access

9. **Dedicated reader threads.** Every index read (`query`, `contains`, `expired`, `len`, and any later
   read) runs on one of `index_max_readers` dedicated threads owned by the index component. The threads
   are created at start-up and live as long as the process. They are not threads of tokio's blocking
   pool. `index_max_readers` is the size of this pool.
10. **One writer thread.** Every index write (insert, remove, flush) runs on one dedicated writer thread
    (ADR 0013 rule 3). The threads that touch the index are these `index_max_readers + 1` threads and no
    others.
11. **Below the callers.** The bound is enforced inside the component that implements `IndexBackend`
    access, not in a handler. Handlers, the `PUT` path, the sweeper and the reconciliation of ADR 0013
    rule 9 all go through it. A caller has no way to read the index on its own thread.
12. **Bounded queue.** Readers take jobs from one queue of at most `index_max_queue` waiting jobs. A job
    is one index call: one page of `/query`, one `contains`, one `expired` batch. A reader thread holds
    no job while a response is written.
13. **Queue full, queue wait, cancellation.**
    - Queue full: the job is refused at once. A request gets `503` (rule 30).
    - Each job carries a deadline, `queue_timeout_ms` after it was queued. A job still queued at its
      deadline is not run: the request gets `503` at the deadline, and the reader that later takes the
      job drops it.
    - A job whose requester is gone (connection closed, request timed out) is dropped when a reader
      takes it, without running.
    - A job that has started runs to its end. It is bounded by ADR 0012 rule 14, and it cannot raise
      the number of threads that touch the index, whatever clients cancel.
    - The sweeper and the reconciliation use the same queue. On a refusal they retry at their next
      period. They MUST NOT bypass the queue.
14. **Clamp in the index.** The index component rejects `limit = 0` and lowers any `limit` or batch size
    to 1,000, independently of the handler (ADR 0012 rule 8; security review F-4).
15. **`index_max_readers` default: provisional.** The default is 2 until the measurement of rule 16 is
    made. It is the only value measured as bounded (macOS, 8 fixed threads, 3 runs).
16. **Decision rule**, fixed before the measurement. The measurement runs on the gate VM
    (`docs/benchmarks/linux-gate-vm-spec.md`), with the `x86_64-unknown-linux-musl` relay over loopback
    HTTP and the reader pool of rules 9 to 13, and follows the check list of the security review
    (F-1, "What the Linux musl check must confirm", points 1 to 7).
    - A value of `index_max_readers` **holds** when, over at least 30 runs with 8 clients, 30 runs with
      32 clients and one soak of at least 30 minutes under the mixed load (`PUT`, `/query`, the sweeper,
      repeated `PUT` of held blocks, clients that reset connections), the largest `VmRSS` sample and
      `VmHWM` are at most 12 MiB (12,582,912 bytes, the threshold of ADR 0013), and the largest `VmRSS`
      of the last third of the soak is at most 1 MiB above that of the first third.
    - The values 2, 4 and 8 are tested.
    - If 2, 4 and 8 all hold, musl shows no growth. The default on Linux musl becomes the number of
      available CPUs, at least 2 and at most 8.
    - Otherwise the default becomes the largest tested value that holds. It is a fixed number and is not
      tied to the CPU count.
    - If 2 does not hold, 1 is tested. If 1 does not hold, the backend decision returns to the project
      owner (ADR 0013 rule 23). An alternative allocator is a new dependency and needs its own review.
17. **Other targets.** On any target that was not measured this way (macOS and Windows for the desktop
    daemon, Linux with glibc) the default stays 2. An operator MAY raise the setting; the relay logs a
    warning when the value exceeds the default of its target.

### Bounded operations

18. Besides the index, three operation classes are bounded. Each has a number of permits and a bounded
    queue of waiters; rule 13 applies to them (queue full, deadline `queue_timeout_ms`, cancellation).

    | Class | Permit covers | Permits | Queue |
    |---|---|---|---|
    | Block read | One read of a block file after a cache miss in `GET /block`. | `block_max_readers` | `block_max_queue` |
    | `PUT` | From before the body is read until the response is produced: body buffer, checks F1 to C3, quota check, file write, index insert. | `put_max_in_flight` | `put_max_queue` |
    | `PUT` per client | The same span, counted per client key (rule 20). | `put_max_in_flight_per_client` | none: `429` |

    - A `GET /block` served from the cache takes no permit and uses no blocking thread. `/info` takes no
      permit.
    - A permit MUST be owned by the code that does the work. When work moves to a blocking thread, the
      permit moves into the closure, so that a cancelled request cannot release a permit while its work
      still runs.
    - At most `put_max_in_flight` signature verifications run at once. No signature is verified outside
      a `PUT` permit.
    - A `PUT` waiting for a permit has not read its body (ADR 0012 rule 29 applies to `503` as well).
19. **Runtime.** The relay sets `worker_threads` and `max_blocking_threads` explicitly. The blocking pool
    serves block file reads and writes, the sweeper's file deletions and the reconciliation only. Every
    blocking task is submitted while a permit of rule 18 is held, or by a single background task, so the
    blocking queue cannot grow beyond the number of permits plus 2.

### Client key and rate limits

20. **Client key.** A request is attributed to a client key:
    - the peer address of the connection; or, when the peer address is in `trusted_proxies`, the
      rightmost address of `X-Forwarded-For` that is not itself in `trusted_proxies` (ADR 0012,
      "Security"). The header is ignored for any other peer;
    - an IPv4 address is its own key;
    - an IPv6 address is aggregated to its first `client_ipv6_prefix` bits (default 64). One /64 is one
      client. IPv4-mapped IPv6 addresses are treated as IPv4.
21. **Token buckets.** Each client key has three token buckets, one per class: `block` (`GET /block` and
    `/info`), `query` (`/query`) and `put` (`PUT`). A bucket holds at most `rate_<class>_burst` tokens
    and refills at `rate_<class>_per_min` tokens per minute. A request takes one token of its class. With
    no token, the request gets `429` (rule 29). The limiter runs before the body is read and before any
    index, file or signature work.
    - **Shared addresses.** Clients behind one NAT address or inside one IPv6 /64 share one key and one
      allowance. The relay cannot tell them apart. The bursts are sized for several users; an operator
      raises them or lists known addresses in `rate_limit_exempt`.
    - **Bounded state.** The limiter holds at most `rate_limit_max_clients` keys. A key whose three
      buckets are full is dropped first. When the table is full of active keys, requests from unknown
      keys share one overflow key with the same allowance as a single client.
    - **Exemptions.** A request whose client key is in `rate_limit_exempt` skips rule 21 and the
      per-client `PUT` bound. The other bounds still apply. Default: empty.
    - The limiter state lives in memory only. Client addresses are not written to persistent logs
      (the implementer rules).

### Settings

22. All durations are integers in milliseconds, all sizes integers in bytes. Constraints checked at
    start-up: `queue_timeout_ms < request_timeout_ms`; `header_timeout_ms ≤ request_timeout_ms`;
    `body_timeout_ms ≤ request_timeout_ms`; `put_max_in_flight_per_client ≤ put_max_in_flight`;
    `max_blocking_threads ≥ block_max_readers + put_max_in_flight + 2`; the open-file limit of the
    process is at least `max_connections + block_max_readers + put_max_in_flight + 32`.

    | Setting | Type | Default | Range | At the limit |
    |---|---|---|---|---|
    | `worker_threads` | integer | number of available CPUs | 1 to 256 | None: work is scheduled on these threads. |
    | `max_blocking_threads` | integer | `block_max_readers + put_max_in_flight + 2` | that sum to 512 | None: rule 19 keeps the queue bounded. |
    | `max_connections` | integer | 32 | 1 to 65,535 | The relay stops accepting. New connections wait in the kernel listen queue. No status code (rule 31). |
    | `max_header_bytes` | integer | 16,384 | 8,192 to 65,536 | Response of the HTTP layer (`431` or `400`), connection closed (rule 33). |
    | `header_timeout_ms` | duration | 5,000 | 1,000 to 60,000 | Connection closed. |
    | `body_timeout_ms` | duration | 10,000 | 1,000 to 120,000 | `408` `RequestTimeout`, connection closed (rule 24). |
    | `request_timeout_ms` | duration | 15,000 | 1,000 to 300,000 | `503` `Unavailable` if no response has started; otherwise connection closed (rule 25). |
    | `idle_timeout_ms` | duration | 30,000 | 1,000 to 600,000 | Connection closed (rule 26). |
    | `index_max_readers` | integer | 2, provisional (rules 15 to 17) | 1 to 64 | Jobs queue (rule 12). |
    | `index_max_queue` | integer | 32 | 0 to 4,096 | `503` `Unavailable`, `Retry-After`. |
    | `block_max_readers` | integer | 4 | 1 to 256 | Requests queue. |
    | `block_max_queue` | integer | 32 | 0 to 4,096 | `503` `Unavailable`, `Retry-After`. |
    | `put_max_in_flight` | integer | 4 | 1 to 1,024 | Requests queue, body unread. |
    | `put_max_queue` | integer | 16 | 0 to 4,096 | `503` `Unavailable`, `Retry-After`. |
    | `put_max_in_flight_per_client` | integer | 2 | 1 to `put_max_in_flight` | `429` `RateLimited`, `Retry-After: 1`. |
    | `queue_timeout_ms` | duration | 1,000 | 100 to 10,000 | `503` `Unavailable`, `Retry-After`. |
    | `shed_retry_after_s` | integer, seconds | 2 | 1 to 3,600 | Value of `Retry-After` on a `503` of rule 30. |
    | `rate_block_per_min`, `rate_block_burst` | integers | 3,000 and 200 | 1 to 1,000,000 each | `429` `RateLimited`, `Retry-After`. |
    | `rate_query_per_min`, `rate_query_burst` | integers | 300 and 20 | 1 to 1,000,000 each | `429` `RateLimited`, `Retry-After`. |
    | `rate_put_per_min`, `rate_put_burst` | integers | 30 and 20 | 1 to 1,000,000 each | `429` `RateLimited`, `Retry-After`. |
    | `rate_limit_max_clients` | integer | 4,096 | 64 to 16,777,216 | Unknown keys share the overflow key (rule 21). |
    | `rate_limit_exempt` | list of CIDR | empty | | |
    | `client_ipv6_prefix` | integer, bits | 64 | 32 to 64 | |
    | `trusted_proxies` | list of CIDR | `127.0.0.1/32`, `::1/128` | | |
    | `block_cache_bytes` | size | 2,097,152 (2 MiB) | 0 to the operator's choice | Least recently used blocks leave the cache. 0 disables it. |

    `block_cache_bytes` is new: `architecture.md` §2 requires a cache "bounded in bytes" and no ADR gave
    its size. The bound counts block bytes.

    Limits defined elsewhere, unchanged and not redefined here:

    | Limit | Default | Defined by | At the limit |
    |---|---|---|---|
    | `PUT` body, `MAX_BLOCK_LEN` (not a setting) | 65,909 bytes | ADR 0008 rules 7 and 8, ADR 0014 | `413` `BodyTooLarge` |
    | `limit` of `/query`; `max_query_limit` | 100; 1,000 (1 to 1,000) | ADR 0012 rules 5 and 8 | lowered, no error |
    | `index_cache_bytes` (redb cache) | 4 MiB | ADR 0013 rule 24 | redb evicts pages |
    | `max_future_ms` | 300,000 | ADR 0007 | `400` `TimestampTooFarInFuture` |
    | `min_pow_difficulty` | operator's choice | ADR 0007 | `400` `InsufficientPow` |
    | `max_store_bytes` | 1 GiB | ADR 0013 rules 18 to 21 | `507` `StorageFull` |
    | `block_ttl_ms`, `sweep_interval_ms`, `sweep_batch` | 30 days; 60,000; 1,000 | ADR 0013 rules 12 to 16 | eviction |

    `index_cache_bytes` keeps its value: the diagnosis measured growth with 1 MiB and with 16 MiB, so the
    cache size is not the lever. This ADR adds only its valid range: 1 MiB to the operator's choice.

    **`/query` pages.** One request returns one page of at most `max_query_limit` identifiers (ADR 0012
    rule 10). The relay never follows a cursor on a client's behalf, so there is no "pages per request"
    setting. How fast a client walks pages is bounded by its `query` bucket. The page cap stays at 1,000:
    at equal volume, pages of 100 grew as much as pages of 1,000 in the diagnosis.

### Time bounds

23. **Headers.** The request line and headers MUST arrive within `header_timeout_ms` of the first byte
    and fit in `max_header_bytes`. The read buffer of a connection MUST NOT grow beyond
    `max_header_bytes`.
24. **Body.** The whole body of a `PUT` MUST arrive within `body_timeout_ms` of its admission. This is a
    deadline on the whole transfer, not a timeout between two reads: a body sent one byte at a time does
    not extend it. On expiry: `408` with the error `RequestTimeout`, the connection is closed, the
    permit is released.
25. **Whole request.** A request MUST end within `request_timeout_ms` of the end of its headers: queue
    wait, body, processing and the transfer of the response. If the deadline passes before a response
    has started, the relay answers `503` `Unavailable` with `Retry-After`. If it passes while the
    response is being sent, the relay closes the connection.
26. **Idle connections.** A connection with no request in progress is closed after `idle_timeout_ms`.
27. **HTTP version.** In relay milestone 1 the listener serves HTTP/1.1 only, so that one connection
    carries one request at a time and `max_connections` also bounds the requests in flight. This uses the
    "MAY" of ADR 0012 rule 2; the reverse proxy still offers HTTP/2 and HTTP/3 to clients. Serving
    HTTP/2 from the relay later requires a bound on streams per connection and on requests in flight,
    in a new ADR.

### Behaviour at the limits

28. **Order of admission.** For every request: (1) connection accepted under `max_connections`;
    (2) headers read; (3) client key and token bucket: `429`; (4) checks that need only the request
    head: path, method, parameter syntax, a `Content-Length` over the body limit (`404`, `405`, `400`,
    `413`); (5) readiness (ADR 0013 rule 11): `503`; (6) the bound of the operation class: `429` for the
    per-client `PUT` bound, `503` for a full queue or an expired wait; (7) body, then processing. A
    refused request takes no token back. Step 7 for `PUT` is the pipeline of spec §4, unchanged.
29. **`429 Too Many Requests`, `RateLimited`: this client is over its own allowance.** Causes: an empty
    token bucket; the per-client `PUT` bound. Another client would have been served. `Retry-After` is the
    time until one token is available, in whole seconds, rounded up, at least 1.
30. **`503 Service Unavailable`, `Unavailable`: the relay is at one of its own bounds.** Causes: a full
    queue; a queue wait longer than `queue_timeout_ms`; `request_timeout_ms` reached before the response
    started; the relay starting or stopping (ADR 0013 rule 11). The request did nothing wrong and the
    same refusal applies to every client. `Retry-After` is `shed_retry_after_s`. A relay MUST NOT use
    `503` for a storage quota (`507`, ADR 0013 rule 19) nor `429` for its own saturation.
31. **Connection cap.** At `max_connections` the relay stops accepting. Waiting connections stay in the
    kernel listen queue, whose length is the listen backlog. The relay sends nothing: a refusal would
    cost an accepted connection each. A reverse proxy in front answers in the relay's place (`502`,
    `504`), which ADR 0012 rule 18 already covers.
32. **Separate classes; what is shed first.** There is no global load estimate. Each class refuses on
    its own bound, and a saturated class does not block the others:
    - `/query` is shed first. It is the most expensive read and has the smallest bound. Nothing is lost:
      the client keeps its cursor and retries.
    - `PUT` is shed second. A `PUT` is idempotent (ADR 0008): the client retries, or publishes to
      another relay. Writes MUST NOT take capacity from reads: a relay whose `PUT` class or storage is
      saturated serves reads normally (ADR 0013 rule 21, extended to load).
    - `GET /block` after a cache miss is shed last among the bounded classes: it costs one file read of
      at most 65,909 bytes and no index access.
    - `GET /block` from the cache and `/info` are refused only by the connection cap and the token
      bucket. They are what a client needs to validate what it already knows about.
33. **Responses of the HTTP layer.** A request that is not valid HTTP, or whose headers exceed
    `max_header_bytes`, is answered or dropped by the HTTP library before any relay code runs. Such a
    response MAY lack the JSON error body of ADR 0012 rule 16. A client already accepts a missing error
    body (ADR 0012 rule 18).
34. **Error body.** Every `408`, `429` and `503` produced by relay code carries the JSON error body of
    ADR 0012 rule 16 and the CORS headers of rules 24 and 25. `RequestTimeout` (`408`) is added to the
    names of ADR 0012 rule 17.

### Memory bound

35. The relay MUST keep its peak memory within a bound computed from its settings:

    ```
    baseline
    + index_cache_bytes + block_cache_bytes
    + max_connections × (max_header_bytes + largest response)
    + put_max_in_flight × MAX_BLOCK_LEN
    + (index_max_readers + block_max_readers) × largest working set of one read
    + rate_limit_max_clients × size of one limiter entry
    ```

    Estimates: largest response 70 KiB (ADR 0012 rule 14); working set of one read 100 KiB; limiter
    entry 100 bytes; baseline about 2.5 MiB (start-up figure of the diagnosis tool, without the HTTP
    stack). The relay logs the computed bound at start-up. The estimates are replaced by measures (see
    "What the Linux gate must measure").
36. **Backstop outside the process.** The packaged systemd unit and the container MUST set a memory
    limit (`MemoryMax=`, or the container runtime's equivalent), so that the worst case is a restart of
    the relay and not an out-of-memory condition on the host. Proposed for the small VPS profile:
    `MemoryMax=128M`, with `Restart=on-failure`.

### Robustness

37. From the security review (F-7), for relay milestone 1:
    - a panic in a handler MUST become a `500` `Internal` response with the JSON error body, and MUST be
      counted;
    - a failed blocking task (`JoinError`) MUST be mapped to `500`, never unwrapped;
    - the dedicated threads (index readers, index writer, sweeper) MUST be supervised: if one ends, the
      process exits with a non-zero status and the service manager restarts it;
    - repeated index failures MUST be treated as fatal in the same way, after a fixed, documented number
      of consecutive failures.

### Publication

38. **Nothing is added to `/info`.** A client needs `max_query_limit`, which `/info` already publishes
    (ADR 0012 rule 20). Rates, bounds and timeouts are signalled per response, by the status code and
    `Retry-After`. ADR 0012 rule 31 is confirmed.

## Default profiles

The first column holds the built-in defaults (rule 8). The second is an illustration for an operator; it
is not normative and was not measured.

| Setting | Small VPS (1 vCPU, 1 GB): default | Managed relay (example: 8 vCPU, 16 GB) |
|---|---|---|
| `worker_threads` | 1 (number of CPUs) | 8 |
| `max_blocking_threads` | 10 | 50 |
| `max_connections` | 32 | 4,096 |
| `max_header_bytes` | 16,384 | 16,384 |
| `header_timeout_ms` / `body_timeout_ms` / `request_timeout_ms` / `idle_timeout_ms` | 5,000 / 10,000 / 15,000 / 30,000 | same |
| `index_max_readers` | 2 (provisional) | by rule 16: 8 if musl shows no growth, else the measured bound |
| `index_max_queue` | 32 | 256 |
| `block_max_readers` / `block_max_queue` | 4 / 32 | 16 / 256 |
| `put_max_in_flight` / `put_max_queue` | 4 / 16 | 32 / 128 |
| `put_max_in_flight_per_client` | 2 | 4 |
| `queue_timeout_ms` / `shed_retry_after_s` | 1,000 / 2 | same |
| `rate_block_per_min` / `rate_block_burst` | 3,000 / 200 | 12,000 / 600 |
| `rate_query_per_min` / `rate_query_burst` | 300 / 20 | 1,200 / 60 |
| `rate_put_per_min` / `rate_put_burst` | 30 / 20 | 120 / 60 |
| `rate_limit_max_clients` | 4,096 | 262,144 |
| `block_cache_bytes` | 2 MiB | 512 MiB |
| `index_cache_bytes` (ADR 0013) | 4 MiB | 256 MiB |
| `max_query_limit` (ADR 0012) | 1,000 | 1,000 |
| `max_store_bytes` (ADR 0013) | 1 GiB | operator's choice |
| Memory limit of the unit (rule 36) | 128 MiB | 2 GiB |
| Bound of rule 35, computed from the estimates | about 12.6 MiB plus the baseline | about 1.1 GiB |

Reading of the small VPS bound: 4 MiB index cache, 2 MiB block cache, 5.4 MiB for 64 connections that
each hold a full header buffer and a full response, 0.25 MiB of `PUT` bodies, 0.6 MiB of read working
sets, 0.4 MiB of limiter state. With the baseline this is about 15 MiB, in the case where every
connection slot is held by a hostile client. The benchmark gate of ADR 0013 (12 MiB) uses 8 clients:
its connection term is about 0.7 MiB. With `max_connections = 32` the computed bound is about 10 MiB plus
the baseline. See "Decisions for the project owner", point 2.

## Consequences

- **Memory finding F-1.** The number of threads that touch the index is fixed at
  `index_max_readers + 1`. This is the configuration the diagnosis measured as bounded, with a writer
  thread added. No cancellation raises it. `contains`, `expired` and the sweeper are inside the bound.
  The finding stays open until the measurement of rule 16 is made.
- **`axum::serve` is not enough.** It has no connection limit and no timeout. The relay needs its own
  accept loop over hyper-util's connection builder, with a semaphore for `max_connections`.
  `hyper-util` (and `hyper` for its builder types) may become direct dependencies; they are already in
  the dependency graph of axum. Each direct dependency goes through the rules of `CLAUDE.md`.
- **tower middleware.** `ConcurrencyLimitLayer` inside an axum router waits inside the response future
  with no bound on waiters, which rule 3 forbids. The bounds of rules 12 and 18 are explicit semaphores
  and queues with `try_acquire` semantics and a deadline. `tower::limit::RateLimitLayer` is not keyed
  by client and is not used.
- **No new rate-limiting dependency is required.** A token bucket per key in a bounded table is a small
  amount of code. If the implementer prefers a crate, it goes through the dependency rules and
  the security reviewer.
- **Shared addresses.** A university or a carrier NAT is one client for the limiter. The cost is a `429`
  with an exact `Retry-After`, not a failure. Per-key limits on the PubKey of a block were not adopted
  (see "Rejected alternatives").
- **IPv6.** Aggregation by /64 stops one host from using its 2^64 addresses as 2^64 clients. A sender
  with a /48 still has 65,536 keys; the overflow key (rule 21) bounds the table, and an operator MAY
  lower `client_ipv6_prefix` to 48.
- **Slow clients.** A client that sends or reads slowly holds one connection for at most
  `request_timeout_ms`, and one `PUT` permit for at most `body_timeout_ms`. A sender needs
  `put_max_in_flight / put_max_in_flight_per_client` distinct keys to hold every `PUT` permit; reads are
  not affected (rule 32).
- **Distributed senders.** These limits bound what the relay spends. They do not keep a relay available
  against many distinct addresses. That is the role of the reverse proxy, the network and
  `min_pow_difficulty`.
- **Proxy trust.** A wrong `trusted_proxies` lets a client choose its own key through
  `X-Forwarded-For`. The default trusts loopback only. A relay exposed without a proxy uses peer
  addresses.
- **Benchmark gate.** ADR 0013 runs the gate with "every other setting at its default" and raises "the
  two limits that would stop the load (`max_store_bytes`, rate limits)". Under this ADR, "rate limits"
  reads as the per-client limits of rules 18 and 21, lifted for the load generator with
  `rate_limit_exempt = ["127.0.0.1/32"]`. Every other setting of this ADR stays at its default in the
  gate, `index_max_readers` included. The default of `index_max_readers` MUST therefore be fixed by
  rule 16 before the gate runs (ADR 0017, pre-registration).
- **Desktop daemon.** It embeds the same component and settings. On macOS the default of
  `index_max_readers` stays 2 (rule 17), and the diagnosis shows that `MallocSpaceEfficient=1` removes
  the growth there.
- **`sbtp-core`.** No change. **Test vectors.** None. **Compatibility.** No relay is deployed.
- **Related, not decided here.** The security review also asks to scope `overflow-checks` to workspace
  crates or to measure the gate with it (F-7), to narrow the tokio features (F-8) and to bump redb on or
  after 2026-11-27 (F-5). These are tasks for the implementer.

### Checklist for relay milestone 1 (the implementer)

- [ ] Settings struct with the names, defaults, ranges and constraints of rule 22; loader of rule 6
      (default, file, environment); start-up refusal of rule 7; effective settings and the computed
      bound of rule 35 logged once.
- [ ] Runtime built with explicit `worker_threads` and `max_blocking_threads`; tokio features narrowed
      to what the relay uses.
- [ ] Accept loop over hyper-util: `max_connections` semaphore (permit owned by the connection task),
      HTTP/1.1 only, `header_read_timeout` with a timer, `max_buf_size` = `max_header_bytes`, idle
      timeout (confirm what hyper provides; otherwise a timer per connection), graceful shutdown on
      `SIGTERM` and `SIGINT` followed by the index flush (security review F-3).
- [ ] Index component: `index_max_readers` reader threads and one writer thread (`std::thread`), one
      bounded job queue, deadline and cancellation check when a job is taken, clamp of rule 14. No
      public way to call `IndexBackend` from another thread.
- [ ] Block read and `PUT` classes: semaphores with bounded waiters; permits moved into blocking
      closures; per-client `PUT` counter in the limiter entry.
- [ ] Limiter: client key of rule 20, three buckets per key, bounded table with the overflow key,
      exemption list, `Retry-After` of rule 29. No address in persistent logs.
- [ ] Time bounds: body deadline (`RequestBodyDeadlineLayer` or equivalent) mapped to `408`
      `RequestTimeout`; request deadline mapped to `503`; response transfer inside the same deadline
      (`ResponseBodyDeadlineLayer` or equivalent). `tower-http` features `timeout`, `catch-panic`,
      `limit`, `cors` confirmed for 0.7.1.
- [ ] Every `408`, `429`, `503` and `500` carries the JSON error body and the CORS headers; no
      empty-body response from a middleware reaches a client.
- [ ] `CatchPanicLayer::custom` mapped to `Internal`; `JoinError` mapped; supervision of the dedicated
      threads; fatal exit after repeated index failures (rule 37).
- [ ] `deploy/`: `MemoryMax=` and `Restart=on-failure` in the systemd unit; memory limit in the
      container documentation; `LimitNOFILE` consistent with rule 22.
- [ ] Tests, each with an injected clock where time matters:
      - queue full gives `503` with `Retry-After`; queue wait over `queue_timeout_ms` gives `503` and
        the job never runs;
      - a client that resets its connections never raises the number of running index jobs above
        `index_max_readers` (counter inside the index component);
      - repeated `PUT` of a held block goes through the reader pool;
      - bucket empty gives `429` with the expected `Retry-After`; two IPv6 addresses of one /64 share a
        bucket; `X-Forwarded-For` is ignored from an untrusted peer; table full uses the overflow key;
      - a body sent one byte per second gets `408` at `body_timeout_ms`; headers never completed close
        the connection at `header_timeout_ms`; an idle connection closes at `idle_timeout_ms`;
      - connection `max_connections + 1` is not accepted until one closes;
      - a saturated `PUT` class and a saturated `/query` class leave `GET /block` and `/info` served;
      - a handler panic gives `500` with the JSON body; a dead reader thread stops the process;
      - an out-of-range setting and an unknown key stop the start-up.
- [ ] Security review of the limiter, the accept loop and the index component, and re-review
      of F-1 to F-4.

### What the Linux gate must measure

Before the gate (informative, decides rule 16): the seven points of the security review F-1, on the
gate VM, through the real relay.

In the gate itself (ADR 0013 as clarified by ADR 0017; thresholds and procedure unchanged):

- the relay runs with the defaults of this ADR, the load generator being exempt from per-client limits;
- the report adds the number of `429`, `503` and `408` responses per step. With 8 clients and these
  defaults none is expected; any other count is reported and explained;
- the report gives the effective settings and the computed bound of rule 35.

Informative, in the same campaign, not gating:

- a saturation run: `max_connections` open connections, every class at its bound, slow readers
  included; `VmHWM` compared with the computed bound of rule 35. This replaces the estimates;
- a mixed run: `PUT`, `/query` and the sweeper at the same time. The gate runs them one after the other
  (ADR 0017 rule 21) and never together;
- throughput and 99th percentile latency of `/query` and `PUT` for `index_max_readers` 1, 2, 4 and 8;
- the cost of `overflow-checks` on binary size and throughput (security review F-7).

## Decisions for the project owner

**Decided 2026-11-19:** (1) accepted; (2) the 15 MB target is a worst-case bound, `max_connections`
defaults to 32 (about 12.5 MiB computed worst case). Points 3 and 4 below stand as written.

1. Accept or amend this ADR. On acceptance, ADR 0012 gets "Amended by: 0018 (`RequestTimeout` and
   `408`; error body of HTTP-layer responses)".
2. **Is the 15 MB memory target a figure under typical load or a bound in the worst case?** With the
   proposed defaults the computed worst case is about 15 MiB (64 hostile connections). If the target is
   a worst-case bound, the default of `max_connections` becomes 32 (about 12.5 MiB with the baseline).
   The gate threshold of 12 MiB is not affected: it is measured with 8 clients.
3. The default of `index_max_readers` after the musl measurement follows rule 16 with no further
   decision, unless the value 1 fails.
4. Whether the informative mixed and saturation runs should become gating in a later ADR.

## Clarifications (2026-11-19, after relay milestone 1c-b)

Recorded by the specification editor after relay milestone 1c-b (`feat/relay-m1c-b`, 52f8a7b), accepted by the project owner, 2026-11-19. They state how rules 9 to 13, 30 and 32 read together for the index lookups of
the `PUT` path, the start-up walk and a job that starts before its deadline. They add no setting and no
status code. The security review of the branch (`docs/security/2026-11-19-relay-m1c-b.md`, L-3 and I-3)
reaches the same reading for M1 and M2. The cost of the limiter table (rule 21) is not a clarification:
it is ADR 0027 (accepted, Q-33).

- **M1. A refused repair lookup does not refuse the `PUT`.** On the `PUT` path, the index lookup
  (`contains`) runs only for a block that the relay already holds: the identical-bytes shortcut, a stored
  file that passes full validation, a replaced damaged file, and a file created by a concurrent `PUT`
  (ADR 0023 rule 8). Its only use is to decide whether the orphan repair of ADR 0013 rule 9 runs. The
  answer to the `PUT` (`200`) does not depend on it. The lookup is therefore part of the repair, as ADR
  0021 clarification X2 already states for a failed lookup.
  - When the reader queue refuses the lookup (queue full, or deadline passed: rule 13), the relay
    answers `200` as if the block were indexed, and does not repair. The orphan, if any, stays invisible
    to `/query` until a later `PUT` of the block finds it, or until the next start-up walk (ADR 0023
    rule 15). This is the 1c-a behaviour for a failed lookup, extended to a refused one.
  - Rule 13 ("a request gets `503`") applies to a request whose answer needs the job. It does not apply
    here, and rule 32 decides: a saturated `/query` class MUST NOT make a `PUT` of a held block fail.
  - The relay counts each such skipped repair in `index_repairs_deferred_total` (no label), added to the
    counters of ADR 0021 rule 41. No log event: it is load, not a failure, and it sends no `503`, so the
    `shed` event does not apply.
  - A `PUT` of a new block runs no lookup and is unaffected.
  - The lookup keeps its deadline (`queue_timeout_ms`). The `PUT` permit is held during that wait, which
    stays below `request_timeout_ms` (rule 22).
- **M2. The start-up walk runs on the writer thread.** Rule 9 covers the read jobs that callers submit.
  A read made inside a write job (a lookup that guards an insert, or the reads that a write transaction
  makes on its own) runs on the thread of that job, the writer. The start-up walk of ADR 0023 rule 15 is
  one write job: its lookups and inserts run on the writer thread, before the relay listens (ADR 0013
  rule 11). The threads that touch the index stay the `index_max_readers + 1` threads of rule 10. The last
  bullet of rule 13 ("the sweeper and the reconciliation use the same queue") was written for a
  periodic reconciliation; since ADR 0023 rule 15 there is one walk per start, which goes through the
  writer queue and does not bypass the index component (rule 11). The sweeper still uses the reader
  queue for its `expired` jobs.
- **M3. A job that has started is waited for.** The deadline of rule 13 is a queue deadline: it applies
  while the job waits (`queue_timeout_ms`, "a queue wait", rule 30). A job that a thread has taken before
  its deadline is no longer queued.
  - The requester then waits for its result. That wait is bounded by the cost of one job (ADR 0012
    rule 14) and, for the request, by `request_timeout_ms` (rule 25).
  - If `request_timeout_ms` passes first, the request gets `503` under rule 25 (reason of a request
    timeout, not of the index queue). The job still runs to its end (rule 13) and its result is dropped.
  - The relay MUST NOT answer `503` at the queue deadline for a job that has started: the work is done,
    and a client retry would repeat it under load.
  - The decision "taken or abandoned" is made once per job: a thread that takes the job and a requester
    whose deadline passes MUST NOT both win.
- **M4. `Retry-After` of an index refusal on `PUT`.** A `503` caused by a bound of the index component is
  a case of rule 30 ("a full queue; a queue wait longer than `queue_timeout_ms`; ... the relay ...
  stopping"), whatever the route: `Retry-After` is `shed_retry_after_s`, and `reason` names the bound,
  `index_queue` (`http_refused_total` and the `shed` event of ADR 0021). After M1, a refused repair lookup
  sends no `503`. The writer queue is bounded by the `PUT` permits; it refuses a job only while the relay
  stops, and that `503` is the stopping case of rule 30. If the project owner rejects M1, a refused
  lookup on `PUT` gets `503` with exactly these values.

## Clarification (2026-11-19, after relay milestone 1c-b2)

Recorded by the specification editor after relay milestone 1c-b2 (`db1dffe`), accepted by the project owner,
2026-11-19. It follows the security review `docs/security/2026-11-19-relay-m1c-b2.md` (L-3) and goes
with ADR 0027 clarifications T1 to T3.

- **M5. Start-up constraint `rate_limit_max_clients >= 2 × max_connections`.** Added to the
  constraints of rule 22. An entry with a count above 0 is never dropped (ADR 0019 rule 31, ADR 0027
  rule 4), and there are at most `max_connections` such entries. Without a constraint, an operator can
  set `max_connections` close to or above `rate_limit_max_clients` (both values are in range), and a
  client with that many keys can pin the whole table with a fraction of the connection slots: every
  other client then shares the overflow key. With the constraint, at least half of the table can
  always be dropped once full.
  - The relay checks it at start-up, on the effective values (built-in defaults, profile, file and
    environment, ADR 0019 rule 36). If it does not hold, the relay stops before it listens, with a
    message that names both settings and their values (rule 7). A warning alone is not enough.
  - The built-in defaults and the profiles satisfy it: `small` (the default) 4,096 >= 2 × 32 = 64;
    `standard` 32,768 >= 2 × 256 = 512; `large` 262,144 >= 2 × 4,096 = 8,192.
  - The ranges are unchanged. At the lowest `rate_limit_max_clients` (64), `max_connections` is at
    most 32; at the highest `max_connections` (65,535), `rate_limit_max_clients` is at least 131,070.
  - Connections from a peer in `trusted_proxies` are not counted at accept (ADR 0019 rule 30), but each
    request in flight through them pins its key, one per connection: the bound of `max_connections`
    pinned keys holds for both kinds of peer.

## Clarification (2026-11-19, after relay milestone 1c limits): fatal exit on repeated index failures

Proposed by the specification editor after the branch `feat/relay-m1c-limits`. Status: accepted by the
project owner, 2026-11-19. It follows the security review `docs/security/2026-11-19-relay-m1c-limits.md`
(M-1, L-1, I-1). It states how the last bullet of rule 37 reads. It adds no setting and no status code
on the HTTP interface. The case of a failure for lack of space is ADR 0021 clarification X7.

- **M6. Which index failures count toward the fatal exit of rule 37.**
  - *Purpose.* The exit exists for one case: an index backend left broken in a way that a reopen of
    the index cures, while the relay would otherwise answer `500` forever. A failure that a restart
    does not cure MUST NOT count: a restart loop is a worse outage than `500` on one function, and a
    client that can reach the failure could pull it.
  - *Counted.* A failure counts only when the index backend (the database engine) returns an error
    for a call made by a request or by the writer. A row that the backend returns but that the relay
    cannot decode (a corrupt row) does not count: it is logged and counted in the metrics of ADR 0021
    (`index_read_failed`, `index_read_errors_total`, or the `index_write_failed` counterparts), and
    the request gets `500` as before.
  - *Not counted.* A job refused by a full queue or an expired queue wait (rules 13 and 30, M1, M3): it
    is load, not a failure. A panic in an index thread: it is the supervision case of the third bullet
    of rule 37. A failure for lack of space: ADR 0021 clarification X7. A job of the sweeper: its
    failures are `sweep_failed` (ADR 0021 rule 7); it runs on a timer, not with traffic, and a broken
    write path is already seen by the inserts.
  - *Two families, two counters.* The relay keeps one consecutive-failure counter per family:
    - **write**: the insert of a new block, the insert of an orphan repair (ADR 0013 rule 9) and the
      periodic durable commit (ADR 0013 rule 10). A periodic commit with nothing pending makes no call
      and changes nothing;
    - **read**: a page of `/query` and the index lookup of the `PUT` path (M1).
    A counted failure increments the counter of its family. A success resets the counter of its own
    family only. A success of one family MUST NOT reset the other: a backend whose writes fail while
    cached reads succeed is the main case this rule exists for (review M-1).
  - *Threshold.* The relay exits when either counter reaches a fixed number `N`. `N` is a constant of
    the implementation, not a setting (rule 1: an operator gains nothing by tuning it). It MUST be
    documented next to the constant and in the operator documentation. It MUST be at least 8, so that
    a short burst of transient errors does not end the process, and at most 1,024, so that a broken
    backend is restarted after a short stretch of traffic. `sbtp-relay` uses `N = 32` for both
    families.
  - *Exit.* The relay writes one `fatal` line (ADR 0021 rule 7, clarification X6), flushes the log,
    and exits with status 70 (`EX_SOFTWARE`), the status of the supervision exit of the same rule.
    The `msg` of the line SHOULD name the family (for example `repeated index write failures`).
    Entries not yet durable are lost and restored at the next start by the start-up walk (ADR 0013
    rule 9, ADR 0023 rule 15).
  - *Shutdown.* Once the relay has started to stop, no failure leads to this exit: the stop reports
    its own errors.
  - *Residual case, not covered.* A persistent corruption below the row level (for example a page
    that fails its checksum) is an error of the backend and counts in the family that reads it. If a
    restart does not cure it, read traffic that reaches it can restart the relay in a loop, bounded
    only by the restart policy of the service manager. Recovery from a corrupt index is Q-36.
  - *Tests (`sbtp-relay`).* `N − 1` write failures interleaved with read successes, then one more
    write failure: exit 70. The same with the families swapped. A write success resets the write
    counter only. `N` corrupt rows on `/query`: no exit. `N` refusals of a full queue: no exit. A
    failing periodic commit counts in the write family. No exit once stopping has started.
  - *Alternatives considered.* One counter reset by any success (the code before the review): never
    reaches `N` under mixed traffic when only writes fail (review M-1). Counting corrupt rows: one
    corrupt row lets any client force a restart loop with `N` requests (review L-1). Counting writes
    only: a backend whose reads alone fail would never be restarted, although a reopen may cure it.
    A failure rate over a time window instead of a consecutive count: one more setting or constant
    with a clock, and a broken backend under low traffic would never reach the rate. `N` as a
    setting: an operator has no basis to choose it, and a setting can disable the rule. `N` fixed by
    the ADR for every implementation: the exit is a local behaviour of a relay (rule 5), not an
    interoperability rule; a bounded range is enough.

## Rejected alternatives

- **A semaphore in the `/query` handler** (the first proposal of the diagnosis). Leaves other read paths
  unbounded, is bypassed by cancelled requests, and runs on a pool whose thread population is not the
  one measured (security review F-1).
- **Index reads on tokio's blocking pool with an owned permit.** Bounds concurrency but not the number
  of distinct threads that allocate and free index pages, which the diagnosis points to. The pool also
  mixes index work with file I/O.
- **tower `ConcurrencyLimitLayer` plus `LoadShedLayer` around the router.** One global bound for every
  route: a saturated `/query` would shed `GET /block`. Inside a router the waiters are unbounded.
- **One global in-flight limit only.** Simple, but it cannot keep reads available when writes saturate.
- **Accept, then answer `503`, at the connection cap.** Costs an accepted connection and a response per
  refusal, which is the resource the cap protects.
- **Publishing the rate limits in `/info`.** The values differ per client (exemptions, shared keys),
  change with the settings, and invite clients to run at the edge. `Retry-After` is exact per response.
- **Rate limit per PubKey.** A key costs nothing to create, so the limit bounds no sender. It also needs
  the body to be read before the decision, against ADR 0012 rule 29.
- **A bound on bytes per `/query`, or a smaller page cap.** The diagnosis measured the same growth with
  pages of 100 at equal volume.
- **An alternative global allocator now.** A new dependency in an exposed binary, before the allocator
  that ships has been measured. It stays an option for the owner if rule 16 ends at its last case.
- **Adaptive limits (load estimator, automatic concurrency).** More state and behaviour that an
  operator cannot predict from the settings. Against principle 4.
- **Hot reload of settings.** Not needed for milestone 1; a restart is cheap for a stateless relay.

## Spec change

Applied to `docs/spec/sbtp-core-v0.2.md` §4 and `docs/spec/architecture.md` §2 on 2026-11-19, with the
changes of ADR 0019.

**`PUT /sbtp/v1/block`, "Responses".** Add after the `413` line:

```markdown
  - `408 Request Timeout`: the body did not arrive within the relay's time limit (`RequestTimeout`). The
    relay closes the connection.
```

Replace the `429` and `503` lines with:

```markdown
  - `429 Too Many Requests`: this client is over its allowance, see "Admission control".
  - `503 Service Unavailable`: the relay is starting, stopping or at one of its own limits
    (`Unavailable`), see "Admission control".
```

**"Errors".** In the list of names, add `` `RequestTimeout` (`408`) `` before `` `RateLimited` (`429`) ``.
Add a bullet:

```markdown
- A request that is not valid HTTP, or whose headers are too large, MAY be answered by the HTTP layer of
  the relay without this body. (ADR 0018)
```

**"Rate limiting".** Rename the subsection "Admission control" and replace its content with:

```markdown
- A relay bounds what it spends: connections, requests per client, concurrent operations and the
  duration of a request. The limits are local settings of each relay and are not published by `/info`.
- `429 Too Many Requests` (`RateLimited`): this client is over its own allowance. The relay answers
  before reading the body and SHOULD send `Retry-After` in seconds. A relay counts clients by address;
  an IPv6 /64, or the users of one shared address, are one client.
- `503 Service Unavailable` (`Unavailable`): the relay is at one of its own limits, starting or
  stopping. The refusal does not depend on the client. The relay SHOULD send `Retry-After` in seconds.
- `408 Request Timeout` (`RequestTimeout`): the request body did not arrive in time.
- A relay MAY also close a connection that is idle or too slow, without a response.
- A client MUST NOT repeat the request before `Retry-After` has elapsed. Without the header, it SHOULD
  back off exponentially with jitter, starting at 1 second. After `408` or a closed connection it MAY
  retry once at once, then backs off. Every request of this interface is safe to repeat (`PUT` is
  idempotent).
- A relay under load refuses `/query` and `PUT` before `GET /block`. A client SHOULD keep its cursor and
  the blocks it could not publish, and retry. (ADR 0007, ADR 0012, ADR 0018)
```

`docs/spec/architecture.md` §2: add a part "Admission control" that states principles 1 to 4, the
dedicated index threads (rules 9 and 10) and the memory bound (rule 35), with a reference to this ADR.
