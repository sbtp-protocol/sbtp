# 0021: Relay observability: logs, metrics and disk-space safety

- Status: accepted (by the project owner, 2026-11-19), with every recommendation: in-house logger, `rustix`
  for `statvfs`, `min_free_disk_bytes` 256 MiB (to confirm after measuring redb growth), block_id suffix at
  `debug`, client tag off by default, relay-written timestamps, the per-profile log rates and 1,024-byte
  line cap, `/metrics` in 1c on a loopback-only listener, inodes and read-only remount in `critical`
- Amended by: 0023 (rules 7 and 41: events `block_quarantined` and `store_reconciled`, field `op` of `store_write_failed`, counters `store_quarantined_total`, `store_replaced_total`, `quarantine_files`; `store_corrupt` replaced); 0027 (clarification T1: rule 45 figures recomputed with a limiter entry of 192 bytes); 0028 (rule 7: TLS events and `config_warning` codes; rule 41: TLS counters; rule 42: `stats` fields with TLS on); 0046 (rule 41: demand eviction counters and gauges); 0048 (rule 41: replication counters and gauge); 0049 (rule 41: ingest counters and gauges); 0050 (rule 41: archive copy and read-through counters and gauges); 0051 (rule 41, by its clarification B7: counters `batch_requests_total`, `batch_records_total`, `batch_cut_total`, route label `/sbtp/v1/blocks`); 0052 (rule 7: events `deny_list_loaded` and `deny_list_invalid`, no event per denied request and no client tag on it; rule 41: counter `denied_total`, gauges `deny_entries` and `deny_marking_pending`); 0054 (rule 41: gauges `ws_connections_open` and `ws_subscriptions_open`, counters `ws_frames_sent_total`, `ws_entries_sent_total`, `ws_gaps_total` and `ws_closed_total`, reasons `ws_client`, `ws_group` and `ws_full` of `http_refused_total`)
- Clarifications: X1 to X4 (after relay milestone 1c-a) and X5 (after 1c-b), accepted by the project
  owner, 2026-11-19. X6 and X7 (after relay milestone 1c limits: `fatal` line of ADR 0018 rule 37;
  index full with a latching backend, rule 37 and the state `critical`), accepted by the project owner, 2026-11-19
- Date: 2026-11-19
- Questions: none resolved. Opens Q-31 (the quota of ADR 0013 does not count shard directories or inodes)
- Amends, if accepted:
  - ADR 0018 rule 6 (the key set also holds the setting names of this ADR), rule 22 (open files: the
    metrics listener), rule 35 (two terms added to the memory bound);
  - ADR 0019 rule 36.6 (form of the start-up lines, content unchanged), rule 37 (two rows added:
    `log_rate_per_min`, `log_burst`), rule 38 (the other settings of this ADR are not set by a profile);
  - ADR 0013 rule 19 (a second cause of `507`: free space under the watermark).
  - Clarifies, without changing their text: ADR 0013 rules 8, 9, 10 and 15 (index write failure,
    sweeper under low space), ADR 0018 rule 37 (what is logged for a panic).
- Depends on: ADR 0009 (layout), ADR 0012 (error body), ADR 0013 (quota, sweeper, index), ADR 0018
  (settings, memory bound), ADR 0019 (profiles, precedence), ADR 0020 (throttled warnings)
- Impact: no change to `docs/spec/sbtp-core-v0.2.md`; `docs/spec/architecture.md` §2 (informative bullets,
  see "Spec change", not applied); `sbtp-relay` (new module `log`, `config.rs`, `server.rs`, `lib.rs`,
  `index.rs`, `error.rs`, the store and the sweeper of milestones 1b and 1c); workspace `Cargo.toml` (one
  crate, `rustix`, if point 5 option B is accepted); `deploy/` (journald, Docker and logrotate examples);
  no `sbtp-core` change; no test vector

## Context

The relay at `aadb943` writes 16 `eprintln!` lines to standard error (`lib.rs` 9, `server.rs` 5,
`index.rs` 1, `main.rs` 1). They have no level, no structure and no timestamp. There is no access log.
`Throttle` (`client.rs`) bounds three events that a remote peer can repeat to one line per 60 seconds. No
address and no block content is logged; this is intended (the implementer rules, `CLAUDE.md`).

Milestones 1b and 1c add many events: block rejections per error, `429`, `503`, sweeps, quota. The
the implementer rules ask for structured logs. The owner asks that disk filling be handled the way
routers and web servers handle it: a rate cap at the source, rotation at the sink, and a refusal to write
before the disk is full.

The principle is the one of ADR 0018 rule 4, applied to logs: **the bytes a relay logs per day are a
function of its settings, never of the number or the behaviour of clients.**

### Facts checked on 2026-11-19

| Fact | Source |
|---|---|
| `tracing` 0.1.44 (features `log`, `std`), `tracing-core` 0.1.36 and `log` 0.4.35 are already in the shipped graph of `sbtp-relay`, through `axum`, `axum-core`, `tower` and `tower-http`. `tracing-subscriber` is not. The shipped graph has 83 packages on the host target. | `cargo tree -p sbtp-relay -e normal -i tracing` at `aadb943` |
| `tracing-subscriber` 0.3.23 was published on 2026-03-13. Its only required dependency is `tracing-core`. Feature `fmt` enables `registry`, which pulls `sharded-slab` (0.1.7, 2023-10-04, which requires `lazy_static`) and `thread_local` (1.1.10, 2026-07-10, which requires `cfg-if`). Feature `json` adds `tracing-serde` (0.2.0), `serde` and `serde_json`. `ansi`, `smallvec` and `tracing-log` are default features. Timers other than the built-in one need `time` or `chrono`. | crates.io API, crate and dependency records |
| With `default-features = false, features = ["std", "fmt"]`, `tracing-subscriber` adds 4 packages that the relay does not ship today: `tracing-subscriber`, `sharded-slab`, `lazy_static`, `thread_local`. With `json`: 5 (`tracing-serde`). | Same, compared with `cargo tree` |
| The `fmt` subscriber of `tracing-subscriber` writes to standard output by default. Its documentation describes no rate limit and no dropping. | docs.rs, `tracing_subscriber::fmt`, 0.3.23 |
| The workspace forbids `unsafe` (`unsafe_code = "forbid"`). A `forbid` cannot be lifted inside a crate. `libc::statvfs` is an `unsafe` function. The open-file check already avoids `unsafe` by reading `/proc/self/limits`. | `Cargo.toml` (workspace lints); `config.rs` lines 997 to 1010 |
| `rustix` 1.1.6 (published 2026-10-27) has a safe `rustix::fs::statvfs(path) -> io::Result<StatVfs>`, behind the feature `fs`. `StatVfs` has `f_frsize`, `f_blocks`, `f_bavail`, `f_files`, `f_favail`, `f_flag` (with `RDONLY`). It is in `Cargo.lock` as a dependency of `tempfile` (tests only) and not in the shipped graph. Its dependencies `bitflags`, `errno` and `libc` are in the shipped graph; `linux-raw-sys` is not. | `rustix-1.1.6/src/fs/abs.rs` line 288, `src/backend/linux_raw/fs/types.rs` lines 823 to 835; crates.io; `Cargo.lock` |
| `nix` 0.32.0 was published on 2026-11-14: younger than two weeks. | crates.io |
| `statvfs`: `f_blocks` is in units of `f_frsize`; `f_bavail` is "free blocks for unprivileged users"; `f_favail` is free inodes for unprivileged users. "It is unspecified whether all members of the returned struct have meaningful values on all filesystems." Linux implements it with `statfs(2)`. MT-Safe. | `statvfs(3)`, man7.org |
| journald: "`SystemMaxUse=` and `RuntimeMaxUse=` control how much disk space the journal may use up at most." "`SystemKeepFree=` and `RuntimeKeepFree=` control how much disk space systemd-journald shall leave free for other uses." Defaults 10% and 15% of the file system, each capped to 4G. journald "will respect both limits and use the smaller of the two values". `MaxRetentionSec=` defaults to 0 (off); suffixes `year`, `month`, `week`, `day`, `h`, `m`. | `journald.conf(5)`, freedesktop.org |
| journald rate limit: `RateLimitIntervalSec=` and `RateLimitBurst=` default to 10,000 messages in 30 s, "applied per-service"; further messages "are dropped until the interval is over". A namespace instance reads `/etc/systemd/journald@NAMESPACE.conf`. | `journald.conf(5)` |
| systemd unit: `LogNamespace=` "Run the unit's processes in the specified journal namespace" (system services only, version 245). `LogRateLimitIntervalSec=` and `LogRateLimitBurst=` set the journald limit per unit. `StandardError=` defaults to `inherit`; `StandardOutput=` defaults to `journal`. `append:path` opens a file in append mode. `RestartSec=` defaults to 100 ms. | `systemd.exec(5)`, `systemd.service(5)` |
| Docker: "The default logging driver is `json-file`." "By default, no log-rotation is performed." "Use the `local` logging driver to prevent disk-exhaustion." `json-file`: `max-size` defaults to -1 (unlimited); `max-file` defaults to 1 and is "only effective when `max-size` is also set". `local`: `max-size` defaults to `20m`, `max-file` to 5, `compress` is on. Delivery is blocking by default. Compose: `logging:` with `driver:` and `options:`. | docs.docker.com: "Configure logging drivers", "JSON File logging driver", "Local file logging driver", Compose file reference |
| logrotate: `size`, `rotate`, `compress`, `missingok`, `notifempty`, `copytruncate`. With `copytruncate`, "some logging data might be lost". `hourly` needs logrotate to be run hourly. | `logrotate(8)`, man7.org |
| The flat-file layout has two directory levels of one byte each: up to 65,536 leaf directories. The quota of ADR 0013 rule 18 counts block files and the index, not directories. | ADR 0009 rule 2; ADR 0013 rule 18 |
| The default panic hook still writes the panic message to standard error: `error.rs` line 156 relies on it. That line passes through no throttle. | `crates/sbtp-relay/src/error.rs` |

Not checked: the binary size and the memory cost of `tracing-subscriber`; which events `axum`, `tower` and
`tower-http` emit through `tracing`; the storage overhead of journald and of the Docker drivers per line;
whether systemd reads a `<N>` priority prefix on standard error lines (`SyslogLevelPrefix=`); the
defaults of `StartLimitIntervalSec=` and `StartLimitBurst=`; the default inode ratio of ext4 (16,384
bytes per inode, from memory); how redb grows its file and how it reports a write that fails for lack of
space; the Prometheus text exposition format (to be read through Context7 when rule 44 is implemented);
the size of the start-up lines (estimated at 8 KiB per start).

## Decision

Rules are numbered through the whole ADR. Each point gives the options and a recommendation.

### Point 1: format, levels, events, timestamps

| Subject | Options | Recommendation |
|---|---|---|
| Format | A. Text `key=value` only. B. JSON only. C. Text by default, JSON by a setting. | **C.** Text reads in `journalctl` and `docker logs` without a tool. JSON serves a collector. The two carry the same keys. |
| Timestamp | A. Written by the relay, RFC 3339 UTC. B. Left to the sink (journald and Docker add one). C. A, with a setting to turn it off. | **C.** A line then means the same in every sink, in a pipe and after an export. A plain process has no other clock. Cost: 28 bytes per line. An operator under journald MAY turn it off. |
| Output | A. Standard error only. B. A file written by the relay. | **A.** A relay that writes files needs rotation code, a signal to reopen, and a second disk bound. The sink has them (point 4). |

1. **One event, one line.** The relay writes each event as one line on standard error, ended by one
   line feed. The relay MUST NOT write a log file, open a log socket or rotate anything. Nothing else
   writes to standard error or standard output: no `eprintln!` outside the logger, and the panic hook is
   replaced (rule 9).
2. **Fields.** A line has, in this order: `ts` (rule 5), `level`, `event`, then the fields of the event.
   A key matches `[a-z][a-z0-9_]*`. `msg` is an optional last field of free text for a person; no tool
   may depend on its content.
3. **Text form** (`log_format = "text"`, the default): `key=value` pairs separated by one space. A value
   is written bare when it matches `[A-Za-z0-9_.:/@+-]+`; otherwise it is written between double quotes,
   with `"` and `\` escaped by `\`, and every byte below `0x20` and `0x7F` written as `\n`, `\r`, `\t` or
   `\xHH`. A line therefore never holds a raw control character, whatever an operating system error text
   or a path contains.
4. **JSON form** (`log_format = "json"`): one JSON object per line, the same keys in the same order.
   Integers are JSON numbers; everything else is a string.
5. **Timestamp.** `ts` is the wall-clock time of the event in RFC 3339, UTC, with milliseconds and the
   suffix `Z` (`2026-11-19T14:03:07.123Z`). `log_timestamp = "none"` omits the field.
6. **Levels.** `error`: the relay lost data, a function or a write. `warn`: a limit was reached, or a
   setting deserves the operator's attention. `info`: start-up, shutdown, state changes, periodic
   statistics. `debug`: one line per request or per block. The relay writes the lines whose level is at
   or above `log_level`. Default: `info`. At `info` no line is written per request.
7. **Event vocabulary.** `event` is one of a fixed set of names. A name and the keys of its fields are an
   operator interface: an alert may match them. Adding an event or a field needs no ADR. Renaming or
   removing one needs an ADR and a `CHANGELOG.md` entry. The set is one `enum` in the code; a test
   compares it with the table below.

   | `event` | Level | Fields | When |
   |---|---|---|---|
   | `start` | info | `name`, `version` | First line (ADR 0019 rule 26). |
   | `setting` | info | `name`, `value`, `source` | Once per setting (ADR 0019 rule 36.6). |
   | `profile` | info | `name`, `source` | Once. |
   | `open_files` | info | `limit`, `needed` | Once (ADR 0019 rule 22). |
   | `memory_bound` | info | `bytes` | Once (ADR 0018 rule 35). |
   | `log_bound` | info | `bytes_per_day` | Once (rule 22). |
   | `config_warning` | warn | `code`, `setting` | Once per warning of ADRs 0019, 0020 and this ADR. `code` is a fixed name. |
   | `data_dir` | info | `path` | Once (ADR 0019 rule 10). |
   | `listening` | info | `addr` | Once (ADR 0019 rule 9). |
   | `metrics_listening` | info | `addr` | Once, if rule 44 is enabled. |
   | `accept_failed` | warn | `errno`, `class`, `suppressed` | ADR 0020. `class` is `backoff` or `transient`. |
   | `client_bound` | warn | `limit`, `suppressed` | A client key is at `max_connections_per_client`. |
   | `forwarded_invalid` | warn | `suppressed` | `X-Forwarded-For` with no valid entry (ADR 0020). |
   | `rate_limited` | warn | `class`, `suppressed` | A `429` was sent. `class` is the bucket (`block`, `query`, `put`) or `in_flight`. |
   | `shed` | warn | `reason`, `suppressed` | A `503` was sent. `reason` is fixed per cause of ADR 0018. |
   | `storage_full` | warn | `reason`, `suppressed` | A `507` was sent. `reason`: `quota`, `disk`, `inodes`, `read_only`, `enospc`, `edquot` (ADR 0013 rule 19, as clarified by ADR 0023). |
   | `disk_state` | info, warn, error | `state`, `free_bytes`, `min_free_bytes` | On each change of state (rule 33). `ok` at info, `low` at warn, `critical` at error. |
   | `disk_check_failed` | error | `errno`, `suppressed` | Rule 32. |
   | `index_write_failed` | error | `op`, `step`, `errno`, `suppressed` | An insert, a removal or a durable commit failed (rule 37). `op`: `insert`, `remove`, `flush`. `step` is present only on a failed lookup that guards an insert (`op=insert`, `step=lookup`). |
   | `store_write_failed` | error | `op`, `orphan`, `errno`, `suppressed` | A block-store operation failed, for a cause other than space. `op`: `write` (temporary file, shard directory, link), `sync` (`fsync` of the shard directory after the link; `orphan=true`, the file stays under its final name for reconciliation), `read` (the stored file of a block). `orphan` is present only with `op=sync`. ADR 0023 rule 14 adds `quarantine` and `purge`. |
   | `sweep` | debug | `removed`, `duration_ms` | End of a sweeper run. |
   | `sweep_failed` | error | `errno`, `suppressed` | A sweeper run stopped on an error. |
   | `block_rejected` | debug | `error`, `block` | `error` is the variant name of ADR 0012. `block` per rule 12. |
   | `block_stored` | debug | `block`, `bytes` | A `201`. |
   | `request` | debug | `route`, `method`, `status`, `duration_ms` | End of a request. `route` is a template (`/sbtp/v1/block/{id}`), never the path received. |
   | `panic` | error | `location`, `msg`, `suppressed` | Rule 9. |
   | `stats` | info | counters of rule 41 | Every `stats_interval_ms`. |
   | `log_dropped` | warn | `dropped`, then one field per event | Rule 20. |
   | `shutdown` | info, warn | `phase` | `signal`, `drained`, `deadline`, `forced`, `index_closed`. |
   | `fatal` | error | `msg` | The relay exits with a start-up or shutdown error. |

8. **Throttled events.** An event with a `suppressed` field can be caused by a remote peer. It is
   written at most once per 60 seconds per event name and per value of its `class`, `reason` or `op`
   field; `suppressed` is the number of occurrences not written since the last line. This is the
   `Throttle` of `client.rs`, kept and generalised. Every event that a request can cause at `warn` or
   `error` MUST be throttled this way. Counters (point 6) count every occurrence.
9. **Panics.** The relay installs a panic hook that writes the event `panic` through the logger:
   `location` is `file:line`; `msg` is the panic message, escaped and bounded by rule 17. The default
   hook MUST NOT run. The event is throttled (rule 8).

### Point 2: privacy

| Subject | Options | Recommendation |
|---|---|---|
| `block_id` in logs | A. Never. B. In full at `debug`. C. Truncated at `debug`. | **C.** A `block_id` is public: anyone can `GET` it. A suffix is enough to follow one block through the pipeline. Never at `info` or above, so that a default log does not record which blocks a relay held after their eviction. |
| Client identity | A. Never, in any form. B. Truncated address (/24, /48) behind a setting. C. Keyed hash behind a setting, off by default. | **C.** B is still an address range of a person. A plain hash of an IPv4 address is reversed by trying the 2^32 values, so the hash MUST be keyed. The reverse proxy is the place where addresses are logged and blocked. |

10. **Never logged**, at any level and with any setting: an IP address or a prefix of one; a value of
    `X-Forwarded-For` or of any other request header; a request path as received, or a query string;
    any byte of a block or of its payload; a public key, a signature, a seed or any other key material;
    a cursor.
11. **Allowed:** numbers and names that the relay itself produced (counts, sizes, durations, status
    codes, error variant names, `errno` values, route templates); operating system error text; the
    settings (ADR 0018 rule 7: none is a secret); the paths of `data_dir` and of the configuration file.
12. **`block_id`.** The events `block_rejected` and `block_stored`, at `debug` only, MAY carry `block`:
    the last 8 hexadecimal characters of the `block_id`. The leading characters are not used: the proof
    of work makes them zero (ADR 0009). No other event carries a `block_id`.
13. **Client tag.** With `log_client_tag = "keyed"` (default `"off"`), an event that concerns one client
    carries `client`: the first 8 hexadecimal characters of the BLAKE3 keyed hash of the client key
    (ADR 0018 rule 20). The 32-byte key is drawn from the operating system at start-up, kept in memory
    only, never logged and never written to disk. A tag therefore links lines of one process run and
    cannot be linked across restarts or turned back into an address without the memory of the process.
    A tag is pseudonymous data, not anonymous data: the relay logs a `config_warning` when the setting
    is `keyed`. No setting logs an address.
14. **`debug` is not the default.** With `log_level = "debug"` the relay logs a `config_warning` at
    start-up: the log then holds one line per request and block suffixes.
15. **Retention.** The deployment documentation states that the log retention of the sink SHOULD NOT
    exceed `block_ttl_ms` (30 days by default), so that logs do not outlive the blocks they mention.

### Point 3: bounded log volume

| Option | Against |
|---|---|
| A. Per-event `Throttle` only (today) | The bound is "number of event kinds per minute". It grows with each event added in 1b and 1c, covers no `debug` line, and nobody computes it. |
| B. A, plus a global token bucket in lines per minute, with a counted drop and a summary line (below) | One more mechanism. |
| C. Rely on the sink (`RateLimitBurst=` of journald, `max-size` of Docker) | The sink differs per deployment; a plain process has none. A flood then rotates the useful history out of the sink. |

**Recommendation: B.** It is what `logging rate-limit` does on a router and what journald does per
service; the relay does it at the source so that the bound holds in every sink.

16. **Order.** A log call goes through: the level (rule 6); the per-event throttle (rule 8); the global
    bucket (rule 18); the queue (rule 21). A line dropped at any step is counted (rule 20).
17. **Line length.** A line is at most 1,024 bytes, line feed included. A longer line is cut at a
    character boundary and ends with the field `truncated=true` (text) or `"truncated":true` (JSON). The
    lines of the start-up phase (rule 19) are not cut.
18. **Global bucket.** One token bucket for the whole process: capacity `log_burst` lines, refilled at
    `log_rate_per_min` lines per minute. Each line written takes one token. With no token the line is
    dropped. A line of level `debug` or `info` is also dropped when fewer than `log_burst / 4` tokens
    remain, so that `warn` and `error` keep a reserve.
19. **Outside the bucket**, because no client can cause them: the lines of the start-up phase (from
    `start` to `listening`, both included), the `shutdown` and `fatal` lines, and the `log_dropped`
    summary. Their number is a function of the configuration and of the number of process starts.
20. **Drops are reported.** The relay counts dropped lines per event name. At most once per 60 seconds,
    and only if the count is above 0, it writes one `log_dropped` line: `dropped` is the total since
    the last summary, followed by one field per event (`rate_limited=1200 request=48211`), largest
    first; the events that do not fit in rule 17 are summed in `other`. The exact counts per event are
    in the counters of point 6.
21. **A log call never blocks a request.** A formatted line goes to a bounded queue of 256 lines, read
    by one writer thread that owns standard error. When the queue is full the line is dropped and
    counted. A sink that stops reading (a full pipe, a stalled logging driver) therefore costs lines,
    not requests. At exit the relay drains the queue for at most 1 second. The queue adds
    256 × 1,024 = 262,144 bytes to the bound of ADR 0018 rule 35.
22. **Computed bound.** At start-up the relay computes and logs (`log_bound`) the largest number of
    bytes it can write in 24 hours after start-up:

    ```
    (log_burst + log_rate_per_min × 1,440 + 1,440) × 1,024
    ```

    The three terms: the initial burst, the refill over 1,440 minutes, one `log_dropped` line per
    minute. The lines of rule 19 come on top, once per process start.
23. **Profiles.** Two rows are added to the table of ADR 0019 rule 37:

    | Setting | `small` (default) | `standard` | `large` |
    |---|---|---|---|
    | `log_rate_per_min` / `log_burst` | 60 / 120 | 300 / 300 | 1,200 / 600 |
    | Lines per second, sustained (informative) | 1 | 5 | 20 |
    | Worst case of rule 22, lines per day | 87,960 | 433,740 | 1,730,040 |
    | Worst case of rule 22, bytes per day | 90,071,040 (85.9 MiB) | 444,149,760 (423.6 MiB) | 1,771,560,960 (1,689.5 MiB) |
    | Same line count at 160 bytes per line (informative) | 14,073,600 (13.4 MiB) | 69,398,400 (66.2 MiB) | 276,806,400 (264.0 MiB) |

    The worst case needs every line to be 1,024 bytes long and the bucket to be empty all day. At
    `info` with no attack the steady state is the `stats` line: 288 lines per day by default.
24. **Restarts.** The bucket does not survive a restart. The supervisor bounds the starts: the packaged
    unit sets `Restart=on-failure` (ADR 0018 rule 36) and MUST set `RestartSec=5s` or more (the systemd
    default is 100 ms). At 5 s a crash loop makes at most 17,280 starts per day; with start-up lines
    estimated at 8 KiB per start this is 141,557,760 bytes (135.0 MiB) per day. The bound against it is
    the size cap of the sink (point 4).

### Point 4: rotation, delegated to the sink

The relay bounds the rate (point 3). The sink bounds the size on disk. Both are required: the rate cap
alone lets a log grow without end, and the size cap alone lets a flood erase the history.

25. **A size cap is mandatory.** Every deployment in `deploy/` MUST send standard error to a sink that
    has a size cap, set explicitly in the shipped example. The cap SHOULD hold at least two days of the
    worst case of rule 23 (`small`: 200 MiB; `standard`: 1 GiB; `large`: 4 GiB).
26. **systemd.** The unit sets `StandardOutput=journal` and `StandardError=journal`, and
    `LogNamespace=sbtp-relay` so that the caps apply to the relay alone and not to the host journal.
    `deploy/` ships `/etc/systemd/journald@sbtp-relay.conf`:

    ```ini
    [Journal]
    SystemMaxUse=200M
    SystemKeepFree=1G
    MaxRetentionSec=30day
    ```

    `SystemMaxUse=` is the size cap. `SystemKeepFree=` makes journald stop growing before the file
    system is full; journald applies the smaller of the two. `MaxRetentionSec=` is the retention of
    rule 15. The rate limit of journald (10,000 messages per 30 s per service) is left at its default:
    the upper ranges of rule 46 keep the relay under it (3,000 + 6,000 / 2 lines in 30 s at most).
    Without namespace support (systemd before 245) the same three keys go in a drop-in of
    `journald.conf` and apply to the whole host; the documentation says so.
27. **Docker.** The shipped `compose.yaml` and the `docker run` example MUST set the logging driver and
    its caps explicitly. The default driver (`json-file`) does not rotate.

    ```yaml
    logging:
      driver: local
      options:
        max-size: "20m"
        max-file: "10"
    ```

    `local` is preferred (rotation and compression by default). With `json-file`, `max-size` and
    `max-file` MUST both be set: `max-file` alone has no effect.
28. **Plain process.** The documentation MUST state: redirecting standard error to a file that nothing
    rotates (`2> relay.log`, `2>> relay.log`, `StandardError=append:` or `file:`) is forbidden. A plain
    process sends standard error to a supervisor that rotates, or appends to a file (`2>>`) that
    logrotate rotates with `copytruncate`, run hourly:

    ```
    /var/log/sbtp-relay/relay.log {
        hourly
        size 20M
        rotate 10
        compress
        missingok
        notifempty
        copytruncate
    }
    ```

    logrotate checks the size only when it runs: between two hourly runs the file grows by at most one
    twenty-fourth of rule 23 (`small`: 3.6 MiB; `large`: 70.4 MiB). `copytruncate` may lose lines at the
    rotation; the journald and Docker sinks do not have this defect and are preferred.
29. **Same file system.** The sink often writes to the file system that holds `data_dir` (a single
    partition; `/var/lib/docker`). `deploy/` SHOULD place `data_dir` on its own file system. When it
    does not, the watermark of point 5 is what protects the store from the logs of other services.

### Point 5: free-space watermark

`max_store_bytes` (ADR 0013) bounds what the relay writes. It does not see what the rest of the host
writes, the directories of the layout (Q-31), or a file system smaller than the quota.

| Subject | Options | Recommendation |
|---|---|---|
| Unit | A. Bytes (`min_free_disk_bytes`). B. A percentage. C. Both, the larger wins. | **A.** One number, the same meaning on every disk. 5% of a 2 TB disk is 100 GB; 5% of a 2 GiB volume is too little. A start-up warning covers the small volume (rule 36). |
| Status | A. `507` `StorageFull`. B. `503` `Unavailable`. | **A.** The spec defines `507` as "the relay has no room for it". ADR 0013 already rejected `503` for a full store: `503` tells a client to retry soon and tells a load balancer that the relay is down, while reads still work. |
| How to read free space | A. `libc::statvfs`. B. `rustix::fs::statvfs`. C. No check; rely on `ENOSPC`. | **B.** A needs `unsafe`, which the workspace forbids and no crate can lift. C reacts after the disk is full, when redb and journald fail too. B is a safe call; it adds `rustix` and `linux-raw-sys` to the shipped graph (`rustix` is already in `Cargo.lock` for tests). `std` has no such call. |

30. **Setting.** `min_free_disk_bytes`: the free space, on the file system that holds `data_dir`, under
    which the relay accepts no new block. Default 268,435,456 (256 MiB). Free space is
    `f_bavail × f_frsize` of `statvfs`: the space available to an unprivileged process.
31. **Cheap check.** The relay calls `statvfs` once at start-up and then every
    `disk_check_interval_ms` (default 5,000), on a thread that may block, never on a `PUT`. A `PUT`
    reads the state from memory. Between two samples the relay subtracts from the last sample the bytes
    of the block files it wrote since, rounded as in ADR 0013 rule 18, so that its own writes are
    counted at once and only the writes of other processes wait for the next sample.
32. **Failure of the check.** If `statvfs` fails, the relay keeps the previous state and logs
    `disk_check_failed`. On a target without `statvfs` the check is off and the relay logs a
    `config_warning` at start-up, as it does for the open-file limit.
33. **States.** With `m = min_free_disk_bytes` and `free` the estimate of rule 31:

    | State | Entered when | Left when | Effect |
    |---|---|---|---|
    | `ok` | | | None. |
    | `low` | `free < 2 × m` | `free ≥ 2.5 × m` | Warning only. This is the warning before the threshold. |
    | `critical` | `free < m`, or free inodes under 4,096 when the file system reports inodes (`f_files > 0`), or the file system is mounted read-only (`f_flag`) | `free ≥ 1.25 × m`, 8,192 free inodes or more, and not read-only | New blocks are refused (rule 34). |

    Each change of state writes one `disk_state` line. The gaps between the entry and exit thresholds
    keep a relay from changing state at every sample.
34. **Refusal.** In the state `critical`, a valid block that the relay does not hold gets
    `507 Insufficient Storage` with the error `StorageFull`, and nothing is written. The check sits
    with the quota check of ADR 0013 rule 20: after validation, for new blocks only. A block already
    held still gets `200`; an invalid block still gets its own error. `GET /block`, `/query` and
    `/info` are served normally. `Retry-After` follows ADR 0013 rule 19. The `message` of the error
    body MAY say which cause applies; the `reason` of the event and of the counter always does.
35. **Sweeper.** The sweeper runs in every state: it is what frees space. It deletes the block file
    before the index entries (ADR 0013 rule 15), so it frees space even when the index cannot be
    written; the entries left are phantoms (ADR 0013 rule 8). The relay MUST NOT evict an unexpired
    block to leave the state `critical` (ADR 0013 rule 21).
36. **Start-up warnings** (`config_warning`), computed from the first sample: `min_free_disk_bytes = 0`;
    the free space is under `(max_store_bytes − bytes already stored) + min_free_disk_bytes`, so the
    watermark will be reached before the quota; the free inodes are under
    `(max_store_bytes − bytes already stored) / 4,096`, so inodes may run out before the quota.
37. **Index writes.** The index file is on the same file system and is counted in the quota.
    - An index insert that fails for lack of space gives `507` `StorageFull` (ADR 0013 rule 19). The
      block file just created is left in place: it is an orphan, repaired by ADR 0013 rule 9, and stays
      counted in the quota. It is not deleted, because another `PUT` of the same block may already have
      seen it. No `201` is sent without its index entries (ADR 0013 rule 7).
    - A durable commit (ADR 0013 rule 10) or a removal that fails is logged (`index_write_failed`) and
      counted. After a failure for lack of space the relay is in the state `critical` until a durable
      commit succeeds and rule 33 allows leaving it. Entries not yet durable are restored after a crash
      by ADR 0013 rule 9.
    - An index failure for another cause keeps its present handling (`500`); this ADR adds the event
      and the counter only.
    - The margin `min_free_disk_bytes` MUST exceed the largest single growth of the index file. That
      figure is not known (see "Not checked"); the implementer measures it before the default of rule
      30 is final.
38. **Not a setting of a profile.** As for `max_store_bytes` (ADR 0019 rule 38), disk space is not
    inferred from a profile name.

### Point 6: metrics

| Subject | Options | Recommendation |
|---|---|---|
| What replaces an access log | A. An access log at `info`. B. Aggregated counters; a per-request line at `debug` only. | **B.** An access log grows with traffic and holds one record per client action. Counters have a fixed size. |
| How counters leave the process | A. A periodic `stats` log line. B. A Prometheus text endpoint. C. Both; B off by default. | **C.** A needs no listener and works in every deployment. B serves operators who already run a scraper. |
| Where the endpoint listens | A. A route of the public listener. B. A second listener, loopback only. C. A second listener on any address, with a warning. | **B.** Counters describe load and failures; they are not for clients. A loopback address is refused at start-up if it is anything else, so a typing error cannot expose it. In a container, the scraper shares the network namespace of the relay. |
| Milestone | A. All in 1b. B. Logger and counters in 1b; watermark in 1c; endpoint in 1c. C. After milestone 1. | **B.** The events of 1b and 1c are then written once, in their final form. The endpoint is a new listener: it comes last and goes through the security reviewer. |

39. **Counters.** The relay keeps counters in memory, in fixed-size tables of atomic integers. A label
    value comes from a fixed set in the code (status class, route template, reason, error variant
    name, event name, level). A label MUST NOT hold a client key, an address, a `block_id`, a public
    key or anything a client chose. The number of series is therefore fixed at build time.
40. **No access log.** No line is written per request at `info` or above (rule 6).
41. **Set.** Names carry the prefix `sbtp_relay_`.

    | Name | Kind | Labels |
    |---|---|---|
    | `http_requests_total` | counter | `route`, `class` (`2xx`, `4xx`, `5xx`) |
    | `http_refused_total` | counter | `status` (`429`, `503`), `reason` |
    | `blocks_accepted_total` | counter | `result` (`new`, `known`) |
    | `blocks_rejected_total` | counter | `error` (variant name of ADR 0012) |
    | `storage_full_total` | counter | `reason` (rule 7) |
    | `sweeps_total`, `sweep_removed_blocks_total`, `sweep_duration_ms_total` | counter | none |
    | `sweep_last_duration_ms` | gauge | none |
    | `index_bytes`, `store_bytes`, `store_max_bytes` | gauge | none |
    | `disk_free_bytes`, `disk_state` (0 `ok`, 1 `low`, 2 `critical`) | gauge | none |
    | `connections_open` | gauge | none |
    | `accept_errors_total` | counter | `class` |
    | `index_write_errors_total` | counter | `op` |
    | `store_errors_total` | counter | `op` (`read`, `write`, `sync`) |
    | `panics_total` | counter | none |
    | `log_lines_total` | counter | `level` |
    | `log_lines_dropped_total` | counter | `event`, `cause` (`rate`, `queue`) |
    | `build_info` | gauge, always 1 | `version` |

    No latency histogram in this version: `sweep_duration_ms_total` and the `request` line at `debug`
    are the only durations.
42. **`stats` line.** Every `stats_interval_ms` (default 300,000) the relay writes one `stats` line at
    `info` with the totals since start-up: requests per class, `429`, `503`, `507`, blocks new, known
    and rejected, `store_bytes`, `index_bytes`, `disk_free_bytes`, `disk_state`, dropped log lines. 0
    disables the line.
43. **`software` stays private.** `build_info` and the `start` line hold the version. Neither is
    reachable from the public listener (ADR 0019 rule 25).
44. **Endpoint.** `metrics_listen` is a socket address, empty by default. Empty: no listener. Set: the
    relay serves `GET /metrics` in the Prometheus text format on that address, on a listener separate
    from `listen`.
    - The address MUST be a loopback address (`127.0.0.0/8` or `::1`); any other value stops the
      start-up (ADR 0018 rule 7). It MUST differ from `listen`.
    - The public listener MUST NOT route `/metrics`: the path gets the `404` of any unknown path there.
    - The metrics listener serves that one route, HTTP/1.1, at most 4 connections, with
      `header_timeout_ms` and `request_timeout_ms`, no CORS header and no body read. It adds 5 to the
      open files of ADR 0018 rule 22 and 4 × (`max_header_bytes` + 16,384) bytes to the bound of ADR
      0018 rule 35 (131,072 bytes with the defaults).
    - It has no authentication. Any local process can read it; the documentation says so.
45. **Memory.** With the defaults of `small` and the endpoint off, the bound of ADR 0018 rule 35
    (13,022,676 bytes, ADR 0020) becomes 13,284,820 bytes; with the endpoint on, 13,415,892 bytes.

### Point 7: library

| | A. `tracing` + `tracing-subscriber` | B. In-house logger in `sbtp-relay` |
|---|---|---|
| New shipped packages | 4 (`tracing-subscriber`, `sharded-slab`, `lazy_static`, `thread_local`); 5 with JSON (`tracing-serde`). `tracing` becomes a direct dependency. | 0. |
| Ages | All older than two weeks (2023-10 to 2026-07). `sharded-slab` has had no release since 2023-10. | Not applicable. |
| Text and JSON, levels, timestamps | Provided. `key=value` text in the exact form of rule 3 needs a custom formatter. | To write: about 300 lines with tests (escaping, JSON, RFC 3339 from `SystemTime`). `serde_json` is already shipped for the JSON escaping. |
| Global rate cap, drop summary, bounded queue, fixed vocabulary | Not provided. Written in-house as a layer and a writer in both options. | Written in-house. The vocabulary is an `enum`, so an unknown event does not compile. |
| Events of dependencies | A global subscriber receives what `axum`, `tower` and `tower-http` emit. Their content is chosen upstream; rule 10 then depends on a target filter being right. | No subscriber is installed: those events go nowhere, as today. |
| Binary size and memory | Not measured. | A queue of 262,144 bytes (rule 21). |
| Spans, async context | Provided. The relay has no use for them: it logs events, not traces. | None. |

**Recommendation: B.** The parts that this ADR requires (rules 16 to 22) are in-house in both options.
A adds four packages to a relay whose rules ask for a small graph, to supply a formatter that still has
to be replaced, and it turns the log content of dependencies into something to filter. B keeps the
whole privacy surface in one file that the security reviewer reads.

A third option, the `tracing` macros with a hand-written `Subscriber` and no `tracing-subscriber`, adds
no package but has the dependency-events defect of A and more code than B.

For point 5 the recommendation adds one direct dependency: `rustix` with `default-features = false,
features = ["std", "fs"]`. It follows the rules of `CLAUDE.md` (workspace dependency, explicit version,
Context7 and crates.io check, older than two weeks: 1.1.6 is 23 days old on 2026-11-19).

### Settings

46. Added to the table of ADR 0018 rule 22. Precedence and validation follow ADR 0018 rules 6 and 7 and
    ADR 0019 rule 36. The environment variable is `SBTP_RELAY_` and the name in upper case.

    | Setting | Type | Default | Range | Set by a profile |
    |---|---|---|---|---|
    | `log_format` | string | `text` | `text`, `json` | no |
    | `log_level` | string | `info` | `error`, `warn`, `info`, `debug` | no |
    | `log_timestamp` | string | `rfc3339` | `rfc3339`, `none` | no |
    | `log_client_tag` | string | `off` | `off`, `keyed` | no |
    | `log_rate_per_min` | integer | 60 | 6 to 6,000 | yes (rule 23) |
    | `log_burst` | integer | 120 | 16 to 3,000 | yes (rule 23) |
    | `stats_interval_ms` | integer, ms | 300,000 | 0 (off), or 10,000 to 86,400,000 | no |
    | `min_free_disk_bytes` | integer, bytes | 268,435,456 | 0 (off, with a warning), or 16,777,216 to `2^63 − 1` | no |
    | `disk_check_interval_ms` | integer, ms | 5,000 | 1,000 to 60,000 | no |
    | `metrics_listen` | socket address, or empty | empty | loopback only (rule 44) | no |

    The four string settings avoid a boolean type, which the configuration does not have (ADR 0019
    point 3). `0` means "off" as in ADR 0019 rule 6. The fixed values (line length 1,024, queue 256,
    throttle 60 s, summary 60 s, inode thresholds, the factors of rule 33) are not settings.

## Consequences

- **Disk.** Three independent bounds: the relay bounds its log rate (rule 22), the sink bounds the log
  size (rule 25), and the relay stops storing before the file system is full (rule 34). A flood can
  cost log lines; it cannot fill the disk through the log, and it is reported (`log_dropped`).
- **Security.** Log lines cannot be forged by a client: no client-chosen string is logged (rule 10),
  and control characters are escaped (rule 3). The panic path is throttled (rule 9); today it is not.
  A stalled sink no longer blocks a worker thread (rule 21). `/metrics` is a new listener and a new
  code path: loopback only, off by default, reviewed by the security reviewer.
- **Privacy.** The default log holds no address, no client tag and no `block_id`. `debug` and
  `log_client_tag` are explicit and each logs a warning.
- **Operators.** Alerts match `event=` names and counter names, which are stable (rule 7). The lines
  of today change form: anything that parses them breaks once. No release has shipped.
- **Client-visible.** One: a relay may answer `507` while under its quota. The status, the error name
  and the client's handling are those of ADR 0013. No client change.
- **Memory.** 262,144 bytes for the queue; 131,072 more with the endpoint; the counters are under
  16 KiB. `small` stays under its 15 MB target (rule 45).
- **Dependencies.** None for logs and metrics. `rustix` and `linux-raw-sys` for the watermark.
- **Cost.** One more thread (the log writer). One `statvfs` every 5 seconds.
- **Compatibility.** No wire change. No `sbtp-core` change. No test vector.

### Code at `aadb943` that this ADR would change (for the implementer)

| File | Today | Rule |
|---|---|---|
| `lib.rs` lines 83 to 110, 164 | 9 free-text `eprintln!` | 1, 2, 7 (`start`, `open_files`, `setting`, `memory_bound`, `config_warning`, `data_dir`, `listening`) |
| `server.rs` lines 217 to 233 | `accept` and per-client lines; the back-off line is not throttled | 7, 8 (`accept_failed`, `client_bound`) |
| `server.rs` lines 270, 273 | Shutdown lines | 7 (`shutdown`) |
| `index.rs` line 301 | Flush failure: one line per second while it lasts, nothing else | 8, 37 (`index_write_failed`, throttled, counted, state) |
| `main.rs` line 29 | Final error | 7 (`fatal`) |
| `error.rs` line 156 | Relies on the default panic hook | 9 |
| `client.rs`, `Throttle` | One instance per call site | 8 (kept; keyed by event and class) |

## Implementation checklist (the implementer)

Milestone 1b, before the handlers:

- [ ] Module `log`: `Level`, `Event` (`enum`, rule 7), field values, text and JSON writers (rules 2 to
      5), escaping tested with control characters, quotes and non-ASCII text.
- [ ] Test: the names of `Event` equal the table of rule 7.
- [ ] RFC 3339 UTC from `SystemTime`, tested on fixed instants (epoch, a leap day, a year end).
- [ ] Per-event throttle keyed by event and class (rule 8); global bucket with the reserve of rule 18;
      bounded queue and writer thread (rule 21); drain at exit; `log_dropped` (rule 20). Tests with an
      injected clock and a writer that blocks.
- [ ] Line cap of rule 17, cut at a character boundary.
- [ ] Panic hook (rule 9); test that a handler panic gives one `panic` line and that a second one within
      60 seconds gives none.
- [ ] Replace the 16 `eprintln!`; a test or a lint (`clippy::print_stderr`, `clippy::print_stdout`)
      keeps new ones out.
- [ ] Settings of rule 46 with ranges; profile rows of rule 23; `log_bound` line with the figures of
      rule 23 asserted in a test.
- [ ] Counters of rule 41 that exist in 1b; `stats` line (rule 42).
- [ ] Privacy test: run requests with a marker address, marker header values and a marker payload at
      `log_level = "debug"`; no marker appears in the captured output (rule 10).
- [ ] Client tag (rule 13): keyed BLAKE3, key from the operating system, off by default, warning.

Milestone 1c:

- [ ] `rustix` added per `CLAUDE.md` (Context7, crates.io, `cargo deny`); the security reviewer reads the
      addition.
- [ ] Disk check thread or timer (rule 31), own-write accounting, states and thresholds (rule 33) tested
      with an injected sample source; `507` path (rule 34) at the quota check point; reads still served.
- [ ] Index failure handling (rule 37), tested with an index backend that fails; orphan left and
      repaired.
- [ ] Measure the largest growth step of the redb file (rule 37) and report it.
- [ ] Start-up warnings of rule 36.
- [ ] Remaining counters; `/metrics` listener (rule 44): loopback check, `404` on the public listener,
      connection cap, open-file and memory terms; security review.
- [ ] `deploy/`: unit with `LogNamespace=`, `StandardError=journal`, `RestartSec=5s`;
      `journald@sbtp-relay.conf`; `compose.yaml` with the `local` driver and its caps; logrotate
      example; the forbidden redirections of rule 28 stated in the README. Each option name checked
      again against its documentation when the file is written.

## Decisions waiting on the owner

1. Accept this ADR. On acceptance: ADRs 0013, 0018 and 0019 get their "Amended by: 0021" line and the
   index is updated; the bullets of "Spec change" are applied; Q-31 stays open.
2. Point 7: in-house logger (recommended) or `tracing-subscriber`.
3. Point 5: `rustix` as a new shipped dependency (recommended), or no free-space check until a
   dependency-free way exists. Default of `min_free_disk_bytes` (256 MiB) and bytes only, no percentage.
4. Point 2: block suffix at `debug` (recommended: allowed); `log_client_tag = "keyed"` exists, off by
   default (recommended), or no client tag at all.
5. Point 1: timestamp written by the relay by default (recommended), or by the sink only.
6. Point 3: the rates of rule 23 (60, 300 and 1,200 lines per minute) and the line cap (1,024 bytes).
7. Point 6: `/metrics` in milestone 1c (recommended), strict loopback (recommended), or later.
8. Rule 33: the inode and read-only conditions as part of the state `critical` (recommended), or bytes
   only.

## Clarification (2026-11-19, after relay milestone 1c-a): index read failures

Recorded by the specification editor after relay milestone 1c-a, accepted by the project owner, 2026-11-19. Rule 7
allows adding an event without an ADR; this section records the event and its counter so that the
vocabulary test has a table to compare with. It changes no rule above. Rule 37 covers index writes
only; this covers reads.

- **X1. Event.** One row is added to the table of rule 7, after the rows of ADR 0023:

  | `event` | Level | Fields | When |
  |---|---|---|---|
  | `index_read_failed` | error | `op`, `errno`, `suppressed` | An index read that a request needs failed: I/O or database error, or a corrupt row. `op`: `query` (the page of `/query`). `errno` is present only when an operating-system error is under the failure. |

  The level is `error` (rule 6: the relay lost a function). A request causes it, so it is throttled by
  rule 8, per value of `op`. It carries no `block_id` (rule 12), no query parameter and no cursor
  (rule 10). Operating-system error text MAY appear (rule 11), bounded by rule 17.
- **X2. Not this event.** A failed lookup that guards an index insert (the orphan repair on the `PUT`
  path) stays `index_write_failed` with `op=insert` and `step=lookup` (rule 7): the insert it guards
  did not run. A panic in the blocking task of `/query` is the event `panic` (rule 9), not this one.
- **X3. Counter.** One counter is added to the set of rule 41: `index_read_errors_total`, label `op`
  (same values as X1). It counts every occurrence, logged or suppressed (rule 8).
- **X4. Response.** `500` `Internal` (ADR 0012 rule 17 and clarification K2). The relay changes no
  state: no `disk_state` change, no epoch change, no shedding.

## Clarification (2026-11-19, after relay milestone 1c-b): deferred repairs

Recorded by the specification editor, accepted by the project owner, 2026-11-19, with ADR 0018 clarification M1.

- **X5. Counter.** One counter is added to the set of rule 41: `index_repairs_deferred_total`, no
  label. It counts each `PUT` of a held block whose orphan-repair lookup the index reader queue refused
  (queue full or deadline passed), answered `200` without repair (ADR 0018 M1). No event is added: no
  `503` is sent, and a failed (not refused) lookup stays `index_write_failed` (X2).

## Clarifications (2026-11-19, after relay milestone 1c limits): fatal line, index full

Proposed by the specification editor after the branch `feat/relay-m1c-limits`. Status: accepted by the
project owner, 2026-11-19. They follow the security review `docs/security/2026-11-19-relay-m1c-limits.md`
(I-1) and go with ADR 0018 clarification M6. They add no setting, no status code and no event name.

- **X6. The `fatal` line also marks an exit of ADR 0018 rule 37 and of X7.** The "When" of the row
  `fatal` in rule 7 reads: "The relay exits with a start-up or shutdown error, after repeated index
  failures (ADR 0018 rule 37, M6), or to reopen its index after it was full (X7)." Its fields stay
  `msg` only. The line is written through the logger and flushed before the process exits.
- **X7. Index write failure for lack of space with a latching backend.** Rule 37 assumes that the
  index recovers by itself once space is freed ("until a durable commit succeeds"). Some backends do
  not. redb 4.6.0 latches the first failed file write: only that first error carries `ENOSPC`; every
  later access to the file fails with an error that has no `errno` (`PreviousIo`), and only a reopen
  of the database clears it. A backend that recovers by itself keeps rule 37 as written. For a
  latching backend:
  - *Entry.* On the first index failure whose operating-system error is `ENOSPC` or `EDQUOT`, the
    relay enters the state `critical` at once, whatever the last sample of rule 31 says. It writes one
    `disk_state` line (rule 33) and records the cause (`enospc` or `edquot`). The index is then
    **latched**.
  - *While latched.* The relay stays in `critical` and keeps serving:
    - every valid new block gets `507` `StorageFull` at the check point of rule 34, before its file is
      written, so the latch creates no further orphan. The `reason` of `storage_full` and of the
      counter is the recorded cause;
    - a `PUT` that passed the check point before the latch was set and whose index write then fails
      gets `507` with the same reason, not `500`;
    - index failures of either family do not count toward ADR 0018 rule 37 (M6): they are the
      expected effect of the latch, and a restart into a full disk cures nothing;
    - `GET /block` and `/info` are served normally (ADR 0013 rule 21). A `/query` page that the
      backend can still serve is served; one that needs a refused file access gets `500` (X4). This
      degradation of `/query` lasts until the restart below;
    - the relay MAY skip the periodic durable commit, which cannot succeed. The sweeper runs (rule
      35); its index removals fail and leave phantoms (ADR 0013 rule 8).
  - *Recovery.* The relay never clears the latch in the process. It exits, so that the service manager
    restarts it with a fresh handle on the index, when both hold:
    - a sample of rule 31 taken after the latch was set meets the exit condition of rule 33
      (`free ≥ 1.25 × m`, enough inodes, not read-only);
    - at least 60 seconds have passed since the latch was set.
    It writes one `fatal` line (X6) whose `msg` says the index is reopened after storage full, flushes
    the log, and exits with status 75 (`EX_TEMPFAIL`). Status 75 tells an operator that the exit is a
    planned recovery, not a fault (status 70, ADR 0018 rule 37). The packaged unit restarts on any
    non-zero status (ADR 0018 rule 36).
  - *If the relay cannot observe recovery.* When the free-space check is off (rule 32), the first
    condition is replaced by the second alone: the relay exits with status 75 60 seconds after the
    latch was set.
  - *After the restart.* The start-up walk (ADR 0023 rule 15) repairs the orphan of the first failure
    (ADR 0013 rule 9) and the entries that were not durable. If the index cannot be opened, the relay
    does not start and the service manager retries.
  - *Bound on restarts.* The 60-second wait bounds a cycle of latch and restart to one restart per
    minute in every case, including `EDQUOT` (a user or project quota that `statvfs` does not show,
    so that rule 33 may report enough space while the quota is still reached) and
    `min_free_disk_bytes = 0`. Between two restarts the relay serves reads. 60 seconds is a constant,
    not a setting; it keeps the packaged unit under the default start-rate limit of systemd.
  - *Alternatives considered.* (A) Exit at once on the first `ENOSPC`, or count the later
    `PreviousIo` errors toward rule 37 (the behaviour of `sbtp-relay` before this clarification,
    review I-1): the relay restarts into a full disk, may fail to open its index, and loops; reads are
    lost during each restart, against ADR 0013 rule 21. (B) Stay up and reopen the index in the
    process when space returns: no restart, but the pool must quiesce every reader and the writer and
    run the start-up walk while it serves; more code on a rare path. Kept as Q-36. (C) Stay up in
    `critical` until an operator restarts the relay: needs a human for a condition the relay can
    observe. (D) Leave the exit to the 32 counted failures of M6: the restart happens while the disk
    is still full.
  - *Tests (`sbtp-relay`).* With an injected backend that latches: the first `ENOSPC` insert gives
    `507` and sets `critical`; the next new block gets `507` before its file is written; `N` later
    failures do not exit; a sample above `1.25 × m` before 60 seconds does not exit; after it, the
    process exits with status 75 and a `fatal` line; with the check off, exit 75 after 60 seconds;
    `GET /block` is served throughout.

## Rejected alternatives

Listed per point in the option tables. Across points:

- **Log files written and rotated by the relay.** A second disk writer with its own bound, a reopen
  signal and rotation code, in a binary whose rules ask for less code facing the host.
- **An access log at `info`.** Grows with traffic; one record per client action; replaced by counters.
- **Logging a truncated address.** Still an address range of a person; the proxy holds addresses.
- **`503` under the watermark.** See point 5.
- **Evicting unexpired blocks when the disk is low.** Forbidden by ADR 0013 rule 21; a full disk caused
  by another service would then delete user data.
- **A syslog priority prefix (`<4>`) on each line**, so that journald stores the level. Not checked;
  the level is in the line. Can be added later behind a value of `log_format` without changing a rule.
- **`/metrics` on the public listener behind a token.** A secret in the settings, which ADR 0018 rule 7
  excludes.
- **Lowering `unsafe_code` from `forbid` to call `libc::statvfs`.** A workspace rule would be weakened
  for one call that a maintained crate already wraps.

## Spec change

Not applied. `docs/spec/sbtp-core-v0.2.md` is unchanged: its `507` text ("the relay has no room for it")
already covers rule 34, and logs and metrics are not part of the protocol.

**`docs/spec/architecture.md` §2.** Add, in the part on relay operation:

```markdown
- The relay logs one line per event on standard error, as `key=value` text or JSON, with a fixed set of
  event names. It writes no log file: rotation and the size cap belong to the sink (journald, the
  container runtime). It logs no address, no header value, no block content and no key. (ADR 0021)
- The log volume is bounded by the settings: a global rate cap drops lines beyond `log_rate_per_min` and
  reports how many were dropped. (ADR 0021)
- A relay refuses new blocks with `507` when its quota is reached or when the file system that holds its
  data has less free space than `min_free_disk_bytes`. Reads continue. (ADRs 0013 and 0021)
- Counters replace an access log. An optional Prometheus endpoint listens on a separate loopback
  address, never on the public listener. (ADR 0021)
```
