# 0019: Relay configuration clarifications

- Status: accepted (by the project owner, 2026-11-19), with the owner's choices recorded in "Decisions of
  the project owner"
- Amended by: 0020 (rule 23, accept errors; rule 37 worst-case figures; X-Forwarded-For parsing, trust bounds); 0021 (rules
  36.6, 37 and 38: logging and disk settings in profiles); 0025 (rule 4: lower bound of `max_store_bytes`); 0027 (clarification T1: rule 37 worst-case figures recomputed with a limiter entry of 192 bytes); 0028 (rule 9: warning with TLS off; rule 12: fresh phase after the handshake; rule 37: `tls` bucket rows; rule 39: the 15 MB target applies with TLS off; rule 42: built-in TLS or reverse proxy); 0045 (rule 1: the default of `min_pow_difficulty` is `D_NET`); 0046 (rule 4: default `block_ttl_ms = 0`; rule 37: one profile row; rule 38: demand eviction settings); 0048 (rule 37: replication profile rows; rule 38: replication and relay list policy settings; rule 39: the 15 MB target of `small` applies with the default settings, and `small` with every function on is under 20 MB, owner decision of 2026-11-21 replacing the 16 MB bound with replication on); 0049 (rule 37: ingest profile rows; rule 38: ingest share settings); 0050 (rule 37: archive copy and read-through profile rows; rule 38: their policy settings)
- Date: 2026-11-19
- Questions: Q-29 (connections held by one client), resolved by point 10. Opens Q-28 (mining cost in a
  browser and review of the default difficulty) and Q-30 (single-binary deployment with built-in TLS)
- Amends, if accepted:
  - ADR 0018 rule 6 (the key set also holds the setting names of this ADR; a profile sits between the
    built-in defaults and the file), rule 8 and the table "Default profiles" (three named profiles
    replace the two columns), rule 22 (default of `min_pow_difficulty` in "Limits defined elsewhere";
    three settings and one constraint added), rule 26 (a new connection that has sent no byte is bounded
    by `header_timeout_ms`), rule 28 (per-client bound at step 3);
  - ADR 0012 rule 2 (wording only: the reverse proxy is named by its function, not as "Caddy").
  - Clarifies, without changing their text: ADR 0007 rules 1 and 2 (default, range), ADR 0013 rules 12,
    15, 16 and 18 (ranges, representation of "unset"), ADR 0018 rules 23, 25 and 27
- Revised: 2026-11-19, after the security review of relay milestone 1a
  (`docs/security/2026-11-19-relay-m1a.md`, F-1 to F-4) and its fixes (commit `e064e22`): rules 12 to
  17, 21 and 23 changed; point 10 (rules 28 to 34) added. Revised again on 2026-11-19 with the owner's
  choices (see "Decisions of the project owner") and additions: `max_connections_per_client` defaults
  to 8; point 11 (profiles, rules 35 to 40) and point 12 (proxy-neutral wording, rules 41 to 43) added
- Depends on: ADR 0007 (settings, `/info`), ADR 0012 (rules 2, 20 and 21), ADR 0013 (eviction, quota),
  ADR 0018 (configuration, time bounds)
- Impact: spec §3.3 and §4 (`/info`: default difficulty; see "Spec change", not applied); `sbtp-relay`
  (`config.rs`, `server.rs`, `api.rs`, limiter, tests); `deploy/` (listen address and data directory of
  the unit and the container, reverse proxy settings, one unit per profile or a documented variable);
  no `sbtp-core` change; no test vector

## Context

Relay milestone 1a (branch `feat/relay-m1a-foundation`, commit `6ff5f64`) implements the settings and
the accept loop of ADR 0018. the implementer reported nine points that ADRs 0007, 0012, 0013 and 0018
leave open. Each point below gives the options, a recommendation and a rule. The rules are numbered
through the whole ADR. Point 10 was added after the security review of milestone 1a. Points 11 and 12 were
added at the owner's request.

### Facts checked on 2026-11-19

| Fact | Source |
|---|---|
| hyper arms the `header_read_timeout` timer when it starts to wait for a request head (`poll_read_head`), before any byte has arrived, and arms it again after each response. | `hyper-1.12.0/src/proto/h1/conn.rs`, lines 224 to 238 and 1156 to 1160 (version resolved by `Cargo.lock` at `6ff5f64`) |
| The feature `server-auto` of hyper-util enables `http1` and `http2`; `http2` enables `hyper/http2`, which depends on the `h2` crate. | `hyper-util-0.1.21/Cargo.toml`, lines 97 to 108 |
| At `6ff5f64` the workspace enables `hyper` with `http1` and `server` only, and `hyper-util` with `tokio` only. | `Cargo.toml` at `6ff5f64`, lines 39 and 40 |
| A TOML integer is a signed 64-bit value. A setting above `2^63 − 1` cannot be written in the file. | TOML 1.0, "Integer" |
| Mining on one Apple Silicon core: about 11 ms at `d = 16`, about 132 ms at `d = 20`. | `sbtp-core` benches, as reported by the maintainer |
| The benchmark gate sets `min_pow_difficulty = 0` explicitly. | ADR 0013, "Benchmark" (line 146) |
| With `max_connections = 4` and a new connection bounded by `idle_timeout_ms`, 8 silent sockets re-opened as they are closed leave 0 of 8 legitimate requests served within 1 second. A connection that sends one request per `idle_timeout_ms` is never closed. | Security review of milestone 1a, "Attack results", F-1 and F-2 |
| Caddy `reverse_proxy`, `http` transport: `keepalive` defaults to `2m`; when it exceeds the keep-alive timeout of an HTTP/1.1 upstream, requests "may fail due to connection reset by peer" and Caddy answers `502` for those that are not retried. `versions` defaults to `1.1 2`. Caddy sets or augments `X-Forwarded-For` and ignores the incoming value unless its own `trusted_proxies` is set. Request bodies are streamed unless `request_buffers` is set. | caddyserver.com, `reverse_proxy` directive, read through Context7 on 2026-11-19 |

Not checked: whether `hyper_util::server::conn::auto` compiles and runs with the `http1` feature alone;
the mining time in a browser (WASM) or on a phone; the size of an empty redb file; whether Caddy opens
an upstream connection only once it holds a complete request head (stated by the security review, not
verified here); the nginx and HAProxy directives named in rule 43 (written from memory, to be confirmed
against each proxy's documentation when `deploy/` is written).

## Decision

### Point 1: default of `min_pow_difficulty`

The expected number of attempts is `2^d`. Derived from the two measures: about 90 blocks per second and
per core at `d = 16`, about 7.6 at `d = 20`. The default `put` bucket (ADR 0018 rule 21) allows 30
blocks per minute and per client key, which is 0.5 per second. One address is therefore bound by the
rate limit, not by the difficulty, at both values. Filling the default quota (1 GiB, 15,420 blocks of
maximum size) costs about 3 minutes of one core at `d = 16` and about 34 minutes at `d = 20`, spread
over enough addresses. Neither value stops a distributed sender; the quota and `507` do (ADR 0013).

| Option | For | Against |
|---|---|---|
| A. Required, no default (implemented) | The operator chooses knowingly. | `sbtp-relay` does not start without a file or a variable. Against "deployable with one command" (a project goal). The operator has no figure to choose from. |
| B. Default 16 | Starts with no configuration. About 11 ms native; the cost to an honest sender stays small on a slow device. Same value as the `/info` example of the spec. | Low cost per block for a sender with many addresses. |
| C. Default 20 | 12 times the cost of B per block. | About 132 ms native; a browser is slower and the time is not measured. Mining time follows a geometric law: 5% of blocks take 3 times the mean. Votes are blocks too. |
| D. Default 0 | None. | A relay that starts with no proof of work by accident. |

**Recommendation: B.**

1. The default of `min_pow_difficulty` is 16. The range stays 0 to 256 (ADR 0007 rule 1).
2. The value 0 (no proof of work) is valid only when set explicitly. The relay logs a warning at
   start-up when the effective value is 0.
3. The default is provisional until Q-28 is answered with a measure in a browser.

### Point 2: ranges

Ranges exist to catch a wrong unit or a value that breaks another rule. They do not express a policy.

| Option | Against |
|---|---|
| A. Full `u64` (implemented) | Values above `2^63 − 1` are accepted from the environment and cannot be written in the file. `sweep_batch` above 1,000 is lowered by the index (ADR 0018 rule 14), which rule 7 of ADR 0018 forbids ("MUST NOT clamp"). `max_future_ms = 0` rejects every sender whose clock is ahead by 1 ms. |
| B. Bounded ranges (below) | Tests that need a short lifetime use the injected clock. |

**Recommendation: B.**

4. Ranges:

   | Setting | Default (unchanged) | Range | Reason for the bounds |
   |---|---|---|---|
   | `max_future_ms` | 300,000 | 1,000 to 86,400,000 (24 hours) | Below 1 second, ordinary clock drift rejects valid blocks, and a value given in seconds by mistake is caught. Above one day P1 bounds nothing. |
   | `block_ttl_ms` | 2,592,000,000 | 0 (rule 6), or 60,000 to 315,360,000,000 (3,650 days) | A lifetime under one sweeper period has no use. The upper bound keeps `received_at + block_ttl_ms` far from `2^64`. |
   | `max_store_bytes` | 1,073,741,824 | 1,048,576 to 9,223,372,036,854,775,807 (`2^63 − 1`) | 0 has no meaning. The upper bound is the largest TOML integer. |
   | `sweep_interval_ms` | 60,000 | 1,000 to 3,600,000 (1 hour) | Below 1 second the sweeper competes with requests for the index queue. Above 1 hour disk space is not returned in useful time. |
   | `sweep_batch` | 1,000 | 1 to 1,000 | One sweeper run is one `expired` job (ADR 0018 rule 12), and the index lowers a batch to 1,000 (ADR 0018 rule 14). |

5. The upper bound of `index_cache_bytes` and `block_cache_bytes` ("operator's choice" in ADR 0018) is
   `2^63 − 1`. A value that the target cannot represent as a memory size stops the start-up (ADR 0018
   rule 7). The file and the environment MUST accept the same set of values for every setting.
   `received_at + block_ttl_ms` MUST be computed without overflow (saturating addition).

A relay whose index alone is larger than `max_store_bytes` answers `507` to every new block and serves
reads (ADR 0013 rules 19 and 21). This needs no special case.

### Point 3: eviction disabled

ADR 0013 rule 16 says "`block_ttl_ms` unset". The default is 30 days, so a missing key cannot mean
"disabled". An environment variable has no null value.

| Option | For | Against |
|---|---|---|
| A. `block_ttl_ms = 0` means disabled | One key. Same form in the file and the environment. The type stays an integer. Same convention as `block_cache_bytes = 0` (ADR 0018). | 0 could be read as "expires at once". The range of rule 4 removes that reading: no value from 1 to 59,999 is valid. |
| B. A boolean `evict_by_age` | Explicit. | A second key, a new setting type, and an invalid combination to reject (`false` with a lifetime). |
| C. A string value (`"off"`) | Explicit. | A setting with two types. |

**Recommendation: A.**

6. `block_ttl_ms = 0` disables eviction by age. This is the "unset" of ADR 0013 rule 16. With 0:
   - no block expires; the sweeper submits no `expired` job and deletes nothing;
   - `/query` applies no expiry bound;
   - a `507` carries no `Retry-After` (ADR 0013 rule 19);
   - `sweep_interval_ms` and `sweep_batch` are still validated and have no effect.
7. `/info` publishes `"block_ttl_ms": null` when the setting is 0, and the integer otherwise. It MUST
   NOT publish `0`. ADR 0012 rule 20, ADR 0013 rule 16 and the spec are unchanged.

### Point 4: `listen` and `data_dir`

| Option | Against |
|---|---|
| A. Add both as settings of this ADR and extend rule 6 of ADR 0018 to this ADR (below) | None found. |
| B. Command-line arguments instead of settings | A second configuration surface with its own precedence. |
| C. Leave them out of every ADR | The implementation breaks rule 6 of ADR 0018 as written. |

**Recommendation: A.**

8. ADR 0018 rule 6 is amended: the keys of the file are the setting names of ADRs 0007, 0012, 0013,
   0018 and 0019. Rules 6 to 8 of ADR 0018 apply to the two settings below.

   | Setting | Type | Default | Valid values |
   |---|---|---|---|
   | `listen` | string | `127.0.0.1:8080` | One literal IP address and a port: `192.0.2.1:8080`, `[::1]:8080`. No host name. Port 0 is valid and asks the system for a free port. |
   | `data_dir` | string, a path | `data` | Not empty. A relative path is resolved against the working directory of the process. |

9. The relay listens on one address. The default is loopback because a public relay is reached through
   a reverse proxy (ADR 0012 rule 2). The relay logs the bound address. It logs a warning when the
   address is not loopback: the relay then serves plain HTTP on that address.
10. The relay creates `data_dir` when it is missing. If the directory cannot be created or written, the
    relay stops before it listens. The relay logs the absolute path. The packaged unit and the container
    MUST set `data_dir` to an absolute path.
11. `SBTP_RELAY_CONFIG` names the file (ADR 0018 rule 6). No setting may be named `config`.

With rules 1 and 8, `sbtp-relay` with no argument, no file and no variable starts: loopback, port 8080,
directory `data`, difficulty 16.

### Point 5: timers

A connection is in one of four phases. One timer runs at a time. The timers do not add up, except as
stated in rule 16.

| Option | Against |
|---|---|
| A. hyper's `header_read_timeout` as the header and idle timer | It starts before the first byte and again after each response. An idle keep-alive connection closes at `header_timeout_ms` (5 seconds), and `idle_timeout_ms` (30 seconds) never applies. Against ADR 0018 rule 26. |
| B. One relay timer per connection; a new connection is idle until its first byte (first draft of this ADR, implemented at `6ff5f64`) | Measured by the security review (F-1): a client that sends nothing holds a slot for `idle_timeout_ms` at the cost of one socket. 8 sockets starve a relay with 4 slots. |
| C. One relay timer per connection; a new connection is bounded by `header_timeout_ms` from the accept; `idle_timeout_ms` applies between requests only (implemented at `e064e22`) | Holding a slot for `idle_timeout_ms` now costs one valid request and one token. The hold time of a silent socket is divided by 6 with the defaults. It does not remove the attack: point 10 does. |

**Recommendation: C.** hyper's `header_read_timeout` is disabled.

12. **Fresh phase.** From the accept to the first byte of the first request. The connection is closed
    without a response when no byte has arrived `header_timeout_ms` after the accept. A new connection
    that sends nothing is not an idle connection. This amends ADR 0018 rule 26: "a connection with no
    request in progress" reads "a connection that has served at least one request and has no request
    in progress".
13. **Head phase.** From the first byte of a request to the end of its headers. The connection is closed
    without a response when the phase has lasted `header_timeout_ms`. The deadline is on the whole head:
    a byte does not extend it. On a new connection the period starts again at the first byte, so the
    first head is complete at most `2 × header_timeout_ms` after the accept. This is the meaning of
    ADR 0018 rule 23.
14. **Request phase.** From the end of the headers until every byte of the response has been written to
    the socket: `request_timeout_ms` (ADR 0018 rule 25, and rules 19 to 21 below). A response that the
    HTTP layer holds in its buffer is not finished; a client that stops reading stays in this phase. The
    body deadline of ADR 0018 rule 24 runs inside this phase: from the admission of the `PUT` (its
    permit is held) to the last byte of the body, `body_timeout_ms`. It is a deadline on the whole body,
    as rule 24 states.
15. **Idle phase (keep-alive).** From the end of a response, as defined in rule 14, to the first byte of
    the next request. The connection is closed without a response when the phase has lasted
    `idle_timeout_ms`. Each idle phase starts a new full period. The header and request timers of the
    finished request are cancelled: a connection that has served a request is closed `idle_timeout_ms`
    after the end of that response if no byte arrives, not `header_timeout_ms` after.
16. **Pipelined bytes.** When the relay knows that bytes of the next request were read before the
    current response ended, the head phase of that request MUST start when the response ends. The relay
    knows it when it can locate the end of the current request exactly: the end of its head, and a body
    whose length is declared. When it cannot (a chunked body, or a later request of one pipelined burst),
    the relay MAY enter the idle phase instead; the head phase then starts at the next byte read. An
    incomplete head is closed at most `idle_timeout_ms + header_timeout_ms` after the response in that
    case. No other path may give a request head the idle deadline.
17. The checklist item of ADR 0018 "`header_read_timeout` with a timer" is replaced by rules 12 to 16.
    The start-up constraints of ADR 0018 rule 22 are unchanged.

| Phase | Starts | Ends | Limit | At the limit |
|---|---|---|---|---|
| Fresh | accept | first byte | `header_timeout_ms` | closed, no response |
| Head | first byte of a request | end of its headers | `header_timeout_ms` | closed, no response |
| Request | end of the headers | response written to the socket | `request_timeout_ms`, then rule 20 | `503` or closed (ADR 0018 rule 25) |
| Idle | end of a response | first byte of the next request | `idle_timeout_ms` | closed, no response |

A connection that sends nothing is open for at most `header_timeout_ms`. A request holds its connection
for at most `header_timeout_ms + request_timeout_ms + 1,000 ms` from its first byte. A connection can
still stay open without limit by sending one request per idle period: point 10 bounds that.

### Point 6: HTTP/1.1 only

| Option | Against |
|---|---|
| A. hyper's `http1` builder (implemented) | None found. |
| B. `hyper_util::server::conn::auto` with `http1_only()` | The `server-auto` feature brings `hyper/http2` and the `h2` crate into an exposed binary that never serves HTTP/2. Whether `auto` works with `http1` alone was not checked. |

**Recommendation: A.** It is what ADR 0018 rule 27 requires ("the listener serves HTTP/1.1 only") and
what ADR 0012 rule 2 allows ("serves HTTP/1.1 and MAY serve HTTP/2"). ADR 0018 did not amend rule 2 of
ADR 0012; it uses its "MAY". Nothing is amended here.

18. In relay milestone 1 the relay binary MUST NOT contain an HTTP/2 server: the `http2` features of
    `hyper` and `hyper-util` stay off and `h2` MUST NOT appear in `Cargo.lock` through `sbtp-relay`. An
    HTTP/2 connection preface or an `Upgrade: h2c` request is not upgraded; a preface is a request that
    is not valid HTTP/1.1 (ADR 0018 rule 33). The packaged reverse proxy configuration MUST reach the
    relay over HTTP/1.1.

### Point 7: hard close after the request deadline

ADR 0018 rule 25 has two outcomes at `request_timeout_ms`: a `503` if no response has started, a closed
connection otherwise. A connection closed at the deadline itself cannot carry the `503`.

| Option | Against |
|---|---|
| A. Fixed grace of 1,000 ms (implemented) | A response in progress is cut 1 second after the deadline, not at the deadline. |
| B. A setting `response_grace_ms` | One more setting with no known use. |
| C. No grace | The `503` of rule 25 is lost in most cases. |
| D. Grace only when the `503` is being written; close at the deadline otherwise | Exact, but the connection task must know which response is in flight. More state for a 1-second difference. |

**Recommendation: A.** A `503` with its error body is under 1 KiB and fits the socket buffer.

19. At `request_timeout_ms` after the end of the headers, a request with no response started gets `503`
    `Unavailable` with `Retry-After` (ADR 0018 rules 25 and 30).
20. The relay closes the connection 1,000 ms after that deadline if the response, whichever it is, has
    not been sent in full. The value is a constant, not a setting. A request therefore holds its
    connection for at most `request_timeout_ms + 1,000 ms` after the end of its headers. The "Slow
    clients" consequence of ADR 0018 reads with this value.
21. At a first stop request the relay stops accepting and waits at most `request_timeout_ms + 1,000 ms`
    for the connections to end, then drops them. A second stop request during that wait drops them at
    once (security review F-4). In both cases the relay then flushes and closes the index.

### Point 8: open-file limit

ADR 0018 rule 22 checks the open-file limit at start-up. The implementation reads the soft limit from
`/proc/self/limits` on Linux. Elsewhere it logs that the limit was not checked.

| Option | Against |
|---|---|
| A. Checked on Linux, logged elsewhere (implemented) | macOS and Windows are not checked. They are development targets today. |
| B. `getrlimit` on every Unix | Needs `unsafe` or a new dependency (`libc`, `rustix`) in an exposed binary, for targets that do not ship. |

**Recommendation: A.**

22. The open-file constraint of ADR 0018 rule 22 is a MUST on Linux, against the soft limit; `unlimited`
    passes. On another target, or when the limit cannot be read, the relay MUST log one line that gives
    the number of descriptors it needs, and starts.
23. When `accept` fails for lack of a resource (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`), the relay MUST
    NOT retry in a tight loop: it logs the error and waits 50 ms before the next `accept`. The value is
    a constant. Any other `accept` error concerns one connection only (for example a connection reset
    before it was accepted): the relay retries at once, without a pause. Reason for 50 ms: the condition
    ends when a descriptor is freed; the pause bounds the loop at 20 failed calls per second, and a
    freed slot is used within 50 ms. A longer pause adds latency and saves nothing measurable.
24. This point is decided again with the desktop daemon (macOS, Windows), before that daemon ships.

### Point 9: `software` in `/info`

ADR 0012 rule 21 already decides the protocol side: a relay MAY publish `software`, and it MUST be
possible to turn it off. Not publishing it conforms. The open part is the behaviour of `sbtp-relay`.

| Option | For | Against |
|---|---|---|
| A. Not published, no setting (implemented) | Nothing to fingerprint. No new setting or setting type. | A client developer cannot tell which version of a relay misbehaves. |
| B. A boolean setting, default off | Opt-in for an operator. | A new setting type for a member that no client reads today. |
| C. Published by default, with a setting to turn it off | Debugging and network statistics. | Any unauthenticated client learns the exact version of an exposed binary. Operators who do not read the documentation publish it. |
| D. Name without version | No patch level. | The name carries no information while one implementation exists. |

**Recommendation: A for relay milestone 1.** Clients negotiate on `block_versions`, not on a software
version. The operator, who is the party that debugs a relay, has the log.

25. `sbtp-relay` does not publish `software` in `/info` and has no setting for it. It MUST NOT send a
    `Server` header or any other response header that carries its name or version.
26. The relay MUST log its name and version once at start-up.
27. If a later need appears, the member is added behind a boolean setting `info_software` whose default
    is `false`. That name is reserved. The security reviewer MAY comment on this point in the review of
    milestone 1; a different outcome is a new ADR.

### Point 10: connections per client and keep-alive caps (Q-29, security review F-2)

ADR 0018 bounds the connections of the relay (`max_connections`, default 32) and the requests of a
client key (rule 21). Nothing bounds the share of `max_connections` that one client holds. Measured by
the security review: a connection that sends one request per idle period is never closed, so 32
connections with one `GET /info` every 29 seconds each hold every slot inside every rate limit. Once
`PUT` exists, the same holds through a reverse proxy that streams bodies (Caddy does): 32 slow bodies hold 32 upstream
connections for `body_timeout_ms` each.

| Option | For | Against |
|---|---|---|
| A. No bound in the relay; the documentation requires a reverse proxy that sets one | No code. | Whether a given proxy can bound connections per client depends on the product; it was not checked for Caddy. The slow-body case passes through the proxy. The protection depends on what each operator configures. |
| B. `max_connections_per_client`, counted at accept by peer address only | Simple. Refuses before any byte is read. | Behind a proxy every connection comes from the proxy address: the bound either blocks the proxy or, if the proxy is exempt, bounds nothing. |
| C. `max_connections_per_client` with the client key of ADR 0018 rule 20: connections at accept for a direct peer, requests in flight at admission for a peer in `trusted_proxies` (below) | One setting covers both deployments. Covers the slow-body case: the refusal comes before the body is read. | A client that sends more than the bound in parallel through a proxy gets `429`. Users behind one address share the bound. |
| D. C, plus keep-alive caps: a maximum connection age and a maximum number of requests per connection | Slots turn over: a connection waiting in the listen queue gets one. Bounds per-connection state over time. | Not a defence alone: the client reconnects. A reverse proxy sees its upstream connections closed on a schedule. |

**Recommendation: D.** The per-client bound is the fix for F-2. The keep-alive caps are secondary.
**Owner's choice: D, with a default of 8** for `max_connections_per_client`: a browser opens about 6
connections per host and a PWA sends requests in parallel; 8 still stops one client from holding the
32 slots.

28. **Settings.** Added to the table of ADR 0018 rule 22:

    | Setting | Type | Default | Range | At the limit |
    |---|---|---|---|---|
    | `max_connections_per_client` | integer | 8 (profile `small`; rule 37) | 1 to `max_connections` | Direct peer: connection closed at accept, no response. Proxied request: `429` `RateLimited`, `Retry-After: 1` (rules 29 and 30). |
    | `max_connection_age_ms` | duration | 300,000 | 1,000 to 86,400,000 | The connection is closed after the request in progress (rule 32). |
    | `max_requests_per_connection` | integer | 1,000 | 1 to 1,000,000 | The connection is closed after that response (rule 33). |

    Constraint added to ADR 0018 rule 22: `max_connections_per_client ≤ max_connections`.
29. **Direct peer.** When the peer address of a new connection is not in `trusted_proxies`, its client
    key is derived from the peer address as in ADR 0018 rule 20 (an IPv4 address; the first
    `client_ipv6_prefix` bits of an IPv6 address; an IPv4-mapped address as IPv4). If that key already
    holds `max_connections_per_client` open connections, the relay closes the new connection at once and
    sends nothing. The count is taken after the accept and before any byte is read. It is decremented
    when the connection task ends.
30. **Peer in `trusted_proxies`.** Its connections are not counted at accept: one proxy carries many
    clients. Each request on such a connection is attributed to the client key of ADR 0018 rule 20 (the
    rightmost address of `X-Forwarded-For` that is not in `trusted_proxies`; the peer address when there
    is none). A client key MUST NOT have more than `max_connections_per_client` requests in flight
    through trusted peers. A request beyond the bound gets `429` `RateLimited` with `Retry-After: 1`, at
    step 3 of ADR 0018 rule 28, before the body is read. A request is in flight from the end of its
    headers until its response is written to the socket (rule 14). The request takes its token first; a
    refused request takes no token back (ADR 0018 rule 28).
31. **Shared rules.**
    - A key in `rate_limit_exempt` skips rules 29 and 30. The other bounds still apply.
    - The counts live in memory with the limiter state. An entry with a count above 0 MUST NOT be
      dropped by the bound of `rate_limit_max_clients`; there are at most `max_connections` such
      entries. Requests attributed to the overflow key of ADR 0018 rule 21 share one count.
    - `X-Forwarded-For` is never read from a peer that is not in `trusted_proxies`.
    - The per-client `PUT` bound of ADR 0018 rule 18 is unchanged and applies as well.
    - A relay behind a proxy whose address is missing from `trusted_proxies` sees one client, the proxy,
      and allows it `max_connections_per_client` connections. The relay logs a warning when a key is
      refused under rule 29. The deployment documentation MUST state that the proxy address belongs in
      `trusted_proxies` and that the proxy MUST set, or append to, `X-Forwarded-For` the address of its
      own peer (rule 42). Addresses that a client wrote to the left of it are never used (ADR 0018
      rule 20).
32. **Connection age.** When a connection has been open for `max_connection_age_ms`:
    - in the idle phase, it is closed at once, without a response;
    - in any other phase, the request in progress is served under its own time bounds, its response
      carries `Connection: close`, and the connection is closed after it.
    A connection is therefore open for at most
    `max_connection_age_ms + header_timeout_ms + request_timeout_ms + 1,000 ms`.
33. **Requests per connection.** The response to request number `max_requests_per_connection` of a
    connection carries `Connection: close`, and the connection is closed after it. Bytes of a later
    pipelined request are discarded. Every request of this interface is safe to repeat on a new
    connection (ADR 0018, "Spec change").
34. **Reverse proxy.** The idle keep-alive time of the proxy's upstream connections MUST be shorter than
    the relay's `idle_timeout_ms` (proposed: 20 seconds for the default of 30), and the proxy MUST reach
    the relay over HTTP/1.1. Otherwise the relay closes idle upstream connections first, and the proxy
    answers `502` to a request it cannot retry. Rule 42 lists what the proxy must do; rule 43 gives the
    settings for three proxies.

### Point 11: profiles

The owner asks for one setting that gives coherent values to every resource limit, so that an operator
does not set thirty values to run a larger relay.

| Option | Against |
|---|---|
| A. No profile; the "managed relay" column of ADR 0018 stays an illustration | Each operator derives a coherent set alone. The constraints between settings (ADR 0018 rule 22) are easy to break. |
| B. A `profile` setting with fixed, documented value sets; each setting still overrides it (below) | One more precedence level to implement and test. |
| C. Values derived at start-up from the machine (CPU count, RAM) | The memory bound would depend on the host and not on the settings alone. Against principle 4 of ADR 0018 and its rejection of adaptive limits. |

**Recommendation and owner's request: B.**

35. **Setting.** `profile` is a string: `small`, `standard` or `large`. Default: `small`. Any other value
    stops the start-up (ADR 0018 rule 7). Its environment variable is `SBTP_RELAY_PROFILE`.
36. **Precedence.** ADR 0018 rule 6 is amended. Lowest to highest: built-in default; profile;
    configuration file; environment variable. Exactly:
    1. The relay resolves `profile` itself first: the environment variable if set, else the key of the
       file if present, else `small`.
    2. For every other setting, the effective value is: the environment variable if set; else the key
       of the file if present; else the value of the chosen profile if the table of rule 37 has a row
       for the setting; else the built-in default of the ADR that defines the setting.
    3. Defaults that are computed from other settings (`max_blocking_threads`, `worker_threads`) are
       computed last, from the effective values.
    4. Ranges and constraints (ADR 0018 rules 7 and 22, and rule 28 above) are checked on the effective
       values. An override that breaks a constraint with a profile value stops the start-up; the message
       names both settings. Nothing is adjusted to make a combination valid.
    5. The built-in defaults of the settings in rule 37 are the `small` column. "Built-in default" and
       "profile `small`" are therefore the same values, and ADR 0018 rule 8 stays true.
    6. The relay logs the profile and, for each setting, the effective value and its source (`default`,
       `profile`, `file` or `env`).
37. **Values.** The profiles set the settings below and no others.

    | Setting | `small` (default) | `standard` | `large` |
    |---|---|---|---|
    | Intended host (informative) | 1 vCPU, 1 GB; Raspberry Pi; desktop daemon | 2 to 4 vCPU, 4 GB | 8 vCPU, 16 GB |
    | `max_connections` | 32 | 256 | 4,096 |
    | `max_connections_per_client` | 8 | 16 | 32 |
    | `index_max_queue` | 32 | 128 | 256 |
    | `block_max_readers` / `block_max_queue` | 4 / 32 | 8 / 128 | 16 / 256 |
    | `put_max_in_flight` / `put_max_queue` | 4 / 16 | 16 / 64 | 32 / 128 |
    | `put_max_in_flight_per_client` | 2 | 4 | 8 |
    | `rate_block_per_min` / `rate_block_burst` | 3,000 / 200 | 6,000 / 400 | 12,000 / 600 |
    | `rate_query_per_min` / `rate_query_burst` | 300 / 20 | 600 / 40 | 1,200 / 60 |
    | `rate_put_per_min` / `rate_put_burst` | 30 / 20 | 120 / 60 | 600 / 300 |
    | `rate_limit_max_clients` | 4,096 | 32,768 | 262,144 |
    | `block_cache_bytes` | 2,097,152 (2 MiB) | 33,554,432 (32 MiB) | 536,870,912 (512 MiB) |
    | `index_cache_bytes` | 4,194,304 (4 MiB) | 33,554,432 (32 MiB) | 268,435,456 (256 MiB) |
    | `max_blocking_threads` (computed, rule 36.3) | 10 | 26 | 50 |
    | Open files needed (ADR 0018 rule 22) | 72 | 312 | 4,176 |
    | Worst case of ADR 0018 rule 35, from its estimates, `index_max_readers = 2` | 13,018,580 bytes (12.4 MiB) | 97,630,032 bytes (93.1 MiB) | 1,198,804,640 bytes (1,143 MiB) |
    | Memory limit of the packaged unit (ADR 0018 rule 36) | 128 MiB | 512 MiB | 2 GiB |

    `large` is the "managed relay" column of ADR 0018, with a higher `put` allowance,
    `put_max_in_flight_per_client` at 8 and the per-client connection bound.
38. **Not set by a profile**, the same in the three profiles unless the operator sets them:
    - every time bound (`header_timeout_ms`, `body_timeout_ms`, `request_timeout_ms`, `idle_timeout_ms`,
      `queue_timeout_ms`, `max_connection_age_ms`), `max_requests_per_connection`, `max_header_bytes`
      and `shed_retry_after_s`: they describe a request, not the size of the host;
    - `worker_threads`: the number of available CPUs in every profile;
    - `index_max_readers`: its default follows ADR 0018 rules 15 to 17 (2, provisional) in every
      profile, because it is fixed by a measure and not by the size of the host;
    - `max_store_bytes` (1 GiB): disk space cannot be inferred from a profile name, and a profile MUST
      NOT make a relay take more disk than its operator stated. The relay logs a warning when the
      profile is `standard` or `large` and `max_store_bytes` is left at its default;
    - policy and deployment settings: `min_pow_difficulty`, `max_future_ms`, `block_ttl_ms`,
      `sweep_interval_ms`, `sweep_batch`, `max_query_limit`, `cors_allow_origins`, `listen`, `data_dir`,
      `trusted_proxies`, `rate_limit_exempt`, `client_ipv6_prefix`.
39. **Memory targets.** The 15 MB worst-case target of the owner's decision on ADR 0018 applies to the
    profile `small` only. `standard` and `large` have no fixed target: their bound is the value that
    ADR 0018 rule 35 computes, which the relay logs. The figures of rule 37 use the estimates of ADR 0018
    rule 35; none was measured. The benchmark gate of ADR 0013 runs with the profile `small`
    ("every other setting at its default").
40. **`put` allowance.** `standard` allows 4 times and `large` 20 times the `put` rate of `small`,
    because agents and bridges publish in bursts. At 600 blocks per minute one client key can write up
    to about 42 MB per minute (blocks of maximum size, 69,632 bytes on disk each). The quota and `507`
    bound the total (ADR 0013); the operator of a `standard` or `large` relay sets `max_store_bytes`
    (rule 38).

A profile value is part of this ADR: changing one is a new ADR. `large` needs 4,176 open files; a
default soft limit of 1,024 stops the start-up on Linux (rule 22), so the packaged unit sets
`LimitNOFILE` for that profile.

### Point 12: proxy-neutral wording

ADR 0012 rule 2 names Caddy. The requirement is a function, and several proxies provide it.

41. **The protocol does not depend on a proxy.** The relay interface is defined on HTTP semantics
    (ADR 0012 rule 1). A reverse proxy is a deployment requirement of the reference relay `sbtp-relay`,
    because that program does not terminate TLS (Q-30). No rule of the spec for clients or for other
    relay implementations mentions a proxy.
42. **Function required.** ADR 0012 rule 2 is amended in its wording: "terminated by a reverse proxy
    (Caddy)" reads "terminated by a reverse proxy that also buffers request heads (for example Caddy,
    nginx or HAProxy)". A
    public `sbtp-relay` MUST be placed behind a reverse proxy that:
    - terminates TLS, and MAY offer HTTP/2 and HTTP/3 to clients;
    - buffers request heads: it sends nothing to the relay for a request before it holds the complete
      head of that request;
    - reaches the relay over HTTP/1.1 (rule 18);
    - closes its idle connections to the relay before `idle_timeout_ms` (rule 34);
    - sets, or appends to, `X-Forwarded-For` the address of the peer it accepted the request from;
    - has its own address listed in the relay's `trusted_proxies`.
    Where an accepted ADR or the spec says "Caddy" in another place (ADR 0012, "Consequences" and
    "Rejected alternatives"; ADR 0018, "Not checked"; `architecture.md` §3), it is an example and reads
    "the reverse proxy".
43. **Examples** (informative; Caddy read on 2026-11-19, the two others to be confirmed when `deploy/`
    is written):

    | Function | Caddy | nginx | HAProxy |
    |---|---|---|---|
    | HTTP/1.1 to the relay | `transport http { versions 1.1 }` | `proxy_http_version 1.1;` and `proxy_set_header Connection "";` | default for a `server` line without `proto h2` |
    | Idle upstream keep-alive below `idle_timeout_ms` | `transport http { keepalive 20s }` (default `2m`) | `keepalive_timeout 20s;` in the `upstream` block, with `keepalive <n>;` | `pool-purge-delay`, or `http-reuse never` |
    | Client address | `X-Forwarded-For` set by default | `proxy_set_header X-Forwarded-For $remote_addr;` | `option forwardfor` |
    | Request heads buffered | to be confirmed (see "Not checked") | yes | yes (`timeout http-request` bounds the wait) |

## Consequences

- **One command.** A relay starts with no configuration and binds loopback only. An operator still has
  to set up the reverse proxy to expose it, which is the intended step.
- **Security.**
  - The default difficulty is a cost for honest use, not the defence. The defences against a flood are
    the per-client buckets, the quota and the reverse proxy (ADR 0018, "Distributed senders").
  - No version is disclosed on the network (rules 25 to 27).
  - A warning is logged for a non-loopback `listen` and for a difficulty of 0.
  - The binary has no HTTP/2 code (rule 18): fewer parsers face the network.
  - A silent connection holds a slot for `header_timeout_ms` (rule 12). An idle keep-alive connection
    holds one for `idle_timeout_ms` and costs one request per period.
  - With point 10 and the defaults, one client key holds at most 8 of 32 slots; holding them all needs
    4 distinct IPv4 addresses or IPv6 /64 prefixes. This raises the cost and does not make the relay
    available against many addresses (ADR 0018, "Distributed senders"). Without point 10, one client
    holds every slot (security review F-2) and the relay MUST NOT be exposed.
  - `sbtp-relay` MUST NOT be exposed without a reverse proxy in milestone 1 (rule 42). The bound of
    rule 29 covers a relay that is reachable directly by mistake or inside a private network, and is a
    precondition of Q-30.
- **Cost of point 10 for honest clients.** A client that sends more than 8 requests in parallel through
  the proxy gets `429` with `Retry-After: 1` on the extra ones. Clients SHOULD keep at most 8 requests
  in flight per relay. Users behind one NAT address share the 8. An operator raises the setting, picks
  a larger profile, or lists known addresses in `rate_limit_exempt`.
- **Profiles.** The loader gains one precedence level and a source per setting. The "managed relay"
  column of ADR 0018 is replaced by `large`. A daemon that embeds the relay uses `small`.
- **Implementation against these rules** (for the implementer; the code is not modified by this ADR).
  Rules 1 to 11 and 18 to 27 were read at `6ff5f64`; rules 12 to 17, 21 and 23 at `e064e22`, from the
  module documentation of `server.rs` and the accept loop:

  | Rule | File | State |
  |---|---|---|
  | 1 | `crates/sbtp-relay/src/config.rs`, `ConfigError::Missing("min_pow_difficulty")` in `finish` | Diverges: required. Becomes default 16. |
  | 2 | `crates/sbtp-relay/src/lib.rs` | Missing: warning when 0. |
  | 4 | `config.rs`, `int_settings!` (`max_future_ms: 0, u64::MAX`; `block_ttl_ms: 1, u64::MAX`; `max_store_bytes: 0, u64::MAX`; `sweep_interval_ms` and `sweep_batch: 1, u64::MAX`) | Diverges: ranges. `block_ttl_ms` needs a range with a gap (0, or 60,000 and above). |
  | 5 | `config.rs`, `Raw::int` and `index_cache_bytes`, `block_cache_bytes` | Diverges: the environment accepts values up to `2^64 − 1`, the file up to `2^63 − 1`. |
  | 6, 7 | `config.rs` (`block_ttl_ms: u64`), `crates/sbtp-relay/src/api.rs`, `info_body` (`TODO(1c)`) | Missing: 0 is rejected and `/info` always publishes an integer. |
  | 8, 10 | `config.rs`, `OTHER_KEYS`, `parse_listen`, `parse_data_dir`; `lib.rs` (`create_dir_all`) | Conforms. The absolute path is not logged. |
  | 9 | `lib.rs` (`listening on`) | Missing: warning for a non-loopback address. |
  | 12 to 16 | `crates/sbtp-relay/src/server.rs`, connection phases (fresh, idle, head, busy), at `e064e22` | Conforms by its module documentation, including the fallback of rule 16. |
  | 18 | `Cargo.toml` lines 39 and 40; `server.rs` (`http1::Builder`) | Conforms. |
  | 19 to 21 | `server.rs`, `RESPONSE_GRACE` (1 second), the drain timeout and `StopSignal` (second stop request) | Conforms. |
  | 22 | `config.rs`, `soft_open_file_limit`, `check_open_files`; `lib.rs` line 85 | Conforms, except that the log line does not give the number needed. |
  | 23 | `server.rs`, `ACCEPT_BACKOFF` (50 ms) and `accept_needs_backoff`, at `e064e22` | Conforms; the list of error codes in `accept_needs_backoff` was not read. |
  | 28 to 33 | none | Not implemented: point 10 is new. |
  | 35 to 40 | `config.rs`, `Settings::load` and `finish` | Not implemented: no `profile` key, no source per setting. |
  | 25 | `api.rs`, `info_body` | Conforms. The absence of a `Server` header is to be covered by a test. |
  | 26 | `lib.rs` | Not checked. |

- **Tests to add or change.** No configuration starts with difficulty 16; each bound of rule 4, on both
  sides; the gap 1 to 59,999 of `block_ttl_ms`; `block_ttl_ms = 0` gives `"block_ttl_ms": null` and
  nothing is evicted (injected clock); the same value is accepted or refused from the file and from the
  environment; a silent new connection closes at `header_timeout_ms`; a keep-alive connection closes at
  `idle_timeout_ms` after a response, not at `header_timeout_ms`; a head started and not finished closes
  at `header_timeout_ms`; a pipelined partial head after a request with a declared length closes at
  `header_timeout_ms`, after a chunked body within `idle_timeout_ms + header_timeout_ms`; no `Server`
  header; no `h2` in `Cargo.lock`. For point 10: connection 9 of one IPv4 address is closed at accept
  while another address is served; two addresses of one IPv6 /64 share the count; a peer in
  `trusted_proxies` is not counted at accept, and request 9 in flight for one `X-Forwarded-For` key gets
  `429` with its body unread; `X-Forwarded-For` from an untrusted peer does not change the key; an
  exempt key is not bounded; the count returns to 0 after resets and timeouts; a connection past its
  age closes when idle and gets `Connection: close` when busy; request `max_requests_per_connection`
  gets `Connection: close`; the security review's attack (8 sockets against 4 slots, from one address)
  leaves requests from another address served. For point 11: no `profile` gives the `small` values;
  each profile gives the values of rule 37 and passes every constraint; a file key and an environment
  variable each override a profile value; an override that breaks a constraint stops the start-up; an
  unknown profile name stops the start-up; the logged memory bound of each profile equals the figure
  of rule 37.
- **`deploy/`.** The unit and the container set `data_dir` to an absolute path. The container sets
  `listen` to a non-loopback address inside its network namespace, and the documentation states that the
  published port MUST be bound to loopback or to the proxy network. The documentation states the six
  functions of rule 42 and gives the settings of rule 43 for each proxy it packages. When the proxy runs
  in another container its address is not loopback and MUST be added to `trusted_proxies`. The unit
  sets `MemoryMax=` and `LimitNOFILE` per profile (rule 37).
- **Memory bound** (ADR 0018 rule 35). Point 10 adds one counter per limiter entry. The estimate of 100
  bytes per entry is unchanged until it is measured.
- **Benchmark gate.** Unchanged: it sets `min_pow_difficulty = 0` explicitly (ADR 0013). Its settings
  stay inside the ranges of rule 4. The expiry bound of the gate comes from the control of ADR 0017
  rule 5, not from a short `block_ttl_ms`.
- **`sbtp-core`.** No change. **Test vectors.** None. **Compatibility.** No relay is deployed.

## Decisions of the project owner

The status stays **proposed** until the owner accepts the ADR as a whole.

**Choices stated by the owner on 2026-11-19:**

| Point | Choice |
|---|---|
| 1 | Default of `min_pow_difficulty`: 16. |
| 2 | Ranges of rules 4 and 5 as proposed. |
| 3 | `block_ttl_ms = 0` disables eviction; `/info` publishes `null`. |
| 7 | Grace of 1,000 ms, a constant. |
| 9 | No `software` member in `/info`. |
| 10 | Option D: per-client bound and keep-alive caps. `max_connections_per_client` defaults to 8, not 4. |
| 11 | A `profile` setting (`small`, `standard`, `large`), added at the owner's request. |
| 12 | Proxy-neutral wording, added at the owner's request. |

Points 4, 5, 6 and 8 follow the recommendations; the owner agreed with the ADR overall.

**Still to decide:**

1. Accept this ADR. On acceptance:
   - ADR 0018 gets "Amended by: 0019 (rule 6, key set and profile precedence; rule 8 and "Default
     profiles", named profiles; rule 22, default of `min_pow_difficulty`, three settings and one
     constraint; rule 26, new connections; rule 28, per-client bound at step 3)";
   - ADR 0012 gets "Amended by: 0019 (rule 2, wording of the reverse proxy)";
   - the spec change below is applied.
2. The values of `standard` and `large` in rule 37, in particular the `put` rates (120 / 60 and
   600 / 300) and the choice of rule 38 to keep `max_store_bytes` and `index_max_readers` outside the
   profiles.

## Rejected alternatives

They are listed per point in the option tables above. Across points:

- **A second ADR per point.** Nine small ADRs for one milestone; the points share the configuration
  loader and the accept loop.
- **Editing ADRs 0007, 0013 and 0018 in place.** An accepted ADR is not modified
  (`docs/decisions/README.md`).

## Spec change

Applied to `docs/spec/sbtp-core-v0.2.md` and `docs/spec/architecture.md` on 2026-11-19.

**`docs/spec/sbtp-core-v0.2.md` §3.3**, last bullet. After "published by `GET /sbtp/v1/info` (§4).",
add:

```markdown
  The default of `sbtp-relay` is 16. (ADR 0019)
```

**§4, `GET /sbtp/v1/info`.** Replace the `block_ttl_ms` bullet with:

```markdown
- `block_ttl_ms`: integer in milliseconds, or `null` when the relay does not evict by age. A relay never
  publishes `0`.
```

Replace the `software` sentence with:

```markdown
- A relay MAY publish `software` (free string). `sbtp-relay` does not publish it. (ADR 0019)
```

**§4, "Admission control"** (subsection to be added by the spec change of ADR 0018). Replace the
`429` bullet with:

```markdown
- `429 Too Many Requests` (`RateLimited`): this client is over its own allowance, in requests per period
  or in requests in flight. The relay answers before reading the body and SHOULD send `Retry-After` in
  seconds. A relay counts clients by address; an IPv6 /64, or the users of one shared address, are one
  client. A client SHOULD keep at most 8 requests in flight per relay.
```

and replace "A relay MAY also close a connection that is idle or too slow, without a response." with:

```markdown
- A relay MAY close a connection without a response: when it is idle or too slow, when the client holds
  too many connections, or after a number of requests or a duration. A response MAY carry
  `Connection: close`. (ADR 0019)
```

**§4, intro, and any sentence of the spec that requires a proxy.** State the function: "a public
`sbtp-relay` is placed behind a reverse proxy that terminates TLS and buffers request heads (for example
Caddy, nginx or HAProxy)". The spec states no proxy requirement for clients or for other relay
implementations. (ADR 0019 rules 41 and 42)

**`docs/spec/architecture.md` §3**, tier table, row 2. Replace "Backbone, behind Caddy or Nginx." with:

```markdown
Backbone, behind a reverse proxy that terminates TLS and buffers request heads (Caddy, nginx, HAProxy).
```

**`docs/spec/architecture.md` §2.** In the part "Admission control" (to be added by ADR 0018), add:

```markdown
- A connection is new, reading a request head, serving a request, or idle between two requests. One
  time limit applies to each phase (`header_timeout_ms` for the first two, `request_timeout_ms`,
  `idle_timeout_ms`). A new connection that sends nothing is closed at `header_timeout_ms`. (ADR 0019)
- One client holds at most `max_connections_per_client` connections, or requests in flight when it
  comes through a trusted proxy. (ADR 0019)
- A `profile` setting (`small`, `standard`, `large`) gives coherent values to the resource limits. Each
  setting overrides it. The 15 MB worst-case memory target applies to `small`. (ADR 0019)
- The relay listens on one address (`listen`, default `127.0.0.1:8080`) and keeps its blocks and index
  under `data_dir`. It serves HTTP/1.1 only. (ADR 0019)
```
