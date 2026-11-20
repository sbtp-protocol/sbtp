# 0020: Relay admission control refinements

- Status: accepted (by the project owner, 2026-11-19), with the recommended choice on every point: guard pause
  1 ms after 16 consecutive failures; proxy key plus a throttled warning when X-Forwarded-For has no valid
  entry; `unknown` ends the search; loopback trusted by default; prefix 0 refused, warning below /16 (IPv4)
  or /32 (IPv6); warning, not a strict bound, for L-6; preflights and unknown paths cost a token
- Amended by: 0022 (rule 7: a non-ASCII byte invalidates the element, not the whole line); 0027
  (clarification T1: the worst-case figures below are recomputed with a limiter entry of 192 bytes); 0044
  (rule 6: `client_ip_header` is the one header read besides `X-Forwarded-For`, and replaces it when set)
- Also amends: ADR 0019 rule 37 computed worst cases, now including the per-client tables (d2f54f6):
  small 13,022,676 bytes, standard 97,662,800 bytes, large 1,199,328,928 bytes
- Clarifications: 2026-11-19, after relay milestone 1c-b (N1: overflow key and per-client `PUT` bound;
  N2: class of a preflight), accepted by the project owner, 2026-11-19
- Date: 2026-11-19
- Questions: none. Follows the security reviews `docs/security/2026-11-19-relay-adr0019.md` (L-1 to L-7,
  I-1 to I-4) and `docs/security/2026-11-19-relay-m1a.md` (R-1, F-6)
- Amends, if accepted:
  - ADR 0019 rule 23 (accept errors: the default is inverted), rule 28 (a warning is added to the
    constraint; the constraint is unchanged), rule 30 (how the forwarded address is read; the order of
    the token and the count), rule 31 (separate counts; the overflow key; one more warning);
  - ADR 0018 rule 20 (exact reading of `X-Forwarded-For`; exemption and trust tested on the address),
    rule 21 (class of a request that matches no route, and of a preflight), rule 22 (validation of the
    CIDR lists).
  - Clarifies, without changing its text: ADR 0018 rule 28 (step 3 has a fixed internal order).
- Depends on: ADR 0018 (client key, token buckets, admission order), ADR 0019 (points 8, 10 and 12)
- Impact: spec §4 "Admission control" (two sentences, see "Spec change", not applied); `sbtp-relay`
  (`server.rs`, `client.rs`, `config.rs`, the limiter of milestone 1c, tests); `deploy/` (forwarder rule,
  form of `X-Forwarded-For`); no `sbtp-core` change; no test vector

## Context

ADR 0019 was implemented on branch `feat/relay-m1a-adr0019` (commit `3fc75af`) and reviewed. The review
found no blocking defect. It found behaviour that the code had to choose because no accepted rule states
it, and one place where the code, on the reviewer's advice, does the opposite of an accepted rule
(ADR 0019 rule 23). The project rule is spec first: this ADR states those behaviours before any further
code change. Rules are numbered through the whole ADR.

State of the code at `3fc75af`, read for this ADR:

| Subject | Code | Behaviour today |
|---|---|---|
| Accept errors | `server.rs`, `accept_needs_backoff` and the accept loop | Pause 50 ms and one log line per failure by default. Retry at once, with a throttled log line, for 13 listed error numbers. No guard on consecutive failures. |
| Forwarded address | `client.rs`, `ClientPolicy::forwarded_client` | Header lines and elements read from the right. A trusted address is stepped over. The first untrusted address is used. Any element that is not a bare IP address, an empty element included, ends the search and gives the peer address. No log line. |
| CIDR lists | `config.rs`, `Cidr::parse` | Host bits set: refused. Any prefix from 0 accepted. A block inside `::ffff:0:0/96` accepted; it never matches. |
| Per-client bound | `config.rs`, constraint check | `max_connections_per_client ≤ max_connections`; equality accepted, no warning. |
| Admission step 3 | `server.rs`, service function in `Connection::run` | The in-flight count is taken in the hyper service function. The token bucket does not exist yet (`TODO(1c)`). |

## Decision

### Point 1: accept errors (R-1, L-3)

ADR 0019 rule 23 pauses for four resource errors and retries every other error at once. The review of
milestone 1a (R-1) showed that an unforeseen persistent error then spins one core without a log line. The
code now does the opposite. The review of `3fc75af` (L-3) found two residual cases: a persistent error
inside the retried list (`EPERM` returned by a seccomp filter leaves the connection in the queue), and
20 log lines per second on the pause branch.

| Option | For | Against |
|---|---|---|
| A. Keep rule 23 as accepted | No amendment. | An error outside the four classes spins a core. The code already departs from it. |
| B. Inverted default, closed list of retried errors (implemented) | An unknown error is slow and logged. | A persistent error in the list still spins (L-3). |
| C. B, plus a guard: after 16 consecutive failures every further failure pauses 50 ms | One constant. Closes L-3. | Where `accept` reports aborted connections (BSD, macOS), a run of them slows the loop to 20 calls per second: a listen queue of 1,024 aborted connections delays the next client by 51 s. |
| D. B, plus a guard with a short pause (1 ms) for the listed errors | Closes L-3: at most 1,000 failed calls per second. The same queue drains in about 1 s. | Two pause constants. |

**Recommendation: D.** Option C is acceptable if the owner prefers one constant; its cost falls on a
relay reached directly, which rule 42 of ADR 0019 already forbids for a public relay.

1. **Two classes.** ADR 0019 rule 23 is replaced by rules 1 to 5. A failed `accept` belongs to one of two
   classes:
   - **per-connection**: the error number is in the list of rule 2. The error concerns one pending
     connection. The relay calls `accept` again at once, subject to rule 3;
   - **other**: every other error, including `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, an error number
     that this ADR does not list, and an error without an error number. The relay MUST wait 50 ms before
     the next `accept`. The value is a constant (ADR 0019 rule 23, reason unchanged).
2. **List of per-connection errors.** `ECONNABORTED`, `ECONNRESET`, `EINTR`, `EPERM`, `EPROTO`,
   `ENOPROTOOPT`, `ENETDOWN`, `ENETUNREACH`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENONET`, `EOPNOTSUPP`,
   `ETIMEDOUT`. The list is closed: an implementation MUST NOT add to it without an ADR. A name that the
   target does not define is left out on that target (`ENONET` exists on Linux only).
3. **Consecutive-failure guard.** The relay counts failed `accept` calls of both classes. A successful
   `accept` resets the count to 0. While the count is above 16, a per-connection failure MUST be followed
   by a pause of 1 ms before the next `accept`. The pause of the other class stays 50 ms. Both values and
   the threshold are constants. A failed `accept` therefore never repeats more than 1,000 times per
   second for longer than 16 calls.
4. **Logging.** Each class has its own log line, and each line is throttled as in rule 27: the first
   failure is logged at once, then at most one line per 60 s, with the number of failures not logged
   since the last line. The line carries the text of the operating system error. It MUST NOT carry an
   address.
5. **No exit.** A failed `accept` never ends the relay process and never closes an open connection. A
   stop request is served during a pause after at most the length of that pause.

### Point 2: reading `X-Forwarded-For` (L-1)

ADR 0018 rule 20 says "the rightmost address of `X-Forwarded-For` that is not itself in
`trusted_proxies`" and "the peer address when there is none". It does not say what an address is, what
several header lines mean, or what an element that is not an address does. Some proxies write `ip:port`
or `[v6]:port` (the review names Azure Application Gateway and IIS ARR); some write `unknown`.

The header has no standard. Rule 6 takes the list syntax of RFC 9110 section 5.6.1 and the address text
forms of RFC 4291 section 2.2, and nothing else.

**Which element is used.** Unchanged, and verified by the review: the rightmost address that is not in
`trusted_proxies`. A proxy that follows rule 42 of ADR 0019 appends its own peer on the right; elements to
the left of it may have been written by the client and are never used.

**An element that is not an address.** The task brief for this ADR groups `unknown` with the empty
elements, as "skipped". This ADR separates them, for a security reason. Read from the right, every
element before the first untrusted address was written by a trusted proxy. An empty element carries no
claim, and RFC 9110 requires a recipient to ignore it. `unknown` is a claim: the proxy states that it
does not know its peer. Stepping over it would use the next element to the left, which the client may
have written, so the client would choose its own key. `unknown` therefore ends the search (rule 9), as
the code does today.

**When no client address is found.** Two cases must be told apart. (a) No header, or only trusted
addresses: the request comes from the proxy itself or from a local process (a health check). The peer
address is the correct key, as ADR 0018 rule 20 says. (b) An element that is not an address: the proxy
writes a form the relay cannot read, and every client of that proxy shares one key.

| Option for case (b) | For | Against |
|---|---|---|
| A. Peer address as the key, with a throttled warning | Fails closed: the unreadable proxy is one client. No new status code. The outcome of ADR 0018 rule 20 is kept. The operator is told. | Service is degraded for every client of that proxy (8 requests in flight, one set of buckets) until the operator acts. |
| B. `400` for the request | Immediate and total: found at the first test. | The client did nothing wrong and cannot fix it. A relay that works for most requests refuses all of them when one path writes `unknown`. A new cause of `400` in the spec. |
| C. A key per request | No client is refused. | No bound and no bucket applies: this removes the limiter exactly when the configuration is wrong. Rejected. |

**Recommendation: A.** Rule 7 removes the common cause (a port), and rule 11 makes the remaining cases
visible.

6. **Scope.** The header is read only on a connection whose peer address is in `trusted_proxies`
   (ADR 0019 rule 31). The field name is `X-Forwarded-For`, compared without regard to case. `Forwarded`
   (RFC 7239), `X-Real-IP` and every other header MUST NOT be read for the client key. All field lines
   with that name form one list: the lines in the order received, each line split at every comma. The
   first element of the first line is the leftmost; the last element of the last line is the rightmost.
7. **Element forms.** Leading and trailing spaces and horizontal tabs of an element are removed. The
   element is then one of:

   | Form | Example | Result |
   |---|---|---|
   | empty | a trailing comma, two commas in a row, an empty field value | empty element |
   | IPv4 address | `203.0.113.7` | that address |
   | IPv6 address | `2001:db8::1`, `::ffff:203.0.113.7` | that address |
   | IPv4 address, `:`, port | `203.0.113.7:4711` | the address; the port is dropped |
   | `[`, IPv6 address, `]`, `:`, port | `[2001:db8::1]:4711` | the address; the port is dropped |
   | anything else | `unknown`, `_hidden`, `"203.0.113.7"`, `[2001:db8::1]`, `203.000.113.007`, `0xcb.0.113.7`, `fe80::1%eth0`, a host name | invalid element |

   An IPv4 address is four decimal numbers from 0 to 255 separated by dots, without a leading zero. An
   IPv6 address is one of the text forms of RFC 4291 section 2.2, in either letter case, without a zone
   identifier. A port is 1 to 5 decimal digits with a value of at most 65,535. A field line that
   contains a byte outside visible ASCII, space and horizontal tab is one invalid element.
8. **Normalisation.** An IPv4-mapped IPv6 address (`::ffff:0:0/96`) is replaced by its IPv4 address
   before any test (ADR 0018 rule 20). This holds for a peer address and for an element.
9. **Selection.** The relay reads the list from the rightmost element to the leftmost:
   - an empty element is ignored;
   - an address in `trusted_proxies` is ignored;
   - an address that is not in `trusted_proxies` is the client address; the search ends;
   - an invalid element ends the search without a client address (case (b)).

   If the list is absent or ends without a client address, this is case (a). Elements to the left of
   the one that ended the search are not read.
10. **No client address.** In cases (a) and (b) the client address of the request is the peer address
    of the connection, as in ADR 0018 rule 20. The relay MUST NOT refuse a request because of the
    content of `X-Forwarded-For`, and MUST NOT give such a request a key of its own.
11. **Warnings.** Both are throttled as in rule 27 and name `trusted_proxies`, `X-Forwarded-For` and
    ADR 0019 rule 42. Neither carries the header value or an address.
    - Case (b): the relay logs a warning that a trusted proxy sent an element it cannot read, and that
      the requests of that proxy share one client key.
    - A request refused under ADR 0019 rule 30, or for an empty bucket, whose client address is the
      address of a trusted peer: the relay logs a warning that requests arriving without a client
      address are being refused. This covers case (a) when a proxy writes no header at all, without a
      line per health check.
12. **Deployment.** The reverse proxy SHOULD write a bare address. `deploy/` MUST state the forms of
    rule 7 and MUST give, for each proxy it documents, the setting that produces one of them.

### Point 3: over-broad trust (L-2, L-7)

A peer in `trusted_proxies` is not counted at accept, and what it writes in `X-Forwarded-For` becomes
the client key. Two configurations give that power to clients: a block that covers client addresses
(`0.0.0.0/0`, a private /8 on a relay that listens on that network), and a trusted address from which a
TCP-level forwarder relays client bytes unchanged (`ssh -R`, `socat`, `stunnel`, nginx `stream`, HAProxy
`mode tcp`). Measured by the review for the second: 31 forged keys through loopback, 31 requests served.

| Option for a broad block | For | Against |
|---|---|---|
| A. Accept in silence (today) | Nothing to do. | One line of configuration removes every per-client rule, unseen. |
| B. Warning below a prefix length | The operator is told; legitimate ranges still start (a container network /16, the published ranges of a hosted proxy). | A warning can be ignored. |
| C. Refuse a prefix of 0, warn below a prefix length | A block that trusts every address of a family has no use: "trust everything" is never a proxy list. Follows ADR 0018 rule 7. | Two thresholds. |
| D. Refuse everything wider than one host | Strictest. | Refuses container networks and hosted proxies, where the proxy address is one of a range. |

**Recommendation: C.**

| Option for the default | For | Against |
|---|---|---|
| A. Keep `127.0.0.1/32`, `::1/128` (ADR 0018 rule 22) | The documented deployment (reverse proxy on the same host) works without a setting. An accepted default is kept. A remote peer is never a loopback address. | A TCP-level forwarder on the host fails open, in silence. Every local process can choose a key. |
| B. Empty default | Fails closed: a proxy that is not listed is one client with `max_connections_per_client` connections, and ADR 0019 rule 31 warns. | The documented deployment needs one more setting, or starts degraded. Changes an accepted default for a case that rule 42 already forbids. |

**Recommendation: A, with the start-up line of rule 16 and the deployment rule of rule 17.**

13. **Refused.** A block with a prefix length of 0 (`0.0.0.0/0`, `::/0`) in `trusted_proxies` MUST stop
    the start-up, with a message that names the setting and the block.
14. **Warned.** The relay MUST log one warning at start-up for each block of `trusted_proxies` whose
    prefix length is below 16 for IPv4 or below 32 for IPv6. The warning names the block and states that
    every address in it may write `X-Forwarded-For` and is not counted at accept.
15. **`rate_limit_exempt`.** A block with a prefix length of 0 is accepted: it turns the per-client
    rules off for one address family, which an operator may want on a closed network. The relay MUST log
    one warning at start-up for it, and for each block below the prefix lengths of rule 14. The relay
    MUST also log one warning for each pair of blocks, one from `trusted_proxies` and one from
    `rate_limit_exempt`, that share an address: a request without a client address (rule 10) is then
    exempt.
16. **Loopback stays trusted by default.** The default of `trusted_proxies` is unchanged. When
    `trusted_proxies` contains a loopback address, the relay MUST log one line at start-up: every local
    process is trusted to write `X-Forwarded-For`, and a forwarder that does not write it needs
    `trusted_proxies = []`.
17. **Deployment rule.** An address MUST be listed in `trusted_proxies` only if every connection from
    it comes from a program that sets, or appends to, `X-Forwarded-For` the address of its own peer on
    every request (ADR 0019 rule 42). A forwarder that relays bytes without writing the header MUST NOT
    have an address in `trusted_proxies`; when it runs on the relay's host, the operator MUST set
    `trusted_proxies = []`. Such a forwarder is then one direct client: all its users share
    `max_connections_per_client` connections and one set of buckets. It is not a supported way to
    publish a relay. `deploy/` MUST state this rule.

### Point 4: silent configuration cases (L-6, L-4)

**`max_connections_per_client` against `max_connections`.** With equality one client key may hold every
slot, which is the starvation that the bound exists to stop (F-2).

| Option | For | Against |
|---|---|---|
| A. Accept in silence (today) | Nothing to do. | `profile = "large"` with `max_connections = 32` gives 32 and 32, unseen. |
| B. Strict constraint, `<` | Start-up fails. | Forbids `max_connections = 1`, which is in range. Forbids a relay for one user (desktop daemon, test). 31 of 32 passes and protects nobody: a strict bound draws the line at the wrong place. |
| C. Warning when one key can hold more than half of the slots | Names the real condition. No valid configuration is refused. | A warning can be ignored. |

**Recommendation: C.** The three profiles of ADR 0019 rule 37 stay below the threshold (8 of 32, 16 of
256, 32 of 4,096).

**IPv4-mapped blocks.** Addresses are normalised to IPv4 before any test (rule 8), so a block inside
`::ffff:0:0/96` never matches.

| Option | For | Against |
|---|---|---|
| A. Accept (today) | Nothing to do. | A proxy that is silently not trusted; an exemption that is silently absent. |
| B. Convert to the IPv4 block at load, and log it | The operator's intent is served. | ADR 0018 rule 7: the relay does not adjust a value. Two spellings of one block. |
| C. Refuse, and give the IPv4 form in the message | One spelling. The operator fixes the file once. | A start-up failure for a block whose intent is clear. |

**Recommendation: C.**

18. **Warning on the per-client bound.** The constraint of ADR 0019 rule 28 is unchanged
    (`max_connections_per_client ≤ max_connections`). When
    `2 × max_connections_per_client > max_connections`, the relay MUST log one warning at start-up that
    names both settings, their values and the source of each (default, profile, file, environment).
19. **CIDR syntax.** A block of `trusted_proxies` or `rate_limit_exempt` is `address/prefix`, the
    address in a form of rule 7 without a port, the prefix 0 to 32 for IPv4 and 0 to 128 for IPv6. A
    block whose address has a bit set beyond the prefix MUST stop the start-up (implemented; stated
    here). A block inside `::ffff:0:0/96` (an IPv4-mapped address with a prefix of 96 or more) MUST stop
    the start-up, with a message that gives the IPv4 block to write instead (`::ffff:10.0.0.0/104` is
    `10.0.0.0/8`).
20. **Families do not mix.** An IPv4 block matches IPv4 addresses, including the IPv4-mapped form of a
    peer or an element. An IPv6 block never matches an IPv4 or IPv4-mapped address, whatever its prefix
    (`::/1` contains no IPv4 client). To cover both families the operator writes two blocks.

### Point 5: order of the token and the count, for milestone 1c (L-5)

ADR 0019 rule 30 says that a request takes its token first, then its place in the in-flight count. The
count is already taken in the connection's service function, before the router. A limiter written as a
router layer in milestone 1c would run after it. An over-bound request would then be refused before it
pays a token, a request refused by the limiter would hold an in-flight place, and the client key would
be derived twice.

| Option | For | Against |
|---|---|---|
| A. Limiter as a router layer; count stays in the service function | The usual shape of a `tower` limiter. | Contradicts rule 30. `429` traffic of a client at its bound is free. Two derivations of the key. |
| B. Move the count into the router as well | One place. | The count must be released when the response is written to the socket (ADR 0019 rule 14), which the router does not see. |
| C. Token, then count, in the service function, from one key computed once | Follows rule 30. The class is known from the method and the path. One derivation. | The service function must classify the request before routing. |

**Recommendation: C.**

21. **One key per request.** The client key of a request is computed once, at step 3 of ADR 0018
    rule 28, before the request reaches the router. On a direct connection it is the key of the peer
    address and MAY be computed once per connection. Every per-client rule applied to that request uses
    that value: the token bucket (ADR 0018 rule 21), the in-flight count (ADR 0019 rule 30) and the
    per-client `PUT` bound (ADR 0018 rule 18). The key MUST NOT be derived a second time from the
    connection or the headers.
22. **Order inside step 3.** (a) Client address (rules 6 to 10) and exemption (rule 26). An exempt
    request skips (b) to (d). (b) Class of the request (rule 23). (c) One token of that class is taken
    from the bucket of the key; with no token, `429` with the `Retry-After` of ADR 0018 rule 29. (d) On
    a connection from a trusted peer, the in-flight count of ADR 0019 rule 30; over the bound, `429`
    with `Retry-After: 1`. A request refused at (c) is not counted at (d). A request refused at (d) has
    spent its token: no token is given back (ADR 0018 rule 28). Both refusals are sent before the body
    is read, with the error body and CORS headers of ADR 0018 rule 34.
23. **Class without the router.** The class is a function of the method and the path only: method
    `PUT`: `put`; path `/sbtp/v1/query`: `query`; every other request: `block`. A request that will get
    `404` or `405` at step 4, and a CORS preflight, each take one `block` token and are counted in
    flight like any request. No request is answered before step 3 (this settles F-6 of the milestone 1a
    review).
24. **Overflow key.** When the limiter attributes a request to the overflow key (ADR 0018 rule 21), the
    token and the in-flight count of that request are both taken on the overflow key. All such requests
    share one bucket set and one in-flight count of `max_connections_per_client`. The connection count
    of a direct peer (ADR 0019 rule 29) does not use the limiter table and has no overflow key: it holds
    at most `max_connections` entries.
25. **Tests required in milestone 1c.** A client at its in-flight bound that keeps sending exhausts its
    bucket (the `Retry-After` of its `429` becomes that of rule 29). A request refused for an empty
    bucket leaves the in-flight count unchanged. A preflight and a request to an unknown path each cost
    one `block` token.

### Point 6: other findings that need a rule

| Finding | Rule needed? |
|---|---|
| I-2, separate counts for direct and proxied clients | Yes: rule 28. ADR 0019 rule 31 does not say whether the two counts are one. |
| "Verified and holds", exemption tested before the /64 aggregation | Yes: rule 26. ADR 0018 rule 21 says "client key in `rate_limit_exempt`", and the key of an IPv6 client is a /64. |
| "Verified and holds", throttled log lines | Yes: rule 27. The period and the content are in the code only. |
| "Verified and holds", `Forwarded` is not read | Yes: rule 6. |
| F-6 (milestone 1a review), preflight and the limiter | Yes: rule 23. |
| I-1, residual of F-2 on a relay reached directly | No. ADR 0019 rule 42 stands: a public relay is behind a reverse proxy. |
| I-3, the age cap does not shorten the fresh and head phases | No. ADR 0019 rule 32 gives the bound, and the review confirms it. |
| I-4, review range | No. Process, not behaviour. |
| L-3 scenario B, open-file check skipped outside Linux | No new rule. ADR 0019 rules 22 and 24 stand; rule 4 bounds the log volume. |

26. **Exemption and trust are tested on the address.** `rate_limit_exempt` and `trusted_proxies` are
    tested against the normalised address (rule 8), before the aggregation of an IPv6 address to
    `client_ipv6_prefix` bits. An exempt /128 exempts that address and not its /64. "Client key in
    `rate_limit_exempt`" in ADR 0018 rule 21 and ADR 0019 rule 31 reads "client address in
    `rate_limit_exempt`".
27. **Throttled log lines.** A log line that a remote peer, a proxy or a lasting error can cause
    repeatedly MUST be throttled: the first event is logged at once, then at most one line per 60 s for
    that event, with the number of events not logged since the last line. This applies to the lines of
    rules 4 and 11 and to the warning of ADR 0019 rule 31. Such a line MUST NOT carry a client address,
    a header value or a path (ADR 0018 rule 21).
28. **Two counts.** The connection count of direct peers (ADR 0019 rule 29) and the in-flight count of
    requests through trusted peers (ADR 0019 rule 30) are separate. A client key may hold up to
    `max_connections_per_client` in each. They count different units, and a client reaches both only on
    a relay whose port is exposed next to its proxy, which rule 17 and ADR 0019 rule 42 exclude.

## Consequences

**Implementation (the implementer), after acceptance.**

| Rule | File at `3fc75af` | Change |
|---|---|---|
| 1, 2 | `server.rs`, `accept_needs_backoff` | None: the list and the default match. |
| 3 | `server.rs`, accept loop | Add the consecutive-failure count and the 1 ms pause. |
| 4 | `server.rs`, accept loop | Route the 50 ms branch through a `Throttle` of its own. |
| 6 to 9 | `client.rs`, `forwarded_client` | Accept the two forms with a port. Ignore empty elements (today they end the search). Reject a zone identifier and a port of more than 5 digits if the standard library parser accepts them (not checked, see below). Return which case applied, for rule 11. |
| 11 | `server.rs`, service function | Two throttled warnings. |
| 13 to 16, 18 | `config.rs`, load and `Settings::warnings` | One refusal, the warnings and the start-up line. |
| 19 | `config.rs`, `Cidr::parse` | Refuse a block inside `::ffff:0:0/96`. |
| 21 to 25 | `server.rs`, limiter (milestone 1c) | Token and count in the service function, in that order; the key passed to the handlers in a request extension; `ConnectInfo` no longer used for the key; CORS answered after step 3. |
| 26, 28 | `client.rs`, `server.rs` | None: implemented as stated. |

**Tests to add.** Rule 3 (a mock listener that fails 17 times); the table of rule 7, one case per row,
with the forms measured by the review; empty elements to the right of an address; `unknown` to the right
of a forged address gives the peer key; rules 13, 14, 15, 18 and 19 through the binary's exit status and
log; the tests of rule 25.

**Compatibility.** No wire change and no `/info` change. A configuration with a prefix of 0 in
`trusted_proxies`, or with an IPv4-mapped block, stops starting; the message gives the fix. A proxy that
writes `ip:port` goes from one shared key to per-client keys. A request with an empty element in the
header (`a, ,b` or a trailing comma) is now read past the empty element; before, it fell back to the
peer key.

**Security.** Rule 9 keeps the property the review verified: a client behind an appending proxy
controls only elements to the left of the one the proxy writes, and the search never reads past an
untrusted or invalid element. Ignoring an empty element does not weaken it: an appending proxy writes a
non-empty element on the right. Rule 3 removes the last accept path that can hold a core. Rules 13 to 17
do not make a relay safe to expose without a proxy; they make three wrong configurations visible.

**Not checked.**

- Whether the Rust standard library parser accepts a zone identifier or more than 5 port digits in
  `[v6]:port`. The toolchain was not available in this session. Rule 7 is the reference; the code
  follows it.
- Whether Linux returns `ECONNABORTED` from `accept` for a connection reset in the queue often enough
  for option C of point 1 to matter there. The argument for option D rests on BSD and macOS behaviour
  and on reading, not on a run.
- The forms of `X-Forwarded-For` written by Caddy, nginx and HAProxy (bare address expected), and by the
  two products the review names for `ip:port`. To confirm when `deploy/` is written.

## Decisions for the project owner

1. Accept this ADR. On acceptance (pending note; ADR 0019 and ADR 0018 are not edited before that):
   - ADR 0019 gets "Amended by: 0020 (rule 23, accept errors; rule 28, warning on the per-client
     constraint; rule 30, reading of `X-Forwarded-For` and order of token and count; rule 31, separate
     counts and overflow key)", and its index line reads "accepted, amended by 0020";
   - ADR 0018 gets "Amended by: 0019 (...) and 0020 (rule 20, reading of `X-Forwarded-For`, exemption and
     trust tested on the address; rule 21, class of unmatched requests and preflights; rule 22,
     validation of the CIDR lists)", and its index line reads "accepted, amended by 0019 and 0020";
   - the spec change below is applied.
2. Point 1: guard pause of 1 ms for the listed errors (D, recommended) or 50 ms for every error (C).
3. Point 2: peer key with a warning when a proxy writes an unreadable element (A, recommended) or `400`
   (B). And confirm that `unknown` ends the search and is not stepped over.
4. Point 3: loopback stays trusted by default (A, recommended) or the default becomes empty (B); the
   warning thresholds of rule 14 (/16 and /32).
5. Point 4: warning (recommended) or strict constraint for the per-client bound; refusal (recommended) or
   conversion of IPv4-mapped blocks.
6. Point 5: a preflight and an unmatched request each cost one `block` token (rule 23).

## Clarifications (2026-11-19, after relay milestone 1c-b)

Recorded by the specification editor after relay milestone 1c-b (`feat/relay-m1c-b`, 52f8a7b), pending the
project owner's approval. They change no decision above.

- **N1. The overflow key and the per-client `PUT` bound.** Rule 24 moves two per-client values to the
  overflow key: the token and the in-flight count of ADR 0019 rule 30. Both live in the limiter table
  (ADR 0019 rule 31), whose size is bounded by `rate_limit_max_clients`; the overflow key exists because
  that table has no room. The per-client `PUT` bound of ADR 0018 rule 18 is not moved.
  - It is counted on the client key computed at step 3 (rule 21), never on `ClientKey::OVERFLOW`.
  - Its entries need no table bound: a key has an entry only while it has a `PUT` waiting for a permit or
    holding one, so there are at most `put_max_in_flight + put_max_queue` entries. This is the same
    reasoning as the direct-peer connection count of rule 24, last sentence.
  - Reason: on the overflow key, every client that the table could not hold would share
    `put_max_in_flight_per_client` slots (2 by default), and one of them could block the `PUT`s of all
    the others. The global bound `put_max_in_flight` still applies to all.
  - This holds whether or not the `put` bucket is enabled; the `put` token itself follows rule 24.
- **N2. Class of a CORS preflight and of an unrouted method.** Rule 23 has two sentences that disagree
  for an `OPTIONS` request to `/sbtp/v1/query` (and for, say, `POST /sbtp/v1/query`): the first gives the
  class `query` from the path; the second says that a preflight, and a request that gets `405`, take a
  `block` token. Decision 6 of the project owner (preflights and unmatched requests cost one `block`
  token) settles it in favour of the second. The class is computed from the method and the path only,
  as follows:
  - `put`: method `PUT` and path `/sbtp/v1/block`;
  - `query`: method `GET` and path `/sbtp/v1/query` (and `HEAD` on that path, if the router answers it as
    a `GET`);
  - `block`: every other request, including `OPTIONS` on any path, any other method on
    `/sbtp/v1/query`, and `PUT` on any other path.
  - Reason: a preflight and a `405` are answered without index access. The `query` bucket is the
    smallest (20 tokens, 300 per minute); a browser that sends a preflight before a cross-origin `/query`
    would otherwise spend two `query` tokens per page. The security review of 1c-b
    (`docs/security/2026-11-19-relay-m1c-b.md`, I-4) raised it.
  - The tests of rule 25 are unchanged: a preflight and a request to an unknown path each cost one
    `block` token.

## Rejected alternatives

Listed per point in the option tables. Across points:

- **Reading `Forwarded` (RFC 7239) as well.** A standard header, but two sources for one key need a rule
  for their disagreement, and the three documented proxies write `X-Forwarded-For`.
- **PROXY protocol for TCP-level forwarders.** It would make the forwarder case of rule 17 safe. It adds
  a parser in front of HTTP on an exposed port, for a deployment that is not supported.
- **A fatal error after N failed accepts.** A relay at its descriptor limit under load would exit and
  drop every open connection. The pause and the throttled line are enough.
- **Editing ADR 0019 rule 23 in place.** An accepted ADR is not modified (`docs/decisions/README.md`).

## Spec change

Not applied. To apply to `docs/spec/sbtp-core-v0.2.md` on acceptance. Only two behaviours of this ADR
are visible to a client; the rest is local to `sbtp-relay` and its deployment, and the spec states no
proxy rule for clients (ADR 0019 rule 41).

**§4, "Admission control".** In the `429` bullet, after "A client SHOULD keep at most 8 requests in
flight per relay.", add:

```markdown
  A request refused with `429` still counts against the client's allowance: repeating it before
  `Retry-After` delays the next accepted request. (ADR 0020)
```

After the `429` bullet, add:

```markdown
- Every request counts against the client's allowance, whatever its response: a request to an unknown
  path, a request with a wrong method and a CORS preflight included. A relay MAY answer any of them with
  `429`. (ADR 0020)
```

In the closing line of the subsection, "(ADR 0007, ADR 0012, ADR 0018)" becomes
"(ADR 0007, ADR 0012, ADR 0018, ADR 0020)".
