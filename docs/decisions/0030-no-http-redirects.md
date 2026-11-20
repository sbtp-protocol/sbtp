# 0030: No HTTP redirects on the relay interface

- Status: accepted (by the project owner, 2026-11-20)
- Date: 2026-11-19
- Questions: Q-37 (HTTP redirects on the relay interface)
- Amends: ADR 0029 rule 15 (a `3xx` response is added to the failed requests). Nothing else in ADR
  0029 changes. ADR 0028 rules 3 and 52 are not amended: they become cases of the general rule of this
  ADR, with the same effect
- Depends on: ADR 0012 (relay API, errors, CORS), ADR 0024 (cursors belong to one relay and one index
  epoch), ADR 0028 (rule 3: a TLS `sbtp-relay` sends no redirect; rule 52: `cli-demo` follows none),
  ADR 0029 (rule 1: every relay, proxy and mirror is untrusted; rules 6, 7, 15 and 16)
- Impact: spec §4 (new subsection "Redirects", one bullet in "Client bounds"; see "Spec change on
  acceptance", applied 2026-11-20); `examples/cli-demo` (already conforms at `c041eba`); `web/` (Phase 3 web client: every
  `fetch()` to a relay sets `redirect: "manual"` or `"error"`); `sbtp-relay` (already conforms; one test
  to add); `deploy/` (proxy examples: no redirect on the relay URL); no `sbtp-core` change; no test
  vector

## Context

Spec §4 does not mention redirects. Two existing rules cover one program each:

- ADR 0028 rule 3: `sbtp-relay` with `tls_mode = "files"` serves no plain HTTP and sends no redirect.
- ADR 0028 rule 52: `cli-demo` keeps `max_redirects(0)` in `ureq`, so an `https://` relay cannot send it
  to `http://`. `cli-demo` reports every `3xx` with "A relay does not redirect: check the URL."
  (`examples/cli-demo/src/relay.rs`), and `tests/e2e.rs` `redirects_are_not_followed` checks it.

`sbtp-relay` emits no `3xx` on any route. Neither rule binds a third-party relay, a reverse proxy or a
third-party client.

The Phase 3 web client calls `fetch()`, which follows redirects by default. Under the Fetch Standard,
`redirect: "follow"` follows up to 20 redirects, to any origin in `cors` mode; a `303` turns a `PUT`
into a body-less `GET`; a cross-origin redirect sends `Origin: null` to the target. A page served over
`https` cannot follow a redirect to `http` (mixed content), but a client outside a browser can.

The other two modes:

- `redirect: "error"`: a `3xx` with a `Location` is a network error. Script sees a `TypeError`, the same
  as for a refused connection.
- `redirect: "manual"`: in a browser the result is an opaque-redirect response: `type` is
  `"opaqueredirect"`, `status` is `0`, headers and body are not readable. Script can tell that a
  redirect happened. It cannot read the `Location`.

So a browser client cannot check a redirect target before the request reaches it. "Follow only
same-origin redirects" can be checked only after the fact, through `response.url`, once the request,
a `PUT` body included, has reached the other server.

What a redirect would let a relay or a proxy do, beyond what it can already do by serving bad content:

- **Send a client to a server the client did not choose.** For a browser this is bounded by CORS and
  mixed content. For a client outside a browser (an indexer, a super-peer reading another relay, a
  script), it is a request to any address the relay names, loopback and private ranges included.
- **Downgrade `https` to `http`** for a client outside a browser. Blocks stay protected (§3.4: the
  recipient checks `block_id` and signature). `/query` hints, `/info` values and the identifiers a user
  reads are exposed to the network path.
- **Mix relay identities.** A `201` from the target is an acknowledgement from a relay the user did not
  pick (ADR 0029 rule 12 keeps an own block until "a relay" acknowledges it). A cursor issued by the
  target is then sent to the first relay, or the reverse (ADR 0024: a cursor belongs to one relay and one
  index epoch).
- **Spend client time and requests** through redirect chains, bounded only by the client's deadline
  (ADR 0029 rule 7) and its HTTP stack.

What a redirect would give a deployment: a relay that moves can point clients to its new URL. This is
rare. A configuration change on the client, or a reverse proxy at the old URL that forwards to the new
relay, gives the same result without a protocol rule.

Common proxy defaults matter. Caddy answers plain HTTP on port 80 with a `308` to `https` for every site
with automatic HTTPS. nginx answers `301` when a request for a directory path lacks its trailing slash
in some `location` configurations. Neither is on the `https` relay URL with an exact `/sbtp/v1/` path,
which is what a conforming client requests.

## Decision

### Scope

1. **Relay URL.** A relay is reached at the URL its operator publishes: a scheme, a host, an optional
   port and an optional path prefix. The routes of spec §4 are under it. A public relay URL uses
   `https` (spec §4).
2. **Covered responses.** The rules below cover every response to a request whose path, under the relay
   URL, starts with `/sbtp/v1/`. This includes a CORS preflight and a response produced by a reverse
   proxy, a gateway or a static mirror that serves the relay URL. A `3xx` status is any status from 300
   to 399.

### Relay side

3. **No redirect.** A relay, and a proxy or mirror serving its relay URL, MUST NOT answer a covered
   request with a `3xx` status.
4. **`304`.** The one exception is `304 Not Modified` in answer to a conditional request
   (`If-None-Match`, `If-Modified-Since`) that the client sent. The relay interface defines no
   validator, so `sbtp-relay` never sends it; a cache or mirror in front of a relay MAY.
5. **Other origins.** A request to another origin than the relay URL is outside this interface. A proxy
   MAY redirect plain-HTTP requests on port 80 to `https` (for example Caddy's default). A client that
   was given the `http` URL still does not follow it (rule 6).

### Client side

6. **No follow.** A client MUST NOT follow a redirect on a covered request. A `3xx` response, other than
   a `304` to a conditional request the client sent, is a failed request (ADR 0029 rule 15): nothing from
   it is used, its `Location` included.
7. **Body.** A client does not parse the body of a `3xx`. If it reads the body, it reads at most 16,384
   bytes plus one (the ceiling of an error body, ADR 0029 rule 4); above that it closes the connection.
   The request deadline (ADR 0029 rule 7) covers the `3xx` response like any other.
8. **No automatic repeat.** A redirect shows a configuration error, not a transient one. A client SHOULD
   NOT repeat the request to that relay URL automatically. It SHOULD end the operation on that relay and
   tell the user that the relay URL answered with a redirect. It MAY show the status code and, when its
   HTTP stack exposes it, the `Location` value, as untrusted text, and never as a link it opens.
9. **Browser clients.** Every `fetch()` to a relay MUST set `redirect: "manual"` or `redirect: "error"`.
   `"follow"`, the default, does not conform. With `"manual"`, a response whose `type` is
   `"opaqueredirect"` is the `3xx` of rule 6. A browser client SHOULD use `"manual"`, so that it can tell
   a redirect from a network failure for rule 8. The same holds for any other request API of the
   platform (`XMLHttpRequest` cannot refuse redirects and MUST NOT be used for the relay interface).
10. **Other clients.** A client built on an HTTP library MUST turn its redirect following off (for
    example `max_redirects(0)` in `ureq`, `redirect::Policy::none()` in `reqwest`). Library defaults
    follow redirects.
11. **Per-relay fault count.** A `3xx` counts as a failed request for the per-relay count of ADR 0029
    rule 16.

### Relay relocation (non-normative)

12. An operator that moves a relay announces the new relay URL out of band (where the old one was
    published). During a transition, the old URL MAY be served by a reverse proxy that forwards requests
    to the new relay; a proxy is transparent to clients. Cursors issued by the new relay are valid at
    both URLs only if the proxy reaches the same relay. A client that changes relay URL restarts its
    walks without a cursor and deduplicates by `block_id` (ADR 0024 rule 8).

### Amended rule

13. **ADR 0029 rule 15**, first sentence, becomes: "A response that fails rule 6, 8 or 13, a `3xx`
    response other than a `304` to a conditional request the client sent (ADR 0030), or a request that
    exceeds its deadline (rule 7), is treated like a network failure: nothing from it is used." The rest
    of rule 15 is unchanged; ADR 0030 rule 8 adds that a client SHOULD NOT repeat a request after a
    `3xx`.

## Consequences

- **Interoperability.** One shared fact: no `3xx` on `/sbtp/v1/`. A relay and a client agree without
  discovery. A misconfigured proxy is detected at the first request, with a clear message, instead of
  sending clients elsewhere.
- **`sbtp-relay` at `c041eba` conforms.** It emits no `3xx` (no redirect route, axum does not add
  trailing-slash redirects), sends no `ETag` or `Last-Modified`, and ADR 0028 rule 3 already holds.
  Test to add: a request with a trailing slash (`/sbtp/v1/info/`) and with a doubled slash gets a `4xx`,
  never a `3xx`.
- **`cli-demo` at `c041eba` conforms.** `max_redirects(0)`, every `3xx` reported as a refusal (exit 3)
  and not repeated, test `redirects_are_not_followed`. It does not print the `Location`; rule 8 makes
  that optional.
- **Web client.** It wraps `fetch()` once, sets `redirect: "manual"` there, maps `opaqueredirect` to a
  "relay URL redirects" error, and never retries it. Tests: a mock relay that answers `301`, `307` and
  `308` to `GET /info`, `GET /query` and `PUT /block` (no second request reaches the target); a `303` to
  `PUT` (no `GET` is sent).
- **Deployment.** Proxy examples in `deploy/` SHOULD route `/sbtp/v1/` without any `redir`, `rewrite`
  that answers `3xx`, or trailing-slash redirect. Caddy's port 80 to `https` redirect stays: it is on
  another origin (rule 5). An operator publishes the `https` URL.
- **Security.** A relay or proxy can no longer send a conforming client to another server, downgrade it
  to plain HTTP, or make it mix cursors and acknowledgements of two relays. For clients outside a
  browser, this removes a request-forgery path to loopback and private addresses through a relay
  response. A hostile relay can still refuse service; that is availability, as before.
- **Cost.** A relay that moves loses clients that are not reconfigured. This is accepted for the MVP.
- **Compatibility.** No wire format change, no frozen vector affected. These are crate tests.

## Rejected alternatives

- **A client MAY follow a bounded number of same-origin redirects that never downgrade `https`.** A
  browser cannot check the target before the request reaches it (`"manual"` hides the `Location`), so
  the rule cannot be implemented in the main client of Phase 3. It adds a count bound and per-hop rules
  for a gain (a moved path under one origin) that a proxy rewrite gives without any client change.
- **A client MAY follow cross-origin redirects to `https`.** Lets a relay choose the server a client
  talks to and the relay that acknowledges its blocks, and gives clients outside a browser a
  request-forgery path. A hostile relay URL would be enough to redirect an indexer to a private address.
- **Relay MUST NOT redirect, client behaviour left open.** Clients must still handle a misconfigured or
  hostile proxy (ADR 0029 rule 1). Leaving the client open keeps the default of every HTTP stack, which
  is to follow.
- **`redirect: "error"` only, for browsers.** Conforms, but a redirect then looks like a network failure,
  and the client cannot apply rule 8. Both modes are allowed; `"manual"` is recommended.
- **A `moved` member in `/info` or a `410 Gone` with a new URL.** A relocation signal from an
  unauthenticated response raises the same trust question as a redirect, and nothing in the MVP needs
  it. Deferred until a use appears; no question opened.
- **Forbidding `304`.** A cache or mirror may answer a conditional request the client itself sent, and a
  browser's HTTP cache resolves it before script sees it. Forbidding it gains nothing.

## Spec change on acceptance

Applied on acceptance (2026-11-20). In `docs/spec/sbtp-core-v0.2.md` §4:

1. **Introduction of §4**, after "A `block_id` in a path or a query string is exactly 64 lowercase
   hexadecimal characters; …", add:

   "A relay is reached at the relay URL its operator publishes: scheme, host, optional port and optional
   path prefix. The routes of this section are under it."

2. New subsection after "CORS", before "Admission control":

   ```markdown
   ### Redirects

   - A relay, and a proxy or mirror serving its relay URL, MUST NOT answer a request under `/sbtp/v1/`
     with a `3xx` status, a preflight included. The exception is `304 Not Modified` to a conditional
     request the client sent.
   - A client MUST NOT follow a redirect. A `3xx` response, other than such a `304`, is a failed request
     (see "Client bounds"): its `Location` and its body are not used. A client SHOULD NOT repeat the
     request automatically and SHOULD report that the relay URL redirects.
   - A browser client sets `redirect: "manual"` (recommended: an `opaqueredirect` response shows the
     redirect) or `redirect: "error"` on every `fetch()` to a relay. Other clients turn off the
     redirect following of their HTTP library.
   - A redirect on another origin, such as a proxy that sends plain HTTP on port 80 to `https`, is
     outside this interface. A client still does not follow it.
   - A relay that moves announces its new URL out of band; a reverse proxy at the old URL MAY forward to
     it. (ADR 0028, ADR 0030)
   ```

3. **Client bounds**, the bullet "A failed request is treated like a network failure: …" becomes:

   "- A failed request is treated like a network failure: nothing from it is used. The client backs off
     before repeating it, or ends the operation. A `3xx` response is a failed request that is not
     repeated (see "Redirects"). (ADR 0029, ADR 0030)"

No change to §1 to §3 or §5. `architecture.md`: no change (its proxy section describes TLS termination,
not redirects). ADR index on acceptance: ADR 0029 becomes "accepted, amended by 0030", with the line
"Amended by: 0030 (rule 15, a `3xx` is a failed request)" under its status.
