# 0053: Client SDK: boundary, conformance and packaging

- Status: accepted (by the project owner, 2026-11-21), with the owner choices recorded in "Decisions of
  the project owner": npm scope `@sbtp`, packages `@sbtp/wasm` and `@sbtp/client`, repository
  `sbtp-client-js`, deferred crate `sbtp-client`; the TypeScript SDK first, `@sbtp/wasm` published first
  on npm, crates.io only when a Rust consumer outside the workspace exists; the first-party exception of
  rules 36 to 45, with a required cooling delay of 48 hours (rule 45)
- Amended: 2026-11-21, accepted by the project owner on 2026-11-21 (Q-83): rule 12 (the SDK keeps
  the availability of ADR 0047 amendment D1) and rule 14, second bullet (a `451` to a presence check
  of an acknowledged block changes its availability, not its delivery state)
- Date: 2026-11-21
- Questions: none resolved; opens Q-78 and Q-79. Refers to Q-23 (subscriptions, `follow`), Q-26
  (peer-to-peer serving) and Q-77 (snapshot format)
- Impact: no wire format change, no relay API change, no change to a frozen vector set. Core spec §4
  gains one non-normative subsection, `architecture.md` §3 one paragraph; `docs/test-vectors/README.md`
  gains a planned set `client-v1/`.
  `sbtp-wasm` gets an npm package and CI gains a release workflow (first); a separate public
  repository holds the TypeScript SDK (next). Later, with no milestone yet: crate `sbtp-client`, onto
  which `sbtp-relay` (replication client) and `examples/cli-demo` move.

## Context

Every layer 2 application that talks to relays reimplements the same client plumbing; this repository
holds two copies in Rust (the replication
client of `sbtp-relay` and the client of `cli-demo`) and one in JavaScript (`web/`). The plumbing is:

- bounded `/query` walks with cursors, and a restart on `InvalidCursor` (core spec §4, ADR 0024);
- batch fetch by `POST /sbtp/v1/blocks`, with a fallback to `GET /sbtp/v1/block/{block_id}` when `/info`
  `read_api` is below 2 (ADR 0051 rule 31);
- completeness bookkeeping: a listing is complete as of relay R at cursor C; over several relays it is
  complete only when every relay of the list was asked (ADR 0051 rules 28 and 29, clarification B8);
- `/info` parsing and the relay classes it implies: read-only (ADR 0050), age-bounded
  (`block_ttl_ms`), demand-evicting (ADR 0046), archive (ADR 0048 rule 1);
- `Retry-After` and back-off on `429`, `503` and `507`, and the handling of `408`, `502` and `504`;
- response body ceilings and response shape checks (ADR 0029);
- presence checks and re-submission of the same bytes (ADR 0043 rule 5, ADR 0045 rule 6), and the
  delivery state of own blocks per relay (ADR 0047);
- keeping long-lived blocks available on relays that evict by demand (ADR 0046 rules 20 and 21).

Every one of these rules is already normative. What is missing is one shared implementation per
language, and a way to show that independent implementations behave the same.

Constraints:

- The supply-chain rules of this repository forbid `git` dependencies and `path` dependencies outside
  a repository. A client library in another repository can therefore depend only on published
  packages. Nothing from this repository is published to a registry yet.
- Layer 0 stays minimal and neutral. A client library MUST NOT bring layer 2 semantics into the
  protocol, and the specification MUST stay the reference.
- The size budget of ADR 0048 (relay binary under 8 MB, core `.wasm` under 200 KB gzip) still holds.

## Decision

### Status of the SDK

1. **Not normative.** The SDK is a conforming implementation of the client rules of the
   specification. It is not part of the specification and adds no protocol rule. Where the SDK and
   the specification differ, the specification is right and the SDK has a bug. An application MAY
   implement the client rules itself; it is then held to the same rules and MAY run the same
   conformance cases (rule 22).
2. **Two implementations, TypeScript first.**
   - **TypeScript (first):** a package in a separate public repository of the project organisation
     (repository `sbtp-client-js`, package `@sbtp/client`). It uses the npm package of `sbtp-wasm`
     (`@sbtp/wasm`) for every layer 0 operation. Its only prerequisite in this
     repository is the publication of `@sbtp/wasm`.
   - **Rust (deferred):** a crate `sbtp-client` in this workspace. This ADR records its intended
     design; it is not a prerequisite of the TypeScript SDK and has no milestone yet.
   The two are kept in line by the shared conformance cases of rules 18 to 25, not by sharing code.
3. **No protocol logic in the SDK that `sbtp-core` already holds.** Decoding, `block_id`, proof of
   work, signature verification and the receipt rule (§3.4, R1 included) run in `sbtp-core`, natively
   or through `sbtp-wasm`. The TypeScript SDK MUST NOT reimplement them in JavaScript and MUST NOT use
   a JavaScript Ed25519 library or Web Crypto `verify` to verify a block (they do not apply the strict
   criteria V1 to V6 of §3.2).

### Boundary: rules the SDK MUST implement

4. **Transport rules.** For every request to a relay URL:
   - no redirect is followed; a `3xx` other than `304` to a conditional request is a failed request
     that is not repeated (core §4 "Redirects", ADR 0030); a browser build sets `redirect: "manual"`;
   - no cookies and no HTTP authentication are sent (`credentials: "omit"` in a browser build), since a
     relay MUST NOT use them (core §4 "CORS");
   - each request has a total time limit covering the whole body;
   - each body is read up to its ceiling plus one byte, after removal of any content coding: 65,909
     (`GET /block`), 1,048,576 (`POST /blocks`), 131,072 (`/query`), 16,384 (`/info`, any `4xx` or
     `5xx`); a `2xx` body above its ceiling is a failed request (core §4 "Client bounds", ADR 0029);
   - the status code decides; an error body is optional, MAY be unparseable, and unknown members are
     ignored (core §4 "Errors").
5. **`/info`.** The SDK reads `/info` once per relay and per session, and again after a failure that
   may follow a settings change. It checks `min_pow_difficulty` and `max_future_ms` and treats a
   response that fails the check as a failed request. It reads an absent `demand_eviction` and an
   absent `read_only` as `false`, an absent `read_api` as `1`, an absent `relays` as an empty list, and
   ignores unknown members. It exposes the relay class derived from these members (archive, keeping,
   age-bounded, read-only) as data, without a new protocol field (ADR 0048 rule 1).
6. **Capability gating.** The SDK MUST NOT send `PUT` or `/query` to a `read_only` URL, and MUST NOT
   send `POST /blocks`, `order`, `fields`, a repeated `parent` or a per-parent cursor to a relay whose
   `read_api` is below 2 (ADR 0050, ADR 0051 rule 31). It falls back to single `GET /block` requests
   and single-parent `/query` requests.
7. **Walks.** One cursor per relay and per listing; a cursor is never sent to another relay. On
   `400` `InvalidCursor` the walk starts again without a cursor and deduplicates by `block_id`; on
   `500`, `502`, `503`, `504` and `429` the walk keeps its cursor and repeats after the delay of rule 9.
   A `/query` response that fails the shape checks of core §4 "Client bounds" is a failed request and
   none of its identifiers is used. The number of pages and identifiers per walk is bounded by a
   setting.
8. **Fetches.** Every block received, by `GET /block` or as a batch record, goes through the receipt
   rule (§3.4) with the requested `block_id` and the client's own difficulty floor (ADR 0026), never
   the serving relay's `min_pow_difficulty`. Batches hold 1 to 256 distinct identifiers; a body that
   ends after a complete record is a prefix, and the rest is requested again; a record `length` above
   65,909 makes the response a failed request; a body that ends inside a record keeps only the complete
   records before it (ADR 0051, clarifications B3 and B5). A `length = 0` record and a `404` mean
   "not served by this relay", never "does not exist".
9. **Admission.** At most 8 requests in flight per relay. No request to a relay before its
   `Retry-After` has elapsed. Without the header, or with one that is not a number of seconds,
   exponential back-off with jitter starting at 1 second. After `408` or a closed connection, at most
   one immediate retry, then back-off. `502` and `504` are handled as `503`. A `Retry-After` above the
   client's maximum wait MAY end the operation on that relay; it does not shorten the wait. Back-off
   state is per relay (core §4 "Admission control", "Several relays").
10. **Completeness.** The SDK reports, per listing and per relay, one of: complete at cursor C
    (`more = false`), incomplete, not asked. A relay skipped because it lacks `read_api` ≥ 2 for the
    requested form is "not asked". A listing over a relay set is complete only when every relay of the
    set is "complete". When it merges `fields=parents` hints from several relays, the SDK takes the
    union of the parents listed for each `block_id`. The SDK MUST NOT return a listing that ended with
    `more = true` as complete (ADR 0051 rules 28 and 29, clarification B8).
11. **Publication.** A sender mines at `max(D_NET, min_pow_difficulty of each target)`, each value read
    within a maximum difficulty that is an SDK setting; above it, it does not mine for that relay
    (ADR 0045 rule 5, ADR 0029). It sends only Version values in the target's `block_versions`. `200`
    and `201` are the same success.
12. **Delivery state of own blocks.** For a block the user created, the SDK keeps a per-relay state
    `pending`, `acknowledged`, `refused` or `given-up` under the rules of ADR 0047 (final refusals,
    attempt and time bounds, relays added to or removed from the list), with the per-relay
    availability `available` or `refused` of ADR 0047 amendment D1, and exposes whether the block is
    protected. Persisting it is the application's: the SDK takes a storage interface and holds no
    storage of its own.
13. **Re-submission.** A re-submission sends the same bytes. The SDK MUST NOT re-mine, re-sign or alter
    a block (ADR 0043 rule 5, ADR 0045 rule 6). It re-submits a block it keeps available on a relay
    when a single `GET` of that block gets `404` from that relay (never after a `451`, rule 14), and, on a relay with `block_ttl_ms`, no
    earlier than its last `201` from that relay plus `block_ttl_ms`. It skips a target whose difficulty
    the block's `block_id` does not meet, and does not retry it until that relay's `/info` shows a lower
    value (ADR 0045 rule 6).
14. **Denied blocks.** The SDK has an outcome `denied`, distinct from `404` and from `length = 0`: a
    `451` from a relay, on any route (ADR 0052; core §4 "Denied blocks"). On `denied`:
    - the block is not served by that relay; the SDK MAY ask another relay;
    - for a block the user created, the state of that relay becomes `refused`, a final refusal
      (ADR 0047 rule 3), on a `PUT` and on a presence check while that relay is `pending`. On a
      presence check of a block that relay had acknowledged, the delivery state stays `acknowledged`
      and the availability on that relay becomes `refused`: the relay no longer counts as holding the
      block for protection, and the bound from the first acknowledgement does not restart (ADR 0047
      amendment D1, accepted 2026-11-21);
    - the SDK never sends that block to that relay again automatically; only an explicit call of the
      application, on a user action, does. After `DeniedKey` it sends no block signed by that key to
      that relay automatically;
    - the SDK never creates a new block because of a `451` (re-signing, re-mining, altering);
    - a `length = 0` record is never by itself a reason to re-submit: the SDK confirms with a single
      `GET` first (ADR 0052 rule 13).

    The denied `block_id` values and keys are kept per relay through the storage interface of rule 12.
    A denial by one relay says nothing about another.
15. **Relay lists and privacy.** The SDK parses relay lists in the format of ADR 0048 rule 20 (at most
    16 relay URLs, `https` only, no userinfo, query or fragment, no duplicates after normalisation). A
    relay learned from `/info` `relays`, `/.well-known/sbtp` or a URI hint is a candidate: the SDK uses
    it for public reads only when the application enables that, and never for the user's own traffic
    (publication, polling of private delivery tags) unless the user or the application's
    configuration chose it (ADR 0048 rule 22).
16. **Replication marker.** The SDK sends `Sbtp-Replication: 1` only when the caller declares itself a
    relay copying blocks from a peer (ADR 0048 rule 18). An end-user client MUST NOT send it: its reads
    are demand.

### Boundary: helpers

17. The SDK MAY provide the following. Each is optional for a conforming client; when the SDK provides
    one, the bounds the specification requires still apply.
    - **Relay set:** one object over a relay list, holding each relay's `/info`, health and back-off,
      with read failover and publication to every target.
    - **DAG traversal** from a set of roots, with a visited set (each `block_id` at most once) and a
      bound on visited blocks (core §4 "Client bounds"). A missing parent is pending, not an error
      (ADR 0043 rule 6).
    - **View versus bulk fetch:** single `GET /block` for the blocks of a view (the cacheable form) and
      batches for walks and bulk fetches (core §4 `POST /sbtp/v1/blocks`).
    - **Keep available:** for a set of blocks the application names, a bounded schedule of presence
      checks (`GET /block`) per relay, with the re-submission of rule 13 on a `404`. A presence check is
      a read and counts as demand on a demand-evicting relay; the schedule is an application setting,
      off by default. The SDK MUST NOT issue reads whose only purpose is to keep blocks warm for blocks
      the application did not name. Long-lived availability rests on archive relays and re-submission,
      not on demand (ADR 0046 rule 20).
    - **Local store budget:** an eviction planner that follows the order of core §4 "Client bounds"
      (fetched blocks first, then own unprotected blocks, never the user's keys or protected own
      blocks). Keys are never handled by the SDK.
    - **First catch-up:** the order of core §4 "Fast first catch-up". Snapshot import waits for a common
      snapshot format (Q-77).
    - **Discovery:** `/.well-known/sbtp` and `sbtp:` URI hints (ADR 0040).
    - **Signing:** the SDK takes a signer (a function from the 49-byte signing message to a 64-byte
      signature) and never holds a private key. A test-only key from a public seed MAY be offered,
      marked as such.

### Boundary: out of scope

- Layer 2 kinds and application semantics: none, in either SDK.
- The generic layer 2 grammar (`sbtp-l2`) and the sealed envelope (`sbtp-seal`): not in the SDK. If
  `sbtp-wasm` later exposes them, the TypeScript SDK MAY re-export that API unchanged; it MUST NOT
  reimplement it (Q-78).
- Key generation, key storage and identity backup.
- The graph gateway client (ADR 0041) and the MCP server (ADR 0042): MAY become separate modules later.
- WebSocket or other subscriptions until Q-23 is decided; peer-to-peer serving (Q-26).

### API shape

The operations below are the public surface of both SDKs, with the same names and the same outcomes.
Exact signatures are each SDK's.

- **`RelaySet`**: built from a relay list and settings (bounds, maximum difficulty, maximum
  `Retry-After` wait, the client's difficulty floor on receipt). Exposes each relay's `/info` and class.
- **`walk(filter)`**: `parent` (one or several), `since`, `order`, `fields`, a starting cursor or
  `head`, per relay. Yields pages of identifiers, deduplicated across relays, with per-relay cursors and
  `head`, and ends with the completeness report of rule 10. Resumable from the returned cursors.
- **`fetchMany(ids, hints?)`**: validated blocks, the identifiers no relay served, and, per identifier,
  which relays answered `404`, `length = 0` or (rule 14) `denied`. Uses batches where rule 6 allows,
  single `GET`s otherwise or on request.
- **`publish(block, targets?)`**: `PUT` to each target under rules 9 and 11, returns the per-relay
  delivery state of rule 12. **`ensurePresent(block, relays)`**: presence check, then re-submission
  under rule 13.
- **`follow(parents, from)`**: a stream of new identifiers for a parent set. Until Q-23 is decided it is
  grouped `asc` polling from `head` with the back-off of rule 9 and an interval that is a setting;
  afterwards the same stream MAY be fed by the subscription of ADR 0051 rule 30, resuming by `/query`
  `asc` from the last delivered gap after a disconnect.
- **`Completeness`**: the report of rule 10, as data the application can keep with what it shows.

The Rust crate is sans-I/O: its walk, batch, admission, completeness and delivery logic take responses
and return the next requests and outcomes, and do no I/O. Transports are adapters:
- a blocking adapter on the HTTP client `cli-demo` already uses, behind a Cargo feature;
- `sbtp-relay` keeps its own transport for replication (connection to checked addresses only,
  `Sbtp-Replication: 1`, its TLS settings, ADR 0048 rules 14 and 19) and its held check before fetches.

The TypeScript SDK runs on `fetch` with an injectable `fetch` and clock, so that it runs in browsers,
workers and Node.js, and in tests against a scripted relay.

### Conformance

18. **Two layers.** Conformance is shown by:
    - **scripted cases** (`client-v1/`): data-driven exchanges between a client and a scripted relay,
      with a virtual clock. Each case lists the relay URLs and their `/info`, the client settings, the
      operation, then a sequence of expected requests (method, route, query parameters, body for a
      batch, the `Sbtp-Replication` header) each with the scripted response (status, headers, body),
      and the expected outcome (validated identifiers, completeness per relay, delivery states,
      earliest allowed time of each next request). Bodies of blocks come from `v1/`. No network.
    - **a live suite** run against a real `sbtp-relay` test instance with a fixture store built from
      blocks signed with the public seeds of `v1/`, using the scenarios of `relay-v1/` (ADR 0051, "Test
      vectors") and the end-to-end operations of the API shape above.
19. **What the cases fix and what they leave free.** A case checks a rule, never an SDK setting: it
    states bounds, not timings (no request before `Retry-After`; the first back-off at least 1 second
    and growing; at most 8 in flight). Jitter is taken from a seeded source given in the case or
    checked only against its bounds. Cursor values in scripted responses are opaque fixtures: a case
    checks that a client sends back the cursor it received, to the relay that issued it, and nothing
    else about it.
20. **Coverage.** Each MUST rule of rules 4 to 16 has at least one positive and one negative case, and
    each case names the spec section and ADR rule it checks. Negative cases discriminate: an
    implementation that omits the targeted rule fails the case. The security review checks this before
    the set is frozen, as for the other sets.
21. **Location and versioning.** The cases live in this repository under
    `docs/test-vectors/client-v1/`, next to `v1/` and `relay-v1/`, with a manifest listing each file
    and its SHA-256. The rules of `docs/test-vectors/README.md` apply: once published, a set never
    changes; a change creates `client-v2/`. `client-v1/` includes the `denied` cases of rule 14
    (ADR 0052 rules 12 and 13).
22. **Consumption.**
    - The TypeScript SDK is the first consumer. Until the Rust crate exists, no Rust code runs the
      cases.
    - `sbtp-client`, once it exists, reads the cases from the repository in its tests.
    - The TypeScript repository holds a copy of a published set and its manifest, checks the copy
      against the manifest attached to the tagged release of this repository, and runs it in CI. It
      takes no `git` dependency and no submodule on this repository.
    - The live suite runs against the published relay image of a tagged release, pinned by digest.
23. **Conformance statement.** Each SDK release states the core specification version it implements,
    the `read_api` levels it speaks, the vector and case sets it passes (`v1/`, `relay-v1/`,
    `client-v1/`), the exact version of `sbtp-core` or `@sbtp/wasm` it uses, and the relay release it
    was tested against.
24. **Third-party clients.** The same cases MAY be run by any client implementation. Passing them is
    evidence, not certification; the project runs no certification.
25. **Divergence.** A case that contradicts the specification is a defect of the case. It is corrected
    in a new set, never by changing the specification to match the case without an ADR.

### Packaging and versioning

26. **Packages** (names fixed by the owner on 2026-11-21; availability on each registry is checked
    before the first publication):

    | Package | Registry | Source | Contents |
    |---|---|---|---|
    | `@sbtp/wasm` | npm | this repository, `crates/sbtp-wasm` | wasm-bindgen output for bundlers and Node.js, type declarations, no install script |
    | `@sbtp/client` | npm | separate repository | the TypeScript SDK; depends on `@sbtp/wasm` at an exact version |
    | `sbtp-client` | crates.io, deferred | this repository | the Rust SDK |
    | `sbtp-core` | crates.io, deferred | this repository | layer 0 |

    npm comes first: `@sbtp/wasm` is the first package published. A crate is published on crates.io
    only when a Rust consumer outside this workspace exists.

    `@sbtp/client` re-exports the parts of `@sbtp/wasm` it relies on, so that an application loads one
    WebAssembly module and one version of it.
27. **Semantic versioning per package.** A published crate stops inheriting the workspace version and
    gets its own. Each package follows semantic versioning; while its major version is 0, a breaking
    change raises the minor version. `@sbtp/wasm` carries the version of the `sbtp-wasm` crate it is
    built from. No package goes to 1.0 before the core specification leaves draft status.
28. **Protocol compatibility.**
    - The route prefix `/sbtp/v1/` is part of an SDK major line. A future prefix is a new major
      version.
    - `read_api` is negotiated per relay from `/info` (rule 6). The SDK uses the highest level it
      implements that the relay publishes, and reads a value above it as that level.
    - Block versions: the SDK builds only the Version values `sbtp-core` supports, and publishes a block
      only to a relay that lists its Version in `block_versions`.
    - A new `/info` member or error name never breaks an SDK (rules 4 and 5).
29. **Runtimes.**
    - Node.js: the release lines in active or maintenance long-term support at the time of each SDK
      release; older lines are dropped in a minor release, with a note.
    - Browsers: those that support the WebAssembly features the published `.wasm` uses (read from its
      `target_features` section in CI), JavaScript `BigInt` integration with WebAssembly, `fetch` with
      `redirect: "manual"` and a readable body stream, and `AbortController`. The package states the
      resulting minimum versions of the major engines and the set tested in CI. Signing with a
      non-extractable Web Crypto Ed25519 key needs a more recent browser; that is an application
      concern, since the SDK takes a signer (rule 17).
    - Rust: the workspace `rust-version`.

### Release policy

30. **CI only.** Packages are published only by the CI of the repository that holds their source, from
    a protected tag, in a protected CI environment. Nobody publishes from a workstation.
31. **Provenance.** Every npm package is published with a provenance statement linking it to the source
    repository, commit and workflow. Where a registry supports publishing with short-lived credentials
    issued to the CI workflow (OpenID Connect), no long-lived registry token exists. Where it does not,
    the token is scoped to the package, publish-only, with an expiry, and held only by the protected
    CI environment. crates.io uses the same rule.
32. **Accounts.** Registry scopes and crate ownership belong to the project organisation, not to a
    personal account. Accounts that can publish use two-factor authentication. A two-person rule for
    releases is not required at this stage; it is reconsidered when maintainers are added.
33. **First-party packages and the two-week rule.** The rule "no package published less than two weeks
    ago" has one bounded exception, for the organisation's own npm packages, stated in rules 36 to 45.
34. **Release order.** A tag of this repository publishes `@sbtp/wasm` (and, once rule 26 calls for it,
    the crates published on crates.io), the relay image and the case manifest. The TypeScript repository then raises its exact
    pin, runs the conformance suite of rule 22 against that tag, and only then releases.
35. **Contents check.** CI builds the npm package from a clean checkout, lists its files and fails if
    the package holds anything other than the build output, the type declarations, the licences and the
    README, or declares an install script.

### Supply-chain exception for first-party packages

The two-week rule protects against a package that is new or newly taken over and not yet noticed. It
would make the TypeScript SDK wait two weeks after each `@sbtp/wasm` release, and an application wait
two weeks after each SDK release, for code the project wrote and reviewed. Rules 36 to 45 bound an
exception. A compromised publisher account or CI workflow would give the same access as a classic
supply-chain takeover; the exception therefore rests on provenance, CI-only publication and a reviewed
bump, never on trust in a package name or scope.

36. **Scope.** The exception covers only the packages of the organisation's npm scope: `@sbtp/wasm` and
    `@sbtp/client` (rule 26). A package joins the scope only through an ADR. No other
    package, scope or registry is covered.
37. **Publisher.** A covered package is published only by the organisation's CI, from a protected tag
    on a commit reachable from `main` of the package's own repository (this repository for
    `@sbtp/wasm`, the TypeScript repository for `@sbtp/client`). It is never published from a
    workstation. A version published any other way is not covered, and the two-week rule applies to it.
38. **Provenance.** A Sigstore provenance attestation is REQUIRED for every covered version. It links
    the tarball to the repository, the workflow file and the commit of rule 37. A consumer MUST verify
    it before an update (`npm audit signatures`, or an equivalent check of the registry signature and
    the attestation) and MUST check that the repository, the workflow and the commit are the expected
    ones. A version without an attestation, or whose attestation names anything else, is refused.
39. **Pinning.** A consumer pins an exact version, commits its lockfile, and its install checks the
    integrity hash. No version range and no dist-tag (`latest`, `next`) names a covered package.
40. **Bump.** Moving a pin is one explicit commit in the consumer. Its message states the old and the
    new version, the source commit of each, and the changelog entries between them. It is reviewed like
    a dependency update: the reviewer checks rule 38 and reads the source diff for API and behaviour
    changes. A bump whose new version brings changes to the decoder, the cryptography or the
    dependencies that are not yet audited in this repository waits for that audit.
41. **Publishing hardening.**
    - The organisation's npm account and every account that can change the scope use two-factor
      authentication.
    - Publication uses trusted publishing: short-lived credentials issued to the CI workflow through
      OpenID Connect. No long-lived npm token exists for a covered package. Where trusted publishing is
      not available, the exception does not apply, and the two-week rule holds.
    - The default branch and release tags of the source repository are protected; force-push is off;
      Actions are pinned by commit SHA.
42. **No install scripts.** A covered package declares no install script (`preinstall`, `install`,
    `postinstall`, `prepare`). The contents check of rule 35 enforces it before publication, and the
    consumer's install keeps scripts disabled.
43. **Third-party dependencies.** The exception covers the first-party package itself, never what it
    pulls in. The two-week rule and the other supply-chain rules apply to every third-party dependency
    of a covered package, transitively, in its source repository and in every consumer.
44. **What it does not show.** Provenance proves which repository, workflow and commit built a
    tarball. It does not prove that the workflow was not tampered with, nor that the `.wasm` matches
    the source. A reproducible build of the `.wasm`, with its expected hash published at the release
    (Q-79), closes the second gap when it exists.
45. **Cooling delay.** A consumer MUST NOT bump a pin to a covered version earlier than 48 hours after
    that version was published on the registry, so that a malicious release published through a
    hijacked workflow can be spotted and deprecated or removed before anyone takes it. The delay is
    revisited once the `.wasm` build is reproducible and its hash is checked against a rebuild (Q-79);
    a shorter delay or none MAY then be enough for `@sbtp/wasm`. A version published less than 48 hours
    ago is not refused by the exception; it is only not taken yet.

## Consequences

- **Order of work.**
  1. Publication of `@sbtp/wasm` from the CI of this repository (rules 30 to 45).
  2. The scripted cases `client-v1/` and `relay-v1/`, defined and published in this repository, with
     the live-suite fixture.
  3. The TypeScript SDK in its own repository, passing them.
  4. Later, with no milestone yet: the Rust crate `sbtp-client`.
- **WASM.** `sbtp-wasm` gets a package manifest and a build for the npm package. Its API does not
  change for this ADR.
- **TypeScript.** A new public repository under the same supply-chain rules: pnpm, exact versions,
  committed lockfile with integrity hashes, install scripts disabled, Actions pinned by commit,
  protected default branch, no force-push. Its first milestone extracts the generic plumbing of `web/`;
  layer 2 clients then move to it. `web/` MAY move to the SDK
  later; it stays the demonstrator of this repository.
- **Rust (later).** New crate `crates/sbtp-client` (`std`, no `unsafe`, sans-I/O core). The walk of
  `examples/cli-demo/src/walk.rs` and the request and response checks of `examples/cli-demo/src/relay.rs`
  are its starting point; `crates/sbtp-relay/src/replication/` moves onto its walk and batch logic and
  keeps its transport, held check, budgets and metrics. No new third-party crate: the blocking adapter
  uses the HTTP client `cli-demo` already uses. The relay's size budget (ADR 0048) is checked as usual.
  The merge touches networking and parsing of untrusted responses: a security review is required
  before it lands. Until then, the relay's replication client and `cli-demo` keep their own code.
- **Vectors.** No frozen set changes. New set `client-v1/` (planned). `relay-v1/` (planned by ADR 0051)
  becomes an input of the live suite, which makes its generation a prerequisite.
- **Compatibility.** No relay or client behaviour changes. A client that does not use the SDK is
  unaffected.
- **Security.** The SDK concentrates the client bounds in one place per language: a defect there
  affects every application that uses it, and a fix reaches them all. Publication adds a registry to
  the threat model; rules 30 to 45 bound it. Provenance shows where a package was built, not that the
  source is safe; the `.wasm` is checked against a rebuild only once its build is reproducible (Q-79).
- **Accounts.** Organisation-owned registry accounts and CI-only publication keep personal accounts
  and workstation tokens out of the release path.

## Spec change on acceptance

Applied on acceptance (2026-11-21).

**Core spec §4**, new subsection after "Fast first catch-up (non-normative)":

> ### Client implementations (non-normative)
>
> Nothing in this subsection is a new rule. The project maintains a TypeScript client library (and
> later a Rust one, `sbtp-client`) that implements the client rules of this section: transport rules,
> `/info` and capability gating, walks, batch fetch, admission, completeness, publication, delivery
> state of own blocks and re-submission. Client libraries are conforming implementations, not part of
> this specification; where one differs from this specification, the specification applies. The client
> conformance cases are in `docs/test-vectors/` (`client-v1/`) and MAY be run by any client.
> (ADR 0053)

**`docs/test-vectors/README.md`**, new paragraph after "Relay API vectors":

> Client conformance cases (planned, ADR 0053; not generated, not frozen): `client-v1/` holds scripted
> exchanges between a client and a scripted relay, with a virtual clock: relay `/info`, client
> settings, the operation, the expected requests with their scripted responses, and the expected
> outcome. Block bodies come from `v1/`; cursor values are opaque fixtures. Each case names the rule it
> checks. A manifest lists each file and its SHA-256, for consumers outside this repository. The set
> includes the `denied` cases of ADR 0052. Frozen only after the security review has checked that each
> negative case discriminates its rule.

**`docs/spec/architecture.md` §3**, after the table:

> Clients in every tier reach relays through the same client rules (core spec §4). The project's
> client libraries (a TypeScript package on the npm package of `sbtp-wasm`, and later `sbtp-client` in
> Rust) implement them; they are not normative (ADR 0053).

## Decisions of the project owner (2026-11-21)

1. **Names.** npm scope `@sbtp`; packages `@sbtp/wasm` and `@sbtp/client`; repository `sbtp-client-js`;
   Rust crate `sbtp-client`, deferred (rules 2 and 26).
2. **Order.** The TypeScript SDK first. `@sbtp/wasm` is the first package published, on npm. crates.io
   comes later, only when a Rust consumer outside the workspace exists (rule 26).
3. **Accounts.** Registry scopes and crate ownership belong to the project organisation (rule 32).
4. **Supply-chain exception.** Rules 36 to 45 are accepted. The alternative, a two-week wait after each
   first-party release, is rejected.
5. **Cooling delay.** Required: 48 hours between the publication of a covered version and the first
   consumer bump to it (rule 45). Revisited once Q-79's reproducible build exists.

## Rejected alternatives

- **A normative SDK, or a client profile defined by the SDK.** It would make one implementation the
  reference and hide rules in code. The specification stays the reference; the cases are derived from
  it.
- **The TypeScript SDK in this repository.** It would bring JavaScript tooling and its dependency tree
  into the repository that holds the layer 0 reference, and tie the SDK's release cadence to it. The
  owner chose a separate repository.
- **The SDK inside an application repository.** It would tie neutral plumbing to one application and
  keep other applications from reusing it.
- **`git` dependency or submodule from the SDK repository on this one.** Forbidden by the supply-chain
  rules; a submodule exception exists only for an application (ADR 0038). Published packages with
  provenance replace it.
- **One implementation: a single Rust sans-I/O core shipped to browsers through `sbtp-wasm`, with a
  thin TypeScript I/O layer (deferred, not rejected).** One logic for every language. Not chosen now:
  JSON parsing and the state machines make the `.wasm` heavier, against the core budget of ADR 0048
  (200 KB gzip); every page and response crosses the WebAssembly boundary; the stream and cancellation
  API is awkward; and web developers debug the client logic inside a compiled module instead of in
  TypeScript. The Rust crate it would need does not exist yet either. It stays possible: once
  `sbtp-client` exists, its sans-I/O core could be exposed through `sbtp-wasm` (in a separate module if
  the size requires it) behind the same TypeScript API, and the shared cases would show that nothing
  changed. Reconsidered if the two implementations drift despite the shared cases.
- **`@sbtp/wasm` as a peer dependency of `@sbtp/client`.** Lets an application load two versions or
  two instances of the module. An exact dependency with re-exports avoids it.
- **One Rust client with an async transport only.** `cli-demo` is blocking and the relay has its own
  checked transport; a sans-I/O core serves both without pulling an async runtime into the CLI.
- **The relay keeps its own replication client.** Two Rust copies of the walk and batch rules keep
  drifting; the relay keeps only what is specific to it (rule on checked addresses, held check,
  replication marker).
- **Conformance only against a live relay.** It tests one relay's behaviour, not the client's handling
  of `InvalidCursor`, prefixes, partial records, `Retry-After`, `502` or a relay that misbehaves.
  Scripted cases cover those deterministically; the live suite covers end-to-end behaviour.
- **The cases as an npm data package.** One more package and registry account for data that a
  manifest with checksums already pins. MAY be revisited if third parties ask for it.
- **An exception based on the package name or scope alone.** A taken-over account or workflow
  publishes under the same name; only provenance, CI-only publication and a reviewed bump bound it
  (rules 36 to 45).
- **No exception: wait two weeks for first-party packages too.** Safe, but it delays every fix in the
  SDK chain by two weeks per hop.
- **No cooling delay.** Provenance does not show a tampered workflow; until the `.wasm` build is
  reproducible (Q-79), a 48-hour delay is the only window in which a hijacked release can be noticed
  before a consumer takes it.
- **crates.io now.** It adds a registry, its ownership and its tokens to the threat model before any
  Rust consumer outside the workspace needs it.
- **Publishing from a workstation with a long-lived token.** The token is exposed to the workstation
  and has no expiry; provenance cannot be produced.
- **A two-person release rule now.** With the current maintainers it would block every release. It
  is reconsidered when maintainers are added (rule 32).
