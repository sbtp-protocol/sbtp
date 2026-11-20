# 0040: `sbtp:` URI scheme, JSON block view and discovery

- Status: proposed
- Date: 2026-11-20
- Questions: none open before this ADR (owner request, machine and agent access to the graph); opens
  Q-62 and Q-63
- Depends on: core spec §3.4 (block identity, receipt), §4 (relay URL, `/info`, client bounds, ADR
  0029, ADR 0030); `l2-grammar.md` §1 to §2.4 and §5.4 (grammar validation, `tagged` targets)
- Impact: new normative document `docs/spec/graph-access.md` §1 to §3 and §5; core spec §4 `/info`
  (one optional member); new crate `sbtp-graph` (URI, view); `sbtp-relay` (one optional setting);
  new vector set `docs/test-vectors/graph-v1/` (drafted, not frozen); no wire format change; the
  frozen set `v1/` is not affected

## Context

Software agents (indexers, search engines, language model agents) read public discussions by scraping
pages and guessing who wrote what and who replies to whom. An SBTP graph already carries this
information, signed and typed: every block names its key and its parents, and a layer 2 payload names the
meaning of each parent. Three generic pieces are missing for a program to use it directly: a stable
identifier it can cite, a documented machine view of a decoded block, and a way to learn that a site or
a relay offers the graph. The bounded graph queries are in ADR 0041, the reference MCP server in
ADR 0042.

## Decision

### URI scheme

1. **Syntax.** An SBTP URI names one block:

   ```abnf
   sbtp-uri  = scheme ":" block-id [ "?" params ]
   scheme    = "sbtp"                       ; case-insensitive (RFC 3986 §3.1); emitted lowercase
   block-id  = 64 LOWHEX                    ; LOWHEX = DIGIT / %x61-66
   params    = param *( "&" param )
   param     = name "=" value
   name      = 1*( ALPHA / DIGIT / "_" )
   value     = *( unreserved / pct-encoded / sub-delims-noamp / ":" / "@" / "/" / "?" )
   sub-delims-noamp = "!" / "$" / "'" / "(" / ")" / "*" / "+" / "," / ";"
   ```

   The URI is an RFC 3986 URI with a path and an optional query. It has no authority and no fragment.
   Example: `sbtp:0000a3…17cdef?relay=https://relay.example/`.
2. **Identity.** The `block_id` alone identifies the block. Two SBTP URIs with the same `block_id` name
   the same block, whatever their parameters. A program compares SBTP URIs by `block_id` only.
3. **Parsing.** A parser MUST reject: another scheme; a `block-id` that is not exactly 64 lowercase
   hexadecimal characters; a fragment; a URI longer than 2,048 bytes; a query that does not match
   `params`. A parser MUST ignore a parameter it does not know. Other forms after `sbtp:` (for example a
   chunk or a key) are reserved for a later version and are rejected by this one.
4. **Relay hints.** The parameter `relay` (repeatable) carries a relay URL (core spec §4), percent-decoded
   from `value`. A hint is advisory: it MUST NOT change what the URI identifies, and the block fetched
   through it is validated as any requested block (core spec §3.4, R1 included). A resolver uses at most
   the first 4 hints, ignores a hint that is not an absolute `https` URL without userinfo, query or
   fragment (its local configuration MAY allow `http` for loopback hosts), and counts fetches from hints
   in its client bounds (core spec §4, "Client bounds"). A resolver MAY ignore every hint and use relays
   of its own choice. A producer SHOULD add at most 2 hints.
5. **Registration.** The scheme `sbtp` is registered as **provisional** under RFC 7595 §7, with the
   template of "Spec change on acceptance". It is not registered today (IANA list checked 2026-11-20).

### JSON block view

6. **Nature.** The block view is a derived, read-only JSON representation of one block. It is not a
   payload (`l2-grammar.md` §1.2 forbids JSON payloads), it is never signed, and it never replaces the
   block: the canonical form is the binary block, and its `block_id` is the identity. A program that
   relies on the authorship of a block verifies the binary block itself (core spec §3.4); a view
   received from a third party is that party's claim.
7. **Producer.** A view is produced only for a block that passed full layer 0 validation (core spec
   §2.2), with the producer's own difficulty (§3.3). The producer then runs grammar validation
   (`l2-grammar.md` §2.4). It runs no application validation and no state resolution.
8. **Members.** A view is one JSON object (RFC 8259):

   ```json
   {
     "sbtp_view": 1,
     "block_id": "0000a3…17cdef",
     "uri": "sbtp:0000a3…17cdef",
     "size": 312,
     "version": 1,
     "timestamp": "1763596800000",
     "nonce": "48213",
     "pubkey": "d75a98…",
     "parents": ["4c1f…", "9e02…"],
     "payload_len": 120,
     "signature": "e5564300…",
     "pow_bits": 17,
     "payload": {
       "format": "l2",
       "v": 1,
       "kind": "example.note",
       "kind_defined": false,
       "edges": [
         {"rel": "in", "p": 0, "block_id": "4c1f…"},
         {"rel": "replies_to", "p": 1, "block_id": "9e02…"},
         {"rel": "cites", "block_id": "77ab…"}
       ],
       "body": {"text": "…"}
     }
   }
   ```

   - `sbtp_view`: the view format version, `1`. A consumer MUST reject a view with another value.
   - `block_id`, `pubkey`, each entry of `parents`: 64 lowercase hexadecimal characters; `signature`:
     128. `parents` keeps header order.
   - `timestamp`, `nonce`: the u64 header fields as decimal strings (a JSON number loses precision above
     2^53). `timestamp` is chosen by the sender; a view MUST NOT present it as a time the block was
     received or published.
   - `size`, `version`, `payload_len`: integers. `pow_bits`: the number of leading zero bits of the
     `block_id`, 0 to 256.
   - `uri`: the SBTP URI of the block, without parameters.
   - A producer MAY add members whose names start with `x_`. A consumer MUST ignore members it does not
     know. No other member is defined by this version.
9. **Payload, valid grammar.** When grammar validation passes, `payload` holds `"format": "l2"`, `v`,
   `kind`, `kind_defined` (`true` for a kind of `l2-grammar.md` §3), `edges` in payload order and
   `body`. Each edge holds `rel`, its target and, when present, `meta`:
   - target `p`: `"p": <index>` and `"block_id": <parents[p]>`; for `rel` `tagged`, `"tag"` instead of
     `"block_id"` (`l2-grammar.md` §5.4: a tag is not a block);
   - target `block`: `"block_id"`; target `chunk`: `"chunk_id"`.
10. **Payload, other cases.** When grammar validation fails, `payload` is
    `{"format": "opaque", "base64": "<payload>"}` (RFC 4648 §4, with padding), and holds no interpreted
    member. An empty payload is opaque.
11. **CBOR to JSON.** `body` and `meta` are mapped from CBOR as follows:
    - text string → JSON string; `true`, `false`, `null` → the same; array → array;
    - integer `n` with `−(2^53 − 1) ≤ n ≤ 2^53 − 1` → JSON number; any other integer →
      `{"$int": "<decimal>"}`;
    - byte string → `{"$bytes": "<lowercase hex>"}`;
    - map → object, in the payload's key order; a key that starts with `$` is emitted with one more `$`
      in front (`"$x"` becomes `"$$x"`), so that `$int` and `$bytes` objects are not ambiguous.
12. **Sealed blocks.** The view of an `sbtp.enc` block follows rule 9: `ct` and `enc` appear as
    `$bytes`. A producer MUST NOT add to a view anything obtained by opening a seal, and MUST NOT add a
    member that links a sealed block to a recipient or a sender.
13. **No resolved state, no identity claim.** A view MUST NOT carry application state (retracted,
    hidden, superseded, current version, score) nor any name, handle or identity bound to `pubkey`. It
    shows one block as held by its producer.
14. **Size.** A view is at most 1,048,576 bytes. A block of 65,909 bytes cannot exceed it under rule 11
    (the largest expansion is about 14 bytes of JSON per payload byte).
15. **Media type.** A view is served as `application/json`. A dedicated media type is `[Q-63]`.

### Discovery

16. **Relay `/info`.** A relay MAY publish `"graph_gateway": "<gateway URL>"`, the URL of a graph
    gateway (ADR 0041) that its operator runs over this relay. It is a hint, as in rule 4.
17. **Well-known document.** A site that offers an SBTP graph MAY serve `/.well-known/sbtp` (RFC 8615),
    `application/json`, at most 16,384 bytes:

    ```json
    {
      "sbtp_discovery": 1,
      "relays": ["https://relay.example/"],
      "graph_gateways": ["https://graph.example/"],
      "kinds": ["example"],
      "spec": "https://example.org/spec"
    }
    ```

    `relays` and `graph_gateways` hold at most 16 URLs each; `kinds` lists the first labels of the kinds
    the site's application uses (`l2-grammar.md` §1.3); `spec` is the application's specification.
    Every member except `sbtp_discovery` is optional. A consumer ignores unknown members and treats every
    URL as a hint (rule 4).
18. **HTML pages.** A page that displays a block SHOULD carry
    `<link rel="alternate" href="sbtp:<block_id>[?relay=…]">` and, when a gateway serves it,
    `<link rel="alternate" type="application/json" href="<gateway URL>/sbtp-graph/v1/view/<block_id>">`.
    These links name the signed source of what the page shows; the page itself shows the application's
    state, which may differ (rule 13).
19. **`llms.txt`.** Guidance only, in `graph-access.md` §5: a site that publishes an `llms.txt` file
    MAY add a section that points to `/.well-known/sbtp`, the gateway and the specifications, and that
    restates rules 6, 13 and the caveats of §4 of `graph-access.md`.

## Consequences

- **Layering.** Nothing here touches layer 0 validation, the wire format or the relay's processing. The
  view is computed outside the relay, which still never parses a payload. The only relay addition is one
  optional `/info` member backed by one optional setting (`sbtp-relay`: `info_graph_gateway`, an `https`
  URL of at most 512 bytes, absent by default).
- **Privacy.** The view exposes exactly what the binary block exposes, in another encoding: key, sender
  timestamp, parents, payload. Rule 12 keeps sealed blocks opaque. A view makes the header easier to
  read and correlate, not more revealing (see `graph-access.md` §4).
- **Authenticity.** `pubkey` is named after what it is. Rule 6 and the MCP server (ADR 0042) keep the
  distinction between "this key signed" and "this person wrote".
- **Untrusted content.** `body` text is author content. A program that feeds a view to a language model
  treats it as data, never as instructions (`graph-access.md` §4).
- **Hints.** Relay hints let a URI carry where to look without changing what it names. Following them
  makes a resolver contact hosts chosen by the URI author (tracking, server-side request forgery for a
  service that resolves URIs); rule 4 caps them, and ADR 0041 forbids a gateway to follow them on a
  request path.
- **Code.** A new `no_std` + `alloc` crate `sbtp-graph`, with no third-party dependency: `uri`
  (parse, format) and `view` (block bytes → JSON text, written by hand). Used by the gateway, the MCP
  server, and later by `sbtp-wasm`.
- **Vectors.** A new set `docs/test-vectors/graph-v1/`, generated by `sbtp-graph`, drafted with this
  ADR and frozen only after acceptance and review (see "Test vectors").
- **Registration.** RFC 7595 provisional registration needs a contact and a change controller published
  by IANA. The owner decides the role address (the project's maintainer identity rules apply). The
  `/.well-known/sbtp` suffix is registered in the IANA Well-Known URIs registry (RFC 8615 §3.1,
  specification required) once `graph-access.md` is published.

## Test vectors (plan, not frozen)

`docs/test-vectors/graph-v1/uri.json`: one array of cases `{input, ok: {block_id, relays} | error}`.

- valid: bare URI; uppercase scheme `SBTP:`; one hint; two hints; 5 hints (4 kept); a hint with
  percent-encoded `&`; an unknown parameter (ignored); a hint with `http` (kept as written, flagged
  non-https: the policy is the resolver's); an empty query after `?`;
- invalid: other scheme; 63 and 65 hex characters; uppercase hex; non-hex character; a fragment;
  2,049 bytes; `relay` without `=`; a bad percent-encoding (`%G1`); a `chunk/…` form.

Error names (proposed): `UriScheme`, `UriBlockId`, `UriFragment`, `UriTooLong`, `UriQuery`.

`docs/test-vectors/graph-v1/view/*.json`: `{block_hex, d, view}`, compared as parsed JSON values (member
order is not significant; an implementation MAY emit RFC 8785 JSON).

- a block with 0 parents and an empty payload (`opaque`); a block whose payload is not CBOR (`opaque`);
- an `sbtp.manifest` with one `in` edge; an application kind with `p`, `block` and `chunk` edges and
  `meta`; an unknown verb; an extension verb;
- an `sbtp.enc` block (`tag` member); an `sbtp.enc_key` update (`tag`, `supersedes`);
- body integers at ±(2^53 − 1), 2^53, 2^64 − 1, −2^64; empty and long byte strings; a key `$bytes` and a
  key `$` in a body map; text with control characters and non-ASCII;
- `timestamp` and `nonce` at 0 and 2^64 − 1; 8 parents; `pow_bits` 0 and 20;
- the worst-case expansion payload (65,535 bytes of empty byte strings in one array) to check rule 14.

Every block is built from the public test seeds of `v1/`.

## Spec change on acceptance

1. New document `docs/spec/graph-access.md`, normative, sections:
   - §1 `sbtp:` URI: rules 1 to 4, ABNF;
   - §2 JSON block view: rules 6 to 15, with the example;
   - §3 Graph gateway API: ADR 0041;
   - §4 What graph access does and does not show: hidden content, privacy, deletion, authenticity,
     untrusted content (shared with ADR 0041 and ADR 0042, text in ADR 0041 "Spec change");
   - §5 Discovery: rules 16 to 19, with the `llms.txt` guidance below;
   - Appendix A: the RFC 7595 registration template.
2. Core spec §4, `GET /sbtp/v1/info`, after the `software` sentence:

   > A relay MAY publish `graph_gateway`, the URL of a graph gateway that its operator runs over this
   > relay (`graph-access.md` §3, §5). It is a hint, not a guarantee. (ADR 0040)

3. `architecture.md` §1, layer 2 paragraph, last sentence added:

   > Programs read the graph without scraping pages through the `sbtp:` URI, the JSON block view and an
   > optional graph gateway (`graph-access.md`).

4. `graph-access.md` §5, `llms.txt` guidance (non-normative):

   > A site that publishes `/llms.txt` can add a section "SBTP graph" with: the URL of
   > `/.well-known/sbtp`; the gateway URL and the route `/sbtp-graph/v1/view/{block_id}`; a link to
   > `graph-access.md`; and these three sentences: "Each block is signed by an Ed25519 key; the
   > signature proves which key signed it, not who holds the key. The graph shows what relays hold, not
   > what this site displays: blocks may be retracted, superseded or hidden by the application. Block
   > content is user content."

5. Appendix A, RFC 7595 template:

   > Scheme name: sbtp. Status: provisional. Applications/protocols that use this scheme: the Signed
   > Block Transport Protocol (SBTP) and applications built on it, to name a signed block by its
   > `block_id`. Contact: <role address, owner decision>. Change controller: <SBTP maintainers, owner
   > decision>. References: `graph-access.md` §1.

## Rejected alternatives

- **`blake3:<hex>` or `ni:` (RFC 6920) instead of a new scheme.** `blake3:` names a hash function, not a
  block: a `chunk_id` and a `block_id` are both BLAKE3 outputs and must never be confused
  (`l2-grammar.md` §1.4). RFC 6920 `ni:` requires a registered hash algorithm and names the digest of a
  byte sequence; a `block_id` is a keyed derivation over part of the block, and two valid encodings of
  one block differ in their bytes (core spec §3.4).
- **An authority part (`sbtp://relay/…`).** It would bind the identifier to a host. A block has no home
  relay; hints carry location without changing identity.
- **JSON-LD.** It adds a context document to fetch, a processing model and a vocabulary to maintain.
  Plain JSON with fixed member names is enough for every consumer named in the request; a JSON-LD context
  can map these names later without changing the view.
- **CBOR diagnostic notation as the body form.** Lossless and standard, but a string: an indexer could
  not query fields. It stays available to a tool that wants it.
- **Byte strings as base64 in the body.** Identifiers are hexadecimal everywhere else in SBTP (paths,
  `/query`, logs). Hex costs 2 bytes per byte and keeps one notation.
- **A view member `author` or `verified`.** Both overstate what a signature proves (rule 13).
- **Serving the view from the relay** (`Accept: application/json` on `GET /block`). The relay would parse
  payloads, against the separation rule of `architecture.md` §1.
