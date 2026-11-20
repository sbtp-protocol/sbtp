# 0041: Graph gateway: an optional read API over the relay interface

- Status: accepted (2026-11-20, owner)
- Date: 2026-11-20
- Questions: touches Q-11 (synchronisation, not decided here) and Q-23 (push delivery, not decided
  here); opens Q-64 and Q-65
- Clarification: 2026-11-20 (owner): the gateway is `GET`-only, so a preflight gets
  `Access-Control-Allow-Methods: GET`, not the relay's `GET, PUT` (rule 9; `graph-access.md` §3.2)
- Depends on: ADR 0040 (URI, view); core spec §3.4 (receipt), §4 (`/query`, errors, CORS, redirects,
  admission control, client bounds; ADRs 0012, 0018, 0029, 0030); `l2-grammar.md` §2.4, §5.4, §5.9
- Impact: `docs/spec/graph-access.md` §3 and §4; new binary crate `sbtp-gateway`; `sbtp-graph`
  (API types); no change to the relay interface beyond the `/info` member of ADR 0040; no wire format
  change

## Context

An agent that reads a thread needs a block together with the blocks it points to, the children of a
block by edge verb (replies, citations, votes), a bounded neighbourhood, and an incremental feed. The
relay interface offers `GET /block`, `/query?parent=` and `/query?since=`. Each answer costs one request
per block, and children by verb need every child fetched and decoded.

The relay cannot offer more without breaking its design. Children by verb require reading payloads; the
relay never parses a payload (`architecture.md` §1). A subgraph query joins the index many times per
request and amplifies one request into hundreds of block reads, against the `O(log n + limit)` bound of
`/query` and the admission model of ADR 0018.

## Decision

### Placement

1. **The relay stays as it is.** No subgraph, verb index, view or feed route is added to `/sbtp/v1/`.
   The only relay addition is the optional `/info` member `graph_gateway` (ADR 0040 rule 16).
2. **Graph gateway.** A graph gateway is an optional, separate service. It ingests blocks through the
   public relay interface only (core spec §4) and answers the read API below from its own store. It is a
   layer 2 indexer: it MAY parse payloads. A program MUST NOT require a gateway to read the graph; every
   gateway answer can be rebuilt from relays.
3. **No upstream request on the request path.** A gateway MUST NOT contact a relay or any other host
   while it serves a request. It answers from what it holds. This keeps the cost of a request bounded
   by local work, and makes relay hints in a request unusable for server-side request forgery.
4. **Ingestion.** A gateway is a client of each relay it reads (its sources, a local setting):
   - it walks `/query` with a cursor (core spec §4), fetches each new block, and validates it as a
     requested block (§3.4, R1 included) with its own difficulty;
   - it MAY fetch the parents and `block` targets of an ingested block from its sources, within its
     client bounds;
   - it obeys the client rules of core spec §4 (`Retry-After`, backoff, at most 8 requests in flight per
     relay, client bounds, no redirects);
   - it runs grammar validation (`l2-grammar.md` §2.4) and indexes edges only from a payload that passes
     it. A block whose payload is opaque is indexed by its header parents only.
5. **Retention.** A gateway keeps blocks under its own retention setting (`retention_ms`, or `null` for
   none). Like relay eviction, retention and removal by the operator are local and are not deletion
   (§4 below).
6. **Sealed blocks.** By default a gateway SHOULD NOT index `tagged` edges and SHOULD NOT list
   `sbtp.enc` blocks in `/feed` or `/subgraph`. Clients read tags from relays (`l2-grammar.md` §5.4).
   This removes no information from the public graph; it avoids offering traffic analysis of sealed
   traffic as a query. An operator MAY change the default; `/info` says which applies.

### Common rules of the API

7. **Base.** Routes are under `<gateway URL>/sbtp-graph/v1/`. The gateway URL follows the relay URL
   rule (core spec §4: scheme, host, optional port, optional path prefix). A gateway MAY share its host
   with a relay. A public gateway MUST be reachable over HTTPS.
8. **Methods.** `GET` only, and `OPTIONS` for CORS preflight. Any other method gets `405`
   (`MethodNotAllowed`).
9. **Shared relay rules.** The error body, error names, CORS, the ban on redirects and admission control
   of core spec §4 apply unchanged (`400` `InvalidParameter` and `InvalidCursor`, `404` `NotFound`,
   `408`, `429`, `500`, `503`, `Retry-After`). A `block_id` in a path or a parameter is 64 lowercase
   hexadecimal characters. A parameter that is unknown, repeated or malformed gets `400`
   (`InvalidParameter`). A numeric parameter above its maximum is lowered to it.
10. **Cursors.** Same syntax and semantics as `/query` cursors (core spec §4): opaque, 1 to 128
    characters of `A-Z a-z 0-9 - _`, valid only on the gateway that issued them, refused with
    `InvalidCursor` after a rebuild of its index. A client then walks again and deduplicates by
    `block_id`.
11. **Order.** Lists are in the gateway's ingestion order. It differs between gateways and between a
    gateway and a relay. A client MUST NOT derive application state from it.
12. **Cost.** Each route is served with work bounded by its parameters and the gateway's settings, given
    per route below. A gateway charges a request in its per-client allowance by the number of blocks it
    reads to build the response, not by request count.
13. **Body ceilings.** Per route, below. A gateway MUST NOT exceed them; a client applies the rules of
    core spec §4 "Client bounds" to them.

### Routes

14. **`GET /sbtp-graph/v1/info`.** `200`, `application/json`, at most 16,384 bytes:

    ```json
    {
      "sbtp_graph": 1,
      "view_versions": [1],
      "sources": ["https://relay.example/"],
      "min_pow_difficulty": 0,
      "retention_ms": null,
      "sealed_indexed": false,
      "max_limit": 1000,
      "max_depth": 4,
      "max_nodes": 256,
      "max_children_per_node": 32,
      "feed_filters": ["kind", "pubkey"]
    }
    ```

    `min_pow_difficulty` is the difficulty the gateway applies on ingestion. `feed_filters` lists the
    `/feed` filters it supports, a subset of `kind` and `pubkey`. A client ignores unknown members.

15. **`GET /sbtp-graph/v1/block/{block_id}`.** The binary block, with the rules of the relay's
    `GET /sbtp/v1/block/{block_id}` (core spec §4): `application/octet-stream`, at most 65,909 bytes,
    `404` when not held, only fully validated bytes, `Cache-Control: public, max-age=31536000,
    immutable`. The recipient validates it (§3.4). Cost: one block read.

16. **`GET /sbtp-graph/v1/view/{block_id}`.** The JSON view of the block (ADR 0040), at most 1,048,576
    bytes; `404` when not held. `Cache-Control: public, max-age=86400`. The view MAY carry
    `"x_canonical": "<gateway URL>/sbtp-graph/v1/block/<block_id>"`. Cost: one block read.

17. **`GET /sbtp-graph/v1/children/{target}?rel={verb}&limit={n}&cursor={cursor}`.** The blocks that
    name `{target}` (a `block_id`, or a tag when `sealed_indexed` is `true`), by a header parent or by a
    non-causal `block` edge.
    - `rel` (optional): only edges with this exact `rel` value (registry, extension or unknown verb, 1 to
      64 bytes, percent-encoded). Without `rel`, every child is listed, opaque payloads included.
    - `limit`: 1 to `max_limit`, default 100. `cursor`: as in rule 10.
    - Response: `200`, `application/json`, `Cache-Control: no-store`, at most 262,144 bytes:

      ```json
      {
        "children": [
          {"block_id": "9e02…", "rel": "replies_to", "p": 1, "kind": "example.note",
           "pubkey": "d75a98…", "timestamp": "1763596800000"},
          {"block_id": "77ab…", "rel": "cites", "kind": "example.note",
           "pubkey": "3b6a27…", "timestamp": "1763596900000"},
          {"block_id": "51e0…", "rel": null, "p": 0, "kind": null,
           "pubkey": "0f1e2d…", "timestamp": "1763597000000"}
        ],
        "cursor": "k3_Zr0AAAAEAAAAq",
        "more": false
      }
      ```

      One entry per (child, edge): a child that names the target twice (a parent and a `block` edge
      cannot both, `l2-grammar.md` §2.1) appears once per edge. `p` is present for a causal edge only.
      `rel` and `kind` are `null` when the child's payload is opaque. An unknown target gets `200` and
      an empty list.
    - Cost: `O(log n + limit)` index work, no block read.

18. **`GET /sbtp-graph/v1/subgraph/{block_id}?dir={dir}&depth={d}&max_nodes={m}&rel={verb}&form={form}`.**
    A breadth-first walk from the root.
    - `dir`: `out` (default), `in` or `both`. `out` follows the causal edges of a node (except `tagged`)
      and its `block` edges; a node with an opaque payload follows its header parents. `in` follows the
      node's children, as in rule 17, at most `max_children_per_node` per node, oldest first.
    - `depth`: 0 to `max_depth`, default 1. `max_nodes`: 1 to `max_nodes` of `/info`, default 64.
    - `rel` (optional): only edges with this `rel` are followed, in either direction.
    - `form`: `view` (default: each node is its ADR 0040 view) or `summary` (each node is
      `{block_id, kind, pubkey, timestamp}`).
    - `GET /sbtp-graph/v1/subgraph/{id}?dir=out&depth=1` is "a block and the blocks it points to".
    - Response: `200`, `application/json`, `Cache-Control: no-store`, at most 4,194,304 bytes; `404`
      when the root is not held:

      ```json
      {
        "root": "0000a3…",
        "nodes": [{"sbtp_view": 1, "block_id": "0000a3…"}, {"sbtp_view": 1, "block_id": "4c1f…"}],
        "edges": [{"from": "0000a3…", "to": "4c1f…", "rel": "in", "p": 0}],
        "missing": ["9e02…"],
        "truncated": false
      }
      ```

      `nodes` (views abridged above) starts with the root and holds each block at most once, in visit
      order. `edges` holds every followed edge between two listed nodes, and from a listed node to a
      `missing` target. `missing` lists followed targets the gateway does not hold (at most
      `max_nodes`); they are not walked. `truncated` is `true` when the walk stopped at `max_nodes`, at
      the per-node children cap or at the body ceiling, before it reached `depth`. A client continues
      from a frontier node with another request.
    - Cost: at most `max_nodes` block reads and `max_nodes × (log n + max_children_per_node)` index
      work.

19. **`GET /sbtp-graph/v1/feed?since={ms}&kind={kind}&pubkey={key}&limit={n}&cursor={cursor}`.** The
    blocks the gateway ingested, in ingestion order.
    - `since`: decimal u64, gateway ingestion time in Unix milliseconds (not the Timestamp field).
    - `kind` or `pubkey` (optional, at most one of the two, only if listed in `feed_filters`; otherwise
      `400` `InvalidParameter`): exact kind; 64-hex public key.
    - `limit`, `cursor`: as in rule 17.
    - Response: `200`, `application/json`, `Cache-Control: no-store`, at most 262,144 bytes:
      `{"items": [{"block_id", "kind", "pubkey", "timestamp"}], "cursor", "more"}`, with the meaning of
      `/query` (core spec §4): the same request with the returned cursor gives the blocks ingested since.
    - Cost: `O(log n + limit)` index work, no block read.
    - This is a pull feed. Push delivery follows the relay's WebSocket design once it exists (Q-23).
      Relay-to-relay reconciliation (Q-11) is not affected.

### What graph access does and does not show

20. **Held, not displayed.** A gateway and a view show what relays and the gateway hold. They do not show
    what an application displays: hiding, retraction, moderation and supersession are application rules
    (`l2-grammar.md` §4) that the gateway does not apply. A program that presents gateway data MUST NOT
    present it as an application's displayed state. An application that wants to expose its resolved
    state does it with its own service, outside this API.
21. **Deletion.** A retraction is a signed request to hide a block. It deletes nothing: relays keep the
    block until their own eviction, and gateways, indexers and agents that ingested it keep their
    copies. An application SHOULD say so to its users before they publish. Documents MUST NOT state
    that retracting a block removes it from the network.
22. **Privacy.** A gateway exposes no information that the relays it reads do not already expose: block
    headers and payloads, and what `/query` lists. It lowers the cost of correlating them. From a feed
    and the children index, an observer can list every block of one key with its sender timestamps
    (activity hours, time zone, response delays), the keys that answer each other, and the volume of
    each thread. Sealed blocks keep the properties and limits of `l2-grammar.md` §5.9. A gateway sees
    the addresses and queries of its clients; it is one more party that can log what a client reads.
23. **Authenticity.** A valid signature proves that the holder of the private key of `pubkey` signed
    the block. It does not prove who that is, that the key was not stolen, or that the content is
    true. A gateway's answer is the gateway's claim; a program that relies on a block verifies its
    bytes (core spec §3.4).
24. **Untrusted content.** Payload text, kinds, verbs and metadata are chosen by authors. A program that
    passes them to a language model MUST mark them as data, separate from its instructions.

## Consequences

- **Relay.** Unchanged, except the optional `/info` member. The relay's cost model and its
  `O(log n + limit)` bound stay intact. A gateway reading a relay is one ordinary client under its
  admission control; a relay operator may rate-limit it like any other.
- **Amplification.** Rule 3 removes upstream fan-out. The heaviest request reads at most `max_nodes`
  (≤ 256) blocks of ≤ 65,909 bytes from local storage and returns ≤ 4 MiB; rule 12 charges it as such.
  A gateway's peak memory follows the relay model (`architecture.md` §2): a function of its settings.
- **Interoperability.** The routes, parameters, ceilings and response members are protocol; the limits
  (`max_*`, retention, sources) are gateway settings published by `/info`. Two gateways with the same
  sources may differ in content and order; neither is wrong.
- **Q-24.** A gateway with `retention_ms: null` is an archive. It serves reads only: it does not accept
  `PUT`. Whether a gateway also republishes to relays is ADR 0043's concern, not this API's.
- **Code.** New binary crate `sbtp-gateway`: `axum`, `tokio`, `redb`, `serde_json`, `ureq`, all already in
  `[workspace.dependencies]`; no new third-party crate. Index tables: `(target, position) → (child, rel,
  p)`; `(target, rel, position) → child`; `(position) → (block_id, kind, pubkey, timestamp)`;
  `(kind, position)`; `(pubkey, position)`. Blocks stored as files like the relay.
- **Compatibility.** Nothing is released. The route prefix carries `v1`; a later version adds a prefix.

## Implementation plan (ADRs 0040 to 0042)

1. `sbtp-graph` (core-engineer): `uri` and `view`, the `graph-v1` vector generator and loader; review by
   `security-auditor` (parser on untrusted input).
2. `sbtp-relay` (relay-engineer): optional `info_graph_gateway` setting and `/info` member.
3. `sbtp-gateway` (relay-engineer): ingestion loop, index, routes of rules 14 to 19, admission control
   reused from `sbtp-relay`; integration test against an in-process relay.
4. `sbtp-mcp` (wasm-engineer or a new owner, ADR 0042).
5. `sbtp-wasm`: expose `uri` and `view` (later, on demand).
6. One combined security review of steps 1 to 4 before any public gateway.

## Spec change on acceptance

`docs/spec/graph-access.md` §3 "Graph gateway API": rules 1 to 19, with the examples. §4 "What graph
access does and does not show": rules 20 to 24. `architecture.md` §3, row "Desktop / mobile daemon",
role: "Super-peers: 24/7 seeding, indexing; MAY run a graph gateway (`graph-access.md` §3)".

## Rejected alternatives

- **Subgraph and verb index in the relay.** It would make the relay parse payloads and break the
  `O(log n + limit)` bound; every relay would pay for a feature only some readers need.
- **A relay route `?parent=X&rel=Y` computed by fetching children on the fly.** Same payload parsing,
  plus unbounded work per request.
- **A stateless gateway that fans out to relays per request.** Simple to deploy, but each agent request
  becomes up to hundreds of relay requests, from the gateway's address, which concentrates load and gets
  the gateway rate-limited for its users; and hints in requests become a request-forgery channel.
- **A generic graph query language (GraphQL, SPARQL, Cypher).** Unbounded cost per request and a large
  dependency; the five routes cover the stated needs with fixed bounds.
- **Kind filter on `/children`.** It needs one more index per target; the entries already carry `kind`
  for client-side filtering.
