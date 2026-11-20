# Architecture decision records (ADR)

One file per decision: `NNNN-short-title.md` (continuous numbering, never reused).
An accepted decision is never modified; it is replaced by a new ADR that marks it "superseded by".
When a new ADR changes one rule of an accepted ADR and leaves the rest in force, the body of the accepted
ADR stays as is: it gets one line "Amended by: NNNN (rule, scope)" under its status, the index shows
"accepted, amended by NNNN", and the new ADR states exactly what it amends.

Some decision records are not published; the specification is self-contained and normative on its own.

## Template

```markdown
# NNNN: <title>

- Status: proposed | accepted | superseded by NNNN
- Amended by: NNNN (rule, scope)        (only on an accepted ADR amended by a later one)
- Date: YYYY-MM-DD
- Questions: Q-xx
- Impact: spec §x, affected crates, test vectors to regenerate

## Context
What forces the decision, in a few lines.

## Decision
What is adopted, stated normatively.

## Consequences
What it changes for implementation, compatibility and security.

## Rejected alternatives
Option, reason.
```

## Index

| No. | Title | Status |
|---|---|---|
| [0001](0001-endianness-big-endian.md) | Big-endian header integers (Q-03) | accepted |
| [0002](0002-domain-separation.md) | Domain separation of the `block_id` and the signature (Q-04) | accepted, amended by 0010 and 0016 |
| [0003](0003-strict-verification-and-identity.md) | Strict Ed25519 verification and block identity by `block_id` (Q-05) | accepted |
| [0004](0004-decoder-rejection-rules.md) | Decoder rejection rules and validation order (Q-10) | accepted, amended by 0014 |
| [0005](0005-protocol-name.md) | Protocol name (Q-15) | accepted |
| 0006 | *Not published.* | |
| [0007](0007-relay-settings-difficulty-and-future-window.md) | Relay settings: PoW difficulty and future timestamp window (Q-06, Q-07) | accepted, amended by 0045 |
| [0008](0008-put-idempotence-status-codes.md) | Idempotent `PUT`: `201` for a new block, `200` for a known block (Q-08, Q-09) | accepted, amended by 0014 |
| [0009](0009-storage-sharding-by-suffix.md) | Flat-file storage sharded by the trailing bytes of the `block_id` (Q-12, B-6) | accepted, amended by 0025 |
| [0010](0010-media-chunks-raw-blobs.md) | Media chunks are raw BLAKE3 blobs outside the SBTP envelope (Q-01); amends 0002 rule 10 | accepted |
| [0011](0011-deterministic-cbor-layer-2.md) | Deterministic CBOR for layer 2 payloads (Q-13) | accepted, amended by 0032 |
| [0012](0012-relay-read-api-and-errors.md) | Relay read API and errors (MVP): `/query`, error body, `/info`, CORS, rate-limit signalling (Q-08) | accepted, amended by 0014, 0018, 0019, 0024, 0028, 0029 and 0040 |
| [0013](0013-relay-index-eviction-and-quota.md) | Relay index, TTL eviction and storage quota (Q-12) | accepted, amended by 0014, 0017, 0021, 0023, 0024, 0025, 0043 and 0046 |
| [0014](0014-parent-limit-8.md) | Parent limit lowered from 15 to 8; maximum block size 65,909 bytes; amends 0004 rules 5 and 8 and the adversarial data set of 0013 | accepted |
| 0015 | *Not published.* | |
| 0016 | *Not published.* | |
| [0017](0017-benchmark-protocol-clarifications.md) | Clarifications of the ADR 0013 benchmark protocol; amends the benchmark protocol of 0013 | accepted |
| [0018](0018-relay-resource-limits.md) | Relay resource limits (admission control): settings, dedicated index reader threads, `429` and `503` semantics, `408`; amends 0012 rules 16 and 17; clarification M6 (which index failures count toward the fatal exit of rule 37: backend errors only, read and write counters, corrupt rows not counted) accepted 2026-11-19 | accepted, amended by 0019, 0020, 0021, 0023, 0027, 0028, 0040, 0044 and 0046 |
| [0019](0019-relay-configuration-clarifications.md) | Relay configuration clarifications: default difficulty, ranges, eviction disabled (`block_ttl_ms = 0`), `listen` and `data_dir`, connection timers, HTTP/1.1 only, close grace, open-file check, `software`, connections per client and keep-alive caps (Q-29), profiles `small` / `standard` / `large`, proxy-neutral wording; amends 0018 rules 6, 8, 22, 26 and 28 and the wording of 0012 rule 2 | accepted, amended by 0020, 0021, 0025, 0027, 0028, 0045 and 0046 |
| [0020](0020-relay-admission-control-refinements.md) | Relay admission control refinements: accept errors (inverted default, consecutive-failure guard), reading of `X-Forwarded-For`, over-broad `trusted_proxies`, CIDR validation, warning on the per-client bound, order of token and in-flight count; amends 0019 rules 23, 28, 30 and 31 and 0018 rules 20, 21 and 22 | accepted, amended by 0022, 0027 and 0044 |
| [0021](0021-relay-observability-logs-metrics-disk-safety.md) | Relay observability: structured logs on standard error (`key=value` or JSON, fixed event names), privacy rules, global log rate cap with computed daily bound, rotation delegated to the sink, free-space watermark (`min_free_disk_bytes`, `507`), counters and optional loopback `/metrics`; amends 0018 rules 6, 22 and 35, 0019 rules 36.6, 37 and 38 and 0013 rule 19; opens Q-31; clarifications X6 and X7 (`fatal` line of 0018 rule 37; index full with a latching backend: `critical` at once, `507`, exit 75 once space returns) accepted 2026-11-19, opens Q-36 | accepted, amended by 0023, 0027, 0028 and 0046 |
| [0022](0022-xff-element-level-invalidation.md) | X-Forwarded-For: a non-ASCII byte invalidates the element, not the line (security M-1); amends 0020 rule 7 | accepted |
| [0023](0023-relay-store-integrity.md) | Relay store integrity: damaged files are quarantined and replaced only by a validated `PUT`, signature check on a `GET` cache miss (`404` for a damaged file), `Cache-Control` per response, start-up walk once per start, 1b event vocabulary; amends 0013 rules 9 and 18, 0018 rule 18 and 0021 rules 7 and 41 | accepted, amended by 0024, 0025 and 0046 |
| [0024](0024-cursor-validity-after-unclean-shutdown.md) | Cursor validity after an unclean shutdown: a start-up walk that indexes an orphan draws a new index epoch, durable before the first orphan entry; clients restart a walk on `InvalidCursor` (Q-27); amends 0012 rule 9, 0013 rule 5 and 0023 rule 14 | accepted |
| [0025](0025-shard-directories-in-storage-quota.md) | One shard level of 256 directories created at start-up, never on the write path, never removed; quota counts a fixed tree charge (259 × 4,096 bytes) and 128 bytes per file entry; no file-count setting; minimum `max_store_bytes` 4 MiB (Q-31); amends 0009 rule 2, 0013 rule 18, 0019 rule 4 and 0023 rules 5 and 14 | accepted |
| [0026](0026-pow-difficulty-on-receipt.md) | PoW difficulty applied by the recipient of a requested block: a local setting of the recipient, `0` by default, never taken from the serving relay's `/info` (Q-32) | accepted |
| [0027](0027-limiter-table-cost-bound.md) | Cost bound of the rate-limiter table: no pass over the table, a full key found by its full time, O(log n) per request (Q-33); amends 0018 rules 21 and 35; clarifications T1 to T3 (entry estimate 192 bytes and recomputed bounds, preallocated map, pinned keys out of the order); clarifications T4 and T5 (the map never resizes or rehashes, preallocation alone does not ensure it; memory may be written at start-up) accepted 2026-11-19 | accepted |
| [0028](0028-built-in-tls.md) | Built-in TLS for `sbtp-relay` and `cli-demo`: cargo feature `tls` on by default, `tls_mode` off by default, operator-supplied PEM files (ACME deferred, Q-34), ring provider, TLS 1.3 and ALPN `http/1.1` only, no resumption or 0-RTT, reload by periodic check and `SIGHUP`, handshake within `header_timeout_ms` and a per-client `tls` token bucket, key file permission checks, TLS events and counters; CLI `https://` with OS roots and `--ca-file`, no `--insecure` (Q-30); amends 0012 rule 2, 0018 rules 21, 22, 28 and 35, 0019 rules 9, 12, 37, 39 and 42, 0021 rules 7, 41 and 42; opens Q-34 and Q-35 | accepted |
| [0029](0029-client-resource-bounds.md) | Client resource bounds against an untrusted relay: response body ceilings shared by relay and client (`/block` 65,909, `/query` 131,072, `/info` and errors 16,384 bytes, after decoding); a conforming client bounds its request time, `/query` walk, fetches, DAG traversal (visited set), memory and storage (never drops keys or unacknowledged own blocks), checks `/query` and `/info` responses, bounds a mining difficulty read from `/info`, and MAY cap its `Retry-After` wait; values are client settings; peer bounds left open (Q-26, client part); amends 0012 rules 10, 14, 16, 20 and 30 | accepted, amended by 0030 |
| [0030](0030-no-http-redirects.md) | No HTTP redirects on the relay interface: a relay, proxy or mirror serving the relay URL MUST NOT answer `/sbtp/v1/` with a `3xx` (except `304` to a conditional request); a client MUST NOT follow one and treats it as a failed request it does not repeat; browser clients set `redirect: "manual"` or `"error"` (Q-37); amends 0029 rule 15 | accepted |
| 0031 | *Not published.* | |
| 0032 | *Not published.* | |
| 0033 | *Not published.* | |
| 0034 | *Not published.* | |
| 0035 | *Not published.* | |
| 0036 | *Not published.* | |
| 0037 | *Not published.* | |
| 0038 | *Not published.* | |
| [0039](0039-sealed-kinds-edge-positions-and-closed-set.md) | Parent roles of `sbtp.enc_key` (`tagged` is `p: 0`, `supersedes` is `p: 1` on an update), closed edge set of `sbtp.enc`, undefined `sbtp.*` kinds are unknown kinds, tag/PubKey match of a key block is a resolution rule; amends 0016 rule 21 and 0032 rule 4 | accepted |
| [0040](0040-sbtp-uri-json-block-view-discovery.md) | `sbtp:` URI scheme (64-hex `block_id`, advisory `relay` hints, RFC 7595 provisional registration), derived read-only JSON block view (decimal-string u64 fields, `$bytes`/`$int` CBOR mapping, opaque payloads, no resolved state, 1 MiB), discovery (`graph_gateway` in `/info`, `/.well-known/sbtp`, `<link rel="alternate">`, `llms.txt` guidance); amends 0012 rule 20 and 0018 rule 6; opens Q-62 and Q-63 | accepted |
| [0041](0041-graph-gateway-read-api.md) | Graph gateway: optional service over the public relay interface, no upstream request on the request path; routes `info`, `block`, `view`, `children` by verb, bounded `subgraph`, `feed` under `/sbtp-graph/v1/`, with limits and ceilings; what graph access does not show (displayed state, deletion, privacy, authenticity, untrusted content); relay unchanged; opens Q-64 and Q-65 | accepted |
| [0042](0042-reference-mcp-server.md) | Reference MCP server `sbtp-mcp`: stdio, read-only, no keys, fixed sources, hints off by default, every returned view verified locally, six tools with a fixed notice, no new third-party crate; opens Q-66 | accepted |
| [0043](0043-long-lived-blocks-archive-relays-republication.md) | Long-lived blocks (Q-24): archive relays, client and super-peer re-publication after expiry, no renewal on `PUT`; a `PUT` of an expired block is a new block (`201`, new `received_at`) even before the sweep, and the sweeper then deletes nothing of it; amends 0013 rules 13 and 15 | accepted, amended by 0046 |
| [0044](0044-client-ip-header-behind-cdn.md) | Client address from a single-value CDN header (`client_ip_header`, off by default): read only from a peer in `trusted_proxies`, replaces `X-Forwarded-For`, one bare address or fallback to the peer address, never logged, deployment guarantees and cross-tenant risk stated; amends 0018 rules 6 and 20 and 0020 rule 6 | accepted |
| [0045](0045-network-pow-difficulty.md) | Network PoW difficulty `D_NET = 16`: relays SHOULD use it, a relay that takes part in replication MUST NOT require more, MAY require less; senders mine at `max(D_NET, target)`; a mirror skips a block below its target's floor and never re-mines; lowering strands nothing, raising is announced (clients first, relays at the effective date) and held blocks stay; amends 0007 rule 1 and 0019 rule 1 (Q-28 in part) | accepted |
| [0046](0046-keep-by-default-demand-eviction.md) | Relays keep by default (`block_ttl_ms = 0`); eviction under disk pressure by least recent demand (high/low water marks of the quota, coarse demand epoch, at most one counted demand per block per epoch, in-memory set flushed in batches, no eviction within `3 × E` of the last demand, a lost demand suspends eviction for `2 × E`, never on the `PUT` path, `507` when nothing is a candidate); shared caches bounded to `E / 2` (`s-maxage`, `CDN-Cache-Control`) so that revalidations (`304`) carry demand through a CDN, with an origin load budget; children refresh parents, no absolute DAG protection; gaming, cursors, re-acceptance and chunks (Q-21) stated; `/info` `demand_eviction`; settings and metrics; amends 0013 rules 12, 16 and 21, 0018 rule 35, 0019 rules 4, 37 and 38, 0021 rule 41, 0023 rule 13 and 0043 rule 1 | accepted |
| [0047](0047-own-block-protection-until-every-relay-acknowledges.md) | An own block stays protected in the client's local store until every relay of its relay list has acknowledged it (`200`, `201`) or is no longer pending: final refusals (`400` other than `TimestampTooFarInFuture`, `413`, `422`, `3xx`, other `4xx`) end at once; a pending relay is given up after a minimum number of attempts over a minimum time, or a maximum time after the first acknowledgement (client settings); a removed relay no longer protects nor counts; an added relay is pending for protected blocks; eviction order fetched, unprotected own, then partly delivered own blocks only for a new own block; amends 0029 rule 12 | proposed |
