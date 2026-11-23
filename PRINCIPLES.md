# SBTP principles

SBTP carries signed, content-addressed blocks between clients through dumb relays. A block's identifier
is the BLAKE3 hash of its bytes, its author signs it with Ed25519, and it may name up to 8 parents, so
blocks form a DAG. A relay keeps blocks in the order it received them and serves that order back
(`since`), so a client can resume a sync without loss.

This file and a one-page spec are the only design documents. The v0.2 engineering work, much larger,
is kept on the `legacy/v0.2` branch (tag `archive-2026-11-22`) as a reference to compare against and
to recycle from.

## Principles

1. **The relay transports; it does not understand.** It checks the layer 0 envelope (size, decoding,
   `block_id`, signature, proof of work) and never reads the payload.
2. **What a client can do from outside stays outside the relay.** Indexing, search, ranking,
   replication and backup are clients of `GET` and `since`, not relay features.
3. **A rule exists only if a real attack or a real bug calls for it.** The attack or the bug is written
   next to the rule, in one line.
4. **Budgets are hard limits** (below). Going over one means deleting something else first.
5. **Small standard building blocks beat home-made ones**: `tracing` for logs, `tower` for limits,
   SQLite or flat files for storage.
6. **The wire format is frozen.** It is the v0.2 binary format, checked by the frozen vectors in
   `docs/test-vectors/`. A published vector set never changes; a new set is added instead.
7. **Rigour goes where input crosses a trust boundary**: the decoder, signatures, limits, key handling
   and the supply chain. Elsewhere, simple and tested wins.
8. **Compare before adding.** Before a new feature, check how Nostr or another existing system does
   it, and write why SBTP differs.
9. **Deleting beats adding an option.** No configuration setting without a deployment that needs it.
10. **One decision, one line**, in the Decisions section below. No other decision records.

## Relay scope (v1)

Routes, a subset of v0.2:

- `PUT /sbtp/v1/block`: validate, then store atomically.
- `GET /sbtp/v1/block/{id}`.
- `GET /sbtp/v1/query?parent=<id>`: the children of one parent, in receipt order.
- `GET /sbtp/v1/query` with no parent: every block in receipt order (`since`), for catch-up.
- `GET /sbtp/v1/subscribe`: a minimal WebSocket stream of new blocks, so that applications stay
  responsive. The client gives a start position and at most one parent filter. The relay sends each
  new block with its position, in receipt order. A client that reads too slowly is disconnected; it
  reconnects and catches up with `since`, which is what guarantees completeness, not the stream.
- `GET /sbtp/v1/info`: limits, proof-of-work difficulty, a few counters.

Logging is minimal: `tracing` to standard error, one line per event, never a payload, a key or a
client's IP address in clear.

Survival guards, all needed by a public relay:

- maximum block size, checked before the body is read; a body read timeout;
- minimum proof of work;
- per-IP rate limit and a cap on concurrent connections;
- a global disk quota: over it, writes are refused (`507`), with no eviction policy;
- a deny list of block ids and keys in a file, reloaded without a restart;
- TLS handled by a reverse proxy, not by the relay.

- a cap on open WebSocket connections, an idle timeout and a bounded send queue per connection.

Not in v1: batch reads, multi-parent queries, subscription gaps and per-thread tables, replication,
object-storage mirrors, caches, demand-based eviction, detailed metrics, a home-made logger.

## Budgets

| Component | Budget, excluding tests |
|---|---|
| Spec | 1 page |
| `sbtp-core` | ≤ 1,000 lines |
| Relay | 600 to 900 lines |
| CLI | ≤ 300 lines |
| JavaScript client (separate repository) | 600 to 900 lines, pure TypeScript, no WASM required |

## Decisions

- 2026-11-23: v1 restarts from a blank slate; v0.2 stays on `legacy/v0.2` (tag `archive-2026-11-22`).
- 2026-11-23: v1 keeps the v0.2 binary wire format (BLAKE3, Ed25519, proof of work, up to 8 parents)
  and its frozen vectors.
- 2026-11-23: `since` is a position in the relay's receipt order, not an author-declared time.
- 2026-11-23: responsiveness comes from a minimal WebSocket stream; completeness comes from `since`.
  A slow consumer is disconnected, never sent a gap message.
- 2026-11-23: relay logging uses `tracing`, not a home-made logger.
- 2026-11-23: a client implementation need not use WASM; any implementation must pass the frozen
  vectors.
- 2026-11-23: a position is a persisted u64 from 1, never reused or renumbered (gaps allowed), visible
  in increasing order, named only `since`; one beyond the last gets `400 InvalidPosition`.
- 2026-11-23: `/info` carries a random `relay_id` per store; a client that sees it change resumes from 0.
- 2026-11-23: a relay never evicts a stored block; only the deny list (`451`) stops serving it, so a
  `404` means "never stored here".
- 2026-11-23: a `/subscribe` frame is `position ‖ block`, one filter per connection; the backlog
  catch-up is paced by TCP flow control and replaces batch reads; only a slow live consumer is closed
  with 4000.
- 2026-11-23 (review fixes): positions are decimal strings in JSON; `last_position` counts only
  served blocks, while `InvalidPosition` compares with every position ever given; a restored store
  draws a new `relay_id`; a `/query` page always advances `since`; clients drop blocks outside their
  filter and treat out-of-order positions as a relay error; operators MAY raise limits for listed
  addresses; a denial is never announced, so indexes re-check with `GET /block`.
- 2026-11-23: `/query` lists each block's position next to its id, so a client walking `/query` orders
  blocks as a `/subscribe` client does; `GET /block` carries no position (its response is cached as
  immutable, a position is local to one store).
