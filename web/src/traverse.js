// Bounded DAG traversal (ADR 0029 rule 11): breadth first over a queue, never recursive, each
// block_id visited at most once. With up to 8 parents per block the number of paths grows
// exponentially with depth; the number of blocks visited here does not.

import { LIMITS } from "./bounds.js";

/**
 * Visits blocks from `start` (an id or a list of ids). `visit(id)` resolves with the neighbour ids
 * of `id` (its parents, or its children from /query), or null when the block is unavailable.
 * Resolves with `{ visited, unavailable, partial }`: `visited` in visit order; `partial` is true when
 * the bound stopped the traversal with blocks still queued.
 */
export async function traverse(start, visit, { maxVisited = LIMITS.traverseMaxVisited, signal } = {}) {
  const queue = Array.isArray(start) ? [...start] : [start];
  const known = new Set(queue);
  const visited = [];
  const unavailable = [];
  let head = 0;
  let overflow = false;
  while (head < queue.length) {
    if (signal?.aborted || visited.length + unavailable.length >= maxVisited) {
      return { visited, unavailable, partial: true };
    }
    const id = queue[head];
    head += 1;
    const next = await visit(id);
    if (next === null) {
      unavailable.push(id);
      continue;
    }
    visited.push(id);
    for (const n of next) {
      // Ids are only queued once, and the queue never holds more than the bound needs.
      if (!known.has(n) && known.size < maxVisited) {
        known.add(n);
        queue.push(n);
      } else if (!known.has(n)) {
        overflow = true;
      }
    }
  }
  return { visited, unavailable, partial: overflow };
}

/**
 * `traverse`, one breadth-first level at a time, so that a level's blocks are fetched together
 * (in batches with a `read_api >= 2` relay, ADR 0051 rule 12). `visitLevel(ids)` resolves with a
 * Map id → neighbour ids, or null when the block is unavailable (a missing entry counts as null).
 * Same bound and result as `traverse`: at most `maxVisited` blocks visited or unavailable.
 */
export async function traverseLevels(start, visitLevel, { maxVisited = LIMITS.traverseMaxVisited, signal } = {}) {
  let level = [...new Set(Array.isArray(start) ? start : [start])].slice(0, maxVisited);
  const known = new Set(level);
  const visited = [];
  const unavailable = [];
  let overflow = known.size < (Array.isArray(start) ? new Set(start).size : 1);
  while (level.length > 0) {
    if (signal?.aborted) return { visited, unavailable, partial: true };
    const room = maxVisited - visited.length - unavailable.length;
    if (room <= 0) return { visited, unavailable, partial: true };
    const ask = level.slice(0, room);
    const cut = ask.length < level.length;
    const answers = await visitLevel(ask);
    const next = [];
    for (const id of ask) {
      const ns = answers.get(id) ?? null;
      if (ns === null) {
        unavailable.push(id);
        continue;
      }
      visited.push(id);
      for (const n of ns) {
        if (known.has(n)) continue;
        if (known.size >= maxVisited) {
          overflow = true;
          continue;
        }
        known.add(n);
        next.push(n);
      }
    }
    if (cut) return { visited, unavailable, partial: true };
    level = next;
  }
  return { visited, unavailable, partial: overflow };
}
