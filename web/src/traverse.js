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
