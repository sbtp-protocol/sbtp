// The view of one block (its newest children and their children), its refresh, and the cold start
// of a subgraph, over a RelaySet (ADR 0051 "Expected request counts", rules 12, 13, 18, 19, 28,
// 29). Kept apart from the page so that they are tested against fake relays.
//
// With a relay whose /info says `read_api >= 2`:
// - the root is listed newest first (`order=desc`, one page of `viewSize`), and its `head` kept;
// - the children of the shown items are listed in grouped requests (32 parents per request), with
//   a per-parent cursor and `more` as the completeness signal;
// - blocks are fetched with single GETs (the cacheable form) up to `viewSingleGetMax` per round,
//   in batches above it;
// - a refresh polls the root and the shown items `asc` from `head` in one grouped request per 32.
// Any other relay gets exactly the requests of before: one ascending walk of the root, single
// GETs, no grandchildren.
//
// Every block is validated by the caller's `validate` (R1 and full validation) whatever relay
// served it; `have(id)` returns the bytes of a block already held locally (they are validated
// again, never fetched).

import { LIMITS } from "./bounds.js";
import { fetchBlocksFrom, walkAll, walkGroupAll } from "./relays.js";
import { traverse } from "./traverse.js";

/**
 * Blocks of `ids`: those held locally (validated again), then the others fetched from `set`.
 * Resolves with `{ blocks: Map id → block, fetch }` (`fetch`: the fetchBlocksFrom result).
 */
async function obtain(set, ids, { validate, have, mode = "view", hints = null, limits, max = limits.fetchMaxBlocks, signal }) {
  const blocks = new Map();
  const missing = [];
  for (const id of ids) {
    const bytes = await have(id);
    if (bytes !== null && bytes !== undefined) {
      try {
        blocks.set(id, validate(bytes, id));
        continue;
      } catch (e) {
        if (e?.name === "WasmPoisoned") throw e;
        // A local copy that fails validation is fetched again.
      }
    }
    missing.push(id);
  }
  const fetch = await fetchBlocksFrom(set, missing, validate, {
    mode, hints, limits, signal, max,
  });
  for (const b of fetch.blocks) blocks.set(b.idHex, b);
  return { blocks, fetch };
}

/**
 * Updates `poll` (Map base → Map parent → cursor) from a walkGroupAll `result`. A listing that
 * ended (`more = false`) is complete up to the relay's `head` (rules 18, 28): the next poll asks
 * only what came after it. A listing cut by a bound continues from its own cursor.
 */
function nextPoll(poll, result) {
  for (const [base, per] of result.cursors) {
    const head = result.heads.get(base);
    const next = new Map(poll.get(base) ?? []);
    for (const [parent, cursor] of per) {
      const complete = result.parents.get(parent)?.completeOn.includes(base) ?? false;
      next.set(parent, head && complete ? head : cursor);
    }
    poll.set(base, next);
  }
}

/**
 * Loads the view of `root`. Resolves with the view state:
 * `{ root, items: [{ id, block, children: [id], complete, completeOn, incompleteOn }], blocks: Map,
 *   rootPartial, poll, grouped, stats }`. `items` are the root's children (newest first from a
 * `read_api >= 2` relay); `children` of an item are known only from such relays, and `complete`
 * says whether every relay asked gave a complete listing (rule 29: only then may the client derive
 * the absence of a block, for example "no retraction").
 */
export async function loadView(set, root, { validate, have = async () => null, limits = LIMITS, signal } = {}) {
  const top = await walkAll(set, { parent: root }, {
    signal, limits, perRelayMaxIds: limits.fetchMaxBlocks, maxTotalIds: limits.fetchMaxBlocks,
    upgrade: { filter: { order: "desc", limit: limits.viewSize }, perRelayMaxIds: limits.viewSize },
  });
  const items = top.ids;
  const grouped = top.runs.some((r) => r.readApi);
  const [first, kids] = await Promise.all([
    obtain(set, items, { validate, have, limits, signal }),
    grouped && items.length > 0
      ? walkGroupAll(set, items, { filter: { limit: limits.viewChildLimit }, compat: "skip", limits, signal })
      : null,
  ]);
  const shown = new Set([root, ...items]);
  const grand = [];
  for (const id of items) {
    for (const c of kids?.parents.get(id)?.ids ?? []) {
      if (!shown.has(c)) {
        shown.add(c);
        grand.push(c);
      }
    }
  }
  const second = await obtain(set, grand.slice(0, Math.max(0, limits.fetchMaxBlocks - items.length)),
    { validate, have, limits, signal });
  const blocks = new Map([...first.blocks, ...second.blocks]);
  const view = {
    root,
    items: realChildren(items, root, blocks).map((id) => {
      const m = kids?.parents.get(id);
      return {
        id, block: blocks.get(id) ?? null, children: realChildren(m?.ids ?? [], id, blocks), complete: m?.complete ?? false,
        completeOn: m?.completeOn ?? [], incompleteOn: m?.incompleteOn ?? [],
      };
    }),
    blocks,
    rootPartial: top.partial,
    grouped,
    poll: new Map(),
    stats: {
      listed: items.length, fetched: first.fetch.blocks.length + second.fetch.blocks.length,
      notFound: first.fetch.notFound.length + second.fetch.notFound.length,
      failed: first.fetch.failed.length + second.fetch.failed.length,
      partial: top.partial || first.fetch.partial || second.fetch.partial || grand.length > limits.fetchMaxBlocks - items.length,
      runs: top.runs,
    },
  };
  // Poll cursors, per relay: the root from the head of its desc response (it shows the newest
  // children only; what is older stays unshown), or the asc cursor of an older relay; each item
  // as nextPoll says.
  for (const run of top.runs) view.poll.set(run.base, new Map([[root, run.head ?? run.cursor]]));
  if (kids) nextPoll(view.poll, kids);
  return view;
}

/**
 * Refreshes `view` in place (rule 29): one grouped `asc` request per 32 parents from the kept
 * cursors (the root and every shown item), on each `read_api >= 2` relay; an older relay walks
 * the root from its cursor. New items are added first (newest first), with their children listed
 * in full; new children of shown items are added to them. New blocks are fetched. Resolves with
 * `{ newItems, newChildren }`.
 */
export async function refreshView(set, view, { validate, have = async () => null, limits = LIMITS, signal } = {}) {
  const parents = [view.root, ...view.items.map((i) => i.id)];
  const r = await walkGroupAll(set, parents, {
    cursors: view.poll, compat: "walk", compatParents: [view.root], limits, signal,
  });
  const known = new Set([view.root, ...view.items.map((i) => i.id)]);
  for (const i of view.items) for (const c of i.children) known.add(c);
  const newItems = (r.parents.get(view.root)?.ids ?? []).filter((id) => !known.has(id));
  for (const id of newItems) known.add(id);
  // A new item's children are listed in full: some may have been stored before it.
  const fresh = newItems.length > 0 && view.grouped
    ? await walkGroupAll(set, newItems, { filter: { limit: limits.viewChildLimit }, compat: "skip", limits, signal })
    : null;
  const newChildren = [];
  for (const i of view.items) {
    const m = r.parents.get(i.id);
    for (const c of m?.ids ?? []) {
      if (known.has(c)) continue;
      known.add(c);
      i.children.push(c);
      newChildren.push(c);
    }
  }
  const added = newItems.map((id) => {
    const m = fresh?.parents.get(id);
    const item = {
      id, block: null, children: [], complete: m?.complete ?? false,
      completeOn: m?.completeOn ?? [], incompleteOn: m?.incompleteOn ?? [],
    };
    for (const c of m?.ids ?? []) {
      if (known.has(c)) continue;
      known.add(c);
      item.children.push(c);
      newChildren.push(c);
    }
    return item;
  });
  // A poll that did not complete leaves the item's completeness unknown.
  for (const i of view.items) {
    const m = r.parents.get(i.id);
    if (m && !m.complete && m.incompleteOn.length > 0) {
      i.complete = false;
      i.incompleteOn = m.incompleteOn;
    }
  }
  view.items.unshift(...added.reverse());
  const got = await obtain(set, [...newItems, ...newChildren], { validate, have, limits, signal });
  for (const [id, b] of got.blocks) view.blocks.set(id, b);
  for (const item of added) item.block = view.blocks.get(item.id) ?? null;
  // A listed id whose fetched header does not name the parent it was listed under is not shown.
  view.items = view.items.filter((i) => realChildren([i.id], view.root, view.blocks).length === 1);
  for (const i of view.items) i.children = realChildren(i.children, i.id, view.blocks);
  const shownIds = new Set(view.items.flatMap((i) => [i.id, ...i.children]));
  nextPoll(view.poll, r);
  if (fresh) nextPoll(view.poll, fresh);
  return {
    newItems: newItems.filter((id) => shownIds.has(id)),
    newChildren: newChildren.filter((id) => shownIds.has(id)),
    fetch: got.fetch,
  };
}

/**
 * Cold start of the subgraph under `root` (its descendants). With `read_api >= 2` relays: one
 * relay-wide walk with `fields=parents` (rule 13), from which the descendants are found without
 * fetching any other block, then batches. Without: a bounded traversal over per-parent walks.
 * Resolves with `{ blocks: Map, members, listed, partial }`; at most `traverseMaxVisited` blocks.
 */
export async function loadDescendants(set, root, { validate, have = async () => null, limits = LIMITS, signal } = {}) {
  const w = await walkAll(set, {}, {
    signal, limits, upgradeOnly: true, maxTotalIds: limits.walkMaxIds,
    upgrade: { filter: { fields: true, limit: 200 }, perRelayMaxIds: limits.walkMaxIds },
  });
  let members;
  let partial;
  if (w.runs.length > 0) {
    // Children by parent, from the hints only: a hint is never trusted for more than a skip, and
    // each block kept is validated when fetched.
    const children = new Map();
    for (const [id, h] of w.hints) {
      for (const p of h.parents) {
        if (!children.has(p)) children.set(p, []);
        children.get(p).push(id);
      }
    }
    const t = await traverse(root, async (id) => children.get(id) ?? [], { maxVisited: limits.traverseMaxVisited + 1, signal });
    members = t.visited.filter((id) => id !== root);
    partial = w.partial || t.partial;
  } else {
    const t = await traverse(root, async (id) => {
      const r = await walkAll(set, { parent: id }, { signal, limits, perRelayMaxIds: limits.groupMaxIdsPerParent });
      return r.ids;
    }, { maxVisited: limits.traverseMaxVisited + 1, signal });
    members = t.visited.filter((id) => id !== root);
    partial = t.partial;
  }
  const got = await obtain(set, [root, ...members], {
    validate, have, mode: "bulk", hints: w.hints, max: limits.traverseMaxVisited + 1, limits, signal,
  });
  // The hints chose what to fetch; the headers decide what is shown. A block is a descendant only
  // if one of its own parents is the root or a descendant (a relay that lies in `parents` can make
  // the client fetch a block, never show it in the wrong place).
  const keep = new Set([root]);
  for (let changed = true; changed;) {
    changed = false;
    for (const id of members) {
      if (keep.has(id)) continue;
      const b = got.blocks.get(id);
      if (b && b.parents.some((p) => keep.has(p))) {
        keep.add(id);
        changed = true;
      }
    }
  }
  const shown = members.filter((id) => keep.has(id));
  const blocks = new Map([...got.blocks].filter(([id]) => keep.has(id)));
  return {
    blocks, members: shown, listed: w.ids.length, partial: partial || got.fetch.partial, fetch: got.fetch,
  };
}

/** The ids of `ids` whose fetched block names `parent` among its own parents (or not fetched). */
const realChildren = (ids, parent, blocks) =>
  ids.filter((id) => !blocks.has(id) || blocks.get(id).parents.includes(parent));
