// Local storage budget (ADR 0029 rule 12), as a pure function so that it is tested in Node.
// Keys are in another store and never counted or dropped here. Order of eviction: blocks fetched
// from relays first, least recently used first; then the user's own blocks a relay acknowledged
// (they can be fetched back). Never an own block no relay has acknowledged with 200 or 201.

/**
 * `metas`: [{ id, size, own, acked, accessed }] currently stored; `incoming`: { size, own }.
 * Returns `{ drop, accept }`: the ids to delete, and whether to store the incoming block. A fetched
 * block is refused when the budget cannot be met; an own block is always accepted (its count is
 * capped separately, LIMITS.storeMaxPending), even if pending own blocks alone exceed the budget.
 */
export function planEviction(metas, incoming, { maxBlocks, maxBytes }) {
  let count = metas.length + 1;
  let bytes = metas.reduce((n, m) => n + m.size, 0) + incoming.size;
  const fits = () => count <= maxBlocks && bytes <= maxBytes;
  const byAge = (a, b) => a.accessed - b.accessed;
  const candidates = [
    ...metas.filter((m) => !m.own).sort(byAge),
    ...metas.filter((m) => m.own && m.acked).sort(byAge),
  ];
  const drop = [];
  for (const m of candidates) {
    if (fits()) break;
    drop.push(m.id);
    count -= 1;
    bytes -= m.size;
  }
  if (fits() || incoming.own) return { drop, accept: true };
  return { drop: [], accept: false };
}
