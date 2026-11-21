// Local storage budget (ADR 0029 rule 12 as amended by ADR 0047 rule 8), as a pure function so that
// it is tested in Node. Keys are in another store and never counted or dropped here. Order:
//   1. blocks fetched from relays, least recently used first;
//   2. own blocks that are not protected (every relay of the list acknowledged, refused or was given
//      up), least recently used first;
//   3. only to store a new own block: partly delivered own blocks (acknowledged by one relay, still
//      pending on another), the one whose first acknowledgement is oldest first.
// Never an own block that no relay of the list acknowledged. A partly delivered block never gives
// way to a fetched block.

import { LIMITS } from "./bounds.js";
import { deliveryOf, DELIVERED, firstAck, NOT_OWN, PARTIAL, protection } from "./delivery.js";

/**
 * `metas`: the stored records (`{ id, size, own, accessed, delivery? }`); `incoming`:
 * `{ size, own }`; `bases`: the relay list; `now`: the time used for the bounds of ADR 0047 rule 4.
 * Returns `{ drop, accept }`: the ids to delete, and whether to store the incoming block. A fetched
 * block is refused when the budget cannot be met after steps 1 and 2; an own block is always
 * accepted (its count is capped separately, LIMITS.storeMaxPending), even over the budget.
 */
export function planEviction(metas, incoming, { maxBlocks, maxBytes }, { bases = [], now = Date.now(), limits = LIMITS } = {}) {
  let count = metas.length + 1;
  let bytes = metas.reduce((n, m) => n + m.size, 0) + incoming.size;
  const fits = () => count <= maxBlocks && bytes <= maxBytes;
  const byAge = (a, b) => a.accessed - b.accessed;
  const kind = new Map(metas.map((m) => [m.id, protection(m, bases, now, limits)]));
  const is = (k) => (m) => kind.get(m.id) === k;
  const ackTime = (m) => firstAck(deliveryOf(m, bases, now), bases) ?? now;
  const steps = [
    metas.filter(is(NOT_OWN)).sort(byAge),
    metas.filter(is(DELIVERED)).sort(byAge),
  ];
  if (incoming.own) steps.push(metas.filter(is(PARTIAL)).sort((a, b) => ackTime(a) - ackTime(b)));
  const drop = [];
  for (const m of steps.flat()) {
    if (fits()) break;
    drop.push(m.id);
    count -= 1;
    bytes -= m.size;
  }
  if (fits() || incoming.own) return { drop, accept: true };
  return { drop: [], accept: false };
}
