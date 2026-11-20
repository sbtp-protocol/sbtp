// Local block store in IndexedDB. Only validated blocks are stored: fetched blocks after the §3.4
// receipt rule, own blocks after attachSignature and a full validation. Blocks are validated again
// when read back (cheap, and a same-origin script could have edited the database).
//
// Running totals (count, bytes, pending own blocks) are kept in the `stats` store, updated in the
// same transaction as every change, so a put reads one record; blockMeta is scanned only when the
// budget is exceeded (eviction) or when the totals are missing (first use after the v2 upgrade).

import { LIMITS } from "./bounds.js";
import { planEviction } from "./eviction.js";
import { tx } from "./idb.js";

export class StoreFull extends Error {
  constructor(message) {
    super(message);
    this.name = "StoreFull";
  }
}

const TOTALS = "totals";
/** Relay bases remembered per own block for a retry (`failedOn`). */
const MAX_FAILED_ON = 2 * LIMITS.maxRelays;
const isPending = (m) => m.own && !m.acked;

function totalsOf(metas) {
  return {
    name: TOTALS,
    count: metas.length,
    bytes: metas.reduce((n, m) => n + m.size, 0),
    pending: metas.filter(isPending).length,
  };
}

async function readTotals(s) {
  return (await s.stats.get(TOTALS)) ?? totalsOf(await s.blockMeta.getAll());
}

export class BlockStore {
  constructor(db, limits = LIMITS) {
    this.db = db;
    this.limits = { maxBlocks: limits.storeMaxBlocks, maxBytes: limits.storeMaxBytes };
    this.maxPending = limits.storeMaxPending;
  }

  /** Stores a validated block. `own`: created by the user (then `acked` starts false). */
  async put(id, bytes, { own = false } = {}) {
    // A tight copy: a view over a larger buffer would persist the whole buffer (structured clone)
    // while the budget counts only `byteLength`.
    const copy = bytes.slice();
    // Read, plan and write in one transaction, so two tabs cannot both exceed the budget.
    return tx(this.db, ["blockMeta", "blockBytes", "stats"], "readwrite", async (s) => {
      const totals = await readTotals(s);
      const existing = await s.blockMeta.get(id);
      if (existing) {
        if (own && !existing.own) {
          existing.own = true; // a fetched copy of an own block: now protected until acknowledged
          totals.pending += existing.acked ? 0 : 1;
        }
        existing.accessed = Date.now();
        await s.blockMeta.put(existing);
        await s.stats.put(totals);
        return "present";
      }
      if (own && totals.pending >= this.maxPending) {
        throw new StoreFull(`${this.maxPending} own blocks are waiting for a relay: publish them first`);
      }
      const size = copy.byteLength;
      if (totals.count + 1 > this.limits.maxBlocks || totals.bytes + size > this.limits.maxBytes) {
        const metas = await s.blockMeta.getAll();
        const plan = planEviction(metas, { size, own }, this.limits);
        if (!plan.accept) throw new StoreFull("local storage budget reached by unpublished own blocks");
        const byId = new Map(metas.map((m) => [m.id, m]));
        for (const victim of plan.drop) {
          await s.blockMeta.delete(victim);
          await s.blockBytes.delete(victim);
          totals.count -= 1;
          totals.bytes -= byId.get(victim).size;
        }
      }
      await s.blockMeta.put({ id, size, own, acked: false, accessed: Date.now() });
      await s.blockBytes.put({ id, bytes: copy });
      totals.count += 1;
      totals.bytes += size;
      totals.pending += own ? 1 : 0;
      await s.stats.put(totals);
      return "stored";
    });
  }

  /**
   * Records one PUT round of an own block: `acked`, the relay bases that answered 200 or 201, and
   * `failed`, the ones that did not. From the first acknowledgement the block may be evicted; the
   * relays it failed on are kept in `failedOn` (at most `maxFailedOn`) so that it is sent to them
   * again.
   */
  recordPublish(id, acked, failed) {
    return tx(this.db, ["blockMeta", "stats"], "readwrite", async (s) => {
      const m = await s.blockMeta.get(id);
      if (!m) return;
      const failedOn = new Set(m.failedOn ?? []);
      for (const b of acked) failedOn.delete(b);
      for (const b of failed) failedOn.add(b);
      m.failedOn = [...failedOn].slice(-MAX_FAILED_ON);
      if (acked.length > 0 && !m.acked) {
        const totals = await readTotals(s);
        totals.pending -= isPending(m) ? 1 : 0;
        m.acked = true;
        await s.stats.put(totals);
      }
      await s.blockMeta.put(m);
    });
  }

  async get(id) {
    const r = await tx(this.db, ["blockBytes"], "readonly", (s) => s.blockBytes.get(id));
    return r ? r.bytes : null;
  }

  list() {
    return tx(this.db, ["blockMeta"], "readonly", (s) => s.blockMeta.getAll());
  }

  /** Drops every fetched block (never own blocks, never keys). */
  clearFetched() {
    return tx(this.db, ["blockMeta", "blockBytes", "stats"], "readwrite", async (s) => {
      const kept = [];
      for (const m of await s.blockMeta.getAll()) {
        if (m.own) {
          kept.push(m);
        } else {
          await s.blockMeta.delete(m.id);
          await s.blockBytes.delete(m.id);
        }
      }
      await s.stats.put(totalsOf(kept));
    });
  }
}
