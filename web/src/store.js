// Local block store in IndexedDB. Only validated blocks are stored: fetched blocks after the §3.4
// receipt rule, own blocks after attachSignature and a full validation. Blocks are validated again
// when read back (cheap, and a same-origin script could have edited the database).
//
// Own blocks carry a delivery state per relay of the list (ADR 0047, `delivery.js`): pending,
// acknowledged, refused or given up. The store knows the relay list (`setRelays`), so that the
// protection of rule 2 and the eviction order of rule 8 are decided in the same transaction as the
// write. Records written before ADR 0047 (`acked`, `failedOn`) are read through the ADR's mapping and
// rewritten in the new form by `setRelays` (called on start and on every change of the list).
//
// Running totals (count, bytes, pending own blocks) are kept in the `stats` store, updated in the
// same transaction as every change, so a put reads one record; blockMeta is scanned only when the
// budget is exceeded (eviction), when the relay list changes, or when the totals are missing.
// `pending` counts the own blocks no relay of the list acknowledged (rule 2, first case): they are
// never evicted, so their number is capped (`storeMaxPending`).

import { LIMITS } from "./bounds.js";
import { applyResults, newDelivery, protection, reconcile, UNACKNOWLEDGED } from "./delivery.js";
import { planEviction } from "./eviction.js";
import { tx } from "./idb.js";

export class StoreFull extends Error {
  constructor(message) {
    super(message);
    this.name = "StoreFull";
  }
}

const TOTALS = "totals";

export class BlockStore {
  /** `bases`: the relay list; `now`: the clock (tests inject one). */
  constructor(db, limits = LIMITS, { bases = [], now = Date.now } = {}) {
    this.db = db;
    this.limits = { maxBlocks: limits.storeMaxBlocks, maxBytes: limits.storeMaxBytes };
    this.maxPending = limits.storeMaxPending;
    this.bounds = limits;
    this.bases = [...bases];
    this.now = now;
  }

  #unacked(m, now) {
    return protection(m, this.bases, now, this.bounds) === UNACKNOWLEDGED;
  }

  #totalsOf(metas, now) {
    return {
      name: TOTALS,
      count: metas.length,
      bytes: metas.reduce((n, m) => n + m.size, 0),
      pending: metas.filter((m) => this.#unacked(m, now)).length,
    };
  }

  async #readTotals(s, now) {
    return (await s.stats.get(TOTALS)) ?? this.#totalsOf(await s.blockMeta.getAll(), now);
  }

  /** Stores a validated block. `own`: created by the user (then pending on every relay of the list). */
  async put(id, bytes, { own = false } = {}) {
    // A tight copy: a view over a larger buffer would persist the whole buffer (structured clone)
    // while the budget counts only `byteLength`.
    const copy = bytes.slice();
    const now = this.now();
    // Read, plan and write in one transaction, so two tabs cannot both exceed the budget.
    return tx(this.db, ["blockMeta", "blockBytes", "stats"], "readwrite", async (s) => {
      const totals = await this.#readTotals(s, now);
      const existing = await s.blockMeta.get(id);
      if (existing) {
        if (own && !existing.own) {
          // A fetched copy of an own block: now protected and sent to every relay of the list.
          existing.own = true;
          existing.delivery = newDelivery(this.bases);
          totals.pending += 1;
        }
        existing.accessed = now;
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
        const plan = planEviction(metas, { size, own }, this.limits, { bases: this.bases, now, limits: this.bounds });
        if (!plan.accept) throw new StoreFull("local storage budget reached by own blocks still being delivered");
        const byId = new Map(metas.map((m) => [m.id, m]));
        // A partly delivered block dropped by step 3 has its pending relays given up first (rule 8):
        // its record goes with it, so nothing is left to update.
        for (const victim of plan.drop) {
          await s.blockMeta.delete(victim);
          await s.blockBytes.delete(victim);
          totals.count -= 1;
          totals.bytes -= byId.get(victim).size;
        }
      }
      const meta = { id, size, own, accessed: now };
      if (own) meta.delivery = newDelivery(this.bases);
      await s.blockMeta.put(meta);
      await s.blockBytes.put({ id, bytes: copy });
      totals.count += 1;
      totals.bytes += size;
      totals.pending += own ? 1 : 0;
      await s.stats.put(totals);
      return "stored";
    });
  }

  /**
   * Records one PUT round of an own block: `results` of `publishAll` (each `{ base, outcome, error }`).
   * Acknowledgements, final refusals and transient failures update the relay's state (ADR 0047
   * rule 3); a request not sent is not an attempt. Resolves with the new delivery record.
   */
  recordPublish(id, results) {
    const now = this.now();
    return tx(this.db, ["blockMeta", "stats"], "readwrite", async (s) => {
      const m = await s.blockMeta.get(id);
      if (!m || !m.own) return undefined;
      const before = this.#unacked(m, now);
      const next = { ...m, delivery: applyResults(m, results, this.bases, now, this.bounds) };
      delete next.acked;
      delete next.failedOn;
      const after = this.#unacked(next, now);
      if (before !== after) {
        const totals = await this.#readTotals(s, now);
        totals.pending += (after ? 1 : 0) - (before ? 1 : 0);
        await s.stats.put(totals);
      }
      await s.blockMeta.put(next);
      return next.delivery;
    });
  }

  /**
   * The relay list became `bases` (settings.js hook; also called on start). Every own block is
   * reconciled (ADR 0047 rules 6 and 7) and migrated from the pre-ADR form; totals are recomputed.
   */
  setRelays(bases) {
    this.bases = [...bases];
    const now = this.now();
    return tx(this.db, ["blockMeta", "stats"], "readwrite", async (s) => {
      const metas = await s.blockMeta.getAll();
      const out = [];
      for (const m of metas) {
        if (!m.own) {
          out.push(m);
          continue;
        }
        const next = { ...m, delivery: reconcile(m, this.bases, now, this.bounds) };
        delete next.acked;
        delete next.failedOn;
        await s.blockMeta.put(next);
        out.push(next);
      }
      await s.stats.put(this.#totalsOf(out, now));
    });
  }

  async get(id) {
    const r = await tx(this.db, ["blockBytes"], "readonly", (s) => s.blockBytes.get(id));
    return r ? r.bytes : null;
  }

  list() {
    return tx(this.db, ["blockMeta"], "readonly", (s) => s.blockMeta.getAll());
  }

  /** Deletes one block at the user's request (not an eviction: ADR 0047 rule 9). */
  delete(id) {
    const now = this.now();
    return tx(this.db, ["blockMeta", "blockBytes", "stats"], "readwrite", async (s) => {
      const m = await s.blockMeta.get(id);
      if (!m) return false;
      const totals = await this.#readTotals(s, now);
      totals.count -= 1;
      totals.bytes -= m.size;
      totals.pending -= this.#unacked(m, now) ? 1 : 0;
      await s.blockMeta.delete(id);
      await s.blockBytes.delete(id);
      await s.stats.put(totals);
      return true;
    });
  }

  /** Drops every fetched block (never own blocks, never keys). */
  clearFetched() {
    const now = this.now();
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
      await s.stats.put(this.#totalsOf(kept, now));
    });
  }
}
