// Delivery state of own blocks per relay of the list (ADR 0047). Pure functions over plain records,
// so that every rule is tested in Node; store.js persists the records, relays.js reads the targets,
// eviction.js the protection.
//
// A record (`meta.delivery`, own blocks only):
//   { relays: [{ base, state, attempts, firstAttempt, ackedAt, error }] }
//   state: "pending" | "acknowledged" | "refused" | "given-up"
//   attempts, firstAttempt: PUT attempts counted toward the first bound of rule 4 (ms since epoch)
//   ackedAt: when this relay first acknowledged the block (rule 1)
//   error: a short label of the last answer that was not an acknowledgement, for the page
// Only the entries of relays in the current list count (rule 6). The block's first acknowledgement
// is the earliest `ackedAt` among them (rule 4, second bound).

import { RelayRequestError } from "./http.js";
import { LIMITS } from "./bounds.js";
import { RelayStatus } from "./relay.js";

export const PENDING = "pending";
export const ACKNOWLEDGED = "acknowledged";
export const REFUSED = "refused";
export const GIVEN_UP = "given-up";

/** Protection of an own block (rule 2). */
export const UNACKNOWLEDGED = "unacknowledged"; // first case: no relay of the list acknowledged it
export const PARTIAL = "partial"; // second case: acknowledged by one, still pending on another
export const DELIVERED = "delivered"; // not protected
export const NOT_OWN = "not-own";

const boundsOf = (limits) => ({
  minAttempts: limits.publishMinAttempts,
  minWaitMs: limits.publishMinWaitMs,
  maxWaitMs: limits.publishMaxWaitMs,
});

/** The status and error name of a PUT result of `publishAll` (`status` null: no HTTP answer). */
export function putStatus(error) {
  if (error instanceof RelayStatus) return { status: error.status, errorName: error.errorName };
  return { status: null, errorName: null };
}

/**
 * Classifies one PUT result `{ outcome, error }` (rule 3): "acknowledged" (201, 200), "transient"
 * (stays pending, counts as an attempt), "final" (refused), or "none" (no request was sent: backing
 * off, or the operation was cancelled; not an attempt).
 */
export function classifyPut({ outcome, error }) {
  if (outcome === "created" || outcome === "stored") return "acknowledged";
  if (outcome === "backing-off") return "none";
  if (error instanceof RelayRequestError) {
    if (error.kind === "aborted") return "none"; // ended by the user, not by the relay
    if (error.kind === "redirect") return "final"; // a 3xx (ADR 0030)
    return "transient"; // network, timeout, body too large: a failed request (ADR 0029 rule 15)
  }
  if (error instanceof RelayStatus) {
    const s = error.status;
    if (s === 408 || s === 429 || (s >= 500 && s <= 599)) return "transient"; // 507 included (ADR 0046)
    if (s === 400) return error.errorName === "TimestampTooFarInFuture" ? "transient" : "final";
    if (s >= 300 && s <= 499) return "final"; // 413, 422, InsufficientPow, any other 4xx
  }
  // Anything else (an unexpected status, a malformed answer): a failed request, bounded by rule 4.
  return "transient";
}

/** A short label of a result that was not an acknowledgement. */
function label({ error }) {
  if (error instanceof RelayStatus) return `${error.status}${error.errorName ? ` ${error.errorName}` : ""}`;
  if (error instanceof RelayRequestError) return error.kind;
  return String(error?.name ?? "error").slice(0, 64);
}

const pendingEntry = (base) => ({ base, state: PENDING, attempts: 0, firstAttempt: null, ackedAt: null, error: null });
const copy = (d) => ({ relays: d.relays.map((e) => ({ ...e })) });

/** The delivery record of a new own block: pending on every relay of the list. */
export function newDelivery(bases) {
  return { relays: bases.map(pendingEntry) };
}

/**
 * The delivery record of `meta`, migrating a record written before ADR 0047 (`acked`, `failedOn`)
 * as the ADR's "Compatibility" says: `acked = false` is pending on every relay of the list;
 * `acked = true` is pending on the relays of `failedOn` and acknowledged on the others, first
 * acknowledged at `now`. Undefined for a fetched block.
 */
export function deliveryOf(meta, bases, now) {
  if (!meta.own) return undefined;
  if (meta.delivery) return meta.delivery;
  if (!meta.acked) return newDelivery(bases);
  const failed = new Set(meta.failedOn ?? []);
  return {
    relays: bases.map((b) => (failed.has(b)
      ? pendingEntry(b)
      : { ...pendingEntry(b), state: ACKNOWLEDGED, ackedAt: now })),
  };
}

const listed = (d, bases) => {
  const set = new Set(bases);
  return d.relays.filter((e) => set.has(e.base));
};

/** The block's first acknowledgement by a relay of the list, or null. */
export function firstAck(d, bases) {
  const t = listed(d, bases).filter((e) => e.state === ACKNOWLEDGED).map((e) => e.ackedAt ?? 0);
  return t.length > 0 ? Math.min(...t) : null;
}

/**
 * Applies the bounds of rule 4 at `now`: a pending relay is given up after at least `minAttempts`
 * attempts and `minWaitMs` since the first of them, and in any case `maxWaitMs` after the block's
 * first acknowledgement. Returns a new record (or `d` itself when nothing changes).
 */
export function settle(d, bases, now, limits = LIMITS) {
  const b = boundsOf(limits);
  const fa = firstAck(d, bases);
  const set = new Set(bases);
  const expired = (e) => (fa !== null && now - fa >= b.maxWaitMs)
    || (e.attempts >= b.minAttempts && e.firstAttempt !== null && now - e.firstAttempt >= b.minWaitMs);
  if (!d.relays.some((e) => set.has(e.base) && e.state === PENDING && expired(e))) return d;
  const out = copy(d);
  for (const e of out.relays) {
    if (set.has(e.base) && e.state === PENDING && expired(e)) e.state = GIVEN_UP;
  }
  return out;
}

/** Rule 2 for a delivery record that `settle` has seen. */
function protectionOfSettled(d, bases) {
  const l = listed(d, bases);
  if (!l.some((e) => e.state === ACKNOWLEDGED)) return UNACKNOWLEDGED;
  return l.some((e) => e.state === PENDING) ? PARTIAL : DELIVERED;
}

/** The protection of a stored block at `now` (rule 2): NOT_OWN, UNACKNOWLEDGED, PARTIAL or DELIVERED. */
export function protection(meta, bases, now, limits = LIMITS) {
  if (!meta.own) return NOT_OWN;
  return protectionOfSettled(settle(deliveryOf(meta, bases, now), bases, now, limits), bases);
}

/**
 * The relays an own block is (re)sent to (rules 2, 5, 7): while no relay of the list acknowledged
 * it, every relay of the list except those that refused it for good (the same bytes get the same
 * answer); once one did, the relays still pending. Given-up relays of an unacknowledged block stay
 * targets: they ended no protection, and a later acknowledgement is welcome (rule 5).
 */
export function deliveryTargets(meta, bases, now, limits = LIMITS) {
  if (!meta.own) return [];
  const d = settle(deliveryOf(meta, bases, now), bases, now, limits);
  const byBase = new Map(d.relays.map((e) => [e.base, e]));
  if (protectionOfSettled(d, bases) === UNACKNOWLEDGED) {
    return bases.filter((b) => byBase.get(b)?.state !== REFUSED);
  }
  return bases.filter((b) => byBase.get(b)?.state === PENDING);
}

/**
 * An own block no relay of the list holds and that no relay is pending for: every relay refused it
 * or was given up (rule 9). No automatic action is expected to deliver it; the user can add a relay,
 * export it or delete it.
 */
export function isStranded(meta, bases, now, limits = LIMITS) {
  if (!meta.own || bases.length === 0) return false;
  const d = settle(deliveryOf(meta, bases, now), bases, now, limits);
  const byBase = new Map(d.relays.map((e) => [e.base, e]));
  return protectionOfSettled(d, bases) === UNACKNOWLEDGED
    && bases.every((b) => [REFUSED, GIVEN_UP].includes(byBase.get(b)?.state));
}

/**
 * Records one round of PUT results (`publishAll().results`) into the record of `meta` at `now`
 * (rules 1, 3, 5), then applies the bounds. Results for relays not in `bases` are ignored. Returns
 * the new record.
 */
export function applyResults(meta, results, bases, now, limits = LIMITS) {
  const d = copy(deliveryOf(meta, bases, now));
  const set = new Set(bases);
  for (const r of results) {
    if (!set.has(r.base)) continue;
    const kind = classifyPut(r);
    if (kind === "none") continue;
    let e = d.relays.find((x) => x.base === r.base);
    if (!e) {
      e = pendingEntry(r.base);
      d.relays.push(e);
    }
    if (kind === "acknowledged") {
      if (e.state !== ACKNOWLEDGED) e.ackedAt = now;
      e.state = ACKNOWLEDGED;
      e.error = null;
      continue;
    }
    if (e.state === ACKNOWLEDGED) continue; // never back to pending while in the list (rule 1)
    e.error = label(r);
    if (kind === "final") {
      e.state = REFUSED;
    } else if (e.state === PENDING) {
      e.attempts += 1;
      e.firstAttempt ??= now;
    }
    // A transient failure of a refused or given-up relay changes nothing (rule 5).
  }
  return settle(d, bases, now, limits);
}

/**
 * The record of `meta` after the relay list became `bases` (rules 6 and 7): the states of removed
 * relays are deleted; a relay of the list without a state becomes pending when the block is
 * protected at that moment (after the removals). Idempotent.
 */
export function reconcile(meta, bases, now, limits = LIMITS) {
  const set = new Set(bases);
  const kept = { relays: deliveryOf(meta, bases, now).relays.filter((e) => set.has(e.base)).map((e) => ({ ...e })) };
  const d = settle(kept, bases, now, limits);
  if (protectionOfSettled(d, bases) === DELIVERED) return d;
  const have = new Set(d.relays.map((e) => e.base));
  const out = copy(d);
  for (const b of bases) if (!have.has(b)) out.relays.push(pendingEntry(b));
  return settle(out, bases, now, limits);
}

/** One line per relay of the list for the page. */
export function describeDelivery(meta, bases, now, limits = LIMITS) {
  const d = settle(deliveryOf(meta, bases, now), bases, now, limits);
  const byBase = new Map(d.relays.map((e) => [e.base, e]));
  return bases.map((b) => {
    const e = byBase.get(b);
    if (!e) return `${b}: not a target`;
    const extra = e.state === PENDING || e.state === GIVEN_UP ? `, ${e.attempts} attempt(s)` : "";
    return `${b}: ${e.state}${extra}${e.error ? ` (last: ${e.error})` : ""}`;
  });
}
