// Several relays: publish to all of them, read with failover, merge /query walks. Kept apart from
// the page so that it is tested against fake relays. Non-normative guidance: spec §4 "Several
// relays".
//
// - Every relay is untrusted (ADR 0029 rule 1). A block is validated by the caller's `validate`
//   (sbtp-wasm `validateRequested`: R1 and full validation) whatever relay served it; one that fails
//   is discarded and the next relay is asked.
// - A cursor belongs to the relay that issued it (ADR 0012, ADR 0024): each relay is walked with its
//   own cursor, and cursors are kept per relay base URL, never mixed.
// - Bounds hold per relay (the walk, the request deadline, the body ceilings of relay.js and
//   http.js) and for the whole operation (relays per list, identifiers merged, GET attempts).
// - Health: a relay that keeps failing is left aside for a back-off; a Retry-After is always
//   obeyed (spec §4 "Admission control": no request to that relay before it has elapsed).

import { LIMITS } from "./bounds.js";
import {
  classifyPut, deliveryOf, deliveryTargets, firstAck, PARTIAL, protection, putStatus, UNACKNOWLEDGED,
} from "./delivery.js";
import { checkRelayUrl, RelayRequestError } from "./http.js";
import { InvalidResponse, NETWORK_POW_DIFFICULTY, Relay, RelayStatus } from "./relay.js";
import { backoffMs, walk } from "./walk.js";

const MAX_URL_LEN = 2048;

/**
 * Parses a relay list typed by the user: URLs separated by spaces, commas or line ends. Each is
 * checked with `checkRelayUrl`; duplicates are dropped; at most `max`. Throws a `bad-url`
 * RelayRequestError naming the first bad entry.
 */
export function parseRelayList(text, max = LIMITS.maxRelays) {
  const out = [];
  for (const item of String(text).split(/[\s,]+/).filter(Boolean)) {
    if (item.length > MAX_URL_LEN) throw new RelayRequestError("bad-url", `a relay URL is longer than ${MAX_URL_LEN} characters`);
    let base;
    try {
      base = checkRelayUrl(item);
    } catch (e) {
      throw new RelayRequestError("bad-url", `${item.slice(0, 80)}: ${e.message}`);
    }
    if (!out.includes(base)) out.push(base);
  }
  if (out.length === 0) throw new RelayRequestError("bad-url", "no relay: give at least one relay URL");
  if (out.length > max) throw new RelayRequestError("bad-url", `${out.length} relays: this client uses at most ${max}`);
  return out;
}

/** An operation ended by the caller (Cancel, operation deadline): never a relay fault. */
const isAborted = (e) => e instanceof RelayRequestError && e.kind === "aborted";

/**
 * Whether an error shows a faulty or unavailable relay (ADR 0029 rules 15, 16): a failed request,
 * a transient refusal, or a block that fails the receipt rule. A 404 or a non-transient 4xx (a PUT
 * refused for the block's own sake) is not counted.
 */
export function isRelayFault(e) {
  if (isAborted(e)) return false;
  if (e instanceof RelayRequestError || e instanceof InvalidResponse) return true;
  if (e instanceof RelayStatus) return e.transient;
  return e?.invalidBlock === true;
}

/** A block from a relay failed `validate`: a relay fault (ADR 0029 rule 16). */
export class InvalidBlock extends Error {
  constructor(base, cause) {
    super(`${base} served an invalid block (${cause?.name ?? "Error"}: ${cause?.message ?? cause})`);
    this.name = "InvalidBlock";
    this.invalidBlock = true;
    this.cause = cause;
  }
}

/**
 * The relays of one client, in the user's order, with their health. Health lives in memory only:
 * a reload starts every relay healthy.
 */
export class RelaySet {
  constructor(bases, { makeRelay = (b) => new Relay(b), now = Date.now, random = Math.random, limits = LIMITS } = {}) {
    if (bases.length > limits.maxRelays) throw new RangeError(`at most ${limits.maxRelays} relays`);
    this.entries = bases.map((base) => ({ base, relay: makeRelay(base), failures: 0, until: 0, lastError: null }));
    this.now = now;
    this.random = random;
    this.limits = limits;
  }

  get bases() {
    return this.entries.map((e) => e.base);
  }

  entry(base) {
    return this.entries.find((e) => e.base === base);
  }

  /** The relays not backing off, in the user's order. */
  available() {
    const t = this.now();
    return this.entries.filter((e) => e.until <= t);
  }

  /** Milliseconds before `e` may be used again (0 when available). */
  waitMs(e) {
    return Math.max(0, e.until - this.now());
  }

  /**
   * Records a success. `until` is left as is: a success that was in flight when another request got
   * a Retry-After must not lift it (security review 2026-11-21, L-1).
   */
  ok(e) {
    e.failures = 0;
    e.lastError = null;
  }

  /**
   * Records an outcome that failed. A relay fault counts toward the threshold: from
   * `relayFailThreshold` faults in a row the relay is left aside for an exponential back-off. A
   * Retry-After in seconds always holds the relay back that long, fault or not, threshold or not.
   */
  fail(e, error) {
    const t = this.now();
    if (isRelayFault(error)) {
      e.failures += 1;
      e.lastError = error;
      const over = e.failures - this.limits.relayFailThreshold + 1;
      if (over >= 1) e.until = Math.max(e.until, t + backoffMs(over, this.limits.relayBackoffCapMs, this.random));
    }
    const ra = error instanceof RelayStatus ? error.retryAfter : null;
    if (ra && ra.ms !== null) e.until = Math.max(e.until, t + ra.ms);
  }

  /** One line per relay for the page. */
  describe() {
    return this.entries.map((e) => {
      const wait = this.waitMs(e);
      const state = wait > 0 ? `backing off ${Math.ceil(wait / 1000)} s` : e.failures > 0 ? `${e.failures} failure(s)` : "ok";
      const why = e.lastError ? ` (${e.lastError.name}: ${e.lastError.message})` : "";
      return `${e.base}  ${state}${why}`;
    });
  }
}

/** Throws the error of an aborted operation, if `signal` aborted. */
function checkAborted(signal) {
  if (signal?.aborted) throw new RelayRequestError("aborted", "cancelled");
}

/**
 * The difficulty to mine one block at for every relay of `set`. An explicit value (0 to 256) is used
 * as is, without /info, and every relay is a target. Otherwise each available relay's /info is read
 * in parallel and the block is mined once at the highest `min_pow_difficulty` among them, and at
 * least at the network difficulty `D_NET` (ADR 0045 rule 5):
 * - a relay asking for more than `max` (ADR 0029 rule 13) is skipped: no mining for it, no PUT;
 * - a relay whose /info fails stays a target (its PUT will tell), but sets no difficulty.
 * Throws when no relay gave a usable difficulty.
 * Resolves with `{ difficulty, targets, skipped: [{ base, reason }], infoFailed: [{ base, error }] }`.
 */
export async function publishDifficulty(set, explicit, { max = LIMITS.maxInfoDifficulty, signal } = {}) {
  if (explicit !== undefined && explicit !== null) {
    if (!Number.isInteger(explicit) || explicit < 0 || explicit > 256) {
      throw new RangeError("the difficulty must be an integer from 0 to 256");
    }
    return { difficulty: explicit, targets: set.bases, skipped: [], infoFailed: [] };
  }
  const skipped = [];
  const infoFailed = [];
  const known = [];
  const targets = [];
  const available = new Set(set.available());
  for (const e of set.entries) {
    if (!available.has(e)) {
      targets.push(e.base); // publishAll reports it as backing off; it is retried later
      infoFailed.push({ base: e.base, error: new Error(`backing off for ${Math.ceil(set.waitMs(e) / 1000)} s`) });
    }
  }
  const answers = await Promise.all([...available].map(async (e) => {
    try {
      const info = await e.relay.info({ signal });
      set.ok(e);
      return { e, info };
    } catch (error) {
      if (isAborted(error)) throw error;
      set.fail(e, error);
      return { e, error };
    }
  }));
  checkAborted(signal);
  for (const { e, info, error } of answers) {
    if (error) {
      infoFailed.push({ base: e.base, error });
      targets.push(e.base);
    } else if (info.minPowDifficulty > max) {
      skipped.push({ base: e.base, reason: `asks for difficulty ${info.minPowDifficulty}, above this client's maximum of ${max} for a value read from /info` });
    } else {
      known.push(info.minPowDifficulty);
      targets.push(e.base);
    }
  }
  if (known.length === 0) {
    const why = [...skipped.map((s) => `${s.base} ${s.reason}`), ...infoFailed.map((f) => `${f.base}: ${f.error.message}`)];
    throw new InvalidResponse(`no relay gave a usable difficulty (${why.join("; ")}); set a difficulty explicitly to mine anyway`);
  }
  // Keep the user's order among targets.
  const order = set.bases;
  targets.sort((a, b) => order.indexOf(a) - order.indexOf(b));
  return { difficulty: Math.max(NETWORK_POW_DIFFICULTY, ...known), targets, skipped, infoFailed };
}

/**
 * PUTs `bytes` to every relay of `targets` (default: all) in parallel. A relay backing off is not
 * contacted. Resolves with `{ results, acked, failed }`. Each result is
 * `{ base, outcome, error, status, errorName, delivery }`: `outcome` is "created" (201), "stored"
 * (200), "failed" or "backing-off"; `status` and `errorName` are the HTTP status and error name of a
 * refusal (null without an HTTP answer); `delivery` is the class of ADR 0047 rule 3:
 * "acknowledged", "transient" (the relay stays pending), "final" (refused) or "none" (not sent, not
 * an attempt). `acked` and `failed` list bases. The block counts as published when `acked` is not
 * empty.
 */
export async function publishAll(set, bytes, { targets = set.bases, signal } = {}) {
  const t = new Set(targets);
  const results = await Promise.all(set.entries.filter((e) => t.has(e.base)).map(async (e) => {
    const wait = set.waitMs(e);
    if (wait > 0) {
      return { base: e.base, outcome: "backing-off", error: new Error(`backing off for ${Math.ceil(wait / 1000)} s`) };
    }
    try {
      const outcome = await e.relay.put(bytes, { signal });
      set.ok(e);
      return { base: e.base, outcome, error: null };
    } catch (error) {
      if (!isAborted(error)) set.fail(e, error);
      return { base: e.base, outcome: "failed", error };
    }
  }));
  for (const r of results) Object.assign(r, putStatus(r.error), { delivery: classifyPut(r) });
  const ok = (r) => r.outcome === "created" || r.outcome === "stored";
  return {
    results,
    acked: results.filter(ok).map((r) => r.base),
    failed: results.filter((r) => !ok(r)).map((r) => r.base),
  };
}

/** Whether an error of `validate` is the client's own PoW floor only (ADR 0026 rule 4). */
const isLocalFloor = (e) => e?.name === "InsufficientPow";

/**
 * Fetches one block from the relays of `set` in order, falling back on 404, a failed request, a
 * transient refusal or an invalid block. `validate(bytes, id)` returns the verified block or throws.
 * `budget`: an optional `{ left }` shared by an operation, decremented per GET (overall bound).
 *
 * Resolves with `{ status, block, base, tried }`; `status` is:
 * - "ok": `block` from relay `base`;
 * - "not-found": every relay asked answered 404;
 * - "refused": the block is below the client's own difficulty floor. Its PoW is a property of the
 *   block_id, so no other relay is asked, and no relay is blamed;
 * - "failed": no relay served a valid block; `tried` says why for each;
 * - "unavailable": every relay is backing off;
 * - "bound": `budget` ran out.
 */
export async function fetchOne(set, id, validate, { budget, signal } = {}) {
  const tried = [];
  const candidates = set.available();
  if (candidates.length === 0) return { status: "unavailable", tried };
  for (const e of candidates) {
    checkAborted(signal);
    // Checked again before each GET: another worker may have received a Retry-After from this
    // relay meanwhile (security review 2026-11-21, L-1).
    if (set.waitMs(e) > 0) {
      tried.push({ base: e.base, backingOff: true });
      continue;
    }
    if (budget && budget.left <= 0) return { status: "bound", tried };
    if (budget) budget.left -= 1;
    let bytes;
    try {
      bytes = await e.relay.get(id, { signal });
    } catch (error) {
      if (isAborted(error)) throw error;
      set.fail(e, error);
      tried.push({ base: e.base, error });
      continue;
    }
    if (bytes === null) {
      tried.push({ base: e.base, notFound: true });
      continue;
    }
    let block;
    try {
      block = validate(bytes, id);
    } catch (cause) {
      if (cause?.name === "WasmPoisoned") throw cause;
      if (isLocalFloor(cause)) return { status: "refused", tried: [...tried, { base: e.base, error: cause }] };
      const error = new InvalidBlock(e.base, cause);
      set.fail(e, error);
      tried.push({ base: e.base, error });
      continue;
    }
    set.ok(e);
    return { status: "ok", block, base: e.base, tried };
  }
  if (tried.every((t) => t.backingOff)) return { status: "unavailable", tried };
  const allNotFound = tried.every((t) => t.notFound || t.backingOff);
  return { status: allNotFound ? "not-found" : "failed", tried };
}

/**
 * Fetches and validates up to `max` blocks of `ids` (ADR 0029 rule 10) with failover, at most
 * `concurrency` GETs in flight in all (so at most that many per relay) and at most `maxAttempts`
 * GETs in the whole operation, whatever the relays answer.
 * Resolves with `{ blocks, notFound, failed, partial, sources }`: `sources` maps a base to the
 * number of blocks it served.
 */
export async function fetchBlocksFrom(set, ids, validate, {
  max = LIMITS.fetchMaxBlocks, concurrency = LIMITS.fetchConcurrency,
  maxAttempts = LIMITS.fetchMaxAttempts, signal,
} = {}) {
  const todo = ids.slice(0, max);
  const budget = { left: maxAttempts };
  const result = { blocks: [], notFound: [], failed: [], partial: ids.length > max, sources: new Map() };
  let next = 0;
  async function worker() {
    while (next < todo.length && !signal?.aborted) {
      const id = todo[next];
      next += 1;
      let r;
      try {
        r = await fetchOne(set, id, validate, { budget, signal });
      } catch (error) {
        result.failed.push({ id, error });
        continue;
      }
      if (r.status === "ok") {
        result.blocks.push(r.block);
        result.sources.set(r.base, (result.sources.get(r.base) ?? 0) + 1);
      } else if (r.status === "not-found") {
        result.notFound.push(id);
      } else {
        if (r.status === "bound" || r.status === "unavailable") result.partial = true;
        result.failed.push({ id, status: r.status, tried: r.tried });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, 8, todo.length) }, worker));
  if (signal?.aborted) result.partial = true;
  return result;
}

/**
 * Walks /query on every available relay of `set` in parallel, each with its own cursor from
 * `cursors` (a Map base → cursor) and its own walk bound `perRelayMaxIds`, then merges the ids
 * round-robin across the relays (in the user's order within a round), deduplicated by block_id, at
 * most `maxTotalIds` in all.
 *
 * Resolves with `{ ids, runs, cursors, partial, backingOff }`: `runs` holds each relay's walk
 * result (`base`, `stop`, `error`, `ids`, `cursor`); `cursors` maps each walked base to the cursor to
 * resume from. A relay whose identifiers were cut by the overall bound keeps its starting cursor, so
 * that a later walk re-reads them (deduplication hides the rest).
 */
export async function walkAll(set, filter = {}, {
  cursors = new Map(), perRelayMaxIds = LIMITS.walkMaxIds, maxTotalIds = LIMITS.walkMaxIds,
  limits = LIMITS, sleep, random, signal,
} = {}) {
  const available = set.available();
  const backingOff = set.entries.filter((e) => !available.includes(e)).map((e) => e.base);
  const runs = await Promise.all(available.map(async (e) => {
    const start = cursors.get(e.base) ?? null;
    const w = await walk(e.relay, filter, {
      cursor: start, limits: { ...limits, walkMaxIds: perRelayMaxIds }, sleep, random, signal,
    });
    if (w.stop === "failed") set.fail(e, w.error);
    else if (w.stop !== "aborted") set.ok(e);
    return { base: e.base, start, ...w };
  }));
  // Round-robin over the relays, so that one relay (hostile, or just large) cannot fill the whole
  // budget and hide the others (security review 2026-11-21, L-2).
  const seen = new Set();
  const ids = [];
  const dropped = new Set();
  const longest = Math.max(0, ...runs.map((r) => r.ids.length));
  for (let i = 0; i < longest; i += 1) {
    for (const run of runs) {
      const id = run.ids[i];
      if (id === undefined || seen.has(id)) continue;
      if (ids.length >= maxTotalIds) {
        dropped.add(run.base);
        continue;
      }
      seen.add(id);
      ids.push(id);
    }
  }
  const out = new Map(cursors);
  for (const run of runs) out.set(run.base, dropped.has(run.base) ? run.start : run.cursor);
  const cut = dropped.size > 0;
  const partial = cut || backingOff.length > 0 || runs.some((r) => r.stop !== "done");
  return { ids, runs, cursors: out, partial, backingOff };
}

/**
 * The relays an own block is (re)sent to (ADR 0047 rules 2, 5, 7; `delivery.js`): while no relay of
 * the list acknowledged it, every relay of the list that did not refuse it for good; once one did,
 * the relays still pending for it. `now` and `limits` set the bounds of rule 4.
 */
export function retryTargets(meta, bases, { now = Date.now(), limits = LIMITS } = {}) {
  return deliveryTargets(meta, bases, now, limits);
}

/**
 * Own blocks to send again, at most `max`: those no relay of the list acknowledged first (they hold
 * storage for good), then the partly delivered ones, oldest first acknowledgement first (closest to
 * their bound). Resolves `[{ id, targets }]`.
 */
export function retryPlan(metas, bases, { max = LIMITS.storeMaxPending, now = Date.now(), limits = LIMITS } = {}) {
  const plan = [];
  const partial = [];
  for (const m of metas) {
    const p = protection(m, bases, now, limits);
    if (p === UNACKNOWLEDGED) plan.push(m);
    else if (p === PARTIAL) partial.push(m);
  }
  const ackTime = (m) => firstAck(deliveryOf(m, bases, now), bases) ?? now;
  partial.sort((a, b) => ackTime(a) - ackTime(b));
  const out = [];
  for (const m of [...plan, ...partial]) {
    if (out.length >= max) break;
    const targets = deliveryTargets(m, bases, now, limits);
    if (targets.length > 0) out.push({ id: m.id, targets });
  }
  return out;
}
