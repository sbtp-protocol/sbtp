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
// - Read API (ADR 0051): the batch route, `order`, `fields` and grouped `parent` are used only
//   with a relay whose /info says `read_api >= 2` (rule 31), read once per relay and kept in
//   memory. Any other relay gets exactly the requests of before.

import { CEILING, LIMITS, READ_API } from "./bounds.js";
import {
  classifyPut, deliveryOf, deliveryTargets, firstAck, PARTIAL, protection, putStatus, UNACKNOWLEDGED,
} from "./delivery.js";
import { checkRelayUrl, RelayRequestError } from "./http.js";
import { InvalidResponse, NETWORK_POW_DIFFICULTY, Relay, RelayStatus } from "./relay.js";
import { backoffMs, walk, walkGroup } from "./walk.js";

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
    this.entries = bases.map((base) => ({
      base, relay: makeRelay(base), failures: 0, until: 0, lastError: null, readApi: null, batchBroken: false,
    }));
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

  /** Keeps what an /info answer says of the read API (ADR 0051 rule 31). */
  noteInfo(e, info) {
    e.readApi = info.readApi ?? 1;
  }

  /**
   * The `read_api` of relay `e`: kept from an earlier /info, else read now. A failed /info is a
   * relay fault and reads as 1 for this operation (nothing new is sent), without being kept.
   */
  async readApi(e, { signal } = {}) {
    if (e.readApi !== null) return e.readApi;
    try {
      const info = await e.relay.info({ signal });
      this.ok(e);
      this.noteInfo(e, info);
      return e.readApi;
    } catch (error) {
      if (isAborted(error)) throw error;
      this.fail(e, error);
      return 1;
    }
  }

  /** Whether relay `e` takes the forms of ADR 0051, read from /info if needed. */
  async hasReadApi(e, opts) {
    return (await this.readApi(e, opts)) >= READ_API.version;
  }

  /**
   * Forgets what relay `e` said of its read API, after it refused a form of ADR 0051 that it
   * announced (404 or 405 on POST /blocks, InvalidParameter): the next operation reads /info again.
   */
  forgetReadApi(e) {
    e.readApi = null;
  }

  /**
   * Remembers, for the session (in memory), that `POST /blocks` does not work on relay `e`
   * (refused, or a broken answer, for example a proxy that forwards the body chunked): its blocks
   * are fetched with single GETs from now on (security review 2026-11-21, I-1).
   */
  dropBatch(e) {
    e.batchBroken = true;
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
      set.noteInfo(e, info);
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
 * block requests in the whole operation, whatever the relays answer. A batch of N identifiers
 * costs N of `maxAttempts`, as N GETs would: the relay reads N blocks (ADR 0051 rule 7).
 *
 * `mode` chooses the form with a `read_api >= 2` relay (ADR 0051 rule 12): "view" (the default)
 * uses single GETs, the cacheable form, unless more than `viewSingleGetMax` blocks are asked;
 * "bulk" (walks, cold starts, back-fills) uses batches. `hints` (id → { len }, from
 * `fields=parents`) packs batches under the 1 MiB ceiling. With no `read_api >= 2` relay, or in
 * "view" mode under the threshold, the requests are exactly those of single GETs with failover.
 *
 * Resolves with `{ blocks, notFound, failed, partial, sources, attempts }`: `sources` maps a base
 * to the number of blocks it served; `attempts` is the number of blocks requested.
 */
export async function fetchBlocksFrom(set, ids, validate, {
  max = LIMITS.fetchMaxBlocks, concurrency = LIMITS.fetchConcurrency,
  maxAttempts = LIMITS.fetchMaxAttempts, mode = "view", hints = null, limits = LIMITS, signal,
} = {}) {
  const todo = ids.slice(0, max);
  const budget = { left: maxAttempts };
  const result = { blocks: [], notFound: [], failed: [], partial: ids.length > max, sources: new Map() };
  const wantBatch = todo.length > 0 && (mode === "bulk" || todo.length > limits.viewSingleGetMax);
  if (wantBatch) {
    let apis;
    try {
      apis = await Promise.all(set.available().map((e) => set.hasReadApi(e, { signal })));
    } catch (error) {
      if (!isAborted(error)) throw error;
      result.partial = true;
      return result;
    }
    if (apis.some(Boolean)) {
      await fetchRelayByRelay(set, todo, validate, result, { budget, concurrency, hints, limits, signal });
      result.attempts = maxAttempts - budget.left;
      return result;
    }
  }
  await fetchByGet(set, todo, validate, result, { budget, concurrency, signal });
  result.attempts = maxAttempts - budget.left;
  return result;
}

/** Single GETs with failover per block (the form of every relay before ADR 0051). */
async function fetchByGet(set, todo, validate, result, { budget, concurrency, signal }) {
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
 * Splits `ids` into batches of at most 256 identifiers whose known lengths (`hints`, from
 * `fields=parents`) fit the 1 MiB ceiling with their 4-byte length prefixes (ADR 0051 rules 4,
 * 13). An unknown length counts for its prefix only: the relay then ends the body early (rule 3).
 */
export function packBatches(ids, hints = null, ceiling = CEILING.batch) {
  const out = [];
  let cur = [];
  let bytes = 0;
  for (const id of ids) {
    const cost = 4 + (hints?.get(id)?.len ?? 0);
    if (cur.length > 0 && (cur.length >= READ_API.batchMaxIds || bytes + cost > ceiling)) {
      out.push(cur);
      cur = [];
      bytes = 0;
    }
    cur.push(id);
    bytes += cost;
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

/** The outcome of one record or GET answer: a valid block, a local-floor refusal or a relay fault. */
function checkServed(set, e, bytes, id, validate) {
  try {
    return { ok: true, block: validate(bytes, id) };
  } catch (cause) {
    if (cause?.name === "WasmPoisoned") throw cause;
    if (isLocalFloor(cause)) return { refused: true, error: cause };
    const error = new InvalidBlock(e.base, cause);
    set.fail(e, error);
    return { error };
  }
}

/** A refusal showing that relay `e` does not take a form of ADR 0051 it announced. */
const refusesReadApi = (error) => error instanceof RelayStatus &&
  (error.status === 404 || error.status === 405 || (error.status === 400 && error.errorName === "InvalidParameter"));

/**
 * Whether a failed `POST /blocks` shows that the batch route itself does not work on that relay
 * (or behind what is in front of it): a refusal of the request form (400, for example
 * `InvalidParameter` or the `NoLength` of a proxy that forwards the body chunked; 404; 405; 411;
 * 413) or a broken answer (a body over 1 MiB, a record above MAX_BLOCK_LEN, extra records, an
 * empty 200). Not a network failure, a 429 or a 5xx: those say nothing about the route.
 */
const breaksBatch = (error) => error instanceof InvalidResponse ||
  (error instanceof RelayRequestError && error.kind === "body-too-large") ||
  (error instanceof RelayStatus && [400, 404, 405, 411, 413].includes(error.status));

/**
 * Asks relay `e` (`read_api >= 2`) for `ids` with `POST /blocks`, at most `batchConcurrency`
 * batches in flight. Each record is checked against the id at its position (R1 and full
 * validation by `validate`, ADR 0051 rule 6). `length = 0`: not served by this relay. A prefix
 * (rule 3): the rest is requested again. A failed request (an error status, a network failure, a
 * body over 1 MiB, a record above MAX_BLOCK_LEN, a body ending inside a record) ends batches on
 * this relay for the operation; the complete records before a truncation are used. When the
 * route itself failed (`breaksBatch`, or a truncated body), the relay is marked for single GETs
 * for the session and the ids not answered come back as `{ fallback: true }`; otherwise they go
 * to the next relay. Resolves with `{ out, bound }`: `out` maps each id to its outcome.
 */
async function batchFrom(set, e, ids, validate, { budget, hints, limits, signal }) {
  const out = new Map();
  const chunks = packBatches(ids, hints);
  let stopped = null;
  let broken = false;
  let bound = false;
  let next = 0;
  async function worker() {
    while (next < chunks.length) {
      let chunk = chunks[next];
      next += 1;
      let leftover = null;
      while (chunk.length > 0 && leftover === null) {
        if (signal?.aborted) leftover = { unasked: true };
        else if (stopped) leftover = broken ? { fallback: true, error: stopped } : { error: stopped };
        else if (set.waitMs(e) > 0) leftover = { backingOff: true };
        else if (budget.left <= 0) {
          bound = true;
          leftover = { unasked: true };
        }
        if (leftover !== null) break;
        const ask = chunk.slice(0, budget.left);
        budget.left -= ask.length;
        let res;
        try {
          res = await e.relay.fetchBatch(ask, { signal });
        } catch (error) {
          if (isAborted(error)) throw error;
          set.fail(e, error);
          if (breaksBatch(error)) {
            broken = true;
            set.dropBatch(e);
          }
          stopped = error;
          continue;
        }
        let clean = true;
        res.records.forEach((bytes, i) => {
          const o = bytes === null ? { notFound: true } : checkServed(set, e, bytes, ask[i], validate);
          if (o.error) clean = false;
          out.set(ask[i], o);
        });
        chunk = chunk.slice(res.records.length);
        if (res.truncated) {
          stopped = new InvalidResponse(`${e.base}: the POST /blocks body ends inside a record`);
          set.fail(e, stopped);
          broken = true;
          set.dropBatch(e);
        } else if (clean) {
          set.ok(e);
        }
      }
      for (const id of chunk) if (!out.has(id)) out.set(id, leftover ?? { error: stopped });
    }
  }
  await Promise.all(Array.from({ length: Math.min(limits.batchConcurrency, chunks.length) }, worker));
  return { out, bound };
}

/** Asks relay `e` (no read API) for `ids` with single GETs; outcomes as `batchFrom`. */
async function getsFrom(set, e, ids, validate, { budget, concurrency, signal }) {
  const out = new Map();
  let bound = false;
  let next = 0;
  async function worker() {
    while (next < ids.length) {
      const id = ids[next];
      next += 1;
      if (signal?.aborted) {
        out.set(id, { unasked: true });
        continue;
      }
      if (set.waitMs(e) > 0) {
        out.set(id, { backingOff: true });
        continue;
      }
      if (budget.left <= 0) {
        bound = true;
        out.set(id, { unasked: true });
        continue;
      }
      budget.left -= 1;
      let bytes;
      try {
        bytes = await e.relay.get(id, { signal });
      } catch (error) {
        if (isAborted(error)) throw error;
        set.fail(e, error);
        out.set(id, { error });
        continue;
      }
      if (bytes === null) {
        out.set(id, { notFound: true });
        continue;
      }
      const o = checkServed(set, e, bytes, id, validate);
      if (o.ok) set.ok(e);
      out.set(id, o);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, 8, ids.length) }, worker));
  return { out, bound };
}

/**
 * Failover relay by relay, in the user's order: each relay is asked for every block still
 * missing, in batches when it has the read API, else with single GETs. A block refused by the
 * local floor is not asked again (its PoW is a property of its block_id).
 */
async function fetchRelayByRelay(set, todo, validate, result, { budget, concurrency, hints, limits, signal }) {
  const tried = new Map(todo.map((id) => [id, []]));
  let pending = todo;
  let bound = false;
  for (const e of set.entries) {
    if (pending.length === 0 || bound || signal?.aborted) break;
    if (set.waitMs(e) > 0) {
      for (const id of pending) tried.get(id).push({ base: e.base, backingOff: true });
      continue;
    }
    let r;
    try {
      r = !e.batchBroken && (await set.hasReadApi(e, { signal }))
        ? await batchFrom(set, e, pending, validate, { budget, hints, limits, signal })
        : await getsFrom(set, e, pending, validate, { budget, concurrency, signal });
      // A batch route that failed: the ids it did not answer get single GETs on the same relay
      // (security review 2026-11-21, I-1), so that one relay is enough.
      const again = pending.filter((id) => r.out.get(id)?.fallback);
      if (again.length > 0) {
        const g = await getsFrom(set, e, again, validate, { budget, concurrency, signal });
        for (const [id, o] of g.out) r.out.set(id, o);
        r.bound ||= g.bound;
      }
    } catch (error) {
      if (!isAborted(error)) throw error;
      break;
    }
    bound = r.bound;
    const left = [];
    for (const id of pending) {
      const o = r.out.get(id) ?? { unasked: true };
      if (o.ok) {
        result.blocks.push(o.block);
        result.sources.set(e.base, (result.sources.get(e.base) ?? 0) + 1);
      } else if (o.refused) {
        result.failed.push({ id, status: "refused", tried: [...tried.get(id), { base: e.base, error: o.error }] });
      } else {
        tried.get(id).push({ base: e.base, ...o });
        left.push(id);
      }
    }
    pending = left;
  }
  for (const id of pending) {
    const t = tried.get(id);
    if (t.length === 0 || t.some((x) => x.unasked)) {
      result.partial = true;
      result.failed.push({ id, status: bound ? "bound" : "unavailable", tried: t });
    } else if (t.every((x) => x.backingOff)) {
      result.partial = true;
      result.failed.push({ id, status: "unavailable", tried: t });
    } else if (t.every((x) => x.notFound || x.backingOff)) {
      result.notFound.push(id);
    } else {
      result.failed.push({ id, status: "failed", tried: t });
    }
  }
  if (signal?.aborted) result.partial = true;
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
 *
 * `upgrade` (ADR 0051): `{ filter, perRelayMaxIds }` used instead of `filter` and `perRelayMaxIds`
 * on a relay whose /info says `read_api >= 2`, for example `{ order: "desc" }` for a newest-first
 * view or `{ fields: true }` for a relay-wide walk that skips what it does not need. The other
 * relays get exactly `filter`. Each run then also carries `head`, `hints` and `readApi` (true when
 * the upgraded filter was used); `heads` maps a base to its head, and `hints` merges the hints.
 */
export async function walkAll(set, filter = {}, {
  cursors = new Map(), perRelayMaxIds = LIMITS.walkMaxIds, maxTotalIds = LIMITS.walkMaxIds,
  upgrade = null, upgradeOnly = false, limits = LIMITS, sleep, random, signal,
} = {}) {
  const available = set.available();
  const backingOff = set.entries.filter((e) => !available.includes(e)).map((e) => e.base);
  const runs = (await Promise.all(available.map(async (e) => {
    const start = cursors.get(e.base) ?? null;
    let readApi = false;
    try {
      readApi = upgrade !== null && await set.hasReadApi(e, { signal });
    } catch (error) {
      if (!isAborted(error)) throw error;
      return { base: e.base, start, ids: [], cursor: start, more: true, stop: "aborted", error, head: null, hints: null, readApi };
    }
    // `upgradeOnly`: a walk that is useful only with the read API (a relay-wide walk for parent
    // ids) does not ask the other relays at all.
    if (upgradeOnly && !readApi) return null;
    const f = readApi ? { ...filter, ...upgrade.filter } : filter;
    const max = readApi ? upgrade.perRelayMaxIds ?? perRelayMaxIds : perRelayMaxIds;
    const w = await walk(e.relay, f, {
      cursor: start, limits: { ...limits, walkMaxIds: max }, sleep, random, signal,
    });
    if (w.stop === "failed") {
      set.fail(e, w.error);
      if (readApi && refusesReadApi(w.error)) set.forgetReadApi(e);
    } else if (w.stop !== "aborted") {
      set.ok(e);
    }
    return { base: e.base, start, readApi, ...w };
  }))).filter(Boolean);
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
  const heads = new Map(runs.filter((r) => r.head).map((r) => [r.base, r.head]));
  // Per id, the union of the parents every relay claims and the largest claimed length (security
  // review 2026-11-21, M-1): with first-wins hints, a hostile relay listed first could give a
  // block `parents: []` and hide it although an honest relay lists it. A hint only causes a fetch
  // (the fetched header decides what is shown); a larger length only makes batches smaller.
  const hints = new Map();
  for (const run of runs) {
    for (const [id, h] of run.hints ?? []) {
      const m = hints.get(id);
      if (!m) {
        hints.set(id, { parents: [...h.parents], len: h.len });
        continue;
      }
      for (const p of h.parents) if (!m.parents.includes(p)) m.parents.push(p);
      m.len = Math.max(m.len, h.len);
    }
  }
  return { ids, runs, cursors: out, partial, backingOff, heads, hints };
}

/**
 * Lists the children of `parents` on every available relay of `set` in parallel (ADR 0051 rules
 * 21 to 29). A relay with `read_api >= 2` gets grouped requests (`walkGroup`, 32 parents per
 * request, a cursor per parent from `cursors`: Map base → Map parent → cursor). Any other relay
 * gets one plain walk per parent when `compat` is "walk", or is not asked when it is "skip" (it
 * is then in every parent's `incompleteOn`).
 * `filter` gives `limit`, `since` and, for the grouped form only, `order`.
 *
 * Resolves with `{ parents, cursors, heads, runs, backingOff }`. `parents` maps each parent to
 * `{ ids, complete, completeOn, incompleteOn }`: the union of the ids of every relay asked, and
 * the relays whose listing of it was complete or not. `complete` holds only when every relay asked
 * gave a complete listing and none was skipped, for backing off or for lacking `read_api >= 2`
 * with "skip" (rule 29: a client derives absence
 * only from complete listings). `cursors` maps each relay to its per-parent cursors to resume from;
 * `heads` maps each grouped relay to its `head`.
 */
export async function walkGroupAll(set, parents, {
  filter = {}, cursors = new Map(), compat = "walk", compatParents = parents, limits = LIMITS, sleep, random, signal,
} = {}) {
  const available = set.available();
  const backingOff = set.entries.filter((e) => !available.includes(e)).map((e) => e.base);
  const runs = (await Promise.all(available.map(async (e) => {
    const start = cursors.get(e.base) ?? new Map();
    let grouped;
    try {
      grouped = await set.hasReadApi(e, { signal });
    } catch (error) {
      if (!isAborted(error)) throw error;
      return { base: e.base, stop: "aborted", assigned: parents, groups: [], head: null };
    }
    if (grouped) {
      const g = await walkGroup(e.relay, parents, { filter, cursors: start, limits, sleep, random, signal });
      if (g.stop === "failed") {
        set.fail(e, g.error);
        if (refusesReadApi(g.error)) set.forgetReadApi(e);
      } else if (g.stop !== "aborted") {
        set.ok(e);
      }
      return { base: e.base, grouped: true, assigned: parents, ...g };
    }
    // "skip": this relay is not asked, so no parent's listing is complete on it (rule 29;
    // security review 2026-11-21, L-2): it may hold a child the others lack.
    if (compat !== "walk") return { base: e.base, grouped: false, skipped: true, assigned: parents, groups: [], head: null, stop: "skipped" };
    // A relay before ADR 0051: one ascending walk per parent, exactly as before.
    const plain = { limit: filter.limit, since: filter.since };
    const groups = [];
    let stop = "done";
    for (const parent of compatParents) {
      if (signal?.aborted) break;
      const w = await walk(e.relay, { ...plain, parent }, {
        cursor: start.get(parent) ?? null,
        limits: { ...limits, walkMaxIds: limits.groupMaxIdsPerParent }, sleep, random, signal,
      });
      groups.push({ parent, ids: w.ids, cursor: w.cursor, more: w.more, complete: w.stop === "done", stop: w.stop });
      if (w.stop === "failed") {
        set.fail(e, w.error);
        stop = "failed";
        break;
      }
      if (w.stop === "aborted") {
        stop = "aborted";
        break;
      }
    }
    if (stop === "done") set.ok(e);
    return { base: e.base, grouped: false, assigned: compatParents, groups, head: null, stop };
  }))).filter(Boolean);
  const merged = new Map(parents.map((p) => [p, { ids: [], complete: false, completeOn: [], incompleteOn: [] }]));
  const seen = new Map(parents.map((p) => [p, new Set()]));
  const outCursors = new Map(cursors);
  const heads = new Map();
  for (const run of runs) {
    const per = new Map(outCursors.get(run.base) ?? []);
    for (const g of run.groups) {
      const m = merged.get(g.parent);
      if (!m) continue;
      const s = seen.get(g.parent);
      for (const id of g.ids) {
        if (s.has(id)) continue;
        s.add(id);
        m.ids.push(id);
      }
      (g.complete ? m.completeOn : m.incompleteOn).push(run.base);
      per.set(g.parent, g.cursor);
    }
    // A parent this relay did not reach (a walk that stopped early) is not complete on it.
    for (const p of run.assigned ?? []) {
      const m = merged.get(p);
      if (!m.completeOn.includes(run.base) && !m.incompleteOn.includes(run.base)) m.incompleteOn.push(run.base);
    }
    outCursors.set(run.base, per);
    if (run.head) heads.set(run.base, run.head);
  }
  for (const m of merged.values()) {
    m.complete = m.incompleteOn.length === 0 && m.completeOn.length > 0 && backingOff.length === 0;
  }
  return { parents: merged, cursors: outCursors, heads, runs, backingOff };
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
