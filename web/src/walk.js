// The /query walk (spec §4; ADR 0012 rules 9 to 13; ADR 0024 rule 8; ADR 0029 rules 8, 9, 14, 15),
// kept apart from fetch() so that it is tested against a scripted relay.
//
// - 400 InvalidCursor: the walk starts again without a cursor (counted, bounded), deduplicating.
// - 408, 429, 5xx, a network failure or a timeout: the same request again after Retry-After or an
//   exponential back-off with jitter from 1 s, at most `maxRetries` times in a row.
// - A Retry-After above `maxRetryAfterMs` ends the walk on that relay (rule 14).
// - Any other refusal or an invalid page (rule 8) ends the walk; the last valid cursor is kept.

import { DEFAULT_QUERY_LIMIT, LIMITS, READ_API } from "./bounds.js";
import { abortedError, RelayRequestError } from "./http.js";
import { RelayStatus } from "./relay.js";

/** Waits `ms`, or rejects as soon as `signal` aborts, at once if it already has. */
export const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) {
    reject(abortedError(signal));
    return;
  }
  const t = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => {
    clearTimeout(t);
    reject(abortedError(signal));
  }, { once: true });
});

/** Back-off before retry `n` (1-based): 1 s, 2 s, 4 s ... up to `cap`, with jitter in [50 %, 100 %]. */
export const backoffMs = (n, cap, random = Math.random) =>
  Math.min(cap, 1000 * 2 ** (n - 1)) * (0.5 + random() / 2);

/**
 * Walks /query on `source` (an object with `queryPage(filter, cursor, {signal})`, such as a
 * `Relay`). `seen` deduplicates across calls (poll from the returned cursor with the same set).
 *
 * Resolves with `{ ids, cursor, more, stop, error, pages, restarts, head, hints }`: `ids` are the
 * identifiers new to `seen`; `stop` is "done", "bound" (walk bound reached: partial, resume from
 * `cursor`), "idle" (pages without anything new), "failed" (see `error`) or "aborted". `filter`
 * may carry `order` and `fields` (ADR 0051), for a `read_api >= 2` relay only: the walk is the same
 * in both orders, a cursor being a gap (rule 16).
 */
export async function walk(source, filter = {}, {
  cursor = null, seen = new Set(), limits = LIMITS, sleep: wait = sleep, random = Math.random, signal,
} = {}) {
  const pageSize = filter.limit ?? DEFAULT_QUERY_LIMIT;
  // `head`: of the first page since the walk (re)started (ADR 0051 rules 18, 19), null from a
  // relay that sends none. `hints`: id → { parents, len } with `fields=parents` (rule 13).
  const out = {
    ids: [], cursor, more: true, stop: "done", error: null, pages: 0, restarts: 0, head: null, hints: null,
  };
  let headTaken = false;
  let retries = 0;
  let idle = 0;
  let idleAllowance = limits.walkMaxIdlePages;
  const end = (stop, error = null) => Object.assign(out, { stop, error });

  for (;;) {
    if (signal?.aborted) return end("aborted");
    if (out.ids.length >= limits.walkMaxIds) return end("bound");
    let page;
    try {
      page = await source.queryPage(filter, out.cursor, { signal });
    } catch (e) {
      if (e instanceof RelayStatus && e.status === 400 && e.errorName === "InvalidCursor") {
        out.restarts += 1;
        if (out.restarts > limits.walkMaxRestarts) return end("failed", e);
        out.cursor = null;
        headTaken = false; // a head of the rejected epoch says nothing of the new one
        // The relay re-serves what was already seen: allow that many pages without news.
        idle = 0;
        idleAllowance = limits.walkMaxIdlePages + Math.ceil(seen.size / pageSize);
        continue;
      }
      const transient = (e instanceof RelayStatus && e.transient) ||
        (e instanceof RelayRequestError && (e.kind === "network" || e.kind === "timeout"));
      if (!transient) return end(e?.kind === "aborted" ? "aborted" : "failed", e);
      retries += 1;
      if (retries > limits.maxRetries) return end("failed", e);
      let delay = backoffMs(retries, limits.backoffCapMs, random);
      const ra = e instanceof RelayStatus ? e.retryAfter : null;
      if (ra && ra.ms !== null) {
        if (ra.ms > limits.maxRetryAfterMs) return end("failed", e);
        delay = ra.ms;
      }
      try {
        await wait(delay, signal);
      } catch {
        return end("aborted");
      }
      continue;
    }
    retries = 0;
    out.pages += 1;
    if (!headTaken) {
      out.head = page.head ?? null;
      headTaken = true;
    }
    const hintOf = new Map();
    if (page.hints) {
      out.hints ??= new Map();
      page.blockIds.forEach((id, i) => hintOf.set(id, page.hints[i]));
    }
    const fresh = [];
    for (const id of page.blockIds) {
      if (!seen.has(id) && !fresh.includes(id)) fresh.push(id);
    }
    const room = limits.walkMaxIds - out.ids.length;
    for (const id of fresh.slice(0, room)) {
      seen.add(id);
      if (hintOf.has(id)) out.hints.set(id, hintOf.get(id));
      out.ids.push(id);
    }
    out.more = page.more;
    // A page cut by the bound keeps the previous cursor, so that a later walk re-reads its rest.
    if (fresh.length > room) return end("bound");
    out.cursor = page.cursor;
    if (!page.more) return end("done");
    idle = fresh.length === 0 ? idle + 1 : 0;
    if (idle > idleAllowance) return end("idle");
  }
}

/**
 * The delay before repeating a request after `e`, or null when the operation gives up: not a
 * transient failure, too many retries in a row, or a Retry-After above `maxRetryAfterMs`.
 */
function retryDelay(e, retries, limits, random) {
  const transient = (e instanceof RelayStatus && e.transient) ||
    (e instanceof RelayRequestError && (e.kind === "network" || e.kind === "timeout"));
  if (!transient || retries > limits.maxRetries) return null;
  const ra = e instanceof RelayStatus ? e.retryAfter : null;
  if (ra && ra.ms !== null) return ra.ms > limits.maxRetryAfterMs ? null : ra.ms;
  return backoffMs(retries, limits.backoffCapMs, random);
}

/**
 * Lists the children of several parents on one `read_api >= 2` relay with grouped /query
 * requests (ADR 0051 rules 21 to 29): at most 32 parents per request, each with its own cursor
 * (`cursors`: parent → cursor), until every listing is complete or a bound stops it. `source` has
 * `queryGroup(parents, filter, {signal})` (a `Relay`). `filter` gives `order`, `limit`, `since`.
 *
 * Resolves with `{ groups, head, requests, restarts, stop, error }`. `groups` is one entry per
 * parent, in the order given: `{ parent, ids, cursor, more, complete, stop }`. `complete` is true
 * only for a listing that ended with `more = false` (rule 28): every child the relay held from the
 * starting cursor to the end of the walk. A listing cut by a bound keeps the cursor before the cut
 * page and is not complete; a client never presents it as complete (rule 29). `head` is the one of
 * the first response since the walk (re)started. `stop` is "done", "bound", "failed" or "aborted".
 *
 * - `400 InvalidCursor` (one cursor makes the whole request fail, rule 27; an epoch change
 *   invalidates them all): every listing starts again without a cursor, deduplicating, at most
 *   `walkMaxRestarts` times.
 * - Transient failures: the same request again after Retry-After or a back-off, as `walk`.
 * - Per parent: at most `groupMaxIdsPerParent` ids and `walkMaxIdlePages` pages without news; at
 *   most `walkMaxIds` ids and `groupMaxRequests` requests over the whole walk.
 */
export async function walkGroup(source, parents, {
  filter = {}, cursors = new Map(), limits = LIMITS, sleep: wait = sleep, random = Math.random, signal,
} = {}) {
  const per = [...new Set(parents)].map((parent) => ({
    parent, ids: [], seen: new Set(), cursor: cursors.get(parent) ?? null, more: true, complete: false,
    stop: null, idle: 0,
  }));
  const out = { groups: per, head: null, requests: 0, restarts: 0, stop: "done", error: null };
  const end = (stop, error = null) => {
    Object.assign(out, { stop, error });
    out.groups = per.map(({ parent, ids, cursor, more, complete, stop: s }) =>
      ({ parent, ids, cursor, more, complete, stop: s ?? stop }));
    return out;
  };
  let total = 0;
  let retries = 0;
  let headTaken = false;
  for (;;) {
    if (signal?.aborted) return end("aborted");
    const pending = per.filter((p) => p.stop === null);
    if (pending.length === 0) return end(per.every((p) => p.complete) ? "done" : "bound");
    if (out.requests >= limits.groupMaxRequests || total >= limits.walkMaxIds) return end("bound");
    const chunk = pending.slice(0, READ_API.maxParents);
    let res;
    try {
      out.requests += 1;
      res = await source.queryGroup(chunk.map((p) => ({ parent: p.parent, cursor: p.cursor })), filter, { signal });
    } catch (e) {
      if (e instanceof RelayStatus && e.status === 400 && e.errorName === "InvalidCursor") {
        out.restarts += 1;
        if (out.restarts > limits.walkMaxRestarts) return end("failed", e);
        for (const p of per) Object.assign(p, { cursor: null, more: true, complete: false, stop: null, idle: 0 });
        headTaken = false;
        continue;
      }
      if (e?.kind === "aborted") return end("aborted", e);
      retries += 1;
      const delay = retryDelay(e, retries, limits, random);
      if (delay === null) return end("failed", e);
      try {
        await wait(delay, signal);
      } catch {
        return end("aborted");
      }
      continue;
    }
    retries = 0;
    if (!headTaken) {
      out.head = res.head;
      headTaken = true;
    }
    res.groups.forEach((g, i) => {
      const p = chunk[i];
      const fresh = g.blockIds.filter((id, j) => !p.seen.has(id) && g.blockIds.indexOf(id) === j);
      const room = Math.max(0, Math.min(limits.groupMaxIdsPerParent - p.ids.length, limits.walkMaxIds - total));
      for (const id of fresh.slice(0, room)) {
        p.seen.add(id);
        p.ids.push(id);
        total += 1;
      }
      p.more = g.more;
      // A page cut by a bound keeps the previous cursor: a later walk re-reads its rest.
      if (fresh.length > room) {
        p.stop = "bound";
        return;
      }
      p.cursor = g.cursor;
      if (!g.more) {
        p.complete = true;
        p.stop = "done";
        return;
      }
      p.idle = fresh.length === 0 ? p.idle + 1 : 0;
      if (p.idle > limits.walkMaxIdlePages) p.stop = "idle";
    });
  }
}
