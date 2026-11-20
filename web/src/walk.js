// The /query walk (spec §4; ADR 0012 rules 9 to 13; ADR 0024 rule 8; ADR 0029 rules 8, 9, 14, 15),
// kept apart from fetch() so that it is tested against a scripted relay.
//
// - 400 InvalidCursor: the walk starts again without a cursor (counted, bounded), deduplicating.
// - 408, 429, 5xx, a network failure or a timeout: the same request again after Retry-After or an
//   exponential back-off with jitter from 1 s, at most `maxRetries` times in a row.
// - A Retry-After above `maxRetryAfterMs` ends the walk on that relay (rule 14).
// - Any other refusal or an invalid page (rule 8) ends the walk; the last valid cursor is kept.

import { DEFAULT_QUERY_LIMIT, LIMITS } from "./bounds.js";
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
 * Resolves with `{ ids, cursor, more, stop, error, pages, restarts }`: `ids` are the identifiers
 * new to `seen`; `stop` is "done", "bound" (walk bound reached: partial, resume from `cursor`),
 * "idle" (pages without anything new), "failed" (see `error`) or "aborted".
 */
export async function walk(source, filter = {}, {
  cursor = null, seen = new Set(), limits = LIMITS, sleep: wait = sleep, random = Math.random, signal,
} = {}) {
  const pageSize = filter.limit ?? DEFAULT_QUERY_LIMIT;
  const out = { ids: [], cursor, more: true, stop: "done", error: null, pages: 0, restarts: 0 };
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
    const fresh = [];
    for (const id of page.blockIds) {
      if (!seen.has(id) && !fresh.includes(id)) fresh.push(id);
    }
    const room = limits.walkMaxIds - out.ids.length;
    for (const id of fresh.slice(0, room)) {
      seen.add(id);
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
