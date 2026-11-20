// Walk, fetch and traversal bounds (ADR 0029 rules 9 to 11, 14) against scripted relays.
import assert from "node:assert/strict";
import { test } from "node:test";

import { LIMITS } from "../src/bounds.js";
import { RelayRequestError } from "../src/http.js";
import { fetchBlocks, RelayStatus } from "../src/relay.js";
import { traverse } from "../src/traverse.js";
import { sleep, walk } from "../src/walk.js";

const id = (n) => n.toString(16).padStart(64, "0");
const opts = (extra = {}) => {
  const s = { sleeps: [] };
  return { sleep: async (ms) => { s.sleeps.push(ms); }, random: () => 1, s, ...extra };
};

/** A source that answers from a list of pages or functions, one call each. */
function scripted(steps) {
  const calls = [];
  return {
    calls,
    async queryPage(filter, cursor) {
      calls.push(cursor);
      const step = steps[Math.min(calls.length - 1, steps.length - 1)];
      return typeof step === "function" ? step(cursor, calls.length) : step;
    },
  };
}

test("walk: pages until more = false, deduplicating", async () => {
  const src = scripted([
    { blockIds: [id(1), id(2)], cursor: "c1", more: true },
    { blockIds: [id(2), id(3)], cursor: "c2", more: false },
  ]);
  const w = await walk(src, {}, opts());
  assert.deepEqual(w.ids, [id(1), id(2), id(3)]);
  assert.equal(w.stop, "done");
  assert.equal(w.cursor, "c2");
  assert.deepEqual(src.calls, [null, "c1"]);
});

test("walk: more = true for ever stops at the id bound and keeps a resume cursor", async () => {
  let n = 0;
  const src = scripted([() => ({ blockIds: Array.from({ length: 100 }, () => id(++n)), cursor: `c${n}`, more: true })]);
  const w = await walk(src, {}, opts());
  assert.equal(w.stop, "bound");
  assert.equal(w.ids.length, LIMITS.walkMaxIds);
  assert.equal(w.cursor, `c${LIMITS.walkMaxIds}`);
});

test("walk: a page cut by the bound keeps the previous cursor", async () => {
  const src = scripted([
    { blockIds: [id(1), id(2)], cursor: "c1", more: true },
    { blockIds: [id(3), id(4)], cursor: "c2", more: true },
  ]);
  const w = await walk(src, {}, opts({ limits: { ...LIMITS, walkMaxIds: 3 } }));
  assert.equal(w.stop, "bound");
  assert.deepEqual(w.ids, [id(1), id(2), id(3)]);
  assert.equal(w.cursor, "c1");
});

test("walk: empty pages with more = true end as idle", async () => {
  const src = scripted([{ blockIds: [], cursor: "c", more: true }]);
  const w = await walk(src, {}, opts());
  assert.equal(w.stop, "idle");
  assert.equal(src.calls.length, LIMITS.walkMaxIdlePages + 1);
});

test("walk: InvalidCursor restarts without a cursor, bounded", async () => {
  const bad = () => { throw new RelayStatus(400, "InvalidCursor", null); };
  const src = scripted([bad, { blockIds: [id(1)], cursor: "c1", more: false }]);
  const w = await walk(src, {}, opts({ cursor: "stale" }));
  assert.deepEqual(src.calls, ["stale", null]);
  assert.equal(w.restarts, 1);
  assert.equal(w.stop, "done");
  const always = await walk(scripted([bad]), {}, opts({ cursor: "x" }));
  assert.equal(always.stop, "failed");
  assert.equal(always.restarts, LIMITS.walkMaxRestarts + 1);
});

test("walk: Retry-After obeyed, too long or retries exhausted ends; a date backs off", async () => {
  const limited = (ra) => () => { throw new RelayStatus(429, "RateLimited", ra); };
  const o = opts();
  const ok = await walk(scripted([limited({ ms: 5000 }), { blockIds: [], cursor: "c", more: false }]), {}, o);
  assert.equal(ok.stop, "done");
  assert.deepEqual(o.s.sleeps, [5000]);
  const tooLong = await walk(scripted([limited({ ms: LIMITS.maxRetryAfterMs + 1000 })]), {}, opts());
  assert.equal(tooLong.stop, "failed");
  const o2 = opts();
  const dated = await walk(scripted([limited({ ms: null })]), {}, o2);
  assert.equal(dated.stop, "failed");
  assert.deepEqual(o2.s.sleeps, [1000, 2000, 4000]); // exponential back-off, then give up
  const net = await walk(scripted([() => { throw new RelayRequestError("network", "x"); }]), {}, opts());
  assert.equal(net.stop, "failed");
  const fatal = await walk(scripted([() => { throw new RelayStatus(400, "InvalidParameter", null); }]), {}, opts());
  assert.equal(fatal.stop, "failed");
});

test("sleep rejects at once on an aborted signal; an aborted walk is not retried (finding 3)", async () => {
  const t0 = Date.now();
  await assert.rejects(sleep(60_000, AbortSignal.abort()), { kind: "aborted" });
  assert.ok(Date.now() - t0 < 100);
  const src = scripted([() => { throw new RelayRequestError("aborted", "cancelled"); }]);
  const w = await walk(src, {}, opts());
  assert.equal(w.stop, "aborted");
  assert.equal(src.calls.length, 1);
  const pre = scripted([{ blockIds: [], cursor: "c", more: false }]);
  assert.equal((await walk(pre, {}, { signal: AbortSignal.abort() })).stop, "aborted");
  assert.equal(pre.calls.length, 0);
});

test("fetch: bounded count and concurrency, 404 counted", async () => {
  let inFlight = 0;
  let peak = 0;
  const relay = {
    async get(i) {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight -= 1;
      return i === id(3) ? null : new Uint8Array([1]);
    },
  };
  const ids = Array.from({ length: 50 }, (_, i) => id(i));
  const r = await fetchBlocks(relay, ids, (b, i) => i, { max: 10, concurrency: 4 });
  assert.equal(r.blocks.length + r.notFound.length + r.failed.length, 10);
  assert.deepEqual(r.notFound, [id(3)]);
  assert.ok(r.partial);
  assert.ok(peak <= 4);
});

test("traverse: diamond DAG of depth 40 visits each block once", async () => {
  // Layer k has two blocks, each with both blocks of layer k + 1 as parents: 2^40 paths.
  const name = (k, s) => `${k}-${s}`;
  let calls = 0;
  const visit = async (n) => {
    calls += 1;
    const k = Number(n.split("-")[0]);
    return k >= 40 ? [] : [name(k + 1, 0), name(k + 1, 1)];
  };
  const t = await traverse(name(0, 0), visit);
  assert.equal(t.visited.length, 1 + 2 * 40);
  assert.equal(calls, t.visited.length);
  assert.equal(t.partial, false);
  const bounded = await traverse(name(0, 0), visit, { maxVisited: 10 });
  assert.equal(bounded.visited.length, 10);
  assert.equal(bounded.partial, true);
});
