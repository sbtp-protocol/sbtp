// Response checks (ADR 0029 rules 8, 13, 14), URL rule, eviction plan, statistics.
import assert from "node:assert/strict";
import { test } from "node:test";

import { planEviction } from "../src/eviction.js";
import { checkRelayUrl } from "../src/http.js";
import { errorName, InvalidResponse, isCursorSyntax, parseInfo, parsePage, parseRetryAfter, resolveDifficulty, sendingDifficulty } from "../src/relay.js";
import { percentile, summarize } from "../src/stats.js";

const enc = (v) => new TextEncoder().encode(typeof v === "string" ? v : JSON.stringify(v));
const ID = "0".repeat(60) + "abcd";

test("info: required members checked, optional ones dropped when out of range", () => {
  const ok = parseInfo(enc({ min_pow_difficulty: 16, max_future_ms: 300000, max_query_limit: 5000, block_ttl_ms: null, x: 1 }));
  assert.deepEqual({ ...ok }, { minPowDifficulty: 16, maxFutureMs: 300000, blockTtlMs: null });
  for (const bad of [
    "[]", "nope", { max_future_ms: 1 }, { min_pow_difficulty: 257, max_future_ms: 1 },
    { min_pow_difficulty: 1.5, max_future_ms: 1 }, { min_pow_difficulty: "16", max_future_ms: 1 },
    { min_pow_difficulty: 16, max_future_ms: -1 }, { min_pow_difficulty: 16 },
    { min_pow_difficulty: 16, max_future_ms: 2 ** 64 },
  ]) {
    assert.throws(() => parseInfo(enc(bad)), InvalidResponse, JSON.stringify(bad));
  }
  assert.equal(parseInfo(enc({ min_pow_difficulty: 0, max_future_ms: 2 ** 63 })).maxFutureMs, 2 ** 63);
});

test("sending difficulty: bounded when read from /info, not when explicit", () => {
  assert.equal(sendingDifficulty({ minPowDifficulty: 24 }, null), 24);
  assert.throws(() => sendingDifficulty({ minPowDifficulty: 25 }, null), InvalidResponse);
  assert.throws(() => sendingDifficulty({ minPowDifficulty: 256 }, undefined), InvalidResponse);
  assert.equal(sendingDifficulty({ minPowDifficulty: 256 }, 30), 30);
});

test("an explicit difficulty does not read /info (finding 10)", async () => {
  let infoCalls = 0;
  const relay = { async info() { infoCalls += 1; throw new Error("relay down"); } };
  assert.equal(await resolveDifficulty(relay, 12), 12);
  assert.equal(await resolveDifficulty(relay, 0), 0);
  assert.equal(infoCalls, 0);
  for (const bad of [NaN, -1, 1.5, 257]) await assert.rejects(resolveDifficulty(relay, bad), RangeError);
  await assert.rejects(resolveDifficulty(relay, null), /relay down/);
  assert.equal(infoCalls, 1);
  const ok = { async info() { return { minPowDifficulty: 16 }; } };
  assert.equal(await resolveDifficulty(ok, null), 16);
});

test("query page: shape, limit, identifiers and cursor", () => {
  const page = (o) => enc({ block_ids: [ID], cursor: "abc_-9Z", more: false, ...o });
  assert.deepEqual(parsePage(page({}), 1), { blockIds: [ID], cursor: "abc_-9Z", more: false });
  assert.equal(parsePage(page({ block_ids: [ID, ID] }), 2).blockIds.length, 2); // duplicates allowed
  const bad = [
    [page({ block_ids: [ID, ID] }), 1], // more than the limit sent
    [page({ block_ids: Array(101).fill(ID) }), undefined], // default limit 100
    [page({ block_ids: [ID.toUpperCase()] }), 10],
    [page({ block_ids: [ID + "0"] }), 10],
    [page({ block_ids: [1] }), 10],
    [page({ cursor: "" }), 10],
    [page({ cursor: "a".repeat(129) }), 10],
    [page({ cursor: "a/b" }), 10],
    [page({ more: "false" }), 10],
    [enc([]), 10],
    [enc("{"), 10],
    [new Uint8Array([0xff, 0xfe]), 10],
  ];
  for (const [bytes, limit] of bad) assert.throws(() => parsePage(bytes, limit), InvalidResponse);
  assert.ok(parsePage(page({ cursor: "a".repeat(128), block_ids: [] }), 10));
  assert.ok(isCursorSyntax("A-z_0") && !isCursorSyntax(null));
});

test("Retry-After: seconds only; a date or garbage gives no delay", () => {
  assert.equal(parseRetryAfter(null), null);
  assert.deepEqual(parseRetryAfter("120"), { ms: 120000 });
  assert.deepEqual(parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"), { ms: null });
  assert.deepEqual(parseRetryAfter("-1"), { ms: null });
  assert.deepEqual(parseRetryAfter("99999999999999999999"), { ms: null });
});

test("error body: name or null", () => {
  assert.equal(errorName(enc({ error: "InvalidCursor", message: "x" })), "InvalidCursor");
  assert.equal(errorName(enc("<html>")), null);
  assert.equal(errorName(null), null);
});

test("relay URL: https anywhere, http on loopback only, no credentials/query/fragment", () => {
  assert.equal(checkRelayUrl("http://127.0.0.1:8080/"), "http://127.0.0.1:8080");
  assert.equal(checkRelayUrl("https://relay.example/sbtp/"), "https://relay.example/sbtp");
  for (const bad of ["http://relay.example", "ftp://127.0.0.1", "https://u:p@relay.example",
    "https://relay.example/?a=1", "https://relay.example/#x", "nope", "javascript:alert(1)"]) {
    assert.throws(() => checkRelayUrl(bad), { name: "RelayRequestError" }, bad);
  }
});

test("eviction: fetched first (LRU), then acknowledged own, never pending own", () => {
  const m = (id, own, acked, accessed, size = 10) => ({ id, own, acked, accessed, size });
  const metas = [m("f-old", false, false, 1), m("f-new", false, false, 5), m("own-acked", true, true, 0), m("own-pending", true, false, 0)];
  const plan = (incoming, maxBlocks) => planEviction(metas, incoming, { maxBlocks, maxBytes: 1e9 });
  assert.deepEqual(plan({ size: 10, own: false }, 4), { drop: ["f-old"], accept: true });
  assert.deepEqual(plan({ size: 10, own: false }, 2), { drop: ["f-old", "f-new", "own-acked"], accept: true });
  assert.deepEqual(plan({ size: 10, own: false }, 1), { drop: [], accept: false });
  const own = plan({ size: 10, own: true }, 1); // own blocks are always kept and accepted
  assert.equal(own.accept, true);
  assert.ok(!own.drop.includes("own-pending"));
  assert.deepEqual(planEviction(metas, { size: 25, own: false }, { maxBlocks: 99, maxBytes: 50 }).drop, ["f-old", "f-new"]);
});

test("statistics: nearest-rank percentiles", () => {
  const v = Array.from({ length: 20 }, (_, i) => i + 1);
  assert.equal(percentile(v, 50), 10);
  assert.equal(percentile(v, 95), 19);
  const s = summarize([{ ms: 10, attempts: 1000 }, { ms: 30, attempts: 3000 }]);
  assert.equal(s.medianMs, 10);
  assert.equal(s.hashesPerSecond, 100000);
});
