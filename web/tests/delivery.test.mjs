// Own-block protection until every relay acknowledges, within a bound (ADR 0047): classification of
// PUT answers, the bounds of rule 4 with an injected clock, changes of the relay list, the eviction
// order of rule 8, and the migration of IndexedDB records written before the ADR. The store runs
// over an in-memory IndexedDB double (fake-idb.mjs); no WASM needed.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, test } from "node:test";

import { LIMITS } from "../src/bounds.js";
import {
  ACKNOWLEDGED, applyResults, classifyPut, DELIVERED, deliveryOf, deliveryTargets, GIVEN_UP,
  isStranded, newDelivery, NOT_OWN, PARTIAL, PENDING, protection, reconcile, REFUSED, UNACKNOWLEDGED,
} from "../src/delivery.js";
import { planEviction } from "../src/eviction.js";
import { RelayRequestError } from "../src/http.js";
import { Relay, RelayStatus } from "../src/relay.js";
import { publishAll, RelaySet, retryPlan } from "../src/relays.js";
import { onRelaysChange, saveRelays } from "../src/settings.js";
import { BlockStore, StoreFull } from "../src/store.js";
import { fakeDb } from "./fake-idb.mjs";

const A = "https://a.example.org";
const B = "https://b.example.org";
const C = "https://c.example.org";
const H = 60 * 60 * 1000;
const DAY = 24 * H;
const T0 = 1_800_000_000_000;

const status = (s, name = null) => ({ outcome: "failed", error: new RelayStatus(s, name, null) });
const reqErr = (kind) => ({ outcome: "failed", error: new RelayRequestError(kind, kind) });
const ok = { outcome: "created", error: null };
const own = (delivery, extra = {}) => ({ id: "x", size: 10, own: true, accessed: 0, delivery, ...extra });
const at = (base, r) => ({ base, ...r });

test("classification of PUT answers (rule 3)", () => {
  const cases = [
    [ok, "acknowledged"], [{ outcome: "stored", error: null }, "acknowledged"],
    [{ outcome: "backing-off", error: new Error("backing off") }, "none"],
    [reqErr("aborted"), "none"],
    [reqErr("network"), "transient"], [reqErr("timeout"), "transient"], [reqErr("body-too-large"), "transient"],
    [{ outcome: "failed", error: new Error("InvalidResponse") }, "transient"],
    [status(408), "transient"], [status(429, "RateLimited"), "transient"],
    [status(500), "transient"], [status(502), "transient"], [status(503, "Overloaded"), "transient"],
    [status(504), "transient"], [status(507, "InsufficientStorage"), "transient"],
    [status(400, "TimestampTooFarInFuture"), "transient"],
    [status(400, "InsufficientPow"), "final"], [status(400, "InvalidSignature"), "final"],
    [status(400, null), "final"], // a missing or unparseable error body
    [status(413), "final"], [status(422), "final"], [status(403), "final"], [status(404), "final"],
    [status(301), "final"], [reqErr("redirect"), "final"], // a 3xx (ADR 0030)
  ];
  for (const [r, want] of cases) assert.equal(classifyPut(r), want, `${r.error?.message ?? r.outcome}`);
});

test("publishAll: status, error name and class per relay; a relay backing off is not an attempt", async () => {
  const answers = new Map([
    [A, () => "created"],
    [B, () => { throw new RelayStatus(400, "InsufficientPow", null); }],
    [C, () => { throw new RelayStatus(507, "InsufficientStorage", null); }],
  ]);
  const puts = [];
  const set = new RelaySet([A, B, C], {
    makeRelay: (base) => ({ put: async () => { puts.push(base); return answers.get(base)(); } }),
  });
  const res = await publishAll(set, new Uint8Array(1));
  assert.deepEqual(res.results.map((r) => [r.base, r.status, r.errorName, r.delivery]), [
    [A, null, null, "acknowledged"], [B, 400, "InsufficientPow", "final"], [C, 507, "InsufficientStorage", "transient"],
  ]);
  set.fail(set.entry(C), new RelayStatus(429, "RateLimited", { ms: 60_000 }));
  puts.length = 0;
  const again = await publishAll(set, new Uint8Array(1), { targets: [C] });
  assert.deepEqual(puts, []);
  assert.equal(again.results[0].delivery, "none");
});

const servers = [];
after(() => { for (const s of servers) s.close(); });

test("publishAll over HTTP: the error name of a 400 decides (TimestampTooFarInFuture vs InvalidSignature)", async () => {
  const relay = async (code, body) => {
    const server = createServer((req, res) => { req.resume(); req.on("end", () => res.writeHead(code).end(body)); });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    servers.push(server);
    return `http://127.0.0.1:${server.address().port}`;
  };
  const future = await relay(400, '{"error":"TimestampTooFarInFuture"}');
  const badSig = await relay(400, '{"error":"InvalidSignature"}');
  const tooBig = await relay(413, "");
  const set = new RelaySet([future, badSig, tooBig], { makeRelay: (b) => new Relay(b) });
  const res = await publishAll(set, new Uint8Array(118));
  assert.deepEqual(res.results.map((r) => [r.status, r.errorName, r.delivery]), [
    [400, "TimestampTooFarInFuture", "transient"], [400, "InvalidSignature", "final"], [413, null, "final"],
  ]);
});

test("final answers refuse at once; TimestampTooFarInFuture and 507 stay pending", () => {
  const bases = [A, B, C];
  let d = applyResults(own(newDelivery(bases)), [at(A, ok), at(B, status(400, "InvalidSignature")), at(C, status(422))], bases, T0);
  assert.deepEqual(d.relays.map((e) => e.state), [ACKNOWLEDGED, REFUSED, REFUSED]);
  assert.equal(protection(own(d), bases, T0), DELIVERED);
  d = applyResults(own(newDelivery(bases)), [at(A, ok), at(B, status(413)), at(C, status(400, "TimestampTooFarInFuture"))], bases, T0);
  assert.deepEqual(d.relays.map((e) => e.state), [ACKNOWLEDGED, REFUSED, PENDING]);
  d = applyResults(own(newDelivery(bases)), [at(A, ok), at(B, status(507)), at(C, status(301))], bases, T0);
  assert.deepEqual(d.relays.map((e) => e.state), [ACKNOWLEDGED, PENDING, REFUSED]);
  assert.equal(d.relays[1].attempts, 1);
  assert.equal(protection(own(d), bases, T0), PARTIAL);
  assert.deepEqual(deliveryTargets(own(d), bases, T0), [B]);
  // Not sent: not an attempt.
  const n = applyResults(own(d), [at(B, { outcome: "backing-off", error: new Error("x") }), at(B, reqErr("aborted"))], bases, T0 + 1);
  assert.equal(n.relays[1].attempts, 1);
});

test("first bound: at least N attempts AND at least T since the first (503 relay)", () => {
  const bases = [A, B];
  let d = applyResults(own(newDelivery(bases)), [at(A, ok), at(B, status(503))], bases, T0);
  // Four more attempts within an hour: five attempts, but not 24 h yet.
  for (let i = 1; i <= 4; i += 1) d = applyResults(own(d), [at(B, status(503))], bases, T0 + i * 10 * 60_000);
  assert.equal(d.relays[1].attempts, LIMITS.publishMinAttempts);
  assert.equal(protection(own(d), bases, T0 + DAY - 1), PARTIAL);
  assert.equal(protection(own(d), bases, T0 + DAY), DELIVERED); // both conditions hold: given up
  // 24 h with fewer than five attempts: still pending (the client was closed most of the time).
  let e = applyResults(own(newDelivery(bases)), [at(A, ok), at(B, status(503))], bases, T0);
  for (let i = 1; i <= 3; i += 1) e = applyResults(own(e), [at(B, reqErr("network"))], bases, T0 + i * DAY);
  assert.equal(e.relays[1].attempts, 4);
  assert.equal(protection(own(e), bases, T0 + 4 * DAY), PARTIAL);
  e = applyResults(own(e), [at(B, status(503))], bases, T0 + 4 * DAY);
  assert.equal(e.relays[1].state, GIVEN_UP);
  assert.equal(protection(own(e), bases, T0 + 4 * DAY), DELIVERED);
  // A later acknowledgement of a given-up relay counts; a failure does not protect again (rule 5).
  const back = applyResults(own(e), [at(B, status(503))], bases, T0 + 5 * DAY);
  assert.equal(back.relays[1].state, GIVEN_UP);
  assert.equal(applyResults(own(e), [at(B, ok)], bases, T0 + 5 * DAY).relays[1].state, ACKNOWLEDGED);
});

test("second bound: M after the first acknowledgement, with no attempt at all", () => {
  const bases = [A, B];
  const d = applyResults(own(newDelivery(bases)), [at(A, ok)], bases, T0); // B never tried
  assert.equal(d.relays[1].attempts, 0);
  assert.equal(protection(own(d), bases, T0 + LIMITS.publishMaxWaitMs - 1), PARTIAL);
  assert.equal(protection(own(d), bases, T0 + LIMITS.publishMaxWaitMs), DELIVERED);
  assert.deepEqual(deliveryTargets(own(d), bases, T0 + LIMITS.publishMaxWaitMs), []);
  // Acknowledged never goes back to pending while the relay stays in the list (rule 1).
  const later = applyResults(own(d), [at(A, status(503)), at(A, status(400, "InvalidSignature"))], bases, T0 + 1);
  assert.equal(later.relays[0].state, ACKNOWLEDGED);
  assert.equal(later.relays[0].ackedAt, T0);
});

test("a block no relay acknowledged keeps unbounded protection; stranded when every relay refused or gave up", () => {
  const bases = [A, B];
  let d = newDelivery(bases);
  for (let i = 0; i < 10; i += 1) d = applyResults(own(d), [at(A, status(503)), at(B, status(400, "InsufficientPow"))], bases, T0 + i * 3 * DAY);
  const now = T0 + 60 * DAY;
  assert.equal(protection(own(d), bases, now), UNACKNOWLEDGED);
  assert.deepEqual(d.relays.map((e) => e.state), [GIVEN_UP, REFUSED]);
  assert.equal(isStranded(own(d), bases, now), true);
  assert.deepEqual(deliveryTargets(own(d), bases, now), [A]); // given up, still tried; refused is not
  assert.equal(isStranded(own(newDelivery(bases)), bases, now), false);
  assert.equal(isStranded({ id: "f", own: false }, bases, now), false);
});

test("eviction order (rule 8): fetched LRU, delivered own LRU, partial only for a new own block, never unacknowledged", () => {
  const bases = [A, B];
  const delivered = (id, accessed) => own(applyResults(own(newDelivery(bases)), [at(A, ok), at(B, ok)], bases, T0), { id, accessed });
  const partial = (id, ackAt, accessed) => own(applyResults(own(newDelivery(bases)), [at(A, ok)], bases, ackAt), { id, accessed });
  const metas = [
    { id: "f-new", size: 10, own: false, accessed: 9 },
    { id: "f-old", size: 10, own: false, accessed: 1 },
    delivered("d-new", 8), delivered("d-old", 2),
    partial("p-young", T0 + 2 * H, 0), partial("p-old", T0 + H, 7),
    own(newDelivery(bases), { id: "unacked", accessed: 0 }),
  ];
  const ctx = { bases, now: T0 + 3 * H };
  const plan = (incoming, maxBlocks) => planEviction(metas, incoming, { maxBlocks, maxBytes: 1e9 }, ctx);
  assert.deepEqual(plan({ size: 10, own: false }, 7).drop, ["f-old"]);
  assert.deepEqual(plan({ size: 10, own: false }, 4).drop, ["f-old", "f-new", "d-old", "d-new"]);
  // A partly delivered block never gives way to a fetched block.
  assert.deepEqual(plan({ size: 10, own: false }, 2), { drop: [], accept: false });
  // For a new own block: partial ones, oldest first acknowledgement first, never the unacknowledged one.
  assert.deepEqual(plan({ size: 10, own: true }, 2), { drop: ["f-old", "f-new", "d-old", "d-new", "p-old", "p-young"], accept: true });
  assert.deepEqual(plan({ size: 10, own: true }, 3).drop, ["f-old", "f-new", "d-old", "d-new", "p-old"]);
  assert.equal(protection(metas[0], bases, 0), NOT_OWN);
});

test("relay list changes (rules 6, 7): removal unprotects nothing it should not, addition targets protected blocks only", () => {
  // Acknowledged only by A; B pending. Removing A makes it unacknowledged again, sent to B and C.
  let d = applyResults(own(newDelivery([A, B])), [at(A, ok), at(B, status(503))], [A, B], T0);
  const removed = reconcile(own(d), [B, C], T0 + H);
  assert.deepEqual(removed.relays.map((e) => [e.base, e.state]), [[B, PENDING], [C, PENDING]]);
  assert.equal(removed.relays[0].attempts, 1); // its own count is kept
  assert.equal(protection(own(removed), [B, C], T0 + H), UNACKNOWLEDGED);
  assert.deepEqual(deliveryTargets(own(removed), [B, C], T0 + H), [B, C]);
  // Addition: a delivered block does not target C; a partial one does, without resetting M.
  const delivered = applyResults(own(newDelivery([A, B])), [at(A, ok), at(B, ok)], [A, B], T0);
  assert.deepEqual(reconcile(own(delivered), [A, B, C], T0 + H).relays.map((e) => e.base), [A, B]);
  d = applyResults(own(newDelivery([A, B])), [at(A, ok)], [A, B], T0);
  const added = reconcile(own(d), [A, B, C], T0 + H);
  assert.deepEqual(added.relays.map((e) => [e.base, e.state, e.attempts]), [[A, ACKNOWLEDGED, 0], [B, PENDING, 0], [C, PENDING, 0]]);
  // The second bound is not reset by the addition: C is given up with B, M after A's acknowledgement.
  assert.equal(protection(own(added), [A, B, C], T0 + LIMITS.publishMaxWaitMs), DELIVERED);
  assert.deepEqual(deliveryTargets(own(added), [A, B, C], T0 + LIMITS.publishMaxWaitMs), []);
  // Added after that bound: the block is no longer protected, so C is not added at all.
  const late = reconcile(own(d), [A, B, C], T0 + LIMITS.publishMaxWaitMs);
  assert.deepEqual(late.relays.map((e) => [e.base, e.state]), [[A, ACKNOWLEDGED], [B, GIVEN_UP]]);
  // Idempotent.
  assert.deepEqual(reconcile(own(added), [A, B, C], T0 + H), added);
});

test("settings hook: called on a change of the relay list only", () => {
  const mem = new Map();
  const storage = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  const calls = [];
  const off = onRelaysChange((next, prev) => { calls.push([next, prev]); });
  saveRelays(A, storage);
  saveRelays(A, storage);
  saveRelays(`${A}\n${B}`, storage);
  off();
  saveRelays(C, storage);
  assert.deepEqual(calls, [[[A], ["http://127.0.0.1:8080"]], [[A, B], [A]]]);
});

function clock(t) {
  const c = () => c.t;
  c.t = t;
  return c;
}
const bytes = (n) => new Uint8Array(n).fill(7);
const small = { ...LIMITS, storeMaxBlocks: 2, storeMaxBytes: 1e9 };

test("store: a block acknowledged by one relay of three stays when the store fills with fetched blocks", async () => {
  const now = clock(T0);
  const store = new BlockStore(fakeDb(), small, { bases: [A, B, C], now });
  await store.put("own", bytes(10), { own: true });
  await store.recordPublish("own", [at(A, ok), at(B, status(503)), at(C, reqErr("network"))]);
  await store.put("f1", bytes(10));
  await store.put("f2", bytes(10)); // f1 evicted, not the own block
  assert.deepEqual((await store.list()).map((m) => m.id).sort(), ["f2", "own"]);
  const solo = new BlockStore(fakeDb(), { ...small, storeMaxBlocks: 1 }, { bases: [A, B, C], now });
  await solo.put("own", bytes(10), { own: true });
  await solo.recordPublish("own", [at(A, ok)]);
  await assert.rejects(solo.put("f", bytes(10)), StoreFull);
  // Step 3: only a new own block makes it give way.
  assert.equal(await solo.put("own2", bytes(10), { own: true }), "stored");
  assert.deepEqual((await solo.list()).map((m) => m.id), ["own2"]);
});

test("store: removing the only acknowledging relay protects the block again and counts it against the cap", async () => {
  const now = clock(T0);
  const store = new BlockStore(fakeDb(), { ...LIMITS, storeMaxPending: 1 }, { bases: [A, B], now });
  await store.put("x", bytes(10), { own: true });
  await store.recordPublish("x", [at(A, ok), at(B, status(400, "InsufficientPow"))]);
  assert.equal(await store.put("y", bytes(10), { own: true }), "stored"); // x no longer counts
  await store.recordPublish("y", [at(A, ok), at(B, ok)]);
  await store.setRelays([B, C]);
  const x = (await store.list()).find((m) => m.id === "x");
  assert.deepEqual(x.delivery.relays.map((e) => [e.base, e.state]), [[B, REFUSED], [C, PENDING]]);
  // y is still held by B: delivered, so C is not one of its targets.
  assert.deepEqual(retryPlan(await store.list(), [B, C], { now: now() }), [{ id: "x", targets: [C] }]);
  await assert.rejects(store.put("z", bytes(10), { own: true }), StoreFull);
  // A relay added later is pending only for the blocks protected then.
  await store.recordPublish("x", [at(C, ok)]);
  await store.recordPublish("y", [at(B, ok), at(C, ok)]);
  await store.setRelays([B, C, A]);
  const after = new Map((await store.list()).map((m) => [m.id, m.delivery.relays.map((e) => e.base)]));
  assert.deepEqual(after.get("x"), [B, C]); // delivered (B refused, C acknowledged): not a target of A
  assert.deepEqual(after.get("y"), [B, C]);
  assert.equal(await store.delete("x"), true);
  assert.equal(await store.put("z", bytes(10), { own: true }), "stored");
});

test("store: migration of records written before ADR 0047", async () => {
  const db = fakeDb();
  const meta = db.data.get("blockMeta");
  meta.set("acked", { id: "acked", size: 10, own: true, acked: true, accessed: 1, failedOn: [B, "https://gone.example.org"] });
  meta.set("full", { id: "full", size: 10, own: true, acked: true, accessed: 2 });
  meta.set("pending", { id: "pending", size: 10, own: true, acked: false, accessed: 3 });
  meta.set("fetched", { id: "fetched", size: 10, own: false, acked: false, accessed: 4 });
  db.data.get("stats").set("totals", { name: "totals", count: 4, bytes: 40, pending: 1 });
  const bases = [A, B];
  const now = clock(T0);
  // Before the rewrite, the old records are read through the ADR mapping: still protected as before.
  const old = [...meta.values()];
  assert.deepEqual(old.map((m) => protection(m, bases, T0)), [PARTIAL, DELIVERED, UNACKNOWLEDGED, NOT_OWN]);
  assert.deepEqual(deliveryOf(old[0], bases, T0).relays.map((e) => [e.base, e.state]), [[A, ACKNOWLEDGED], [B, PENDING]]);
  const store = new BlockStore(db, LIMITS, { bases, now });
  await store.setRelays(bases);
  const after = new Map((await store.list()).map((m) => [m.id, m]));
  for (const m of after.values()) {
    if (m.own) assert.ok(!("acked" in m) && !("failedOn" in m), m.id); // fetched records are left as they are
  }
  assert.deepEqual(after.get("acked").delivery.relays.map((e) => [e.base, e.state, e.ackedAt]), [[A, ACKNOWLEDGED, T0], [B, PENDING, null]]);
  assert.deepEqual(after.get("full").delivery.relays.map((e) => e.state), [ACKNOWLEDGED, ACKNOWLEDGED]);
  assert.deepEqual(after.get("pending").delivery.relays.map((e) => e.state), [PENDING, PENDING]);
  assert.equal(after.get("fetched").delivery, undefined);
  assert.deepEqual(db.data.get("stats").get("totals"), { name: "totals", count: 4, bytes: 40, pending: 1 });
  // The migration time starts the second bound.
  assert.equal(protection(after.get("acked"), bases, T0 + LIMITS.publishMaxWaitMs), DELIVERED);
});
