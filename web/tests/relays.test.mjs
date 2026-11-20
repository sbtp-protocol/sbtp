// Several relays (relays.js): publish to all, read with failover, merged /query walks, health and
// bounds, against fake relays over real HTTP on loopback: one healthy, one that answers 404, one
// hostile that serves a wrong block (and asks for difficulty 30), one slow (past the deadline).
// Blocks are built, mined and verified with sbtp-wasm; needs web/pkg (web/build.sh).
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { LIMITS } from "../src/bounds.js";
import { RelayRequestError } from "../src/http.js";
import { Relay } from "../src/relay.js";
import {
  fetchBlocksFrom, fetchOne, isRelayFault, parseRelayList, publishAll, publishDifficulty, RelaySet,
  retryPlan, retryTargets, walkAll,
} from "../src/relays.js";
import { DEFAULT_RELAYS, loadRelays, saveRelays } from "../src/settings.js";

const wasmPath = new URL("../pkg/sbtp_wasm_bg.wasm", import.meta.url);
const skip = existsSync(wasmPath) ? false : "web/pkg missing: run web/build.sh";

let w;
let key;
const servers = [];

/**
 * A fake relay. `mode`: "healthy" (stores PUTs, serves them, /query over them in pages of 2),
 * "notfound" (accepts PUTs, never serves: 404), "hostile" (serves `wrong` for every id, lists
 * ids it does not hold, /info difficulty 30), "slow" (answers after `delayMs`), "busy" (429 with
 * Retry-After 120). Records every request as "METHOD path?query".
 */
async function fakeRelay(mode, { difficulty = 8, wrong = null, delayMs = 400, listed = [] } = {}) {
  const blocks = new Map();
  const order = [];
  const hits = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    hits.push(`${req.method} ${url.pathname}${url.search}`);
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const answer = () => {
        if (mode === "busy") {
          res.writeHead(429, { "Retry-After": "120" }).end('{"error":"RateLimited"}');
          return;
        }
        if (url.pathname === "/sbtp/v1/info") {
          res.writeHead(200).end(JSON.stringify({
            min_pow_difficulty: mode === "hostile" ? 30 : difficulty, max_future_ms: 300000,
          }));
        } else if (url.pathname === "/sbtp/v1/block" && req.method === "PUT") {
          const bytes = Buffer.concat(chunks);
          const id = w.blockIdHex(new Uint8Array(bytes));
          const had = blocks.has(id);
          if (!had) {
            blocks.set(id, bytes);
            order.push(id);
          }
          res.writeHead(had ? 200 : 201).end("{}");
        } else if (url.pathname.startsWith("/sbtp/v1/block/")) {
          const id = url.pathname.slice("/sbtp/v1/block/".length);
          if (mode === "hostile") res.writeHead(200).end(wrong);
          else if (mode === "notfound" || !blocks.has(id)) res.writeHead(404).end('{"error":"NotFound"}');
          else res.writeHead(200).end(blocks.get(id));
        } else if (url.pathname === "/sbtp/v1/query") {
          const all = mode === "hostile" ? listed : mode === "notfound" ? [] : order;
          const cursor = url.searchParams.get("cursor");
          const prefix = `${mode}${port()}x`;
          if (cursor !== null && !cursor.startsWith(prefix)) {
            res.writeHead(400).end('{"error":"InvalidCursor"}');
            return;
          }
          const from = cursor === null ? 0 : Number(cursor.slice(prefix.length));
          const page = all.slice(from, from + 2);
          res.writeHead(200).end(JSON.stringify({
            block_ids: page, cursor: `${prefix}${from + page.length}`, more: from + page.length < all.length,
          }));
        } else {
          res.writeHead(404).end();
        }
      };
      if (mode === "slow") setTimeout(answer, delayMs);
      else answer();
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = () => server.address().port;
  servers.push(server);
  return { base: `http://127.0.0.1:${port()}`, hits, blocks, order };
}

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

async function makeBlock(text, d = 8) {
  const { signBlock } = await import("../src/keys.js");
  const block = w.buildUnsignedBlock(key.publicKey, BigInt(Date.now()), 0n, new Uint8Array(0), new TextEncoder().encode(text));
  while (w.mineSlice(block, d, 1 << 16) === undefined) { /* next slice */ }
  const signed = await signBlock(key, block);
  return { bytes: signed, id: w.verifySubmitted(signed, d).idHex };
}

const validate = (bytes, id) => w.verifyFetched(bytes, 0, id);
/** Relays with a short deadline, so that the slow one times out quickly. */
const makeRelay = (b) => new Relay(b, { deadlineMs: 150 });
const fastWalk = { sleep: async () => {}, random: () => 0 };

before(async () => {
  if (skip) return;
  w = await import("../src/wasm.js");
  await w.loadSbtp(readFileSync(wasmPath));
  key = await newKey();
});

after(() => {
  for (const s of servers) {
    s.closeAllConnections?.();
    s.close();
  }
});

test("relay list: parsing, deduplication, bounds; saved settings", () => {
  assert.deepEqual(parseRelayList("http://127.0.0.1:1/, http://127.0.0.1:1\nhttps://relay.example.org"),
    ["http://127.0.0.1:1", "https://relay.example.org"]);
  assert.throws(() => parseRelayList(""), { kind: "bad-url" });
  assert.throws(() => parseRelayList("http://relay.example.org"), /loopback/); // plain HTTP off loopback
  assert.throws(() => parseRelayList("https://a.example.org?x=1"), { kind: "bad-url" });
  const nine = Array.from({ length: 9 }, (_, i) => `https://r${i}.example.org`).join(" ");
  assert.throws(() => parseRelayList(nine), /at most 8/);
  assert.throws(() => parseRelayList(`https://${"a".repeat(3000)}.example.org`), /longer than/);

  const mem = new Map();
  const storage = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  assert.deepEqual(loadRelays(storage), [...DEFAULT_RELAYS]);
  assert.deepEqual(saveRelays("https://a.example.org https://b.example.org", storage), ["https://a.example.org", "https://b.example.org"]);
  assert.deepEqual(loadRelays(storage), ["https://a.example.org", "https://b.example.org"]);
  mem.set("sbtp-web.relays", '["http://relay.example.org"]'); // edited by hand: refused again on load
  assert.deepEqual(loadRelays(storage), [...DEFAULT_RELAYS]);
  mem.set("sbtp-web.relays", "{not json");
  assert.deepEqual(loadRelays(storage), [...DEFAULT_RELAYS]);
  const broken = { getItem: () => { throw new Error("SecurityError"); }, setItem: () => { throw new Error("QuotaExceeded"); } };
  assert.deepEqual(loadRelays(broken), [...DEFAULT_RELAYS]);
  assert.deepEqual(saveRelays("https://a.example.org", broken), ["https://a.example.org"]);
});

test("publish: one mining at the highest usable /info difficulty, hostile and slow relays handled", { skip }, async () => {
  const a = await fakeRelay("healthy", { difficulty: 8 });
  const b = await fakeRelay("healthy", { difficulty: 10 });
  const hostile = await fakeRelay("hostile");
  const slow = await fakeRelay("slow");
  const set = new RelaySet([a.base, hostile.base, slow.base, b.base], { makeRelay });
  const plan = await publishDifficulty(set, null);
  assert.equal(plan.difficulty, 10); // the max of 8 and 10; 30 is above the maximum of 24
  assert.deepEqual(plan.skipped.map((s) => s.base), [hostile.base]);
  assert.deepEqual(plan.infoFailed.map((f) => f.base), [slow.base]); // timed out: still a target
  assert.equal(plan.infoFailed[0].error.kind, "timeout");
  assert.deepEqual(plan.targets, [a.base, slow.base, b.base]);

  const blk = await makeBlock("published twice", plan.difficulty);
  const res = await publishAll(set, blk.bytes, { targets: plan.targets });
  assert.deepEqual(res.acked, [a.base, b.base]);
  assert.deepEqual(res.failed, [slow.base]);
  assert.deepEqual(res.results.map((r) => r.outcome), ["created", "failed", "created"]);
  assert.ok(!hostile.hits.some((h) => h.startsWith("PUT")), "no PUT to a skipped relay");
  const again = await publishAll(set, blk.bytes, { targets: [a.base] });
  assert.deepEqual(again.results.map((r) => r.outcome), ["stored"]);

  // An explicit difficulty reads no /info and targets every relay.
  const n = a.hits.length;
  const explicit = await publishDifficulty(set, 12);
  assert.equal(explicit.difficulty, 12);
  assert.deepEqual(explicit.targets, set.bases);
  assert.equal(a.hits.length, n);
  await assert.rejects(publishDifficulty(set, 257), RangeError);

  // No usable difficulty at all: refused, as with one relay.
  await assert.rejects(publishDifficulty(new RelaySet([hostile.base], { makeRelay }), null), /no relay gave a usable difficulty/);
});

test("read: failover over 404, hostile and slow relays; every block validated", { skip }, async () => {
  const good = await fakeRelay("healthy");
  const blk = await makeBlock("the real one");
  const other = await makeBlock("a wrong block");
  const missing = await fakeRelay("notfound");
  const hostile = await fakeRelay("hostile", { wrong: Buffer.from(other.bytes) });
  const slow = await fakeRelay("slow");
  await publishAll(new RelaySet([good.base]), blk.bytes);

  const set = new RelaySet([hostile.base, missing.base, slow.base, good.base], { makeRelay });
  const r = await fetchOne(set, blk.id, validate);
  assert.equal(r.status, "ok");
  assert.equal(r.base, good.base);
  assert.equal(r.block.idHex, blk.id);
  assert.equal(new TextDecoder().decode(r.block.payload), "the real one");
  assert.equal(r.tried[0].error.name, "InvalidBlock");
  assert.equal(r.tried[0].error.cause.name, "BlockIdMismatch"); // R1: never trusted, never used
  assert.ok(r.tried[1].notFound);
  assert.equal(r.tried[2].error.kind, "timeout");
  // 404 is not a fault; a wrong block and a timeout are.
  assert.deepEqual(set.entries.map((e) => e.failures), [1, 0, 1, 0]);

  // Every relay answering 404: not-found; a hostile relay alone: failed, nothing returned.
  assert.equal((await fetchOne(new RelaySet([missing.base]), blk.id, validate)).status, "not-found");
  const bad = await fetchOne(new RelaySet([hostile.base]), blk.id, validate);
  assert.equal(bad.status, "failed");
  assert.equal(bad.block, undefined);

  // A block below the client's own floor: refused by policy, no other relay asked, nobody blamed.
  const both = new RelaySet([good.base, missing.base]);
  const before = missing.hits.length;
  const floor = await fetchOne(both, blk.id, (bytes, id) => w.verifyFetched(bytes, 255, id));
  assert.equal(floor.status, "refused");
  assert.equal(missing.hits.length, before);
  assert.equal(both.entries[0].failures, 0);
});

test("health: a relay that keeps failing is left aside with a back-off; Retry-After is obeyed", { skip }, async () => {
  const good = await fakeRelay("healthy");
  const blk = await makeBlock("health");
  const other = await makeBlock("wrong again");
  const hostile = await fakeRelay("hostile", { wrong: Buffer.from(other.bytes) });
  await publishAll(new RelaySet([good.base]), blk.bytes);
  let clock = 1_000_000;
  const set = new RelaySet([hostile.base, good.base], { now: () => clock, random: () => 1 });
  for (let i = 0; i < LIMITS.relayFailThreshold; i += 1) {
    assert.equal((await fetchOne(set, blk.id, validate)).base, good.base);
  }
  const asked = hostile.hits.length;
  assert.equal(set.available().length, 1);
  assert.match(set.describe()[0], /backing off 1 s \(InvalidBlock/);
  await fetchOne(set, blk.id, validate);
  assert.equal(hostile.hits.length, asked, "a relay backing off is not asked");
  clock += 1_001;
  await fetchOne(set, blk.id, validate);
  assert.equal(hostile.hits.length, asked + 1, "asked again after the back-off");
  assert.equal(set.waitMs(set.entries[0]), 2_000); // second back-off step

  const busy = await fakeRelay("busy");
  const two = new RelaySet([busy.base, good.base], { now: () => clock });
  assert.equal((await fetchOne(two, blk.id, validate)).base, good.base);
  assert.equal(two.waitMs(two.entries[0]), 120_000); // one 429 is enough: Retry-After holds it back
  const put = await publishAll(two, blk.bytes);
  assert.deepEqual(put.results.map((r) => r.outcome), ["backing-off", "stored"]);
  assert.equal(busy.hits.filter((h) => h.startsWith("PUT")).length, 0);
  assert.equal((await fetchOne(new RelaySet([busy.base], { now: () => clock }), blk.id, validate)).status, "failed");

  assert.ok(!isRelayFault(new RelayRequestError("aborted", "cancelled")));
});

test("walk: ids merged across relays, deduplicated, cursors kept per relay", { skip }, async () => {
  const a = await fakeRelay("healthy");
  const b = await fakeRelay("healthy");
  const blocks = [];
  for (let i = 0; i < 5; i += 1) blocks.push(await makeBlock(`walk ${i}`));
  for (const x of blocks.slice(0, 3)) await publishAll(new RelaySet([a.base]), x.bytes);
  for (const x of blocks.slice(1, 5)) await publishAll(new RelaySet([b.base]), x.bytes);
  const missing = await fakeRelay("notfound");
  const set = new RelaySet([a.base, missing.base, b.base]);
  const r = await walkAll(set, {}, fastWalk);
  assert.deepEqual(r.ids, blocks.map((x) => x.id)); // a's order first, then what only b holds
  assert.equal(r.partial, false);
  assert.deepEqual(r.runs.map((x) => x.stop), ["done", "done", "done"]);
  // Each relay got only cursors it issued itself.
  for (const s of [a, b]) {
    const sent = s.hits.filter((h) => h.includes("cursor=")).map((h) => h.split("cursor=")[1]);
    assert.ok(sent.length > 0 && sent.every((c) => c.startsWith(`healthy${new URL(s.base).port}x`)), String(sent));
  }
  assert.equal(r.cursors.get(a.base), `healthy${new URL(a.base).port}x3`);
  assert.equal(r.cursors.get(b.base), `healthy${new URL(b.base).port}x4`);

  // A poll from the cursors: only what was stored since, from the relay that has it.
  const late = await makeBlock("late");
  await publishAll(new RelaySet([b.base]), late.bytes);
  const poll = await walkAll(set, {}, { ...fastWalk, cursors: r.cursors });
  assert.deepEqual(poll.ids, [late.id]);

  // The overall bound: 3 ids in all; the relay cut keeps its starting cursor.
  const cut = await walkAll(set, {}, { ...fastWalk, maxTotalIds: 3 });
  assert.deepEqual(cut.ids, blocks.slice(0, 3).map((x) => x.id));
  assert.equal(cut.partial, true);
  assert.equal(cut.cursors.get(b.base), null);

  // A hostile relay listing ids nobody holds: they are only hints; fetching them is bounded.
  const fake = Array.from({ length: 6 }, (_, i) => (i + 1).toString(16).padStart(64, "0"));
  const hostile = await fakeRelay("hostile", { wrong: Buffer.from(blocks[0].bytes), listed: fake });
  const mixed = new RelaySet([hostile.base, a.base, missing.base]);
  const listed = await walkAll(mixed, {}, fastWalk);
  assert.equal(listed.ids.length, 6 + 3);
  const got = await fetchBlocksFrom(mixed, listed.ids, validate, { maxAttempts: 10 });
  const gets = [hostile, a, missing].reduce((n, s) => n + s.hits.filter((h) => h.startsWith("GET /sbtp/v1/block/")).length, 0);
  assert.ok(gets <= 10, `${gets} GETs for a budget of 10`);
  assert.equal(got.partial, true);
  assert.ok(got.blocks.every((x) => blocks.some((y) => y.id === x.idHex)));
});

test("fetch: bounded per operation, at most `concurrency` in flight in all", { skip }, async () => {
  const slow = await fakeRelay("slow", { delayMs: 30 });
  let inFlight = 0;
  let peak = 0;
  const counting = (b) => {
    const r = new Relay(b);
    const get = r.get.bind(r);
    r.get = async (...args) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      try {
        return await get(...args);
      } finally {
        inFlight -= 1;
      }
    };
    return r;
  };
  const set = new RelaySet([slow.base], { makeRelay: counting });
  const ids = Array.from({ length: 30 }, (_, i) => (i + 1).toString(16).padStart(64, "0"));
  const got = await fetchBlocksFrom(set, ids, validate, { max: 12, concurrency: 3 });
  assert.equal(got.notFound.length, 12);
  assert.equal(got.partial, true); // 30 ids, 12 fetched
  assert.ok(peak <= 3, `peak ${peak}`);
});

test("retry plan: pending blocks to every relay, partial ones to the relays that failed", () => {
  const bases = ["https://a.example.org", "https://b.example.org"];
  assert.deepEqual(retryTargets({ own: true, acked: false }, bases), bases);
  assert.deepEqual(retryTargets({ own: true, acked: true, failedOn: ["https://b.example.org", "https://gone.example.org"] }, bases), ["https://b.example.org"]);
  assert.deepEqual(retryTargets({ own: true, acked: true }, bases), []);
  assert.deepEqual(retryTargets({ own: false, acked: false }, bases), []);
  const metas = [
    { id: "x", own: true, acked: true, failedOn: ["https://a.example.org"] },
    { id: "y", own: true, acked: false },
    { id: "z", own: false, acked: false },
    { id: "v", own: true, acked: false },
  ];
  assert.deepEqual(retryPlan(metas, bases).map((p) => p.id), ["y", "v", "x"]);
  assert.deepEqual(retryPlan(metas, bases, 2).map((p) => p.id), ["y", "v"]);
});
