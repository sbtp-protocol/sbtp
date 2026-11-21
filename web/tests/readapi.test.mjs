// Read API of ADR 0051 in the web client: record framing of POST /blocks, batches with failover,
// partial answers and the 1 MiB ceiling, newest-first walks with `head`, grouped parents with
// per-parent cursors, `fields=parents`, the view and its request count, the cold start, and the
// fallback to the requests of before when /info has no `read_api`. Against fake relays over real
// HTTP on loopback that follow the ADR; blocks are built and verified with sbtp-wasm (web/pkg,
// web/build.sh). Pure checks run without it.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { CEILING, LIMITS } from "../src/bounds.js";
import { fromHex, toHex } from "../src/hex.js";
import { InvalidResponse, parseGroup, parseInfo, parsePage, parseRecords, Relay } from "../src/relay.js";
import { fetchBlocksFrom, packBatches, RelaySet, walkAll, walkGroupAll } from "../src/relays.js";
import { traverseLevels } from "../src/traverse.js";
import { loadDescendants, loadView, refreshView } from "../src/view.js";
import { walk, walkGroup } from "../src/walk.js";

const wasmPath = new URL("../pkg/sbtp_wasm_bg.wasm", import.meta.url);
const skip = existsSync(wasmPath) ? false : "web/pkg missing: run web/build.sh";

const enc = (v) => new TextEncoder().encode(typeof v === "string" ? v : JSON.stringify(v));
const id = (n) => n.toString(16).padStart(64, "0");
const u32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const frame = (...records) => new Uint8Array(records.flatMap((r) => (r === null ? u32(0) : [...u32(r.length), ...r])));

test("records: framing, length 0, prefix, truncation, a length above the ceiling, extra records", () => {
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([9]);
  let r = parseRecords(frame(a, null, b), 3);
  assert.deepEqual(r.records.map((x) => x && [...x]), [[1, 2, 3], null, [9]]);
  assert.equal(r.truncated, false);
  // A prefix (rule 3): fewer records than ids, the rest is requested again by the caller.
  r = parseRecords(frame(a), 3);
  assert.equal(r.records.length, 1);
  assert.equal(r.truncated, false);
  // A body ending inside a record or inside a length: the complete records before it are kept.
  const whole = frame(a, b);
  r = parseRecords(whole.slice(0, whole.length - 1), 2);
  assert.deepEqual(r.records.map((x) => [...x]), [[1, 2, 3]]);
  assert.equal(r.truncated, true);
  r = parseRecords(whole.slice(0, 7 + 2), 2);
  assert.equal(r.records.length, 1);
  assert.equal(r.truncated, true);
  // A length above MAX_BLOCK_LEN: the whole response is a failed request, even after good records.
  assert.throws(() => parseRecords(new Uint8Array([...frame(a), ...u32(CEILING.block + 1)]), 2), InvalidResponse);
  assert.equal(parseRecords(new Uint8Array([...u32(CEILING.block), ...new Uint8Array(CEILING.block)]), 1).records[0].length, CEILING.block);
  assert.throws(() => parseRecords(frame(a, b), 1), /more records/);
  assert.throws(() => parseRecords(new Uint8Array(0), 1), /no record/);
  // Records are copies: they do not keep the response buffer alive.
  assert.equal(parseRecords(frame(a, b), 2).records[1].buffer.byteLength, 1);
});

test("info read_api, fields hints, head, grouped response checks", () => {
  const info = (o) => parseInfo(enc({ min_pow_difficulty: 8, max_future_ms: 1, ...o }));
  assert.equal(info({}).readApi, 1);
  assert.equal(info({ read_api: 2 }).readApi, 2);
  for (const v of ["2", 2.5, 0, -1, null, true]) assert.equal(info({ read_api: v }).readApi, 1, String(v));

  const ID = id(7);
  const page = (o) => enc({ block_ids: [ID], cursor: "c1", more: true, head: "h9", ...o });
  const p = parsePage(page({ parents: [[id(1), id(2)]], lens: [300] }), 10, true);
  assert.deepEqual(p.hints, [{ parents: [id(1), id(2)], len: 300 }]);
  assert.equal(p.head, "h9");
  for (const bad of [
    { parents: [[id(1)]] }, // no lens
    { parents: [], lens: [] }, // not aligned
    { parents: [[id(0xab).toUpperCase()]], lens: [300] },
    { parents: [Array(9).fill(id(1))], lens: [300] },
    { parents: [[]], lens: [0] },
    { parents: [[]], lens: [CEILING.block + 1] },
  ]) assert.throws(() => parsePage(page(bad), 10, true), InvalidResponse, JSON.stringify(bad));
  assert.throws(() => parsePage(page({ head: "a/b" }), 10), /head/);
  // With fields the page is at most 200 entries (rule 14).
  assert.throws(() => parsePage(enc({ block_ids: Array(201).fill(ID), parents: Array(201).fill([]), lens: Array(201).fill(1), cursor: "c", more: true }), 1000, true), /200/);

  const g = (parents, head = "h") => enc({ parents, head });
  const entry = (parent, ids = [], more = false) => ({ parent, block_ids: ids, cursor: "c", more });
  const ok = parseGroup(g([entry(id(1), [ID]), entry(id(2))]), [id(1), id(2)], 10);
  assert.deepEqual(ok.groups.map((x) => [x.parent, x.blockIds.length, x.more]), [[id(1), 1, false], [id(2), 0, false]]);
  for (const [bytes, why] of [
    [g([entry(id(2)), entry(id(1))]), "order"],
    [g([entry(id(1))]), "count"],
    [g([entry(id(1), [ID, ID, ID]), entry(id(2))]), "per-parent limit"],
    [g([entry(id(1)), { ...entry(id(2)), cursor: "" }]), "cursor"],
    [enc({ parents: [entry(id(1)), entry(id(2))] }), "head"],
  ]) assert.throws(() => parseGroup(bytes, [id(1), id(2)], 2), InvalidResponse, why);
});

test("batches are packed under 256 ids and 1 MiB of known lengths", () => {
  const ids = Array.from({ length: 600 }, (_, i) => id(i));
  assert.deepEqual(packBatches(ids).map((b) => b.length), [256, 256, 88]);
  const hints = new Map(ids.map((x) => [x, { len: 60_000 }]));
  const packed = packBatches(ids.slice(0, 40), hints);
  assert.deepEqual(packed.map((b) => b.length), [17, 17, 6]); // 17 × 60,004 = 1,020,068 bytes
  for (const b of packed) assert.ok(b.reduce((s, x) => s + 4 + hints.get(x).len, 0) <= CEILING.batch);
});

test("traverseLevels: one call per level, bounded, each id once", async () => {
  const graph = { a: ["b", "c"], b: ["d"], c: ["d", "e"], d: [], e: ["a"] };
  const levels = [];
  const t = await traverseLevels("a", async (ids) => {
    levels.push(ids);
    return new Map(ids.map((x) => [x, graph[x] ?? null]));
  });
  assert.deepEqual(levels, [["a"], ["b", "c"], ["d", "e"]]);
  assert.deepEqual(t.visited, ["a", "b", "c", "d", "e"]);
  assert.equal(t.partial, false);
  const cut = await traverseLevels("a", async (ids) => new Map(ids.map((x) => [x, graph[x]])), { maxVisited: 2 });
  assert.equal(cut.visited.length, 2);
  assert.equal(cut.partial, true);
});

test("walkGroup: per-parent cursors, completeness, restart on InvalidCursor, bounds (scripted)", async () => {
  const { RelayStatus } = await import("../src/relay.js");
  const calls = [];
  let n = 0;
  const src = {
    async queryGroup(parents) {
      calls.push(parents.map((p) => `${p.parent.slice(-1)}.${p.cursor ?? "-"}`).join(" "));
      n += 1;
      if (n === 3) throw new RelayStatus(400, "InvalidCursor", null);
      return {
        head: `h${n}`,
        groups: parents.map((p) => p.parent === id(1)
          ? { parent: p.parent, blockIds: [id(100 + n)], cursor: `a${n}`, more: n < 5 }
          : { parent: p.parent, blockIds: [], cursor: "z", more: false }),
      };
    },
  };
  const g = await walkGroup(src, [id(1), id(2)], { sleep: async () => {} });
  // Request 1: both; 2: only the parent with more; 3: InvalidCursor; 4: both again, no cursor.
  assert.deepEqual(calls, ["1.- 2.-", "1.a1", "1.a2", "1.- 2.-", "1.a4"]);
  assert.equal(g.stop, "done");
  assert.deepEqual(g.groups.map((x) => x.complete), [true, true]);
  assert.equal(g.head, "h4"); // the first response since the restart
  assert.equal(g.restarts, 1);
  assert.deepEqual(g.groups[0].ids, [id(101), id(102), id(104), id(105)]);

  // A parent whose children exceed the per-parent bound stays incomplete (rule 29).
  let m = 0;
  const big = { async queryGroup(parents) { m += 1; return { head: "h", groups: parents.map((p) => ({ parent: p.parent, blockIds: [id(1000 + m)], cursor: `c${m}`, more: true })) }; } };
  const b = await walkGroup(big, [id(1)], { limits: { ...LIMITS, groupMaxIdsPerParent: 3 } });
  assert.equal(b.groups[0].complete, false);
  assert.equal(b.groups[0].stop, "bound");
  assert.equal(b.groups[0].ids.length, 3);
  assert.equal(b.groups[0].cursor, "c3"); // the page cut by the bound is read again later
  assert.equal(b.stop, "bound");
});

// ---- Fake relays over HTTP ------------------------------------------------------------------

let w;
let key;
const servers = [];

before(async () => {
  if (skip) return;
  w = await import("../src/wasm.js");
  await w.loadSbtp(readFileSync(wasmPath));
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  key = { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
});

after(() => {
  for (const s of servers) {
    s.closeAllConnections?.();
    s.close();
  }
});

let serial = 0;
async function makeBlock(text, parents = []) {
  const { signBlock } = await import("../src/keys.js");
  serial += 1;
  const block = w.buildUnsignedBlock(key.publicKey, BigInt(Date.now() + serial), 0n,
    fromHex(parents.join("")), new TextEncoder().encode(`${text} #${serial}`));
  while (w.mineSlice(block, 0, 1 << 16) === undefined) { /* next slice */ }
  const bytes = await signBlock(key, block);
  return { bytes, id: w.verifySubmitted(bytes, 0).idHex, parents };
}

/**
 * A fake relay following ADR 0051 when `readApi` is 2: store order is insertion order, a cursor
 * `p<N>` names the gap before position N, `head` is the gap after the newest position. Options:
 * `readApi` (absent from /info when null; the new forms are then refused as an old relay would),
 * `prefix` (most records per POST response), `zero` (ids answered with length 0), `wrong` (id →
 * bytes served instead), `overLength` (a record length above the ceiling), `truncate` (the body
 * ends inside the second record), `lie` (id → the parents the relay claims), `refuseBatch`
 * (`[status, error]`: POST /blocks refused so, /info still saying `read_api`). Records every request.
 */
async function fakeRelay({ readApi = 2, prefix = Infinity, zero = new Set(), wrong = new Map(), overLength = false, truncate = false, lie = new Map(), refuseBatch = null } = {}) {
  const blocks = new Map();
  const order = [];
  const parentsOf = new Map();
  const hits = [];
  const add = (b) => {
    if (blocks.has(b.id)) return;
    blocks.set(b.id, Buffer.from(b.bytes));
    order.push(b.id);
    parentsOf.set(b.id, lie.get(b.id) ?? b.parents); // `lie`: parents the relay claims
  };
  const json = (res, code, v) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(v));
  const bad = (res, name = "InvalidParameter") => json(res, 400, { error: name });
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (url.pathname === "/sbtp/v1/blocks" && req.method === "POST") {
        hits.push(`POST /sbtp/v1/blocks n=${body.length / 32}`);
        if (readApi === null) return json(res, 405, { error: "MethodNotAllowed" });
        if (refuseBatch) return json(res, refuseBatch[0], { error: refuseBatch[1] });
        if (body.length === 0 || body.length % 32 !== 0 || body.length > 8192) return bad(res);
        const ids = [];
        for (let i = 0; i < body.length; i += 32) ids.push(toHex(body.subarray(i, i + 32)));
        if (new Set(ids).size !== ids.length) return bad(res);
        const out = [];
        let size = 0;
        for (const [i, x] of ids.entries()) {
          if (i >= prefix) break;
          let rec = zero.has(x) ? Buffer.alloc(0) : wrong.get(x) ?? blocks.get(x) ?? Buffer.alloc(0);
          if (overLength && i === 1) {
            out.push(Buffer.from(u32(CEILING.block + 1)), rec);
            break;
          }
          if (size + 4 + rec.length > CEILING.batch) break; // rule 4
          if (truncate && i === 1) {
            out.push(Buffer.from(u32(rec.length)), rec.subarray(0, rec.length >> 1));
            break;
          }
          out.push(Buffer.from(u32(rec.length)), rec);
          size += 4 + rec.length;
        }
        return res.writeHead(200, { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" }).end(Buffer.concat(out));
      }
      hits.push(`${req.method} ${url.pathname}${url.search}`);
      if (url.pathname === "/sbtp/v1/info") {
        const v = { min_pow_difficulty: 0, max_future_ms: 300000 };
        if (readApi !== null) v.read_api = readApi;
        return json(res, 200, v);
      }
      if (url.pathname.startsWith("/sbtp/v1/block/")) {
        const x = url.pathname.slice("/sbtp/v1/block/".length);
        if (wrong.has(x)) return res.writeHead(200).end(wrong.get(x));
        return blocks.has(x) ? res.writeHead(200).end(blocks.get(x)) : json(res, 404, { error: "NotFound" });
      }
      if (url.pathname !== "/sbtp/v1/query") return json(res, 404, { error: "NotFound" });
      const q = url.searchParams;
      const parentValues = q.getAll("parent");
      const orderParam = q.get("order");
      const fields = q.get("fields");
      if (readApi === null && (parentValues.length > 1 || orderParam !== null || fields !== null || parentValues.some((p) => p.includes(".")))) {
        return bad(res);
      }
      if (orderParam !== null && orderParam !== "asc" && orderParam !== "desc") return bad(res);
      if (fields !== null && (fields !== "parents" || parentValues.length > 0)) return bad(res);
      if (parentValues.length > 32 || new Set(parentValues.map((p) => p.split(".")[0])).size !== parentValues.length) return bad(res);
      const desc = orderParam === "desc";
      const gapOf = (c) => {
        if (c === null) return desc ? order.length : 0;
        const m = /^p([0-9]+)$/.exec(c);
        return m ? Math.min(Number(m[1]), order.length) : undefined;
      };
      const head = `p${order.length}`;
      const max = 1000;
      const listing = (parent, cursor, limit) => {
        const gap = gapOf(cursor);
        if (gap === undefined) return undefined;
        const match = (i) => parent === null || (parentsOf.get(order[i]) ?? []).includes(parent);
        const ids = [];
        let last = gap;
        if (desc) {
          for (let i = gap - 1; i >= 0 && ids.length < limit; i -= 1) if (match(i)) { ids.push(order[i]); last = i; }
          let more = false;
          for (let i = last - 1; i >= 0; i -= 1) if (match(i)) { more = true; break; }
          return { block_ids: ids, cursor: `p${ids.length ? last : gap}`, more };
        }
        for (let i = gap; i < order.length && ids.length < limit; i += 1) if (match(i)) { ids.push(order[i]); last = i + 1; }
        let more = false;
        for (let i = last; i < order.length; i += 1) if (match(i)) { more = true; break; }
        return { block_ids: ids, cursor: `p${ids.length ? last : gap}`, more };
      };
      const limit = Math.min(Number(q.get("limit") ?? 100), max);
      if (parentValues.length >= 2) {
        const per = Math.min(limit, Math.max(1, Math.floor(max / parentValues.length)));
        const groups = [];
        for (const v of parentValues) {
          const [parent, c] = v.split(".");
          const l = listing(parent, c ?? q.get("cursor"), per);
          if (l === undefined) return bad(res, "InvalidCursor");
          groups.push({ parent, ...l });
        }
        return json(res, 200, readApi === null ? undefined : { parents: groups, head });
      }
      const l = listing(parentValues[0] ?? null, q.get("cursor"), fields ? Math.min(limit, 200) : limit);
      if (l === undefined) return bad(res, "InvalidCursor");
      const page = { ...l };
      if (readApi !== null) page.head = head;
      if (fields) {
        page.parents = l.block_ids.map((x) => parentsOf.get(x));
        page.lens = l.block_ids.map((x) => blocks.get(x).length);
      }
      return json(res, 200, page);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  const count = (re) => hits.filter((h) => re.test(h)).length;
  return { base: `http://127.0.0.1:${server.address().port}`, hits, add, order, count };
}

const validate = (bytes, x) => w.verifyFetched(bytes, 0, x);

/** A root with `n` children; returns them oldest first. */
async function family(relays, n, text = "child") {
  const root = await makeBlock("root");
  for (const r of relays) r.add(root);
  const kids = [];
  for (let i = 0; i < n; i += 1) {
    const k = await makeBlock(`${text} ${i}`, [root.id]);
    for (const r of relays) r.add(k);
    kids.push(k);
  }
  return { root, kids };
}

test("batch: wrong bytes for one id, length 0, partial answers: failover and re-requests", { skip }, async () => {
  const blocks = await Promise.all(Array.from({ length: 6 }, (_, i) => makeBlock(`b${i}`)));
  const ids = blocks.map((b) => b.id);
  const other = await makeBlock("not the one asked for");
  // The first relay serves another block's bytes for ids[1], length 0 for ids[2], one record per
  // response; the second serves everything.
  const hostile = await fakeRelay({ prefix: 1, zero: new Set([ids[2]]), wrong: new Map([[ids[1], Buffer.from(other.bytes)]]) });
  const good = await fakeRelay();
  for (const b of blocks) {
    hostile.add(b);
    good.add(b);
  }
  const set = new RelaySet([hostile.base, good.base]);
  const r = await fetchBlocksFrom(set, ids, validate, { mode: "bulk" });
  assert.deepEqual(r.blocks.map((b) => b.idHex).sort(), [...ids].sort());
  assert.equal(r.failed.length, 0);
  assert.equal(r.sources.get(hostile.base), 4);
  assert.equal(r.sources.get(good.base), 2); // ids[1] (R1 failed) and ids[2] (length 0)
  // Rule 3: one record per answer, the rest requested again: 6, 5, 4, 3, 2, 1 ids.
  assert.deepEqual(hostile.hits.filter((h) => h.startsWith("POST")), [6, 5, 4, 3, 2, 1].map((n) => `POST /sbtp/v1/blocks n=${n}`));
  assert.deepEqual(good.hits.filter((h) => h.startsWith("POST")), ["POST /sbtp/v1/blocks n=2"]);
  assert.equal(hostile.count(/^GET \/sbtp\/v1\/block\//), 0);
  // Each batch of N counts N toward the operation's bound: 6+5+4+3+2+1 + 2.
  assert.equal(r.attempts, 23);
});

test("batch: a length above the ceiling or a truncated body breaks the route; that relay falls back to GETs", { skip }, async () => {
  const blocks = await Promise.all(Array.from({ length: 3 }, (_, i) => makeBlock(`t${i}`)));
  const ids = blocks.map((b) => b.id);
  for (const [opt, firstServed] of [[{ overLength: true }, 0], [{ truncate: true }, 1]]) {
    const broken = await fakeRelay(opt);
    const good = await fakeRelay();
    for (const b of blocks) {
      broken.add(b);
      good.add(b);
    }
    const set = new RelaySet([broken.base, good.base]);
    const r = await fetchBlocksFrom(set, ids, validate, { mode: "bulk" });
    assert.equal(r.blocks.length, 3, JSON.stringify(opt));
    // overLength: nothing from the response is used; truncate: the complete first record is.
    // The rest comes from single GETs on the same relay; the next relay is not asked.
    assert.equal(r.sources.get(broken.base), 3, JSON.stringify(opt));
    assert.equal(broken.count(/^GET \/sbtp\/v1\/block\//), 3 - firstServed);
    assert.deepEqual(good.hits, ["GET /sbtp/v1/info"], "the next relay is asked for no block");
    assert.equal(set.entry(broken.base).failures, 0, "the GETs that followed succeeded");
    assert.equal(broken.count(/^POST/), 1, "a failed request is not repeated on that relay");
  }
});

test("batch route refused (405, 404, 400) with one relay: single GETs, remembered for the session (I-1)", { skip }, async () => {
  const blocks = await Promise.all(Array.from({ length: 4 }, (_, i) => makeBlock(`r${i}`)));
  const ids = blocks.map((b) => b.id);
  for (const refuseBatch of [[405, "MethodNotAllowed"], [404, "NotFound"], [400, "InvalidParameter"], [400, "NoLength"]]) {
    const relay = await fakeRelay({ refuseBatch });
    for (const b of blocks) relay.add(b);
    const set = new RelaySet([relay.base]);
    const r = await fetchBlocksFrom(set, ids, validate, { mode: "bulk" });
    assert.equal(r.blocks.length, 4, JSON.stringify(refuseBatch));
    assert.equal(r.failed.length, 0);
    assert.equal(r.partial, false);
    assert.deepEqual(relay.hits.map((h) => h.replace(/[0-9a-f]{64}/, "<id>")), [
      "GET /sbtp/v1/info", "POST /sbtp/v1/blocks n=4", ...ids.map(() => "GET /sbtp/v1/block/<id>"),
    ]);
    // The next bulk fetch goes straight to GETs: no POST, no /info.
    const n = relay.hits.length;
    const again = await fetchBlocksFrom(set, ids.slice(0, 2), validate, { mode: "bulk" });
    assert.equal(again.blocks.length, 2);
    assert.deepEqual(relay.hits.slice(n).map((h) => h.split("/").slice(0, 4).join("/")), [
      "GET /sbtp/v1/block", "GET /sbtp/v1/block",
    ]);
  }
  // A server error says nothing about the route: no fallback, the next relay is asked.
  const busy = await fakeRelay({ refuseBatch: [503, "Busy"] });
  const good = await fakeRelay();
  for (const b of blocks) {
    busy.add(b);
    good.add(b);
  }
  const set = new RelaySet([busy.base, good.base]);
  const r = await fetchBlocksFrom(set, ids, validate, { mode: "bulk" });
  assert.equal(r.sources.get(good.base), 4);
  assert.equal(busy.count(/^GET \/sbtp\/v1\/block\//), 0);
  assert.equal(set.entry(busy.base).batchBroken, false);
});

test("cold start: a hostile relay listed first cannot hide a block an honest relay lists (M-1)", { skip }, async () => {
  const root = await makeBlock("root");
  const child = await makeBlock("child", [root.id]);
  const x = await makeBlock("retraction", [child.id]);
  // A lists X with no parents; B lists it with its true parent.
  const hostile = await fakeRelay({ lie: new Map([[x.id, []]]) });
  const honest = await fakeRelay();
  for (const b of [root, child, x]) {
    hostile.add(b);
    honest.add(b);
  }
  const set = new RelaySet([hostile.base, honest.base]);
  const d = await loadDescendants(set, root.id, { validate });
  assert.deepEqual(new Set(d.members), new Set([child.id, x.id]));
  assert.ok(d.blocks.has(x.id), "X is fetched and shown");
  // The union of the claims makes a fetch only; a claim of a wrong parent shows nothing.
  const stranger = await makeBlock("unrelated");
  const liar = await fakeRelay({ lie: new Map([[stranger.id, [root.id]]]) });
  for (const b of [root, child, stranger]) liar.add(b);
  honest.add(stranger);
  const d2 = await loadDescendants(new RelaySet([liar.base, honest.base]), root.id, { validate });
  assert.ok(!d2.members.includes(stranger.id));
  assert.ok(!d2.blocks.has(stranger.id));
});

test("view: a relay skipped for lacking read_api 2 leaves every item's replies incomplete (L-2)", { skip }, async () => {
  const v2 = await fakeRelay();
  const old = await fakeRelay({ readApi: null });
  const { root, kids } = await family([v2, old], 3);
  v2.add(await makeBlock("reply", [kids[0].id]));
  const set = new RelaySet([v2.base, old.base]);
  const v = await loadView(set, root.id, { validate });
  assert.equal(v.grouped, true);
  assert.equal(v.items.length, 3);
  for (const i of v.items) {
    assert.equal(i.complete, false, "the old relay was never asked about this item's children");
    assert.ok(i.incompleteOn.includes(old.base));
    assert.ok(i.completeOn.includes(v2.base));
  }
  // The old relay is still not asked for grandchildren.
  assert.ok(!old.hits.some((h) => kids.some((k) => h.includes(`parent=${k.id}`))));
  // A refresh does not turn them complete either.
  const child = await makeBlock("new child", [root.id]);
  v2.add(child);
  old.add(child);
  await refreshView(set, v, { validate });
  assert.ok(v.items.every((i) => !i.complete));
  // With the v2 relay alone, the same items are complete.
  const alone = await loadView(new RelaySet([v2.base]), root.id, { validate });
  assert.ok(alone.items.every((i) => i.complete));
});

test("batch: the overall bound counts each id of a batch; a relay without read_api gets GETs", { skip }, async () => {
  const blocks = await Promise.all(Array.from({ length: 8 }, (_, i) => makeBlock(`n${i}`)));
  const ids = blocks.map((b) => b.id);
  const v2 = await fakeRelay();
  for (const b of blocks) v2.add(b);
  const capped = await fetchBlocksFrom(new RelaySet([v2.base]), ids, validate, { mode: "bulk", maxAttempts: 5 });
  assert.equal(capped.blocks.length, 5);
  assert.equal(capped.partial, true);
  assert.deepEqual(capped.failed.map((f) => f.status), ["bound", "bound", "bound"]);
  assert.deepEqual(v2.hits.filter((h) => h.startsWith("POST")), ["POST /sbtp/v1/blocks n=5"]);

  // Old relay first (no read_api: GETs, as before), then a v2 relay for what it lacks.
  const old = await fakeRelay({ readApi: null });
  const v2b = await fakeRelay();
  for (const b of blocks.slice(0, 5)) old.add(b);
  for (const b of blocks) v2b.add(b);
  const mixed = await fetchBlocksFrom(new RelaySet([old.base, v2b.base]), ids, validate, { mode: "bulk" });
  assert.equal(mixed.blocks.length, 8);
  assert.equal(old.count(/^POST/), 0, "no POST to a relay without read_api 2 (rule 31)");
  assert.equal(old.count(/^GET \/sbtp\/v1\/block\//), 8);
  assert.deepEqual(v2b.hits.filter((h) => h.startsWith("POST")), ["POST /sbtp/v1/blocks n=3"]);
});

test("old relay (no read_api): exactly the requests of before for a view, a list and a fetch of 40", { skip }, async () => {
  const old = await fakeRelay({ readApi: null });
  const { root, kids } = await family([old], 40);
  const grand = await makeBlock("reply", [kids[0].id]);
  old.add(grand);
  const set = new RelaySet([old.base]);
  const v = await loadView(set, root.id, { validate });
  assert.equal(v.grouped, false);
  assert.deepEqual(v.items.map((i) => i.id), kids.map((k) => k.id)); // ascending, as before
  assert.ok(v.items.every((i) => i.children.length === 0 && !i.complete), "no grandchildren from an old relay");
  const queries = old.hits.filter((h) => h.startsWith("GET /sbtp/v1/query"));
  assert.deepEqual(queries, [`GET /sbtp/v1/query?parent=${root.id}`]);
  assert.equal(old.count(/^GET \/sbtp\/v1\/block\//), 40);
  assert.equal(old.count(/^POST/), 0);
  assert.ok(!old.hits.some((h) => /order=|fields=|\.p[0-9]/.test(h)));
  // A refresh walks the root from its cursor, nothing else.
  const n = old.hits.length;
  const r = await refreshView(set, v, { validate });
  assert.equal(r.newItems.length, 0);
  assert.deepEqual(old.hits.slice(n), [`GET /sbtp/v1/query?parent=${root.id}&cursor=p41`]);
});

test("desc paging with head: newest first, then asc from head returns exactly what came after", { skip }, async () => {
  const relay = await fakeRelay();
  const { root, kids } = await family([relay], 5);
  const r = new Relay(relay.base);
  const d = await walk(r, { parent: root.id, order: "desc", limit: 2 }, { sleep: async () => {} });
  assert.deepEqual(d.ids, kids.map((k) => k.id).reverse());
  assert.equal(d.pages, 3);
  assert.equal(d.stop, "done");
  assert.equal(d.head, "p6");
  const late = await makeBlock("late", [root.id]);
  relay.add(late);
  const poll = await walk(r, { parent: root.id }, { cursor: d.head, sleep: async () => {} });
  assert.deepEqual(poll.ids, [late.id]);
  assert.deepEqual(relay.hits.filter((h) => h.includes("query")), [
    `GET /sbtp/v1/query?parent=${root.id}&limit=2&order=desc`,
    `GET /sbtp/v1/query?parent=${root.id}&limit=2&order=desc&cursor=p4`,
    `GET /sbtp/v1/query?parent=${root.id}&limit=2&order=desc&cursor=p2`,
    `GET /sbtp/v1/query?parent=${root.id}&cursor=p6`,
  ]);
});

test("grouped parents with per-parent cursors and per-parent completeness (HTTP)", { skip }, async () => {
  const relay = await fakeRelay();
  const a = await family([relay], 5, "a");
  const b = await family([relay], 1, "b");
  const c = await makeBlock("childless");
  relay.add(c);
  const set = new RelaySet([relay.base]);
  const g = await walkGroupAll(set, [a.root.id, b.root.id, c.id], { filter: { limit: 2 } });
  const pa = g.parents.get(a.root.id);
  assert.deepEqual(pa.ids, a.kids.map((k) => k.id));
  assert.ok(pa.complete && g.parents.get(b.root.id).complete && g.parents.get(c.id).complete);
  const q = relay.hits.filter((h) => h.includes("query"));
  // One request for the three, then only `a` with its own cursor, twice.
  assert.equal(q.length, 3);
  assert.ok(q[0].includes(`parent=${a.root.id}&parent=${b.root.id}&parent=${c.id}`), q[0]);
  assert.ok(q[1].includes(`parent=${a.root.id}&limit=2&cursor=p`), q[1]); // a single parent: plain form
  assert.equal(g.heads.get(relay.base), `p${relay.order.length}`);

  // Per-parent cursors in one request: `<id>.<cursor>`, each its own.
  const cur = new Map([[relay.base, new Map([[a.root.id, "p3"], [b.root.id, "p0"]])]]);
  const n = relay.hits.length;
  const h = await walkGroupAll(set, [a.root.id, b.root.id], { filter: { limit: 10 }, cursors: cur });
  assert.ok(relay.hits[n].includes(`parent=${a.root.id}.p3&parent=${b.root.id}.p0`), relay.hits[n]);
  assert.deepEqual(h.parents.get(a.root.id).ids, a.kids.slice(2).map((k) => k.id));

  // A parent over the client's per-parent bound stays incomplete, the others are complete.
  const bounded = await walkGroupAll(set, [a.root.id, b.root.id], {
    filter: { limit: 2 }, limits: { ...LIMITS, groupMaxIdsPerParent: 3 },
  });
  assert.equal(bounded.parents.get(a.root.id).complete, false);
  assert.equal(bounded.parents.get(b.root.id).complete, true);

  // An old relay in the set: one plain walk per parent; a listing is complete only on every relay.
  const old = await fakeRelay({ readApi: null });
  for (const x of [a.root, ...a.kids]) old.add(x);
  const mixed = await walkGroupAll(new RelaySet([relay.base, old.base]), [a.root.id, b.root.id], { filter: { limit: 2 } });
  assert.ok(mixed.parents.get(a.root.id).complete);
  assert.ok(!old.hits.some((x) => /order=|fields=|\.p[0-9]|parent=.*parent=/.test(x)));
  assert.equal(old.count(/query\?parent=/), 4); // a: 3 pages; b: 1
});

test("the 35-block view: request count, completeness, refresh in one grouped request", { skip }, async () => {
  const relay = await fakeRelay();
  const { root } = await family([relay], 30); // 30 children: the view shows the 25 newest
  const kidsNewest = [...relay.order].slice(1).reverse().slice(0, 25);
  // 10 grandchildren on the newest children.
  for (let i = 0; i < 10; i += 1) relay.add(await makeBlock(`reply ${i}`, [kidsNewest[i % 4]]));
  const set = new RelaySet([relay.base]);
  const v = await loadView(set, root.id, { validate });
  assert.equal(v.items.length, 25);
  assert.deepEqual(v.items.map((i) => i.id), kidsNewest);
  assert.equal(v.blocks.size, 35);
  assert.ok(v.items.every((i) => i.complete), "every item's children listing is complete");
  assert.equal(v.items.reduce((s, i) => s + i.children.length, 0), 10);
  const counts = {
    info: relay.count(/^GET \/sbtp\/v1\/info/), query: relay.count(/^GET \/sbtp\/v1\/query/),
    get: relay.count(/^GET \/sbtp\/v1\/block\//), post: relay.count(/^POST/),
  };
  // 1 /info (once per relay and session), desc on the root, 1 grouped query, 35 cacheable GETs.
  assert.deepEqual(counts, { info: 1, query: 2, get: 35, post: 0 });
  console.log(`35-block view, single GETs: ${relay.hits.length} requests ${JSON.stringify(counts)}`);

  // Refresh: one grouped asc request from head for the root and the 25 items, nothing to fetch.
  let n = relay.hits.length;
  const r0 = await refreshView(set, v, { validate });
  assert.deepEqual([r0.newItems.length, r0.newChildren.length], [0, 0]);
  assert.equal(relay.hits.length - n, 1);
  assert.equal((relay.hits.at(-1).match(/parent=/g) ?? []).length, 26);
  assert.ok(relay.hits.at(-1).includes(`parent=${root.id}.p41`), "the root polls from the head");
  // A new reply and a new child: one grouped poll, one grouped listing of the new item, 2 GETs.
  const reply = await makeBlock("new reply", [kidsNewest[3]]);
  const child = await makeBlock("new child", [root.id]);
  relay.add(reply);
  relay.add(child);
  n = relay.hits.length;
  const r1 = await refreshView(set, v, { validate });
  assert.deepEqual(r1.newItems, [child.id]);
  assert.deepEqual(r1.newChildren, [reply.id]);
  assert.equal(v.items[0].id, child.id);
  assert.ok(v.items[0].complete);
  assert.equal(relay.hits.length - n, 4);

  // The same view with batches (threshold 0): 1 desc, 1 grouped, 2 batches; no /info (kept).
  const set2 = new RelaySet([relay.base]);
  n = relay.hits.length;
  const v2 = await loadView(set2, root.id, { validate, limits: { ...LIMITS, viewSingleGetMax: 0 } });
  assert.equal(v2.blocks.size, 36); // the new child pushed the oldest of the 25 out
  const batched = relay.hits.slice(n);
  assert.deepEqual(batched.map((h) => h.split("?")[0].replace(/[0-9a-f]{64}/, "<id>")), [
    "GET /sbtp/v1/info", "GET /sbtp/v1/query", "GET /sbtp/v1/query", "POST /sbtp/v1/blocks n=25", "POST /sbtp/v1/blocks n=11",
  ]);
  console.log(`35-block view, batches: ${batched.length} requests (info included)`);
});

test("cold start: one relay-wide fields=parents walk, only the descendants fetched, in batches", { skip }, async () => {
  const relay = await fakeRelay();
  const old = await fakeRelay({ readApi: null });
  const { root, kids } = await family([relay], 3, "mine");
  const deep = await makeBlock("deep", [kids[1].id]);
  relay.add(deep);
  // Unrelated blocks of another graph on the same relay: listed, never fetched.
  const otherRoot = await makeBlock("other");
  relay.add(otherRoot);
  for (let i = 0; i < 20; i += 1) relay.add(await makeBlock(`other ${i}`, [otherRoot.id]));
  const set = new RelaySet([old.base, relay.base]);
  const d = await loadDescendants(set, root.id, { validate });
  assert.deepEqual(new Set(d.members), new Set([...kids.map((k) => k.id), deep.id]));
  assert.equal(d.blocks.size, 5);
  assert.equal(d.listed, relay.order.length);
  assert.deepEqual(relay.hits.filter((h) => !h.includes("info")), [
    "GET /sbtp/v1/query?limit=200&fields=parents",
    "POST /sbtp/v1/blocks n=5",
  ]);
  // The old relay is not walked relay-wide; it is asked for blocks first (user order) with GETs.
  assert.equal(old.count(/query/), 0);
  assert.equal(old.count(/^GET \/sbtp\/v1\/block\//), 5);
});

test("a relay that lies about parents makes the client fetch a block, never show it in the wrong place", { skip }, async () => {
  const root = await makeBlock("root");
  const real = await makeBlock("real child", [root.id]);
  const stranger = await makeBlock("unrelated");
  const lying = await fakeRelay({ lie: new Map([[stranger.id, [root.id]]]) });
  for (const b of [root, real, stranger]) lying.add(b);
  const set = new RelaySet([lying.base]);
  // Cold start: the hint is followed (the block is fetched), the header decides.
  const d = await loadDescendants(set, root.id, { validate });
  assert.deepEqual(d.members, [real.id]);
  assert.ok(!d.blocks.has(stranger.id));
  assert.ok(lying.hits.includes("POST /sbtp/v1/blocks n=3"));
  // The view: the relay lists the stranger under the root; it is not shown as a child.
  const v = await loadView(set, root.id, { validate });
  assert.deepEqual(v.items.map((i) => i.id), [real.id]);
});
