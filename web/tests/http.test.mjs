// Body ceilings after decompression, deadline over the whole body, redirects refused (ADR 0029
// rules 4 to 7), against a hostile local HTTP server and Node's fetch (undici decodes gzip, like a
// browser).
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, test } from "node:test";
import { gzipSync } from "node:zlib";

import { CEILING } from "../src/bounds.js";
import { readLimited, request } from "../src/http.js";
import { Relay, RelayStatus } from "../src/relay.js";

let server;
let base;
const hits = []; // "METHOD /path" of every request the server received

before(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    hits.push(`${req.method} ${url.pathname}`);
    const redirect = url.pathname.match(/^\/s(30[1378])\//);
    if (redirect) {
      res.writeHead(Number(redirect[1]), { Location: "/target" }).end("x".repeat(100));
      return;
    }
    const n = Number(url.searchParams.get("n") ?? 0);
    const status = Number(url.searchParams.get("status") ?? 200);
    switch (url.pathname) {
      case "/exact":
        res.writeHead(status).end(Buffer.alloc(n, 0x20));
        break;
      case "/gzip":
        res.writeHead(200, { "Content-Encoding": "gzip" }).end(gzipSync(Buffer.alloc(n, 0x20)));
        break;
      case "/drip": {
        res.writeHead(200);
        const t = setInterval(() => res.write("x"), 50);
        res.on("close", () => clearInterval(t));
        break;
      }
      case "/sbtp/v1/info":
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ min_pow_difficulty: 16, max_future_ms: 1, pad: "x".repeat(CEILING.info) }));
        break;
      case "/sbtp/v1/query":
        res.writeHead(429, { "Retry-After": "7" }).end(JSON.stringify({ error: "RateLimited" }));
        break;
      default:
        res.writeHead(404).end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

const kind = (k) => ({ name: "RelayRequestError", kind: k });

test("bounded reads return a tight copy, BYOB and default reader (finding 1)", async () => {
  const byob = await readLimited(new Response(new Uint8Array(10)).body, 65_909);
  assert.equal(byob.byteLength, 10);
  assert.equal(byob.buffer.byteLength, byob.byteLength);
  const plain = new ReadableStream({ start(c) { c.enqueue(new Uint8Array(7)); c.close(); } });
  const dflt = await readLimited(plain, 65_909);
  assert.equal(dflt.buffer.byteLength, 7);
  const net = await request(`${base}/exact?n=5`, { ceiling: CEILING.block });
  assert.equal(net.body.buffer.byteLength, 5);
});

test("the caller's deadline is an abort, not a per-request timeout (finding 3)", async () => {
  await assert.rejects(
    request(`${base}/drip`, { ceiling: CEILING.query, signal: AbortSignal.timeout(300) }),
    { name: "RelayRequestError", kind: "aborted", message: "the operation took too long and was stopped" });
  const cancel = new AbortController();
  setTimeout(() => cancel.abort(), 200);
  await assert.rejects(request(`${base}/drip`, { ceiling: CEILING.query, signal: cancel.signal }),
    { kind: "aborted", message: "cancelled" });
});

test("each ceiling: accepted at the ceiling, refused one byte above", async () => {
  for (const ceiling of [CEILING.block, CEILING.query, CEILING.info]) {
    const ok = await request(`${base}/exact?n=${ceiling}`, { ceiling });
    assert.equal(ok.body.byteLength, ceiling);
    await assert.rejects(request(`${base}/exact?n=${ceiling + 1}`, { ceiling }), kind("body-too-large"));
  }
});

test("error bodies: at the ceiling kept, above it unparseable (null), status still decides", async () => {
  const at = await request(`${base}/exact?status=500&n=${CEILING.error}`, { ceiling: 1 });
  assert.equal(at.status, 500);
  assert.equal(at.body.byteLength, CEILING.error);
  const above = await request(`${base}/exact?status=503&n=${CEILING.error + 1}`, { ceiling: 1 });
  assert.equal(above.status, 503);
  assert.equal(above.body, null);
});

test("the ceiling counts decoded bytes (gzip bomb)", async () => {
  const ok = await request(`${base}/gzip?n=${CEILING.query}`, { ceiling: CEILING.query });
  assert.equal(ok.body.byteLength, CEILING.query);
  await assert.rejects(request(`${base}/gzip?n=${10 * 2 ** 20}`, { ceiling: CEILING.query }), kind("body-too-large"));
});

test("the deadline covers the body: a drip feed times out", async () => {
  const t0 = Date.now();
  await assert.rejects(request(`${base}/drip`, { ceiling: CEILING.query, deadlineMs: 400 }), kind("timeout"));
  assert.ok(Date.now() - t0 < 2000);
});

test("ADR 0030: 301, 307, 308 on /info, /query, PUT /block are not followed (real 3xx, Node)", async () => {
  for (const code of [301, 307, 308]) {
    const relay = new Relay(`${base}/s${code}`);
    for (const call of [() => relay.info(), () => relay.queryPage({}, null), () => relay.put(new Uint8Array(118))]) {
      hits.length = 0;
      await assert.rejects(call(), kind("redirect"));
      assert.equal(hits.length, 1, `${code}: ${hits.join(", ")}`); // nothing reached the target
    }
  }
});

test("ADR 0030: a 303 to PUT does not turn into a GET", async () => {
  hits.length = 0;
  await assert.rejects(new Relay(`${base}/s303`).put(new Uint8Array(118)), kind("redirect"));
  assert.deepEqual(hits, ["PUT /s303/sbtp/v1/block"]);
});

test("ADR 0030: a browser opaque-redirect response is a redirect error, not retried by a walk", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { type: "opaqueredirect", status: 0, headers: new Headers(), body: null };
  };
  await assert.rejects(request("http://127.0.0.1:1/x", { ceiling: 10, fetchImpl }), kind("redirect"));
  const { walk } = await import("../src/walk.js");
  calls = 0;
  const w = await walk(new Relay("http://127.0.0.1:1", { fetchImpl }), {}, { sleep: async () => {} });
  assert.equal(w.stop, "failed");
  assert.equal(w.error.kind, "redirect");
  assert.equal(calls, 1);
});

test("Relay: oversized /info fails; 429 carries Retry-After and is transient", async () => {
  const relay = new Relay(base);
  await assert.rejects(relay.info(), kind("body-too-large"));
  await assert.rejects(relay.queryPage({}, null), (e) => {
    assert.ok(e instanceof RelayStatus && e.transient);
    assert.equal(e.errorName, "RateLimited");
    assert.deepEqual(e.retryAfter, { ms: 7000 });
    return true;
  });
});
