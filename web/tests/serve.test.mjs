// Dev server robustness (security review 2026-11-20, L-3) and timestamp display (L-1).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { test } from "node:test";

import { formatTimestamp } from "../src/format.js";

test("serve.mjs: a malformed escape gets 400 and the server keeps serving", async () => {
  const child = spawn(process.execPath, [new URL("../serve.mjs", import.meta.url).pathname, "0"]);
  try {
    const [line] = await once(child.stdout, "data");
    const base = String(line).trim().replace(/\/$/, "");
    assert.equal((await fetch(`${base}/%E0`)).status, 400);
    const page = await fetch(`${base}/index.html`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy"), /'wasm-unsafe-eval'/);
    assert.equal((await fetch(`${base}/tests/serve.test.mjs`)).status, 404);
    assert.equal((await fetch(`${base}/../Cargo.toml`)).status, 404);
  } finally {
    child.kill();
  }
});

test("timestamps beyond the Date range are shown as raw milliseconds", () => {
  assert.equal(formatTimestamp(0n), "1970-01-01T00:00:00.000Z");
  assert.equal(formatTimestamp(8_640_000_000_000_000n), "+275760-09-13T00:00:00.000Z");
  assert.equal(formatTimestamp(9_000_000_000_000_000n), "9000000000000000 ms");
  assert.equal(formatTimestamp(2n ** 63n), "9223372036854775808 ms");
  assert.equal(formatTimestamp(2n ** 64n - 1n), "18446744073709551615 ms");
});
