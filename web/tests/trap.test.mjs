// I-5: a foreign exception through WASM poisons the instance. Its own file, so its own process.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const wasmPath = new URL("../pkg/sbtp_wasm_bg.wasm", import.meta.url);
const skip = existsSync(wasmPath) ? false : "web/pkg missing: run web/build.sh";

test("a foreign exception through WASM poisons the instance", { skip }, async () => {
  const w = await import("../src/wasm.js");
  await w.loadSbtp(readFileSync(wasmPath));
  class Liar extends Uint8Array { get length() { return 60; } }
  assert.throws(() => w.blockIdHex(new Liar(118)), { name: "WasmPoisoned" });
  assert.ok(w.isPoisoned());
  assert.throws(() => w.blockIdHex(new Uint8Array(118)), { name: "WasmPoisoned" });
});

