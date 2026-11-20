// Smoke test of the real JS API of sbtp-wasm (wasm-bindgen glue included), with plain Node and no
// npm package. Build and run (from the repository root):
//
//   cargo build -p sbtp-wasm --target wasm32-unknown-unknown --release
//   wasm-bindgen --target nodejs --out-dir target/wasm-pkg/node \
//     target/wasm32-unknown-unknown/release/sbtp_wasm.wasm
//   node crates/sbtp-wasm/tests-js/smoke.mjs target/wasm-pkg/node
//
// Exit code 0 when every check passes, 1 otherwise.

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = resolve(process.argv[2] ?? "target/wasm-pkg/node");
const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "../../../docs/test-vectors/v1");

let passed = 0;
async function check(name, body) {
  try {
    await body();
    passed += 1;
    console.log(`ok   ${name}`);
  } catch (error) {
    console.log(`FAIL ${name}\n     ${error.stack ?? error}`);
    process.exitCode = 1;
  }
}

/** Asserts that `body` throws an `Error` named `name`. */
function throwsNamed(body, name) {
  assert.throws(body, (error) => {
    assert.ok(error instanceof Error, `not an Error: ${error}`);
    assert.equal(error.name, name, error.message);
    return true;
  });
}

const hex = (text) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// Loading the glue instantiates the module and runs its start function (the self-test).
const sbtp = createRequire(import.meta.url)(join(pkg, "sbtp_wasm.js"));

function minedBlock(publicKey, difficulty, payload = "smoke") {
  const block = sbtp.buildUnsignedBlock(
    publicKey, BigInt(Date.now()), 0n, new Uint8Array(0), new TextEncoder().encode(payload));
  while (sbtp.mineSlice(block, difficulty, 1 << 12) === undefined) { /* next slice */ }
  return block;
}

await check("instantiation runs the self-test (ADR 0003 rule 16)", () => {
  const wasm = new WebAssembly.Module(readFileSync(join(pkg, "sbtp_wasm_bg.wasm")));
  const exports = WebAssembly.Module.exports(wasm).map((e) => e.name);
  assert.ok(exports.includes("__wbindgen_start"), "no start function exported");
  assert.match(readFileSync(join(pkg, "sbtp_wasm.js"), "utf8"), /__wbindgen_start\(\)/);
  sbtp.selfTest(); // and on demand
});

await check("82 frozen vectors through the JS API", () => {
  const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json"));
  assert.equal(files.length, 82);
  for (const file of files) {
    const v = JSON.parse(readFileSync(join(vectorsDir, file), "utf8"));
    const block = hex(v.block_hex);
    const run = () => v.params.requested_block_id === null
      ? sbtp.validateSubmitted(block, v.params.difficulty)
      : sbtp.validateRequested(block, v.params.difficulty, hex(v.params.requested_block_id));
    if (v.expect.error === null) {
      const info = run();
      assert.equal(info.authenticated, true, file);
      assert.equal(info.blockIdHex, v.expect.block_id, file);
      info.free();
    } else {
      throwsNamed(run, v.expect.error);
    }
    if (v.expect.block_id !== null) {
      assert.equal(toHex(sbtp.signingMessage(block)), v.expect.signed_message_hex, file);
    }
  }
});

await check("demo key: build, mine, sign, verify round trip", () => {
  const key = sbtp.DemoSigningKey.generate();
  const block = minedBlock(key.publicKey, 8);
  const signed = key.signBlock(block);
  const info = sbtp.validateSubmitted(signed, 8);
  assert.equal(info.authenticated, true);
  assert.ok(info.leadingZeroBits >= 8);
  assert.equal(new TextDecoder().decode(info.payload), "smoke");
  const fetched = sbtp.validateRequested(signed, 8, info.blockId);
  assert.equal(fetched.blockIdHex, info.blockIdHex);
  // Tampering is caught with the spec name.
  const tampered = signed.slice();
  tampered[tampered.length - 65] ^= 1; // the last payload byte, just before the signature
  throwsNamed(() => sbtp.validateSubmitted(tampered, 0), "InvalidSignature");
  throwsNamed(() => sbtp.validateRequested(signed, 8, new Uint8Array(32)), "BlockIdMismatch");
  // Seed round trip.
  const seed = key.exportSeed();
  const again = sbtp.DemoSigningKey.fromSeed(seed);
  seed.fill(0);
  assert.deepEqual(again.publicKey, key.publicKey);
  info.free(); fetched.free(); again.free(); key.free();
});

await check("external signer: Web Crypto Ed25519, signing bytes out, signature in", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const block = minedBlock(publicKey, 4, "webcrypto");
  const message = sbtp.signingMessage(block);
  assert.equal(message.length, 49);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, message));
  const signed = sbtp.attachSignature(block, signature);
  assert.equal(sbtp.validateSubmitted(signed, 4).authenticated, true);
  // A signature over something else is refused at attach time.
  const wrong = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, block));
  throwsNamed(() => sbtp.attachSignature(block, wrong), "InvalidSignature");
});

await check("item 1: end of the nonce space throws NonceSpaceExhausted", () => {
  const key = sbtp.DemoSigningKey.fromSeed(new Uint8Array(32).fill(1));
  const block = sbtp.buildUnsignedBlock(
    key.publicKey, 0n, 2n ** 64n - 3n, new Uint8Array(0), new Uint8Array(0));
  assert.equal(sbtp.mineSlice(block, 256, 1), undefined); // tried 2^64-3, resumes at 2^64-2
  throwsNamed(() => sbtp.mineSlice(block, 256, 5), "NonceSpaceExhausted");
  throwsNamed(() => sbtp.mineSlice(block, 256, 5), "NonceSpaceExhausted"); // and stays so
  key.free();
});

await check("item 2: numeric arguments are checked, not coerced", () => {
  const key = sbtp.DemoSigningKey.fromSeed(new Uint8Array(32).fill(1));
  const signed = key.signBlock(minedBlock(key.publicKey, 0));
  for (const bad of [undefined, null, NaN, 1.5, -1, "8", 8n, Infinity]) {
    throwsNamed(() => sbtp.validateSubmitted(signed, bad), "InvalidArgument");
    throwsNamed(() => sbtp.validateRequested(signed, bad, new Uint8Array(32)), "InvalidArgument");
    throwsNamed(() => sbtp.mineSlice(signed, bad, 1), "InvalidArgument");
  }
  throwsNamed(() => sbtp.validateSubmitted(signed, 257), "DifficultyTooHigh");
  throwsNamed(() => sbtp.validateSubmitted(signed, 2 ** 32), "DifficultyTooHigh");
  for (const bad of [undefined, 0, -1, 0.5, NaN, 2 ** 53, "1"]) {
    throwsNamed(() => sbtp.mineSlice(signed, 1, bad), "InvalidArgument");
  }
  const build = (timestamp, nonce) => sbtp.buildUnsignedBlock(
    key.publicKey, timestamp, nonce, new Uint8Array(0), new Uint8Array(0));
  for (const bad of [-1n, 2n ** 64n, 5, undefined, "5"]) {
    throwsNamed(() => build(bad, 0n), "InvalidArgument");
    throwsNamed(() => build(0n, bad), "InvalidArgument");
  }
  assert.equal(sbtp.parseBlock(build(2n ** 64n - 1n, 0n)).timestamp, 2n ** 64n - 1n);
  key.free();
});

await check("item 3: non-Uint8Array arguments throw InvalidArgument; free() still wipes", () => {
  for (const bad of [undefined, null, [1, 2, 3], "SB", new ArrayBuffer(118), new Uint16Array(59)]) {
    throwsNamed(() => sbtp.parseBlock(bad), "InvalidArgument");
    throwsNamed(() => sbtp.blockId(bad), "InvalidArgument");
    throwsNamed(() => sbtp.DemoSigningKey.fromSeed(bad), "InvalidArgument");
  }
  const key = sbtp.DemoSigningKey.generate();
  throwsNamed(() => key.signBlock(undefined), "InvalidArgument");
  throwsNamed(() => key.signBlock(new Uint8Array(3)), "TooShort");
  throwsNamed(() => key.signBlock(minedBlock(new Uint8Array(32).fill(9), 0)), "KeyMismatch");
  // No borrow was left behind by the failed calls: free() succeeds, the object is then dead.
  key.free();
  assert.throws(() => key.publicKey);
});

await check("length caps and named length errors", () => {
  throwsNamed(() => sbtp.parseBlock(new Uint8Array(70_000)), "TooLong");
  const pk = new Uint8Array(32).fill(1);
  const build = (key, parents, payload) => sbtp.buildUnsignedBlock(key, 0n, 0n, parents, payload);
  throwsNamed(() => build(new Uint8Array(31), new Uint8Array(0), new Uint8Array(0)), "InvalidLength");
  throwsNamed(() => build(pk, new Uint8Array(33), new Uint8Array(0)), "InvalidLength");
  throwsNamed(() => build(pk, new Uint8Array(9 * 32).map((_, i) => i), new Uint8Array(0)), "TooManyParents");
  throwsNamed(() => build(pk, new Uint8Array(100_000), new Uint8Array(0)), "TooManyParents");
  throwsNamed(() => build(pk, new Uint8Array(64), new Uint8Array(0)), "DuplicateParent");
  throwsNamed(() => build(pk, new Uint8Array(0), new Uint8Array(65_536)), "PayloadTooLong");
  throwsNamed(() => build(pk, new Uint8Array(0), new Uint8Array(1_000_000)), "PayloadTooLong");
  throwsNamed(() => sbtp.attachSignature(new Uint8Array(118), new Uint8Array(63)), "InvalidLength");
});

console.log(`${passed} checks passed${process.exitCode ? ", some FAILED" : ""}`);
