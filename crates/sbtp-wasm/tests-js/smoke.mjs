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
import { gzipSync } from "node:zlib";

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

// --- Layer 2 grammar and sealed envelope (features `l2` and `seal`, on by default) ---

// {"v": 1, "body": {"t": "hi"}, "kind": "app.note", "edges": []}, deterministic CBOR (keys in
// bytewise order of their encodings). A test fixture, checked by validateL2Payload below.
const NOTE = hex("a4617601" + "64626f6479a1617462" + "6869" + "646b696e6468" + "6170702e6e6f7465"
  + "65656467657380");
const fill = (n, byte) => new Uint8Array(n).fill(byte);

await check("validateL2Payload: kind, raw body, rule names", () => {
  const info = sbtp.validateL2Payload(new Uint8Array(0), NOTE);
  assert.equal(info.kind, "app.note");
  assert.equal(info.edgeCount, 0);
  assert.ok(info.rawBody instanceof Uint8Array);
  assert.equal(info.x25519, undefined);
  info.free();
  const rule = (parents, payload) => {
    try { sbtp.validateL2Payload(parents, payload); } catch (e) { return `${e.name}:${e.message}`; }
    return "valid";
  };
  assert.equal(rule(new Uint8Array(0), new Uint8Array([0xa0])), "InvalidPayload:BadEnvelope");
  assert.equal(rule(fill(32, 7), NOTE), "InvalidPayload:UncoveredParent");
  assert.equal(rule(fill(9 * 32, 7), NOTE), "InvalidPayload:TooManyParents");
  throwsNamed(() => sbtp.validateL2Payload(fill(33, 7), NOTE), "InvalidLength");
  throwsNamed(() => sbtp.validateL2Payload(undefined, NOTE), "InvalidArgument");
});

// Test keys from public seeds only.
function sealFixture(bucket) {
  const sender = sbtp.DemoSigningKey.fromSeed(fill(32, 0x11));
  const recipient = sbtp.EncKeyPair.fromSecret(fill(32, 0x22));
  const id = fill(32, 0x33);
  const tag = sbtp.applicationTag("app 2026-11-21 test inbox", id);
  const env = sbtp.seal(sender, recipient.publicKey, id, tag, NOTE, bucket);
  return { sender, recipient, id, tag, env };
}

await check("seal, mine, sign, validate, open: round trip", () => {
  const { sender, recipient, id, tag, env } = sealFixture();
  assert.equal(env.bucket, 512);
  assert.equal(env.payload.length, 512);
  assert.deepEqual(env.tag, tag);
  const block = env.unsignedBlock(BigInt(Date.now()));
  while (sbtp.mineSlice(block, 4, 1 << 12) === undefined) { /* next slice */ }
  assert.equal(env.signed, false);
  const signed = env.signBlock(block);
  assert.equal(env.signed, true);
  throwsNamed(() => env.signBlock(block), "EphemeralKeyUsed"); // one signature only
  // The receiving side: layer 0, then grammar, then open.
  const info = sbtp.validateSubmitted(signed, 4);
  assert.deepEqual(info.publicKey, env.publicKey);
  const outer = sbtp.validateL2Payload(info.parents, info.payload);
  assert.equal(outer.kind, "sbtp.enc");
  const opened = sbtp.openSealed(recipient, info.publicKey, info.parent(0), info.payload, id,
    "app.other, app.note");
  assert.deepEqual(opened.msg, NOTE);
  assert.deepEqual(opened.from, sender.publicKey);
  assert.equal(opened.kind, "app.note");
  opened.free(); outer.free(); info.free(); env.free(); recipient.free(); sender.free();
});

await check("openSealed: every failure is the same opaque OpenFailed (review I-4)", () => {
  const { recipient, id, tag, env } = sealFixture(2048);
  assert.equal(env.payload.length, 2048);
  const other = sbtp.EncKeyPair.fromSecret(fill(32, 0x44));
  const flipped = env.payload; flipped[flipped.length - 1] ^= 1;
  const cases = [
    [other, env.publicKey, tag, env.payload, id, "app.note"],      // wrong key
    [recipient, env.publicKey, tag, flipped, id, "app.note"],      // tampered ciphertext
    [recipient, fill(32, 0x55), tag, env.payload, id, "app.note"], // wrong outer PubKey
    [recipient, env.publicKey, fill(32, 9), env.payload, id, "app.note"], // wrong tag
    [recipient, env.publicKey, tag, env.payload, fill(32, 0x66), "app.note"], // wrong recipient id
    [recipient, env.publicKey, tag, env.payload, id, "app.other"], // kind not allowed
    [recipient, env.publicKey, tag, env.payload, id, ""],          // no kind allowed
    [recipient, env.publicKey, tag, NOTE, id, "app.note"],         // not an sbtp.enc payload
    [recipient, env.publicKey, tag, new Uint8Array(70_000), id, "app.note"], // oversized
  ];
  const messages = new Set();
  for (const args of cases) {
    assert.throws(() => sbtp.openSealed(...args), (e) => {
      assert.equal(e.constructor, Error);
      assert.equal(e.name, "OpenFailed");
      messages.add(e.message);
      return true;
    });
  }
  assert.equal(messages.size, 1, [...messages].join(" | "));
  // Argument shapes are the caller's bugs, reported as such.
  throwsNamed(() => sbtp.openSealed(recipient, env.publicKey, tag, env.payload, id, ["app.note"]),
    "InvalidArgument");
  throwsNamed(() => sbtp.openSealed(recipient, new Uint8Array(31), tag, env.payload, id, "app.note"),
    "InvalidLength");
  // The key is not left borrowed by the failures: it still opens, and free() works.
  sbtp.openSealed(recipient, env.publicKey, tag, env.payload, id, "app.note").free();
  other.free(); recipient.free(); env.free();
});

await check("seal: arguments, buckets and named errors", () => {
  const sender = sbtp.DemoSigningKey.fromSeed(fill(32, 0x11));
  const key = sbtp.EncKeyPair.generate();
  const id = fill(32, 1);
  const tag = fill(32, 2);
  for (const [bucket, len] of [[undefined, 512], [null, 512], [8192, 8192], [65535, 65535]]) {
    const env = sbtp.seal(sender, key.publicKey, id, tag, NOTE, bucket);
    assert.equal(env.payload.length, len);
    env.free();
  }
  for (const bad of [1000, 512.5, "512", 512n, -1]) {
    throwsNamed(() => sbtp.seal(sender, key.publicKey, id, tag, NOTE, bad), "InvalidArgument");
  }
  throwsNamed(() => sbtp.seal(sender, key.publicKey, id, tag, new Uint8Array([0xa0])),
    "InvalidPayload");
  throwsNamed(() => sbtp.seal(sender, new Uint8Array(32), id, tag, NOTE), "InvalidRecipientKey");
  throwsNamed(() => sbtp.seal(sender, key.publicKey, id, tag, new Uint8Array(70_000)),
    "SealTooLong");
  throwsNamed(() => sbtp.seal(sender, key.publicKey, new Uint8Array(3), tag, NOTE), "InvalidLength");
  assert.throws(() => sbtp.seal(key, key.publicKey, id, tag, NOTE)); // not a DemoSigningKey
  // The outer block of another envelope is refused, and the key kept.
  const env = sbtp.seal(sender, key.publicKey, id, tag, NOTE);
  const foreign = sbtp.buildUnsignedBlock(env.publicKey, 0n, 0n, tag, new Uint8Array(512));
  throwsNamed(() => env.signBlock(foreign), "NotOuterBlock");
  assert.equal(env.signed, false);
  env.signBlock(env.unsignedBlock(0n));
  env.free(); key.free(); sender.free();
});

await check("EncKeyPair and tags", () => {
  const a = sbtp.EncKeyPair.generate();
  const b = sbtp.EncKeyPair.generate();
  assert.notDeepEqual(a.publicKey, b.publicKey);
  const secret = a.exportSecret();
  const again = sbtp.EncKeyPair.fromSecret(secret);
  secret.fill(0);
  assert.deepEqual(again.publicKey, a.publicKey);
  throwsNamed(() => sbtp.EncKeyPair.fromSecret(new Uint8Array(31)), "InvalidLength");
  a.free(); b.free(); again.free();
  const identity = fill(32, 7);
  const tag = sbtp.directoryTag(identity);
  assert.equal(tag.length, 32);
  assert.equal(sbtp.isDirectoryTag(identity, tag), true);
  assert.equal(sbtp.isDirectoryTag(fill(32, 8), tag), false);
  throwsNamed(() => sbtp.applicationTag("SBTP-x", new Uint8Array(0)), "ReservedContext");
  throwsNamed(() => sbtp.applicationTag("", new Uint8Array(0)), "ReservedContext");
  throwsNamed(() => sbtp.applicationTag(42, new Uint8Array(0)), "InvalidArgument");
  assert.notDeepEqual(sbtp.applicationTag("app 1 a", identity), sbtp.applicationTag("app 1 b", identity));
});

await check("module size: under the 200,000-byte gzip budget of ADR 0048", () => {
  // The unoptimised wasm-bindgen output, an upper bound of the shipped module.
  const gz = gzipSync(readFileSync(join(pkg, "sbtp_wasm_bg.wasm")), { level: 9 }).length;
  assert.ok(gz < 200_000, `${gz} bytes gzip`);
});

console.log(`${passed} checks passed${process.exitCode ? ", some FAILED" : ""}`);
