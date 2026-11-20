// The sbtp-wasm facade in Node: plain results (I-3), external Web Crypto signer, poisoning after a
// foreign exception (I-5, in trap.test.mjs: it poisons the module for the whole process). Needs web/pkg (web/build.sh); skipped otherwise. With SBTP_RELAY set
// (for example http://127.0.0.1:8080), also publishes, lists and fetches back on that relay.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const wasmPath = new URL("../pkg/sbtp_wasm_bg.wasm", import.meta.url);
const skip = existsSync(wasmPath) ? false : "web/pkg missing: run web/build.sh";

async function load() {
  const w = await import("../src/wasm.js");
  await w.loadSbtp(readFileSync(wasmPath));
  return w;
}

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

function mine(w, block, d) {
  while (w.mineSlice(block, d, 1 << 16) === undefined) { /* next slice */ }
  return block;
}

test("build, mine, sign with a non-extractable Web Crypto key, verify", { skip }, async () => {
  const w = await load();
  const { signBlock } = await import("../src/keys.js");
  const key = await newKey();
  const payload = new TextEncoder().encode("web client test");
  const block = mine(w, w.buildUnsignedBlock(key.publicKey, BigInt(Date.now()), 0n, new Uint8Array(0), payload), 8);
  const signed = await signBlock(key, block);
  const b = w.verifySubmitted(signed, 8);
  assert.ok(Object.isFrozen(b) && !("free" in b)); // a plain object, the BlockInfo is freed
  assert.equal(new TextDecoder().decode(b.payload), "web client test");
  assert.equal(w.verifyFetched(signed, 8, b.idHex).idHex, b.idHex);
  assert.throws(() => w.verifyFetched(signed, 8, "00".repeat(32)), { name: "BlockIdMismatch" });
  assert.throws(() => w.verifySubmitted(signed, 255), { name: "InsufficientPow" });
  const other = await newKey();
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", other.privateKey, w.signingMessage(block)));
  assert.throws(() => w.attachSignature(block, sig), { name: "InvalidSignature" });
  // A bad argument converted in JS is a plain error and does not poison the module (finding 8).
  assert.throws(() => w.verifyFetched(signed, 8, "not hex"), TypeError);
  assert.ok(!w.isPoisoned());
  assert.equal(w.blockIdHex(signed), b.idHex);
});

const relayUrl = process.env.SBTP_RELAY;
test("end to end on a local relay: info, publish, walk, fetch and verify, ancestors", {
  skip: skip || (relayUrl ? false : "set SBTP_RELAY to run"),
}, async () => {
  const w = await load();
  const { signBlock } = await import("../src/keys.js");
  const { checkRelayUrl } = await import("../src/http.js");
  const { Relay, fetchBlocks, sendingDifficulty } = await import("../src/relay.js");
  const { walk } = await import("../src/walk.js");
  const { traverse } = await import("../src/traverse.js");
  const { fromHex } = await import("../src/hex.js");
  const relay = new Relay(checkRelayUrl(relayUrl));
  const d = sendingDifficulty(await relay.info(), null);
  const key = await newKey();
  const publish = async (text, parents = []) => {
    const unsigned = w.buildUnsignedBlock(key.publicKey, BigInt(Date.now()), 0n,
      fromHex(parents.join("")), new TextEncoder().encode(text));
    const signed = await signBlock(key, mine(w, unsigned, d));
    const b = w.verifySubmitted(signed, d);
    assert.equal(await relay.put(signed), "created");
    assert.equal(await relay.put(signed), "stored");
    return b.idHex;
  };
  const root = await publish(`root ${Date.now()}`);
  const child = await publish("child", [root]);
  const listed = await walk(relay, { parent: root });
  assert.deepEqual(listed.ids, [child]);
  const got = await fetchBlocks(relay, listed.ids, (bytes, i) => w.verifyFetched(bytes, 0, i));
  assert.equal(new TextDecoder().decode(got.blocks[0].payload), "child");
  const up = await traverse(child, async (i) => {
    const bytes = await relay.get(i);
    return bytes === null ? null : w.verifyFetched(bytes, 0, i).parents;
  });
  assert.deepEqual(up.visited, [child, root]);
  assert.equal(await relay.get("ff".repeat(32)), null);
});
