// Smoke test of the installed @sbtp/wasm package (run by smoke.sh from a scratch project that
// installed the tarball): resolution through package.json "exports", the Node.js entry, and a
// seal, mine, sign, validate, open round trip. Test keys from public seeds only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import init, * as sbtp from "@sbtp/wasm";

const require = createRequire(import.meta.url);
const hex = (text) => Uint8Array.from(text.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fill = (n, byte) => new Uint8Array(n).fill(byte);

// The Node.js entry has instantiated the module (and run the self-test) on import.
const resolved = require.resolve("@sbtp/wasm");
assert.match(resolved, /[\\/]node_modules[\\/]@sbtp[\\/]wasm[\\/]node\.js$/);
await init(); // accepted, returns at once
sbtp.selfTest();
const manifest = JSON.parse(readFileSync(require.resolve("@sbtp/wasm/package.json"), "utf8"));
assert.equal(manifest.scripts, undefined);
assert.equal(typeof sbtp.validateRequested, "function");

// {"v": 1, "body": {"t": "hi"}, "kind": "app.note", "edges": []}, deterministic CBOR.
const NOTE = hex("a4617601" + "64626f6479a1617462" + "6869" + "646b696e6468" + "6170702e6e6f7465"
  + "65656467657380");

// Layer 2 grammar.
const note = sbtp.validateL2Payload(new Uint8Array(0), NOTE);
assert.equal(note.kind, "app.note");
note.free();

// Seal to a recipient, mine, sign with the ephemeral key, then the receiving side: layer 0,
// grammar, open.
const sender = sbtp.DemoSigningKey.fromSeed(fill(32, 0x11));
const recipient = sbtp.EncKeyPair.fromSecret(fill(32, 0x22));
const recipientId = fill(32, 0x33);
const tag = sbtp.applicationTag("app 2026-11-21 test inbox", recipientId);
const env = sbtp.seal(sender, recipient.publicKey, recipientId, tag, NOTE);
const block = env.unsignedBlock(BigInt(Date.now()));
let blockId;
while ((blockId = sbtp.mineSlice(block, 8, 1 << 12)) === undefined) { /* next slice */ }
const signed = env.signBlock(block);

const info = sbtp.validateRequested(signed, 8, blockId);
assert.equal(info.authenticated, true);
assert.equal(info.blockIdHex, toHex(blockId));
const outer = sbtp.validateL2Payload(info.parents, info.payload);
assert.equal(outer.kind, "sbtp.enc");
const opened = sbtp.openSealed(recipient, info.publicKey, info.parent(0), info.payload, recipientId,
  "app.note");
assert.deepEqual(opened.msg, NOTE);
assert.deepEqual(opened.from, sender.publicKey);
assert.equal(opened.kind, "app.note");

// A tampered block is refused with a named error.
const tampered = signed.slice();
tampered[tampered.length - 1] ^= 1;
assert.throws(() => sbtp.validateSubmitted(tampered, 8), (e) => e instanceof Error && e.name !== "Error");

// A recipient with another key cannot open it, and learns nothing about why.
const other = sbtp.EncKeyPair.fromSecret(fill(32, 0x44));
assert.throws(() => sbtp.openSealed(other, info.publicKey, info.parent(0), info.payload, recipientId,
  "app.note"), (e) => e.name === "OpenFailed");

for (const o of [opened, outer, info, env, recipient, other, sender]) o.free();
console.log(`ok   @sbtp/wasm ${manifest.version}: exports, Node.js entry, seal/open and validate round trip`);
