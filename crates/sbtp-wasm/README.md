# sbtp-wasm

WebAssembly bindings of `sbtp-core` for browsers and other JavaScript runtimes. Every protocol rule
(decoding, `block_id`, proof of work, strict Ed25519) runs in `sbtp-core`; the bindings only move bytes
across the boundary.

**Browsers verify blocks through these bindings only.** JS Ed25519 libraries and Web Crypto `verify`
do not apply the strict criteria V1 to V6 of spec §3.2 and diverge from the test vectors.

## Build

Tools: the wasm-bindgen CLI of the **same version** as the crate (0.2.130) and binaryen's `wasm-opt`.

```bash
cargo build -p sbtp-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir target/wasm-pkg/web \
  target/wasm32-unknown-unknown/release/sbtp_wasm.wasm
wasm-opt -Os --strip-debug --strip-producers --strip-target-features \
  target/wasm-pkg/web/sbtp_wasm_bg.wasm -o target/wasm-pkg/web/sbtp_wasm_bg.wasm
```

`wasm-opt` needs no feature flags: it reads them from the `target_features` section, which is why the
release profile does not set `strip` (it would drop that section). The final module is about 141 KB raw,
79 KB gzip; the JS glue about 23 KB raw, 6 KB gzip (2026-11-19).

The page's Content Security Policy needs `'wasm-unsafe-eval'` in `script-src` (not `'unsafe-eval'`).

## Tests

- Native: `cargo test -p sbtp-wasm` (binding logic, the 82 frozen vectors through the binding API).
- JS API, with plain Node (no npm package): build as above with `--target nodejs --out-dir
  target/wasm-pkg/node`, then `node crates/sbtp-wasm/tests-js/smoke.mjs target/wasm-pkg/node`.

## API

Byte arguments and results are `Uint8Array`; `timestamp` and `nonce` are `bigint` (0 to 2^64 − 1);
`difficulty` (0 to 256) and `maxAttempts` (1 to 2^53 − 1) are integer `number`s. Arguments are checked,
never coerced: `undefined`, `NaN`, a fraction, a plain `Array` or a negative `bigint` throws
`InvalidArgument`.

Every failure throws an `Error` whose `name` is stable: the spec §2.2 rule (`TooShort`, ...,
`InvalidSignature`, as in `docs/test-vectors/`) for a validation failure, otherwise `InvalidArgument`,
`InvalidLength`, `TooManyParents`, `DuplicateParent`, `PayloadTooLong`, `DifficultyTooHigh`,
`NonceSpaceExhausted`, `KeyMismatch`, `Signing`, `EntropyUnavailable` or `SelfTestFailed`.

```js
import init, * as sbtp from "./pkg/sbtp_wasm.js";
await init(); // runs the S + L self-test (ADR 0003 rule 16): rejects on a bad build

// Receive: every block fetched by id goes through validateRequested (R1 included).
const info = sbtp.validateRequested(bytes, relayDifficulty, requestedId);
info.authenticated; // true
info.payload, info.publicKey, info.parentCount, info.parent(0), info.blockIdHex;
info.free(); // BlockInfo lives in WASM memory

// Send, with a key held outside WASM (Web Crypto Ed25519, extractable: false):
const block = sbtp.buildUnsignedBlock(publicKey, BigInt(Date.now()), 0n, parents, payload);
while (sbtp.mineSlice(block, difficulty, 1 << 16) === undefined) { /* yield; in a Worker */ }
const message = sbtp.signingMessage(block);              // 49 bytes: SIG_PREFIX || block_id
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, message));
const signed = sbtp.attachSignature(block, signature);   // verified (C2, C3) before it returns
```

`parents` is the concatenation of 0 to 8 distinct 32-byte identifiers. `mineSlice` mines in place and
returns the `block_id` once found, `undefined` when the slice is spent (call it again: the block holds the
next nonce), and throws `NonceSpaceExhausted` once nonce 2^64 − 1 has been tried. Run it in a Web Worker.

`parseBlock(bytes)` decodes the format only (F1 to F9): its result has `authenticated === false` and must
not be shown or stored as an authored block.

## Demo key (not for long-lived identities)

`DemoSigningKey.generate()` (entropy from `crypto.getRandomValues`), `DemoSigningKey.fromSeed(seed)`,
`key.publicKey`, `key.signBlock(block)`, `key.exportSeed()`, `key.free()`.

Threat model: the secret lives in WASM linear memory, readable by any script running in the page (an XSS
or a malicious dependency gets the key). The crate never logs or formats it, and wipes the key on
`free()`; wiping its other copies is best effort (transient copies on the WASM stack may remain). It
cannot wipe copies held by JS (`fromSeed` input, `exportSeed` output: call `fill(0)` on them). A persisted
seed MUST be stored encrypted (IndexedDB), never in `localStorage`, a log or a URL. A real client keeps its
identity in a non-extractable Web Crypto key and signs through `signingMessage` / `attachSignature`, so
that the secret never enters script-readable memory.

A non-extractable key prevents exfiltration, not use: a script running in the page can still have it sign
arbitrary SBTP blocks while the page is open. The web client should therefore sign only the output of
`signingMessage` (always `SIG_PREFIX`-prefixed, so domain separation holds) and dedicate that key to SBTP.
