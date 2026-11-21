# sbtp-wasm

WebAssembly bindings of `sbtp-core`, the generic layer 2 grammar (`sbtp-l2`) and the sealed envelope
(`sbtp-seal`) for browsers and other JavaScript runtimes. Every protocol rule (decoding, `block_id`,
proof of work, strict Ed25519, grammar validation, HPKE, buckets, padding, the order of the open checks)
runs in those crates; the bindings only move bytes across the boundary.

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
release profile does not set `strip` (it would drop that section).

### Features and size (Q-78)

| Cargo features | `.wasm` raw | `.wasm` gzip -9 | JS glue raw / gzip -9 |
|---|---|---|---|
| `--no-default-features` (layer 0 only) | 139,170 | 78,512 | 23,315 / 5,530 |
| `--no-default-features --features l2` | 165,304 | 89,918 | 27,029 / 6,133 |
| default (`seal`, which includes `l2`) | 237,091 | 119,069 | 43,069 / 8,860 |

Bytes, measured 2026-11-21 after `wasm-opt -Os --strip-debug --strip-producers --strip-target-features`
(binaryen 133, wasm-bindgen 0.2.130). The full module uses 60 % of the 200,000-byte gzip budget of
ADR 0048, so the layer 2 grammar and the sealed envelope ship **in the core module**, behind the
features `l2` and `seal`, both on by default; there is no second module. An application that needs
layer 0 only builds with `--no-default-features`. CI checks the default build against the budget
(`web/wasm-budget.py`), and so does the Node smoke test.

The page's Content Security Policy needs `'wasm-unsafe-eval'` in `script-src` (not `'unsafe-eval'`).

## Tests

- Native: `cargo test -p sbtp-wasm` (binding logic, the 82 frozen vectors through the binding API, seal
  and open round trips, every open failure giving the same error, an entropy failure giving an error).
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
`NonceSpaceExhausted`, `KeyMismatch`, `Signing`, `EntropyUnavailable` or `SelfTestFailed`; for layer 2 and
sealing, `InvalidPayload`, `OpenFailed`, `SealTooLong`, `InvalidRecipientKey`, `ReservedContext`,
`NotOuterBlock` or `EphemeralKeyUsed`.

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

## Layer 2 grammar (feature `l2`)

```js
const l2 = sbtp.validateL2Payload(info.parents, info.payload); // after validateRequested
l2.kind; l2.edgeCount;
l2.x25519; l2.introBucket; // sbtp.enc_key only, otherwise undefined
l2.rawBody;                // application kinds: the encoded body, for the application's own checks
l2.free();
```

A grammar failure throws `InvalidPayload` whose `message` is exactly the `sbtp-l2` rule name
(`BadEnvelope`, `UncoveredParent`, `MapKeysUnsorted`...).

## Sealed envelope (feature `seal`)

`docs/spec/l2-grammar.md` §5. The sender seals a grammar payload `msg` to a recipient's X25519 key; the
outer `sbtp.enc` block is signed by a fresh ephemeral key that never leaves WASM.

```js
// Recipient: an X25519 key, published in an sbtp.enc_key block under directoryTag(identity).
const encKey = sbtp.EncKeyPair.generate();     // crypto.getRandomValues
encKey.publicKey;                              // the x25519 field of sbtp.enc_key

// Sender. `sender` is a DemoSigningKey (see "Remaining limits"); `tag` comes from the application
// (applicationTag), and `recipientId` is the one the application fixes for that tag.
const env = sbtp.seal(sender, recipientX25519, recipientId, tag, msg /*, bucket */);
const block = env.unsignedBlock(BigInt(Date.now()));  // PubKey: the ephemeral key; parent: the tag
while (sbtp.mineSlice(block, difficulty, 1 << 16) === undefined) { /* in a Worker */ }
const signed = env.signBlock(block);  // once: the ephemeral key is wiped right after
env.free();

// Recipient, on a block that passed validateRequested:
try {
  const m = sbtp.openSealed(encKey, info.publicKey, info.parent(0), info.payload, myRecipientId,
                            "app.note app.reply");
  m.msg; m.from; m.kind;  // then the application's own checks (spec §5.3 steps 9 and 10)
  m.free();
} catch (e) {
  if (e.name !== "OpenFailed") throw e;  // not for us: ignore it silently, tell no one
}
```

- `bucket`: omitted (or `null`) for the smallest that fits, or one of `512`, `2048`, `8192`, `65535`.
- `openSealed` takes one key: with several (rotation), try each, newest first, and keep the first
  success. **Every failure is `OpenFailed` with the same message** (security review 2026-11-21, I-4):
  nothing tells which check failed. Only argument shapes are reported separately (`InvalidArgument`,
  `InvalidLength`).
- `allowedKinds` is one string, kinds separated by spaces or commas (a kind never contains either). It
  is not an array on purpose: reading an array runs JS getters while the key is borrowed, and in the
  glue an array-like with a huge `length` can overwrite the instance's memory.
- `signBlock` refuses a block that does not carry the envelope's tag as its only parent and its payload
  (`NotOuterBlock`), so the ephemeral key cannot be made to sign anything else.
- Tags: `directoryTag(identityPublicKey)`, `isDirectoryTag(publicKey, tag)` (spec §5.5: ignore a key
  block for which it is `false`), `applicationTag(context, input)` (spec §5.4). `input` is the
  concatenation of the derivation inputs, with no separator or length prefix: the inputs SHOULD be of
  fixed length, or length-prefixed by the application's specification, otherwise two different tuples
  can give the same tag (review I-1).
- `EncKeyPair.fromSecret(secret)` and `encKey.exportSecret()` are for storage. The rules of a demo seed
  apply: stored encrypted, never in `localStorage`, a log or a URL; `fill(0)` the JS copy afterwards.

### Randomness

The only random source is Web Crypto `crypto.getRandomValues`, through `getrandom`'s `wasm_js` backend
(the OS source natively). No caller can pass a generator (review L-3). If the source fails, whatever was
computed is discarded and the call throws `EntropyUnavailable`; it never panics.

### Secrets: what is wiped, what cannot be

Wiped when the object is freed (call `free()`: garbage collection is neither prompt nor guaranteed):
the X25519 private key of an `EncKeyPair`, the ephemeral Ed25519 key of a `SealedEnvelope` (also wiped
right after its one `signBlock`), and the `msg` and `kind` an `OpenedMessage` holds. The binding's own
copy of the `msg` argument of `seal` is wiped when `seal` returns. No secret, no `from` and no `msg` appears in a `Debug` output or in
an error message.

Cannot be wiped from WASM:
- the caller's arguments: `msg` given to `seal`, `secret` given to `EncKeyPair.fromSecret`;
- every value a getter returns, which is a fresh JS copy: `OpenedMessage.msg`, `.from`, `.kind`, and
  `EncKeyPair.exportSecret()`. `fill(0)` the typed arrays once done; a JS string (`kind`) cannot be
  wiped at all;
- transient copies inside WASM: moves of the key values into the objects wasm-bindgen allocates, the
  internal temporaries of the HPKE and Ed25519 code, freed heap buffers (best effort, as for
  `DemoSigningKey`). On the seal side, `sbtp-seal` grows its plaintext buffer while it encodes and pads
  the item, which leaves copies of `msg` in freed heap memory (review L-1, to be fixed in `sbtp-seal`).

### Remaining limits

- The sender's identity key must be a `DemoSigningKey` (its seed in WASM memory): `sbtp_seal::seal`
  makes the inner signature itself, so a non-extractable Web Crypto identity cannot seal yet. That needs
  a split of the seal step in `sbtp-seal` (signing bytes out, signature in), as `signingMessage` and
  `attachSignature` do for blocks.
- The threat model is unchanged: WASM linear memory is readable by any script of the page. An XSS or a
  malicious dependency can read the X25519 keys and an opened message while they are in memory.
