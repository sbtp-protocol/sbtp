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

### npm package `@sbtp/wasm` (ADR 0053)

`crates/sbtp-wasm/npm/build.sh` builds the npm package from a clean tree into
`dist-npm/sbtp-wasm-<version>.tgz` and prints its SHA-256 and integrity string; `check.sh` checks a
tarball's contents (file list, no script, no local path, size budget). The tools are pinned in
`build.sh` (rustc from `rust-toolchain.toml`, wasm-bindgen from `Cargo.lock`, binaryen 133, Node.js
22.23.4 with npm 10.9.9). The package ships one module and one glue (`--target web`) with a Node.js
entry (`npm/node.js`) that instantiates the module synchronously; see `npm/README.md`. Packages are
published by CI only (`.github/workflows/release-npm.yml`), never from a workstation.

### Features and size (Q-78)

| Cargo features | `.wasm` raw | `.wasm` gzip -9 | JS glue raw / gzip -9 |
|---|---|---|---|
| `--no-default-features` (layer 0 only) | 139,170 | 78,512 | 23,315 / 5,530 |
| `--no-default-features --features l2` | 165,304 | 89,918 | 27,029 / 6,133 |
| default (`seal`, which includes `l2`) | 245,177 | 122,377 | 49,149 / 9,990 |

Bytes, measured 2026-11-21 (default row: 2026-11-22, with `SigningMessage`) after `wasm-opt -Os --strip-debug --strip-producers --strip-target-features`
(binaryen 133, wasm-bindgen 0.2.130). The full module uses 61 % of the 200,000-byte gzip budget of
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
`InvalidSignature`, as in `docs/test-vectors/`) for a validation failure (also used by
`SealPending.finish` for the inner signature: `InvalidPublicKey`, `InvalidSignature`), otherwise `InvalidArgument`,
`InvalidLength`, `TooManyParents`, `DuplicateParent`, `PayloadTooLong`, `DifficultyTooHigh`,
`NonceSpaceExhausted`, `KeyMismatch`, `Signing`, `EntropyUnavailable` or `SelfTestFailed`; for layer 2 and
sealing, `InvalidPayload`, `OpenFailed`, `SealTooLong`, `InvalidRecipientKey`, `ReservedContext`,
`NotOuterBlock`, `EphemeralKeyUsed` or `PendingSealUsed`.

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
const message = sbtp.signingMessage(block);  // SigningMessage, kind "block": SIG_PREFIX || block_id
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, message.bytes));
message.free();
const signed = sbtp.attachSignature(block, signature);   // verified (C2, C3) before it returns
```

### Signing messages (ADR 0055 E1)

`signingMessage(block)` and `SealPending.message` return a `SigningMessage`, not bytes: `bytes` (a
copy, 49 bytes for kind `"block"`, the spec §5.3 message for kind `"sealed"`), `kind` (`"block"` or
`"sealed"`), `free()`. It has no constructor and no factory: only these two typed builders make one.
The shipped `.d.ts` also brands it, so a `Uint8Array` or an object literal does not type-check where a
`SigningMessage` is expected.

This protects against API misuse, not against code in the same JavaScript realm. A signer that takes a
`SigningMessage` and checks `message instanceof SigningMessage` cannot be handed caller bytes by
mistake, but code running in the page can forge one (`Object.create(SigningMessage.prototype)`, the
glue's static `__wrap`, or a write to the module's `memory`), and can call `crypto.subtle.sign` on the
key handle directly anyway (see the threat model below). A signer should therefore also check the
shape of `bytes`: kind `"block"` is exactly 49 bytes starting with `SBTP-v1-block-sig`; kind `"sealed"`
is at least 114 bytes starting with `SBTP-v1-sealed-sig`. A sealed message holds `msg`: free it after
signing, and `fill(0)` the `bytes` copy.

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

// Sender with a DemoSigningKey `sender` (seed in WASM memory); `tag` comes from the application
// (applicationTag), and `recipientId` is the one the application fixes for that tag.
const env = sbtp.seal(sender, recipientX25519, recipientId, tag, msg /*, bucket */);
const block = env.unsignedBlock(BigInt(Date.now()));  // PubKey: the ephemeral key; parent: the tag
while (sbtp.mineSlice(block, difficulty, 1 << 16) === undefined) { /* in a Worker */ }
const signed = env.signBlock(block);  // once: the ephemeral key is wiped right after
env.free();

// Sender whose identity is a non-extractable Web Crypto key: two phases, the signature made outside.
const pending = sbtp.sealPrepare(identityPublicKey, recipientX25519, recipientId, tag, msg);
const toSign = pending.message;    // SigningMessage, kind "sealed"
const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", identityKey, toSign.bytes));
toSign.free();
const env2 = pending.finish(sig);  // verifies sig (strict) before sealing; once only
pending.free();
// ...then unsignedBlock, mine, signBlock as above.

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
- `sealPrepare(from, ...)` draws the ephemeral key and returns a `SealPending`; `pending.message` is
  a `SigningMessage` whose `bytes` are the exact sealed signature message of `l2-grammar.md` §5.3 (`SBTP-v1-sealed-sig ‖ outer_pubkey ‖
  recipient_id ‖ recipient_x25519 ‖ msg`), built in WASM by the typed builder. Sign it, and nothing else,
  with the key of `from`. `pending.finish(signature)` verifies the signature with criteria V1 to V6
  (`InvalidPublicKey`, `InvalidSignature`) and only then seals. It runs once: the state is consumed even
  on error (`PendingSealUsed` afterwards; call `sealPrepare` again), except for an argument of the wrong
  shape. `sealPrepare` returns a class rather than a `{ message, pending }` object on purpose: building a
  JS object from WASM sets properties, which can run setters of a polluted `Object.prototype`, and a
  throw there would unwind through WASM frames without wiping the ephemeral key.
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
the X25519 private key of an `EncKeyPair`, the ephemeral Ed25519 key and the encoded plaintext of a
`SealPending` (moved out by `finish`: a copy of the pending state, ephemeral key included, stays in the
`SealPending`'s freed memory and is not wiped yet, see `docs/security/2026-11-21-wasm-seal.md` L-1), the ephemeral Ed25519 key of a `SealedEnvelope` (also wiped
right after its one `signBlock`), and the `msg` and `kind` an `OpenedMessage` holds. The binding's own
copy of the `msg` argument of `seal` and `sealPrepare` is wiped when the call returns. No secret, no `from` and no `msg` appears in a `Debug` output or in
an error message.

Cannot be wiped from WASM:
- the caller's arguments: `msg` given to `seal` or `sealPrepare`, `secret` given to `EncKeyPair.fromSecret`;
- every value a getter returns, which is a fresh JS copy: `SigningMessage.bytes` of `SealPending.message` (it contains `msg`),
  `OpenedMessage.msg`, `.from`, `.kind`, and
  `EncKeyPair.exportSecret()`. `fill(0)` the typed arrays once done; a JS string (`kind`) cannot be
  wiped at all;
- transient copies inside WASM: moves of the key values into the objects wasm-bindgen allocates, the
  internal temporaries of the HPKE and Ed25519 code, freed heap buffers (best effort, as for
  `DemoSigningKey`). `sbtp-seal` writes the item into one buffer of the bucket's plaintext length and
  never resizes it (review L-1, fixed), so no freed buffer of its own holds `msg`.

### Remaining limits

- The threat model is unchanged: WASM linear memory is readable by any script of the page. An XSS or a
  malicious dependency can read the X25519 keys and an opened message while they are in memory.
