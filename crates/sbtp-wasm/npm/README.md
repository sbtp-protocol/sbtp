# @sbtp/wasm

The WebAssembly build of the SBTP reference implementation (Signed Block Transport Protocol): layer 0
(`sbtp-core`: binary block format, BLAKE3 `block_id`, strict Ed25519, proof of work), the generic layer 2
grammar (`sbtp-l2`) and the sealed envelope (`sbtp-seal`), for browsers, bundlers and Node.js.

Every protocol rule runs in Rust, inside the module; the JavaScript glue only moves bytes across the
boundary. **Verify blocks through this package only**: JavaScript Ed25519 libraries and Web Crypto
`verify` do not apply the strict criteria of the specification and diverge from its test vectors.

- Specification: [`docs/spec/`](https://github.com/sbtp-protocol/sbtp/tree/main/docs/spec)
- Full API, threat model of the keys, what is wiped and what cannot be:
  [`crates/sbtp-wasm/README.md`](https://github.com/sbtp-protocol/sbtp/blob/main/crates/sbtp-wasm/README.md)

## Install

Pin the exact version, commit your lockfile, and keep install scripts disabled. This package has no
dependencies and no install script.

```bash
npm install --save-exact --ignore-scripts @sbtp/wasm
# or
pnpm add --save-exact @sbtp/wasm
```

Before taking a new version, check its provenance (`npm audit signatures`): it MUST name the repository
`sbtp-protocol/sbtp`, the workflow `.github/workflows/release-npm.yml` and a commit on `main`.

## Use

Browsers and bundlers (the `default` entry). The module is loaded from `sbtp_wasm_bg.wasm` next to the
glue, through `new URL("sbtp_wasm_bg.wasm", import.meta.url)`, which Vite, webpack 5, Rollup and Parcel
resolve. `init()` instantiates it and runs the built-in self-test; it rejects on a bad build.

```js
import init, * as sbtp from "@sbtp/wasm";
await init();

// Every block fetched by id goes through validateRequested.
const info = sbtp.validateRequested(bytes, relayDifficulty, requestedId);
info.blockIdHex; info.payload; info.publicKey;
info.free(); // results live in WebAssembly memory
```

To serve the module from elsewhere, pass it: `await init({ module_or_path: url })`. The module is also
exported as `@sbtp/wasm/sbtp_wasm_bg.wasm`. A page's Content Security Policy needs `'wasm-unsafe-eval'` in
`script-src`.

Node.js (the `node` entry) instantiates the module synchronously on import; `await init()` is accepted
and returns at once, so the same code runs in both.

```js
import * as sbtp from "@sbtp/wasm";
const info = sbtp.validateSubmitted(bytes, difficulty);
```

Byte arguments and results are `Uint8Array`; `timestamp` and `nonce` are `bigint`. Every failure throws an
`Error` whose `name` is stable (the specification rule, such as `InvalidSignature`, or `InvalidArgument`,
`OpenFailed`...). Type declarations ship in `sbtp_wasm.d.ts`. Mining (`mineSlice`) belongs in a Web
Worker in a browser.

`DemoSigningKey` keeps its seed in WebAssembly memory, readable by any script in the page: it is for
demos and tests. A real client keeps its identity in a non-extractable Web Crypto Ed25519 key and signs
through `signingMessage` / `attachSignature`, or `sealPrepare` / `finish` for sealing.

Those two builders return a `SigningMessage` (`bytes`, `kind`: `"block"` or `"sealed"`, `free()`),
never bare bytes, and nothing else creates one: there is no constructor or factory. An external signer
should accept only a `SigningMessage` (`instanceof` at run time; the `.d.ts` brands the type, so a
`Uint8Array` does not type-check) and sign its `bytes`, so that it never signs bytes its caller chose
(ADR 0055 E1).

```js
const message = sbtp.signingMessage(minedBlock);   // or pending.message, kind "sealed"
const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", identityKey, message.bytes));
message.free();
const signed = sbtp.attachSignature(minedBlock, sig); // verified before it returns
```

## Runtimes

- Node.js 22 and later (the release lines in active or maintenance long-term support).
- Browsers: the module uses the WebAssembly features `bulk-memory`, `multivalue`, `mutable-globals`,
  `nontrapping-fptoint`, `reference-types` and `sign-ext`, and the glue uses `BigInt` integration. That
  gives Chrome and Edge 96, Firefox 79 and Safari 15 as minimum versions. These are derived from the
  features of the build, not yet tested in CI. Signing with a non-extractable Web Crypto Ed25519 key needs
  a more recent browser.

## Contents and size

`sbtp_wasm_bg.wasm` (the module, about 120 KB gzip), `sbtp_wasm.js` (glue for browsers and bundlers),
`node.js` (Node.js entry), `sbtp_wasm.d.ts` (types), this README and the two licence files. Nothing else:
CI checks the file list, the absence of install scripts and of local paths, and the size budget of
200,000 bytes gzip for the module.

## Versions

The version is the one of the `sbtp-wasm` crate it is built from. While the major version is 0, a
breaking change raises the minor version. The package does not reach 1.0 before the core specification
leaves draft status.

## License

At your option: MIT (`LICENSE-MIT`) or Apache-2.0 (`LICENSE-APACHE`).
