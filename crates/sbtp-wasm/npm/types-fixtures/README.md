# Type declaration fixtures of `@sbtp/wasm`

Compile-time checks of the shipped `sbtp_wasm.d.ts`, for a project that has TypeScript (this
repository has none, so CI checks the declarations with `tools.mjs dts-check` instead: no DOM-only
type name, the `SigningMessage` brand present). Not shipped in the package; never run, only
type-checked.

| File | Checks |
|---|---|
| `brand.ts` | A `SigningMessage` from `signingMessage` is accepted; a `Uint8Array`, an object with the same public members and `new SigningMessage()` are rejected (each line marked `@ts-expect-error` must fail). |
| `node-only.ts` | `initSync` and `InitOutput` compile for a Node.js-only program. |
| `dom.ts` | With the `dom` lib, `init` accepts a `Response` and a `URL`, and `memory` is a `WebAssembly.Memory`. |
| `tsconfig.node.json` | Node.js only: `lib: ["es2022"]`, `types: ["node"]`, no `dom`, `strict`, `skipLibCheck: false`. Runs `brand.ts` and `node-only.ts`. |
| `tsconfig.dom.json` | Browser: `lib: ["es2022", "esnext.disposable", "dom"]`, no `@types/node`. Runs `brand.ts` and `dom.ts`. |

To run them, in a scratch directory whose `package.json` has `"type": "module"`, with the tarball
installed as `@sbtp/wasm`, `typescript` and (for the first command) `@types/node`:

```sh
cp path/to/sbtp/crates/sbtp-wasm/npm/types-fixtures/* .
npx tsc -p tsconfig.node.json
npx tsc -p tsconfig.dom.json
```

Both must print nothing and exit 0. `skipLibCheck` stays `false`: it would also hide an error in the
brand. The declarations use `Symbol.dispose` (wasm-bindgen's `[Symbol.dispose]()`), so the program
needs either `@types/node` or the `esnext.disposable` lib (TypeScript 5.2 or later).
