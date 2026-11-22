// Tests of tools.mjs (node --test crates/sbtp-wasm/npm/*.test.mjs). Synthetic inputs only; no build needed.
import assert from "node:assert/strict";
import { test } from "node:test";

import { DTS_LOCAL_TYPES, dtsCheck, dtsFix } from "./tools.mjs";

// The shape of the sbtp_wasm.d.ts that wasm-bindgen 0.2.130 writes, cut down to the parts the
// post-processing touches or keeps.
const BINDGEN_DTS = `/* tslint:disable */
/* eslint-disable */

declare const signingMessageBrand: unique symbol;
export interface SigningMessage {
    /** Type-level brand only (absent at run time): built by signingMessage or SealPending.message. */
    readonly [signingMessageBrand]: true;
}
export {};

export class SigningMessage {
    private constructor();
    free(): void;
    readonly bytes: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbindgen_externrefs: WebAssembly.Table;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * If \`module_or_path\` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls \`WebAssembly.instantiate\` directly.
 */
export default function __wbg_init (module_or_path?: InitInput): Promise<InitOutput>;
`;

test("the wasm-bindgen declarations name DOM-only types", () => {
  assert.throws(() => dtsCheck(BINDGEN_DTS), /DOM-only type RequestInfo on line 17/);
});

test("dts-fix replaces every DOM-only type and keeps the brand", () => {
  const fixed = dtsFix(BINDGEN_DTS);
  dtsCheck(fixed);
  assert.ok(fixed.includes(DTS_LOCAL_TYPES));
  assert.ok(fixed.includes("export type InitInput = string | SbtpRequest | SbtpURL | SbtpResponse | SbtpBufferSource | SbtpWasmModule;\n"));
  assert.ok(fixed.includes("    readonly memory: SbtpWasmMemory;\n"));
  assert.ok(fixed.includes("    readonly __wbindgen_externrefs: SbtpWasmTable;\n"));
  assert.ok(fixed.includes("export type SyncInitInput = SbtpBufferSource | SbtpWasmModule;\n"));
  // Only the four rewritten lines change; the brand section is byte-identical.
  assert.ok(fixed.startsWith(BINDGEN_DTS.slice(0, BINDGEN_DTS.indexOf("export type InitInput"))));
});

test("dts-fix fails when wasm-bindgen output changes", () => {
  const changed = BINDGEN_DTS.replace("readonly memory: WebAssembly.Memory;", "readonly memory: WebAssembly.Memory | undefined;");
  assert.throws(() => dtsFix(changed), /expected exactly one "readonly memory: WebAssembly.Memory;", found 0/);
});

test("dts-check rejects a lost or altered brand", () => {
  const fixed = dtsFix(BINDGEN_DTS);
  assert.throws(() => dtsCheck(fixed.replace("    readonly [signingMessageBrand]: true;\n", "")),
    /SigningMessage brand/);
  assert.throws(() => dtsCheck(fixed.replace("export {};\n", "")), /SigningMessage brand/);
  assert.throws(() => dtsCheck(fixed.replace("    private constructor();\n", "")), /SigningMessage brand/);
});

test("dts-check rejects altered aliases or a DOM type in code", () => {
  const fixed = dtsFix(BINDGEN_DTS);
  assert.throws(() => dtsCheck(fixed.replace("? T : never;", "? T : any;")), /local type aliases occur 0 times/);
  assert.throws(() => dtsCheck(`${fixed}export declare function f(r: Response): void;\n`), /DOM-only type Response/);
  // A DOM name in a comment is fine.
  dtsCheck(`${fixed}// takes a Response\n`);
});
