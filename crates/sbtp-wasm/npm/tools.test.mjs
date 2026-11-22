// Tests of tools.mjs (node --test crates/sbtp-wasm/npm/*.test.mjs). Synthetic inputs only; no build needed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { entry, tar, tgz } from "./tar-fixture.mjs";
import { DTS_LOCAL_TYPES, dtsCheck, dtsFix, PACKAGE_FILES, readPackage } from "./tools.mjs";

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

// --- readPackage (security review 2026-11-22, L-1) ---

const FILES = PACKAGE_FILES.map((name) => [name, `contents of ${name}\n`]);
const entries = (files = FILES) => files.map(([name, data]) => entry(name, data));
const gz = (buf) => gzipSync(buf, { level: 9 });

test("readPackage accepts the files npm pack writes", () => {
  const files = readPackage(tgz(FILES));
  assert.deepEqual([...files.keys()], PACKAGE_FILES);
  assert.equal(files.get("package/node.js").toString(), "contents of package/node.js\n");
});

test("readPackage refuses an entry hidden after a lone zero block", () => {
  // The review's case: bsdtar stops at the first zero block, node-tar (npm) reads on.
  const hidden = Buffer.concat([...entries(), Buffer.alloc(512), entry("package/hidden.js", "x"), Buffer.alloc(1024)]);
  assert.throws(() => readPackage(gz(hidden)), /non-zero byte at offset \d+, after the end-of-archive block/);
  // The same with the hidden entry a known name, or after the two closing zero blocks: still refused.
  const again = Buffer.concat([...entries(), Buffer.alloc(512), entry("package/node.js", "x"), Buffer.alloc(1024)]);
  assert.throws(() => readPackage(gz(again)), /after the end-of-archive block/);
  assert.throws(() => readPackage(gz(tar(entries(), { trailer: entry("package/hidden.js", "x") }))),
    /after the end-of-archive block/);
});

test("readPackage refuses a second gzip member or trailing bytes", () => {
  const second = Buffer.concat([tgz(FILES), tgz([["package/hidden.js", "x"]])]);
  assert.throws(() => readPackage(second), /after the first gzip member/);
  assert.throws(() => readPackage(Buffer.concat([tgz(FILES), Buffer.from("junk")])), /after the first gzip member/);
});

test("readPackage refuses a gzip header with optional fields", () => {
  const flagged = Buffer.from(tgz(FILES));
  flagged[3] = 0x08; // FNAME
  assert.throws(() => readPackage(flagged), /gzip header flags 0x8/);
});

test("readPackage refuses a corrupt gzip trailer", () => {
  const bad = Buffer.from(tgz(FILES));
  bad[bad.length - 8] ^= 1;
  assert.throws(() => readPackage(bad), /CRC-32 mismatch/);
});

test("readPackage refuses unexpected, duplicate or missing files", () => {
  assert.throws(() => readPackage(tgz([...FILES, ["package/extra.js", "x"]])), /unexpected file "package\/extra.js"/);
  assert.throws(() => readPackage(tgz([...FILES, FILES[0]])), /occurs twice/);
  assert.throws(() => readPackage(tgz(FILES.slice(1))), /missing package\/LICENSE-APACHE/);
  assert.throws(() => readPackage(tgz([...FILES.slice(1), ["LICENSE-APACHE", "x"]])), /unexpected file "LICENSE-APACHE"/);
});

test("readPackage refuses anything but a regular file of mode 0644", () => {
  const dir = [entry("package/", "", { type: "5", mode: 0o755 }), ...entries()];
  assert.throws(() => readPackage(gz(tar(dir))), /not a regular file \(type "5"\)/);
  const link = [...entries(FILES.slice(1)), entry("package/LICENSE-APACHE", "", { type: "2", linkname: "/etc/passwd" })];
  assert.throws(() => readPackage(gz(tar(link))), /not a regular file \(type "2"\)/);
  const pax = [entry("package/PaxHeader", "30 path=package/other.js\n", { type: "x" }), ...entries()];
  assert.throws(() => readPackage(gz(tar(pax))), /not a regular file \(type "x"\)/);
  const exec = [entry(FILES[0][0], FILES[0][1], { mode: 0o755 }), ...entries(FILES.slice(1))];
  assert.throws(() => readPackage(gz(tar(exec))), /has mode 755, expected 644/);
});

test("readPackage refuses a bad checksum or a non-ustar header", () => {
  const raw = tar(entries());
  const sum = Buffer.from(raw);
  sum[0] ^= 1;
  assert.throws(() => readPackage(gz(sum)), /bad checksum/);
  const magic = Buffer.from(raw);
  magic.write("gnutar", 257, "latin1");
  assert.throws(() => readPackage(gz(magic)), /bad checksum|not a ustar header/);
});

test("readPackage refuses a truncated archive and stops a decompression bomb", () => {
  const raw = tar(entries());
  assert.throws(() => readPackage(gz(raw.subarray(0, raw.length - 1024))), /without an end-of-archive zero block/);
  assert.throws(() => readPackage(gz(raw.subarray(0, raw.length - 100))), /not whole 512-byte blocks/);
  const bomb = gz(Buffer.concat([raw, Buffer.alloc(3_000_000)]));
  assert.throws(() => readPackage(bomb), /gzip data/);
});
