// Helpers of build.sh and check.sh (not shipped in the package). Plain Node.js, no dependency;
// reads files and stdin only, runs nothing.
//
//   node tools.mjs crate-version < cargo-metadata.json   version of the sbtp-wasm crate
//   node tools.mjs features <module.wasm>                 the target_features custom section
//   node tools.mjs digest <file>                          SHA-256 (hex) and npm integrity (sha512-...)
//   node tools.mjs manifest <version> < package.json      checks a packed manifest, exit 1 on a finding
//   node tools.mjs pack-integrity < npm-pack.json         the integrity npm pack reported
//   node tools.mjs dts-fix <sbtp_wasm.d.ts>               rewrites the DOM-only types of the init API
//   node tools.mjs dts-check < sbtp_wasm.d.ts             checks the declarations, exit 1 on a finding
//
// The functions are exported for tools.test.mjs; they throw on a finding.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// The files of the package (rule 35 of ADR 0053: build output, type declarations, licences, README).
// npm adds package.json and README.md whatever `files` says.
export const SHIPPED = [
  "sbtp_wasm.js",
  "sbtp_wasm.d.ts",
  "sbtp_wasm_bg.wasm",
  "node.js",
  "LICENSE-MIT",
  "LICENSE-APACHE",
];

export function crateVersion(metadataJson) {
  const meta = JSON.parse(metadataJson);
  const pkg = meta.packages.find((p) => p.name === "sbtp-wasm");
  if (!pkg) throw new Error("no sbtp-wasm package in cargo metadata");
  return pkg.version;
}

// Reads the names of the `target_features` custom section (tool-conventions, Linking.md):
// a vector of (prefix byte, name) pairs.
export function features(b) {
  let p = 8;
  const leb = () => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (p >= b.length || shift > 28) throw new Error("bad LEB128");
      const byte = b[p++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (byte < 0x80) return value;
    }
  };
  if (b.length < 8 || b.readUInt32LE(0) !== 0x6d736100) throw new Error("not a WebAssembly module");
  while (p < b.length) {
    const id = b[p++];
    const size = leb();
    const end = p + size;
    if (id === 0) {
      const len = leb();
      const name = b.subarray(p, p + len).toString("utf8");
      p += len;
      if (name === "target_features") {
        const out = [];
        for (let n = leb(); n > 0; n--) {
          const prefix = String.fromCharCode(b[p++]);
          const l = leb();
          out.push(prefix + b.subarray(p, p + l).toString("utf8"));
          p += l;
        }
        return out.sort().join(" ");
      }
    }
    p = end;
  }
  throw new Error("no target_features section");
}

export function digest(data) {
  return {
    sha256: createHash("sha256").update(data).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(data).digest("base64")}`,
  };
}

export function manifest(m, version) {
  const findings = [];
  const expect = (cond, message) => cond || findings.push(message);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  expect(m.name === "@sbtp/wasm", `name is ${m.name}`);
  expect(m.version === version, `version ${m.version} is not the crate version ${version}`);
  expect(m.license === "MIT OR Apache-2.0", `license is ${m.license}`);
  expect(m.type === "module", `type is ${m.type}`);
  expect(m.types === "./sbtp_wasm.d.ts", `types is ${m.types}`);
  expect(same(m.files, SHIPPED), `files is ${JSON.stringify(m.files)}`);
  expect(same(m.sideEffects, ["./node.js"]), `sideEffects is ${JSON.stringify(m.sideEffects)}`);
  expect(m.repository?.url === "git+https://github.com/sbtp-protocol/sbtp.git",
    `repository is ${JSON.stringify(m.repository)}`);
  // Rule 42: no install script. No script at all is simpler to check and to review.
  expect(m.scripts === undefined, `declares scripts: ${JSON.stringify(m.scripts)}`);
  expect(m.gypfile === undefined, "declares gypfile");
  expect(m.bin === undefined, "declares bin");
  for (const key of ["dependencies", "optionalDependencies", "peerDependencies",
    "bundleDependencies", "bundledDependencies", "devDependencies"]) {
    expect(m[key] === undefined, `declares ${key}`);
  }
  if (findings.length > 0) throw new Error(findings.join("; "));
}

export function packIntegrity(packJson) {
  const [entry] = JSON.parse(packJson);
  if (!entry?.integrity || !entry?.filename) throw new Error("unexpected npm pack --json output");
  return `${entry.filename} ${entry.integrity}`;
}

// --- Type declarations ----------------------------------------------------------------------
//
// wasm-bindgen types the init API (`init`, `initSync`, `InitInput`, `InitOutput`) with DOM lib
// names (RequestInfo, URL, Response, BufferSource, the WebAssembly namespace). A consumer whose
// program has no "dom" lib (Node.js only: `types: ["node"]`) then gets compile errors in the
// shipped .d.ts, and `skipLibCheck` would hide every other error of the file with them, the
// SigningMessage brand included. dts-fix replaces those names by the local aliases below. Each
// alias is the DOM type when the consumer's program declares the matching global (read from
// `typeof globalThis`, the pattern @types/node uses), and a fallback that needs only the ES lib
// otherwise. The aliases are not exported (`export {}` of the brand section makes the file's
// declarations explicit-export only).

export const DTS_LOCAL_TYPES = `// Added by crates/sbtp-wasm/npm/build.sh: local aliases of the DOM types of the init API, so that
// these declarations compile without the "dom" lib. Each is the global type when the program has
// it, and a fallback that needs only the ES lib otherwise.
type SbtpRequest = typeof globalThis extends { Request: { prototype: infer T } } ? T : never;
type SbtpURL = typeof globalThis extends { URL: { prototype: infer T } } ? T : never;
type SbtpResponse = typeof globalThis extends { Response: { prototype: infer T } } ? T : never;
type SbtpBufferSource = ArrayBuffer | ArrayBufferView;
type SbtpWasmModule = typeof globalThis extends { WebAssembly: { Module: { prototype: infer T } } } ? T : never;
type SbtpWasmMemory = typeof globalThis extends { WebAssembly: { Memory: { prototype: infer T } } } ? T : {
    readonly buffer: ArrayBuffer;
    grow(delta: number): number;
};
type SbtpWasmTable = typeof globalThis extends { WebAssembly: { Table: { prototype: infer T } } } ? T : {
    readonly length: number;
    get(index: number): unknown;
    grow(delta: number, value?: unknown): number;
    set(index: number, value?: unknown): void;
};
// End of the local aliases.
`;

// The exact lines wasm-bindgen writes, and their replacements. Each must occur exactly once: a
// wasm-bindgen upgrade that changes them fails the build instead of shipping DOM names again.
const DTS_REWRITES = [
  [
    "export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;\n",
    DTS_LOCAL_TYPES +
      "\nexport type InitInput = string | SbtpRequest | SbtpURL | SbtpResponse | SbtpBufferSource | SbtpWasmModule;\n",
  ],
  ["    readonly memory: WebAssembly.Memory;\n", "    readonly memory: SbtpWasmMemory;\n"],
  [
    "    readonly __wbindgen_externrefs: WebAssembly.Table;\n",
    "    readonly __wbindgen_externrefs: SbtpWasmTable;\n",
  ],
  [
    "export type SyncInitInput = BufferSource | WebAssembly.Module;\n",
    "export type SyncInitInput = SbtpBufferSource | SbtpWasmModule;\n",
  ],
];

const count = (text, needle) => text.split(needle).length - 1;

export function dtsFix(text) {
  let out = text;
  for (const [from, to] of DTS_REWRITES) {
    const n = count(out, from);
    if (n !== 1) throw new Error(`expected exactly one ${JSON.stringify(from.trim())}, found ${n}`);
    out = out.replace(from, () => to);
  }
  dtsCheck(out);
  return out;
}

// Global types a consumer without the "dom" lib does not have. `URL` and `Response` are also
// declared by @types/node, but a consumer may have neither.
const DOM_ONLY =
  /\b(RequestInfo|Request|Response|URL|BufferSource|WebAssembly|Blob|ReadableStream|Window|Document|HTMLElement|Worker|CryptoKey|SubtleCrypto|IDBDatabase|EventTarget)\b/;

// The brand of SigningMessage (crates/sbtp-wasm/src/message.rs), exactly as it must be shipped.
const DTS_BRAND = [
  "declare const signingMessageBrand: unique symbol;\n",
  "export interface SigningMessage {\n",
  "    readonly [signingMessageBrand]: true;\n",
  "export {};\n",
  "export class SigningMessage {\n    private constructor();\n",
];

// Comments and the aliases are blanked, newlines kept, so that line numbers stay those of the file.
const blank = (s) => s.replace(/[^\n]/g, "");
const stripComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/\/\/[^\n]*/g, "");

export function dtsCheck(text) {
  const findings = [];
  const n = count(text, DTS_LOCAL_TYPES);
  if (n !== 1) findings.push(`the local type aliases occur ${n} times (expected once, unchanged)`);
  const code = stripComments(text.replace(DTS_LOCAL_TYPES, blank));
  code.split("\n").forEach((line, i) => {
    const hit = DOM_ONLY.exec(line);
    if (hit) findings.push(`DOM-only type ${hit[1]} on line ${i + 1}: ${line.trim()}`);
  });
  for (const part of DTS_BRAND) {
    const k = count(text, part);
    if (k !== 1) findings.push(`SigningMessage brand: ${JSON.stringify(part.trim())} occurs ${k} times`);
  }
  if (findings.length > 0) throw new Error(findings.join("; "));
}

// --- Command line ---------------------------------------------------------------------------

function main([command, arg]) {
  const stdin = () => readFileSync(0, "utf8");
  try {
    switch (command) {
      case "crate-version": console.log(crateVersion(stdin())); break;
      case "features": console.log(features(readFileSync(arg))); break;
      case "digest": {
        const d = digest(readFileSync(arg));
        console.log(`sha256    ${d.sha256}`);
        console.log(`integrity ${d.integrity}`);
        break;
      }
      case "manifest": manifest(JSON.parse(stdin()), arg); break;
      case "pack-integrity": console.log(packIntegrity(stdin())); break;
      case "dts-fix": writeFileSync(arg, dtsFix(readFileSync(arg, "utf8"))); break;
      case "dts-check": dtsCheck(stdin()); break;
      default: throw new Error("unknown command");
    }
  } catch (e) {
    console.error(`tools.mjs ${command}: ${e.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
