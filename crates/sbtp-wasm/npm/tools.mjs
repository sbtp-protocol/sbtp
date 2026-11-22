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
//   node tools.mjs tar-list <package.tgz>                 checks the archive; prints "size name" lines
//   node tools.mjs tar-cat <package.tgz> <name>           checks the archive; writes one file to stdout
//
// The functions are exported for tools.test.mjs; they throw on a finding.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { crc32, inflateRawSync } from "node:zlib";

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

// --- Package archive ------------------------------------------------------------------------
//
// check.sh reads the tarball through readPackage only, so that it checks the bytes npm installs
// (security review 2026-11-22, L-1): bsdtar stops at a lone zero block where node-tar, which npm
// uses, reads on. The archive is therefore accepted only in the exact form npm pack writes: one
// gzip member with no optional header field and nothing after it; ustar headers of regular files
// with valid checksums, mode 0644, names on the expected list, each exactly once; then zero blocks
// only, to the end.

// Every file of the package, as npm pack names it: npm adds package.json and README.md.
export const PACKAGE_FILES = ["package.json", "README.md", ...SHIPPED].map((f) => `package/${f}`).sort();

// The bound on the decompressed archive: above check.sh's MAX_UNPACKED_BYTES plus the tar headers,
// so that check.sh reports the size, and a gzip bomb stops here.
export const MAX_TAR_BYTES = 2_000_000;

function gunzipOneMember(gz, maxBytes) {
  // RFC 1952: ID1 ID2 CM FLG MTIME(4) XFL OS. npm pack sets no flag (no name, comment or extra).
  if (gz.length < 18 || gz[0] !== 0x1f || gz[1] !== 0x8b) throw new Error("not a gzip file");
  if (gz[2] !== 8) throw new Error(`gzip compression method ${gz[2]}, expected 8 (deflate)`);
  if (gz[3] !== 0) throw new Error(`gzip header flags 0x${gz[3].toString(16)}, expected none`);
  let inflated;
  try {
    inflated = inflateRawSync(gz.subarray(10), { info: true, maxOutputLength: maxBytes });
  } catch (e) {
    throw new Error(`gzip data: ${e.message}`);
  }
  const { buffer: data, engine } = inflated;
  const end = 10 + engine.bytesWritten;
  if (end + 8 > gz.length) throw new Error("gzip trailer missing");
  if (gz.readUInt32LE(end) !== crc32(data)) throw new Error("gzip CRC-32 mismatch");
  if (gz.readUInt32LE(end + 4) !== data.length % 2 ** 32) throw new Error("gzip size mismatch");
  if (end + 8 !== gz.length) {
    throw new Error(`${gz.length - end - 8} bytes after the first gzip member (a second member or trailing data)`);
  }
  return data;
}

// A NUL- or space-terminated octal field. Base-256 sizes (high bit set) are refused.
function octalField(h, offset, width, what) {
  const text = h.subarray(offset, offset + width).toString("latin1").replace(/[\0 ]+$/, "");
  if (!/^[0-7]+$/.test(text)) throw new Error(`bad ${what} field ${JSON.stringify(text)}`);
  return parseInt(text, 8);
}

const cString = (h, offset, width) => {
  const field = h.subarray(offset, offset + width);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? width : nul).toString("utf8");
};

// The files of a package tarball, as a Map from name to contents, in archive order.
export function readPackage(gz, expected = PACKAGE_FILES, maxBytes = MAX_TAR_BYTES) {
  const tarData = gunzipOneMember(gz, maxBytes);
  if (tarData.length % 512 !== 0) throw new Error(`tar stream of ${tarData.length} bytes, not whole 512-byte blocks`);
  const files = new Map();
  let p = 0;
  for (;;) {
    if (p >= tarData.length) throw new Error("tar stream without an end-of-archive zero block");
    const h = tarData.subarray(p, p + 512);
    if (h.every((b) => b === 0)) break;
    const at = `tar header at offset ${p}`;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
    if (octalField(h, 148, 8, "checksum") !== sum) throw new Error(`${at}: bad checksum`);
    if (h.subarray(257, 265).toString("latin1") !== "ustar\u000000") throw new Error(`${at}: not a ustar header`);
    const type = String.fromCharCode(h[156]);
    const prefix = cString(h, 345, 155);
    const name = prefix ? `${prefix}/${cString(h, 0, 100)}` : cString(h, 0, 100);
    if (type !== "0") throw new Error(`${at}: ${JSON.stringify(name)} is not a regular file (type ${JSON.stringify(type)})`);
    if (!expected.includes(name)) throw new Error(`${at}: unexpected file ${JSON.stringify(name)}`);
    if (files.has(name)) throw new Error(`${at}: ${name} occurs twice`);
    const mode = octalField(h, 100, 8, "mode");
    if (mode !== 0o644) throw new Error(`${at}: ${name} has mode ${mode.toString(8)}, expected 644`);
    const size = octalField(h, 124, 12, "size");
    const start = p + 512;
    if (start + size > tarData.length) throw new Error(`${at}: ${name} runs past the end of the archive`);
    files.set(name, tarData.subarray(start, start + size));
    p = start + Math.ceil(size / 512) * 512;
  }
  // Everything after the first zero block is zero: no entry hides behind it.
  const rest = tarData.subarray(p);
  const nonZero = rest.findIndex((b) => b !== 0);
  if (nonZero !== -1) throw new Error(`non-zero byte at offset ${p + nonZero}, after the end-of-archive block`);
  const missing = expected.filter((f) => !files.has(f));
  if (missing.length > 0) throw new Error(`missing ${missing.join(", ")}`);
  return files;
}

// --- Command line ---------------------------------------------------------------------------

function main([command, arg, arg2]) {
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
      case "tar-list":
        for (const [name, data] of readPackage(readFileSync(arg))) console.log(`${data.length} ${name}`);
        break;
      case "tar-cat": {
        const name = arg2;
        const data = readPackage(readFileSync(arg)).get(name);
        if (!data) throw new Error(`no file ${name}`);
        process.stdout.write(data);
        break;
      }
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
