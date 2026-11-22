// Helpers of build.sh and check.sh (not shipped in the package). Plain Node.js, no dependency;
// reads files and stdin only, runs nothing.
//
//   node tools.mjs crate-version < cargo-metadata.json   version of the sbtp-wasm crate
//   node tools.mjs features <module.wasm>                 the target_features custom section
//   node tools.mjs digest <file>                          SHA-256 (hex) and npm integrity (sha512-...)
//   node tools.mjs manifest <version> < package.json      checks a packed manifest, exit 1 on a finding
//   node tools.mjs pack-integrity < npm-pack.json         the integrity npm pack reported
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const [command, arg] = process.argv.slice(2);
const stdin = () => readFileSync(0, "utf8");
const fail = (message) => {
  console.error(`tools.mjs ${command}: ${message}`);
  process.exit(1);
};

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

function crateVersion() {
  const meta = JSON.parse(stdin());
  const pkg = meta.packages.find((p) => p.name === "sbtp-wasm");
  if (!pkg) fail("no sbtp-wasm package in cargo metadata");
  console.log(pkg.version);
}

// Reads the names of the `target_features` custom section (tool-conventions, Linking.md):
// a vector of (prefix byte, name) pairs.
function features(path) {
  const b = readFileSync(path);
  let p = 8;
  const leb = () => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (p >= b.length || shift > 28) fail("bad LEB128");
      const byte = b[p++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (byte < 0x80) return value;
    }
  };
  if (b.length < 8 || b.readUInt32LE(0) !== 0x6d736100) fail(`${path} is not a WebAssembly module`);
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
        console.log(out.sort().join(" "));
        return;
      }
    }
    p = end;
  }
  fail(`${path} has no target_features section`);
}

function digest(path) {
  const data = readFileSync(path);
  console.log(`sha256    ${createHash("sha256").update(data).digest("hex")}`);
  console.log(`integrity sha512-${createHash("sha512").update(data).digest("base64")}`);
}

function manifest(version) {
  const m = JSON.parse(stdin());
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
  if (findings.length > 0) fail(findings.join("; "));
}

function packIntegrity() {
  const [entry] = JSON.parse(stdin());
  if (!entry?.integrity || !entry?.filename) fail("unexpected npm pack --json output");
  console.log(`${entry.filename} ${entry.integrity}`);
}

switch (command) {
  case "crate-version": crateVersion(); break;
  case "features": features(arg); break;
  case "digest": digest(arg); break;
  case "manifest": manifest(arg); break;
  case "pack-integrity": packIntegrity(); break;
  default: fail("unknown command");
}
