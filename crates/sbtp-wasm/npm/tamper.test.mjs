// check.sh against tampered copies of a built tarball (security review 2026-11-22, L-2): each case
// rewrites one file of the package, repacks it and expects check.sh to refuse it. Needs a tarball
// from build.sh, so it is skipped unless SBTP_NPM_TARBALL names one:
//
//   SBTP_NPM_TARBALL=dist-npm/sbtp-wasm-0.1.0.tgz node --test crates/sbtp-wasm/npm/tamper.test.mjs
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { tgz } from "./tar-fixture.mjs";

const original = process.env.SBTP_NPM_TARBALL;
const skip = original ? false : "SBTP_NPM_TARBALL is not set (build the package first)";
const checkSh = fileURLToPath(new URL("./check.sh", import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), "sbtp-wasm-tamper-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

// The files of the original tarball, in order: [name, Buffer].
const files = () => {
  const names = execFileSync("tar", ["-tzf", original], { encoding: "utf8" }).trim().split("\n");
  return names.map((name) => [name, execFileSync("tar", ["-xOzf", original, name], { maxBuffer: 1 << 26 })]);
};

let n = 0;
// Repacks the package with `change(files)` applied and runs check.sh on it.
function check(change) {
  const dir = join(scratch, String(n++));
  mkdirSync(dir);
  const path = join(dir, basename(original));
  writeFileSync(path, tgz(change(files())));
  return spawnSync("sh", [checkSh, path], { encoding: "utf8" });
}

const editFile = (name, edit) => (list) =>
  list.map(([n2, data]) => [n2, n2 === `package/${name}` ? Buffer.from(edit(data)) : data]);
const editManifest = (edit) => editFile("package.json", (data) => {
  const m = JSON.parse(data);
  edit(m);
  return `${JSON.stringify(m, null, 2)}\n`;
});

test("the repacked original passes", { skip }, () => {
  const r = check((list) => list);
  assert.equal(r.status, 0, r.stderr);
});

const refused = {
  "directories.bin": editManifest((m) => { m.directories = { bin: "." }; }),
  "publishConfig registry and tag": editManifest((m) => {
    m.publishConfig = { ...m.publishConfig, registry: "https://registry.example.invalid/", tag: "next" };
  }),
  "exports node redirected": editManifest((m) => { m.exports["."].node = "./sbtp_wasm.js"; }),
  "main added": editManifest((m) => { m.main = "./node.js"; }),
  "browser added": editManifest((m) => { m.browser = "./node.js"; }),
  "os added": editManifest((m) => { m.os = ["linux"]; }),
  "workspaces added": editManifest((m) => { m.workspaces = ["*"]; }),
  "overrides added": editManifest((m) => { m.overrides = { x: "1.0.0" }; }),
  "imports added": editManifest((m) => { m.imports = { "#x": "./node.js" }; }),
  "engines changed": editManifest((m) => { m.engines = { node: ">=0" }; }),
  "same manifest, other whitespace": editFile("package.json", (d) => `${d.toString().trimEnd()}\n\n`),
  "node.js runs a command on import": editFile("node.js", (d) =>
    `import { execSync } from "node:child_process";\nexecSync("true");\n${d}`),
  "README changed": editFile("README.md", (d) => `${d}\nSee https://example.invalid/\n`),
  "licence changed": editFile("LICENSE-MIT", (d) => d.toString().replace("MIT", "XYZ")),
};
for (const [name, change] of Object.entries(refused)) {
  test(`refused: ${name}`, { skip }, () => {
    const r = check(change);
    assert.notEqual(r.status, 0, `check.sh accepted it:\n${r.stdout}`);
    assert.match(r.stderr, /differs from the repository copy/);
  });
}

test("refused: unpacked size above the bound", { skip }, () => {
  const r = check(editFile("sbtp_wasm.js", (d) => Buffer.concat([d, Buffer.alloc(1_000_000, 0x20)])));
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /bytes, the bound is 1000000/);
});

test("refused: tarball size above the bound", { skip }, () => {
  // Random bytes do not compress: the tarball grows by about as much.
  const noise = `/*${randomBytes(200_000).toString("hex")}*/`;
  const r = check(editFile("sbtp_wasm.js", (d) => `${d}${noise}`));
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /the tarball is \d+ bytes, the bound is 300000/);
});
