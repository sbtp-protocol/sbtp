// Static checks of .github/workflows/release-npm.yml (security review 2026-11-22, M-1): publication
// runs from `main` only, stays disabled behind NPM_PUBLISH_ENABLED, and each privilege is held by
// one job. Text checks, no YAML parser (no dependency): the file keeps one job per `  <name>:` block.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const text = readFileSync(new URL("../../../.github/workflows/release-npm.yml", import.meta.url), "utf8");
const code = text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");

const jobs = (() => {
  const body = code.slice(code.indexOf("\njobs:\n") + 7);
  const out = {};
  let name = null;
  for (const line of body.split("\n")) {
    const m = /^ {2}([a-z-]+):$/.exec(line);
    if (m) { name = m[1]; out[name] = ""; } else if (name) out[name] += `${line}\n`;
  }
  return out;
})();

test("the only trigger is a manual dispatch with a version input", () => {
  const on = code.slice(code.indexOf("\non:\n"), code.indexOf("\npermissions:"));
  assert.match(on, /^\non:\n {2}workflow_dispatch:\n {4}inputs:\n {6}version:\n/);
  for (const trigger of ["push", "pull_request", "pull_request_target", "schedule", "workflow_run", "release"]) {
    assert.doesNotMatch(on, new RegExp(`\\n {2}${trigger}:`), trigger);
  }
  assert.match(code, /\npermissions: \{\}\n/);
});

test("every job is disabled unless enabled, and runs on main only", () => {
  assert.deepEqual(Object.keys(jobs), ["build", "publish", "tag"]);
  for (const [name, body] of Object.entries(jobs)) {
    assert.match(body, /\n {4}if: vars\.NPM_PUBLISH_ENABLED == 'true' && github\.ref == 'refs\/heads\/main'\n/, name);
  }
});

test("each privilege is held by one job", () => {
  assert.match(jobs.build, /permissions:\n {6}contents: read\n {4}env:/);
  assert.match(jobs.publish, /\n {4}environment: npm-release\n/);
  assert.match(jobs.publish, /permissions:\n {6}contents: read\n {6}id-token: write/);
  assert.match(jobs.tag, /permissions:\n {6}contents: write/);
  assert.doesNotMatch(jobs.build + jobs.tag, /id-token/);
  assert.doesNotMatch(jobs.build + jobs.publish, /contents: write/);
  assert.doesNotMatch(jobs.publish, /actions\/checkout/);
});

test("the version input reaches the shell through env only", () => {
  const uses = code.match(/\$\{\{ *inputs\.[a-z_]+ *\}\}/g) ?? [];
  assert.equal(uses.length, 1);
  assert.match(code, /\n {10}VERSION: \$\{\{ inputs\.version \}\}\n/);
  // No expression inside a run script.
  for (const block of code.split(/\n {8}run: \|\n/).slice(1)) {
    const script = [];
    for (const line of block.split("\n")) {
      if (line !== "" && !line.startsWith(" ".repeat(10))) break;
      script.push(line);
    }
    assert.doesNotMatch(script.join("\n"), /\$\{\{/, script.join("\n"));
  }
});

test("an existing tag must point at the commit of the run", () => {
  assert.match(jobs.build, /git rev-parse -q --verify "refs\/tags\/\$tag\^\{commit\}"/);
  assert.match(jobs.build, /if \[ "\$tagged" != "\$GITHUB_SHA" \]; then/);
});
