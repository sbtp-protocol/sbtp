// PoW measurement page (Q-28): median and p95 mining time at d = 16, 18, 20, 22, in a Worker.

import { benchInWorker } from "./miner.js";
import { summarize } from "./stats.js";

const $ = (id) => document.getElementById(id);
const DIFFICULTIES = [16, 18, 20, 22];
let controller = null;

function render(results, wallMs, done) {
  const body = $("table").tBodies[0];
  body.replaceChildren();
  const summary = {};
  for (const d of DIFFICULTIES) {
    if (!results[d].length) continue;
    const s = summarize(results[d]);
    summary[d] = s;
    const row = body.insertRow();
    for (const v of [d, s.runs, s.medianMs, s.p95Ms, s.minMs, s.maxMs, s.hashesPerSecond]) {
      row.insertCell().textContent = String(v);
    }
  }
  $("json").value = JSON.stringify({
    complete: done,
    date: new Date().toISOString(),
    userAgent: navigator.userAgent,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    wallTimeMs: Math.round(wallMs),
    summary,
    runsMs: Object.fromEntries(DIFFICULTIES.map((d) => [d, results[d].map((r) => Math.round(r.ms * 10) / 10)])),
  }, null, 1);
}

async function start() {
  const runs = Object.fromEntries(DIFFICULTIES.map((d) => [d, Math.max(1, Number($(`r${d}`).value) | 0)]));
  const results = Object.fromEntries(DIFFICULTIES.map((d) => [d, []]));
  controller = new AbortController();
  $("start").disabled = true;
  $("stop").disabled = false;
  const t0 = performance.now();
  let done = false;
  try {
    await benchInWorker(DIFFICULTIES, runs, {
      signal: controller.signal,
      onRun: (r) => {
        results[r.d].push(r);
        $("progress").textContent = `d = ${r.d}: run ${results[r.d].length} of ${runs[r.d]} (${Math.round(r.ms)} ms)`;
        render(results, performance.now() - t0, false);
      },
    });
    done = true;
    $("progress").textContent = "Done.";
  } catch (e) {
    $("progress").textContent = `${e.name}: ${e.message}`;
  } finally {
    render(results, performance.now() - t0, done);
    $("start").disabled = false;
    $("stop").disabled = true;
  }
}

$("start").addEventListener("click", start);
$("stop").addEventListener("click", () => controller?.abort());
if (new URLSearchParams(location.search).get("auto") === "1") start();
