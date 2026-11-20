// Module Web Worker: proof of work off the main thread. One worker per job (miner.js): cancelling
// a job, or recovering from a trap (security review I-5), is `worker.terminate()`, and the next job
// gets a freshly instantiated module.

import { buildUnsignedBlock, loadSbtp, mineSlice, nonceOf } from "./wasm.js";

const SLICE = 1 << 16; // attempts per call: about 10 ms, frequent enough for progress messages

function mine(block, difficulty, onSlice) {
  for (;;) {
    const id = mineSlice(block, difficulty, SLICE);
    if (id !== undefined) return id;
    onSlice();
  }
}

async function bench({ difficulties, runs }) {
  const publicKey = new Uint8Array(32).fill(1); // mining does not depend on the key
  for (const d of difficulties) {
    for (let i = 0; i < runs[d]; i += 1) {
      const payload = crypto.getRandomValues(new Uint8Array(16)); // an independent search per run
      const block = buildUnsignedBlock(publicKey, BigInt(Date.now()), 0n, new Uint8Array(0), payload);
      const t0 = performance.now();
      mine(block, d, () => {});
      const ms = performance.now() - t0;
      postMessage({ type: "run", d, ms, attempts: Number(nonceOf(block)) + 1 });
    }
  }
  postMessage({ type: "benchdone" });
}

self.onmessage = async ({ data }) => {
  try {
    await loadSbtp();
    if (data.op === "mine") {
      let slices = 0;
      const id = mine(data.block, data.difficulty, () => {
        slices += 1;
        postMessage({ type: "progress", attempts: slices * SLICE });
      });
      postMessage({ type: "done", block: data.block, id });
    } else if (data.op === "bench") {
      await bench(data);
    }
  } catch (e) {
    postMessage({ type: "error", name: e?.name ?? "Error", message: e?.message ?? String(e) });
  }
};
