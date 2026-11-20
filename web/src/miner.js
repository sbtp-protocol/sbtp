// Main-thread side of mine-worker.js. Each job gets its own worker, terminated when the job ends,
// fails or is cancelled.

function job(message, onMessage, signal) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./mine-worker.js", import.meta.url), { type: "module" });
    const stop = (fn, value) => {
      worker.terminate();
      signal?.removeEventListener("abort", onAbort);
      fn(value);
    };
    const onAbort = () => stop(reject, Object.assign(new Error("mining cancelled"), { name: "AbortError" }));
    if (signal?.aborted) return onAbort();
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.onmessage = ({ data }) => {
      if (data.type === "error") stop(reject, Object.assign(new Error(data.message), { name: data.name }));
      else {
        const result = onMessage(data);
        if (result !== undefined) stop(resolve, result);
      }
    };
    worker.onerror = (e) => stop(reject, new Error(`mining worker failed: ${e.message ?? "load error"}`));
    worker.postMessage(message);
  });
}

/** Mines `block` (unsigned) at `difficulty` in a worker. Resolves with the mined block bytes. */
export function mineInWorker(block, difficulty, { onProgress, signal } = {}) {
  return job({ op: "mine", block, difficulty }, (data) => {
    if (data.type === "progress") onProgress?.(data.attempts);
    else if (data.type === "done") return data.block;
    return undefined;
  }, signal);
}

/** Runs the PoW benchmark; `onRun({ d, ms, attempts })` per run. Resolves when all runs are done. */
export function benchInWorker(difficulties, runs, { onRun, signal } = {}) {
  return job({ op: "bench", difficulties, runs }, (data) => {
    if (data.type === "run") onRun?.(data);
    else if (data.type === "benchdone") return true;
    return undefined;
  }, signal);
}
