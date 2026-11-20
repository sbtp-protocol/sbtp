// Summary statistics of PoW runs (Q-28 measurements).

/** Nearest-rank percentile `p` (0 < p <= 100) of `values`. */
export function percentile(values, p) {
  if (values.length === 0) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

/** `runs`: [{ ms, attempts }] at one difficulty. */
export function summarize(runs) {
  const ms = runs.map((r) => r.ms);
  const totalMs = ms.reduce((a, b) => a + b, 0);
  const attempts = runs.reduce((a, r) => a + r.attempts, 0);
  const round = (x) => Math.round(x * 10) / 10;
  return {
    runs: runs.length,
    medianMs: round(percentile(ms, 50)),
    p95Ms: round(percentile(ms, 95)),
    minMs: round(Math.min(...ms)),
    maxMs: round(Math.max(...ms)),
    hashesPerSecond: totalMs > 0 ? Math.round((attempts / totalMs) * 1000) : 0,
  };
}
