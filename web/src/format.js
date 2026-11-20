// Display helpers for values taken from blocks. Pure, so that they are tested in Node.

/** Largest time a JS Date represents: ±8.64e15 ms (ECMA-262 "Time Values and Time Range"). */
const MAX_DATE_MS = 8_640_000_000_000_000n;

/**
 * A block Timestamp (u64 ms, a bigint) as an ISO date, or as raw milliseconds when it lies beyond
 * the Date range. Any u64 is a valid Timestamp (spec §2.2); `new Date(ts).toISOString()` throws a
 * RangeError above that range (security review 2026-11-20, L-1).
 */
export function formatTimestamp(ts) {
  const value = BigInt(ts);
  if (value < 0n || value > MAX_DATE_MS) return `${value} ms`;
  return new Date(Number(value)).toISOString();
}
