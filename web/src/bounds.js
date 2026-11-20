// Client bounds (ADR 0029, spec §4 "Client bounds"). The body ceilings are protocol values; every
// other number here is a local setting of this client (ADR 0029 rule 17), chosen from the
// non-normative starting values of rule 16 for an interactive browser view.

/** Body ceilings after removal of any content coding (ADR 0029 rule 4). */
export const CEILING = Object.freeze({
  block: 65_909, // MAX_BLOCK_LEN (ADR 0014)
  query: 131_072,
  info: 16_384,
  error: 16_384,
});

export const LIMITS = Object.freeze({
  /** Total time of one request, head and whole body included (rule 7). */
  requestDeadlineMs: 30_000,
  /** Identifiers taken from one relay in one walk of /query (rule 9). */
  walkMaxIds: 10_000,
  /** Pages in a row without a new identifier before a walk stops (hostile `more = true`). */
  walkMaxIdlePages: 16,
  /** Restarts after InvalidCursor in one walk; they count toward the walk (rule 9). */
  walkMaxRestarts: 3,
  /** Transient failures in a row on one request before the operation gives up. */
  maxRetries: 3,
  /** Longest Retry-After obeyed; above it the operation gives up on that relay (rule 14). */
  maxRetryAfterMs: 300_000,
  /** Cap of the exponential back-off, before jitter (spec §4 "Admission control"). */
  backoffCapMs: 60_000,
  /** Blocks fetched because of /query hints in one operation, 404 included (rule 10). */
  fetchMaxBlocks: 200,
  /** GET /block requests in flight per relay (spec §4: at most 8). */
  fetchConcurrency: 4,
  /** Blocks visited by one DAG traversal (rule 11). */
  traverseMaxVisited: 1_000,
  /** Local store budget (rule 12): blocks fetched from relays are evicted first. */
  storeMaxBlocks: 5_000,
  storeMaxBytes: 64 * 1024 * 1024,
  /** Own blocks not yet acknowledged by a relay: they are never evicted, so their count is capped. */
  storeMaxPending: 200,
  /**
   * Highest difficulty this client mines when it takes it from a relay's /info (rule 13). Same
   * value as cli-demo (MAX_RELAY_DIFFICULTY); the default difficulty itself is Q-28. A difficulty
   * the user types is not bound by it.
   */
  maxInfoDifficulty: 24,
  /** Difficulty applied on receipt: a local setting, never from /info (ADR 0026, default 0). */
  receiptDifficulty: 0,
});

/** Default `limit` of /query when none is sent, and the largest page (ADR 0012 rules 5, 8). */
export const DEFAULT_QUERY_LIMIT = 100;
export const MAX_QUERY_LIMIT = 1_000;
