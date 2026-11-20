// Relay interface of spec §4: /info, PUT and GET /block, /query. Response checks of ADR 0029 rules
// 8 and 13. No block is validated here: callers pass fetched bytes to sbtp-wasm (spec §3.4).

import { CEILING, DEFAULT_QUERY_LIMIT, LIMITS, MAX_QUERY_LIMIT } from "./bounds.js";
import { isIdHex } from "./hex.js";
import { request } from "./http.js";

const MAX_CURSOR_LEN = 128;
const CURSOR_RE = /^[A-Za-z0-9_-]+$/;
const U64_LIMIT = 2 ** 64;

/** A response that is a failed request (ADR 0029 rule 15): nothing from it is used. */
export class InvalidResponse extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidResponse";
  }
}

/** A non-2xx status the operation did not expect. */
export class RelayStatus extends Error {
  constructor(status, errorName, retryAfter) {
    super(`relay answered ${status}${errorName ? ` ${errorName}` : ""}`);
    this.name = "RelayStatus";
    this.status = status;
    this.errorName = errorName; // from the error body, or null (missing or unparseable)
    this.retryAfter = retryAfter; // see parseRetryAfter
  }

  /** The same request may be repeated after a delay (spec §4 "Admission control", K3). */
  get transient() {
    return [408, 429, 500, 502, 503, 504].includes(this.status);
  }
}

/** Cursor syntax a relay MUST issue (ADR 0012 rule 5, clarification K1). */
export const isCursorSyntax = (c) =>
  typeof c === "string" && c.length >= 1 && c.length <= MAX_CURSOR_LEN && CURSOR_RE.test(c);

function parseJson(bytes) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isNonNegInt = (v, max) => Number.isInteger(v) && v >= 0 && v <= max;

/**
 * `/info` body (ADR 0029 rule 13). `min_pow_difficulty` and `max_future_ms` are required and
 * checked; `max_query_limit` and `block_ttl_ms` are kept only when in range, else treated as absent.
 */
export function parseInfo(bytes) {
  const v = parseJson(bytes);
  if (!isObject(v)) throw new InvalidResponse("/info is not a JSON object");
  if (!isNonNegInt(v.min_pow_difficulty, 256)) {
    throw new InvalidResponse("/info: min_pow_difficulty is not an integer from 0 to 256");
  }
  if (!Number.isInteger(v.max_future_ms) || v.max_future_ms < 0 || v.max_future_ms >= U64_LIMIT) {
    throw new InvalidResponse("/info: max_future_ms is not a non-negative u64");
  }
  const info = { minPowDifficulty: v.min_pow_difficulty, maxFutureMs: v.max_future_ms };
  if (Number.isInteger(v.max_query_limit) && v.max_query_limit >= 1 && v.max_query_limit <= MAX_QUERY_LIMIT) {
    info.maxQueryLimit = v.max_query_limit;
  }
  if (v.block_ttl_ms === null || (Number.isInteger(v.block_ttl_ms) && v.block_ttl_ms > 0)) {
    info.blockTtlMs = v.block_ttl_ms;
  }
  return Object.freeze(info);
}

/**
 * The difficulty to mine at for a relay (ADR 0029 rule 13). An explicit user value wins; a value
 * from /info above `max` is refused rather than mined.
 */
export function sendingDifficulty(info, explicit, max = LIMITS.maxInfoDifficulty) {
  if (explicit !== undefined && explicit !== null) return explicit;
  if (info.minPowDifficulty > max) {
    throw new InvalidResponse(
      `the relay asks for difficulty ${info.minPowDifficulty}, above this client's maximum of ${max} ` +
      "for a value read from /info; set a difficulty explicitly to mine anyway");
  }
  return info.minPowDifficulty;
}

/**
 * The difficulty to mine at: an explicit value (an integer from 0 to 256) is used as is, without
 * reading /info, so publishing works when /info fails; otherwise `/info` bounded as above.
 */
export async function resolveDifficulty(relay, explicit, { signal } = {}) {
  if (explicit !== undefined && explicit !== null) {
    if (!Number.isInteger(explicit) || explicit < 0 || explicit > 256) {
      throw new RangeError("the difficulty must be an integer from 0 to 256");
    }
    return explicit;
  }
  return sendingDifficulty(await relay.info({ signal }), null);
}

/** `/query` page (ADR 0029 rule 8). `limit` is the one sent, or undefined for none. */
export function parsePage(bytes, limit) {
  const v = parseJson(bytes);
  if (!isObject(v) || !Array.isArray(v.block_ids) || typeof v.cursor !== "string" || typeof v.more !== "boolean") {
    throw new InvalidResponse("/query is not {block_ids, cursor, more}");
  }
  const max = Math.min(limit ?? DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT);
  if (v.block_ids.length > max) throw new InvalidResponse(`/query returned more than ${max} identifiers`);
  if (!v.block_ids.every(isIdHex)) throw new InvalidResponse("/query returned a malformed identifier");
  if (!isCursorSyntax(v.cursor)) throw new InvalidResponse("/query returned a malformed cursor");
  return { blockIds: v.block_ids, cursor: v.cursor, more: v.more };
}

/**
 * `Retry-After` (ADR 0029 rule 14): `{ ms }` for delay-seconds, `null` when absent, `{ ms: null }`
 * when present but not delay-seconds (an HTTP date, garbage): no delay is given.
 */
export function parseRetryAfter(value) {
  if (value === null || value === undefined) return null;
  const text = value.trim();
  if (!/^[0-9]{1,15}$/.test(text)) return { ms: null };
  return { ms: Number(text) * 1000 };
}

/** The `error` member of an error body, or null when missing or unparseable (spec §4 "Errors"). */
export function errorName(bytes) {
  if (bytes === null) return null;
  const v = parseJson(bytes);
  return isObject(v) && typeof v.error === "string" ? v.error.slice(0, 64) : null;
}

function statusError(res) {
  return new RelayStatus(res.status, errorName(res.body), parseRetryAfter(res.headers.get("Retry-After")));
}

/** One relay. `base` comes from `checkRelayUrl`. */
export class Relay {
  constructor(base, { fetchImpl, deadlineMs } = {}) {
    this.base = base;
    this.opts = { fetchImpl, deadlineMs };
  }

  #req(path, extra) {
    return request(this.base + path, { ...this.opts, ...extra });
  }

  async info({ signal } = {}) {
    const res = await this.#req("/sbtp/v1/info", { ceiling: CEILING.info, signal });
    if (res.status !== 200) throw statusError(res);
    return parseInfo(res.body);
  }

  /** PUT a block. Resolves "created" (201) or "stored" (200): the same success (spec §4). */
  async put(bytes, { signal } = {}) {
    const res = await this.#req("/sbtp/v1/block", {
      method: "PUT", body: bytes, contentType: "application/octet-stream", discardBody: true, signal,
    });
    if (res.status === 201) return "created";
    if (res.status === 200) return "stored";
    throw statusError(res);
  }

  /** GET a block by id: its unvalidated bytes, or null on 404. Validate with sbtp-wasm. */
  async get(idHex, { signal } = {}) {
    if (!isIdHex(idHex)) throw new TypeError("block id must be 64 lowercase hex characters");
    const res = await this.#req(`/sbtp/v1/block/${idHex}`, { ceiling: CEILING.block, signal });
    if (res.status === 200) return res.body;
    if (res.status === 404) return null;
    throw statusError(res);
  }

  /** One /query page. `filter`: { parent, since, limit }. */
  async queryPage(filter, cursor, { signal } = {}) {
    const params = new URLSearchParams();
    if (filter.parent !== undefined) params.set("parent", filter.parent);
    if (filter.since !== undefined) params.set("since", String(filter.since));
    if (filter.limit !== undefined) params.set("limit", String(filter.limit));
    if (cursor !== undefined && cursor !== null) params.set("cursor", cursor);
    const qs = params.toString();
    const res = await this.#req(`/sbtp/v1/query${qs ? `?${qs}` : ""}`, { ceiling: CEILING.query, signal });
    if (res.status !== 200) throw statusError(res);
    return parsePage(res.body, filter.limit);
  }
}

/**
 * Fetches and validates up to `max` blocks of `ids` (ADR 0029 rule 10), at most `concurrency` in
 * flight. `validate(bytes, idHex)` returns the verified block or throws. Returns the verified
 * blocks, the ids not found (404) and failures, and whether the bound cut the list.
 */
export async function fetchBlocks(relay, ids, validate, {
  max = LIMITS.fetchMaxBlocks, concurrency = LIMITS.fetchConcurrency, signal,
} = {}) {
  const todo = ids.slice(0, max);
  const result = { blocks: [], notFound: [], failed: [], partial: ids.length > max };
  let next = 0;
  async function worker() {
    while (next < todo.length && !signal?.aborted) {
      const id = todo[next];
      next += 1;
      try {
        const bytes = await relay.get(id, { signal });
        if (bytes === null) result.notFound.push(id);
        else result.blocks.push(validate(bytes, id));
      } catch (e) {
        result.failed.push({ id, error: e });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, 8, todo.length) }, worker));
  return result;
}
