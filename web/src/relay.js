// Relay interface of spec §4: /info, PUT and GET /block, /query, and the read API of ADR 0051
// (POST /blocks, `order`, `fields`, `head`, grouped `parent`). Response checks of ADR 0029 rules 8
// and 13 and ADR 0051 rules 2, 6, 14, 24. No block is validated here: callers pass fetched bytes to
// sbtp-wasm (spec §3.4). The ADR 0051 forms are sent only to a relay whose /info has
// `read_api >= 2` (rule 31): the callers (relays.js) check it first.

import { CEILING, DEFAULT_QUERY_LIMIT, LIMITS, MAX_QUERY_LIMIT, READ_API } from "./bounds.js";
import { fromHex, isIdHex } from "./hex.js";
import { request } from "./http.js";

const MAX_CURSOR_LEN = 128;

/**
 * The network difficulty `D_NET` (spec §3.3, ADR 0045; `sbtp_core::NETWORK_POW_DIFFICULTY`). A
 * difficulty read from /info is raised to it, so that a published block can be copied to every
 * relay of the network (ADR 0045 rule 5). It changes only by a revision of the specification.
 */
export const NETWORK_POW_DIFFICULTY = 16;
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
  // ADR 0051 rule 31: absent reads as 1. A value that is not a positive integer reads as 1 too:
  // the new forms are sent only to a relay that clearly announces them.
  info.readApi = Number.isInteger(v.read_api) && v.read_api >= 1 && v.read_api < 2 ** 31 ? v.read_api : 1;
  return Object.freeze(info);
}

/**
 * The difficulty to mine at for a relay (ADR 0029 rule 13). An explicit user value wins; a value
 * from /info above `max` is refused rather than mined, and one below `D_NET` is raised to it
 * (ADR 0045 rule 5).
 */
export function sendingDifficulty(info, explicit, max = LIMITS.maxInfoDifficulty) {
  if (explicit !== undefined && explicit !== null) return explicit;
  if (info.minPowDifficulty > max) {
    throw new InvalidResponse(
      `the relay asks for difficulty ${info.minPowDifficulty}, above this client's maximum of ${max} ` +
      "for a value read from /info; set a difficulty explicitly to mine anyway");
  }
  return Math.max(NETWORK_POW_DIFFICULTY, info.minPowDifficulty);
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

/**
 * `head` (ADR 0051 rule 18): null when absent (a relay before `read_api` 2); a member that is
 * present but not a cursor makes the response a failed request.
 */
function parseHead(v) {
  if (v.head === undefined) return null;
  if (!isCursorSyntax(v.head)) throw new InvalidResponse("/query returned a malformed head");
  return v.head;
}

/**
 * The `parents` and `lens` members of `fields=parents` (ADR 0051 rule 13), aligned with `ids`:
 * `[{ parents, len }]`. They are hints: a block's own header is authoritative once fetched.
 */
function parseHints(v, ids) {
  if (!Array.isArray(v.parents) || !Array.isArray(v.lens) ||
      v.parents.length !== ids.length || v.lens.length !== ids.length) {
    throw new InvalidResponse("/query with fields=parents: parents and lens are not aligned with block_ids");
  }
  return ids.map((_, i) => {
    const parents = v.parents[i];
    const len = v.lens[i];
    if (!Array.isArray(parents) || parents.length > READ_API.maxParentsPerBlock || !parents.every(isIdHex)) {
      throw new InvalidResponse("/query returned malformed parents");
    }
    if (!Number.isInteger(len) || len < 1 || len > CEILING.block) {
      throw new InvalidResponse("/query returned a block length out of range");
    }
    return Object.freeze({ parents: Object.freeze([...parents]), len });
  });
}

/** The largest page a request may get back: the `limit` sent (default 100), at most 1,000, 200 with `fields`. */
export const pageMax = (limit, fields) =>
  Math.min(limit ?? DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT, fields ? READ_API.fieldsMaxPage : MAX_QUERY_LIMIT);

/**
 * `/query` page (ADR 0029 rule 8). `limit` is the one sent, or undefined for none; `fields` is
 * true when `fields=parents` was sent (ADR 0051 rules 13 and 14). Resolves `{ blockIds, cursor,
 * more, head, hints }`; `hints` is null without `fields`, `head` null when the relay sent none.
 */
export function parsePage(bytes, limit, fields = false) {
  const v = parseJson(bytes);
  if (!isObject(v) || !Array.isArray(v.block_ids) || typeof v.cursor !== "string" || typeof v.more !== "boolean") {
    throw new InvalidResponse("/query is not {block_ids, cursor, more}");
  }
  const max = pageMax(limit, fields);
  if (v.block_ids.length > max) throw new InvalidResponse(`/query returned more than ${max} identifiers`);
  if (!v.block_ids.every(isIdHex)) throw new InvalidResponse("/query returned a malformed identifier");
  if (!isCursorSyntax(v.cursor)) throw new InvalidResponse("/query returned a malformed cursor");
  const head = parseHead(v);
  const hints = fields ? parseHints(v, v.block_ids) : null;
  return { blockIds: v.block_ids, cursor: v.cursor, more: v.more, head, hints };
}

/**
 * Grouped `/query` response (ADR 0051 rule 24) for `parents` (the ids requested, in order): one
 * entry per parent, in request order, each a single-parent page. `limit` bounds each entry; the
 * total is at most `max(N, 1000)` (rule 23). Resolves `{ groups: [{ parent, blockIds, cursor,
 * more }], head }`.
 */
export function parseGroup(bytes, parents, limit) {
  const v = parseJson(bytes);
  if (!isObject(v) || !Array.isArray(v.parents) || v.parents.length !== parents.length) {
    throw new InvalidResponse("grouped /query is not {parents: [one entry per parent requested], head}");
  }
  const max = pageMax(limit, false);
  let total = 0;
  const groups = v.parents.map((g, i) => {
    if (!isObject(g) || g.parent !== parents[i]) {
      throw new InvalidResponse("grouped /query: an entry does not match the parent requested at its position");
    }
    if (!Array.isArray(g.block_ids) || typeof g.cursor !== "string" || typeof g.more !== "boolean") {
      throw new InvalidResponse("grouped /query: an entry is not {parent, block_ids, cursor, more}");
    }
    if (g.block_ids.length > max) throw new InvalidResponse(`grouped /query: more than ${max} identifiers for one parent`);
    if (!g.block_ids.every(isIdHex)) throw new InvalidResponse("grouped /query returned a malformed identifier");
    if (!isCursorSyntax(g.cursor)) throw new InvalidResponse("grouped /query returned a malformed cursor");
    total += g.block_ids.length;
    return { parent: g.parent, blockIds: g.block_ids, cursor: g.cursor, more: g.more };
  });
  if (total > Math.max(parents.length, MAX_QUERY_LIMIT)) {
    throw new InvalidResponse("grouped /query returned more identifiers than rule 23 allows");
  }
  const head = parseHead(v);
  if (head === null) throw new InvalidResponse("grouped /query has no head");
  return { groups, head };
}

/**
 * `POST /sbtp/v1/blocks` body (ADR 0051 rules 2, 3, 6) for `count` identifiers requested: the
 * records in request order, each the unvalidated bytes or null (`length = 0`: not served).
 *
 * - A length above MAX_BLOCK_LEN, more records than identifiers, or no record at all: a failed
 *   request (throws InvalidResponse); nothing is used.
 * - A body that ends inside a record (or inside a length): `truncated` is true; the complete
 *   records before it are returned, since each is checked on its own (rule 6), but the response
 *   is a failed request for the rest.
 * - Fewer records than identifiers (rule 3, a prefix): the caller requests the rest again.
 */
export function parseRecords(bytes, count) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const records = [];
  let at = 0;
  while (at < bytes.byteLength) {
    if (records.length >= count) throw new InvalidResponse("POST /blocks returned more records than identifiers requested");
    if (bytes.byteLength - at < 4) return { records, truncated: true };
    const len = view.getUint32(at, false);
    if (len > CEILING.block) {
      throw new InvalidResponse(`POST /blocks returned a record of ${len} bytes, above the largest block (${CEILING.block})`);
    }
    if (bytes.byteLength - at - 4 < len) return { records, truncated: true };
    records.push(len === 0 ? null : bytes.slice(at + 4, at + 4 + len));
    at += 4 + len;
  }
  if (records.length === 0) throw new InvalidResponse("POST /blocks returned 200 with no record");
  return { records, truncated: false };
}

/** The query string of a /query request; `parents` (2 or more) as `<id>` or `<id>.<cursor>`. */
function queryString(filter, cursor, parents = null) {
  const params = new URLSearchParams();
  if (parents) {
    for (const { parent, cursor: c } of parents) params.append("parent", c ? `${parent}.${c}` : parent);
  } else if (filter.parent !== undefined) {
    params.set("parent", filter.parent);
  }
  if (filter.since !== undefined) params.set("since", String(filter.since));
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  // `order` and `fields` only when they differ from the defaults: a request without them is the
  // one an old relay understands (ADR 0051 rule 31).
  if (filter.order !== undefined && filter.order !== "asc") params.set("order", filter.order);
  if (filter.fields) params.set("fields", "parents");
  if (cursor !== undefined && cursor !== null) params.set("cursor", cursor);
  return params.toString();
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

/**
 * The `error` member of an error body, or null when missing or unparseable (spec §4 "Errors"). Only
 * `[A-Za-z0-9_-]` is kept (at most 64 characters), so that a relay cannot put a line break or other
 * text into what is stored and shown (security review 2026-11-21 pre-push, I-2); a name left empty
 * is null.
 */
export function errorName(bytes) {
  if (bytes === null) return null;
  const v = parseJson(bytes);
  if (!isObject(v) || typeof v.error !== "string") return null;
  const name = v.error.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
  return name === "" ? null : name;
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

  /**
   * One /query page. `filter`: { parent, since, limit } and, for a `read_api >= 2` relay only,
   * `order` ("asc" or "desc") and `fields` (true for `fields=parents`; not with `parent`).
   */
  async queryPage(filter, cursor, { signal } = {}) {
    if (filter.fields && filter.parent !== undefined) {
      throw new TypeError("fields=parents is not combined with parent (ADR 0051 rule 14)");
    }
    const qs = queryString(filter, cursor);
    const res = await this.#req(`/sbtp/v1/query${qs ? `?${qs}` : ""}`, { ceiling: CEILING.query, signal });
    if (res.status !== 200) throw statusError(res);
    return parsePage(res.body, filter.limit, !!filter.fields);
  }

  /**
   * Grouped /query (ADR 0051 rules 21 to 24), `read_api >= 2` only: `parents` is 1 to 32
   * `{ parent, cursor }` with distinct parents, each cursor its own (rule 21); `filter` gives
   * `since`, `limit`, `order`. One parent uses the single-parent form. Resolves `{ groups, head }`
   * as parseGroup.
   */
  async queryGroup(parents, filter = {}, { signal } = {}) {
    if (parents.length < 1 || parents.length > READ_API.maxParents) {
      throw new RangeError(`a grouped /query takes 1 to ${READ_API.maxParents} parents`);
    }
    if (new Set(parents.map((p) => p.parent)).size !== parents.length || !parents.every((p) => isIdHex(p.parent))) {
      throw new TypeError("the parents of a grouped /query are distinct block ids");
    }
    const { since, limit, order } = filter;
    if (parents.length === 1) {
      const [only] = parents;
      const page = await this.queryPage({ parent: only.parent, since, limit, order }, only.cursor, { signal });
      return {
        groups: [{ parent: only.parent, blockIds: page.blockIds, cursor: page.cursor, more: page.more }],
        head: page.head,
      };
    }
    const qs = queryString({ since, limit, order }, null, parents);
    const res = await this.#req(`/sbtp/v1/query?${qs}`, { ceiling: CEILING.query, signal });
    if (res.status !== 200) throw statusError(res);
    return parseGroup(res.body, parents.map((p) => p.parent), limit);
  }

  /**
   * `POST /sbtp/v1/blocks` (ADR 0051 rules 1 to 6), `read_api >= 2` only: 1 to 256 distinct ids.
   * Resolves `{ records, truncated }` as parseRecords: the unvalidated bytes (or null) of a prefix
   * of `ids`, to be validated each against the id at its position. The body is read up to 1 MiB
   * (rule 4); above it the request fails (`body-too-large`).
   */
  async fetchBatch(ids, { signal } = {}) {
    if (ids.length < 1 || ids.length > READ_API.batchMaxIds) {
      throw new RangeError(`a batch takes 1 to ${READ_API.batchMaxIds} block ids`);
    }
    if (new Set(ids).size !== ids.length || !ids.every(isIdHex)) {
      throw new TypeError("the ids of a batch are distinct 64-character lowercase hex block ids");
    }
    const body = new Uint8Array(32 * ids.length);
    ids.forEach((id, i) => body.set(fromHex(id), 32 * i));
    const res = await this.#req("/sbtp/v1/blocks", {
      method: "POST", body, contentType: "application/octet-stream", ceiling: CEILING.batch, signal,
    });
    if (res.status !== 200) throw statusError(res);
    return parseRecords(res.body, ids.length);
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
