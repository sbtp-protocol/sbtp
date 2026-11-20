// The one place where this client calls fetch() on a relay. Every relay request goes through
// `request()`, so the fetch options (redirects, credentials, deadline) are set once.

import { CEILING, LIMITS } from "./bounds.js";

/**
 * Redirect policy for every relay request (ADR 0030 rule 9): never follow. "manual" rather than
 * "error", so that a redirect is told apart from a network failure (rule 8): in a browser it yields
 * an opaque-redirect response; Node's fetch returns the 3xx itself. Both become `redirect` errors.
 */
export const REDIRECT_MODE = "manual";

/** A failed relay request. `kind`: network, timeout, aborted, body-too-large, bad-url, redirect. */
export class RelayRequestError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = "RelayRequestError";
    this.kind = kind;
  }
}

const LOOPBACK = new Set(["127.0.0.1", "localhost"]); // the CSP connect-src lists the same two

/**
 * Checks a relay base URL. `https://` for any host; plain `http://` only on loopback (a public
 * relay MUST be reachable over HTTPS, spec §4). No user name, query or fragment.
 * Returns the base without a trailing slash.
 */
export function checkRelayUrl(text) {
  let url;
  try {
    url = new URL(String(text).trim());
  } catch {
    throw new RelayRequestError("bad-url", "not a URL; expected for example http://127.0.0.1:8080");
  }
  if (url.username || url.password || url.search || url.hash || String(text).includes("#")) {
    throw new RelayRequestError("bad-url", "the relay URL must have no user name, query or fragment");
  }
  if (url.protocol === "http:" && !LOOPBACK.has(url.hostname)) {
    throw new RelayRequestError("bad-url", "plain http:// is accepted only for a loopback relay; use https://");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new RelayRequestError("bad-url", "expected an http:// (loopback) or https:// URL");
  }
  return (url.origin + url.pathname).replace(/\/+$/, "");
}

/** The error for an operation ended by the caller's `signal`: cancelled, or its own deadline. */
export function abortedError(signal) {
  return new RelayRequestError("aborted", signal?.reason?.name === "TimeoutError"
    ? "the operation took too long and was stopped" : "cancelled");
}

/** A signal that aborts on `signal` or after `ms`, whichever comes first (AbortSignal.any fallback). */
export function deadline(ms, signal) {
  const timeout = AbortSignal.timeout(ms);
  if (!signal) return timeout;
  if (typeof AbortSignal.any === "function") return AbortSignal.any([signal, timeout]);
  const controller = new AbortController();
  const forward = (s) => () => controller.abort(s.reason);
  for (const s of [signal, timeout]) {
    if (s.aborted) controller.abort(s.reason);
    else s.addEventListener("abort", forward(s), { once: true });
  }
  return controller.signal;
}

/**
 * Reads at most `ceiling + 1` bytes of a decoded body (ADR 0029 rule 6). Throws `body-too-large`
 * above the ceiling. With a BYOB reader (Chrome, Firefox, Node) the read stops at exactly
 * `ceiling + 1` bytes; with the default reader at most one browser chunk more is buffered.
 */
export async function readLimited(body, ceiling) {
  if (body === null || body === undefined) return new Uint8Array(0);
  const limit = ceiling + 1;
  let byob = null;
  try {
    byob = body.getReader({ mode: "byob" });
  } catch {
    // Not a byte stream: fall back to the default reader below.
  }
  if (byob !== null) {
    let buffer = new ArrayBuffer(limit);
    let filled = 0;
    while (filled < limit) {
      const { value, done } = await byob.read(new Uint8Array(buffer, filled, limit - filled));
      if (value) buffer = value.buffer;
      if (done) break;
      filled += value.byteLength;
    }
    if (filled > ceiling) {
      await byob.cancel().catch(() => {});
      throw new RelayRequestError("body-too-large", `response body above ${ceiling} bytes`);
    }
    // A tight copy: a view over the ceiling + 1 buffer would carry (and, stored in IndexedDB,
    // persist) the whole buffer whatever the body length.
    return new Uint8Array(buffer.slice(0, filled));
  }
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > ceiling) {
      await reader.cancel().catch(() => {});
      throw new RelayRequestError("body-too-large", `response body above ${ceiling} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/**
 * One relay request. Resolves with `{ status, headers, body }` once the whole body is read within
 * the deadline (ADR 0029 rule 7: the signal covers the body read too). `ceiling` bounds a 2xx body;
 * an error body is bounded by 16,384 bytes and is `null` when it exceeds it (unparseable, rule 6).
 * `discardBody` cancels a 2xx body unread (PUT: its success body carries nothing the client uses).
 */
export async function request(url, {
  method = "GET", body, contentType, ceiling, signal, discardBody = false,
  deadlineMs = LIMITS.requestDeadlineMs, fetchImpl = globalThis.fetch,
} = {}) {
  const sig = deadline(deadlineMs, signal);
  const init = {
    method,
    redirect: REDIRECT_MODE,
    credentials: "omit", // spec §4 CORS: no cookies, no HTTP authentication
    referrerPolicy: "no-referrer",
    cache: "no-store",
    signal: sig,
  };
  if (body !== undefined) {
    init.body = body;
    init.headers = { "Content-Type": contentType };
  }
  try {
    const response = await fetchImpl(url, init);
    // ADR 0030 rules 6 to 8: a 3xx (this client sends no conditional request, so a 304 is one too)
    // is a failed request, never repeated automatically. Its body is not read and its Location is
    // not used.
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status <= 399)) {
      await response.body?.cancel().catch(() => {});
      const code = response.type === "opaqueredirect" ? "" : ` (${response.status})`;
      throw new RelayRequestError("redirect",
        `the relay URL redirects${code}; a relay never redirects (ADR 0030): check the relay URL`);
    }
    const ok = response.status >= 200 && response.status < 300;
    let bytes = null;
    if (ok && discardBody) {
      await response.body?.cancel().catch(() => {});
    } else if (ok) {
      bytes = await readLimited(response.body, ceiling);
    } else {
      try {
        bytes = await readLimited(response.body, CEILING.error);
      } catch (e) {
        if (!(e instanceof RelayRequestError && e.kind === "body-too-large")) throw e;
      }
    }
    return { status: response.status, headers: response.headers, body: bytes };
  } catch (e) {
    if (e instanceof RelayRequestError) throw e;
    // The caller's signal (a Cancel button, an operation deadline) first: that is an end of the
    // operation, never retried. Only this request's own deadline is a `timeout` (transient).
    if (signal?.aborted) throw abortedError(signal);
    if (sig.aborted) {
      throw new RelayRequestError("timeout", `no complete response within ${deadlineMs / 1000} s`);
    }
    // fetch() rejects with a TypeError on a network failure or a CORS refusal; the browser does not
    // tell them apart.
    throw new RelayRequestError("network", "network failure or CORS refusal");
  }
}
