// Local settings of this page: the relay list. Not a secret (no key, no token): kept in
// localStorage, read and written inside try/catch, since storage can be unavailable (private window,
// blocked site data). Each entry is checked again on load; a bad saved list falls back to the default.
//
// A change of the list is announced to the listeners of `onRelaysChange` (ADR 0047 rules 6 and 7:
// the store deletes the delivery states of a removed relay and makes an added relay pending for the
// blocks protected at that moment).

import { parseRelayList } from "./relays.js";

export const RELAYS_KEY = "sbtp-web.relays";
export const DEFAULT_RELAYS = Object.freeze(["http://127.0.0.1:8080"]);

const listeners = new Set();

/**
 * Calls `fn(next, previous)` after each `saveRelays` that changes the list (order included).
 * Returns a function that removes the listener. A listener that throws or rejects does not stop the
 * others; its error is passed to `onError`, when given.
 */
export function onRelaysChange(fn, onError) {
  const entry = { fn, onError };
  listeners.add(entry);
  return () => listeners.delete(entry);
}

/** Announces a change of the list (also used for a change made in another tab). */
export function announceRelays(next, previous) {
  if (previous && next.length === previous.length && next.every((b, i) => b === previous[i])) return;
  for (const { fn, onError } of [...listeners]) {
    try {
      Promise.resolve(fn(next, previous)).catch((e) => onError?.(e));
    } catch (e) {
      onError?.(e);
    }
  }
}

/** The saved relay list, checked, or the default. `storage`: localStorage or a test double. */
export function loadRelays(storage) {
  try {
    const v = JSON.parse((storage ?? globalThis.localStorage)?.getItem(RELAYS_KEY) ?? "null");
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) return parseRelayList(v.join("\n"));
  } catch {
    // Unavailable storage or a bad saved value: the default.
  }
  return [...DEFAULT_RELAYS];
}

/**
 * Checks and saves `text` (URLs separated by spaces, commas or line ends). Returns the list.
 * `previous`: the list in use, so that listeners are told only of a change (default: the saved one).
 */
export function saveRelays(text, storage, previous) {
  const list = parseRelayList(text);
  const before = previous ?? loadRelays(storage);
  try {
    (storage ?? globalThis.localStorage)?.setItem(RELAYS_KEY, JSON.stringify(list));
  } catch {
    // Not persisted: the list still applies to this page.
  }
  announceRelays(list, before);
  return list;
}
