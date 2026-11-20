// Local settings of this page: the relay list. Not a secret (no key, no token): kept in
// localStorage, read and written inside try/catch, since storage can be unavailable (private window,
// blocked site data). Each entry is checked again on load; a bad saved list falls back to the default.

import { parseRelayList } from "./relays.js";

const KEY = "sbtp-web.relays";
export const DEFAULT_RELAYS = Object.freeze(["http://127.0.0.1:8080"]);

/** The saved relay list, checked, or the default. `storage`: localStorage or a test double. */
export function loadRelays(storage) {
  try {
    const v = JSON.parse((storage ?? globalThis.localStorage)?.getItem(KEY) ?? "null");
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) return parseRelayList(v.join("\n"));
  } catch {
    // Unavailable storage or a bad saved value: the default.
  }
  return [...DEFAULT_RELAYS];
}

/** Checks and saves `text` (URLs separated by spaces, commas or line ends). Returns the list. */
export function saveRelays(text, storage) {
  const list = parseRelayList(text);
  try {
    (storage ?? globalThis.localStorage)?.setItem(KEY, JSON.stringify(list));
  } catch {
    // Not persisted: the list still applies to this page.
  }
  return list;
}
