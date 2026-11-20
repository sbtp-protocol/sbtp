// UI of index.html. Every value from a relay or a block is written with textContent, never as HTML.

import { LIMITS } from "./bounds.js";
import { formatTimestamp } from "./format.js";
import { fromHex, isIdHex, toHex } from "./hex.js";
import { checkRelayUrl, deadline, RelayRequestError } from "./http.js";
import { openDb } from "./idb.js";
import { createIdentity, deleteIdentity, loadIdentity, signBlock } from "./keys.js";
import { mineInWorker } from "./miner.js";
import { fetchBlocks, Relay, RelayStatus, resolveDifficulty } from "./relay.js";
import { BlockStore } from "./store.js";
import { traverse } from "./traverse.js";
import { walk } from "./walk.js";
import { buildUnsignedBlock, loadSbtp, verifyFetched, verifySubmitted } from "./wasm.js";

const $ = (id) => document.getElementById(id);
const say = (id, text, cls = "") => { $(id).textContent = text; $(id).className = cls; };
const fail = (id, e) => say(id, `${e.name ?? "Error"}: ${e.message ?? e}`, "bad");

let db;
let store;
let identity = null;
let brokenKey = null; // the error of a stored identity record that failed to load
let mining = null;
let republishing = false;

const relay = () => new Relay(checkRelayUrl($("relay").value));

/**
 * Asks the browser not to evict this origin's storage once a key exists: the identity cannot be
 * exported, so evicted site data loses it (README, "Key storage"). Refused or unavailable: warn.
 */
async function requestPersistence() {
  if (!identity) return say("persist-out", "");
  let persisted = false;
  try {
    persisted = (await navigator.storage?.persisted?.()) || (await navigator.storage?.persist?.()) || false;
  } catch {
    persisted = false;
  }
  if (persisted) return say("persist-out", "Persistent storage granted: the browser will not evict the identity on its own.", "ok");
  say("persist-out", "Warning: persistent storage was refused or is unavailable. The browser may clear this " +
    "site's data (Safari can after about 7 days without use, others under storage pressure), and the " +
    "identity would be lost: it cannot be exported.", "bad");
}

function showIdentity() {
  requestPersistence();
  if (brokenKey) {
    say("key-out", `A stored identity could not be loaded (${brokenKey.name}: ${brokenKey.message}). ` +
      "It cannot be repaired or recovered. Delete it to generate a new one.", "bad");
  } else {
    say("key-out", identity
      ? `Public key ${toHex(identity.publicKey)}\nCreated ${new Date(identity.created).toISOString()}; ` +
        "private key: Web Crypto Ed25519, non-extractable, in IndexedDB."
      : "No key. Generate one to publish.");
  }
  $("key-delete").disabled = !identity && !brokenKey;
  $("key-new").disabled = !!identity || !!brokenKey;
}

/** Renders one block. Never throws: one odd block cannot abort a view (review L-1). */
function renderBlock(b, note) {
  const div = document.createElement("div");
  div.className = "block";
  try {
    const head = document.createElement("div");
    head.className = "mono muted";
    head.textContent = `${b.idHex}\nby ${b.publicKeyHex.slice(0, 16)}…  ${formatTimestamp(b.timestamp)}  ` +
      `pow ${b.leadingZeroBits}  parents ${b.parents.length}${note ? `  ${note}` : ""}`;
    const text = document.createElement("div");
    text.textContent = new TextDecoder().decode(b.payload).slice(0, 4000);
    const reply = document.createElement("button");
    reply.textContent = "Use as parent";
    reply.addEventListener("click", () => {
      $("parents").value = `${$("parents").value} ${b.idHex}`.trim();
    });
    div.append(head, text, reply);
  } catch (e) {
    div.replaceChildren();
    div.textContent = `${b?.idHex ?? "block"}: cannot be displayed (${e?.name ?? "Error"})`;
  }
  $("blocks").append(div);
}

/**
 * Runs one browse operation (List or Ancestors) with a Cancel button and an overall deadline
 * (review L-2): at most one at a time, buttons disabled while it runs.
 */
const BROWSE_DEADLINE_MS = 120_000;
const BROWSE_BUTTONS = ["list", "ancestors", "local"];
let browsing = null;

async function browse(run) {
  if (browsing) return;
  browsing = new AbortController();
  const signal = deadline(BROWSE_DEADLINE_MS, browsing.signal);
  for (const id of BROWSE_BUTTONS) $(id).disabled = true;
  $("browse-cancel").disabled = false;
  $("blocks").replaceChildren();
  try {
    await run(signal);
  } catch (e) {
    fail("list-out", e);
  } finally {
    if (signal.aborted) {
      say("list-out", `${$("list-out").textContent} Stopped: ${signal.reason?.name === "TimeoutError"
        ? `over ${BROWSE_DEADLINE_MS / 1000} s` : "cancelled"}; partial view.`, "bad");
    }
    browsing = null;
    for (const id of BROWSE_BUTTONS) $(id).disabled = false;
    $("browse-cancel").disabled = true;
  }
}

/** Validates a fetched block (spec §3.4, client difficulty) and keeps it locally. */
async function receive(bytes, idHex) {
  const b = verifyFetched(bytes, LIMITS.receiptDifficulty, idHex);
  await store.put(idHex, bytes).catch(() => {}); // a full store only means it is not cached
  return b;
}

async function publishOne(r, id, bytes, signal) {
  const outcome = await r.put(bytes, { signal });
  await store.ack(id);
  return outcome;
}

async function onPublish() {
  if (!identity) return say("publish-out", "Generate a key first.", "bad");
  const controller = new AbortController();
  mining = controller;
  $("cancel").disabled = false;
  $("publish").disabled = true;
  try {
    const r = relay();
    const parentIds = $("parents").value.split(/\s+/).filter(Boolean);
    if (!parentIds.every(isIdHex)) throw new Error("a parent is not a 64-character lowercase hex id");
    const parents = fromHex(parentIds.join(""));
    const payload = new TextEncoder().encode($("payload").value);
    const typed = $("difficulty").value.trim();
    const explicit = typed === "" ? null : Number(typed);
    // An explicit difficulty needs no /info (review finding 10).
    const d = await resolveDifficulty(r, explicit, { signal: controller.signal });
    const unsigned = buildUnsignedBlock(identity.publicKey, BigInt(Date.now()), 0n, parents, payload);
    const t0 = performance.now();
    say("publish-out", `Mining at difficulty ${d} in a Web Worker…`);
    const mined = await mineInWorker(unsigned, d, {
      signal: controller.signal,
      onProgress: (n) => say("publish-out", `Mining at difficulty ${d}: ${n.toLocaleString()} attempts…`),
    });
    const ms = Math.round(performance.now() - t0);
    const signed = await signBlock(identity, mined);
    const b = verifySubmitted(signed, d);
    await store.put(b.idHex, signed, { own: true }); // kept until a relay acknowledges it
    controller.signal.throwIfAborted();
    const outcome = await publishOne(r, b.idHex, signed, controller.signal);
    say("publish-out", `Published ${b.idHex} (${outcome === "created" ? "201 created" : "200 already stored"}); ` +
      `mined in ${ms} ms.`, "ok");
  } catch (e) {
    if (controller.signal.aborted) {
      say("publish-out", "Cancelled. A block already signed is kept as pending: " +
        "\"Publish pending blocks\" sends it later.", "bad");
    } else {
      fail("publish-out", e);
    }
  } finally {
    mining = null;
    $("cancel").disabled = true;
    $("publish").disabled = false;
  }
}

/** A failure that concerns the relay, not one block: the run stops instead of trying the rest. */
const relayWide = (e) => e instanceof RelayRequestError || (e instanceof RelayStatus && e.transient);

async function onRepublish() {
  if (republishing) return;
  republishing = true;
  $("republish").disabled = true;
  let acked = 0;
  let failed = 0;
  let pending = [];
  let stopped = null;
  let last = null;
  try {
    const r = relay();
    pending = (await store.list()).filter((m) => m.own && !m.acked);
    for (const m of pending) {
      try {
        const bytes = await store.get(m.id);
        verifySubmitted(bytes, 0);
        await publishOne(r, m.id, bytes);
        acked += 1;
      } catch (e) {
        failed += 1;
        last = e;
        if (relayWide(e)) {
          stopped = e;
          break;
        }
      }
    }
  } catch (e) {
    stopped = e;
  } finally {
    republishing = false;
    $("republish").disabled = false;
  }
  const left = pending.length - acked;
  const why = stopped ?? last;
  say("publish-out", `${acked} pending block(s) acknowledged, ${failed} failed, ${left} still pending` +
    `${stopped ? "; stopped" : ""}${why ? ` (${why.name}: ${why.message})` : ""}.`, why ? "bad" : "ok");
}

function onList() {
  return browse(async (signal) => {
    const r = relay();
    const parent = $("parent-filter").value.trim();
    if (parent && !isIdHex(parent)) throw new Error("the filter is not a 64-character lowercase hex id");
    say("list-out", "Walking /query…");
    // The view fetches at most fetchMaxBlocks blocks: walking further would be wasted (review L-2).
    const w = await walk(r, parent ? { parent } : {}, {
      signal, limits: { ...LIMITS, walkMaxIds: LIMITS.fetchMaxBlocks },
    });
    const got = await fetchBlocks(r, w.ids,
      (bytes, id) => ({ b: verifyFetched(bytes, LIMITS.receiptDifficulty, id), bytes }), { signal });
    for (const { b, bytes } of got.blocks) {
      await store.put(b.idHex, bytes).catch(() => {}); // a full store only means it is not cached
      renderBlock(b);
    }
    const partial = w.stop !== "done" || got.partial;
    say("list-out", `${w.ids.length} id(s) listed (walk: ${w.stop}${w.error ? `, ${w.error.message}` : ""}); ` +
      `${got.blocks.length} fetched and verified, ${got.notFound.length} not found, ${got.failed.length} failed` +
      `${partial ? ". Partial view: a bound or a failure stopped it." : "."}`, partial ? "bad" : "ok");
  });
}

function onAncestors() {
  return browse(async (signal) => {
    const r = relay();
    const start = $("parent-filter").value.trim();
    if (!isIdHex(start)) throw new Error("enter a block id in the field above");
    say("list-out", "Walking ancestors…");
    const t = await traverse(start, async (id) => {
      let b;
      try {
        const bytes = (await store.get(id)) ?? (await r.get(id, { signal }));
        if (bytes === null) return null;
        b = await receive(bytes, id);
      } catch {
        return null; // unreachable, or fails §3.4: discarded, never stored
      }
      renderBlock(b);
      return b.parents;
    }, { signal });
    say("list-out", `${t.visited.length} block(s) visited, ${t.unavailable.length} unavailable` +
      `${t.partial ? `; partial: stopped at ${LIMITS.traverseMaxVisited} blocks or cancelled` : ""}.`, t.partial ? "bad" : "ok");
  });
}

async function onLocal() {
  $("blocks").replaceChildren();
  try {
    const metas = (await store.list()).sort((a, b) => b.accessed - a.accessed);
    let bytes = 0;
    let bad = 0;
    for (const m of metas.slice(0, 100)) {
      bytes += m.size;
      let b;
      try {
        b = verifyFetched(await store.get(m.id), 0, m.id);
      } catch {
        bad += 1;
        continue;
      }
      renderBlock(b, m.own ? (m.acked ? "own, published" : "own, PENDING") : "fetched");
    }
    say("list-out", `${metas.length} local block(s); budget ${LIMITS.storeMaxBlocks} blocks, ` +
      `${LIMITS.storeMaxBytes / 2 ** 20} MiB (showing the 100 most recent, ${bytes} bytes)` +
      `${bad ? `; ${bad} failed validation and are not shown` : ""}.`, bad ? "bad" : "");
  } catch (e) {
    fail("list-out", e);
  }
}

async function main() {
  try {
    await loadSbtp();
    db = await openDb();
    store = new BlockStore(db);
    say("status", "sbtp-wasm loaded, self-test passed (ADR 0003 rule 16).", "ok");
    try {
      identity = await loadIdentity(db);
    } catch (e) {
      brokenKey = e; // the record exists but is unusable: offer to delete it
    }
  } catch (e) {
    fail("status", e);
  }
  showIdentity();
  $("info").addEventListener("click", async () => {
    try {
      say("info-out", JSON.stringify(await relay().info(), null, 1));
    } catch (e) {
      fail("info-out", e);
    }
  });
  $("key-new").addEventListener("click", async () => {
    try {
      identity = await createIdentity(db);
      showIdentity();
    } catch (e) {
      fail("key-out", e);
    }
  });
  $("key-delete").addEventListener("click", async () => {
    const question = brokenKey
      ? "Delete the stored identity that cannot be loaded? It is lost for good: it cannot be recovered."
      : "Delete this identity? It cannot be exported or recovered.";
    if (!confirm(question)) return;
    try {
      await deleteIdentity(db);
    } catch (e) {
      say("key-out", `The key was NOT deleted (${e.name}: ${e.message}).`, "bad");
      return;
    }
    identity = null;
    brokenKey = null;
    showIdentity();
    say("persist-out", "The identity was deleted.");
  });
  $("publish").addEventListener("click", onPublish);
  $("cancel").addEventListener("click", () => mining?.abort());
  $("republish").addEventListener("click", onRepublish);
  $("list").addEventListener("click", onList);
  $("browse-cancel").addEventListener("click", () => browsing?.abort());
  $("ancestors").addEventListener("click", onAncestors);
  $("local").addEventListener("click", onLocal);
  $("clear-fetched").addEventListener("click", async () => {
    await store.clearFetched();
    say("list-out", "Fetched blocks cleared; keys and own blocks kept.");
  });
}

main();
