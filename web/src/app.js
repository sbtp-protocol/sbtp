// UI of index.html. Every value from a relay or a block is written with textContent, never as HTML.

import { LIMITS } from "./bounds.js";
import { describeDelivery, isStranded, PARTIAL, protection, UNACKNOWLEDGED } from "./delivery.js";
import { formatTimestamp } from "./format.js";
import { fromHex, isIdHex, toHex } from "./hex.js";
import { deadline } from "./http.js";
import { openDb } from "./idb.js";
import { createIdentity, deleteIdentity, loadIdentity, signBlock } from "./keys.js";
import { mineInWorker } from "./miner.js";
import {
  fetchBlocksFrom, fetchOne, publishAll, publishDifficulty, RelaySet, retryPlan, walkAll,
} from "./relays.js";
import { announceRelays, loadRelays, onRelaysChange, RELAYS_KEY, saveRelays } from "./settings.js";
import { BlockStore } from "./store.js";
import { traverse } from "./traverse.js";
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

let relays = new RelaySet(loadRelays());

/** Shows the relay list and the health of each relay (in memory: a reload starts them healthy). */
function showRelays() {
  say("relays-health", relays.describe().join("\n"));
}

function onSaveRelays() {
  try {
    relays = new RelaySet(saveRelays($("relays").value, undefined, relays.bases));
    $("relays").value = relays.bases.join("\n");
    showRelays();
  } catch (e) {
    fail("relays-health", e);
  }
}

/**
 * The relay list changed (here or in another tab): the store reconciles the delivery states of own
 * blocks (ADR 0047 rules 6 and 7) before the stranded blocks are shown again.
 */
onRelaysChange(async (next) => {
  if (!store) return;
  await store.setRelays(next);
  await showStranded();
}, (e) => fail("stranded-out", e));

/** A change of the list saved by another tab of this origin. */
globalThis.addEventListener?.("storage", (event) => {
  if (event.key !== RELAYS_KEY) return;
  const previous = relays.bases;
  relays = new RelaySet(loadRelays());
  $("relays").value = relays.bases.join("\n");
  showRelays();
  announceRelays(relays.bases, previous);
});

/** One line per relay of a publishAll result, with the class of ADR 0047 rule 3. */
const NAMES = { created: "201 created", stored: "200 already stored", "backing-off": "not sent (backing off)" };
const CLASSES = { transient: "will be sent again", final: "refused for good", none: "not an attempt" };
const perRelay = (results) => results.map((r) =>
  `  ${r.base}: ${NAMES[r.outcome] ?? `failed, ${CLASSES[r.delivery] ?? r.delivery}`}` +
  `${r.error ? ` (${r.error.name}: ${r.error.message})` : ""}`).join("\n");

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

/** PUTs an own block to `targets` in parallel and records which relays acknowledged it. */
async function publishTo(targets, id, bytes, signal) {
  const res = await publishAll(relays, bytes, { targets, signal });
  await store.recordPublish(id, res.results);
  return res;
}

async function onPublish() {
  if (!identity) return say("publish-out", "Generate a key first.", "bad");
  const controller = new AbortController();
  mining = controller;
  $("cancel").disabled = false;
  $("publish").disabled = true;
  try {
    const parentIds = $("parents").value.split(/\s+/).filter(Boolean);
    if (!parentIds.every(isIdHex)) throw new Error("a parent is not a 64-character lowercase hex id");
    const parents = fromHex(parentIds.join(""));
    const payload = new TextEncoder().encode($("payload").value);
    const typed = $("difficulty").value.trim();
    const explicit = typed === "" ? null : Number(typed);
    // An explicit difficulty needs no /info (review finding 10). Otherwise one mining at the
    // highest /info difficulty of the relays, each bounded by maxInfoDifficulty (ADR 0029 rule 13),
    // and at least the network difficulty (ADR 0045 rule 5).
    const plan = await publishDifficulty(relays, explicit, { signal: controller.signal });
    const d = plan.difficulty;
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
    const res = await publishTo(plan.targets, b.idHex, signed, controller.signal);
    const skipped = plan.skipped.map((x) => `  ${x.base}: skipped, ${x.reason}`).join("\n");
    const head = res.acked.length > 0
      ? `Published ${b.idHex} on ${res.acked.length} of ${relays.bases.length} relay(s); mined in ${ms} ms at difficulty ${d}.`
      : `${b.idHex} was mined in ${ms} ms but no relay acknowledged it: it is kept as pending.`;
    const retry = res.results.some((r) => r.delivery === "transient" || r.delivery === "none")
      ? "\n\"Publish pending blocks\" sends it again to the relays still pending." : "";
    say("publish-out", `${head}\n${perRelay(res.results)}${skipped ? `\n${skipped}` : ""}${retry}`,
      res.acked.length > 0 && res.failed.length === 0 ? "ok" : "bad");
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
    showRelays();
    showStranded();
  }
}

/**
 * Sends own blocks again (ADR 0047): those no relay of the list acknowledged, to every relay that
 * did not refuse them for good; partly delivered ones, to the relays still pending (relays.js
 * retryPlan, at most storeMaxPending blocks per run). Stops when every relay is backing off.
 */
async function onRepublish() {
  if (republishing) return;
  republishing = true;
  $("republish").disabled = true;
  let done = 0;
  let incomplete = 0;
  let plan = [];
  let stopped = null;
  let last = null;
  try {
    plan = retryPlan(await store.list(), relays.bases);
    for (const { id, targets } of plan) {
      if (relays.available().length === 0) {
        stopped = new Error("every relay is backing off");
        break;
      }
      try {
        const bytes = await store.get(id);
        verifySubmitted(bytes, 0);
        const res = await publishTo(targets, id, bytes);
        if (res.results.every((r) => r.delivery === "acknowledged" || r.delivery === "final")) done += 1;
        else {
          incomplete += 1;
          last = res.results.find((r) => r.error)?.error ?? last;
        }
      } catch (e) {
        incomplete += 1;
        last = e;
      }
    }
  } catch (e) {
    stopped = e;
  } finally {
    republishing = false;
    $("republish").disabled = false;
    showRelays();
    showStranded();
  }
  const why = stopped ?? last;
  say("publish-out", `${plan.length} own block(s) to send: ${done} answered for good by every relay asked, ` +
    `${incomplete} still pending on some relay${stopped ? "; stopped" : ""}` +
    `${why ? ` (${why.name}: ${why.message})` : ""}.`, why ? "bad" : "ok");
}

function onList() {
  return browse(async (signal) => {
    const parent = $("parent-filter").value.trim();
    if (parent && !isIdHex(parent)) throw new Error("the filter is not a 64-character lowercase hex id");
    say("list-out", `Walking /query on ${relays.bases.length} relay(s)…`);
    // The view fetches at most fetchMaxBlocks blocks: walking further would be wasted (review L-2).
    // Each relay is walked with its own cursor; the ids are merged and deduplicated.
    const w = await walkAll(relays, parent ? { parent } : {}, {
      signal, perRelayMaxIds: LIMITS.fetchMaxBlocks, maxTotalIds: LIMITS.fetchMaxBlocks,
    });
    // Every block is validated (R1 and full validation) whatever relay serves it.
    const got = await fetchBlocksFrom(relays, w.ids,
      (bytes, id) => ({ b: verifyFetched(bytes, LIMITS.receiptDifficulty, id), bytes }), { signal });
    for (const { b, bytes } of got.blocks) {
      await store.put(b.idHex, bytes).catch(() => {}); // a full store only means it is not cached
      renderBlock(b);
    }
    const partial = w.partial || got.partial;
    const walks = w.runs.map((x) => `${x.base}: ${x.ids.length} id(s), ${x.stop}${x.error ? ` (${x.error.message})` : ""}`)
      .concat(w.backingOff.map((b) => `${b}: not asked, backing off`)).join("; ");
    say("list-out", `${w.ids.length} distinct id(s) listed [${walks}]; ` +
      `${got.blocks.length} fetched and verified, ${got.notFound.length} not found, ${got.failed.length} failed` +
      `${partial ? ". Partial view: a bound or a failure stopped it." : "."}`, partial ? "bad" : "ok");
  });
}

function onAncestors() {
  return browse(async (signal) => {
    const start = $("parent-filter").value.trim();
    if (!isIdHex(start)) throw new Error("enter a block id in the field above");
    say("list-out", "Walking ancestors…");
    const budget = { left: LIMITS.fetchMaxAttempts };
    const t = await traverse(start, async (id) => {
      let b;
      try {
        const local = await store.get(id);
        if (local !== null) {
          b = await receive(local, id);
        } else {
          // Failover over the relays; each answer is validated (§3.4) before it is used or stored.
          const r = await fetchOne(relays, id,
            (bytes, i) => ({ b: verifyFetched(bytes, LIMITS.receiptDifficulty, i), bytes }), { budget, signal });
          if (r.status !== "ok") return null;
          b = r.block.b;
          await store.put(id, r.block.bytes).catch(() => {}); // a full store only means it is not cached
        }
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

/** How far an own block is delivered (ADR 0047 rule 2), for the list of local blocks. */
function ownNote(m) {
  if (!m.own) return "fetched";
  const now = Date.now();
  if (isStranded(m, relays.bases, now)) return "own, UNDELIVERABLE (see above)";
  const p = protection(m, relays.bases, now);
  if (p === UNACKNOWLEDGED) return "own, PENDING: no relay acknowledged it";
  if (p === PARTIAL) return "own, partly delivered: kept until every relay has it";
  return "own, delivered";
}

/** Saves the bytes of one block as a file (the user keeps it; any client can publish it). */
function exportBlock(id, bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${id}.sbtp`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Own blocks that no relay of the list holds and that no relay is pending for: every relay refused
 * them or was given up (ADR 0047 rule 9). Nothing automatic will deliver them.
 */
async function showStranded() {
  if (!store) return;
  const list = $("stranded");
  list.replaceChildren();
  try {
    const now = Date.now();
    const stranded = (await store.list()).filter((m) => isStranded(m, relays.bases, now));
    if (stranded.length === 0) return say("stranded-out", "None: every own block is held by a relay or still pending.", "ok");
    say("stranded-out", `${stranded.length} own block(s) that no relay of the list holds, and that every relay ` +
      "refused or was given up on. Add a relay to the list above (it becomes a target of these blocks), " +
      "export them to keep the bytes, or delete them.", "bad");
    for (const m of stranded.slice(0, 100)) {
      const div = document.createElement("div");
      div.className = "block";
      const head = document.createElement("div");
      head.className = "mono muted";
      head.textContent = `${m.id}\n${describeDelivery(m, relays.bases, now).join("\n")}`;
      const add = document.createElement("button");
      add.textContent = "Add a relay";
      add.addEventListener("click", () => $("relays").focus());
      const exp = document.createElement("button");
      exp.textContent = "Export";
      exp.addEventListener("click", async () => {
        try {
          const bytes = await store.get(m.id);
          verifySubmitted(bytes, 0);
          exportBlock(m.id, bytes);
        } catch (e) {
          fail("stranded-out", e);
        }
      });
      const del = document.createElement("button");
      del.textContent = "Delete";
      del.addEventListener("click", async () => {
        if (!confirm(`Delete own block ${m.id}? No relay of the list holds it: unless it was exported, it is lost.`)) return;
        try {
          await store.delete(m.id);
          await showStranded();
        } catch (e) {
          fail("stranded-out", e);
        }
      });
      div.append(head, add, exp, del);
      list.append(div);
    }
  } catch (e) {
    fail("stranded-out", e);
  }
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
      renderBlock(b, ownNote(m));
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
    store = new BlockStore(db, LIMITS, { bases: relays.bases });
    // Reconciles the delivery states with the list, and migrates records from before ADR 0047.
    await store.setRelays(relays.bases);
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
  $("relays").value = relays.bases.join("\n");
  showRelays();
  $("relays-save").addEventListener("click", onSaveRelays);
  $("info").addEventListener("click", async () => {
    const lines = await Promise.all(relays.entries.map(async (e) => {
      // A relay backing off is not asked: a Retry-After must elapse first.
      const wait = relays.waitMs(e);
      if (wait > 0) return `${e.base}\nnot asked: backing off for ${Math.ceil(wait / 1000)} s`;
      try {
        const info = await e.relay.info();
        relays.ok(e);
        return `${e.base}\n${JSON.stringify(info, null, 1)}`;
      } catch (err) {
        relays.fail(e, err);
        return `${e.base}\n${err.name}: ${err.message}`;
      }
    }));
    say("info-out", lines.join("\n\n"));
    showRelays();
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
  $("stranded-check").addEventListener("click", showStranded);
  showStranded();
  $("clear-fetched").addEventListener("click", async () => {
    await store.clearFetched();
    say("list-out", "Fetched blocks cleared; keys and own blocks kept.");
  });
}

main();
