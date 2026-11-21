// Minimal promise wrapper over IndexedDB. One database per origin for this client:
//   keys       { name, privateKey: CryptoKey (non-extractable), publicKey: Uint8Array, created }
//   blockMeta  { id, size, own, accessed, delivery? }   (index "accessed"; delivery: own blocks only,
//              the per-relay state of ADR 0047, see delivery.js. Records from before ADR 0047 carry
//              `acked` and `failedOn` instead; BlockStore.setRelays rewrites them, no version change)
//   blockBytes { id, bytes }
//   stats      { name: "totals", count, bytes, pending }   (running totals of blockMeta; v2)

const DB_NAME = "sbtp-web";
const DB_VERSION = 2;

export function openDb() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is not available (private window or blocked site data?)"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = req.result;
      if (event.oldVersion < 1) {
        db.createObjectStore("keys", { keyPath: "name" });
        db.createObjectStore("blockMeta", { keyPath: "id" }).createIndex("accessed", "accessed");
        db.createObjectStore("blockBytes", { keyPath: "id" });
      }
      // The totals record is absent after this upgrade: BlockStore rebuilds it on first use.
      if (event.oldVersion < 2) db.createObjectStore("stats", { keyPath: "name" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error("the database is open in an older tab; close it"));
  });
}

const done = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

/**
 * Runs `body(stores)` in one transaction over `names` and resolves with its result once the
 * transaction commits. `stores` maps each name to an object of promise-returning helpers.
 */
export function tx(db, names, mode, body) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(names, mode);
    const stores = {};
    for (const name of names) {
      const s = t.objectStore(name);
      stores[name] = {
        get: (k) => done(s.get(k)),
        getAll: () => done(s.getAll()),
        put: (v) => done(s.put(v)),
        delete: (k) => done(s.delete(k)),
        clear: () => done(s.clear()),
        count: () => done(s.count()),
      };
    }
    let result;
    Promise.resolve(body(stores)).then((r) => { result = r; }, (e) => { t.abort(); reject(e); });
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error ?? new Error("transaction aborted"));
  });
}
