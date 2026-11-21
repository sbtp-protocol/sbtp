// A minimal in-memory IndexedDB double for the `tx` helper of src/idb.js: object stores with a key
// path, requests that succeed on a later macrotask, and a transaction that commits (copy-on-write)
// once no request is pending, or rolls back on abort. Enough for BlockStore; not a full IndexedDB.

const KEY_PATHS = { keys: "name", blockMeta: "id", blockBytes: "id", stats: "name" };

export function fakeDb() {
  const data = new Map(Object.keys(KEY_PATHS).map((n) => [n, new Map()]));
  return {
    data,
    transaction(names, mode) {
      const work = new Map(names.map((n) => [n, new Map([...data.get(n)].map(([k, v]) => [k, structuredClone(v)]))]));
      let pending = 0;
      let finished = false;
      const t = {
        error: null,
        oncomplete: null,
        onerror: null,
        onabort: null,
        abort() {
          if (finished) return;
          finished = true;
          setImmediate(() => t.onabort?.());
        },
        objectStore(name) {
          const m = work.get(name);
          const kp = KEY_PATHS[name];
          const op = (fn) => {
            if (finished) throw new Error("TransactionInactiveError");
            if (mode !== "readwrite" && fn.write) throw new Error("ReadOnlyError");
            pending += 1;
            const req = { result: undefined, onsuccess: null, onerror: null };
            setImmediate(() => {
              pending -= 1;
              if (finished) return;
              req.result = fn();
              req.onsuccess?.();
              setImmediate(check);
            });
            return req;
          };
          const w = (fn) => Object.assign(fn, { write: true });
          return {
            get: (k) => op(() => structuredClone(m.get(k))),
            getAll: () => op(() => [...m.keys()].sort().map((k) => structuredClone(m.get(k)))),
            put: (v) => op(w(() => { m.set(v[kp], structuredClone(v)); return v[kp]; })),
            delete: (k) => op(w(() => { m.delete(k); })),
            clear: () => op(w(() => { m.clear(); })),
            count: () => op(() => m.size),
          };
        },
      };
      const check = () => {
        if (finished || pending > 0) return;
        finished = true;
        if (mode === "readwrite") for (const [n, m] of work) data.set(n, m);
        t.oncomplete?.();
      };
      setImmediate(check);
      return t;
    },
  };
}
