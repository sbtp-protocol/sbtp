// Node.js entry point of @sbtp/wasm (the "node" condition of package.json "exports").
//
// The browser and bundler entry, sbtp_wasm.js, loads the module with `fetch(new URL(...))`, which
// Node.js does not do for a file: URL. This entry reads the module from the package directory and
// instantiates it synchronously when it is imported, so the self-test (ADR 0003 rule 16) runs before
// any export is used. Every export of sbtp_wasm.js is re-exported unchanged; the default export
// (init) and initSync return at once, since the module is already instantiated.
import { readFileSync } from "node:fs";
import { initSync } from "./sbtp_wasm.js";

initSync({ module: readFileSync(new URL("./sbtp_wasm_bg.wasm", import.meta.url)) });

export * from "./sbtp_wasm.js";
export { default } from "./sbtp_wasm.js";
