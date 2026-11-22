// Compile-time check of the init API of @sbtp/wasm for a browser program (with the "dom" lib): the
// local aliases of the shipped .d.ts must resolve to the DOM types. Never run, only type-checked:
// see README.md in this directory.
import init from "@sbtp/wasm";

declare const response: Response;

await init({ module_or_path: response });
await init({ module_or_path: new URL("./sbtp_wasm_bg.wasm", "https://example.invalid/") });
const memory: WebAssembly.Memory = (await init()).memory;
void memory;
