// Compile-time check of the init API of @sbtp/wasm for a Node.js-only program (no "dom" lib).
// Never run, only type-checked: see README.md in this directory.
import { initSync, type InitOutput } from "@sbtp/wasm";

declare const bytes: Uint8Array;

const out: InitOutput = initSync({ module: bytes });
const size: number = out.memory.buffer.byteLength;
void size;
