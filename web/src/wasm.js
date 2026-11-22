// Loads sbtp-wasm and exposes it to the rest of the client. All protocol logic (decoding,
// block_id, PoW, strict Ed25519 verification) stays in sbtp-core: nothing here reimplements it.
//
// - Self-test: instantiation runs the S + L vector (ADR 0003 rule 16) in the module start function
//   and rejects on a bad build; `selfTest()` is replayed once more after load.
// - BlockInfo (security review I-3): it lives in WASM memory, which never shrinks. No BlockInfo
//   leaves this module: results are copied into plain frozen JS objects and freed at once.
// - Trap (I-5): a WebAssembly.RuntimeError (out of memory, a js-sys length assertion), or a foreign
//   JS exception unwinding through WASM frames, may leave the instance half-updated (allocator,
//   borrow flags; see `guard`). The instance is then poisoned: every later
//   call throws `WasmPoisoned`, and the page asks for a reload. Workers are terminated and
//   respawned instead (miner.js). A JS module instance cannot be re-instantiated in place.

import init, * as raw from "../pkg/sbtp_wasm.js";
import { toHex, fromHex } from "./hex.js";

let poisoned = null;

export class WasmPoisoned extends Error {
  constructor(cause) {
    super("the WebAssembly module trapped and is no longer used; reload the page");
    this.name = "WasmPoisoned";
    this.cause = cause;
  }
}

/**
 * Binding errors are plain `Error`s built by the module (name = spec rule or argument error).
 * Anything else is a trap (`WebAssembly.RuntimeError`) or a foreign JS exception that unwound
 * through WASM frames without running Rust destructors (for example a RangeError from a typed
 * array with a lying `length`, review I-1 and L-2): both poison the instance.
 */
export function guard(fn) {
  return (...args) => {
    if (poisoned) throw new WasmPoisoned(poisoned);
    try {
      return fn(...args);
    } catch (e) {
      if (e instanceof Error && e.constructor === Error) throw e;
      poisoned = e;
      throw new WasmPoisoned(e);
    }
  };
}

export const isPoisoned = () => poisoned !== null;

/**
 * Instantiates the module. `source`: omitted in a browser (fetches ../pkg/sbtp_wasm_bg.wasm),
 * or the module bytes / a WebAssembly.Module (Node tests).
 */
export async function loadSbtp(source) {
  await init(source === undefined ? undefined : { module_or_path: source });
  guard(raw.selfTest)();
}

/** Copies a BlockInfo into a plain object and frees it (I-3). */
function plain(info) {
  try {
    const parents = [];
    for (let i = 0; i < info.parentCount; i += 1) parents.push(toHex(info.parent(i)));
    return Object.freeze({
      idHex: info.blockIdHex,
      version: info.version,
      timestamp: info.timestamp,
      nonce: info.nonce,
      publicKeyHex: toHex(info.publicKey),
      parents: Object.freeze(parents),
      payload: info.payload,
      leadingZeroBits: info.leadingZeroBits,
    });
  } finally {
    info.free();
  }
}

// Only calls into the module are guarded: arguments are converted in plain JS before, so that a
// caller's bad argument (a TypeError from fromHex) cannot poison the instance.
const validateRequested = guard((bytes, difficulty, id) => plain(raw.validateRequested(bytes, difficulty, id)));

/** Receipt rule (spec §3.4): F1-F9, R1, C1 at the client's own difficulty, C2, C3. */
export const verifyFetched = (bytes, difficulty, idHex) => validateRequested(bytes, difficulty, fromHex(idHex));

/** Full validation of a block without an expected id (own blocks, before storing). */
export const verifySubmitted = guard((bytes, difficulty) => plain(raw.validateSubmitted(bytes, difficulty)));

export const buildUnsignedBlock = guard(raw.buildUnsignedBlock);
export const mineSlice = guard(raw.mineSlice);
/**
 * The 49 bytes to sign for a mined block (SIG_PREFIX ‖ block_id), read out of the SigningMessage
 * sbtp-wasm builds (ADR 0055 E1: the signer only receives builder output) and freed at once.
 */
export const signingMessageBytes = guard((block) => {
  const message = raw.signingMessage(block);
  try {
    return message.bytes;
  } finally {
    message.free();
  }
});
/** Inserts an external signature; sbtp-core verifies it (C2, C3, strict) before returning. */
export const attachSignature = guard(raw.attachSignature);
const rawBlockId = guard(raw.blockId);
export const blockIdHex = (bytes) => toHex(rawBlockId(bytes));

/** The Nonce field of a well-formed block (format only); used to count mining attempts. */
export const nonceOf = guard((bytes) => {
  const info = raw.parseBlock(bytes);
  try {
    return info.nonce;
  } finally {
    info.free();
  }
});
