// The user's identity: a Web Crypto Ed25519 key pair whose private key is NON-EXTRACTABLE, kept in
// IndexedDB as a structured clone of the CryptoKey. The secret never enters script-readable
// memory: no seed, no JWK, no export. sbtp-wasm's DemoSigningKey and exportSeed are not used.
// Signing goes through the external signature path: signingMessageBytes (SIG_PREFIX ‖ block_id, always
// domain-separated) → crypto.subtle.sign → attachSignature, which verifies strictly in sbtp-core.
// Threat model: web/README.md, "Key storage".

import { tx } from "./idb.js";
import { attachSignature, buildUnsignedBlock, signingMessageBytes } from "./wasm.js";

const SLOT = "identity";

export class KeyUnsupported extends Error {
  constructor(cause) {
    super("this browser has no Web Crypto Ed25519 (needs Chrome 137+, Firefox 129+ or Safari 17+); " +
      "the client does not fall back to a key held in page memory");
    this.name = "KeyUnsupported";
    this.cause = cause;
  }
}

/**
 * Proves the key pair works end to end: a test block signed with the private key passes
 * sbtp-core's strict verification under the public key. Run after generation and after loading.
 */
async function selfCheck(privateKey, publicKey) {
  const block = buildUnsignedBlock(publicKey, 0n, 0n, new Uint8Array(0), new Uint8Array(0));
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, signingMessageBytes(block)));
  attachSignature(block, sig); // throws InvalidSignature on a mismatch
}

function checkPrivate(key) {
  if (!(key instanceof CryptoKey) || key.type !== "private" || key.algorithm.name !== "Ed25519" ||
      key.extractable !== false || !key.usages.includes("sign")) {
    throw new Error("the stored identity is not a non-extractable Ed25519 signing key");
  }
}

/** The stored identity `{ privateKey, publicKey, created }`, or null when there is none. */
export async function loadIdentity(db) {
  const rec = await tx(db, ["keys"], "readonly", (s) => s.keys.get(SLOT));
  if (!rec) return null;
  checkPrivate(rec.privateKey);
  await selfCheck(rec.privateKey, rec.publicKey);
  return rec;
}

/** Generates and stores a new identity. Replaces nothing: delete the old one first. */
export async function createIdentity(db) {
  let pair;
  try {
    pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  } catch (e) {
    throw new KeyUnsupported(e);
  }
  checkPrivate(pair.privateKey);
  // Public keys are always exportable; the private key is not (extractable: false above).
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  await selfCheck(pair.privateKey, publicKey);
  const rec = { name: SLOT, privateKey: pair.privateKey, publicKey, created: Date.now() };
  await tx(db, ["keys"], "readwrite", async (s) => {
    if (await s.keys.get(SLOT)) throw new Error("an identity already exists");
    await s.keys.put(rec);
  });
  return rec;
}

/** Deletes the identity. It cannot be recovered: the key was never exportable. */
export function deleteIdentity(db) {
  return tx(db, ["keys"], "readwrite", (s) => s.keys.delete(SLOT));
}

/** Signs a mined block (spec §3.2) and returns the signed, verified copy. */
export async function signBlock(identity, block) {
  const message = signingMessageBytes(block);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, message));
  return attachSignature(block, sig);
}
