// Hexadecimal helpers. A block_id on the relay interface is exactly 64 lowercase hex characters.

const ID_RE = /^[0-9a-f]{64}$/;

export const isIdHex = (text) => typeof text === "string" && ID_RE.test(text);

export function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Bytes of an even-length lowercase or uppercase hex string; throws on anything else. */
export function fromHex(text) {
  if (typeof text !== "string" || text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new TypeError("expected an even number of hexadecimal characters");
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}
