// Test helper (not shipped): writes ustar archives the way npm pack does (regular files, mode 0644,
// uid and gid 0, a fixed timestamp), so that tests can build tampered or hostile packages.
import { gzipSync } from "node:zlib";

const MTIME = 499162500; // 1985-10-26T08:15:00Z, npm pack's fixed timestamp

function octal(value, width) {
  return `${value.toString(8).padStart(width - 1, "0")}\0`;
}

// One 512-byte ustar header. `type` is the typeflag ("0" regular file, "5" directory, "2" symlink).
export function header(name, size, { type = "0", mode = 0o644, linkname = "" } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write(octal(mode, 8), 100, "ascii");
  h.write(octal(0, 8), 108, "ascii");
  h.write(octal(0, 8), 116, "ascii");
  h.write(octal(size, 12), 124, "ascii");
  h.write(octal(MTIME, 12), 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write(type, 156, "ascii");
  h.write(linkname, 157, 100, "utf8");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  let sum = 0;
  for (const byte of h) sum += byte;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return h;
}

// An entry: its header, then its data padded to a multiple of 512 bytes.
export function entry(name, data, options) {
  const body = Buffer.from(data);
  const pad = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header(name, body.length, options), body, pad]);
}

// A tar stream: the entries, then two zero blocks (and `trailer`, raw bytes after them).
export function tar(entries, { trailer = Buffer.alloc(0) } = {}) {
  return Buffer.concat([...entries, Buffer.alloc(1024), trailer]);
}

// `files` is a list of [name, data] pairs, in order.
export function tgz(files, options) {
  return gzipSync(tar(files.map(([name, data]) => entry(name, data)), options), { level: 9 });
}
