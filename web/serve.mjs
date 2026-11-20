// Development server for web/: static files on loopback only, with the security headers a real
// deployment should send (the CSP below adds frame-ancestors, which a meta tag cannot carry).
// Plain Node, no dependency.   Usage: node web/serve.mjs [port]   (default 8731; 0 picks a free one)
//
// The default port is deliberately uncommon (security review 2026-11-20, L-4): IndexedDB, and so
// the identity key, belongs to the origin http://127.0.0.1:<port>. Any other dev server later run
// on the same origin (8000 is python -m http.server's default) could use or delete the key.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.argv[2] ?? 8731);

export const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'", // compile the module; never 'unsafe-eval' (review I-4)
  "worker-src 'self'",
  "connect-src 'self' https: http://127.0.0.1:* http://localhost:*",
  "style-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
};

const server = createServer(async (req, res) => {
  let path;
  try {
    // A malformed escape such as /%E0 throws URIError: answer 400, never crash (review L-3).
    path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const file = normalize(join(root, path.endsWith("/") ? `${path}index.html` : path));
  const type = TYPES[extname(file)];
  if (!file.startsWith(root) || file.includes(`${sep}tests${sep}`) || !type || req.method !== "GET") {
    res.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Security-Policy": CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
server.listen(port, "127.0.0.1", () => console.log(`http://127.0.0.1:${server.address().port}/`));
