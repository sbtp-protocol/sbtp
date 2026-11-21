# SBTP minimal web client

A browser client of the SBTP relay interface: generate or load an identity, mine, sign and publish a
block, list blocks with `/query`, fetch and verify them, walk ancestors, over one relay or several. Plus a proof-of-work measurement
page (`pow.html`, Q-28).

Plain ES modules and a Web Worker: **no JavaScript dependency, no bundler, no `package.json`**. Every
protocol rule (decoding, `block_id`, PoW, strict Ed25519 verification) runs in `sbtp-core` through
`sbtp-wasm`; the JavaScript here moves bytes, talks HTTP and stores things.

## Build and run

Tools: Rust with the `wasm32-unknown-unknown` target, the `wasm-bindgen` CLI of the same version as the
`wasm-bindgen` crate in `Cargo.lock` (0.2.130; the script refuses a mismatch), binaryen's `wasm-opt`,
Node 22 for the dev server and the tests.

```bash
web/build.sh                       # cargo build --release, wasm-bindgen --target web, wasm-opt -Os → web/pkg/
cargo run -p sbtp-relay            # a local relay on http://127.0.0.1:8080 (plain HTTP, loopback)
node web/serve.mjs                 # http://127.0.0.1:8731/ (static files, loopback only, security headers)
```

Open `http://127.0.0.1:8731/` for the client, `http://127.0.0.1:8731/pow.html` for the measurement.
The port is deliberately uncommon: the identity key lives in this origin's IndexedDB, and any other dev
server run later on the same origin (`127.0.0.1:8000` is the default of `python -m http.server` and many
tools) would serve scripts that can use or delete the key. Do not reuse this origin for another project;
a public deployment uses its own host name.
`web/pkg/` is a build output and is not committed. Optimised module (2026-11-21, layer 2 grammar and
sealed envelope included): 237,091 bytes, 119,069 bytes with `gzip -9`; JS glue 43,069 bytes. Layer 0
only (`--no-default-features`): 139,170 and 78,512 bytes (`crates/sbtp-wasm/README.md`).

Any static server works if it serves `.wasm` as `application/wasm` and `.js` as `text/javascript`;
`serve.mjs` also sends the headers below.

## Tests

```bash
node --test web/tests/*.test.mjs                                   # pure modules + sbtp-wasm in Node
SBTP_RELAY=http://127.0.0.1:8080 node --test web/tests/*.test.mjs  # adds the end-to-end test
```

The tests cover the response checks, the four body ceilings (at the ceiling and one byte above, gzip
included), the deadline against a drip-fed body, redirects not followed (ADR 0030: 301, 307, 308, 303 on PUT, opaque redirect), the `/query` walk against scripted
hostile relays, fetch and traversal bounds (a diamond DAG of depth 40), the eviction plan, a Web Crypto
signature through `attachSignature`, the poisoning of the module after a foreign exception, and several
relays (`relays.test.mjs`: fake relays over loopback HTTP, one healthy, one answering 404, one hostile
serving a wrong block, one slow past the deadline, one answering 429 with `Retry-After`), and the
delivery state of own blocks (`delivery.test.mjs`, ADR 0047: each classification of a `PUT` answer, the
attempt and time bounds with an injected clock, relay removal and addition, the eviction order, the
migration of older records). IndexedDB and the Worker are not available in Node: the store is tested
over an in-memory double (`tests/fake-idb.mjs`), and both were checked in headless Chrome before
ADR 0047.

## Layout

| File | Does |
|---|---|
| `src/wasm.js` | Loads `pkg/`, self-test, plain-object results, poisoning after a trap |
| `src/keys.js` | Identity: non-extractable Web Crypto Ed25519 key in IndexedDB, signing |
| `src/store.js`, `src/eviction.js`, `src/idb.js` | Local block store and its budget |
| `src/delivery.js` | Per-relay delivery state of own blocks, protection and bounds (ADR 0047) |
| `src/http.js` | The only `fetch()` call: redirect policy, deadline, bounded body read |
| `src/relay.js` | `/info`, `PUT`/`GET /block`, `/query`, `POST /blocks` (ADR 0051), response checks, bounded fetch |
| `src/relays.js`, `src/settings.js` | Several relays: publish to all, failover reads (single GETs or batches), merged and grouped walks, health; the saved list |
| `src/walk.js`, `src/traverse.js` | `/query` walk, grouped walk of several parents, bounded DAG traversal (per block or per level) |
| `src/view.js` | The view of a block, its refresh, the cold start of its descendants (ADR 0051) |
| `src/bounds.js` | Every client bound in one place |
| `src/mine-worker.js`, `src/miner.js` | PoW in a module Web Worker, one worker per job |
| `src/app.js`, `src/pow.js`, `src/stats.js` | The two pages |

## Key storage (threat model)

- **Choice.** The identity is a Web Crypto Ed25519 key pair generated with `extractable: false`. The
  `CryptoKey` is stored in IndexedDB by structured clone. Its secret never enters memory a script can
  read: no seed, no JWK, no `exportKey`. Signing uses the external path of `sbtp-wasm`:
  `signingMessage` (49 bytes, `SIG_PREFIX ‖ block_id`) → `crypto.subtle.sign` → `attachSignature`, which
  verifies the result strictly in `sbtp-core`. On load and after generation, a test block is signed and
  verified the same way, so a corrupted record or a browser signing differently is caught at once.
- **`exportSeed` and `DemoSigningKey` are not used.** There is no fallback to a key in WASM or JS memory:
  without Web Crypto Ed25519 (Chrome 137+, Firefox 129+, Safari 17+) the client says so and does not
  offer to publish.
- **What it protects against.** Theft of the key by a script that runs in the page (XSS, a compromised
  dependency, a malicious extension reading page memory), and by anything that reads the IndexedDB files
  on disk: the browser keeps the key material out of reach of the page.
- **What it does not protect against.** A script running in the origin can still *use* the key while the
  page is open: sign any SBTP block as the user. Mitigations: a strict CSP (below), no third-party script,
  no `innerHTML` (every relay or block value is written with `textContent`), and serving the client from
  a dedicated origin (IndexedDB is per origin): the dev server's uncommon default port serves that
  purpose locally. The key is dedicated to SBTP, and SBTP signatures are
  domain-separated by `SIG_PREFIX`, so it cannot be abused for another protocol.
- **Consequences.** The identity cannot be backed up or moved to another browser; clearing site data
  deletes it. Acceptable for the demonstrator; a backup (for example a passphrase-wrapped extractable key)
  would be a separate decision with its own review. Private keys are never in `localStorage`, a URL or a
  log.
- **Eviction by the browser.** Once a key exists, the client calls `navigator.storage.persist()`. If the
  browser refuses or lacks the API, the page shows a warning: the browser may clear the site's data on its
  own (Safari's tracking prevention can after about 7 days without use; other browsers under storage
  pressure), and the identity would be lost with it. Chrome decides on its own heuristics (it may refuse
  for a site not installed or bookmarked); Firefox may ask the user.

## Local storage: IndexedDB, not OPFS

IndexedDB is needed anyway for the `CryptoKey` (OPFS stores bytes, not keys); it is transactional, so
the budget check and the write are atomic across tabs; it works on the main thread in every browser
(OPFS synchronous access is Worker-only); blocks are at most 65,909 bytes, a good fit for records. Two
stores: `blockMeta` (small records, read for eviction) and `blockBytes`.

Budget (ADR 0029 rule 12, ADR 0047 rule 8): 5,000 blocks and 64 MiB. Fetched blocks are evicted first
(least recently used), then own blocks that are no longer protected (least recently used), then, only to
store a new own block, partly delivered own blocks (oldest first acknowledgement first). Never keys,
never an own block no relay of the list acknowledged with `200`/`201`, and a partly delivered block never
gives way to a fetched block. At most 200 own blocks no relay acknowledged: beyond that, creating a block
is refused. Only validated blocks are stored, and they are validated again when read back.

### Delivery of own blocks (ADR 0047)

Code: `src/delivery.js` (pure functions), persisted by `src/store.js`. Each own block keeps, per relay of
the list, a state: `pending`, `acknowledged`, `refused` or `given up`, with the attempt count and first
attempt time of a pending relay and the time of each acknowledgement.

- **Protected** while no relay of the list acknowledged it, or while one did and another is still
  pending.
- **A `PUT` answer.** `201`/`200`: acknowledged. Transient (stays pending, counts as an attempt): no
  response, a timeout or another failed request, `408`, `429`, `5xx` (`507` included),
  `400 TimestampTooFarInFuture`. Final (refused): any other `400` (`InsufficientPow` included, or no
  parseable error name), `413`, `422`, a `3xx`, any other `4xx`. A request not sent (the relay backing
  off, or a cancelled operation) is not an attempt.
- **Bounds** (`bounds.js`): a pending relay is given up after at least 5 attempts and at least 24 hours
  since the first, and in any case 7 days after the block's first acknowledgement. A block no relay
  acknowledged keeps its protection; its given-up relays are still tried, its refused ones are not.
- **Relay list changes** (`settings.js` `onRelaysChange`, also on start and on a change made in another
  tab): a removed relay's states are deleted, so a block only it held is protected again and sent to
  the others; an added relay becomes pending only for the blocks protected at that moment, without
  resetting the 7-day bound.
- **Undeliverable own blocks.** A block no relay of the list holds and that every relay refused or was
  given up on is listed in its own section, with "Add a relay", "Export" (the block's bytes as a file)
  and "Delete".
- **Records from before ADR 0047** (`acked`, `failedOn`) are read through the ADR's mapping (pending on
  the relays of `failedOn`, or on every relay when not acknowledged; acknowledged on the others, at the
  migration time) and rewritten in the new form on the first start. No IndexedDB version change.

## Relay access (ADR 0029, spec §4 "Client bounds")

| Rule | Here |
|---|---|
| 4-6 body ceilings | `http.js` `readLimited`: decoded bytes, BYOB reader stops at ceiling + 1 (default reader: one chunk more at most); error body above 16,384 → unparseable |
| 7 deadline | `AbortSignal.timeout(30 s)` covering head and body |
| 8 `/query` checks | `parsePage` |
| 9 walk bound | 10,000 ids per walk, 16 pages in a row without news, 3 `InvalidCursor` restarts; a cut page keeps the previous cursor |
| 10 fetch bound | 200 blocks per operation, 4 in flight, `404` counted |
| 11 traversal | breadth first, visited set, 1,000 blocks, no recursion |
| 13 `/info` | `parseInfo`; a difficulty read from `/info` above 24 is refused (an explicit one is not); receipt difficulty is local (0, ADR 0026) |
| 14 `Retry-After` | seconds only; above 300 s the operation gives up on that relay; a date backs off from 1 s |

**Redirects (ADR 0030).** Every relay request uses `redirect: "manual"` (`REDIRECT_MODE` in
`src/http.js`). An opaque-redirect response (browser) or any `3xx` status (Node) is a `redirect` error:
"the relay URL redirects", a failed request whose body and `Location` are not used, never retried by a
walk, shown to the user. Also fixed there: `credentials: "omit"`, `referrerPolicy: "no-referrer"`, `cache: "no-store"`. Plain `http://`
relays are accepted on loopback only.

## Content Security Policy (review I-4)

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self';
connect-src 'self' https: http://127.0.0.1:* http://localhost:*; style-src 'self'; img-src 'self';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

`'wasm-unsafe-eval'` compiles the module; `'unsafe-eval'` and inline scripts are not allowed. The pages
carry it as a meta tag (without `frame-ancestors`, which a meta tag cannot set); a deployment should send
it as a header on every response, workers included, as `serve.mjs` does. Checked in headless Chrome: the
module loads, an inline script, a foreign script and a plain-HTTP connection to a non-loopback host are
blocked.

## WASM memory and traps (reviews I-3, I-5)

- `BlockInfo` objects never leave `src/wasm.js`: each is copied into a frozen plain object and freed at
  once, so WASM memory does not grow with the blocks shown.
- A `WebAssembly.RuntimeError` (trap), or any exception other than the module's own `Error`s unwinding
  through WASM frames (Rust destructors skipped), **poisons** the instance: every later call throws
  `WasmPoisoned` and the page must be reloaded. A JS module cannot be re-instantiated in place. Mining
  workers are terminated after each job, so the next job gets a fresh instance.

## Several relays

The relay list (one URL per line, at most 8) is a local setting kept in `localStorage`: it holds no
secret. Each URL is checked again on load (`https://`, or `http://` on loopback only); a bad saved list
falls back to `http://127.0.0.1:8080`. Code: `src/relays.js`.

- **Publish.** The block is mined once, at the highest `min_pow_difficulty` among the relays' `/info`,
  each bounded by 24 as for one relay (ADR 0029 rule 13). A relay asking for more is skipped (no mining
  for it, no `PUT`); a relay whose `/info` fails stays a target but sets no difficulty. An explicit
  difficulty reads no `/info`. The block is then sent to every target in parallel and the page shows
  each relay's answer (`201`, `200`, or the error). It counts as published from the first `200` or
  `201`, but it stays protected locally until every relay of the list acknowledged it, refused it for
  good or was given up (ADR 0047, "Delivery of own blocks" above). "Publish pending blocks" sends the
  blocks no relay acknowledged to every relay that did not refuse them, then the partly delivered ones
  to their pending relays (at most 200 blocks per run).
- **Read.** A block is asked from the relays in order; a `404`, a failed request, a transient refusal or
  a block that fails `validateRequested` (R1 and full validation) moves on to the next relay. No relay is
  trusted: every block is validated whatever relay served it, and an invalid one is never stored. A block
  below the client's own floor is refused at once (its proof of work is a property of its `block_id`).
- **`/query`.** Each relay is walked with its own cursor (ADR 0012, ADR 0024), in parallel; the ids are
  merged round-robin across the relays (so one relay cannot fill the view) and deduplicated by
  `block_id`. A relay whose ids were cut by the overall bound keeps its starting cursor.
- **Read API (ADR 0051).** Used only with a relay whose `/info` says `read_api: 2`, read once per relay
  and kept in memory (forgotten if the relay then refuses a form it announced); every other relay gets
  exactly the requests above. With it:
  - *Batch fetch*: `POST /sbtp/v1/blocks`, up to 256 ids packed under 1 MiB (from the `lens` of
    `fields=parents` when known). Each record is validated against the id at its position (R1 and
    full validation); `length = 0` or an invalid record sends that id to the next relay; a prefix
    answer gets the rest asked again; a record above 65,909 bytes, a body over 1 MiB or an error is a
    failed request (the ids go to the next relay); after a truncated body the complete records are
    kept. A batch of N ids counts N in the 800-request bound of an operation. Single GETs (the
    cacheable form) stay the rule for up to 32 blocks of a view; batches above that and for walks.
  - *View* (List with a block id): the 25 newest children (`order=desc`, one page, `head` kept), then
    in parallel their blocks and a grouped `/query` of their children (32 parents per request, a cursor
    per parent, `more` as the completeness signal), then the replies. An item's replies are shown as
    complete only when every relay asked gave a complete listing (rule 29). *Refresh the view* polls
    the root and every shown item `asc` from `head` (a listing cut by a bound continues from its own
    cursor) in one grouped request per 32 parents, and fetches only what is new.
  - *Descendants* (cold start): one relay-wide walk with `fields=parents`, the descendants found from
    the parent ids alone (other blocks are never fetched), then batches. Without the read API: a
    bounded traversal over per-parent walks.
  - *List* without a block id lists newest first; *Ancestors* fetches one level at a time.
- **Bounds.** Per relay, every bound of the table below; overall: 8 relays, 200 ids merged in a view,
  4 `GET /block` in flight in all, 800 `GET /block` per operation, failovers included.
- **Health (in memory).** A failed request, a transient refusal or an invalid block counts as a relay
  fault (ADR 0029 rule 16); a `404` or a refused `PUT` does not. From 3 faults in a row the relay is left
  aside for an exponential back-off (1 s doubling, capped at 5 minutes, with jitter) and is not asked
  meanwhile. A `Retry-After` in seconds always holds the relay back that long, even when a success
  that was already in flight arrives after it, and it is checked again before each `GET`. A reload
  starts every relay healthy. The page shows each relay's state under the list.

## Proof-of-work measurement (Q-28)

`pow.html` mines independent blocks in a Worker at d = 16, 18, 20 and 22 (50, 30, 20, 10 runs by default)
and shows median, p95, min, max and hash rate, plus a JSON result to copy. `pow.html?auto=1` starts at
once. Keep the screen on and the tab in the foreground: browsers throttle background tabs.
