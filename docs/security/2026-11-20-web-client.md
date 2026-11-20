# Security review: minimal web client (`web/`, combined pass)

- Date: 2026-11-20.
- Scope: branch `feat/web-client` at `097bc9e` (2 commits), read as `git diff main...feat/web-client`
  (`main` at `1c32150`; 28 files, +2,144, all under `web/`): `index.html`, `pow.html`, `serve.mjs`,
  `build.sh`, `src/*.js`, `tests/*.test.mjs`, `README.md`. No Rust, manifest or lockfile change, and
  no JavaScript dependency (no `package.json`): no new supply-chain surface beyond the build tools.
- References: spec `sbtp-core-v0.2.md` §2.2, §3.2 to §3.4, §4 ("Admission control", "Redirects",
  "Client bounds"); ADR 0026, ADR 0029 rules 4 to 17, ADR 0030; the previous review
  `2026-11-19-wasm-bindings.md` (items I-2 to I-5). The author's conclusions were not used.
- Method: reading of every file of the diff and of the `sbtp-wasm` argument conversions it relies on
  (`block_in`, `difficulty_in`, `u64_in`, `exact_into`, `attach_signature`). In a temporary detached
  worktree (removed afterwards): `web/build.sh` (wasm-bindgen CLI 0.2.130 found and matched, module
  141,124 bytes, identical to the README figure), `node --test web/tests/*.test.mjs` with Node 22.23:
  26 pass, 0 fail, 1 skipped (end-to-end test, needs `SBTP_RELAY`). `serve.mjs` was started on
  loopback and probed with `curl` (traversal and malformed URLs). No repository file outside this
  report was modified.

## Verdict

**Mergeable.** No blocking, high or medium finding. The design choices that carry the risk are right:
a non-extractable Web Crypto Ed25519 key, signing only `signingMessage` output, every relay and
local block validated by `sbtp-core` before use, no `innerHTML`, a strict CSP with no inline script,
one `fetch()` call site with the ADR 0029 and ADR 0030 settings. The four low findings are
availability issues (a far-future timestamp aborting a view, unbounded wall time of a walk against a
hostile relay, a one-request crash of the dev server, the shared-origin risk of the default dev
port). None lets a relay or a third party read or misuse the key, inject markup, or get an
unvalidated block displayed or stored. They can be fixed in this branch (each is a few lines) or put
in the roadmap.

What holds:

- **Key generation and storage** (`src/keys.js`). `crypto.subtle.generateKey({name: "Ed25519"},
  false, ["sign", "verify"])`: the private `CryptoKey` is non-extractable, kept in IndexedDB by
  structured clone, never exported, never in `localStorage`, a URL or a log. `checkPrivate`
  (`keys.js:32`) refuses a stored record that is not a private, non-extractable Ed25519 key with
  `sign`. `selfCheck` signs a throwaway block and passes it through `attachSignature`, which verifies
  strictly under the **stored** public key, so a record whose public key does not match its private
  key is refused on load. The self-check block is never stored or sent. No fallback to
  `DemoSigningKey`/`exportSeed` when Web Crypto Ed25519 is missing (`KeyUnsupported`). Creation runs
  the "already exists" check and the write in one transaction (no double identity across tabs).
- **Signing** goes only through `signingMessage` (always `SIG_PREFIX ‖ block_id`, 49 bytes, computed
  in `sbtp-core`), then `attachSignature`, then `verifySubmitted` at the sending difficulty before
  storing or sending. This closes previous review I-2: the key is dedicated to SBTP and never signs a
  caller-chosen message. Nothing from a relay can trigger a signature: signing happens only on the
  user's "Mine, sign and publish" click, over the textarea payload and user-typed parents checked by
  `isIdHex`.
- **Validation before use.** Every block from a relay goes through `verifyFetched` (§3.4: F1-F9, R1,
  C1 at the local receipt difficulty 0, C2, C3) before it is stored or rendered: `onList` via the
  `fetchBlocks` callback (`app.js:150`), `onAncestors` via `receive` (`app.js:171-178`, failures return
  `null` and are never stored). Local blocks are revalidated on read (`onLocal` `app.js:197`,
  `onRepublish` `app.js:132`, `onAncestors`). Parents used by the traversal come from validated blocks
  only. The receipt difficulty is a local constant, never `/info` (ADR 0026).
- **DOM.** Every relay- or block-derived value is written with `textContent` (`say`, `renderBlock`);
  no `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or URL built from relay data. Relay
  error names are cut to 64 characters; `/info` is shown only as the frozen object of checked members.
- **ADR 0029.** Checked rule by rule:
  - Rules 4 to 6: `readLimited` counts the bytes the stream yields, which `fetch()` has already
    decoded (gzip bomb test); BYOB reads stop at exactly ceiling + 1, the default reader at one chunk
    more; a 2xx above the ceiling is a `body-too-large` failure; an error body above 16,384 becomes
    `null` (unparseable) and the status still decides. PUT success bodies are cancelled unread.
  - Rule 7: one `AbortSignal.timeout(30 s)` passed to `fetch()`, which also aborts the body stream;
    the body is read inside the same `try` (drip-feed test).
  - Rule 8: `parsePage` checks shape, count against the `limit` sent (100 when none), lowercase
    64-hex identifiers and cursor syntax; nothing from a failed page is used; duplicates deduplicated.
  - Rule 9: 10,000 identifiers per walk, a page cut by the bound keeps the previous cursor, idle-page
    guard (16, widened after a restart by `seen.size / pageSize`), `InvalidCursor` restarts capped at
    3 and counted in the same walk.
  - Rule 10: 200 fetched blocks per operation, `404` counted, at most 4 in flight (`min(…, 8)`).
  - Rule 11: breadth-first queue, visited set (`known`), 1,000 blocks, no recursion; the queue never
    grows past the bound.
  - Rule 12: `planEviction` drops fetched blocks (LRU) then acknowledged own blocks; never keys (other
    object store) and never a pending own block; the read-plan-write is one IndexedDB transaction.
    Pending own blocks are capped at 200, so the overrun of the budget is bounded (about 13 MB).
  - Rule 13: `min_pow_difficulty` integer 0..256 and `max_future_ms` non-negative u64 required;
    `/info` difficulty above 24 refused, an explicit one is not; non-integer explicit values are
    refused by `difficulty_in` in `sbtp-wasm`.
  - Rule 14: `Retry-After` delay-seconds only (1 to 15 digits), obeyed exactly, the walk gives up
    above 300 s; a date backs off from 1 s, which rule 14 allows.
  - Rule 15: failed requests are retried only with back-off (3 in a row) or end the operation.
- **ADR 0030.** `redirect: "manual"` on the single `fetch()` call; `opaqueredirect` and any 3xx
  (including 304, since no conditional request is sent) become a `redirect` error whose body and
  `Location` are not read, classified as non-transient so the walk does not repeat it; the message
  says the relay URL redirects. `credentials: "omit"`, `referrerPolicy: "no-referrer"`,
  `cache: "no-store"`. Plain `http://` only to `127.0.0.1`/`localhost`.
- **WASM (previous review I-3, I-4, I-5).** I-3: no `BlockInfo` leaves `wasm.js`; `plain()` copies
  and frees in `finally`. I-4: CSP has `'wasm-unsafe-eval'` and no `'unsafe-eval'` or
  `'unsafe-inline'`. I-5: `guard` poisons the main-thread instance on anything other than the
  module's own plain `Error` (trap, or a foreign exception through WASM frames), and every later call
  throws `WasmPoisoned`; the trap test reproduces it with a lying `length`. `null`/`undefined`
  arguments (for example a missing local record) are refused inside the bindings as
  `InvalidArgument` and do not poison. Workers are one per job and terminated after it. The glue loads
  `pkg/sbtp_wasm_bg.wasm` same-origin; the start function and `selfTest()` replay the S + L vector.
- **Dev server** (`serve.mjs`): binds `127.0.0.1` only; `GET` only; extension allow-list; `tests/`
  excluded; `..%2f` traversal normalised and refused by `startsWith(root)` (root ends with a
  separator, so no sibling-prefix bypass; probed: `/..%2f..%2fCargo.toml` → 404). Headers: CSP with
  `frame-ancestors 'none'`, `nosniff`, `no-referrer`, COOP, `no-store`.
- **Build** (`build.sh`): nothing downloaded; refuses a wasm-bindgen CLI whose version differs from
  the crate in `Cargo.lock`; output in the git-ignored `web/pkg/`.

| # | Severity | Finding |
|---|---|---|
| L-1 | low | A block with a timestamp in (8.64e15, 2^53) ms throws in `renderBlock` and aborts List and Ancestors |
| L-2 | low | List has no cancel and a walk has no total time or page bound: a hostile relay can keep it running for hours |
| L-3 | low | `serve.mjs` crashes on one malformed percent-encoding (unhandled rejection) |
| L-4 | low | The default dev origin `http://127.0.0.1:8000` is shared with any other local dev server: its scripts can use or delete the key |
| I-1 to I-6 | info | See below |

## Findings

### L-1 (low): a far-future timestamp aborts the List and Ancestors views

- `web/src/app.js:59-61` (`renderBlock`), called unguarded at `app.js:153` and `app.js:179`.
- Scenario: a block whose Timestamp is, for example, 9,000,000,000,000,000 ms. It is well-formed and
  valid (§2.2: "any value of Timestamp"); only a relay's P1 refuses it on `PUT`, so it reaches the
  client from a hostile relay, or from an honest relay configured with a very large
  `max_future_ms`. `Number.isSafeInteger(ts)` is true, so `new Date(ts).toISOString()` is called and
  throws `RangeError: Invalid time value` (verified in Node 22). In `onList` the loop stops at that
  block: the blocks after it are not rendered and the status shows the `RangeError`. In
  `onAncestors` the exception escapes `visit`, `traverse` rejects and the whole traversal is lost. As
  a reply to a popular block, it breaks "List children" of that block for every user of this client
  on every attempt. In `onLocal` the same exception is caught but reported as "fails validation",
  which is wrong: the block is valid.
- Effect: availability of a view only; no injection, no stored invalid data. A hostile relay can
  already hide blocks, hence low; the third-party-author variant needs a permissive relay.
- Fix: format the date defensively, for example
  `const d = new Date(ts); Number.isNaN(d.getTime()) ? String(b.timestamp) : d.toISOString()`, and
  wrap each `renderBlock` call so one block cannot abort the loop. Add a unit test with
  `timestamp = 2^63`-like and `9e15` values.

### L-2 (low): a walk against a hostile relay has no wall-time bound and List cannot be cancelled

- `web/src/app.js:149` (`walk(r, …)` without `signal` or limits; no cancel control for List or
  Ancestors), `web/src/walk.js:44-96`, `web/src/app.js:170` (sequential `r.get` in the traversal).
- Scenario: a relay answers each `/query` page with exactly one new identifier and `more = true`,
  each after 29 s (under the deadline), or alternates `429` with `Retry-After: 300` and such pages.
  The idle guard never fires (each page brings something new), so the walk runs until the 10,000
  identifier bound: 10,000 pages × up to 30 s, plus up to 3 × 300 s per page with the `429` variant,
  that is days. The walk then fetches only the first 200 identifiers (`fetchMaxBlocks`), so 98 % of
  the bounded work is for nothing even against an honest relay (100 pages for 200 blocks). Similarly
  `onAncestors` can take 1,000 × 30 s (8 hours) with a slow relay. Each click starts another
  operation in parallel, so repeated clicks also exceed the "at most 8 in flight" SHOULD of spec §4.
- Effect: the view hangs; memory stays bounded (identifiers and 200 blocks), nothing is used from a
  failed request, and reloading the page stops it. ADR 0029 asks for bounds on pages or identifiers,
  which hold; the spending in *time* is what ADR 0029 rule 2 asks to keep a function of the client's
  settings, hence low rather than info.
- Fix: in `onList`, pass `limits: { ...LIMITS, walkMaxIds: LIMITS.fetchMaxBlocks }` (the view never
  uses more), and an `AbortSignal` with a Cancel button (reuse the `cancel` button and the `mining`
  controller pattern) and an overall operation deadline (for example 2 minutes) for List and
  Ancestors. Disable the List/Ancestors buttons while one is running.

### L-3 (low): one request crashes the dev server

- `web/serve.mjs:34`.
- Scenario: `GET /%E0`. `decodeURIComponent` throws `URIError` before the `try`; the handler is an
  `async` function, so the rejection is unhandled and Node 22 exits the process (verified: the next
  request gets no answer). Any web page the user visits can send it with `<img
  src="http://127.0.0.1:8000/%E0">` (no CORS needed; Chrome's local-network protections may block
  it, Firefox and Safari do not).
- Effect: the development server stops; restart it. No data exposure.
- Fix: move the decode inside the `try`, or `try { … } catch { res.writeHead(400).end(); return; }`
  around `decodeURIComponent`; once the handler cannot throw, no `unhandledRejection` hook is needed.
  Optionally check the `Host` header against `127.0.0.1:<port>` (see I-4).

### L-4 (low): the default dev origin is shared with other local servers

- `web/serve.mjs:11` (default port 8000), `web/README.md` "Build and run".
- Scenario: IndexedDB is per origin (scheme, host, port). `http://127.0.0.1:8000` is the default of
  `python -m http.server`, Django and many other dev tools. Any page served later on that origin by
  another project, including one of its npm dependencies, can open the `sbtp-web` database and call
  `crypto.subtle.sign("Ed25519", rec.privateKey, …)` to sign any SBTP block as the user, rewrite
  `blockMeta` (for example mark pending own blocks `acked` so they become evictable), or delete the
  identity. The key cannot be extracted, only used, and only while such a page is open. The README
  already says "serving the client from a dedicated origin"; the default does the opposite. Given the
  October incident (poisoned dependencies of other projects run on this workstation), this is the
  realistic path to the key, even if the identity has little value during the MVP.
- Fix: default to an uncommon fixed port (for example 8731) in `serve.mjs` and the README, and say
  in "Key storage" that the dev origin must not be reused by other projects. A public deployment
  should use its own host name.

## Information

- **I-1. Clickjacking without the header.** `frame-ancestors` cannot be set by the meta CSP; on a
  static host that does not send `serve.mjs`'s headers the page can be framed and a user tricked into
  clicking "Mine, sign and publish" (publishing the textarea content to the relay in the field; a
  framing page cannot set those inputs). "Delete the key" needs `confirm()`, which browsers suppress
  in cross-origin frames. The README already says to send the CSP as a header; keep it a deployment
  requirement (also for workers, which do not inherit the page's meta CSP).
- **I-2. A hostile relay can make an own block evictable.** `ack` follows any `200`/`201` from the
  relay in the field (`app.js:81-85`). A relay that answers `201` without storing turns the block
  into "acknowledged", which rule 12 then allows to evict, and the only copy may be lost. Conformant
  with the letter of rule 12; worth a sentence in the README, and, later, keeping own blocks until
  they can be fetched back from the relay (`GET /block` after the `PUT`).
- **I-3. Pending-cap check after mining.** `StoreFull` for the 200 pending own blocks is raised after
  mining and signing (`app.js:112`); the work is lost. Check the count before mining. `onRepublish`
  stops at the first pending block that fails revalidation, which blocks the ones after it; skip and
  report instead.
- **I-4. Dev server details.** No `Host` check, so a DNS-rebinding page can read the served files;
  they are the public client, so nothing is gained. `serve.mjs` itself is served (`.mjs` in the
  allow-list); harmless.
- **I-5. Build tools.** `build.sh` uses `wasm-bindgen` (version-checked) and `wasm-opt` from `PATH`
  (version not checked). The README should say how to install them reproducibly (`cargo install
  wasm-bindgen-cli --version 0.2.130 --locked`; binaryen from the system package manager) so nobody
  follows a third-party installer. The module self-test at instantiation catches a build whose
  verifier accepts `S + L`, but not every miscompilation.
- **I-6. Small conformance and robustness notes.** `parseInfo` refuses a `max_future_ms` within 2,048
  of 2^64 (JSON numbers round to 2^64), so a relay publishing `u64::MAX` as "no limit" would be a
  failed request; parse the raw text or accept `>= 2^53` as "very large". A redirect on a CORS
  preflight (PUT) surfaces as a "network failure", not a redirect: the browser does not expose it;
  PUT is not retried, so ADR 0030's "SHOULD NOT repeat" still holds. If `loadIdentity` throws (for
  example a browser that dropped Ed25519 support), `identity` stays `null`, "Generate" fails with
  "an identity already exists" and "Delete" is disabled: the user cannot recover without clearing site
  data; enable Delete when a record exists but fails to load.

## Not checked

- Real browsers. IndexedDB transactions with `await` inside (`idb.js` relies on promise
  continuations running while the transaction is active, which current Chrome, Firefox and Safari
  do), `CryptoKey` structured clone, `navigator.storage.persist()`, the Worker and the CSP were not
  exercised here; the author reports a headless Chrome check. Firefox and Safari behaviour (BYOB
  reader on `fetch()` bodies, Ed25519 availability, Safari's storage eviction) is unverified.
- The end-to-end test against a running relay (skipped: `SBTP_RELAY` not set).
- Browser-specific handling of `redirect: "manual"` for cross-origin redirects and of the
  `opaqueredirect` type, beyond the Node test with a scripted opaque response.
- Behaviour of wasm-bindgen 0.2.130 glue after a real trap (out of memory) rather than a foreign
  exception; the generated glue has no `__instance_terminated` check, so the client's own `guard` is
  the only protection, which is what it is meant to be.
- `cargo deny` and `cargo clippy` were not rerun: the branch changes no Rust code or manifest.
