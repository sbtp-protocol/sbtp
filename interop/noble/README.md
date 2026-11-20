# Interop check: `@noble/ed25519` against the v1 vectors

Scratch cross-check (roadmap, "Layer 0 hardening"). It runs every well-formed vector of
`docs/test-vectors/v1/` through a second Ed25519 implementation, `@noble/ed25519` 3.2.0, and compares its
verdict with criteria V1 to V6 of ADR 0003. It is not shipped, not part of the Cargo workspace, and does not
change `sbtp-core`.

## Run

```bash
cd interop/noble
pnpm install --frozen-lockfile --ignore-scripts
node check-vectors.mjs              # plain table
node check-vectors.mjs --markdown   # Markdown table
```

Node 22 or later (`engines`); the script uses WebCrypto SHA-512 through `verifyAsync`, as a browser
would, and `node:crypto` SHA-512 for the diagnosis. Exit code 1 means an inconsistency: a vector that does
not parse, an unknown `expect.error`, a description that does not state a verdict for each of V1 to V6, a
diagnosis that disagrees with it, or a valid signature rejected. Divergences of noble from V1 to V6 are the
expected output and do not fail the run.

## Supply chain

- Exact version `3.2.0` (published 2026-08-27), zero runtime dependencies, maintainer `paulmillr`.
- `pnpm-lock.yaml` is committed. Its integrity
  `sha512-criDgRlnUA09hchYrTy/JUWPIEap5rZxQe6wDWzRx51oWWpDRcUpuNzlgPxDJaOK6AsW9c0wKcj3rKRv6t+bPQ==` matches
  the registry's `dist.integrity` and the SHA-512 of the downloaded tarball, computed independently.
- The package declares no `preinstall`, `install`, `postinstall` or `prepare` script and no `gypfile`.
  Scripts are disabled anyway: `ignoreScripts: true` in `pnpm-workspace.yaml` (pnpm 11 and later read only
  auth and registry settings from `.npmrc`), and `ignore-scripts=true` in `.npmrc` for npm.
- pnpm is pinned: `packageManager` is `pnpm@12.15.0` with its SHA-512. pnpm 12 records that pin in a
  leading boot document of `pnpm-lock.yaml` (`packageManagerDependencies`, with the integrity of `pnpm` and
  of each platform binary `@pnpm/exe.*`); the dependency document after it is unchanged.
- The README states that 3.x "has not been independently audited"; it is a rewrite of v1, audited by cure53
  in February 2022.

## What noble checks (read in `index.ts` of 3.2.0, not from memory)

`verify(sig, msg, pubkey, { zip215 })`, default `zip215: true`.

| Check | `zip215: false` ("strict RFC 8032 / FIPS 186-5") | `zip215: true` (default) |
|---|---|---|
| `A` decoding: `y < p` | yes | no (`y < 2^255` after masking the sign bit) |
| `A` decoding: `x = 0` with sign bit 1 rejected | yes | no |
| `A` on the curve (square root exists) | yes | yes |
| `A` of small order rejected | yes (`A.isSmallOrder()`) | no |
| `S < L` | yes (`arange(s, 1, N)`, `S = 0` allowed) | yes |
| `R` decoding: `y < p`, `x = 0` with sign bit 1 rejected | yes | no |
| `R` on the curve | yes | yes |
| `R` of small order rejected | **no** | no |
| `k = SHA-512(R ‖ A ‖ M) mod L`, `R` and `A` as received | yes | yes |
| Equation | **cofactored**: `[8](R + [k]A − [S]B) = O` | cofactored |

So noble's strict mode covers V1, V2, V3 and V4 exactly, and rejects non-canonical `R` at decoding (part of
what V6 implies). It differs from ADR 0003 on two points: it does not check V5, and it uses the cofactored
equation where V6 requires the cofactorless one, which ADR 0003 rule 3 forbids.

## Result (2026-11-18)

82 vectors: 15 format vectors (F1 to F9) skipped (no `block_id`, signature not meaningful), 67 checked
(15 valid, C1, R1, 24 C2, 26 C3). The per-criterion diagnosis matches the criteria listed in every vector's
description (0 inconsistencies).

- **noble strict (`zip215: false`): 9 divergences**, all "noble accepts, sbtp-core rejects":
  - `c3_v5_only_r_*` (8 vectors): `R` of small order, cofactorless equation holds. V5 not checked.
  - `c3_v6_cofactored_only`: valid only under the cofactored equation. noble's equation is cofactored.
- **noble ZIP-215 (default): 19 divergences**: the 9 above, plus
  - `c2_v2_only_*` (9 vectors): small-order `A` (V2) not rejected;
  - `c2_v1_v2_non_canonical_identity`: non-canonical `A` (V1) accepted by ZIP-215 decoding, small order (V2)
    not rejected, and the equation holds.

No divergence in the other direction: noble never rejects a signature that V1 to V6 accept (cofactorless
implies cofactored). A browser client that verified with noble, in either mode, would accept blocks that
every relay rejects. This confirms ADR 0003: the Phase 3 web client must verify through `sbtp-wasm`.
