# Security and correctness review: review fixes in sbtp-core and sbtp-l2

- Date: 2026-11-20
- Branch: `fix/review-core-l2` (3 commits on `main`: `31059e0`, `69dae0e`, `4202f1d`)
- Scope: `git diff main fix/review-core-l2`, judged against `docs/spec/sbtp-core-v0.2.md` and
  `docs/spec/l2-grammar.md` (§2.2, §2.3, §3, §3.1, §5.2, §5.4, §5.5).
- Review type: combined (security and correctness), one pass.

## Verdict

**Mergeable.** No critical, high or medium finding. Two low findings (a cost bound that is about
twice the documented one for small blocks, and a CLI budget inconsistency) and several info points,
all of which can go to the roadmap.

## Automated checks (run by the reviewer)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | all suites pass, 0 failures |
| `cargo build -p sbtp-core --no-default-features` | builds (`no_std`) |
| `cargo build -p sbtp-wasm --target wasm32-unknown-unknown` | builds |
| `gen_vectors -- --check` | 82 vectors, 0 written, 0 problems; `docs/test-vectors/` untouched by the diff |
| `cargo deny check`, and the same on `fuzz/Cargo.toml` | advisories, bans, licenses, sources ok |
| `validate_l2_seeds -- --check` | seeds verified |
| `cargo +nightly fuzz run validate_l2` (seeds + dict, 90 s, scratch corpus) | 6.1 M runs, no crash |

No dependency was added or updated.

## Findings

### L-1 (low): the byte budget undercounts BLAKE3 compressions, so small blocks can cost up to about twice the documented bound

- File: `crates/sbtp-core/src/builder.rs:137` (`default_max_attempts`), doc at lines 108 to 116.
- The budget divides `2^34` by the covered length, floored at 64. BLAKE3 costs one compression
  per started 64-byte block, so the real cost of an attempt is `ceil(h / 64) * 64` bytes, not `h`.
  For a covered range of `h = 65` bytes (a 129-byte block: no parent and an 11-byte payload, for
  example), the call gets about `2^34 / 65` attempts of 2 compressions each, about 1.97 times the
  compressions of the root-block case. The ratio falls to about 1.5 at `h = 129..192` and toward
  1 + 1/16 (chunk tree parents) for large blocks. The doc sentence "BLAKE3 hashes longer inputs at
  least as fast per byte" is wrong for inputs between 65 bytes and about 1 KiB: below one chunk
  there is no multi-chunk SIMD parallelism, and the last compression is partly empty.
- Scenario: a relay announces a difficulty the client accepts; the client mines a short reply
  that it cannot find a nonce for. The call runs about 90 s natively instead of the documented
  45 s. Still bounded and not exploitable beyond that factor; this is a documentation and bound
  accuracy issue, not a DoS hole.
- Fix: count the rounded-up length,
  `let hashed = hashed.max(1).div_ceil(HASH_BLOCK_LEN) * HASH_BLOCK_LEN;` (or equivalently divide
  the compressions budget by `ceil(h / 64)`), and drop or correct the "at least as fast per byte"
  sentence. The test `default_mining_budget_is_independent_of_block_size`
  (`crates/sbtp-core/tests/validation.rs:982`) computes `per` the same unrounded way and must use
  the rounded length too (lengths 200 and 1,088 in its loop would change).

### L-2 (low): the CLI mining budget is now inconsistent across difficulties

- File: `examples/cli-demo/src/commands.rs:98` to `103`.
- The CLI keeps "difficulty above 26: unbounded, otherwise the default budget". With the budget now
  in bytes, a block with a full payload gets about 2^18 attempts. A relay-supplied difficulty of
  24 (the CLI's `MAX_RELAY_DIFFICULTY`) succeeds with probability about 1.5 % on such a block, and
  an explicit `--difficulty 20` about 22 %, while `--difficulty 27` mines unbounded. Before the
  branch both succeeded (2^28 attempts). The error then says "lower the difficulty", which the user
  cannot do when the relay imposes it.
- Scenario: an operator mines a large post for a relay at difficulty 20 to 24; the command fails
  almost always, then succeeds at a higher difficulty. Not a security issue; a correctness and UX
  regression of the demonstrator.
- Fix: unbounded (`u64::MAX`) for an explicit `--difficulty` (the user's own choice, no hostile
  input), `default_max_attempts(block.len())` only for a difficulty read from a relay, and an error
  message that suggests `--difficulty <d>` to mine anyway, as `target_difficulty` already does for
  the cap.

### I-1 (info): `mineSlice` error precedence changed in one corner case

- File: `crates/sbtp-wasm/src/api.rs:262`.
- The binding no longer parses the block before calling `mine`, and `mine` checks the difficulty
  before parsing. A JS caller passing both a malformed block and a difficulty above 256 now gets
  `DifficultyTooHigh` instead of the F-rule name. Both are documented errors of `mineSlice`; every
  other observable behaviour is unchanged (resume nonce on a spent slice, `NonceSpaceExhausted` at
  `u64::MAX`, and its stickiness, which I traced by hand against `tests-js/smoke.mjs:127-129`:
  start `2^64 - 3`, slice of 1 resumes at `2^64 - 2`, slice of 5 tries `2^64 - 2` and `2^64 - 1`
  then reports exhaustion, and a later call tries `2^64 - 1` once and reports it again). No fix
  needed.

### I-2 (info): `KindRow` multiplicity is now per row; application rows must opt in

- File: `crates/sbtp-l2/src/decode.rs:453`.
- `cites` and `composed_of` are no longer repeatable by default on every row; a row must call
  `.repeatable(&[...])`. This is stricter and matches spec §3.1 ("at most once, unless the row says
  any number"). Required verbs are now allowed without being listed in `allowed`, which only fixes
  rows that previously could never pass. `KindRow` gained a public field, a source break for struct
  literals. No in-repository caller outside the tests. Note it in the changelog for application
  crates.

## Checks with no finding

- **Hostile input in the new paths.** `enc`, `enc_key`, `check_shape`, `check_row`, `closed_map`
  and `first_duplicate` use iterators, `get`, `try_from` and `checked_add` only; no indexing,
  `unwrap` or unchecked arithmetic. Body keys cannot repeat (the profile rejects equal keys), so
  the `Option` overwrites in the closures are unreachable. Fuzzing confirms (above).
- **Byte budget arithmetic.** For every block length 118 to 65,909 (and any `usize`): the
  subtraction saturates, the divisor is at least 64 (no division by zero), the quotient is at most
  2^28 and at least 1 (about 260,900 for the largest block). `u64::try_from` cannot fail on 64-bit
  hosts and saturates otherwise. An explicit `.max_attempts(n)` is still honoured as is.
- **Nonce exhaustion.** `mine` returns `NonceSpaceExhausted` from inside the loop, before the
  budget test, so a slice ending exactly at `u64::MAX` reports exhaustion; the block keeps
  `u64::MAX`. `max_attempts = 0` returns `PowNotFound` with the block unchanged, as before.
- **Refactors.** The shared `first_duplicate` reports the same lexicographic first pair as the old
  loops (decoder and builder). The builder's `checked_lens` replaces two `unwrap_or` re-conversions
  and keeps F5 and the `u16` payload bound (`MAX_PAYLOAD_LEN` is `u16::MAX`). The removed local
  `fields` returned a count nobody used; `closed_map` keeps the same errors.
- **`sbtp.enc` against §5.2.** Row: exactly 1 parent, `tagged` exactly once, no other registry verb.
  Body: exactly `ct` (bstr) and `enc` (32 bytes). Payload Len in {512, 2,048, 8,192, 65,535}.
  The 90-byte overhead is correct: I recounted the canonical encoding (envelope 1, `v` 3, `body`
  key 5, body map 1, `ct` key 3, `ct` header 3, `enc` key 4, `enc` value 34, `kind` 5 + 9,
  `edges` 6, array 1, edge 1 + 3 + 4 + 7 = 90), with a 3-byte `ct` header for every bucket
  (`ct` is 422 to 65,445 bytes). "Ciphertext is plaintext plus 16" is implied (ct is at least
  422). Nothing the spec rejects is accepted, and nothing it accepts is rejected.
- **`sbtp.enc_key` against §5.5.** Row: 1 or 2 parents, `tagged` exactly once, `supersedes` at most
  once. Body: exactly `x25519` (32 bytes) and `intro_bucket` (unsigned, 0 to 15; a negative or
  larger integer is rejected).
- **`tagged` and `tallies`.** Both `p` only and without `meta` (§2.2). `tagged` is refused on every
  kind but the two above, unknown and application kinds included, before the row check. `tallies`
  is refused on every `sbtp.*` row and left to application validation elsewhere, as §2.2 says.
- **WASM error mapping.** `NonceSpaceExhausted` maps to the existing JS name; `PowNotFound` stays
  internal (`mineSlice` turns it into `undefined`).

## The author's four open spec points

1. **`sbtp.enc_key` parent positions not enforced.** §5.5 says the tag is `p: 0` and the previous
   version `p: 1`; §2.1 says a parent's position carries no meaning. The code follows §2.1, so a
   key block with `supersedes` at `p: 0` and `tagged` at `p: 1` passes, and so does a 2-parent key
   block whose second edge is an extension or unknown causal verb instead of `supersedes` (§2.3
   allows it on an open edge set). The risk is divergence: a resolver that takes `parents[0]` as
   the tag and one that follows the `tagged` edge reach different key states for the same block
   set, against §4. My view: the spec should decide in one sentence, and the cheaper and safer
   choice is a MUST in §5.5 ("the `tagged` edge is `p: 0`"), checked by grammar validation (one
   comparison). Until then, resolvers must locate the tag through the `tagged` edge. Route to the
   specification owner.
2. **Should the `sbtp.enc` edge set be stated closed?** It is already closed in effect: with the
   overhead fixed at 90 bytes and a 3-byte `ct` header forced, any extra edge (at least about
   40 bytes) breaks `ct + 90 = Payload Len`, so it is rejected as `EncCiphertextLen` (the test
   `sealed_block_row_body_and_buckets` covers it). Stating it closed in §5.2 costs nothing, gives a
   clearer error, and keeps the property if a later version changes the length rule. Recommended;
   in code, `closed: true` on the row as defence in depth.
3. **Undefined `sbtp.*` kinds treated as unknown.** Correct reading: §1.3 binds authors, §2.4
   passes any other kind with its body checked for type, and §1.3 forbids applying an unknown kind.
   No security impact. One forward-compatibility note for the specification: since `tagged` is
   refused on every kind but the two current ones, a future `sbtp.*` kind that uses `tagged` would
   be invalid, not unknown, for older clients. Acceptable, but worth a line in the ADR that
   introduces such a kind.
4. **Key-block tag/PubKey match left to state resolution.** Correct: §5.5 says such a block is
   "ignored for state resolution", and §2.4 restricts grammar validation to the parents' count and,
   for the `block` rule only, their values. It is nevertheless the check that prevents key
   directory spoofing: anyone can file a validly signed `sbtp.enc_key` under another identity's
   directory tag, and a sender that trusts `/query?parent=<tag>` without recomputing
   `derive_key("SBTP 2026-11-20 enc_key directory v1", PubKey)` would seal to the attacker's key.
   No consumer of `Body::EncKey` exists yet; the milestone that adds key resolution or sealing must
   implement this check, together with the same-author check on `supersedes`, with a negative test.
   I would rate a missing check there high.

## Not checked

- The JS smoke test (`crates/sbtp-wasm/tests-js/smoke.mjs`) was not run; its nonce-exhaustion
  sequence was traced by hand against the Rust code.
- The mining time bound was not measured; L-1 rests on BLAKE3's compression structure, not on a
  benchmark.
- Fuzzing was short (90 s on `validate_l2`, none on `decode_block`, which the diff does not touch
  beyond the shared duplicate helper, covered by the unit tests).
- Sealing, opening, padding and inner-signature rules (§5.1, §5.3) are not implemented on this
  branch and were not in scope.
