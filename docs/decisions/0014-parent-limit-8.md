# 0014: Parent limit lowered from 15 to 8

- Status: accepted (by the project owner, 2026-11-18)
- Date: 2026-11-18
- Decision: project owner, 2026-11-18 (the limit of 8); acceptance of this ADR is recorded by the owner
- Questions: none (follows Q-10, resolved by ADR 0004)
- Amends: ADR 0004 rules 5 and 8 and the thresholds of checks F2 and F5; rules 6 and 7 are restated
  unchanged. ADR 0013, benchmark protocol, adversarial data set only
- Impact: spec §2 (Parents Count row, block sizes), §2.2 (F2, F5, parent limit), §4 (`PUT` body limit);
  the layer 2 payload specification of the time, §1.3; `sbtp-core` (`layout.rs` constants, comments, error messages,
  tests, benches, vector generator); `docs/test-vectors/v1/` (four files replaced in place); fuzz seeds;
  `sbtp-relay` (body limit, Phase 2 tests, benchmark generator)

## Context

ADR 0004 wrote a limit of 15 parents into the format (rule 5) and derived the maximum block size from it
(rule 8: 66,133 bytes). The project owner lowers the limit to 8.

Reason given by the owner: even with 8 parents, an author can very quickly supersede a very large number
of blocks. One block acts on up to 8 blocks; merge blocks compound, so `d` levels reach `8^d` blocks
(4,096 at four levels).

Supporting reasons:

- The layer 2 payloads drafted so far rarely need more than 3 to 5 parents (a vote takes 1, a tombstone
  at most 2, a media manifest at most 1; a content block takes one anchor plus cross-references).
- Every parent is one relay index entry (ADR 0013 rule 4). A sender chooses its parents freely, so one
  proof of work buys as many index entries as the format allows. The amplification goes from 15 to 8
  entries per block.

State of the repository on 2026-11-18:

- No block exists outside the tests and the vector set. No relay is deployed.
- `docs/test-vectors/v1/` (82 vectors) is merged in `main` and has never been published: the repository
  has no remote and no external consumer.
- The benchmark of ADR 0013 (rule 23) has not run. Its adversarial data set is defined with 15 parents
  per valid block; such a block is malformed under the new limit, so the data set cannot be generated as
  written.

## Decision

### Parent limit (replaces ADR 0004 rules 5 and 8)

1. A block MUST have from 0 to 8 parents. A block whose Parents Count field exceeds 8 is malformed for
   every implementation (check F5). Values 9 to 255 of the field are reserved.
2. An implementation MUST NOT make this limit configurable, neither upwards nor downwards (ADR 0004
   rule 6, unchanged).
3. Relaxing the limit requires a new value of the Version field, and therefore an ADR (ADR 0004 rule 7,
   unchanged).
4. The maximum block size is `52 + 8·32 + 2 + 65,535 + 64 = 65,909` bytes (`MAX_BLOCK_LEN`).

### Checks

5. The order, the conditions and the error variants of ADR 0004 are unchanged. Two thresholds change:

   | Order | Rejection condition | Variant |
   |---|---|---|
   | F2 | `len > 65,909` (`MAX_BLOCK_LEN`). | `TooLong { len }` |
   | F5 | `N > 8` (`MAX_PARENTS`). | `TooManyParents { count }` |

6. `MIN_BLOCK_LEN` (118), every offset and every other rule of ADR 0004 are unchanged. The Version field
   stays `0x01`.

### Relay body limit

7. The transport limit of `PUT /sbtp/v1/block` is `MAX_BLOCK_LEN` (ADR 0008 rule 7), that is 65,909
   bytes. A body of 65,910 bytes gets `413` before any parsing. ADR 0008 defines the limit by the
   constant; the literal values 66,133 and 66,134 in ADR 0008 and in the checklist of ADR 0012 read as
   65,909 and 65,910.

### Test vector set

8. `docs/test-vectors/v1/` is regenerated in place. No `v2/` is created. The rule "a published set never
   changes" did not apply yet: `v1/` was never published.
9. This is the last time `v1/` changes before publication. Publication is the first time the set leaves
   this repository: a push to a remote, a release, or a copy handed to another implementation. From then
   on, a format change creates `v2/`.
10. Cases affected:

    | Current file | After | Content |
    |---|---|---|
    | `valid_15_parents` | removed; replaced by `valid_8_parents` | 8 parents (`32 × 0x01` to `32 × 0x08`), short payload. Valid. F5 boundary. |
    | `valid_max_size` | same name, new bytes | 8 parents, payload of 65,535 bytes: 65,909 bytes. Valid. F2 boundary. |
    | `f2_66134_bytes` | removed; replaced by `f2_65910_bytes` | The maximum-size block followed by one `0x00` byte: 65,910 bytes. `TooLong`. |
    | `f5_16_parents` | removed; replaced by `f5_9_parents` | Parents Count 9, 9 distinct parents, empty payload, consistent layout: 406 bytes. `TooManyParents`. |
    | `f5_255_parents` | unchanged | 8,278 bytes, below the new maximum, so F2 does not fire. `TooManyParents`. |

11. The 78 other files MUST be byte-identical after the regeneration. No other vector uses more than 4
    parents or depends on the maximum size. The set stays at 82 vectors.
12. No case is added for the old bounds. An implementation that keeps 15 fails `f5_9_parents`; one that
    keeps 66,133 returns `TrailingBytes` on `f2_65910_bytes`.
13. The fuzz seeds derive from the vectors and are regenerated (`--fuzz-seeds`).

### Benchmark of ADR 0013 (replaces the adversarial row of its data set table)

14. The adversarial data set uses the format maximum:

    | Data set | Blocks | Parents |
    |---|---|---|
    | Adversarial | 1,000,000 | 8 per block, each a distinct random 32-byte value that is not a stored block (8,000,000 edges). |

15. This change follows a format change, not a benchmark result. The benchmark has not run. The data set
    is "the worst case the format allows"; the format maximum moved, and a 15-parent block is no longer
    valid.
16. The pass thresholds are unchanged: binary under 5,000,000 bytes; peak memory at most 12 MiB for both
    data sets at every step; the correctness criterion. The typical data set, the build, the procedure,
    the measures and the three runs are unchanged. The thresholds still MUST NOT be changed after the
    results are known.
17. Elsewhere in ADR 0013, "15 parents" reads as "the format maximum, 8": the index growth bound in
    "Security" (8 edges per block), the rows per block in one transaction (at most 10), and the test
    "15 distinct unknown parents counted" of its checklist (8). The estimates of its comparison table were
    computed for 15 and are not recomputed; they are upper bounds, and the benchmark measures the real
    values.

## Consequences

- **Binary layout: `layout.rs` is touched.** No offset changes. `MAX_PARENTS` goes from 15 to 8 and
  `MAX_BLOCK_LEN` from 66,133 to 65,909.
- **Cost of F9.** At most `8·7/2 = 28` comparisons of 32 bytes (105 before).
- **Relay index.** At most 8 edges per accepted block. The smallest block that carries the maximum number
  of edges is `118 + 8·32 = 374` bytes (598 before).
- **Upper layers.** A block cannot merge more than 8 DAG heads. A wider merge requires intermediate
  blocks. A content block carries one anchor and at most 7 cross-references.
- **Compatibility.** Nothing exists outside this repository, so the limit is lowered without a new
  Version value. After publication, lowering the limit would split validity between implementations in
  the same way as raising it. Rule 3 covers relaxing only; this ADR does not extend it.
- **Reviews.** The security reports of 2026-11-18 quote 15, 66,133 and 105 comparisons. They are dated
  records and are not edited. The change touches decoder constants and reviewed vectors: a
  the security reviewer pass on the diff is due before the Phase 1 state is declared closed again.

### Checklist for the implementer

- [ ] `crates/sbtp-core/src/layout.rs`: `MAX_PARENTS = 8` and its comment ("Values 9 to 255 are
      reserved", ADR 0014); module doc line "N, 0 to 8"; `MAX_BLOCK_LEN` comment (8 parents, 65,909);
      `size_bounds` test: `assert_eq!(MAX_BLOCK_LEN, 65_909)`.
- [ ] `src/block.rs`: comments of F2, F5, F6 and F9 (65,909; `N > 8`; `N ≤ 8`; 28 comparisons; indices
      below 8). `src/error.rs` and `src/builder.rs`: doc comments and the `Display` texts "maximum 15" and
      "maximum 66133"; build them from the constants.
- [ ] `tests/validation.rs` and `tests/properties.rs`: every literal 15, 16, 66_133 and 66_134 that stands
      for a bound (boundary tests, generators, the model oracle, `BuildError::TooManyParents { count }`).
      Prefer `MAX_PARENTS` and `MAX_BLOCK_LEN` where the test is not pinning the value.
- [ ] `benches/core.rs`: the maximum shape is 8 parents; rename `max_66133B`.
- [ ] `examples/gen_vectors.rs`: `valid_8_parents`; `max_block` with 8 parents and
      `assert_eq!(max_block.len(), 65_909)`; `f2_65910_bytes`; F5 loop over `[9, 255]`.
- [ ] `docs/test-vectors/v1/`: delete `valid_15_parents.json`, `valid_max_size.json`,
      `f2_66134_bytes.json` and `f5_16_parents.json` (the generator never overwrites), run the generator,
      then `--check`. `git diff --stat` MUST show these four removed, four added, and no other file
      touched (rule 11).
- [ ] `tests/vectors.rs`: the required-names list (`valid_8_parents`, `f2_65910_bytes`, `f5_9_parents`)
      and the length assertions (65,909 and 65,910).
- [ ] Fuzz: re-run `--fuzz-seeds`; update the comment in `fuzz/README.md` (65,909 and 65,910;
      `-max_len=66200` still covers both). The target uses the constants and needs no change.
- [ ] `sbtp-relay`: `src/main.rs` already reads `MAX_BLOCK_LEN`. In Phase 2 the body limit MUST use the
      constant, not the literal `66_133` quoted in the checklist of ADR 0012; integration tests: 65,909
      bytes parsed, 65,910 bytes `413`.
- [ ] ADR 0013 benchmark generator (the implementer, when written): adversarial data set with 8 parents
      per block (rule 14).
- [ ] Docs outside the architect's scope: the roadmap (not published) (Phase 0 line "15-parent format limit",
      Phase 1 line `MAX_PARENTS = 15`, `MAX_BLOCK_LEN = 66,133`). Stale local working copies are ignored.
- [ ] `cargo test --workspace`, the `wasm32` and `no_std` checks, then the security reviewer pass.

## Rejected alternatives

- **Keep 15.** The owner's reason stands against it; no payload type needs it.
- **A lower limit (4 or 5).** Matches the usual layer 2 need, but leaves no room for a block with several
  cross-references or for a merge of more than a few heads, and the format is meant to be neutral towards
  layer 2. Raising it later costs a Version value.
- **Limit as a relay policy.** Rejected by ADR 0004 for the same reason as before: validity would depend
  on the relay.
- **A new Version value for the change.** Nothing was published under `0x01`; a second value would
  describe a format that never existed outside this repository.
- **Create `v2/` and keep `v1/`.** `v1/` would hold vectors that are wrong for the only format ever
  published. The "never changes" rule protects external consumers; there is none.
- **Keep the adversarial data set at 15 parents.** The protocol requires valid blocks; a 15-parent block
  is malformed. The relay cannot receive it through the `PUT` handler.
- **Lower the benchmark thresholds with the data set.** The thresholds come from the RAM and binary
  targets, not from the data set. They were confirmed before any run and stay as confirmed.

## Spec change

Applied on 2026-11-18, on the owner's decision relayed by the maintainer.

### `docs/spec/sbtp-core-v0.2.md`

**§2, table.** Parents Count row:

```markdown
| Parents Count | 1 | u8 | Number N of parents, from 0 to 8. Values 9 to 255 are reserved (§2.2). |
```

**§2, after the table.**

```markdown
Block size: from 118 bytes (0 parents, empty payload) to 65,909 bytes (8 parents, max payload).
```

**§2.2, table.** Rows F2 and F5:

```markdown
| F2 | `len > 65,909`. | `TooLong` |
| F5 | `N > 8`. | `TooManyParents` |
```

**§2.2, "Parent limit".**

```markdown
- **Parent limit.** A block MUST have from 0 to 8 parents. An implementation MUST NOT make this limit
  configurable. Raising it requires a new value of the Version field.
```

**§2.2, last line.**

```markdown
Every new rejection rule goes through an ADR. (ADR 0004, ADR 0014)
```

**§4, `PUT /sbtp/v1/block`, "Body limit".**

```markdown
- Body limit: a relay MUST limit the request body to 65,909 bytes (`MAX_BLOCK_LEN`) at the transport
  level. A longer body gets `413 Content Too Large` before any parsing.
```

### Layer 2 payload specification

Neither 15 nor 66,133 appears. §1.3 gets one line, because the table of §2 uses `N` as a maximum without
bounding it:

```markdown
- `N` is bounded by the block format: at most 8 parents, anchor included (core spec §2.2, ADR 0014).
```

### `docs/spec/architecture.md`

No change. Neither the parent limit nor the maximum block size appears (its "15 MB" is the RAM target).

### Other documents

- `docs/test-vectors/README.md`: bounds, required cases, status of `v1/` (rules 8 to 11).
- ADR 0004 and ADR 0013: one "Amended by: 0014" line each; bodies unchanged.
- `docs/decisions/README.md` (index) and the open questions (not published) (Q-10 and Q-19 notes).
