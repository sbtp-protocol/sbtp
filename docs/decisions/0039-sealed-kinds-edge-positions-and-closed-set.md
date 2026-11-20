# 0039: Parent roles of `sbtp.enc_key`, closed edge set of `sbtp.enc`, undefined `sbtp.*` kinds

- Status: accepted (2026-11-20, owner)
- Date: 2026-11-20
- Questions: none open; points raised by the 2026-11-20 review of the `sbtp-l2` fixes
  (`docs/security/2026-11-20-review-fixes-core-l2.md`, "The author's four open spec points")
- Amends: ADR 0016 rule 21 (the parent positions of an `sbtp.enc_key` become a grammar
  validation rule) and the `sbtp.enc` row of its mapping table (closed edge set); ADR 0032 rule 4 (one
  more kind with a closed edge set). Nothing else in ADR 0016 or ADR 0032 changes
- Clarification: 2026-11-20 (owner): with rule 4, the `sbtp.enc` length rule (payload = 90 bytes +
  ciphertext) always holds at the four bucket lengths; `l2-grammar.md` §5.2 says so and keeps the check
  as optional defence in depth
- Depends on: ADR 0015 (grammar, coverage and order of edges), ADR 0016 (sealed envelope, key
  directory), ADR 0032 (kind rows, closed edge sets, validation inputs)
- Impact: `l2-grammar.md` §2.1, §5.2, §5.5 (rules 1 to 4, "Spec change on acceptance", applied on acceptance), §1.3 and §5.5
  (rules 5 and 6, editorial, applied with this proposal); `crates/sbtp-l2` (`check_shape`, two error
  variants, tests); no layer 0 change; no test vector (there is no layer 2 vector set yet; the frozen set
  `docs/test-vectors/v1/` is not affected)

## Context

The review of the `sbtp-l2` fixes raised four points on the grammar of the two `sbtp.*` sealed kinds.

1. **Parent positions of `sbtp.enc_key`.** §5.5 says the directory tag is `p: 0` (`tagged`) and the
   previous version `p: 1` (`supersedes`). §2.1 says the position of a parent in the header carries no
   meaning of its own. The code follows §2.1: a key block with `supersedes` at `p: 0` and `tagged` at
   `p: 1` passes grammar validation, and so does a block with 2 parents whose second edge is an extension
   or unknown causal verb instead of `supersedes` (§2.3 allows such a verb on an open edge set). A
   resolver that reads `parents[0]` as the tag and one that follows the `tagged` edge reach different
   key states for the same set of blocks, against §4.
2. **Edge set of `sbtp.enc`.** It is closed in effect: the payload overhead is fixed at 90 bytes, so any
   extra edge breaks `len(ct) + 90 = Payload Len` and the payload fails with `EncCiphertextLen`. The
   property depends on the length rule and is not stated.
3. **`sbtp.*` kinds this specification does not define.** `sbtp-l2` treats them as unknown kinds. §1.3
   forbids applications to define such kinds, but does not say what a decoder does when it meets one.
4. **Tag/PubKey match of a key block.** §5.5 says a key block whose tag does not match its PubKey is
   ignored for state resolution. It does not say that grammar validation leaves this check out. It is
   the check that prevents an author from filing a validly signed key under another identity's
   directory tag.

## Decision

1. **`sbtp.enc_key`, directory tag.** The `tagged` edge of an `sbtp.enc_key` MUST be `p: 0`.
2. **`sbtp.enc_key`, previous version.** An `sbtp.enc_key` with 2 parents MUST carry the `supersedes`
   edge as `p: 1`. With the coverage and order rules of §2.1, a root version is exactly
   `[{"p": 0, "rel": "tagged"}]` plus any non-causal edges, and an update is exactly
   `[{"p": 0, "rel": "tagged"}, {"p": 1, "rel": "supersedes", ...}]` plus any non-causal edges. The edge
   set stays open for non-causal extension and unknown verbs.
3. **Position exception.** §2.1 keeps "the position of a parent in the header carries no meaning of its
   own", with one exception: a kind whose definition fixes the position of a verb. Only `sbtp.enc_key`
   does so.
4. **`sbtp.enc`, closed edge set.** The edge set of `sbtp.enc` is closed (§3.1): no extension or unknown
   verb, causal or not. The set of valid `sbtp.enc` payloads does not change; a payload with an extra
   edge fails on the row instead of the length rule.
5. **Undefined `sbtp.*` kinds (editorial).** A decoder MUST treat an `sbtp.*` kind that this
   specification does not define as an unknown kind (§1.3): a later version may define it. The registry
   rules still apply to it. In particular `tagged` is allowed only on `sbtp.enc` and `sbtp.enc_key`, so a
   later `sbtp.*` kind that uses `tagged` is invalid, not unknown, for a decoder of this version. The ADR
   that defines such a kind states this.
6. **Tag/PubKey match (editorial).** The match between the directory tag of a key block and its PubKey
   is a state resolution rule, not a grammar validation rule: grammar validation reads parent values only
   for the `block` rule of §2.1 (§2.4). A client that reads a key directory MUST recompute
   `derive_key("SBTP 2026-11-20 enc_key directory v1", PubKey)` for each listed block and ignore a block
   whose `tagged` parent differs. A client MUST NOT trust `/query?parent=<tag>` alone. This restates the
   existing rule "ignored for state resolution"; it adds no new obligation.

Rules 1 to 4 change what grammar validation accepts or the error it reports, and wait for acceptance.
Rules 5 and 6 state existing behaviour and are applied to the specification with this proposal.

## Consequences

- **Validation cost.** Rules 1 and 2 are two comparisons on edges already decoded; rule 4 is the
  existing closed-set check. Grammar validation stays linear in the payload size and reads no other
  block.
- **Interoperability.** Every resolver locates the tag and the previous version at the same position.
  A key block that a resolver of the current code accepts with swapped positions, or with an extension
  causal verb as its second parent, becomes invalid. No such block is produced by `sbtp-l2`'s encoder.
- **`sbtp-l2`.** `check_shape` for `Kind::EncKey` checks rules 1 and 2 after `check_row`, with one error
  variant per rule (proposed names `EncKeyTagPosition` and `EncKeySupersedesPosition`, spec §5.5);
  `Kind::Enc` sets `closed: true` on its row (spec §5.2). One test per rule: `tagged` at `p: 1` with
  `supersedes` at `p: 0`; 2 parents with an extension causal verb at `p: 1`; an extension non-causal
  edge on `sbtp.enc` reported by the row check.
- **Security.** Rule 6 is the check that prevents key directory spoofing. No consumer of the key body
  exists yet; the milestone that adds key resolution or sealing implements it, with the same-author check
  on `supersedes` (§4.3), and a negative test for each.
- **Compatibility.** Nothing is released. No layer 0 change and no vector change.

## Spec change on acceptance

`l2-grammar.md` §2.1, bullet "Coverage", last sentence, replaced by:

> The position of a parent in the header carries no meaning of its own, unless the definition of the
> kind fixes the position of a verb (§5.5).

`l2-grammar.md` §5.2, after the first bullet:

> - The edge set is closed (§3.1): the payload carries no extension or unknown verb.

`l2-grammar.md` §5.5, bullet "Parents", first sentence, replaced by:

> - Parents: the directory tag `derive_key("SBTP 2026-11-20 enc_key directory v1", identity_pubkey)`
>   MUST be `p: 0`, named by the `tagged` edge; an update has 2 parents and MUST name the previous
>   version as `p: 1`, by the `supersedes` edge. Grammar validation checks both positions.

`crates/sbtp-l2`: the `sbtp.enc` row gains `closed`; the `sbtp.enc_key` row comment cites the positions.

## Rejected alternatives

- **Keep positions meaningless and locate the tag by the `tagged` edge.** No grammar change, but every
  resolver must implement the indirection, and the two readings already diverge. A fixed position costs
  one comparison and removes the ambiguity.
- **Close the edge set of `sbtp.enc_key`.** Rule 2 would follow from it, but it would also refuse
  non-causal extension edges, which carry no risk on a key block. Rule 2 fixes the causal edges only.
- **Leave `sbtp.enc` open and rely on the length rule.** Correct today, but the property would silently
  depend on the overhead computation, and a payload with an extra edge reports a length error instead of
  an edge error.
- **Check the tag/PubKey match in grammar validation.** It would make §2.4 read parent values and
  compute a `derive_key` per key block. Resolution reads the directory anyway and applies the check
  there; a block that fails it stays a valid payload that is never applied.
