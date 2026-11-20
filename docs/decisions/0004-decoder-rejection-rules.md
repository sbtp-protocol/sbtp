# 0004: Decoder rejection rules and validation order

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0014 (rules 5 and 8, thresholds of F2 and F5: 8 parents, 65,909 bytes)
- Date: 2026-11-18
- Questions: Q-10
- Impact: spec §2 (Parents Count row, block sizes), §2.1, new §2.2, §4 (`PUT`); `sbtp-core` (decoder, error
  `enum`, **`layout.rs` constants**), `sbtp-relay` (maximum body size, HTTP codes); one test vector per
  variant
- Review: docs/security/2026-11-18-adr-0002-0003.md (findings M-3 and B-1, carried over here; this ADR has not been audited)

## Context

The v0.2-draft sets only one rejection rule: the total length must be exact (§2.1). It says nothing about an
unknown version, duplicate parents or their order. For the number of parents, it gives "recommended ≤ 15,
hard maximum 255", without saying who enforces the recommendation.

Two independent decoders must accept exactly the same set of byte sequences. Otherwise a block accepted by
one relay is refused by another: its descendants then reference a parent that this relay will never hold,
and gossip leaves holes in the DAG. Test vectors also expect a precise error per case, which imposes an
order of checks.

The project requires one error variant per spec rule (`CLAUDE.md`, code conventions).

## Decision

### Principles

1. A block that passes the rules below is **well-formed**. For a given content (version, timestamp, nonce,
   key, ordered list of parents, payload), there is a single well-formed byte sequence, signature excluded.
   Signature variants fall under ADR 0003.
2. The format validity of a block MUST be the same for every implementation. No format check depends on a
   local configuration.
3. The checks MUST be done in the order of the table. The first one that fails determines the error
   returned. A decoder MUST NOT read a byte before checking that the buffer contains it.
4. All checks are stateless and bounded by a constant. None requires an allocation.

### Format checks (decoder)

Notation: `len` is the buffer length, `N` the byte at offset 51, `P` the big-endian u16 at offset
`52 + 32·N`.

| Order | Rejection condition | Suggested variant |
|---|---|---|
| F1 | `len < 118` (`MIN_BLOCK_LEN`). Covers the empty buffer. | `TooShort { len }` |
| F2 | `len > 66,133` (`MAX_BLOCK_LEN`). | `TooLong { len }` |
| F3 | Bytes 0 and 1 differ from `0x53 0x42`. | `BadMagic` |
| F4 | Byte 2 differs from `0x01`. | `UnsupportedVersion { version }` |
| F5 | `N > 15` (`MAX_PARENTS`). | `TooManyParents { count }` |
| F6 | `len < 118 + 32·N`: the buffer cannot hold `N` parents, Payload Len and the signature. | `Truncated { expected_min, len }` |
| F7 | `len < 118 + 32·N + P`: missing bytes. | `Truncated { expected_min, len }` |
| F8 | `len > 118 + 32·N + P`: bytes after the signature. | `TrailingBytes { expected, len }` |
| F9 | Two identical parent hashes, at any positions. | `DuplicateParent { first, second }` |

F6 and F7 share the `Truncated` variant. In F7, `expected_min` is the exact expected length.

### Parent limit

5. A block MUST have from 0 to 15 parents. A block whose Parents Count field exceeds 15 is malformed for
   every implementation (F5). Values 16 to 255 of the field are reserved.
6. An implementation MUST NOT make this limit configurable, neither upwards nor downwards.
7. Relaxing the limit requires a new value of the Version field, and therefore an ADR.
8. The maximum block size is `52 + 15·32 + 2 + 65,535 + 64 = 66,133` bytes.

### Parents

9. The order of parents is significant and kept as is. A decoder MUST NOT require an order (sorting) or
   reorder.
10. Duplicate parents are rejected (F9), whatever their position.

### What a decoder MUST NOT reject

11. The following cases are well-formed. A decoder MUST NOT reject them on format grounds:

    | Case | Reason |
    |---|---|
    | `N = 0` (root block). | Provided for by the format. |
    | `P = 0` (empty payload). | Provided for by the format. |
    | Parent unknown to the validator. | Stateless validation; blocks arrive out of order. |
    | Parent whose 32 bytes are zero, or equal to any value. | A hash is opaque. |
    | Any Timestamp value, including 0 and `2^64 − 1`. | The time bound is a relay policy (`[Q-07]`), not a format rule. |
    | Any Nonce value. | Free field (ADR 0001). |
    | Any payload content. | Opaque to layer 0. |

### Cryptographic checks (after the format)

12. After the format, validation MUST continue in this order:

    | Order | Rejection condition | Suggested variant |
    |---|---|---|
    | C1 | The `block_id` (ADR 0002) has fewer than `d` leading zero bits, `d` being the required difficulty. | `InsufficientPow { required, actual }` |
    | C2 | Invalid PubKey: criteria V1 (non-canonical encoding included) or V2 of ADR 0003. | `InvalidPublicKey` |
    | C3 | Invalid signature: criteria V3 to V6 of ADR 0003. | `InvalidSignature` |

13. With `d = 0`, C1 rejects nothing. `sbtp-core` takes `d` as a parameter. The difficulty is the only local
    parameter of validation (`[Q-06]`).

### Check on receipt of a requested block

14. When a block is received in response to a request by identifier (ADR 0003, rule 11), one check is added
    between F9 and C1:

    | Order | Rejection condition | Suggested variant |
    |---|---|---|
    | R1 | The computed `block_id` differs from the requested identifier. | `BlockIdMismatch { expected, actual }` |

    R1 does not apply to a `PUT`: no identifier is expected there.

### Full list of variants

`TooShort`, `TooLong`, `BadMagic`, `UnsupportedVersion`, `TooManyParents`, `Truncated`, `TrailingBytes`,
`DuplicateParent`, `BlockIdMismatch`, `InsufficientPow`, `InvalidPublicKey`, `InvalidSignature`. That is
12 variants for 13 checks. Every new rejection rule MUST go through an ADR and add its variant.

### HTTP codes (pending Q-08 and Q-09)

15. F1 to F9 and C1: `400 Bad Request`. C2 and C3: `422 Unprocessable Entity`. This is the direct
    application of the current §4. Q-09 recommends `413` for F2.

## Consequences

- **Binary layout: `layout.rs` is touched.** No offset changes, but the maximum block size goes from 73,813
  to 66,133 bytes. To be changed by the implementer in `crates/sbtp-core/src/layout.rs`:
  - line 51: `RECOMMENDED_MAX_PARENTS: u8 = 15` becomes a format limit (suggested name: `MAX_PARENTS`), and
    its comment "recommended maximum" must be corrected;
  - lines 57 to 59: `MAX_BLOCK_LEN` is computed with `u8::MAX` parents; it must be computed with
    `MAX_PARENTS`, that is `52 + 15·32 + 2 + 65,535 + 64 = 66,133`;
  - `size_bounds` test (lines 105 and 107): `assert_eq!(MAX_BLOCK_LEN, 73_813)` and
    `block_len(u8::MAX, u16::MAX)` must be replaced by 66,133 and `block_len(MAX_PARENTS, u16::MAX)`.

  `MIN_BLOCK_LEN` (118), the fixed offsets and the functions `payload_len_offset`, `payload_offset`,
  `signature_offset` and `block_len` remain valid.
- **Relay.** The maximum size of a `PUT` body is 66,133 bytes. The relay has no setting for the number of
  parents.
- **F2 is redundant with F8** for a decoder that receives a complete buffer (beyond 66,133 bytes, the length
  cannot be exact). It is kept as a separate rule: a relay must be able to refuse an over-long body before
  reading all of it.
- **Cost of F9.** Comparison of all pairs with no allocation: at most `15·14/2 = 105` comparisons of
  32 bytes, since F5 is placed before F9.
- **Test vectors.** At least one vector per variant, with the variant name in `expect.error`. Unless stated
  otherwise, a vector is evaluated with `d = 0`. Cases to add to the list in `docs/test-vectors/README.md`:
  empty buffer; 117 and 118 bytes; 66,133 bytes (valid) and 66,134 bytes; 15 parents (valid), 16 parents and
  255 parents (`TooManyParents`); truncation in the middle of the parents (F6) and in the middle of the
  payload (F7); one extra byte; adjacent and non-adjacent duplicates; zero parent (valid); valid block with a
  different requested identifier (R1). Signature vectors are listed in ADR 0003.
- **Compatibility.** No block or vector exists. The limit can be raised by a later version of the format; a
  v1 decoder then rejects those blocks through F4, uniformly.
- **Upper layers.** A block cannot merge more than 15 DAG heads. A wider merge requires intermediate blocks.
- **Security.** The order F1 to F8 guarantees that no computed offset is read outside the buffer. The
  `decode_block` fuzz target must check that no input causes a panic and that every accepted block
  re-encodes identically.

## Rejected alternatives

- **Parent limit as a relay policy** (format from 0 to 255, configurable `max_parents`, 15 by default). The
  validity of a block would depend on the relay: a 20-parent block accepted here and refused there leaves
  holes in the DAG during gossip, and its descendants become orphans on part of the network. The limit can
  be relaxed later through the version byte, for everyone at once.
- **No limit, 255 everywhere.** A 255-parent block costs 8,160 bytes and 32,385 duplicate comparisons before
  the PoW, with no identified need from the upper layers.
- **Tolerate trailing bytes.** Creates several byte sequences for the same block and a channel of unsigned,
  unhashed data.
- **Ignore an unknown version or try to decode it.** A v1 decoder knows neither the layout nor the bytes
  covered by the hash of another version.
- **Accept duplicate parents.** Two encodings for the same set of edges, and a way to inflate a block with
  no information.
- **Require sorted parents** (check in `N − 1` comparisons, duplicates detected along the way). Destroys the
  order, which layer 2 uses.
- **A single `InvalidLength` variant.** Does not distinguish truncation from trailing bytes; contrary to the
  "one variant per rule" rule.
- **Check that parents exist.** Requires state; contrary to the stateless validation principle.

## Spec change

To apply to `docs/spec/sbtp-core-v0.2.md` after acceptance.

**§2, table.** Replace the Parents Count row with:

```markdown
| Parents Count | 1 | u8 | Number N of parents, from 0 to 15. Values 16 to 255 are reserved (§2.2). |
```

**§2, after the table.** Replace the sentence "Block size: from 118 bytes (0 parents, empty payload) to
73,813 bytes (255 parents, max payload)." with:

```markdown
Block size: from 118 bytes (0 parents, empty payload) to 66,133 bytes (15 parents, max payload).
```

**§2.1.** Delete the last paragraph ("A decoder MUST reject any block whose total length… `[Q-10]`").

**New §2.2,** after §2.1:

```markdown
### 2.2 Format validation

A block that passes the checks below is well-formed. Format validity is the same for every implementation:
no check depends on a local configuration. The checks MUST be done in this order; the first one that fails
determines the error. A decoder MUST NOT read a byte before checking that the buffer contains it. `len` is
the buffer length, `N` the Parents Count field, `P` the Payload Len field.

| Order | Rejection condition | Error |
|---|---|---|
| F1 | `len < 118`. | `TooShort` |
| F2 | `len > 66,133`. | `TooLong` |
| F3 | Magic differs from `0x53 0x42`. | `BadMagic` |
| F4 | Version differs from `0x01`. | `UnsupportedVersion` |
| F5 | `N > 15`. | `TooManyParents` |
| F6 | `len < 118 + 32·N`. | `Truncated` |
| F7 | `len < 118 + 32·N + P`. | `Truncated` |
| F8 | `len > 118 + 32·N + P`. | `TrailingBytes` |
| F9 | Two identical parent hashes, at any positions. | `DuplicateParent` |

- **Parent limit.** A block MUST have from 0 to 15 parents. An implementation MUST NOT make this limit
  configurable. Raising it requires a new value of the Version field.
- **Parent order.** It is significant and kept. A decoder MUST NOT require sorting or reorder.
- **Well-formed cases.** A decoder MUST NOT reject on format grounds: `N = 0`; `P = 0`; a parent unknown to
  it; a parent of any value, zero included; any value of Timestamp (`[Q-07]`) or Nonce; any payload content.

After the format, validation MUST continue in this order:

| Order | Rejection condition | Error |
|---|---|---|
| C1 | Insufficient proof of work (§3.3). | `InsufficientPow` |
| C2 | Invalid PubKey (§3.2, V1 and V2). | `InvalidPublicKey` |
| C3 | Invalid signature (§3.2, V3 to V6). | `InvalidSignature` |

For a block received in response to a request by identifier (§3.4), one check is added between F9 and C1:
the computed `block_id` MUST equal the requested identifier, otherwise `BlockIdMismatch`.

Every new rejection rule goes through an ADR. (ADR 0004)
```

**§4, `PUT /sbtp/v1/block`.** Replace steps 1 to 3 of the processing and the "Responses" line with:

```markdown
  1. format: checks F1 to F9 (§2.2);
  2. PoW difficulty on the `block_id`: check C1;
  3. Ed25519 signature: checks C2 and C3;
```

```markdown
- Responses: `201 Created`; `400 Bad Request` (F1 to F9, C1); `422 Unprocessable Entity` (C2, C3).
  A block already present: `[Q-09]`.
```
