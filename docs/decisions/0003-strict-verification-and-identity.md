# 0003: Strict Ed25519 verification and block identity by `block_id`

- Status: accepted (by the project owner, 2026-11-18)
- Date: 2026-11-18
- Questions: Q-05
- Impact: spec §3.2, new §3.4, §4 (`PUT`, `GET`); `sbtp-core` (verification, error variants, check of the
  received identifier), `sbtp-relay` (idempotent storage, self-test at startup), clients and peers (check on
  receipt); test vectors for invalid signatures
- Review: docs/security/2026-11-18-adr-0002-0003.md

## Context

The `block_id` does not cover the 64 signature bytes. Two different byte sequences can therefore carry the
same `block_id` if two valid signatures exist for the same content.

Three possible sources:

1. **Third-party malleability.** A lax verification accepts `S + L` in place of `S`, `R` points with a
   torsion component, or non-canonical encodings. A third party can then forge a variant of a block without
   knowing the private key.
2. **Weak keys.** A small-order public key accepts valid signatures for almost any message.
3. **Non-deterministic signer.** The holder of the private key can always produce several valid signatures
   of the same message. No verification rule prevents it.

The v0.2-draft only says that verification "SHOULD be strict". Two implementations with different criteria
do not accept the same set of blocks: the network partitions on edge cases.

In addition, nothing currently requires the recipient of a `GET` to check that the received block carries
the requested identifier. A hostile relay can answer with another valid block.

### Verified APIs (docs.rs, source of `ed25519-dalek` 3.0.0, on 2026-11-18)

```rust
impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError>
    pub fn is_weak(&self) -> bool
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError>
}
```

None of these three methods depends on a Cargo feature. Findings, read in the source (`verifying.rs`,
`signature.rs`):

| Check | `verify` (trait `Verifier`) | `verify_strict` |
|---|---|---|
| `S < L` (`Scalar::from_canonical_bytes`) | yes | yes |
| `R` decodes to a point | not required | yes |
| small-order `R` rejected (`is_small_order`) | no | yes |
| small-order public key rejected | no | yes |
| cofactorless equation, recomputed `R` compared **byte for byte** | yes | yes |
| non-canonical `R` rejected (consequence of the byte comparison) | yes | yes |

Points to watch:

- `VerifyingKey::from_bytes` validates the point "under ZIP-215 rules": it accepts a non-canonical encoding
  of the `y` coordinate (`y ≥ 2^255 − 19`). The documentation states that the RFC 8032 / NIST criteria are
  not supported. The rejection required by V1 therefore needs an extra check (rule 13).
- The `legacy_compatibility` feature of `ed25519-dalek` replaces the `S < L` check with a test of the three
  most significant bits. It makes signatures malleable.
- `verify_strict` is documented as "technically non-RFC8032 compliant": it is stricter than the RFC minimum,
  which is the intended effect.

Points established by the security review (reading the source of the published crates, without compiling):

- `Signature::from_bytes(&[u8; 64]) -> Signature` (crate `ed25519` 3.0.0) is infallible and validates
  nothing: every check is done by `verify_strict`.
- `VerifyingKey::to_edwards()` exists in 3.0.0 and enables the recompression of rule 13.
- `verify_batch` (feature `batch`) **is not equivalent** to `verify_strict`: it decompresses `R` instead of
  comparing bytes, tests small order on neither `R` nor `A`, and its verdict on a torsion component depends
  on random coefficients.
- The `legacy_compatibility` feature of `curve25519-dalek` alone does not weaken V3; the one in
  `ed25519-dalek` does.

**Not verified.** Nothing was compiled or run (no Rust toolchain on the workstation). No vector was passed
through `verify_strict`: the Phase 1 negative vectors will be the proof. The `cargo deny` syntax for banning
a feature is not verified.

## Decision

### Verification criteria

1. Strict verification is mandatory. Let `M` be the signed message (ADR 0002), `A` the PubKey field, `R` the
   first 32 bytes of the signature and `S` the last 32, read as a little-endian integer (RFC 8032). A
   verifier MUST reject the block if any of the following conditions is true:

   | # | Rejection condition |
   |---|---|
   | V1 | `A` is not the canonical encoding of a point on the curve (RFC 8032 §5.1.3 decoding). Rejected: `y ≥ 2^255 − 19`; `y` not on the curve; `x = 0` with the sign bit set to 1. |
   | V2 | `A` is of small order (`[8]A` is the identity element). |
   | V3 | `S ≥ L`, with `L = 2^252 + 27742317777372353535851937790883648493`. |
   | V4 | `R` does not decode to a point on the curve. |
   | V5 | `R` is of small order. |
   | V6 | The canonical encoding of the point `[S]B − [k]A` differs from `R` byte for byte, with `k = SHA-512(R ‖ A ‖ M) mod L`. |

2. In V6, `R` and `A` enter SHA-512 as received. The digest is read as a 512-bit little-endian integer,
   then reduced modulo `L` before the multiplication.
3. V6 is the cofactorless equation. It implies the rejection of any non-canonical `R`. A verifier MUST NOT
   use the cofactored equation (`[8][S]B = [8]R + [8][k]A`).
4. Batch verification MUST NOT be used to validate a block. Each signature is verified on its own, according
   to V1 to V6.

### Signature

5. A sender SHOULD sign deterministically (RFC 8032 §5.1.6).
6. A sender SHOULD NOT publish two different signatures for the same `block_id`.
7. A layer (0, 1 or 2) MUST NOT make any state depend on the signature bytes of a block (sorting, random
   selection, deduplication).

### Block identity

8. A block is identified by its `block_id` alone. Two valid byte sequences with the same `block_id` are the
   same block. They can differ only in the 64 signature bytes.
9. Storage is idempotent, "first write wins" rule: a relay that receives a valid block whose `block_id` is
   already stored MUST NOT replace the stored bytes. It answers as for a block already present (`[Q-09]`).
   The rule applies only to fully validated bytes.
10. A relay validates the received block (format, PoW, signature) before storing it. A duplicate whose
    signature is invalid is rejected like any invalid block. Allowed shortcut: after format and PoW, if the
    `block_id` is already stored **and** the received bytes are identical to the stored bytes, the relay
    MAY answer "already present" without re-verifying the signature. If the bytes differ, it MUST verify
    the signature.
11. Every recipient of a block requested by its identifier (client, peer, cache) MUST, before any storage or
    use: recompute the `block_id` of the received bytes; reject the block if this `block_id` differs from
    the requested identifier; apply full validation, criteria V1 to V6 included.
12. An implementation MUST NOT identify, deduplicate or reference a block by a hash of its full bytes,
    signature included. Synchronisation (§5) compares `block_id` values.

### Reference implementation

13. `sbtp-core` MUST verify as follows, in this order:
    1. `VerifyingKey::from_bytes(&pubkey)`; failure: V1;
    2. recompression: `key.to_edwards().compress().as_bytes() != &pubkey`; true: V1;
    3. `VerifyingKey::is_weak()`; true: V2;
    4. `VerifyingKey::verify_strict(&message, &signature)`; failure: V3 to V6.
14. `ed25519_dalek::verify_batch` MUST NOT be called, and the `batch` feature of `ed25519-dalek` MUST NOT be
    enabled in the workspace.
15. The `legacy_compatibility` feature of `ed25519-dalek` MUST NOT be enabled, in any crate of the workspace
    or by a transitive dependency. Cargo unifies features: a single activation in the graph is enough to
    weaken V3 everywhere. As a precaution, the one in `curve25519-dalek` MUST NOT be enabled either.
16. The check for rule 15 is executable. A negative test vector "`S + L`" (a valid signature whose `S` is
    replaced by `S + L`; expected: `InvalidSignature`) is mandatory. It MUST be run by
    `cargo test --workspace` and by every shipped binary: the relay replays it at startup and MUST refuse to
    start if the vector is accepted. A `cargo deny` rule on the feature is a complement; it does not replace
    the vector.

## Consequences

- **Binary layout.** No size or offset changes. `layout.rs` is not touched.
- **Interoperability.** Criteria V1 to V6 are stated without reference to a library. A third-party
  implementation must check them one by one: many Ed25519 libraries apply laxer criteria by default
  (cofactor, small-order keys accepted). A web client MUST validate through `sbtp-wasm` and not through
  `crypto.subtle.verify`, whose criteria are not guaranteed to be identical from one browser to another (not
  tested here).
- **Residual malleability.** Under V1 to V6, a third party cannot derive a second valid signature from an
  existing one. Only the holder of the private key can produce two signatures of the same `block_id`.
  Rule 9 makes this case harmless: relays may store different signature bytes, but the `block_id`, the
  content and the author are identical. Rule 6 is a SHOULD: a validator cannot detect the violation, and a
  randomised signer (HSM) can re-sign in good faith.
- **Non-canonical PubKey.** Mandatory rejection (V1), variant `InvalidPublicKey`. The review counts
  26 non-canonical encodings: 6 of small order, 20 denoting points with no known discrete logarithm. No
  valid block can carry such a key; the rule therefore does not change the set of accepted blocks. It fixes
  the returned error, aligns V1 with RFC 8032 and makes the case testable by a vector. Cost: one point
  compression per verification.
- **No batch verification.** A relay verifies each signature on its own. The throughput gain of batches is
  lost. This can be revisited by a new ADR, with a batch variant proven equivalent to V1-V6 and covered by
  the same vectors.
- **`legacy_compatibility` and "first write wins".** If the feature is silently enabled on a relay, a third
  party can deposit `(R, S + L)` there before the original; rule 9 then freezes bytes that every strict
  client rejects. Rule 16 turns this risk into a refusal to start.
- **Block substituted by a relay.** A relay can serve only invalid bytes or another block. Both cases are
  detected by rule 11. Without it, a client would file arbitrary content under the identifier of a parent.
- **Replay of an already stored block.** The shortcut of rule 10 avoids one Ed25519 verification per replay.
  The observable behaviour is unchanged. Rate limiting remains the main defence.
- **Error variants** (ADR 0004): `InvalidPublicKey` for V1 and V2, `InvalidSignature` for V3 to V6,
  `BlockIdMismatch` for rule 11. `ed25519-dalek` returns an opaque error: V3 to V6 cannot be told apart
  without rewriting the verification, which is ruled out.
- **Test vectors.** At a minimum: one case per criterion V1 to V6; non-canonical PubKey (of small order and
  not); `S + L` (rule 16); mixed-order PubKey with a valid signature (accepted; pins the "mod L" of V6);
  valid block paired with a different requested identifier (`BlockIdMismatch`). The C2SP CCTV
  `ed25519vectors` cover free-form messages: equivalent SBTP blocks must be built.
- **Cost.** Two small-order tests (three point doublings each) and one extra compression per verification.
  Negligible next to the double scalar multiplication.
- **Supply chain.** Out of scope, handled by the maintainer (finding B-4 of the review): `zeroize` and
  `fast` features, `Cargo.lock`.

## Rejected alternatives

- **Minimal RFC 8032 verification (`verify`).** Accepts small-order keys and torsion `R` values.
  Third-party implementations diverge precisely on these cases.
- **ZIP-215 criteria.** Well specified and compatible with batch verification, but designed to accept as
  many signatures as possible (cofactor, non-canonical encodings, small order). That is the opposite of the
  need: here malleability affects the identity of the stored bytes.
- **Batch verification allowed "if the verdict is identical".** First draft of this ADR. The condition
  cannot be checked by an implementer, and the only available variant (`verify_batch`) does not meet it:
  the same block is accepted or rejected depending on the composition of the batch.
- **Also require a PubKey with no torsion component.** Costs one scalar multiplication per verification.
  Only the sender can forge a mixed-order key, and the verdict stays deterministic under V1 to V6.
- **Include the signature in the `block_id`.** Removes all byte ambiguity, but mining would have to re-sign
  at each nonce, and the PoW could no longer be checked before the signature in the relay pipeline.
- **Two identifiers (content, and content + signature).** Doubles the protocol surface for a case only the
  author can cause.
- **Require deterministic signing, or uniqueness of the published signature (MUST).** Cannot be checked by
  a validator: a signature with chosen randomness is indistinguishable from a deterministic one.
- **Non-canonical PubKey left as a MAY.** First draft of this ADR. No effect on the set of accepted blocks,
  but the returned error depended on the library, and V1 contradicted the RFC it cited.
- **Checking `legacy_compatibility` with `cargo deny` alone.** Declarative, and no effect against a
  regression in the crate itself.

## Spec change

To apply to `docs/spec/sbtp-core-v0.2.md` after acceptance (and after ADR 0002, which defines `M`).

**§3.2.** Replace the "Verification" bullet with:

```markdown
- Verification: strict and mandatory. Let `A` be the PubKey field, `R` the first 32 bytes of the signature
  and `S` the last 32 (little-endian integer, RFC 8032). A verifier MUST reject the block if any of the
  following conditions is true:

  | # | Rejection condition |
  |---|---|
  | V1 | `A` is not the canonical encoding of a point on the curve (RFC 8032 §5.1.3 decoding). Rejected: `y ≥ 2^255 − 19`; `y` not on the curve; `x = 0` with the sign bit set to 1. |
  | V2 | `A` is of small order (`[8]A` is the identity element). |
  | V3 | `S ≥ L`, with `L = 2^252 + 27742317777372353535851937790883648493`. |
  | V4 | `R` does not decode to a point on the curve. |
  | V5 | `R` is of small order. |
  | V6 | The canonical encoding of `[S]B − [k]A` differs from `R` byte for byte, with `k = SHA-512(R ‖ A ‖ M) mod L`. |

  In V6, `R` and `A` enter SHA-512 as received; the digest is read as a 512-bit little-endian integer, then
  reduced modulo `L`. V6 is the cofactorless equation; the cofactored equation MUST NOT be used. Batch
  verification MUST NOT be used to validate a block.
- A sender SHOULD sign deterministically (RFC 8032 §5.1.6) and SHOULD NOT publish two different signatures
  for the same `block_id`. A layer MUST NOT make any state depend on the signature bytes (sorting, random
  selection, deduplication). (ADR 0003)
```

**New §3.4,** after §3.3:

```markdown
### 3.4 Block identity

A block is identified by its `block_id` alone. The `block_id` does not cover the signature: two valid byte
sequences with the same `block_id` are the same block and can differ only in their 64 signature bytes. Under
the strict verification of §3.2, only the holder of the private key can produce such a variant.

- **Storage.** It is idempotent, "first write wins" rule: a valid block whose `block_id` is already stored
  MUST NOT replace the stored bytes. The rule applies only to fully validated bytes.
- **Replayed block.** If the `block_id` is already stored and the received bytes are identical to the stored
  bytes, signature verification MAY be skipped. If the bytes differ, it MUST be done.
- **Receipt.** Every recipient of a block requested by its identifier (client, peer, cache) MUST, before any
  storage or use: recompute the `block_id` of the received bytes; reject the block if this `block_id`
  differs from the requested identifier (`BlockIdMismatch`); apply full validation (§2.2), criteria V1 to V6
  included.
- **Full bytes.** An implementation MUST NOT identify, deduplicate or reference a block by a hash of its full
  bytes. Two relays may return different bytes for the same `block_id`. (ADR 0003)
```

**§4, `PUT /sbtp/v1/block`.** Replace step 4 of the processing with:

```markdown
  4. storage addressed by the `block_id`, without replacing a block already present (§3.4).
```

**§4, `GET /sbtp/v1/block/{block_id}`.** Add a bullet:

```markdown
- The recipient MUST check that the received block carries the requested `block_id` and validate it (§3.4).
```

**§5, step 4.** Replace "each received block is validated independently" with:

```markdown
each received block is compared with the requested identifier then validated independently (§3.4)
```
