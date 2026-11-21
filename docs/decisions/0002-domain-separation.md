# 0002: Domain separation of the `block_id` and the signature

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0010 (rule 10, layer-1 chunk_id); 0016 (rule 12, registry rows for layer 2 strings); 0055,
  accepted 2026-11-21 (rule 8 extended to every signature prefix of the registry)
- Date: 2026-11-18
- Questions: Q-04
- Impact: spec §2 (Signature row), §3.1, §3.2, new §3.5; `sbtp-core` (`block_id` computation, signing,
  verification, two new constants); all test vectors (none exist yet)
- Review: docs/security/2026-11-18-adr-0002-0003.md

## Context

The v0.2-draft defines `block_id = BLAKE3(bytes)` and signs the 32 raw bytes of the `block_id`.

Two risks follow:

1. An Ed25519 key also used in another protocol that signs 32-byte values (a hash, an authentication
   challenge) can produce, at a third party's request, a valid signature for an SBTP block. Conversely, an
   SBTP signature can be replayed in that other protocol.
2. A `block_id` is indistinguishable from any other BLAKE3 hash of the same content (content-addressed
   storage, file checksum).

The decision must be frozen before the first test vectors: it changes every `block_id` and every signature.

### Verified APIs (docs.rs, on 2026-11-18)

`blake3` 1.8.7 (released 2026-08-20):

```rust
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32]
pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash
// incremental form
pub fn Hasher::new_derive_key(context: &str) -> Self
pub fn Hasher::new_keyed(key: &[u8; 32]) -> Self
pub fn Hasher::update(&mut self, input: &[u8]) -> &mut Self
pub fn Hasher::finalize(&self) -> Hash
```

The documentation of `derive_key` and `Hasher::new_derive_key` requires: "The context string should be
hardcoded, globally unique, and application-specific", and recommends the format "application name, date,
purpose", with the example `example.com 2019-12-25 16:18:03 session tokens v1`. It states that
`Hasher::new_derive_key` + `update` + `finalize` gives the same result as `derive_key`.

`ed25519-dalek` 3.0.0 (released 2026-07-06): the Ed25519 context is exposed only for Ed25519ph
(`VerifyingKey::with_context`, `verify_prehashed`, feature `digest`). The Ed25519ctx variant of RFC 8032
does not appear in the public API reviewed.

**Not confirmed.** The `blake3` documentation does not say explicitly that `key_material` may be public data
chosen by a third party. Using `derive_key` as a domain-separated hash relies on the design of BLAKE3: the
`derive_key` mode is separated from the `hash` and `keyed_hash` modes by internal flags, and keeps collision
resistance. This point must be confirmed by the security reviewer against the BLAKE3 paper before acceptance.
`no_std` compilation of `blake3` with `default-features = false` is not confirmed by the documentation (only
the `std` feature, on by default, is described); it could not be tested, as the Rust toolchain is not
installed on the workstation.

**After security review.** Using `derive_key` on public, hostile data is confirmed by analysis of the BLAKE3
paper (§2.3, §4.1, §4.3, §6.2), without a literal quote. `no_std` support in `blake3` is confirmed by
reading the source, not by compiling. The absence of Ed25519ctx in `ed25519-dalek` 3.0.0 is confirmed. The
`derive_key` mode is confirmed present in the sources of `noble-hashes`, `lukechampine/blake3`,
`zeebo/blake3` and `blake3` for Python.

## Decision

### `block_id`

1. The `block_id` MUST be computed with the BLAKE3 key derivation mode (`derive_key`), 32-byte output:

   ```
   block_id = BLAKE3_derive_key(context = BLOCK_ID_CONTEXT, key_material = block[0 .. Offset(Signature)])
   ```

2. `BLOCK_ID_CONTEXT` is the 27-byte ASCII string, with no terminator:

   ```
   SBTP 2026-11-18 block_id v1
   ```

   Byte by byte (hexadecimal):

   ```
   53 42 54 50 20 32 30 32 36 2d 31 31 2d 31 38 20 62 6c 6f 63 6b 5f 69 64 20 76 31
   ```

3. The hashed bytes are unchanged: the whole block except the 64 signature bytes.
4. Parent hashes and the proof of work (§3.3) apply to this `block_id`.

### Signature

5. The signed message MUST be the concatenation of `SIG_PREFIX` and the `block_id`, 49 bytes in total:

   ```
   Signature = Ed25519_Sign(sk, SIG_PREFIX ‖ block_id)
   ```

6. `SIG_PREFIX` is the 17-byte ASCII string, with no terminator:

   ```
   SBTP-v1-block-sig
   ```

   Byte by byte (hexadecimal):

   ```
   53 42 54 50 2d 76 31 2d 62 6c 6f 63 6b 2d 73 69 67
   ```

7. The algorithm is "pure" Ed25519 (RFC 8032 §5.1), with no prehashing and no context parameter.
8. An implementation MUST NOT use an SBTP key to sign a message that starts with `SIG_PREFIX` and is not a
   block signature message.

### Evolution

9. The `v1` suffix of both strings corresponds to the Version field `0x01`. Every new value of the Version
   field MUST define new strings, unconditionally. A published string never changes and is never reused for
   another purpose.
10. Every new use of BLAKE3 or Ed25519 in SBTP (layers 1 and 2 included) MUST use a context string distinct
    from these two.
11. An SBTP signature prefix MUST NOT be a prefix of another SBTP signature prefix. The signed message has
    neither a length field nor a terminator: separation between uses relies on the prefix alone.
12. The spec MUST keep the list of every context string and every signature prefix defined by SBTP.

## Consequences

- **Binary layout.** No size or offset changes: the `block_id` stays 32 bytes (`HASH_LEN`), the signature
  64 bytes. The constants in `layout.rs` remain valid. To be added by the implementer:
  `BLOCK_ID_CONTEXT: &str`, `SIG_PREFIX: [u8; 17]`, `SIGNED_MESSAGE_LEN: usize = 49`. The comment
  `signature  Ed25519(block_id)` (line 14) becomes inaccurate.
- **Rust implementation.** `blake3::Hasher::new_derive_key(BLOCK_ID_CONTEXT)`, then `update` on the buffer
  view, then `finalize`: no copy of the block. The signed message fits in a `[u8; 49]` array on the stack:
  no allocation.
- **Cost.** `derive_key` first hashes the context string (one extra compression per call). A miner MAY build
  the `Hasher` once and clone it. The signature overhead is 17 bytes hashed by SHA-512.
- **Interoperability.** A third-party implementation needs the BLAKE3 `derive_key` mode. It is part of the
  BLAKE3 specification and of its reference implementations (Rust, C). Its presence in each third-party
  library (JavaScript, Go, Python) must be checked case by case. Test vectors SHOULD include the
  intermediate `block_id` and signed message.
- **Security.** An SBTP block signature is valid in no protocol that signs a raw 32-byte hash, and vice
  versa. The protection does not cover a third-party protocol that would sign arbitrary bytes supplied by an
  attacker: reusing an SBTP key outside SBTP remains discouraged.
- **Future prefixes.** Without rule 11, a prefix `SBTP-v1-block-sig-ack` followed by bytes chosen by a third
  party could form a 49-byte message that would also be a valid block signature. Rule 8 forbids this to the
  implementation; rule 11 forbids it to the design.
- **Compatibility.** No block or vector exists. The Version field stays `0x01`.

## Rejected alternatives

- **`BLAKE3(bytes)` with no context, signature over the raw `block_id` (status quo).** Leaves both risks
  from the context open.
- **`keyed_hash` mode with a fixed, public 32-byte key.** Equivalent in security, but the key is an
  arbitrary constant to publish and copy. `keyed_hash` is documented as a message authentication code, not
  as a domain separator. `derive_key` takes a readable string, and that is the use its documentation
  describes.
- **Prefix in `hash` mode: `BLAKE3(prefix ‖ bytes)`.** Works with any BLAKE3 library, but it is an
  SBTP-specific convention, with no separation at the primitive level. To adopt only if the `derive_key`
  mode is missing from a target library deemed essential.
- **Ed25519ctx (RFC 8032 §5.1, native context).** This is the standard construction for this need, but it
  is not exposed by `ed25519-dalek` 3.0.0 and it is absent from most libraries (WebCrypto included).
  Interoperability wins.
- **Ed25519ph with context.** Available in `ed25519-dalek` (feature `digest`), but forces a SHA-512 prehash
  of the message, useless here (the message is 49 bytes), and remains uncommon.
- **Separation on the hash only, signature over the raw `block_id`.** The `block_id` is then SBTP-specific,
  but a third-party protocol that signs a 32-byte challenge supplied by an attacker would produce a valid
  block signature. The signature prefix costs 17 hashed bytes.
- **Sign the block bytes directly instead of the `block_id`.** Doubles the hashing of the payload (BLAKE3
  for the `block_id`, SHA-512 for the signature) with no benefit.

## Spec change

To apply to `docs/spec/sbtp-core-v0.2.md` after acceptance.

**§2, table.** Replace the Signature row with:

```markdown
| Signature | 64 | bytes | Ed25519 signature (§3.2). |
```

**§3.1.** Replace the whole content of the section with:

````markdown
```
block_id = BLAKE3_derive_key( BLOCK_ID_CONTEXT, fixed_header ‖ parents_hashes ‖ payload_len ‖ payload )
```

The `block_id` MUST be computed with the BLAKE3 key derivation mode (`derive_key`), 32-byte output. The
input (`key_material`) covers the whole block except the 64 signature bytes, that is
`block[0 .. Offset(Signature)]`.

`BLOCK_ID_CONTEXT` is the 27-byte ASCII string, with no terminator:

```
SBTP 2026-11-18 block_id v1
53 42 54 50 20 32 30 32 36 2d 31 31 2d 31 38 20 62 6c 6f 63 6b 5f 69 64 20 76 31
```

This string is bound to the Version field `0x01`. It MUST NOT be used for any other purpose. Every new value
of the Version field MUST define new strings. (ADR 0002)
````

**§3.2.** Replace the first two bullets (Algorithm, Signature) with:

````markdown
- Algorithm: pure Ed25519 (RFC 8032 §5.1), with no prehashing and no context parameter.
- Signed message: `M = SIG_PREFIX ‖ block_id` (49 bytes). `SIG_PREFIX` is the 17-byte ASCII string, with
  no terminator:

  ```
  SBTP-v1-block-sig
  53 42 54 50 2d 76 31 2d 62 6c 6f 63 6b 2d 73 69 67
  ```

- Signature: `Signature = Ed25519_Sign(sk, M)`. An SBTP key MUST NOT sign a message that starts with
  `SIG_PREFIX` and is not a block signature message. (ADR 0002)
````

**New §3.5,** after the §3.4 created by ADR 0003:

```markdown
### 3.5 Registry of domain separation strings

| String | Use | Version |
|---|---|---|
| `SBTP 2026-11-18 block_id v1` | BLAKE3 `derive_key` context of the `block_id` (§3.1) | `0x01` |
| `SBTP-v1-block-sig` | prefix of the signed message (§3.2) | `0x01` |

- Every new use of BLAKE3 or Ed25519 in SBTP, all layers included, MUST use a distinct string and add it to
  this table.
- Every new value of the Version field MUST define new strings.
- A signature prefix MUST NOT be a prefix of another. A published string never changes and is never reused.
  (ADR 0002)
```

In the third bullet (Verification), replace `Ed25519_Verify(PubKey, block_id, Signature)` with
`Ed25519_Verify(PubKey, M, Signature)`. The rest of that bullet belongs to ADR 0003.
