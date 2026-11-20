# 0010: Media chunks are raw BLAKE3 blobs outside the SBTP envelope

- Status: accepted (by the project owner, 2026-11-18)
- Date: 2026-11-18
- Decision: project owner, 2026-11-18
- Questions: Q-01 (partially); opens Q-21
- Amends: ADR 0002 rule 10, for the layer 1 `chunk_id` only
- Impact: `docs/spec/architecture.md` §1 (layer 1); spec §2 (Payload Len row), §3.5 (registry);
  the layer 2 payload specification of the time (`media.manifest`); future layer 1 crate; `sbtp-relay` only if it
  serves chunks (Q-21); no `sbtp-core` change; layer 1 test vectors to create

## Context

Layer 1 splits files into 256 KiB chunks (`chunk_size: 262144` in `media.manifest`). An SBTP payload holds
at most 65,535 bytes (Payload Len is a u16). A chunk does not fit in a block (Q-01).

Putting a chunk in several blocks would cost, for each 64 KiB, a header, a signature and a proof of work,
for data that is already authenticated by its hash.

ADR 0002 rule 10 (accepted) says: "Every new use of BLAKE3 or Ed25519 in SBTP (layers 1 and 2 included)
MUST use a context string distinct from these two." A chunk identified by a plain BLAKE3 hash has no
context string. The owner chose between three hash modes ("Rejected alternatives") and decided for the
plain mode.

## Decision

1. A chunk is a raw byte sequence of 1 to 262,144 bytes (256 KiB). It is not an SBTP block: it has no
   header, no signature, no proof of work, no parents. It is not subject to spec §2.
2. Every chunk of an object except the last MUST be exactly 262,144 bytes. The last chunk is 1 to 262,144
   bytes. An object of length zero has no chunk.
3. A chunk is identified by its `chunk_id`, the standard BLAKE3 hash of its bytes: `hash` mode, no key, no
   context string, 32-byte output.

   ```
   chunk_id = BLAKE3( chunk bytes )
   ```

4. A chunk is referenced by a manifest. A manifest is carried in the payload of an SBTP block: it is
   signed, mined and identified by its `block_id` like any block. The manifest gives the ordered list of
   `chunk_id` values of the object.
5. The recipient of a chunk requested by its `chunk_id` MUST recompute the BLAKE3 hash of the received
   bytes and MUST reject the chunk if the result differs from the requested `chunk_id`, or if the chunk is
   longer than 262,144 bytes. It MUST do so before any storage or use.
6. A chunk carries no authorship. Authorship and time come only from the manifest block that references
   it. An implementation MUST NOT attribute a chunk to a key outside a manifest.
7. Layer 0 is unchanged: the maximum payload stays 65,535 bytes, a relay validates blocks without knowing
   chunks, and the `block_id` keeps the `derive_key` mode of ADR 0002. Layer 0 MUST NOT use the BLAKE3
   `hash` mode.

### Amendment of ADR 0002 rule 10

8. This ADR amends ADR 0002 rule 10 for the layer 1 `chunk_id` only: the `chunk_id` is the single SBTP use
   of BLAKE3 with no context string.
9. The BLAKE3 `hash` mode is reserved to the `chunk_id`. No other SBTP use, in any layer, may hash in this
   mode. Every other new use of BLAKE3 or Ed25519 stays under rule 10 (distinct context string).
10. The `hash` mode is entered in the registry of spec §3.5 as a use of its own.
11. The `chunk_id` is not bound to the Version field of the block format. ADR 0002 rule 9 is not concerned:
    it applies to strings, and the `chunk_id` has none.

## Justification

**Owner's stated rationale.** A raw chunk and an SBTP block are structurally different objects.

**Normative justification.** Structure is not the argument: a chunk may contain any bytes, including
exactly the bytes hashed for a block, or a whole block. What prevents a `chunk_id` from being confused with
a `block_id` is the hash mode.

- A `block_id` is `BLAKE3_derive_key("SBTP 2026-11-18 block_id v1", …)`. A `chunk_id` is `BLAKE3(…)` in
  `hash` mode. BLAKE3 separates its modes by flags present in every compression, and `derive_key` by a key
  derived from the context. The security review confirmed this against the BLAKE3 paper (§2.3, §4.1, §4.3;
  `docs/security/2026-11-18-adr-0002-0003.md`, info point 1), and noted: "Blobs would be addressed by
  plain BLAKE3: a `block_id` can then never be confused with a blob hash."
- Bytes `X` and `Y` with `BLAKE3(X) = block_id(Y)`, `X = Y` included, are a collision between two
  independent 256-bit functions: about `2^128` work.
- The separation is cryptographic. It does not rely on endpoints: identifiers travel inside payloads,
  caches and peer messages, where nothing ties an identifier to an endpoint.
- BLAKE3 has no length extension, and interior tree values are not root outputs: a chunk cannot stand for
  a subtree of another chunk.
- What the plain mode gives up is separation from BLAKE3 hashes computed outside SBTP. For a `block_id`,
  that separation protects the signature built on it (ADR 0002, context). A chunk is unsigned: its
  identifier commits to its bytes and to nothing else. Equality with an outside hash of the same bytes
  creates no forgery.

**Interoperability** (checked on 2026-11-18: `blake3` 1.8.7 and `bao` 0.13.1 on docs.rs, `bao` README and
`docs/spec.md`, `b3sum` README, `iroh-blobs` 0.105.0 on docs.rs):

- `b3sum <file>` with no option gives the `chunk_id`. Every BLAKE3 library computes it.
- Bao verified streaming works as published: "the `bao hash` of a file is the same as the regular BLAKE3
  hash". The `encode` and `decode` modules of `bao` list no keyed or `derive_key` variant.
- Stores that address content by its plain BLAKE3 hash use the same identifier for the same bytes, for
  example `iroh-blobs` ("32-byte BLAKE3 hash of a blob", "BLAKE3 verified streaming").

Not confirmed: the `bao` signatures were read from the module listings, not from the source. `bao` states
it is "beta cryptography software" and "has not been formally audited".

## Consequences

- **`sbtp-core`.** No change. The crate does not know chunks and MUST NOT expose a plain-mode hash as an
  SBTP identifier. The `chunk_id` function belongs to a layer 1 crate (not created).
- **`sbtp-relay`.** No change by this ADR. Whether a relay serves chunks, through which endpoint, and under
  which admission rule is open (Q-21).
- **ADR 0002.** Its body is unchanged. A line "Amended by: 0010 (rule 10, layer-1 chunk_id)" is added under
  its status, and the index of `docs/decisions/README.md` shows "accepted, amended by 0010".
- **Abuse.** A chunk has no proof of work and no signature. A node that accepts chunks from anyone has no
  protocol-level anti-spam, and cannot check that a chunk is referenced by a manifest without parsing
  payloads, which a relay never does. This must be decided before any node accepts chunk uploads (Q-21).
- **Type confusion in layer 2.** The notation `blake3:<64 hex>` designates both a block (`media_manifest`)
  and a chunk (`chunks`). It is accurate for a chunk and inaccurate for a block. The hash mode does not fix
  this; references must be typed (Q-22).
- **Manifest capacity.** With the current text notation (`"blake3:<64 hex>"`, 73 bytes per entry in CBOR),
  a manifest holds about 890 chunks, that is about 220 MiB. With 32-byte byte strings (34 bytes per entry),
  about 1,920 chunks, that is about 480 MiB. Larger objects need another mechanism (open, Q-01).
- **Large objects.** A 262,144-byte chunk is exactly 256 BLAKE3 leaves: a complete subtree. A manifest
  that stores one BLAKE3 root of the whole object, with ranges verified by Bao, is possible with the
  published `bao` crate. The `chunk_id` of rule 3 (root hash of the chunk alone) is not the interior value
  of that tree: the two designs do not share identifiers.
- **Deduplication.** Identical chunks have the same `chunk_id`, whoever publishes them. A chunk can be
  referenced by several manifests.
- **Privacy.** Anyone who knows a `chunk_id` can test whether a node holds the chunk, and the `chunk_id` of
  a known public file is computable by anyone. This is inherent to content addressing (Q-17).
- **Units.** "256 KB" in `architecture.md` becomes "256 KiB" (262,144 bytes).
- **Test vectors.** To create with the layer 1 crate: `chunk_id` of 1 byte, of 1,024 and 1,025 bytes
  (BLAKE3 leaf boundary), of 262,144 bytes; an empty chunk (rejected); a chunk of 262,145 bytes (rejected);
  a chunk whose bytes do not match the requested `chunk_id`. The official BLAKE3 vectors cover the `hash`
  mode.
- **Compatibility.** No chunk and no manifest exist.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-01 | A chunk is a raw blob outside the envelope, identified by its standard BLAKE3 hash, referenced by a manifest block. The payload limit is unchanged. | Large manifests: objects beyond about 480 MiB (hierarchical manifests, or a single root with Bao). Manifest format: which layer defines it (`media.manifest` is today a layer 2 type), whether `chunk_size` stays a field, binary or text identifiers (Q-22). |
| Q-21 (new) | | Chunk transport and admission: endpoint (for example `/sbtp/v1/blob/{chunk_id}`), WebRTC, who may upload, limits. |

## Rejected alternatives

### Hash mode

- **`BLAKE3_derive_key("SBTP 2026-11-18 chunk_id v1", chunk)`.** Satisfies ADR 0002 rule 10 as written,
  but needs an exemption from rule 9, otherwise every `chunk_id` changes with the block Version. Not the
  default output of `b3sum` (`--derive-key` needed). Not usable with the published `bao` crate: a custom
  verified-streaming implementation would be needed (`blake3::hazmat::Mode::DeriveKeyMaterial` exists).
  Different identifier from other BLAKE3 stores. What it adds, separation from outside hashes, removes no
  attack on unsigned bytes.
- **`BLAKE3_keyed_hash(K, chunk)` with a published constant `K`.** Same costs, plus an arbitrary constant
  to publish. ADR 0002 already rejected this mode for the `block_id`.
- **Prefix in `hash` mode, `BLAKE3(prefix ‖ chunk)`.** No primitive-level separation, breaks default
  tools, and shifts the BLAKE3 tree by the prefix length, which breaks Bao offsets.

### Carrying chunks

- **Raise the payload limit to hold a chunk (u32 Payload Len).** Changes the format and `MAX_BLOCK_LEN`,
  hence a new Version; makes every relay accept 256 KiB bodies for any application; costs a signature
  verification and a PoW per chunk.
- **Split a chunk over several blocks.** Five blocks, signatures and proofs of work per chunk, for bytes
  already authenticated by a hash.
- **Reduce the chunk size to fit a payload (for example 60 KiB).** Four times more identifiers per object
  and four times more requests; the envelope cost stays.
- **Sign each chunk.** The manifest signature already covers every `chunk_id`.

## Spec change

Applied on 2026-11-18.

### `docs/spec/sbtp-core-v0.2.md`

**§2, table.** In the Payload Len row, `` `[Q-01]` `` is replaced with
`Larger objects are carried as chunks outside the block (ADR 0010).`

**§3.5.** Row added:

```markdown
| (none: BLAKE3 `hash` mode) | `chunk_id` of a layer 1 chunk (ADR 0010) | not bound to Version |
```

First bullet under the table replaced, and one bullet added:

```markdown
- Every new use of BLAKE3 or Ed25519 in SBTP, all layers included, MUST use a distinct string and add it to
  this table. One exception: the `chunk_id` of a layer 1 chunk is the standard BLAKE3 hash of the chunk
  bytes (`hash` mode, 32-byte output, no string). The `hash` mode is reserved to this use: no other SBTP
  use may hash in this mode, and layer 0 MUST NOT use it. The `chunk_id` does not depend on the Version
  field. (ADR 0002, amended by ADR 0010)
- A `chunk_id` and a `block_id` come from two BLAKE3 modes (`hash` and `derive_key`), which BLAKE3
  separates internally. The separation does not rely on the content or the structure of the hashed bytes:
  a chunk may contain any bytes, those of a block included.
```

### `docs/spec/architecture.md`

**§1, "Layer 1".** Paragraph replaced with:

```markdown
Files and streams are split into chunks of **256 KiB** (262,144 bytes); the last chunk of an object may be
shorter. A chunk is a raw byte sequence outside the SBTP envelope: no header, no signature, no proof of
work. It is identified by its `chunk_id`, the standard BLAKE3 hash of its bytes (`hash` mode, 32 bytes;
`sbtp-core-v0.2.md` §3.5), and a recipient MUST check it before any use. A manifest, carried in the
payload of a signed SBTP block, lists the `chunk_id` values of the object in order. Authorship comes from
the manifest block only. Lightweight relays help set up WebRTC Data Channels between peers for
high-throughput transfer. Transport and admission of chunks: `[Q-21]`. (ADR 0010)
```

### Layer 2 payload specification

**`media.manifest`.** ``Size constraint `[Q-01]`.`` replaced with:

```markdown
Each entry of `chunks` is the `chunk_id` of a raw chunk outside the SBTP envelope: the standard BLAKE3
hash of the chunk bytes (ADR 0010). A manifest must fit in one payload (65,535 bytes); objects with more
chunks than fit are not specified yet `[Q-01]`.
```

**Identifier notation (last line).** Completed: accurate for a chunk, not for a block; distinct notations
`[Q-22]`.
