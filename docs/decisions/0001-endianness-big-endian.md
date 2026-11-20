# 0001: Big-endian header integers

- Status: accepted (by the project owner, 2026-11-18)
- Date: 2026-11-18
- Questions: Q-03
- Impact: spec §2 (table, Timestamp, Nonce and Payload Len rows); `sbtp-core` (fixed-endianness `zerocopy`
  types, header comment of `layout.rs`); all test vectors (none exist yet)

## Context

The v0.2-draft spec encodes Timestamp (u64) and Payload Len (u16) as big-endian, and Nonce (u64) as
little-endian. No text justifies this difference. The nonce is a free value: no validator interprets it.
Mixed endianness in a 52-byte header is a known source of errors between independent implementations.

The `block_id` is already compared "as a 256-bit big-endian integer" for the proof of work (§3.3).

## Decision

1. Every integer field longer than one byte in the layer 0 format MUST be encoded as big-endian (network
   order). This covers Timestamp (u64), Nonce (u64) and Payload Len (u16).
2. The Nonce field is a big-endian u64. A validator MUST NOT interpret its value: the 8 bytes are covered by
   the `block_id` as they are. Any value from `0` to `2^64 − 1` is valid.
3. A sender MAY walk the nonce space in any order it chooses. The convention of the reference tools (CLI,
   test vectors) is: a starting u64 value, increment by 1, big-endian encoding.
4. Every integer field added by a later version of the format MUST follow the same rule.

## Consequences

- No size or offset changes. The constants in `crates/sbtp-core/src/layout.rs` remain valid. Only its header
  comment (lines 7 and 8, "endianness: see Q-03") must be updated by the implementer.
- Implementation: `zerocopy::byteorder::U64<BigEndian>` and `U16<BigEndian>` for the three fields. A single
  byte order across the whole crate.
- Compatibility: the v0.2-draft has no implementation and no published vector. No existing block is
  invalidated. The Version field stays `0x01`.
- Security: no effect. Mining is neither faster nor slower: the nonce is in the first hashed 64-byte block,
  whatever its byte order.

## Rejected alternatives

- **Keep mixed endianness.** No benefit; every third-party implementation must handle a special case.
- **Everything little-endian.** Matches the native order of x86-64, AArch64 and wasm32, but the gain is nil
  with fixed-endianness types, and the spec already compares the `block_id` as big-endian. Network order is
  the convention expected of a transport protocol.
- **Nonce defined as 8 opaque bytes, with no integer type.** Neutral for a validator, but the tools (CLI,
  WASM bindings, test vectors, logs) must display and increment the nonce. Without a defined type, each tool
  would pick its own convention.

## Spec change

To apply to `docs/spec/sbtp-core-v0.2.md` after acceptance.

**§2, table.** Replace the three rows Timestamp, Nonce and Payload Len with:

```markdown
| Timestamp | 8 | u64 big-endian | Unix timestamp **in milliseconds**. `[Q-07]` |
| Nonce | 8 | u64 big-endian | Free value for the proof of work. Not interpreted by a validator. |
| Payload Len | 2 | u16 big-endian | Payload size, at most 65,535 bytes. `[Q-01]` |
```

**§2, after the table,** before "Block size:", insert:

```markdown
Every integer field longer than one byte MUST be encoded as big-endian (network order). (ADR 0001)
```
