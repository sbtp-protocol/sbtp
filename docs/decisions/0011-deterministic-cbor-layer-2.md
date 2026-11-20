# 0011: Deterministic CBOR for layer 2 payloads

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0032 ("Consequences", "Test vectors": the planned negative vector "length-first order where
  it differs from bytewise order" cannot be built and reads "map key that is not a text string")
- Date: 2026-11-18
- Decision: project owner, 2026-11-18
- Questions: Q-13 (resolved); opens Q-22
- Impact: the layer 2 payload specification of the time, §1.2 and type definitions; future crate `sbtp-l2`; web
  client; layer 2 test vectors to create; no change to layer 0, `sbtp-core` or `sbtp-relay`

## Context

The layer 2 payload specification (§1.2) recognised two payload formats: canonical JSON (RFC 8785, JCS) and CBOR
(RFC 8949). The same payload encoded both ways gives two payloads, hence two `block_id` values. References,
deduplication and votes become ambiguous (Q-13). Plain CBOR alone has the same defect: it allows several
encodings of one value (integer widths, map key order, indefinite lengths).

### RFC 8949 §4.2, checked on rfc-editor.org on 2026-11-18

- §4.2: protocols "are free to define what they mean by a 'deterministic format' and what encoders and
  decoders are expected to do. This section defines a set of restrictions that can serve as the base of
  such a deterministic format."
- §4.2.1, "core deterministic encoding requirements", three restrictions:
  1. "Preferred serialization MUST be used": shortest argument for integers, lengths and tags; shortest
     floating-point form that preserves the value.
  2. "Indefinite-length items MUST NOT appear."
  3. "The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic
     encodings."
- §4.2.2 lists what the RFC leaves to the protocol: presence or absence of tags; big integers (tags 2 and
  3) versus major types 0 and 1; floating-point values (negative zero, NaN, integers versus floats,
  subnormals).
- §4.2.3 defines a second profile, "length-first core deterministic encoding requirements", with the map
  key order of RFC 7049 ("Canonical CBOR"). It is not the profile of §4.2.1.
- The RFC does not require a decoder to check determinism: protocols "might also have the decoders check
  that their input is in that deterministic format".

"Deterministic CBOR (RFC 8949)" is therefore not a complete definition. A profile must be named and the
points of §4.2.2 must be closed.

## Decision

Rules 4 to 12 close the points that RFC 8949 leaves to the protocol.

1. A layer 2 payload MUST be a single CBOR data item (RFC 8949) that satisfies the **core deterministic
   encoding requirements of RFC 8949 §4.2.1**.
2. CBOR is the only layer 2 payload format. JSON, canonical or not, MUST NOT be used as a payload. JSON and
   CBOR diagnostic notation MAY be used for display, debugging and documentation.
3. Layer 0 is unchanged: the payload stays opaque. A relay MUST NOT parse or check CBOR.

### Profile

4. **Map key order.** Bytewise lexicographic order of the encoded keys (§4.2.1). The length-first order of
   §4.2.3 MUST NOT be used.
5. **Map keys.** Keys MUST be text strings. A map MUST NOT contain two equal keys.
6. **Integers.** Major types 0 and 1 only, shortest form. Range: `−2^64` to `2^64 − 1`.
7. **No floating-point.** Floating-point values (major type 7, additional information 25, 26, 27) MUST NOT
   appear. A fractional quantity is carried as a scaled integer defined by its field.
8. **No tags.** Major type 6 MUST NOT appear. This excludes big integers (tags 2, 3) and tagged dates. A
   time is an unsigned integer.
9. **Simple values.** Only `false`, `true` and `null` are allowed. `undefined` and other simple values
   MUST NOT appear.
10. **Strings.** Definite length only. A text string MUST be valid UTF-8. No Unicode normalisation is
    applied: two strings are equal if and only if their bytes are equal.
11. **Whole payload.** The payload is exactly one data item: no byte before or after it. Its encoded size
    is at most 65,535 bytes.
12. **Decoders are strict.** A layer 2 decoder MUST reject a payload that breaks any rule above, and MUST
    NOT interpret it. An encoder MUST emit only conforming payloads.

## Consequences

- **What determinism gives.** One data-model value has exactly one payload encoding. Two clients that
  encode the same envelope produce the same payload bytes. The `block_id` also covers Timestamp, Nonce,
  PubKey and parents: the same content published twice still gives two blocks. Determinism removes the
  ambiguity due to the format, not duplicates.
- **Why rule 12.** Without it, a sender could publish a non-deterministic encoding of an existing content
  and obtain a second valid payload for the same value; the defect of Q-13 would return through lax
  decoders. This follows the strict decoding of layer 0 (ADR 0004).
- **Key order differs from JCS.** The envelope keys sort as `"data"`, `"type"`, `"schema"` (encodings
  `0x64…`, `0x64…`, `0x66…`: shorter keys first for keys under 24 bytes, then bytewise). JCS would give
  `data`, `schema`, `type`. An implementation that reuses a JSON key sort is not conforming. The examples
  of the layer 2 payload specification are JSON renderings; the order of their members is not the wire order.
- **Constraints on the layer 2 types (the rest is Q-22).**
  - `index.rolling.entries.score`: MUST be an integer (rule 7); written in the spec. A ranking score
    computed as a float cannot be published as is.
  - `window_start`, `window_end`, `duration_ms`: unsigned integers; the unit stays open (Q-07).
  - `vote.cast.value`: integers `−1`, `0`, `1`, encoded `0x20`, `0x00`, `0x01`.
  - Identifiers and keys are today text (`"blake3:<64 hex>"`, `"ed25519:<64 hex>"`): 73 bytes per hash in
    CBOR. As byte strings they take 34 bytes. This doubles the capacity of a manifest (ADR 0010).
  - The notation `blake3:<64 hex>` for a block is inaccurate since ADR 0002: a `block_id` is a
    `derive_key` output, not the BLAKE3 hash of the block.
- **`sbtp-l2` (future).** The CBOR library must emit deterministic encodings and let the decoder check
  them: sorted keys, shortest forms, no indefinite length, no duplicate key. Which Rust CBOR crate
  guarantees this was not checked; the implementer must verify the chosen crate (Context7) and cover the
  rules with negative tests. A decode, re-encode and compare step is one way to implement rule 12.
- **Web client.** The same rules apply in JavaScript or WASM. JavaScript numbers are floats: integers above
  `2^53 − 1` (for example a millisecond timestamp is safe, a u64 counter is not) need `BigInt` or the WASM
  codec.
- **`sbtp-core`, `sbtp-relay`.** No change.
- **Scope.** The rule binds the layer 2 defined in this repository. Layer 0 stays application-agnostic:
  another application over SBTP can carry any payload. Whether the layer 1 manifest follows the same
  profile is decided with its format (Q-01).
- **Test vectors.** To create with `sbtp-l2`, in a layer 2 folder of `docs/test-vectors/`: for each type,
  the payload in hexadecimal and in diagnostic notation; negative vectors: unsorted keys, length-first
  order where it differs from bytewise order, non-shortest integer, indefinite-length string, array and
  map, float, tag, `undefined`, duplicate key, invalid UTF-8, trailing byte.
- **Compatibility.** No layer 2 block exists. The schema string of the layer 2
  payloads is not frozen yet.
- **Not adopted.** IETF drafts on a common deterministic encoding of CBOR exist. Their status was not
  checked. This ADR relies on RFC 8949 only.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-13 | One payload format, deterministic CBOR, with a named profile. | Nothing. |
| Q-22 (new) | | CBOR typing of each layer 2 field: byte strings or text for identifiers and keys, distinct notations for a block reference and a chunk reference, removal of the inaccurate `blake3:` notation for blocks. |

## Rejected alternatives

- **JCS (RFC 8785) as the single format.** Readable, but larger (hexadecimal identifiers), and its number
  serialisation follows ECMAScript floats. Not the owner's choice.
- **Both formats, with the format flagged in the payload.** Keeps two `block_id` values per content.
- **Length-first profile (RFC 8949 §4.2.3).** Exists for compatibility with RFC 7049. SBTP has no such
  constraint.
- **Core requirements without restrictions on floats and tags.** Leaves the choices of §4.2.2 to each
  implementation (`1` versus `1.0`, NaN encodings, tagged versus raw dates): the encoding is no longer
  unique in practice.
- **Lenient decoders.** See rule 12.

## Spec change

Applied to the layer 2 payload specification on 2026-11-18. No change to
`docs/spec/sbtp-core-v0.2.md` nor to `docs/spec/architecture.md`.

**§1.2.** Replace the section, up to and excluding "Mandatory envelope", with:

```markdown
### 1.2 Format and envelope
A payload MUST be a single CBOR data item (RFC 8949) that satisfies the core deterministic encoding
requirements of RFC 8949 §4.2.1, with the following profile. (ADR 0011)

- Map keys are text strings, sorted in the bytewise lexicographic order of their encodings. The
  length-first order of RFC 8949 §4.2.3 MUST NOT be used. A map MUST NOT contain two equal keys.
- Integers use major types 0 and 1, in their shortest form.
- Floating-point values, tags, `undefined` and indefinite-length items MUST NOT appear. `false`, `true`
  and `null` are the only simple values.
- Text strings MUST be valid UTF-8. No Unicode normalisation is applied.
- The payload is exactly one data item, with no byte before or after it.
- A decoder MUST reject a payload that breaks one of these rules. JSON MUST NOT be used as a payload.

The examples below are JSON renderings for reading. On the wire, the envelope keys are ordered `data`,
`type`, `schema`. The CBOR type of each field is not specified yet `[Q-22]`.
```

The "Mandatory envelope" block is unchanged.

**`index.rolling`.** After the `data` list, add: `` `score` and the count fields are integers (ADR 0011). ``
