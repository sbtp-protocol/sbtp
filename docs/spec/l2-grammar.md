# Layer 2: payload grammar, generic kinds and sealed envelope

> Status: normative. This document holds what every layer 2 application shares: the deterministic CBOR
> profile (ADR 0011), the grammar `{v, kind, edges, body}` and its verb registry (ADR 0015, ADR 0032),
> the kinds in the `sbtp.` namespace, the resolution rules that every application builds on, and the
> sealed envelope (ADR 0016). Application kinds are defined by each application's own specification,
> outside this repository (ADR 0038).
>
> Some decision records are not published; the specification is self-contained and normative on its
> own. A `[Q-xx]` marker flags a point that is not specified yet. Section numbers are stable; numbers
> with no content here (§4.4, §5.6, §5.7) are intentionally absent.

The words MUST, MUST NOT, SHOULD and MAY have the meaning given in RFC 2119.

## 1. Serialisation

### 1.1 Opaque payload
A block's payload (≤ 65,535 bytes) is opaque to layers 0 and 1. Only clients, PWAs and
indexers interpret it. A relay MUST NOT parse or check a payload (ADR 0011 rule 3).

### 1.2 Format
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

The examples of this document are in CBOR diagnostic notation, for reading.

### 1.3 Envelope
(ADR 0015 rules 1 to 6)

- A payload MUST be a CBOR map with exactly four keys: `v`, `kind`, `edges`, `body`. On the wire the keys
  are ordered `v`, `body`, `kind`, `edges`.
- `v` MUST be the unsigned integer 1. A decoder MUST reject a payload with another value and MUST NOT
  interpret it.
- `kind` MUST be a text string of 3 to 64 bytes, made of two or more labels separated by `.`. A label is
  a lowercase ASCII letter followed by lowercase ASCII letters, digits or `_`. The whole string MUST
  match. The first label names the application.
- **Reserved prefix.** The first label `sbtp` is reserved for the kinds of this specification (§3). An
  application uses its own first label and documents its kinds in its own specification; it MUST NOT
  define a kind whose first label is `sbtp`. Application kinds are not registered here. An
  application's context strings follow the reserved prefixes of core spec §3.5.
- `edges` MUST be an array of 0 to 64 edges (§2). It MUST be present when empty.
- `body` MUST be present. Its CBOR type is fixed by the kind. Every kind of §3 has a map body, possibly
  empty. A byte string body is allowed only for a kind whose definition says so.
- A client that does not know a `kind` MUST still check §1 and §2, and MAY use the edges for ordering and
  display. It MUST NOT apply the block to any resolved state.

Example, a block with one parent and an application kind:

```
{"v": 1, "body": {}, "kind": "example.ack", "edges": [{"p": 0, "rel": "endorses"}]}
```

### 1.4 Identifiers and times
- Identifiers in a payload are byte strings of 32 bytes: a `block_id` (the BLAKE3 `derive_key` output of
  ADR 0002), a `chunk_id` (the standard BLAKE3 hash of the chunk bytes, ADR 0010) or an Ed25519 public
  key. The text notations `blake3:<hex>` and `ed25519:<hex>` MUST NOT appear in a payload. (ADR 0015
  rule 9)
- A `block_id` and a `chunk_id` are never interchangeable. The key that carries the value gives its type
  (`block`, `chunk`, §2.1).
- Every time in a body is an unsigned integer of Unix milliseconds, the unit of the header Timestamp.
  (ADR 0015 rule 33)

## 2. Edges

The header parents give causality. The edges give its meaning. (ADR 0015 rules 7 to 17)

### 2.1 Edge format
An edge MUST be a map with exactly one target key (`p`, `block` or `chunk`), the key `rel`, and
optionally the key `meta`. Wire order: `p`, `rel`, `meta`, `block` or `chunk`.

| Key | Value | Meaning | Causal |
|---|---|---|---|
| `p` | unsigned integer 0 to 7 | the header parent at that index; a `block_id` | yes |
| `block` | byte string, 32 bytes | a `block_id` | no |
| `chunk` | byte string, 32 bytes | a `chunk_id` | no |

- An edge is causal if and only if its target key is `p`. `p` MUST be lower than the Parents Count of the
  block that carries the payload. A block has 0 to 8 parents (core spec §2.2, ADR 0014).
- **Coverage.** Every header parent MUST be named by exactly one edge. Two edges MUST NOT carry the same
  `p`. A payload in a block with `N` parents has exactly `N` causal edges. The position of a parent in
  the header carries no meaning of its own.
- **Order.** The causal edges come first, in increasing `p`. The other edges follow in the author's
  order. A `block` value MUST NOT equal one of the block's header parents.
- `meta`, when present, MUST be a non-empty map. An edge with no metadata MUST omit the key. The keys
  allowed for a registry verb are those of §2.2; any other key makes the payload invalid.
- A block needs more than 8 causal relations: it MUST use intermediate blocks (for example a synthesis
  block), or non-causal edges where the verb allows them.

### 2.2 Verb registry
`rel` MUST be a registry verb or an extension verb (§2.3). The registry is one namespace for every
application. A new registry verb requires an SBTP ADR in this repository, whatever the domain (ADR 0038).
An application that needs a verb without such an ADR uses an extension verb (§2.3).

| Domain | Verb | Meaning | Target forms | Same author | `meta` |
|---|---|---|---|---|---|
| Structure | `follows` | next block of the same author's sequence | `p` | yes | none |
| Structure | `in` | the block belongs to the container | `p` | no | none |
| Structure | `supersedes` | replaces an earlier version | `p` | yes | `reason`: text, optional |
| Structure | `composed_of` | ordered part of a document or file | `p`, `block`, `chunk` | no | `seq`: unsigned integer, required; `mime`: text, optional |
| Structure | `tagged` | filed under a delivery tag; the target is not a block (§5.4) | `p` | no | none |
| Content | `replies_to` | reply | `p` | no | none |
| Content | `cites` | quotation or reference, no thread dependency | `block`, `chunk` | no | `span`: `[offset, length]`, optional (Q-25) |
| Content | `endorses` | vote +1 | `p` | no | none |
| Content | `opposes` | vote −1 | `p` | no | none |
| Content | `tombstones` | the author retracts its own block | `p` | yes | none |
| Content | `moderates` | a moderator hides the target block | `p` | no | none |
| Content | `tallies` | a published count over the target's supersession chain | `p` | no | none |
| Agents | `supports` | argument for | `p` | no | `confidence`: 0 to 100, optional |
| Agents | `refutes` | argument against | `p` | no | `confidence`: 0 to 100, optional |
| Agents | `synthesizes` | merges the target branch | `p` | no | none |
| Agents | `delegates_to` | delegates a task | `p` | no | `task_id`: text, optional (Q-25) |
| Agents | `fulfills` | answers a delegation | `p` | no | `status`: text, optional (Q-25) |

The domain column records where a verb was first needed; any application MAY use any registry verb on
its own kinds. `tagged` is allowed only on `sbtp.enc` and `sbtp.enc_key`. `tallies` is allowed only on
the one application kind that the application requesting the verb designates in its specification;
application validation checks it. (ADR 0016 rule 10, ADR 0037 rule 11)
A verb used with a target form outside its row makes the payload invalid. Two `composed_of` edges of one
payload MUST NOT carry the same `meta.seq`, whatever their target forms. (ADR 0032 rule 7) The
agent-domain verbs have a registered shape; their state resolution and the types of `span`, `task_id`
and `status` are provisional `[Q-25]`.

### 2.3 Extension verbs
- A verb outside the registry MUST have the form `x.<app>.<verb>`, each part following the label rule of
  §1.3. It MAY use any target form and any `meta` map. An author MUST NOT emit any other verb.
- A client MUST NOT use an extension verb, or a verb it does not know, in any automatic state resolution
  (votes, retraction, moderation, supersession, ordering beyond §4.5). It MAY display the edge.
- A `rel` value MUST be 1 to 64 bytes. An unknown verb without the `x.` prefix MUST be one label
  (§1.3). It does not make the payload invalid: it may come from a later registry. (ADR 0032 rules 5
  and 6)
- Extension and unknown verbs are outside every kind row (§3.1). They MAY appear on a payload of a
  known kind, unless the kind's definition closes its edge set, and do not count toward its
  multiplicities. A causal one names a header parent and counts toward the Parents column. (ADR 0032
  rule 4)

### 2.4 Validation
Validation has two parts. Both read the payload and the header parents: their count, and their values
only for the `block` rule of §2.1. Neither reads another block. Each costs time linear in the payload
size. (ADR 0032 rule 8)

- **Grammar validation**, `validate_l2_invariants(header, payload)`, checks §1.2, §1.3, §2.1 to §2.3
  and, for a kind of §3, its row (§3.1) and its body rule, with the tolerance of §2.3 for an unknown
  verb. It knows no application kind: the payload of any other kind passes with its body checked for
  type only (a map, or a byte string, §1.3).
- **Application validation** runs on the output of grammar validation, for the kinds an application
  defines. It checks their rows under §3.1 and their body rules.

A payload that fails either part is invalid: a client MUST NOT interpret it, and MUST NOT fail because
of it. The block stays a valid layer 0 block. A client that does not implement an application validates
the kinds of that application as unknown kinds (§1.3).

### 2.5 CDDL
RFC 8610. The schema summarises §1.3, §2 and the bodies of §3 and §5. It cannot express the bound by
Parents Count, coverage, edge order, nor the link between a kind and its body, the multiplicities of
§3.1, unknown verbs, distinct `seq` values, nor the cross-field rules of `sbtp.manifest`: the prose
rules apply in addition, and win in case of doubt. RFC 8610 does not state that `.regexp` matches the
whole string; this document requires it. `label-re` is documentation. The bodies of application kinds
are in each application's specification.

```cddl
payload = {
  v: 1,
  kind: kind,
  edges: [0*64 edge],
  body: { * tstr => any } / bstr,
}

label-re = "[a-z][a-z0-9_]*"
kind     = (tstr .size (3..64)) .and (tstr .regexp "[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+")
ext-verb = (tstr .size (5..64)) .and (tstr .regexp "x\\.[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*")

block-id = bstr .size 32   ; BLAKE3 derive_key output, ADR 0002
chunk-id = bstr .size 32   ; BLAKE3 hash of the chunk bytes, ADR 0010
pubkey   = bstr .size 32   ; Ed25519 public key
pidx     = 0..7            ; index into the header parents
ms       = uint            ; Unix time in milliseconds

edge = plain-edge / supersedes-edge / composed-edge / cites-edge
     / argument-edge / delegates-edge / fulfills-edge / ext-edge

plain-edge = {
  p: pidx,
  rel: "follows" / "in" / "replies_to" / "endorses" / "opposes"
     / "tombstones" / "moderates" / "synthesizes" / "tagged" / "tallies",
}
supersedes-edge = { p: pidx, rel: "supersedes", ? meta: { reason: tstr } }
composed-edge = {
  ( p: pidx // block: block-id // chunk: chunk-id ),
  rel: "composed_of",
  meta: { seq: uint, ? mime: tstr },
}
cites-edge = {
  ( block: block-id // chunk: chunk-id ),
  rel: "cites",
  ? meta: { span: [offset: uint, length: uint] },
}
argument-edge  = { p: pidx, rel: "supports" / "refutes", ? meta: { confidence: 0..100 } }
delegates-edge = { p: pidx, rel: "delegates_to", ? meta: { task_id: tstr } }
fulfills-edge  = { p: pidx, rel: "fulfills", ? meta: { status: tstr } }
ext-edge = {
  ( p: pidx // block: block-id // chunk: chunk-id ),
  rel: ext-verb,
  ? meta: { + tstr => any },
}

; Bodies of the kinds of §3
manifest-body = {
  mime: tstr, total_size: uint, chunk_size: 262144, chunks: [+ chunk-id],
  ? duration_ms: uint, ? resolution: [width: uint, height: uint],
}
enc-body        = { ct: bstr, enc: bstr .size 32 }                      ; sbtp.enc
enc-key-body    = { x25519: bstr .size 32, intro_bucket: 0..15 }        ; sbtp.enc_key
sealed          = { from: pubkey, msg: bstr, sig: bstr .size 64 }       ; plaintext item, §5.3
```

## 3. Kinds

| `kind` | Required edges (exactly one each) | Optional edges | Parents | Authority |
|---|---|---|---|---|
| `sbtp.manifest` | none | at most one `in` → container | 0 or 1 | author |
| `sbtp.enc` | `tagged` → delivery tag | none | 1 | none (ephemeral signer, §5.2) |
| `sbtp.enc_key` | `tagged` → directory tag | at most one `supersedes` → previous version | 1 or 2 | identity |

Application kinds are defined in each application's specification (§1.3).

### 3.1 Reading a kind row
These rules apply to the rows of this section and to the rows of every application specification.
(ADR 0032 rules 1, 2 and 4, stated for every application by ADR 0038)

- A payload of a known kind whose edges or body do not match its row and its body rule is invalid.
- A registry verb outside the row makes it invalid. A required verb appears exactly once. An optional
  verb appears at most once, unless the row says "any number".
- The Parents column bounds the Parents Count, whatever verbs name the parents.
- Extension and unknown verbs follow §2.3. A kind whose definition says its edge set is closed admits
  none.

### `sbtp.manifest`
Body `manifest-body`: `mime`, `total_size`, `chunk_size` (262,144), `chunks`, `duration_ms` and
`resolution` (optional). Each entry of `chunks` is the 32-byte `chunk_id` of a raw chunk outside the SBTP
envelope, in object order (ADR 0010). Every chunk except the last is exactly `chunk_size` bytes. With `n`
entries in `chunks`, `total_size` MUST satisfy `(n − 1) × chunk_size < total_size ≤ n × chunk_size`.
(ADR 0032 rule 10) A manifest must fit in one payload (65,535 bytes), about 1,920 chunks; larger objects,
and which layer defines the manifest, are not specified yet `[Q-01]`.

### `sbtp.enc` and `sbtp.enc_key`
Defined in §5.2 and §5.5.

## 4. Resolution rules shared by every application

Resolution is a function of the set of blocks a client holds. Two clients that hold the same set MUST
obtain the same state. Two clients that hold different sets may differ until they converge: SBTP has no
consensus. (ADR 0015 rules 18 to 33) An application specification adds its own rules and its order of
evaluation on top of this section; it MUST NOT relax a rule of this section.

### 4.1 Applicability, same author and identity
- A causal edge is **applicable** when the client holds the target block and has validated it (core spec
  §2.2, check R1 included). A client MUST NOT apply `follows`, `supersedes` or `tombstones`, nor any verb
  that an application lists as needing its target, when the edge is not applicable. It keeps the block
  and applies it when the target arrives. (ADR 0015 rule 18)
- **Order independence.** When a block arrives, a client MUST evaluate again every block kept waiting
  for it, directly or through a chain, and MUST NOT keep a result computed without it. The state does
  not depend on the order in which the blocks arrived. (ADR 0034 rule 9, stated for every application
  by ADR 0038)
- **Same author.** For `follows`, `supersedes` and `tombstones`, the PubKey field of the target block MUST
  equal the PubKey field of the block that carries the edge. Otherwise the client MUST ignore the whole
  block for state resolution. (ADR 0015 rule 19)
- No other registry verb restricts the author of its target. A key MAY reply to, cite or vote on its own
  blocks. (ADR 0015 rule 20)
- A block whose payload is invalid (§2.4) is not a valid target of `supersedes` or `follows`.
- <a id="identity"></a>**Identity.** An identity is one public key. No layer 2 block links two keys,
  transfers authorship or revokes a key. A block stays attributed to the key that signed it. A link
  between two keys published as display text has no effect on state resolution. Key succession and
  recovery are not specified `[Q-38]`. (ADR 0031 rules 15 to 18, stated for every application by
  ADR 0038)

### 4.2 Retraction
- A block with an applicable `tombstones` edge that passes the same-author check retracts its target. A
  client MUST hide the content of a retracted block. Retraction is permanent: no block cancels it.
  (ADR 0015 rule 21)
- If the target belongs to a supersession chain (§4.3), the whole chain is retracted. An application MAY
  define how far a retraction extends for its kinds that carry no `supersedes` edge.
- The kind that carries a `tombstones` edge is an application kind. This specification defines no
  tombstone kind, for `sbtp.enc_key` (§5.5) included: an application kind retracts it, and a kind in the
  `sbtp.` namespace for this purpose is `[Q-60]`.
- A retraction does not delete a block from a relay. Relay eviction is separate and local (ADR 0013).

### 4.3 Supersession
- `B supersedes A` is valid if the same-author check holds and `A` and `B` have the same `kind`. An
  application MAY add conditions for its kinds; a `supersedes` edge that fails one of them makes the
  block ignored for state resolution. (ADR 0015 rule 24)
- <a id="supersession-chain"></a>The **supersession chain** of a block is the block and every block
  linked to it through valid `supersedes` edges, followed in either direction, over blocks not ignored.
  (ADR 0036 rule 1, stated for every application by ADR 0038)
- A block with a valid superseding block is replaced. The **heads** of a chain are its blocks that are
  not replaced and not retracted.
- With one head, that block is the current version. With several heads (forks by the same author), the
  current version is the head with the greatest Timestamp, then the greatest `block_id` (bytewise).

### 4.5 Ordering
- **Causal order.** If `B` has `A` among its header parents, `A` precedes `B`. No Timestamp changes this.
- **Canonical order of a block set.** Kahn's algorithm over the header parents held in the set; among the
  blocks whose held parents are all placed, the next is the one with the smallest Timestamp, then the
  smallest `block_id` (bytewise).
- `composed_of` parts are ordered by `meta.seq`, increasing; the values are distinct (§2.2). The
  Timestamp of a part is ignored.
- **No ranking across authors by sender-chosen values.** The Timestamp is chosen by the sender and the
  `block_id` can be ground through the Nonce. A resolution rule MUST NOT give precedence to a block over
  a block of another author on the basis of either. Precedence across authors comes from causal order or
  from an authority named by a block (author, moderator list).
- A relay rejects a submitted block dated beyond its clock plus `max_future_ms` (ADR 0007). A client
  SHOULD NOT apply or display a block whose Timestamp is greater than its own clock plus 300,000 ms until
  that instant.
- For display by date, a client SHOULD use `max(Timestamp, greatest display time of its held parents)`,
  and MAY cap it by the instant it first received the block. This value is local to the client. It MUST
  NOT enter any state resolution.

### 4.6 Media
The chunks listed in a manifest are fetched in parallel from peers (DHT / WebRTC), each checked against
its `chunk_id` before any use (ADR 0010 rule 5) and against its length: `chunk_size` for every chunk but
the last, `total_size − (n − 1) × chunk_size` for the last. A client MUST NOT use an object one of whose
checks fails. (ADR 0032 rule 11) The chunks are then reassembled locally in list order. Transport and
admission of chunks: `[Q-21]`.

## 5. Sealed envelope and encryption keys
(ADR 0016)

The header stays in clear in every case: PubKey, Timestamp, parents and payload length are visible to
every relay and reader. This section hides payload content, not metadata (§5.9). An application uses
the envelope through the tags it defines (§5.4).

### 5.1 Suite
- Every seal MUST use HPKE (RFC 9180) in `mode_base` (`0x00`), single-shot, with KEM `0x0020`
  (DHKEM(X25519, HKDF-SHA256)), KDF `0x0001` (HKDF-SHA256) and AEAD `0x0003` (ChaCha20Poly1305). No other
  mode or suite is allowed; the envelope carries no suite identifier.
- `info` is the 27-byte ASCII string `SBTP 2026-11-20 sbtp.enc v1`. `aad` is the 64 bytes
  `PubKey ‖ tag` of the outer block (its PubKey field, then its single header parent).
- A recipient MUST perform the all-zero shared secret check of RFC 9180 §7.1.4. A seal to a key that
  yields an all-zero shared secret fails and is not sent.
- Randomness comes from the operating system's secure source. A seeded generator is for tests only.

### 5.2 Outer block (`sbtp.enc`)
- Payload: `{"v": 1, "body": {"ct": h'…', "enc": h'<32 bytes>'}, "kind": "sbtp.enc", "edges": [{"p": 0,
  "rel": "tagged"}]}`. `enc` is the HPKE encapsulated key; `ct` is the HPKE ciphertext. The body has
  exactly these two keys.
- The block MUST have exactly 1 header parent: a delivery tag (§5.4), named by the single `tagged` edge.
- **Ephemeral signer.** The PubKey MUST be a fresh Ed25519 key from a secure random source, used for this
  block only. The sender SHOULD erase its private key after signing, and MUST NOT use its identity key,
  an encryption key or another sealed block's key. A recipient MUST ignore a sealed block whose PubKey
  equals the `from` of its plaintext.
- **Length buckets.** Payload Len MUST be 512, 2,048, 8,192 or 65,535 bytes. The payload is 90 bytes plus
  the ciphertext, and the ciphertext is the plaintext plus 16 bytes: plaintexts are 406, 1,942, 8,086 or
  65,429 bytes. Sealed blocks are 662 to 65,685 bytes.
- `validate_l2_invariants` checks this subsection from the payload and the header, with no key.

### 5.3 Plaintext and inner signature
- The plaintext MUST be one deterministic CBOR item (§1.2) followed by `0x00` bytes up to the bucket's
  plaintext length. A recipient decodes exactly one item and MUST reject the plaintext if a byte after it
  is not `0x00`. A sender SHOULD use the smallest bucket that fits.
- The item is a map with exactly the keys `from` (the sender's Ed25519 identity key), `msg` (a byte
  string holding a payload of this grammar) and `sig` (64 bytes).
- `sig` is a pure Ed25519 signature (RFC 8032 §5.1) by `from` over
  `SBTP-v1-sealed-sig ‖ outer_pubkey (32) ‖ recipient_id (32) ‖ recipient_x25519_pubkey (32) ‖ msg`.
  `recipient_id` is fixed by the application that defines the tag (§5.4), for example the recipient's
  identity key, or the `block_id` of a block that names the recipient. The recipient
  builds this message with its own `recipient_id` and the key that opened the block, and verifies it
  with criteria V1 to V6 of core spec §3.2. Implementations expose this message through a typed builder
  only, never a generic signature of arbitrary bytes.
- `msg` is validated as a payload in a block with 0 parents: it MUST NOT carry a causal edge. Its kind
  MUST be one that the outer tag allows (§5.4) and MUST NOT be `sbtp.enc`.
- **Order of checks.** The first failure makes the recipient ignore the block silently, and it tells no
  one which check failed: (1) layer 0 (core spec §3.4); (2) §2.4; (3) the tag is one it polls; (4) HPKE
  Open with each of its private keys for that purpose published no later than the end of the day after
  the outer block's day, newest first; (5) padding; (6) the item; (7) `sig`; (8) `msg`; (9) the tag check
  of the application that defines the tag (§5.4); (10) the checks of the kind.

### 5.4 Tags and the verb `tagged`
- A tag is a 32-byte BLAKE3 `derive_key` output under a context of core spec §3.5 or a context of the
  application that defines the tag (core spec §3.5, reserved prefixes). It is not a `block_id`.
- A client MUST NOT fetch a `tagged` target, treat it as a missing parent or count it in a DAG
  traversal. A `tagged` edge is never applicable and never makes a block pending. It is allowed only on
  `sbtp.enc` and `sbtp.enc_key`.
- Blocks under a tag are listed by `/query?parent=<tag>` (core spec §4). No relay change is involved.
- Before a `GET`, a client SHOULD check its difficulty on each listed `block_id` and SHOULD stop reading
  a body above the largest valid block for that tag: 1,024 bytes for a key directory child (§5.5), and
  the bound the application states for its own tags.
- **Tags defined by an application.** An application that files sealed blocks under its own tags MUST
  state in its own specification, for each tag: its `derive_key` context, which MUST NOT start with a
  prefix reserved by core spec §3.5; the inputs of the derivation; the `msg` kinds the tag allows; the `recipient_id` of §5.3; the tag check of
  step (9) of §5.3; the length buckets allowed; the difficulty a recipient applies; and the largest
  valid block for the bound above.

### 5.5 Encryption keys (`sbtp.enc_key`)
- Signed by the identity key. Body `enc-key-body`: `x25519` (32 bytes, the HPKE recipient key) and
  `intro_bucket` (0 to 15). `intro_bucket` is a value the identity publishes for applications that
  file first contacts under bucketed tags.
- The Ed25519 identity key MUST NOT be converted to X25519 or used for key agreement. The X25519 key is
  generated independently and serves one identity and one purpose.
- Parents: the directory tag `derive_key("SBTP 2026-11-20 enc_key directory v1", identity_pubkey)` as
  `p: 0` (`tagged`); an update adds the previous version as `p: 1` (`supersedes`). A key block whose tag
  does not match its PubKey is ignored for state resolution. The current key is the current version of
  the chain (§4.3).
- A sender MUST seal to the current key it holds and MUST NOT seal to a retracted key (a retraction of
  any version retracts the chain, §4.2). A user SHOULD rotate at least every 90 days. A recipient keeps
  older private keys as long as it wants to read messages sealed to them, and MAY erase one once no relay
  it uses can still hold such a message and it has kept the plaintexts.
- A client MUST submit its current key block again (the same bytes) before the shortest `block_ttl_ms`
  of its relays, or rotate at that interval.
- **Storage.** In the web client, X25519 private keys are raw bytes in IndexedDB: an injected script can
  copy them, whereas it can only use the non-extractable identity key. A web build that holds them MUST
  be served with the web client's strict Content Security Policy; otherwise it MUST NOT enable any
  feature that holds an X25519 private key. Native programs keep private keys in files readable by their
  owner only and never log them.

### 5.8 Groups
Not specified: 1:1 sealing only `[Q-56]`.

### 5.9 What is not hidden
- Relays and proxies see IP addresses and request times. A relay can link the address that polls a tag
  to the address that writes to it, learn who a user writes to from key directory lookups, and link a
  user's tags by its polling pattern. An active relay can withhold blocks, serve a stale key block, and
  drop every block under a public tag.
- Any reader sees the header of every sealed block, how many blocks each tag holds, and every key block.
- A recipient holds a transferable proof (`sig`) of what the sender wrote to it.
- There is no forward secrecy against recipient compromise (RFC 9180 §9.1): the holder of a recipient's
  X25519 private key reads every message sealed to it that is still stored anywhere. The ephemeral HPKE
  sender key gives forward secrecy against sender compromise only.
- Documents MUST NOT claim "no metadata", "metadata-free", "anonymous", "untraceable", or forward secrecy
  without this qualification.
