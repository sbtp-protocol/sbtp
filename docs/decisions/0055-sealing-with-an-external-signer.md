# 0055: Sealing with an external signer

- Status: accepted (by the project owner, 2026-11-21), as a whole: E1 to E4 as proposed
- Date: 2026-11-21
- Questions: none
- Clarifies: `l2-grammar.md` §5.2 (ephemeral signer) and §5.3 (inner signature), from ADR 0016; extends
  ADR 0002 rule 8 to every signature prefix of core spec §3.5. Nothing else changes
- Impact: `l2-grammar.md` §5.2 and §5.3; core spec §3.2 and §3.5 (one sentence each); `sbtp-seal`
  (`seal_prepare`: a `from` check, E2); `sbtp-core` (a public check of V1 and V2, E2); no wire format
  change; no frozen vector set changes

## Context

The inner signature `sig` of a sealed payload is made by the sender's key `from` (`l2-grammar.md`
§5.3). The sender's identity key may live outside the implementation: a non-extractable Web Crypto key,
a hardware token, an operating system key store. Such a signer signs whatever bytes it is given. A
two-phase seal serves it: the implementation prepares the sealed signature message, the external signer
signs it, and the implementation finishes the seal with the signature.

`l2-grammar.md` §5.3 says the message is exposed "through a typed builder only, never a generic
signature of arbitrary bytes". With an external signer, the signature step is generic by nature. Four
points need a rule: what the typed builder still guarantees, when `from` is checked, whether the sender
verifies `sig`, and whether the ephemeral outer key may serve a retry.

### Signing contexts of core spec §3.5

Ed25519 signs two kinds of message in this specification. The other strings of §3.5 are BLAKE3
contexts or an HPKE `info`; no Ed25519 key signs them, and the X25519 keys of `sbtp.enc_key` are
separate keys (`l2-grammar.md` §5.5).

| Prefix | Bytes | Message | Signed by |
|---|---|---|---|
| `SBTP-v1-block-sig` | 17 | `prefix ‖ block_id`, exactly 49 bytes (§3.2) | the block's PubKey: an identity key, or the ephemeral key of a sealed block |
| `SBTP-v1-sealed-sig` | 18 | `prefix ‖ outer_pubkey ‖ recipient_id ‖ recipient_x25519_pubkey ‖ msg`, at least 114 bytes (`l2-grammar.md` §5.3) | `from`, usually an identity key |

The two prefixes are equal on their first 8 bytes (`SBTP-v1-`) and differ at byte 8 (`b`, `0x62`,
against `s`, `0x73`). Neither is a prefix of the other (ADR 0002 rule 11), so no byte string is a
message of both kinds: a signature made by an identity key for one use does not verify for the other.
An application's signature prefix cannot start with `SBTP-` (core spec §3.5, reserved prefixes), so it
differs from both within the first 5 bytes. The separation holds whoever computes the signature, inside
the implementation or outside it, provided the signer receives only messages built for their use. It
does not cover an external signer that other code, or another protocol, also uses to sign bytes of its
choice (ADR 0002, "Security").

## Decision

- **E1. Typed message, external signer.** An implementation MUST build the sealed signature message
  with its typed builder, from the outer PubKey, the `recipient_id`, the recipient's X25519 key and
  `msg`. It MAY hand exactly those bytes to an external signer that holds the private key of `from`,
  and MUST NOT offer a function that passes bytes chosen by its caller to that signer as an SBTP
  signature. The same holds for the block signature message (core spec §3.2) and for the signer of
  ADR 0053 rule 17. An SBTP key MUST NOT sign a message that starts with a signature prefix of core
  spec §3.5 and was not built for that prefix's use; this extends ADR 0002 rule 8 from `SIG_PREFIX` to
  every prefix of the table.
  *Reason:* the typed builder is what binds a signature to one use. The signer cannot check that; the
  code that calls it can.
- **E2. `from` before the signature.** A sender SHOULD check `from` before it asks for a signature:
  `from` passes V1 and V2 of core spec §3.2, and is the public key of the signer it will ask. A
  two-phase seal SHOULD refuse, in its preparation step, a `from` that fails V1 or V2.
  *Reason:* `from` is not part of the signed message, so a bad `from` is found only when `sig` is
  verified, after the signer was used. An external signature may need a user action, and a signature
  that is then thrown away still exists outside the implementation.
  *Note for `sbtp-core`:* the V1 and V2 check is private (`check_public_key` in `verify.rs`). E2 needs
  a public function, for example `check_public_key(&[u8; 32]) -> Result<(), Error>` returning
  `InvalidPublicKey`, documented as the V1 and V2 check of §3.2.
- **E3. Verify before use.** A sender SHOULD verify `sig` by `from` over the sealed signature message,
  with criteria V1 to V6 of core spec §3.2, before it seals the plaintext. A sender whose block
  signature is made outside the implementation SHOULD verify it the same way before it publishes the
  block.
  *Reason:* a recipient ignores a block with a bad `sig` silently (`l2-grammar.md` §5.3, order of
  checks): the sender would never learn that its message was lost. A faulty deterministic Ed25519
  signature can also expose the private key; verifying it before it leaves the sender keeps it off the
  network. The cost is one verification per seal. Not a MUST: a recipient verifies anyway, and an
  implementation that signs inside itself with a tested library gains little.
- **E4. One ephemeral key, one block.** The ephemeral outer key of a sealed block (`l2-grammar.md`
  §5.2) signs exactly one `block_id`. Each seal draws a new key from the secure random source. After a
  failed seal (a refused `from`, a bad `sig`, an error of the external signer) or for any later
  attempt, the sender MUST draw a new key and MUST NOT reuse the earlier one or a signature made for
  it. Submitting the same bytes of a sealed block again (ADR 0043) is not a new use: it is the same
  block. The HPKE encapsulation is also new for each seal (RFC 9180 single-shot).
  *Reason:* "used for this block only" already forbids a second block under one key; a retry that
  builds a new plaintext, a new encapsulation or a new nonce makes a new block. Reusing the key would
  link two sealed blocks to one sender action and break the unlinkability that the ephemeral key
  gives.

## Consequences

- **`sbtp-seal`.** The two-phase seal already builds the message with `sealed_sig_message` (E1),
  verifies `sig` in `PendingSeal::finish` (E3) and draws a new ephemeral key at each `seal_prepare`,
  with `PendingSeal` consumed by `finish` and not `Clone` (E4). E2 needs a `from` check in
  `seal_prepare`, on a public V1 and V2 check of `sbtp-core`.
- **`sbtp-core`.** A public `check_public_key` (E2). The rule of E1 on the block signature is already
  met: `sbtp-core` builds the 49-byte message.
- **`sbtp-wasm`, client SDK.** A binding that hands a message to a Web Crypto key MUST take that
  message from the typed builders only (E1). The signer of ADR 0053 rule 17 receives 49-byte block
  messages; a sealed message goes through the two-phase seal.
- **Security.** Unchanged for a key held inside the implementation. For an external signer, the
  domain separation of §3.5 holds as long as only typed messages reach it (E1); an application that
  lets other code use the same key handle is outside this guarantee.
- **Test cases.** `sbtp-seal` tests: a `from` that fails V1 or V2 is refused at preparation; a wrong
  `sig` is refused at `finish`; two preparations draw two different outer keys. No frozen vector.
- **Compatibility.** No wire change. A sealed block made before this ADR is valid.

## Spec change on acceptance

Applied on acceptance (2026-11-21).

`l2-grammar.md` §5.3, the sentence "Implementations expose this message through a typed builder only,
never a generic signature of arbitrary bytes." is replaced by (E1):

> An implementation MUST build this message with a typed builder from these fields, and MUST NOT
> offer a function that signs bytes chosen by its caller as `sig`. It MAY hand exactly the built
> message to an external signer that holds the private key of `from`. (ADR 0055)

and gains, after it (E2, E3):

> - A sender SHOULD check, before it asks for `sig`, that `from` passes V1 and V2 of core spec §3.2
>   and is the key of the signer it asks. It SHOULD verify `sig` with V1 to V6 before it seals the
>   plaintext. (ADR 0055)

`l2-grammar.md` §5.2, the bullet **Ephemeral signer** gains (E4):

> The key signs exactly one `block_id`. A sender that seals again, after a failure or for any other
> reason, draws a new key; submitting the same block bytes again is not a new use. (ADR 0055)

Core spec §3.5, a bullet after "A signature prefix MUST NOT be a prefix of another." (E1):

> - An SBTP key MUST NOT sign a message that starts with a signature prefix of this table and was not
>   built for that prefix's use. A signer outside the implementation receives only such built
>   messages. (ADR 0002, ADR 0055)

Core spec §3.2, the bullet on deterministic signing gains (E3):

> A sender whose signature is made outside the implementation SHOULD verify it with V1 to V6 before
> it publishes the block. (ADR 0055)

## Rejected alternatives

- **Forbid external signers for `sig`.** The identity key would have to be extractable to reach the
  implementation, which exposes it to any script of the page (`l2-grammar.md` §5.5, storage). A
  non-extractable key is the safer custody.
- **Put `from` in the signed message.** It would bind `sig` to `from` explicitly, but it changes the
  wire meaning of every sealed payload, and the signature by `from` already binds it. E2 removes the
  practical cost without a wire change.
- **Ed25519ctx for domain separation.** Not exposed by Web Crypto or by most libraries (ADR 0002,
  rejected alternatives); the prefixes give the same separation with pure Ed25519.
- **Verification as a MUST (E3).** The recipient's check already decides validity; a MUST would add
  nothing to interoperability. The SHOULD covers the silent loss and the fault case.
- **Reuse the ephemeral key on a retry of the same message.** A retry builds a new encapsulation and a
  new block; one key across two blocks links them.
