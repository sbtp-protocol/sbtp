# 0008: Idempotent `PUT`: `201 Created` for a new block, `200 OK` for a known block

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0014 (the 66,133 / 66,134-byte bounds read as 65,909 / 65,910)
- Date: 2026-11-18
- Decision: project owner, 2026-11-18
- Questions: Q-09 (resolved), Q-08 (partially: `PUT` status codes)
- Clarifies: ADR 0004 rule 15 (HTTP code of an oversized body)
- Impact: spec §4 (`PUT /sbtp/v1/block`); `sbtp-relay` (`PUT` handler, storage return value); clients
  (`cli-demo`, `sbtp-wasm`, web client); no `sbtp-core` change; no test vector to regenerate

## Context

Spec §4 gives `201 Created` for a stored block and leaves the answer for a block already present to
`[Q-09]`. ADR 0003 (accepted) fixes the storage behaviour: "first write wins" (rule 9), validation before
storage and the identical-bytes shortcut (rule 10). Only the HTTP status is missing.

## Decision

### Success codes

1. `PUT /sbtp/v1/block` answers `201 Created` when the block is valid and its `block_id` was not stored:
   the request stored it.
2. `PUT /sbtp/v1/block` answers `200 OK` when the block is valid and its `block_id` is already stored. The
   stored bytes are not replaced (ADR 0003 rule 9).
3. A relay MUST NOT answer `409 Conflict`, nor any other error status, to a valid block already present.
4. A client MUST treat `200` and `201` as the same success: the relay holds a block with this `block_id`.
5. On `201`, a relay SHOULD send `Location: /sbtp/v1/block/{block_id}`, the `block_id` in lowercase
   hexadecimal. It MAY send it on `200`. This ADR defines no response body.
6. When several concurrent requests carry the same new `block_id`, at most one gets `201`: the one whose
   write created the stored file. The others get `200`.

### Oversized body (clarification of ADR 0004 rule 15)

7. A relay MUST limit the request body of `PUT /sbtp/v1/block` to `MAX_BLOCK_LEN` (66,133 bytes) at the
   transport level, before any parsing.
8. A body longer than this limit gets `413 Content Too Large`. This is a transport rejection: no check of
   spec §2.2 has run, and no `sbtp-core` error is produced.
9. A block whose binary analysis fails gets `400 Bad Request`, as ADR 0004 rule 15 states for F1 to F9.
   This includes F2 (`TooLong`) whenever it is reached, for example behind a proxy or a transport with
   another limit.
10. ADR 0004 rule 15 is not amended: it assigns codes to check results. Rules 7 and 8 add a rejection that
    happens before the checks. The `413` recommended by Q-09 "for F2" is adopted for the transport limit,
    not for F2.

## Consequences

- **Validation comes first.** "Valid" means: F1 to F9, the relay policy check P1 (ADR 0007), C1,
  then C2 and C3, or the shortcut of ADR 0003 rule 10 (identical bytes already stored). A duplicate that
  fails a check gets the error status of that check, not `200`. A known block that no longer meets a raised
  `min_pow_difficulty` gets `400`; it stays stored.
- **Signature variants.** A valid block with a known `block_id` and different signature bytes gets `200`.
  The relay keeps the first bytes. A client MUST NOT conclude from `200` that the relay stores the exact
  bytes it sent (spec §3.4, "Full bytes").
- **Retries.** A client can resend a block after a timeout without special handling. This is what makes
  gossip and multi-relay publication simple.
- **`sbtp-relay`.** The storage operation must report "created" or "already present". With exclusive
  creation of the final file (security review B-6, ADR 0009), this is the result of the create call: no
  extra lookup, and rule 6 holds without a lock.
- **`Location`.** RFC 9110 §15.3.2 (checked on rfc-editor.org, 2026-11-18): the resource created by a `201`
  "is identified by either a Location header field in the response or, if no Location header field is
  received, by the target URI". The target URI here is `/sbtp/v1/block`, which is not the block. Rule 5
  avoids that reading.
- **Information disclosed.** `200` versus `201` tells the sender whether the relay already had the block.
  `GET /sbtp/v1/block/{block_id}` already gives the same information.
- **Oversized body.** With the limit of rule 7, F2 is not reachable through `PUT`: the transport rejects
  first. `sbtp-core` keeps F2 and its `TooLong` vector: the decoder is also used outside HTTP (WebSocket,
  files, peers). the implementer must check that the framework's body limit answers `413` and that it
  counts the bytes actually read, not only `Content-Length`. Integration tests: 66,133 bytes (parsed),
  66,134 bytes (`413`).
- **`sbtp-core`.** No change.
- **Test vectors.** None at layer 0. Relay integration tests: new block (`201`), same bytes again (`200`),
  signature variant (`200`, stored bytes unchanged), duplicate with an invalid signature (`422`), two
  concurrent `PUT`s of the same block (one `201`, one `200`).
- **Compatibility.** No relay is deployed.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-09 | Status for a block already present (`200`), no `409`; `413` for a body over the transport limit, `400` for every binary analysis failure. | Nothing. |
| Q-08 | Status codes of `PUT`. | `/query` response format and pagination; WebSocket protocol (acknowledgement of a submitted frame included); HTTP/3; error body. |

## Rejected alternatives

- **`409 Conflict` for a known block.** Makes a retry look like a failure. The block is not in conflict
  with anything: it is the same block (ADR 0003 rule 8).
- **`201` in both cases.** Hides useful information and is inaccurate: nothing is created.
- **`200` in both cases.** Simpler, but a sender can no longer tell that its block was new, for example to
  decide whether to announce it to peers.
- **`204 No Content` for a known block.** Equivalent to `200` without a body. `200` leaves room for a body
  if Q-08 defines one.

## Spec change

Applied to `docs/spec/sbtp-core-v0.2.md` on 2026-11-18, merged with the processing list of ADR 0007.

**§4, `PUT /sbtp/v1/block`.** A "Body limit" bullet is added before the processing list, and the
"Responses" bullet is replaced:

```markdown
- Body limit: a relay MUST limit the request body to 66,133 bytes (`MAX_BLOCK_LEN`) at the transport
  level. A longer body gets `413 Content Too Large` before any parsing.
```

```markdown
- Responses:
  - `201 Created`: the block is valid and was not stored; the relay stored it. The relay SHOULD send
    `Location: /sbtp/v1/block/{block_id}` (lowercase hexadecimal).
  - `200 OK`: the block is valid and its `block_id` is already stored. The stored bytes are not replaced
    (§3.4). A relay MUST NOT answer `409` in this case.
  - `400 Bad Request`: F1 to F9, P1, C1. Every failure of the binary analysis gets `400`, F2 included if
    it is reached despite the body limit.
  - `413 Content Too Large`: body longer than the body limit, rejected before any parsing.
  - `422 Unprocessable Entity`: C2, C3.
- A client MUST treat `200` and `201` as the same success. When concurrent requests carry the same new
  `block_id`, at most one gets `201`. (ADR 0004, ADR 0007, ADR 0008)
```
