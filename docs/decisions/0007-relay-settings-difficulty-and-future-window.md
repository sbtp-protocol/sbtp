# 0007: Relay settings: PoW difficulty and future timestamp window

- Status: accepted (by the project owner, 2026-11-18)
- Amended by: 0045 (rule 1, last sentence: a network difficulty `D_NET` is defined by the specification; rejected alternative "Network-wide difficulty")
- Date: 2026-11-18
- Decision: project owner, 2026-11-18
- Questions: Q-06 (resolved), Q-07 (partially), Q-08 (partially: `GET /sbtp/v1/info`)
- Impact: spec §2 (Timestamp row), §2.2, §3.3, §4 (`PUT`, new `GET /sbtp/v1/info`); `sbtp-relay`
  (settings, clock, policy check, `/info`); `sbtp-core` (no change; constraint "no clock"); clients (read
  `/info` before mining); no layer 0 test vector to regenerate

## Context

- **Q-06.** The difficulty is "network-wide" in doc 01, "configured on the relay" in doc 02 and per
  application container (`pow_min_difficulty`) in doc 04. A client has no way to learn a relay's difficulty.
- **Q-07.** The Timestamp field is chosen by the sender. Nothing bounds it. ADR 0004 rule 11 makes every
  Timestamp value well-formed and states that "the time bound is a relay policy".
- ADR 0004 rule 13: `sbtp-core` takes the difficulty `d` as a parameter; "the difficulty is the only local
  parameter of validation".

## Decision

### Settings

1. The minimum PoW difficulty is a setting of each relay, named `min_pow_difficulty`: an integer from 0 to
   256, the value `d` of check C1 (spec §3.3). There is no network-wide difficulty.
2. The maximum future window is a setting of each relay, named `max_future_ms`: a duration in
   milliseconds. Its default value is 300,000 (5 minutes).
3. A relay MUST reject a submitted block whose Timestamp is greater than `now + max_future_ms`, `now`
   being the relay's clock as a Unix time in milliseconds. This is policy check P1.
4. P1 is a relay policy check, not a format rule. A block rejected by P1 is well-formed (ADR 0004 rule 11
   is unchanged) and may be accepted later or by another relay.

### Publication

5. A relay MUST publish both settings through `GET /sbtp/v1/info`.
6. A sender SHOULD read `/info` before mining a block for a relay.

### `sbtp-core`

7. `sbtp-core` MUST NOT read a clock, nor any other ambient state (environment, configuration, network).
   Its functions depend only on their arguments. The difficulty is an argument (ADR 0004 rule 13). The
   Timestamp of a built block is an argument. P1 is implemented in `sbtp-relay`.

### Order, HTTP code, scope and `/info`

8. **Order.** A relay applies P1 after F9 and before C1: the Timestamp is at a fixed offset and the
   comparison costs less than the hash. The comparison MUST NOT overflow (`now + max_future_ms` saturates
   at `2^64 − 1`).
9. **HTTP code.** A block rejected by P1 gets `400 Bad Request`, like C1, the other check that depends on
   a relay setting.
10. **Scope of P1.** P1 applies to blocks submitted to the relay (`PUT`, and WebSocket submission when it
    is specified). It does not apply to blocks already stored, nor to `GET`. This ADR sets no bound in the
    past. The synchronisation path (spec §5) is decided with Q-11.
11. **`/info` response.** `200 OK`, `Content-Type: application/json`, a JSON object with at least:

    ```json
    { "min_pow_difficulty": 16, "max_future_ms": 300000 }
    ```

    Both members are integers. A relay MAY add members. A client MUST ignore members it does not know.
12. **Changes.** A relay MAY change its settings at any time. A client MUST NOT assume that a value read
    from `/info` stays valid; after a `400`, it SHOULD read `/info` again before retrying.

## Consequences

- **`sbtp-core`: no code change required.** The working tree was checked on 2026-11-18: no `std::time`,
  `SystemTime` or `Instant` in `crates/sbtp-core/`; `BlockBuilder::timestamp(u64)` and
  `BlockId::meets_difficulty(u32)` take their inputs as arguments. Rule 7 is a constraint for the future:
  no "current time" helper, no default difficulty constant read from the environment. It keeps the crate
  `no_std`, deterministic and usable in WASM without a time source. ADR 0004 rule 13 stays true: P1 is not
  part of `sbtp-core` validation and adds no variant to its error type.
- **`sbtp-relay`.** Two settings, a clock, check P1, the `/info` handler. The relay stays stateless in the
  sense of spec §1: the clock is local and shared with no one.
- **Test vectors.** No layer 0 vector changes: the vectors "Timestamp `0`" and "Timestamp `2^64 − 1`" stay
  valid at the `sbtp-core` level. P1 is covered by relay integration tests, with an injected clock:
  `Timestamp = now + max_future_ms` accepted, `now + max_future_ms + 1` rejected, `2^64 − 1` rejected
  without overflow.
- **Application difficulty.** A layer 2 difficulty threshold (`pow_min_difficulty`) is not enforced by a relay: a relay
  never parses a payload (`architecture.md` §1). It can only be a filter applied by layer 2 clients.
- **Interoperability.** A block accepted by one relay can be refused by another (higher difficulty, slower
  clock). This is inherent to per-relay settings. Until the error body is specified (Q-08), a client cannot
  tell P1 from C1 or from a format error: all three give `400`.
- **Security.**
  - P1 bounds how far a sender can post-date a block on a given relay. It does not make the Timestamp
    trustworthy: a sender can still back-date freely, and can submit a block dated in the future once that
    date is reached. The layer 2 rules that depend on Timestamp (votes, indexes) stay open (Q-07).
  - PoW alone does not stop an attacker with GPUs. The cost of one attempt is one BLAKE3 compression for a
    minimal block and does not grow with the payload size (security review, info point 1). Rate limiting
    per IP and per key stays a relay implementation task (the roadmap (not published), Phase 2); it is not a protocol
    rule.
  - A relay with a wrong clock rejects valid blocks (clock behind) or accepts post-dated ones (clock
    ahead). Operators SHOULD synchronise the relay clock (NTP).
- **Compatibility.** No block exists. No format change.

## What this ADR resolves and what stays open

| Question | Resolved here | Still open |
|---|---|---|
| Q-06 | Who sets the difficulty (each relay); how a client learns it (`/info`). | Nothing. |
| Q-07 | Bound on future timestamps, as a relay setting. | Milliseconds everywhere in layer 2 (`index.rolling.window_start` is in seconds); vote tie-breaking on equal timestamps; client-side capping of future dates. |
| Q-08 | Existence and minimal content of `GET /sbtp/v1/info`. | `/query` response format and pagination; WebSocket protocol; HTTP/3; error body. |

## Rejected alternatives

- **Network-wide difficulty.** Needs a consensus or a shared state. Contradicts the stateless principle.
- **Difficulty per application container, enforced by the relay.** The relay would have to parse payloads.
- **Fixed 5-minute window in the format.** A format rule cannot depend on a clock: two implementations
  would disagree on the same bytes. ADR 0004 rule 11 already excludes it.
- **Timestamp check in `sbtp-core` with an internal clock.** Breaks `no_std`, determinism and the test
  vectors.
- **`425 Too Early` or `422` for P1.** `425` is defined for TLS early data replay (RFC 8470). `422` is used
  by the spec for cryptographic failures (C2, C3).

## Spec change

Applied to `docs/spec/sbtp-core-v0.2.md` on 2026-11-18.

**§2, table.** In the Timestamp row, replace `` `[Q-07]` `` with `Not interpreted by layer 0 validation (§2.2).`

**§2.2, "Well-formed cases".** Replace ``any value of Timestamp (`[Q-07]`) or Nonce`` with
`any value of Timestamp or Nonce`.

**§2.2.** After the paragraph about R1, add:

```markdown
A relay adds one policy check, P1, between F9 and C1, on submitted blocks only: the Timestamp MUST NOT be
greater than `now + max_future_ms` (§4, `GET /sbtp/v1/info`). P1 depends on the relay's clock and
settings. It is not a format rule, and `sbtp-core` does not implement it. (ADR 0007)
```

**§3.3.** Replace the last bullet (``The minimum difficulty is a relay setting. `[Q-06]` ``) with:

```markdown
- The minimum difficulty `d` is a setting of each relay (`min_pow_difficulty`, 0 to 256), published by
  `GET /sbtp/v1/info` (§4). There is no network-wide difficulty. An implementation of validation takes `d`
  as a parameter and MUST NOT read a clock or any ambient state. (ADR 0007)
```

**§4, intro.** "validates only binary conformance, the PoW and the signature" becomes "validates only
binary conformance, its timestamp policy, the PoW and the signature".

**§4, `PUT /sbtp/v1/block`.** Replace the processing list and the first response line with:

```markdown
- Processing, in this order (cheapest to most expensive):
  1. format: checks F1 to F9 (§2.2);
  2. timestamp policy: check P1 (§2.2);
  3. PoW difficulty on the `block_id`: check C1;
  4. Ed25519 signature: checks C2 and C3;
  5. storage addressed by the `block_id`, without replacing a block already present (§3.4).
- Responses: `201 Created`; `400 Bad Request` (F1 to F9, P1, C1); `422 Unprocessable Entity` (C2, C3).
```

(The responses are stated in full by ADR 0008.)

**§4.** Add, after `GET /sbtp/v1/block/{block_id}`:

````markdown
### `GET /sbtp/v1/info`

- Response: `200 OK`, `application/json`, a JSON object with at least:

  ```json
  { "min_pow_difficulty": 16, "max_future_ms": 300000 }
  ```

- `min_pow_difficulty`: integer from 0 to 256, the difficulty `d` of check C1 (§3.3).
- `max_future_ms`: integer, in milliseconds. The relay rejects a submitted block whose Timestamp is greater
  than its clock plus this value (P1). Default: 300,000.
- A relay MAY add members. A client MUST ignore members it does not know. A relay MAY change its settings
  at any time. A sender SHOULD read `/info` before mining. (ADR 0007)
````

Applied to `docs/spec/architecture.md` §2, "Validation pipeline": insert, between items 1 and 2,
`Timestamp policy: Timestamp against the relay clock plus the configured window.` and renumber.
