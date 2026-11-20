# 0026: PoW difficulty applied by the recipient of a requested block

- Status: accepted (project owner, 2026-11-19)
- Clarifications: 2026-11-19, after `cli-demo query` (exit status of `cli-demo get` below the local
  floor), accepted by the project owner, 2026-11-19
- Date: 2026-11-19
- Questions: Q-32
- Depends on: ADR 0003 rule 11 (receipt), ADR 0004 rule 13 (`d` is the only local parameter of
  validation), ADR 0007 rules 1, 6 and 12 (`min_pow_difficulty` is a relay setting that may change),
  ADR 0023 rule 1 (a relay does not re-check C1 on a stored file)
- Related: Q-28 (default relay difficulty; not affected), Q-26 (client-side resource bounds), Q-11
  (admission of blocks received by synchronisation; not decided here)
- Impact: spec §3.3 and §3.4 ("Receipt"), §4 `GET /sbtp/v1/block/{block_id}`; `examples/cli-demo`
  (`get`: help text and error message; no change of default); `sbtp-wasm` and the web client (Phase 3:
  same rule); no `sbtp-core` change; no `sbtp-relay` change; no test vector

## Context

Spec §3.4 "Receipt" requires every recipient of a block requested by its identifier to apply full
validation (§2.2) before any storage or use. Full validation includes C1, which takes a difficulty `d`
as a parameter (ADR 0004 rule 13). The spec says which `d` a relay applies to a submitted block
(`min_pow_difficulty`, §3.3). It does not say which `d` a recipient applies to a block it fetched.

Facts that the decision relies on:

- The format carries no claimed difficulty. The only difficulty of a block is the number of leading
  zero bits of its `block_id`. "The block's own difficulty" is therefore not a criterion: every block
  meets it.
- A relay MAY change `min_pow_difficulty` at any time (ADR 0007 rule 12). A block stored under an
  earlier, lower setting stays stored and served: ADR 0023 rule 1 does not re-check C1 on a stored file,
  and `sbtp-relay` applies C1 at `d = 0` there (`store.rs`, `full_validation`).
- One block can be held by several relays with different settings. Identity is the `block_id` alone
  (§3.4).
- `/info` is not authenticated by the protocol. Over plain HTTP a network attacker can change it
  (security review `docs/security/2026-11-19-cli-demo.md`, I-1).
- At `8c42d95`, `cli-demo get` applies `--difficulty <D>`, default `0`, and never reads `/info` for `get`.
- Layer 2 already defines a client-side difficulty filter: `pow_min_difficulty`
  (ADR 0007 "Application difficulty").

Options:

| Option | Assessment |
|---|---|
| A. The `min_pow_difficulty` that the serving relay publishes in `/info` | The same bytes become valid from one relay and invalid from another, or from the same relay before and after a settings change. A relay that raised its setting would appear to serve invalid blocks it is allowed to serve. A forged `/info` turns into a denial of reads. One extra request per relay. |
| B. The block's own claimed difficulty | No such field exists. Vacuous. |
| C. A local setting of the recipient, `0` when it has none | Validity of a received block depends only on its bytes, the requested identifier and the recipient's own policy. Same result from every relay. A recipient that wants an anti-spam floor still has one. |
| D. No C1 on receipt | Equivalent to C with `d = 0` in every case, but removes the floor some recipients want, and contradicts "full validation" in §3.4. |

## Decision

1. **Local parameter.** The difficulty `d` that a recipient applies in C1 to a block received in response
   to a request by identifier (§3.4 "Receipt") is a local setting of that recipient. It is independent of
   any relay.
2. **Default.** A recipient that has no difficulty policy of its own applies `d = 0`. C1 then rejects
   nothing (ADR 0004 rule 13).
3. **Not from `/info`.** A recipient MUST NOT take `d` from the `/info` response of the relay that served
   the block, nor from any other relay's settings. `min_pow_difficulty` describes what a relay admits
   with `PUT` now (ADR 0007); it is not a property of the blocks it holds.
4. **Local floor.** A recipient MAY apply `d > 0`, for example as an anti-spam filter on blocks listed by
   `/query`. A block that fails only this C1 is refused by the recipient's policy. The recipient MUST NOT
   report it as an invalid block served by the relay: unlike R1, C2 and C3, it does not show that the
   relay broke spec §4 ("A relay MUST serve only bytes that pass full validation").
5. **Layer 2 filters.** A layer 2 filter on difficulty (`pow_min_difficulty`) applies
   after receipt validation and does not change rules 1 to 4.
6. **Scope.** These rules cover the use of a fetched block by a client, and the receipt check of
   §3.4. They do not decide what a relay or a peer applies before it stores a block received by
   synchronisation (§5); that is an admission policy, decided with Q-11 (ADR 0007 rule 10).

## Consequences

- **Interoperability.** Two recipients with the default policy accept and refuse the same bytes for the
  same requested identifier, whatever relay served them.
- **Security.** PoW stays an admission cost paid at `PUT` time on each relay. A hostile relay can serve
  blocks it mined at low difficulty with its own keys; the default recipient accepts them, because their
  signatures are valid. A recipient that cares sets a local floor (rule 4) or filters at layer 2
  (rule 5). A network attacker who forges `/info` can no longer make a client refuse valid blocks. R1,
  C2 and C3 are unchanged.
- **`sbtp-core`.** No change: `validate_requested(bytes, difficulty, requested)` already takes `d`.
- **`sbtp-relay`.** No change: `GET` already validates stored files at `d = 0` (ADR 0023 rule 1).
- **`examples/cli-demo` (the implementer).** `get` already conforms (default `0`, `/info` not read). Two
  changes: the help text of `get --difficulty` states that it is a local floor, independent of the
  relay's `/info`; when `validate_requested` fails with `InsufficientPow` only because of `--difficulty`,
  the message says the block is below the local floor, not that the relay sent an invalid block.
- **Web client (Phase 3).** Applies `d = 0` by default; any floor is a local or layer 2 setting.
- **Test vectors.** None: the vectors already exercise C1 at given values of `d`.
- **Compatibility.** No format change. No published behaviour of a relay changes.

## Clarification (2026-11-19, after `cli-demo query`): exit status below the local floor

Recorded by the specification editor after the `cli-demo query` merge (`a27ce6e`), accepted by the project
owner, 2026-11-19. It follows the combined review `docs/security/2026-11-19-cli-demo-query.md` (I-3). It
changes no rule above.

- Rule 4 governs what a recipient reports about the relay: its message. It does not require a
  distinct exit status.
- `cli-demo` exits with status 4 both when a block fails full validation (an invalid block, from a
  local file or from the relay's answer) and when a block fails only C1 at the local floor of
  `get --difficulty`. Status 4 means "the block was not accepted by this client"; it does not say who
  is at fault. The messages stay as rule 4 and the Consequences above require: below the local floor,
  the message says the block is valid but below this client's floor and is not a fault of the relay.
- A script that needs to tell the two cases apart runs `get` again without `--difficulty` (`d = 0`):
  exit status 0 then means the first refusal was the local floor.
- The help text of `cli-demo` lists both cases under status 4.

## Rejected alternatives

- **The serving relay's `/info` value** (option A): makes validity depend on the source and on time,
  and turns an unauthenticated response into a read filter.
- **A claimed difficulty in the header**: needs a format change (a new Version value) for no gain; the
  `block_id` already carries the work.
- **No C1 on receipt** (option D): removes the optional floor and contradicts §3.4 as written.
- **A protocol-wide reader floor (for example 16)**: a network-wide difficulty, which ADR 0007 rejects.

## Spec change

Applied on acceptance (2026-11-19). `docs/spec/sbtp-core-v0.2.md`:

**§3.3.** After the bullet on `min_pow_difficulty`, add:

```markdown
- The recipient of a block requested by its identifier (§3.4) applies C1 with a difficulty `d` of its
  own, independent of any relay, and `d = 0` when it has none. It MUST NOT take `d` from the `/info` of
  the relay that served the block. A block that fails only a recipient's own `d > 0` is refused by that
  recipient's policy; it does not show that the relay served an invalid block. (ADR 0026)
```

**§3.4, "Receipt".** Replace "apply full validation (§2.2), criteria V1 to V6 included." with "apply full
validation (§2.2), criteria V1 to V6 included, C1 with the recipient's own difficulty (§3.3)."

**§4, `GET /sbtp/v1/block/{block_id}`.** Replace the last bullet with:

```markdown
- The recipient MUST check that the received block carries the requested `block_id` and validate it
  (§3.4). The `min_pow_difficulty` of `/info` applies to `PUT` only (§3.3).
```

No change to `docs/spec/architecture.md`.
