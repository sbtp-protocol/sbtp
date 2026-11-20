# 0045: Network PoW difficulty: one value that replicating relays do not exceed

- Status: accepted (by the project owner, 2026-11-21)
- Date: 2026-11-20
- Questions: Q-28 (partially: the default value; the phone measurement stays open)
- Amends: ADR 0007 rule 1 (last sentence, "There is no network-wide difficulty") and its rejected
  alternative "Network-wide difficulty"; ADR 0019 rule 1 (the default of `min_pow_difficulty` is the
  network value). Nothing else in ADR 0007, ADR 0019 or ADR 0026 changes
- Depends on: ADR 0007 rules 10 and 12, ADR 0023 rule 1 (a stored file is not re-checked against C1),
  ADR 0026 (recipient difficulty, `0` by default), ADR 0043 rule 3 (a `PUT` of an expired block is a new
  block)
- Impact: core spec §3.3; `architecture.md` §2 (one part, "Replication"); `sbtp-core` (one constant);
  `sbtp-relay` (default taken from the constant, one start-up warning); clients and the mirror tool
  (mining target, skip rule); no wire format change, no test vector change

## Context

Every relay sets its own `min_pow_difficulty` (ADR 0007 rule 1; default 16, ADR 0019 rule 1). The network
layer now starts: clients publish one block to several relays, and a mirror tool copies blocks between
relays. A block is signed and its Nonce is covered by the `block_id` and the signature: nobody but its
author can raise its difficulty. A block accepted by a relay at `d = 16` and copied to a relay at `d = 20`
is refused there, forever.

ADR 0007 rejected a network-wide difficulty because it "needs a consensus or a shared state". A value fixed
by the specification is neither: it is a constant of the protocol, like the maximum block size, and a
relay reads nothing to apply it.

Mining time of the WASM build in V8 (Node 22, Apple Silicon), median / 95th percentile:

| `d` | Median | p95 |
|---|---|---|
| 16 | 6 ms | 22 ms |
| 18 | 17 ms | 84 ms |
| 20 | 82 ms | 251 ms |

Phones are slower and were not measured.

## Decision

1. **Network value.** The specification defines the network difficulty `D_NET`. Its value is 16. It
   changes only by a revision of the specification (a new ADR), under rule 7.
2. **Relay default.** A relay SHOULD set `min_pow_difficulty = D_NET`. The default of `sbtp-relay` is
   `D_NET`.
3. **Ceiling for replication.** A relay that takes part in replication (it accepts blocks copied from
   other relays, or is offered to clients as one of several publication targets) MUST NOT set
   `min_pow_difficulty` above `D_NET`. A relay with a higher value is outside the network: a block
   accepted elsewhere may be refused there. Its `/info` shows it; a client or a mirror treats it as a
   relay with its own policy. A relay list published for the network (bootstrap list, to be specified)
   SHOULD list only relays at or below `D_NET`.
4. **Lower is allowed.** A relay MAY set `min_pow_difficulty` below `D_NET`, down to 0. Blocks it accepts
   below `D_NET` may then be refused by other relays.
5. **Senders.** A client that publishes to several relays, or wants its block to be copyable, SHOULD mine
   at `max(D_NET, the min_pow_difficulty of each target)`, even when a target asks for less. It reads
   `/info` as before (ADR 0007 rule 6).
6. **Mirrors.** A mirror copies a block by a `PUT` of the same bytes. It MUST NOT re-mine, re-sign or
   alter a block: it cannot, and the result would be another block. When the block's `block_id` has fewer
   leading zero bits than the target's `min_pow_difficulty`, or the target answers `400`
   `InsufficientPow`, the mirror skips the block for that target, counts the skip, and does not retry it
   until the target's `/info` shows a lower value. A skip is not an error of the source relay
   (ADR 0026 rule 4). The mirror MAY check the leading zero bits before the `PUT` to save the request.
7. **Changing `D_NET`.** The floor applies at first acceptance only: a relay never re-checks C1 on a block
   it holds (ADR 0023 rule 1), so a change of `D_NET` never removes a held block.
   - **Lowering** strands nothing. Relays lower first; clients mine at the new value after the relays
     they target publish it.
   - **Raising** is announced by a spec revision that names the new value and an effective date.
     Clients mine at the new value from the announcement; relays raise `min_pow_difficulty` at the
     effective date, not earlier. Blocks mined before the announcement at the old value stay held and
     served where they are. They can no longer be copied to a relay that has raised, nor re-accepted by
     it after an eviction (ADR 0043 rule 3: a re-acceptance is a new block and passes C1 again). Their
     availability then rests on the relays that hold them and on archive relays (ADR 0043 rule 1).
   - Copying older blocks below a raised floor between relays that trust each other is an admission
     policy for synchronisation, decided with Q-11 (ADR 0007 rule 10, ADR 0026 rule 6). This ADR does
     not allow it on `PUT`.
8. **Recipients.** ADR 0026 is unchanged: a recipient of a fetched block applies its own `d`, `0` by
   default. `D_NET` is an admission bound on `PUT`, not a validity rule for readers.

## Consequences

- **Interoperability.** A block mined at `D_NET` is accepted by every relay that follows rule 3. Mirrors
  and multi-relay publication work without per-pair negotiation.
- **Cost.** At 16 the median mining time is 6 ms on a desktop browser; the phone figure is Q-28.
  Lowering later is free (rule 7), raising needs a transition; 16 is therefore a safe starting value.
- **Anti-spam.** A relay can no longer defend itself by raising the difficulty while it stays in the
  network. Its other defences are unchanged: rate limits per client (ADR 0018), the quota and `507`
  (ADR 0013).
- **`sbtp-core`.** One public constant, `NETWORK_POW_DIFFICULTY: u32 = 16`, next to `MAX_DIFFICULTY`.
  It is a value, not ambient state (ADR 0007 rule 7 holds). Validation still takes `d` as an argument.
- **`sbtp-relay`.** The default of `min_pow_difficulty` reads the constant (today a literal 16 in
  `config.rs`). A `config_warning` at start-up when the value is above `D_NET`: "this relay is outside
  the network difficulty; blocks accepted by other relays may be refused".
- **Clients.** `cli-demo` and the web client mine at `max(D_NET, target)` by default (rule 5).
- **Mirror tool.** Implements rule 6 and a counter of skipped blocks per target.
- **Test vectors.** None: the vectors already exercise C1 at given values of `d`.
- **Compatibility.** Nothing is released. Relays at the default are already at 16.

## Spec change on acceptance

Applied on acceptance (2026-11-21).

Core spec §3.3, the bullet "The minimum difficulty `d` is a setting of each relay…" replaced by:

> - The minimum difficulty `d` is a setting of each relay (`min_pow_difficulty`, 0 to 256), published by
>   `GET /sbtp/v1/info` (§4). An implementation of validation takes `d` as a parameter and MUST NOT read
>   a clock or any ambient state. (ADR 0007)
> - The network difficulty `D_NET` is 16. A relay SHOULD set `min_pow_difficulty = D_NET`. A relay that
>   takes part in replication MUST NOT set it above `D_NET`; it MAY set it below. A sender that wants its
>   block to be accepted by every such relay mines at `D_NET` or above. `D_NET` changes only by a
>   revision of this specification; a relay never re-checks C1 on a block it holds. (ADR 0045)

`architecture.md` §2, new part after "Quota":

> ### Replication
> - A mirror copies a block by a `PUT` of the same bytes to another relay. It never re-mines, re-signs or
>   alters a block. A block below the target's `min_pow_difficulty` is skipped for that target and
>   counted; it is not an error of the source. (ADR 0045)
> - When `D_NET` is raised, clients mine at the new value from its announcement and relays raise their
>   floor at its effective date. Blocks mined earlier stay where they are held. (ADR 0045)

## Rejected alternatives

- **Keep per-relay difficulty with no ceiling.** Replication then fails silently between any two relays
  whose settings differ, and a sender cannot know which relays a mirror will later target.
- **Difficulty that depends on the block's Timestamp** (old floor for blocks dated before a raise). The
  Timestamp is chosen by the sender: a spammer back-dates and pays the old price, so the raise buys
  nothing.
- **Accept below-floor blocks on `PUT` when they come from a mirror.** A `PUT` does not authenticate its
  sender; any spammer would claim to be a mirror. Trusted peer admission belongs to Q-11.
- **A difficulty member in `/info` that announces the network value.** `/info` is not authenticated
  (ADR 0026) and the value is a constant of the spec; publishing it adds nothing a client can trust.
