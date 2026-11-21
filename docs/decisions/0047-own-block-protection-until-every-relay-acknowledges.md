# 0047: An own block stays protected locally until every relay of the list acknowledges it, within a bound

- Status: accepted (by the project owner, 2026-11-21), as proposed, with the starting values of
  rule 11: `publish_min_attempts` 5, `publish_min_wait` 24 hours, `publish_max_wait` 7 days
- Amended by: 0052 (rule 3: a `451` is a final refusal, `refused`; rule 5: a block a relay denied is
  not sent to that relay again automatically, only on a user action, and after `DeniedKey` no block of
  that key is)
- Amended: 2026-11-21, accepted by the project owner on 2026-11-21 (Q-83): amendment D1 below (rules 1,
  2 and 4: a `451` to a presence check of an acknowledged block is an availability event; delivery
  stays `acknowledged`, the relay no longer counts as holding the block, the second bound of rule 4
  does not restart)
- Amended by: 0053, proposed (2026-11-21): amendments D2 (rule 3: every other `5xx` is transient) and
  D3 (rules 2, 3 and 7: a `read_only` URL is not a publication target; a relay the block cannot
  satisfy is `refused` without a request; a failed `/info` read is an attempt)
- Date: 2026-11-21
- Questions: none open; owner direction of 2026-11-21 (a block published to several relays is kept
  until each of them has it, not only the first)
- Amends: ADR 0029 rule 12 (the protection of an own block and the eviction order of the local store).
  Nothing else in ADR 0029 changes
- Depends on: ADR 0008 (`200` and `201` are the same success), ADR 0012 (error names), ADR 0018 and
  spec §4 "Admission control" (`429`, `503`, `Retry-After`, back-off), ADR 0029 rules 7, 14 and 15,
  ADR 0030 (a `3xx` is not repeated), ADR 0043 (re-publication after expiry), ADR 0045 (sender
  difficulty), ADR 0046 (`507` clears when the sweeper makes room)
- Impact: core spec §4, "Client bounds" (one bullet replaced, two added) and "Several relays" (one
  bullet); web client (`web/src/store.js`, `eviction.js`, `relays.js`, `app.js`, `bounds.js`,
  `settings.js` and their tests); `cli-demo` unchanged (it keeps no local store of own blocks); no relay
  change; no wire format change; no test vector

## Context

ADR 0029 rule 12 forbids a client to drop, for its storage budget, "a block the user created that no
relay has yet acknowledged with `200` or `201`". From the first acknowledgement the block may be
evicted.

The clients now publish one block to several relays (spec §4, "Several relays"). With rule 12 as it
stands, a block acknowledged by one relay out of three may be evicted before the other two have it. If
that one relay later evicts it or disappears, the block is lost although the client could have
delivered it. The web client already remembers, per own block, the relays it failed on (`failedOn`) and
sends the block to them again, but the store may evict the block in the meantime.

Protecting a block until every relay acknowledges it has three limits:

1. a relay that is down for good, or that the user stops using, would pin the block forever;
2. some refusals never turn into a success for the same bytes (`400` for a format error, `422`, a
   difficulty above the relay's floor);
3. the local store has a budget (rule 12), and protected blocks are not counted against it.

## Decision

Terms. The **relay list** is the set of relays a client publishes to, identified by their relay URL
(spec §4; ADR 0030). An **own block** is a block the user created. For each own block and each relay of
the list, the client keeps a **delivery state**: `pending`, `acknowledged`, `refused` or `given up`.

1. **Acknowledgement.** A relay acknowledges a block when it answers `201` or `200` to a `PUT` of it.
   A client MAY also count as an acknowledgement a `200` to `GET /sbtp/v1/block/{block_id}` from that
   relay whose body passes the receipt rule (spec §3.4). An acknowledged state never goes back to
   `pending` while the relay stays in the list. A relay can lie about holding a block; no rule of the
   protocol can detect it, and this rule does not try.
2. **Protection.** An own block is **protected** while either:
   - no relay currently in the list has acknowledged it; or
   - at least one relay of the list has acknowledged it and at least one relay of the list is
     `pending` for it.

   A client MUST NOT drop a protected own block to stay within its storage budget, except under
   rule 8. It MUST NOT drop the user's private keys.
3. **Outcomes of a `PUT`.** The client sets the state of the relay for the block from the response:
   - `201`, `200`: `acknowledged`.
   - **Transient**, the state stays `pending` and the attempt counts toward rule 4: no response (a
     network failure, a closed connection), a failed request of ADR 0029 rule 15, `408`, `429`, `500`,
     `502`, `503`, `504`, `507`, and `400` with the error name `TimestampTooFarInFuture` (the relay's
     clock reaches the block's Timestamp later). A `Retry-After` above the client's maximum wait
     (ADR 0029 rule 14) ends the attempt and counts it.
   - **Final**, the state becomes `refused`: `400` with any other error name or with a missing or
     unparseable body, `413`, `422`, a `3xx` (ADR 0030), and any other `4xx`. These answers do not
     change when the same bytes are sent again to the same relay with the same settings.

   A request the client does not send, because the relay is backing off or because it waits for a
   `Retry-After`, is not an attempt.
4. **Bound on a pending relay.** The state of a relay for a block becomes `given up`:
   - when the client has made at least `publish_min_attempts` attempts to that relay for that block
     with no acknowledgement, **and** at least `publish_min_wait` has passed since the first of them;
     or
   - in any case, when `publish_max_wait` has passed since the first acknowledgement of the block by a
     relay of the list.

   The three values are client settings (ADR 0029 rule 2). A client MUST have all three bounds. The
   first bound needs both conditions so that neither a short outage of the relay nor a period where
   the client is not running ends the protection. The second bound ends it even when the client runs
   too rarely to reach the first. While no relay of the list has acknowledged the block, rule 4 does
   not end its protection (rule 2, first case).
5. **After the bound.** A `refused` or `given up` relay no longer protects the block. The client MAY
   still send the block to it later, for example when the relay's `/info` shows a lower
   `min_pow_difficulty` than the block's leading zero bits (ADR 0045 rule 6), or when it republishes
   under ADR 0043. An acknowledgement then sets the state to `acknowledged`; a failure does not make
   the block protected again.
6. **Relay removed from the list.** The client deletes the delivery states of that relay. The relay no
   longer protects any block, and its acknowledgements no longer count for rule 2. An own block that no
   remaining relay has acknowledged is therefore protected again by the first case of rule 2, and the
   client sends it to the remaining relays.
7. **Relay added to the list.** The relay becomes `pending` for every own block that is protected at
   that moment, with its own count of attempts (rule 4, first bound). The second bound of rule 4 is not
   reset. The relay is not a target of the other own blocks; the client MAY send them to it.
8. **Storage budget.** When the client drops blocks to stay within its storage budget, the order is:
   1. blocks fetched from relays, least recently used first;
   2. own blocks that are not protected, least recently used first;
   3. only to store a new own block: own blocks protected by the second case of rule 2, the one whose
      first acknowledgement is oldest first. The client sets their `pending` relays to `given up`
      before it drops them.

   It never drops an own block protected by the first case of rule 2. A fetched block that does not
   fit after steps 1 and 2 is not stored. A new own block is stored even when the budget is not met
   after step 3; the number of own blocks protected by the first case of rule 2 MUST be bounded by a
   client setting, and a new own block above that bound is refused before it is published (ADR 0029
   rule 12, unchanged).
9. **Showing the state.** A client SHOULD show the user an own block protected by the first case of
   rule 2 whose relays are all `refused` or `given up`: no automatic action will deliver it. The user
   can add a relay, export the block or delete it. A deletion by the user is not an eviction and is not
   limited by this ADR.
10. **Clients with no local store.** A client that keeps no local store of own blocks (for example a
    command line tool whose user keeps the block file) has nothing to evict; rules 2 and 8 do not
    apply to it. It SHOULD report, per relay, whether the block was acknowledged, refused or not
    reached, so that the user can send it again.
11. **Guidance (non-normative).** Starting values for a browser client: `publish_min_attempts` 5,
    `publish_min_wait` 24 hours, `publish_max_wait` 7 days. With the per-relay back-off of the web
    client (capped at 5 minutes), five attempts take less than an hour of running time; the 24-hour
    wait makes the bound outlast a relay restart or a day-long outage.

## Consequences

- **Availability.** A block published to several relays is kept until each of them has it, or until
  that relay is found final or unreachable for a bounded time. Losing the one relay that acknowledged
  first no longer loses a block the client could have delivered elsewhere.
- **Storage.** A protected block of the second case of rule 2 is held at most `publish_max_wait` after
  its first acknowledgement, and yields to new own blocks under budget pressure (rule 8, step 3). It
  never yields to fetched blocks. The worst case of rule 8 is unchanged: the cap on own blocks that no
  relay has acknowledged, times 65,909 bytes, above the budget.
- **State per block.** At most one delivery state per relay of the list (bounded by the client's maximum
  number of relays) and, per pending relay, an attempt count and the time of the first attempt; per
  block, the time of its first acknowledgement. The state is local and persistent with the block.
- **Security.** A hostile relay can keep a block protected only up to the bounds of rule 4: it cannot
  pin storage by never answering, nor by answering `503` forever. A relay that falsely acknowledges a
  block shortens its protection; rule 1 accepts this, as ADR 0029 rule 12 did.
- **Interoperability.** None: this ADR changes no message and no relay behaviour.
- **Web client.** Today (`web/src/store.js`) a block has one `acked` flag and a `failedOn` list cut to
  `2 × maxRelays` entries; the store may evict an acknowledged block (`eviction.js`). To conform: a
  per-relay delivery state with attempt counts and times (rules 3 and 4); the outcome of `publishAll`
  carries the status and error name so that final and transient answers differ (rule 3; a
  `backing-off` outcome is not an attempt); `retryTargets` takes the `pending` relays, and every relay
  of the list while no relay of the list acknowledged the block (rules 2 and 7); a hook on a change of
  the relay list (`settings.js`, rules 6 and 7); `planEviction` follows rule 8; three new values in
  `bounds.js` (rule 11); the user sees the blocks of rule 9.
- **`cli-demo`.** Already conforms to rule 10: `publish` lists the relays that failed with the command
  that retries them.
- **Tests.** Web client tests: a block acknowledged by one relay of three stays when the store is full
  of fetched blocks; a relay answering `503` keeps the block protected until both conditions of the
  first bound hold, and no longer; the second bound with no attempt made; `400 InvalidSignature`,
  `422` and `413` make the relay `refused` at once, `400 TimestampTooFarInFuture` and `507` do not;
  removing the only acknowledging relay protects the block again and targets the remaining relays; a
  relay added later is pending only for protected blocks; rule 8 step 3 drops the oldest partly
  delivered block only for a new own block. Crate or package tests, not frozen vectors.
- **Compatibility.** Nothing is released. A block already stored with `acked = true` maps to:
  `pending` for each relay of the list in its `failedOn`, `acknowledged` for the other relays of the
  list, and a first acknowledgement time set to the migration time. A block with `acked = false` is
  `pending` on every relay of the list.

## Amendments (2026-11-21, accepted by the project owner on 2026-11-21)

Raised by ADR 0052 rule 12, which sets a relay to `refused` when a `GET` or `HEAD` of an own block gets
`451`, and by Q-83: that rule did not say what happens when that relay had already acknowledged the
block. No wire format, relay interface or test vector of a frozen set changes.

- **D1. A denial after an acknowledgement is an availability event, not a delivery event (rules 1, 2
  and 4).** Besides its delivery state, the client keeps, per own block and per relay of the list, an
  **availability**: `available` or `refused`. A relay's availability for a block becomes `refused` when
  it answers `451` to a `GET` or `HEAD` of that block; the client records it with the denials of
  ADR 0052 rule 12. When that relay's delivery state is `acknowledged`:
  - *rule 1:* the delivery state stays `acknowledged`. It does not become `refused` or `pending`;
  - *rule 2:* a relay whose availability is `refused` does not count as having acknowledged the block,
    nor as pending for it. If no other relay of the list has acknowledged the block with availability
    `available`, the block is protected again by the first case of rule 2, as after rule 6;
  - *rule 4:* the second bound keeps running from the first acknowledgement of the block by a relay of
    the list, including one whose availability is now `refused`. It does not restart.

  The client keeps the block available on its other relays (rule 5, ADR 0043). It MUST NOT send the
  block to that relay again automatically (ADR 0052 rule 12). The availability returns to `available`
  only when that relay later serves the block (a `200` to a `GET` whose body passes the receipt rule,
  spec §3.4) or acknowledges a `PUT` sent on a user action. A client that drops the denial record
  within its storage bounds (ADR 0052 rule 12) also drops the `refused` availability.

  A `451` to a presence check from a relay whose delivery state is `pending` sets that state to
  `refused` (ADR 0052 rule 12, unchanged): no acknowledgement was acquired. A `451` from a relay whose
  delivery state is `refused` or `given up` changes no delivery state.

Spec change, applied with this amendment: core spec §4, "Client bounds", a bullet after the bullet on
protected blocks:

> - A relay that acknowledged a block and later answers `451` to a `GET` or `HEAD` of it stays
>   acknowledged, but no longer counts as holding the block for this protection, nor as pending for it.
>   The bounded time since the block's first acknowledgement does not restart. (ADR 0047, ADR 0052)

and §4, "Denied blocks", after "MUST NOT send that block to that relay again automatically.":

> When that relay had already acknowledged the block, the `451` changes the block's availability on
> that relay, not its delivery: see "Client bounds".

## Amendments D2 and D3 (2026-11-21, proposed)

Raised by the first TypeScript client (ADR 0053 clarifications S4 and S7). Each is proposed on its own.
No wire format, relay interface or frozen vector set changes.

- **D2. Other `5xx` (rule 3).** Every `5xx` status that rule 3 does not name (`501`, `505`, `506`,
  `508`, `511` and any other) is transient: the state stays `pending` and the attempt counts toward
  rule 4. *Reason:* a `5xx` reports a fault of the server or of a gateway in front of it, not of the
  block's bytes. Rule 4 already bounds what a lasting fault costs; a final classification would let
  one misconfigured proxy end the delivery of every block.
- **D3. Relays the client does not send a block to (rules 2, 3 and 7).** Rule 3 classifies answers;
  it did not say what happens when the client, by the rules of spec §4, sends no `PUT` at all. Such a
  relay received no attempt and stayed `pending` until the second bound of rule 4.
  - **`read_only` URL.** A relay whose last valid `/info` has `"read_only": true` (ADR 0050) is not a
    publication target. It keeps no delivery state, does not protect a block and does not count for
    rule 2. It stays in the relay list for reads. When a later `/info` no longer has
    `"read_only": true`, the relay is handled as a relay added to the list (rule 7). When a relay
    becomes `read_only`, its delivery states are deleted as under rule 6.
  - **Local final refusal.** The client sets the state of a relay to `refused` without sending a
    request when the answer is known and would not change on a repeat (rule 3): the block's
    `block_id` does not meet that relay's `min_pow_difficulty` (the answer would be `400`
    `InsufficientPow`; ADR 0045 rule 6), or the block's Version is not in that relay's
    `block_versions` (the answer would be `400` `UnsupportedVersion`). A relay above the client's
    maximum difficulty (ADR 0029 rule 13) is in the first case only when the block's `block_id`
    does not meet its floor; otherwise it is an ordinary target. Rule 5 applies: when a later `/info`
    makes the block acceptable, the client MAY send it; an acknowledgement sets `acknowledged`.
  - **`/info` not read.** A failed request to `/info` of a relay, made before a `PUT` to it, counts
    as an attempt toward the first bound of rule 4, as the `PUT` would have.

  *Reason:* each of these relays would otherwise keep a block protected for up to `publish_max_wait`
  (7 days by default) with no request that could deliver it.

Spec change on acceptance: core spec §4, "Client bounds", after the bullet "A relay stops being
pending for a block when…":

> - Every `5xx` answer to a `PUT` is transient: the relay stays pending, within the bounds above.
>   (ADR 0047, amendment D2)
> - A `read_only` URL is not a target of publication and is never pending. A relay whose
>   `min_pow_difficulty` the block's `block_id` does not meet, or whose `block_versions` lacks the
>   block's Version, stops being pending without a request: the answer would be a final refusal. A
>   failed `/info` request made before a `PUT` counts as an attempt. (ADR 0047, amendment D3)

Test cases (`client-v1/`, planned): a `501` and a `511` to a `PUT` keep the relay pending; a
`read_only` URL in the list never holds a block protected; a relay at difficulty 24 with a block of 20
leading zero bits is `refused` with no request, and becomes a target again when its `/info` shows 16.

## Spec change on acceptance

Applied on acceptance (2026-11-21).

Core spec §4, "Client bounds", the bullet "When it drops blocks to stay within its storage budget, a
client MUST NOT drop the user's private keys, nor a block the user created that no relay has
acknowledged with `200` or `201`." replaced by:

> - When it drops blocks to stay within its storage budget, a client MUST NOT drop the user's private
>   keys, nor a protected block the user created. Such a block is protected while no relay of the
>   client's relay list has acknowledged it with `200` or `201`, or while one has and another relay of
>   the list is still pending for it. It drops blocks fetched from relays first, then own blocks that
>   are not protected. Only to store a new own block, it MAY drop a block of the second kind, oldest
>   first acknowledgement first. (ADR 0029, ADR 0047)
> - A relay stops being pending for a block when it acknowledges it; when it refuses it with an answer
>   that does not change on a repeat (`400` other than `TimestampTooFarInFuture`, `413`, `422`, a
>   `3xx`, another `4xx` other than `408` and `429`); when the client has made a bounded number of
>   attempts to it over at least a bounded time; when a bounded time has passed since the block's first
>   acknowledgement; or when the user removes it from the list. A request not sent because of a
>   back-off is not an attempt. The bounds are client settings. (ADR 0047)
> - A relay added to the list is pending for every block protected at that moment. Acknowledgements
>   by a relay removed from the list no longer count. (ADR 0047)

Core spec §4, "Several relays (non-normative)", the sentence "`PUT` is idempotent: a block refused or
not reached on one relay MAY be sent again to it later." replaced by:

> `PUT` is idempotent: a block refused or not reached on one relay MAY be sent again to it later. The
> client keeps it until each relay of its list has acknowledged it or is no longer pending for it (see
> "Client bounds").

## Rejected alternatives

- **Keep rule 12 as it is (one acknowledgement suffices).** The first relay to answer decides how long
  the block is kept. A block can be lost while two of three relays never received it.
- **Protect until every relay acknowledges, with no bound.** A relay that is gone, or that refuses the
  block for good, pins it forever, and the local store fills with blocks it cannot release.
- **A time bound alone.** A client that is closed for longer than the bound gives up every relay on its
  next start without one attempt.
- **An attempt count alone.** A client that runs rarely keeps a block protected for months; a client
  that runs constantly gives up during a one-hour outage.
- **A quorum (k of n acknowledgements).** It adds a setting that users cannot judge, and it still needs
  the bounds and the final refusals of this ADR for the relays outside the quorum.
- **Keep counting the acknowledgements of a removed relay.** A user who removes a relay because it
  closed or cannot be trusted would leave blocks that no relay in use holds unprotected.
- **Treat `507` as final.** Under ADR 0046 a relay makes room by demand eviction; `507` is a state of the
  relay, not of the block. It stays bounded by rule 4.
- **Treat a `400` `InsufficientPow` as transient.** The block's proof of work cannot change; only a
  lower floor of the relay makes it acceptable, which rule 5 covers without protecting the block.
