# 0049: Ingest bounds against disk filling: byte budgets per network group, a global cap under disk pressure

- Status: proposed
- Date: 2026-11-21
- Questions: Q-71 (opened: many-network floods and a higher PoW above a share)
- Amends: ADR 0018 rule 35 (one term in the memory bound); ADR 0019 rules 37 and 38 (profile rows and
  policy settings); ADR 0021 rule 41 (counters and gauges). Nothing else in these ADRs changes
- Depends on: ADR 0013 rule 18 and ADR 0025 (stored total), ADR 0018 rules 20 and 21 (client key,
  token buckets), ADR 0027 (limiter table), ADR 0043 (re-acceptance), ADR 0044 (client address behind a
  CDN), ADR 0045 (`D_NET`), ADR 0046 (demand eviction), ADR 0048 (replication bounds)
- Impact: core spec §4 ("Admission control"); `architecture.md` §2 ("Admission control");
  `sbtp-relay` (settings, a second limiter table, the `PUT` storage step, metrics); `deploy/README.md`
  (alerts, CDN edge rule); no wire format change, no test vector

## Context

Security review `docs/security/2026-11-21-demand-eviction.md`, finding M-2. With demand eviction
(ADR 0046), a flood of valid blocks within the rate limits evicts legitimate cold blocks, then keeps the
store full.

- On `small`, one client key (`rate_put_per_min` 30, burst 20, blocks of about 70 KB) writes about
  2.1 MB per minute: 1 GiB in about 8 hours. 100 IPv6 /64s, which one /48 holds, do it in about
  5 minutes.
- PoW at `D_NET = 16` costs about 6 ms per block: one server core mines about 150 blocks per second.
  The proof of work does not bound a flood; the byte budget must.
- The relay cannot judge content, and keys are free: a quota per public key bounds nothing.
- The only attribute a relay has for a writer is its network address, aggregated to `client_ipv6_prefix`
  (/64) or a single IPv4 address (ADR 0018 rule 20).

Owner direction of 2026-11-21: a global ingest cap, limits per larger network prefix, a decision on a
storage share per prefix group, alerts, and a CDN edge rule. The owner's added requirement: **the relay
must not block itself.** Every cap is also a lever: an attacker who exhausts a shared budget denies it
to every honest publisher, and a cap set too tight refuses normal traffic. Each mechanism below is
judged as a defence and as a lever (see "Self-blocking analysis").

## Decision

### Byte budgets per network group (always on)

1. **Groups.** The relay derives the groups of a `PUT` from the same resolved client address as the
   client key (ADR 0018 rule 20, ADR 0020, ADR 0044): for IPv6, its /56 and its /48; for IPv4 (and
   IPv4-mapped IPv6), its /24. A level whose prefix is not shorter than `client_ipv6_prefix` is skipped
   (with `client_ipv6_prefix = 48`, only the /48 is used, and it is also the client key). A key in
   `rate_limit_exempt` has no group and is never charged under rules 1 to 7.
2. **Budget.** Each group has one token bucket counted in bytes. Its rate is `share × R` per hour, where
   `R = ingest_bytes_per_hour` and `share` is `ingest_group_share_pct` for a /48 or a /24 and
   `ingest_group56_share_pct` for a /56. Its capacity is one twelfth of its hourly rate (five minutes).
   A new group starts full.
3. **Charge.** A block stored as new (`201`, a re-acceptance under ADR 0043 included) is charged, to
   each of its groups, the bytes it adds to the stored total (ADR 0013 rule 18, ADR 0025). A `PUT`
   answered `200`, a refused `PUT` and a replicated block (rule 9) are not charged. A bucket MAY go below
   zero by the charges of the `PUT`s already in flight; it is never below `−put_max_in_flight × 70,000`.
4. **Refusal.** A `PUT` whose group bucket is at zero or below gets `429` `RateLimited` before its body
   is read, with `Retry-After` set to the seconds until that bucket is back above zero, rounded up,
   at least 1. Only the requests of that group are refused.
5. **Table.** Group buckets live in a second limiter table with the design of ADR 0027 (bounded map
   preallocated at start-up, order by full time, a full entry dropped first, O(log n) per request), of
   at most `ingest_group_max` entries. An IPv6 `PUT` uses up to two entries, an IPv4 `PUT` one. An entry
   holds one bucket. **When the table is full of entries that are not full, a `PUT` from a group not in
   the table is not checked by rules 2 to 4 and is not charged** (fail open). There is no shared
   overflow group: a full table never refuses an honest group. The global cap (rule 6) still applies.

### Global cap under disk pressure

6. **Global bucket.** One token bucket counted in bytes, rate `R` per hour, capacity `R / 12`. It is
   charged as in rule 3 for every block stored from a `PUT` (exempt keys excepted).
   - It is **checked only while the stored total is at or above the low-water mark**:
     `demand_low_water_pct` of `max_store_bytes` (80 % by default; the same 80 % when demand eviction is
     off). Below it, no `PUT` is refused by this rule, and the bucket still refills and is charged.
   - It is checked at the storage step (core spec §4, `PUT` step 5) for a block that would be stored as
     new, after validation and after the held check. A block the relay holds, not expired, gets `200`
     whatever the bucket. A new block with the bucket at zero or below gets `503` `Unavailable` with
     `Retry-After` set to the seconds until the bucket is back above zero, rounded up, at least 1, at
     most 300. Nothing is stored.
   - With `R = 0`, rules 2 to 7 are off.
7. **No latch.** Every bucket of rules 2 and 6 refills with time alone. No refusal under this ADR
   depends on state other than these buckets and the stored total; none is persisted; none needs a
   restart or an operator action to end. A refused `PUT` is retried by the client later or sent to
   another relay (core spec §4, "Admission control"; ADR 0047).

### Replication and re-acceptance

8. **Re-acceptance.** A `PUT` of an expired or evicted block is a new block (ADR 0043, ADR 0046 rule 22):
   it adds bytes, so it is charged and may be refused as any new block. Republication to a relay under
   pressure therefore goes at the cap's pace; the client keeps the block (ADR 0047) and uses its other
   relays.
9. **Replication has its own budget.** A block stored by replication (ADR 0048) is not charged to the
   global bucket or to any group, and is never refused by this ADR. It is bounded by
   `replication_bytes_per_hour`, by the round-robin share of each peer and by the high-water pause
   (ADR 0048 rules 10, 13, 15). Neither flow can starve the other. The total ingest of a relay is at most
   `R + replication_bytes_per_hour` per hour (on `small`: 200 MiB + 256 MiB).

### Storage share per group: not adopted

10. A relay MUST NOT record the network address, the client key or a group of a client with a stored
    block, in the index or elsewhere on disk. Demand eviction (ADR 0046) does not take the origin of a
    block into account. Reasons in "Rejected alternatives"; the byte budgets of rules 2 to 6 bound what a
    group can add per hour without storing anything.

### First line, operator guidance and later option

11. **CDN edge.** An operator behind a CDN SHOULD also rate-limit `PUT /sbtp/v1/block` at the edge, per
    client address and, where the CDN offers it, per network prefix, so that a flood stops before it
    reaches the origin; the relay's own bounds remain the guarantee.
12. **Alerts.** `deploy/README.md` (written by the relay engineer) lists these alerts on the metrics of
    rule 14 and ADR 0046 rule 29, with these starting thresholds:

    | Alert | Condition | Meaning |
    |---|---|---|
    | Ingest capped | `ingest_capped_total` increases for 15 minutes | The store is above the low-water mark and writers use the whole budget: a flood or real growth. Check `ingest_group_limited_total` and the disk. |
    | Group limited | `ingest_group_limited_total` increases by more than 100 in 15 minutes | One network takes more than its share. Usually a flood; with a carrier NAT, raise `ingest_group_share_pct`. |
    | Group table full | `ingest_group_unchecked_total` increases | Many networks write at once; rule 5 fails open. A many-network flood (Q-71). |
    | Store full | `storage_full_total` increases | `507`: nothing is a candidate for eviction. |
    | Eviction of recent blocks | `demand_evicted_blocks_total` increases while `demand_coldest_ms` is less than 7 days old | Blocks requested within the week are evicted: the store is too small for its traffic, or a flood. |
    | Demand suspended | `demand_suspended` is 1 for more than `demand_epoch_ms` | ADR 0046 rule 13. |

13. **Later option, left open (Q-71).** A writer above its group share could be asked for a higher proof
    of work instead of a `429`. This is not adopted: ADR 0045 makes the difficulty common so that one
    mined block is accepted by every relay and by replication; a per-group difficulty would be a local
    requirement above `D_NET` that the sender cannot learn before it is refused (`/info` is per relay,
    not per group), and a block mined for it would carry extra cost nowhere else.

### Settings, memory and metrics

14. **Settings** (environment variables `SBTP_RELAY_<NAME>`, ADR 0019).

    | Setting | `small` | `standard` | `large` | Range | Kind |
    |---|---|---|---|---|---|
    | `ingest_bytes_per_hour` (`R`) | 209,715,200 (200 MiB) | 2,147,483,648 (2 GiB) | 17,179,869,184 (16 GiB) | 0 (off), or 1,048,576 to 1,099,511,627,776 | profile row |
    | `ingest_group_max` | 1,024 | 16,384 | 131,072 | 64 to 16,777,216 | profile row |
    | `ingest_group_share_pct` (/48, IPv4 /24) | 25 | 25 | 25 | 1 to 100 | policy |
    | `ingest_group56_share_pct` (/56) | 10 | 10 | 10 | 1 to `ingest_group_share_pct` | policy |

    `R` is a profile row (ADR 0019 rule 37), as `replication_bytes_per_hour` is: it follows what the
    host can write and serve, not the disk size. An operator with much more disk than 1 GiB on `small`
    keeps `R` or raises it; the fill time is `max_store_bytes / R`.
15. **Memory.** One entry holds a group key (19 bytes), one level and one time (16 bytes). With the
    formula of ADR 0027 clarification T1 (map element 40 bytes at most half full, two order elements of
    32 bytes): at most 146 bytes; estimate 160 bytes. New term of ADR 0018 rule 35:
    `ingest_group_max × 160 + 64` (the global bucket and the two counters of rule 6). `small`:
    163,904 bytes. On top of the computed `small` bound at `7caedba` (14,747,092 bytes) it gives
    14,910,996 bytes, 89,004 bytes under 15,000,000. `standard`: 2.6 MiB; `large`: 20 MiB. A unit test
    asserts the per-entry estimate as ADR 0027 clarification T1 does.
16. **Metrics** (prefix `sbtp_relay_`, ADR 0021 rule 41). No label names a client or a network.

    | Name | Kind | Labels |
    |---|---|---|
    | `ingest_bytes_total` | counter (bytes charged under rule 6) | none |
    | `ingest_capped_total` | counter (`503` of rule 6) | none |
    | `ingest_group_limited_total` | counter (`429` of rule 4) | `level`: `v6_56`, `v6_48`, `v4_24` |
    | `ingest_group_unchecked_total` | counter (`PUT`s not checked under rule 5) | none |
    | `ingest_cap_active` | gauge (1 while rule 6 is checked) | none |
    | `ingest_bucket_bytes` | gauge (level of the global bucket) | none |
    | `ingest_group_entries` | gauge | none |

    Events: `ingest_capped` (rate-capped, ADR 0021; once when the global bucket first refuses, and
    `ingest_cap_ended` with the count and the duration when it holds a full charge again). No event
    names a client or a network.

## Self-blocking analysis

For each mechanism: can an attacker trigger it to refuse others, at what cost, and what an honest client
sees. Figures for `small` with the defaults (`R` = 200 MiB/h; group rate 50 MiB/h for a /48 or a /24,
20 MiB/h for a /56).

**Normal traffic never meets a bound.** A small relay with 1,000 active writers, 50 blocks each per day
of 2 KB, receives 100 MB per day, about 4 MB/h on average; at a peak of five times the average,
21 MB/h. That is a tenth of `R`. A single /48 or /24 would need 25,000 blocks of 2 KB in one hour to
reach its 50 MiB/h; a whole carrier NAT pool of 1,000 users at the same peak sends 21 MB/h, under its
share. The per-key limit of ADR 0018 (30 `PUT`s per minute) is reached long before a group budget by a
single client. The global cap is not checked at all until the store passes 80 %.

| Mechanism | Lever? | Cost to use it against others | What an honest client sees |
|---|---|---|---|
| Group budget (rules 2 to 4) | Only against hosts in the attacker's own /56, /48 or /24. | The attacker must share a network with its victim. | Only if it shares a group with a flooder (a NAT, a shared host): `429` with `Retry-After` of seconds, then success or another relay. |
| Group table full (rule 5) | No: it fails open. | Many networks at once only remove the group check for new groups. | Nothing. |
| Global cap (rule 6) | **Yes**, under disk pressure only. | At least four networks (/48s or /24s), each at its full share, for as long as the denial lasts, each block with its PoW. | `503` with `Retry-After` of at most 300 s for new blocks on this relay. Reads, `200` acknowledgements of held blocks and replication continue. The client publishes through its other relays (ADR 0047, ADR 0048) and retries here later. |
| Storage share (not adopted) | Would have been: a legitimate large network (carrier NAT) holding much of a relay's content would have been refused. | None needed. | n/a |

Why the global cap is still adopted: without it, the same four networks fill the store and, with
demand eviction, delete cold legitimate blocks at their full rate, then the store answers `507` to
everyone while their fresh blocks are protected for `3 × E` (ADR 0046 rule 7). That is also a denial of
writes, and it destroys content. The cap turns it into a write denial on one relay, bounded in time by
the attack, with no loss beyond `R` per hour of evicted cold blocks. Checking it only above the
low-water mark means a relay with free space never refuses for it. A mature keeping relay sits near
its watermarks, so the cap is normally checked there; the factor of ten between `R` and the peak above
is what keeps it out of reach of honest traffic.

What it does not stop: an attacker with many networks. Layer 0 cannot tell many honest networks from
many networks of one attacker; a reserve for "light" groups gives no protection against them, because
each attacker network can stay light. This residual is Q-71. The answer today is the network: several
relays, archives and replication; one relay's write denial is local.

## Consequences

- **Fill time and eviction rate.** From the low-water mark, a flood adds at most `R` per hour: from 80 %
  to 90 % of 1 GiB takes at least 30 minutes, and demand eviction then removes at most `R` per hour of
  cold blocks (about 3,000 full-size blocks per hour on `small`) instead of the full flood rate. One /48
  (the 100-/64 case of M-2) writes at most 50 MiB/h from any fill level: 1 GiB in about 20 hours, not
  5 minutes.
- **Cost.** Per `PUT`: up to two ordered-map updates under the group table mutex before the body, one
  atomic update of the global bucket at the storage step, and the charge after the store. No index or
  disk work. Reads are unchanged.
- **Privacy.** Group keys live in memory only, as the client keys of ADR 0018 rule 21 do; nothing about a
  writer's network is stored with a block (rule 10).
- **Compatibility.** No wire change. A relay with this ADR answers `429` and `503` as before, in new
  cases; clients already handle both.
- **Behind a proxy without `client_ip_header` or `trusted_proxies`.** Every client has the proxy's
  address, so one group: the relay's whole ingest is held to the group share. ADR 0044 and ADR 0019
  already require the client address to be resolved; the start-up warning of ADR 0020 rule 22 covers it.

## Implementation plan (relay-engineer)

1. `config.rs`: the settings of rule 14, profile rows, ranges, the `ingest_group56_share_pct ≤
   ingest_group_share_pct` check; the memory term of rule 15 in `memory_bound_bytes`.
2. `limiter.rs`: generalise the table of ADR 0027 to a bucket count of 1 or 3 (or a second, smaller
   type sharing the order logic), with signed levels in bytes; fail open when full (rule 5); size test
   of the entry estimate.
3. `client.rs`: derive the group keys of rule 1 from the resolved address.
4. `blocks.rs`: group check before the body (rule 4); global check at the storage step for a new block
   only (rule 6), after the held check; charge on `201`; `Retry-After` from the bucket.
5. `metrics.rs`, `log.rs`: rule 16.
6. Tests: a group refused while another group of the same relay is accepted; `200` for a held block
   with the global bucket empty; no global refusal below the low-water mark; a full group table admits
   an unknown group; exempt keys never charged; replicated blocks never charged; `Retry-After` values;
   refill ends every refusal without restart.
7. `deploy/README.md`: rule 11 (edge rule example for one CDN, vendor named there only as an example)
   and the alerts of rule 12.

Effort: 1.5 to 2 days.

**Security-auditor review:** that a refusal under this ADR can only last as long as a bucket is
drained (no latch, no persisted state); the group derivation behind `client_ip_header` and
`X-Forwarded-For`; fail open of rule 5 cannot be turned into a bypass of the global cap; the bound of
the negative level; the charge counted once per stored block under concurrent `PUT`s of the same
`block_id`; the `small` memory bound; no client or network in logs or metrics.

## Spec change on acceptance

Core spec §4, "Admission control", the `429` bullet, after "are one client.":

> A relay MAY also bound the bytes stored per hour from a network prefix (an IPv6 /56 or /48, an IPv4
> /24); a `PUT` over that bound gets `429` before its body is read. (ADR 0049)

Core spec §4, "Admission control", the `503` bullet, appended:

> A relay whose store is near full MAY bound the bytes it stores per hour from all clients together; a
> new block over that bound gets `503` with `Retry-After`, and a block the relay holds still gets `200`.
> (ADR 0049)

`architecture.md` §2, "Admission control", new bullet:

> - `sbtp-relay` bounds stored bytes per hour per network group (/56, /48, /24), always, and for all
>   clients together once the store passes its low-water mark. It records no network origin with a
>   block. Replication has its own budget. (ADR 0049)

## Rejected alternatives

- **Storage share per group (X % of `max_store_bytes` held per group).** It needs the group of every
  stored block on disk, to decrement the share when the block is evicted: a record of each author's
  network next to a signed, attributable block, readable by anyone with the disk. A keyed or truncated
  tag still confirms a suspected network across many blocks of one key. It costs index bytes per block
  and a counter table, misattributes behind shared addresses, and refuses a legitimate large network
  (carrier NAT, university) that holds much of a relay's content. It is a lever as well as a
  privacy cost. Eviction that prefers over-share groups has the same cost.
- **Global cap always on.** A relay with free space would refuse honest traffic during a flood for no
  benefit: nothing is evicted below the high-water mark.
- **No global cap, group budgets only.** A many-network flood fills and evicts at its full rate.
- **Shared overflow group when the table is full (as ADR 0027 does for client keys).** An attacker with
  enough networks would push honest new groups into a group it floods: a lever. Fail open costs nothing
  the global cap does not cover.
- **A reserve of the global budget for light groups.** Each attacker network can stay light; it adds
  state and a rule and protects only against few-network attackers, whom the group budgets already
  stop.
- **Counting requests per group instead of bytes.** Disk filling is in bytes; a request count lets a
  group of full-size blocks take 30 times the bytes of a group of small ones.
- **Higher PoW above a share.** Rule 13, Q-71.
- **A per-public-key quota.** Keys are free.
