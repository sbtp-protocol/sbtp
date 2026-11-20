# 0044: Client address from a single-value header set by a CDN (`client_ip_header`)

- Status: proposed
- Date: 2026-11-20
- Questions: none open; found while deploying the first public relay behind a CDN and a proxy that
  replaces `X-Forwarded-For`
- Amends, if accepted: ADR 0018 rule 20 (one more source of the client address) and ADR 0020 rule 6
  ("every other header MUST NOT be read" gets one exception). Nothing else in ADR 0018 or ADR 0020
  changes
- Depends on: ADR 0018 rules 20 to 22, ADR 0019 rule 42, ADR 0020 rules 6 to 17, ADR 0021 (privacy of
  logs)
- Impact: `sbtp-relay` (one setting, client key derivation, start-up lines, warnings, tests);
  `deploy/README.md`; `architecture.md` §2 "Admission control" (one bullet); no change to the relay
  interface, no wire format change

## Context

The relay attributes a request to a client key (ADR 0018 rule 20). Behind trusted proxies it reads
`X-Forwarded-For` from the right (ADR 0020 rules 6 to 10). This needs every hop to append its peer.

A common chain is a CDN in proxy mode, then an ingress proxy, then the relay. Some ingress proxies do
not trust the incoming `X-Forwarded-For` from the CDN and replace it with their own peer, the CDN edge
address. Every client behind one edge then shares one key: one busy client gives the others `429`.
Trusting the CDN's ranges in the proxy fixes it only if those ranges are also listed in
`trusted_proxies`, and CDN ranges are wide (ADR 0020 rule 14 warns) and shared by every customer of the
CDN.

Many CDNs write the address of their own peer into one header with exactly one value (for example
Cloudflare's `CF-Connecting-IP`), overwriting any value the client sent. The ingress proxy forwards it
unchanged.

## Decision

1. **Setting.** `client_ip_header`: an HTTP field name (RFC 9110 §5.1 token, 1 to 64 bytes), compared
   without regard to case. Absent by default. The relay MUST refuse to start when it is
   `X-Forwarded-For` or `Forwarded`, with a message that names the setting.
2. **Scope.** The header is read only on a connection whose peer address is in `trusted_proxies`
   (ADR 0019 rule 31). From any other peer it is ignored, and the client address is the peer address
   (ADR 0018 rule 20).
3. **Replaces `X-Forwarded-For`.** When `client_ip_header` is set, the relay MUST NOT read
   `X-Forwarded-For` for the client key, on any connection.
4. **Value.** The header MUST appear in exactly one field line, whose value, after removal of leading
   and trailing spaces and horizontal tabs, is one IPv4 or IPv6 address in the forms of ADR 0020 rule 7
   without a port and without brackets. An IPv4-mapped address is normalised (ADR 0020 rule 8). That
   address is the client address, unless it is in `trusted_proxies`.
5. **Fallback.** When the header is absent, appears in several field lines, holds a list, a port, any
   other form, a byte outside visible ASCII, space and tab, or an address in `trusted_proxies`, the
   client address is the peer address of the connection. The relay MUST NOT refuse the request because
   of this header and MUST NOT give it a key of its own (as ADR 0020 rule 10).
6. **Key.** The client address becomes a client key under ADR 0018 rule 20, unchanged: IPv4 as is, IPv6
   aggregated to `client_ipv6_prefix` bits, IPv4-mapped as IPv4. `rate_limit_exempt` applies to the
   resulting key as to any key.
7. **Logs.** The header value and the derived address MUST NOT be logged (ADR 0021). At start-up, when
   `client_ip_header` is set, the relay logs one line that names the header and states that every
   peer in `trusted_proxies` is trusted to forward it unchanged from the CDN, and that `X-Forwarded-For`
   is not read. A request that falls back under rule 5 from a trusted peer gives a throttled warning
   (ADR 0020 rule 27 throttling) that names `client_ip_header` and this ADR, without value or address.
   A health check from the proxy, without the header, is such a request; the throttling keeps it to one
   line per period.
8. **`trusted_proxies` and `trusted_proxies_broad`.** With `client_ip_header`, `trusted_proxies` lists
   only the proxies that connect to the relay (the ingress proxy), not the CDN's ranges: the relay never
   reads an address chain. ADR 0020 rules 13 and 14 apply unchanged. A broad block then has no reason
   to be listed for the CDN, and the `trusted_proxies_broad` warning, if it appears, points to a
   configuration that is no longer needed.
9. **Deployment (MUST).** An operator MUST set `client_ip_header` only when both hold:
   - only the CDN can reach the first proxy (the origin): no other path to its ports, and no other
     program on a trusted address;
   - the CDN overwrites the header on every request with the address of its own peer, whatever the
     client sent.
   The relay cannot check either. `deploy/` MUST state them, and MUST name the cross-tenant risk:
   another customer of the same CDN (their own zone, an edge script) reaches the origin through the
   CDN's addresses and sets the header to any value, choosing a fresh client key per request. The
   mitigation is to authenticate the CDN's connection to the origin (for example authenticated origin
   pulls with a per-zone client certificate verified by the proxy) or to reach the origin only through
   the CDN's tunnel with no open port, plus a firewall that admits only the CDN's ranges. This is the
   rule `deploy/README.md` already states for `X-Forwarded-For`.

**Fallback against refusal (rule 5).** Refusing a request whose header is missing or malformed would
fail loudly, but the client cannot fix it, health checks would need an exception, and ADR 0020 rule 10
already chose the peer address for the same case. The fallback fails closed: every such request shares
the proxy's single key and its allowance, and rule 7 tells the operator.

## Consequences

- **Rules for `sbtp-relay`.** Key derivation, in this order, once per request (ADR 0020 rule 21): peer
  address normalised; if the peer is not in `trusted_proxies`, the key is the peer address; else if
  `client_ip_header` is set, rules 4 and 5; else ADR 0020 rules 6 to 10. Start-up: rule 1 refusal,
  rule 7 line. Tests: header from an untrusted peer ignored; one valid IPv4, one valid IPv6 (aggregated
  to /64), IPv4-mapped normalised; two field lines, a comma list, `ip:port`, `[v6]`, `unknown`, an
  address in `trusted_proxies`, and an absent header each fall back to the peer; `X-Forwarded-For` is
  ignored when the setting is on; rule 1 refusal for both names; no value in any log line.
- **Security.** The setting moves trust from an address chain to one header and to the deployment. It
  is no weaker than listing the CDN's ranges for `X-Forwarded-For`, which needs the same guarantee, and
  it removes the wide ranges from `trusted_proxies`.
- **Compatibility.** Off by default; nothing changes for existing configurations.

## Spec change on acceptance

`architecture.md` §2 "Admission control", bullet added after the per-client connection bullet:

> - Behind trusted proxies, the client address comes from `X-Forwarded-For`, or, when the operator
>   sets `client_ip_header`, from that single-value header written by a CDN. Either source is read only
>   from a peer in `trusted_proxies`. (ADR 0020, ADR 0044)

## Rejected alternatives

- **Trust the CDN's ranges in the proxy and in `trusted_proxies`.** Works with `X-Forwarded-For`, but
  needs every hop to append, lists wide shared ranges, and depends on the proxy's own forwarding
  policy.
- **Read the header from any peer.** Any client would choose its key.
- **Accept the first value of a list, or `ip:port`.** The CDNs this targets write one bare address. Any
  other form means another writer, so it is not trusted.
- **Several header names.** One CDN in front of one relay is the case; a list adds precedence rules for
  no stated need.
