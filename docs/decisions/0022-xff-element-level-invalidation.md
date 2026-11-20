# 0022: X-Forwarded-For: invalidate the element, not the line

- Status: accepted (by the project owner, 2026-11-19)
- Date: 2026-11-19
- Questions: none
- Amends: ADR 0020 rule 7 (last sentence) and the splitting step of rule 6
- Review: `docs/security/2026-11-19-relay-adr0020.md`, finding M-1

## Context

ADR 0020 rule 7 ends: "A field line that contains a byte outside visible ASCII, space and horizontal tab is
one invalid element." Reverse proxies such as Caddy, nginx and Traefik append the real client address to
the existing `X-Forwarded-For` line, after the value the client sent. A client that sends
`X-Forwarded-For: \xff` therefore makes the whole line one invalid element, including the address its
proxy appended. Selection (rule 9) stops at that invalid element, and the request falls back to the
proxy's key (rule 11).

The security review measured it with a bound of 1: the client's own key stays free, header-less traffic
from the proxy gets `429`, and with the proxy's address in `rate_limit_exempt` the client is served
without limit. The client chooses to be counted as the proxy. Milestone 1c inherits the same key for its
token bucket.

## Decision

1. **Split before validating.** Each `X-Forwarded-For` field line is split at every comma byte (`0x2C`)
   on its raw bytes, before any check of the bytes themselves. Rule 6's ordering of lines and elements is
   unchanged.
2. **Invalidate the element.** An element that contains a byte outside visible ASCII (`0x21`–`0x7E`),
   space and horizontal tab is one invalid element. The other elements of the same line are parsed by
   rule 7 as usual.
3. Rule 7's sentence "A field line that contains a byte outside visible ASCII, space and horizontal tab is
   one invalid element" is replaced by rule 2 above. Every other rule of ADR 0020 applies unchanged,
   in particular rule 9: the rightmost element not in `trusted_proxies` is selected, and an invalid
   element or `unknown` met first ends the search.

## Consequences

- With an appending proxy, the address our proxy wrote is the rightmost element and is read whatever
  the client put before it. A client can no longer make itself counted as the proxy by sending
  non-ASCII bytes.
- A proxy that itself writes a non-ASCII element is still a configuration error, handled by rule 11
  (proxy key plus a throttled warning).
- Tests: a line `\xff, 203.0.113.7` from a trusted proxy keys the request to `203.0.113.7`; a line
  `203.0.113.7, \xff` keys it to the proxy with the rule 11 warning; a non-ASCII byte inside one element
  of a multi-line list affects only that element.

## Rejected alternatives

| Option | Why not |
|---|---|
| Keep line-level invalidation | Lets a client choose the proxy's key behind any appending proxy (M-1). |
| Drop non-ASCII bytes and parse the rest | Rewrites client input into an address it did not send. |
