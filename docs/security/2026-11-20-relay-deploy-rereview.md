# Re-review (2026-11-20): relay deploy fixes

- Original report: `docs/security/2026-11-20-relay-deploy.md` (in `main`, commit `bf9f5f0`).
- Fix diff: `git diff 4688d5d ab0b426` on `feat/relay-e2e-deploy`. Files: `deploy/README.md`,
  `deploy/Caddyfile`, `crates/sbtp-relay/tests/e2e.rs`.
- Checks run on `ab0b426`: `cargo fmt --all --check` passes. `cargo clippy -p sbtp-relay
  --all-targets -- -D warnings` passes. `cargo test -p sbtp-relay --test e2e` passes 3 runs in a
  row (3 tests, 0.95 to 1.38 s).

## Verdict

**Mergeable: yes.** All findings are resolved. The fixes add no blocking, high or medium issue.
Three info notes follow; none needs a change before the merge.

## Status of each finding

| Finding | Status | Notes |
|---|---|---|
| M-1 K3s client collapse | Resolved | `externalTrafficPolicy: Local` (or PROXY protocol) is now a requirement, with the K3s `HelmChartConfig` path. A `NetworkPolicy` limits ingress to the Traefik pods. A concrete two-host post-deploy check replaces "check the first `PUT`s". |
| M-2 Cloudflare origin trust | Resolved | Authenticated Origin Pulls with a per-zone certificate and `RequireAndVerifyClientCert`, or a Tunnel, is required *before* the Cloudflare ranges are listed. The Hetzner Cloud Firewall, not `ufw`, restricts ports 80 and 443. The README ties both to ADR 0020 rule 17. |
| M-3 Traefik body streaming | Resolved | A `buffering` middleware is required, with `maxRequestBodyBytes` and `memRequestBodyBytes` at 131072. Option names were checked against the Traefik docs. Traefik answers `413` above the maximum. `http.maxHeaderBytes` (default 1048576) is listed, and the name was checked. |
| L-1 Rule 17 not stated | Resolved | The rule is stated nearly verbatim, with the forwarder examples and `trusted_proxies = []`. |
| L-2 Cloudflare 3xx / HTML pages | Resolved | The README requires Full (strict), a WAF skip rule for challenges, Bot Fight and "Under Attack", and a cache bypass on `/sbtp/v1/*`. |
| L-3 Published ports bypass the firewall | Resolved | The Docker/`ufw` caveat is documented. On Coolify, "Ports Mappings" stays empty and only "Ports Exposes: 8080" is set. The cloud firewall is the perimeter. |
| L-4 PVC ownership | Resolved | The pod and container `securityContext` is documented as recommended. Two useful additions: the relay does not check the owner or mode of an existing `data_dir`, and `enableServiceLinks: false` is needed. That last one was checked: the relay rejects unknown `SBTP_RELAY_*` keys, `config.rs` `ConfigError::UnknownKey`. |
| L-5 Caddy admin API | Resolved | `admin off` in the global options block. The syntax was checked against the Caddy global options docs (`admin off\|<addr> { ... }`: "If set to `off`, then the admin endpoint will be disabled"). The block placement is correct: global block, first directive, before `servers`. |
| L-6 Test cleanup | Resolved | `Drop` no longer calls `terminate()`. It is best effort and never panics: SIGTERM, polls `try_wait`, SIGKILL after 10 s, then joins the reader. The strict assertions remain in `stop()`. The optional `tmp_dir` cleanup was not done, which is acceptable. |

## New notes from the fixes (info)

- **N-1. `admin off` also disables `caddy stop` and `caddy reload`.** Both commands use the admin
  API. The Caddyfile comment says "restart Caddy instead", which is correct. Under systemd or with
  `caddy run` in the foreground, the normal stop signal (SIGTERM or SIGINT) still works. Optional:
  one line in the README's Caddy section.
- **N-2. Traefik `buffering` also buffers responses.** By default, `maxResponseBodyBytes` is 0
  (unlimited) and `memResponseBodyBytes` is 1 MiB, with spill-to-disk above that. The relay has no
  streaming or WebSocket route (`/info`, `PUT /block`, `GET /block/{id}`, `GET /query`), and its
  responses are bounded, so this breaks nothing and costs at most one bounded buffer per request.
  If a streaming or WebSocket route is ever added, it needs a router without this middleware.
- **N-3. Statements about the planned cluster cannot be checked from this repository.** Two
  sentences cannot be verified here: "On the planned K3s cluster the Traefik Service already uses
  `Local` and LAN client IPs are preserved", and "The planned K3s manifests include it [NetworkPolicy,
  buffering, `enableServiceLinks: false`]". No manifests are in `deploy/`. These are claims about
  infrastructure outside the repository. The two-host post-deploy check (M-1 fix) is what actually
  verifies the first claim, so run it on the first K3s deploy.
- In `Drop`, an `Err` from `try_wait` breaks out of the loop without SIGKILL, and the reader join
  could then wait on a live child. `waitpid` failing on our own child is practically impossible.
  This is not worth a change.

## Not checked

- `caddy validate` was not run (Caddy is not installed). The syntax was checked against the docs
  only.
- No Traefik, K3s, Coolify or Cloudflare configuration was applied or tested. The middleware, TLS
  option and entry point names were checked against the Traefik reference docs only.
- The planned K3s manifests mentioned in the README (outside this repository).
