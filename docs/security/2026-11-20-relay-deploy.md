# Security and correctness review: relay end-to-end tests and deployment files

- Branch: `feat/relay-e2e-deploy`, commit `4688d5d`, diff `main...feat/relay-e2e-deploy` (618 lines).
- Files: `crates/sbtp-relay/tests/e2e.rs`, `deploy/Dockerfile`, `deploy/Dockerfile.dockerignore`,
  `deploy/Caddyfile`, `deploy/README.md`.
- Reference: spec `sbtp-core-v0.2.md` §4; ADR 0018 rule 20; ADR 0019 rules 18, 25, 29 to 31, 34, 42,
  43; ADR 0020 rules 6 to 17; ADR 0029 rules 4 and 5; ADR 0030.
- Planned deployments: (1) LAN-only K3s behind Traefik, (2) public Hetzner VPS with Coolify (Traefik),
  proxied by Cloudflare.

## Verdict

**Mergeable: yes.** No blocking or high finding. The code (tests) and the shipped artefacts
(Dockerfile, Caddyfile) are sound. The three medium findings are in the README's Traefik, K3s and
Cloudflare guidance: they do not block the merge, but **M-1 must be fixed before the K3s deploy
and M-2 and M-3 before the public Coolify/Cloudflare deploy**. They are documentation fixes (and
the operator's Traefik/Cloudflare configuration), not code changes.

Checks run (on `4688d5d`): `cargo fmt --all --check` passes; `cargo clippy -p sbtp-relay
--all-targets -- -D warnings` passes; `cargo test -p sbtp-relay --test e2e` passes, 6 runs in a row,
1.1 to 2.5 s each; `cargo deny check` green (advisories, bans, licenses, sources);
`cargo tree -p sbtp-relay -e normal,features -i sbtp-core` shows only the `std` feature (no
`vector-gen` in the relay's normal build).

## Blocking

None.

## High

None.

## Medium

### M-1. K3s: the recommended `trusted_proxies` plus the default Service policy collapse every LAN client into one key

- File: `deploy/README.md`, "Traefik (K3s, Coolify)", bullets on `trusted_proxies` (pod network
  `10.42.0.0/16`) and on `externalTrafficPolicy` ("to be checked on the cluster").
- Scenario: K3s exposes Traefik through ServiceLB (klipper-lb) or MetalLB with
  `externalTrafficPolicy: Cluster`, the default. The connection is source-NATed before it reaches
  Traefik, which then sees an address of the node: with ServiceLB, typically the `cni0` bridge or
  svclb pod address, inside `10.42.0.0/16` (to be confirmed on the cluster). Traefik does not trust
  that peer, strips any incoming `X-Forwarded-For` and writes that address. The relay, configured as
  the README says with `trusted_proxies = 10.42.0.0/16`, steps over it (ADR 0020 rule 8), finds no
  untrusted address and falls back to the Traefik pod's exact address (rule 10,
  `server.rs:438`). Effect: every LAN client shares one set of token buckets, one in-flight bound
  (`max_connections_per_client`, 8) and one `put_max_in_flight_per_client` (2). One busy browser tab
  gives everyone else `429`. With MetalLB/`Cluster`, the SNAT address is a node address outside the
  pod CIDR: one key per node, same effect. The README calls it a "may" to be checked. With the
  recommended trust list, the README's own check ("check the first `PUT`s") shows nothing wrong,
  because no warning fires.
- Second-order point, also on `10.42.0.0/16`: every pod of the cluster may then write
  `X-Forwarded-For` and is not counted at accept (ADR 0020 rule 14 warns; rule 17 requires every
  connection from a trusted address to come from a header-writing proxy). On a shared cluster, any
  compromised or hostile pod can choose any client key. LAN-only, so low impact on its own.
- Fix (README):
  - State as a requirement, not a "may": the Traefik Service needs `externalTrafficPolicy: Local`
    (K3s: a `HelmChartConfig` for `traefik` with `service.spec.externalTrafficPolicy: Local`), or an
    upstream L4 balancer with PROXY protocol and Traefik's `proxyProtocol.trustedIPs`.
  - Add a `NetworkPolicy` that allows ingress to the relay pod only from the Traefik pods
    (namespace `kube-system`, label `app.kubernetes.io/name=traefik`). This makes the pod-CIDR trust
    satisfy rule 17 in practice.
  - Give a concrete post-deploy check: two `PUT`s from two different LAN hosts must land in two
    different keys (for example, exhaust one host's `block` bucket and check the other still gets
    `201`/`200`), not just "the first `PUT`s work".

### M-2. Cloudflare: trusting Cloudflare's ranges in Traefik and in the relay without authenticating the origin pull

- File: `deploy/README.md`, Traefik bullets "Behind Cloudflare, list Cloudflare's published ranges
  in `forwardedHeaders.trustedIPs`" and "Behind Cloudflare it must also hold Cloudflare's ranges".
- The configuration described is the right *shape*: Traefik keeps the header from Cloudflare,
  appends Cloudflare's address; the relay steps over the Traefik network and Cloudflare's ranges and
  takes the client Cloudflare appended. A client that forges `X-Forwarded-For` through this zone is
  harmless, because Cloudflare appends the real address to its right.
- Scenario: Cloudflare's ranges carry every Cloudflare customer's traffic, not only this zone's. An
  attacker who reaches the origin IP from inside Cloudflare (their own zone with a DNS record
  pointing at the VPS, or a Worker `fetch()` to the origin) arrives from a "trusted" address. Whether
  Cloudflare appends the true client address in every such path, Workers subrequests in particular,
  could not be verified here. If it does not, the attacker sets `X-Forwarded-For: <random>` on each
  request and gets a fresh client key every time: the per-client buckets, the in-flight bound and the
  per-client `PUT` bound no longer apply to them. What remains is the global bounds and PoW. ADR 0020
  rule 17 says an address MUST be in `trusted_proxies` only if *every* connection from it comes from
  a program that appends its peer. A range shared with every Cloudflare tenant cannot be shown to
  meet that rule.
- Separately, Traefik's ports 80 and 443 on the VPS are open to the world. Direct hits on the origin
  IP are keyed correctly (Traefik does not trust them), but they bypass Cloudflare.
- Fix (README, and the operator's setup): require Cloudflare **Authenticated Origin Pulls**
  (per-zone certificate) with Traefik TLS option `clientAuth.clientAuthType:
  RequireAndVerifyClientCert` on the relay router, or publish through a Cloudflare Tunnel instead of
  an open port. Also restrict 80 and 443 to Cloudflare's ranges in the **Hetzner Cloud Firewall**, not
  `ufw`, because Docker's published ports bypass `ufw`. Only then list Cloudflare's ranges as
  trusted. Note in the README that this is what makes the Cloudflare entries meet ADR 0020 rule 17.

### M-3. Traefik guidance has no request body limit and no body buffering: a few slow `PUT`s hold all global `PUT` slots

- File: `deploy/README.md`, "Traefik (K3s, Coolify)". Compare `deploy/Caddyfile` lines 33 to 42,
  which solve exactly this with `request_body max_size` and `request_buffers`.
- Scenario: Traefik streams request bodies to the upstream by default. A client sends `PUT` heads
  with `Content-Length: 65909` and trickles the body. Each such request holds a relay connection and
  a `PUT` slot until `body_timeout_ms` (10 s), then starts again. The `small` profile allows
  `put_max_in_flight = 4` globally and 2 per client key. Two client keys (two IPv4 addresses, or two
  IPv6 /64s, which are cheap) hold every `PUT` slot continuously, and honest publishers get `429`
  or `503`. Whether Cloudflare buffers request bodies on the plan in use was not verified. On the
  LAN deploy there is no Cloudflare in the path.
- Fix (README): require a Traefik `buffering` middleware on the relay router, with
  `maxRequestBodyBytes: 131072` and `memRequestBodyBytes: 131072`, the same values as the Caddyfile.
  Traefik then reads the whole body before it opens the upstream request, and refuses larger bodies
  itself. Also list Traefik's header limit (entry point `http.maxHeaderBytes`, Go default 1 MiB):
  harmless, because the relay answers `431` itself above 16,384 bytes, but it belongs in the same
  table as Caddy's.

## Low

### L-1. ADR 0020 rule 17 is not stated in `deploy/`, although the rule requires it

- File: `deploy/README.md`, "Client identification", paragraph "If a proxy in `trusted_proxies`
  does not write the header, its requests share one key per proxy address".
- That sentence holds for an HTTP proxy that forgets the header. It leaves out the dangerous case
  that rule 17 exists for: a byte-level forwarder (`ssh -R`, `socat`, `stunnel`, nginx `stream`,
  HAProxy `mode tcp`) on a trusted address, loopback by default. Through such a forwarder, clients
  write their own `X-Forwarded-For` and pick any key (the review that led to ADR 0020 measured 31
  forged keys through loopback). Rule 17 ends with "`deploy/` MUST state this rule." It is relevant
  to the bare-VM Caddy setup, where loopback is trusted by default.
- Fix: add rule 17 nearly verbatim. Never put a byte-level forwarder on an address in
  `trusted_proxies`. If one runs on the relay's host, set `trusted_proxies = []`; it is then one
  client and not a supported way to publish.

### L-2. Cloudflare settings that would put a `3xx` or an oversized body on `/sbtp/v1/`

- File: `deploy/README.md`, last Traefik bullet (Cloudflare limits).
- Scenarios:
  - SSL/TLS mode **Flexible**: Cloudflare reaches the origin over HTTP, Coolify's Traefik answers
    its HTTP-to-HTTPS redirect, and clients get a `301`/`308` on `/sbtp/v1/` (ADR 0030 rule 3), or a
    redirect loop.
  - "Under Attack" mode, Bot Fight Mode or a managed challenge: these answer API requests with HTML
    challenge pages (`403`/`503`), which may exceed the 16,384-byte error-body ceiling (ADR 0029
    rules 4 and 5).
  - Cloudflare's own `52x` error pages are HTML; their size was not measured.
  - Clients treat all of these as failed requests, so nothing is unsafe, but the relay is unusable.
- Fix: in the README, require SSL mode **Full (strict)**. Require no challenge, Bot Fight or
  "Under Attack" rule on `/sbtp/v1/*` (a WAF skip rule for that path). Cache rule "bypass" on
  `/sbtp/v1/*`: the default does not cache extension-less paths, but say so explicitly. "Always Use
  HTTPS" is fine (ADR 0030 rule 5).

### L-3. Published container ports bypass the host firewall (Docker and Coolify)

- File: `deploy/README.md`, "Listen address".
- The advice (`-p 127.0.0.1:8080:8080`, or an internal network) is correct. Coolify, however, has a
  "Ports Mappings" field that publishes on `0.0.0.0`, and Docker's iptables rules bypass `ufw`. An
  operator who fills it in exposes plain-HTTP relay port 8080 to the internet. That skips TLS, head
  buffering and Cloudflare. Client keys stay correct, because the peer is not trusted.
- Fix: one line for Coolify: leave "Ports Mappings" empty and route only through Traefik ("Ports
  Exposes: 8080"). Use the Hetzner Cloud Firewall as the real perimeter.

### L-4. Volume ownership on Kubernetes

- File: `deploy/Dockerfile` lines 39 to 41; `deploy/README.md`, "File system".
- The `--chown=65532:65532` / `0700` mount point initialises a Docker *named volume* only. A
  Kubernetes PVC is mounted with the provisioner's ownership, often `root:root 0755`. The relay
  (uid 65532) then cannot write and stops at start-up (fails closed, so no security issue). K3s
  `local-path` creates `0777` directories, which works but is world-writable on the node.
- Fix: in the README's Kubernetes notes, add `securityContext: { runAsNonRoot: true, runAsUser:
  65532, runAsGroup: 65532, fsGroup: 65532, readOnlyRootFilesystem: true,
  allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }`, the Kubernetes counterpart of
  the `docker run` flags already documented.

### L-5. Caddy's admin API stays on `localhost:2019`

- File: `deploy/Caddyfile`, global options block.
- Any local process can reconfigure Caddy at runtime (add routes, add a redirect, change header
  handling) through the default admin endpoint. On the bare VM, a local process can already reach the
  relay on loopback and is trusted for `X-Forwarded-For` (ADR 0020 rule 16), so the extra exposure is
  small.
- Fix: `admin off` in the global block (the demo never reloads through the API), or
  `admin unix//run/caddy/admin.sock`.

### L-6. Test cleanup can abort or hang instead of failing

- File: `crates/sbtp-relay/tests/e2e.rs`, `RelayProcess::terminate` and `Drop`.
- `terminate` has `assert!(sent.success())` and several `unwrap()`s, and `Drop` calls it. If a test
  is already unwinding from a failed assertion and `kill` or `wait` then fails, the second panic
  aborts the whole test binary, and the other tests' relays may be left running. `child.wait()` has
  no bound: a relay that hangs in its drain hangs the test run instead of failing it. Ports are not a
  flakiness risk (`127.0.0.1:0`, the address is read from the `listening` line, where `addr` is the
  last field, `lib.rs:297`). Timing is safe as well (10 s read timeout, 30 s start-up bound). The
  test fails clean on 6 consecutive runs.
- Fix: in `Drop`, ignore errors and fall back to `child.kill()` (SIGKILL) when the SIGTERM wait
  exceeds, say, 10 s (poll `try_wait`). Keep the strict checks in `stop()` only. Optional: remove
  the `tmp_dir` directories at the end of a passing test (they accumulate under
  `CARGO_TARGET_TMPDIR`).

## Info

- **I-1. Supply chain of the Dockerfile: correct.**
  - Both bases are pinned by digest.
  - No `# syntax=` line, no `apk add`, no `curl`.
  - `rust-toolchain.toml` is excluded on purpose, so rustup downloads nothing.
  - The build is `cargo build --release --locked -p sbtp-relay --bin sbtp-relay`: no
    `--all-targets`, no test profile, no `vector-gen`. The feature tree confirms it.
  - No `.cargo/config.toml` in the repository can redirect the registry.
  - Dependency build scripts (for example `blake3`'s C/asm through `cc`) run in the builder stage,
    which is expected and already covered by `cargo deny`.
  - Rust 1.99 rather than 1.100 is consistent with the two-week rule (1.100 shipped 2026-11-12).
  - What is missing is a record of the *digest's* creation date: the `1.99-alpine` tag is rebuilt on
    every Alpine update, so "1.99 is old enough" does not prove "this digest is old enough". Add the
    `created` date next to each digest in the comment.
- **I-2. Build context.** `deploy/Dockerfile.dockerignore` is honoured by BuildKit only. With the
  legacy builder (`DOCKER_BUILDKIT=0`) the whole repository, `.git` included, is sent as context.
  Nothing outside the `COPY` lines reaches an image layer, so this costs time, not secrets. Coolify
  uses BuildKit.
- **I-3. Container hardening: correct.**
  - Runtime is distroless `static` `nonroot` (uid/gid 65532): no shell, no libc.
  - `--read-only`, `--cap-drop ALL` and `no-new-privileges` are documented.
  - The only writable path is `/data`, mode `0700`.
  - The relay makes no outbound connection, so egress can be closed.
  - `listen 0.0.0.0:8080` inside the container's namespace is necessary and documented with its
    warning.
- **I-4. Caddyfile against the spec: correct.**
  - `versions 1.1` (rule 18) and `keepalive 20s` (rule 34).
  - Heads buffered through Go `net/http` (rule 42; reasoning, not measured, as the README says).
  - Caddy replaces `X-Forwarded-For` with its peer, because no `trusted_proxies` is set in
    `servers`. A client cannot inject a left-hand value that the relay would use, and the relay reads
    right to left anyway.
  - Only `/sbtp/v1/*` is proxied, with no `redir` or `rewrite` (ADR 0030 rule 3).
  - Body backstop at 128 KiB, above `MAX_BLOCK_LEN`, so the relay's JSON `413` is the normal answer.
  - `header -Server` and `header_down -Via`. Caddy's own `413`/`431`/`404` bodies are empty, inside
    the ADR 0029 ceilings.
  - No access log, so no client addresses at rest.
  - If Caddy is ever put behind Cloudflare, it will need `servers { trusted_proxies static <CF
    ranges> }`, with the same origin-authentication caveat as M-2.
- **I-5. Header leaks behind Cloudflare.** Cloudflare adds `Server: cloudflare` and `CF-RAY`. This
  cannot be avoided and discloses nothing about the relay.
- **I-6. One replica and `Recreate`** for one data directory is the right rule. Without it a rolling
  update opens the same index twice.

## Not checked

- The base image digests against the registries (no registry query was run), their creation dates,
  and the Alpine/distroless contents (no image was built or scanned in this review).
- The `docker build` itself, the static linking of the musl binary, and the ~3 MiB memory figure.
- The behaviour of a real K3s ServiceLB/MetalLB path (M-1 is reasoned from documented SNAT
  behaviour, not measured on the cluster).
- Whether Cloudflare appends the true client address for Workers subrequests and cross-zone
  origin pulls, and whether it buffers request bodies (M-2 and M-3).
- Coolify's default Traefik flags (for example whether `forwardedHeaders.insecure` is set). This
  does not change the relay's client choice, which uses the rightmost untrusted address, but it
  should be read on the VPS.
- The Caddy local test results claimed in the README were not reproduced.
