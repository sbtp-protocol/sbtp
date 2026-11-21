# Deploying `sbtp-relay`

The goal is a public demo relay, not a production service. `sbtp-relay` serves plain HTTP/1.1 and
MUST NOT be exposed without a reverse proxy that terminates TLS (ADR 0019 rule 42). This directory
has:

| File | What it does |
|---|---|
| `Dockerfile` | Multi-stage build: a static musl binary, then a distroless `nonroot` image |
| `Dockerfile.dockerignore` | The build context: workspace manifests and Rust sources only |
| `Caddyfile` | Caddy in front of the relay on a bare VM, for the demo |

## Static binary

The relay builds as a fully static musl binary (`x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl`). The Rust Alpine builder image is natively musl and has the C
toolchain that `blake3` needs, so no cross toolchain is needed. Run from the repository root:

```bash
docker build -f deploy/Dockerfile --platform linux/amd64 --target export --output type=local,dest=dist/amd64 .
docker build -f deploy/Dockerfile --platform linux/arm64 --target export --output type=local,dest=dist/arm64 .
```

Each command writes `dist/<arch>/sbtp-relay`. A build for the other architecture runs under
emulation and is slower. On a Linux host that already has the musl target and a musl C compiler,
`cargo build --release --locked -p sbtp-relay --target x86_64-unknown-linux-musl` gives the same
result.

Release builds use the `release` profile only (ADR 0013 "Build": `opt-level = "s"`, LTO, stripped,
no `panic = "abort"`). They never use `--all-targets`, a test profile or the `vector-gen` feature.
The runtime image has no libc, so it is also the check that the binary is static: a dynamically
linked binary does not start there.

## Docker image

```bash
docker build -f deploy/Dockerfile -t sbtp-relay .
docker run -d --name sbtp-relay \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v sbtp-data:/data -p 127.0.0.1:8080:8080 sbtp-relay
```

- **Base images.** Both are pinned by the digest of their multi-platform index:
  `rust:1.99-alpine` for the build and `gcr.io/distroless/static-debian12:nonroot` for the runtime.
  The build downloads only crates from crates.io, through `Cargo.lock` (`--locked`): no `apk add`,
  no `curl`. To update a base image, read the new digest with
  `docker buildx imagetools inspect <image>:<tag>` and wait until it is two weeks old.
- **User.** uid/gid 65532 (`nonroot`). No shell and no package manager in the image.
- **File system.** The root file system can be read-only (`--read-only`, Kubernetes
  `readOnlyRootFilesystem: true`). The relay writes only to `data_dir` (`/data`, the volume): its
  temporary files are in `data_dir/tmp`, and logs go to standard error, never to a file. It does
  not need `/tmp`. It makes no outbound connection, so egress can be closed.
- **Kubernetes security context.** The `--chown=65532:65532` / `0700` mount point of the image
  only initialises a Docker named volume. A PersistentVolumeClaim is mounted with the
  provisioner's ownership, often `root:root 0755`, and the relay (uid 65532) then cannot write and
  stops at start-up (it fails closed). K3s `local-path` creates `0777` directories, which work but
  are world-writable on the node. Set, on the pod and container:

  ```yaml
  securityContext:   # pod level
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
  # container level
  securityContext:
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    capabilities: { drop: [ALL] }
  ```

- **Existing `data_dir`.** The relay does not check the owner or mode of a `data_dir` that already
  exists; it only needs it to be writable by uid 65532. Setting the ownership and mode (`0700`) is
  the operator's job.
- **Kubernetes service links.** A Service named `sbtp-relay` makes Kubernetes inject environment
  variables such as `SBTP_RELAY_PORT` and `SBTP_RELAY_SERVICE_HOST` into every pod of the
  namespace. The relay rejects any unknown `SBTP_RELAY_*` variable, so the pod fails at start-up
  unless the pod spec sets `enableServiceLinks: false` (or the Service has another name).
- **Listen address.** The image sets `SBTP_RELAY_LISTEN=0.0.0.0:8080`, so that a proxy in another
  container or pod can reach it, and the relay logs a `listen_not_loopback` warning at start-up.
  Publish the port only on loopback (`-p 127.0.0.1:8080:8080`) or keep it on an internal network
  (a Kubernetes `ClusterIP` Service). Override it with `-e SBTP_RELAY_LISTEN=...`. Docker's
  published ports bypass host firewalls such as `ufw`, so a mapping on `0.0.0.0` exposes plain HTTP
  to the internet. On Coolify, leave "Ports Mappings" empty, set only "Ports Exposes: 8080" and
  route through Traefik; use the cloud provider's firewall (Hetzner Cloud Firewall) as the real
  perimeter.
- **Settings.** Every setting is an `SBTP_RELAY_*` environment variable (ADR 0018 rule 6), or a
  TOML file mounted read-only and named by `SBTP_RELAY_CONFIG`.
- **Stop.** `SIGTERM` (Docker's and Kubernetes' default) drains connections and closes the index;
  a clean stop keeps the `/query` cursors valid. Give it a few seconds (`terminationGracePeriodSeconds`
  of the default 30 is enough).
- **Health check.** The image has no `HEALTHCHECK`: there is no shell or HTTP client inside it, and
  the relay has no health subcommand. A Kubernetes `httpGet` probe on `/sbtp/v1/info` (port 8080)
  needs neither. Each probe takes a token from the probing address's `block` bucket (burst 200,
  3,000 per minute by default), so one probe every 10 seconds costs nothing noticeable.
- **Memory.** About 3 MiB resident when idle (measured, `docker stats`, arm64). The start-up line
  `memory_bound` gives the computed worst case of the settings in use (14,747,092 bytes, about
  14.7 MB, with the `small` profile, the demand set of ADR 0046 included). A container limit of
  32 MiB leaves room.

## Retention: keep, demand eviction, archive

By default the relay keeps what it receives (ADR 0046): `block_ttl_ms = 0` (no eviction by age)
and `demand_eviction = true`. When the store passes `demand_high_water_pct` (90 %) of
`max_store_bytes`, the sweeper deletes the blocks requested least recently, down to
`demand_low_water_pct` (80 %); a block requested in the last `demand_epoch_ms` (8 hours), directly
or through at most two shared caches in series, is never deleted, and a new block stays at least
three epochs (24 hours). A `PUT` never deletes anything: a new block that does not fit gets `507`, with a
`Retry-After` of one sweeper interval only while the store is above the high-water mark and the
sweeper can make room (demand eviction neither suspended nor stuck, ADR 0046 clarification D5);
otherwise without `Retry-After`, so that clients try another relay.

- **Archive relay.** Set `demand_eviction = false` and leave `block_ttl_ms = 0`. Nothing is ever
  deleted; a full store answers `507` (ADR 0013 rule 19). `/info` publishes
  `"block_ttl_ms": null` and `"demand_eviction": false`, which is how clients and mirrors recognise
  an archive (ADR 0043 rule 1, as amended). Size `max_store_bytes` for the data you intend to keep
  and watch `store_bytes` and `storage_full_total`.
- **Age-only relay.** `demand_eviction = false` and a `block_ttl_ms` of your choice (at least
  60,000 ms).
- **Privacy.** With demand eviction on, the index records, per block, the epoch in which it was
  last requested (never by whom). An operator who does not want this turns demand eviction off.
- **Restarts and suspensions.** Demand eviction is suspended for two epochs (`2 ×
  demand_epoch_ms`, 16 hours by default) whenever a demand may have gone unrecorded (ADR 0046
  rule 13 and clarifications D1 to D4); reads and writes are unaffected and a full store answers
  `507` meanwhile. The start-up line `demand_suspended` gives the `cause`:
  - `unclean_start`: the last stop was not clean: `SIGKILL`, a crash, a power loss, or a drain
    cut by a second signal or by its deadline (requests were still running). Stop with one
    `SIGTERM` and let the drain finish.
  - `no_history`: the first start after an upgrade that added demand tracking or the record of
    the `demand_eviction` setting (a relay already running the previous build gets this one-off
    `2 × demand_epoch_ms` suspension once), or an index rebuilt from the block files: the index
    knows when blocks were accepted, not when they were last read. A new, empty data directory
    is not suspended.
  - `enabled`: `demand_eviction` was `false` at the previous start, when reads were not recorded.
  - `restored`: a suspension was running at the last clean stop; it keeps its end.
  - `lost` (while running, rate-capped): the demand set was full or a flush failed.

  The first start on an index written before demand tracking also fills the demand tables before
  it listens, logging `demand_migration` lines (`phase=start`, `progress` every 100,000 blocks,
  `end` with `filled` and `duration_ms`), so that a slow start on a large index can be told from
  a hang.
- **Response headers.** With demand eviction on, a block response carries
  `Cache-Control: public, max-age=31536000, s-maxage=<E/2>, immutable` and
  `CDN-Cache-Control: public, max-age=<E/2>, must-revalidate` (`E/2` in seconds, 14,400, that is
  4 hours, by default), so that a shared cache revalidates each requested block at least once per
  `E/2` and the relay sees that demand. Browsers keep the one-year lifetime. The relay computes these
  values; nothing is configured for them. With demand eviction off, the one-year
  `Cache-Control` alone, as before.

## Ingest bounds against disk filling

Valid blocks within the per-client rates can still fill a store and, with demand eviction, push
out cold legitimate blocks (ADR 0049). The relay bounds the **bytes it stores per hour**, counted
as quota cost (a block file rounded up to 4 KiB plus its entry charge), with two kinds of token
bucket. Nothing is recorded about a writer: group buckets live in memory only, and no network,
address or client key is stored with a block, logged or put in a metric label.

- **Per network group, always on.** Each `PUT` belongs to the IPv6 /56 and /48, or the IPv4 /24,
  of its client address (the same address as the client key, so `trusted_proxies` and
  `client_ip_header` must be right). A /48 or a /24 may store `ingest_group_share_pct` (25 %) of
  `ingest_bytes_per_hour` per hour, a /56 `ingest_group56_share_pct` (10 %), with five minutes of
  burst. Over its budget a group gets `429 RateLimited` with `Retry-After`, before its body is
  read; only that group is refused. At most `ingest_group_max` groups are tracked (1,024 on
  `small`); when the table is full of active groups, a new group passes unchecked
  (`ingest_group_unchecked_total`) rather than sharing a bucket with a flooder.
- **Global cap, only under disk pressure.** All `PUT`s together may store
  `ingest_bytes_per_hour` (200 MiB on `small`, 2 GiB on `standard`, 16 GiB on `large`) per hour,
  with five minutes of burst. The cap is checked only while the store is at or above
  `demand_low_water_pct` (80 %) of `max_store_bytes`; a new block over it gets `503 Unavailable`
  with `Retry-After` of at most 300 s, and nothing is stored. A block the relay already holds
  still gets `200`; reads and replication are not affected. A re-sent expired or evicted block is
  a new block.
- **No latch.** Every refusal ends as the buckets refill with time; nothing is persisted and no
  restart or operator action is needed. Addresses in `rate_limit_exempt` are neither charged nor
  refused. `ingest_bytes_per_hour = 0` turns both bounds off.

Normal traffic does not meet these bounds: a relay with 1,000 writers at five times their average
rate stores about 21 MB/h, a tenth of the `small` budget. Behind a carrier NAT or a shared host,
one /24 or /48 carries many users; if `ingest_group_limited_total` grows for such a network,
raise `ingest_group_share_pct`. Behind a proxy that hides client addresses (no
`client_ip_header`, proxy outside `trusted_proxies`) every client is one group and the whole relay
is held to one group's share.

**At the CDN edge.** Behind a CDN, also rate-limit `PUT /sbtp/v1/block` at the edge, per client
address and, where the CDN offers it, per network prefix, so that a flood stops before it reaches
the origin; the relay's own bounds remain the guarantee (ADR 0049 rule 11). For example, a
Cloudflare rate limiting rule on `http.request.method eq "PUT" and http.request.uri.path eq
"/sbtp/v1/block"`, counted per IP, of a few hundred requests per ten minutes, with the action
"Block" for the rest of the period.

## Replication

A relay can copy blocks from other relays its operator chooses (ADR 0048, pull replication). It
is compiled into the published binary and image, and **off** until `peers` is set: with the
default settings nothing is contacted.

```toml
# Relays to copy from: absolute https URLs, without userinfo, query or fragment, at most
# replication_max_peers (4 on small, 16 on standard, 64 on large). A peer is never added from
# anything the relay receives.
peers = ["https://relay-a.example", "https://relay-b.example/sbtp"]
# `now` (default): copy what a peer stores from the first time it is seen (minus
# replication_resync_margin_ms). `all`: its full history, for an archive relay.
replication_start = "now"
```

Two operators who list each other hold the same blocks within one poll interval
(`replication_poll_ms`, 10 s). A loop between relays is harmless: a block the relay holds is
never fetched again. For each peer the relay walks `/query` with a cursor kept in its index,
skips the blocks it holds and those below its `min_pow_difficulty` without fetching them,
fetches the others with `GET` and `Sbtp-Replication: 1`, validates each as a `PUT` body (format,
timestamp, proof of work, signature, and that it is the requested block) and stores it as a new
block. A copy is not a read: the source does not count it as demand.

- **Archive relay.** `block_ttl_ms = 0`, `demand_eviction = false` and
  `replication_start = "all"`; size `max_store_bytes` for the history of every peer.
- **Bounds** (profile rows): `replication_max_in_flight` requests at a time (1 on `small`),
  `replication_blocks_per_min` (600) and `replication_bytes_per_hour` (256 MiB) for all peers
  together, shared round robin. Every request has the body ceilings of ADR 0029 and a total time
  limit (`replication_request_timeout_ms`, 30 s). The peer's `Retry-After` is obeyed; without it
  the relay backs off exponentially up to `replication_max_backoff_s` (1 hour) and never gives a
  peer up. These defaults stay well under a `small` peer's own allowances.
- **Disk.** Replication stores nothing while the store is above `demand_high_water_pct` (90 %)
  of `max_store_bytes` (`replication_paused`); the room above the mark stays for clients.
  Replicated blocks are not charged to the ingest bounds of ADR 0049: replication has its own
  budget.
- **Minimum difficulty.** A relay with `peers` set refuses to start with `min_pow_difficulty`
  above the network difficulty (16).
- **Memory.** With replication on, the computed bound of `small` grows by 723,077 bytes (bound
  under 16 MB); it is logged at start-up (`memory_bound`).
- **Trust roots.** `https` peers are verified with TLS 1.3 against the operating system bundle
  (`/etc/ssl/certs/ca-certificates.crt` in the image; the first of the usual Debian, RHEL, SUSE
  and Alpine or macOS paths elsewhere) or, when set, `peer_ca_file` (a PEM file of at most
  4 MiB). A relay with an `https` peer and no root refuses to start. No redirect is followed.
- **Private addresses.** A peer name that resolves to a loopback, private, shared (RFC 6598),
  link-local (cloud metadata), unspecified, multicast or reserved address is not contacted,
  unless the peer URL is that literal address or `replication_allow_private = true`. Names are
  resolved for each connection and the checked address is the one connected to. `http` is
  accepted for a loopback host only (tests).
- **Logs and metrics** name a peer by its position in `peers`, never by its URL; the `peers`
  setting line logs the number of peers. Counters: `replication_blocks_stored_total`,
  `replication_bytes_total`, `replication_skipped_total{reason}` (`held`, `pow`, `invalid`,
  `not_found`, `future`), `replication_requests_failed_total{status}`,
  `replication_cursor_resets_total`, gauge `replication_paused`. Events:
  `replication_peer_backoff`, `replication_paused`, `replication_cursor_reset`, rate-capped.

**Firewall egress.** With `peers` set the relay makes outbound connections: allow TCP 443 (and
any other port named in `peers`) to the peers' addresses, and DNS. Without `peers` it needs no
egress at all; keep egress closed then. A host or Kubernetes network policy that allows egress
only to the listed peers also covers the private-address rule above.

## Alerts

The counters and gauges worth an alert on a public relay, with plain starting thresholds. They are
named as in ADR 0046 rule 29 and ADR 0049 rule 16 (prefix `sbtp_relay_` once `/metrics` is
served); until then, read them from the periodic `stats` log line (field in parentheses) and the
`demand_stuck`, `demand_suspended` and `ingest_capped` events.

| Signal | Alert when | What it means |
|---|---|---|
| `storage_full_total` (`refused_507`) | increases for more than one hour | New blocks are refused with `507`: the store is full and eviction is not making room fast enough, or cannot (see `demand_stuck`). |
| `demand_evicted_blocks_total` (`demand_evicted`) | grows by more than 10 % of the held blocks in a day | Blocks are pushed out faster than usual: a write flood (security review 2026-11-21, M-2) or a store sized too small. Consider a larger `max_store_bytes` or a `block_ttl_ms` as an outer bound. |
| `demand_suspended` (`demand_suspended`) | is `1` for longer than `2 × demand_epoch_ms` (16 hours by default) | A suspension should end after two epochs; one that keeps renewing means demands keep being lost (see `demand_lost_total`) or the relay keeps stopping uncleanly. |
| `demand_stuck_total` (`demand_stuck` events) | increases on two sweeper runs in a row | Above the high-water mark with nothing to evict: every block is protected (requested or accepted within three epochs, 24 hours by default), or `cause=index`, the index file alone reaches the low-water mark. Grow `max_store_bytes`. |
| `ingest_capped_total` (`ingest_capped`; `ingest_capped` and `ingest_cap_ended` events) | increases for 15 minutes | Ingest capped: the store is above the low-water mark and writers use the whole hourly budget, a flood or real growth. Check `ingest_group_limited_total` and the disk. |
| `ingest_group_limited_total` (`ingest_group_limited`) | increases by more than 100 in 15 minutes | Group limited: one network takes more than its share. Usually a flood; with a carrier NAT, raise `ingest_group_share_pct`. |
| `ingest_group_unchecked_total` (`ingest_group_unchecked`) | increases | Group table full: many networks write at once and new groups pass unchecked (ADR 0049 rule 5), possibly a many-network flood (Q-71). |
| `demand_evicted_blocks_total` while `demand_coldest_ms` is less than 7 days old | increases | Eviction of recent blocks: blocks requested within the week are evicted; the store is too small for its traffic, or a flood. |
| `demand_lost_total` (`demand_lost`) | increases at all | A demand could not be recorded (set full, or an index write failed); each loss suspends demand eviction for two epochs (16 hours by default). Repeated losses point at index write errors (`index_write_errors_total`) or at `demand_touch_max` too small for the read rate. |

## Pulling the CI image

The `relay-image.yml` workflow (docs/ci.md) builds `deploy/Dockerfile` on GitHub Actions and
pushes `ghcr.io/sbtp-protocol/sbtp-relay` for `linux/amd64`. It runs on a `relay-v<version>` tag
(image tags `<version>` and `sha-<commit>`) or on a manual dispatch from `main` (`sha-<commit>`
only). The digest is in the run's job summary, and in the package page on GitHub.

**Deploy by digest, never by tag.** A tag can be moved to another image; a digest names exactly
the bytes that CI built:

```bash
docker pull ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest>
docker run -d --name sbtp-relay \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v sbtp-data:/data -p 127.0.0.1:8080:8080 \
  ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest>
```

In Compose, Kubernetes or Coolify, write the image as `ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest>`
too. To check which commit an image was built from:
`docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' <image>`.
Check its build provenance before deploying:
`gh attestation verify oci://ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest> -R sbtp-protocol/sbtp`.

**Access.** The repository is public and so is the package: pulling needs no token and no
`docker login` on the host. Do not create a token for it. If a pull is refused with `denied` or
`unauthorized`, the package is still private (GHCR creates a package private on its first push in
some organisation settings): make it public in the package settings ("Change visibility") rather
than giving the host a token. Only if the package must stay private, use a classic personal access
token with the `read:packages` scope only (GHCR does not accept fine-grained tokens for pulls at
the time of writing), with an expiry of 90 days or less, stored on that host only (`docker login
ghcr.io -u <account> --password-stdin`), never in the repository or a deployment file.

## Behind a reverse proxy

Whatever the proxy, it MUST (ADR 0019 rules 18, 34 and 42; ADR 0030):

- terminate TLS; it MAY offer HTTP/2 and HTTP/3 to clients;
- buffer each request head before it sends anything to the relay;
- reach the relay over HTTP/1.1;
- close idle upstream connections before the relay's `idle_timeout_ms` (30 s): 20 s is the
  recommended value;
- set, or append to, `X-Forwarded-For` the address of the peer it accepted the request from;
- have its own address in the relay's `trusted_proxies` (default: `127.0.0.1/32, ::1/128`);
- answer no `3xx` on `/sbtp/v1/` (no trailing-slash or path redirect; the plain-HTTP-to-HTTPS
  redirect on port 80 is allowed).

### Client identification

The per-client limits (token buckets, `max_connections_per_client`, in-flight `PUT`s) key each
client by its IPv4 address or IPv6 /64 (ADR 0018 rule 20, ADR 0019 rules 29 to 31). For a request
from a peer in `trusted_proxies`, the relay reads `X-Forwarded-For` from right to left, steps over
every address in `trusted_proxies`, and uses the first other address (ADR 0020 rules 6 to 10). A
peer in `trusted_proxies` is not counted at accept; each of its requests counts against the client
named in the header.

If the proxy's address is missing from `trusted_proxies`, every request has the proxy as its
client: all clients share one set of buckets and one `max_connections_per_client` bound (8), and
the relay logs a warning when that key is refused. If a proxy in `trusted_proxies` does not write
the header, its requests share one key per proxy address.

Never put a byte-level forwarder (`ssh -R`, `socat`, `stunnel`, nginx `stream`, HAProxy
`mode tcp`) on an address in `trusted_proxies` (ADR 0020 rule 17). Every address in the list MUST
only ever connect through a program that appends the address of its own peer to `X-Forwarded-For`.
Through a byte-level forwarder, clients write their own `X-Forwarded-For` and pick any client key,
which defeats every per-client bound. Loopback is trusted by default: if such a forwarder runs on
the relay's host, set `trusted_proxies = []`; the forwarder is then one client, and not a
supported way to publish.

After deployment, check that clients are told apart: send `PUT`s from two different hosts, exhaust
the `block` bucket of the first one (it gets `429`), and check that the second still gets `201`
or `200`. If both get `429`, all clients share one key (see "Traefik (K3s, Coolify)").

With several proxies in a row (Cloudflare, then Traefik), every hop that writes the header must be
in `trusted_proxies`, and each hop must keep the address its own peer wrote rather than replace it.

Cloudflare's ranges carry every Cloudflare customer's traffic, not only this zone's. Listing them
in `trusted_proxies` (and in Traefik's `forwardedHeaders.trustedIPs`) meets ADR 0020 rule 17 only
if nothing but this zone's Cloudflare can reach the origin. Before listing them, authenticate the
origin pull: Cloudflare **Authenticated Origin Pulls** (per-zone certificate, with a Traefik TLS
option `clientAuth.clientAuthType: RequireAndVerifyClientCert` on the relay's router), or a
Cloudflare Tunnel with no open port. Also restrict ports 80 and 443 to Cloudflare's ranges in the
cloud firewall (Hetzner Cloud Firewall, not `ufw`: Docker's published ports bypass `ufw`). Without
this, someone who reaches the origin from inside Cloudflare (their own zone, a Worker) can pick a
fresh client key per request.

### Behind a CDN: `client_ip_header`

Some chains break `X-Forwarded-For`: Cloudflare → Traefik → relay, where Traefik does not trust
the incoming header (Cloudflare's ranges are not in its `forwardedHeaders.trustedIPs`) and
replaces it with the Cloudflare edge address. Every client behind one edge then shares one key.
Cloudflare also writes the address of its own peer into `CF-Connecting-IP`, one value,
overwriting whatever the client sent, and Traefik forwards that header unchanged. The relay can
read it instead (ADR 0044):

```bash
SBTP_RELAY_CLIENT_IP_HEADER=cf-connecting-ip   # off by default
```

What the relay does with it:

- It reads the header only on a connection from a peer in `trusted_proxies`; from any other peer
  the header is ignored and the client is the peer address. `trusted_proxies` lists the proxy that
  connects to the relay (Traefik's pod network, for example), **not** Cloudflare's ranges: no address
  chain is read.
- With the setting on, `X-Forwarded-For` is never read.
- The header must appear once and hold exactly one bare IPv4 or IPv6 address (no port, no brackets,
  no list), not itself in `trusted_proxies`. The address is keyed as any client address (IPv6
  aggregated to `client_ipv6_prefix` bits, `rate_limit_exempt` applies). Anything else (absent, two
  lines, a list, a port, `unknown`) falls back to the proxy's own address: the request is served,
  and every such request shares that one key. A throttled `forwarded_invalid reason=client_ip_header`
  warning says so. A health check without the header is such a request.
- Neither the header value nor the derived address is ever logged. At start-up a `config_warning`
  line with code `client_ip_header` names the header and the trust it implies.
- `X-Forwarded-For` and `Forwarded` are refused as values (the relay does not start): they are
  address chains, handled by the default path.

Set it only when **both** hold; the relay cannot check either:

1. **Only the CDN can reach the origin.** No other path to the proxy's ports, and no other program
   on an address in `trusted_proxies`.
2. **The CDN overwrites the header** on every request with the address of its own peer, whatever
   the client sent. Cloudflare does this for `CF-Connecting-IP`.

**Cross-tenant risk.** Cloudflare's addresses carry every Cloudflare customer's traffic. Another
customer (their own zone pointed at your origin's address, or a Worker making `fetch()` calls to
it) reaches the origin through those addresses and can set `CF-Connecting-IP` to any value, choosing
a fresh client key for every request and defeating every per-client bound. A firewall that admits
only Cloudflare's ranges does not stop this. Before setting `client_ip_header`:

- authenticate the CDN's connection to the origin: Cloudflare **Authenticated Origin Pulls** with a
  per-zone (not the shared global) certificate, verified by the proxy (Traefik TLS option
  `clientAuth.clientAuthType: RequireAndVerifyClientCert` with that zone's CA), or reach the origin
  only through a **Cloudflare Tunnel** with no open port; and
- restrict ports 80 and 443 to Cloudflare's published ranges in the cloud firewall (not `ufw`:
  Docker's published ports bypass it).

Check after deployment as in "Client identification": two hosts, one exhausts its `block` bucket,
the other is still served.

### Bare VM with Caddy

`Caddyfile` is for a demo on a single VM where the relay and Caddy share the host. It is not used
on K3s or Coolify, where Traefik is the proxy.

```bash
SBTP_RELAY_DOMAIN=relay.example.org caddy run --config deploy/Caddyfile
```

- The relay listens on `127.0.0.1:8080`: the binary's default, or the container with
  `--network host` and `-e SBTP_RELAY_LISTEN=127.0.0.1:8080`. The default `trusted_proxies` already
  trusts Caddy on loopback.
- The DNS record of the domain points at the VM and ports 80 and 443 are open: Caddy obtains the
  certificate itself (automatic HTTPS).
- Only `/sbtp/v1/*` is proxied; any other path gets `404` from Caddy. No access log is configured
  (Caddy writes none unless a `log` directive asks for one); see "Logs and client addresses" for
  what Caddy's runtime log can still hold and how to log safely if you need access logs.
- Limits, against the relay's defaults:

  | Caddy | Value | Relay |
  |---|---|---|
  | `max_header_size` | 12 KiB | `max_header_bytes` 16,384 (leaves room for the `X-Forwarded-*` headers Caddy adds) |
  | `timeouts read_header` | 5 s | `header_timeout_ms` 5,000 |
  | `timeouts read_body` | 10 s | `body_timeout_ms` 10,000 |
  | `request_body max_size` | 128 KiB | body limit `MAX_BLOCK_LEN` 65,909 bytes: a body between the two gets the relay's `413 BodyTooLarge` JSON body |
  | `request_buffers` | 128 KiB | the whole body is read by Caddy first, so a slow upload holds no relay connection slot |
  | `transport http versions` | `1.1` | no HTTP/2 in the relay (ADR 0019 rule 18) |
  | `transport http keepalive` | 20 s | `idle_timeout_ms` 30,000 (ADR 0019 rule 34) |

- Head buffering (rule 42): Caddy is built on Go's `net/http`, which parses the whole request head
  before any handler runs, so nothing reaches the relay before the head is complete. This follows
  from how `net/http` works; it was not measured.
- Checked locally (Caddy 2.11.9, relay image, `localhost` with Caddy's internal CA): `caddy fmt`
  and `caddy validate` pass; `PUT` gives `201` then `200`, `GET /query` works over HTTP/2;
  `/sbtp/v1/info/`, `//sbtp/v1/info` and `/sbtp/v1` give `404`, never `3xx`; a 70,000-byte body
  gets the relay's `413 BodyTooLarge` (chunked too), a 200,000-byte body Caddy's `413`; port 80
  answers `308` to `https`. A 13 KB header gets `431` over HTTP/1.1; over HTTP/2 Go resets the
  stream instead.

### Traefik (K3s, Coolify)

No configuration file is shipped for Traefik yet. What the relay needs from it (Traefik
documentation and source read through Context7 on 2026-11-20):

- HTTP/1.1 upstream: a plain `http://` service, never the `h2c` scheme.
- Idle upstream connections: `serversTransport` `forwardingTimeouts.idleConnTimeout` defaults to
  90 s, above the relay's `idle_timeout_ms` (30 s). Set it to 20 s on the relay's transport (ADR
  0019 rule 34); otherwise a `PUT` sent on a connection the relay just closed gets `502`.
- `X-Forwarded-For`: Traefik deletes the incoming `X-Forwarded-*` headers unless the peer is in
  the entry point's `forwardedHeaders.trustedIPs` (or `insecure` is set), then appends the
  address of its own peer. Behind Cloudflare, list Cloudflare's published ranges in
  `forwardedHeaders.trustedIPs`, or every client is seen as a Cloudflare address.
- Request bodies: Traefik streams them to the upstream by default, so a few slow `PUT`s would
  hold every global `PUT` slot until `body_timeout_ms`. Require a `buffering` middleware on the
  relay's router, with `maxRequestBodyBytes: 131072` and `memRequestBodyBytes: 131072` (the
  same values as the Caddyfile): Traefik then reads the whole body before it opens the upstream
  request, and refuses larger bodies itself. The relay's own `413` stays the normal answer
  between 65,909 and 131,072 bytes.
- Request heads: Traefik's entry point `http.maxHeaderBytes` defaults to 1 MiB (Go). That is
  harmless, because the relay answers `431` itself above `max_header_bytes` (16,384), but set it
  to 12 KiB to match the Caddyfile if you want Traefik to answer first.
- `trusted_proxies` of the relay must hold the address Traefik connects from: the pod network on
  K3s (by default `10.42.0.0/16`), the Docker network of Coolify. Behind Cloudflare it must also
  hold Cloudflare's ranges, because the relay steps over every trusted address from the right
  (see "Client identification"); several of those ranges are wider than /16, so the relay logs
  `trusted_proxies_broad` for them.
- Traefik must see the real client address in the first place. This is a requirement: its
  Service needs `externalTrafficPolicy: Local` (on K3s, a `HelmChartConfig` for `traefik` with
  `service.spec.externalTrafficPolicy: Local`), or an upstream L4 balancer using the PROXY protocol
  with Traefik's `proxyProtocol.trustedIPs`. With the default `Cluster` policy the connection is
  source-NATed to a node address, Traefik writes that address, and the relay (which steps over the
  pod network) falls back to Traefik's own address: every client then shares one set of buckets,
  and one busy client gives the others `429`. On the planned K3s cluster the Traefik Service
  already uses `Local` and LAN client IPs are preserved.
- Pod network trust: with `trusted_proxies` on the pod CIDR (`10.42.0.0/16`), any pod of the
  cluster could write `X-Forwarded-For` and choose its client key. Add a `NetworkPolicy` that
  allows ingress to the relay pod only from the Traefik pods (namespace `kube-system`, label
  `app.kubernetes.io/name=traefik`). The planned K3s manifests include it, together with the
  buffering middleware above (131072) and `enableServiceLinks: false`.
- Coolify: do not fill "Ports Mappings" (see "Listen address").
- Cloudflare's limits (100 MB request body, 100 s to the first response byte) are far above the
  relay's (65,909-byte body, 15 s request deadline) and change nothing. Its settings must not put
  a `3xx` or an HTML page on `/sbtp/v1/` (ADR 0030 rule 3, ADR 0029 rules 4 and 5):
  - SSL/TLS mode **Full (strict)**. Flexible makes Cloudflare reach the origin over HTTP and hit
    the HTTP-to-HTTPS redirect (a `3xx`, or a loop). "Always Use HTTPS" is fine.
  - No challenge, Bot Fight Mode or "Under Attack" rule on `/sbtp/v1/*` (add a WAF skip rule for
    that path): their HTML challenge pages can exceed the 16,384-byte error-body ceiling.
  - Cache rules on `/sbtp/v1/*`. Either bypass the cache for the whole path (every request reaches
    the relay), or:
    - bypass for every path except `GET /sbtp/v1/block/*`;
    - for `/sbtp/v1/block/*`: "Eligible for cache"; Edge TTL "Use cache-control header if present,
      bypass cache if not"; Browser TTL "Respect origin". Never "Ignore cache-control header and use
      this TTL", and no Cache Response Rule that sets `Cache-Control` on this path: either one
      overrides the lifetime that the relay sets for demand eviction (ADR 0046 rule 15);
    - Tiered Cache with Smart Topology on, so that one upper tier contacts the relay.
    - The relay's default shared lifetime is 4 hours (`s-maxage=14400`, `CDN-Cache-Control:
      max-age=14400`), above the 2-hour minimum Edge Cache TTL of the Free plan (ADR 0046, "Shared
      cache behaviour checked"). With one upper tier, expect up to six revalidations (`304`, no body)
      per requested block per day, about 6.9 per second at 100,000 active blocks (ADR 0046 rule 27).
    - `client_ip_header = "CF-Connecting-IP"` on the relay (ADR 0044).

    No more than two caches in series may sit in front of a relay with demand eviction on (an edge
    and one upper tier, ADR 0046 rule 17); with more, turn demand eviction off. `/sbtp/v1/info`
    and `/sbtp/v1/query` are always bypassed: `/info` is `no-store`, and a cached `/query` page
    would hide new blocks.
  - **Turning demand eviction on.** A relay that served blocks with `demand_eviction = false` sent
    a one-year shared lifetime, and the CDN may serve those entries for a year without asking the
    relay, so their demand never reaches it. Restart the relay with `demand_eviction = true` first,
    then purge `/sbtp/v1/block/*` from the CDN cache (a purge by prefix where the plan offers it,
    otherwise a purge of everything cached for the relay's host), within
    `2 × demand_epoch_ms` (16 hours by default) of the restart. A purge before the restart is not
    enough. With the cache bypassed on `/sbtp/v1/*`, no purge is needed.

    Why: the relay suspends demand eviction for `2 × demand_epoch_ms` after this restart
    (`demand_suspended cause=enabled`), which covers the reads it did not record while it was off,
    but not the ones a CDN keeps answering from its own one-year entries. Requests made before the
    restart are still cached with the one-year lifetime, so a purge made then is refilled at once;
    a purge after the restart makes every later request reach the relay, or be cached with the
    short lifetime of demand eviction, before the suspension ends.
  - Replication requests (`Sbtp-Replication: 1`, ADR 0048 rule 18) are answered
    `Cache-Control: no-store` and `CDN-Cache-Control: no-store`, and are not counted as demand:
    a copy made by another relay is not a read.

## Logs and client addresses

The relay and the proxy in front of it keep different things. An IP address is personal data in
most jurisdictions; the reverse proxy is the one place where addresses are logged at all (ADR 0021
"Client identity"), so its retention is the operator's decision.

What the relay logs (ADR 0021 rules 10 to 15), on standard error only:

- Never, at any level or setting: a client IP address or a prefix of one, a value of
  `X-Forwarded-For` or of any other request header, a request path as received or a query string,
  a cursor, any byte of a block, a public key or a signature. Call sites pass only values the relay
  produced from fixed sets (counts, sizes, durations, statuses, error names, route templates,
  `errno`).
- At start-up: the settings (including `trusted_proxies`, which are proxy addresses the operator
  chose), the data directory and the relay's own listen address. No client is involved.
- No per-request line at the default level `info` (rule 40). At `debug` (a start-up warning says
  so) one `request` line per request with the route template, method, status and duration, and the
  last 8 hexadecimal characters of a `block_id` on `block_stored` and `block_rejected`: still no
  address.
- `log_client_tag = "keyed"` (off by default, with a start-up warning) adds a `client` field: 8
  hexadecimal characters of a BLAKE3 keyed hash of the client key, with a key drawn at start and
  kept in memory only. Lines of one run can be linked; nothing can be turned back into an address
  or linked across restarts.

The relay's own lines therefore hold no client address. Their retention is the log sink's
(journald, Docker's log driver, the cluster's log collector). On a relay with eviction by age it
SHOULD NOT exceed `block_ttl_ms` (rule 15), so that logs do not outlive the blocks they mention; by
default there is no age limit (ADR 0046), and 30 days remains a reasonable retention for these
lines.

What a reverse proxy logs, and what to do about it:

- **Caddy.** No access log unless a site has a `log` directive; the shipped `Caddyfile` has none.
  Caddy's runtime log (standard error) still holds error entries, and an entry about a failed
  request (for example the relay being down) can carry the request with `remote_ip`, `client_ip`
  and its headers. Keep that sink's retention short. If you need access logs, drop the addresses or
  mask them, and bound the retention:

  ```caddyfile
  log {
  	output file /var/log/caddy/sbtp-relay.log {
  		# 7 days; Caddy's default is 2160h (90 days).
  		roll_keep_for 168h
  	}
  	format filter {
  		request>remote_ip delete
  		request>client_ip delete
  		request>headers>X-Forwarded-For delete
  		request>headers>Cf-Connecting-Ip delete
  	}
  }
  ```

  To keep coarse ranges for abuse handling instead, replace `delete` on the two address fields with
  `ip_mask 16 32` (16 bits of IPv4, 32 bits of IPv6). A /24 or a /48 still often designates one
  person or household: prefer `delete` unless you act on ranges.
- **Traefik.** Access logs are off by default (`accessLog` disabled). If you enable them, set
  `accesslog.fields.names.ClientAddr=drop`, `accesslog.fields.names.ClientHost=drop` and
  `accesslog.fields.names.ClientPort=drop`; header fields are dropped by default
  (`accesslog.fields.headers.defaultmode=drop`), keep it so. Bound the retention in the log
  collector.
- **Cloudflare** or another CDN keeps its own request logs under its own retention; that is a term of
  the CDN account, outside this configuration.

Recommended retention for any log that holds client addresses: none, or at most 7 days.

## Data directory

- `data_dir/tmp`, `data_dir/quarantine` and `data_dir/blocks` must be on **one file system**. The
  relay moves files between them with `link` and `unlink` (ADR 0013 rule 7, ADR 0023 rule 4), which
  fail across file systems (`EXDEV`): with `tmp/` elsewhere no block can be stored, with
  `quarantine/` elsewhere no damaged file can be moved out of the way. Do not mount a separate
  volume or a `tmpfs` on any of these subdirectories; mount the data volume at `data_dir` itself.
- A file-system quota on the data volume (`EDQUOT`) is reported like a full disk: `507` and a
  `storage_full` line (reason `edquot`).
- One relay process per data directory: a Kubernetes Deployment with one replica and the
  `Recreate` strategy, so that two pods never open the same volume.
