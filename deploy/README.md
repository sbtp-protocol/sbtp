# Deploying the relay

Operator notes for `sbtp-relay`. The relay serves plain HTTP; a public relay sits behind a reverse
proxy that terminates TLS and bounds slow or idle clients.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SBTP_LISTEN` | `127.0.0.1:8080` | Listen address. Keep it on loopback (or a private network only the proxy reaches). |
| `SBTP_DATA_DIR` | `data` | The store (`relay.redb`, `relay.position`) and the deny list (`deny.txt`). |
| `SBTP_CLIENT_IP_HEADER` | unset | Header holding the client address, written by the proxy. The relay uses its last entry. |
| `SBTP_MIN_POW_DIFFICULTY` | `16` | Minimum proof of work on `PUT`. |
| `SBTP_MAX_STORE_BYTES` | 8 GiB | Disk quota: over it, new blocks get `507`. |
| `SBTP_LISTED_ADDRESSES` | empty | Comma-separated client addresses given 16 times the per-client limits (a gateway). |

## Behind a reverse proxy

Every per-client limit (request rate, requests in flight, `PUT` bytes, subscriptions) is keyed on
the client address. Behind a proxy, the TCP peer is the proxy, so:

- **Set `SBTP_CLIENT_IP_HEADER`**, or every user shares one client address: one browser tab holding
  8 requests or 4 subscriptions locks everybody out with `429`.
- **The proxy must overwrite that header** (or append the real peer as the last entry). A header the
  client sent through unchanged lets it claim any address.
- **Only the proxy may reach the relay** when the header is set: a client that connects directly can
  write the header itself.

The relay logs a warning at startup when the header is set on a non-loopback listener, or unset on a
loopback one. The value may be a bare address, `ip:port` or `[v6]:port`; a request whose header is
missing or unparseable is counted under the proxy's address.

The proxy should also buffer request bodies (so that slow uploads never hold a relay request slot),
time out slow request heads and bodies, cap connections per client, and pass WebSocket upgrades for
`/sbtp/v1/subscribe` with a read timeout above the relay's ping interval (20 s).

nginx example (adapt names and certificates; any proxy with the same properties works):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
limit_conn_zone $binary_remote_addr zone=sbtp_conn:10m;

server {
    listen 443 ssl;
    # ssl_certificate ...; ssl_certificate_key ...;
    client_header_timeout 10s;
    client_body_timeout   10s;
    client_max_body_size  65909;
    limit_conn sbtp_conn 32;

    location /sbtp/v1/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_request_buffering on;
        proxy_set_header X-Real-IP $remote_addr;   # overwritten, never passed through
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 75s;
    }
}
```

with `SBTP_CLIENT_IP_HEADER=x-real-ip`. (`proxy_http_version 1.1;` is needed before nginx
1.29.7.)

## Deny list

`$SBTP_DATA_DIR/deny.txt`, one rule per line: `block <block_id hex>` or `key <public key hex>`; `#`
starts a comment. It is reloaded within 2 seconds of a change. A file that does not parse keeps the
previous list while running, and **stops the relay from starting**: starting without it would serve
every denied block again. A missing file is an empty list.

## Backup and restore

The spec requires a restored store to draw a new `relay_id`, so that clients drop positions that
the restored store may give again to other blocks. The relay draws one by itself when:

- the store file is a copy (a new file, so a new inode);
- `relay.position`, written next to the store after each new block, shows a greater position than
  the store holds: the store file was restored in place (`cp` or `rsync --inplace` over it).

It cannot tell when the whole data directory or volume is rolled back (a filesystem, LVM or cloud
disk snapshot, or a restore of the directory with `relay.position` in it). **After any restore,
create an empty `restored` file in the data directory before starting the relay:**

```sh
touch "$SBTP_DATA_DIR/restored"
```

The relay then draws a new `relay_id` and deletes the file. Doing so when it was not needed only
makes clients resync from position 0.

## Container

`deploy/Dockerfile` builds a static binary into a distroless image with no shell, running as
`65532:65532`. CI (`.github/workflows/relay-image.yml`, manual or on a `relay-v*` tag) publishes
it as `ghcr.io/sbtp-protocol/sbtp-relay` for `linux/amd64`, tagged `sha-<commit>` and, for a tag,
`<version>`. The job summary prints the pushed digest. **Deploy by digest, never by tag**, and
check the SLSA build provenance before the first use of a digest:

```sh
gh attestation verify oci://ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest> \
  --repo sbtp-protocol/sbtp \
  --signer-workflow sbtp-protocol/sbtp/.github/workflows/relay-image.yml \
  --source-ref refs/tags/relay-v<version> \
  --source-digest <commit you reviewed> \
  --deny-self-hosted-runners
```

It succeeds only if the digest carries a provenance attestation signed by the `relay-image.yml`
workflow of this repository, running on that tag and that commit, on a GitHub-hosted runner. It
does not prove the commit is free of bugs or that the tag points at reviewed history: review the
commit yourself, and prefer tags (protected by a repository ruleset) over `--source-ref
refs/heads/v1` or `refs/heads/main`, which is what a manually dispatched build carries. A bare
`-R sbtp-protocol/sbtp` check is not enough: it accepts an attestation from any workflow run in
the repository, including one on an attacker's branch.

Settings inside the container (the table above otherwise applies):

| Variable | Container default |
|---|---|
| `SBTP_LISTEN` | `0.0.0.0:8080` (the container's own network; `EXPOSE 8080`) |
| `SBTP_DATA_DIR` | `/data` (a volume) |
| `SBTP_CLIENT_IP_HEADER`, `SBTP_MIN_POW_DIFFICULTY`, `SBTP_MAX_STORE_BYTES`, `SBTP_LISTED_ADDRESSES` | as above |

Unknown variables are ignored: the v0.2 names (`SBTP_RELAY_*`) do nothing. Behind a proxy, set
`SBTP_CLIENT_IP_HEADER`; the relay then logs its startup warning (header on a non-loopback
listener), which is expected while only the proxy can reach port 8080. Never publish that port on
a public interface.

Run it with a read-only root filesystem: `/data` is the only path the relay writes, and logs go to
standard error. A memory limit of 256 MB is recommended; the relay needs far less, the limit only
keeps a fault from taking the host down.

```sh
docker run -d --name sbtp-relay --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m -v sbtp-data:/data -p 127.0.0.1:8080:8080 -e SBTP_CLIENT_IP_HEADER=x-real-ip \
  ghcr.io/sbtp-protocol/sbtp-relay@sha256:<digest>
```

Bind the port to loopback only, as above. Publishing it on a public interface (`-p 8080:8080`)
bypasses the proxy (and host firewalls such as ufw), so any client could forge the client-address
header and escape every per-client limit. The alternative is a user-defined Docker network shared
with the proxy container and no `-p` at all.

A named volume starts owned by `65532:65532`. A bind-mounted host directory must be writable by
that uid.

There is no healthcheck in the image (no shell, no HTTP client): the process exits on a fatal
error, and a probe from outside can call `GET /sbtp/v1/info`.

### Disk quota: no eviction

The relay never evicts a block. Once the store reaches the quota, new blocks get `507` and
everything already stored is still served. The operator then either grows the volume (and raises
the quota) or adds the keys that fill it to the deny list.

The quota is compared with the **length of `relay.redb`**, checked before each new block, and the
database grows that file in large steps (redb 4.6.0, `page_manager.rs`): it doubles the file while
it is smaller than one 4 GiB region, then adds one whole 4 GiB region at a time (a step is at most
4 GiB plus a few MiB of region headers). The file is extended with `ftruncate`, so it is sparse
(no disk space is used until pages are written), but a copy that does not preserve holes
(`docker cp`, a plain `cp`, `tar` without `-S`) materialises the full length. A file just under
the quota can still grow by one full step before the next check. So:

> volume usable space >= quota + min(quota, 4 GiB) + headroom (1 GiB or more, for the deny list,
> `relay.position`, file system overhead and a backup copy made in place)

Real data stops at the last file length below the quota, so the usable capacity is smaller than
the quota (between about half of it and all of it); the quota is a ceiling, not a target.

Example, a 7 GB volume (about 6.5 GiB usable on ext4): set `SBTP_MAX_STORE_BYTES=2147483648`
(2 GiB). The file cannot exceed about 4 GiB, which leaves about 2.5 GiB of headroom. A quota of
4 GiB would allow an 8 GiB file and does not fit. The default (8 GiB) needs a volume of about
16 GiB or more.

### Backup in a container

Either stop the container, copy the volume's contents, and start it again:

```sh
docker stop sbtp-relay
docker cp sbtp-relay:/data ./sbtp-data-backup   # works on a stopped container, needs no shell
docker start sbtp-relay
```

or take a snapshot of the volume (file system, LVM or cloud disk). Restoring either kind is a
rollback the relay cannot detect by itself: **before starting the relay on restored data, create
`restored` in the volume** (see "Backup and restore" above), for example with
`touch <volume path>/restored` on the host.

To restore a copy into a container (the image has no shell), put the files in the volume owned by
the relay user, then add the marker. `docker cp` writes root-owned files, which the relay (uid
65532) cannot open: it then refuses to start, which is fail-safe, not a bug. For example, with
any small image that has a shell and `cp`, on a stopped relay:

```sh
docker run --rm --user 0 -v sbtp-data:/data -v "$PWD/sbtp-data-backup:/b:ro" <image with sh> \
  sh -c 'cp -a /b/. /data/ && chown -R 65532:65532 /data && touch /data/restored'
```

or, on the volume's host path, `chown -R 65532:65532 <path>` and `touch <path>/restored`.
