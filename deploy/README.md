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
