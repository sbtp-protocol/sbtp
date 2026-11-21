# 0028: Built-in TLS for `sbtp-relay` and `cli-demo`

- Status: accepted (by the project owner, 2026-11-19), with the nine recommendations of "Decisions for
  the project owner": feature `tls` in the default build (one published artefact; a
  `--no-default-features` build keeps compiling and is not published); ACME deferred to Q-34; `ring`;
  server TLS 1.3 only; the 15 MB `small` target applies with TLS off; `tls` bucket values provisional;
  `rustls-native-certs` in the CLI; in-house DER `notAfter` reader reviewed by the security reviewer; both
  deployments documented
- Amended by: 0048 (rule 1: the one published image also compiles in `replication`; server TLS stays
  off at run time unless its certificate settings are given, owner decision on Q-70 of 2026-11-21;
  rule 36: the 15 MB target of `small` applies with the default settings, TLS and replication off)
- Date: 2026-11-19
- Questions: Q-30 (single-binary deployment with built-in TLS). Opens Q-34 (built-in ACME client) and
  Q-35 (TLS for a desktop super-peer without a public name)
- Amends:
  - ADR 0012 rule 2 (`sbtp-relay` MAY terminate TLS itself);
  - ADR 0018 rule 21 (a fourth token bucket, `tls`, per client key), rule 22 (settings and one
    constraint added), rule 28 (steps 1a to 1c added before step 2), rule 35 (one term added to the
    memory bound);
  - ADR 0019 rule 9 (the plain-HTTP warning applies when TLS is off), rule 12 (with TLS on, the fresh
    phase starts at the end of the handshake), rule 37 (two rows added to the profile table), rule 39
    (the 15 MB target of `small` applies with TLS off), rule 42 (a public `sbtp-relay` terminates TLS
    itself or sits behind the reverse proxy);
  - ADR 0021 rule 7 (events added), rule 41 (counters added), rule 42 (fields of the `stats` line).
  - Clarifies, without changing their text: ADR 0018 rule 7 (settings hold paths, never key material),
    ADR 0019 rules 13 to 16 (timers measured on decrypted bytes), ADR 0019 rule 18 (no HTTP/2 server).
- Depends on: ADR 0012 (rule 2), ADR 0018 (settings, admission order, memory bound, supervision),
  ADR 0019 (timers, per-client bound, profiles, proxy function), ADR 0020 (throttled warnings), ADR 0021
  (event vocabulary, privacy, counters), ADR 0027 (limiter table)
- Impact: spec §4 (one paragraph) and `architecture.md` §2 and §3 (see "Spec changes on acceptance",
  applied 2026-11-19); `sbtp-relay` (new module `tls`, `config.rs`, `server.rs`, `lib.rs`, `log.rs`,
  `metrics.rs`, `limiter.rs`); `examples/cli-demo` (`relay.rs`, `args.rs`); workspace `Cargo.toml`,
  `Cargo.lock` and `deny.toml` (new crates, after review); `deploy/` (TLS examples); no `sbtp-core`
  change; no wire format change; no test vector

## Context

`sbtp-relay` does not terminate TLS (ADR 0012 rule 2). A public relay needs a reverse proxy that
terminates TLS and buffers request heads (ADR 0019 rule 42). The spec requires a public relay to be
reachable over HTTPS (spec §4); this is satisfied today only through the proxy.

The project owner pulled Q-30 forward on 2026-11-19 (the roadmap (not published), Phase 2 and Phase 3): a relay
runs as one binary with TLS and no reverse proxy, while plain HTTP behind a proxy stays supported; and
`cli-demo` reaches `https://` relays with rustls and the operating system trust store, plain `http://`
kept. ACME is explicitly "later" in the roadmap.

The preconditions listed by Q-30 are partly met:

- the per-client connection bound exists (ADR 0019 point 10, implemented in `server.rs`);
- request heads are read under `header_timeout_ms` by the relay itself (ADR 0019 rules 12 and 13), so
  the head-buffering function of the proxy is already inside the relay;
- the rate-limiter table has a bounded cost (ADR 0027).

What is missing, and what this ADR decides: the TLS configuration, the certificate source, the crypto
provider, the protocol versions and ALPN, certificate reload, how a handshake counts against the limits
of ADRs 0018 and 0019, the log events and counters, the private key file rules, and the client side.

### Facts checked on 2026-11-19

Crate facts come from crates.io (`cargo info` and the crates.io API). Advisories come from the local
copy of the RustSec database that `cargo deny` uses. Library behaviour comes from docs.rs through
Context7. None of these crates is in `Cargo.lock` today.

| Crate | Latest stable | Released | MSRV | Licence | Note |
|---|---|---|---|---|---|
| `rustls` | 0.23.46 | 2026-10-14 | 1.71 | Apache-2.0 OR ISC OR MIT | RUSTSEC-2026-0285, -0346, -0347, -0348, -0349 are patched in 0.23.46 only: the minimum version is 0.23.46. 0.24 is a pre-release. |
| `tokio-rustls` | 0.26.6 | 2026-09-28 | 1.71 | MIT OR Apache-2.0 | |
| `ring` | 0.17.14 | 2025-03-11 | 1.66 | Apache-2.0 AND ISC | RUSTSEC-2025-0007 ("unmaintained") was withdrawn on 2025-02-22; RUSTSEC-2025-0010 marks only versions below 0.17 unmaintained. No release for 20 months. |
| `aws-lc-rs` / `aws-lc-sys` | 1.19.0 / 0.47.0 | 2026-10-28 | 1.71 | `aws-lc-sys`: ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | `aws-lc-sys` has five advisories in 2026 (RUSTSEC-2026-0044 to -0048). `MIT-0` is not in the `deny.toml` allow list. |
| `rustls-pki-types` | 1.16.0 (1.15.1) | 2026-11-10 (2026-07-23) | 1.60 | MIT OR Apache-2.0 | 1.16.0 is younger than two weeks; 1.15.1 is not. |
| `rustls-webpki` | 0.103.17 (0.103.16) | 2026-11-12 (2026-10-20) | 1.71 | ISC | RUSTSEC-2026-0382 is patched from 0.103.16. 0.103.17 is younger than two weeks. |
| `rustls-native-certs` | 0.8.5 | 2026-10-13 | 1.71 | Apache-2.0 OR ISC OR MIT | |
| `rustls-platform-verifier` | 0.7.1 | 2026-09-24 | 1.85 | MIT OR Apache-2.0 | |
| `webpki-roots` | 1.0.12 (1.0.11) | 2026-11-10 (2026-10-23) | 1.71 | CDLA-Permissive-2.0 | RUSTSEC-2026-0381 is patched from 1.0.10. The licence is not in the allow list. |
| `rustls-pemfile` | | | | | RUSTSEC-2025-0134: unmaintained. PEM parsing is in `rustls-pki-types`. |
| `instant-acme` | 0.8.5 | 2026-02-24 | 1.70 | Apache-2.0 | ACME candidate, for Q-34 only. |
| `rcgen` | 0.14.10 | 2026-08-28 | 1.88 | MIT OR Apache-2.0 | Certificate generation for tests, or for Q-34. |

| Fact | Source |
|---|---|
| `rustls` 0.23.46 default features: `aws_lc_rs`, `logging`, `prefer-post-quantum`, `std`, `tls12`. `aws_lc_rs` also enables `aws-lc-rs/prebuilt-nasm`. `prefer-post-quantum` requires `aws_lc_rs`. `ring` is a separate feature. `brotli` and `zlib` (certificate compression) are optional. | `cargo info rustls@0.23` |
| `ServerConfig` defaults: `max_fragment_size` none (16 kB); `session_storage` stores 256 sessions in memory with `std`; `alpn_protocols` empty (no ALPN); `key_log` logs nothing; `send_tls13_tickets` 2. | docs.rs `rustls`, `ServerConfig`, via Context7 |
| `ServerConfig::builder_with_protocol_versions` panics when the versions and the provider leave no usable cipher suite, or when no provider can be resolved. | docs.rs `rustls`, via Context7 |
| `ResolvesServerCert::resolve(&self, ClientHello) -> Option<Arc<CertifiedKey>>` chooses the certificate per handshake; `None` aborts the handshake. | docs.rs `rustls`, via Context7 |
| The server selects the first protocol of `alpn_protocols` that the client offers; `ClientHello::alpn()` is `None` when the client sends no ALPN extension. | docs.rs `rustls`, via Context7 |
| `ureq` 3.5.1 features: `rustls` = `rustls-no-provider` + ring + `rustls-webpki-roots`; `rustls-no-provider` alone; `platform-verifier`. `cli-demo` sets `max_redirects(0)` and `proxy(None)`. | `cargo info ureq@3.5.1`; `examples/cli-demo/src/relay.rs` |
| `blake3` already compiles C and assembly through `cc` in its build script; `cc` is in `Cargo.lock`. | `Cargo.lock` |
| The relay counts the bytes it reads on a connection to locate pipelined requests (ADR 0019 rule 16). | `crates/sbtp-relay/src/server.rs`, module documentation |
| The relay handles `SIGINT` and `SIGTERM`. `SIGHUP` is not handled: its default action ends the process. | `crates/sbtp-relay/src/lib.rs` |

Not checked: whether rustls aborts a handshake when the client offers ALPN protocols and none matches
(RFC 7301 `no_application_protocol`); the default and the effect of `set_buffer_limit` on a server
connection (64 KiB, from memory) and how `tokio-rustls` behaves at that limit; the largest
`ClientHello` that rustls buffers; whether `CertifiedKey::keys_match` exists in 0.23.46; whether
`rustls-native-certs` 0.8.5 reads `SSL_CERT_FILE` and `SSL_CERT_DIR` (from memory: it does); the
binary size, the memory per connection and the handshake cost with ring. None of the memory figures
below was measured.

## Decision

### Point 1: build and mode

| Option | For | Against |
|---|---|---|
| A. A cargo feature `tls`, off by default; a separate release binary with TLS | The default binary keeps today's dependency graph. | Two binaries to build, test and document. Against "one binary". |
| B. A cargo feature `tls`, on by default; TLS off at run time unless configured | One shipped binary serves both deployments. `--no-default-features` still builds a plain-HTTP binary. | The TLS crates are in every shipped binary and in its size; the code is unreachable from the network while TLS is off. |
| C. No feature; TLS always compiled in | Simplest build. | No way to build a relay without the TLS crates. |

**Recommendation: B.**

1. **Feature.** `sbtp-relay` has a cargo feature `tls`, in its default features. A build without it
   has no TLS crate in its graph. The published `sbtp-relay` artefacts (binary, container image,
   package) are built with the default features: there is one published artefact. A build with
   `--no-default-features` MUST keep compiling and passing its tests (CI checks it); it is not a
   published artefact.
2. **Setting.** `tls_mode` is a string: `off` (default) or `files`. The value `acme` is reserved for
   Q-34 and is refused at start-up until an ADR defines it. Any other value stops the start-up (ADR 0018
   rule 7). The setting is a known key in every build: a build without the feature that reads
   `tls_mode = "files"` stops before it listens, with a message that names the setting and says that
   the build has no TLS support.
3. **One listener.** With `tls_mode = "files"`, every connection accepted on `listen` is a TLS
   connection. The relay serves no plain HTTP on that address and sends no redirect. Plain bytes on that
   address fail the handshake (rule 32). There is no second listener in this ADR.
4. **Off is today.** With `tls_mode = "off"` the relay behaves exactly as before this ADR: the TLS code
   is not reached, and rules 31 to 41 do not apply.
5. **Defaults unchanged.** `listen` keeps its default (`127.0.0.1:8080`, ADR 0019 rule 8). TLS does not
   change the port. The `metrics_listen` endpoint stays plain HTTP on loopback (ADR 0021 rule 44).

### Point 2: certificate source

| Option | For | Against |
|---|---|---|
| A. Files only (certificate chain and key given by the operator); ACME in a later ADR | Small code and graph. Works with every ACME client that writes files (certbot, lego, acme.sh) and with any internal CA. | The operator runs an ACME client and a renewal hook. |
| B. Files and a built-in ACME client now (TLS-ALPN-01) | One binary does everything. | An outbound HTTP client in an exposed relay, an account key to store, a renewal state machine, CA rate limits, a CSR generator: several more crates and a second secret. Not ready for review in this milestone. |
| C. ACME only | No file handling. | No internal CA, no test certificate, no fallback. |

**Recommendation: A.** ACME is deferred to Q-34 (the roadmap already says "ACME later").

6. **Two paths.** With `tls_mode = "files"`, `tls_cert_file` and `tls_key_file` MUST both be set;
   otherwise the start-up stops. They are paths, never PEM text and never key material, so ADR 0018
   rule 7 ("none of these settings is a secret") stays true. A relative path is resolved against the
   working directory, as for `data_dir` (ADR 0019 rule 8). The relay logs both absolute paths.
7. **Formats.** `tls_cert_file` holds one or more PEM `CERTIFICATE` blocks: the leaf first, then the
   intermediates. `tls_key_file` holds exactly one PEM private key: PKCS#8 (`PRIVATE KEY`), SEC1
   (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`). An encrypted key (`ENCRYPTED PRIVATE KEY`) is
   refused: the relay has no passphrase setting. Any other PEM block, or text outside PEM blocks, is
   ignored in the certificate file and refused in the key file.
8. **Size bounds.** Each file MUST be at most 65,536 bytes (a constant, not a setting). A larger file is
   refused without reading past the bound.
9. **Checks at load.** A pair is usable only when: the chain holds at least one certificate; the key
   parses; the key type is one the provider signs with (ECDSA P-256 or P-384, Ed25519, RSA of at least
   2,048 bits); and the public key of the key matches that of the leaf. The relay does not check the
   names of the leaf: it does not know the name its clients use. Browsers do not accept Ed25519 server
   certificates; the deployment documentation recommends ECDSA P-256.
10. **Start-up.** An unusable pair at start-up stops the relay before it listens, with a message that
    names the setting and the reason (rule 40), never the content of the file.
11. **Expiry.** The relay reads the `notAfter` time of the leaf with a minimal DER reader of its own
    (no new crate; bounded by rule 8; every access through `get()`, no panic). The reader reads
    operator files only, never network input. It MUST be reviewed by the security reviewer before the
    TLS milestone is merged. A leaf already expired
    at load is used, and the relay logs `config_warning` with `code=tls_cert_expired` at start-up or
    `tls_cert_expiring` at reload (rule 39): a stopped relay would not pick up the renewed file. The
    relay checks the time left once at load and once every 24 hours.

### Point 3: the private key

12. **Permissions.** On Unix, at every load, the relay reads the metadata of the key file after
    following links (certbot's `live/` directory holds links). It MUST refuse the file when it is not a
    regular file, or when any permission bit for others is set (`mode & 0o007 != 0`). It logs a
    `config_warning` with `code=tls_key_group_writable` when the group-write bit is set. A
    group-readable key (`0640`, the Debian `ssl-cert` convention) is accepted. On other targets the
    relay logs `config_warning` with `code=tls_key_permissions_unchecked` and loads the file.
13. **Storage.** The relay reads the key file and keeps the key in memory only. It never copies, moves,
    writes or creates a key file, and never stores anything under `data_dir` for TLS in this ADR. The
    deployment documentation states: key file owned by the relay user or `root`, mode `0600` or `0640`,
    in a directory not writable by others.
14. **Buffers.** The relay SHOULD wipe the buffer it read the key file into, and the decoded key bytes it
    owns, once the provider holds the key (`zeroize`, already in the graph). The provider's own copy is
    outside this rule.
15. **Never logged, never exposed.** No log line, error message, counter, `/info` member or response
    carries any byte of the key file, of the key, of a session secret or of the certificate chain.
    Messages name the file and a fixed reason (rule 40). This applies ADR 0021 rule 10 ("key
    material").
16. **No key log.** The relay MUST NOT enable a TLS key log (`SSLKEYLOGFILE` or rustls's `KeyLog`). No
    setting enables one, in any build.

### Point 4: provider, versions, ALPN

| Subject | Options | Recommendation |
|---|---|---|
| Crypto provider | A. `ring`. B. `aws-lc-rs`. | **A.** See below. |
| TLS versions (server) | A. 1.3 only. B. 1.2 and 1.3. | **A.** The relay's clients are browsers that run the WASM client and rustls clients; all support 1.3. Less negotiation code reachable. |
| ALPN | A. `http/1.1` only. B. `h2` and `http/1.1`. | **A.** ADR 0018 rule 27 and ADR 0019 rule 18 keep HTTP/2 out until an ADR bounds streams per connection. |
| Resumption | A. None. B. rustls's default (256 stateful sessions, 2 tickets). C. Stateless tickets. | **A.** No per-session state to bound, no ticket key (a second secret). Each connection does a full handshake; with keep-alive this is about one handshake per connection lifetime. |

Provider, in detail:

| | `ring` 0.17.14 | `aws-lc-rs` 1.19.0 |
|---|---|---|
| Build | Its build script compiles the C and assembly it ships through `cc`. No download. A C compiler for the target is already needed by `blake3`. | `aws-lc-sys` compiles a much larger C code base; through rustls's `aws_lc_rs` feature it enables `prebuilt-nasm`, which runs a prebuilt NASM binary on some Windows targets. Against the rule "no `build.rs` that downloads or executes anything" as the project reads it. |
| `cargo deny` | Licence `Apache-2.0 AND ISC`: both allowed. | `MIT-0` not allowed; an exception would be needed. Five advisories in 2026 in `aws-lc-sys`. |
| MSRV | 1.66. | 1.71. Both below 1.85. |
| Post-quantum key exchange | None in rustls with ring (`prefer-post-quantum` requires `aws_lc_rs`). | X25519MLKEM768 hybrid. |
| Maintenance | No release for 20 months; the "unmaintained" advisory was withdrawn. | Active. |

Blocks are public and signed (spec §1, Q-17). TLS protects the integrity of the channel and the
privacy of what a client reads or sends before publication. A recorded session decrypted years later
reveals public data and read patterns. The post-quantum gain is therefore lower than for a protocol
that carries secrets, and does not outweigh the build and licence cost. The choice is revisited by ADR
when ring's provider or another reviewed provider offers ML-KEM, or when `ring` stops being maintained.

17. **Provider.** The relay builds its `ServerConfig` with an explicit provider,
    `rustls::crypto::ring::default_provider()`, through the builder that returns a `Result`. It MUST NOT
    rely on a process-default provider and MUST NOT call a builder that panics; a configuration error
    stops the start-up (ADR 0018 rule 7). The rustls features `aws_lc_rs`, `prefer-post-quantum`, `fips`,
    `brotli`, `zlib` and `logging` stay off.
18. **Versions.** The server offers TLS 1.3 only, set at run time in its `ServerConfig`. A client that
    does not offer 1.3 fails the handshake. The rustls `tls12` feature may be compiled into the relay
    through the CLI (cargo feature unification in one workspace build); the run-time setting decides.
19. **Suites and groups.** The provider's default TLS 1.3 cipher suites and key exchange groups, in its
    order. No setting changes them.
20. **ALPN.** `alpn_protocols` is `["http/1.1"]`. A client that sends no ALPN extension is served as
    HTTP/1.1. A client whose ALPN list does not contain `http/1.1` MUST NOT complete a handshake; if
    rustls does not refuse it, the relay refuses it in its certificate resolver (rule 26).
21. **HTTP/2 stays out.** ADR 0018 rule 27 and ADR 0019 rule 18 are unchanged: the binary contains no
    HTTP/2 server, and `h2` MUST NOT appear in `Cargo.lock` through `sbtp-relay`. A browser over
    HTTP/1.1 opens about 6 connections per host, below `max_connections_per_client` (8). HTTP/2 needs
    its own ADR.
22. **No early data.** 0-RTT data is refused (`max_early_data_size` 0).
23. **No resumption.** `send_tls13_tickets` is 0 and the session store keeps nothing.
24. **No client authentication.** The relay requests no client certificate.
25. **SNI.** The relay serves its one certificate whatever the server name a client sends, and accepts a
    `ClientHello` without one (a client that connects by IP address). It does not compare the name with
    the certificate; the client does.

### Point 5: reload without restart

| Option | For | Against |
|---|---|---|
| A. Restart to load a new certificate | No code. | Drops every connection; a renewal hook needs restart rights. |
| B. `SIGHUP` only | Explicit trigger; the usual convention (`ExecReload=`). | Needs a hook in every ACME client; no signal on Windows (desktop daemon). |
| C. Periodic check of the two files | Works with any ACME client and without hooks, on every target. | Up to one period of delay; a pair written in two steps is seen half-written. |
| D. C, plus `SIGHUP` on Unix as an immediate check | Both habits work. | Two triggers for one action. |

**Recommendation: D.**

26. **Resolver.** The certificate is chosen per handshake by a resolver that holds the current pair
    behind a shared pointer. A reload replaces the pointer. A handshake in progress keeps the pair it
    started with; open connections are not affected.
27. **Check.** When `tls_reload_interval_ms` is above 0, the relay checks both files every
    `tls_reload_interval_ms`: it reads their metadata (length, modification time, and the target after
    links). When either changed since the last load, it loads the pair under rules 7 to 12. On Unix,
    `SIGHUP` triggers the same load at once, whether or not the metadata changed.
28. **Failure keeps the current pair.** A pair that fails any check is not used. The relay keeps the
    pair it has, logs `tls_cert_reload_failed` (rule 39), and tries again at the next check or signal.
    A pair written in two steps (certificate first, key second) therefore fails once on a key mismatch
    and loads at the next check.
29. **Where it runs.** Checks and loads run on one dedicated thread owned by the TLS component, created
    at start-up when TLS is on. It is not a thread of tokio's blocking pool, so ADR 0018 rule 19 is
    unchanged. It is supervised as in ADR 0018 rule 37: if it ends, the process exits with a non-zero
    status.
30. **`SIGHUP` in every mode.** The relay handles `SIGHUP` whether TLS is on or off. With TLS off it
    logs nothing and does nothing. A `SIGHUP` never stops the relay.

### Point 6: admission, timers and memory

31. **Order of admission.** ADR 0018 rule 28 is amended: after step 1 (connection accepted under
    `max_connections`), and when TLS is on:
    - (1a) the per-client connection bound of ADR 0019 rule 29, unchanged, before any byte is read;
    - (1b) for a direct peer whose key is not in `rate_limit_exempt`, one token of the `tls` bucket of
      its client key (rule 34). With no token the connection is closed at once: no byte is read, no
      alert is sent;
    - (1c) the handshake, under the deadline of rule 32;
    - then step 2 (headers read) and the rest of rule 28, unchanged.
    A peer in `trusted_proxies` takes no `tls` token: one proxy carries many clients.
32. **Handshake phase.** A new phase is added before the fresh phase of ADR 0019 rule 12. It starts at
    the accept and ends when the handshake is complete. Its limit is `header_timeout_ms`, a deadline on
    the whole handshake: a byte does not extend it. At the deadline, or on any handshake error, the
    connection is closed; the relay sends a TLS alert when rustls produces one, and no HTTP response.
    The fresh phase of ADR 0019 rule 12 then starts at the end of the handshake, with a full period. A
    connection that completes a handshake and sends nothing is therefore open for at most
    `2 × header_timeout_ms` (10 seconds with the defaults), at the cost of one handshake and one `tls`
    token.
33. **Timers on decrypted bytes.** The phases and deadlines of ADR 0019 rules 12 to 16, the head limit
    `max_header_bytes` and the byte count of rule 16 apply to the decrypted stream: the counting layer
    sits above TLS. Their values are unchanged. The request deadline of ADR 0018 rule 25 includes the
    time to write the encrypted response.
34. **`tls` bucket.** ADR 0018 rule 21 is amended: each client key has a fourth token bucket, `tls`,
    with `rate_tls_per_min` and `rate_tls_burst`. A connection takes one token at step 1b. The bucket
    bounds the handshakes, and so the server signatures, that one client key can cause per minute. The
    rules of ADR 0018 rule 21 and ADR 0027 apply: shared addresses share it, a key is "full" when its
    four buckets are full, the overflow key has the same allowance. With TLS off the bucket is not
    consulted and stays full.
35. **What a handshake costs, and its bounds.** The handshakes in progress are bounded by
    `max_connections`, and per client key by `max_connections_per_client`. Each costs one key exchange
    and one signature with the certificate's key; both run on the connection's worker thread. No
    handshake work happens before steps 1a and 1b. Distributed handshake floods are the "distributed
    senders" case of ADR 0018 and are not bounded per client.
36. **Memory.** ADR 0018 rule 35 is amended. When TLS is on, the bound adds:

    ```
    + max_connections × TLS_CONNECTION_BYTES
    + 2 × 65,536          (the two files during a load, rule 8)
    ```

    `TLS_CONNECTION_BYTES` is estimated at 65,536 bytes: one received record of up to 16 KiB plus its
    overhead, the outgoing buffer, and the handshake and key schedule state. The relay MUST set an
    explicit outgoing buffer limit on each TLS connection, at most 16,384 bytes unless the measurement
    shows a reason for more. With the profile `small` and the endpoint of ADR 0021 off, the bound of
    ADR 0021 rule 45, as recomputed by ADR 0027 clarification T1 (13,665,748 bytes), becomes
    13,665,748 + 2,097,152 + 131,072 = 15,893,972 bytes (15.2 MiB). This is above 15,000,000 bytes.
    With TLS off the bound is unchanged. The estimate is replaced by a measure on `bench-sbtp`.

    **Memory target.** The 15 MB worst-case target of ADR 0019 rule 39 applies to `small` with TLS
    off. With TLS on, `small` has no fixed target: the relay logs its computed bound at start-up, as
    for `standard` and `large` (ADR 0019 rule 39). The packaged unit keeps `MemoryMax=128M` for
    `small` (ADR 0019 rule 37), which is above the bound with TLS on.
37. **Shutdown.** A connection closed by the relay (deadline, keep-alive cap, stop) MAY end without a
    TLS `close_notify`. HTTP/1.1 framing makes truncation visible to the client. The drain of ADR 0019
    rule 21 is unchanged.
38. **Plain HTTP stays as it is.** With TLS off, steps 1b and 1c, the handshake phase and the `tls`
    bucket do not exist, and the relay behind a reverse proxy is exactly the relay of ADRs 0018 to 0027.

### Point 7: logs and counters

39. **Events.** Added to the vocabulary of ADR 0021 rule 7:

    | `event` | Level | Fields | When |
    |---|---|---|---|
    | `tls` | info | `mode`, `provider`, `versions`, `alpn` | Once at start-up, in the start-up phase (ADR 0021 rule 19), when TLS is on. Values are fixed strings (`files`, `ring`, `1.3`, `http/1.1`). |
    | `tls_files` | info | `cert`, `key` | Once at start-up: the two absolute paths (ADR 0021 rule 11 allows paths). |
    | `tls_cert_loaded` | info | `trigger`, `chain_len`, `key_type`, `not_after` | Each load that succeeds. `trigger`: `start`, `interval`, `signal`. `key_type`: `ecdsa_p256`, `ecdsa_p384`, `ed25519`, `rsa`. `not_after`: RFC 3339 UTC. |
    | `tls_cert_reload_failed` | warn | `reason`, `file`, `errno`, `suppressed` | A load at run time failed (rule 28). `reason` per rule 40. `file`: `cert` or `key`. `errno` only for an operating system error. Throttled (ADR 0021 rule 8, per `reason`). |
    | `tls_cert_expiring` | warn | `not_after`, `days_left` | The leaf expires in less than 14 days, or has expired (`days_left` 0). At load and once per 24 hours. |
    | `tls_handshake_failed` | debug | `reason` | A handshake did not complete. `reason`: `timeout`, `eof`, `protocol`, `version`, `alpn`, `cert_unavailable`. |

    New `config_warning` codes: `tls_cert_expired`, `tls_key_group_writable`,
    `tls_key_permissions_unchecked`. The `rate_limited` event of ADR 0021 gets the class value `tls` for
    step 1b. The `listening` event is unchanged; the `tls` line says the listener is TLS.
40. **Fixed reasons.** `reason` of a load failure is one of: `read`, `too_large`, `not_regular`,
    `permissions`, `no_certificate`, `no_key`, `several_keys`, `encrypted_key`, `bad_pem`,
    `unsupported_key`, `key_mismatch`, `bad_certificate`. The relay maps every rustls and parser error
    to one of these names or to the handshake reasons of rule 39. It MUST NOT log the text of a rustls
    error, an alert received from a peer, the server name a client sent, the ALPN list a client
    offered, or any byte of a handshake. With rule 15, these extend ADR 0021 rule 10.
41. **Counters.** Added to ADR 0021 rule 41:

    | Name | Kind | Labels |
    |---|---|---|
    | `tls_handshakes_total` | counter | `result`: `ok`, `refused` (step 1b), and the reasons of rule 39 |
    | `tls_cert_loads_total` | counter | `result`: `ok`, `failed` |
    | `tls_cert_not_after_seconds` | gauge | none; Unix time of the `notAfter` of the current leaf, 0 when TLS is off |

    The `stats` line of ADR 0021 rule 42 adds `tls_handshakes_ok` and `tls_handshakes_failed` when TLS
    is on. rustls's `log` output is off (rule 17), so no event of a dependency reaches the log.

### Point 8: deployment

42. **Two supported deployments.** ADR 0019 rule 42 is amended: a public `sbtp-relay` MUST either run
    with `tls_mode = "files"` and listen on a public address, or be placed behind a reverse proxy that
    provides the functions of ADR 0019 rule 42. Behind a reverse proxy, TLS stays off. The deployment
    documentation describes both. It recommends the reverse proxy when the host also serves the web
    client or needs HTTP/2 or HTTP/3, and built-in TLS when the host runs the relay alone. ADR 0012 rule 2
    is amended: "`sbtp-relay` serves HTTP/1.1 and MAY serve HTTP/2. It does not implement HTTP/3. It
    terminates TLS when configured to (ADR 0028); otherwise TLS, HTTP/2 and HTTP/3 are terminated by a
    reverse proxy."
43. **Warning.** ADR 0019 rule 9 is amended: the warning for a non-loopback `listen` is logged when TLS
    is off ("the relay serves plain HTTP on that address"). With TLS on there is no such warning.
44. **No TCP proxy in front of a TLS relay.** A relay with TLS on sees the address of whatever connects
    to it. A TCP-level load balancer in front of it makes every client one client key. The relay does
    not read the PROXY protocol. The deployment documentation states this.
45. **Port 443.** The packaged unit sets `AmbientCapabilities=CAP_NET_BIND_SERVICE` only in the TLS
    example; the container example maps a host port to an unprivileged container port. The relay never
    runs as `root` to bind a port.
46. **Exposure gate.** A relay with TLS on and a public `listen` MUST NOT be announced before: the
    `block` and `put` token buckets are enabled (roadmap, relay milestone 1c); ADR 0027 is implemented;
    the security reviewer has reviewed the TLS milestone (crates and code); and the binary size, the
    memory per TLS connection and the handshake cost are measured on `bench-sbtp`.

### Point 9: client side (`cli-demo`)

| Subject | Options | Recommendation |
|---|---|---|
| Trust roots | A. `rustls-native-certs` (OS roots, rustls's verifier). B. `rustls-platform-verifier` (the OS verifier: Security.framework, CryptoAPI; native roots on Linux). C. `webpki-roots` (bundled Mozilla roots). | **A.** One verifier on every target, a smaller graph than B, no licence to add (C needs `CDLA-Permissive-2.0` in `deny.toml`). B adds OS revocation and policy; it is the alternative if the owner prefers the OS's own decision. |
| Verification off | A. No flag. B. `--insecure`, with a warning. C. `--ca-file <path>`. | **C, and no flag that disables verification.** A self-signed test relay is reached by trusting its certificate explicitly. |
| Versions (client) | A. 1.3 only. B. 1.2 and 1.3. | **B.** The client reaches relays it does not control, behind any proxy. rustls offers only ECDHE and AEAD suites for 1.2. |

47. **Feature.** `cli-demo` has a cargo feature `tls`, in its default features. As for the relay
    (rule 1), a build with `--no-default-features` MUST keep compiling and is not a published artefact. It uses `ureq` with
    `rustls-no-provider`, `rustls` with the `ring` feature and an explicit provider (rule 17 applies),
    and `rustls-native-certs`. It does not use `webpki-roots`. A build without the feature keeps
    today's message for an `https://` URL.
48. **URLs.** `--relay` accepts `http://` and `https://`. The checks of `relay.rs` (no user name, query
    or fragment) apply to both. `http://` is kept for local relays and SSH tunnels. The CLI SHOULD
    print one warning on standard error when an `http://` URL names a host that is not a loopback
    address or `localhost`.
49. **Verification.** For `https://`, the CLI verifies the chain and the host name of the URL (an IP
    address is checked against the IP addresses of the certificate). No flag, environment variable or
    setting of the CLI turns verification off. `--insecure` MUST NOT exist.
50. **Roots.** By default the trust anchors are the operating system's, loaded by
    `rustls-native-certs`. If none can be loaded, an `https://` request fails with a message that
    suggests `--ca-file`. Where `rustls-native-certs` honours `SSL_CERT_FILE` or `SSL_CERT_DIR`, the
    CLI documents it as the operating system convention.
51. **`--ca-file <path>`.** A PEM file of one or more trust anchors, at most 65,536 bytes. When given,
    it replaces the operating system roots for that run. The file is never written by the CLI.
52. **Versions and ALPN.** The client offers TLS 1.3 and 1.2, ALPN `http/1.1` only, and no early
    data. It keeps `max_redirects(0)`, so an `https://` relay can never redirect it to `http://`.
53. **Errors.** A certificate or handshake failure is reported as such, with the host and a fixed
    reason; the CLI does not retry it.

### Point 10: dependencies and review

54. **Candidate crates**, none added by this ADR. Each needs the checks of `CLAUDE.md` (Context7,
    crates.io maintainers, date, downloads) and a security review before it enters
    `[workspace.dependencies]`:

    | Crate | Version to pin | Used by | Features |
    |---|---|---|---|
    | `rustls` | 0.23.46 (minimum, advisories) | relay, CLI | `default-features = false`, `ring`, `std` (`tls12` for the CLI, rule 52) |
    | `ring` | 0.17.14 | through `rustls` | default |
    | `rustls-pki-types` | 1.15.1, or 1.16.0 after 2026-11-24 | relay, CLI (PEM parsing) | `std` |
    | `rustls-webpki` | 0.103.16, or 0.103.17 after 2026-11-26 | through `rustls` | |
    | `tokio-rustls` | 0.26.6 | relay | `default-features = false`, `ring` |
    | `rustls-native-certs` | 0.8.5 | CLI | default |
    | `rcgen` | 0.14.10 | relay tests only (dev-dependency) | `default-features = false`, `ring`, `pem` |

    `rustls-pemfile` MUST NOT be used (RUSTSEC-2025-0134). The `deny.toml` licence list needs no change
    for this set; the security reviewer confirms it with `cargo deny check` on the branch. The transitive
    crates of `rustls-native-certs` (`openssl-probe` on Linux, `security-framework` and
    `core-foundation` on macOS, `schannel` on Windows) are part of the review. `openssl-probe` is not
    the banned `openssl` crate.
55. **Tests.** Relay tests generate their certificate and key at test time with `rcgen`; nothing is
    committed. Required tests: the load checks of rules 7 to 12, one per reason of rule 40; reload
    success, failure that keeps the old pair, and a pair written in two steps; `SIGHUP` with TLS off;
    the handshake deadline; a `tls` bucket refusal; ALPN `h2` only refused; TLS 1.2 refused; plain
    HTTP on the TLS port; the pipelined-request test of ADR 0019 rule 16 over TLS; the CLI against the
    relay with `--ca-file`, and with no root that matches.
56. **Measures** on `bench-sbtp`, before rule 46 is met: binary size with and without the feature
    (against the ADR 0013 size gate), resident memory with 32 TLS connections held open, and
    handshakes per second on one core.

### Settings

57. Added to the table of ADR 0018 rule 22. Precedence and validation follow ADR 0018 rules 6 and 7 and
    ADR 0019 rule 36.

    | Setting | Type | Default | Range | Set by a profile |
    |---|---|---|---|---|
    | `tls_mode` | string | `off` | `off`, `files` (`acme` reserved) | no |
    | `tls_cert_file` | string, a path | empty | not empty when `tls_mode = "files"` | no |
    | `tls_key_file` | string, a path | empty | not empty when `tls_mode = "files"` | no |
    | `tls_reload_interval_ms` | integer, ms | 300,000 | 0 (off), or 10,000 to 86,400,000 | no |
    | `rate_tls_per_min`, `rate_tls_burst` | integers | 120 and 32 | 1 to 1,000,000 each | yes |

    Constraint added: `tls_cert_file` and `tls_key_file` are set when, and only when, `tls_mode` is
    `files`; a path set with `tls_mode = "off"` stops the start-up, so that a forgotten mode does not
    silently serve plain HTTP.

    Two rows added to the table of ADR 0019 rule 37 (provisional, revisited after the measure of rule
    56):

    | Setting | `small` (default) | `standard` | `large` |
    |---|---|---|---|
    | `rate_tls_per_min` / `rate_tls_burst` | 120 / 32 | 480 / 64 | 1,920 / 256 |

    Reading of the `small` values: a browser that keeps 6 connections until `max_connection_age_ms`
    (5 minutes) makes 1.2 handshakes per minute; one that reopens its 6 connections after every
    30-second idle close makes 12. 120 per minute serves 10 to 100 such browsers behind one address.

## Consequences

- **One binary.** `sbtp-relay` with `tls_mode = "files"`, two paths and `listen = "0.0.0.0:443"` (or a
  mapped port) serves HTTPS without a proxy. The reverse proxy remains supported and unchanged.
- **Certificates.** The operator runs an ACME client that writes files (certbot, lego, acme.sh) or uses
  any CA. Renewal needs no restart and no hook (rule 27). A built-in ACME client is Q-34.
- **Security.**
  - New network-facing code: the rustls handshake parser and the provider's C and assembly. It is
    reached only when TLS is on.
  - One new secret, the private key, held in memory only, in a file the relay only reads, checked for
    permissions, never logged.
  - A handshake flood from one client key is bounded by the `tls` bucket; from many keys it is not
    (ADR 0018, "distributed senders"), as for requests.
  - TLS 1.3 only, no 0-RTT, no resumption, no client certificates, no HTTP/2: the surface stays small.
  - No post-quantum key exchange with ring. Accepted for public data (Point 4), revisited by ADR.
  - `SIGHUP` no longer ends the relay (rule 30), with TLS on or off.
- **Memory.** With TLS on, the `small` bound rises by about 2.2 MB, to about 15.9 MB, on estimates
  (rule 36, with the limiter entry estimate of ADR 0027 clarification T1). The 15 MB target applies
  with TLS off (rule 36). With TLS off the bound is unchanged.
- **Clients.** No protocol change. A client sees a relay at an `https://` URL either way. The CLI gains
  `https://`, `--ca-file`, and a warning for remote `http://`.
- **Compatibility.** No wire change, no `sbtp-core` change, no test vector. A configuration file
  written before this ADR is valid and means the same.
- **Dependencies.** About six crates for the relay and four or five for the CLI, all to review (rule
  54). No change to `deny.toml` is expected.
- **Implementation** (for the implementer and the implementer; the code is not modified by this ADR):

  | Rule | File | Change |
  |---|---|---|
  | 1, 2, 57 | `crates/sbtp-relay/Cargo.toml`, `config.rs` | feature `tls`; settings, constraint, profile rows; a CI step that builds and tests `--no-default-features` |
  | 6 to 16, 26 to 30 | new `tls.rs` | loader, permission check, DER `notAfter` reader, resolver, reload thread |
  | 30 | `lib.rs` | `SIGHUP` handler in every mode |
  | 31 to 34 | `server.rs`, `limiter.rs` | steps 1b and 1c, handshake phase, counting layer above TLS, `tls` bucket |
  | 36 | `config.rs` (`memory_bound_bytes`) | TLS term; the computed bound logged with TLS on |
  | 39 to 41 | `log.rs`, `metrics.rs` | events, codes, counters, `stats` fields |
  | 42 to 45 | `deploy/` | TLS examples (unit, container), key file permissions, port binding |
  | 47 to 53 | `examples/cli-demo/src/relay.rs`, `args.rs` | `https://`, `--ca-file`, warning |

## Spec changes on acceptance

Applied on acceptance (2026-11-19).

- `docs/spec/sbtp-core-v0.2.md` §4, third paragraph, replaced by:

  > The protocol does not depend on a proxy. The reference relay `sbtp-relay` serves HTTP/1.1. It
  > terminates TLS when its operator configures a certificate (ADR 0028); otherwise a public
  > `sbtp-relay` is placed behind a reverse proxy that terminates TLS and buffers request heads (for
  > example Caddy, nginx or HAProxy). This is a deployment requirement of that program only.
  > (ADR 0012, ADR 0019, ADR 0028)

- `docs/spec/architecture.md` §2, "Admission control", the bullet on `listen`, replaced by:

  > The relay listens on one address (`listen`, default `127.0.0.1:8080`) and keeps its blocks and index
  > under `data_dir`. It serves HTTP/1.1 only, over TLS when `tls_mode` is `files` (TLS 1.3, ALPN
  > `http/1.1`). With TLS on, a handshake takes a per-client token and completes within
  > `header_timeout_ms`. (ADR 0019, ADR 0028)

- `docs/spec/architecture.md` §3, tier 2 row, "Role" column, replaced by:

  > Backbone. Either with built-in TLS (one binary, ADR 0028), or behind a reverse proxy that terminates
  > TLS and buffers request heads (Caddy, nginx, HAProxy).

## Rejected alternatives

- **A built-in ACME client now.** Deferred, not rejected: Q-34. Reasons in Point 2.
- **`aws-lc-rs` as provider.** Build script and licence cost; its post-quantum gain is low for public
  data (Point 4).
- **TLS 1.2 on the server.** No known client of a relay needs it.
- **HTTP/2 over TLS now.** Needs bounds on streams and requests in flight per connection (ADR 0018 rule
  27); browsers work over HTTP/1.1 within the per-client bound.
- **A plain-HTTP listener next to the TLS one** (for redirects or local tools). Two connection
  policies for one relay. A local tool uses the TLS port, or a second relay process. Revisited with
  Q-35.
- **A self-signed certificate generated by the relay.** Browsers refuse it, and a client that trusts it
  blindly learns nothing. Q-35.
- **`--insecure` in the CLI.** A flag that turns verification off ends up in scripts. `--ca-file` covers
  the test case and keeps verification.
- **Session resumption with stateless tickets.** A second secret (the ticket key) and its rotation, for
  a handshake saving that keep-alive already gives.
- **Reading the PROXY protocol.** Not needed by either supported deployment; a new parser facing the
  network.
- **A new setting for the handshake deadline.** `header_timeout_ms` already bounds the step before a
  request head; one more timer setting has no known use.

## Decisions for the project owner

**Decided 2026-11-19:** every recommendation below is accepted. (1) B: the feature is in the default
build; there is one published artefact per program, and a `--no-default-features` build keeps
compiling but is not published (rules 1 and 47). (2) ACME deferred to Q-34. (3) `ring`. (4) Server
TLS 1.3 only. (5) The 15 MB target applies with TLS off; with TLS on the relay logs its computed bound
(rule 36). (6) The `tls` bucket values are accepted as provisional and revisited after the measure
of rule 56. (7) `rustls-native-certs`. (8) The in-house DER reader, reviewed by the security reviewer
(rule 11). (9) Both deployments documented, with the recommendation of rule 42. The figures of point 5
below were computed with a limiter entry of 100 bytes; with 192 bytes (ADR 0027 clarification T1) the
`small` bound with TLS on is 15,893,972 bytes, and the alternative of point 5 would have needed
`TLS_CONNECTION_BYTES` of at most 37,599 bytes. The decision is unchanged.

1. **Feature default (Point 1).** The `tls` feature is in the default build of `sbtp-relay` and
   `cli-demo` (B), or off by default with a separate TLS binary (A). Recommendation: B.
2. **ACME deferred (Point 2).** Files only now; ACME in a later ADR (Q-34). Recommendation: defer.
3. **Provider (Point 4).** `ring`, without post-quantum key exchange; or `aws-lc-rs`, with a `deny.toml`
   exception for `MIT-0` and its build script. Recommendation: `ring`.
4. **Server TLS versions (Point 4).** 1.3 only, or 1.2 and 1.3. Recommendation: 1.3 only.
5. **Memory target with TLS on (rule 36).** The estimated `small` bound with TLS on is 15,513,044 bytes,
   above 15,000,000 and below 15 MiB. Either the 15 MB target applies with TLS off only, or it applies
   with TLS on and `TLS_CONNECTION_BYTES` must measure at most 49,503 bytes
   ((15,000,000 − 13,284,820 − 131,072) / 32). Recommendation: the
   target applies with TLS off; with TLS on the relay logs the computed bound, as for `standard` and
   `large` (ADR 0019 rule 39).
6. **Handshake bucket values (rule 57).** 120 per minute and a burst of 32 for `small`, provisional.
   Recommendation: accept, revisit after the measure of rule 56.
7. **Client trust roots (Point 9).** `rustls-native-certs` (A) or `rustls-platform-verifier` (B).
   Recommendation: A.
8. **Certificate expiry reading (rule 11).** A minimal in-house DER reader for `notAfter`, reviewed by
   the security reviewer, or no expiry information (the operator monitors it outside the relay).
   Recommendation: the in-house reader; it reads operator files only, never network input.
9. **Recommended server deployment (rule 42).** Both deployments documented; the reverse proxy stays
   the recommendation when the host also serves the web client or needs HTTP/2 or HTTP/3, and built-in
   TLS is the recommendation for a host that runs the relay alone. Recommendation: accept.
