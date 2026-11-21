# sbtp-relay: static musl binary in a distroless image. See deploy/README.md.
#
# Build from the repository root (the build context is the workspace):
#   docker build -f deploy/Dockerfile -t sbtp-relay .
# Static binary only, no image:
#   docker build -f deploy/Dockerfile --target export --output type=local,dest=dist .
#
# Supply chain: both base images are pinned by the digest of their multi-platform index (checked
# 2026-11-20); the build downloads nothing except crates from crates.io, through `Cargo.lock`
# (`--locked`). No `apk add`, no `curl`, no `# syntax=` line (it would pull a frontend image).

# Rust 1.99.1 on Alpine 3.24 (musl, with gcc and musl-dev for the C code of `blake3`). The host
# target of this image is `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`, following
# `--platform`; musl targets link statically by default. 1.99 rather than 1.100: the 1.100 image
# was younger than two weeks when this file was written. The relay needs Rust 1.90 or later.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build
WORKDIR /src
# The workspace manifests and sources only. `rust-toolchain.toml` is left out on purpose: it names
# the `stable` channel and the wasm32 target, which rustup would download.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY examples examples
# The shipped profile (ADR 0013, "Build"): `--release`, the relay binary alone. Never
# `--all-targets`, a test profile or the `vector-gen` feature. One image with every function
# compiled in (ADR 0048 rule 3, ADR 0050 rule 26): `object-store` on top of the defaults; each
# function stays off until its settings are given.
RUN cargo build --release --locked -p sbtp-relay --bin sbtp-relay --features object-store \
 && mkdir -p /out/data \
 && cp target/release/sbtp-relay /out/sbtp-relay \
 && chmod 0700 /out/data

# `--target export`: the static binary alone, for `--output type=local`.
FROM scratch AS export
COPY --from=build /out/sbtp-relay /sbtp-relay

# Runtime: no shell, no package manager, no libc (a dynamically linked binary would not start).
# The `nonroot` variant runs as uid/gid 65532.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
COPY --from=build /out/sbtp-relay /usr/local/bin/sbtp-relay
# The data volume mount point, owned by the relay user, mode 0700. A named volume mounted here
# starts with this owner and mode.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
# `data_dir` on the volume, the only path the relay writes (its temporary files are in
# `data_dir/tmp`; logs go to standard error). `listen` is all interfaces of the container's own
# network namespace, so that a proxy in another container or pod reaches it; override it with
# `-e SBTP_RELAY_LISTEN=...`. The relay logs a `listen_not_loopback` warning for it: never publish
# this port on a public interface (deploy/README.md).
ENV SBTP_RELAY_DATA_DIR=/data \
    SBTP_RELAY_LISTEN=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
# The relay drains and closes its index on SIGTERM (Docker's default stop signal); a second
# signal skips the drain.
STOPSIGNAL SIGTERM
# No HEALTHCHECK: the image has no shell and no HTTP client, and the relay has no health
# subcommand. Liveness is `docker ps` (the process exits on a fatal error) or a probe from the
# host to `/sbtp/v1/info`.
ENTRYPOINT ["/usr/local/bin/sbtp-relay"]
