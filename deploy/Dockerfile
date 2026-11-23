# sbtp-relay: static musl binary in a distroless image. See deploy/README.md, "Container".
#
# Build from the repository root (the build context is the workspace):
#   docker build -f deploy/Dockerfile -t sbtp-relay .
# Static binary only, no image:
#   docker build -f deploy/Dockerfile --target export --output type=local,dest=dist .
#
# Supply chain: both base images are pinned by the digest of their multi-platform index (the v0.2
# pins, checked 2026-11-20); the build downloads nothing except crates from crates.io, through
# `Cargo.lock` (`--locked`). No `apk add`, no `curl`, no `# syntax=` line (it would pull a frontend
# image).

# Rust 1.99.1 (the channel of rust-toolchain.toml) on Alpine 3.24: musl, with gcc and musl-dev for
# the C code of `blake3`. The host target follows `--platform` (`x86_64-unknown-linux-musl` or
# `aarch64-unknown-linux-musl`); musl targets link statically by default.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build
WORKDIR /src
# The workspace manifests and sources only. `rust-toolchain.toml` is left out on purpose: it adds
# the wasm32 target and components, which rustup would download; the image's toolchain is the
# same version.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY examples examples
# The shipped profile: `--release`, the relay binary alone, never `--all-targets`.
RUN cargo build --release --locked -p sbtp-relay --bin sbtp-relay \
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
# The data directory is the volume, the only path the relay writes (logs go to standard error), so
# the root filesystem can be read-only. The listener is every interface of the container's own
# network namespace, so that a proxy in another container reaches it. Behind that proxy, set
# SBTP_CLIENT_IP_HEADER; the relay then logs a startup warning (header on a non-loopback
# listener), which is expected as long as only the proxy reaches this port. Never publish it on a
# public interface.
ENV SBTP_LISTEN=0.0.0.0:8080 \
    SBTP_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
# The relay stops on SIGTERM, Docker's default stop signal.
STOPSIGNAL SIGTERM
# No HEALTHCHECK: the image has no shell and no HTTP client, and the relay has no health
# subcommand. Liveness is the process itself (it exits on a fatal error) or a probe of
# `/sbtp/v1/info` from outside the container.
ENTRYPOINT ["/usr/local/bin/sbtp-relay"]
