# syntax=docker/dockerfile:1.7

# The toolchain is pinned in rust-toolchain.toml. Keep the builder pinned too
# so an image cannot silently move to a different compiler release.
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder

WORKDIR /src

# ring/wasmtime and the vendored Rust dependencies need a native C toolchain
# during compilation. No runtime build tools are copied into the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes build-essential clang \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY config ./config
COPY presets ./presets
COPY deploy ./deploy
COPY schema ./schema
COPY fixtures ./fixtures
COPY scripts ./scripts
COPY docs ./docs
COPY README.md LICENSE NOTICE ./

RUN cargo build --locked --release --package pooler-cli

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

ARG POOLER_UID=10001
ARG POOLER_GID=10001

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${POOLER_GID}" pooler \
    && useradd --system --uid "${POOLER_UID}" --gid "${POOLER_GID}" \
        --home-dir /var/lib/pooler --create-home --shell /usr/sbin/nologin pooler \
    && install --directory --owner=pooler --group=pooler --mode=0750 \
        /etc/pooler /run/secrets /var/lib/pooler

COPY --from=builder --chown=pooler:pooler /src/target/release/pooler /usr/local/bin/pooler
COPY --from=builder --chown=pooler:pooler /src/deploy/pooler.example.yaml /etc/pooler/pooler.yaml.example

RUN chmod 0555 /usr/local/bin/pooler

USER pooler:pooler
WORKDIR /var/lib/pooler

# Inference is published by the compose/systemd deployment. The management
# bind is loopback-only and is intentionally not exposed from the image.
EXPOSE 8400
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/pooler"]
CMD ["--help"]
