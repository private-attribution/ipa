# syntax=docker/dockerfile:1
ARG SOURCES_DIR=/usr/src/ipa
FROM rust:bookworm AS builder
ARG SOURCES_DIR

# Prepare helper binaries
WORKDIR "$SOURCES_DIR"
COPY . .
RUN set -eux; \
    cargo build --bin helper --release --no-default-features --features "web-app real-world-infra compact-gate multi-threading"

# Copy them to the final image
FROM rust:slim-bookworm
ENV HELPER_BIN_PATH=/usr/local/bin/ipa-helper
ENV CONF_DIR=/etc/ipa
ARG SOURCES_DIR

RUN apt-get update && apt-get install -y ca-certificates curl procps && rm -rf /var/lib/apt/lists/*

COPY --from=builder ${SOURCES_DIR}/target/release/helper $HELPER_BIN_PATH
