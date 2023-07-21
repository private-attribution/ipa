# syntax=docker/dockerfile:1
ARG SOURCES_DIR=/usr/src/ipa
FROM rust:latest as builder
ARG SOURCES_DIR
LABEL maintainer="akoshelev"

# Prepare helper binaries
WORKDIR "$SOURCES_DIR"
COPY . .
RUN set -eux; \
    cargo build --bin helper --release --no-default-features --features "web-app real-world-infra compact-gate"

# Copy them to the final image
FROM debian:bullseye-slim
ENV HELPER_BIN_PATH=/usr/local/bin/ipa-helper
ENV CONF_DIR=/etc/ipa
ARG IDENTITY
ARG HOSTNAME
ARG SOURCES_DIR

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder ${SOURCES_DIR}/target/release/helper $HELPER_BIN_PATH

# generate certificate/private key for TLS
# make sure these names are consistent with the ones defined in CliPaths trait: src\cli\paths.rs
RUN set -eux; \
    mkdir -p $CONF_DIR/pub; \
    $HELPER_BIN_PATH keygen \
    --name $HOSTNAME \
    --tls-cert $CONF_DIR/pub/h$IDENTITY.pem \
    --tls-key $CONF_DIR/h$IDENTITY.key \
    --mk-public-key $CONF_DIR/pub/h${IDENTITY}_mk.pub \
    --mk-private-key $CONF_DIR/h${IDENTITY}_mk.key
