# syntax=docker/dockerfile:1
ARG SOURCES_DIR=/usr/src/ipa
FROM rust:latest as builder

LABEL maintainer="akoshelev"

# Prepare helper binaries
WORKDIR "$SOURCES_DIR"
COPY . .
RUN set -eux; \
    cargo build --bin helper --release --no-default-features --features "web-app real-world-infra"

# Copy them to the final image
FROM debian:bullseye-slim
ENV HELPER_BIN_PATH=/usr/local/bin/ipa-helper
ENV CONF_DIR=/etc/ipa
ARG IDENTITY
ARG HOSTNAME

RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder ${SOURCES_DIR}/target/release/helper $HELPER_BIN_PATH

# generate certificate/private key for TLS
RUN set -eux; \
    mkdir -p $CONF_DIR/pub; \
    $HELPER_BIN_PATH keygen --name $HOSTNAME --tls-cert $CONF_DIR/pub/$IDENTITY.pem --tls-key $CONF_DIR/$IDENTITY.key
