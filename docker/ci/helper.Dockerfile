# syntax=docker/dockerfile:1
ARG SOURCES_DIR=/usr/src/ipa
FROM rust:latest as builder

# Prepare helper binaries
WORKDIR "$SOURCES_DIR"
COPY . .
RUN set -eux; \
    cargo build --bin helper --release --no-default-features --features "web-app real-world-infra"

# Copy them to the final image
FROM debian:bullseye-slim
ENV HELPER_BIN_PATH=/usr/local/bin/ipa-helper
ARG SOURCES_DIR

RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder ${SOURCES_DIR}/target/release/helper $HELPER_BIN_PATH
