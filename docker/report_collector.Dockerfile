# syntax=docker/dockerfile:1
ARG SOURCES_DIR=/usr/src/ipa
FROM rust:bookworm AS builder
ARG SOURCES_DIR

# Prepare report collector binaries
WORKDIR "$SOURCES_DIR"
COPY . .
RUN set -eux; \
    cargo build --bin in_the_clear --bin crypto_util --bin report_collector --release --no-default-features --features "cli test-fixture web-app real-world-infra compact-gate"

# Copy them to the final image
FROM rust:slim-bookworm
ENV RC_BIN_PATH=/usr/local/bin
ENV CONF_DIR=/etc/ipa
ARG SOURCES_DIR

RUN apt-get update && apt-get install -y curl procps ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder ${SOURCES_DIR}/target/release/in_the_clear $RC_BIN_PATH/in_the_clear
COPY --from=builder ${SOURCES_DIR}/target/release/crypto_util $RC_BIN_PATH/crypto_util
COPY --from=builder ${SOURCES_DIR}/target/release/report_collector $RC_BIN_PATH/report_collector
