# syntax=docker/dockerfile:1
FROM rust:latest as builder

COPY . /ipa/
RUN cd /ipa && \
  cargo build --bin helper --release --no-default-features \
        --features "web-app real-world-infra compact-gate"

# Copy them to the final image
FROM debian:bullseye-slim

COPY --from=builder /ipa/target/release/helper /bin/ipa-helper
ENTRYPOINT ["/bin/ipa-helper"]
