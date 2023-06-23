# syntax=docker/dockerfile:1
FROM rust:latest as builder

RUN mkdir -p /ipa
COPY . /ipa
RUN cargo -C /ipa build --bin helper --release --no-default-features \
      --features "web-app real-world-infra"

# Copy them to the final image
FROM debian:bullseye-slim

COPY --from=builder /ipa/target/release/helper /bin/ipa-helper
ENTRYPOINT ["/bin/ipa-helper"]
