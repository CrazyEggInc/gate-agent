FROM rust:1.94.1-alpine3.23@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS builder
RUN apk add --no-cache musl-dev=1.2.5-r23
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked --bin gate-agent

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates=20261020-r0
WORKDIR /app
COPY --from=builder --chmod=0555 /build/target/release/gate-agent /app/gate-agent
USER nobody
EXPOSE 8787
ENTRYPOINT ["/app/gate-agent"]
CMD ["start", "--config", "/app/.secrets"]
