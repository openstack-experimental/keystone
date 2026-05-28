################
##### Builder
FROM rust:1.94.1-slim-trixie AS base

RUN cargo install --locked cargo-chef
WORKDIR app

################
##### Plan
FROM base AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

################
##### Build
FROM base AS builder

#RUN rustup target add x86_64-unknown-linux-gnu &&\
RUN apt update &&\
    apt install -y openssl libssl-dev libssl3 pkg-config \
    protobuf-compiler &&\
    update-ca-certificates

COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Copy the actual sources
#COPY . .
COPY crates crates
COPY tests tests
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

# This is the actual application build.
RUN cargo build --release --bins

################
##### Runtime
FROM debian:trixie-slim AS runtime

LABEL maintainer="Artem Goncharov"

#RUN apk add --no-cache bash openssl ca-certificates
RUN apt update && apt install -y ca-certificates libssl3 && update-ca-certificates

# Copy application binary from builder image
COPY --from=builder /app/target/release/keystone /usr/local/bin
COPY --from=builder /app/target/release/keystone-manage /usr/local/bin

CMD ["/usr/local/bin/keystone"]

################
##### Runtime with embedded OPA and policies
FROM runtime AS runtime-opa

ARG OPA_VERSION=1.16.2

LABEL maintainer="Artem Goncharov"

# Download OPA binary directly from GitHub releases
ADD https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod 755 /usr/local/bin/opa

# Copy policy files
COPY policy /policy
