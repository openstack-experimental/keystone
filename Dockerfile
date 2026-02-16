################
##### Builder
FROM rust:1.92.0-slim-bookworm AS builder

#RUN rustup target add x86_64-unknown-linux-gnu &&\
RUN apt update &&\
    apt install -y openssl libssl-dev libssl3 pkg-config musl-tools musl-dev \
    protobuf-compiler &&\
    update-ca-certificates

WORKDIR /usr/src

# Create blank project
RUN USER=root cargo new keystone

# We want dependencies cached, so copy those first.
COPY Cargo.toml Cargo.lock /usr/src/keystone/
COPY crates/keystone/Cargo.toml /usr/src/keystone/crates/keystone/
COPY crates/keystone_distributed_storage/Cargo.toml /usr/src/keystone/crates/keystone_distributed_storage/
COPY tests/federation/Cargo.toml /usr/src/keystone/tests/federation/
COPY tests/integration/Cargo.toml /usr/src/keystone/tests/integration/
COPY tests/api/Cargo.toml /usr/src/keystone/tests/api/
COPY tests/loadtest/Cargo.toml /usr/src/keystone/tests/loadtest/
RUN mkdir -p keystone/crates/keystone/src/bin && touch keystone/crates/keystone/src/lib.rs &&\
  cp keystone/src/main.rs keystone/crates/keystone/src/bin/keystone.rs &&\
  cp keystone/src/main.rs keystone/crates/keystone/src/bin/keystone_db.rs &&\
  mkdir keystone/tests/loadtest/src &&\
  cp keystone/src/main.rs keystone/tests/loadtest/src/main.rs &&\
  mkdir keystone/crates/keystone_distributed_storage/src &&\
  touch keystone/crates/keystone_distributed_storage/src/lib.rs

# Set the working directory
WORKDIR /usr/src/keystone

## This is a dummy build to get the dependencies cached.
#RUN cargo build --target x86_64-unknown-linux-musl --release
RUN cargo build -p openstack_keystone --release

# Now copy in the rest of the sources
COPY crates/keystone/ /usr/src/keystone/crates/keystone
COPY crates/keystone_distributed_storage/ /usr/src/keystone/crates/keystone_distributed_storage

## Touch main.rs to prevent cached release build
RUN touch crates/keystone/src/lib.rs && touch crates/keystone/src/bin/keystone.rs

# This is the actual application build.
RUN cargo build --release --bins

################
##### Runtime
FROM debian:bookworm-slim AS runtime

LABEL maintainer="Artem Goncharov"

#RUN apk add --no-cache bash openssl ca-certificates
RUN apt update && apt install -y ca-certificates libssl3 && update-ca-certificates

# Copy application binary from builder image
COPY --from=builder /usr/src/keystone/target/release/keystone /usr/local/bin
COPY --from=builder /usr/src/keystone/target/release/keystone-db /usr/local/bin

CMD ["/usr/local/bin/keystone"]
