################
##### Builder
FROM rust:1.93.1-slim-trixie AS builder

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
COPY crates/api-types/Cargo.toml /usr/src/keystone/crates/api-types/
COPY crates/assignment-sql/Cargo.toml /usr/src/keystone/crates/assignment-sql/
COPY crates/config/Cargo.toml /usr/src/keystone/crates/config/
COPY crates/core/Cargo.toml /usr/src/keystone/crates/core/
COPY crates/keystone/Cargo.toml /usr/src/keystone/crates/keystone/
COPY crates/storage/Cargo.toml /usr/src/keystone/crates/storage/
COPY crates/token-fernet/Cargo.toml /usr/src/keystone/crates/token-fernet/
COPY crates/webauthn/Cargo.toml /usr/src/keystone/crates/webauthn/
COPY tests/federation/Cargo.toml /usr/src/keystone/tests/federation/
COPY tests/integration/Cargo.toml /usr/src/keystone/tests/integration/
COPY tests/api/Cargo.toml /usr/src/keystone/tests/api/
COPY tests/loadtest/Cargo.toml /usr/src/keystone/tests/loadtest/
RUN mkdir -p keystone/crates/keystone/src/bin && touch keystone/crates/keystone/src/lib.rs &&\
  cp keystone/src/main.rs keystone/crates/keystone/src/bin/keystone.rs &&\
  cp keystone/src/main.rs keystone/crates/keystone/src/bin/keystone_db.rs &&\
  mkdir -p keystone/tests/loadtest/src &&\
  cp keystone/src/main.rs keystone/tests/loadtest/src/main.rs &&\
  mkdir -p keystone/crates/api-types/src && touch keystone/crates/api-types/src/lib.rs &&\
  mkdir -p keystone/crates/assignment-sql/src && touch keystone/crates/assignment-sql/src/lib.rs &&\
  mkdir -p keystone/crates/config/src && touch keystone/crates/config/src/lib.rs &&\
  mkdir -p keystone/crates/core/src && touch keystone/crates/core/src/lib.rs &&\
  mkdir -p keystone/crates/storage/src && touch keystone/crates/storage/src/lib.rs &&\
  mkdir -p keystone/crates/token-fernet/src && touch keystone/crates/token-fernet/src/lib.rs &&\
  mkdir -p keystone/crates/token-fernet/benches && touch keystone/crates/token-fernet/benches/fernet_token.rs &&\
  mkdir -p keystone/crates/webauthn/src && touch keystone/crates/webauthn/src/lib.rs

# Set the working directory
WORKDIR /usr/src/keystone

## This is a dummy build to get the dependencies cached.
#RUN cargo build --target x86_64-unknown-linux-musl --release
RUN cargo build -p openstack-keystone --release

# Now copy in the rest of the sources
COPY crates/keystone/ /usr/src/keystone/crates/keystone
COPY crates/config/ /usr/src/keystone/crates/config
COPY crates/core/ /usr/src/keystone/crates/core
COPY crates/api-types/ /usr/src/keystone/crates/api-types
COPY crates/storage/ /usr/src/keystone/crates/storage
COPY crates/token-fernet/ /usr/src/keystone/crates/token-fernet
COPY crates/webauthn/ /usr/src/keystone/crates/webauthn
COPY crates/assignment-sql/ /usr/src/keystone/crates/assignment-sql

## Touch main.rs to prevent cached release build
RUN touch crates/keystone/src/lib.rs && touch crates/keystone/src/bin/keystone.rs

# This is the actual application build.
RUN cargo build --release --bins

################
##### Runtime
FROM debian:trixie-slim AS runtime

LABEL maintainer="Artem Goncharov"

#RUN apk add --no-cache bash openssl ca-certificates
RUN apt update && apt install -y ca-certificates libssl3 && update-ca-certificates

# Copy application binary from builder image
COPY --from=builder /usr/src/keystone/target/release/keystone /usr/local/bin
COPY --from=builder /usr/src/keystone/target/release/keystone-db /usr/local/bin

CMD ["/usr/local/bin/keystone"]
