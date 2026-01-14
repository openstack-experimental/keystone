################
##### Builder
FROM rust:1.92.0-slim-bookworm AS builder

#RUN rustup target add x86_64-unknown-linux-gnu &&\
RUN apt update &&\
    apt install -y openssl libssl-dev libssl3 pkg-config musl-tools musl-dev &&\
    update-ca-certificates

WORKDIR /usr/src

# Create blank project
RUN USER=root cargo new keystone

# We want dependencies cached, so copy those first.
COPY Cargo.toml Cargo.lock /usr/src/keystone/
RUN mkdir -p keystone/src/bin && touch keystone/src/lib.rs &&\
  cp keystone/src/main.rs keystone/src/bin/keystone.rs &&\
  cp keystone/src/main.rs keystone/src/bin/keystone_db.rs &&\
  mkdir -p keystone/benches && touch keystone/benches/fernet_token.rs

# Set the working directory
WORKDIR /usr/src/keystone

## This is a dummy build to get the dependencies cached.
#RUN cargo build --target x86_64-unknown-linux-musl --release
RUN cargo build --release

# Now copy in the rest of the sources
COPY . /usr/src/keystone/

## Touch main.rs to prevent cached release build
RUN touch src/lib.rs && touch src/bin/keystone.rs

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
