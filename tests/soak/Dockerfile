# Image with the soak controller and the goose `load_test` it drives.
# Build from the repository root:
#   docker build -f tests/soak/Dockerfile -t keystone-soak .
FROM rust:1.99.0-slim-trixie AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY tests/loadtest tests/loadtest
COPY tests/soak tests/soak
RUN cargo build --release --locked --manifest-path tests/loadtest/Cargo.toml \
 && cargo build --release --locked --manifest-path tests/soak/Cargo.toml

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/tests/loadtest/target/release/load_test /usr/local/bin/load_test
COPY --from=builder /src/tests/soak/target/release/soak /usr/local/bin/soak
RUN useradd --system --create-home soak
USER soak
ENV HOME=/home/soak
EXPOSE 9100
ENTRYPOINT ["soak"]
