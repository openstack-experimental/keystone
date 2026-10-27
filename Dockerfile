################
##### Builder
FROM rust:1.99.0-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS base
ENV CARGO_HOME=/usr/local/cargo
ENV CARGO_TARGET_DIR=/app/target

RUN cargo install --locked cargo-chef
WORKDIR /app

################
##### Plan
FROM base AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

################
##### Build
FROM base AS builder

#RUN rustup target add x86_64-unknown-linux-gnu &&\
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl libssl-dev libssl3t64 pkg-config protobuf-compiler libprotobuf-dev libtss2-dev && \
    rm -rf /var/lib/apt/lists/* && update-ca-certificates

COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release -p openstack-keystone -p openstack-keystone-cli-manage --recipe-path recipe.json

# Copy the actual sources
#COPY . .
COPY crates crates
COPY tests tests
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

# Optional cargo features, e.g. `--build-arg KEYSTONE_FEATURES=openstack-keystone/pkcs11`
# for the PKCS#11 KEK provider required by production Raft storage.
ARG KEYSTONE_FEATURES=""
RUN cargo build --release --bins --features "${KEYSTONE_FEATURES}"

################
##### Runtime
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime

LABEL maintainer="Artem Goncharov"

#RUN apk add --no-cache bash openssl ca-certificates
# libtss2-* runtime libraries are required by the TPM KEK provider (the
# `tpm` cargo feature); they are pulled in unconditionally so a single image
# can serve both the PKCS#11 and TPM backends, selected by config. The
# `libtss2-tctildr` package pulls the device and swtpm TCTI backends used by
# `device:` and `swtpm:` TCTI connection strings.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 \
    libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-sys1t64 \
    libtss2-tctildr0t64 && \
    rm -rf /var/lib/apt/lists/* && update-ca-certificates

# Copy application binary from builder image
COPY --from=builder /app/target/release/keystone /usr/local/bin
COPY --from=builder /app/target/release/keystone-manage /usr/local/bin

# Optional user-space KEK-provider test tools (e.g. `softhsm2 opensc swtpm
# tpm2-tools`) for the single-voter k3s smoke-test overlays. Empty in the
# published image.
ARG KEYSTONE_TEST_TOOLS=""
RUN if [ -n "${KEYSTONE_TEST_TOOLS}" ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends ${KEYSTONE_TEST_TOOLS} && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# Run as an unprivileged user. The numeric uid/gid match the `runAsUser` /
# `fsGroup` of the Kubernetes manifests (tools/k8s/keystone). Binaries stay
# root-owned and are not writable by this user.
RUN groupadd --gid 65532 keystone && \
    useradd --uid 65532 --gid 65532 --no-create-home \
      --shell /usr/sbin/nologin keystone
USER 65532:65532

CMD ["/usr/local/bin/keystone"]
