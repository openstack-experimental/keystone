################
##### Runtime with embedded OPA and policies
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG OPA_VERSION=1.16.2

LABEL maintainer="Artem Goncharov"

# Download OPA binary directly from GitHub releases
ADD https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod 755 /usr/local/bin/opa

# Copy policy files
COPY policy /policy

# Run as an unprivileged user; uid/gid match the Kubernetes manifests.
RUN groupadd --gid 65532 keystone && \
    useradd --uid 65532 --gid 65532 --no-create-home \
      --shell /usr/sbin/nologin keystone
USER 65532:65532
