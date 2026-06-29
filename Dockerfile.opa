################
##### Runtime with embedded OPA and policies
FROM debian:trixie-slim

ARG OPA_VERSION=1.16.2

LABEL maintainer="Artem Goncharov"

# Download OPA binary directly from GitHub releases
ADD https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod 755 /usr/local/bin/opa

# Copy policy files
COPY policy /policy
