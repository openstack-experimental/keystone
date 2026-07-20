# Administrator Configuration Guide

Keystone reads an OpenStack-style INI file. Values are merged in this order,
with later sources winning:

1. The file selected with `keystone --config`.
2. The optional file named by `KEYSTONE_SITE_VARS_FILE`.
3. Environment variables prefixed with `OS_`, using `__` between section and
   option.

For example, `OS_API_POLICY__OPA_BASE_URL=http://opa:8181` overrides
`opa_base_url` in `[api_policy]`.

The [configuration reference](../configuration/index.md) lists every section
and directs operators to the authoritative detailed guide.

## Interfaces

Use `[interface_public]` for the public HTTP listener. Terminate public HTTPS at
a trusted reverse proxy or load balancer and restrict direct access to the
listener. Public SPIFFE is not currently implemented.

The optional `[interface_internal]` listener supports SPIFFE mTLS and requires
`SPIFFE_ENDPOINT_SOCKET`. `[interface_admin]` uses SPIFFE mTLS over a Unix-domain
socket and can restrict peer UID and GID. `[interface_metrics]` exposes health,
readiness, and Prometheus metrics and must not be placed on an untrusted network.

## Core Services

- `[database]` selects the SQL connection.
- `[api_policy]` selects OPA and an optional local policy directory.
- `[auth]` enables built-in and registered authentication methods.
- `[token]` selects the token provider and lifetime.
- `[fernet_tokens]` configures the Fernet key repository.
- `[distributed_storage]` enables OpenRaft storage and its KEK and transport
  settings.

Feature-specific configuration belongs with the corresponding administrator
guide. Do not copy partial distributed-storage examples into production; follow
the complete [storage runbook](storage/distributed.md).
