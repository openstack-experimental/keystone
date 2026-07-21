# API Development

Keystone-NG follows domain-driven crate boundaries:

- `crates/keystone` owns the service binary and HTTP handlers.
- `crates/core` owns domain providers and backend traits.
- `crates/core-types` owns shared domain structures.
- `crates/api-types` owns request and response structures.
- `crates/*-sql` and `crates/*-raft` own persistence drivers.

## Handlers and Types

Place v3 and v4 handlers below the owning API module, keep one handler per
module, and register it with the domain's `openapi_router()`. API request and
response types belong in `crates/api-types` so the OpenAPI document follows the
implementation.

CRUD handlers require tests for valid authentication with positive and negative
policy decisions and for invalid authentication.

## Backend Traits

Use the established CRUD names: `create_<resource>`, `get_<resource>`,
`list_<resources>`, `update_<resource>`, and `delete_<resource>`. Keep each
driver in the crate belonging to its domain and storage technology.

## Policies

Policy files use `policy/<domain>/<resource>/<action>.rego`. List handlers must
run collection policy and then re-check each returned item with its read policy.
Never send decrypted secrets to OPA. Read the [security model](security-model.md)
before changing authentication, scope, delegation, credentials, tokens, or
policy input.
