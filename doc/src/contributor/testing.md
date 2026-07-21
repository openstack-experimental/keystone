# Testing

Choose the narrowest command that covers the change and always specify the
crate for crate-level commands.

| Purpose | Command |
| --- | --- |
| Workspace type check | `cargo check --message-format=short` |
| Crate unit tests | `cargo test -p <crate_name>` |
| Integration tests | `cargo test -p test_integration` |
| Raft integration tests | `cargo nextest run -p test_integration --profile raft` |
| Live API tests | `cargo nextest run --profile api -p test_api` |
| Formatting check | `cargo fmt --all -- --check` |
| Crate lint | `cargo clippy -p <crate_name>` |

## Live API Tests

The API profile starts SPIRE, OPA, and a real Keystone server through
`tools/start-api.sh`. Run `tools/teardown-api.sh` before a fresh run if a prior
run was interrupted. Do not pipe nextest through `tail`; redirect it to a file
because long-running child processes inherit the output descriptor.

The bootstrap-created `default` domain does not receive OAuth2 signing keys.
Tests that need JWKS or discovery must create a new domain through the API and
poll for asynchronous key provisioning.

Password authentication returns `IdentityInfo::User`. Mocks for the real
password-auth path must use the same identity variant.

## Documentation Tests

Regenerate the API specification and build the book:

```console
cargo run -p openstack-keystone --bin keystone -- --dump-openapi yaml \
  > doc/src/openapi.yaml
mdbook build doc
```

`doc/src/openapi.yaml` is generated input for the documentation build and is
intentionally ignored by Git. The mdBook workflow regenerates it before every
published build; do not add it to a commit.
