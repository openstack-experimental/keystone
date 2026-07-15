# `test_api`: functional tests against a live Keystone server

These tests run against a real, running `keystone` binary with SPIRE and OPA
(see `tools/start-api.sh`, driven by nextest's `api`/`ci-api` profiles in
`.config/nextest.toml`). They exercise real HTTP wire formats and policy
enforcement, complementing `tests/integration`'s provider-level (mocked
policy, real backend) coverage.

## OAuth2/OIDC provider (ADR 0026) manual compliance smoke check

RFC 8628 (Device Authorization Grant) and RFC 8693 (Token Exchange) have no
actively maintained, self-hostable conformance suite comparable to the
OpenID Foundation's OIDC Conformance Suite -- and that suite itself targets
full OIDC discovery/dynamic-client-registration profiles ADR 0026 doesn't
implement, so adopting it would mean building scaffolding to satisfy the
tool rather than proving real interop. This repo does not run one in CI.

Instead, periodically (not CI-gated) sanity-check the `/v4/oauth2/*`
endpoints against a generic, RFC-8628-compliant OAuth2 client that was never
tuned to Keystone's own response shapes -- this catches wire-format
deviations that `test_api::oauth2`'s purpose-built helpers would never
surface, since they were written against Keystone's actual responses.

To run this check:

1. Start a local server: `tools/start-api.sh` (leaves the server running;
   `tools/teardown-api.sh` stops it).
2. Register a device-flow-capable client via the admin API (see
   `test_api::oauth2::register_client` for the exact request shape, or use
   `keystone-manage oauth2` once a registration subcommand exists).
3. Run a generic RFC 8628 client against it, e.g.
   [`oauth2c`](https://github.com/cloudentity/oauth2c) or an equivalent
   scriptable OAuth2 CLI, pointed at
   `http://localhost:8080/v4/oauth2/default/device_authorization` and
   `.../token`.
4. Confirm it completes the full device flow (poll -> user verification ->
   token issuance) and can parse the issued token, without any
   Keystone-specific client code.

Re-evaluate adopting an automated conformance suite only if Keystone later
claims formal OIDC-provider compliance beyond ADR 0026's current scope.
