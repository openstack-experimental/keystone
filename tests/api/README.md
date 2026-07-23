# `test_api`: functional tests against a live Keystone server

These tests run against a real, running `keystone` binary with SPIRE and OPA
(see `tools/start-api.sh`, driven by nextest's `api`/`ci-api` profiles in
`.config/nextest.toml`). They exercise real HTTP wire formats and policy
enforcement, complementing `tests/integration`'s provider-level (mocked
policy, real backend) coverage.

## Test-writing toolkit

The `test_api` support library ships helpers that make the mandated
"≥3 tests per CRUD handler" pattern (valid auth + allowed policy, valid
auth + denied policy, invalid auth) cheap to write. The v3 group suite
(`tests/api_v3/identity/group.rs`) is the reference implementation of the
full matrix.

### Scoped sessions (`test_api::common`)

```rust,ignore
// Sync, composable CloudConfig builders:
let config = get_domain_scope_config("domain-id")?;          // admin, domain scope
let config = get_project_scope_config("proj-id", "dom-id")?; // admin, project scope
let config = config_for_user("alice", "pw", "dom-id", Some(&scope))?; // any user

// Async wrappers producing authenticated sessions:
let session = get_domain_scope_session("domain-id").await?;
let session = get_user_session("alice", "pw", "dom-id", Some(&scope)).await?;
```

Domain- and project-scoped credentials are scope-isolated: policies such as
`domain_matches_domain_scope` only pass for a *genuinely domain-scoped*
token — holding a role on a project inside the domain is not sufficient
(`credentials.domain_id` is never populated from a project scope).

### Negative assertions (`test_api::asserts`)

```rust,ignore
assert_forbidden(result, "manager without domain scope must not create groups");
assert_unauthorized(result, "invalid token must be rejected");
assert_status(result, StatusCode::NOT_FOUND, "deleted group must be gone");
```

All three extract the HTTP status from the `openstack_sdk` error chain via
`status_from_error` and, on failure, report the expected status, the
extracted status and the complete error chain. A denied-policy test is a
one-liner on top of a scoped session:

```rust,ignore
let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;
assert_forbidden(
    create_group(&manager.session, group_create(&domain.id)?).await,
    "manager role without domain scope must not create groups",
);
```

### CRUD endpoint boilerplate (`test_api::macros::crud_endpoint`)

Crate-private macro generating request structs, `RestEndpoint` impls and
public wrapper functions for the common create/show/update/list/delete
shapes — see the module docs in `src/macros.rs` for the invocation syntax
and `src/identity/group.rs` for a complete example. Operations are
selectable and all names are explicit (no identifier generation). Endpoints
that do not fit (sub-resources, grants, borrowed fields) keep hand-written
impls.

### Resource cleanup (`test_api::guard`)

`AsyncResourceGuard` **requires an explicit `guard.delete().await?`** —
Rust has no async `Drop`, so drop-time cleanup is impossible; the `Drop`
impl only *detects* leaks (including on the panic path) and prints the
leaked resource type. Create fixtures with an admin session and clean them
up with that same session so cleanup never depends on an underprivileged
session.

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
