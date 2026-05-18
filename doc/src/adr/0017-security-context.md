# 17. SecurityContext Design and Security Principles

Date: 2025-11-15

## Status

Proposed

## Context

Keystone endpoints require a verified, untamperable security context to make
authorization decisions. Previous Python implementations passed mutable context
object that flattened the authentication and authorization information into a
set of optional fields through the request lifecycle, creating a class of
vulnerabilities where downstream code does not have unambiguous information.

The Rust Keystone must enforce:

- A security context cannot be used for policy enforcement before it is fully
  resolved
- Unscoped authentication is valid and must not be mistaken for unresolved
  context
- Authorization flows from authenticated parent tokens are propagated into the
  security context
- Test paths cannot bypass validation gates in production

Key types involved:

- `SecurityContext` (core-types) — holds principal, authentication methods,
  authorization, audit IDs
- `ValidatedSecurityContext` (core) — wrapper that gates the raw context behind
  a validation barrier
- `AuthenticationResult` — produced by a single auth method, may carry
  authorization from parent token
- `AuthzInfo` — scope + roles extracted at authentication time
- `Credentials` (policy) — subset of context projected for OPA policy evaluation

## Decision

### Two-Phase Validation: Construction Then Validation

`SecurityContext` is the raw, possibly incomplete structure.
`ValidatedSecurityContext` wraps it and represents the validated, resolvable
security context. The two-phase design ensures that no endpoint handler can
observe a partially-authenticated context:

1. `SecurityContext::try_from(AuthenticationResult)` constructs the raw context
   from authentication results
2. `ValidatedSecurityContext::new_with_roles(ctx, state)` is the only production
   path to obtain a validated context. It:
   - Calls `ctx.validate()` to check principal integrity
   - Calls `calculate_effective_roles_in_security_context()` to populate role
     assignments from the database
   - Returns `ValidatedSecurityContext(ctx)` on success

Production code can only obtain `ValidatedSecurityContext` through
`new_with_roles()`. The `ValidatedSecurityContext` struct wraps the context in a
private inner field.

### `#[cfg]`-Guarded Test Constructors

During testing the `ValidatedSecurityContext::test_new(ctx)` constructor is
available under `#[cfg(any(test, feature = "mock"))]`. This allows unit tests
and integration test mocks to inject a pre-built context without going through
the full validation pipeline, while production compiles can never call this
path.

### API Extractor Enforcement

The `Auth` extractor (`core/src/api/auth.rs`) is the Axum extractor that
validates and resolves the context for every authenticated request. Two paths
exist:

1. **Extension injection (tests only)**: When `ValidatedSecurityContext` is
   present in request extensions, the extractor calls `vsc.fully_resolved()?` to
   verify the context is complete, then returns `Auth(vsc)`.
2. **Token header flow (production)**: The extractor reads `X-Auth-Token`, calls
   `state.provider.get_token_provider().authenticate_by_token()`, builds the
   context, resolves roles via `ValidatedSecurityContext::new_with_roles()`,
   calls `vsc.fully_resolved()?`, and returns `Auth(vsc)`.

Both paths call `fully_resolved()` before returning, ensuring the validation
gate cannot be bypassed.

### `fully_resolved()` Semantics

The `SecurityContext::fully_resolved()` gate at `core-types/src/auth.rs:293`
enforces:

- `authorization` is `None` — returns `Err(SecurityContextNotResolved)`:
  authorization has not been bound from the parent token or request scope
- `authorization` is `Some(AuthzInfo { scope: Unscoped, roles: None })` —
  passes: unscoped is valid with no roles
- `authorization` is `Some(AuthzInfo { scope: Scoped, roles: None })` — returns
  `Err(SecurityContextNotResolved)`: scoped authorization must have roles
- `authorization` is `Some(AuthzInfo { scope: _, roles: Some(_) })` — passes:
  roles are populated

The critical distinction is that unscoped authorization with `roles: None` is
valid, while scoped authorization with `roles: None` indicates an incomplete
resolution.

### Authorization Propagation from Authentication

`Authorization` lives at the `AuthenticationResult` level, not nested inside
`TokenContext`. This design allows any authentication method (token, SPIFFE,
K8s, OIDC, etc.) to produce authorization context at authentication time rather
than deferring all role computation to a later phase.

For token authentication, `Token::authorization()` maps each token variant to
`AuthzInfo { scope, roles }` using the already-fetched role data from the
expanded token payload. This avoids redundant backend queries in the
`authenticate_by_token()` path.

The `TryFrom<AuthenticationResult>` and `TryFrom<Vec<AuthenticationResult>>`
both propagate the authorization into the resulting context:

- Single authentication result: the result's authorization is set on the context
- MFA: the first result's authorization is preferred; subsequent results fill in
  if the first is missing
- All MFA results must share the same principal or `AuthnPrincipalMismatch` is
  returned

### Effective Role Calculation

`calculate_effective_roles_in_security_context()` in `core/src/auth.rs` queries
the assignment provider for effective role assignments based on the scope type:

- **Project scope**: queries effective user+group role assignments on the
  project; for application credentials, takes the intersection of frozen AC
  roles with currently assigned user roles
- **Domain scope**: queries effective user+group role assignments on the domain
- **System scope**: queries effective role assignments on the system
- **Trust scope**: resolves trustor roles on the trust's project scope; if the
  trust declares explicit roles, verifies the trustor still has those roles and
  applies implied role expansion
- **Unscoped**: no role query is performed; roles remain `None`

After assignment queries, if `roles` is empty and the scope is not unscoped,
`ActorHasNoRolesOnTarget` is returned. Token restrictions are applied last to
potentially narrow the role set.

### Scope Boundary Validation

`SecurityContext::validate_scope_boundaries(scope)` at `core-types/src/auth.rs`
validates whether the authentication context permits a requested scope type. It
does NOT verify role ownership — only whether the auth method and any token
restrictions allow the target scope. Returns `ScopeNotAllowed` on violation.

Key constraints:

- Application credentials cannot be scoped beyond their bound project
- Token restrictions block domain, system, trust, and unscoped scopes; project
  scope must match the restriction's project ID
- Trust authentication cannot be re-scoped to a different trust
- K8s authentication is limited by its token restriction

### Policy Credentials Projection

`Credentials` is the subset of `ValidatedSecurityContext` projected for OPA
policy evaluation. The `TryFrom<&ValidatedSecurityContext>` implementation at
`core/src/policy.rs` extracts `user_id`, `role_ids`, and scope-specific
identifiers (`project_id`, `domain_id`, `system`). Unscoped tokens produce
`role_ids: []` with no scope ID set. The OPA policy must handle this unscoped
case correctly.

## Consequences

### Security Improvements

- **No mutable context exposure**: `ValidatedSecurityContext::inner()` returns
  `&SecurityContext`, preventing endpoint handlers from modifying the security
  context after validation.
- **Validation is mandatory**: `fully_resolved()` is called both in the
  production Auth extractor path and the test extension-injection path, ensuring
  no endpoint receives an unresolved context.
- **Scope boundary enforcement**: `validate_scope_boundaries()` prevents auth
  methods with narrower scope permissions from being broadened by request-scoped
  scope specifications.
- **Test/production separation**: `test_new()` is compile-time excluded from
  production builds, preventing accidental bypass.

### Performance Considerations

- **Role computation at validation time**: The `new_with_roles()` path performs
  1-8 database queries depending on scope type and number of effective
  assignments. This cost is paid once per API request.
- **Authorization propagation from token auth**: The `Token::authorization()`
  method uses role data already fetched during token expansion, avoiding a
  second set of backend queries. The role set is then re-queried by
  `new_with_roles()` for effective assignments (which may differ from
  token-frozen roles due to interim role removal).
- **Revoked token expansion**: The `validate_token` path expands token role data
  from database before checking revocation. This is necessary since the token
  may be consideres expired by `project_id`, `role_id`, `user_id`, or any
  combination of those. It is therefore necessary to have a fully expanded token
  before checking for the revocation.
- **OPA policy credentials gap (known gap)**: The `Credentials::try_from`
  silently produces `role_ids: []` for unscoped tokens. While correct for
  unscoped, the same silent skip applies when `authorization.roles` is
  unexpectedly `None` for a scoped context. A defense-in-depth check would catch
  this case.

### Maintenance Surface

- `ValidatedSecurityContext` adds one indirection layer to all handlers using
  `Auth`. The `Deref` implementation minimizes friction, but accessing
  `ctx.authorization.roles` requires going through
  `ctx.authorization.as_ref().unwrap()`.
- Adding a new authentication method requires:
  1. Implementing the provider's authentication logic
  2. Producing an `AuthenticationResult` (with `authorization` if applicable)
  3. Ensuring `AuthenticationContext::methods()` returns the correct method
     names
  4. Verifying `validate_scope_boundaries()` handles the new context variant
- Adding a new `ScopeInfo` variant requires updating
  `validate_scope_boundaries()`, `fully_resolved()`,
  `calculate_effective_roles_in_security_context()`, `ScopeInfo::validate()`,
  and all downstream match arms that consume scope information.
