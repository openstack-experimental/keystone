# 17. SecurityContext Design and Security Principles

Date: 2025-11-15
Updated: 2026-05-21

## Status

Accepted; all production APIs documented with parameter descriptions, return
values, and validation architecture. Clippy clean.

## Validation Architecture

All auth types use a single `validate()` method returning `AuthenticationError`
for both structural checks (field presence, length) and business rules (user
enabled, domain enabled, trust chain). The `validator` crate is not used in
`auth.rs` — all validation is manual, ensuring every check produces a
dedicated, typed error (`UserDisabled(id)`, `DomainDisabled(id)`,
`AuthzPrincipalMismatch`, etc.) rather than an opaque `ValidationErrors` bag.

Validation flow:

1. `SecurityContext::validate()` validates the principal (identity, domain,
   user data), then checks authentication-context-specific constraints
   (Trust/AppCred user_id match).
2. `PrincipalInfo::validate()` checks `domain_id` length, then delegates to
   `IdentityInfo::validate()`.
3. `IdentityInfo::validate()` dispatches:
   - `UserIdentityInfo::validate()` — checks user_id length, user presence/match,
     user enabled, domain enabled.
   - `PrincipalIdentityInfo::validate()` — checks id and issuer non-empty;
     IdentityInfo then checks domain enabled.
4. `ScopeInfo::validate()` — checks domain/project/trust project enabled status.
5. `SecurityContext::fully_resolved()` — calls `validate()` + checks that
   scoped authorization carries non-empty roles.

The `validator` crate remains in use by other core-types modules
(`identity`, `assignment`, `token`), but is not used by `auth.rs`.

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

- `SecurityContext` (core-types) — holds principal, authentication context,
  authentication methods, authorization, audit IDs, token, token restriction.
  All fields are `pub(crate)` with explicit getter/setter accessors to prevent
  external mutation.
- `ValidatedSecurityContext` (core) — wrapper that gates the raw context behind
  a validation barrier. Internal field is private; only `Deref` is implemented
  (no `DerefMut`), so the wrapped context is externally immutable.
- `AuthenticationResult` — produced by a single auth method, may carry
  authorization from parent token
- `AuthzInfo` — scope + roles extracted at authentication time. `scope` is
  `pub`, `roles` is `pub(crate)` with setters (`set_roles`, `roles`,
  `try_set_roles`)
- `ScopeInfo` — enum capturing the authorization scope: `Domain`, `Project`,
  `System`, `TrustProject`, `Unscoped`. The `TrustProject` variant boxes its
  payload (`TrustProjectInfo`) to avoid inflating the enum size for the smaller
  variants (Domain, System, Unscoped).
- `Credentials` (policy) — subset of context projected for OPA policy
  evaluation. Uses read-only getters: `principal()`, `authorization()`,
  `effective_roles()`
- `SecurityContextTestingBuilder` (core-types, `#[cfg]`-guarded) — builder for
  constructing `SecurityContext` in test fixtures. Replaces positional
  `for_testing()` with named setters
- `IntoAuthContext` (core) — conversion trait that forces the caller to provide
  context information when converting a provider error into
  `AuthenticationError::Provider`

## Decision

### Two-Phase Validation: Construction Then Validation

`SecurityContext` is the raw, possibly incomplete structure.
`ValidatedSecurityContext` wraps it and represents the validated, resolvable
security context. The two-phase design ensures that no endpoint handler can
observe a partially-authenticated context:

1. `SecurityContext::try_from(AuthenticationResult)` constructs the raw context
   from authentication results
2. `ValidatedSecurityContext::new_for_scope(ctx, scope, state)` is the only
   production path to obtain a validated context. The scope is passed as an
   explicit parameter (not derived from the context) so callers have unambiguous
   control over the target scope. It:
   - If `ctx.authorization()` already set and differs from `scope`, calls
     `ctx.validate_scope_boundaries(&scope)` to guard scope override
   - If `ctx.authorization()` is `None`, calls `ctx.set_authorization_scope(scope)`
   - Populates `user_domain` for `IdentityInfo::User` by querying the resource
     provider — required before `xvalidate()`
   - Calls `ctx.validate()` to check principal integrity (user enabled, appcred/
     trust user_id match)
   - Checks token expiration: if `ctx.expires_at() < Utc::now()`, returns
     `AuthTokenExpired`
   - Runs auth-context-specific validation:
     - `ApplicationCredential`: verifies user_id match and AC expiration
     - `Trust`: validates trust delegation chain, trustor enabled, trustor
       domain enabled, trustor domain compatibility
   - Calls `calculate_effective_roles(state, ctx, scope)` (private, read-only)
     to resolve role assignments from the database
   - Calls `ctx.set_effective_roles(roles)` via setter
   - Returns `ValidatedSecurityContext(ctx)` on success

Production code can only obtain `ValidatedSecurityContext` through
`new_for_scope()`. The `ValidatedSecurityContext` struct wraps the context in a
private inner field. The `Deref` implementation provides read-only access
(`&SecurityContext`); there is no `DerefMut`, `into_inner()`, or `inner_mut()`.
All 8 fields on `SecurityContext` are `pub(crate)`, so external crates cannot
obtain `&mut` access to any field. Setter methods (`set_token`,
`set_authorization`, `set_effective_roles`, `set_token_restriction`,
`expires_at_mut`) are `pub` but require `&mut self`, which is unreachable once
the context is wrapped in `ValidatedSecurityContext`.

### `#[cfg]`-Guarded Test Constructors and Builder

During testing, two mechanisms are available under `#[cfg(any(test, feature = "mock"))]`:

1. `ValidatedSecurityContext::test_new(ctx)` — constructs a validated context
   without going through the validation pipeline. This allows unit tests and
   integration test mocks to inject a pre-built context.

2. `SecurityContextTestingBuilder` (accessed via `SecurityContext::test_build()`)
   — a named-setter builder that replaces the positional `for_testing()` approach.
   Required fields are `authentication_context` and `principal`; optional fields
   are `token`, `authorization`, `expires_at`, and `token_restriction`. The
   builder derives `auth_methods` from `authentication_context.methods()`. Both
   compile-time tests (`#[cfg(test)]`) and the optional `mock` feature gate these
   constructors, so production builds can never call them.

### API Extractor Enforcement

The `Auth` extractor (`core/src/api/auth.rs`) is the Axum extractor that
validates and resolves the context for every authenticated request. Two paths
exist:

1. **Extension injection (tests only)**: When `ValidatedSecurityContext` is
   present in request extensions, the extractor calls `vsc.fully_resolved()?` to
   verify the context is complete, then returns `Auth(vsc)`. This path is
   `#[cfg(any(test, feature = "mock"))]`-guarded.

2. **Token header flow (production)**: The extractor reads `X-Auth-Token`, calls
   `state.provider.get_token_provider().authorize_by_token()`, which builds the
   context, resolves roles via `ValidatedSecurityContext::new_for_scope()`, and
   returns the validated context. The extractor then calls
   `vsc.fully_resolved()?`, and returns `Auth(vsc)`.

Both paths call `fully_resolved()` before returning, ensuring the validation
gate cannot be bypassed.

### `fully_resolved()` Semantics

The `SecurityContext::fully_resolved()` gate at `core-types/src/auth.rs:581`
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

For token authentication, `FernetToken::from_security_context(ctx, expires_at)`
constructs the appropriate token variant from the validated context, using the
scope and role data from `ctx.authorization()`. The token provider's
`build_authz_info_from_fernet_token()` method maps each `FernetToken` variant
to `AuthzInfo { scope, roles }` by fetching scope objects (project, domain,
project_domain) from the database.

The `TryFrom<AuthenticationResult>` and `TryFrom<Vec<AuthenticationResult>>`
both propagate the authorization into the resulting context:

- Single authentication result: the result's authorization is set on the context
- MFA: the first result's authorization is preferred; subsequent results fill in
  if the first is missing
- All MFA results must share the same principal or `AuthnPrincipalMismatch` is
  returned

### Effective Role Calculation

`calculate_effective_roles()` in `core/src/auth.rs` is a private, read-only
function that queries the assignment provider for effective role assignments
based on the scope type. It takes `&SecurityContext` (immutable reference) and
returns `Vec<RoleRef>`. The caller then sets roles via
`SecurityContext::set_effective_roles()`, which uses the setter path through
`AuthzInfo::set_roles()` (no `&mut` borrows escape the constructor).

Based on the scope type:

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
`core/src/policy.rs` extracts `user_id` via `sc.principal().get_user_id()`,
`role_ids` via `sc.authorization().effective_roles()`, and scope-specific
identifiers (`project_id`, `domain_id`, `system`). The implementation uses
only read-only getters — no `&mut` borrows are involved.

Unscoped tokens produce `role_ids: []` with no scope ID set. The OPA policy
must handle this unscoped case correctly. For scoped contexts, the implementation
returns `SecurityContextNotResolved` if `authorization.roles` is unexpectedly
`None` — this is a defense-in-depth check that catches the case where
`fully_resolved()` was not properly gated.

## Consequences

### Security Improvements

- **No mutable context exposure**: `ValidatedSecurityContext::inner()` returns
  `&SecurityContext`. Only `Deref` is implemented (no `DerefMut`), so there is
  no path to obtain `&mut SecurityContext` from `ValidatedSecurityContext`.
  `Clone` produces an independent copy that does not share state.
- **Private fields on `SecurityContext`**: All 8 fields are `pub(crate)` in
  `core-types`. The `ValidatedSecurityContext` type in `core` is a different
  crate, so it also cannot mutate the fields directly — only through the
  getter/setter API. After wrapping, no `&mut` reference is reachable.
- **Explicit getter/setter API**: All field access goes through getters
  (returning `&T` or `Option<&T>`) and setters (taking `&mut self`). No
  interior mutability (`RefCell`, `Cell`, `UnsafeCell`, atomics) is used
  anywhere in the auth context types.
- **Validation is mandatory**: `fully_resolved()` is called both in the
  production Auth extractor path and the test extension-injection path, ensuring
  no endpoint receives an unresolved context.
- **Scope boundary enforcement**: `validate_scope_boundaries()` prevents auth
  methods with narrower scope permissions from being broadened by request-scoped
  scope specifications. The scope override guard in `new_for_scope` calls
  `validate_scope_boundaries()` when the requested scope differs from the
  context's existing scope.
- **Test/production separation**: `test_new()` and `SecurityContextTestingBuilder`
  are compile-time excluded from production builds, preventing accidental bypass.

### Performance Considerations

- **Role computation at validation time**: The `new_for_scope()` path performs
  1-8 database queries depending on scope type and number of effective
  assignments. This cost is paid once per API request.
- **Authorization propagation from token auth**: The token provider builds
  `AuthzInfo` from `FernetToken` by fetching scope objects from the database
  (project, domain, project_domain). The role set is then re-queried by
  `new_for_scope()` for effective assignments (which may differ from
  token-frozen roles due to interim role removal).
- **Revoked token expansion**: The `authorize_by_token` path expands token role
  data from database before checking revocation. This is necessary since the
  token may be considered expired by `project_id`, `role_id`, `user_id`, or any
  combination of those. It is therefore necessary to have a fully expanded token
  before checking for the revocation.
- **Trust validation overhead**: The `new_for_scope()` path for trust contexts
  performs additional queries: trust delegation chain validation, trustor user
  lookup, and trustor domain enabled check. These are necessary for security but
  add 2-3 queries per trust-scoped authentication.

### Maintenance Surface

- `ValidatedSecurityContext` adds one indirection layer to all handlers using
  `Auth`. The `Deref` implementation minimizes friction, but direct field access
  is not possible. Instead, use the getter API: `ctx.principal()`,
  `ctx.authorization()`, `ctx.token()`, `ctx.token_restriction()`, etc.
- Adding a new authentication method requires:
  1. Implementing the provider's authentication logic
  2. Producing an `AuthenticationResult` (with `authorization` if applicable)
  3. Ensuring `AuthenticationContext::methods()` returns the correct method
     names
  4. Verifying `validate_scope_boundaries()` handles the new context variant
  5. Adding a match arm in `new_for_scope()` for auth-context-specific validation
     (even if empty, to trigger a compile error for future context additions)
- Adding a new `ScopeInfo` variant requires updating
  `validate_scope_boundaries()`, `fully_resolved()`,
  `calculate_effective_roles()`, `ScopeInfo::validate()`,
  `FernetToken::from_security_context()`,
  `build_authz_info_from_fernet_token()`, `Credentials::try_from`,
  and all downstream match arms that consume scope information.
- The `ScopeInfo::TrustProject` variant boxes its payload as
  `Box<TrustProjectInfo>` to keep the enum size reasonable. Adding fields to
  `TrustProjectInfo` only affects the trust variant, not the smaller variants
  (`Domain`, `System`, `Unscoped`).
