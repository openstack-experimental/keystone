# 37. Application-Credential Access-Rule Enforcement

**Date:** 2026-09-14

## Status

Accepted. Implemented in `crates/core/src/api/auth.rs` (`enforce_access_rules`,
called from every return path of `Auth::from_request_parts`) and
`crates/core-types/src/application_credential/access_rule.rs`
(`access_rules_permit`, the pure matcher).

## Reference

Closes the gap security review V5 (`doc/src/contributor/security-review.md`)
and `doc/src/contributor/security-model.md` §5/§9 named as the single
highest-impact known live gap: application-credential `access_rules` were
stored and CRUD'd but never checked at request time. Extends ADR 0014
(Application Credentials) and ADR 0017 (Security Context).

## Context

An application credential's `access_rules` restrict it to a named subset of
`(service, method, path)` calls — e.g. "this credential may only
`GET /v3/servers`". `create_application_credential` accepted, stored, and
returned these rules from day one; nothing ever matched an incoming request
against them. A rules-restricted credential could call any endpoint its
underlying roles allowed, silently converting a control the operator believed
was active into a no-op.

The interim mitigation (security review V5, shipped before this ADR) made
that dishonesty visible rather than closing it:
`create_application_credential` logs a `WARN` on any non-empty `access_rules`
list, and `application_credential.reject_unenforced_access_rules` (default
`false`) lets an operator fail the create outright. Neither enforces
anything; both remain in place as they were, unrelated to whether
enforcement exists.

### Why Keystone can only enforce its own service's rules

In a full OpenStack deployment, an access-rules-restricted credential is
normally used against *other* services (compute, image, ...), each fronted
by `keystonemiddleware`, which fetches the token's `access_rules` via token
introspection (`GET /v3/auth/tokens`) and matches the incoming request
itself before it reaches that service's application code. Keystone is not in
that request path and cannot enforce those rules — it never sees the
request.

The gap this ADR closes is narrower and Keystone-local: when an
access-rules-restricted credential calls **Keystone's own API directly**
(creating a trust, listing users, ...), there is no middleware in front of
Keystone to do this check — Keystone is both the token issuer and the
resource server, so it must self-enforce. A rule naming a different service
type is therefore not an error and not silently ignored; it simply never
matches a request Keystone itself receives, exactly as intended (that
restriction is a different service's job).

### Why this is not a `tower`/`axum` middleware layer

ADR 0022 (rate limiting) already rejected generic middleware layers for
security-decision logic in this codebase, because they run before handler
extraction and can't easily reach request-specific context. The same
argument applies here in reverse: the context this check needs (the
resolved `ValidatedSecurityContext`, specifically whether the caller is an
`ApplicationCredential` with rules) is exactly what `Auth`'s own
`FromRequestParts` implementation produces. A separate middleware layer
would have to re-run authentication itself (re-decoding the Fernet token, a
second `authorize_by_token` round trip) to get that context independently —
doubling authentication cost on every request, most of which are not even
application-credential calls, to reach data `Auth` already has for free.

Instead, `enforce_access_rules` runs *inside* `Auth::from_request_parts`,
immediately before every one of its return paths (including the
`#[cfg(test)]` mock-injection shortcut, so handler tests can exercise it
without extra plumbing). This is still "before handler dispatch" — `Auth` is
an extractor, and extractors run before the handler body — but it costs zero
extra authentication work and cannot be skipped by a handler that forgets to
call something, because every handler that needs the caller's identity
already extracts `Auth`.

## Decision

### The matcher (`access_rule.rs`)

```rust
pub fn access_rules_permit(rules: &[AccessRule], method: &str, path: &str) -> bool
```

A pure function, no I/O, easy to exhaustively unit test. A rule matches when:

1. `rule.service` case-insensitively equals `OWN_SERVICE_TYPE` (`"identity"`,
   Keystone's own catalog service type). A rule naming any other service
   never matches here (see "Why Keystone can only enforce its own service's
   rules" above).
2. `rule.method` case-insensitively equals the request method.
3. `rule.path` matches the request path segment-by-segment, per the
   wildcard syntax already documented on `AccessRule::path`:
   - a literal segment must match exactly,
   - `{tag}` (any name) or `*` matches exactly one path segment,
   - `**` matches zero or more segments, including across `/`.

A rule missing `method`, `path`, or `service` never matches anything — those
fields are required by the API layer at creation time, but this function
fails closed on a malformed stored rule rather than treating a missing field
as "matches anything".

`access_rules_permit` returns `true` if **any** rule in the list matches
(the rules are a permitted-actions allowlist, not an ordered chain).

### The enforcement point (`auth.rs`)

```rust
fn enforce_access_rules(
    vsc: &ValidatedSecurityContext,
    parts: &Parts,
) -> Result<(), KeystoneApiError>
```

A no-op unless `vsc`'s `AuthenticationContext` is `ApplicationCredential`
with a non-empty `access_rules` list. When it applies and no rule permits
`(parts.method, parts.uri.path())`, returns
`ApplicationCredentialProviderError::AccessRuleDenied`, converted to
`KeystoneApiError::Forbidden` (HTTP 403) — the same status code an OPA
policy denial produces, so a client cannot distinguish "the policy denied
this" from "your access_rules don't cover this" by status code alone
(deliberately: neither should leak more about *why* than a generic 403).

This runs **before** OPA policy evaluation (`enforce()`), not after: an
access-rules-restricted credential that is technically authorized by policy
for an endpoint outside its rules must still be denied, and there is no
reason to pay for a policy round trip on a request that is going to be
rejected regardless.

Enforcement is unconditional once `access_rules` is non-empty — it does not
read `reject_unenforced_access_rules`. That flag's purpose was to let an
operator fail loud *at creation time*, while enforcement did not exist yet;
now that enforcement exists, honoring a restriction the operator explicitly
set is not something a config flag should be able to turn off. The flag
stays for backward compatibility of the create-time API but no longer
describes the true state ("unenforced") — see the doc-comment fix in
`crates/config/src/application_credentials.rs` and
`security-model.md` §9.

### Interaction with rescope and reauth

An application-credential token can be reauthenticated (token-from-token)
but not rescoped (`security-model.md` §5). `enforce_access_rules` reads the
rules straight from the `AuthenticationContext::ApplicationCredential`
payload, which is carried unchanged through both the initial authentication
and any reauthentication (`ApplicationCredentialPayload`, security-model.md
§5's table) — so the restriction applies identically regardless of how the
current request's token was obtained, with no separate rescope-specific
logic needed.

## Consequences

- **Closes the gap.** An access-rules-restricted application credential can
  no longer call a Keystone endpoint outside its declared rules; the
  previous no-op silently accepted a call the operator believed was
  restricted, this now rejects it (HTTP 403).
- **Scope is deliberately narrow.** This ADR does not implement or claim to
  implement enforcement for other OpenStack services — that remains
  `keystonemiddleware`'s job in each service, unchanged.
- **No migration needed.** Because enforcement previously did not exist,
  there is no prior "working" behavior this could regress for a caller that
  actually depended on it; any application credential whose calls now fail
  as `AccessRuleDenied` was already calling outside a restriction its
  creator declared, which was always the intended behavior once enforcement
  shipped.
- **`security-model.md` §9's "Known open gap"** entry for `access_rules` is
  closed by this ADR; the entry is updated to record that.
