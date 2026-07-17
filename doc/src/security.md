# Security Model: Scope, Delegation, Rescope, and Reauth

This document is the **security-review reference** for authentication and
authorization in Rust Keystone. It captures the threat model, the invariants
that defend against it, and a concrete reviewer checklist to apply when adding
or changing any code that touches scope, delegation, rescope, or reauth.

It is deliberately advisory-driven: the invariants below were hardened in
response to real Keystone vulnerabilities (see
[Advisory cross-reference](#advisory-cross-reference)) and exist to prevent that
class of bug from recurring. Treat a change that weakens any invariant here as a
security regression until proven otherwise.

Related design docs:

- [ADR 0017 — Security Context](adr/0017-security-context.md) — the
  `SecurityContext` / `ValidatedSecurityContext` design these rules build on.
- [ADR 0014 — Application Credentials](adr/0014-application-credentials.md)
- [ADR 0019 — Credentials API](adr/0019-credentials.md)
- [Policy enforcement](policy.md) and [ADR 0002](adr/0002-open-policy-agent)

## 1. Vocabulary

| Term                     | Meaning                                                                                                                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Authentication chain** | The immutable record of _how_ the caller authenticated: `AuthenticationContext` (token, app-cred, trust, EC2, K8s, …) plus the delegation objects themselves. Fixed at authentication time.                                  |
| **Scope**                | The _authorization target_ of the current token: `ScopeInfo` (`Project`, `Domain`, `System`, `TrustProject`, `Unscoped`). Chosen per-request and re-chosen on every rescope.                                                 |
| **Delegated auth**       | Any auth where the caller acts on behalf of another principal with a bounded slice of their power: **trusts**, **application credentials**, and **EC2 credentials** minted under either.                                     |
| **Rescope**              | Exchanging a token for another token with a different scope.                                                                                                                                                                 |
| **Reauth**               | Re-running authentication (new token) rather than reusing/rescoping an existing one.                                                                                                                                         |
| **Scope-bind escape**    | A privilege escalation where a delegated caller acts outside the delegation's fixed boundary by influencing the _scope_ while the security decision was (wrongly) keyed on the scope instead of on the immutable delegation. |

## 2. The one rule that prevents scope-bind escapes

> **Security decisions about a delegation MUST be keyed on the authentication
> chain (immutable), never on the token scope (attacker-influenceable).**

The token scope can legitimately change across a rescope, and the delegation's
own binding cannot. If a check reads `credentials.project_id` (scope) to decide
"is this caller bound to project X", an attacker who can rescope to X defeats
the check. If the same check reads the delegation object's own `project_id`
(chain), rescoping cannot move the boundary.

Every invariant in §4 is a specialization of this rule.

## 3. Trust boundaries

```
 X-Auth-Token / creds ─▶ authenticate ─▶ SecurityContext (raw)
                                              │
                              new_for_scope(ctx, scope, state)   ◀── scope pinning,
                                              │                       role bounding
                                              ▼
                                   ValidatedSecurityContext (VSC)  ◀── ONLY validated form
                                              │
                        TryFrom<&VSC>  ─▶  Credentials  ─▶  OPA policy (input.credentials)
```

- **Nothing downstream of `ValidatedSecurityContext` may reconstruct trust from
  scope.** The VSC already carries the full chain; project it, do not re-derive
  it.
- **OPA sees only `Credentials`.** If a fact is not on `Credentials`, the policy
  cannot enforce it. Adding a delegation-sensitive policy rule almost always
  requires first projecting a new _chain-derived_ field onto `Credentials`.
- **Secrets never reach OPA.** Decrypted credential `blob`s (EC2 secret keys,
  TOTP seeds) are stripped before policy input is built.

## 4. Invariants

Each invariant lists **what**, **why**, and **where enforced**. When you touch
the "where", re-verify the "what".

### I1 — Delegation facts come from the chain

**What:** `Credentials.auth_type`, `is_delegated`, `unrestricted`, `trust`, and
`delegated_project_id` are all read from `sc.authentication_context()`, never
from the scope. **Why:** keying on scope is the scope-bind escape
(OSSA-2026-015). **Where:** `TryFrom<&ValidatedSecurityContext> for Credentials`
(`crates/core/src/policy.rs`).

### I2 — Delegation boundary anchors on `delegated_project_id`

**What:** every delegated-caller policy rule compares the resource's project to
`input.credentials.delegated_project_id` (the delegation's own immutable
project), not to `input.credentials.project_id`. **Why:** same as I1, enforced
at the policy layer. **Where:** `bound_to_own_delegation_project(project_id)` /
`not_delegated_or_bound_to_own_project(project_id)`, defined once in
`policy/credential/common.rego` (`package identity.credential`) and imported as
`credential_common` by `policy/credential/{create,show,update,delete}.rego` and
`policy/os_ec2/create_credential.rego` — a new delegation-sensitive endpoint
imports the check instead of hand-copying it. Callers **must** pass an argument
that is never `undefined` (e.g.
`object.get(input.target.credential, "project_id", null)`, not a bare
`input.target.credential.project_id`): Rego evaluates a function's argument
before dispatching to either body, so an undefined argument makes even the "not
delegated" fast path undefined too — `common.rego`'s doc comment calls this out.

### I3 — Scope-drift tripwire, enforced twice

**What:** delegated rules additionally assert
`credentials.project_id == credentials.delegated_project_id` and that
`delegated_project_id != null`; the rule fails closed on divergence. This is
checked in **two independent layers**: the rego helper above (I2), and a
Rust-side assertion inside `TryFrom<&ValidatedSecurityContext> for Credentials`
(`PolicyError::ScopeDrift`, `crates/core/src/policy.rs`) that runs for every
caller of that conversion, including a future policy that forgets to import the
rego helper. **Why:** defense-in-depth. `validate_scope_boundaries()` keeps
scope pinned to the delegation project today, so any observed drift means a
scope-pinning regression upstream — fail rather than trust it. **Where:** the
rego helpers (I2); the Rust tripwire in `policy.rs`; every delegated policy test
carries a "scope-drift tripwire" negative case.

### I4 — Effective roles are bounded by the delegation, on every scope shape

**What:** a delegated auth's effective roles are always the delegation's role
set (∩ current assignments), regardless of whether it presents as its native
`TrustProject`/app-cred scope **or** as a plain `Project` scope. **Why:** an EC2
credential minted under a restricted delegation and redeemed at `/v3/ec2tokens`
reconstructs the delegated chain but presents a bare project scope; without
bounding it would inherit the trustee's _full_ project roles (OSSA-2026-005 /
CVE-2026-33551). **Where:** `calculate_effective_roles()` routes
`AuthenticationContext::Trust` under `ScopeInfo::Project` through
`resolve_trust_roles()`; app-cred roles are intersected in
`resolve_project_default_roles()` (`crates/core/src/auth.rs`).

A Trust presented on a plain `Project` scope is legal at the boundary layer only
for the trust's **own** bound project, _and_ only when the
`AuthenticationContext::Trust` was freshly reconstructed rather than decoded
from a presented bearer token (`token.is_none()`):
`validate_scope_boundaries()`'s `Project` arm mirrors the
`ApplicationCredential` arm and checks `trust.project_id == project.id` **and**
`token.is_none()` (`crates/core-types/src/auth.rs`), rather than rejecting
Trust-on-Project outright. Earlier, that arm rejected the combination
unconditionally, which made this invariant's "Trust presented on a plain Project
scope" premise unreachable — any EC2 credential minted under a trust would fail
at redemption with `ScopeNotAllowed` before role resolution was ever reached (a
functional bug masking the intended defense-in-depth, not an exploitable
escalation, since it failed closed).

The `token.is_none()` condition matters because a real OS-Trust auth request can
only ever ask for `OS-TRUST:trust` scope — there is no client-facing way to
present a trust identity and request a plain project scope. The single
legitimate producer of the Trust+`Project` shape is `/v3/ec2tokens` redemption
of an EC2 credential minted under a trust, which reconstructs
`AuthenticationContext::Trust` directly from the credential's stored `trust_id`
blob field with `token: None` (`create_inner` in
`crates/keystone/src/api/v3/ec2tokens/create.rs`), because the EC2 credential
carries a bare `project_id`, never a `TrustProject` scope. A caller
reauthenticating with auth method `"token"` against an actual trust-scoped
bearer token (`token: Some(_)`, the shape `validate_to_context_impl` in
`crates/core/src/token/service.rs` produces when decoding a presented trust
Fernet token) and requesting a project scope is rejected: trust tokens can never
be used to mint another token, matching the existing `TrustProject`-arm
rejection of trust-from-trust renewal and closing the equivalent escape hatch on
the `Project` arm. See
`test_new_for_scope_delegated_roles_never_exceed_delegation_matrix` and
`test_new_for_scope_trust_on_foreign_project_rejected` in
`crates/core/src/auth.rs` for end-to-end coverage through `new_for_scope()` (not
just `calculate_effective_roles()` in isolation) across both
Trust-on-`TrustProject` and Trust-on-`Project`, plus the negative case for a
different project; `test_validate_scope_boundarires_trust` in
`crates/core-types/src/auth.rs` covers the `token: Some(_)` reauth-rejection
case directly.

Making that shape reachable exposed a second, more serious gap one layer down:
`FernetToken::from_security_context()` (`crates/core-types/src/token.rs`) chose
the _encoded payload_ by scope shape, and a plain `ScopeInfo::Project` fell
through to a bare `ProjectScopePayload` regardless of `AuthenticationContext` —
including for `Trust`. `ProjectScopePayload` carries no trust reference, so on
the _next_ use of that issued token, `validate_to_context_impl` /
`build_authz_info_from_fernet_token` (`crates/core/src/token/service.rs`) would
decode it back to a generic `AuthenticationContext::Token`, and
`calculate_effective_roles()` would resolve the trustee's own live project roles
instead of the trust's bounded set — the delegation restriction silently
disappearing on reuse, one round-trip after the correctly-bounded first
response. This affected every trust-backed EC2 credential redemption, since the
token handed back by `/v3/ec2tokens` is a normal token meant for repeated use,
not a one-shot artifact. Fixed by adding an explicit
`AuthenticationContext::Trust` arm in `from_security_context()`'s `Project`
match that emits the same `TrustPayload` used for the native `TrustProject`
scope (valid here because `validate_scope_boundaries()` already guarantees
`project.id == trust.project_id`), so decoding always re-derives
`AuthenticationContext::Trust` and re-bounds roles on every use. Covered by
`test_from_security_context_trust_on_project_scope_emits_trust_payload` in
`crates/core-types/src/token.rs`.

### I5 — Scope changes are re-validated against the auth method

**What:** app-creds cannot be scoped beyond their bound project; trusts cannot
be re-scoped to a different trust; token restrictions block domain/system/trust/
unscoped and pin project scope to the restriction's project. **Why:** prevents a
narrow auth method from being broadened via a request-supplied scope. **Where:**
`SecurityContext::validate_scope_boundaries()`
(`crates/core-types/src/auth.rs`), invoked from `new_for_scope()` when the
requested scope differs from the context's existing scope, and unconditionally
(via `set_authorization_scope()`) when no scope is set yet. **Caveat:**
re-presenting an _already-validated_ token with its stored scope unchanged
(token/trust re-authentication, which reconstructs `authorization` directly from
a decoded Fernet token) intentionally skips re-validation — the scope was
checked once at issuance, and a Fernet token is authenticated encryption, so the
stored scope cannot have been tampered with between issuance and reuse. This is
_not_ a hole: every `authorization`-setting path in the codebase either runs
through `set_authorization_scope()` (validated) or reconstructs a value that was
already validated when its own token was minted. I3 exists as an independent,
second-layer backstop regardless.

### I6 — Redemption paths re-assert type and shape

**What:** the EC2 redemption lookup (`get_by_ec2_access` → primary key
`sha256(access)`) has no `type` filter, so the handler must reject any fetched
credential whose `type != "ec2"`, and must reject blobs carrying an
`access_token_id` (OAuth1, unimplemented → would drop restrictions). **Why:**
the `sha256(access) == id` invariant is load-bearing; a mislabelled or
wrong-shaped credential redeemed here would bypass every `type=="ec2"`
create-time guard. **Where:** `crates/keystone/src/api/v3/ec2tokens/create.rs`.

### I7 — Secrets are stripped from policy input

**What:** the decrypted credential `blob` is removed before the object is passed
to OPA as `input.target`/`input.existing`. **Why:** no policy rule reads it;
shipping it leaks EC2 secret keys / TOTP seeds into OPA decision logs.
**Where:** `credential_policy_input()` in
`crates/keystone/src/api/v3/credential/mod.rs`, used by all credential handlers.

### I8 — List re-checks every item individually

**What:** list endpoints run the collection-level policy first, then re-enforce
the per-item `show` policy against **each record's own** identifiers, dropping
unreadable rows. **Why:** a permissive list filter must not leak individual
objects the caller cannot read (CVE-2019-19687). **Where:**
`crates/keystone/src/api/v3/credential/list.rs`.

## 5. Delegated-auth specifics

Trust, application-credential, and EC2 are authentication _methods_, each with
its own `AuthenticationContext` variant. All three are permanently bound to a
single project (optionally further narrowed to a role subset) at credential
creation time; none of them can escape that binding through rescope or reauth —
the mechanism differs per method (below), but the invariant is uniform.

Each method also carries its source-auth information differently:

| Method                 | Fernet payload                                                             | Source-auth carrier                                                                                                                                                                                                                                                                                                                                     | Token-from-token (reauth)                                                                           |
| ---------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Trust                  | dedicated `TrustPayload`                                                   | `trust` embedded in the payload                                                                                                                                                                                                                                                                                                                         | **Forbidden** — see `AuthenticationError` "Token renewal (getting token from token) is prohibited." |
| Application credential | dedicated `ApplicationCredentialPayload`                                   | `application_credential` embedded in the payload                                                                                                                                                                                                                                                                                                        | Allowed, but scope-locked — a token minted from an AC token cannot change scope                     |
| EC2 credential         | regular `ProjectScopePayload` (same shape as a plain project-scoped token) | none in the payload itself — `auth_methods` carries the `"ec2credential"` marker, and if the EC2 credential was minted under a trust/app-cred, redemption reconstructs `AuthenticationContext::Trust`/`ApplicationCredential` from the credential's stored `trust_id`/`app_cred_id` blob fields instead of using `AuthenticationContext::Ec2Credential` | N/A — EC2 redemption is a fresh authentication (signed request), not a token-from-token flow        |

### Trusts

Reconstructed as `AuthenticationContext::Trust { trust, token }`.
`is_delegated == true`, `delegated_project_id == trust.project_id`. Roles
bounded to the trust's delegated set (I4). Cannot be re-scoped to another trust
(I5). Cannot be reauthenticated token-from-token (table above).

### Application credentials

`AuthenticationContext::ApplicationCredential { application_credential, token }`.
`unrestricted` flows to OPA from the AC object (I1).
`delegated_project_id == application_credential.project_id`. Roles = frozen AC
roles ∩ current user assignments (I4). Cannot be scoped beyond the bound project
(I5). May be reauthenticated token-from-token, but the new token is locked to
the same scope (table above).

> **Open gap:** application-credential `access_rules` (per-endpoint
> restrictions) are stored and CRUD'd but **not enforced at request time** — no
> middleware matches the incoming (service, method, path) against them. A
> rules-restricted app-cred can currently call any endpoint. Tracked separately;
> see §7. Interim mitigation (security review V5): `create_application_credential`
> logs a `WARN` whenever a non-empty `access_rules` list is accepted, and
> `application_credential.reject_unenforced_access_rules` (default `false`) lets
> an operator fail loud — reject the create outright — instead of silently
> accepting an unenforceable restriction. Neither replaces the middleware.

### EC2 credentials

Minted under a trust or app-cred, redeemed at `/v3/ec2tokens`. This is the
highest-risk delegated path because redemption **reconstructs** the delegated
chain from stored blob fields and presents a plain project scope (via the
regular `ProjectScopePayload`, not a dedicated trust/AC payload — see table
above). All of I4/I6 exist specifically for it. Any change to EC2 mint/redeem
must be reviewed against §6 below in full.

A bare `AuthenticationContext::Ec2Credential` (an EC2 credential _not_ minted
under a trust/app-cred) carries no delegation metadata at all —
`validate_scope_boundaries` allows it on every scope shape unconditionally,
since there is no delegation boundary to enforce.

## 6. Rescope and reauth rules

- **Rescope preserves the chain.** A rescoped token keeps its
  `AuthenticationContext`; only `ScopeInfo` changes. Therefore delegation
  decisions survive rescope unchanged **iff** they key on the chain (I1/I2).
- **Rescope is bounded by I5.** The new scope is checked against the auth method
  before it is accepted.
- **Delegated tokens do not widen on rescope.** Roles are recomputed via
  `new_for_scope()` and re-bounded by the delegation (I4); rescoping a trust/AC
  token cannot yield roles outside the delegation.
- **Reauth (fresh authentication) re-runs the full pipeline** —
  `SecurityContext::validate()`, expiry, trust-chain validation, role resolution
  — so it is the safe path when in doubt. A validated context is only obtainable
  via `new_for_scope()` / `test_new()` (test-only).

## 7. Reviewer checklist

Apply to any diff touching auth, scope, delegation, tokens, credentials, EC2, or
policy input:

- [ ] Does any delegation/authorization decision read the **scope**
      (`project_id`, `ScopeInfo`) where it should read the **chain**
      (`authentication_context()`, delegation object)? → violates I1/I2.
- [ ] New delegation-sensitive policy rule? Is the fact it needs **projected
      onto `Credentials` from the chain**, and does the rule anchor on
      `delegated_project_id` + carry the scope-drift tripwire (I2/I3)?
- [ ] New scope shape or redemption path for a delegated auth? Are effective
      roles still **bounded by the delegation** (I4)? Add a test that a
      _restricted_ delegation cannot exceed its roles via the new path.
- [ ] New `ScopeInfo` variant or auth method? Updated
      `validate_scope_boundaries()`, `calculate_effective_roles()`,
      `fully_resolved()`, and `Credentials::try_from` (I5)?
- [ ] New lookup by a client-derivable key (like `sha256(access)`)? Does it
      **re-assert `type`/shape** after fetch (I6)?
- [ ] Does any new data reaching OPA include **secrets/decrypted blobs** (I7)?
- [ ] New list/collection endpoint? Does it **re-check each item** with the
      per-item read policy (I8)?
- [ ] Does the change let a narrow auth method be **broadened by a
      request-supplied scope** (I5)?
- [ ] Are there **negative tests** proving the escape is blocked, not just
      positive tests proving the happy path works?
- [ ] Does the test drive `ValidatedSecurityContext::new_for_scope()`
      **end-to-end**, not just the inner helper (`calculate_effective_roles`,
      `validate_scope_boundaries`) in isolation? A unit test on the helper can
      pass while the full call chain still rejects or mis-routes the case — see
      I4's history.

## 8. Advisory cross-reference

| Advisory / CVE                 | Class                                                                  | Invariants                               |
| ------------------------------ | ---------------------------------------------------------------------- | ---------------------------------------- |
| OSSA-2026-015                  | Delegated token not bound to its delegation project on credential CRUD | I1, I2, I3                               |
| OSSA-2026-005 / CVE-2026-33551 | Restricted app-cred escapes role restriction via minted EC2 credential | I4, I6                                   |
| CVE-2019-19687                 | List leaks objects the caller cannot read                              | I8                                       |
| CVE-2020-12691                 | Mutation of immutable credential fields                                | provider-layer field guard; see ADR 0019 |

## 9. Known open gaps

- **App-cred `access_rules` unenforced at request time** (§5). Feature-sized;
  needs request-matching middleware and likely its own ADR. Until then, treat
  `access_rules` as advisory, not a security control. An interim gate exists
  (security review V5): creation warns unconditionally on a non-empty
  `access_rules` list, and `application_credential.reject_unenforced_access_rules`
  (default `false`) can be set to fail loud instead.
