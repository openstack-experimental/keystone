# Security Architecture Review: Preemptive Gates, Testing, and Vulnerability Vectors

Status: advisory review (2026-07-09). Companion to [Security model](security.md)
(the normative invariant reference) and [Policy enforcement](policy.md). Where
the two disagree, `security.md` wins; this document proposes _additions_, it
does not restate or replace the invariants there.

Disclaimer: This review was performed by Claude Fable model with a human
directions.

## 1. Purpose and scope

This is an architecture-level security review of Rust Keystone from the
attacker's point of view. It answers three questions the project asked:

1. Where can **more preemptive security gates** (CI, design-time, structural) be
   added so that a class of bug is caught before merge rather than by review or
   in production?
2. How should the project **test for security gaps** rather than only testing
   the happy path?
3. What **vulnerability vectors** should the project name explicitly and control
   on purpose — through CI jobs, design documents, and penetration testing?

It deliberately does not re-derive the threat model already captured in
`security.md`. That document, ADR 0017 (Security Context), and ADR 0002 (OPA)
are the substrate; this review builds on them.

## 2. Assessment of the current posture

The core authorization design is strong and, in the areas that have already been
attacked, well defended:

- **The load-bearing invariant is correct and enforced in depth.** Security
  decisions key on the immutable authentication chain
  (`sc.authentication_context()`), never on the attacker-influenceable token
  scope (`security.md` §2, invariants I1–I2). The scope-drift tripwire (I3) is
  enforced _twice_ — once in Rego per delegated policy and once in Rust in
  `TryFrom<&ValidatedSecurityContext> for Credentials`
  (`crates/core/src/policy.rs`), so a future policy that forgets the Rego
  assertion still fails closed.
- **Two-phase validation is structurally sound.** A handler can only ever
  observe a `ValidatedSecurityContext`, obtainable in production solely via
  `new_for_scope()`; `Deref`-only, no `DerefMut`, `pub(crate)` fields, and
  `#[cfg]`-gated test constructors mean an unresolved or mutated context is
  unreachable from an endpoint (ADR 0017).
- **The highest-risk path is explicitly modeled.** EC2-credential redemption
  reconstructing a delegated chain onto a bare project scope (I4/I6,
  OSSA-2026-005 / CVE-2026-33551) is documented down to the individual match
  arm, with the token round-trip regression (`from_security_context` falling
  through to `ProjectScopePayload`) called out and covered.
- **Advisories map to invariants.** `security.md` §8 ties each hardening back to
  a real CVE/OSSA, which is exactly the discipline that prevents regression.

The gaps below are therefore not "the design is wrong." They are "the design
depends on humans remembering a checklist, and the checklist is not yet
mechanically enforced," plus a handful of named surfaces that are documented as
open or are newly proposed.

## 3. Vulnerability vectors to control explicitly

Each vector lists the **attack**, the **current state**, and the **control** the
project should commit to (gate / design / pentest). Priority is the review's
opinion, not a mandate.

### V1 — Delegation boundary escape via rescope/reauth (P1, mitigated, keep proving it)

**Attack.** A delegated caller (trust, app-cred, or EC2 credential minted under
one) rescopes or reauthenticates to influence the token scope and act outside
the delegation's fixed project or role set. This is the scope-bind escape class
(OSSA-2026-015, OSSA-2026-005).

**Current state.** Defended by I1–I5. The residual risk is not the existing code
— it is _the next change_. The defense is spread across
`validate_scope_boundaries()`, `calculate_effective_roles()`,
`from_security_context()`, `build_authz_info_from_fernet_token()`, and
`Credentials::try_from`. A change that touches one and forgets another reopens
the class, exactly as the `from_security_context` → `ProjectScopePayload`
fall-through nearly did (I4 history).

**Control.**

- _Testing:_ make the delegation-bound property a **matrix test** that is
  generated, not hand-written — every
  `(AuthenticationContext variant) × (ScopeInfo variant) × (restricted / unrestricted delegation)`
  cell asserted end-to-end through `new_for_scope()`, with the invariant
  "effective roles ⊆ delegation role set" checked mechanically.
  `test_new_for_scope_delegated_roles_never_exceed_delegation_matrix` is the
  seed; the gate is that adding a variant to either enum without adding its row
  fails to compile or fails the test (see Gate D, §4).
- _Design:_ keep V1's controls anchored on `delegated_project_id` (chain), and
  keep the Rust tripwire as the catch-all backstop.

### V2 — Incomplete fan-out on a new auth method or scope shape (P1, structural)

**Attack.** Not an external attacker per se — a contributor adds an auth method
or `ScopeInfo` variant and updates 6 of the 7 places that must change (ADR 0017
lists them). The missed one silently widens authority.

**Current state.** Partially compile-enforced: exhaustive `match` on
`AuthenticationContext` / `ScopeInfo` forces _some_ arms. But projections that
use a catch-all `_ =>` arm (as `Credentials::try_from` does for the
non-delegated cases) or a fall-through default (the `from_security_context` bug)
are **not** caught by the compiler.

**Control.**

- _Design gate:_ forbid wildcard `_ =>` arms in the security-critical
  projections (`Credentials::try_from`, `from_security_context`,
  `build_authz_info_from_fernet_token`, `validate_scope_boundaries`,
  `calculate_effective_roles`). Require every variant named explicitly so a new
  variant is a compile error, not a silent default. Encode as a clippy
  `wildcard_enum_match_arm` allow-list scoped to those files, or a review
  checklist item promoted to a grep-based CI lint (Gate J).
- _Testing:_ the V1 matrix (Gate D) doubles as V2's coverage — a new variant
  with no matrix row is a visible hole.

### V3 — OPA policy correctness, coverage, and fail-open (P1)

**Attack.** A policy is missing, references the wrong input field, hits the Rego
"undefined argument poisons the function" trap (`security.md` I2), or the
handler never calls `enforce()` at all. Any of these is an authz bypass that no
Rust type catches.

**Current state.**

- `opa test policy` runs, but only in `policy-container.yml`, gated on
  `paths: policy/**`. **A Rust-only change that alters which `policy_name` a
  handler enforces, or changes the `Credentials` projection, does not trigger
  the policy test suite.** The two halves of the authz decision are tested in
  separate CI jobs that never both run on a cross-cutting PR.
- `opa fmt --check` runs in `linters.yml`, but formatting is not correctness.
- There is no gate asserting **every enforced `policy_name` has a matching
  `.rego` rule and a `_test.rego`**, nor that **every CRUD handler calls
  `enforce()`**. CLAUDE.md requires ">=3 tests per CRUD handler" and the ">=1
  negative policy test" convention, but nothing enforces it mechanically (a
  `grep -rL enforce` over `v3` today returns only `auth/token/create.rs`, which
  is fine — but nothing keeps it that way).
- Fail-closed on OPA error looks correct (`PolicyError` → `forbidden()`), but
  there is no explicit test that an OPA outage / malformed response / timeout
  yields deny, not allow.

**Control.**

- _Gate A:_ run `opa test policy` in the **main** `ci.yml` matrix (OPA is
  already installed there for the API tests), unconditionally, so a Rust PR that
  changes enforcement is gated by policy tests too.
- _Gate B (coverage checker):_ a small CI script that (1) extracts every
  `enforce("<name>", …)` string literal from the handlers, (2) asserts a
  `policy/**/<name>.rego` rule and a sibling `_test.rego` exist, and (3) asserts
  every handler module implementing a CRUD verb contains an `enforce` call. Fail
  the build on any orphan in either direction.
- _Gate E (Rego footgun lint):_ a `conftest`/`opa`-based check (or a regex gate)
  that flags delegated-policy helpers called with a bare
  `input.target.<x>.project_id` instead of `object.get(..., null)` — the exact
  trap `security.md` I2 warns about, where an `undefined` argument makes even
  the "not delegated" fast path undefined.
- _Testing:_ add an explicit "OPA unreachable / returns garbage → request
  denied" integration test.

### V3a — The handler→policy input-contract seam is untested (P1)

**Attack.** This is the sharpest and most under-appreciated form of V3, and it
is worth calling out on its own. The authorization decision is `policy(input)`,
where `input = {credentials, target, existing}` is assembled in
`HttpPolicyEnforcer::enforce` (`crates/keystone/src/policy.rs:118`). Only the
**`credentials`** half comes from a tested projection (`Credentials::try_from` +
the Rust tripwire). The **`target`, `existing`, and `policy_name`** are chosen
by each handler, by hand, and the correctness of that choice is asserted nowhere
systematic. A handler that:

- picks the wrong `policy_name` (evaluates `…/show` logic on a `delete`),
- keys the object under the wrong resource name (ADR 0002 mandates
  `{"target": {"<resource>": obj}}`; a typo makes every
  `input.target.<resource>.…` lookup `undefined`, and an `undefined`-driven Rego
  rule can silently allow),
- puts the stored object in `target` instead of `existing` on an update (so an
  ownership check reads the attacker's patch instead of the current row),
- or forgets to strip a secret (I7),

produces a _well-formed request to a correct policy that nonetheless decides on
the wrong document_. `opa test policy` cannot catch this — it tests the policy
against **hand-authored** input that matches the intended contract, not the
input the handler actually emits.

**Current state.** Three layers exist; only two are tested.

| Layer                                                                                         | Tested today                                                 |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Rego logic in isolation                                                                       | ✅ `opa test policy` (synthetic input)                       |
| `credentials` (chain) projection                                                              | ✅ `Credentials::try_from` tests + Rust scope-drift tripwire |
| Handler-built `target`/`existing`/`policy_name`, and its **composition** with the real policy | ❌ ad-hoc mock captures only                                 |

The seam is exercised only two ways today, neither sufficient:

- **Ad-hoc mock capture.** A handler test may inject `MockPolicy` and assert on
  the captured arguments — e.g. `test_create_policy_input_omits_password`
  (`crates/keystone/src/api/v4/user/create.rs`) checks `existing.is_none()` and
  that the password is absent from `target`. This is exactly the right idea, but
  it is **opt-in and sparse**: it exists where an author remembered it. The
  delegation-sensitive credential handlers
  (`credential/{create,show,update,delete,list}`, the OSSA-2026-015 surface)
  ship an **empty `#[cfg(test)] mod tests {}`** and assert nothing at the seam.
  And a mock, by construction, **short-circuits the real Rego** — it proves "the
  handler built shape X," never "policy P decides correctly on shape X."
- **Implicit API tests.** `test_api` runs a real OPA, but asserts functional /
  HTTP outcomes; it is not an authorization test suite — it does not sweep
  actor×target authorization matrices, and it does not isolate the input
  contract, so a handler that feeds OPA a subtly-wrong document but still
  returns the expected status on the happy path passes.

**Control.** Split the coverage gate (Gate B) into three graduated levels and
make the seam a first-class, non-opt-in test target:

- _Gate B2 (input-contract harness)._ Provide one shared capturing test enforcer
  (a `PolicyEnforcer` double that records every
  `(policy_name, target, existing)`) with a **standard, uniform** assertion set
  applied to every handler, not re-derived per test:
  1. `policy_name` is a member of the known policy set **and** resolves to an
     existing `.rego` (ties to Gate B1);
  2. `target` (and `existing`, when present) is a JSON object whose single outer
     key equals the endpoint's expected resource name (ADR 0002 contract), so a
     mis-key is a test failure, not an `undefined` at runtime;
  3. operation/slot correctness: create/show/delete/list pass `existing: None`;
     update passes `existing: Some(stored)` **and** `target: patch` (never
     swapped);
  4. secret-free: no denylisted field (`blob`, `password`, `*_secret`, TOTP
     seed, token) appears anywhere in `target`/`existing` — the generalized,
     mechanically-checked form of I7. Drive it as a **route-sweep**: enumerate
     the registered routes and push a request through each, so a newly-added
     handler is covered automatically and a handler that never calls `enforce()`
     is a visible failure. This is the piece that converts "someone remembered
     to assert the shape" into "the shape is always asserted."
- _Gate B3 (composition / decision test)._ Evaluate the _handler-produced_ input
  against the _real_ `policy/` bundle, so the test asserts an actual allow/deny
  — the layer a mock can never reach. Today only `HttpPolicyEnforcer` exists
  (OPA over HTTP/unix socket); to make this usable in handler-level and
  `test_api` tests without a hand-maintained live server, add a `PolicyEnforcer`
  implementation that evaluates the compiled bundle **in-process** (OPA already
  compiles a bundle in `policy-container.yml`; `opa build -t wasm` + an
  in-process wasm evaluator, or a managed `opa eval` subprocess, are the two
  options). With that in place, write a dedicated **authorization matrix** per
  endpoint — authorized actor → allow, unauthorized → deny, cross-domain → deny,
  delegated-escape → deny — driven through the real handler and the real policy.
  This is the suite that "targets authorization checks," as distinct from the
  functional API tests that do not.

Gate B1 (existence) is cheap and should land first; B2 (contract) is the highest
value-to-effort item for this specific gap and needs only a shared harness plus
the route sweep; B3 (composition) is the strongest but carries the
in-process-evaluator design cost and can follow.

### V4 — OPA policy-bundle supply chain (P2)

**Attack.** The authorization logic is shipped as an OCI artifact
(`opa build … --bundle` → `oras push ghcr.io/…/opa-bundle:latest`,
`policy-container.yml`). Whatever the running Keystone loads _is_ the policy. If
the bundle can be tampered with in the registry, or a stale/rolled-back `latest`
is pulled, every authz decision is attacker-defined — without touching
Keystone's code or the `policy/` tree.

**Current state.** The bundle is pushed unsigned; there is no evidence of
signature generation or of verification at load time. `latest` is mutable.

**Control.**

- _Gate H:_ sign the bundle at publish (cosign / Sigstore keyless, which fits
  the existing `id-token: write` permission already present in the publish job)
  and **verify the signature + digest at bundle load** in Keystone. Pin by
  digest, not `latest`, in deployment config.
- _Design:_ document the policy bundle as a first-class trust boundary in
  `security.md` (today it is implicit) — the running policy is as
  security-critical as the binary, and should have the same provenance bar.

### V5 — Application-credential `access_rules` unenforced at request time (P1, live gap)

**Attack.** An operator creates a restricted app-cred with `access_rules`
limiting it to, say, `GET /v3/servers`. The rules are stored and CRUD'd
(`crates/core-types/src/application_credential/…`, `appcred-driver-sql`) but
**no middleware matches the incoming (service, method, path) against them**, so
the credential can call any endpoint. This is documented as an open gap in
`security.md` §5 and §9 — the review flags it as the single highest-impact
_known_ live gap, because it silently converts a control the operator believes
is active into a no-op.

**Current state.** Advisory only, by the project's own admission.

**Control.**

- _Design:_ the ADR the gap already calls for — request-matching middleware
  keyed on the app-cred's stored rules, evaluated before handler dispatch.
- _Gate:_ until enforcement lands, add a **startup/CRUD-time warning** (and a
  doc banner) that `access_rules` are not enforced, so operators are not misled.
  Optionally reject creation of an app-cred with non-empty `access_rules` behind
  a config flag, to fail loud rather than silently accept an unenforceable
  restriction.
- _Testing:_ the enforcement middleware, when built, needs the full
  positive/negative matrix (in-scope call allowed, out-of-scope call denied,
  path/method/service each varied) plus a rescope test (rules survive rescope,
  per V1).

### V6 — Denial of service on unrate-limited cryptographic endpoints (P2)

**Attack.** ADR 0022 phase 1 rate-limits `POST /v3/auth/tokens` by IP (and
optionally per confirmed user). The ADR itself notes that **federation
authenticate endpoints, application-credential flows, EC2 token redemption, and
token validation are not covered** — all perform crypto (signature/hash
verification) and are DoS amplifiers. An attacker hits `/v3/ec2tokens` or an
OIDC `authenticate` endpoint to burn CPU without ever authenticating.

**Current state.** Global-IP limiter merged (phase 1); per-endpoint coverage is
"follow-up ADR TBD." Also note `governor` is per-node in-memory, so effective
limits are N× in an N-replica deployment (documented consequence).

**Control.**

- _Design:_ the promised follow-up ADR extending handler-level limiting to
  federation / app-cred / EC2 / token-validate, with IP governance before the
  crypto step (ADR 0022 Invariant 4, "pre-hash enforcement," generalized to
  "pre-crypto").
- _Testing:_ a load/abuse test per crypto endpoint asserting 429 before the
  expensive path executes; a test that spoofed `X-Forwarded-For` from an
  untrusted peer does not reset the bucket (ADR 0022 Invariant 9).
- _Pentest:_ resource-exhaustion probing of every unauthenticated,
  crypto-bearing endpoint.

### V7 — Dynamic auth plugins: pre-auth attack surface (P1 when implemented, ADR 0025 is Proposed)

**Attack.** ADR 0025 introduces WASM auth plugins invoked _pre-authentication_
by definition — a remote, unauthenticated party triggers plugin execution and
its `http_fetch` calls at will. Named sub-vectors from the ADR's own threat
model:

- **SSRF** via `http_fetch` (DNS-rebinding / connect-time IP re-validation
  against `allowed_hosts`).
- **Claims injection**: a plugin's response claims shadowing a
  privilege-relevant field — mitigated structurally by outer-keying under
  `plugin_claims.<plugin_name>` (visible already in `Credentials`,
  `crates/core/src/policy.rs`) and a reserved-key denylist.
- **Identity-binding bypass**: a `find_user` that does an unscoped lookup would
  be a full account-takeover; the ADR binds to a per-plugin
  `(plugin_name, external_id)` namespace precisely to prevent it.
- **`route`-mode observation surface**: a router sees raw credential material
  for a _larger_ slice of traffic than any other plugin.
- **Resource exhaustion**: fuel/deadline/memory caps + per-source-IP token
  bucket.

**Current state.** Design-stage; `AuthenticationContext::WasmPlugin` and
`plugin_claims` projection already exist in the tree, so partial plumbing has
landed ahead of the full mechanism.

**Control.**

- _Design:_ ADR 0025 is unusually thorough — the review's ask is that its §4–§7
  controls each land with a **test that exercises the failure**, not just the
  intended path (SSRF to a rebinding host is blocked; a fabricated
  `ResolvedIdentityHandle` is rejected; a claim named `is_system` is dropped; a
  `route` target off the allowlist is rejected).
- _Gate:_ fuzz the host↔guest JSON boundary (`AuthPluginRequest` /
  `AuthPluginResponse` / `RouteResponse`) — untrusted guest output parsed by the
  host is a classic memory/logic sink. Add a CI gate that the reserved header
  denylist (`Authorization`, `Cookie`, `X-Auth-Token`, …) cannot be named in
  `exposed_headers` (config-load rejection), tested directly.
- _Pentest:_ treat the plugin invocation path as an internet-facing,
  unauthenticated endpoint — SSRF, request smuggling into `route` targets, and
  rate-limit bypass are the priority scenarios.

### V8 — OAuth2/OIDC provider role (P2, ADR 0026 implemented; status field still says Proposed)

**Attack.** Acting as an OAuth2/OIDC _provider_ adds the classic web-authz
surface Keystone did not previously have: open-redirect via `redirect_uri`,
authorization-code interception without PKCE, CSRF on the consent flow,
clickjacking, refresh-token replay.

**Current state.** ADR 0026's controls are implemented, not just specified:
exact-match `redirect_uris` (wildcards rejected) with unregistered-`redirect_uri`
errors rendered directly rather than redirected (`authorize.rs:294-302`,
correct open-redirect defense), mandatory `S256` PKCE (`pkce.rs`), HTTPS-only
confidential clients, refresh-token rotation with reuse-triggers-family-revoke
(§13). Verified 2026-07-16 with a dedicated read of `token.rs`, `authorize.rs`,
`device.rs`, `crypto.rs`, `pkce.rs` — see V8a below for the enumeration/timing
sub-review this triggered.

**Control.**

- _Testing:_ a negative test per web-authz vector — non-matching `redirect_uri`
  rejected, `plain` PKCE rejected, missing `code_verifier` rejected, reused
  authorization code rejected, rotated refresh token's predecessor invalidated.
- _Pentest:_ standard OAuth2 provider test suite (redirect handling, PKCE
  downgrade, mix-up, token substitution).

### V8a — OAuth2 client enumeration, timing side-channels, and credential-probing (fixed 2026-07-16; P1 device-flow rate-limit gap closed)

**Attack.** Prompted by public research on "OAuth client ID spoofing"
(Proofpoint, July 2026: attackers validate stolen Entra ID credentials at
scale by presenting spoofed/arbitrary `client_id`s to a token endpoint that
distinguishes valid from invalid client IDs, checking passwords without a
successful sign-in ever being logged against a real, registered application —
and without needing that application to actually exist). The generalizable
attack classes are: (a) distinguish "unknown client_id" from "wrong secret"
by response content, status, or timing; (b) probe usernames/passwords through
an endpoint that doesn't require a real, pre-registered relying party; (c)
brute-force short human-facing codes (device `user_code`) with no throttle.

**Current state — verified by direct code read, 2026-07-16.**

| Sub-vector | Verdict | Evidence |
| --- | --- | --- |
| `client_credentials`/`authorization_code`/`refresh_token`/token-exchange: unknown client_id vs. wrong secret vs. disabled client, by response | Mitigated | `token.rs:376-448` (`client_credentials`), `:580-638` (`authenticate_client`, shared by the other three grants) — `get_by_client_id` runs unconditionally; every rejection branch (unknown `:396`, disabled/deleted `:403,605`, no secret `:419,425`) calls `crypto::generate_dummy_hash()` before returning the same `401 invalid_client` / `"client authentication failed"` body as a real wrong-secret rejection (`:437-448`, `:617-621`) |
| Argon2id timing (unknown client vs. known client, wrong secret) | Mitigated (defense-in-depth, residual accepted) | `crypto.rs:81-107` — `generate_dummy_hash()` performs a real Argon2id **hash** (not a cheap early-return) with the same configured cost params as `verify_secret()`'s **verify**; hash and verify are comparable-cost Argon2id operations but not byte-identical code paths, and the DB lookup itself is faster for an unknown client_id than a known one. This residual gap is explicitly called out in-code (`token.rs:387-395`) and bounded by the pre-hash, raw-client_id-keyed rate limiter (`token.rs:367-373`, checked *before* the DB lookup) |
| `client_credentials` grant: existence+grant-type oracle | **Fixed** | `token.rs` now checks `grant_types.contains(ClientCredentials)` **after** secret verification (moved below the `verify_secret`/`generate_dummy_hash` block), matching the shared `authenticate_client()` posture used by the other three grants. Covered by the existing `test_client_without_client_credentials_grant_is_unauthorized_client` |
| `/authorize`: unknown client_id vs. unregistered `redirect_uri` | Not vulnerable (by design) | `authorize.rs:257-302` — messages differ ("unknown or disabled client" vs. "redirect_uri is not registered"), but `client_id` is intentionally public (RFC 6749 §2.2) and client registration is admin/Tier-1/Tier-2-gated per domain (ADR 0020), not a global self-service namespace an outsider can probe cross-tenant the way Entra's is — the precondition that makes Entra's spoofing technique work (any `client_id`, from any tenant, reaches a password check without being registered) does not exist here: every `client_id` presented anywhere must already be a real `OAuth2Client` row in that domain |
| Human login (`/authorize/login`, `/device/login`): username enumeration | Mitigated | `authorize.rs:470-521` — uniform `"invalid username or password"` on both bad-request-shape and `authenticate_by_password` failure; ADR 0010's per-user throttle applies inside `authenticate_by_password` itself regardless of entry point |
| **`/device`, `/device/login`, `/device_authorization`: per-IP rate limiting** | **Fixed** | `device.rs`'s `device_login_code` (user_code submission) and `device_login` (password check) and `device_authorization.rs`'s `device_authorization` now call `state.rate_limiters.check_ip()` before any DB lookup or password hashing, mirroring `authorize.rs`'s `/authorize`/`/authorize/login` posture exactly. `/device/consent` intentionally left unguarded, mirroring `authorize_consent`'s precedent (only reachable with an already-authenticated session, so it carries no unauthenticated probing surface of its own). Covered by new tests `test_device_submit_code_rate_limited_by_ip_before_lookup`, `test_device_login_rate_limited_by_ip_before_password_check` (`device.rs`) and `test_rate_limit_returns_429_before_client_lookup` (`device_authorization.rs`) |
| Refresh token lookup | Not vulnerable | `oauth2_session/service.rs:70-73,275-287` — lookup key is `SHA-256(bearer)`, an indexed equality read, not a raw-value or prefix comparison; no partial-match timing leak |

**Control (implemented 2026-07-16).**

- Per-IP `check_ip` rate limiting, identical to `/authorize`/`/authorize/login`'s,
  now gates `/device_authorization`, `/device`, and `/device/login`, applied
  before any DB lookup or password hashing — closing the one concrete gap
  this review found; everything else in the OAuth2 provider was already
  either spec-correct-by-design or carrying a matching defense.
- `handle_client_credentials_grant` (`token.rs`) now checks `grant_types`
  after secret verification, so it matches the uniform-response posture of
  the other three grant handlers.
- _Testing:_ negative tests asserting `429` under burst-exhaustion now exist
  for `/device`, `/device/login`, `/device_authorization`, alongside the
  pre-existing `/authorize`/`/token` coverage.
- _Design:_ V6's "endpoints not yet covered by rate limiting" list (ADR 0022
  follow-up) should still be updated to note the device-flow browser
  endpoints are now covered, alongside the federation/app-cred/EC2/
  token-validate endpoints that remain open.
- _Pentest:_ password-spray `/device/login` across many usernames from a
  single IP; brute-force `/device` `user_code` guessing at volume; attempt to
  reach a password check via any `client_id` value without it being a
  pre-registered `OAuth2Client` row (expected: impossible, confirm it stays
  that way) — all should now hit `429` after one request under a tight burst
  config, matching `/authorize`'s behavior.

### V9 — Secret leakage into policy input, logs, and audit (P2, mitigated)

**Attack.** Decrypted credential blobs (EC2 secret keys, TOTP seeds) reaching
OPA (which logs decisions) or the CADF audit trail.

**Current state.** I7 strips the blob in `credential_policy_input()`; secrets
are now wrapped with the `secrecy` crate (recent commit `b35ca42`). Good.

**Control.**

- _Gate I:_ a structural test that serializes a `Credentials` / policy-input
  object built from a secret-bearing credential and asserts the secret bytes do
  not appear in the JSON — run in CI so a future field addition that
  re-introduces a blob is caught. Extend the same assertion to the audit event
  payload (ADR 0023) and to error `Display` impls.
- _Design:_ document "no secret in policy input / audit / logs / error strings"
  as a named invariant (I7 covers policy input; generalize it).

### V10 — Token lifecycle: revocation and version binding (P2)

**Attack.** A token outliving the authority it was minted under — a role
removed, a trust deleted, a plugin patched to fix a bug, an identity link
revoked. If validation trusts the token's frozen claims over live state, the
window stays open.

**Current state.** `authorize_by_token` re-expands and re-resolves roles against
live assignments and checks revocation (ADR 0017); ADR 0025 adds `plugin_sha256`
version-binding and bulk `revoke_all`. The design is revocation-aware.

**Control.**

- _Testing:_ property test — "role removed at time T ⇒ token issued before T
  cannot exercise that role after T," across each scope shape; likewise trust
  deletion and app-cred expiry mid-token-lifetime.
- _Pentest:_ revocation-window probing.

## 4. Preemptive security gates to add (CI + design)

Summary of the gates referenced above, ordered by value-to-effort. All are
additive to the existing pipeline (`ci.yml`, `linters.yml`, `audit.yml`,
`policy-container.yml`).

| Gate   | What it does                                                                                                                                                                                                           | Catches                                                                                                         | Effort   |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------- |
| **A**  | Run `opa test policy` in main `ci.yml`, not only on `policy/**` paths                                                                                                                                                  | V3 — Rust change that breaks policy enforcement merges green today                                              | Low      |
| **B1** | Policy↔handler _existence_ checker (every `enforce(name)` ⇒ `.rego` + `_test.rego`; every CRUD handler ⇒ `enforce`)                                                                                                    | V3 — missing policy, orphan policy, unenforced handler                                                          | Low      |
| **B2** | Handler→policy _input-contract_ harness: a shared capturing enforcer + route-sweep asserting resource-key correctness, target/existing slotting, and secret-free input, on every handler automatically                 | V3a — wrong `policy_name`, mis-keyed resource, target/existing swap, secret leak — none caught by `opa test`    | Med      |
| **B3** | Handler→policy _composition_ test: an in-process real-Rego enforcer feeding handler-built input to the actual bundle, plus a per-endpoint authorization matrix (authorized/unauthorized/cross-domain/delegated-escape) | V3a — handler feeds a subtly-wrong document that a mock accepts but the real policy would decide differently on | Med/High |
| **C**  | Invariant-test presence check: every delegated-auth policy carries a scope-drift negative case; every new scope/auth arm has a matrix row                                                                              | V1/V2 — silent boundary regression                                                                              | Med      |
| **D**  | Generated `(auth method × scope × restricted?)` matrix test through `new_for_scope()` with "roles ⊆ delegation" assertion                                                                                              | V1/V2 — the I4 near-miss class                                                                                  | Med      |
| **E**  | Rego lint for the undefined-argument footgun (`object.get(…, null)` required for delegated helper args)                                                                                                                | V3 — I2 trap                                                                                                    | Low      |
| **F**  | Fuzz `Credentials::try_from`, Fernet token decode, and (when built) the WASM host↔guest JSON boundary                                                                                                                  | V1/V7 — malformed-input logic bugs                                                                              | Med      |
| **G**  | Mutation testing (`cargo-mutants`) scoped to `core`/`core-types` auth+policy modules, to prove the negative tests actually fail on a regression                                                                        | all — verifies the tests have teeth                                                                             | Med      |
| **H**  | Sign the OPA policy bundle (cosign) + verify signature/digest at load                                                                                                                                                  | V4 — policy supply chain                                                                                        | Med      |
| **I**  | Structural "no secret in policy input / audit / error string" serialization test                                                                                                                                       | V9                                                                                                              | Low      |
| **J**  | Grep-based SAST encoding the `security.md` §7 checklist (e.g. flag `credentials.project_id` used as a delegation boundary; flag wildcard `_ =>` in the 5 critical projections)                                         | V1/V2                                                                                                           | Low      |

The highest-leverage items are **A**, **B1**, and **B2**. A and B1 close the
structural blind spot where the Rust half and the Rego half of an authorization
decision are validated by different CI jobs that don't both run on a
cross-cutting PR. **B2** closes the seam that neither `opa test` nor the
existing handler mocks cover: whether the handler actually _feeds the policy the
right document_ (V3a). Together they remove the ways an authz bypass can merge
green; B3 then upgrades from "the input shape is right" to "the real policy
decides right on that input," and everything else hardens an already-good
position.

### Design-time gates (not CI)

- **Promote the `security.md` §7 reviewer checklist into a required PR template
  section** for any diff touching auth/scope/delegation/token/policy, with the
  reviewer ticking each invariant. It exists as prose today; make it a gate on
  the PR.
- **Name new trust boundaries in `security.md` as they appear**: the OPA policy
  bundle (V4), the WASM plugin invocation path (V7), and the OAuth2 provider
  surface (V8) are all boundaries the current §3 diagram does not draw.

## 5. Testing strategy for security gaps

The project already tests the happy path well and has good negative coverage in
the hot spots. To find _gaps_ rather than confirm _behavior_:

1. **Negative-test-first, mechanically required.** `security.md` §7 already asks
   "are there negative tests proving the escape is blocked?" Gate C makes it
   non-optional for delegated policies and new scope shapes.
2. **Property-based invariants over example-based cases.** Encode the security
   properties as properties, not fixtures:
   - _Delegation monotonicity:_ for any rescope/reauth sequence, effective roles
     never exceed the original delegation's role set.
   - _Scope pinning:_ `delegated_project_id == project_id` holds for every
     delegated `Credentials` the projection can produce (the tripwire, as a
     property, not just a per-policy assertion).
   - _Revocation:_ authority removed at T is unusable after T (V10). Use
     `proptest` to search the input space around these.
3. **Matrix/exhaustiveness tests tied to the enums** (Gate D) so coverage grows
   automatically with the type system. 3a. **Test the handler→policy input
   contract and its composition, not just the policy** (Gates B2/B3, vector
   V3a). `opa test policy` proves the policy is right on the _intended_ input;
   it says nothing about whether the handler emits that input. Assert the
   emitted `(policy_name, target, existing)` uniformly across every handler
   (B2), and — separately from the functional API tests — run a dedicated
   **authorization matrix** (authorized / unauthorized / cross-domain /
   delegated-escape actors per endpoint) through the real handler _and_ the real
   policy (B3). Functional API tests that assert HTTP status on the happy path
   are not authorization tests and must not be counted as such.
4. **Differential testing against Python Keystone.** CI already installs
   `pip install keystone` for cross-verification — extend it to
   authorization-decision differentials on the delegated paths, so a divergence
   from the reference implementation's allow/deny is visible.
5. **Mutation testing** (Gate G) to confirm the negative tests fail when the
   invariant is broken — a negative test that still passes after you delete the
   check is worse than none.
6. **Fuzzing** the untrusted-input parsers (Gate F): Fernet decode, the OPA
   response deserializer, and the WASM boundary.

## 6. Penetration testing targets

A pentest engagement should be handed this prioritized scenario list rather than
"test Keystone." Each maps to a vector above.

1. **Delegation escape (V1).** Mint a restricted app-cred / trust, mint an EC2
   credential under it, redeem at `/v3/ec2tokens`, then rescope/reauth the
   resulting token every way the API allows; assert roles never exceed the
   delegation and scope never leaves the delegation project. This is the
   crown-jewel scenario and maps directly to OSSA-2026-005/015.
2. **List leakage (I8, CVE-2019-19687).** For every list endpoint, confirm
   per-item re-check drops rows the caller cannot individually read.
3. **OPA bypass / supply chain (V3/V4).** Attempt to reach a handler whose
   policy is missing or misnamed; test behavior when OPA is unreachable; assess
   bundle provenance.
4. **Pre-auth DoS (V6).** Resource-exhaust every unauthenticated crypto
   endpoint; attempt `X-Forwarded-For` spoofing to defeat per-IP limits.
5. **App-cred `access_rules` (V5).** Confirm the currently-unenforced state, and
   re-test once middleware lands.
6. **WASM plugins (V7)** and **OAuth2 provider (V8)** — full dedicated suites
   when those features ship; treat both as internet-facing pre-auth surfaces.
7. **Token lifecycle (V10).** Revocation-window and version-binding probing.
8. **OAuth2 device-flow rate limiting (V8a, fixed 2026-07-16).** Password-spray
   `/device/login` from a single IP across many usernames; brute-force
   `/device` `user_code` guessing at volume — both should now hit `429`
   after burst exhaustion; re-verify this holds after any future change to
   `device.rs`/`device_authorization.rs`.

## 7. Prioritized recommendation

If the project adopts nothing else from this review:

1. **Gate A + Gate B1 + Gate B2** (§4) — close the split-CI authz blind spot
   _and_ the untested handler→policy input contract (V3a). A + B1 are low
   effort; B2 needs only a shared capturing enforcer and a route sweep, and is
   the single highest value-to-effort item because it makes "the handler feeds
   the policy the right document" a mechanical, non-opt-in test on every handler
   — which `opa test` and the current mocks do not.
2. **Ship `access_rules` enforcement or fail loud** (V5) — the highest-impact
   _known_ live gap; today a control operators trust is a no-op.
3. ~~Rate-limit the OAuth2 device-flow browser endpoints (V8a)~~ — **done
   2026-07-16**: `/device`, `/device/login`, `/device_authorization` now
   carry the same per-IP throttle as `/authorize`/`/token`.
4. **Gate D matrix + Gate G mutation testing** (V1/V2) — convert the "remembered
   checklist" defense of the delegation boundary into a structural one.
5. **Sign the policy bundle** (V4) — the running policy deserves the same
   provenance bar as the binary.

The rest (rate-limit coverage, plugin/OAuth2 test suites, secret-leak structural
tests) should land alongside the features they protect, with the
failure-exercising tests treated as part of the feature's definition of done,
not a follow-up.
