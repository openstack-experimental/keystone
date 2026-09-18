# OAuth2 / OIDC Provider: Production Readiness Audit

Status: audit performed 2026-09-18 against `main` by direct code read of
`crates/keystone/src/api/v4/oauth2/`, `crates/core/src/oauth2_{client,key,session}/`,
`crates/oauth2-*-driver-raft/`, `crates/config/src/oauth2.rs`, `policy/oauth2/`,
`tests/{api,integration,loadtest}`, and the three OAuth2 documents
([ADR 0026](../adr/0026-oauth2-oidc-provider.md),
[ADR 0028](../adr/0028-oauth2-quorum-bypass-emergency-rotation.md),
[admin guide](../admin/features/oauth2.md), [user guide](../user/features/oauth2.md)).
Companion to [Security architecture review](security-review.md) §V8/V8a, which
covered enumeration and timing side channels and is **not** repeated here.

Disclaimer: this audit was performed by Claude Fable model with human
direction. Every finding cites the file and line it was verified against.

## 0. Verdict at a glance

| Surface                                          | Readiness                | Blocking reason                                                                                                            |
| ------------------------------------------------ | ------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `client_credentials` (machine identity)          | **Pilot-ready**          | Works end to end, offline-verifiable (`tests/integration/src/oauth2_token_verify.rs`). No revocation short of key rotation. |
| RFC 8693 token exchange                          | **Pilot-ready**          | Same posture as `client_credentials`; `AppCred` only.                                                                       |
| `authorization_code` + PKCE (browser login)      | **Not production-ready** | `openstack:api` rejected (F-B1); no `userinfo`, `profile`/`email` claims never populated (F-B2); no revocation (F-A1).       |
| RFC 8628 device grant (CLI login)                | **Not production-ready** | Same as above: the flow works but can only mint identity-only tokens no OpenStack service, including Keystone, accepts.     |
| Refresh tokens                                   | **Not production-ready** | Not revocable by user, operator, or client deletion (F-A1..A4); cross-client presentation spends the victim's token (F-D1). |
| Signing-key lifecycle                            | **Production-ready**     | Rotation, emergency rotation, quorum-bypass, janitor all built and integration-tested. Automatic time-based rotation is not (F-G1). |
| Browser UI                                       | **Not production-ready** | Compile-time embedded, unstyled, no operator customization, password-only login (F-E1..E3).                                 |
| Storage hygiene                                  | **Not production-ready** | Abandoned sessions/codes/grants/refresh tokens are never deleted (F-F1).                                                    |

The single most important structural gap: **the OP has no revocation surface
at all** beyond emergency signing-key rotation. There is no `/revoke`
(RFC 7009), no `/introspect` (RFC 7662), no per-user or per-client refresh
family index, no hook from user/domain lifecycle events, and Keystone's own
API does not accept OP-issued access tokens, so `openstack:api` on the human
grants was never wired.

## 1. Inventory: what exists today

### Endpoints (`crates/keystone/src/api/v4/oauth2/mod.rs`)

| Route                                              | Auth           | Status                                                              |
| -------------------------------------------------- | -------------- | ------------------------------------------------------------------- |
| `GET  /{d}/jwks`                                   | none           | Built. `Cache-Control: max-age=300`.                                 |
| `GET  /{d}/jwks/revocation`                        | none           | Built. JTI list, emergency-rotation only, `max-age=60`.              |
| `GET  /{d}/.well-known/openid-configuration`       | none           | Built. Incomplete/inaccurate (F-C1).                                 |
| `POST /{d}/token`                                  | client secret  | Built: 5 grants (`client_credentials`, `authorization_code`, `refresh_token`, `device_code`, token exchange). |
| `GET  /{d}/authorize`, `POST .../login`, `.../consent` | cookie+CSRF | Built. Display scopes only.                                          |
| `POST /{d}/device_authorization`                   | none           | Built.                                                               |
| `GET/POST /{d}/device`, `POST .../login`, `.../consent` | cookie+CSRF | Built.                                                              |
| `/{d}/clients` CRUD + `rotate-secret`              | Keystone token | Built. Rego policies + tests for all six actions.                    |
| Key admin: `rotate-signing-key`, `confirm-…`, `ensure-signing-key`, `local-emergency-candidates`, `reconcile-…` | admin UDS/SPIFFE | Built. CLI in `crates/cli-manage/src/oauth2/`. |
| `POST /{d}/revoke` (RFC 7009)                      |                | **Missing**                                                          |
| `POST /{d}/introspect` (RFC 7662)                  |                | **Missing**                                                          |
| `GET/POST /{d}/userinfo` (OIDC Core §5.3)          |                | **Missing** (but referenced by the user guide, F-G3)                 |
| `GET /{d}/logout` / `end_session_endpoint`         |                | **Missing**                                                          |
| RFC 7591 dynamic registration, RFC 9126 PAR, RFC 9449 DPoP |         | Missing; ADR defers DPoP to v1.5, others never mentioned.            |

### Storage (`crates/oauth2-session-driver-raft/src/lib.rs`)

Raft + Fjall keys: `oauth2:session:v1:<id>`, `oauth2:code:v1:<code>`,
`oauth2:refresh:v1:<sha256>`, `oauth2:refresh_family_idx:v1:<family>:<token>`,
`oauth2:device_code:v1:<code>`, `oauth2:device_user_code:v1:<user_code>`.
There is **no** index by `user_id`, `client_id`, or `domain_id`, and no
expiry index. All writes go through `set_value(key, envelope, None, None)`
(`lib.rs:72-83`) with no TTL.

### Tests

| Layer                              | Count | Coverage notes                                                                                                                       |
| ---------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Handler unit tests (`api/v4/oauth2`) | ~93 | Good negative coverage per grant. **No** test for: device-grant path rate limiting, disabled client at device redemption, cross-client refresh presentation, `Cache-Control` on token responses. |
| Core service unit tests            | ~64  | Refresh reuse state machine well covered.                                                                                            |
| Raft driver unit tests             | 47   | CRUD round-trips only.                                                                                                               |
| Rego tests                         | 12   | One `_test.rego` per policy.                                                                                                         |
| Integration (`test_integration`)   | 15   | auth-code+refresh-reuse, device grant, token exchange, offline verify, emergency rotation, janitor.                                    |
| Live API (`test_api`)              | 13   | Device flow, discovery, jwks/revocation only. **No** live test for `client_credentials`, `authorization_code` browser flow, refresh rotation, client CRUD, or key rotation via CLI. |
| Loadtest                           | 6 tx | `jwks`, `well_known`, client CRUD. **No** token-issuing transaction.                                                                 |
| Conformance                        | 0    | No OIDC conformance / third-party RP library interop test.                                                                            |

## 2. Findings

Severity: **P0** blocks any production use of the affected surface; **P1**
must land before general availability; **P2** should land before the surface
is promoted beyond pilots; **P3** hardening/UX.

### A. Revocation and session lifecycle

**F-A1 (P0) No token revocation surface.** There is no RFC 7009 `/revoke`
endpoint, and no internal API that revokes a refresh family by anything
other than reuse detection (`crates/core/src/oauth2_session/service.rs:336-345`).
A user who loses a laptop, an RP that detects compromise, or an operator
offboarding a user has no way to end a refresh family. Combined with F-A2 the
family lives indefinitely.

**F-A2 (P0) Refresh families are idle-renewed forever and never re-check the
user.** `redeem_refresh_token` resets `expires_at` on every rotation
(`service.rs:299-300`) with no absolute lifetime, and
`handle_refresh_token_grant` (`crates/keystone/src/api/v4/oauth2/token.rs:820-950`)
never looks the user up. A user that is disabled, deleted, or has changed
their password keeps refreshing access tokens for as long as the RP keeps
rotating. The v3 Fernet path revokes on these events (ADR 0009); the OP path
regresses that guarantee silently, contrary to ADR 0026 §13's "Revocation
Semantics Parity" gate.

**F-A3 (P0) No user/client/domain index over refresh families.** Storage keys
are hash-of-bearer and family-id only. Even with an endpoint, "revoke all
sessions for user X", "for client Y", or "for domain Z" is a full scan.

**F-A4 (P1) Client deletion does not revoke refresh families.** The admin
guide states "`DELETE` … immediately invalidates all refresh tokens in its
family tree" (`doc/src/admin/features/oauth2.md:92`), and the resource type's
doc comment justifies soft-delete with that walk
(`crates/core-types/src/oauth2_client/resource.rs:111-113`). No such walk
exists: `Oauth2ClientService::delete` is a pass-through
(`crates/core/src/oauth2_client/service.rs:182-191`). Refresh tokens of a
deleted client are only rejected because `authenticate_client` checks
`deleted_at` at redemption time, which is correct but not what is documented,
and leaves the records in Raft forever (F-F1).

**F-A5 (P1) No lifecycle hooks.** `crates/core/src/oauth2_key/hook.rs` handles
only `Domain Create`. There is no `ProviderHooks` listener for `User
Delete/Disable`, `Domain Disable/Delete`, password change, or
`RoleAssignment` removal on the session or key providers. The event bus
already carries these (`crates/core-types/src/events.rs:44-185`), and
`auth_plugin_identity/hook.rs:46` shows the pattern.

**F-A6 (P1) No introspection endpoint.** RFC 7662 `/introspect` is the
ADR's own named mitigation for the "Revocation Durability Gap" (ADR 0026 §11,
§13) and is required for any RP or downstream service that needs
sub-`exp` revocation latency. It also is the natural home for checking the
JTI revocation list without every RP re-implementing the middleware.

**F-A7 (P2) JTI revocation list is emergency-only and manual.** `revoked_jtis`
is populated solely by `confirm_emergency_rotation --revoke-jti`. There is no
way to revoke a single outstanding access token by `jti` outside an emergency
rotation, even though the list and the `verify.rs` check already exist.

### B. Grant and flow gaps against the ADR

**F-B1 (P0) `openstack:api` is rejected on every human grant.** `/authorize`
(`authorize.rs:333-340`), `/device_authorization`
(`device_authorization.rs:134-140`) and `/token` for `authorization_code`
(`token.rs:722-737`) all refuse the scope with "not yet supported". The
consent step collects no project/domain scope, so no
`OpenStackAccessTokenClaims` can be minted for a human. Consequence: the
device grant, which ADR 0026 §13 Stage 4 names as the CLI login path, can
only produce `OidcAccessTokenClaims` with `aud = client_id` that no OpenStack
service accepts. The ADR's Phase 4 deliverable is therefore not met.

**F-B2 (P0) `profile`/`email` scopes are accepted but grant nothing.** The
`id_token` is built with `extra_claims: Default::default()` in every path
(`token.rs:770`, `token.rs:1164`), and there is no `userinfo` endpoint. An RP
requesting `openid profile email` receives only `sub`. `claims_template` is
validated at client save time (`crates/core/src/oauth2_client/service.rs:72`)
but never interpolated anywhere, so ADR 0026 §4 "Claim Safety" is
specification only. "Login with OpenStack" for Grafana/Harbor (ADR §1 use
case) does not work beyond a bare identifier.

**F-B3 (P1) Keystone's own API does not accept OP-issued tokens.** No
extractor in `crates/core/src/api/` or `crates/keystone/src/api/` reads
`Authorization: Bearer <jwt>` except the API-key path
(`crates/core/src/api/api_key_auth.rs:249`). A `client_credentials` token
cannot call `/v3` or `/v4` on Keystone itself, so a machine identity still
needs a Fernet/JWS token for identity operations, reproducing the "Circular
Token Exchange Trap" the ADR set out to remove. The `verify.rs` reference
verifier is a pure function and can back this extractor directly.

**F-B4 (P1) `max_age`, `prompt`, `login_hint`, `id_token_hint`,
`acr_values`, `ui_locales` are not parsed** (`authorize.rs:56-74`). ADR 0026
§8 specifies `max_age` re-authentication as delivered. There is also no
persistent browser SSO session: every `/authorize` demands a fresh password,
so `prompt=none` silent renewal used by SPA libraries is impossible.

**F-B5 (P2) No per-user consent memory.** Consent is asked on every
authorization; there is no stored grant to skip it on repeat visits, and no
user-facing "revoke this application" surface (which F-A1 would need).

**F-B6 (P2) Refresh grant ignores `scope` narrowing** (RFC 6749 §6) and the
device grant ignores `nonce` (`DeviceCodeGrant.nonce` is never set;
`device_authorization.rs` does not read it).

**F-B7 (P2) `token_endpoint_auth_method` and `require_pkce` are stored but
not enforced.** `/token` accepts both Basic and body credentials regardless
of the registered method (`token.rs:247-266`), and PKCE is unconditionally
mandatory, so `require_pkce=false` is a lie in the API. Either enforce or
remove from the API type.

### C. Spec conformance

**F-C1 (P1) Discovery document is inaccurate.** `well_known.rs:105-123`:

- `grant_types_supported` lists `"device_code"`; RFC 8628 §4 requires
  `urn:ietf:params:oauth:grant-type:device_code`. Standard clients will not
  detect the flow. `urn:ietf:params:oauth:grant-type:token-exchange` is
  absent although implemented.
- `device_authorization_endpoint` (RFC 8628 §4) is absent, so `gcloud`-style
  clients cannot discover the flow.
- `code_challenge_methods_supported: ["S256"]` is absent although PKCE is
  mandatory; libraries fall back to `plain`, which the server then rejects.
- `token_endpoint_auth_methods_supported` omits `none` and
  `client_secret_post`, both of which the token endpoint accepts.
- `claims_supported` omits `nonce`, `at_hash`, `jti`, `scope`, `token_use`.
- `revocation_endpoint`, `introspection_endpoint`, `userinfo_endpoint`,
  `end_session_endpoint` are absent (they do not exist yet, F-A/F-B).

**F-C2 (P1) Token and HTML responses lack `Cache-Control: no-store`.** RFC
6749 §5.1 requires `Cache-Control: no-store` (and `Pragma: no-cache`) on
every token response; every success path returns bare `Json`
(`token.rs:535, 815, 950, 1060, 1212`). Login/consent pages carry no
`Cache-Control` either (`html.rs:53-71`), so a shared-proxy or browser
back-cache can retain the CSRF-token-bearing form.

**F-C3 (P2) No `iss` in authorization responses (RFC 9207)** and no
`authorization_response_iss_parameter_supported` in discovery. This is the
standard mix-up defense for a multi-issuer deployment, which a per-domain
issuer is.

**F-C4 (P2) Redirect URI matching for native apps.** RFC 8252 §7.3 requires
loopback redirect URIs to match on any port; `authorize.rs:294` is exact
string match, so a native client must register every ephemeral port.

**F-C5 (P3) Error page for a bad `redirect_uri` is correct** (never
redirects), but `/authorize` errors before `redirect_uri` validation render
HTML with HTTP 400 rather than the RFC 6749 §4.1.2.1 JSON-free page; fine,
recorded for completeness.

### D. Security defects found in this pass

**F-D1 (P1) Cross-client refresh presentation spends the victim's token.**
`handle_refresh_token_grant` calls `redeem_refresh_token` (`token.rs:880`)
before checking `record.client_id != client_id` (`token.rs:908`). Any
registered client that obtains another client's refresh bearer (or a public
client presenting a guessed-impossible but leaked one) rotates the family
leaf: the victim's next legitimate refresh then hits `spent_at`, and outside
the grace window the whole family is revoked as a "breach". The attacker
gets `invalid_grant`, but the outcome is a denial of service on the legitimate
session and a spurious critical audit event. Ownership must be checked before
the rotation write; `Oauth2SessionApi::redeem_refresh_token` should take
`client_id`/`domain_id` and refuse before mutating.

**F-D2 (P1) Device-code polling at `/token` is unthrottled.**
`handle_device_code_grant` (`token.rs:1071-1212`) applies neither the
per-client `oauth2_token_rate_limiter` nor `rate_limiters.check_ip`, unlike
every other grant arm. ADR 0026 §7.C requires per-IP and per-`user_code`
limits with exponential backoff and a 5-minute quiet period on invalid
`device_code`; none is implemented. Security review V8a closed the browser
side (`/device`, `/device/login`) only. `device_code` entropy makes guessing
infeasible, but each poll is an unauthenticated Raft read, and a `Pending`
poll is a Raft **write** (`mark_device_code_grant_polled`).

**F-D3 (P1) Device grant redemption skips the client enabled check.**
`token.rs:1128` binds `let Some(client) = client else` with no
`enabled`/`deleted_at`/`domain_id` filter, unlike `/device_authorization`
(`device_authorization.rs:111-113`). A client disabled or soft-deleted after
the user approved still receives tokens, and a refresh family is created for
it.

**F-D4 (P2) Issuer derives from the `Host` header when `public_endpoint` is
unset** (`crates/keystone/src/api/common.rs:58-88`). Discovery, `iss`, and
`verification_uri` follow whatever `Host` the client sends. The OP should
refuse to serve (or log at startup) when `[default] public_endpoint` is not
configured, and the admin guide should list it as mandatory for the OP.

**F-D5 (P2) Session cookies are `Secure` only when proxy headers are
enabled** (`common.rs:100-112`), so a TLS-terminating deployment without
`enable_proxy_headers_parsing` ships the pre-auth cookie without `Secure`.
Tie this to `public_endpoint`'s scheme as well.

**F-D6 (P2) Audit initiator is `unknown` on successful human grants.**
`authorization_code`, `refresh_token`, and `device_code` success events use
`build_initiator_unknown()` (`token.rs:801, 936, 1198`) even though
`record.user_id` is known. CADF consumers cannot attribute OP logins to users.

**F-D7 (P3) `client_id_for_display` is a no-op** (`device.rs:180-193`,
returns `c.client_id`). Consent and result pages show a UUID, which trains
users to approve opaque identifiers. `OAuth2ClientResource` has no
`name`/`description`/`logo_uri`/`policy_uri`/`tos_uri` (RFC 7591 metadata).

### E. Browser UI

**F-E1 (P1) UI is compile-time embedded and not operator-configurable.**
Templates live in `crates/keystone/templates/oauth2/*.html` and are baked in
by `askama` derive (`html.rs:23-46`). There is no config option for a
template directory, static asset path, logo, product name, or CSS; changing
the login page requires a rebuild. There is no stylesheet at all, and the
`class="error"` hook has nothing to style it.

**F-E2 (P1) Login is password-only; `amr` is hard-coded `["pwd"]`**
(`authorize.rs:703`, `device.rs:435`). TOTP (`authenticate_by_totp`,
`crates/core/src/identity/service.rs:800`) and WebAuthn/passkey
(`crates/webauthn/`) exist in Keystone but are unreachable from the OP login
page, so any domain with MFA policy gets a weaker path via OIDC than via v3.
Federated users (ADR 0006/0020) cannot log in through the OP at all, since
there is no upstream-IdP redirect step.

**F-E3 (P2) Templates carry no `<meta name="viewport">`, no autofocus, no
i18n**, and the CSP `default-src 'self'` means any future inline style or
script silently breaks; adopt a nonce or an external stylesheet route now.

**F-E4 (P2) No project/domain scope picker.** Required for F-B1: a human
must choose (or the client must request via RFC 8707 `resource` /
`openstack:project:<id>` scope) which authorization scope the
`openstack:api` token carries.

### F. Storage hygiene

**F-F1 (P0) Abandoned records are never deleted.** Expiry is enforced lazily
on read only (`service.rs:147, 240, 289, 393, 411, 464`). A pre-auth
session created by an unauthenticated `GET /authorize` that is never
completed, an authorization code never redeemed, a device grant never
polled, and a refresh token never rotated all remain in Raft/Fjall
indefinitely. `GET /authorize` is an unauthenticated Raft write per request,
bounded only by the per-IP limiter. `oauth2_key::janitor` sweeps keys and
JTIs only; there is no session janitor. Needs either an expiry index
(`oauth2:expiry_idx:v1:<expires_at>:<kind>:<key>`) swept by a janitor, or
TTL support in `StorageApi`.

**F-F2 (P2) `revoke_refresh_token_family` deletes the family**, so
post-incident forensics cannot see which tokens existed. Prefer tombstoning
with `revoked_at` and letting the janitor purge after the retention window.

### G. Documentation drift

**F-G1 (P1) "Also runs automatically every `signing_key_rotation_days`"**
(admin guide, "Normal rotation") is false. `signing_key_rotation_days` is
read nowhere outside `crates/config` (grep across `crates/`), and
`janitor::run_once` only retires `Previous` keys and prunes JTIs
(`crates/core/src/oauth2_key/janitor.rs:64-141`).

**F-G2 (P1) "`DELETE` … immediately invalidates all refresh tokens"** is
false (F-A4).

**F-G3 (P1) User guide references `/userinfo`** twice
(`doc/src/user/features/oauth2.md:41,172`); the endpoint does not exist.

**F-G4 (P2) ADR 0026 §6 describes a Python middleware that ships nowhere.**
The admin guide's "Downstream control-plane enforcement" section gives an
`api-paste.ini` config for `KeystoneNativeJwtMiddleware` as if it were
installable. Only the Rust reference verifier exists
(`crates/core/src/oauth2_client/verify.rs`). Either publish the middleware
(separate repo, linked) or mark the section as design-only.

**F-G5 (P2) ADR 0026 §7.C, §8 (`max_age`), §4 (claims template) describe
behaviour as delivered that is not implemented** (F-D2, F-B4, F-B2). The ADR
needs an "Implementation status" table like ADR 0028 has.

**F-G6 (P3) `[oauth2]` is missing from `doc/src/configuration/options.md`
per-option table** (only a one-line summary at line 68); the admin guide's
table is the only reference and is not linked from options.md.

### H. Tests

**F-H1 (P1) No live-server coverage for the two most important grants.**
`tests/api/tests/api_v4/oauth2/` has no `client_credentials`,
`authorization_code` (browser), refresh rotation, or client CRUD test; the
integration crate exercises them against the raft driver in-process only.
The admin/user docs' curl examples are untested.

**F-H2 (P1) No regression tests for F-D1, F-D2, F-D3, F-C2.**

**F-H3 (P2) No interop test with a standard RP library.** A single
`openidconnect`-crate (or `oauth2`-crate) client run against the live server
in `test_api` would have caught F-C1 and F-B2 immediately.

**F-H4 (P2) Loadtest has no token-issuing transaction**, so Argon2 cost and
Raft write amplification on `/token` and `/authorize` are unmeasured.

**F-H5 (P3) Rego tests exist for every policy**, but
`check_policy_handler_coverage.py`'s B2/B3 contracts
(`security-review.md` §0) are not applied to the six client handlers.

### I. Operations

**F-I1 (P1) No metrics.** `crates/metrics` has no OAuth2 series: token
issuance by grant/outcome, refresh reuse detections, device polls, key
rotations, janitor sweeps. `KeystoneAuditPostauditDrops` is the only
OP-adjacent alert.

**F-I2 (P2) No `keystone-manage oauth2 client …` commands.** Client
registration is API-only; bootstrap of a first-party client (e.g. the CLI's
own device-flow client) requires a token and a script.

**F-I3 (P2) No feature switch.** `[oauth2]` has no `enabled` flag and no
per-domain opt-in; the OP surface is live for every domain that has keys,
and the raft-only drivers mean an SQL-only deployment gets 500s rather than
404s on `/token`.

**F-I4 (P3) No CADF event for pre-auth session creation rate or for janitor
purge counts** once F-F1 lands.

## 3. Roadmap: concrete steps

Ordered so that each step is independently mergeable and the P0 set closes
first. Every step is tracked as a GitHub sub-issue of its milestone issue,
all under umbrella [#939](https://github.com/openstack-experimental/keystone/issues/939). Estimates are in engineer-days for one contributor familiar with the
codebase.

### R1. Revocation foundation (P0, ~8 days) ([#1250](https://github.com/openstack-experimental/keystone/issues/1250))

1. **[#1255](https://github.com/openstack-experimental/keystone/issues/1255)** **Add secondary indexes to the session driver**: `user_idx`, `client_idx`,
   `domain_idx` for refresh families and device grants, plus an
   `expiry_idx` keyed by `expires_at`. Extend `Oauth2SessionBackend` with
   `list_refresh_families_by_user/client/domain`, `revoke_families_by_*`,
   and `sweep_expired(before: i64)`. (F-A3, F-F1 prerequisite)
2. **[#1256](https://github.com/openstack-experimental/keystone/issues/1256)** **Tombstone instead of delete** on family revocation: add
   `revoked_at: Option<i64>` and `revocation_reason` to `RefreshToken`;
   `redeem_refresh_token` treats a tombstone as `Invalid` without re-raising
   the breach event. (F-F2)
3. **[#1257](https://github.com/openstack-experimental/keystone/issues/1257)** **Session janitor**: `crates/core/src/oauth2_session/janitor.rs`, same
   shape as `oauth2_key::janitor` (spawn from `keystone.rs`, `run_once`
   testable, CADF maintenance event, per-domain error isolation), sweeping
   `expiry_idx`. Cover with an integration test that creates an abandoned
   pre-auth session and asserts the key is gone after one pass. (F-F1)
4. **[#1258](https://github.com/openstack-experimental/keystone/issues/1258)** **`POST /v4/oauth2/{domain_id}/revoke` (RFC 7009)**: accepts
   `token` + `token_type_hint`; authenticates the client with
   `authenticate_client`; for a refresh token revokes the family only if
   `record.client_id` matches (else 200 per RFC 7009 §2.2 without action,
   and audit); for an access token appends its `jti` to the existing
   `revoked_jtis` list via a new `Oauth2KeyApi::revoke_jti(domain, jti, exp)`.
   Add `revocation_endpoint` to discovery. (F-A1, F-A7)
5. **[#1259](https://github.com/openstack-experimental/keystone/issues/1259)** **Lifecycle hook** `crates/core/src/oauth2_session/hook.rs`: on
   `User Delete/Disable`, `Domain Disable/Delete`, and password change
   (`Operation::Update` on `User` with a `password_changed` marker, or a new
   `Operation::Other("password_change")`), call `revoke_families_by_user` /
   `by_domain`. Register next to `Oauth2KeyHook`. (F-A5)
6. **[#1260](https://github.com/openstack-experimental/keystone/issues/1260)** **Re-validate the user on refresh**: in `handle_refresh_token_grant`,
   fetch the user and require `enabled` and same domain before rotating;
   add `[oauth2] refresh_token_absolute_lifetime_days` (default 90) stored
   as `family_expires_at` on the root and checked on every rotation. (F-A2)
7. **[#1261](https://github.com/openstack-experimental/keystone/issues/1261)** **Client delete revokes families** via `revoke_families_by_client`,
   making the admin guide true. (F-A4, F-G2)
8. **[#1262](https://github.com/openstack-experimental/keystone/issues/1262)** **Fix F-D1**: move the ownership check into
   `Oauth2SessionApi::redeem_refresh_token(state, bearer, client_id,
   domain_id)`; return `Invalid` before any write. Unit test: family leaf
   remains unspent after a foreign client presents it.

Deliverable check: an operator can run `keystone-manage oauth2 revoke
--user <id>` (thin wrapper over step 5's provider call, F-I2), a user
disable ends OP sessions within one access-token lifetime, and Raft key
count stays flat under an abandoned-`/authorize` loop.

### R2. Make human grants useful (P0, ~10 days) ([#1251](https://github.com/openstack-experimental/keystone/issues/1251))

9. **[#1263](https://github.com/openstack-experimental/keystone/issues/1263)** **`userinfo` endpoint** (`GET/POST /{d}/userinfo`, Bearer
   `OidcAccessTokenClaims` or `OpenStackAccessTokenClaims` with `openid`):
   verify with `verify.rs` logic + JTI list, return `sub`, and `name`,
   `preferred_username`, `email` (from the identity provider) gated by
   `profile`/`email` scope. Add `userinfo_endpoint` to discovery. (F-B2,
   F-G3)
10. **[#1264](https://github.com/openstack-experimental/keystone/issues/1264)** **Populate `id_token` standard claims** for `profile`/`email`, and
    **apply `claims_template`** through a small interpolator over
    `${user.id}`, `${user.domain_id}`, `${scope.*}` per ADR §4 with the
    control-character output check. (F-B2)
11. **[#1265](https://github.com/openstack-experimental/keystone/issues/1265)** **`openstack:api` on human grants**: extend `PreAuthSession` /
    `DeviceCodeGrant` with `requested_authorization: Option<ScopeRequest>`;
    accept `scope=openstack:api openstack:project:<id>` (or RFC 8707
    `resource=`), render a scope picker on the consent page listing the
    user's projects/domains (`assignment` provider `list_user_projects`),
    resolve roles with `calculate_effective_roles()` at code issuance, and
    mint `OpenStackAccessTokenClaims` in `handle_authorization_code_grant`
    and `handle_device_code_grant`. Store the chosen scope on the refresh
    family so refresh re-resolves roles at rotation time (closing the ADR
    §11 "Static Roles Window" for refreshed tokens). (F-B1, F-E4)
12. **[#1266](https://github.com/openstack-experimental/keystone/issues/1266)** **Bearer JWT extractor for Keystone's own API**: in
    `crates/core/src/api/auth.rs`, accept `Authorization: Bearer <jwt>`
    whose `iss` matches a local domain issuer, verify with
    `verify_openstack_access_token` against the local key provider and JTI
    list, and hydrate a `ValidatedSecurityContext` from `openstack_context`.
    Must key on the authentication chain per `security-model.md`. (F-B3)
13. **[#1267](https://github.com/openstack-experimental/keystone/issues/1267)** **Introspection endpoint** (`POST /{d}/introspect`, client-authenticated):
    returns `active`, `scope`, `client_id`, `sub`, `exp`, `token_use`,
    consulting the JTI list and, for refresh tokens, family state. Add
    `introspection_endpoint` to discovery and document it as the ADR §13
    back-channel option. (F-A6)

### R3. Conformance and security fixes (P1, ~4 days) ([#1252](https://github.com/openstack-experimental/keystone/issues/1252))

14. **[#1268](https://github.com/openstack-experimental/keystone/issues/1268)** **Discovery correctness** (F-C1): fix the device grant URN, add
    token-exchange URN, `device_authorization_endpoint`,
    `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`
    (`client_secret_basic`, `client_secret_post`, `none`), full
    `claims_supported`, `revocation_endpoint`, `introspection_endpoint`,
    `userinfo_endpoint`, `authorization_response_iss_parameter_supported`.
    Update the `test_api` discovery test to assert exact values.
15. **[#1269](https://github.com/openstack-experimental/keystone/issues/1269)** **`Cache-Control: no-store` + `Pragma: no-cache`** on every `/token`,
    `/device_authorization`, `/userinfo`, `/introspect` response and on every
    HTML page (`security_headers`). (F-C2)
16. **[#1270](https://github.com/openstack-experimental/keystone/issues/1270)** **Rate-limit the device polling arm** with `check_ip` and the per-client
    limiter, plus a per-`device_code` penalty on `InvalidGrant` (ADR §7.C
    5-minute quiet period) implemented as a governor keyed on
    `sha256(device_code)`. (F-D2)
17. **[#1271](https://github.com/openstack-experimental/keystone/issues/1271)** **Filter the client at device redemption** by `enabled && deleted_at
    is None && domain_id` (F-D3), and pass the real user as the CADF
    initiator on human-grant success events (F-D6).
18. **[#1272](https://github.com/openstack-experimental/keystone/issues/1272)** **RFC 9207 `iss`** in code and error redirects (F-C3); **RFC 8252
    loopback port wildcard** in `redirect_uri` matching for public clients
    (F-C4).
19. **[#1273](https://github.com/openstack-experimental/keystone/issues/1273)** **Require `public_endpoint` for the OP**: refuse `/authorize`,
    `/device_authorization`, `/token` and discovery with a logged 503 when
    `[default] public_endpoint` is unset, and derive cookie `Secure` from its
    scheme. (F-D4, F-D5)
20. **[#1274](https://github.com/openstack-experimental/keystone/issues/1274)** **Enforce or remove** `token_endpoint_auth_method` and `require_pkce`
    (F-B7). Recommendation: enforce the registered auth method at `/token`,
    keep PKCE unconditional and drop `require_pkce` from the API type in v4
    with a deprecation note.

### R4. Operator-configurable browser UI (P1, ~5 days) ([#1253](https://github.com/openstack-experimental/keystone/issues/1253))

21. **[#1275](https://github.com/openstack-experimental/keystone/issues/1275)** **Runtime template override**: add `[oauth2] templates_dir` and
    `[oauth2] static_dir`. Keep the askama-compiled templates as the
    fallback; at startup, if `templates_dir` is set, load `login.html`,
    `consent.html`, `device_entry.html`, `device_result.html`, `error.html`
    with a runtime engine (`minijinja` is the lightest fit and shares Jinja
    syntax with askama) into `ServiceState`, and render through one
    `Renderer` trait so handlers do not care which engine produced the body.
    Serve `static_dir` at `/v4/oauth2/static/` with `Cache-Control` and
    extend the CSP to `style-src 'self'; img-src 'self' data:`.
22. **[#1276](https://github.com/openstack-experimental/keystone/issues/1276)** **Branding knobs without templates**: `[oauth2] ui_product_name`,
    `ui_logo_url`, `ui_support_url`, `ui_privacy_url`, exposed to templates
    as a `branding` context; ship a minimal default stylesheet and viewport
    meta. (F-E1, F-E3)
23. **[#1277](https://github.com/openstack-experimental/keystone/issues/1277)** **Client display metadata**: add `name`, `description`, `logo_uri`,
    `policy_uri`, `tos_uri`, `contacts` to `OAuth2ClientResource` and the
    v4 API type; render `name` (HTML-escaped) instead of `client_id` on
    consent/result pages; make `client_id_for_display` real. (F-D7)
24. **[#1278](https://github.com/openstack-experimental/keystone/issues/1278)** **Second-factor step**: after password success, if the user has TOTP
    credentials or a registered passkey (and/or domain policy requires MFA),
    render a second form (`/authorize/mfa`, `/device/mfa`) driving
    `authenticate_by_totp` or the WebAuthn assertion ceremony; set `amr`
    accordingly and record it on the code/grant. (F-E2)
25. **[#1279](https://github.com/openstack-experimental/keystone/issues/1279)** **Federated login through the OP**: on the login page, offer the
    domain's configured upstream IdPs (`federation` provider), redirect
    through the existing OIDC/SAML callback, and complete the pre-auth
    session with the mapped user; `amr = ["federated"]`. (F-E2, larger,
    can trail R4)
26. **[#1280](https://github.com/openstack-experimental/keystone/issues/1280)** **`max_age` and `prompt`**: persist an authenticated browser session
    cookie (separate from the pre-auth cookie) with `auth_time`; honour
    `max_age` (ADR §8), `prompt=login|none|consent`, and `login_hint`.
    Add `end_session_endpoint` that clears it. (F-B4)
27. **[#1281](https://github.com/openstack-experimental/keystone/issues/1281)** **Consent memory**: `oauth2:consent:v1:<user>:<client>` with the granted
    scope set; skip the consent page when the request is a subset; expose
    `GET /v4/users/{id}/oauth2/consents` + `DELETE` for self-service
    revocation (which also revokes that client's families via R1). (F-B5)

### R5. Operations, tests, docs (P1/P2, ~5 days) ([#1254](https://github.com/openstack-experimental/keystone/issues/1254))

28. **[#1282](https://github.com/openstack-experimental/keystone/issues/1282)** **Automatic key rotation** per `signing_key_rotation_days` in
    `oauth2_key::janitor` (rotate when `Primary.created_at + days < now`,
    leader-only, CADF event), or delete the option and the doc sentence.
    (F-G1)
29. **[#1283](https://github.com/openstack-experimental/keystone/issues/1283)** **Metrics**: `keystone_oauth2_tokens_issued_total{grant,outcome}`,
    `keystone_oauth2_refresh_reuse_total`, `keystone_oauth2_device_polls_total{outcome}`,
    `keystone_oauth2_key_rotations_total{kind}`,
    `keystone_oauth2_janitor_purged_total{kind}`; alert on reuse detections.
    (F-I1)
30. **[#1284](https://github.com/openstack-experimental/keystone/issues/1284)** **`keystone-manage oauth2 client create|list|show|delete|rotate-secret`
    and `oauth2 revoke --user|--client|--domain`** over the admin UDS. (F-I2)
31. **[#1285](https://github.com/openstack-experimental/keystone/issues/1285)** **`[oauth2] enabled` flag and 404 on SQL-only deployments**; document
    the raft requirement up front. (F-I3)
32. **[#1286](https://github.com/openstack-experimental/keystone/issues/1286)** **Live API tests** for `client_credentials`, the full browser
    `authorization_code` flow via `DeviceBrowser`-style helper, refresh
    rotation and reuse, `/revoke`, `/introspect`, `/userinfo`, and client
    CRUD; regression tests for F-D1/D2/D3/C2; an `openidconnect`-crate RP
    interop test against discovery; a `/token` loadtest transaction.
    (F-H1..H4)
33. **[#1287](https://github.com/openstack-experimental/keystone/issues/1287)** **Docs**: remove the false statements (F-G1/G2/G3), add an
    "Implementation status" table to ADR 0026 mirroring ADR 0028, mark §6 as
    design-only until a middleware repo exists (F-G4/G5), add the
    `[oauth2]` option table to `configuration/options.md` (F-G6), and add a
    "Production checklist" section to the admin guide (public_endpoint,
    TLS/proxy headers, rate-limit config, key rotation cadence, revocation
    runbook, monitoring).

### Sequencing summary

| Milestone | Steps | Unblocks                                                        |
| --------- | ----- | --------------------------------------------------------------- |
| M1        | 1-8   | Revocation, storage growth, refresh DoS. GA for `client_credentials`. |
| M2        | 9-13  | Usable human login and CLI device flow; Keystone accepts its own JWTs. |
| M3        | 14-20 | Standards-conformant discovery; remaining P1 security fixes.     |
| M4        | 21-27 | Operator-brandable UI, MFA/federated login, SSO semantics.       |
| M5        | 28-33 | Observability, CLI, tests, docs; GA for human grants.            |

M1 and M3 are small and should land first regardless of appetite for M2/M4;
M2 step 12 (Bearer extractor) touches the security-critical auth path and
must go through the `security-model.md` reviewer checklist.
