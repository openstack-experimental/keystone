# 26. Native Stateless OAuth2 / OpenID Connect Provider

**Date:** 2026-07-06

## Status

Proposed

## Reference

Extends ADR 0006 (Federation IDP), ADR 0016-v2 (Distributed Secure Storage), ADR
0017 (SecurityContext Architecture), ADR 0020 (Unified Mapping Engine), ADR 0022
(Handler Rate Limiting), and ADR 0023 (CADF Auditing Architecture). This
document completely supersedes and replaces the previous draft of ADR 0026, which
isolated JSON Web Tokens (JWTs) exclusively to external third-party consumers.
This record formalizes the structural, cryptographic, and architectural pipeline
necessary to elevate the signed JWT access token to a primary citizen natively
ingested across the internal OpenStack control plane.

---

## 1. Context & Motivation

Traditional iterations of OpenStack authentication rely entirely on the manual
exchange of symmetric Fernet tokens or blocking back-channel API validation
calls. While previous architectural blueprints for `keystone-rs` introduced a
centralized **Unified Mapping Engine (ADR 0020)** to ingest external
cryptographic assertions, the outbound token tracks remained bound to the local
cluster. Restricting the outbound OAuth2 capability to third-party integrations
(e.g., "Login with OpenStack" for Grafana) introduced a severe **Circular Token
Exchange Trap**. External cloud-native operators or containerized workloads
authenticating via OIDC had to immediately execute an RFC 8693 Token Exchange
round trip to trade their JWT for a Fernet token before they could make a
single call to Nova or Neutron.

To scale to the performance requirements of modern public cloud hyperscalers
(AWS, GCP, Azure), `keystone-rs` must act as an authoritative **OAuth2
Authorization Server / OpenID Connect Provider (OP)** whose tokens are directly
consumed by OpenStack infrastructure components.

By building an **Egress Token Minting Pipeline** that mirrors the security
configurations of our **Inbound Ingress Validation pipeline**, `keystone-rs` can
issue compact, cryptographically signed, stateless access tokens. These tokens
encapsulate the entire user identity, project scopes, and effective roles inside
the cryptographic claims payload. This configuration empowers downstream Python
services to authorize requests completely offline via memory-bound signature
verification, cutting the central database and network lookup bottleneck to
absolute zero.

### Primary Use Cases

Being an authoritative OAuth2/OIDC Provider is not an abstract compliance
checkbox; it unlocks concrete, high-leverage scenarios that neither Fernet nor
the Python JWS token provider can serve:

1. **Cloud-native workloads calling OpenStack APIs directly.** Kubernetes
   operators (Cluster API, Crossplane), CI/CD pipelines (GitHub Actions /
   GitLab OIDC-style workload federation), and Terraform controllers hold
   short-lived OIDC credentials natively. Today they must trade them for a
   Fernet token first (the Circular Token Exchange Trap, above). With the OP in
   place, a `client_credentials` grant yields a JWT that Nova/Neutron accept
   directly — no long-lived application credentials embedded in cluster
   secrets.
2. **Offline, per-request validation at hyperscaler request rates.** Every
   Fernet validation is a back-channel keystonemiddleware round trip to
   Keystone. Signed JWTs are verified in-memory by the downstream middleware
   (§6), by Envoy/API gateways at the edge, and by service meshes (e.g. Istio
   `RequestAuthentication`) — removing Keystone from the data path of every
   OpenStack API call. This is the single largest scalability win in this ADR.
3. **"Login with OpenStack" for the surrounding ecosystem.** Grafana, Harbor,
   ArgoCD, internal developer portals, and any standard OIDC RP can
   authenticate users against Keystone with stock OIDC libraries — Keystone
   becomes the identity anchor for the whole cloud's tooling, not just for
   OpenStack services.
4. **Replacing long-lived machine secrets with short-lived tokens.**
   Application credentials and EC2 keys are long-lived bearer secrets stored
   client-side. OAuth2 clients with 15-minute access tokens plus rotating
   refresh tokens (with family-tree breach detection, §9) shrink the credential
   theft window from months to minutes.
5. **Modern CLI login.** The Device Authorization Grant (§7.C) gives
   `openstack`/`osc` CLI users browser-based login with MFA/passkey support on
   headless machines — the flow every major cloud CLI (aws sso, gcloud, az)
   already uses, impossible with password-in-clouds-yaml Fernet flows.
6. **Standards-based delegation (v2, §12).** Trusts, application credentials,
   and EC2 delegation re-expressed as RFC 8693 Token Exchange, plus
   on-behalf-of downscoping for service-to-service hops (Nova → Neutron with a
   narrowed, short-TTL token instead of forwarding the user's full bearer
   token).

Use cases 1 and 2 are the strategic drivers: they shed load and unblock
cloud-native adoption. Use cases 3-5 are adoption accelerators that fall out of
the same machinery nearly for free.

### Threat Model & Defensive Boundaries

1. **Malicious or Compromised Relying Parties (RPs):** An external application
   consuming an `id_token` or `access_token` must be structurally barred from
   leveraging that credential to access native OpenStack core APIs. This is
   achieved by enforcing strict, segregated audience (`aud`) targeting: an
   `authorization_code`/`refresh_token` grant only ever produces an
   OpenStack-capable access token (`aud: "openstack-apis:{domain_id}"`, carrying
   `openstack_context`/roles) when the client explicitly requested and was
   granted the `openstack:api` scope (§4, "Scope Validation"). Every other RP -
   including every client that only wants "Login with OpenStack" identity
   display - receives a minimal `OidcAccessTokenClaims` (§4) whose `aud` is its
   own `client_id`, structurally incapable of passing downstream `aud`
   verification (§6) against any OpenStack service.
2. **Perimeter Network Interception at Ingress Handlers:** Authorization code
   hijacking, Cross-Site Request Forgery (CSRF) on `/authorize`, and
   open-redirector phishing vectors are closed by design through mandatory PKCE
   verification (`S256` only), exact-match redirect allowlists, and persistent
   runtime `state` bindings.
3. **Cryptographic Signing Key Exposure:** Because issued JWTs cross the
   enterprise trust boundary, a signing-key compromise cannot be handled within
   internal clusters. This requires an immutable, `kid`-addressed JSON Web Key
   Set (JWKS) with multi-generational public key publishing windows.

---

## 2. Decision Summary

| Architectural Axis            | Formal Decision                                                                                                                                                                                                                                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cluster Operational Role**  | Authoritative OAuth2 Authorization Server & OpenID Connect Provider (OP).                                                                                                                                                                                                                                                         |
| **Token Architecture**        | Stateless JWTs for `id_token` and `access_token`, default 15-minute `exp` for both. Stateful rotating refresh tokens with family tracking in Raft + FjallDB (OAuth 2.1 §4.1.4), default 30-day idle lifetime (`[oauth2] refresh_token_lifetime_days`), reset on each successful rotation.                                         |
| **Cryptographic Track**       | ES256 (default) or RS256 configurable via `[oauth2] signing_algorithm`.                                                                                                                                                                                                                                                           |
| **Discovery & JWKS**          | Per-domain issuer, per ADR 0006. `GET /v4/oauth2/{domain_id}/jwks` + `/.well-known/openid-configuration`.                                                                                                                                                                                                                         |
| **Scope Model**               | Standard OIDC scopes (`openid`, `profile`, `email`) for identity display. `openstack:api` is a distinct, explicit resource scope gating whether `authorization_code`/`refresh_token` grants ever receive OpenStack authorization data (§4); role resolution itself runs via the mapping engine/claims template, not OAuth2 scope. |
| **Key Synchronization**       | Distributed via **Raft + FjallDB** log replication.                                                                                                                                                                                                                                                                               |
| **Target Audience (`aud`)**   | Domain-bound service identifier (`aud: "openstack-apis:{domain_id}"`) for internal control plane verification; not a single cluster-wide value (see §4 threat note).                                                                                                                                                              |
| **Downstream Acceptance**     | Executed via a lightweight, custom Python WSGI middleware injected into existing Paste Deploy pipelines.                                                                                                                                                                                                                          |
| **Machine Workspace Storage** | Typically resolves via `IdentityMode::Ephemeral` shadow registration mappings to bypass SQL table bloating; `identity_mode` is a property of the matched `MappingRule` (ADR 0020 §3), not a fixed property of `OAuth2Client` (§5).                                                                                                |
| **Rate Limiting Engine**      | Handled natively at the handler layer using the `governor` crate with pre-hash enforcement.                                                                                                                                                                                                                                       |
| **Audit Verification**        | JCS-canonicalized (RFC 8785) payloads signed using the _same_ per-node KEK-derived HMAC engine.                                                                                                                                                                                                                                   |

---

## 3. Cryptographic Token Pipeline & Key Architecture

To ensure broad compatibility across HSM backends, `keystone-rs` defaults to
**ES256** (ECDSA over P-256, SHA-256) but allows operators to configure
**RS256** (RSA-2048, SHA-256) via `[oauth2] signing_algorithm = RS256`.
Asymmetric signing keys are generated, synchronized, and rotated across the
infrastructure utilizing the core mechanics of `KeyRepository`, backed by the
distributed **Raft + FjallDB** storage stack.

This same `signing_algorithm` configuration governs inbound JWT verification in
`keystone-rs` token handlers. The algorithm for outbound signing and inbound
verification must always match the operator-selected value from
`[oauth2] signing_algorithm`, preventing cross-algorithm signature exploits
where an attacker presents a token signed with a weaker or unconfigured
algorithm.

### Key Lifecycle & The Cache Invalidation Window

Each keypair file is assigned a stable Key ID (`kid`) computed deterministically
as the first 32 hex characters of the SHA-256 hash of its DER-encoded public key
(128 bits, negligible collision probability under rapid rotation). This
eliminates the need for an external key tracking table. Public keys are exposed
via the unauthenticated endpoint `GET /v4/oauth2/{domain_id}/jwks`, which
carries `Cache-Control: public, max-age=300` so intermediate proxies do not
cache JWKS indefinitely.

The Python middleware (§6) aligns its local JWKS memory cache TTL to this same
300-second boundary. Phase 1 verification must include integration tests that
simulate a sudden, active key retirement and confirm that edge nodes update
their cached JWKS precisely at the 300-second boundary without human
intervention, ensuring zero validation dropouts during the cache refresh window.

To prevent external caching clients (like Envoy edge proxies, Kubernetes API
gateways, or the local Python middleware) from suffering validation dropouts
when keys rotate, the system configures a strict **multi-generational key
publishing pool**:

1. **Primary/Active Key:** Used exclusively by the Raft leader to sign newly
   minted outbound JWTs.
2. **Previous Key:** No longer used for token generation, but permanently
   retained on the JWKS public endpoint for at least one full token max-lifetime
   (`exp`) after retirement. This ensures that outstanding tokens remain valid
   while external clients flush their local cache TTLs.

### Key Lifecycle Operations

Rotation is triggered either by time (configurable via
`[oauth2] signing_key_rotation_days`, default 90 days) or manually via
`keystone-manage oauth2 rotate-signing-key --domain <domain_id>`. Since each
domain owns an independent keypair (§5), rotation always targets a single
`domain_id` - there is no cluster-wide rotation operation.

**Normal Rotation Flow:**

1. Generate a fresh asymmetric keypair in memory, per the configured
   `[oauth2] signing_algorithm`.
2. Commit it via a Raft proposal to
   `_meta:oauth2:signing_key:<domain_id>:pending`, computing its `kid` (§3).
3. On commit, the pending key is atomically promoted to Primary/Active and the
   prior Primary is demoted to Previous in the same Raft proposal - no
   intermediate state is observable to readers.
4. The Previous key remains published on JWKS for one full token max-lifetime
   after demotion (§3, point 2); a background janitor (mirroring ADR 0020 §4.A's
   shadow-registry sweep) then removes it from
   `_meta:oauth2:signing_key:<domain_id>:previous` and the JWKS response.
5. The rotation event is recorded as a CADF audit event (ADR 0023) with
   `domain_id`, the new `kid`, and the retiring `kid`.

**Raft leader relationship.** Key material is Raft-replicated cluster state, not
leader-local: any node can verify signatures against it, and only the current
Raft leader signs newly issued JWTs with it. On leader failover, the new leader
signs with the same replicated Active key - failover never generates a new
keypair. This clarifies point 1 above, which read ambiguously on its own.

**Domain creation.** A domain's initial signing keypair is generated
synchronously as part of domain creation, not lazily on first token request.
`GET /v4/oauth2/{domain_id}/jwks` and `/.well-known/openid-configuration` are
populated immediately for a newly created, enabled domain - they never return an
empty key set.

### Emergency Rotation and Signing Key Compromise

When a domain's Active signing key is suspected or confirmed compromised, the
operator triggers emergency rotation, which skips the normal Previous-retention
grace window above in favor of immediate containment - mirroring ADR 0016 §6.2's
DEK emergency rotation:

1. **Trigger:**
   `keystone-manage oauth2 rotate-signing-key --domain <domain_id> --emergency`,
   requiring `SystemAdmin` and dual-control confirmation
   (`ConfirmRotateSigningKey` from a second operator within 15 minutes). The
   confirmation window is 15 min (not 5) to accommodate after-hours incident
   response. Unconfirmed requests auto-abort at the window's expiry; the abort
   is recorded in the audit log with the initiating operator's identity. As a
   fallback, an out-of-band emergency rotation can be triggered locally on any
   node via UDS + loopback, without Raft quorum coordination, when the cluster
   is compromised and dual-control is impossible.
2. **Immediate replacement:** A fresh keypair is generated and committed via
   Raft, promoted directly to Primary/Active.
3. **JTI revocation list:** Instead of removing the compromised key from JWKS
   (which would invalidate ALL outstanding domain tokens — a domain-wide DoS —
   see §11), emergency rotation marks the compromised key as `revoked` and
   publishes a jti-based revocation list alongside JWKS at
   `GET /v4/oauth2/{domain_id}/jwks/revocation`. The list initially includes the
   `jti` of any tokens issued within the compromise window (derived from the
   audit log). The middleware (§6) checks this list on every token verification.
   Tokens without `jti` (notably `IdTokenClaims`) are unaffected — they carry no
   downstream authorization authority and are rejected by the middleware absent
   `openstack_context` (Finding 1.4). `OpenStackAccessTokenClaims` always
   carries `jti`, so they are covered. The revocation list TTL mirrors the
   one-max-lifetime retention window of normal rotation.
4. **Incident logging:** Recorded as a distinct CADF event type
   (`OAUTH2_EMERGENCY_KEY_ROTATION`) with `domain_id`, revoked `kid`, new `kid`,
   operator identity, and the full `revoked_jtis` list appended to the event
   attachment. Including the jti revocation entries at event time provides an
   instant cryptographic baseline for security teams to reconcile which
   outstanding tokens were actively blacklisted during the incident window
   without cross-referencing the revocation endpoint separately.

Normal rotation cadence resumes once the emergency rotation completes; the
`signing_key_rotation_days` timer resets to account for the forced rotation.

---

## 4. Outbound Token Payload & Scoping Specification

The OP issues two distinct token tracks: `id_token` (identity for the relying
party) and `access_token` (authorization for downstream services). Both are
stateless JWTs signed by the OP, carrying the identity context as defined by
ADR 0017.

### Rust Struct Layout Specification

```rust
/// Identity claims delivered to the relying party (per OIDC Core §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,            // Issuer URL bound to the domain: /v4/oauth2/{domain_id}
    pub sub: String,            // Keystone user_id (or virtual identity via HMAC-SHA256)
    pub aud: String,            // OAuth2Client.client_id of the consuming RP
    pub exp: i64,               // Default 15 minutes ([oauth2] id_token_lifetime_minutes)
    pub iat: i64,
    pub nbf: i64,               // Not-before, always == iat (defense-in-depth per Token Replay Model, §4); verified by relying parties per OIDC Core §2
    pub auth_time: i64,         // Epoch timestamp of primary authentication (for max_age, OIDC Core §3.1.2.1)
    pub nonce: Option<String>,  // Echoed verbatim from /authorize request (replay prevention)
    pub amr: Vec<String>,       // Authentication methods references: "pwd", "mfa_totp", "webauthn", etc.
    pub at_hash: Option<String>,// Per OIDC Core §3.2.2.10: SHA-256(access_token)[:96 bits, base64url]. Binds id_token to its co-issued access_token, preventing access_token substitution attacks at the RP. Omitted when no access_token is issued (e.g. id_token-only scope).
    pub token_use: String,       // Fixed "id" (OIDC Core §3.1.3.4). Downstream services reject this token as authorization.
    // Per-OAuth2Client `claims_template` output merged here (e.g. email, groups, roles).
    // Populated by interpolating OAuth2Client.claims_template (see Claim Safety below).
    #[serde(flatten)]
    pub extra_claims: serde_json::Map<String, String>,
}

/// Minimal `access_token` issued on `authorization_code`/`refresh_token` grants
/// that did NOT request (or were not granted) the `openstack:api` scope (§4,
/// "Scope Validation"). Carries no OpenStack authorization data at all - no
/// `openstack_context`, no roles, no `openstack-apis:{domain_id}` audience.
/// Exists purely as the standard RFC 6749 access token for calling Keystone's
/// own `/userinfo` endpoint (OIDC Core §5.3), the same role a generic OIDC
/// access token plays for any RP that never intends to touch OpenStack APIs.
/// This is what closes Threat Model item 1 (§1): a compromised RP holding only
/// this token has no `aud` value any downstream OpenStack middleware (§6) will
/// ever accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAccessTokenClaims {
    pub iss: String,            // Issuer URL bound to the domain
    pub sub: String,            // Keystone user_id
    pub aud: String,            // The requesting OAuth2Client.client_id itself, NEVER "openstack-apis:{domain_id}"
    pub exp: i64,               // Mirrors id_token lifetime (default 15 minutes)
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub scope: String,          // Granted scope string, echoed per RFC 6749 §5.1
    pub token_use: String,      // Fixed "access" (mirrors IdTokenClaims.token_use); downstream middleware (§6) checks this alongside `openstack_context` presence
}

/// Authorization claims consumed by downstream OpenStack services. Issued as
/// the `access_token` on `client_credentials` grants unconditionally (the
/// client itself is always the OpenStack-facing subject there), and on
/// `authorization_code`/`refresh_token` grants only when `openstack:api` was
/// requested and granted (§4, "Scope Validation") - otherwise those grants
/// produce `OidcAccessTokenClaims` above instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackAccessTokenClaims {
    pub iss: String,            // Issuer URL bound to the domain
    pub sub: String,            // Keystone user_id
    pub aud: String,            // Domain-bound identifier: "openstack-apis:{domain_id}" (see §5 threat note; NOT a flat cluster-wide value)
    pub client_id: String,      // Registered OAuth2Client that initiated the grant
    pub exp: i64,               // Short-lived expiration (default 15 minutes)
    pub iat: i64,
    pub nbf: i64,                // Not-before, always == iat (defense-in-depth per Token Replay Model, §4); enforced by the downstream middleware (§6)
    pub jti: String,            // Unique token UUID for revocation mapping
    pub keystone_ruleset_version: u128,            // Policy rule state anchor: first 32 hex chars (128 bits) of the SHA-256 hash, same truncation convention as `kid` (§3)
    pub amr: Vec<String>,                          // Authentication methods references (mirrors id_token for downstream)
    pub token_use: String,                         // Fixed "access" (OIDC Core §3.1.3.4 analogue); downstream middleware (§6) checks this alongside `openstack_context` presence, rejecting id_token/OidcAccessTokenClaims presented here

    /// Delegated auth context: structurally enforces that a plain auth method
    /// cannot carry a `delegated_project_id`. V1 only produces `Plain` — the
    /// three delegated variants are forward-declared now so the type already
    /// matches what §12's v2 Token Exchange grant will populate, rather than
    /// requiring a breaking enum change later. Each delegated variant carries
    /// the immutable projection of the delegation boundary (security.md I2).
    pub delegation_context: DelegationContext,

    #[serde(flatten)]
    pub openstack_context: OpenStackContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "auth_method", rename_all = "snake_case")]
pub enum DelegationContext {
    Plain,
    Trust {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    AppCred {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
    Ec2 {
        #[serde(rename = "delegated_project_id")]
        project_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStackContext {
    pub user_id: String,                     // Core user UUID or virtual identity string
    pub user_name: String,                   // Normalized, case-folded alphanumeric principal name
    pub user_domain_id: Option<String>,      // Home domain UUID of the identity itself (matches 0020's IdentityBinding.user_domain_id), distinct from scope below
    #[serde(flatten)]
    pub scope: OpenStackScope,               // Structure structurally identical to `openstack_keystone_core::mapping::authorization::Authorization`
    pub roles: Vec<String>,                  // List of effective roles evaluated at token issuance
}

/// Mirrors ADR 0020's `Authorization` enum shape exactly (same `#[serde(tag = ...)]`
/// pattern, same `system_id` field name) so a token's scope is one of exactly three
/// well-typed shapes instead of a bag of optional fields. The prior design (flat
/// `project_id`/`project_domain_id`/`system: Option<String>`/`is_system: bool`) let
/// illegal states compile - e.g. `is_system: true` with `system: None`, or `project_id`
/// and `system` both set - and the downstream WSGI shim (§4) had to re-derive
/// mutual exclusion by hand with `if/elif` presence checks, silently dropping the
/// domain-scope case entirely because no field ever signaled it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope_type", rename_all = "snake_case")]
pub enum OpenStackScope {
    Project {
        project_id: String,
        project_domain_id: String,
        roles: Vec<RoleRef>
    },
    Domain {
        domain_id: String,
        roles: Vec<RoleRef>
    },
    System {
        system_id: String,
        roles: Vec<RoleRef>
    },
    Unscoped,
}

```

### Amendment: `scope_roles` Wire Rename (Found in Phase 5)

The struct layout above, as originally specified, has `OpenStackContext.roles`
(`Vec<String>`, the effective role *names* the §6 middleware reads via
`ctx['roles']`) and each `OpenStackScope` variant's `roles: Vec<RoleRef>`
both flatten into the same JSON object via nested `#[serde(flatten)]`. Since
both fields serialize to the identical wire key `"roles"`, the actual JSON
produced contains a duplicate key -- valid to *write* (`serde_json` silently
overwrites the earlier entry) but never valid to *read back*: flattened
deserialization resolves each Rust field by name against the first matching
key in the source object, not the last, so no `OpenStackAccessTokenClaims`
with a `Project`/`Domain`/`System` scope could ever be decoded back into this
type at all. This went unnoticed through Phases 3-4 because the only existing
tests serialized claims one-way and never round-tripped them. Phase 5's
offline verifier is the first code to actually decode a signed token, and it
surfaced the defect immediately.

**Fix:** each `OpenStackScope` variant's `roles: Vec<RoleRef>` field carries
`#[serde(rename = "scope_roles")]`, keeping the Rust field name (and every
existing call site) unchanged while giving it a distinct wire key. The outer
`OpenStackContext.roles: Vec<String>` -- the one the §6 middleware actually
reads -- keeps the unrenamed `"roles"` key.

### Token Replay Model

Access tokens are bearer tokens with no DPoP (RFC 9449) demonstrable proof of
possession in v1. Replay protection relies on short TTL (15 minutes) and `nbf`
(not before) claim enforcement. `jti` is included for audit trail and refresh
token family tracking, but is not used for server-side replay blocking (which
would contradict the stateless model). This bearer-only design carries inherent
token theft risk: a compromised access token (via XSS, log leakage, or network
capture on internal traffic) grants full access until `exp`. Operators deploying
to non-mTLS control planes should treat the network as partially trusted and
consider mTLS or shorter TTLs (see §11). DPoP binding is scoped to v1.5 to close
this gap without adding v1 complexity. For high-security environments in v1,
downstream services should implement per-request nonce tracking or use
back-channel introspection for `access_token` validation.

### Claim Safety

`claims_template` (§5, `OAuth2Client`) is a per-client map of output claim name
to a template string, admin-authored via the Client Registration CRUD API. At
`/token` issuance, each template is interpolated against Keystone's own
already-resolved session state and merged into `extra_claims` on the `id_token`.
This is a **separate, outbound-only** interpolation pass - it is not a reuse of
ADR 0020 §5.4's engine. 0020's `${claims.*}` interpolates _inbound_ claims
presented by an upstream federated IdP into identity/group fields, to decide who
a user is; `claims_template` here interpolates Keystone's own _outbound_,
already-decided identity/scope/roles into extra token claims, to decide what to
tell the relying party. Different direction, different variable namespace
(`${user.*}`/`${scope.*}`/`${roles.*}`, not `${claims.*}`), same
single-pass-no-recursion discipline.

Three mechanisms prevent claim name collision and value manipulation through
`#[serde(flatten)]`:

1. **Reserved claim name rejection.** Interpolated output keys that collide with
   OIDC-standard, JWT-reserved, and `OpenStackContext`-owned claims (`sub`,
   `iss`, `aud`, `exp`, `iat`, `nbf`, `auth_time`, `nonce`, `acr`, `amr`,
   `at_hash`, `c_hash`, `azp`, `jti`, `client_id`, `keystone_ruleset_version`,
   `delegation_context`, `auth_method`, `delegated_project_id`, `token_use`,
   `openstack_context`, `user_id`, `user_name`, `user_domain_id`, `scope_type`,
   `project_id`, `project_domain_id`, `domain_id`, `system_id`, `roles`) are
   rejected at template compilation time. The reserved set is derived
   programmatically from the struct field names of `IdTokenClaims`,
   `OpenStackContext`, and `OpenStackScope` at compile time, not maintained
   manually, so future field additions cannot silently escape the check. The
   template save fails if any claim-template key matches the reserved set,
   preventing baseline claims from being overridden via `#[serde(flatten)]`.

2. **Trusted sources only.** Template interpolation variables are restricted to
   admin-controlled sources: `${user.id}`, `${user.domain_id}`,
   `${scope.project_id}`, `${scope.domain_id}`, `${scope.system_id}` - one
   variable per `OpenStackScope` variant (§4). `${roles.*}` is excluded from v1
   `claims_template` to prevent role data from leaking to `id_token` (the RP's
   browser-visible identity token). User-settable attributes (`${user.email}`,
   `${user.name}`) are excluded in v1. This prevents user-influenced data from
   appearing in the signed JWT.

3. **Output validation.** Interpolated claim values must produce valid strings
   per RFC 7519 §2. Values containing control characters (U+0000-U+001F,
   U+007F-U+009F) are rejected at token issuance. The `extra_claims` map is
   restricted to string values only (`HashMap<String, String>`) in v1, not
   arbitrary JSON.

### Protocol Scope Integration

OAuth2 `scope` uses standard OIDC identifiers for display and identity control
(`openid`, `profile`, `email`). Role and authorization _content_ is never
requested via a scope value the RP invents, because the RP cannot know the
user's assignments ahead of time - but whether OpenStack authorization data is
included at all **is** gated by one explicit scope value, `openstack:api` (§4,
"Scope Validation"). When `openstack:api` is requested and granted,
`keystone-rs` resolves the user's actual assignments at `/authorize` time via
`calculate_effective_roles()` and encodes the result directly into
`openstack_context.roles` on an `OpenStackAccessTokenClaims` access token,
bypassing parallel permission models entirely. When it is not requested (the
default for RPs that only want identity, e.g. `openid profile email`), the
access token issued is the minimal `OidcAccessTokenClaims` (§4) - no roles, no
`openstack_context`, no OpenStack-facing `aud`. The `id_token` itself never
carries roles either way; only `claims_template` output (Claim Safety, above)
reaches it.

### Scope Validation and `allowed_scopes` Enforcement

`OAuth2Client.allowed_scopes` is validated differently depending on which grant
is invoked at `/token` - the two grants use incompatible scope grammars, not one
shared surface:

- **`authorization_code` / `refresh_token`:** the requested `scope` must be a
  subset of `allowed_scopes ∩ {openid, profile, email, openstack:api}`. Any
  requested value outside that set is rejected outright with `invalid_scope`
  (400, RFC 6749 §5.2) - the server never silently narrows the grant to the
  allowed subset. Silent narrowing would let a client believe it received a
  broader identity disclosure than it did. `openstack:api` is not a display
  scope: it must be explicitly present in the client's `allowed_scopes` (an
  admin, Tier 1/Tier 2-gated action, §5) _and_ explicitly requested per-call
  before the access token carries any OpenStack authorization data at all - see
  "Protocol Scope Integration" above and Threat Model item 1 (§1). Its absence
  is the safe default; omitting `scope` entirely (below) does **not** imply
  `openstack:api` even if the client's `allowed_scopes` includes it, since
  defaulting to "full access" on an omitted scope would silently hand OpenStack
  authority to any client that merely forgets to pass `scope`.
- **`client_credentials`:** the requested `scope` (if present) must be a subset
  of `allowed_scopes`, same reject-outright rule. These values are **opaque
  resource-scope strings** in v1 - they carry no OIDC meaning (no `id_token` is
  issued for this grant, so there is no display-claim surface to bound) and no
  bearing on role/authorization resolution, which is fully owned by the mapping
  engine regardless of requested scope (see Amendment below). They are echoed
  verbatim in the token response `scope` field per RFC 6749 §4.4.3 and reserved
  for a future RFC 8707 resource-indicator scheme - out of scope here, same
  deferral posture as §12's Token Exchange.
- **Omitted `scope` param (either grant):** defaults to the client's full
  `allowed_scopes` value, per RFC 6749 §3.3 - **except** `openstack:api` on
  `authorization_code`/`refresh_token`, which is never implied by omission and
  must always be requested explicitly (see above); `client_credentials` is
  unaffected by this carve-out since it has no display-scope surface to begin
  with.

---

## 5. Client & Issuer Topology (Machine Identity Execution)

To separate human directory assets from automated server processes,
`keystone-rs` treats non-human machine workloads as first-class citizens using
domain-bound client resource blocks.

```rust
pub struct OAuth2Client {
    pub client_id: String,                   // Public, globally unique lookup identifier presented at /token and /authorize
    pub provider_id: String,                 // Functional configuration slug anchor (mirrors ADR 0020 §2.A-C); unique within domain_id
    pub domain_id: String,                   // Owning tenant domain; required, matching OidcProviderResource/K8sClusterResource/SpiffeTrustResource (ADR 0020 §2.A-C). No global/domain-less client: the registration endpoint (§5) is already domain-scoped (`POST /v4/oauth2/{domain_id}/clients`), and the resource key `data:oauth2:client:<domain_id>:<provider_id>` (§5) requires a concrete value. Cluster-wide machine identities register under a reserved system domain like any other ingress source.
    pub client_secret_hash: Option<String>,  // Argon2id PHC representation for confidential applications
    pub redirect_uris: Vec<String>,          // Exact-match allowlist strings; wildcards rejected. Confidential clients (non-null client_secret_hash) must use HTTPS-only URIs; rejected at CRUD time (422) for non-HTTPS schemes. `http://localhost:*` allowed for public clients with a one-time warning logged.
    pub token_endpoint_auth_method: String,  // Client authentication at /token: "client_secret_basic" (default), "private_key_jwt" or "tls_client_auth" (RFC 8705)
    pub grant_types: Vec<GrantType>,         // Set of {authorization_code, client_credentials, refresh_token, device_code}
    pub require_pkce: bool,                  // Mandatory for public clients; S256 method only. Enforced at CRUD time: a public client (null client_secret_hash) with require_pkce=false is rejected (422) to prevent authorization code interception without PKCE binding.
    pub allowed_scopes: Vec<String>,         // Per-grant scope allowlist (Scope Validation, §4): OIDC identifiers + `openstack:api` for authorization_code/refresh_token, opaque resource-scope strings for client_credentials
    pub pre_authorized: bool,                // Skips user consent step for trusted first-party device-code clients (§7.C); SystemAdmin-only to set, high-severity CADF event on change
    pub enabled: bool,                       // Active administrative switch
    // NOTE: no `identity_mode` field here - Local vs. Ephemeral (ADR 0020 §3) is a
    // property of the matched `MappingRule`'s `IdentityBinding`, not the provider
    // resource. None of the sibling resources (`OidcProviderResource`,
    // `K8sClusterResource`, `SpiffeTrustResource`) carry it either; it is resolved
    // per-rule at match time against the ruleset attached to this client's
    // `provider_id`, same as every other ingress source.
    pub claims_template: HashMap<String, String>, // Output claim name -> template string (Claim Safety below); populates IdTokenClaims.extra_claims
}

```

### Amendment to ADR 0020: OAuth2 Client as a Fourth Provider Resource

`OAuth2Client` is not a parallel, bespoke resource type - it is a fourth entry
in ADR 0020 §2's Provider Configuration Resources, alongside
`OidcProviderResource` (§2.A), `K8sClusterResource` (§2.B), and
`SpiffeTrustResource` (§2.C). ADR 0020 §8 already reserved the keyspace slot for
this (`index:oauth2:client:<client_id>`, "Global Client Index"); this ADR
formalizes the resource that fills it:

- **Resource key:** `data:oauth2:client:<domain_id>:<provider_id>` (parallel to
  the other three crypto resource keys in ADR 0020 §8).
- **Global index:** `index:oauth2:client:<client_id>` →
  `{"domain_id", "provider_id"}`, resolving the OAuth2-protocol-facing
  `client_id` presented at `/token` to the resource's admin-facing coordinate,
  exactly as the OIDC/K8s/SPIFFE resources resolve their own protocol
  identifiers.
- **`IdentitySource` variant:** ADR 0020 §3 gains
  `IdentitySource::OAuth2Client { provider_id: String }`, matching the existing
  `Federation { idp_id }`, `K8s { cluster_id }`, and `Spiffe { trust_domain }`
  pattern - the anchor is the resource's own identifying field, not a generic
  wrapper (ADR 0020 §13 D1/D7).
- **`client_credentials` grant is an ingress event.** When a machine workload
  authenticates with `client_id`/`client_secret`, it flattens to a minimal
  claims map (`client_id`, `domain_id`) and runs through the exact same
  `MappingRuleSet` match → upsert pipeline as SPIFFE/K8s ingress (ADR 0020 §5,
  §7.2), not a separate authorization mechanism. Any `scope` requested on this
  grant is validated against `allowed_scopes` as an opaque resource-scope string
  (§4 above, "Scope Validation") - it never feeds role/authorization resolution,
  which flows entirely through the mapping engine, not a parallel scope-to-role
  table.

### Dual-Role Clients: RP and Machine Identity Coexist by Design

A single `OAuth2Client` may legitimately hold both `authorization_code` and
`client_credentials` in `grant_types` at once - this is intentional, not an
oversight to close off. The two grants produce structurally different tokens
from the same registration:

- **RP role (`authorization_code`):** the client is never the subject. An end
  user authenticates; `sub` is the real `user_id`; the client's own `client_id`
  appears only as `aud` on the `id_token` it consumes (`azp` is reserved, §4,
  but unused in v1 since `aud` is always the single requesting client).
- **Machine-identity role (`client_credentials`):** the client _is_ the subject.
  `sub` is the ephemeral shadow `user_id` derived per "Virtual Machine
  Alignment" below.

Token subject semantics are keyed on **which grant is invoked at `/token`**,
never on a per-client exclusive flag - the same shape as an application that
both offers "Login with OpenStack" to its human users and holds its own backend
service identity for calling OpenStack APIs. One registration, two roles.

Enabling `client_credentials` on a client is **not** itself a privileged
operation requiring a bespoke gate: it attaches the client's `provider_id` to a
`MappingRuleSet` via `IdentitySource::OAuth2Client`, exactly like any K8s/SPIFFE
ingress source, and that ruleset write already goes through ADR 0020 §9.A's
existing Tier 1/Tier 2 split unchanged:

- **Tier 2 (default):** a domain-confined, non-admin operator enables
  `client_credentials` and writes `Authorization::Project`/`Domain` rules scoped
  to their own domain, granting only roles they themselves already hold - full
  self-service, no SystemAdmin involved. This is the common case and the point
  of domain-owned OAuth2 client management.
- **Tier 1 (SystemAdmin gate):** triggers only if the attached rule requests
  `is_system: true` or `Authorization::System`, same control-plane-bypass line
  ADR 0020 already draws for every ingress source - nothing OAuth2Client-
  specific about it.

### Virtual Machine Alignment

When an external automated system (e.g., a Kubernetes service account)
authenticates via the `client_credentials` grant, the matched `MappingRule`
typically resolves to `IdentityMode::Ephemeral` (the common case for machine
workloads with no directory-backed account; an admin may configure `Local`
instead, same as any other ingress source, ADR 0020 §3). `keystone-rs` derives
the deterministic `user_id` inside the **Shadow Virtual User Registry** (ADR
0020 §4) using the same generic formula as every other ingress source:

$$\text{HMAC-SHA256}(\text{cluster\_salt}, \text{client\_id} \parallel \text{provider\_id})$$

Here `client_id` plays the role of `workload_id` and `provider_id` anchors the
owning `OAuth2Client` resource - the same two-component shape ADR 0020 §4 uses
for Federation/K8s/SPIFFE sources. This record is **not** stateless: it is
persisted in the Shadow Virtual User Registry via Raft + FjallDB, subject to the
same creation/auth rate limits, 90-day inactivity janitor, and archive retention
as any other shadow principal (ADR 0020 §4.A, §7.2). The benefit is narrower
than "no persistence" - it is _no SQL row_, avoiding bloat in the relational
`user` tables that back real, directory-backed accounts.

**Client ID Uniqueness Invariant:** `client_id` is globally unique across all
domains (it is the sole key clients present at `/token`, before `domain_id` is
known), while `provider_id` need only be unique within its owning `domain_id`,
matching the other three provider resource types. The
`token_endpoint_auth_method` field in `OAuth2Client` determines how the client
authenticates at `/token`; v1 supports `client_secret_basic`, with
`private_key_jwt` and `tls_client_auth` reserved for v2.

### Client Registration CRUD API

`OAuth2Client` administration follows the identical Tier 1/Tier 2 validation
pattern established for mappings (ADR 0020 §9.A) - SystemAdmin gate for anything
crossing domain/system boundaries, domain-confined self-service otherwise:

- **`POST /v4/oauth2/{domain_id}/clients`** - Register a client. Confidential
  clients receive a one-time plaintext `client_secret` in the response body
  (never persisted or retrievable again; only `client_secret_hash` is stored).
  `provider_id` must be unique within `domain_id` (409 on collision);
  `client_id` is server-generated and globally unique.
- **`GET /v4/oauth2/{domain_id}/clients`** - List clients (domain-isolated,
  mirrors ADR 0020 §9.B).
- **`GET /v4/oauth2/{domain_id}/clients/{provider_id}`** - Get client profile
  (never includes `client_secret_hash`).
- **`PUT /v4/oauth2/{domain_id}/clients/{provider_id}`** - Update mutable fields
  (`redirect_uris`, `grant_types`, `require_pkce`, `allowed_scopes`, `enabled`,
  `claims_template`, `pre_authorized`). Reserved-key and trusted-source
  validation (Claim Safety, §4) runs at save time - a write with an invalid
  template is rejected (422), not silently truncated. Setting `pre_authorized`
  requires `SystemAdmin` regardless of the Tier 2 self-service path otherwise
  available for this endpoint (§7.C). `client_id`, `provider_id`, and
  `domain_id` are immutable post-creation, mirroring `MappingRuleSet.domain_id`
  immutability (ADR 0020 §9.D).
- **`POST /v4/oauth2/{domain_id}/clients/{provider_id}/rotate-secret`** -
  Invalidates the current `client_secret_hash` and issues a new plaintext
  secret, one-time, in the response.
- **`DELETE /v4/oauth2/{domain_id}/clients/{provider_id}`** - Revokes the client
  and immediately invalidates all refresh tokens in its family tree (§9).
  Outstanding bearer access/id tokens remain valid until natural `exp` per the
  stateless token model (§4). The jti revocation list (§3) is not populated on
  delete (access tokens are short-lived at 15 min); only the stateful refresh
  path is targeted. Operators requiring immediate access-token revocation for a
  compromised client should trigger emergency signing key rotation (§3) instead.

Every create/update/delete/rotate-secret event triggers a CADF audit event (§9),
same as mapping ruleset mutations.

### Domain Key Isolation and `aud` Binding

Each domain owns an independent signing keypair (§3), synchronized separately
via Raft + FjallDB. If `aud` were a single flat cluster-wide value (e.g.
`"openstack-apis"`), compromise of **any one domain's** signing key would let an
attacker forge tokens accepted by every internal OpenStack service cluster-wide

- collapsing the per-domain trust isolation this ADR otherwise builds (mirroring
  ADR 0006's domain segregation). To close this, `aud` is domain-bound
  (`"openstack-apis:{domain_id}"`), and the downstream middleware (§6) validates
  both `aud` against its configured domain and `iss` against an explicit
  per-deployment issuer allowlist, not merely claim presence. A compromised
  domain key therefore only forges tokens accepted within that domain's own
  blast radius, not the whole control plane.

---

## 6. Downstream Control Plane Enforcement Layer (Python WSGI Middleware)

To execute an incremental, zero-downtime parallel rollout alongside existing
OpenStack installations, a thin custom Python WSGI middleware is dropped
directly into the Paste Deploy pipelines of existing services (e.g., inside
`/etc/nova/api-paste.ini` or `/etc/neutron/api-paste.ini`).

This layer acts as an completely offline signature verification gate:

```python
import jwt
import requests
import logging
from cachetools import TTLCache
from werkzeug.exceptions import Unauthorized

# Module-level logger for audit and operational monitoring
logger = logging.getLogger(__name__)

class KeystoneNativeJwtMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.jwks_url = config.get('keystone_jwks_url')
        self.jwt_jti_revocation_url = config.get('keystone_jwt_jti_revocation_url')
        # Domain-bound aud (see ADR §5, "Domain Key Isolation and `aud` Binding"):
        # a flat cluster-wide audience would let a single compromised domain
        # signing key forge tokens accepted by every service in the cluster.
        domain_id = config.get('keystone_domain_id')
        self.expected_audience = f"openstack-apis:{domain_id}"
        # Explicit issuer allowlist. jwt.decode's `require: ["iss"]` only checks
        # claim *presence*, not the value, so `iss` is verified separately below.
        self.expected_issuers = config.get('keystone_expected_issuers', [])
        # JWKS cache TTL must not exceed the JWKS endpoint Cache-Control max-age (300s)
        # to ensure prompt validation of tokens after key rotation or emergency
        # revocation. Fail-closed policy (see _get_cached_jwks): on fetch failure
        # past this TTL, requests are rejected rather than served against a
        # possibly-revoked stale keyset — a key pulled from JWKS during emergency
        # rotation (§3) must stop validating immediately, not after some grace
        # window an attacker can extend by interfering with connectivity.
        self.jwks_cache = TTLCache(maxsize=1, ttl=300)
        self._jwks_cache_key = 'jwks'
        # JTI revocation list cache (lightweight, separate from JWKS). Same
        # fail-closed policy: an unreachable revocation list is indistinguishable
        # from an attacker actively suppressing it mid-incident, so fetch failure
        # rejects the request rather than accepting the token (§11).
        self.revocation_cache = TTLCache(maxsize=1, ttl=60)
        self._revocation_cache_key = 'revoked'
        # Primary signing algorithm. During operator transitions (ES256 <-> RS256),
        # `fallback_signing_algorithm` enables dual verification with warning logs.
        self.algorithms = [config.get('signing_algorithm', 'ES256')]
        if fallback := config.get('fallback_signing_algorithm'):
            self.algorithms.append(fallback)

    def _sanitize_token_value(self, val, field_name):
        """Reject control characters in JWT claim values before WSGI injection.

        Prevents HTTP response splitting via crafted claim values (Finding 5.4).
        Even though the value was cryptographically signed, the origin may be
        admin-authored claims_template data, which we do not trust at injection time.
        """
        if not isinstance(val, str):
            raise ValueError(f'{field_name}: non-string value')
        if any(c in val for c in ('\r', '\n', '\x00')):
            raise ValueError(
                f'{field_name}: contains control character '
                f'(rejecting to prevent HTTP response splitting)'
            )
        return val

    def __call__(self, environ, start_response):
        # 0. Sanitize identity headers on every request, not just the Bearer-path.
        # Prevents stale headers leaking to the Fernet fallback path (Finding 5.1).
        self._sanitize_environment_headers(environ)

        auth_header = environ.get('HTTP_AUTHORIZATION', '')

        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # 1. Fetch/update asymmetric public verification keys. Raises
                # requests.RequestException on failure past the cache TTL,
                # caught below and treated as fail-closed (§11).
                public_keys = self._get_cached_jwks()

                # 2. Execute local, CPU-bound cryptographic signature validation.
                # Supports dual-algorithm for operator transitions (Finding 5.2).
                decoded_claims = jwt.decode(
                    token,
                    public_keys,
                    algorithms=self.algorithms,
                    audience=self.expected_audience,
                    options={
                        "require": ["exp", "iat", "nbf", "iss", "aud", "sub"],
                        "verify_exp": True,
                        "verify_nbf": True,
                        "verify_signature": True,
                    }
                )

                # Warn on fallback algorithm use (transition monitoring).
                if len(self.algorithms) > 1:
                    header = jwt.get_unverified_header(token)
                    if header.get('alg') == self.algorithms[1]:
                        logger.warning(
                            'Token uses fallback algorithm %s',
                            header.get('alg'),
                        )

                # 3. Verify iss value against the explicit allowlist (claim
                # presence alone, enforced by `require` above, is not enough)
                if decoded_claims['iss'] not in self.expected_issuers:
                    logger.warning('Unexpected issuer: %s', decoded_claims['iss'])
                    return self._abort_unauthorized(start_response, 'Untrusted issuer')

                # 4. Structural type check: reject non-access-tokens (Finding 1.4).
                # Belt-and-suspenders: both the explicit `token_use` claim and the
                # structural presence of `openstack_context` must agree this is an
                # OpenStack access_token — an id_token or RP-only OidcAccessToken
                # has neither.
                if (
                    decoded_claims.get('token_use') != 'access'
                    or 'openstack_context' not in decoded_claims
                ):
                    logger.warning(
                        'Token is not an OpenStack access_token (id_token or '
                        'RP-only access_token presented to OpenStack endpoint)'
                    )
                    return self._abort_unauthorized(
                        start_response, 'Token type not an OpenStack access_token'
                    )

                # 5. JTI revocation list check (Finding 8.3). Raises
                # requests.RequestException on fetch failure, caught below and
                # treated as fail-closed (§11) — same policy as JWKS fetch.
                jti = decoded_claims.get('jti')
                if jti and self._is_jti_revoked(jti):
                    logger.warning('Revoked JTI: %s', jti)
                    return self._abort_unauthorized(
                        start_response, 'Token JTI has been revoked'
                    )

                # 6. Extract the embedded context block
                ctx = decoded_claims['openstack_context']

                # 7. Enforce delegation invariants (security.md I1, I2, I3, I5)
                # delegation_context is a tagged enum: {"auth_method": "plain"} or
                # {"auth_method": "trust"|"app_cred"|"ec2", "delegated_project_id": "<id>"}.
                # All three delegated variants carry the same delegated_project_id
                # field (§4), so the check below is uniform across them — v1 only
                # ever produces "plain" (§12); v2's Token Exchange grant is what
                # populates the other three.
                auth_ctx = decoded_claims.get('delegation_context', {})
                auth_method = auth_ctx.get('auth_method', 'plain')

                if auth_method != 'plain':
                    delegated_project = auth_ctx.get('delegated_project_id')
                    if delegated_project is None:
                        logger.warning(
                            'Delegation context "%s" missing delegated_project_id',
                            auth_method,
                        )
                        return self._abort_unauthorized(
                            start_response, 'Delegation context malformed'
                        )

                    # I3: Scope-drift tripwire — verify that the token's project scope
                    # matches the delegation's immutable project_id.
                    # Only Project scope carries project_id; delegated auth must be
                    # project-scoped (I5: delegated cannot be domain/system/scoped).
                    if ctx.get('scope_type') != 'project':
                        logger.warning(
                            'Delegated token with non-project scope_type: %s',
                            ctx.get('scope_type'),
                        )
                        return self._abort_unauthorized(
                            start_response,
                            'Delegated auth must be project-scoped (I5)',
                        )

                    if ctx.get('project_id') != delegated_project:
                        logger.warning(
                            'Scope-drift detected: token project_id=%s != '
                            'delegated_project_id=%s',
                            ctx.get('project_id'),
                            delegated_project,
                        )
                        return self._abort_unauthorized(
                            start_response, 'Scope-drift tripwire triggered (I3)'
                        )

                # 8. Inject flat context variables expected downstream by oslo.policy.
                # Sanitize each value to prevent HTTP response splitting (Finding 5.4).
                environ['HTTP_X_IDENTITY_STATUS'] = 'Confirmed'
                environ['HTTP_X_USER_ID'] = self._sanitize_token_value(
                    decoded_claims['sub'], 'sub'
                )
                environ['HTTP_X_USER_NAME'] = self._sanitize_token_value(
                    ctx['user_name'], 'user_name'
                )
                environ['HTTP_X_ROLES'] = ','.join(
                    self._sanitize_token_value(r, f'roles[{i}]')
                    for i, r in enumerate(ctx['roles'])
                )

                scope_type = ctx.get('scope_type')
                if scope_type == 'project':
                    environ['HTTP_X_PROJECT_ID'] = self._sanitize_token_value(
                        ctx['project_id'], 'project_id'
                    )
                    environ['HTTP_X_PROJECT_DOMAIN_ID'] = self._sanitize_token_value(
                        ctx['project_domain_id'], 'project_domain_id'
                    )
                elif scope_type == 'domain':
                    environ['HTTP_X_DOMAIN_ID'] = self._sanitize_token_value(
                        ctx['domain_id'], 'domain_id'
                    )
                elif scope_type == 'system':
                    environ['HTTP_X_SYSTEM_SCOPE'] = self._sanitize_token_value(
                        ctx['system_id'], 'system_id'
                    )

                return self.app(environ, start_response)

            except ValueError as sanitize_err:
                # Token claim sanitization failure.
                logger.warning('Token sanitization failed: %s', sanitize_err)
                return self._abort_unauthorized(
                    start_response, 'Token claim value invalid'
                )

            except requests.RequestException as fetch_err:
                # Fail closed (§11): cannot reach the JWKS or JTI-revocation
                # endpoint, so the token cannot be verified against current
                # signing keys or checked for emergency revocation. Accepting
                # it anyway would let a network partition (attacker-induced or
                # not) resurrect an already-revoked compromised key for the
                # duration of the outage — the exact window emergency rotation
                # (§3) exists to close. Cost: a Keystone/network outage also
                # blocks OpenStack API calls, not just token issuance.
                logger.error('Verification dependency unreachable: %s', fetch_err)
                return self._abort_unauthorized(
                    start_response, 'Verification service unavailable'
                )

            except (
                jwt.ExpiredSignatureError,
                jwt.InvalidSignatureError,
                jwt.InvalidAudienceError,
                jwt.InvalidIssuerError,
                jwt.ImmatureSignatureError,
                jwt.MissingRequiredClaimError,
                jwt.DecodeError,
            ) as crypto_err:
                # Instantly drop requests failing cryptographic or structural
                # verification. The catch list is exhaustive over jwt.decode's
                # documented exception set so no malformed/hostile token can
                # fall through as an unhandled exception (fail closed, not
                # fail open, on decode error).
                return self._abort_unauthorized(start_response, str(crypto_err))

        # Fallback path: pass through to traditional symmetric Fernet filters
        return self.app(environ, start_response)

    def _sanitize_environment_headers(self, environ):
        """Strict Sanitation: Purge pre-existing user-supplied identity headers

        to eliminate spoofing and header injection vulnerabilities. Called on
        every request (including Fernet fallback) to prevent stale header leakage.
        """
        for header in [
            'HTTP_X_USER_ID',
            'HTTP_X_USER_NAME',
            'HTTP_X_ROLES',
            'HTTP_X_PROJECT_ID',
            'HTTP_X_PROJECT_DOMAIN_ID',
            'HTTP_X_DOMAIN_ID',
            'HTTP_X_SYSTEM_SCOPE',
            'HTTP_X_IDENTITY_STATUS',
        ]:
            environ.pop(header, None)

    def _get_cached_jwks(self):
        """Fetch JWKS, fail closed on failure (§11).

        Serves the cached keyset while within the 300s TTL (matching the JWKS
        endpoint's `Cache-Control: max-age=300`). On expiry, fetches
        synchronously. Raises `requests.RequestException` on failure instead
        of serving stale data — caught by the caller and translated into a
        401, since a key pulled from JWKS during emergency rotation (§3) must
        stop validating immediately, not after some grace window an attacker
        can extend by interfering with connectivity to this endpoint.
        """
        cached = self.jwks_cache.get(self._jwks_cache_key)
        if cached is not None:
            return cached
        return self._fetch_jwks_from_network()

    def _fetch_jwks_from_network(self):
        """Raw JWKS fetch from Keystone. Raises on failure (fail closed)."""
        resp = requests.get(self.jwks_url, timeout=5)
        resp.raise_for_status()
        keys = resp.json()
        self.jwks_cache[self._jwks_cache_key] = keys
        return keys

    def _is_jti_revoked(self, jti):
        """Check if a JTI appears in the JWKS-published revocation list.

        The revocation list is published alongside JWKS at a dedicated endpoint,
        keyed by `jti`. Only applies to tokens post-emergency-rotation or
        post-client-deletion. Normal-state tokens have an empty list. (Finding 8.3)

        Cached for 60 seconds. Fails closed (§11): an unreachable revocation
        list during an active key compromise is indistinguishable from an
        attacker actively suppressing it, so fetch failure raises
        `requests.RequestException` rather than accepting the token.
        """
        revoked = self.revocation_cache.get(self._revocation_cache_key)
        if revoked is None:
            resp = requests.get(self.jwt_jti_revocation_url, timeout=2)
            resp.raise_for_status()
            revoked = set(resp.json().get('revoked_jtis', []))
            self.revocation_cache[self._revocation_cache_key] = revoked
        return jti in revoked

    def _abort_unauthorized(self, start_response, reason):
        status = '401 Unauthorized'
        start_response(status, [('Content-Type', 'text/plain')])
        return [reason.encode()]
```

---

## 7. Defensive Shield: Throttling & Threat Containment

### A. Pre-Hash Enforcement for `/token` (`client_credentials`)

When an automated workload requests a token using a client secret, the handler
must check the quota bucket **before** executing the Argon2id password-hashing
check.

- **The Key Boundary:** The limiter keys directly on the unverified `client_id`
  string payload.
- **The Defense:** If an adversary triggers a brute-force credential attack, the
  handler trips the governor limit, completely halting execution and skipping
  the CPU-intensive Argon2 verification entirely, thereby insulating the cluster
  from CPU exhaustion.

### B. Post-Lookup User Throttle for Browser `/authorize`

For interactive endpoints where a human provides credentials via the
server-rendered login form, the system enforces **Invariant 8 of ADR 0022**:

1. The incoming request passes through the `global_ip_limiter` using the
   originating client address resolved via trusted proxy CIDRs.
2. The user lookup occurs in the identity backend to confirm actual account
   existence.
3. The per-user authentication limiter (`rate_limit_user_auth`) is applied
   **only after** account existence is verified. This closes the key-exhaustion
   exploit path where an attacker presents an infinite series of randomized
   usernames to flood the in-memory state store and evict active operational
   quotas.

### C. Device Code Rate Limiting (RFC 8628 §3.5)

The Device Authorization Grant introduces a `device_code` redemption path at
`/token` that is more susceptible to brute-force attacks than credential
endpoints. To mitigate:

- `device_code` and `user_code` are subject to separate per-IP and
  per-`user_code` rate limits with exponential backoff.
- Invalid or expired `device_code` presented at `/token` triggers a mandatory
  5-minute quiet period before further codes can be issued for that IP.
- When a valid active grant is polled faster than the advertised `interval`, the
  server returns a `slow_down` error response per RFC 8628 §3.5 (not a generic
  penalty error), signaling the client to increase its polling rate.
- The minimum `interval` between polling attempts is 5 seconds.
- A `pre_authorized` flag on `OAuth2Client` may skip the user consent step for
  trusted first-party devices. Creating or updating this flag requires
  `SystemAdmin` and triggers a high-severity CADF event (ADR 0023). A
  `pre_authorized` client must not include `openstack:api` in `allowed_scopes`
  (enforced at CRUD time), preventing silent consent bypass from granting
  OpenStack authorization. If `openstack:api` is added to a `pre_authorized`
  client, the `PUT` request is rejected with 422.
- **Code entropy requirements (RFC 8628 §3.5):** `device_code` must be at least
  256 bits of entropy (43+ base64url chars) to prevent brute-force at `/token`.
  `user_code` must be at least 8 characters using unambiguous characters
  `[A-Z,0-9]` (excluding `O/0`, `I/l/1`). This length and character set balance
  human-typing ergonomics against brute-force surface on the console
  verification endpoint.

### D. Device Console URI Rate Limiting

The device authorization endpoint returns `verification_uri_complete` (the
console URI where the user enters `user_code`). This page is susceptible to
`user_code` brute-force. The console endpoint enforces:

- Separate per-IP rate limit for console verification attempts (distinct from
  `/token` polling limit in §7.C).
- `user_code` uniqueness checks must use constant-time comparison to prevent
  timing-based enumeration attacks.
- Failed console attempts generate `device_code` reuse alerts via CADF audit
  event (ADR 0023), correlating with `/token` polling attempts to detect
  coordinated brute-force campaigns.

---

## 8. Interactive Login & Web Security Controls

Keystone currently has no web UI (it is an API-only service). The Authorization
Code flow and Device code verification require interactive login pages,
introducing new attack surface. All server-rendered OP endpoints carry defense-
in-depth security headers:

- `Content-Security-Policy: default-src 'self'` (restricts frame-ancestors,
  script-src)
- `X-Frame-Options: DENY` (clickjacking prevention on the consent screen)
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 0` (disabled per OWASP modern guidance; CSP
  `default-src 'self'` handles XSS. Browser-built-in XSS filters are unreliable
  and can introduce false positives. Document this rationale to prevent
  enterprise scanners from flagging it.)

### CSRF Token Binding

The login and consent POST forms carry per-session anti-CSRF tokens. `state` and
`code_challenge` are chosen by whoever initiates `/authorize` - which may be an
attacker, not the victim - so a value merely derived from them (e.g. a plain
hash) carries no secret the attacker doesn't already know, and would not
actually stop login CSRF. The CSRF token is therefore
`HMAC-SHA256(server_side_session_secret, session_id ‖ state ‖ code_challenge)`:
`server_side_session_secret` is generated when `GET /authorize` first
establishes the pre-authentication browser session (set as an `HttpOnly`,
`SameSite=Lax` cookie) and never transmitted to the client in cleartext. An
attacker who crafts an `/authorize` URL for a victim to click still cannot
compute a matching token without that victim browser's own session secret, which
closes the login CSRF vector the naive hash-of-public-values approach would not.

### max_age Enforcement (OIDC Core §3.1.2.1)

The `/authorize` endpoint accepts an optional `max_age` parameter. If present,
`keystone-rs` compares the current time against the user's authenticated session
`auth_time`. If `auth_time + max_age < now`, the server forces re-authentication
(including re-triggering MFA/TOTP/passkey challenges if configured).

## 9. Cryptographic Auditing & Non-Repudiation

Every single token issuance event, token refresh lifecycle step, and
administrative client modification triggers a normative Cloud Auditing Data
Federation (CADF) compliance log.

To prevent structural key sprawl across the deployment, the auditing framework
uses **the exact same per-node KEK-derived HMAC engine** established in the
storage layer:

$$\text{HKDF-Expand}(\text{KEK}, \text{info}=\text{"keystone-audit-hmac-v1"} \parallel \text{node\_id\_u64\_be}, L=32)$$

### JCS Canonicalization Requirements

Before generating an audit signature, the `CadfAuditHook` enforces strict **RFC
8785 (JSON Canonicalization Scheme)** processing on the `CadfEventPayload`.
Array keys must be sorted lexicographically with zero extraneous whitespace.
Missing parameters are skipped according to strict `skip_serializing_if` rules.
This ensures that the generated cryptographic signature matches perfectly when
evaluated downstream by an external SIEM system, closing the log-tampering
vulnerability surface.

### Token Compromise Alerts (Refresh Reuse Invariant)

If a client presents a rotating `refresh_token` that has already been flagged as
spent, `keystone-rs` interprets the event as an active infrastructure breach:

1. To prevent false positives during legitimate multi-device scenarios (e.g., a
   user on phone + laptop where a refresh token might be reused within a short
   window), a configurable grace period is applied
   (`[oauth2] refresh_token_reuse_grace_minutes`, default 10, range 0-30).
   Setting to 0 disables the grace period entirely (tightest breach detection at
   the cost of multi-device false positives). Only refresh token reuse exceeding
   this window triggers the cascade. This reduces user disruption from transient
   race conditions while maintaining rapid breach detection. **Accepted risk:**
   this is a deliberate detection-latency tradeoff - an attacker who steals a
   refresh token has up to `refresh_token_reuse_grace_minutes` to replay it
   before family revocation triggers (see §11).
2. The token engine invalidates the entire token family tree associated with
   that original grant immediately.
3. The event handler bypasses the best-effort perimeter logging pool and commits
   a critical alert via `dispatch_critical()`.
4. If channel congestion occurs, the system writes a local compensating JSONL
   log to disk and exposes the drop metric immediately to the Prometheus
   monitoring alert `KeystoneAuditPostauditDrops`.

---

## 10. Phased Implementation Approach

```text
Phase 0: Token Provider Abstraction & JWS Parity (v3 surface)
   │
   ▼
Phase 1: Crypto & JWKS (Raft Core) ────► Phase 2: Ingress API Routing ────► Phase 3: Client Credentials
                                                                                   │
Phase 5: Native Control Plane Acceptance ◄──── Phase 4: Auth Code & PKCE ◄─────────┘

```

### Phase 0: Token Provider Abstraction & Python JWS Parity

This phase exists because of a gap this ADR otherwise ignores: **Python
Keystone has shipped a second token provider since Stein —
`[token] provider = jws` (ES256-signed JWS tokens, `keystone-manage
create_jws_keypair`, filesystem key repositories) — and `keystone-rs` supports
only Fernet.** `keystone-rs` is deployed in parallel with Python Keystone
during migration, and both sides must decode each other's v3 tokens. A
deployment running the JWS provider today cannot put `keystone-rs` behind the
same VIP at all. Two distinct JWT tracks must therefore not be conflated:

- **v3-surface JWS tokens (this phase):** Python-compatible, _reference_
  tokens — the JWT payload carries only identity/scope anchors (no roles, no
  catalog) and keystonemiddleware still validates them back-channel via
  `GET /v3/auth/tokens`. Purely a token _format_, not an authorization model.
- **OP-issued access tokens (Phases 1-5):** self-contained
  `OpenStackAccessTokenClaims` (§4) with embedded roles, verified fully
  offline (§6). A different product, deliberately not wire-compatible with
  the above.

**Deliverables:**

- Decouple the token provider layer from Fernet: `TokenBackend::decode/encode`
  (`crates/core/src/token/backend.rs`) and `TokenApi::encode_token` currently
  take/return `FernetToken` directly. Introduce a format-neutral token payload
  type and a `[token] provider = fernet | jws` selector (mirroring Python's
  config surface) so drivers are interchangeable. This refactor is a hard
  prerequisite: retrofitting it after OAuth2 code lands on top of the
  Fernet-typed trait would be strictly more expensive.
- New `token-driver-jws` crate: ES256 sign/verify, Python-compatible claim
  layout (`sub`, `exp`, `iat`, `openstack_methods`, `openstack_audit_ids`,
  `openstack_project_id`/`openstack_domain_id`/`openstack_system`,
  `openstack_trust_id`, `openstack_app_cred_id`) and Python-compatible
  key-repository layout, plugged in via the existing `KeySource` abstraction
  in `crates/key-repository` so filesystem keys shared with Python nodes work
  unchanged.

**Verification:** Round-trip fixture tests against tokens minted by Python
Keystone's JWS provider (decode theirs, they validate ours). Config-switch
tests proving a node can validate both Fernet and JWS tokens during a provider
transition.

**Strategic payoff beyond parity:** the ES256 signing/verification plumbing,
key-file handling, and `kid` conventions built here are exactly what Phase 1
generalizes into the Raft-backed OAuth2 `KeyRepository` — Phase 0 is not a
detour, it is the first increment of the same cryptographic engine, delivered
against the existing v3 surface where it immediately widens the set of
deployments `keystone-rs` can stand in for.

### Phase 1: Cryptographic Engine & JWKS Infrastructure

- **Deliverables:** Asymmetric key generation added to `KeyRepository`.
  Implement the public `GET /v4/oauth2/{domain_id}/jwks` endpoint. Implement the
  multi-generational cache preservation logic.
- **Verification:** Unit tests confirming DER-to-kid SHA-256 truncation,
  integration tests verifying multi-key overlap stability on Raft replication
  events, and integration tests simulating a sudden, active key retirement to
  confirm that edge nodes update their cached JWKS precisely at the 300-second
  boundary without human intervention (§3).

### Phase 2: Ingress API Routing & OIDC Discovery

- **Deliverables:** Expose unauthenticated RFC 8414 discovery paths
  (`/.well-known/openid-configuration`). Implement the `OAuth2Client` storage
  schema within the consolidated partition layer in FjallDB.
- **Verification:** Assert that the generated JSON discovery blocks match OIDC
  1.0 structural validation test profiles. Validate Rego policy rules gating the
  administrative CRUD routes.

### Phase 3: Machine-to-Machine `client_credentials` Implementation

- **Deliverables:** Write the `/token` endpoint handling secret matching.
  Integrate the pre-hash rate-limiting checks from ADR 0022. Connect the token
  generation to `IdentityMode::Ephemeral` shadow user allocations.
- **Verification:** Run automated integration scripts simulating high-velocity
  machine logins. Verify that Argon2id computation is skipped when rate-limiting
  thresholds are breached.

### Phase 4: Human Authorization Code Flow with PKCE

- **Deliverables:** Build the secure browser interactive routes for
  `/authorize`. Deliver the server-rendered login and consent forms. Enforce
  mandatory `S256` PKCE verification loops. Implement refresh token rotation
  family tracking.
- **Verification:** Trigger intentional token reuse attempts and assert that the
  entire associated token lineage collapses while generating a critical CADF log
  event via `dispatch_critical()`.

### Phase 5: Native Control Plane Acceptance & Middleware Injection

- **Deliverables:** Deliver the "Regular Python" `KeystoneNativeJwtMiddleware`
  codebase. Inject the filter into target test control plane networks (Nova /
  Neutron).
- **Verification:** End-to-end integration mapping. Execute an OpenStack API
  transaction using an ES256 access token generated by `keystone-rs`. Assert
  that the Python service parses, cryptographically validates, and completes the
  authorization cycle locally without executing a single back-channel database
  lookup.

**Implementation note:** the Python middleware itself, and its injection into
Nova/Neutron, are out of scope for the `keystone-rs` repository -- that code
runs in downstream service repos, not here. What this repository delivers for
Phase 5 is the Rust-side surface the middleware depends on plus a Rust-native
reference implementation of the exact same §6 verification algorithm
(`openstack_keystone_core::oauth2_client::verify_openstack_access_token`,
a pure function over an already-fetched JWKS/JTI-revocation set), and an
integration test that mints a real token through the same pipeline
`POST /token` uses and verifies it fully offline. This is the closest in-repo
proof of the Phase 5 verification bullet available without a second
repository in the loop.

---

## 11. Consequences

### Positive

- **Complete Database Decoupling:** Downstream OpenStack microservices execute
  token authorization purely inside CPU memory cache lanes, completely
  insulating core storage clusters from token validation stress.
- **Unified Protocol Surface:** External cloud-native observability integrations
  (Grafana) and other third-party relying parties authenticate against the same
  standards-compliant OAuth2/OIDC surface, instead of a Keystone-specific
  integration.

### Negative / Risks

- **The Revocation Durability Gap:** Because access tokens are fully stateless,
  immediate user termination or role revocation events must wait out the short
  15-minute token TTL, or require services to implement a back-channel real-time
  verification endpoint for high-criticality operations.
- **Refresh Token Reuse Grace Window:** The 10-minute reuse grace period (§9) is
  a deliberate detection-latency tradeoff to avoid false positives on
  multi-device use. A stolen refresh token can be replayed by an attacker for up
  to 10 minutes before family revocation triggers - a real, bounded window, not
  a single-shot replay. Operators requiring tighter guarantees should disable
  the grace period at the cost of legitimate multi-device false positives.
- **Stateful Refresh Token Bottleneck:** While access and ID tokens are
  stateless, refresh token rotation requires persistent backend storage for
  reuse detection. Every refresh token write hits SQL or Raft, creating a
  partial database dependency that contradicts the "zero lookup" goal for the
  refresh path.
- **Static Roles Window (§4, `openstack_context.roles`):** Roles are resolved at
  `/authorize` time and baked into the JWT. If roles are removed from a user
  after issuance but before `exp`, the token carries stale roles. Unlike the
  Fernet path where roles are re-resolved on every `new_for_scope()`, the
  stateless model has no re-validation at downstream services. The 15-minute
  default TTL bounds the window. This is an inherent tradeoff of stateless
  authorization and is documented rather than mitigated in v1.
- **Increased Key Rotation Surface:** Operators must manage an independent
  asymmetric key rotation lifecycle policy alongside the existing symmetric
  Fernet key repositories.
- **DPoP Deferred to v1.5:** v1 tokens are pure bearer with no demonstrable
  proof of possession (RFC 9449). A compromised access token grants access until
  `exp`. The primary containment is the short 15-minute TTL combined with `nbf`
  enforcement. DPoP binding is scoped to v1.5 to close this gap without adding
  v1 complexity. Operators deploying to non-mTLS control planes should treat
  network traffic as partially trusted and consider mTLS or shorter TTLs as
  compensatory controls.
- **JTI Revocation List (§3 Emergency Rotation):** The jti revocation list
  published alongside JWKS adds a lightweight stateful dimension to an otherwise
  stateless verification pipeline. The middleware must query this endpoint on
  every request. The list is TTL-bounded (15 min per entry) to prevent unbounded
  growth. Both this endpoint and the JWKS endpoint are **fail-closed** (§6): on
  fetch failure, the middleware rejects the request rather than serving stale
  JWKS data or accepting the token unchecked. This is a deliberate
  availability-over-containment tradeoff — a Keystone/network outage now also
  blocks OpenStack API calls, not just token issuance — accepted because fail
  open would let an attacker who can interfere with the middleware's
  connectivity to either endpoint keep an already-revoked compromised key
  validating for the duration of the outage, defeating emergency rotation's
  immediate-containment guarantee. Operators must treat both endpoints'
  availability as load-bearing for the entire control plane, not just for token
  issuance.
- **First HTML Surface:** The server-rendered login/consent forms introduce
  CSRF, clickjacking, and open-redirect vectors that the rest of Keystone's
  API-only design has never had to defend. RFC 9700 mitigations are specified in
  §8.
- **`domain_id` Enumeration via JWKS:** `GET /v4/oauth2/{domain_id}/jwks` is
  unauthenticated by design (relying parties must fetch it without a Keystone
  token) and returns `404` for an unknown `domain_id` versus `200` for a
  provisioned one, letting an anonymous caller confirm whether a given
  `domain_id` exists. This is accepted, not mitigated further: every major
  multi-tenant OIDC provider (Auth0 tenant name, Okta org subdomain, Keycloak
  realm name, Google Workspace `hd` domain) treats the tenant identifier in the
  issuer/JWKS URL as public, not secret — it is embedded in every issued
  token's `iss` claim and handed to every RP's configuration, so it cannot be
  kept confidential once a single client is onboarded. Since `domain_id` is a
  server-generated 128-bit UUIDv4 (`crates/core/src/resource/service.rs`,
  `Uuid::new_v4()`), brute-force guessing across the ID space is
  computationally infeasible and further bounded by the endpoint's per-IP rate
  limit (ADR-0022). The one exception is the bootstrap domain, whose ID
  defaults to the literal string `"default"`
  (`[identity] default_domain_id`, `crates/config/src/identity.rs`) rather than
  a UUID — its existence is trivially guessable, but this is the same "Default
  domain exists" fact every OpenStack Keystone deployment has always exposed
  via other unauthenticated-adjacent surfaces (e.g. `clouds.yaml` conventions,
  federation metadata), and confirming its existence discloses nothing beyond
  that fact. No code change is planned; operators who consider even this
  disclosure unacceptable may override `[identity] default_domain_id` to a
  random value at bootstrap time.
- **Client ID Claim Enumeration:** `OpenStackAccessTokenClaims` carries
  `client_id`, which identifies the registering OAuth2 client
  (`OidcAccessTokenClaims`, §4, does not). If an attacker obtains an
  `OpenStackAccessTokenClaims` `access_token` (e.g., via XSS on an RP page or
  browser dev tools), they can extract the internal `client_id`. Since the token
  is cryptographically signed and aud-bound, enumeration alone does not enable
  privilege escalation. However, combined with misconfigured endpoints that
  ignore `aud` verification, it could enable targeted `client_id` guessing.
  Mitigation: strict `aud` enforcement in all downstream services; v2 may move
  `client_id` to a separate internal claim not exposed to RP `id_token`.
- **`keystone_ruleset_version` Blast Radius:** When OPA policy rules change, the
  ruleset hash (`keystone_ruleset_version`) updates. All outstanding tokens
  carrying the old hash become stale. This claim is advisory-only: downstream
  middleware accepts tokens with either the current or previous ruleset version
  during a rolling policy update. Only when a new version is published is the
  previous version retired (graceful 15-min window). The claim enables audit
  correlation but does not invalidate tokens.

---

## 12. Deferred: Token Exchange & Delegation (RFC 8693, v2)

`OpenStackAccessTokenClaims` already reserves the `delegation_context`
structurally-typed enum (§4) for trust/app-cred/EC2 delegation —
`DelegationContext` already has `Trust`/`AppCred`/`Ec2` variants alongside
`Plain` (§4) — but v1's grant set - `authorization_code`, `client_credentials`,
`refresh_token`, `device_code` - has no path that ever produces one of them.
Without a grant that can populate `DelegationContext::Trust`/`AppCred`/`Ec2`,
the `Plain` variant is baked into every v1 token. RFC 8693 Token Exchange is the
standards-based mechanism to close that gap, deferred to v2 rather than built
now, so it is recorded here rather than left implicit.

**Not the same RFC 8693 usage §1 calls a trap.** §1's "Circular Token Exchange
Trap" was an external-IdP-issued JWT being traded for a Fernet token -
eliminated by native OP issuance. This is the reverse direction: a
Keystone-native credential (trust, application credential, EC2 signature) traded
for a Keystone-native delegated JWT. That is a first-class OP capability this
ADR enables, not the workaround it replaces.

### v2 Shape (Not Built in Phases 1-5)

- **New grant type:** `urn:ietf:params:oauth:grant-type:token-exchange` added to
  `OAuth2Client.grant_types`.
- **Request:** `/token` accepts `subject_token` (an existing valid Keystone
  token - Fernet or native JWT - representing the trust/app-cred/EC2 grantor
  context), `subject_token_type`, and `requested_token_type`
  (`urn:ietf:params:oauth:token-type:access_token`).
- **Response:** A new `access_token` with `delegation_context` set to whichever
  of `DelegationContext::Trust { project_id }`, `AppCred { project_id }`, or
  `Ec2 { project_id }` (§4) matches the grantor context of the presented
  `subject_token` (replacing the v1 default `Plain`), `project_id` populated
  from the delegation object's immutable project, per security.md invariant I2.
- **Invariant enforcement unchanged:** the downstream middleware's I3
  scope-drift tripwire (§6, step 7) already branches on `auth_method != 'plain'`
  rather than a specific delegated variant, so it enforces I1/I2/I5 identically
  regardless of which of the three delegated variants token exchange populates;
  it does not introduce new enforcement paths.
- **Rate limiting:** the exchange endpoint is a `/token` sub-path and inherits
  the pre-hash enforcement of §7.A - the requesting client's credentials are
  quota-checked before any exchange logic runs.
- **Second candidate use (also deferred):** on-behalf-of downscoping for
  service-to-service hops - e.g., Nova holding a user's bearer `access_token`
  exchanges it for a narrower-audience, shorter-TTL token before calling
  Neutron, rather than forwarding the original bearer token unchanged across a
  service boundary. This reduces the blast radius of a token leaked or logged
  mid-hop, given §4 already establishes these tokens as bearer/stateless with no
  replay binding beyond TTL. Audience-narrowing semantics for this case are
  unspecified here and need their own design pass before implementation.

This section intentionally stops at the shape above - full request/response
schemas, `OAuth2Client` authorization checks for who may request delegation on
whose behalf, and CADF event definitions are left to the follow-up ADR amendment
that actually implements this grant.

### Implemented (Phase 6 Amendment)

The grant above is now built, as the follow-up amendment this section itself
anticipated. Concrete choices made during implementation:

- **`AppCred` only, not `Trust` or `Ec2`.** Only `ApplicationCredential`'s
  immutable project (`ApplicationCredential.project_id`) is carried on the object embedded in
  `AuthenticationContext::ApplicationCredential` once `subject_token` is
  validated through the existing `TokenApi::validate_to_context` pipeline - no
  new provider lookup needed. `AuthenticationContext::Trust` and
  `AuthenticationContext::Ec2Credential` are rejected outright
  (`invalid_grant`). While `Trust.project_id` is technically available, trust
  tokens have special handling characteristics (impersonation, trust-specific
  constraints) that make them unsuitable for token exchange.
  `AuthenticationContext::Ec2Credential` carries no
  such object (by design - see its own doc comment: a plain EC2 credential has no
  delegation metadata of its own unless it was itself minted through a trust or
  app-cred, in which case the *outer* `Trust`/`ApplicationCredential` context
  already applies). Deriving an EC2 credential's own bound project would need a
  provider lookup this phase does not add; guessing wrong on I2's boundary is
  not an acceptable risk. A future increment can add them once those concerns
  are addressed.
- **Authorization gating:** the exchanging `OAuth2Client` must hold
  `token-exchange` in its own `grant_types`, the same Tier-1/Tier-2-agnostic
  mechanism every other grant uses (`client.grant_types.contains(...)`) -
  enabling the grant on a client is itself an ordinary client update, gated by
  the existing `policy/oauth2/client/update.rego`. No new admin-only carve-out
  was added specifically for this grant (unlike `pre_authorized`), since -
  unlike pre-authorization skipping user consent entirely - a Token Exchange
  grant only ever re-expresses a delegation the presented `subject_token`
  already proves the caller holds; it grants no new authority beyond what that
  token's own chain already carries.
- **`keystone_ruleset_version`:** set to `0` (a sentinel, not a real ruleset
  hash) - a token-exchange grant does not go through a `MappingRuleSet` at all
  (the subject is an already-authenticated native Keystone credential, not an
  external ingress source), so there is no ruleset state to anchor to. The
  claim remains advisory-only (§11) and this sentinel does not affect
  downstream enforcement.
- **No audit-log-derived jti backfill dependency:** unlike §3's emergency
  rotation, Token Exchange needed no new audit query capability - the grantor
  object needed is already embedded in the validated
  `ValidatedSecurityContext`, no separate lookup or log query required.
- **CADF event:** reuses the existing `emit_oauth2_session_event` best-effort
  path (the same one `client_credentials`/`authorization_code` use), keyed on
  `client_id` - no new event type was needed since delegation-specific detail
  already lives in the returned `delegation_context` claim itself, and no
  emergency/critical posture applies to a routine token mint.

---

## 13. Fernet Coexistence & Long-Term Migration Strategy

`keystone-rs` is deployed **in parallel with Python Keystone** during the
migration phase: both serve the same v3 API behind a shared VIP, and existing
deployments overwhelmingly run the **Fernet** token provider with a shared,
filesystem-synchronized key repository. Everything in this ADR is therefore
additive by construction — the §6 middleware's explicit fall-through to the
existing Fernet filter chain is the load-bearing coexistence mechanism, and no
stage below invalidates a token or breaks a client that worked in the previous
stage.

### Stage 0 — Today: Fernet Interchangeability (shipped)

Python Keystone is the issuer of record. `keystone-rs` encodes/decodes
byte-compatible Fernet tokens from the shared key repository
(`token-driver-fernet` + `crates/key-repository`). Operational constraint:
Fernet key rotation must remain coordinated across both implementations
(same rotation tooling, same `max_active_keys` discipline).

### Stage 1 — v3 Token Format Parity (Phase 0)

The provider abstraction and Python-compatible JWS driver (§10, Phase 0) land.
`keystone-rs` can now stand in for Python Keystone regardless of which
`[token] provider` the deployment chose, and validates both formats during a
provider transition. This removes the last v3-surface reason a deployment
could not shift token _issuance_ traffic to `keystone-rs`.

### Stage 2 — OP Goes Live, Additive Only (Phases 1-5)

The OAuth2/OIDC surface ships. No existing flow changes: Fernet issuance and
validation continue untouched. New consumers onboard directly to JWT — cloud-
native workloads via `client_credentials`, third-party RPs via
`authorization_code`. The §6 middleware is injected into control-plane Paste
pipelines **in front of** `keystonemiddleware.auth_token`; requests without an
OP-issued Bearer JWT fall through unchanged. Rollout is therefore incremental
per service, per region, with instant rollback (remove the filter). Services
with the loosest revocation-latency requirements (read-heavy, low-criticality)
convert first; see the revocation gate below.

### Stage 3 — Machine Identity Migration

Highest-volume, lowest-friction migration: automated API consumers (billing
collectors, monitoring, orchestrators, K8s operators) move from application
credentials / stored passwords to registered `OAuth2Client`s. This is where
the validation-load win (§11, "Complete Database Decoupling") is actually
realized, since machines dominate request volume. Python Keystone is demoted
to serving existing human/v3 flows.

### Stage 4 — Human Flow Migration & Python Keystone Retirement

CLI login moves to the Device Authorization Grant; dashboards and portals
become OIDC RPs. Remaining v3 Fernet issuance is served by `keystone-rs`
alone (possible since Stage 1), and Python Keystone is removed from the VIP.
The RFC 8693 Token Exchange grant (§12, v2) eases the long tail: any client
still holding a valid Fernet token can trade it for a native JWT without
re-authenticating, inverting the §1 Circular Trap in the direction that helps
migration.

### Stage 5 — Fernet Sunset

A config switch moves Fernet to validate-only (no new issuance), then off.
`keystonemiddleware.auth_token` and the §6 fall-through path are removed from
Paste pipelines; Fernet keys are retired after the last token's `exp`.
End-state: a single asymmetric key lifecycle (§3) instead of two parallel key
repositories — retiring the "Increased Key Rotation Surface" risk in §11.

### Cross-Cutting Gate: Revocation Semantics Parity

Fernet validation consults revocation events on every back-channel check;
stateless JWTs wait out `exp` (§11, "Revocation Durability Gap"). A service
may only move from Stage 2's fall-through posture to preferring JWTs once its
operator explicitly accepts the 15-minute revocation window (or wires
back-channel introspection for its high-criticality operations). This
acceptance is per-service and must be recorded in the deployment's migration
runbook — it is the one semantic regression Fernet-to-JWT migration cannot
paper over, and it is the reason Stages 2-4 are ordered by revocation-latency
tolerance rather than by implementation convenience.
