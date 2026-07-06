# 21. Stateless API-Key Ingress & Ephemeral Security Contexts for SCIM

**Date:** 2026-06-12

**Last-revised:** 2026-07-02 (implementation-status review)

## Status

Accepted

**Implementation-status review 2026-07-02:** implementation confirmed complete
against every §7 Security Invariant and §5/§6 requirement (see §8). Status
moved from Proposed to Accepted. §6.B's `subtle`-crate wording corrected to
match what's actually implemented (Argon2's own constant-time comparison);
this was a doc/code drift, not a security gap. Added janitor and full-pipeline
integration test coverage (previously mock/unit-test only) per §8.

**Security review 2026-06-24:**

- F1 MEDIUM: empty authorization list now fails authentication instead of
  producing an unscoped context (§4 + Invariant 1);
- F2 MEDIUM: §3 Step 2 XFF algorithm aligned with §6.E to prevent IP-allowlist
  bypass via leftmost-take (Invariant 4);
- F3 LOW: `allowed_ips: None` semantics specified as "no restriction" (Invariant
  5);
- F4 LOW: `compute_deterministic_user_id` input contract specified as
  `client_id`-derived (Invariant 6). New §7 Security Invariants section added.

## Context

Machine-to-machine SCIM provisioning integrations utilizing static bearer
tokens, bypassing standard Fernet token lifecycle requirements.

## Reference

Extends ADR 0017 (Security Context) and ADR 0020 (Unified Mapping Engine).

---

## 1. Context & Motivation

Enterprise Identity Providers (IdPs) utilizing the System for Cross-domain
Identity Management (SCIM) protocol generally require a static, long-lived
"Secret Token" passed directly to target API endpoints via the
`Authorization: Bearer <Token>` HTTP header.

To support SCIM seamlessly without requiring a prior credential exchange at
`/v3/auth/tokens`, `keystone-rs` utilizes a specialized ingress adapter capable
of intercepting API keys, verifying them, and constructing a fully valid
`SecurityContext` in a zero-roundtrip, stateless execution path, compliant with
the Unified Mapping Engine (ADR 0020).

---

## 2. Ownership & Storage Model

API Keys are **Domain-Owned Machine Identities**, strictly decoupled from human
user accounts.

### A. Keyspace Configuration

| Functional Purpose             | Key Namespace Pattern                          | Value Payload                |
| ------------------------------ | ---------------------------------------------- | ---------------------------- |
| **API Client Crypto Resource** | `data:api_client:v1:<domain_id>:<lookup_hash>` | `ApiClientResource` (Struct) |

### B. Resource Data Structure

To prevent secret leakage in application error logs, the struct implements a
custom `Debug` trait that explicitly replaces `secret_hash` with `[REDACTED]`.
All timestamps are stored as **UTC Epoch seconds**.

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiClientResource {
    pub domain_id: String,
    pub provider_id: String,
    pub client_id: String,             // Public UUID for management API references
    pub lookup_hash: String,           // Fast SHA-256 hash of the token for O(1) DB index lookups
    pub secret_hash: String,           // PHC format Argon2id hash (e.g., $argon2id$v=19$m=65536$...)
    pub allowed_ips: Option<Vec<String>>,  // None = no IP restriction (any source IP accepted)
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: i64,               // UTC Epoch seconds
    pub expires_at: i64,               // Mandatory TTL (UTC Epoch seconds)
    pub last_used_at: Option<i64>,     // UTC Epoch seconds
    pub revoked_at: Option<i64>,       // Tombstone for audit retention (UTC Epoch seconds)
    pub revoked_by: Option<String>,    // User ID of the revoking operator
}

```

### C. Token Generation & Opaque Formatting

The token consists of a prefix, high-entropy random data, and a CRC32 checksum
for fast format validation. **Format:**
`kscim_{32_bytes_base62_entropy}_{crc32}`

When the token is generated:

1. `lookup_hash` is computed as `SHA-256(entropy)` to serve as the database
   index.
2. `secret_hash` is computed as `Argon2id(entropy)` for cryptographic
   verification.
3. The `client_id` (a standard UUID) is returned to the administrator for CRUD
   operations but is **never** embedded in the token or HTTP headers.

---

## 3. Execution Flow: The Ingress Pipeline

The middleware processes incoming SCIM requests through a strict,
short-circuiting pipeline.

### Step 1: Format Check & Hash-Based Rate Limiting

1. The middleware computes the CRC32 of the entropy. If it does not match the
   appended checksum, the request is dropped immediately. _(Note: This is
   strictly a cheap format validity check to reject malformed data, not a
   cryptographic security boundary)._
2. The middleware computes the fast `SHA-256(entropy)` to derive the
   `lookup_hash`.
3. **Rate Limiting:** A sliding-window token bucket enforces a strict rate limit
   keyed on the `lookup_hash`. If the request fails the CRC32 check (meaning no
   valid entropy exists), the rate limiter falls back to keying on the source IP
   to absorb brute-force garbage traffic. This ensures legitimate SCIM traffic
   originating from shared enterprise egress IPs (like Entra ID NAT gateways) is
   not inadvertently blocked by other tenants.

### Step 2: Database Lookup & IP Whitelisting

1. The middleware queries FjallDB for
   `data:api_client:v1:<domain_id>:<lookup_hash>`.
2. It verifies `enabled: true` and `current_utc_seconds < expires_at`.
3. It determines the effective client IP using the **rightmost non-trusted-proxy
   IP** algorithm: append the raw TCP peer address to the right of the
   `X-Forwarded-For` header chain, then walk right-to-left, returning the first
   address that is **not** in the statically configured `trusted_proxies` CIDR
   array. If the raw TCP peer is not in `trusted_proxies`, it is used directly
   (XFF is not consulted). This prevents leftmost-entry XFF spoofing through
   untrusted intermediate hops. The resulting effective IP is then validated
   against `allowed_ips` CIDR blocks. If `allowed_ips` is `None`, the IP check
   is skipped (no restriction applies).

### Step 3: Cryptographic Verification & Lazy Re-Hash

The entropy is verified against the PHC-formatted `secret_hash` using
`tokio::task::spawn_blocking`.

- **Lazy Re-Hash:** If the hash verifies successfully but the PHC string
  parameters (e.g., memory cost) are lower than the currently configured global
  minimums, the engine enqueues an asynchronous task to re-hash and update the
  database record.
- `last_used_at` is updated asynchronously.

### Step 4: Ephemeral Context Hydration (Anti-Bleed Scoping)

To prevent cross-domain privilege bleeding, an Ephemeral Security Context must
operate under exactly _one_ scope. API Keys are **domain-owned machine
identities** (§2); by design only a domain-scoped authorization is accepted.
This is an allowlist -- `Authorization::Domain` is the sole accepted variant
-- rather than a denylist naming each forbidden authorization type, so it
also covers any authorization type added in the future.

```rust
pub async fn hydrate_ephemeral_context(...) -> Result<ValidatedSecurityContext, AuthenticationError> {
    // Derived exclusively from client_id (the unique key UUID), never from
    // provider_id, so each API key produces a distinct audit identity even
    // during N:1 rotation periods (§5.D).
    let user_id = compute_deterministic_user_id(resource.client_id);

    // Initialize strictly as Unscoped.
    let mut ctx = SecurityContext::new_ephemeral(IdentityInfo::Principal(PrincipalInfo { user_id }), ScopeInfo::Unscoped);

    // Invariant: a key whose UME mapping resolves to zero authorizations MUST
    // fail authentication. Returning an unscoped/role-less context would push
    // the access decision entirely onto downstream OPA policy coverage.
    if match_result.authorizations.is_empty() {
        return Err(AuthenticationError::NoAuthorizationsFound);
    }

    // Enforce Single-Scope Constraint
    if match_result.authorizations.len() > 1 {
        return Err(AuthenticationError::MultipleScopesForbidden);
    }

    validate_target_entities_are_active(state, &match_result.authorizations)?;

    let authorization = &match_result.authorizations[0];

    // System scopes are strictly forbidden for API-Key ingress.
    if matches!(authorization, Authorization::System { .. }) {
        return Err(AuthenticationError::SystemScopeForbiddenForApiKey);
    }

    // Allowlist: only a domain-scoped authorization is accepted. API Keys
    // are domain-owned machine identities (§2), so anything else --
    // `Authorization::Project` included -- is rejected here rather than
    // being enumerated as its own forbidden case.
    let Authorization::Domain { domain_id, roles } = authorization else {
        return Err(AuthenticationError::NonDomainScopeForbiddenForApiKey);
    };
    ctx.set_scope(ScopeInfo::Domain(domain_id.clone()));

    let mut effective_roles = roles.clone();
    effective_roles.sort();
    effective_roles.dedup();
    Ok(ValidatedSecurityContext::finalize(ctx, effective_roles))
}

```

---

## 4. Routing & Boundary Enforcement

**TLS 1.3 Minimum Floor:** Long-lived bearer tokens are functionally equivalent
to passwords. Enforcement is delegated to the infrastructure Reverse Proxy
(Nginx/HAProxy), which is strictly configured to require **TLS 1.3** for all
traffic terminating at the `/SCIM/v2` paths.

**Sub-Router Isolation:** The API-Key middleware is mounted exclusively on the
SCIM sub-router. Core OpenStack infrastructure endpoints utilize the standard
Fernet middleware and will reject API keys outright.

---

## 5. Administrative CRUD, Auditing & OPA Policies

### A. Privilege Matrix & OPA Integration

Management of API keys relies strictly on defined OPA policies per ADR-0002.

- `identity:api_key:create`
- `identity:api_key:list`
- `identity:api_key:update`
- `identity:api_key:revoke`
- `identity:api_key:simulate_access`

**The `DomainManager` Role:** These policies require the `DomainManager` role
(or `SystemAdmin`). `DomainManager` represents an explicit administrative
capability scoped strictly to managing identities and integrations within a
domain. **`DomainAdmin` must not be used**, as it provides overarching
infrastructure privileges. The `DomainManager` role and its associated policy
mappings must be formally ratified in an upcoming revision to **ADR 0002
(OpenStack Policy Engine Integration)** to ensure central governance of the RBAC
hierarchy.

**Implementation status:** The five policies above are implemented under
`policy/identity/api_key/` (`create.rego`, `list.rego`, `update.rego`,
`revoke.rego`, `simulate_access.rego`; a sixth, `show.rego`, gates a
`GET /v4/api-keys/{client_id}` endpoint not explicitly enumerated by this
section but added for consistency with every other v4 resource), each
requiring the pre-existing `manager` role scoped to the key's own domain
(this codebase's realization of `DomainManager`, used identically by
`identity.user.*` and `identity.mapping.ruleset.*`), or `admin`/`is_admin`
(`SystemAdmin`). Unlike `identity.user.list`, there is no `reader` carve-out
on `identity:api_key:list` — all actions sit at the same privilege bar.

ADR 0024's SCIM resource-CRUD policies (`identity/scim/user/*`) reuse this same
`manager`/`admin` string convention, but resolve it through a materially
different path: those requests are authenticated by an API key, which carries
no Role/RoleAssignment at all, so the `manager`/`admin`/`scim_provisioner`
strings they check are produced entirely by the realm's own `MappingRuleSet`
output (§3 Step 4 above), never by a `RoleAssignment` row. The admin CRUD
surface for API keys/realms documented in this section is the opposite case —
invoked by a Fernet-authenticated human operator, where `manager`/`admin` can
be a real RBAC grant.

This does not by itself constitute the formal ADR 0002 ratification called for
above (see §8).

### B. CRUD Endpoints

- **`POST /v4/api-keys`**: Generates a new key.
- **`GET /v4/api-keys`**: Lists metadata.
- **`PUT /v4/api-keys/{client_id}`**: Updates configurations.

### C. Revocation & Incident Response

- **`POST /v4/api-keys/{client_id}/revoke`**: **Emergency Revocation Path.**
  Sets `enabled: false`, stamps `revoked_at` and `revoked_by`, and emits a CADF
  event (`action: revoke`). **It does not perform a hard delete.** This
  preserves the cryptographic footprint (`lookup_hash`) and metadata for
  incident response audits. Physical storage reclamation is deferred to the
  janitor after the organization's audit retention period.
- **Revocation is irreversible via `PUT`.** `ApiKeyApi::update` MUST reject
  (`409 Conflict`) any patch that sets `enabled: true` on a key whose
  `revoked_at` is set. Without this, an emergency revocation could be undone
  by an ordinary configuration update, defeating its purpose as an
  incident-response control (see Invariant 9, §7).

### D. Zero-Downtime Key Rotation (N:1 Provider Mapping)

Because the `ApiClientResource` is indexed by its cryptographic `lookup_hash`
rather than the provider slug, the architecture natively supports an N:1
relationship between API keys and a `provider_id`. Multiple distinct keys can
safely declare the same `provider_id` without database collision.

To execute a zero-downtime rotation, operators generate a new Key B bound to the
existing `provider_id`. Both Key A and Key B will independently resolve against
the exact same ADR 0020 mapping ruleset
(`data:mapping:v1:<domain_id>:<provider_id>`). The IdP is updated with Key B,
traffic migrates seamlessly, and Key A is subsequently revoked.

### E. The Dry-Run Auditing Endpoint

- **Endpoint:** `POST /v4/api-keys/simulate-access`
- **Payload:** `{"client_id": "<uuid>"}` (Shifted to the body to prevent
  `client_id` leakage in proxy access logs).
- **Authentication Required:** Strictly requires `DomainManager` or
  `SystemAdmin` credentials via a valid Fernet token.
- **Behavior:** Performs a mock authentication pass, returning a fully resolved
  JSON matrix detailing the API key's current authorization topology.

---

## 6. Threat Model & Required Mitigations

### A. Targeted Credential Stuffing & DoS

- **Measures:** Rate limiting is enforced via a token bucket keyed primarily on
  `lookup_hash` to protect legitimate shared IdP egress IPs. Argon2id
  verification is constrained to a bounded `spawn_blocking` pool that sheds load
  (`503 Service Unavailable`) if saturated.

### B. Argon2id Parameters & Timing Side-Channels

- **Measures:** Argon2id parameters are globally defined in `keystone.conf` with
  OWASP-compliant strict minimums (e.g., $m=65536, t=3, p=4$). Dummy hashes for
  invalid tokens utilize these exact parameters. Comparisons against the PHC
  strings are constant-time, performed internally by the `argon2` crate's
  `verify_password` (not a separate manual `subtle::ConstantTimeEq` step --
  `verify_password` already provides this property, so a second comparison
  would be redundant).

### C. Write-Time `is_system` Prohibition

- **Measures:** Allowing an API Key to hold `ScopeInfo::System` is highly
  dangerous. To prevent silent failures during auth-time, the prohibition is
  shifted to rule creation. If a `DomainManager` attempts to create or update a
  mapping rule where the `provider_id` belongs to an
  `IdentitySource::ApiClient`, and any authorization grants `is_system: true` or
  `Authorization::System`, the Mapping Engine CRUD API rejects it immediately
  with `422 Unprocessable Entity`. The same write-time guard also enforces a
  domain-scope-only allowlist for `IdentitySource::ApiClient` rulesets: once
  `is_system`/`Authorization::System` is excluded, every remaining
  authorization MUST be `Authorization::Domain` -- API Keys are domain-owned
  machine identities (§2) -- so `Authorization::Project` (or any other
  non-domain authorization) is rejected the same way.

### D. OPSEC Leakage & Log Injection

- **Measures:** 1. The API-key routing prefix allows explicit integration with
  DLP secret scanners (e.g., GitHub Advanced Security).

2. The `client_id` is excluded from the token format, neutralizing capability
   oracle attacks.
3. The Axum middleware actively scrubs the `Authorization` header from all
   internal application traces.

### E. X-Forwarded-For Spoofing

- **Measures:** IP allowlisting uses the **rightmost non-trusted-proxy IP**
  algorithm (§3 Step 2): the raw TCP peer is appended to the right of the XFF
  chain, then the chain is walked right-to-left and the first address not in
  `trusted_proxies` is used as the effective client IP. If the TCP peer is
  untrusted, XFF is not consulted at all. This prevents an attacker from
  bypassing `allowed_ips` by routing through an untrusted intermediate proxy
  that prepends a spoofed originating IP to `X-Forwarded-For` before a trusted
  proxy. `allowed_ips: None` means no IP restriction is applied.

### F. Janitor Disablement, Asynchronous Drift & Physical Reclamation

- **Finding:** Asynchronous `last_used_at` writes may occasionally drop under
  heavy system pressure, causing active integrations to drift toward the 90-day
  PCI-DSS janitor threshold. Furthermore, tombstoned records from revocations
  accumulate indefinitely.
- **Measures:** 1. **Drift Absorption:** The system documents a maximum
  acceptable async write staleness of 24 hours. The janitor operates with a
  7-day grace period beyond the 90-day threshold, mathematically absorbing this
  write-failure window. Before executing a disablement, the janitor emits a
  CADF event (`action: disable_inactive`) and pushes an administrative alert
  payload to the system notification bus.

2. **Physical Reclamation:** To prevent unbounded keyspace bloat, the janitor
   executes a secondary garbage-collection phase. Any `ApiClientResource`
   containing a `revoked_at` timestamp older than 365 days is permanently purged
   from FjallDB.

3. **Per-key fault isolation:** a single key failing its disablement or purge
   (e.g. a storage CAS conflict with a concurrent admin update) MUST NOT
   prevent the rest of the sweep pass from running. Failures are counted and
   logged, and retried on the next pass.

---

## 7. Security Invariants

The following invariants MUST hold at all times. Any implementation deviation is
a security defect.

1. **No-authorizations → authentication failure.** `hydrate_ephemeral_context`
   MUST return `Err(AuthenticationError::NoAuthorizationsFound)` when the UME
   resolves zero authorizations for a key. It MUST NOT produce a
   `ValidatedSecurityContext` with `ScopeInfo::Unscoped` and an empty role set.

2. **Single-scope enforcement.** A key MUST NOT authenticate if its UME mapping
   resolves to more than one authorization entry (`MultipleScopesForbidden`).

3. **System scope prohibited at ingress.** An `Authorization::System` match in
   `hydrate_ephemeral_context` MUST return `SystemScopeForbiddenForApiKey`. The
   companion write-time prohibition (§6.C) is defense-in-depth, not a substitute
   for this runtime check.

3a. **Domain scope only, by allowlist.** API Keys are domain-owned machine
   identities (§2). Once the Invariant 3 system-scope check passes,
   `hydrate_ephemeral_context` MUST accept only `Authorization::Domain`; any
   other authorization (`Authorization::Project` included) MUST return
   `NonDomainScopeForbiddenForApiKey` rather than resolving a non-domain
   `ScopeInfo`. This is an allowlist keyed on the accepted variant, not a
   denylist enumerating each forbidden one, so it also covers any
   authorization type added in the future. The companion write-time
   prohibition (§6.C) is defense-in-depth, not a substitute for this runtime
   check.

4. **XFF rightmost-non-trusted algorithm.** Effective client IP MUST be the
   rightmost address in the XFF chain (with TCP peer appended) that is not in
   `trusted_proxies`. Implementations MUST NOT use XFF[0] (leftmost) as the
   effective IP under any trusted-proxy configuration.

5. **`allowed_ips: None` means unrestricted, not deny-all.** When `allowed_ips`
   is absent from an `ApiClientResource`, the IP check MUST be skipped entirely.
   Implementations MUST treat a missing field and `Some([])` identically (no
   restriction).

6. **`compute_deterministic_user_id` MUST be derived from `client_id`.** The
   ephemeral user_id is computed from the key's unique `client_id` UUID, not
   from `provider_id`. Two distinct keys sharing a `provider_id` MUST produce
   different user_ids so their audit records are not conflated.

7. **Dummy-hash timing parity.** When no `ApiClientResource` is found for a
   given `lookup_hash`, a full Argon2id dummy computation using current global
   parameters MUST be performed before returning a failure response, preventing
   timing-based enumeration of valid lookup hashes.

8. **Argon2id minimum parameters enforced.** The parameters embedded in any
   stored PHC string MUST be validated against configured minimums before
   accepting a verification as sufficient. Parameters below the floor trigger a
   lazy re-hash regardless of verification outcome.

9. **Revocation is irreversible via the update surface.** `ApiKeyApi::update`
   MUST reject with a conflict error any patch that would set `enabled: true`
   on an `ApiClientResource` whose `revoked_at` is `Some`. A revoked key MUST
   NOT become authenticatable again through `PUT /v4/api-keys/{client_id}`;
   the only way back into service is administratively creating a new key
   (§5.D covers zero-downtime rotation for exactly this case).

---

## 8. Implementation Status

- **Done:**
  - The SCIM ingress authentication pipeline (§3), including all security
    invariants (§7).
  - The write-time `is_system` prohibition (§6.C), plus the domain-scope-only
    allowlist (Invariant 3a): both `hydrate_ephemeral_context`
    (`crates/core/src/api/api_key_auth.rs`) and the write-time mapping
    validation (`crates/core/src/mapping/validation.rs`) accept only
    `Authorization::Domain` for `IdentitySource::ApiClient` rulesets, since
    API Keys are domain-owned machine identities (§2). `Authorization::Project`
    is rejected as a consequence of the allowlist, not as a named special
    case. The `simulate-access` dry-run endpoint (§5.E) mirrors this and
    reports `matched: false` for any non-domain match.
  - The storage layer and internal `ApiKeyApi`/`ApiKeyBackend` traits (§2,
    §5.D) with a Raft-backed implementation, including the janitor's
    cross-domain `list_all` and hard-delete `purge` operations (§6.F).
  - Rate limiting (§6.A).
  - The OPA policies for §5.A (`policy/identity/api_key/`), plus a `show`
    policy for the `GET /v4/api-keys/{client_id}` endpoint this section does
    not explicitly enumerate.
  - The `/v4/api-keys*` HTTP admin surface (§5.B): create, list, show,
    update. `update` rejects (`409 Conflict`) re-enabling a revoked key
    (Invariant 9, §5.C), enforced in `ApiKeyService::update`
    (`crates/core/src/api_key/service.rs`) so it holds for every caller, not
    just the HTTP layer.
  - The revoke endpoint (§5.C), including a CADF audit event
    (`action: revoke`).
  - The dry-run `simulate-access` endpoint (§5.E). Deviates from the literal
    request shape in one way: the payload also carries `domain_id` alongside
    `client_id`, because this implementation's storage partitions
    `ApiClientResource` by domain (§2.A), making a `client_id`-only lookup
    impossible without it. The same constraint applies to show/update/revoke,
    which take `domain_id` as a query parameter rather than encoding it in
    the (flat, ADR-specified) URL path. It also does not call
    `MappingApi::authenticate_by_mapping` -- that path may provision a real
    user row for `IdentityMode::Local` rules, an unacceptable side effect for
    a dry-run endpoint -- and instead evaluates the ruleset and reads the
    matched `Authorization`'s roles directly.
  - The janitor (§6.F): an in-process, leader-gated `tokio::time::interval`
    sweep (mirroring the storage crate's existing emergency-rotation
    confirmation-timeout sweeper in `crates/storage/src/app.rs`) that
    disables keys inactive beyond `janitor_inactive_days` +
    `janitor_grace_days`, purges tombstones older than
    `janitor_tombstone_retention_days`, and emits a CADF event
    (`action: disable_inactive`) per disablement. Per-key failures are
    isolated (§6.F.3): one key's disablement/purge error is logged and
    counted in `JanitorReport::errors`, not propagated, so it cannot stall
    the rest of the pass.

    Action strings are intentionally more specific than this ADR's earlier
    `control`/`maintenance` category wording (`revoke`/`disable_inactive`
    rather than a repeated generic label) -- more useful for audit
    filtering; the wording above has been reconciled to match the code
    rather than the other way around.
  - Integration test coverage exercising the real Raft-backed provider and a
    live HTTP router, not just mocks: a janitor sweep suite
    (`tests/integration/src/api_key/janitor.rs`) covering disablement,
    tombstone purge, and cross-domain sweeping against the real storage/CAS
    layer; and a full-pipeline suite
    (`tests/integration/src/api_key/ingress.rs`) driving real requests
    through `openstack_keystone::scim::router()` -- successful end-to-end
    authentication, wrong-secret rejection, an XFF-spoof-through-a-trusted-
    proxy regression case (Invariant 4), and rate-limit tripping (§6.A).
- **Known gap:** the ADR's "pushes an administrative alert payload to the
  system notification bus" (§6.F) is not implemented -- no pub/sub or webhook
  dispatch infrastructure exists in this codebase yet. The janitor emits a
  structured `warn!` log and its CADF event (`action: disable_inactive`) as
  the closest existing substitutes; a real notification channel is unbuilt
  follow-up work, not something to improvise here.
- **Not yet done:** the `DomainManager` role's formal ratification in ADR
  0002. In the interim, the OPA policies enforce the equivalent scoped
  privilege using this codebase's existing `manager` role (§5.A).
