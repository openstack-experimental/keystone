# 21. Stateless API-Key Ingress & Ephemeral Security Contexts for SCIM

**Date:** 2026-06-12

## Status

Proposed

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
    pub allowed_ips: Option<Vec<String>>,
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
3. It extracts the source IP from `X-Forwarded-For` **only** if the immediate
   upstream connection matches an explicitly configured `trusted_proxies` array
   (otherwise falling back to the raw TCP peer IP). It then validates this IP
   against the `allowed_ips` CIDR blocks.

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
operate under exactly _one_ scope.

```rust
pub async fn hydrate_ephemeral_context(...) -> Result<ValidatedSecurityContext, AuthenticationError> {
    let user_id = compute_deterministic_user_id(...);

    // Initialize strictly as Unscoped.
    let mut ctx = SecurityContext::new_ephemeral(IdentityInfo::Principal(PrincipalInfo { user_id }), ScopeInfo::Unscoped);

    // Enforce Single-Scope Constraint
    if match_result.authorizations.len() > 1 {
        return Err(AuthenticationError::MultipleScopesForbidden);
    }

    validate_target_entities_are_active(state, &match_result.authorizations)?;

    let mut effective_roles = Vec::new();
    if let Some(auth) = match_result.authorizations.first() {
        match auth {
            Authorization::Domain { domain_id, roles } => {
                ctx.set_scope(ScopeInfo::Domain(domain_id.clone()));
                effective_roles.extend(roles.clone());
            },
            Authorization::Project { project_id, roles } => {
                ctx.set_scope(ScopeInfo::Project(project_id.clone()));
                effective_roles.extend(roles.clone());
            },
            Authorization::System { .. } => {
                // System scopes are strictly forbidden for API-Key ingress.
                return Err(AuthenticationError::SystemScopeForbiddenForApiKey);
            }
        }
    }

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

### B. CRUD Endpoints

- **`POST /v4/api-keys`**: Generates a new key.
- **`GET /v4/api-keys`**: Lists metadata.
- **`PUT /v4/api-keys/{client_id}`**: Updates configurations.

### C. Revocation & Incident Response

- **`POST /v4/api-keys/{client_id}/revoke`**: **Emergency Revocation Path.**
  Sets `enabled: false`, stamps `revoked_at` and `revoked_by`, and emits a
  `control` CADF event. **It does not perform a hard delete.** This preserves
  the cryptographic footprint (`lookup_hash`) and metadata for incident response
  audits. Physical storage reclamation is deferred to the janitor after the
  organization's audit retention period.

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
  strings use the `subtle` crate for constant-time equality checks.

### C. Write-Time `is_system` Prohibition

- **Measures:** Allowing an API Key to hold `ScopeInfo::System` is highly
  dangerous. To prevent silent failures during auth-time, the prohibition is
  shifted to rule creation. If a `DomainManager` attempts to create or update a
  mapping rule where the `provider_id` belongs to an
  `IdentitySource::ApiClient`, and any authorization grants `is_system: true` or
  `Authorization::System`, the Mapping Engine CRUD API rejects it immediately
  with `422 Unprocessable Entity`.

### D. OPSEC Leakage & Log Injection

- **Measures:** 1. The API-key routing prefix allows explicit integration with
  DLP secret scanners (e.g., GitHub Advanced Security).

2. The `client_id` is excluded from the token format, neutralizing capability
   oracle attacks.
3. The Axum middleware actively scrubs the `Authorization` header from all
   internal application traces.

### E. X-Forwarded-For Spoofing

- **Measures:** IP allowlisting strictly reads the rightmost non-trusted IP in
  the `X-Forwarded-For` chain. This relies on an explicit, statically configured
  `trusted_proxies` CIDR array. If the immediate upstream connection is not in
  `trusted_proxies`, the application falls back to the raw TCP peer IP.

### F. Janitor Disablement, Asynchronous Drift & Physical Reclamation

- **Finding:** Asynchronous `last_used_at` writes may occasionally drop under
  heavy system pressure, causing active integrations to drift toward the 90-day
  PCI-DSS janitor threshold. Furthermore, tombstoned records from revocations
  accumulate indefinitely.
- **Measures:** 1. **Drift Absorption:** The system documents a maximum
  acceptable async write staleness of 24 hours. The janitor operates with a
  7-day grace period beyond the 90-day threshold, mathematically absorbing this
  write-failure window. Before executing a disablement, the janitor emits a
  `maintenance` CADF audit event and pushes an administrative alert payload to
  the system notification bus.

2. **Physical Reclamation:** To prevent unbounded keyspace bloat, the janitor
   executes a secondary garbage-collection phase. Any `ApiClientResource`
   containing a `revoked_at` timestamp older than 365 days is permanently purged
   from FjallDB.
