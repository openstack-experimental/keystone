# 20. Decoupled Multi-Tenant Identity Federation & Named ABAC Mapping Engine

**Date:** 2026-06-11

## Status

Approved

## Context

High-performance, low-latency identity federation mapping for `keystone-rs`
using a distributed **Raft + FjallDB** architecture.

---

## 1. Context & Motivation (Single vs. Dedicated Engine)

Identity federation platforms must map external cryptographic assertions into
localized authorization contexts. Traditional identity systems treat
authentication vectors as isolated, self-contained plugin mounts (e.g., separate
`auth/kubernetes`, `auth/oidc`, and `auth/cert` backends).

In a high-throughput, multi-tenant distributed cloud operating system like
`keystone-rs` built on a Raft + FjallDB consensus architecture, continuing down
the path of dedicated plugin mapping engines creates severe architectural
liabilities:

1. **Massive Code Duplication:** Re-implementing conditional expression
   evaluation (`equals`, `any_of`, `regex`) and macro-string parsing across
   multiple distinct protocol blocks widens the bug surface area.
2. **Fragmented Security Boundaries:** Ensuring strict multi-tenant isolation,
   data sanitization, and domain containment becomes exceptionally brittle when
   logic is spread across completely separate protocol codebases.
3. **Raft Log Bloat & Invalidation Risks:** Modifying multi-auth tenant
   parameters simultaneously requires executing separate, non-atomic API writes
   across distinct plugin endpoints, forcing independent entries through the
   Raft consensus log and risking partial, inconsistent authorization states.
4. **Abuse of Token Restrictions:** In legacy iterations, because external
   service accounts lacked a standard local user row, the system was forced to
   issue an unscoped token format and attach a heavy `token_restriction` payload
   to "clamp" the token into a project container. This abused a client-side
   narrowing tool as an administrative configuration table.

### The Unified Engine Advantage

`keystone-rs` enforces a strict **Split-Execution Model**. Ingress adapters
manage protocol-specific cryptographic validation (signature checking, CRL
validation, remote `TokenReview` executions, and SPIFFE SVID bundle
verification) and immediately flatten the output into a uniform text claims map
(`HashMap<String, Vec<String>>`). Downstream authorization is then handled by a
single, centralized, protocol-blind **Unified Mapping Engine**.

By combining this unified engine with a two-phase **`SecurityContext`**
validation framework, unbacked service accounts (Kubernetes pods, automated mTLS
agents, and SPIFFE control-plane daemons) become native, first-class citizens.
They receive fully scoped, immutable tokens from birth without generating
orphaned rows or database bloat in the local user tables.

Furthermore, to eliminate privilege escalation pathways, any ruleset that
contains a control-plane bypass instruction (`is_system: true`) is structurally
classified as an **Immutable System Mapping**. These maps are blocked from
undergoing subsequent API modifications, updates, or incremental mutations of
any kind.

### Convergence of Local and Distributed Control Planes

To simplify verification logic and prevent security context bifurcation, the
system merges its two system-level superuser authorization paths:

- **The Mapped Route (`is_system`):** Mapped via global, cluster-wide SPIFFE or
  infrastructure rulesets for service-to-service communication across separate
  physical nodes.
- **The Local Bootstrap Route (`is_admin`):** Established natively within the
  `SecurityContext` when an operator connects locally over a secure Unix Domain
  Socket (UDS) with a loopback SPIFFE identity matching the static application
  configuration file.

Both paths are verified through the same strict execution gates, resolving onto
identical system-service shortcut variables to permit fast-path control-plane
transactions.

### Scope, Exclusions, and Trust Boundaries

This ADR defines the unified mapping model, validation rules, storage keyspace,
and execution engine. It explicitly excludes:

- **Session State Management (`AuthState`)** — PKCE verifiers, OIDC state
  tokens, and nonce tracking are handled by the ingress layer.
- **Ingress Trust Boundary** — Ingress adapters are compiled in-tree or run as
  internal static libraries within the application binary's native memory space,
  preventing side-channel data injection.
- **Application Credentials for Virtual Users** — Any principal initialized as
  `IdentityInfo::Principal` is strictly blocked from executing application
  credentials, regular credentials and trusts eliminating the risk of unbacked
  service accounts spawning persistent API keys.

---

## 2. Ingress Phase: Provider Configuration Resources (The Crypto Inputs)

The `provider_id` is a tenant-local functional slug binding an ingress protocol
instance to its access rules. These configuration resource models explicitly
contain their own `domain_id` and `provider_id` keys to enforce structural
identifier symmetry across administrative lookup routines.

### A. OIDC Identity Provider (IdP) Resource

```rust
pub struct OidcProviderResource {
    pub domain_id: Option<String>,    // Owning tenant domain boundary (None if global system mapping)
    pub provider_id: String,              // Functional configuration slug anchor
    pub issuer: String,                   // e.g., "https://auth.acme.com"
    pub client_id: String,                // Client ID registered at the external IdP
    pub client_secret: Option<String>,    // Secret used for authorization code exchanges
    pub jwks_uri: String,                 // Cached public keys URI for signature verification
    pub allowed_redirect_uris: Vec<String>,
    pub oidc_scopes: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
}

```

### B. Kubernetes Cluster Issuer Resource

```rust
pub struct K8sClusterResource {
    pub domain_id: String,
    pub provider_id: String,           // Functional configuration slug anchor
    pub kubernetes_host: String,       // e.g., "https://api.eks.amazonaws.com"
    pub kubernetes_ca_cert: String,    // Public cluster CA certificate
    pub token_reviewer_jwt: String,    // Service account token to execute TokenReviews
    pub disable_local_ca_jwt: bool,    // Force remote verification over local decoding
}

```

### C. SPIFFE Trust Domain Resource

```rust
pub struct SpiffeTrustResource {
    pub domain_id: String,
    pub provider_id: String,           // Functional configuration slug anchor
    pub trust_domain: String,          // e.g., "prod.keystone.internal"
    pub trust_bundle_pem: String,      // Validating root keys for SVID validation
}

```

---

## 3. Downstream Phase: The Named Mapping Model

The rules engine evaluates claims maps using the `MappingRuleSet`. Rules are
structured as an ordered vector where array position defines execution priority.
However, each individual rule includes an immutable, alphanumeric `name` handle.
This enables operators to execute fine-grained additions, deletions, and updates
in the middle of the priority vector without relying on volatile integer
indices.

### Data Structural Spec (`src/identity/mapping/model.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainResolutionMode {
    Fixed,            // Locked to mapping.domain_id; claims templates in user_domain_id are rejected
    ClaimsOrMapping,  // System-Admin Only: Rules may override mapping.domain_id via claims templates
    ClaimsOnly,       // System-Admin Only: Neither mapping nor provider is bound to a domain
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentitySource {
    Federation { idp_id: String },
    K8s { cluster_id: String },
    Spiffe { trust_domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRuleSet {
    pub mapping_id: String,
    pub domain_id: Option<String>,  // Forced to None ("global") for ClaimsOnly/ClaimsOrMapping modes
    pub provider_id: String,
    pub source: IdentitySource,
    pub domain_resolution_mode: DomainResolutionMode,
    pub allowed_domains: Vec<String>,   // Whitelist of domain IDs that claims-based interpolation may resolve to. Mandatory and non-empty for ClaimsOnly/ClaimsOrMapping modes. For Fixed mode, must be empty (no claims-based interpolation possible)
    pub enabled: bool,
    pub rules: Vec<MappingRule>,
    pub ruleset_version: u128,    // Content-aware SHA-256 hash (first 16 bytes) of full ruleset — detects reordering, renaming, authorization swaps, not just addition/deletion
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRule {
    pub name: String,
    pub description: Option<String>,
    pub r#match: MatchCriteria,
    pub identity: IdentityBinding,
    pub authorizations: Vec<Authorization>,
    pub groups: Vec<GroupAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBinding {
    pub user_name: String,
    pub user_id:   Option<String>,
    pub user_domain_id: Option<String>,     // Template: resolves to domain UUID string at evaluation time
    pub is_system: Option<bool>,       // Nuclear control-plane shortcut bypass flag
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Authorization {
    Project {
        project_id: String,
        project_domain_id: String,
        roles: Vec<RoleRef>,
    },
    Domain {
        domain_id: String,
        roles: Vec<RoleRef>,
    },
    System {
        system_id: String,
        roles: Vec<RoleRef>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaimCondition {
    Equals { claim: String, value: serde_json::Value },
    AnyOf { claim: String, values: Vec<serde_json::Value> },
MatchesRegex { claim: String, regex: String },
}

/* ClaimCondition helpers:
   - claim_name(): Extracts the claim key from any variant (Equals, AnyOf, MatchesRegex).
   - walk_all_claim_conditions(): Flattened iterator over all claim conditions nested
     within a MappingRule's match criteria. Walks recursively through nested groups
     to collect every leaf ClaimCondition. Used during write-time validation to verify
     all regex patterns and check template safety before persistence.
*/

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchCriteria {
    AllOf(Vec<MatchCondition>),
    AnyOf(Vec<MatchCondition>),
    AllOfStrict {
        conditions: Vec<MatchCondition>,
        require_all_keys: bool,  // If true, match fails if any referenced claim key is absent from the claims map
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchCondition {
    Condition(ClaimCondition),
    Nested(Box<MatchCriteria>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupAssignment {
    pub group_id: String,                   // Immutable UUID anchor — prevents name-collision attacks
    pub group_name: String,                 // Template for display/lookup; interpolated at runtime
    pub group_domain_id: Option<String>,
    pub strategy: Option<GroupStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupStrategy {
    CreateOrGet,
    Get,
}

```

---

## 4. State Persistence: The Shadow Virtual User Registry

Downstream OpenStack microservices (e.g., Nova, Neutron) or admin users may
perform a `GET /v3/users/{user_id}` call to resolve user attributes.
Furthermore, during token verification, the original HTTP claims map is
completely gone - Keystone only receives the encrypted Fernet token byte string.

To fulfill the token roundtrip without passing bloated claims inside the token,
the mapping engine derives a deterministic identifier for unbacked principals
during authentication — computed as the first 16 bytes of
`HMAC-SHA256(cluster_salt, workload_id || provider_id)`, formatted as a
UUIDv4-compatible string — and registers a stateful bridge record inside the
**Shadow Virtual User Registry** within FjallDB.

`cluster_salt` is a 256-bit cryptographically random key generated at cluster
bootstrap, stored in the static application configuration, and excluded from all
API responses. HMAC-SHA256 replaces naive UUIDv5 (which relies on SHA-1) to
provide a one-way, non-invertible derivation: even if an attacker knows the
`provider_id` and `workload_id` (e.g., K8s service account names, SPIFFE URIs),
they cannot reverse the salt or feasibly enumerate shadow registry keys without
brute-forcing the full HMAC output space.

```rust
pub struct ResolvedGroupBinding {
    pub resolved_group_id: String,          // Immutable UUID anchor — prevents name-collision attacks
    pub group_domain_id: Option<String>,
    pub strategy: Option<GroupStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualUserMetadata {
    pub user_id: String,            // Deterministic HMAC-SHA256-derived handle (formatted as UUIDv4-compatible string)
    pub unique_workload_id: String,
    pub mapping_id: String,         // Direct anchor to the MappingRuleSet that matched; deterministic verification lookup
    pub matched_rule_name: String,
    pub domain_id: Option<String>,
    pub resolved_user_name: String,
    pub is_system: bool,  // Immutably preserved from initial upsert — cannot be escalated or revoked by rule modification, preventing runtime privilege escalation
    pub resolved_group_bindings: Vec<ResolvedGroupBinding>,
    pub authorizations: Vec<Authorization>,        // Snapshot of authorizations at issuance — prevents live rule modification from altering cached tokens
    pub ruleset_version: u128,    // SHA-256 hash (first 16 bytes) captured at issuance — used to detect stale tokens against live ruleset
    pub enabled: bool,
    pub created_at: i64,
    pub last_authenticated_at: i64,       // PCI-DSS compliance tracking variable
}

```

### A. Shadow Record Lifecycle & Virtual User Deactivation

Because the HMAC-SHA256-derived identifier is deterministic, repeated
authentication by the same principal always resolves to the same `user_id`. On
token issuance, the engine performs an upsert: if the shadow record already
exists, it completely refreshes `matched_rule_name`, `resolved_group_bindings`,
and `resolved_user_name`. Set `enabled: true` (a successful match indicates the
principal is active; if previously deactivated, successful authentication
reactivates). The `created_at` timestamp is immutably preserved from initial
creation. The `is_system` flag is **intentionally preserved** from initial
creation — on a subsequent upsert `meta.is_system = meta.is_system` prevents
the flag from being modified. This is a deliberate security measure: once a
principal is granted system-level service privileges, those privileges cannot be
escalated nor revoked through ruleset modification alone. Revoking `is_system`
requires setting `enabled: false` (deactivation) via the provider API, followed
by a fresh authentication lifecycle against a corrected ruleset to re-evaluate
privileges.

To maintain PCI-DSS compliance, the field `last_authenticated_at` tracks
real-time usage. A dedicated background janitor task range-scans the registry
keyspace nightly; any virtual profile that has failed to log an authentication
event for **more than 90 days** is deactivation-set (`enabled: false`), and all
corresponding live authorizations are dropped. This policy applies uniformly —
including virtual users with `is_system: true`, which must re-attest within the
90-day window or be deactivated (SPIFFE control-plane daemons that authenticate
periodically will naturally stay within this window).

**Deactivation preferred over deletion.** The janitor sets `enabled: false`
instead of deleting records, preserving forensic evidence (identity bindings,
authorization snapshots, activity timestamps) for incident response and
compliance auditing. A separate archive cleanup task permanently deletes
deactivated records after a configurable retention period (default: 365 days,
configurable via `[keystone] shadow_registry_archive_retention_days`). The CADF
`maintenance` event type captures these archive deletions with the record's
identity metadata in the attachment payload. The archive cleanup cadence is
configurable (default: weekly, configurable via
`[keystone] shadow_registry_archive_cleanup_interval`).

---

## 5. Execution Engine Logic (`src/identity/mapping/engine.rs`)

### 5.1. Claim Condition Evaluation Semantics

Each `ClaimCondition` variant is evaluated against the flattened claims map
(`HashMap<String, Vec<String>>`). JSON primitive values from the claims are
normalized to strings for comparison: `Number` and `Bool` are converted via
their `Display` representation, `String` is used directly, and nested objects
fall back to their JSON serialization. This ensures that a claim value of
boolean `true` matches a rule condition specifying the string `"true"`.

| Variant        | Evaluation Semantics                                                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Equals`       | The claim key must exist in the claims map, and at least one value must match the target after JSON-to-string normalization                                                                                   |
| `AnyOf`        | The claim key must exist, and at least one claim value must match at least one target value in `values`                                                                                                       |
| `MatchesRegex` | The claim key must exist, and at least one claim value must match the precompiled regex pattern; evaluation is bounded by a 2-second per-regex deadline and a 4 KiB per-value limit to prevent CPU exhaustion |

**Regex caching.** Precompiled regex patterns are cached in a thread-safe
`OnceLock`-backed `DashMap<String, Regex>`. To prevent adversarial cache
partition attacks, the map enforces a 1024-entry cap; once exceeded, the 100
least-recently-used entries are evicted (LRU policy) to retain frequently used
patterns and minimize adversarial cache thrashing.

**Runtime evaluation bounds.** Two defenses protect against resource exhaustion
during regex matching:

- **Per-claim value limit.** Each individual claim value is capped at 4096
  bytes. Claims exceeding this limit are silently dropped from the flattened
  claims map before evaluation. This limits the input size against which any
  regex operates.
- **Per-match timeout.** Each `MatchesRegex` evaluation runs with a 2-second
  deadline. If a single regex match exceeds the timeout, it short-circuits to
  `false` and emits a CADF `access` event with `RegexMatchTimeout` outcome. This
  prevents adversarial claim values against legitimate regex patterns from
  causing CPU exhaustion.

**Walker utility.** `MappingRule::walk_all_claim_conditions()` provides a flat
iterator over every `ClaimCondition` instance nested within a rule's match
criteria, used during write-time validation to verify all regex patterns pass
ReDoS safety checks before persistence.

### 5.2. Match Criteria Resolution Semantics

A `MatchCriteria` node evaluates nested boolean structures recursively:

| Criteria      | Semantics                                                                                                                                                                                                                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AllOf`       | Every child `MatchCondition` within the vector must evaluate to `true`                                                                                                                                                                                                                                        |
| `AnyOf`       | At least one child `MatchCondition` within the vector must evaluate to `true`                                                                                                                                                                                                                                 |
| `AllOfStrict` | Identical to `AllOf`, but when `require_all_keys` is `true`, the match fails immediately if any `ClaimCondition` references a key absent from the claims map. This prevents attackers from suppressing higher-priority rules by omitting specific claims, forcing fallback to lower-privilege catch-all rules |

A `MatchCondition` dispatches to one of two branches:

| Condition                 | Semantics                                          |
| ------------------------- | -------------------------------------------------- |
| `Condition(claim_cond)`   | Delegates to claim condition evaluation (§5.1)     |
| `Nested(nested_criteria)` | Recursively evaluates the embedded `MatchCriteria` |

This structure allows arbitrary nesting depth, enabling complex multi-claim
combinations such as requiring an exact namespace match AND a regex-matched
service account name within a `claims_or_mapping` scope.

### 5.3. Ruleset Entry Point: Match Evaluation

The ruleset evaluator iterates the `rules` vector top-to-bottom until the first
matching rule. Evaluation is short-circuit: once a rule matches, subsequent
rules are ignored (first-match-wins semantics).

**Returned struct.** A successful match populates `MatchResult`:

```rust
pub struct MatchResult {
    pub rule_name: String,
    pub user_name: String,
    pub user_id: Option<String>,
    pub user_domain_id: Option<String>,
    pub is_system: bool,
    pub authorizations: Vec<Authorization>,
    pub resolved_group_bindings: Vec<ResolvedGroupBinding>,
    pub ruleset_version: u128,    // Content-aware SHA-256 hash (first 16 bytes) — anchors token validity to ruleset state
}
```

**Evaluation algorithm.** For each rule in priority order:

1. **Enable gate.** If `ruleset.enabled == false`, evaluation terminates
   immediately, returning `None`.
2. **Match gate.** Evaluate `rule.match` criteria against the claims map. If it
   does not match, proceed to the next rule.
3. **Domain resolution.** Determine `user_domain_id` according to the active
   `DomainResolutionMode`:

- If `identity.user_domain_id` contains a template, interpolate it via safe
  string interpolation.
  - If interpolation yields an empty string, fall back to `ruleset.domain_id`
    (enclosing domain).
  - If `domain_resolution_mode` is `Fixed` and the interpolated value does not
    match `ruleset.domain_id` exactly, abort the rule match and proceed to the
    next rule. This prevents silent fallback to an unexpected domain.
  - If the interpolated value matches the enclosing domain directly, accept it.
  - If the interpolated value is a valid UUID format, accept it pending
    existence check during upsert (the evaluator itself has no DB access; domain
    existence is validated later).
  - If the interpolated value is neither the enclosing domain nor a valid UUID,
    fall back to `ruleset.domain_id` to prevent domain escape.
  - **Domain whitelist check.** If `ruleset.allowed_domains` is present and the
    interpolated `user_domain_id` is not contained within it, fall back to
    `ruleset.domain_id`. This prevents a compromised IdP from injecting
    arbitrary domain identifiers to redirect principal resolution.
  - If no `user_domain_id` template exists, default to `ruleset.domain_id`.

4. **user_name gate.** Interpolate `identity.user_name`. If interpolation fails
   or produces an empty string, skip this rule and try the next. This prevents
   blank shadow registry records.
5. **user_id resolution.** If `identity.user_id` is present, interpolate it.
   Empty result falls back to the enclosing domain (permitted unlike
   `user_name`).
6. **Group binding resolution.** For each `GroupAssignment`, interpolate
   `group_name` using the truncating variant (overflow is acceptable for display
   fields). Emit a `ResolvedGroupBinding` containing only the resolved anchor
   UUID, domain, and strategy — the interpolated display name is discarded.
7. **Result assembly.** Return `Some(MatchResult)` populated with interpolated
   identity, snapshotted authorizations, resolved groups, and the content-aware
   ruleset version.

If no rule matches, return `None`.

**Content-aware ruleset version.** The `ruleset_version` is computed by
serializing the structural payload — `mapping_id`, `provider_id`, `domain_id`,
the JSON-serialized `rules` vector, `domain_resolution_mode`, `allowed_domains`,
and `enabled` flag — into a canonical string, then hashing it with SHA-256 and
extracting the first 16 bytes as a `u128`. This replaces a naive length-based
counter, making the version resistant to rule reordering, renaming,
authorization swaps, and cross-rule priority manipulation. The SHA-256 hash (128
bits yields a birthday collision window of ~2^64 attempts), preventing
adversaries from crafting colliding rulesets to bypass TOCTOU detection during
token verification.

### 5.4. String Interpolation & Template Safety

All template expansion is single-pass with no recursive substitution. Two macro
patterns are recognized: `${claims.<key>}` for claim values and
`${enclosing_domain_id}` for the ruleset's enclosing domain. The interpolation
regex is compiled once and cached via `OnceLock` to eliminate per-request
compilation cost.

**Non-truncating variant (strict).** Used for `user_name`, `user_id`, and
`user_domain_id`. The interpolation accumulates literal segments and substituted
values in order. On any intermediate or final overflow past 256 characters, it
returns `Err(InterpolatedValueTooLong)` — the caller is responsible for handling
the error (e.g., skipping the rule for `user_name`).

**Truncating variant (display).** Used for `group_name` and other display-only
fields. If interpolation exceeds 256 characters, the original template string is
truncated to 253 characters and appended with `...`. This never extracts
arbitrary claim values on overflow — only the static template is preserved for
operator debugging.

**Security properties:**

- Single-pass expansion prevents nested template injection chains.
- Missing claims resolve to empty string (no error), but empty `user_name`
  causes the rule to be skipped during evaluation.
- The `enclosing_domain_id` macro is excluded from claim templates via
  write-time validation (§10.1) to prevent domain shadowing.

### 5.5. Engine Error Type

All execution-path failures funnel through a single typed enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum MappingEngineError {
    #[error("mapping ruleset is disabled")]
    MappingDisabled,
    #[error("mapping not found")]
    MappingNotFound,
    #[error("matched rule no longer exists in live ruleset")]
    MappingRuleNoLongerExists,
    #[error("database transaction error")]
    TransactionError,
    #[error("interpolation failed — claim key not available")]
    ClaimKeyNotFound,
    #[error("interpolated value exceeds length limit")]
    InterpolatedValueTooLong,
    #[error("ruleset version mismatch — token issued against stale ruleset")]
    RulesetVersionMismatch,
}

```

### 5.6. Real-Time Effective Role Calculation Core (`core/src/auth.rs`)

During token verification, `calculate_effective_roles` reconstructs the
authorization context from the shadow registry. The algorithm:

1. **System-service shortcut convergence.** If `ctx.is_admin()`, set the
   `is_system` flag on the context. This unifies local loopback credentials with
   remote service accounts.

2. **Principal dispatch.** For `IdentityInfo::Principal`, proceed with shadow
   registry lookup. For `IdentityInfo::User`, use the existing role resolution
   path (unchanged).

3. **Shadow registry bridge.** Look up `VirtualUserMetadata` using the virtual
   `user_id` from the token. If missing or disabled, return an authentication
   error.

4. **System flag propagation.** If `shadow_meta.is_system == true`, set the
   system service flag on the context, enabling control-plane shortcut bypasses.

5. **Live ruleset fetch.** Use `shadow_meta.mapping_id` to resolve the index key
   `index:mapping_id:<mapping_id>`, which yields `(domain_id, provider_id)`
   coordinates, then fetch the live `MappingRuleSet`. If disabled, abort.

6. **TOCTOU version check.** Compute the content-aware SHA-256 version of the
   live ruleset. If it differs from `shadow_meta.ruleset_version`, reject the
   token with `RulesetVersionMismatch` containing both shadow and live versions
   for incident response audit trail.

7. **Rule existence check.** Verify that `shadow_meta.matched_rule_name` still
   exists in the live ruleset. If the rule was removed, abort with
   `MappingRuleNoLongerExists`.

8. **Authorization from snapshot.** Iterate `shadow_meta.authorizations` (the
   snapshotted version from issuance time, not the live ruleset). For each
   authorization variant, check scope match:
   - `Project`: If scope matches the target project and domain, extend roles.
   - `Domain`: If scope matches the target domain, extend roles.
   - `System`: If context is marked system service and scope is system-level,
     extend roles.

9. **Group role resolution.** For each `resolved_group_binding` in the shadow
   record, resolve group roles from the assignment provider:
   - On success, extend effective roles.
   - On failure with `GroupStrategy::Get`, abort with `GroupNotFound`.
   - On failure with `GroupStrategy::CreateOrGet`, create the group
     synchronously within the current authorization transaction, then extend
     effective roles. This ensures the group exists before the token is
     considered valid, eliminating a race window between async enqueuing and
     subsequent verification.

10. **Token restriction application.** If context has a token restriction,
    narrow the effective roles accordingly.

11. **Empty role check.** If no roles were accumulated and the scope is not
    unscoped and the context is not a system service, return
    `ActorHasNoRolesOnTarget`.

12. **Deduplication.** Sort and deduplicate the effective role list before
    returning.

---

## 6. Concrete Examples: How Mapping Rulesets Look

### Use Case 1: SPIFFE Control-Plane Service Binding (`is_system` Enabled)

- **Stored at:** `data:mapping:v1:domain_admin_infra:spiffe-local`
- **Context:** Authorizes the core Nova service account to issue tokens and
  perform service-to-service background API transactions over the OpenStack
  control plane using an explicit system shortcut flag.

```json
{
  "mapping_id": "7c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
  "domain_id": "domain_admin_infra",
  "provider_id": "spiffe-local",
  "source": {
    "type": "spiffe",
    "trust_domain": "prod.keystone.internal"
  },
  "domain_resolution_mode": "fixed",
  "allowed_domains": [],
  "enabled": true,
  "rules": [
    {
      "name": "nova-to-neutron-control-plane",
      "description": "Authorize Nova compute workload to bypass target constraints via system flag shortcut",
      "match": {
        "all_of": [
          {
            "type": "equals",
            "claim": "spiffe.id",
            "value": "spiffe://prod.keystone.internal/ns/openstack/sa/nova"
          }
        ]
      },
      "identity": {
        "user_name": "svc-nova-compute",
        "user_id": "spiffe-nova-compute",
        "is_system": true
      },
      "authorizations": [
        {
          "type": "system",
          "system_id": "all",
          "roles": [{ "type": "system_role", "name": "default-role" }]
        }
      ],
      "groups": []
    }
  ]
}
```

### Use Case 2: OIDC Federation (Enterprise SSO Mapping)

- **Stored at:** `data:mapping:v1:domain_hr:oidc-okta`
- **Context:** Maps Okta enterprise SSO claims to internal project roles and
  groups. Demonstrates `ClaimsOrMapping` domain resolution, regex-based group
  parsing, and multi-role assignment per matched rule.

```json
{
  "mapping_id": "a1b2c3d4-5678-90ab-cdef-123456789abc",
  "domain_id": "domain_hr",
  "provider_id": "oidc-okta",
  "source": {
    "type": "federation",
    "idp_id": "okta-enterprise-idp"
  },
  "domain_resolution_mode": "claims_or_mapping",
  "allowed_domains": ["domain_hr", "550e8400-e29b-41d4-a716-446655440001"],
  "enabled": true,
  "rules": [
    {
      "name": "hr-admin-role-binding",
      "description": "Grant HR admin team _member_ and hr_admin role on HR project",
      "match": {
        "all_of": [
          {
            "type": "matches_regex",
            "claim": "email",
            "regex": "^.*\\.hr@acme\\.com$"
          },
          {
            "type": "any_of",
            "claim": "groups",
            "values": ["HR-Admin", "HR-Super-Admin"]
          }
        ]
      },
      "identity": {
        "user_name": "${claims.preferred_username}",
        "user_id": "${claims.sub}",
        "user_domain_id": "${claims.domain_id}"
      },
      "authorizations": [
        {
          "type": "project",
          "project_id": "550e8400-e29b-41d4-a716-446655440001",
          "project_domain_id": "domain_hr",
          "roles": [
            { "type": "system_role", "name": "_member_" },
            { "type": "system_role", "name": "hr_admin" }
          ]
        },
        {
          "type": "domain",
          "domain_id": "domain_hr",
          "roles": [{ "type": "system_role", "name": "domain_admin" }]
        }
      ],
      "groups": [
        {
          "group_id": "550e8400-e29b-41d4-a716-446655440010",
          "group_name": "HR-Admins-Global",
          "group_domain_id": "domain_hr",
          "strategy": "create_or_get"
        }
      ]
    },
    {
      "name": "regional-team-scope",
      "description": "Match regional HR team members and assign to project using regex",
      "match": {
        "all_of": [
          {
            "type": "matches_regex",
            "claim": "groups",
            "regex": "^HR\\-Team\\-(NA|EU|APAC)$"
          }
        ]
      },
      "identity": {
        "user_name": "${claims.preferred_username}",
        "user_id": "${claims.sub}",
        "user_domain_id": null
      },
      "authorizations": [
        {
          "type": "project",
          "project_id": "550e8400-e29b-41d4-a716-446655440002",
          "project_domain_id": "domain_hr",
          "roles": [{ "type": "system_role", "name": "_member_" }]
        }
      ],
      "groups": [
        {
          "group_id": "550e8400-e29b-41d4-a716-446655440020",
          "group_name": "Regional-HR-${claims.groups}",
          "group_domain_id": "domain_hr",
          "strategy": "create_or_get"
        }
      ]
    },
    {
      "name": "default-reader",
      "description": "Catch-all fallback for unhandled Okta users",
      "match": {
        "all_of": [
          {
            "type": "matches_regex",
            "claim": "email",
            "regex": "^.*@acme\\.com$"
          }
        ]
      },
      "identity": {
        "user_name": "${claims.email}",
        "user_id": "${claims.sub}"
      },
      "authorizations": [
        {
          "type": "project",
          "project_id": "550e8400-e29b-41d4-a716-446655440003",
          "project_domain_id": "domain_hr",
          "roles": [{ "type": "system_role", "name": "reader" }]
        }
      ],
      "groups": []
    }
  ]
}
```

### Use Case 3: Kubernetes Service Account Authorization

- **Stored at:** `data:mapping:v1:domain_infra:k8s-eks-prod`
- **Context:** Grants EKS-deployed workloads scoped access to OpenStack
  resources based on service account name and namespace. Demonstrates `Fixed`
  domain resolution with nested `AnyOf` match criteria.

```json
{
  "mapping_id": "b2c3d4e5-6789-01bc-def0-23456789abcd",
  "domain_id": "domain_infra",
  "provider_id": "k8s-eks-prod",
  "source": {
    "type": "k8s",
    "cluster_id": "eks-prod-cluster-01"
  },
  "domain_resolution_mode": "fixed",
  "allowed_domains": [],
  "enabled": true,
  "rules": [
    {
      "name": "ci-pipeline-admin",
      "description": "Grant CI/CD pipeline service account admin access to infra projects",
      "match": {
        "all_of": [
          {
            "type": "equals",
            "claim": "k8s.serviceaccount.namespace",
            "value": "ci-pipeline"
          },
          {
            "type": "any_of",
            "claim": "k8s.serviceaccount.name",
            "values": ["build-runner", "deploy-agent"]
          }
        ]
      },
      "identity": {
        "user_name": "svc-k8s-${claims.k8s.serviceaccount.name}"
      },
      "authorizations": [
        {
          "type": "project",
          "project_id": "550e8400-e29b-41d4-a716-446655440010",
          "project_domain_id": "domain_infra",
          "roles": [{ "type": "system_role", "name": "admin" }]
        }
      ],
      "groups": []
    },
    {
      "name": "monitoring-reader",
      "description": "Read-only access for Prometheus/Grafana monitoring agents",
      "match": {
        "all_of": [
          {
            "type": "equals",
            "claim": "k8s.serviceaccount.namespace",
            "value": "monitoring"
          },
          {
            "type": "matches_regex",
            "claim": "k8s.serviceaccount.name",
            "regex": "^prometheus-.*$"
          }
        ]
      },
      "identity": {
        "user_name": "svc-k8s-${claims.k8s.serviceaccount.name}"
      },
      "authorizations": [
        {
          "type": "project",
          "project_id": "550e8400-e29b-41d4-a716-446655440010",
          "project_domain_id": "domain_infra",
          "roles": [{ "type": "system_role", "name": "reader" }]
        }
      ],
      "groups": [
        {
          "group_id": "550e8400-e29b-41d4-a716-446655440030",
          "group_name": "Monitoring-Agents",
          "group_domain_id": "domain_infra",
          "strategy": "get"
        }
      ]
    }
  ]
}
```

---

## 7. Runtime Mechanics & Token Lifecycle Roundtrips

### Workflow: SPIFFE Workload Authentication & Verification

#### Phase A: Token Issuance (Login)

1. The Nova compute driver forwards its signed SPIFFE SVID certificate context
   to `keystone-rs`.
2. The SPIFFE ingress provider validates the cryptographic signature using the
   matching `SpiffeTrustResource` trust bundle PEM. It flattens the workload
   metrics into clean text claims (`spiffe.id`, `spiffe.trust_domain`) and hands
   them to the Mapping Engine.
3. The engine matches the rule `"nova-to-neutron-control-plane"` and reads its
   explicit `identity` properties, picking up the `is_system: true` instruction.
4. The system derives the persistent HMAC-SHA256 `user_id` for the workload. It
   executes an atomic transactional upsert against the shadow virtual user
   registry (detailed in Section 7.2 below), recording `mapping_id` (to anchor
   the live ruleset), `matched_rule_name: "nova-to-neutron-control-plane"`,
   capturing `resolved_user_name` and `resolved_group_bindings` from the live
   claims map, and immutably recording `is_system: true` into the registry row.
   Once set, this flag is preserved across all subsequent upserts — the
   `is_system` privilege cannot be revoked by rule modification alone.
5. The token engine compiles a native **`SystemScope` Fernet Token payload**
   variant directly containing the virtual `user_id`. The token is returned to
   the Nova driver.

#### Phase B: Token Verification (Roundtrip)

1. The Nova driver calls Neutron to wire up a VM interface, attaching its token.
   Neutron hands the token back to Keystone's `authorize_by_token` endpoint for
   verification.
2. The token provider decrypts the Fernet payload, matching the `SystemScope`
   layout and pulling the virtual `user_id`.
3. The engine builds an unverified, raw `SecurityContext` initializing the
   identity as an unbacked `IdentityInfo::Principal`.
4. The handler calls `ValidatedSecurityContext::new_for_scope()`. Inside
   `calculate_effective_roles()`, the engine reads the shadow user profile from
   FjallDB using the `user_id`. It uses `mapping_id` to look up the index key
   `index:mapping_id:<mapping_id>` which resolves the `(domain_id, provider_id)`
   coordinates, then fetches the live `MappingRuleSet` from
   `data:mapping:v1:<domain_id>:<provider_id>`. It encounters the active
   `is_system: true` flag.
5. The method calls `ctx.set_system_service_flag(true)`, applying the
   control-plane shortcut bypass directly to the context memory segment. When
   projected into `Credentials` for policy analysis, the OPA engine registers
   `is_system: true` and cleanly validates the communication path.

### 7.2. Atomic Transactional Upsert Flow & Adaptive Rate Limiter

To shield the shadow registry from write-amplification DoS attacks, creation
lookups pass through a sliding-window token bucket rate-limiter tracked per
`provider_id`. The threshold is configurable via
`[keystone] shadow_registry_creation_rate_limit` in `keystone.conf` (default: 50
operations per minute). When unique principal creation events spike past this
threshold, the login path drops further entries with an HTTP
`429 Too Many Requests` status code.

A second rate-limit tier governs total authentications per `provider_id` (both
new and existing principals), configurable via
`[keystone] shadow_registry_auth_rate_limit` (default: 500 operations per
minute). This prevents replay attacks against known valid principals from
bypassing the creation-only limit. When this threshold is exceeded, all
authentication attempts against the provider are rejected with HTTP
`429 Too Many Requests` until the sliding window expires.

**Upsert algorithm.** The virtual user record is persisted atomically within a
single database transaction:

1. **HMAC-SHA256 user_id derivation.** Compute a deterministic identifier for
   the principal using a 256-bit per-cluster secret as the HMAC key:
   `HMAC-SHA256(cluster_salt, workload_id || provider_id)`, taking the first 16
   bytes and formatting as a UUIDv4-compatible string. The `cluster_salt` is
   generated at cluster bootstrap, stored in the static application
   configuration, and excluded from all API responses. HMAC-SHA256 (rather than
   UUIDv5/SHA-1) provides a one-way, non-invertible derivation: an attacker
   knowing `provider_id` and `workload_id` cannot reverse the salt or enumerate
   shadow registry keys. Identical principals always resolve to the same
   `user_id` within a cluster, while cross-cluster correlation is blocked by the
   per-cluster salt.

2. **Domain existence validation.** The `effective_domain` is determined from
   `MatchResult.user_domain_id`:
   - If `user_domain_id` is a valid UUID, check `index:auth:domain_id:<uuid>`
     for existence. If the domain exists, use it.
   - If `user_domain_id` is a human-readable slug, check
     `index:auth:domain_slug:<slug>` for existence. If found, resolve the mapped
     UUID and use it.
   - If the interpolated domain does not exist in either index, reject the
     upsert with `ValidationResult::DomainNotFound`, preventing non-existent
     UUIDs from persisting in shadow records (fixes the UUID-format domain gap).
   - If `user_domain_id` is absent or the above checks fail, fall back to
     `ruleset.domain_id` (the enclosing domain).

3. **Read existing shadow record.** Attempt to fetch from
   `user:v1:virtual:<user_id>`.

4. **Merge or create.**
    - **Update path (existing record):** Refresh `mapping_id`,
      `matched_rule_name`, `resolved_user_name`, `resolved_group_bindings`, and
      snapshotted `authorizations`. Update `ruleset_version` from the match
      result and `last_authenticated_at` to current timestamp. Set `enabled:
      true` — a successful match indicates the principal is active; if the
      record was previously deactivated, successful authentication reactivates
      it. The `created_at` timestamp is immutably preserved from initial
      creation. The `is_system` flag is **immutably preserved** from initial
      creation (`meta.is_system = meta.is_system`) — once a principal is granted
      system-level privileges, those privileges cannot be escalated nor revoked
      through ruleset modification alone. Revoking `is_system` requires setting
      `enabled: false` (deactivation) via the provider API.
    - **Insert path (new record):** Create a fresh `VirtualUserMetadata`
      populated with all fields from the match result, the validated
      `effective_domain`, `enabled: true`, and the current timestamp for
      `created_at` and `last_authenticated_at`.

5. **Persist.** Write the merged or new record atomically to the shadow
   keyspace.

### 7.3. Validation Error Code Reference

| Error Variant                             | HTTP Status | JSON Detail Key                                  | Triggering Condition                                                                                       |
| ----------------------------------------- | ----------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `SystemTokenShadowing(key)`               | 422         | `"detail.system_token_shadowing"`                | Template references `${claims.enclosing_domain_id}`                                                        |
| `DomainClaimRequired`                     | 422         | `"detail.domain_claim_required"`                 | `ClaimsOnly` mode without `${claims.*}` in `user_domain_id`                                                |
| `DomainOverrideInFixedMode`               | 422         | `"detail.domain_override_fixed_mode"`            | Claims template in `user_domain_id` when resolution mode is `Fixed`                                        |
| `InvalidRuleName(name)`                   | 422         | `"detail.invalid_rule_name"`                     | Rule name fails regex rules or exceeds length limits                                                       |
| `DuplicateRuleName(name)`                 | 422         | `"detail.duplicate_rule_name"`                   | Two rules within the same ruleset share the same `name`                                                    |
| `RegexSafetyViolation(pattern, msg)`      | 422         | `"detail.regex_safety_violation"`                | Regex pattern fails write-time ReDoS safety check                                                          |
| `ShadowRegistryConflict`                  | 409         | `"detail.shadow_registry_conflict"`              | Transactional upsert fails after exhaustion of retries                                                     |
| `GroupNotFound(name)`                     | 403         | `"detail.group_not_found"`                       | `GroupStrategy::Get` evaluates against a non-existing group                                                |
| `MappingRuleNoLongerExists`               | 403         | `"detail.mapping_rule_removed"`                  | Shadow record references a rule name missing from the live ruleset (rule name omitted from error response) |
| `MappingDisabled`                         | 403         | `"detail.mapping_disabled"`                      | Ruleset `enabled` flag is false during verification                                                        |
| `MappingNotFound`                         | 404         | `"detail.mapping_not_found"`                     | No ruleset exists at the computed keyspace coordinate                                                      |
| `SystemMappingIsImmutable`                | 422         | `"detail.system_mapping_immutable"`              | Operator attempts to modify a ruleset containing system-level flags                                        |
| `RoleGrantUnauthorized(role, project_id)` | 403         | `"detail.role_grant_unauthorized"`               | Non-admin operator lacks `role` on `project_id`                                                            |
| `CrossDomainMapping(domain_id)`           | 403         | `"detail.cross_domain_mapping"`                  | Non-admin operator targets domain UUID outside own domain                                                  |
| `GroupAssignmentUnauthorized(group_id)`   | 403         | `"detail.group_assignment_unauthorized"`         | Non-admin operator lacks `admin` on target `group_id`                                                      |
| `SystemScopeRequiresIsSystem`             | 422         | `"detail.system_scope_requires_is_system"`       | `Authorization::System` used without `is_system: true` on the rule                                         |
| `DomainMappingUnauthorized(domain_id)`    | 403         | `"detail.domain_mapping_unauthorized"`           | Non-admin operator grants roles at domain scope outside their own                                          |
| `DomainResolutionModeRequiresAdmin(mode)` | 422         | `"detail.domain_resolution_mode_requires_admin"` | Non-admin operator creates `ClaimsOrMapping`/`ClaimsOnly` ruleset                                          |
| `AllowedDomainsRequired(mode)`            | 422         | `"detail.allowed_domains_required"`              | `ClaimsOnly`/`ClaimsOrMapping` ruleset submitted without non-empty `allowed_domains`                       |
| `InterpolatedValueTooLong(msg)`           | 400         | `"detail.interpolated_value_too_long"`           | Template interpolation exceeds 256 char limit (rejects blank records)                                      |
| `RulesetVersionMismatch`                  | 401         | `"detail.ruleset_version_mismatch"`              | Token shadow version differs from live ruleset (version numbers omitted from error response)               |

---

## 8. Unified Keyspace Naming Scheme Summary

All indices, entries, structures, and metadata elements are maintained inside a
single consolidated partition layer in FjallDB.

| Functional Purpose              | Key Namespace Pattern                            | Value Payload                                 |
| ------------------------------- | ------------------------------------------------ | --------------------------------------------- |
| **Global Domain Slug Index**    | `index:auth:domain_slug:<domain_slug>`           | String `domain_id` (UUIDv4)                   |
| **Scoped Mapping Index**        | `index:auth:mapping:<domain_id>:<mapping_name>`  | String `provider_id` (Slug)                   |
| **Global Mapping ID Index**     | `index:mapping_id:<mapping_id>`                  | `{"domain_id": "...", "provider_id": "..."}`  |
| **Global JWT Invariant Index**  | `index:auth:jwt:<sha256(iss+"\0"+aud)>`          | `{"domain_id": "...", "provider_id": "..."}`  |
| **Global Client Index**         | `index:oauth2:client:<client_id>`                | `{"domain_id": "...", "provider_id": "..."}`  |
| **Virtual User Shadow Records** | `data:user:virtual:<user_id_hmac>`               | `VirtualUserMetadata` (Struct object)         |
| **OIDC Crypto Resource**        | `data:federation:oidc:<domain_id>:<provider_id>` | `OidcProviderResource` (Struct)               |
| **K8s Crypto Resource**         | `data:k8s_auth:<domain_id>:<provider_id>`        | `K8sClusterResource` (Struct object)          |
| **SPIFFE Crypto Resource**      | `data:spiffe:<domain_id>:<provider_id>`          | `SpiffeTrustResource` (Struct object)         |
| **Unified ABAC Ruleset**        | `data:mapping:<domain_id>:<provider_id>`         | `MappingRuleSet` (Contains named rule vector) |

---

## 9. Administrative CRUD Management API Specification

### A. Create Mapping Configuration

- **HTTP Method / Path:** `POST /v4/mappings`
- **Validation Bounds — Two-Tier Enforcement:**
  - **Tier 1 (SystemAdmin Gate):** If `mapping.rules` contains at least one
    target where `identity.is_system == true`, and `ctx.is_admin() == false` (no
    `SystemAdmin` credentials), the call is rejected with HTTP `403 Forbidden`.
    Mappings with an active system-bypass flag are stamped as **Immutable System
    Mappings**.
  - **Tier 2 (Authorization Bounds — Non-Admin Only):** If
    `ctx.is_admin() == false`, the engine validates creator scope before
    persistence:
- **Domain confinement** — for `Authorization::Project`, `project_domain_id`
  must match the operator's effective domain UUID; for `Authorization::Domain`,
  `domain_id` must match the operator's domain. Cross-domain mappings are
  rejected with `403 Forbidden` (`CrossDomainMapping`).
  - **Role grant parity** — for every `Authorization`, the operator must hold
    each role listed in `roles` on the target scope. Failure returns
    `403 Forbidden` (`RoleGrantUnauthorized`).
  - **System scope restriction** — `Authorization::System` requires
    `is_system: true` on the mapping rule and `is_admin()` on the operator.
    Non-admin operators are rejected with `422 Unprocessable Entity`
    (`SystemScopeRequiresIsSystem`).
  - **Group assignment authority** — for every `GroupAssignment`, the operator
    must hold `admin` on the target group. Failure returns `403  Forbidden`
    (`GroupAssignmentUnauthorized`).
  - **SystemAdmin bypass:** When `ctx.is_admin() == true`, Tier 2 is bypassed
    entirely. The admin operator may map to any domain, grant any roles, and
    assign to any groups.

### B. List Mapping Configurations (Tenant-Isolated)

- **HTTP Method / Path:** `GET /v4/mappings?domain_id=domain_admin_infra`
- **Response:** `200 OK`

### C. Get Mapping Profile

- **HTTP Method / Path:** `GET /v4/mappings/{mapping_id}`
- **Response:** `200 OK`

### D. Declarative Overwrite / Apply Update

- **HTTP Method / Path:** `PUT /v4/mappings/{mapping_id}`
- **Immutability Protection:** If the target configuration is flagged as an
  **Immutable System Mapping**, the engine will completely abort the operation,
  throwing an HTTP `422 Unprocessable Entity` response. System mappings can
  never be updated; changes require an explicit `DELETE` statement followed by a
  fresh `POST` initialization block to preserve clean audit separation.
- **Domain Immutability:** The `domain_id` field is structurally immutable upon
  ruleset creation. Any `PUT` request attempting to modify `domain_id` to a
  different value is rejected with HTTP `422 Unprocessable Entity`. The owning
  domain anchor cannot be migrated post-creation, as it forms the basis of the
  keyspace coordinate (`data:mapping:v1:<domain_id>:<provider_id>`) and all
  shadow registry lookups for principals issued under the ruleset.

### E. Imperative Rule Mutation (Relative Anchoring Path)

- **HTTP Method / Path:** `POST /v4/mappings/{mapping_id}/rules/mutate`
- **Immutability Protection:** Throws an immediate HTTP
  `422 Unprocessable Entity` if the target is an Immutable System Mapping,
  ensuring no mutation deltas can manipulate control-plane assets.

### F. Virtual User Lifecycle Management

- **Disable Virtual User:**
  - **HTTP Method / Path:** `PATCH /v4/virtual_users/{user_id}/disable`
  - **Response:** `200 OK` — returns the deactivated `VirtualUser` record
  - **Effect:** Sets `enabled: false`, triggers token revocation pipeline
    (`revocation:v1:user:<user_id>`), preserves forensic record for audit trail

- **Enable (Reactivate) Virtual User:**
  - **HTTP Method / Path:** `PATCH /v4/virtual_users/{user_id}/enable`
  - **Response:** `200 OK` — returns the reactivated `VirtualUser` record
  - **Effect:** Sets `enabled: true`, re-activates the principal for future
    authentication

- **Get Virtual User Profile:**
  - **HTTP Method / Path:** `GET /v4/virtual_users/{user_id}`
  - **Response:** `200 OK` — returns full `VirtualUser` metadata including
    snapshotted authorizations, resolved groups, and activity timestamps

---

## 10. Security Architecture, Invariant Protections & Auditing

### 10.1. Write-Time ReDoS and Immutability Validation Rules

The `ValidationError` structure explicitly manages our safety parameters:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("template references reserved key: {0}")]
    SystemTokenShadowing(String),
    #[error("ClaimsOnly mode requires user_domain_id template with ${claims.*}")]
    DomainClaimRequired,
    #[error("Fixed mode does not allow claims templates in user_domain_id")]
    DomainOverrideInFixedMode,
    #[error("rule name '{0}' is not a valid identifier")]
    InvalidRuleName(String),
    #[error("duplicate rule name '{0}' within ruleset")]
    DuplicateRuleName(String),
    #[error("system level bypass mappings are strictly immutable and can never be modified")]
    SystemMappingIsImmutable,
    #[error("regex pattern '{0}' is syntactically invalid")]
    InvalidRegexSyntax(String),
    #[error("regex pattern '{0}' exceeds complexity limit (AST size > 4096)")]
    RegexTooComplex(String),
    #[error("regex pattern '{0}' fails write-time ReDoS safety check: {1}")]
    RegexSafetyViolation(String, String),
    #[error("operator lacks role '{0}' on project '{1}' — cannot grant via mapping")]
    RoleGrantUnauthorized(RoleRef, String),
    #[error("mapping targets domain '{0}' which is outside the operator's domain")]
    CrossDomainMapping(String),
    #[error("operator cannot assign members to group '{0}'")]
    GroupAssignmentUnauthorized(String),
    #[error("system scope authorization requires is_system: true on the mapping rule")]
    SystemScopeRequiresIsSystem,
    #[error("non-admin operator cannot grant roles at domain scope for '{0}'")]
    DomainMappingUnauthorized(String),
    #[error("domain_resolution_mode '{0}' requires SystemAdmin privileges")]
    DomainResolutionModeRequiresAdmin(DomainResolutionMode),
    #[error("domain_resolution_mode '{0}' requires non-empty allowed_domains")]
    AllowedDomainsRequired(DomainResolutionMode),
    #[error("allowed_domains contains domain '{0}' outside operator scope")]
    AllowedDomainOutOfScope(String),
}

```

### ReDoS Protection at Write-Time

Runtime caching mitigates repeated compilation of expensive regexes, but
write-time validation is the primary defense. A regex condition is safe if it:

1. **Passes `regex_syntax::Parser` AST validation** — detects invalid syntax at
   parse time
2. **Lacks nested quantifiers** — `(a+)+`, `(a*)*`, `(a{2,})*` are rejected by
   recursive AST walk detecting `Repetition` nodes that directly contain another
   `Repetition` or alternation group as their child expression
3. **Lacks unbounded alternation under quantifiers** — `(a|a)+`, `(a|b|c)*` with
   overlapping branches are rejected
4. **Stays within complexity bounds** — AST string representation exceeds 4096
   characters

The `regex` crate's NFA engine guarantees linear backtracking at runtime,
neutralizing many ReDoS vectors intrinsically. The write-time AST walk functions
as a defense-in-depth layer, rejecting the remaining pathological patterns at
ingestion time before they can enter the compiled cache.

### Authorization Bound Validation

Every mapping rule is validated before persistence against the operator's
current privileges, enforcing two-tier authorization:

**Tier 1 — SystemAdmin bypass.** When `ctx.is_admin() == true`, all
authorization bound checks are skipped. The admin operator may map to any
domain, grant any roles, and assign to any groups.

**Tier 2 — Regular operator constraints.** When `ctx.is_admin() == false`, the
engine validates:

- **System scope requirement.** For every `Authorization::System` variant, the
  parent rule must have `identity.is_system == true`. Otherwise, reject with
  `SystemScopeRequiresIsSystem`.
- **Domain confinement.** For `Authorization::Project`, `project_domain_id` must
  match the operator's effective domain UUID. For `Authorization::Domain`,
  `domain_id` must match the operator's domain. Cross-domain mappings are
  rejected with `CrossDomainMapping` or `DomainMappingUnauthorized`.
- **Role grant parity.** For every role listed in an authorization's `roles`
  vector, the operator must hold that same role on the target scope. For project
  scope, this is checked against project-specific role assignments. For domain
  scope, against domain-level role assignments. Failure returns
  `RoleGrantUnauthorized`.
- **Group assignment authority.** For every `GroupAssignment`, the operator must
  hold `admin` on the target `group_id`. Failure returns
  `GroupAssignmentUnauthorized`.

### Mapping Definition Validation

The `validate_mapping_definition` function orchestrates all write-time guards:

1. **Template claim extraction.** Extract every `${claims.<key>}` reference from
   `user_name`, `user_id`, and `user_domain_id` templates. If any key equals
   `enclosing_domain_id`, reject with `SystemTokenShadowing` to prevent domain
   context shadowing.

2. **Regex safety.** For every `MatchesRegex` condition reachable via
   `walk_all_claim_conditions()`, invoke ReDoS validation. Any failure
   short-circuits with `RegexSafetyViolation`.

3. **Authorization bounds.** Invoke the two-tier authorization validation
   against the operator's SecurityContext, project roles, domain roles, and
   group roles.

4. **Domain resolution mode enforcement.** Non-admin operators are strictly
   prohibited from creating `ClaimsOrMapping` or `ClaimsOnly` rulesets, as these
   modes enable domain escape and cross-domain virtual user creation. If a
   non-admin operator specifies these modes, reject with
   `DomainResolutionModeRequiresAdmin`.

5. **Mode-internal consistency.**
   - `ClaimsOnly`: The `user_domain_id` template must contain at least one
     `${claims.*}` reference. Otherwise, reject with `DomainClaimRequired`.
   - `Fixed`: The `user_domain_id` must NOT contain any `${claims.*}` reference.
     Otherwise, reject with `DomainOverrideInFixedMode`.
   - `ClaimsOrMapping`: Both claim templates and static values are permitted
     (admin only).

### 9. Claim Value Size Enforcement

Flattened claims maps are subject to size caps before evaluation:

- **Per-claim limit.** Each claim value must not exceed 4096 bytes. Values
  exceeding this limit are silently dropped from the claims map. This prevents a
  single oversized claim causing memory pressure or CPU exhaustion during regex
  evaluation.
- **Total map limit.** The total serialized size of the flattened claims map
  (`HashMap<String, Vec<String>>`) must not exceed 64 KiB. If exceeded, the
  ingress adapter rejects the authentication attempt with
  `413 Payload Too Large`.

### 10. Domain Whitelist Enforcement

**Mandatory for ClaimsOnly/ClaimsOrMapping.** If `domain_resolution_mode` is
`ClaimsOnly` or `ClaimsOrMapping`, `allowed_domains` must be present and
non-empty. This prevents a compromised IdP from injecting arbitrary domain
identifiers to redirect principal resolution. If `allowed_domains` is empty,
reject with `AllowedDomainsRequired`. For `Fixed` mode, `allowed_domains` must
be empty (no claims-based interpolation possible).

For every domain in `allowed_domains`:

- For non-admin operators, each domain must be within the operator's effective
  domain or the operator's own domain. Otherwise, reject with
  `AllowedDomainOutOfScope`.
- For admin operators, each domain must exist in the global domain index.
  Otherwise, reject with `DomainNotFound`.

### 11. Domain Whitelist Intersection Check

At evaluation time (§5.3, step 3), after interpolating `user_domain_id` from
claims, the engine checks that the resolved domain falls within
`allowed_domains`. If the interpolated value is not contained in the whitelist,
fall back to `ruleset.domain_id` to prevent domain escape.

### 12. Real-Time Token Revocation Pipeline

Any Raft proposal that deactivates (`enabled: false`), deletes (archive
cleanup), or alters a `MappingRuleSet` will automatically append explicit
token validation revocation objects directly into the global validation engine
(ADR 0009 keyspace):

- `revocation:v1:mapping:<mapping_id>` $\rightarrow$ Timestamp
- `revocation:v1:user:<virtual_user_id>` $\rightarrow$ Timestamp

All token lookup evaluation tasks cross-reference this keyspace prefix layout;
matching tokens drop validation sessions instantly upon Raft log entry
application on the local node. The mapping provider triggers the revocation
pipeline by calling the revocation provider on virtual user deactivation
(admin-initiated or janitor-triggered).

### 13. Normative CADF Auditing Trail Specifications

Every rule mutation, API declarative replacement, or administrative override
emits a normative Cloud Auditing Data Federation (CADF) event format log into
the system notifier bus. The following event types are emitted:

| Event Type    | Triggering Condition                                                   |
| ------------- | ---------------------------------------------------------------------- |
| `control`     | Mapping CRUD operations (create, update, delete, mutate)               |
| `access`      | Failed authentication attempts, `RulesetVersionMismatch` rejections    |
| `maintenance` | Janitor shadow record deactivations, archive cleanup deletions, virtual user enable/disable, token revocation pipeline activations |
| `privileged`  | Admin Tier 1 bypass API invocations (`ctx.is_admin() == true` paths)   |

#### Example: Control Event (Mapping Mutation)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "control",
  "eventTime": "2026-06-11T14:17:16Z",
  "action": "update/identity/mapping",
  "outcome": "success",
  "initiator": {
    "id": "usr_uuid_of_admin_initiator",
    "typeURI": "data/security/user",
    "name": "cloud-admin-operator",
    "domain_id": "default"
  },
  "target": {
    "id": "7c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
    "typeURI": "data/security/mapping",
    "name": "spiffe-internal"
  },
  "observer": {
    "id": "keystone-rs-raft-cluster-node-01",
    "typeURI": "service/compute/identity"
  },
  "attachments": [
    {
      "name": "mutation_delta",
      "contentType": "application/json",
      "content": {
        "operation": "insert",
        "rule_name": "nova-to-cinder",
        "is_system_applied": true
      }
    }
  ]
}
```

#### Example: Access Event (RulesetVersionMismatch)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "access",
  "eventTime": "2026-06-11T14:20:00Z",
  "action": "read/identity/token/verify",
  "outcome": "failure",
  "initiator": {
    "id": "virtual-user-uuid",
    "typeURI": "data/security/virtual-user",
    "name": "svc-nova-compute"
  },
  "target": {
    "id": "7c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
    "typeURI": "data/security/mapping",
    "name": "spiffe-internal"
  },
  "attachments": [
    {
      "name": "reason",
      "contentType": "application/json",
      "content": {
        "error": "RulesetVersionMismatch",
        "shadow_version": 12345678901234567890,
        "live_version": 12345678901234567891
      }
    }
  ]
}
```

#### Example: Maintenance Event (Janitor Deactivation)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "maintenance",
  "eventTime": "2026-06-11T03:00:00Z",
  "action": "disable/identity/virtual-user/janitor",
  "outcome": "success",
  "initiator": {
    "id": "janitor-task",
    "typeURI": "data/system/task"
  },
  "target": {
    "id": "virtual-user-uuid",
    "typeURI": "data/security/virtual-user",
    "name": "svc-decommissioned-daemon"
  },
  "attachments": [
    {
      "name": "reason",
      "contentType": "application/json",
      "content": {
        "last_authenticated_days_ago": 124,
        "is_system": false
      }
    }
  ]
}
```

#### Example: Maintenance Event (Archive Cleanup Deletion)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "maintenance",
  "eventTime": "2026-06-11T03:00:00Z",
  "action": "delete/identity/virtual-user/archive-cleanup",
  "outcome": "success",
  "initiator": {
    "id": "archive-cleanup-task",
    "typeURI": "data/system/task"
  },
  "target": {
    "id": "virtual-user-uuid",
    "typeURI": "data/security/virtual-user",
    "name": "svc-decommissioned-daemon"
  },
  "attachments": [
    {
      "name": "reason",
      "contentType": "application/json",
      "content": {
        "deactivated_days_ago": 378,
        "last_authenticated_at": 1718000000,
        "is_system": false,
        "mapping_id": "7c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
        "resolved_user_name": "svc-decommissioned-daemon"
      }
    }
  ]
}
```

#### Example: Control Event (Virtual User Disable)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "control",
  "eventTime": "2026-06-11T15:00:00Z",
  "action": "disable/identity/virtual-user",
  "outcome": "success",
  "initiator": {
    "id": "usr_uuid_of_admin_initiator",
    "typeURI": "data/security/user",
    "name": "cloud-admin-operator",
    "domain_id": "default"
  },
  "target": {
    "id": "virtual-user-uuid",
    "typeURI": "data/security/virtual-user",
    "name": "svc-compromised-agent"
  },
  "attachments": [
    {
      "name": "reason",
      "contentType": "application/json",
      "content": {
        "enabled": false,
        "is_system": false,
        "revocation_triggered": true
      }
    }
  ]
}
```

#### Example: Privileged Event (Admin Bypass)

```json
{
  "id": "cadf-uuid-v4-event-id",
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "privileged",
  "eventTime": "2026-06-11T15:00:00Z",
  "action": "create/identity/mapping",
  "outcome": "success",
  "initiator": {
    "id": "usr_uuid_of_admin_initiator",
    "typeURI": "data/security/user",
    "name": "cloud-admin-operator",
    "domain_id": "default"
  },
  "target": {
    "id": "new-mapping-uuid",
    "typeURI": "data/security/mapping",
    "name": "emergency-service-binding"
  },
  "attachments": [
    {
      "name": "privileged_details",
      "contentType": "application/json",
      "content": {
        "bypassed_tier": "authorization_bounds",
        "is_system_granted": true,
        "reason": "emergency_service_repair"
      }
    }
  ]
}
```

## 11. Migration Strategy

### 11.1. Federation Provider Field Translation

| Legacy `Mapping` Field | New Model Location                                                                                                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `r#type` (Oidc/Jwt)    | **Dropped.** `IdentitySource::Federation` covers both lines.                                                                                                                  |
| `bound_audiences`      | `ClaimCondition::AnyOf { claim: "aud", values: [...] }`                                                                                                                       |
| `user_name_claim`      | `identity.user_name = "${claims.<user_name_claim>}"`                                                                                                                          |
| `user_id_claim`        | `identity.user_id = Some("${claims.<user_id_claim>}")`                                                                                                                        |
| `groups_claim`         | `groups.push(GroupAssignment { group_id: compute_sha256_uuid(&claims.<groups_claim>), group_name: "fed_grp:<provider_id>:${claims.<groups_claim>}", strategy: CreateOrGet })` |
| `token_project_id`     | `Authorization::Project` — Project UUID is taken directly from legacy `token_project_id`.                                                                                     |
| `token_restriction_id` | **Obsolete.** Whittled role targets migrate directly into `Authorization::Project.roles`.                                                                                     |

### 11.2. Claim Flattening Per Provider (Ingress Adapter Contract)

| Provider       | Source Data         | Flattening Convention                                                  | Unique Workload Key Invariant                                                                   |
| -------------- | ------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **OIDC / JWT** | JWT ID token claims | Flat string mappings via dotted pathways (`email`, `user.profile.id`)  | Value string of the `sub` claim element                                                         |
| **Kubernetes** | K8s TokenReview JWT | `k8s.serviceaccount.name`, `k8s.serviceaccount.namespace`, `k8s.aud`   | Formatted invariant: `<serviceaccount_name>:<serviceaccount_namespace>`                         |
| **SPIFFE**     | SPIFFE SVID cert    | `spiffe.id`, `spiffe.trust_domain`                                     | Full raw URI format asset string (e.g., `spiffe://prod.keystone.internal/ns/openstack/sa/nova`) |

**Size constraints.** All ingress adapters must enforce the following limits:

- Per-claim value: max 4096 bytes (excess silently dropped)
- Total claims map: max 64 KiB (excess rejected with `413 Payload Too Large`)

## 12. Implementation Plan

Implementation proceeds in five sequential phases, each deliverable, testable,
and independently verifiable before advancing.

### Phase 1: Mapping Provider & Raft Driver

Foundational layer to store, retrieve, and replicate `MappingRuleSet` objects
and `VirtualUser` shadow records across the Raft cluster. The mapping provider
owns the keyspace prefix `data:mapping:v1:` and the index `index:mapping_id:`.

- Implement `MappingProvider` trait exposing `create`, `get`, `update`,
  `delete`, `enable`, `disable`, and `list` operations against FjallDB.
- Implement the Raft driver for mapping mutations: serialize `MappingRuleSet`
  payloads, enforce Raft consensus ordering, and handle snapshot/compaction.
- Implement write-time validation pipeline: regex ReDoS safety, rule name
  uniqueness, template safety, `allowed_domains` intersection checks.
- Implement content-aware `ruleset_version` (SHA-256 first-16-bytes hasher).
- Implement virtual user enable/disable with CAS-based toggle.
- **Deliverable:** Cluster-internal API for mapping CRUD and virtual user
  lifecycle, verifiable via unit and integration tests.

### Phase 2: Mapping CRUD & Evaluation API

HTTP API and engine integration layer. Operators create and manage rulesets; the
evaluation engine exposes match testing utilities.

- Implement `PUT`, `GET`, `DELETE`, and `POST` endpoints under `/v4/mappings/`
  (§9).
- Implement `POST /v4/mappings/{mapping_id}/rules/mutate` for imperative rule
  adjustments with relative anchoring.
- Wire `MappingEngine` into the ingestion pipeline: ingest flattened claims,
  iterate ruleset, produce `MatchResult`.
- **Deliverable:** Fully functional mapping API with engine evaluation, no
  upstream consumers yet.

### Phase 3: SPIFFE Provider Migration

First upstream consumer migration. SPIFFE is lowest-risk: its rulesets map to
`Fixed` domain resolution, deterministic SPIFFE ID claims, and static identity
bindings.

- Rewrite `SpiffeTrustResource` authenticator to emit flattened claims, invoke
  the mapping engine, and consume `MatchResult`.
- Create SPIFFE rulesets via the mapping provider for existing trust domain
  configurations.
- Enable shadow registry upsert flow for SPIFFE principals.
- Deprecate SPIFFE bindings concept; route all SPIFFE logins through the unified
  engine.
- **Deliverable:** SPIFFE SVID authentication fully mediated by mapping engine;
  control-plane `is_system` principals issued via shadow registry.

### Phase 4: Kubernetes Auth Provider Migration

Migrate the K8s TokenReview authenticator to the mapping engine.

- Rewrite `K8sClusterResource` authenticator to flatten `TokenReview` claims and
  invoke the mapping engine.
- Create K8s rulesets via the mapping provider, demonstrating nested match
  criteria and `AllOfStrict` guards.
- Enable shadow registry upsert for K8s service account principals.
- Deprecate legacy `K8s_auth` role.
- **Deliverable:** Kubernetes TokenReview authentication fully mediated by
  mapping engine.

### Phase 5: Federation Provider Migration

Final and broadest migration. Existing federation providers (OIDC, JWT) carry
the most complex claim profiles and legacy `token_restriction` patterns.

- Rewrite `OidcProviderResource` authenticator to flatten JWT claims and invoke
  the mapping engine.
- Migrate legacy `Mapping` objects to `MappingRuleSet` using the field
  translation table (§11.1).
- Enable `ClaimsOrMapping` and `ClaimsOnly` domain resolution modes for
  federation scenarios.
- Remove `token_restriction` payload generation for federated principals; all
  scoping is handled natively by `Authorization` fields in `MatchResult`.
- Deprecate legacy federation mapping code path.
- **Deliverable:** All federation authentication fully mediated by the unified
  mapping engine; legacy `token_restriction` pattern eliminated.

---

## 13. Implementation Deviations from ADR Spec

This section documents decisions made during implementation that deviate from
the original specification.

### D1. `MappingRuleSet` — `provider_id` field removed

The `MappingRuleSet` struct does not carry a separate `provider_id` field. The
ingress provider instance is identified through `source: IdentitySource`, which
contains the relevant anchor (`idp_id`, `cluster_id`, or
`trust_domain`) as its enum variant payload. The `provider_id` slug used in
keyspace coordinates is derived from the `source` field at storage time.

### D2. `DomainResolutionMode` — `allowed_domains` consolidated into enum variants

The `allowed_domains` whitelist was moved from a separate field on
`MappingRuleSet` into the `ClaimsOrMapping` and `ClaimsOnly` enum variants of
`DomainResolutionMode`. This encodes the constraint "must be non-empty for
ClaimsOnly/ClaimsOrMapping, must be empty for Fixed" into Rust's type system,
eliminating cross-field runtime validation.

### D3. `ResolvedGroupBinding` replaced with `GroupRef`

The custom `ResolvedGroupBinding` struct was replaced with `GroupRef` (defined
in `crate::identity::group`), mirroring the existing `RoleRef` pattern. The
`strategy` field from the original `ResolvedGroupBinding` was dropped — group
resolution strategy (`CreateOrGet`/`Get`) is encoded in `GroupAssignment` within
the live ruleset, which the engine fetches during verification. The persisted
shadow record only needs the group anchor (id + domain_id + name).

### D4. `MappingRuleSetUpdate` — mode variant is immutable

The `MappingRuleSetUpdate` type carries `allowed_domains` as a separate
`Option<Vec<String>>` field rather than replacing the entire `DomainResolutionMode`.
The service layer merges the new `allowed_domains` into the existing variant,
preventing an operator from changing `Fixed` → `ClaimsOrMapping` (or vice versa)
via update. The resolution mode variant itself is immutable after creation.

### D5. `is_system: bool` — defaults to `false`

The `is_system` field on `IdentityBinding` is typed as `bool` (not `Option<bool>`)
with a `serde(default)` attribute that resolves missing JSON to `false`. This
removes ambiguity — an omitted field means the operator did not grant system
privileges.

### D6. `GroupStrategy::CreateOrGet` — default for `GroupAssignment`

The `strategy` field on `GroupAssignment` defaults to `CreateOrGet` rather than
requiring explicit specification, as it is the more permissive operator-friendly
default (fewer failures when groups are not pre-provisioned).

### D7. `MappingRule` — `provider_id` not present

`MappingRule` does not carry `provider_id`. It is nested within `MappingRuleSet`,
which identifies the provider through `source: IdentitySource`. All rule-level
context is inherited from the parent ruleset.

### D8. Virtual user lifecycle — deactivation preferred over deletion

The janitor task sets `enabled: false` instead of deleting records. A separate
archive cleanup task permanently removes deactivated records after a configurable
retention period (default: 365 days, configurable via
`[keystone] shadow_registry_archive_retention_days`). This preserves forensic
evidence (identity bindings, authorization snapshots, activity timestamps) for
incident response and compliance auditing. The original spec specified immediate
deletion. The provider interface is extended with explicit `enable_virtual_user`
and `disable_virtual_user` methods. The mapping provider calls the revocation
provider upon virtual user deactivation to trigger the token revocation pipeline.
