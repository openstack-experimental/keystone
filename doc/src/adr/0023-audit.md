# 23. CADF-Compliant Phased Auditing Architecture

Date: 2026-06-16

## Status

Accepted

> **Security review 2026-06-24:** Seven findings applied — HMAC canonicalization
> (RFC 8785/JCS), `boot_session_id` CSPRNG requirement, `initiator.host`
> sanitization rules, `refresh_hmac_key` version-collision fix, HMAC key
> retention policy, cross-node spool tamper detection, and
> `map_event_to_action` dangling-reference correction.
>
> **Schema v1.1 (2026-07-30):** Two fixes applied after real-world audit logs
> showed successful logins and mutations recording `"unknown"` identifiers
> and no client IP at all:
> 1. `sanitize_audit_id` rejected every ID Keystone actually mints. It only
>    accepted canonical hyphenated UUIDs (36 chars); every real ID uses
>    `Uuid::new_v4().simple()` (32 hex chars, no hyphens). Now accepts both
>    shapes.
> 2. `Initiator.host` — a bare `String` carrying only the pre-auth signal —
>    is restructured into a CADF-conformant nested `Host` object
>    (DSP0262 §9.3.3) with `id` (the former string value) and a new
>    `address` attribute for the client network address. Per spec, `host` on
>    a `Resource` (which `Initiator` is) is a structured type; `address` is
>    that type's designated network-address attribute, not a sibling field
>    on `Initiator`. This is a breaking wire-format change (`host` was a
>    string, is now an object), so the payload `version` field bumps from
>    `"1.0"` to `"1.1"`. SIEMs parsing `host` as a string must be updated to
>    read it as an object before ingesting v1.1 events.

## Context

For feature parity with OpenStack's `pycadf`, our Axum/Tonic application
requires CADF-compliant auditing - capturing both perimeter ingress and
business-layer mutations. Our Rust architecture enforces that a security context
cannot be used for policy enforcement before it is fully resolved, using an
externally immutable `ValidatedSecurityContext` with read-only getters. This
design prevents PII leaks while maintaining zero-trust guarantees.

### Wire format: CADF-inspired Keystone schema

The emitted JSON is a **CADF-inspired Keystone schema**, not a literal
DSP0262 serialization. It keeps the CADF data model (initiator, target,
observer, action, outcome, `host`) but uses snake_case keys and a flat layout
so the signed canonical form stays small and stable. A SIEM that expects
literal CADF needs a translation layer; the mapping is:

| Keystone field | DSP0262 / pycadf |
| --- | --- |
| `event_time` | `eventTime` |
| `target.type_uri`, `initiator` / `observer` (no type) | `typeURI` (initiator `service/security/account/user`) |
| `correlation_id` | `attachments` / `tags` (request id) |
| `outcome: "attempt"` | `pending` (pre-commit record of a fail-closed provider operation; Keystone only) |
| `outcome: "client_error"` | `failure` with a client-side cause (perimeter records of rejected requests such as `429`) |
| `domain` | the initiator's domain id, `unknown` when there is none (system actors) |
| `action` | one shared style: lowercase `[a-z0-9_-]` words joined by `/` (e.g. `create`, `oauth2/refresh_reuse_detected`, `wasm_plugin/<host_function>`); applied to every record by `CadfEventPayload::new` |

Renaming the wire keys to the DSP0262 spelling would be a breaking change of
the signed canonical form and is deliberately not done; if it is ever needed
it is a `version: "2.0"` format and the version field already lets a verifier
tell them apart. `seq` is serialized as a JSON number; RFC 8785 numbers are
IEEE-754 doubles, so a verifier that canonicalizes it MUST use a 64-bit
integer type (values above 2^53 are not reachable in practice: the counter
is per boot session). Cross-language vectors, including the v1.1 `host`
cases (`host.id`, `host.address`, both, neither — omitted, never `null`), live
in `tests/audit/hmac_vectors.jsonl`; `tools/audit_vectors.py verify`
re-checks them with an independent Python JCS/HMAC implementation.

## Decision

We implement a hybrid auditing architecture producing standardized CADF events,
dispatched asynchronously to configurable sinks across three phases: Framework,
Perimeter (Extractor + Middleware), and Provider (Hooks).

---

### Phase 1: General Audit Framework & CADF Types

Strict Rust representation of the CADF standard and async dispatch machinery.

**The CADF Payload:** To ensure unsigned events cannot serialize, `CadfEvent`
wraps a private `CadfEventPayload` and `signature` via `serde(flatten)`.

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct CadfEventPayload {
    id: String,
    seq: u64,
    boot_session_id: String,
    hmac_key_version: u64,
    version: String,
    domain: String,
    correlation_id: String,
    event_time: String,
    action: String, outcome: String,
    outcome_reason: Option<String>,
    initiator: Initiator,
    target: Target, observer: Observer,
}

impl CadfEventPayload {
    fn sign(self, dispatcher: &AuditDispatcher) -> CadfEvent {
        dispatcher.finalize_event(self)
    }
    /// Internal test-tooling only — NOT the SIEM verification path.
    /// External SIEMs MUST implement verification by: (1) parse received JSON,
    /// (2) remove the `signature` key, (3) serialize the remainder in JCS
    /// canonical form (RFC 8785), (4) compute HMAC-SHA256 with the key
    /// identified by `hmac_key_version`. Cross-language test vectors
    /// (tests/audit/hmac_vectors.jsonl) cover this exact path.
    fn from_cadf(evt: &CadfEvent) -> Self {
        let e = evt.payload();
        Self {
            id: e.id.clone(), seq: e.seq, boot_session_id: e.boot_session_id.clone(),
            hmac_key_version: e.hmac_key_version, version: e.version.clone(),
            domain: e.domain.clone(), correlation_id: e.correlation_id.clone(),
            event_time: e.event_time.clone(), action: e.action.clone(),
            outcome: e.outcome.clone(), outcome_reason: e.outcome_reason.clone(),
            initiator: e.initiator.clone(), target: e.target.clone(),
            observer: e.observer.clone(), }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CadfEvent {
    #[serde(flatten)]
    event: CadfEventPayload,
    signature: String,
}

impl CadfEvent {
    pub fn payload(&self) -> &CadfEventPayload { &self.event }
    pub fn signature(&self) -> &str { &self.signature }
    pub fn correlation_id(&self) -> &str { &self.event.correlation_id }
    pub fn id(&self) -> &str { &self.event.id }
    pub fn seq(&self) -> u64 { self.event.seq }
    pub fn boot_session_id(&self) -> &str { &self.event.boot_session_id }
}

// `host` is a nested CADF `Host` object (DSP0262 §9.3.3), not a bare
// string — `Resource.host` (Initiator is a `Resource`) is spec-defined as a
// structured type with `id`, `address`, `agent`, `platform`. Only `id` and
// `address` are populated; `agent`/`platform` are valid but unused.
#[derive(Serialize, Clone)]
pub struct Host {
    /// Pre-auth signal (EC2 access key, federation idp_id). No PII.
    /// Content arrives before authentication and is fully attacker-controlled.
    /// Sanitization rules (enforced at construction, not by Host itself):
    ///   EC2 access key  — must match /^AKIA[A-Z0-9]{16}$/; rejected otherwise.
    ///   Federation idp_id (UUID) — passed through sanitize_audit_id().
    ///   Federation idp_id (non-UUID) — filtered to [a-zA-Z0-9._-], max 64 chars.
    ///   Any other value — filtered to printable ASCII (0x20–0x7E), max 128 chars.
    ///   Field is omitted (None) if empty after filtering.
    id: Option<String>,
    /// Client network address. Parsed via `std::net::IpAddr` and re-rendered
    /// through `Display`; anything that doesn't parse as an IP is dropped
    /// rather than stored raw. Field is omitted (None) if never set.
    address: Option<String>,
}
impl Host {
    fn from_id(id: String) -> Self { Self { id: Some(id), address: None } }
    pub fn id(&self) -> Option<&str> { self.id.as_deref() }
    pub fn address(&self) -> Option<&str> { self.address.as_deref() }
}

#[derive(Serialize, Clone)]
pub struct Initiator {
    id: String, project_id: Option<String>, domain_id: Option<String>,
    host: Option<Host>,
}
impl Initiator {
    fn new(id: String, project_id: Option<String>, domain_id: Option<String>,
        host: Option<Host>) -> Self
    { Self { id, project_id, domain_id, host } }
    pub fn id(&self) -> &str { &self.id }
    pub fn project_id(&self) -> Option<&str> { self.project_id.as_deref() }
    pub fn domain_id(&self) -> Option<&str> { self.domain_id.as_deref() }
    pub fn host(&self) -> Option<&Host> { self.host.as_ref() }
    /// Attach a client IP to `host.address`, sanitized. Preserves any
    /// pre-auth `host.id` signal already set.
    fn with_address(mut self, address: Option<String>) -> Self { /* ... */ self }
}
#[derive(Serialize, Clone)]
pub struct Target { pub id: String, pub type_uri: String }
#[derive(Serialize, Clone)]
pub struct Observer { pub node_id: String, pub id: String }
```

**Principal-based initiator** - There is no separate "verified token" type.
After authentication succeeds, `build_initiator_from_principal()` derives the
`Initiator` from the authentication result's `PrincipalInfo` (immutable
authentication chain, never from token scope). A later scope or authorization
failure is therefore attributed to the known principal, while a failure before
authentication completes yields an all-`"unknown"` initiator. Internal
(non-request) actors use the system convention `system:<component>` as the
initiator id (e.g. `system:oauth2-key-hook`).

**Outcome reasons** - `reason` is drawn from the closed `OutcomeReason`
vocabulary (the sanitized error variant name or a static literal). Free-form
error text, plugin-supplied deny messages and route details never enter a
signed record; they are logged instead.

**Request audit context** - A request-scoped middleware
(`with_audit_request_context`) places the resolved client IP and the
correlation id in a task-local `AuditRequestContext`. Perimeter and provider
emitters read it to stamp `initiator.host.address` and `correlation_id`; a
value set explicitly by a handler (e.g. the EC2 access key as `host.id`) wins.
Host functions invoked inside a WASM guest may not see the task-local and then
use a fresh correlation id.

**ID sanitization** - Strips non-ASCII, caps at 64 chars. Accepts either
UUID rendering Keystone actually produces: canonical hyphenated, or
`Uuid::simple()` (no hyphens) — the latter is what every resource ID
minted across the codebase uses (`Uuid::new_v4().simple()`), so a
strict-canonical-only check (schema v1.0) coerced every real ID to
`"unknown"`:

```rust
fn sanitize_audit_id(id: &str) -> String {
    if id.trim().is_empty() { return "unknown".to_string(); }
    let cleaned: String = id.chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .take(64).collect();
    if cleaned.is_empty() { return "unknown".to_string(); }
    // Canonical: len 36, 4 hyphens at canonical positions, 32 hex digits.
    let is_canonical = cleaned.len() == 36
        && cleaned.chars().filter(|c| *c == '-').count() == 4
        && cleaned.chars().filter(|c| c.is_ascii_hexdigit()).count() == 32
        && cleaned.get(8..9) == Some("-")
        && cleaned.get(13..14) == Some("-")
        && cleaned.get(18..19) == Some("-")
        && cleaned.get(23..24) == Some("-");
    // Simple: exactly 32 hex digits, no hyphens (Uuid::simple() format).
    let is_simple = cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if is_canonical || is_simple { cleaned } else { "unknown".to_string() }
}
```

**The Audit Dispatcher** - Dual-channel QoS with atomic HMAC rotation:

```rust
pub struct AuditDispatcher {
    perimeter_sender: mpsc::Sender<CadfEvent>,  // 4096, best-effort
    critical_sender: mpsc::Sender<CadfEvent>,   // 256, fail-closed
    node_id: Arc<str>,
    hmac_key_and_version: ArcSwap<(Arc<[u8]>, u64)>,
    boot_session_id: String,
    seq_counter: AtomicU64,
    dropped_count: Arc<AtomicU64>,
    last_drop_log_time: AtomicU64,
    log_baseline: std::time::Instant,
    postaudit_dropped_count: Arc<AtomicU64>,
    events_total: Arc<AtomicU64>, // total events dispatched (perimeter + critical)
}

impl AuditDispatcher {
    // Signs over unsigned payload. HMAC input is the JCS-canonical (RFC 8785)
    // UTF-8 JSON of all payload fields with keys in lexicographic order, no
    // extra whitespace. Most Option-typed fields serialize as `null` when
    // absent. Exception: `Initiator.host` (and, nested within it, `host.id`
    // / `host.address`) uses skip_serializing_if and is **omitted entirely**
    // (not set to `null`) when absent. SIEMs MUST re-serialize the received
    // JSON (minus `signature`) without inserting absent keys. This is the
    // sole canonical form for HMAC verification.
    fn finalize_event(&self, partial: CadfEventPayload) -> CadfEvent {
        let (key, version) = self.hmac_key_and_version.load_full().as_ref();
        let completed = CadfEventPayload {
            seq: self.seq_counter.fetch_add(1, Ordering::SeqCst),
            boot_session_id: self.boot_session_id.clone(),
            hmac_key_version: **version, ..partial };
        let sig = compute_hmac_sha256(&completed, &**key);
        CadfEvent { event: completed, signature: sig }
    }

    /// Best-effort: drops if full. Floor-rate log: at least once/sec.
    pub fn dispatch(&self, event: CadfEvent) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        let cid = event.correlation_id().to_string();
        if self.perimeter_sender.try_send(event).is_err() {
            let count = self.dropped_count.fetch_add(1, Ordering::Relaxed);
            let now_us = self.log_baseline.elapsed().as_micros() as u64;
            let should_log = (count % 1024) == 0
                || (self.last_drop_log_time.load(Ordering::Relaxed) + 1_000_000)
                    <= now_us;
            if should_log {
                self.last_drop_log_time.store(now_us, Ordering::Relaxed);
                error!(dropped_count = count, correlation_id = %cid,
                    "audit channel full, event dropped (best-effort)");
            }
        }
    }

    /// Fail-closed: blocks until sent.
    pub async fn dispatch_critical(&self, event: CadfEvent)
        -> Result<(), AuditChannelDead>
    {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        self.critical_sender.send(event).await.map_err(|_| AuditChannelDead)
    }

    /// MUST be called from a single serialized context (dedicated key-rotation
    /// task). Concurrent invocations produce version collisions (two different
    /// keys share the same version), breaking SIEM verification.
    pub(crate) fn refresh_hmac_key(&self, new_key: Arc<[u8]>, new_version: u64) {
        self.hmac_key_and_version.store(Arc::new((new_key, new_version)));
    }
}
```

**Spooling & Replay:** Workers drain channels to sinks. On shutdown, unsent
critical events spool. On startup, HMAC-verified and replayed. Corrupted lines
are skipped to recover adjacent valid events; file quarantined at end.

**`boot_session_id`:** MUST be a UUIDv4 generated from the OS CSPRNG at
process startup, before any request handling. MUST NOT be derived from a
wall-clock timestamp, PID, or any predictable value. It is never persisted;
its sole purpose is to namespace the `seq` counter within a single process
lifetime. SIEMs MUST partition `seq`-gap detection by
`(node_id, boot_session_id)` to avoid false gap alerts across restarts.

---

### Phase 2: Perimeter Auditing (Ingress & Completion)

Captures access attempts at the boundary.

1. **Ingress (`Auth` Extractor):** The Axum middleware already injects a
   `request-id` header (UUIDv4). If the client already sent a `request-id`
   header, the middleware must strictly ignore its value and overwrite it with a
   fresh UUIDv4 (prevent client-controlled correlation spoofing).
   `correlation_id` is derived from this header value, not from the request
   token. Extracts `Initiator` from fully resolved `ValidatedSecurityContext`,
   token parse failure: `outcome: "failure"`, `Initiator` is all `"unknown"` (no
   partial data from untrusted payload). On partial validation failure (token
   parsed but policy/scope failed): uses the authenticated principal
   (`build_initiator_from_principal`) to extract the sanitized initiator. For endpoints with
   pre-auth identity signals (EC2 `access` key, federation `idp_id`), include
   non-PII identifiers as `initiator.host.id` — these don't require a
   validated context and don't risk PII leakage. The client network address
   is stamped separately as `initiator.host.address` once available, resolved
   via ADR 0022's `resolve_client_ip_from_headers` under its own trusted-proxy
   configuration (`[oslo_middleware]`) — **not** `public_ingress_peer_addr`,
   which returns the raw, pre-resolution TCP peer (the reverse proxy's own
   address whenever Keystone sits behind one) and exists so each trust
   boundary (rate limiting, auth-plugin dispatch, audit) can apply its own
   resolution independently, per the `crate::net` module's trusted-proxy
   model. For authenticated requests, the `Auth` extractor resolves it once
   and sets it on every `ValidatedSecurityContext` it builds (via
   `SecurityContext.peer_addr`, mirroring how `correlation_id` is threaded);
   the login endpoint, which authenticates before any `ValidatedSecurityContext`
   exists, resolves and stamps it directly, independently of the raw peer
   address it separately feeds to rate limiting and auth-plugin dispatch.

2. **Completion (Middleware):** `with_audit_request_context` wraps the
   request. Authentication layers (`Auth`, API-key auth) record the
   authenticated initiator in the request audit context; after the handler
   returns, the middleware emits one perimeter record with the HTTP status
   mapped to an outcome (`2xx/3xx` success, `401`/`403`/`5xx` failure, other
   `4xx` including `429` `client_error`) and a static reason. It applies only
   to an explicit allowlist of authentication surfaces (`/v3|v4/auth/tokens`,
   `/v3/ec2tokens`, `/v4/auth/passkey`, `/v4/vendordata`, `/SCIM/v2`,
   `POST /v4/k8s_auth/{id}/auth`), so ordinary validated-token traffic does
   not swamp the perimeter channel; and only when the handler did not already
   emit its own perimeter record, so each request leaves exactly one. An
   early rejection such as a rate limit therefore still leaves a record.
   Initiator is `unknown` when authentication never completed.

**Error sanitization** - Exhaustive match prevents silent PII leakage:

```rust
// Excerpts of `crates/keystone/src/audit.rs`. Both matches have no wildcard
// arm, so a new `KeystoneApiError` / `AuthenticationError` variant does not
// compile until it is classified.
pub fn error_variant_name(error: &KeystoneApiError) -> String {
    match error {
        KeystoneApiError::Unauthorized { source, .. }
        | KeystoneApiError::Forbidden { source, .. } => source
            .downcast_ref::<AuthenticationError>()
            .map(|e| sanitize_authentication_error(e).to_string())
            .unwrap_or_else(|| "Unauthorized".to_string()),
        KeystoneApiError::UnauthorizedNoContext => "Unauthorized".to_string(),
        KeystoneApiError::NotFound { .. } => "NotFound".to_string(),
        KeystoneApiError::Conflict(_) => "Conflict".to_string(),
        KeystoneApiError::BadRequest(_) => "BadRequest".to_string(),
        KeystoneApiError::InvalidToken => "InvalidToken".to_string(),
        KeystoneApiError::TooManyRequests { .. } => "TooManyRequests".to_string(),
        KeystoneApiError::ServiceUnavailable(_) => "ServiceUnavailable".to_string(),
        // ... every remaining variant (about two dozen) is listed explicitly.
    }
}

pub fn sanitize_authentication_error(e: &AuthenticationError) -> &'static str {
    match e {
        AuthenticationError::UserDisabled(_) => "UserDisabled",
        AuthenticationError::UserLocked(_) => "UserLocked",
        AuthenticationError::UserNameOrPasswordWrong => "UserNameOrPasswordWrong",
        AuthenticationError::Ec2SignatureInvalid => "Ec2SignatureInvalid",
        AuthenticationError::Provider { source, .. } => {
            extract_provider_name(source.as_ref()).unwrap_or("ProviderError")
        }
        // ... all ~40 variants map to stable literals.
    }
}

/// Type-only dispatch: no provider error string content is used. Guarantees
/// PII in third-party provider errors (emails, tokens) never reaches audit.
fn extract_provider_name(source: &Box<dyn std::error::Error>)
    -> Option<&'static str>
{
    if source.is::<identity::IdentityProviderError>() { Some("Identity") }
    else if source.is::<catalog::CatalogProviderError>() { Some("Catalog") }
    else if source.is::<role::RoleProviderError>() { Some("Role") }
    else if source.is::<assignment::AssignmentProviderError>() { Some("Assignment") }
    else { None }
}
```

**Semantic action mapping** - Hardcodes v3/v4 paths, sanitizes
`Operation::Other`:

```rust
fn map_event_to_action(event: &Event) -> String {
    match &event.operation {
        Operation::Create => "create".to_string(),
        Operation::Update => "update".to_string(),
        Operation::Delete => "delete".to_string(),
        Operation::Disable => "disable".to_string(),
        Operation::Enable => "enable".to_string(),
        Operation::Authenticate => "authenticate".to_string(),
        Operation::Revoke => "revoke".to_string(),
        Operation::Other(action) => {
            // Sanitize: ASCII alphanumeric + /, -, _; cap 64 chars; reject empty.
            let s: String = action.chars()
                .filter(|c| c.is_ascii_alphanumeric()
                    || *c == '-' || *c == '_' || *c == '/')
                .take(64)
                .collect();
            if s.is_empty() { "unknown".to_string() } else { s }
        }
    }
}
```

---

### Phase 3: Provider Auditing via Context-Aware Hooks

`ProviderHooks` (`on_event`) is fire-and-forget without context. Instead,
`AuditHook` receives context and outcome, dispatched inline with fail-closed
semantics. Reentrancy prevented via `tokio::task_local!`.

```rust
pub trait AuditHook: Send + Sync {
    async fn on_auditable_event(&self, ctx: &ValidatedSecurityContext,
        event: &Event, outcome: &AuditOutcome) -> Result<(), AuditDispatchError>;
}

pub enum AuditOutcome { Attempt, Success, Failure { reason: String } }
/// Sanitize hook error to stable literal. Prevents {:?} debug formatting
/// from leaking type names or internal diagnostics into CADF outcomes.
/// Hook errors only abort the provider op; they never flow into outcome_reason.
pub enum AuditDispatchError {
    DispatcherDead,
    HookFailed { description: &'static str },
    Reentered,
}

impl EventDispatcher {
    /// Fail-closed pre-audit: any hook error aborts the provider operation.
    /// Collects hook errors (except DispatcherDead short-circuits).
    pub async fn emit_critical(&self, ctx: &ValidatedSecurityContext,
        event: &Event, outcome: &AuditOutcome) -> Result<(), AuditDispatchError>
    {
        let is_reentered = EMIT_CRITICAL_RECURSION.try_with(|v| *v).unwrap_or(false);
        if is_reentered { return Err(AuditDispatchError::Reentered); }
        EMIT_CRITICAL_RECURSION.scope(true, async move {
            let audit = self.audit_hooks.lock().await.values().cloned().collect::<Vec<_>>();
            let mut error_count = 0u64;
            for hook in &audit {
                match hook.on_auditable_event(ctx, event, outcome).await {
                    Err(AuditDispatchError::DispatcherDead) =>
                        return Err(AuditDispatchError::DispatcherDead),
                    Err(AuditDispatchError::HookFailed { .. }) => error_count += 1,
                    Err(AuditDispatchError::Reentered) => error_count += 1,
                    Ok(()) => {}
                }
            }
            if error_count > 0 {
                return Err(AuditDispatchError::HookFailed {
                    description: "hook execution failed",
                });
            }
            // ... fire-and-forget regular hooks ...
            Ok(())
        }).await
    }
}
```

**Audit-Before-Commit (Fail-Closed Transaction Safety):**

```rust
// Shape of the macro (`crates/core/src/events.rs`); see its rustdoc for the
// full contract.
audited_op! {
    dispatcher: &self.events,
    ctx: vsc,                         // &ValidatedSecurityContext
    event: Event::new(Operation::Delete, EventPayload::User { id }),
    operation: self.backend.delete_user(state, id),
    on_audit_error: |e| ProviderError::AuditDispatchFailed { source: e },
    // optional: reason: |e| "StaticReason"
}
```

Behaviour: (1) emit the `Attempt` record on the critical channel and return
`on_audit_error(..)` without running the operation if that fails (fail-closed);
(2) run the operation; (3) emit `Success`, or `Failure` whose reason is a
`&'static str` variant name from the error's `strum::IntoStaticStr` derive
(never formatted from error data). If the post-audit record cannot be queued, an
`ERROR` log is written and `keystone_audit_postaudit_dropped_total` is
incremented.

**Coverage:** every state-changing provider method is wrapped in `audited_op!`
(through `audited_if_ctx!`, which runs the operation unaudited-but-emitted when
the caller is internal, e.g. a janitor or a hook, and has no principal to
attribute it to). That includes API keys, OAuth2 clients and signing keys,
token revocation (`DELETE /v3/auth/tokens`), domain configuration, ID
mappings, dynamic plugin identities, SCIM index entries and the credential
bulk deletes. Payloads carry IDs only, never secrets or option values. The
unit test `audit_coverage::every_mutating_provider_method_is_audited_or_allow_listed`
walks every provider `service.rs` and fails for a mutating method that has
neither call site nor an `ALLOW_LIST` entry with a reason, so a new provider
cannot ship unaudited by accident.

**CADF Hook:** Single `CadfAuditHook` translates events to CADF, signs via
`CadfEventPayload::sign()`, dispatches via `dispatch_critical()`. Wired at
startup: `state.event_dispatcher.subscribe_audit(CadfAuditHook).await`.

---

## Security Compliance vs. PII Requirements

- **Data Minimization:** `Initiator` has only UUIDs. Human-readable fields
  (usernames, emails) are **excluded by design**.
- **PII Redaction:** `username`, `display_name`, `email_address`,
  `project_name`, `domain_name` excluded. Future fields require opaque wrappers.
- **Outcome Isolation:** `outcome_reason` limited to sanitized variant name.
- **HMAC Signing:** `CadfEvent` wraps `(CadfEventPayload, signature)` via
  `serde(flatten)`. Private fields prevent unsigned construction. Per-node
  signing key derived via:
  ```
  HKDF-Expand(KEK, info="keystone-audit-hmac-v1:{node_id_utf8}", L=32)
  ```
  The `node_id` suffix ensures each node holds a **distinct** signing key; a
  compromised node cannot forge audit records attributed to other nodes.  This
  aligns with ADR 0016-v2 §3.1 (which uses `node_id_u64_be` for Raft nodes;
  here we use the UTF-8 encoding of the string node ID).  HKDF-Expand-only is
  used because the KEK is already uniformly random (Extract is a no-op
  security-wise).  Key+version as `ArcSwap<(Arc<[u8]>, u64)>` for atomic
  rotation (ADR 0016-v2 §6.2).  HMAC input is the JCS-canonical (RFC 8785)
  serialization of the payload (all fields, lexicographically sorted keys,
  compact, null fields included).
- **HMAC Key Retention:** The KEK store MUST retain all HMAC key versions for
  at least `max(spool_drain_timeout + SIEM_lag_budget, 24h)`. Key versions
  are monotonically increasing and permanent — never reused. The version
  number is supplied by the key-rotation task (not derived by
  `refresh_hmac_key` itself) to prevent version collisions under concurrent
  rotation attempts. SIEMs MUST cache all key versions seen and MUST NOT
  delete them without operator confirmation.
- **Spool Integrity:** Corrupted/tampered lines skipped (recovery-first).
  Per-node spool path (`audit-spool-{node_id}.jsonl`) eliminates shared-file
  races; advisory lock as secondary guard. Because the HMAC key is **per-node**
  (node_id is bound into the key derivation), the SIEM can reject events whose
  `observer.node_id` does not match the key used to verify their signature;
  mismatches MUST be quarantined as tamper indicators, not silently accepted.
- **Delivery Guarantee:** At-least-once delivery. SIEMs must deduplicate on
  `CadfEvent.id` (unique `node_id:uuid`).
- **Attempt Reconciliation:** SIEM treats an `Attempt` with no corresponding
  `Success`/`Failure` within 300s as `outcome: unknown` and triggers a warning
  alert. Loki query:
  `sum_over_time({app="keystone"} | cadf_outcome="attempt" [10m]) -   sum_over_time({app="keystone"} | cadf_outcome=~"success|failure" [10m]) > 0`
- **Authenticated Principal Boundary:** the initiator of a post-authentication
  failure comes only from the authentication result's principal
  (`build_initiator_from_principal`). Partial context failure = authorization
  issue, not crypto issue.
- **Provider Error Sanitization:** `extract_provider_name` uses type-only
  dispatch (`is::<T>()`). No error string content used.

---

## Observability

The audit counters are exported as Prometheus **counters** (not gauges), next
to gauges for the queue depth, spool size and signing key version, using the
shared `openstack-keystone-metrics` primitives (ADR 0031):

| Metric | Type | Meaning |
| --- | --- | --- |
| `keystone_audit_events_total` | counter | Events accepted into a channel (drops excluded) |
| `keystone_audit_dropped_total` | counter | Perimeter events dropped because the channel was full |
| `keystone_audit_postaudit_dropped_total` | counter | Post-audit outcomes that could not be recorded |
| `keystone_audit_channel_depth{channel}` | gauge | Events queued for the spool writer (`perimeter`, `critical`) |
| `keystone_audit_hmac_key_version` | gauge | HMAC key version currently signing events |
| `keystone_audit_spool_bytes` | gauge | Live spool plus sealed segments on disk |
| `keystone_audit_spool_write_failures_total` | counter | Events the writer failed to append (lost) |
| `keystone_audit_spool_quarantined_total` | counter | Segments quarantined for tampered or unparsable lines |
| `keystone_audit_spool_verified_total{result}` | counter | Lines checked at startup (`verified`, `invalid`) |
| `keystone_audit_shipped_events_total{result}` | counter | Events handed to the sink (`shipped`, `skipped`) |
| `keystone_audit_sink_errors_total` | counter | Failed batch deliveries to the sink |
| `keystone_audit_spool_retention_deleted_total` | counter | Sealed segments deleted unacknowledged by the size, age or count limits |

Offered load on the perimeter channel is `events + dropped`, so the drop ratio
is `dropped / (events + dropped)`. The rules below live in
`deploy/prometheus/alert_rules.yaml`, together with alerts for spool write
failures, quarantined segments, a failing sink and a backed-up critical
channel:

```yaml
groups:
  - name: keystone_audit
    rules:
      - alert: KeystoneAuditDropsVolumetric
        expr: |
          rate(keystone_audit_dropped_total[5m]) > 100 and
          rate(keystone_audit_dropped_total[5m]) /
          (rate(keystone_audit_events_total[5m]) + rate(keystone_audit_dropped_total[5m])) > 0.05
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Audit drops >100/s (>5% of perimeter events)"
          description:
            "Possible volumetric attack. Check rate limiting (ADR 0022)."

      - alert: KeystoneAuditPostauditDrops
        expr: |
          increase(keystone_audit_postaudit_dropped_total[5m]) > 0 and
          rate(keystone_audit_events_total[5m]) > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Post-audit outcome record lost after DB commit"
          description:
            "The outcome record (Success/Failure) for a high-criticality op
            (disable_user, delete_credential) was dropped. The pre-audit Attempt
            exists, but the final outcome is lost. Compensating local log
            entries (structured JSONL) should be independently shipped to the
            SIEM for dual-delivery."
```

---

## Implementation status

| Area | Status |
| --- | --- |
| Framework: `AuditDispatcher`, HMAC signing, spool, replay | Implemented |
| Spool segments, quarantine of tampered files, writer lock | Implemented |
| Downstream sink and segment acknowledgement | Implemented (`stdout` sink; a segment is deleted only after the sink accepted it; a network sink is tracked separately) |
| Shutdown drain (`spool_drain_timeout_secs`) | Implemented |
| Metrics (`keystone_audit_*`) and alert rules | Implemented; counters, except the gauges named in the metric list |
| Perimeter events: login handlers | Implemented (token, EC2, OAuth2 token, federation JWT/OIDC) |
| Perimeter completion record for the other authentication surfaces | Implemented by the request middleware (path allowlist) |
| `Auth`-extractor ingress event for every request | **Not implemented, by design**: only the completion record exists, to keep the perimeter channel bounded |
| Provider auditing: `audited_op!` / `audited_if_ctx!` | Implemented, enforced by a coverage test over the provider services |
| Initiator from the authenticated principal; request audit context | Implemented |
| Wire format | CADF-inspired Keystone schema (see above), version `1.1` |
| Signing-key rotation | Key versions are stamped and old versions verify; operator-driven rotation is not automated |

Phase numbers in code comments ("Phase 4" metrics, "Phase 5.x" vectors and
integration tests) refer to follow-up work after the three phases above; it
is described in the Observability section and covered by the test suites.

## Related ADRs

- **0016-v2:** HMAC key from KEK. KEK rotation calls `refresh_hmac_key()`.
- **0017:** `ValidatedSecurityContext` in hooks. `correlation_id()`,
  `verified_token()` for partial context.
- **0020:** Mapping engine errors sanitized via `error_variant_name()`.
- **0022:** Rate-limiting. 429 produces `outcome: "client_error"`. Audit drop
  alerts correlated with rate limiter health.

---

## Alternatives

1. **Provider wrapper traits:** Rejected — 30+ enum expansions. `AuditHook` is a
   single subscription point.
2. **Mutable context propagation:** Rejected — Rust ownership enforces
   integrity.
3. **Single-channel dispatch:** Rejected — dual channels provide QoS isolation.
4. **Post-serialization signing:** Rejected — two-phase builder prevents
   unsigned-in-channel window.

---

## Accepted Risk: Millisecond Durability Gap

`dispatch_critical()` returns `Ok(())` after placing the signed event into the
in-memory `mpsc` channel (256 depth). If the node hard-crashes (power loss,
kernel panic) before the background worker drains the event to the spool file,
that signed event is lost from RAM. The DB transaction that triggered the event
has already committed, so the audit trail has a gap.

**Why synchronous fsync is rejected:** Adds ~10-50ms latency per critical
provider operation. At Keystone scale (thousands of ops/sec), this causes SLO
violation. A per-event WAL is equally expensive. The in-memory channel provides
ordering without blocking the provider call path.

**Mitigations:** Graceful shutdown (SIGTERM) drains the full channel (10s
budget) before exit — zero events lost. Spool replay covers process restarts via
graceful shutdown handlers. Compensating local logs for post-audit drops provide
dual delivery for high-criticality ops.

**Risk acceptance:** The millisecond crash window trades an extremely rare
single-event loss for guaranteed sub-1ms provider latency. This aligns with
OpenStack's design philosophy: audit is advisory for SIEM compliance, not a hard
transactional requirement.

---

## Consequences

- **Security:** Two-event perimeter + fail-closed provider audit ensures
  complete coverage. Post-audit uses `emit_critical` with compensating local log
  fallback for dual-delivery. `KeystoneAuditPostauditDrops` alert is critical.
- **Performance:** Dual channels isolate perimeter (4096, best-effort) from
  critical (256, fail-closed). Not a substitute for rate limiting (ADR 0022).
- **Correctness:** Correlation IDs link perimeter through provider events.
- **Integrity:** Two-phase builder, sanitized error names, monotonic seq.
- **Shutdown:** 10s drain timeout, disk spool. Up to 4096 perimeter events may
  be lost. Corrupted spools quarantined for forensic triage.
