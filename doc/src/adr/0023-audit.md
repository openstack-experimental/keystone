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
> **Implementation review 2026-06-29 (Phase 7):** Three correctness bugs fixed:
> (1) `record_postaudit_drop()` incorrectly fired on pre-audit Attempt failures,
> mislabeling the `KeystoneAuditPostauditDrops` Prometheus metric; (2) spool
> file not removed after clean replay, causing unbounded growth and re-delivery
> on every restart; (3) stale KEK `.tmp` file from a crash prevented node
> startup (`create_new(true)` returned `AlreadyExists`).

## Context

For feature parity with OpenStack's `pycadf`, our Axum/Tonic application
requires CADF-compliant auditing - capturing both perimeter ingress and
business-layer mutations. Our Rust architecture enforces that a security context
cannot be used for policy enforcement before it is fully resolved, using an
externally immutable `ValidatedSecurityContext` with read-only getters. This
design prevents PII leaks while maintaining zero-trust guarantees.

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

#[derive(Serialize, Clone)]
pub struct Initiator {
    id: String, project_id: Option<String>, domain_id: Option<String>,
    /// Pre-auth signal (EC2 access key, federation idp_id). No PII.
    /// Content arrives before authentication and is fully attacker-controlled.
    /// Sanitization rules (enforced at construction, not by Initiator itself):
    ///   EC2 access key  — must match /^AKIA[A-Z0-9]{16}$/; rejected otherwise.
    ///   Federation idp_id (UUID) — passed through sanitize_audit_id().
    ///   Federation idp_id (non-UUID) — filtered to [a-zA-Z0-9._-], max 64 chars.
    ///   Any other value — filtered to printable ASCII (0x20–0x7E), max 128 chars.
    ///   Field is omitted (None) if empty after filtering.
    host: Option<String>,
}
impl Initiator {
    fn new(id: String, project_id: Option<String>, domain_id: Option<String>,
        host: Option<String>) -> Self
    { Self { id, project_id, domain_id, host } }
    pub fn id(&self) -> &str { &self.id }
    pub fn project_id(&self) -> Option<&str> { self.project_id.as_deref() }
    pub fn domain_id(&self) -> Option<&str> { self.domain_id.as_deref() }
}
#[derive(Serialize, Clone)]
pub struct Target { pub id: String, pub type_uri: String }
#[derive(Serialize, Clone)]
pub struct Observer { pub node_id: String, pub id: String }
```

**VerifiedFernetToken** - Opaque wrapper only constructible post-verification.
The `_score: NonZeroU32` constructor guard proves crypto validation passed.

```rust
pub struct VerifiedFernetToken(FernetToken);

impl VerifiedFernetToken {
    pub(crate) fn from_verified(token: FernetToken,
        _score: std::num::NonZeroU32) -> Self { Self(token) }
    pub fn user_id(&self) -> &str { self.0.user_id() }
    pub fn domain_id(&self) -> Option<&str> { self.0.domain_id() }
}
```

**ID sanitization** - Strips non-ASCII, caps at 64 chars:

```rust
fn sanitize_audit_id(id: &str) -> String {
    if id.trim().is_empty() { return "unknown".to_string(); }
    let cleaned: String = id.chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .take(64).collect();
    if cleaned.is_empty() { return "unknown".to_string(); }
    // Strict UUID check: len 36, 4 hyphens at canonical positions, 32 hex digits.
    // Reject any non-UUID format — prevents crafted ID bypass.
    if cleaned.len() == 36
        && cleaned.chars().filter(|c| *c == '-').count() == 4
        && cleaned.chars().filter(|c| c.is_ascii_hexdigit()).count() == 32
        && cleaned.get(8..9) == Some("-")
        && cleaned.get(13..14) == Some("-")
        && cleaned.get(18..19) == Some("-")
        && cleaned.get(23..24) == Some("-") {
        cleaned
    } else { "unknown".to_string() }
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
    // extra whitespace, null-valued fields always included. This is the sole
    // canonical form; SIEMs must reproduce it exactly for verification.
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
   parsed but policy/scope failed): uses `VerifiedFernetToken` from
   `vsc.verified_token()` to extract sanitized initiator. For endpoints with
   pre-auth identity signals (EC2 `access` key, federation `idp_id`), include
   non-PII identifiers as `initiator.host` or a custom attachment — these don't
   require a validated context and don't risk PII leakage.

2. **Completion (Middleware):** Post-handler extracts `CorrelationId` and
   `ReadOnlyInitiator`, emits event with HTTP status mapped to outcome.

**Error sanitization** - Exhaustive match prevents silent PII leakage:

```rust
fn error_variant_name(error: &KeystoneApiError) -> String {
    match error {
        KeystoneApiError::Unauthorized { source, .. }
        | KeystoneApiError::Forbidden { source, .. } => {
            source.downcast_ref::<AuthenticationError>()
                .map(|e| sanitize_authentication_error(e).to_string())
                .unwrap_or_else(|| "Unauthorized".to_string())
        }
        KeystoneApiError::NotFound { .. } => "NotFound".to_string(),
        KeystoneApiError::Conflict { .. } => "Conflict".to_string(),
        KeystoneApiError::BadRequest { .. } => "BadRequest".to_string(),
        KeystoneApiError::RateLimited { .. } => "RateLimited".to_string(),
        KeystoneApiError::Gone { .. } => "Gone".to_string(),
        KeystoneApiError::InternalServerError => "InternalServerError".to_string(),
        KeystoneApiError::ServiceUnavailable => "ServiceUnavailable".to_string(),
        KeystoneApiError::GatewayTimeout => "GatewayTimeout".to_string(),
        e => e.type_name().unwrap_or("UnknownError").to_string(),
    }
}

fn sanitize_authentication_error(e: &AuthenticationError) -> &'static str {
    match e {
        AuthenticationError::DomainDisabled(_) => "DomainDisabled",
        AuthenticationError::ProjectDisabled(_) => "ProjectDisabled",
        AuthenticationError::TrustorUserDisabled(_) => "TrustorUserDisabled",
        AuthenticationError::UserDisabled(_) => "UserDisabled",
        AuthenticationError::UserLocked(_) => "UserLocked",
        AuthenticationError::UserPasswordExpired(_) => "UserPasswordExpired",
        AuthenticationError::Provider { source, .. } => {
            extract_provider_name(source).unwrap_or("ProviderError")
        }
        AuthenticationError::Validation(_) => "ValidationError",
        AuthenticationError::StructBuilder { .. } => "StructBuilderError",
        AuthenticationError::TokenExpired(_) => "TokenExpired",
        AuthenticationError::TokenRevoked(_) => "TokenRevoked",
        AuthenticationError::AuthCredentialNotFound(_) => "AuthCredentialNotFound",
        AuthenticationError::AuthCredentialExpired(_) => "AuthCredentialExpired",
        AuthenticationError::AuthCredentialMalformed(_) => "AuthCredentialMalformed",
        AuthenticationError::PrincipalNotUnique(_) => "PrincipalNotUnique",
        AuthenticationError::InvalidAuthMethod(_) => "InvalidAuthMethod",
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
macro_rules! audited_op {
    ( dispatcher: $dispatcher:expr, ctx: $ctx:expr, event: $event:expr,
      operation: $op:expr, error_variant: $err_variant:path ) => {{
        let event = $event;
        // Pre-audit (Attempt): fails if dispatcher dead
        $dispatcher.emit_critical($ctx, &event, &AuditOutcome::Attempt).await
            .map_err(|e| $err_variant { source: e })?;
        let result = $op.await;
        // Post-audit: use emit_critical. If channel full, write compensating
        // local JSONL log to guarantee dual-delivery path to SIEM.
        let outcome = match &result {
            Ok(_) => AuditOutcome::Success,
            Err(e) => AuditOutcome::Failure {
                reason: error_variant_name(e).to_string() }
        };
        if $dispatcher.emit_critical($ctx, &event, &outcome)
            .await.is_err()
        {
            // Fallback: local compensating log (structured JSONL, independent ship)
            // Includes operation and resource ID for forensic SIEM lookup.
            error!(
                correlation_id = %$ctx.correlation_id().to_string(),
                outcome = ?outcome,
                event_operation = ?$event.operation,
                event_resource = ?$event.payload,
                "post-audit channel full — compensating local log written"
            );
            $dispatcher.postaudit_dropped_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }};
}
```

**Provider usage:**
`audited_op! { dispatcher: ..., ctx: ..., event: ..., operation: ..., error_variant: ProviderError::AuditDispatchFailed }`

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
- **Verified Token Boundary:** `build_initiator_from_error()` accepts only
  `VerifiedFernetToken` (constructible post-verification via `_score`). Partial
  context failure = authorization issue, not crypto issue.
- **Provider Error Sanitization:** `extract_provider_name` uses type-only
  dispatch (`is::<T>()`). No error string content used.

---

## Observability

`dropped_count` / `postaudit_dropped_count` exported as Prometheus gauges:

```yaml
groups:
  - name: keystone_audit
    rules:
      - alert: KeystoneAuditDropsVolumetric
        expr: |
          rate(keystone_audit_dropped_total[5m]) > 100 and
          rate(keystone_audit_dropped_total[5m]) /
          rate(keystone_audit_events_total[5m]) > 0.05
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
