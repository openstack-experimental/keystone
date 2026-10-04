// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! Perimeter audit helpers (ADR 0023 Phase 2).
//!
//! Provides the `CorrelationId` Axum extractor, error sanitization, initiator
//! construction, and perimeter event emission for authentication endpoints.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use tower_http::request_id::RequestId;
use uuid::Uuid;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_audit::{
    AuditDispatcher, CadfEventPayload, Initiator, Observer, OutcomeReason, Target,
};
use openstack_keystone_core_types::assignment::AssignmentProviderError;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::catalog::CatalogProviderError;
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::RoleProviderError;

use crate::keystone::ServiceState;

/// Server-generated correlation ID, always a fresh `req-{uuid}`.
///
/// Extracted from the `x-openstack-request-id` request extension inserted by
/// `SetRequestIdLayer`. Because the binary strips any client-supplied header
/// before `SetRequestIdLayer` runs, this value is always server-generated.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

impl<S> FromRequestParts<S> for CorrelationId
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let id = parts
            .extensions
            .get::<RequestId>()
            .and_then(|r| r.header_value().to_str().ok())
            .unwrap_or("req-unknown")
            .to_string();
        Ok(CorrelationId(id))
    }
}

/// Map a `KeystoneApiError` to a safe, PII-free audit outcome reason string.
///
/// Exhaustive match: every variant is explicitly handled. Adding a new variant
/// to `KeystoneApiError` will break compilation here, forcing audit review.
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
        KeystoneApiError::InvalidHeader => "InvalidHeader".to_string(),
        KeystoneApiError::InternalError(_) => "InternalServerError".to_string(),
        KeystoneApiError::AuthMethodNotSupported => "AuthMethodNotSupported".to_string(),
        KeystoneApiError::AuthenticationRescopeForbidden => {
            "AuthenticationRescopeForbidden".to_string()
        }
        KeystoneApiError::SelectedAuthenticationForbidden => {
            "SelectedAuthenticationForbidden".to_string()
        }
        KeystoneApiError::SubjectTokenMissing => "SubjectTokenMissing".to_string(),
        KeystoneApiError::DomainIdOrName => "BadRequest".to_string(),
        KeystoneApiError::ProjectIdOrName => "BadRequest".to_string(),
        KeystoneApiError::ProjectDomain => "BadRequest".to_string(),
        KeystoneApiError::Base64Decode(_) => "BadRequest".to_string(),
        KeystoneApiError::Serde { .. } => "BadRequest".to_string(),
        KeystoneApiError::Other(_) => "InternalServerError".to_string(),
        KeystoneApiError::UnprocessableEntity(_) => "UnprocessableEntity".to_string(),
        KeystoneApiError::NotImplemented(_) => "NotImplemented".to_string(),
        KeystoneApiError::TooManyRequests { .. } => "TooManyRequests".to_string(),
        KeystoneApiError::ServiceUnavailable(_) => "ServiceUnavailable".to_string(),
    }
}

/// Map an `AuthenticationError` to a stable, PII-free string literal.
pub fn sanitize_authentication_error(e: &AuthenticationError) -> &'static str {
    match e {
        AuthenticationError::DomainDisabled(_) => "DomainDisabled",
        AuthenticationError::ProjectDisabled(_) => "ProjectDisabled",
        AuthenticationError::TrustorUserDisabled(_) => "TrustorUserDisabled",
        AuthenticationError::UserDisabled(_) => "UserDisabled",
        AuthenticationError::UserLocked(_) => "UserLocked",
        AuthenticationError::UserPasswordExpired(_) => "UserPasswordExpired",
        AuthenticationError::Provider { source, .. } => {
            extract_provider_name(source.as_ref()).unwrap_or("ProviderError")
        }
        AuthenticationError::Validation(_) => "ValidationError",
        AuthenticationError::StructBuilder { .. } => "StructBuilderError",
        AuthenticationError::AuthTokenExpired => "TokenExpired",
        AuthenticationError::AuthApplicationCredentialExpired => "AuthCredentialExpired",
        AuthenticationError::Unauthorized => "Unauthorized",
        AuthenticationError::Forbidden => "Forbidden",
        AuthenticationError::UserNameOrPasswordWrong => "UserNameOrPasswordWrong",
        AuthenticationError::ActorHasNoRolesOnTarget => "ActorHasNoRolesOnTarget",
        AuthenticationError::AuthnPrincipalMismatch => "PrincipalMismatch",
        AuthenticationError::AuthzPrincipalMismatch => "PrincipalMismatch",
        AuthenticationError::SecurityContextNotResolved => "SecurityContextNotResolved",
        AuthenticationError::ScopeNotAllowed => "ScopeNotAllowed",
        AuthenticationError::TokenNotInContext => "TokenNotInContext",
        AuthenticationError::TokenRenewalForbidden => "TokenRenewalForbidden",
        AuthenticationError::TrustorPrincipalUseNotSupported => "TrustorPrincipalUseNotSupported",
        AuthenticationError::TrustorDomainDisabled => "TrustorDomainDisabled",
        AuthenticationError::UserDomainDisabled => "UserDomainDisabled",
        AuthenticationError::RoleConversionFailed => "RoleConversionFailed",
        AuthenticationError::NoAuthorizationsFound => "NoAuthorizationsFound",
        AuthenticationError::MultipleScopesForbidden => "MultipleScopesForbidden",
        AuthenticationError::SystemScopeForbiddenForApiKey => "SystemScopeForbiddenForApiKey",
        AuthenticationError::NonDomainScopeForbiddenForApiKey => "NonDomainScopeForbiddenForApiKey",
        AuthenticationError::Ec2AccessKeyNotFound => "Ec2AccessKeyNotFound",
        AuthenticationError::Ec2SignatureMissing => "Ec2SignatureMissing",
        AuthenticationError::Ec2SignatureInvalid => "Ec2SignatureInvalid",
        AuthenticationError::Ec2UnknownSignatureVersion => "Ec2UnknownSignatureVersion",
        AuthenticationError::Ec2TimestampMissing => "Ec2TimestampMissing",
        AuthenticationError::Ec2TimestampInvalid(_) => "Ec2TimestampInvalid",
        AuthenticationError::Ec2TimestampExpired => "Ec2TimestampExpired",
        AuthenticationError::Ec2CredentialScopeDateMismatch => "Ec2CredentialScopeDateMismatch",
        AuthenticationError::TotpPasscodeInvalid => "TotpPasscodeInvalid",
        AuthenticationError::PluginVersionMismatch(_) => "PluginVersionMismatch",
    }
}

/// Type-only dispatch — no provider error string content is used.
///
/// Guarantees PII in third-party provider errors (emails, tokens) never
/// reaches audit records.
pub fn extract_provider_name(
    source: &(dyn std::error::Error + Send + Sync + 'static),
) -> Option<&'static str> {
    if source.is::<IdentityProviderError>() {
        Some("Identity")
    } else if source.is::<CatalogProviderError>() {
        Some("Catalog")
    } else if source.is::<RoleProviderError>() {
        Some("Role")
    } else if source.is::<AssignmentProviderError>() {
        Some("Assignment")
    } else if source.is::<ResourceProviderError>() {
        Some("Resource")
    } else {
        None
    }
}

// Initiator-builder functions are provided by
// `openstack_keystone_core::cadf_hook` and imported above. Re-export them under
// the original names so existing callers in this crate don't need to change
// their import paths.
pub use openstack_keystone_core::cadf_hook::{
    build_initiator_from_principal, build_initiator_from_vsc, build_initiator_unknown,
    with_request_address,
};

/// The client IP for the audit trail, resolved through the operator's
/// configured trusted-proxy/forwarding-header settings.
///
/// This is a distinct trust boundary from rate limiting and auth-plugin
/// dispatch, which each apply their own resolution over the same raw
/// `peer_addr` (see `crate::net`): `peer_addr` itself is the raw,
/// pre-resolution TCP peer and must not be recorded directly, or every
/// audited login behind a reverse proxy would record the proxy's address
/// instead of the client's. Every perimeter handler resolves it once through
/// this function and stamps it on the success and the failure event alike.
pub async fn resolve_audit_ip(
    state: &ServiceState,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
) -> Option<IpAddr> {
    let config = state.config_manager.config.read().await;
    openstack_keystone_core::net::resolve_client_ip_from_headers(
        headers,
        peer_addr.map(|addr| addr.ip()),
        &config.oslo_middleware.trusted_proxies,
        config.oslo_middleware.trusted_header,
    )
}

/// Establish the request-scoped audit context (client address and
/// correlation ID, see [`openstack_keystone_core::audit_context`]) around the
/// rest of the request.
///
/// Runs after `SetRequestIdLayer`, so the correlation ID is the
/// server-generated one. The client address is resolved once, here, through
/// the operator's trusted-proxy settings, and only for requests that arrived
/// on the public interface; the emitters in this module stamp it on every
/// perimeter record that does not already carry an address, so no handler has
/// to remember it.
pub async fn with_audit_request_context(
    axum::extract::State(state): axum::extract::State<ServiceState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let peer_addr = openstack_keystone_core::net::public_ingress_peer_addr(request.extensions());
    let client_ip = resolve_audit_ip(&state, request.headers(), peer_addr).await;
    let correlation_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .map(str::to_string);
    let audited = is_authentication_surface(request.method(), request.uri().path());
    let ctx = openstack_keystone_core::audit_context::AuditRequestContext::new(
        client_ip,
        correlation_id.clone(),
    );
    let probe = ctx.clone();
    let response = ctx.scope(next.run(request)).await;
    if audited {
        // Completion record (ADR 0023 Phase 2): authentication surfaces whose
        // handler did not emit its own perimeter record (token validation and
        // revocation, WebAuthn, Kubernetes, API-key, vendordata, and any early
        // rejection such as a rate limit) still leave exactly one record.
        let completion = probe.completion();
        if !completion.perimeter_emitted {
            let (outcome, reason) = status_outcome(response.status());
            let initiator = completion.initiator.unwrap_or_else(build_initiator_unknown);
            // Outside the request scope here, so stamp the address explicitly.
            let initiator = if initiator.address().is_some() {
                initiator
            } else {
                initiator.with_address(client_ip.map(|ip| ip.to_string()))
            };
            emit_perimeter_authenticate_event(
                &state.audit_dispatcher,
                correlation_id.as_deref().unwrap_or("unknown"),
                initiator,
                outcome,
                reason,
            );
        }
    }
    response
}

/// Whether a request is an authentication surface that the completion
/// middleware audits.
///
/// An explicit allowlist keeps the perimeter channel for what ADR 0023 calls
/// authentication events: validated-token traffic on ordinary resource
/// endpoints (very high volume, already covered by the fail-closed provider
/// audit of its mutations) is deliberately not recorded here.
#[must_use]
pub fn is_authentication_surface(method: &axum::http::Method, path: &str) -> bool {
    const PREFIXES: [&str; 7] = [
        "/v3/auth/tokens",
        "/v4/auth/tokens",
        "/v3/ec2tokens",
        "/v4/auth/passkey",
        "/v4/vendordata",
        "/SCIM/v2",
        "/v4/k8s_auth/",
    ];
    if path.starts_with("/v4/k8s_auth/") {
        // Only the authentication call, not the instance administration.
        return path.ends_with("/auth") && method == axum::http::Method::POST;
    }
    PREFIXES.iter().any(|p| path.starts_with(p))
}

/// The CADF `(outcome, reason)` of an HTTP status.
///
/// `401`/`403` and server errors are failures, any other `4xx` (rate limits,
/// malformed requests) is a `client_error` (ADR 0022), the rest a success.
#[must_use]
pub fn status_outcome(status: axum::http::StatusCode) -> (&'static str, Option<OutcomeReason>) {
    use axum::http::StatusCode;
    match status {
        s if s.as_u16() < 400 => ("success", None),
        StatusCode::UNAUTHORIZED => ("failure", Some(OutcomeReason::literal("Unauthorized"))),
        StatusCode::FORBIDDEN => ("failure", Some(OutcomeReason::literal("Forbidden"))),
        StatusCode::TOO_MANY_REQUESTS => (
            "client_error",
            Some(OutcomeReason::literal("TooManyRequests")),
        ),
        s if s.is_client_error() => ("client_error", Some(OutcomeReason::literal("ClientError"))),
        _ => ("failure", Some(OutcomeReason::literal("ServerError"))),
    }
}

/// The CADF `(outcome, outcome_reason)` of a perimeter handler result: the
/// reason is the sanitized error variant name, never error data.
pub fn perimeter_outcome<T>(
    result: &Result<T, KeystoneApiError>,
) -> (&'static str, Option<OutcomeReason>) {
    match result {
        Ok(_) => ("success", None),
        Err(e) => (
            "failure",
            Some(OutcomeReason::variant(&error_variant_name(e))),
        ),
    }
}

/// Emit a best-effort perimeter CADF event for an authentication attempt.
///
/// Maps to CADF action `"authenticate"`, targeting
/// `service/security/keystone/auth`. Uses the dispatcher's `dispatch()` (best-
/// effort) since perimeter events are high-volume and not fail-closed.
pub fn emit_perimeter_authenticate_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    outcome: &str,
    outcome_reason: Option<OutcomeReason>,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "authenticate".to_string(),
        outcome.to_string(),
        outcome_reason,
        with_request_address(initiator),
        Target {
            id: "keystone".to_string(),
            type_uri: "service/security/keystone/auth".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
    // The completion middleware must not add a second record for this request.
    openstack_keystone_core::audit_context::mark_perimeter_emitted();
}

/// Emit a best-effort CADF event for an OAuth2 browser-flow lifecycle step
/// (ADR 0026 §10 Phase 4): `/authorize` request, login attempt, consent
/// granted/denied, authorization code redeemed, refresh token rotated.
/// Uses the dispatcher's `dispatch()` (best-effort), same posture as
/// the other `dispatch()` helpers -- these are low-to-moderate volume
/// administrative/session-lifecycle events, not the critical breach path.
pub fn emit_oauth2_session_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    action: &str,
    initiator: Initiator,
    client_id: &str,
    outcome: &str,
    outcome_reason: Option<OutcomeReason>,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        action.to_string(),
        outcome.to_string(),
        outcome_reason,
        with_request_address(initiator),
        Target {
            id: client_id.to_string(),
            type_uri: "data/security/keystone/oauth2_client".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
}

/// Emit the critical `OAUTH2_REFRESH_REUSE_DETECTED` CADF event (ADR 0026
/// §9, "Token Compromise Alerts") when a `refresh_token` is presented a
/// second time outside the reuse grace window and its family has just been
/// revoked. Fail-closed dispatch via
/// [`AuditDispatcher::dispatch_critical`]: on channel death, bumps the
/// post-audit drop metric and logs an error, mirroring
/// `openstack_keystone_core::cadf_hook::CadfAuditHook`'s own `Err` handling
/// for the identical failure mode.
pub async fn emit_oauth2_refresh_reuse_critical_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    family_id: &str,
    reason: &str,
) {
    tracing::warn!(
        family_id,
        reason,
        "refresh token reuse detected, family revoked"
    );
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "OAUTH2_REFRESH_REUSE_DETECTED".to_string(),
        "failure".to_string(),
        // The family is the target; the revocation reason is a fixed
        // vocabulary.
        Some(OutcomeReason::literal("RefreshTokenReuseDetected")),
        with_request_address(initiator),
        Target {
            id: family_id.to_string(),
            type_uri: "data/security/keystone/oauth2_refresh_family".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    if dispatcher.dispatch_critical(event).await.is_err() {
        dispatcher.record_postaudit_drop();
        tracing::error!(
            family_id,
            "failed to dispatch OAUTH2_REFRESH_REUSE_DETECTED critical audit event: audit channel dead"
        );
    }
}

/// Emit the best-effort `OAUTH2_REFRESH_FAMILY_REVOKED` CADF event when a
/// `refresh_token` family is revoked because its principal is no longer
/// valid (user deleted/disabled/moved, domain disabled), so incident
/// forensics can correlate the tombstones by `family_id` and `reason`.
/// Best-effort `dispatch()`: unlike reuse detection this is not a breach
/// signal, it is the expected consequence of an administrative change.
pub fn emit_oauth2_refresh_family_revoked_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    family_id: &str,
    reason: &str,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "OAUTH2_REFRESH_FAMILY_REVOKED".to_string(),
        "success".to_string(),
        Some(OutcomeReason::variant(reason)),
        with_request_address(initiator),
        Target {
            id: family_id.to_string(),
            type_uri: "data/security/keystone/oauth2_refresh_family".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
}

/// Emit the best-effort `OAUTH2_CLIENT_REVOKED` CADF event when an OAuth2
/// client is deleted or disabled. `action` is `delete` or `disable`;
/// `revoked_families` is the number of refresh token families tombstoned as
/// a consequence.
pub fn emit_oauth2_client_revoked_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    client_id: &str,
    action: &str,
    revoked_families: usize,
) {
    tracing::info!(client_id, action, revoked_families, "oauth2 client revoked");
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "OAUTH2_CLIENT_REVOKED".to_string(),
        "success".to_string(),
        Some(OutcomeReason::counts(&[(
            "revoked_families",
            revoked_families as u64,
        )])),
        with_request_address(initiator),
        Target {
            id: client_id.to_string(),
            type_uri: "data/security/keystone/oauth2_client".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
}

/// Emit the critical `OAUTH2_EMERGENCY_KEY_ROTATION` CADF event (ADR 0026
/// §3, "Emergency Rotation and Signing Key Compromise", step 4) once a
/// pending emergency rotation is confirmed and the compromised key's JTIs
/// are revoked. Fail-closed dispatch via
/// [`AuditDispatcher::dispatch_critical`], mirroring
/// [`emit_oauth2_refresh_reuse_critical_event`] -- this is the breach-
/// response path, not routine key hygiene.
pub async fn emit_oauth2_emergency_key_rotation_critical_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    domain_id: &str,
    new_kid: &str,
    revoked_jtis: &[String],
) {
    tracing::info!(
        domain_id,
        new_kid,
        revoked_jtis = ?revoked_jtis,
        "oauth2 signing key emergency-rotated"
    );
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "OAUTH2_EMERGENCY_KEY_ROTATION".to_string(),
        "success".to_string(),
        // The domain is the target. The new key ID and the revoked JTIs are
        // not part of the signed record (no free text or ID lists in
        // `outcome_reason`); they are logged for the investigation.
        Some(OutcomeReason::counts(&[(
            "revoked_jtis",
            revoked_jtis.len() as u64,
        )])),
        with_request_address(initiator),
        Target {
            id: domain_id.to_string(),
            type_uri: "data/security/keystone/oauth2_signing_key".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    if dispatcher.dispatch_critical(event).await.is_err() {
        dispatcher.record_postaudit_drop();
        tracing::error!(
            domain_id,
            new_kid,
            "failed to dispatch OAUTH2_EMERGENCY_KEY_ROTATION critical audit event: audit channel dead"
        );
    }
}

/// Emit the critical `OAUTH2_LOCAL_EMERGENCY_KEY_RECONCILED` CADF event
/// (ADR 0028 §6) once a node-local, quorum-bypass emergency rotation
/// candidate is reconciled into Raft-replicated state. Fail-closed dispatch
/// via [`AuditDispatcher::dispatch_critical`], same posture as
/// [`emit_oauth2_emergency_key_rotation_critical_event`] -- mirrors that
/// event's "confirm" step rather than `stage_local_emergency_rotation`'s
/// staging step, since staging an ordinary emergency rotation
/// (`stage_emergency_rotation`) is likewise unaudited until confirmed.
///
/// Returns the CADF event id so the caller can persist the
/// `_local:emergency:audit:<rotation_id>` pointer record (ADR 0028
/// implementation plan, design gap 2), letting reconciliation/audit tooling
/// find this spool entry without scanning the whole spool.
pub async fn emit_oauth2_local_emergency_key_reconciled_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    domain_id: &str,
    rotation_id: &str,
    new_kid: &str,
) -> String {
    tracing::info!(
        domain_id,
        rotation_id,
        new_kid,
        "oauth2 local emergency rotation reconciled"
    );
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id.clone(),
        "1.1".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "OAUTH2_LOCAL_EMERGENCY_KEY_RECONCILED".to_string(),
        "success".to_string(),
        // The domain is the target; the rotation ID and new key ID are
        // logged, and the rotation ID is also kept in the spool pointer
        // record the caller persists from the returned event ID.
        None,
        with_request_address(initiator),
        Target {
            id: domain_id.to_string(),
            type_uri: "data/security/keystone/oauth2_signing_key".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    if dispatcher.dispatch_critical(event).await.is_err() {
        dispatcher.record_postaudit_drop();
        tracing::error!(
            domain_id,
            rotation_id,
            new_kid,
            "failed to dispatch OAUTH2_LOCAL_EMERGENCY_KEY_RECONCILED critical audit event: \
             audit channel dead"
        );
    }
    event_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variant_name_covers_all_branches() {
        // Each branch returns a non-empty string.
        let cases: &[KeystoneApiError] = &[
            KeystoneApiError::UnauthorizedNoContext,
            KeystoneApiError::NotFound {
                resource: "user".into(),
                identifier: "id".into(),
            },
            KeystoneApiError::Conflict("x".into()),
            KeystoneApiError::BadRequest("x".into()),
            KeystoneApiError::InvalidToken,
            KeystoneApiError::InvalidHeader,
            KeystoneApiError::InternalError("x".into()),
            KeystoneApiError::AuthMethodNotSupported,
            KeystoneApiError::AuthenticationRescopeForbidden,
            KeystoneApiError::SelectedAuthenticationForbidden,
            KeystoneApiError::SubjectTokenMissing,
            KeystoneApiError::DomainIdOrName,
            KeystoneApiError::ProjectIdOrName,
            KeystoneApiError::ProjectDomain,
            KeystoneApiError::ServiceUnavailable("x".into()),
        ];
        for e in cases {
            let name = error_variant_name(e);
            assert!(!name.is_empty(), "empty name for {:?}", e);
        }
    }

    #[test]
    fn sanitize_auth_error_no_pii() {
        // Returns stable string literals.
        assert_eq!(
            sanitize_authentication_error(&AuthenticationError::UserDisabled("alice".into())),
            "UserDisabled"
        );
        assert_eq!(
            sanitize_authentication_error(&AuthenticationError::TokenRenewalForbidden),
            "TokenRenewalForbidden"
        );
    }

    #[test]
    fn extract_provider_name_identity() {
        let e: Box<dyn std::error::Error + Send + Sync> =
            Box::new(IdentityProviderError::UserNotFound("x".into()));
        assert_eq!(extract_provider_name(e.as_ref()), Some("Identity"));
    }

    #[test]
    fn extract_provider_name_unknown_returns_none() {
        #[derive(Debug, thiserror::Error)]
        #[error("unknown")]
        struct Unknown;
        let e: Box<dyn std::error::Error + Send + Sync> = Box::new(Unknown);
        assert_eq!(extract_provider_name(e.as_ref()), None);
    }

    #[test]
    fn build_initiator_unknown_has_unknown_id() {
        let i = build_initiator_unknown();
        assert_eq!(i.id(), "unknown");
        assert!(i.project_id().is_none());
        assert!(i.domain_id().is_none());
    }

    #[test]
    fn emit_oauth2_session_event_does_not_panic() {
        let dispatcher = AuditDispatcher::noop();
        emit_oauth2_session_event(
            &dispatcher,
            "req-1",
            "authenticate",
            build_initiator_unknown(),
            "client-1",
            "success",
            None,
        );
    }

    #[tokio::test]
    async fn emit_oauth2_refresh_reuse_critical_event_records_drop_on_dead_channel() {
        // `noop()` drops its channel receivers immediately, so
        // `dispatch_critical` observes a dead channel here -- exercising
        // the fail-closed drop-accounting path.
        let dispatcher = AuditDispatcher::noop();
        let before = dispatcher.postaudit_dropped_count();
        emit_oauth2_refresh_reuse_critical_event(
            &dispatcher,
            "req-1",
            build_initiator_unknown(),
            "family-1",
            "reuse_detected",
        )
        .await;
        assert_eq!(dispatcher.postaudit_dropped_count(), before + 1);
    }

    #[test]
    fn emit_oauth2_refresh_family_revoked_event_does_not_panic() {
        let dispatcher = AuditDispatcher::noop();
        emit_oauth2_refresh_family_revoked_event(
            &dispatcher,
            "req-1",
            build_initiator_unknown(),
            "family-1",
            "user_disabled",
        );
    }

    #[tokio::test]
    async fn emit_oauth2_emergency_key_rotation_critical_event_records_drop_on_dead_channel() {
        let dispatcher = AuditDispatcher::noop();
        let before = dispatcher.postaudit_dropped_count();
        emit_oauth2_emergency_key_rotation_critical_event(
            &dispatcher,
            "req-1",
            build_initiator_unknown(),
            "domain-1",
            "kid-new",
            &["jti-1".to_string()],
        )
        .await;
        assert_eq!(dispatcher.postaudit_dropped_count(), before + 1);
    }

    #[tokio::test]
    async fn emit_oauth2_local_emergency_key_reconciled_event_records_drop_on_dead_channel() {
        let dispatcher = AuditDispatcher::noop();
        let before = dispatcher.postaudit_dropped_count();
        let event_id = emit_oauth2_local_emergency_key_reconciled_event(
            &dispatcher,
            "req-1",
            build_initiator_unknown(),
            "domain-1",
            "rot-1",
            "kid-new",
        )
        .await;
        assert!(!event_id.is_empty());
        assert_eq!(dispatcher.postaudit_dropped_count(), before + 1);
    }

    #[tokio::test]
    async fn request_context_middleware_exposes_client_ip_and_correlation_id() {
        use axum::extract::ConnectInfo;
        use axum::routing::get;
        use tower::ServiceExt;

        let state = crate::api::tests::get_mocked_state(
            openstack_keystone_core::provider::Provider::mocked_builder(),
            true,
            None,
        )
        .await;
        let app = axum::Router::new()
            .route(
                "/",
                get(|| async {
                    format!(
                        "{:?}|{:?}",
                        openstack_keystone_core::audit_context::client_ip(),
                        openstack_keystone_core::audit_context::correlation_id()
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                with_audit_request_context,
            ));
        let mut request = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "203.0.113.5:4000".parse::<SocketAddr>().unwrap(),
        ));
        request
            .extensions_mut()
            .insert(RequestId::new(axum::http::HeaderValue::from_static(
                "req-abc",
            )));

        let response = app.oneshot(request).await.unwrap();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "Some(203.0.113.5)|Some(\"req-abc\")"
        );
    }

    #[tokio::test]
    async fn with_request_address_prefers_an_explicit_address() {
        let ctx = openstack_keystone_core::audit_context::AuditRequestContext::new(
            Some("203.0.113.5".parse().unwrap()),
            None,
        );
        ctx.scope(async {
            let from_scope = with_request_address(build_initiator_unknown());
            assert_eq!(from_scope.address(), Some("203.0.113.5"));
            let explicit = with_request_address(
                build_initiator_unknown().with_address(Some("198.51.100.1".into())),
            );
            assert_eq!(explicit.address(), Some("198.51.100.1"));
        })
        .await;
        // Outside any scope the initiator is left as given.
        assert_eq!(
            with_request_address(build_initiator_unknown()).address(),
            None
        );
    }

    #[test]
    fn perimeter_outcome_reason_is_the_sanitized_variant_name() {
        let ok: Result<(), KeystoneApiError> = Ok(());
        assert_eq!(perimeter_outcome(&ok), ("success", None));
        let err: Result<(), KeystoneApiError> = Err(KeystoneApiError::Conflict(
            "user 4f1c already exists".into(),
        ));
        let (outcome, reason) = perimeter_outcome(&err);
        assert_eq!(outcome, "failure");
        assert_eq!(reason.expect("reason").as_str(), "Conflict");
    }

    #[test]
    fn authentication_surfaces_are_an_explicit_allowlist() {
        use axum::http::Method;
        for (m, p) in [
            (Method::GET, "/v3/auth/tokens"),
            (Method::DELETE, "/v3/auth/tokens"),
            (Method::POST, "/v3/ec2tokens"),
            (Method::POST, "/v4/auth/passkey/start"),
            (Method::POST, "/v4/vendordata"),
            (Method::GET, "/SCIM/v2/realms/x/Users"),
            (Method::POST, "/v4/k8s_auth/abc/auth"),
        ] {
            assert!(is_authentication_surface(&m, p), "{m} {p}");
        }
        for (m, p) in [
            (Method::GET, "/v3/projects"),
            (Method::GET, "/v3/users"),
            (Method::POST, "/v4/k8s_auth/instances"),
            (Method::GET, "/v4/k8s_auth/abc/auth"),
        ] {
            assert!(!is_authentication_surface(&m, p), "{m} {p}");
        }
    }

    #[test]
    fn status_maps_to_outcome() {
        use axum::http::StatusCode;
        assert_eq!(status_outcome(StatusCode::OK), ("success", None));
        assert_eq!(status_outcome(StatusCode::NO_CONTENT).0, "success");
        for (code, outcome, reason) in [
            (StatusCode::UNAUTHORIZED, "failure", "Unauthorized"),
            (StatusCode::FORBIDDEN, "failure", "Forbidden"),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "client_error",
                "TooManyRequests",
            ),
            (StatusCode::BAD_REQUEST, "client_error", "ClientError"),
            (StatusCode::INTERNAL_SERVER_ERROR, "failure", "ServerError"),
        ] {
            let (o, r) = status_outcome(code);
            assert_eq!(o, outcome);
            assert_eq!(r.expect("reason").as_str(), reason);
        }
    }

    /// Run one request through the context/completion middleware over a
    /// router with the given handler and return the perimeter receiver.
    async fn run_completion(
        method: &str,
        path: &str,
        handler: axum::routing::MethodRouter,
    ) -> openstack_keystone_audit::AuditChannelReceivers {
        use axum::extract::ConnectInfo;
        use tower::ServiceExt;

        let (state, receivers) = openstack_keystone_core::api::tests::get_mocked_state_with_audit(
            openstack_keystone_core::provider::Provider::mocked_builder(),
            true,
            openstack_keystone_config::Config::default(),
        )
        .await;
        let app = axum::Router::new()
            .route("/v3/auth/tokens", handler.clone())
            .route("/v3/projects", handler)
            .layer(axum::middleware::from_fn_with_state(
                state,
                with_audit_request_context,
            ));
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "203.0.113.5:4000".parse::<SocketAddr>().unwrap(),
        ));
        let _ = app.oneshot(request).await.unwrap();
        receivers
    }

    #[tokio::test]
    async fn completion_records_a_rejected_authentication_surface_request() {
        use axum::routing::get;
        let mut receivers = run_completion(
            "GET",
            "/v3/auth/tokens",
            get(|| async { axum::http::StatusCode::UNAUTHORIZED }),
        )
        .await;
        let event = receivers.perimeter.try_recv().expect("completion event");
        assert_eq!(event.payload().outcome(), "failure");
        assert_eq!(event.payload().initiator().id(), "unknown");
        assert_eq!(event.payload().initiator().address(), Some("203.0.113.5"));
        assert!(receivers.perimeter.try_recv().is_err());
    }

    #[tokio::test]
    async fn completion_records_the_authenticated_initiator_on_success() {
        use axum::routing::get;
        let mut receivers = run_completion(
            "GET",
            "/v3/auth/tokens",
            get(|| async {
                openstack_keystone_core::audit_context::record_initiator(Initiator::new(
                    "0123456789abcdef0123456789abcdef".to_string(),
                    None,
                    None,
                    None,
                ));
                axum::http::StatusCode::OK
            }),
        )
        .await;
        let event = receivers.perimeter.try_recv().expect("completion event");
        assert_eq!(event.payload().outcome(), "success");
        assert_eq!(
            event.payload().initiator().id(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test]
    async fn completion_does_not_duplicate_a_handler_record() {
        use axum::routing::get;
        let mut receivers = run_completion(
            "GET",
            "/v3/auth/tokens",
            get(|| async {
                openstack_keystone_core::audit_context::mark_perimeter_emitted();
                axum::http::StatusCode::OK
            }),
        )
        .await;
        assert!(receivers.perimeter.try_recv().is_err());
    }

    #[tokio::test]
    async fn completion_ignores_ordinary_endpoints() {
        use axum::routing::get;
        let mut receivers = run_completion(
            "GET",
            "/v3/projects",
            get(|| async { axum::http::StatusCode::OK }),
        )
        .await;
        assert!(receivers.perimeter.try_recv().is_err());
    }
}
