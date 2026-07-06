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

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use tower_http::request_id::RequestId;
use uuid::Uuid;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_audit::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Target};
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
        KeystoneApiError::TooManyRequests => "TooManyRequests".to_string(),
        KeystoneApiError::UnprocessableEntity(_) => "UnprocessableEntity".to_string(),
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
    build_initiator_from_verified_token, build_initiator_from_vsc, build_initiator_unknown,
};

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
    outcome_reason: Option<String>,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.0".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "authenticate".to_string(),
        outcome.to_string(),
        outcome_reason,
        initiator,
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
}

/// Emit a `control` CADF event for an API Key lifecycle action performed by
/// an administrator (revoke: ADR 0021 §5.C; janitor disablement/purge: §6.F
/// use `action` `"maintenance"` instead via the same helper).
///
/// Unlike [`emit_perimeter_authenticate_event`], this is for low-volume
/// administrative actions, not the high-volume authentication hot path.
pub fn emit_api_key_control_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    action: &str,
    initiator: Initiator,
    client_id: &str,
    outcome: &str,
    outcome_reason: Option<String>,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.0".to_string(),
        "default".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        action.to_string(),
        outcome.to_string(),
        outcome_reason,
        initiator,
        Target {
            id: client_id.to_string(),
            type_uri: "data/security/keystone/api_key".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
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
}
