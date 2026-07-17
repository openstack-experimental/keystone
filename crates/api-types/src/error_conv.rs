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

use {
    axum::{
        Json,
        extract::rejection::JsonRejection,
        http::{HeaderValue, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

use openstack_keystone_core_types::api_key::ApiKeyProviderError;
use openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core_types::assignment::AssignmentProviderError;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::auth_plugin_identity::AuthPluginIdentityProviderError;
use openstack_keystone_core_types::catalog::CatalogProviderError;
use openstack_keystone_core_types::credential::CredentialProviderError;
use openstack_keystone_core_types::error::BuilderError;
use openstack_keystone_core_types::error::KeystoneError;
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::mapping::MappingProviderError;
use openstack_keystone_core_types::oauth2_client::Oauth2ClientProviderError;
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::revoke::RevokeProviderError;
use openstack_keystone_core_types::role::RoleProviderError;
use openstack_keystone_core_types::scim::{ScimRealmProviderError, ScimResourceProviderError};
use openstack_keystone_core_types::token::TokenProviderError;

use crate::error::KeystoneApiError;

impl IntoResponse for KeystoneApiError {
    fn into_response(self) -> Response {
        // Rate-limit rejections need a `Retry-After` header in addition to the
        // JSON body, so they are handled before the generic status-code path
        // (ADR-0022 Invariants 3 and 4).
        if let KeystoneApiError::TooManyRequests { retry_after } = &self {
            let body = Json(json!({
                "error": {
                    "code": StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    "message": self.to_string(),
                }
            }));
            let retry_value = HeaderValue::from(*retry_after);
            let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry_value);
            return response;
        }

        let status_code = match self {
            KeystoneApiError::Conflict(_) => StatusCode::CONFLICT,
            KeystoneApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            KeystoneApiError::BadRequest(..) => StatusCode::BAD_REQUEST,
            KeystoneApiError::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            KeystoneApiError::UnauthorizedNoContext => StatusCode::UNAUTHORIZED,
            KeystoneApiError::Forbidden { .. } => StatusCode::FORBIDDEN,
            //KeystoneApiError::Policy { .. } => StatusCode::FORBIDDEN,
            KeystoneApiError::SelectedAuthenticationForbidden
            | KeystoneApiError::AuthenticationRescopeForbidden => StatusCode::BAD_REQUEST,
            KeystoneApiError::InternalError(_) | KeystoneApiError::Other(..) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            KeystoneApiError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::BAD_REQUEST,
        };

        (
            status_code,
            Json(json!({"error": {"code": status_code.as_u16(), "message": self.to_string()}})),
        )
            .into_response()
    }
}

impl From<BuilderError> for KeystoneApiError {
    fn from(value: BuilderError) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<JsonRejection> for KeystoneApiError {
    fn from(value: JsonRejection) -> Self {
        Self::BadRequest(value.to_string())
    }
}

impl From<AuthenticationError> for KeystoneApiError {
    fn from(value: AuthenticationError) -> Self {
        match value {
            AuthenticationError::ActorHasNoRolesOnTarget => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::AuthApplicationCredentialExpired => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::AuthnPrincipalMismatch => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::AuthTokenExpired => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::AuthzPrincipalMismatch => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::DomainDisabled(..) => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::Forbidden => KeystoneApiError::forbidden(value),
            AuthenticationError::ProjectDisabled(..) => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::SecurityContextNotResolved => KeystoneApiError::internal(value),
            AuthenticationError::ScopeNotAllowed => KeystoneApiError::forbidden(value),
            AuthenticationError::StructBuilder { source } => {
                KeystoneApiError::InternalError(source.to_string())
            }
            AuthenticationError::UserDisabled(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!("The account is disabled for the user: {uid}")),
                )
            }
            AuthenticationError::UserLocked(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!("The account is locked for the user: {uid}")),
                )
            }
            AuthenticationError::UserPasswordExpired(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!(
                        "The password is expired and need to be changed for user: {uid}"
                    )),
                )
            }
            AuthenticationError::UserNameOrPasswordWrong => KeystoneApiError::unauthorized(
                value,
                Some("Invalid username or password".to_string()),
            ),
            AuthenticationError::TokenRenewalForbidden => {
                KeystoneApiError::SelectedAuthenticationForbidden
            }
            AuthenticationError::Unauthorized => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::RoleConversionFailed => {
                KeystoneApiError::InternalError(value.to_string())
            }
            AuthenticationError::NoAuthorizationsFound => KeystoneApiError::forbidden(value),
            AuthenticationError::Validation(ref ve) => {
                KeystoneApiError::BadRequest(format!("validation error: {ve}"))
            }
            other => KeystoneApiError::unauthorized(other, None::<String>),
        }
    }
}

impl From<AssignmentProviderError> for KeystoneApiError {
    fn from(source: AssignmentProviderError) -> Self {
        match source {
            AssignmentProviderError::AssignmentNotFound(x) => Self::NotFound {
                resource: "assignment".into(),
                identifier: x,
            },
            AssignmentProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            ref err @ AssignmentProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ AssignmentProviderError::Validation { .. } => {
                Self::BadRequest(err.to_string())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<RoleProviderError> for KeystoneApiError {
    fn from(source: RoleProviderError) -> Self {
        match source {
            RoleProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            ref err @ RoleProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ RoleProviderError::Validation { .. } => Self::BadRequest(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<CredentialProviderError> for KeystoneApiError {
    fn from(source: CredentialProviderError) -> Self {
        match source {
            CredentialProviderError::CredentialNotFound(x) => Self::NotFound {
                resource: "credential".into(),
                identifier: x,
            },
            ref err @ CredentialProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ CredentialProviderError::Validation { .. } => {
                Self::BadRequest(err.to_string())
            }
            ref err @ (CredentialProviderError::MissingUserId
            | CredentialProviderError::MissingProjectId
            | CredentialProviderError::InvalidBlob(..)
            | CredentialProviderError::ImmutableField(..)) => Self::BadRequest(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<CatalogProviderError> for KeystoneApiError {
    fn from(value: CatalogProviderError) -> Self {
        match value {
            ref err @ CatalogProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            CatalogProviderError::EndpointNotFound(x) => Self::NotFound {
                resource: "endpoint".into(),
                identifier: x,
            },
            CatalogProviderError::ServiceNotFound(x) => Self::NotFound {
                resource: "service".into(),
                identifier: x,
            },
            CatalogProviderError::RegionNotFound(x) => Self::NotFound {
                resource: "region".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<ApplicationCredentialProviderError> for KeystoneApiError {
    fn from(source: ApplicationCredentialProviderError) -> Self {
        match source {
            ApplicationCredentialProviderError::ApplicationCredentialNotFound(x) => {
                Self::NotFound {
                    resource: "application_credential".into(),
                    identifier: x,
                }
            }
            ref err @ ApplicationCredentialProviderError::Conflict(..) => {
                Self::Conflict(err.to_string())
            }
            err @ ApplicationCredentialProviderError::ApplicationCredentialExpired => {
                Self::unauthorized(err, None::<String>)
            }
            err @ ApplicationCredentialProviderError::AccessRulesUnenforced => {
                Self::BadRequest(err.to_string())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<IdentityProviderError> for KeystoneApiError {
    fn from(value: IdentityProviderError) -> Self {
        match value {
            IdentityProviderError::Authentication { source } => source.into(),
            IdentityProviderError::UserNotFound(x) => Self::NotFound {
                resource: "user".into(),
                identifier: x,
            },
            IdentityProviderError::GroupNotFound(x) => Self::NotFound {
                resource: "group".into(),
                identifier: x,
            },
            ref err @ IdentityProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ IdentityProviderError::SecurityCompliance(..) => {
                Self::BadRequest(err.to_string())
            }
            // Unified 429 shape shared with the global-IP and API-key
            // limiters (ADR-0022, Invariant 3).
            IdentityProviderError::TooManyRequests { retry_after_secs } => Self::TooManyRequests {
                retry_after: retry_after_secs,
            },
            // A write attempt against a read-only backend (e.g. the LDAP
            // identity driver, ADR-0027) is a permissions statement, not a
            // server fault.
            err @ IdentityProviderError::Readonly(..) => Self::forbidden(err),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<ResourceProviderError> for KeystoneApiError {
    fn from(value: ResourceProviderError) -> Self {
        match value {
            ref err @ ResourceProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ResourceProviderError::DomainNotFound(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            ResourceProviderError::ProjectNotFound(x) => Self::NotFound {
                resource: "project".into(),
                identifier: x,
            },
            ResourceProviderError::InvalidProjectDomain(x) => Self::BadRequest(x),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<RevokeProviderError> for KeystoneApiError {
    fn from(value: RevokeProviderError) -> Self {
        match value {
            ref err @ RevokeProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<ApiKeyProviderError> for KeystoneApiError {
    fn from(value: ApiKeyProviderError) -> Self {
        match value {
            ApiKeyProviderError::NotFound(x) => Self::NotFound {
                resource: "api_key".into(),
                identifier: x,
            },
            ApiKeyProviderError::Conflict(x) => Self::Conflict(x),
            ApiKeyProviderError::Authentication { source } => source.into(),
            // Crypto/storage-layer failures on the authentication hot path must
            // never leak detail to the client (ADR 0021 §6.D OPSEC leakage);
            // callers on that path should prefer mapping these to a generic
            // `AuthenticationError::Unauthorized` before this conversion runs.
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<Oauth2ClientProviderError> for KeystoneApiError {
    fn from(value: Oauth2ClientProviderError) -> Self {
        match value {
            Oauth2ClientProviderError::NotFound(x) => Self::NotFound {
                resource: "oauth2_client".into(),
                identifier: x,
            },
            Oauth2ClientProviderError::Conflict(x) => Self::Conflict(x),
            Oauth2ClientProviderError::Validation(x) => Self::UnprocessableEntity(x),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<Oauth2KeyProviderError> for KeystoneApiError {
    fn from(value: Oauth2KeyProviderError) -> Self {
        match value {
            Oauth2KeyProviderError::NotFound(x) => Self::NotFound {
                resource: "oauth2_signing_key".into(),
                identifier: x,
            },
            Oauth2KeyProviderError::NoPendingRotation(x) => Self::NotFound {
                resource: "oauth2_pending_rotation".into(),
                identifier: x,
            },
            Oauth2KeyProviderError::RotationExpired(x) => {
                Self::Conflict(format!("pending emergency rotation {x} has expired"))
            }
            Oauth2KeyProviderError::DualControlViolation => Self::Forbidden {
                source: Box::new(value),
            },
            Oauth2KeyProviderError::EmergencyRotationAlreadyPending(x) => Self::Conflict(format!(
                "an emergency rotation (id {x}) is already pending for this domain"
            )),
            Oauth2KeyProviderError::LocalEmergencyBypassNotAllowed => Self::Forbidden {
                source: Box::new(value),
            },
            Oauth2KeyProviderError::LocalEmergencyAlreadyStaged(x) => Self::Conflict(format!(
                "a local emergency rotation candidate (id {x}) already exists for this domain on this node"
            )),
            Oauth2KeyProviderError::LocalEmergencyCandidateNotFound(x) => Self::NotFound {
                resource: "oauth2_local_emergency_candidate".into(),
                identifier: x,
            },
            Oauth2KeyProviderError::LocalEmergencyCandidateRevoked(x) => Self::Conflict(format!(
                "local emergency rotation candidate {x} has been revoked and cannot be reconciled"
            )),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<AuthPluginIdentityProviderError> for KeystoneApiError {
    fn from(value: AuthPluginIdentityProviderError) -> Self {
        // Every variant is an infra/storage failure with no client-actionable
        // distinction (ADR 0025 §6.B/§6.C); surface as a generic 500 without
        // leaking backend detail on the linking path.
        Self::InternalError(value.to_string())
    }
}

impl From<MappingProviderError> for KeystoneApiError {
    fn from(value: MappingProviderError) -> Self {
        match value {
            MappingProviderError::NotFound(x) => Self::NotFound {
                resource: "mapping".into(),
                identifier: x,
            },
            MappingProviderError::Conflict(x) => Self::Conflict(x),
            MappingProviderError::Validation { source } => Self::BadRequest(source.to_string()),
            MappingProviderError::InvalidRegexSyntax(x) => Self::BadRequest(x),
            MappingProviderError::RegexTooComplex(x) => Self::BadRequest(x),
            MappingProviderError::RegexSafetyViolation(x, msg) => {
                Self::BadRequest(format!("regex safety violation: {x}: {msg}"))
            }
            MappingProviderError::SystemTokenShadowing(x) => Self::BadRequest(x),
            MappingProviderError::InvalidRuleName(x) => Self::BadRequest(x),
            MappingProviderError::DuplicateRuleName(x) => Self::BadRequest(x),
            MappingProviderError::DomainClaimRequired => Self::BadRequest(
                "ClaimsOnly mode requires user_domain_id template with a claims interpolation reference".to_string(),
            ),
            MappingProviderError::DomainOverrideInFixedMode => Self::BadRequest(
                "Fixed mode does not allow claims templates in user_domain_id".to_string(),
            ),
            MappingProviderError::InterpolatedValueTooLong => Self::BadRequest(
                "interpolated value exceeds 256 character limit".to_string(),
            ),
            MappingProviderError::RulesetImmutable(x) => Self::BadRequest(x),
            MappingProviderError::ApiClientSystemScopeForbidden(x) => Self::BadRequest(format!(
                "rule '{x}' grants system scope, which is forbidden for API Key (ApiClient) mapping rulesets"
            )),
            MappingProviderError::ApiClientNonDomainScopeForbidden(x) => Self::BadRequest(format!(
                "rule '{x}' grants a non-domain scope, which is forbidden for API Key (ApiClient) mapping rulesets (only domain scope is accepted)"
            )),
            MappingProviderError::RoleNotFound(x) => Self::UnprocessableEntity(format!(
                "rule references role '{x}' which does not exist"
            )),
            MappingProviderError::RaftNotAvailable => Self::InternalError(
                "raft storage is not available in the mapping provider".to_string(),
            ),
            MappingProviderError::RaftStoreError { source } => {
                Self::InternalError(format!("raft storage error: {source}"))
            }
            MappingProviderError::Driver { source } => {
                Self::InternalError(format!("backend driver error: {source}"))
            }
            MappingProviderError::UnsupportedDriver(x) => {
                Self::InternalError(format!("unsupported driver `{x}`"))
            }
            MappingProviderError::StructBuilder(e) => {
                Self::InternalError(format!("structure builder error: {e}"))
            }
            // MappingProviderError is non-exhaustive; catch any future variants
            _ => Self::InternalError(value.to_string()),
        }
    }
}

impl From<ScimRealmProviderError> for KeystoneApiError {
    fn from(value: ScimRealmProviderError) -> Self {
        match value {
            ScimRealmProviderError::NotFound(x) => Self::NotFound {
                resource: "scim_realm".into(),
                identifier: x,
            },
            ScimRealmProviderError::Conflict(x) => Self::Conflict(x),
            ScimRealmProviderError::RaftNotAvailable => Self::InternalError(
                "raft storage is not available in the scim_realm provider".to_string(),
            ),
            ScimRealmProviderError::RaftStoreError { source } => {
                Self::InternalError(format!("raft storage error: {source}"))
            }
            ScimRealmProviderError::Driver { source } => {
                Self::InternalError(format!("backend driver error: {source}"))
            }
            ScimRealmProviderError::UnsupportedDriver(x) => {
                Self::InternalError(format!("unsupported driver `{x}`"))
            }
            ScimRealmProviderError::StructBuilder(e) => {
                Self::InternalError(format!("structure builder error: {e}"))
            }
            // ScimRealmProviderError is non-exhaustive; catch any future variants
            _ => Self::InternalError(value.to_string()),
        }
    }
}

impl From<ScimResourceProviderError> for KeystoneApiError {
    fn from(value: ScimResourceProviderError) -> Self {
        match value {
            ScimResourceProviderError::NotFound(x) => Self::NotFound {
                resource: "scim_resource".into(),
                identifier: x,
            },
            ScimResourceProviderError::Conflict(x) => Self::Conflict(x),
            ScimResourceProviderError::RaftNotAvailable => Self::InternalError(
                "raft storage is not available in the scim_resource provider".to_string(),
            ),
            ScimResourceProviderError::RaftStoreError { source } => {
                Self::InternalError(format!("raft storage error: {source}"))
            }
            ScimResourceProviderError::Driver { source } => {
                Self::InternalError(format!("backend driver error: {source}"))
            }
            ScimResourceProviderError::UnsupportedDriver(x) => {
                Self::InternalError(format!("unsupported driver `{x}`"))
            }
            ScimResourceProviderError::StructBuilder(e) => {
                Self::InternalError(format!("structure builder error: {e}"))
            }
            // ScimResourceProviderError is non-exhaustive; catch any future variants
            _ => Self::InternalError(value.to_string()),
        }
    }
}

impl From<TokenProviderError> for KeystoneApiError {
    fn from(value: TokenProviderError) -> Self {
        match value {
            TokenProviderError::Authentication(source) => source.into(),
            TokenProviderError::Conflict { message, .. } => Self::Conflict(message),
            TokenProviderError::TrustorDomainDisabled
            | TokenProviderError::TrustorUserDisabled(_) => {
                Self::unauthorized(value, None::<String>)
            }
            TokenProviderError::DomainDisabled(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            TokenProviderError::TokenRestrictionNotFound(x) => Self::NotFound {
                resource: "token restriction".into(),
                identifier: x,
            },
            TokenProviderError::ProjectDisabled(x) => Self::NotFound {
                resource: "project".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<serde_urlencoded::ser::Error> for KeystoneApiError {
    fn from(value: serde_urlencoded::ser::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<url::ParseError> for KeystoneApiError {
    fn from(value: url::ParseError) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<uuid::Error> for KeystoneApiError {
    fn from(value: uuid::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<validator::ValidationErrors> for KeystoneApiError {
    fn from(value: validator::ValidationErrors) -> Self {
        Self::BadRequest(value.to_string())
    }
}

impl From<KeystoneError> for KeystoneApiError {
    fn from(value: KeystoneError) -> Self {
        match value {
            //KeystoneError::ApplicationCredential { source } => source.into(),
            KeystoneError::AssignmentProvider { source } => source.into(),
            KeystoneError::Authentication { source } => source.into(),
            KeystoneError::CatalogProvider { source } => source.into(),
            KeystoneError::CredentialProvider { source } => source.into(),
            KeystoneError::FederationProvider { source } => source.into(),
            KeystoneError::Json { source } => source.into(),
            KeystoneError::K8sAuthProvider { source } => source.into(),
            KeystoneError::PolicyEnforcementNotAvailable => KeystoneApiError::internal(value),
            KeystoneError::ResourceProvider { source } => source.into(),
            KeystoneError::RevokeProvider { source } => source.into(),
            KeystoneError::RoleProvider { source } => source.into(),
            KeystoneError::TokenProvider { source } => source.into(),
            KeystoneError::TrustProvider { source } => source.into(),
            _ => KeystoneApiError::internal(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn mapping_provider_not_found() {
        let err = MappingProviderError::NotFound("test-id".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::NotFound {
                ref resource,
                ref identifier
            } if resource == "mapping" && identifier == "test-id"
        ));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn mapping_provider_conflict() {
        let err = MappingProviderError::Conflict("reason".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::Conflict(msg) if msg == "reason"
        ));
    }

    #[test]
    fn mapping_provider_invalid_regex() {
        let err = MappingProviderError::InvalidRegexSyntax("(unclosed".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg == "(unclosed"
        ));
    }

    #[test]
    fn mapping_provider_regex_too_complex() {
        let err = MappingProviderError::RegexTooComplex("pattern".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg == "pattern"
        ));
    }

    #[test]
    fn mapping_provider_regex_safety_violation() {
        let err = MappingProviderError::RegexSafetyViolation(
            "(a+)+".to_string(),
            "nested quantifier".to_string(),
        );
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg.contains("nested quantifier")
        ));
    }

    #[test]
    fn mapping_provider_system_token_shadowing() {
        let err = MappingProviderError::SystemTokenShadowing("key".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg == "key"
        ));
    }

    #[test]
    fn mapping_provider_invalid_rule_name() {
        let err = MappingProviderError::InvalidRuleName("bad name".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg == "bad name"
        ));
    }

    #[test]
    fn mapping_provider_duplicate_rule_name() {
        let err = MappingProviderError::DuplicateRuleName("dup".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg == "dup"
        ));
    }

    #[test]
    fn mapping_provider_domain_claim_required() {
        let err = MappingProviderError::DomainClaimRequired;
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if !msg.is_empty()
        ));
    }

    #[test]
    fn mapping_provider_domain_override_in_fixed_mode() {
        let err = MappingProviderError::DomainOverrideInFixedMode;
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if !msg.is_empty()
        ));
    }

    #[test]
    fn mapping_provider_interpolated_value_too_long() {
        let err = MappingProviderError::InterpolatedValueTooLong;
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if !msg.is_empty()
        ));
    }

    #[test]
    fn mapping_provider_ruleset_immutable() {
        let err = MappingProviderError::RulesetImmutable("test-id".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::BadRequest(msg) if msg.contains("test-id")
        ));
    }

    #[test]
    fn mapping_provider_raft_not_available() {
        let err = MappingProviderError::RaftNotAvailable;
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::InternalError(msg) if !msg.is_empty()
        ));
    }

    #[test]
    fn mapping_provider_unsupported_driver() {
        let err = MappingProviderError::UnsupportedDriver("bad".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::InternalError(msg) if msg.contains("bad")
        ));
    }

    #[test]
    fn identity_provider_conflict_returns_409() {
        let err = IdentityProviderError::Conflict("reason".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::Conflict(ref msg) if msg.contains("reason")
        ));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn identity_provider_readonly_returns_403() {
        let err = IdentityProviderError::Readonly("ldap identity driver is read-only".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(api_err, KeystoneApiError::Forbidden { .. }));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn identity_provider_not_implemented_falls_through_to_internal_error() {
        let err = IdentityProviderError::NotImplemented("expiring group membership".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(api_err, KeystoneApiError::InternalError(..)));
    }

    #[test]
    fn identity_provider_ldap_connection_falls_through_to_internal_error() {
        let err = IdentityProviderError::LdapConnection("bind failed".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(api_err, KeystoneApiError::InternalError(..)));
    }

    #[test]
    fn resource_provider_conflict_returns_409() {
        let err = ResourceProviderError::Conflict("reason".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::Conflict(ref msg) if msg.contains("reason")
        ));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn revoke_provider_conflict_returns_409() {
        let err = RevokeProviderError::Conflict("reason".to_string());
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::Conflict(ref msg) if msg.contains("reason")
        ));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn token_provider_conflict_returns_409() {
        let err = TokenProviderError::Conflict {
            message: "reason".to_string(),
            context: "".to_string(),
        };
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::Conflict(ref msg) if msg == "reason"
        ));
        assert_eq!(
            <KeystoneApiError as IntoResponse>::into_response(api_err).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn mapping_provider_struct_builder() {
        let err = MappingProviderError::StructBuilder(Box::new(
            openstack_keystone_core_types::error::BuilderError::Validation(
                "test error".to_string(),
            ),
        ));
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::InternalError(msg) if msg.contains("test error")
        ));
    }

    /// ADR-0022 Invariant 3: the per-user limiter's driver-level rejection
    /// converts into the same unified 429 variant the global-IP and API-key
    /// limiters use, carrying `Retry-After` and no identifying information.
    #[test]
    fn identity_provider_too_many_requests_maps_to_unified_429() {
        let err = IdentityProviderError::TooManyRequests {
            retry_after_secs: 7,
        };
        let api_err: KeystoneApiError = err.into();
        assert!(matches!(
            api_err,
            KeystoneApiError::TooManyRequests { retry_after: 7 }
        ));
        let response = <KeystoneApiError as IntoResponse>::into_response(api_err);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .expect("Retry-After header must be present")
                .to_str()
                .unwrap(),
            "7"
        );
    }

    #[test]
    fn too_many_requests_returns_429_with_retry_after() {
        let err = KeystoneApiError::TooManyRequests { retry_after: 42 };
        assert_eq!(err.to_string(), "Rate limit exceeded. Retry in 42 seconds.");
        let response = <KeystoneApiError as IntoResponse>::into_response(err);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header must be present");
        assert_eq!(retry_after.to_str().unwrap(), "42");
    }
}
