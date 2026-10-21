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
//! On-behalf-of exchange (ADR 0036 §6): the RFC 8693 token exchange of a
//! user's token by a delegatable service authenticated with its SVID.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use governor::clock::Clock as _;

use openstack_keystone_core::common::SpiffeId;
use openstack_keystone_core::oauth2_client::on_behalf_of::{
    OnBehalfOfError, OnBehalfOfRequest, OnBehalfOfSubject, build_on_behalf_of_claims,
    exchange_on_behalf_of,
};
use openstack_keystone_core_types::auth::AuthenticationContext;
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use crate::audit::{Oauth2Grant, build_initiator_from_vsc, emit_on_behalf_of_event};
use crate::keystone::ServiceState;

use super::common::sign_jwt;
use super::token_exchange::requested_audience;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// `subject_token_type` of a Keystone (Fernet or JWS) token.
const KEYSTONE_TOKEN_TYPE: &str = "urn:openstack:params:oauth:token-type:keystone";
/// `subject_token_type` of an access token this endpoint minted earlier.
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Rate limiter key of an exchange: a bucket of its own per presented SVID,
/// never shared with the `client_id`-keyed grants or with redemption.
fn rate_limit_key(svid: &str) -> String {
    format!("on_behalf_of:{svid}")
}

/// Exchange a user's token for a token of the calling service, naming the
/// user as `sub` and the service as `act` (ADR 0036 §6).
///
/// The service authenticates with the X.509-SVID of the TLS connection on
/// the internal interface and names its `client_id`. No refresh token is
/// issued; the service exchanges again, presenting the token it received,
/// which re-runs every check until the client's `max_operation_lifetime`
/// since the user authenticated has passed.
pub(super) async fn handle_on_behalf_of_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
    svid: &SpiffeId,
) -> Result<Response, Oauth2TokenError> {
    let Some(client_id) = form.client_id.as_deref().filter(|c| !c.is_empty()) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(subject_token) = form.subject_token.as_deref().filter(|t| !t.is_empty()) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: subject_token",
        ));
    };
    let subject = match form.subject_token_type.as_deref() {
        Some(KEYSTONE_TOKEN_TYPE) => OnBehalfOfSubject::Keystone(subject_token),
        Some(ACCESS_TOKEN_TYPE) => OnBehalfOfSubject::Hop(subject_token),
        Some(_) => {
            return Err(Oauth2TokenError::invalid_request(
                "unsupported subject_token_type",
            ));
        }
        None => {
            return Err(Oauth2TokenError::invalid_request(
                "missing required parameter: subject_token_type",
            ));
        }
    };

    // Step 1 (ADR 0026 §7.A): rate limit before any lookup, keyed on the
    // presented identity.
    if let Err(not_until) = state
        .oauth2_token_rate_limiter
        .check_key(&rate_limit_key(svid.as_str()))
    {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let exchanged = exchange_on_behalf_of(
        state,
        &OnBehalfOfRequest {
            domain_id,
            issuer: &issuer,
            signing_algorithm: match oauth2_cfg.signing_algorithm {
                openstack_keystone_config::SigningAlgorithm::Es256 => SigningAlgorithm::Es256,
                openstack_keystone_config::SigningAlgorithm::Rs256 => SigningAlgorithm::Rs256,
            },
            svid,
            client_id,
            subject,
        },
    )
    .await
    .map_err(|e| {
        tracing::info!(client_id, error = %e, "on-behalf-of exchange refused");
        exchange_error(e)
    })?;

    // `scope` keeps its ADR 0026 §4 meaning and has no effect on roles.
    let scope = match form.scope.as_deref() {
        Some(scope) => {
            if scope
                .split_whitespace()
                .any(|s| !exchanged.client.allowed_scopes.iter().any(|a| a == s))
            {
                return Err(Oauth2TokenError::invalid_scope(
                    "requested scope exceeds the client's allowed_scopes",
                ));
            }
            scope.to_string()
        }
        None => "openstack:api".to_string(),
    };
    let audience = requested_audience(state, &form.audience).await?;

    let now = chrono::Utc::now().timestamp();
    // The token never outlives the chain: the client's operation lifetime
    // since the user authenticated bounds it.
    let access_lifetime = (i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60)
        .min(exchanged.valid_until.timestamp() - now);
    if access_lifetime <= 0 {
        return Err(Oauth2TokenError::invalid_grant(
            "the operation lifetime of the client is exhausted",
        ));
    }
    let claims = build_on_behalf_of_claims(
        &exchanged,
        &issuer,
        uuid::Uuid::new_v4().to_string(),
        now,
        now + access_lifetime,
        audience,
    )
    .map_err(exchange_error)?;
    let access_token = sign_jwt(state, domain_id, &claims).await?;

    if let AuthenticationContext::OnBehalfOf {
        root_jti,
        delegated_project_id,
        ..
    } = exchanged.vsc.inner().authentication_context()
    {
        emit_on_behalf_of_event(
            &state.audit_dispatcher,
            correlation_id,
            "authenticate",
            build_initiator_from_vsc(&exchanged.vsc),
            Oauth2Grant {
                client_id: &exchanged.client.client_id,
                grant_type: "on_behalf_of",
            },
            cadf::OnBehalfOfAudit::new(
                root_jti,
                &claims.sub,
                &exchanged.client.client_id,
                svid.as_str(),
                delegated_project_id.as_deref(),
            ),
            Outcome::Success,
            None,
        );
    }

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope,
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Map a refused exchange to its token endpoint error.
fn exchange_error(e: OnBehalfOfError) -> Oauth2TokenError {
    match e {
        OnBehalfOfError::InvalidClient => {
            Oauth2TokenError::invalid_client("the client is not authenticated for exchange")
        }
        OnBehalfOfError::InvalidSubject
        | OnBehalfOfError::UnsupportedSubject(_)
        | OnBehalfOfError::CrossDomain
        | OnBehalfOfError::Authentication(_) => Oauth2TokenError::invalid_grant(
            "subject_token is invalid, expired, or cannot be exchanged",
        ),
        OnBehalfOfError::OperationExpired => {
            Oauth2TokenError::invalid_grant("the operation lifetime of the client is exhausted")
        }
        OnBehalfOfError::Provider(_) => Oauth2TokenError::internal("token issuance failed"),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use chrono::{Duration, Utc};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_config::Interface;
    use openstack_keystone_core::common::SpiffeId;
    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::oauth2_client::{DelegationPolicy, OAuth2ClientResource};
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_core_types::token::{FernetToken, payload::ProjectScopePayloadBuilder};

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        confidential_client, json_body, jwt_claims, ok_key_mock, refresh_identity_mock,
        refresh_user, request,
    };
    use crate::assignment::MockAssignmentProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::revoke::MockRevokeProvider;
    use crate::role::MockRoleProvider;
    use crate::token::MockTokenProvider;

    const SVID: &str = "spiffe://td/service/glance/host/h1";
    const BODY: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
        &client_id=client-1&subject_token=user-token\
        &subject_token_type=urn%3Aopenstack%3Aparams%3Aoauth%3Atoken-type%3Akeystone";

    #[test]
    fn test_rate_limit_key_is_namespaced() {
        assert_eq!(
            super::rate_limit_key("spiffe://x/ns/a"),
            "on_behalf_of:spiffe://x/ns/a"
        );
    }

    async fn service_client() -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_secret_hash: None,
            token_endpoint_auth_method: "tls_client_auth".into(),
            grant_types: vec![],
            spiffe_ids: vec!["spiffe://td/service/glance/host/*".into()],
            delegation: Some(DelegationPolicy {
                on_behalf_of: true,
                max_operation_lifetime: Some(3600),
                ..Default::default()
            }),
            ..confidential_client().await
        }
    }

    /// The user's Keystone token, as the token provider resolves it.
    fn user_vsc() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        let token = FernetToken::ProjectScope(
            ProjectScopePayloadBuilder::default()
                .methods(vec!["password".to_string()].into_iter())
                .audit_ids(vec!["audit-1".to_string()].into_iter())
                .user_id("user-1")
                .project_id("project-1")
                .expires_at(Utc::now() + Duration::hours(1))
                .issued_at(Utc::now())
                .build()
                .unwrap(),
        );
        let domain = Domain {
            id: "domain-1".into(),
            name: "domain".into(),
            enabled: true,
            ..Default::default()
        };
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Token(token.clone()))
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("user-1")
                        .user(refresh_user(true, "domain-1"))
                        .user_domain(domain.clone())
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .scope(ScopeInfo::Project {
                        project: Project {
                            id: "project-1".into(),
                            domain_id: "domain-1".into(),
                            enabled: true,
                            name: "project".into(),
                            ..Default::default()
                        },
                        project_domain: domain,
                    })
                    .roles(vec![RoleRef {
                        id: "member".into(),
                        name: Some("member".into()),
                        domain_id: None,
                    }])
                    .build()
                    .unwrap(),
            )
            .token(token)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    async fn exchange(
        body: &str,
        interface: Interface,
        svid: Option<&str>,
        revoked: bool,
    ) -> axum::response::Response {
        let client = service_client().await;
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut tokens = MockTokenProvider::default();
        tokens
            .expect_validate_to_context()
            .returning(|_, _, _, _| Ok(user_vsc()));
        let mut revoke = MockRevokeProvider::default();
        revoke
            .expect_is_token_revoked()
            .returning(move |_, _| Ok(revoked));
        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain().returning(|_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: id.to_string(),
                enabled: true,
                ..Default::default()
            }))
        });
        let mut assignments = MockAssignmentProvider::default();
        assignments
            .expect_list_role_assignments()
            .returning(|_, _| {
                Ok(vec![Assignment {
                    actor_id: "user-1".into(),
                    role_id: "member".into(),
                    role_name: Some("member".into()),
                    target_id: "project-1".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                }])
            });
        let mut role = MockRoleProvider::default();
        role.expect_expand_implied_roles().returning(|_, _| Ok(()));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(clients)
            .mock_token(tokens)
            .mock_revoke(revoke)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(resource)
            .mock_assignment(assignments)
            .mock_role(role)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut req = request(body);
        req.extensions_mut().insert(interface);
        if let Some(svid) = svid {
            req.extensions_mut().insert(SpiffeId::new(svid).unwrap());
        }
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_exchange_names_the_user_and_the_service() {
        let response = exchange(BODY, Interface::Internal, Some(SVID), false).await;
        let status = response.status();
        let headers = response.headers().clone();
        let body = json_body(response).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(body.get("refresh_token").is_none());
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["client_id"], "client-1");
        assert_eq!(
            claims["amr"],
            serde_json::json!(["on_behalf_of", "password", "token"])
        );
        assert_eq!(claims["act"]["sub"], SVID);
        assert_eq!(claims["act"]["sub_type"], "spiffe");
        assert_eq!(claims["delegation_context"]["auth_method"], "on_behalf_of");
        assert_eq!(claims["delegation_context"]["root_jti"], "audit-1");
        assert_eq!(claims["project_id"], "project-1");
        assert_eq!(claims["roles"], serde_json::json!(["member"]));
        // Bounded by the client's operation lifetime of an hour.
        assert!(body["expires_in"].as_i64().unwrap() <= 3600);
    }

    #[tokio::test]
    async fn test_exchange_needs_subject_token_type() {
        let without_type = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
            &client_id=client-1&subject_token=user-token";
        let unknown_type = format!("{without_type}&subject_token_type=urn%3Aother");
        for body in [without_type.to_string(), unknown_type] {
            let response = exchange(&body, Interface::Internal, Some(SVID), false).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json_body(response).await["error"], "invalid_request");
        }
    }

    #[tokio::test]
    async fn test_exchange_rejects_other_svid() {
        let response = exchange(
            BODY,
            Interface::Internal,
            Some("spiffe://td/service/nova/host/h1"),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    /// Without an SVID on the internal interface the request is the
    /// secret-authenticated exchange of a delegated credential, which this
    /// client (it has no secret) cannot make.
    #[tokio::test]
    async fn test_exchange_without_svid_is_not_on_behalf_of() {
        for (interface, svid) in [(Interface::Internal, None), (Interface::Public, Some(SVID))] {
            let response = exchange(BODY, interface, svid, false).await;
            assert_ne!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_exchange_of_revoked_token_is_invalid_grant() {
        let response = exchange(BODY, Interface::Internal, Some(SVID), true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }
}
