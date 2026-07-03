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
//! Create token (authenticate).

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use validator::Validate;

use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core::auth::ValidatedSecurityContext;
use openstack_keystone_core_types::auth::*;

use openstack_keystone_core::api::common::get_authz_info;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scope::Scope as ProviderScope;

use crate::api::v3::auth::token::common::authenticate_request;
use crate::api::v3::auth::token::types::{AuthRequest, CreateTokenParameters, TokenResponse};
use crate::api::{Catalog, CatalogService, error::KeystoneApiError};
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, build_initiator_unknown,
    emit_perimeter_authenticate_event, error_variant_name,
};
use crate::common::TracedJson;
use crate::keystone::ServiceState;

/// Raw TCP peer address, if the connection came in through a listener
/// configured with `into_make_service_with_connect_info` (the public
/// interface) - `None` on interfaces that don't populate `ConnectInfo`
/// (e.g. the SPIFFE admin interface), never a request-rejection.
pub(super) struct PeerAddr(Option<SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| *addr),
        ))
    }
}

/// Authenticate user issuing a new token.
#[utoipa::path(
    post,
    path = "/",
    description = "Issue token",
    params(CreateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(name = "api::v3::token::post", level = "debug", skip(state, req))]
#[axum::debug_handler]
pub(super) async fn create(
    CorrelationId(cid): CorrelationId,
    Query(query): Query<CreateTokenParameters>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    TracedJson(req): TracedJson<AuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let result = create_inner(&state, query, req, &headers, peer_addr).await;
    let initiator = result
        .as_ref()
        .ok()
        .map(|(vsc, _)| build_initiator_from_vsc(vsc))
        .unwrap_or_else(build_initiator_unknown);
    let (outcome, reason) = match &result {
        Ok(_) => ("success", None),
        Err(e) => ("failure", Some(error_variant_name(e))),
    };
    emit_perimeter_authenticate_event(&state.audit_dispatcher, &cid, initiator, outcome, reason);
    result.map(|(_, response)| response)
}

/// Inner auth flow that returns the `ValidatedSecurityContext` alongside the
/// HTTP response so the outer handler can build the audit `Initiator`.
async fn create_inner(
    state: &ServiceState,
    query: CreateTokenParameters,
    req: AuthRequest,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
) -> Result<(ValidatedSecurityContext, Response), KeystoneApiError> {
    req.validate()?;

    // Global per-IP rate-limit check (ADR-0022, Invariant 4).
    // Fires BEFORE authenticate_request to avoid consuming CPU on password
    // hashing for rejected requests.
    let xff_header = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(xff_header, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    let auth_res =
        authenticate_request(state, &req, headers, peer_addr.map(|addr| addr.ip())).await?;
    let ctx = SecurityContext::try_from(auth_res)?;
    let provider_scope: Option<ProviderScope> = req.auth.scope.clone().map(Into::into);
    let authz_info = get_authz_info(state, provider_scope.as_ref()).await?;

    // This is a new authentication/reauthentication. Check if that is allowed at
    // all
    if let Some(token_restriction) = ctx.token_restriction()
        && !token_restriction.allow_rescope
        && req.auth.scope.is_some()
    {
        return Err(KeystoneApiError::AuthenticationRescopeForbidden);
    }

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(state, &ctx, &authz_info)
        .await?;

    let mut api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    if !query.nocatalog.is_some_and(|x| x) {
        let exec = ExecutionContext::internal(state);
        let catalog: Catalog = Catalog(
            state
                .provider
                .get_catalog_provider()
                .get_catalog(&exec, true)
                .await?
                .into_iter()
                .map(|(s, es)| CatalogService {
                    id: s.id.clone(),
                    name: s.name(),
                    r#type: s.r#type,
                    endpoints: es.into_iter().map(Into::into).collect(),
                })
                .collect::<Vec<_>>(),
        );
        api_token.token.catalog = Some(catalog);
    }
    let response = (
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response();
    Ok((vsc, response))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, RateLimitSection};
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::identity::{IdentityProviderError, UserPasswordAuthRequest};
    use openstack_keystone_core_types::resource::{Domain, DomainBuilder, Project};
    use openstack_keystone_core_types::token::{ProjectScopePayload, TokenProviderError};
    use secrecy::ExposeSecret;

    use crate::api::v3::auth::token::types::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::catalog::MockCatalogProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::MockTokenProvider;

    use super::super::openapi_router;

    #[tokio::test]
    #[traced_test]
    async fn test_post() {
        let config = Config::default();
        let project = Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let user_domain = Domain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };
        let project_domain = Domain {
            id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let mut assignment_mock = MockAssignmentProvider::default();
        let mut catalog_mock = MockCatalogProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password.expose_secret() == "pass"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth.clone()));
        identity_mock.expect_get_user().returning(|_, _| {
            use openstack_keystone_core_types::identity::UserResponse;
            Ok(Some(UserResponse {
                id: "uid".into(),
                name: "uname".into(),
                domain_id: "user_domain_id".into(),
                enabled: true,
                default_project_id: None,
                extra: std::collections::HashMap::new(),
                federated: None,
                options: openstack_keystone_core_types::identity::UserOptions::default(),
                password_expires_at: None,
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| Ok(Some(project.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(move |_, _| Ok(Some(user_domain.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(move |_, _| Ok(Some(project_domain.clone())));
        let mut token_mock = MockTokenProvider::default();
        let vsc_for_mock = {
            use openstack_keystone_core_types::auth::AuthzInfoBuilder;
            use openstack_keystone_core_types::resource::ProjectBuilder;
            use openstack_keystone_core_types::role::RoleRefBuilder;
            use openstack_keystone_core_types::token::FernetToken;
            let user_resp = openstack_keystone_core_types::identity::UserResponseBuilder::default()
                .id("uid")
                .name("uname".to_string())
                .domain_id("user_domain_id".to_string())
                .enabled(true)
                .build()
                .unwrap();
            let fernet_payload = ProjectScopePayload {
                user_id: "uid".into(),
                methods: Vec::from(["password".to_string()]),
                project_id: "pid".into(),
                ..Default::default()
            };
            let authz = AuthzInfoBuilder::default()
                .roles(vec![
                    RoleRefBuilder::default()
                        .id("admin")
                        .name("admin")
                        .build()
                        .unwrap(),
                ])
                .scope(ScopeInfo::Project {
                    project: ProjectBuilder::default()
                        .id("pid")
                        .domain_id("pdid")
                        .enabled(true)
                        .name("pname")
                        .build()
                        .unwrap(),
                    project_domain: DomainBuilder::default()
                        .id("pdid")
                        .name("pdname")
                        .enabled(true)
                        .build()
                        .unwrap(),
                })
                .build()
                .unwrap();
            let sc = SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("uid")
                            .user(user_resp)
                            .user_domain(
                                DomainBuilder::default()
                                    .id("user_domain_id")
                                    .name("user_domain_name")
                                    .enabled(true)
                                    .build()
                                    .unwrap(),
                            )
                            .build()
                            .unwrap(),
                    ),
                })
                .token(FernetToken::ProjectScope(fernet_payload))
                .authorization(authz)
                .build();
            openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
        };
        let vsc_clone = vsc_for_mock.clone();
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc_clone.clone()));
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_catalog(catalog_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(vec!["password"], res.token.methods);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_post_explicit_empty_roles_unauthorized() {
        let config = Config::default();
        let project = Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let user_domain = Domain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };
        let project_domain = Domain {
            id: "pdid".into(),
            enabled: true,
            ..Default::default()
        };
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| Ok(Vec::new()));

        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .withf(|_, req: &UserPasswordAuthRequest| {
                req.id == Some("uid".to_string())
                    && req.password.expose_secret() == "pass"
                    && req.name == Some("uname".to_string())
            })
            .returning(move |_, _| Ok(auth.clone()));
        identity_mock.expect_get_user().returning(|_, _| {
            use openstack_keystone_core_types::identity::UserResponse;
            Ok(Some(UserResponse {
                id: "uid".into(),
                name: "uname".into(),
                domain_id: "user_domain_id".into(),
                enabled: true,
                default_project_id: None,
                extra: std::collections::HashMap::new(),
                federated: None,
                options: openstack_keystone_core_types::identity::UserOptions::default(),
                password_expires_at: None,
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| Ok(Some(project.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(move |_, _| Ok(Some(user_domain.clone())));
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(move |_, _| Ok(Some(project_domain.clone())));

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_issue_token_context()
            .returning(|_, _, _| {
                Err(TokenProviderError::Authentication(
                    AuthenticationError::ActorHasNoRolesOnTarget,
                ))
            });

        let provider = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .mock_token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_post_project_disabled() {
        let config = Config::default();
        let mut identity_mock = MockIdentityProvider::default();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let auth_clone = auth.clone();
        identity_mock
            .expect_authenticate_by_password()
            .returning(move |_, _| Ok(auth_clone.clone()));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(move |_, _| {
                Ok(Some(Project {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: false,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(move |_, _| {
                Ok(Some(Domain {
                    id: "pdid".into(),
                    name: "pdname".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_resource(resource_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "auth": {
                                "identity": {
                                    "methods": ["password"],
                                    "password": {
                                        "user": {
                                            "id": "uid",
                                            "name": "uname",
                                            "domain": {
                                                "id": "udid",
                                                "name": "udname"
                                            },
                                            "password": "pass",
                                        },
                                    },
                                },
                                "scope": {
                                    "project": {
                                        "id": "pid",
                                        "name": "pname",
                                        "domain": {
                                            "id": "pdid",
                                            "name": "pdname"
                                        }
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // Build a minimal JSON body that passes `req.validate()`.
    fn auth_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "id": "uid",
                            "name": "uname",
                            "domain": { "id": "udid", "name": "udname" },
                            "password": "pass"
                        }
                    }
                }
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit_returns_429_after_burst_exhausted() {
        // burst_size=1: the first request consumes the single burst token and
        // passes through to auth; the second must be rejected with 429 before
        // authenticate_request is ever called.
        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        // The first request reaches identity — we return an error so we don't
        // need the full auth fixture.  The second must never reach identity at
        // all (rate limited before authenticate_request).
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .once()
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.1:1234".parse().unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // First request — passes the rate limit, fails at auth → not 429.
        let mut req1 = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(auth_body()))
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        let resp1 = api.as_service().oneshot(req1).await.unwrap();
        assert_ne!(
            resp1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "first request must not be rate-limited"
        );

        // Second request from the same IP — burst exhausted → 429 + Retry-After.
        let mut req2 = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(auth_body()))
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        let resp2 = api.as_service().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp2.headers().contains_key(header::RETRY_AFTER),
            "429 response must carry Retry-After header"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit_uses_xff_only_for_trusted_peer() {
        let mut config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };
        config
            .rate_limit_trusted_proxies
            .trusted_proxies
            .push("10.0.0.0/8".to_string());

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .times(2)
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));
        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .build()
            .unwrap();
        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );
        let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        for client_ip in ["203.0.113.1", "203.0.113.2"] {
            let mut request = Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", client_ip)
                .body(Body::from(auth_body()))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
            let response = api.as_service().oneshot(request).await.unwrap();
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let mut request = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "203.0.113.1")
            .body(Body::from(auth_body()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = api.as_service().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit_does_not_apply_without_connect_info() {
        // When there is no ConnectInfo in extensions (SPIFFE/internal interface),
        // requests must never be rate-limited regardless of the configured quota.
        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        let mut identity_mock = MockIdentityProvider::default();
        // Two calls expected — both reach identity, neither is rate-limited.
        identity_mock
            .expect_authenticate_by_password()
            .times(2)
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // Neither request carries ConnectInfo — both must reach identity.
        for _ in 0..2 {
            let resp = api
                .as_service()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .method("POST")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(auth_body()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    /// End-to-end path: drive the real `create` route through the exact
    /// make-service the public listener uses
    /// (`into_make_service_with_connect_info::<SocketAddr>`) with a fixed peer
    /// address, so the `ConnectInfo<SocketAddr>` extension is populated by axum
    /// itself — not injected by the test. This proves the whole chain wires up:
    /// TCP peer → `ConnectInfo` extension → `PeerAddr` extractor → `check_ip`
    /// → 429 + `Retry-After`. Confirms the `401 → 429`
    /// flip the manual `curl` loop in the PR test plan would show, without a
    /// live database or socket (`Connected<SocketAddr> for SocketAddr` drives
    /// the make-service with a synthetic peer).
    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit_429_over_connect_info_make_service() {
        use axum::ServiceExt as AxumServiceExt;

        let config = Config {
            rate_limit_global_ip: RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        // Identity returns an auth failure so the first (non-limited) request
        // resolves without the full token fixture; it must be called exactly
        // once — the second request is rejected before reaching identity.
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .once()
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        // Same make-service path as `spawn_public_listener`; explicit request
        // type satisfies inference (E0284), as in the binary.
        let (router, _) = openapi_router().split_for_parts();
        let app = router.with_state(state.clone());
        let make =
            AxumServiceExt::<Request<Body>>::into_make_service_with_connect_info::<SocketAddr>(app);
        let peer: SocketAddr = "203.0.113.7:4444".parse().unwrap();

        let post = || {
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth_body()))
                .unwrap()
        };

        // First request from the peer: passes rate limit, fails at auth → not 429.
        let svc1 = make.clone().oneshot(peer).await.unwrap();
        let resp1 = svc1.oneshot(post()).await.unwrap();
        assert_ne!(
            resp1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "first request from a fresh IP must not be rate-limited"
        );

        // Second request from the same peer: burst spent → 429 + Retry-After.
        let svc2 = make.clone().oneshot(peer).await.unwrap();
        let resp2 = svc2.oneshot(post()).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp2.headers().contains_key(header::RETRY_AFTER),
            "429 response must carry a Retry-After header"
        );
    }
}
