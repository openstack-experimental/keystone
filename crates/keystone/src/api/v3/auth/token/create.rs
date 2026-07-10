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
    let forwarded_header = headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok());
    let xff_header = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    if let Err(retry_after) = state.rate_limiters.check_ip(
        forwarded_header,
        xff_header,
        peer_addr.map(|addr| addr.ip()),
    ) {
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
            .push("10.0.0.0/8".parse().unwrap());

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

    /// ADR-0022 phase 2: the per-user limiter trips deep in the identity
    /// driver (post-lookup, pre-hash); this proves the rejection surfaces
    /// through the handler as the same uniform 429 + `Retry-After` response
    /// the global-IP limiter produces (Invariant 3).
    #[tokio::test]
    #[traced_test]
    async fn test_user_rate_limit_from_driver_surfaces_as_429() {
        let config = Config::default();

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_authenticate_by_password()
            .once()
            .returning(|_, _| {
                Err(IdentityProviderError::TooManyRequests {
                    retry_after_secs: 3,
                })
            });

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

        let response = api
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

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .expect("429 must carry Retry-After")
                .to_str()
                .unwrap(),
            "3"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit_honours_rfc7239_forwarded_header() {
        // End-to-end through the real handler: an RFC 7239 `Forwarded` header
        // from a trusted proxy buckets by the designated client, takes
        // precedence over a co-present X-Forwarded-For, and throttles the
        // third hit on the same Forwarded client.
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
            .push("10.0.0.0/8".parse().unwrap());

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

        // Two distinct Forwarded clients — each gets its own bucket even
        // though the XFF value is identical (Forwarded takes precedence).
        for client_ip in ["203.0.113.1", "203.0.113.2"] {
            let mut request = Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .header("forwarded", format!("for={client_ip};proto=https"))
                .header("x-forwarded-for", "198.51.100.7")
                .body(Body::from(auth_body()))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
            let response = api.as_service().oneshot(request).await.unwrap();
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // Same Forwarded client again — throttled, even with a fresh XFF.
        let mut request = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .header("forwarded", "for=203.0.113.1;proto=https")
            .header("x-forwarded-for", "198.51.100.8")
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

/// End-to-end HTTP-level integration tests for `mapping`/`route` dynamic
/// auth plugins - drives the real `create()` axum handler via
/// `openapi_router()`/`oneshot()` (like this file's own `test_post`) with a
/// real compiled reference plugin loaded (like `common.rs`'s
/// `route_dispatch_tests`), proving the full round trip: HTTP request in ->
/// `authenticate_request` -> auth-plugin dispatch -> `get_authz_info` ->
/// `issue_token_context` -> `X-Subject-Token` HTTP response out. Every
/// existing auth-plugin test stops one layer short of this (calls
/// `authenticate_via_wasm_*`/`authenticate_request` directly) - this module
/// fills that gap for `mapping` mode and for `route` mode redirecting to a
/// real `full_auth` target.
#[cfg(test)]
mod auth_plugin_http_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginsSection, PluginMode};
    use openstack_keystone_core::auth_plugin_http::DynamicPluginHttpFetcher;
    use openstack_keystone_core::auth_plugin_startup::load_auth_plugins;
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::DomainBuilder;

    use crate::api::v3::auth::token::types::*;
    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::catalog::MockCatalogProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::{Service, ServiceState};
    use crate::mapping::MockMappingProvider;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;
    use crate::token::MockTokenProvider;

    use super::super::openapi_router;

    struct UnreachableHttpFetcher;

    #[async_trait::async_trait]
    impl DynamicPluginHttpFetcher for UnreachableHttpFetcher {
        async fn fetch(
            &self,
            _method: &str,
            _url: &str,
            _resolved_addr: std::net::SocketAddr,
            _headers: &std::collections::HashMap<String, String>,
            _body: Option<&str>,
            _timeout_ms: u64,
            _auth_header: Option<(&str, &str)>,
            _max_body_bytes: usize,
        ) -> Result<openstack_keystone_core::auth_plugin_http::FetchResponse, String> {
            panic!("this test's plugins don't grant http_fetch")
        }
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../auth-plugin-runtime/tests/fixtures/reference-plugin")
    }

    fn build_reference_plugin() -> (PathBuf, String) {
        let dir = fixture_dir();
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&dir)
            .status()
            .expect("failed to spawn cargo to build the reference plugin fixture");
        assert!(
            status.success(),
            "building the reference plugin fixture failed"
        );

        let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
        assert!(
            wasm_path.is_file(),
            "expected build artifact at {}",
            wasm_path.display()
        );
        let bytes = std::fs::read(&wasm_path).unwrap();
        let sha256 = {
            use std::fmt::Write;
            Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        };
        (wasm_path, sha256)
    }

    /// Base `DynamicPluginConfig` with every non-essential field at its
    /// documented default (`crates/config/src/auth_plugins.rs`) - no
    /// `Default` impl exists on the struct itself.
    fn base_plugin_config(
        path: PathBuf,
        sha256: String,
        mode: PluginMode,
    ) -> openstack_keystone_config::DynamicPluginConfig {
        openstack_keystone_config::DynamicPluginConfig {
            path,
            sha256,
            mode,
            capabilities: Vec::new(),
            exposed_headers: Vec::new(),
            allowed_hosts: Vec::new(),
            http_fetch_follow_redirects: false,
            http_fetch_auth_header: None,
            http_fetch_auth_secret_env: None,
            provision_domain_id: None,
            allowed_provision_domains: Vec::new(),
            assign_role_allowed: Vec::new(),
            inspect_methods: Vec::new(),
            route_targets: Vec::new(),
            timeout_ms: 1_000,
            fuel_limit: 10_000_000,
            memory_limit_mb: 16,
            invocation_rate_limit_per_source_per_minute: 20,
            invocation_rate_limit_per_minute: 300,
            max_concurrent_invocations: 16,
            valid_since: None,
        }
    }

    async fn build_state(cfg: Config, provider: Provider, plugin_names: &[&str]) -> ServiceState {
        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        std::mem::forget(receivers);

        let state: ServiceState = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        for name in plugin_names {
            assert!(
                state.auth_plugin_registry.read().await.contains(name),
                "reference plugin {name} should have loaded"
            );
        }
        state
    }

    fn user_response(
        id: &str,
        domain_id: &str,
    ) -> openstack_keystone_core_types::identity::UserResponse {
        UserResponseBuilder::default()
            .id(id.to_string())
            .domain_id(domain_id.to_string())
            .name("dave".to_string())
            .enabled(true)
            .build()
            .unwrap()
    }

    fn canned_vsc(
        ctx: AuthenticationContext,
    ) -> openstack_keystone_core::auth::ValidatedSecurityContext {
        let user = UserResponseBuilder::default()
            .id("uid")
            .name("uname".to_string())
            .domain_id("user_domain_id".to_string())
            .enabled(true)
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(ctx)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user)
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
            .token(openstack_keystone_core_types::token::FernetToken::Unscoped(
                openstack_keystone_core_types::token::UnscopedPayload::default(),
            ))
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn mock_token_and_catalog() -> (MockTokenProvider, MockCatalogProvider) {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));
        (token_mock, catalog_mock)
    }

    async fn post(state: &ServiceState, body: serde_json::Value) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());
        api.as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// (1) A `mapping`-mode plugin's claims correctly drive the Mapping
    /// Engine and the resulting `AuthenticationContext::Mapping` correctly
    /// produces an `X-Subject-Token` over real HTTP.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_post_mapping_plugin_issues_token() {
        let (path, sha256) = build_reference_plugin();
        let mut plugin_cfg = base_plugin_config(path, sha256, PluginMode::Mapping);
        plugin_cfg.inspect_methods = Vec::new();
        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec!["mapper".to_string()],
                ..Default::default()
            },
            auth_plugin: [("mapper".to_string(), plugin_cfg)].into_iter().collect(),
            ..Default::default()
        };

        let mut mapping_mock = MockMappingProvider::default();
        let vsc = canned_vsc(AuthenticationContext::Mapping(
            openstack_keystone_core_types::mapping::auth::MappingContext {
                mapping_id: "m1".to_string(),
                matched_rule_name: "r1".to_string(),
                virtual_user_id: "vu1".to_string(),
                is_system: false,
            },
        ));
        mapping_mock.expect_authenticate_by_mapping().returning({
            let auth = AuthenticationResultBuilder::default()
                .context(AuthenticationContext::Mapping(
                    openstack_keystone_core_types::mapping::auth::MappingContext {
                        mapping_id: "m1".to_string(),
                        matched_rule_name: "r1".to_string(),
                        virtual_user_id: "vu1".to_string(),
                        is_system: false,
                    },
                ))
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("vu1")
                            .build()
                            .unwrap(),
                    ),
                })
                .build()
                .unwrap();
            move |_, _| Ok(auth.clone())
        });

        let (mut token_mock, catalog_mock) = mock_token_and_catalog();
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc.clone()));

        let provider = Provider::mocked_builder()
            .mock_mapping(mapping_mock)
            .mock_token(token_mock)
            .mock_catalog(catalog_mock)
            .build()
            .unwrap();

        let state = build_state(cfg, provider, &["mapper"]).await;

        let response = post(
            &state,
            json!({
                "auth": {
                    "identity": {
                        "methods": ["mapper"],
                        "mapper": {"external_id": "alice", "deny": false}
                    }
                }
            }),
        )
        .await;

        let status = response.status();
        let has_token = response.headers().contains_key("X-Subject-Token");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(has_token);
        let _res: TokenResponse = serde_json::from_slice(&body).unwrap();
    }

    /// (2) A `route`-mode plugin redirects an `application_credential`
    /// shaped request to an allowlisted real `full_auth` target, which
    /// independently provisions the user and issues its own token - proves
    /// the full chain: HTTP -> route pre-dispatch -> rewrite -> full_auth
    /// dispatch -> `provision_user` -> token issuance -> HTTP response.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_post_route_to_target_issues_token() {
        let (path, sha256) = build_reference_plugin();
        let mut router_cfg = base_plugin_config(path.clone(), sha256.clone(), PluginMode::Route);
        router_cfg.inspect_methods = vec!["application_credential".to_string()];
        router_cfg.route_targets = vec!["hacked_appcred_handler".to_string()];
        let mut target_cfg = base_plugin_config(path, sha256, PluginMode::FullAuth);
        target_cfg.capabilities = vec!["provision_user".to_string()];
        target_cfg.provision_domain_id = Some("d".to_string());

        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec!["router".to_string(), "hacked_appcred_handler".to_string()],
                ..Default::default()
            },
            auth_plugin: [
                ("router".to_string(), router_cfg),
                ("hacked_appcred_handler".to_string(), target_cfg),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d")));
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response("u1", "d"))));
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("d".to_string()));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        let (mut token_mock, catalog_mock) = mock_token_and_catalog();
        let vsc = canned_vsc(AuthenticationContext::WasmPlugin {
            plugin_name: "hacked_appcred_handler".to_string(),
            claims: std::collections::HashMap::new(),
            token: None,
        });
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc.clone()));

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_auth_plugin_identity(dpi_mock)
            .mock_token(token_mock)
            .mock_catalog(catalog_mock)
            .build()
            .unwrap();

        let state = build_state(cfg, provider, &["router", "hacked_appcred_handler"]).await;

        let response = post(
            &state,
            json!({
                "auth": {
                    "identity": {
                        "methods": ["application_credential"],
                        "application_credential": {"application_credential_id": "tf-alice"}
                    }
                }
            }),
        )
        .await;

        let status = response.status();
        let has_token = response.headers().contains_key("X-Subject-Token");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(has_token);
    }

    /// (3) A `mapping`-mode plugin's `Deny` fails closed all the way to the
    /// HTTP layer, without ever invoking the Mapping Engine.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_post_mapping_plugin_deny_is_unauthorized() {
        let (path, sha256) = build_reference_plugin();
        let plugin_cfg = base_plugin_config(path, sha256, PluginMode::Mapping);
        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec!["mapper".to_string()],
                ..Default::default()
            },
            auth_plugin: [("mapper".to_string(), plugin_cfg)].into_iter().collect(),
            ..Default::default()
        };

        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock.expect_authenticate_by_mapping().times(0);

        let provider = Provider::mocked_builder()
            .mock_mapping(mapping_mock)
            .build()
            .unwrap();

        let state = build_state(cfg, provider, &["mapper"]).await;

        let response = post(
            &state,
            json!({
                "auth": {
                    "identity": {
                        "methods": ["mapper"],
                        "mapper": {"external_id": "mallory", "deny": true}
                    }
                }
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
