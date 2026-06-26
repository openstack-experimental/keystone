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
//! Validate token.
//!
//! Check the token whether it can be accepted as a valid. Additionally the
//! token is being expanded returning information like the user_id, scope,
//! roles, etc.
//!
//! Token validations:
//!
//!  - expiration
//!  - revocation

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{json, to_value};
use tracing::error;

use openstack_keystone_api_types::v3::auth::token::TokenBuilder;

use openstack_keystone_core::auth::ExecutionContext;

use crate::api::v3::auth::token::types::{TokenResponse, ValidateTokenParameters};
use crate::api::{Catalog, CatalogService, auth::Auth, error::KeystoneApiError};
use crate::keystone::ServiceState;

/// Validate and show information for token.
///
/// Validates and shows information for a token, including its expiration date
/// and authorization scope.
///
/// Pass your own token in the X-Auth-Token request header.
///
/// Pass the token that you want to validate in the X-Subject-Token request
/// header.
#[utoipa::path(
    get,
    path = "/",
    params(ValidateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag="auth"
)]
#[tracing::instrument(
    name = "api::v3::token::get",
    level = "debug",
    skip(state, headers, user_auth)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Query(query): Query<ValidateTokenParameters>,
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let subject_token: String = headers
        .get("X-Subject-Token")
        .ok_or(KeystoneApiError::SubjectTokenMissing)?
        .to_str()
        .map_err(|_| KeystoneApiError::InvalidHeader)?
        .to_string();

    // Default behavior is to return 404 for expired tokens. It makes sense to log
    // internally the error before mapping it.
    let vsc = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::from_auth(&state, &user_auth),
            &subject_token,
            query.allow_expired,
            None,
        )
        .await
        .inspect_err(|e| error!("{:?}", e.to_string()))
        .map_err(|_| KeystoneApiError::NotFound {
            resource: "token".into(),
            identifier: String::new(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/auth/token/show",
            &user_auth,
            to_value(json!({"token": &vsc.token()?}))?,
            None,
        )
        .await?;

    let mut response_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };

    if !query.nocatalog.is_some_and(|x| x) {
        let catalog: Catalog = Catalog(
            state
                .provider
                .get_catalog_provider()
                .get_catalog(&ExecutionContext::from_auth(&state, &user_auth), true)
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

        response_token.token.catalog = Some(catalog);
    }

    Ok((StatusCode::OK, Json(response_token)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::auth::token::types::*;
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::{MockTokenProvider, TokenProviderError};

    #[tokio::test]
    async fn test_get() {
        use openstack_keystone_core_types::auth::*;
        use openstack_keystone_core_types::resource::Domain as CoreDomain;
        use openstack_keystone_core_types::token::UnscopedPayload;

        let user_domain = CoreDomain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };

        let authz = AuthzInfoBuilder::default()
            .scope(ScopeInfo::Domain(CoreDomain {
                id: "user_domain_id".into(),
                enabled: true,
                ..Default::default()
            }))
            .build()
            .unwrap();

        let vsc_for_mock = openstack_keystone_core::auth::ValidatedSecurityContext::test_new(
            SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("bar")
                            .user_domain(user_domain)
                            .build()
                            .unwrap(),
                    ),
                })
                .token(openstack_keystone_core_types::token::FernetToken::Unscoped(
                    UnscopedPayload {
                        user_id: "bar".into(),
                        ..Default::default()
                    },
                ))
                .authorization(authz)
                .build(),
        );

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(move |_exec, _, _, _| Ok(vsc_for_mock.clone()));
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_exec, _| Ok(Vec::new()));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_exec, id: &'_ str| id == "user_domain_id")
            .returning(|_exec, _| {
                Ok(Some(CoreDomain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .mock_resource(resource_mock)
            .mock_token(token_mock)
            .mock_catalog(catalog_mock);

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc.clone())
                    .header("x-subject-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: TokenResponse = serde_json::from_slice(&body).unwrap();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_show_domain() {
        use openstack_keystone_core_types::auth::{AuthzInfoBuilder, *};
        use openstack_keystone_core_types::resource::Domain as CoreDomain;
        use openstack_keystone_core_types::token::UnscopedPayload;

        let user_domain = CoreDomain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };

        let authz = AuthzInfoBuilder::default()
            .scope(ScopeInfo::Domain(CoreDomain {
                id: "user_domain_id".into(),
                enabled: true,
                ..Default::default()
            }))
            .build()
            .unwrap();

        let vsc_for_mock = openstack_keystone_core::auth::ValidatedSecurityContext::test_new(
            SecurityContext::test_build()
                .authentication_context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("bar")
                            .user_domain(user_domain)
                            .build()
                            .unwrap(),
                    ),
                })
                .token(openstack_keystone_core_types::token::FernetToken::Unscoped(
                    UnscopedPayload {
                        user_id: "bar".into(),
                        ..Default::default()
                    },
                ))
                .authorization(authz)
                .build(),
        );

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, allow_expired: &Option<bool>, _| {
                token == "bar" && *allow_expired == Some(true)
            })
            .returning(move |_exec, _, _, _| Ok(vsc_for_mock.clone()));

        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_exec, _| Ok(Vec::new()));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_exec, id: &'_ str| id == "user_domain_id")
            .returning(|_exec, _| {
                Ok(Some(CoreDomain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });

        let provider = Provider::mocked_builder()
            .mock_resource(resource_mock)
            .mock_token(token_mock)
            .mock_catalog(catalog_mock);

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?allow_expired=true")
                    .extension(vsc)
                    .header("x-subject-token", "bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_expired() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(|_exec, _, _, _| Err(TokenProviderError::Expired));

        let provider = Provider::mocked_builder().mock_token(token_mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_revoked() {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(|_exec, _, _, _| Err(TokenProviderError::TokenRevoked));

        let provider = Provider::mocked_builder().mock_token(token_mock);

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
