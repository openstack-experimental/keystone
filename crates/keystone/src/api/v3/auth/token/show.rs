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
use serde_json::{Value, json, to_value};
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

    let token = TokenBuilder::try_from(&vsc)?.build()?;

    state
        .policy_enforcer
        .enforce(
            "identity/auth/token/show",
            &user_auth,
            Value::Null,
            Some(to_value(json!({"token": &token}))?),
        )
        .await?;

    let mut response_token = TokenResponse { token };

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

    use openstack_keystone_core::{
        api::tests::test_fixture_ec2_scoped, auth::ValidatedSecurityContext,
    };
    use openstack_keystone_core_types::auth::{AuthzInfoBuilder, *};
    use openstack_keystone_core_types::resource::Domain as CoreDomain;
    use openstack_keystone_core_types::token::{FernetToken, UnscopedPayload};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::auth::token::types::*;
    use crate::catalog::MockCatalogProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::{MockTokenProvider, TokenProviderError};

    #[tokio::test]
    async fn test_get() {
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

        let vsc_for_mock = ValidatedSecurityContext::test_new(
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
                .token(FernetToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
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

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/auth/token/show.rego` decision (via a real `opa
    /// run` subprocess instead of `MockPolicy`) through the owner/non-owner
    /// matrix -- `identity.token_subject` is the rule that actually decides
    /// who may view a token (besides admin/service/system-reader), and a
    /// mock can never catch a handler feeding it the wrong `user_id`
    /// (issue #979 caught exactly this: `token_subject` compared against
    /// `token.user_id`, but the real `Token` struct nests it as
    /// `token.user.id`, so this branch was silently dead -- fixed in
    /// `policy/identity.rego`). Requires `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;
        use openstack_keystone_core_types::auth::{AuthzInfoBuilder, *};
        use openstack_keystone_core_types::resource::Domain as CoreDomain;
        use openstack_keystone_core_types::token::UnscopedPayload;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::member_vsc;
        use crate::provider::ProviderBuilder;

        fn subject_token_vsc(owner_user_id: &str) -> ValidatedSecurityContext {
            let user_domain = CoreDomain {
                id: "d1".into(),
                enabled: true,
                ..Default::default()
            };
            let authz = AuthzInfoBuilder::default()
                .scope(ScopeInfo::Domain(CoreDomain {
                    id: "d1".into(),
                    enabled: true,
                    ..Default::default()
                }))
                .build()
                .unwrap();
            ValidatedSecurityContext::test_new(
                SecurityContext::test_build()
                    .authentication_context(AuthenticationContext::Password)
                    .principal(PrincipalInfo {
                        identity: IdentityInfo::User(
                            UserIdentityInfoBuilder::default()
                                .user_id(owner_user_id)
                                .user_domain(user_domain)
                                .build()
                                .unwrap(),
                        ),
                    })
                    .token(openstack_keystone_core_types::token::FernetToken::Unscoped(
                        UnscopedPayload {
                            user_id: owner_user_id.into(),
                            ..Default::default()
                        },
                    ))
                    .authorization(authz)
                    .build(),
            )
        }

        fn provider_with_subject_token(owner_user_id: &'static str) -> ProviderBuilder {
            let subject_vsc = subject_token_vsc(owner_user_id);

            let mut token_mock = MockTokenProvider::default();
            token_mock
                .expect_validate_to_context()
                .returning(move |_, _, _, _| Ok(subject_vsc.clone()));

            let mut catalog_mock = MockCatalogProvider::default();
            catalog_mock
                .expect_get_catalog()
                .returning(|_, _| Ok(Vec::new()));

            let mut resource_mock = MockResourceProvider::default();
            resource_mock.expect_get_domain().returning(|_, _| {
                Ok(Some(CoreDomain {
                    id: "d1".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });

            Provider::mocked_builder()
                .mock_token(token_mock)
                .mock_catalog(catalog_mock)
                .mock_resource(resource_mock)
        }

        async fn show_request(
            vsc: ValidatedSecurityContext,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            api.as_service()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .extension(vsc)
                        .header("x-subject-token", "subject")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn owner_viewing_own_token_is_allowed() {
            let status = show_request(
                member_vsc("u1", "p1", &[]),
                provider_with_subject_token("u1"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn non_owner_viewing_someone_elses_token_is_denied() {
            let status = show_request(
                member_vsc("u2", "p1", &[]),
                provider_with_subject_token("u1"),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn test_show_domain() {
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

    #[tokio::test]
    async fn test_get_ec2credential() {
        let vsc_for_mock = test_fixture_ec2_scoped();

        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "bar")
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
                    .extension(vsc)
                    .header("x-subject-token", "bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
