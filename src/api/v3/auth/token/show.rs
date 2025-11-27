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
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::{json, to_value};
use tracing::error;

use crate::api::v3::auth::token::types::{
    Token as ApiResponseToken, TokenResponse, ValidateTokenParameters,
};
use crate::api::{Catalog, auth::Auth, error::KeystoneApiError};
use crate::catalog::CatalogApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::token::TokenApi;

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
    skip(state, headers, user_auth, policy)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
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
    let token = state
        .provider
        .get_token_provider()
        .validate_token(
            &state,
            &subject_token,
            query.allow_expired,
            None,
            // Do not expand the token for the policy evaluation
            Some(true),
        )
        .await
        .inspect_err(|e| error!("{:?}", e.to_string()))
        .map_err(|_| KeystoneApiError::NotFound {
            resource: "token".into(),
            identifier: String::new(),
        })?;

    policy
        .enforce(
            "identity/auth/token/show",
            &user_auth,
            to_value(json!({"token": &token}))?,
            None,
        )
        .await?;

    //// Expand the token since we didn't expand it before.
    //token = state
    //    .provider
    //    .get_token_provider()
    //    .expand_token_information(&state, &token)
    //    .await
    //    .map_err(|_| KeystoneApiError::Forbidden)?;

    let mut response_token = ApiResponseToken::from_provider_token(&state, &token).await?;

    if !query.nocatalog.is_some_and(|x| x) {
        let catalog: Catalog = state
            .provider
            .get_catalog_provider()
            .get_catalog(&state, true)
            .await?
            .into();
        response_token.catalog = Some(catalog);
    }

    Ok(TokenResponse {
        token: response_token,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use crate::api::v3::auth::token::types::*;
    use crate::catalog::MockCatalogProvider;
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::UserResponse};
    use crate::keystone::Service;
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types::Domain};
    use crate::tests::api::get_mocked_state_unauthed;
    use crate::token::{
        MockTokenProvider, Token as ProviderToken, TokenProviderError, UnscopedPayload,
    };

    use super::super::{openapi_router, tests::get_policy_factory_mock};

    #[tokio::test]
    async fn test_get() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id: &'_ str| {
            Ok(Some(UserResponse {
                id: id.to_string(),
                domain_id: "user_domain_id".into(),
                ..Default::default()
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_token()
            .returning(|_, _, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .catalog(catalog_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
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
                    .header("x-auth-token", "foo")
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
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_allow_expired() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id: &'_ str| {
            Ok(Some(UserResponse {
                id: id.to_string(),
                domain_id: "user_domain_id".into(),
                ..Default::default()
            }))
        });

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    ..Default::default()
                }))
            });
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "foo")
            .returning(|_, _, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, allow_expired: &Option<bool>, _, _| {
                token == "bar" && *allow_expired == Some(true)
            })
            .returning(|_, _, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_expand_token_information()
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        let mut catalog_mock = MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .identity(identity_mock)
            .resource(resource_mock)
            .token(token_mock)
            .catalog(catalog_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
            .unwrap(),
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?allow_expired=true")
                    .header("x-auth-token", "foo")
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
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "foo")
            .returning(|_, _, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "baz")
            .returning(|_, _, _, _, _| Err(TokenProviderError::Expired));

        let provider = Provider::mocked_builder()
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
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
                    .header("x-auth-token", "foo")
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
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "foo")
            .returning(|_, _, _, _, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "baz")
            .returning(|_, _, _, _, _| Err(TokenProviderError::TokenRevoked));

        let provider = Provider::mocked_builder()
            .token(token_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                get_policy_factory_mock(),
            )
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
                    .header("x-auth-token", "foo")
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
        let state = get_mocked_state_unauthed();

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
