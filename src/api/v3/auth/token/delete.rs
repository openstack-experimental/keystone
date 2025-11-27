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
//! Revoke the authentication token.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::{json, to_value};
use tracing::error;

use crate::api::{auth::Auth, error::KeystoneApiError};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;
use crate::revoke::RevokeApi;
use crate::token::TokenApi;

/// Revoke token.
///
/// Revokes a token.
///
/// This call is similar to the HEAD /auth/tokens call except that the
/// `X-Subject-Token` token is immediately not valid, regardless of the
/// expires_at attribute value. An additional `X-Auth-Token` is not required.
#[utoipa::path(
    delete,
    path = "/",
    responses(
        (status = 204, description = "Token has been revoked."),
    ),
    tag="auth"
)]
#[tracing::instrument(
    name = "api::v3::token::delete",
    level = "debug",
    skip(state, headers, user_auth, policy)
)]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    mut policy: Policy,
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
        .validate_token(&state, &subject_token, None, None, None)
        .await
        .inspect_err(|e| error!("{:?}", e.to_string()))
        .map_err(|_| KeystoneApiError::NotFound {
            resource: "token".into(),
            identifier: String::new(),
        })?;

    policy
        .enforce(
            "identity/auth/token/revoke",
            &user_auth,
            to_value(json!({"token": &token}))?,
            None,
        )
        .await?;

    state
        .provider
        .get_revoke_provider()
        .revoke_token(&state, &token)
        .await
        .map_err(|_| KeystoneApiError::Forbidden)?;

    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use crate::config::Config;
    use crate::keystone::Service;
    use crate::provider::Provider;
    use crate::revoke::MockRevokeProvider;
    use crate::token::{
        MockTokenProvider, Token as ProviderToken, TokenProviderError, UnscopedPayload,
    };

    use super::super::{openapi_router, tests::get_policy_factory_mock};

    fn get_prepopulated_token_mock() -> MockTokenProvider {
        let decoded_auth_token = ProviderToken::Unscoped(UnscopedPayload {
            user_id: "bar".into(),
            ..Default::default()
        });

        let mut token_mock = MockTokenProvider::default();
        // x-auth-token validated
        let decoded_auth_token_clone1 = decoded_auth_token.clone();
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "foo")
            .returning(move |_, _, _, _, _| Ok(decoded_auth_token_clone1.clone()));
        // auth-token expanded
        let decoded_auth_token_clone2 = decoded_auth_token.clone();
        token_mock
            .expect_expand_token_information()
            .withf(move |_, token: &ProviderToken| *token == decoded_auth_token_clone2.clone())
            .returning(|_, _| {
                Ok(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
            });
        // auth-token roles populated
        let decoded_auth_token_clone3 = decoded_auth_token.clone();
        token_mock
            .expect_populate_role_assignments()
            .withf(move |_, token: &ProviderToken| *token == decoded_auth_token_clone3.clone())
            .returning(|_, _| Ok(()));

        token_mock
    }

    #[tokio::test]
    async fn test_delete() {
        let decoded_subject_token = ProviderToken::Unscoped(UnscopedPayload {
            user_id: "foobar".into(),
            ..Default::default()
        });
        let mut token_mock = get_prepopulated_token_mock();

        // subject token validated
        let decoded_subject_token_clone = decoded_subject_token.clone();
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "baz")
            .returning(move |_, _, _, _, _| Ok(decoded_subject_token_clone.clone()));

        let mut revoke_mock = MockRevokeProvider::default();
        // subject token revoked
        let decoded_subject_token_clone2 = decoded_subject_token.clone();
        revoke_mock
            .expect_revoke_token()
            .withf(move |_, token: &ProviderToken| *token == decoded_subject_token_clone2.clone())
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .token(token_mock)
            .revoke(revoke_mock)
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
                    .method("DELETE")
                    .header("x-auth-token", "foo")
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_expired() {
        let mut token_mock = get_prepopulated_token_mock();
        // subject token validated
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "baz")
            .returning(move |_, _, _, _, _| Err(TokenProviderError::Expired));

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
                    .method("DELETE")
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
    async fn test_delete_revoked() {
        let mut token_mock = get_prepopulated_token_mock();
        // subject token validated
        token_mock
            .expect_validate_token()
            .withf(|_, token: &'_ str, _, _, _| token == "baz")
            .returning(move |_, _, _, _, _| Err(TokenProviderError::TokenRevoked));

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
                    .method("DELETE")
                    .header("x-auth-token", "foo")
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
