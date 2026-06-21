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
use serde_json::{json, to_value};
use tracing::error;

use crate::api::{auth::Auth, error::KeystoneApiError};
use crate::keystone::ServiceState;
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
    skip(state, headers, user_auth)
)]
pub(super) async fn delete(
    Auth(user_auth): Auth,
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
        .validate_to_context(&state, &subject_token, None, None)
        .await
        .inspect_err(|e| error!("{:?}", e.to_string()))
        .map_err(|_| KeystoneApiError::NotFound {
            resource: "token".into(),
            identifier: String::new(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/auth/token/revoke",
            &user_auth,
            to_value(json!({"token": &vsc.token()?}))?,
            None,
        )
        .await?;

    state
        .provider
        .get_revoke_provider()
        .revoke_token(&state, vsc.token()?)
        .await
        .map_err(KeystoneApiError::forbidden)?;

    Ok((StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, mocked_builder, test_fixture_scoped};

    use crate::revoke::MockRevokeProvider;
    use crate::token::{FernetToken as ProviderToken, MockTokenProvider, TokenProviderError};

    fn get_prepopulated_context() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::auth::{AuthzInfoBuilder, *};
        use openstack_keystone_core_types::resource::Domain as CoreDomain;
        use openstack_keystone_core_types::token::UnscopedPayload;

        let user_domain = CoreDomain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };

        let authz = AuthzInfoBuilder::default()
            .scope(ScopeInfo::Unscoped)
            .build()
            .unwrap();

        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(
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
                .token(ProviderToken::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    ..Default::default()
                }))
                .authorization(authz)
                .build(),
        )
    }

    fn get_prepopulated_token_mock() -> MockTokenProvider {
        let vsc = get_prepopulated_context();

        let mut token_mock = MockTokenProvider::default();
        // x-auth-token validated via validate_to_context
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "foo")
            .returning(move |_, _, _, _| Ok(vsc.clone()));

        token_mock
    }

    #[tokio::test]
    async fn test_delete() {
        use openstack_keystone_core_types::auth::{AuthzInfoBuilder, *};
        use openstack_keystone_core_types::resource::Domain as CoreDomain;
        use openstack_keystone_core_types::token::UnscopedPayload;

        let user_domain = CoreDomain {
            id: "user_domain_id".into(),
            enabled: true,
            ..Default::default()
        };

        let vsc_for_mock = {
            let authz = AuthzInfoBuilder::default()
                .scope(ScopeInfo::Unscoped)
                .build()
                .unwrap();
            openstack_keystone_core::auth::ValidatedSecurityContext::test_new(
                SecurityContext::test_build()
                    .authentication_context(AuthenticationContext::Password)
                    .principal(PrincipalInfo {
                        identity: IdentityInfo::User(
                            UserIdentityInfoBuilder::default()
                                .user_id("foobar")
                                .user_domain(user_domain)
                                .build()
                                .unwrap(),
                        ),
                    })
                    .token(ProviderToken::Unscoped(UnscopedPayload {
                        user_id: "foobar".into(),
                        ..Default::default()
                    }))
                    .authorization(authz)
                    .build(),
            )
        };

        let fernet_for_revoke = vsc_for_mock.inner().token().unwrap().clone();

        let mut token_mock = get_prepopulated_token_mock();

        // subject token validated
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(move |_, _, _, _| Ok(vsc_for_mock.clone()));

        let mut revoke_mock = MockRevokeProvider::default();
        // subject token revoked
        revoke_mock
            .expect_revoke_token()
            .withf(move |_, token: &ProviderToken| *token == fernet_for_revoke)
            .returning(|_, _| Ok(()));

        let provider = mocked_builder()
            .mock_token(token_mock)
            .mock_revoke(revoke_mock);

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
                    .method("DELETE")
                    .extension(vsc)
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
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(move |_, _, _, _| Err(TokenProviderError::Expired));

        let provider = mocked_builder().mock_token(token_mock);

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
                    .method("DELETE")
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
    async fn test_delete_revoked() {
        let mut token_mock = get_prepopulated_token_mock();
        // subject token validated
        token_mock
            .expect_validate_to_context()
            .withf(|_, token: &'_ str, _, _| token == "baz")
            .returning(move |_, _, _, _| Err(TokenProviderError::TokenRevoked));

        let provider = mocked_builder().mock_token(token_mock);
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
                    .method("DELETE")
                    .extension(vsc)
                    .header("x-subject-token", "baz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
