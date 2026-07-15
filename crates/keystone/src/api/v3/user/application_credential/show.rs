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

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::application_credential::ApplicationCredentialResponse;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

#[utoipa::path(
    get,
    path = "/{application_credential_id}",
    params(),
    responses(
        (status = OK, description = "Single application credential", body = ApplicationCredentialResponse),
        (status = 404, description = "Application credential or user not found"),
        (status = 403, description = "Forbidden"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "application_credentials"
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path((user_id, application_credential_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let execution_context = ExecutionContext::from_auth(&state, &user_auth);

    // Fetch credential first — needed for policy
    let current = state
        .provider
        .get_application_credential_provider()
        .get_application_credential(&execution_context, &application_credential_id)
        .await
        .map_err(KeystoneApiError::from)?
        .ok_or_else(|| {
            KeystoneApiError::not_found("application_credential", &application_credential_id)
        })?;

    // Policy check — uses stored object's real user_id
    state
        .policy_enforcer
        .enforce(
            "identity/user/application_credential/show",
            &user_auth,
            json!({"application_credential": serde_json::to_value(&current)?}),
            None,
        )
        .await?;

    // Verify user exists
    state
        .provider
        .get_identity_provider()
        .get_user(&execution_context, &user_id)
        .await?
        .ok_or_else(|| KeystoneApiError::not_found("user", &user_id))?;

    Ok((
        StatusCode::OK,
        Json(ApplicationCredentialResponse {
            application_credential: current.into(),
        }),
    ))
}
#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder as CoreApplicationCredentialBuilder;
    use openstack_keystone_core_types::identity::*;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::openapi_router;
    use crate::api::v3::user::application_credential::types::application_credential::{
        ApplicationCredentialBuilder as ApiApplicationCredentialBuilder,
        ApplicationCredentialResponse,
    };
    use crate::application_credential::MockApplicationCredentialProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;

    fn mock_user(mock: &mut MockIdentityProvider) {
        mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .domain_id("did")
                    .enabled(true)
                    .name("test_user")
                    .build()
                    .unwrap(),
            ))
        });
    }

    fn mock_credential()
    -> openstack_keystone_core_types::application_credential::ApplicationCredential {
        CoreApplicationCredentialBuilder::default()
            .id("existing-id")
            .name("test-cred")
            .user_id("uid")
            .project_id("pid")
            .unrestricted(false)
            .roles(vec![])
            .build()
            .unwrap()
    }

    #[traced_test]
    #[tokio::test]
    async fn test_show() {
        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_get_application_credential()
            .withf(|_, id: &'_ str| id == "existing-id")
            .returning(|_, _| Ok(Some(mock_credential())));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_application_credential(app_cred_mock),
            true,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials/existing-id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApplicationCredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiApplicationCredentialBuilder::default()
                .id("existing-id")
                .name("test-cred")
                .project_id("pid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
            res.application_credential,
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_show_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_get_application_credential()
            .returning(|_, _| Ok(Some(mock_credential())));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_application_credential(app_cred_mock),
            true,
            None,
        )
        .await;
        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials/existing-id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_show_credential_not_found() {
        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_get_application_credential()
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_application_credential(app_cred_mock),
            true,
            None,
        )
        .await;
        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials/non-existing-id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_show_not_allowed() {
        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_get_application_credential()
            .returning(|_, _| Ok(Some(mock_credential())));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_application_credential(app_cred_mock),
            false,
            None,
        )
        .await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials/existing-id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials/existing-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
