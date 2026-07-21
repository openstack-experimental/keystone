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
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::application_credential::{
    ApplicationCredentialList, ApplicationCredentialListParameters,
};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::application_credential as core_type_application_credential;

#[utoipa::path(
    get,
    path = "/",
    params(ApplicationCredentialListParameters),
    responses(
        (status = OK, description = "List of application credentials", body = ApplicationCredentialList),
        (status = 404, description = "User not found"),
        (status = 403, description = "Forbidden"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "application_credentials"
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    Query(payload): Query<ApplicationCredentialListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;
    let execution_context = ExecutionContext::from_auth(&state, &user_auth);

    // Policy check first
    let mut target = serde_json::to_value(&payload)?;
    target["user_id"] = json!(user_id);
    state
        .policy_enforcer
        .enforce(
            "identity/user/application_credential/list",
            &user_auth,
            json!({"application_credential": target}),
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

    let filter =
        core_type_application_credential::ApplicationCredentialListParametersBuilder::from(payload)
            .user_id(user_id.clone())
            .build()
            .unwrap();
    let application_credentials = state
        .provider
        .get_application_credential_provider()
        .list_application_credentials(&execution_context, &filter)
        .await
        .map_err(KeystoneApiError::from)?;

    Ok((
        StatusCode::OK,
        Json(ApplicationCredentialList {
            application_credentials: application_credentials
                .into_iter()
                .map(Into::into)
                .collect(),
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
    use crate::api::v3::user::application_credential::types::application_credential::ApplicationCredentialList;
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

    fn mock_credentials()
    -> Vec<openstack_keystone_core_types::application_credential::ApplicationCredential> {
        vec![
            CoreApplicationCredentialBuilder::default()
                .id("cred-1")
                .name("first")
                .user_id("uid")
                .project_id("pid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
            CoreApplicationCredentialBuilder::default()
                .id("cred-2")
                .name("second")
                .user_id("uid")
                .project_id("pid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
        ]
    }

    #[traced_test]
    #[tokio::test]
    async fn test_list() {
        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_list_application_credentials()
            .returning(|_, _| Ok(mock_credentials()));

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
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApplicationCredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.application_credentials.len(), 2);
        assert_eq!(res.application_credentials[0].id, "cred-1");
        assert_eq!(res.application_credentials[1].id, "cred-2");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_list_empty() {
        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_list_application_credentials()
            .returning(|_, _| Ok(vec![]));

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
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApplicationCredentialList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.application_credentials.len(), 0);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_list_user_not_found() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
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
                    .uri("/users/uid/application_credentials")
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
    async fn test_list_not_allowed() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials")
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
    async fn test_list_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/users/uid/application_credentials")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
