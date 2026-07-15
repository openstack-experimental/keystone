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
use validator::Validate;

use super::types::application_credential::{
    ApplicationCredentialCreateRequest, ApplicationCredentialCreateResponse,
};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::application_credential as core_type_application_credential;
use openstack_keystone_core_types::auth::ScopeInfo;
/// Create application credential.
///
/// POST /v3/users/{user_id}/application_credentials
#[utoipa::path(
    post,
    path = "/",
    request_body = ApplicationCredentialCreateRequest,
    responses(
        (status = CREATED, description = "Application credential created", body = ApplicationCredentialCreateResponse),
        (status = 400, description = "Bad request — validation error or role not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Conflict — application credential already exists"),
    ),
    tag = "application_credentials"
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(payload): Json<ApplicationCredentialCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;
    let execution_context = ExecutionContext::from_auth(&state, &user_auth);

    // project_id must come from the token scope, not the request body
    let project_id = match user_auth.authorization().map(|a| &a.scope) {
        Some(ScopeInfo::Project { project, .. }) => project.id.clone(),
        _ => {
            return Err(KeystoneApiError::BadRequest(
                "application credentials require a project-scoped token".into(),
            ));
        }
    };

    let mut target = serde_json::to_value(&payload.application_credential)?;
    target["user_id"] = json!(user_id);

    state
        .policy_enforcer
        .enforce(
            "identity/user/application_credential/create",
            &user_auth,
            json!({"application_credential": target}),
            None,
        )
        .await?;

    let app_cred = core_type_application_credential::ApplicationCredentialCreateBuilder::from(
        payload.application_credential,
    )
    .user_id(user_id.clone())
    .project_id(project_id)
    .build()
    .unwrap();

    // Verify user exists — 404 if not found
    state
        .provider
        .get_identity_provider()
        .get_user(&execution_context, &user_id)
        .await?
        .ok_or_else(|| KeystoneApiError::not_found("user", &user_id))?;

    let created = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(&execution_context, app_cred)
        .await
        .map_err(KeystoneApiError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(ApplicationCredentialCreateResponse {
            application_credential: created.into(),
        }),
    ))
}
#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::application_credential::ApplicationCredentialCreateResponseBuilder;
    use openstack_keystone_core_types::identity::*;
    use secrecy::SecretString;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::openapi_router;
    use crate::api::v3::user::application_credential::types::application_credential::{
        ApplicationCredentialCreateBuilder, ApplicationCredentialCreateRequest,
        ApplicationCredentialCreateResponse,
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

    fn mock_create_response()
    -> openstack_keystone_core_types::application_credential::ApplicationCredentialCreateResponse
    {
        ApplicationCredentialCreateResponseBuilder::default()
            .id("new-cred-id")
            .name("my-cred")
            .user_id("uid")
            .project_id("pid")
            .unrestricted(false)
            .roles(vec![])
            .secret(SecretString::new("generated-secret".into()))
            .build()
            .unwrap()
    }

    fn request_body() -> String {
        let req = ApplicationCredentialCreateRequest {
            application_credential: ApplicationCredentialCreateBuilder::default()
                .name("my-cred")
                .roles(vec![])
                .build()
                .unwrap(),
        };
        serde_json::to_string(&req).unwrap()
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_create_application_credential()
            .returning(|_, _| Ok(mock_create_response()));

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
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApplicationCredentialCreateResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.application_credential.id, "new-cred-id");
        assert_eq!(res.application_credential.name, "my-cred");
        // secret must be present in create response
        assert!(!res.application_credential.secret.is_empty());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create_user_not_found() {
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
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create_role_not_found() {
        use openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError;

        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_create_application_credential()
            .returning(|_, _| {
                Err(ApplicationCredentialProviderError::RoleNotFound(
                    "role-id".to_string(),
                ))
            });

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
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Role not found → 404 per OpenStack spec
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create_conflict() {
        use openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError;

        let mut identity_mock = MockIdentityProvider::default();
        mock_user(&mut identity_mock);

        let mut app_cred_mock = MockApplicationCredentialProvider::default();
        app_cred_mock
            .expect_create_application_credential()
            .returning(|_, _| {
                Err(ApplicationCredentialProviderError::Conflict(
                    "already exists".to_string(),
                ))
            });

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
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create_not_allowed() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let response = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/users/uid/application_credentials")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
