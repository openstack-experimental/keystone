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
//! User: create.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use validator::Validate;

use super::types::{User, UserCreateRequest, UserResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create user
#[utoipa::path(
    post,
    path = "/",
    description = "Create new user",
    responses(
        (status = CREATED, description = "New user", body = UserResponse),
    ),
    tag="users"
)]
#[tracing::instrument(name = "api::create_user", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<UserCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/user/create",
            &user_auth,
            json!({"user": req.user.to_policy_input()}),
            None,
        )
        .await?;

    let user = state
        .provider
        .get_identity_provider()
        .create_user(&ExecutionContext::from_auth(&state, &user_auth), req.into())
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            user: User::from(user),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use sea_orm::DatabaseConnection;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::policy::{PolicyError, PolicyEvaluationResult};
    use openstack_keystone_core_types::identity::*;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::user::types::{
        UserCreateBuilder as ApiUserCreate, UserCreateRequest, UserResponse as ApiUserResponse,
    };
    use crate::identity::MockIdentityProvider;
    use crate::keystone::{Service, ServiceState};
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .withf(|_, req: &UserCreate| req.domain_id == "domain" && req.name == "name")
            .returning(|_, req| {
                Ok(UserResponseBuilder::default()
                    .id("bar")
                    .domain_id(req.domain_id.clone())
                    .enabled(true)
                    .name(req.name.clone())
                    .build()
                    .unwrap())
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: ApiUserCreate::default()
                .domain_id("domain")
                .name("name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let created_user: ApiUserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(created_user.user.name, user.user.name);
    }

    async fn get_state_with_policy(
        identity_mock: MockIdentityProvider,
        policy_enforcer_mock: MockPolicy,
    ) -> Result<ServiceState, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .build()?;
        let service = Service::new(
            ConfigManager::not_watched(Config::default()),
            DatabaseConnection::Disconnected,
            provider,
            Arc::new(policy_enforcer_mock),
            AuditDispatcher::noop(),
            None,
        )
        .await?;
        Ok(Arc::new(service))
    }

    #[tokio::test]
    async fn test_create_policy_input_omits_password()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        const POLICY_PASSWORD: &str = "CreatePolicyLeak1!";

        let vsc = test_fixture_scoped();
        let identity_mock = MockIdentityProvider::default();

        let mut policy_enforcer_mock = MockPolicy::default();
        policy_enforcer_mock
            .expect_enforce()
            .returning(|_, _, target, existing| {
                assert!(existing.is_none());
                assert!(!target.to_string().contains(POLICY_PASSWORD));
                let user = target.get("user").and_then(Value::as_object);
                assert!(user.is_some_and(|user| !user.contains_key("password")));
                Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
            });
        policy_enforcer_mock
            .expect_health_check()
            .returning(|| Ok(()));

        let state = get_state_with_policy(identity_mock, policy_enforcer_mock).await?;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = json!({
            "user": {
                "domain_id": "domain",
                "enabled": true,
                "name": "name",
                "password": POLICY_PASSWORD
            }
        });

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(user.to_string()))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let vsc = test_fixture_scoped();

        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: ApiUserCreate::default()
                .domain_id("domain")
                .name("name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let user = UserCreateRequest {
            user: ApiUserCreate::default()
                .domain_id("domain")
                .name("name")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .body(Body::from(serde_json::to_string(&user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
