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
//! # Keystone API
//!
//! Keystone is following the API first principles. The user or other services
//! interact with it using the API.
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;
use utoipa::{
    Modify, OpenApi, ToSchema,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

pub mod auth;
pub(crate) mod common;
pub mod error;
pub mod types;
pub mod v3;
pub mod v4;

use crate::api::types::*;

/// OpenApi specification.
#[derive(OpenApi)]
#[openapi(
    info(version = "4.0.1"),
    modifiers(&SecurityAddon),
    nest(
      (path = "v3", api = v3::ApiDoc),
      (path = "v4", api = v4::ApiDoc),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "x-auth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-auth-token"))),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum HealthStatus {
    Ok,
    Error,
    Skipped,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct HealthDependency {
    name: String,
    status: HealthStatus,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
struct HealthResponse {
    status: HealthStatus,
    dependencies: Vec<HealthDependency>,
}

impl HealthDependency {
    fn new(name: &str, status: HealthStatus, error: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            status,
            error,
        }
    }
}

/// Main API router.
pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .nest("/v3", v3::openapi_router())
        .nest("/v4", v4::openapi_router())
        .routes(routes!(version))
        .routes(routes!(health))
}

/// Version discovery endpoint.
#[utoipa::path(
    get,
    path = "/",
    description = "Version discovery",
    responses(
        (status = OK, description = "Versions", body = Versions),
    ),
    tag = "version"
)]
async fn version(
    headers: HeaderMap,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let host = state
        .config
        .default
        .public_endpoint
        .clone()
        .map(|x| x.to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|header| header.to_str().map(|val| format!("http://{val}")).ok())
        })
        .unwrap_or_else(|| "http://localhost".to_string());

    let res = Versions {
        versions: Values {
            values: vec![
                VersionBuilder::default()
                    .id("v3.14")
                    .status(VersionStatus::Stable)
                    .links(vec![Link::new(format!("{host}/v3"))])
                    .media_types(vec![MediaType::default()])
                    .build()?,
                VersionBuilder::default()
                    .id("v4.0")
                    .status(VersionStatus::Stable)
                    .links(vec![Link::new(format!("{host}/v4"))])
                    .media_types(vec![MediaType::default()])
                    .build()?,
            ],
        },
    };
    Ok((StatusCode::OK, Json(res)).into_response())
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/health",
    description = "Health check for Keystone and its dependencies",
    responses(
        (status = OK, description = "Service is healthy", body = HealthResponse),
        (status = SERVICE_UNAVAILABLE, description = "Service is unhealthy", body = HealthResponse),
    ),
    tag = "health"
)]
async fn health(State(state): State<ServiceState>) -> impl IntoResponse {
    let mut dependencies = Vec::new();

    let db_status = match check_database(&state).await {
        Ok(()) => HealthDependency::new("database", HealthStatus::Ok, None),
        Err(err) => HealthDependency::new("database", HealthStatus::Error, Some(err)),
    };
    dependencies.push(db_status);

    let policy_status = if state.config.api_policy.enable {
        match state.policy_enforcer.health_check().await {
            Ok(()) => HealthDependency::new("policy", HealthStatus::Ok, None),
            Err(err) => HealthDependency::new("policy", HealthStatus::Error, Some(err.to_string())),
        }
    } else {
        HealthDependency::new("policy", HealthStatus::Skipped, None)
    };
    dependencies.push(policy_status);

    let storage_status = match &state.storage {
        None => HealthDependency::new("distributed_storage", HealthStatus::Skipped, None),
        Some(storage) => match storage.raft.is_initialized().await {
            Ok(true) => HealthDependency::new("distributed_storage", HealthStatus::Ok, None),
            Ok(false) => HealthDependency::new(
                "distributed_storage",
                HealthStatus::Error,
                Some("storage not initialized".to_string()),
            ),
            Err(err) => HealthDependency::new(
                "distributed_storage",
                HealthStatus::Error,
                Some(err.to_string()),
            ),
        },
    };
    dependencies.push(storage_status);

    let status = if dependencies
        .iter()
        .any(|dep| dep.status == HealthStatus::Error)
    {
        HealthStatus::Error
    } else {
        HealthStatus::Ok
    };

    let status_code = match status {
        HealthStatus::Ok => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (
        status_code,
        Json(HealthResponse {
            status,
            dependencies,
        }),
    )
        .into_response()
}

async fn check_database(state: &ServiceState) -> Result<(), String> {
    state.db.ping().await.map_err(|err| err.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;
    use tower::ServiceExt;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::{Provider, ProviderBuilder};
    use crate::token::{MockTokenProvider, Token, UnscopedPayload};

    pub async fn get_mocked_state(
        provider_builder: ProviderBuilder,
        policy_allowed: bool,
        policy_allowed_see_other_domains: Option<bool>,
        skip_default_token_provider: Option<bool>,
    ) -> ServiceState {
        let provider = if !skip_default_token_provider.is_some_and(|x| x) {
            let mut token_mock = MockTokenProvider::default();
            token_mock.expect_validate_token().returning(|_, _, _, _| {
                Ok(Token::Unscoped(UnscopedPayload {
                    user_id: "bar".into(),
                    user: Some(
                        UserResponseBuilder::default()
                            .id("bar")
                            .domain_id("udid")
                            .enabled(true)
                            .name("name")
                            .build()
                            .unwrap(),
                    ),
                    ..Default::default()
                }))
            });
            token_mock
                .expect_expand_token_information()
                .returning(|_, _| {
                    Ok(Token::Unscoped(UnscopedPayload {
                        user_id: "bar".into(),
                        ..Default::default()
                    }))
                });
            provider_builder.mock_token(token_mock)
        } else {
            provider_builder
        }
        .build()
        .unwrap();

        let mut policy_enforcer_mock = MockPolicy::default();

        policy_enforcer_mock
            .expect_enforce()
            .returning(move |_, _, _, _| {
                if policy_allowed {
                    if policy_allowed_see_other_domains.is_some_and(|x| x) {
                        Ok(PolicyEvaluationResult::allowed_admin())
                    } else {
                        Ok(PolicyEvaluationResult::allowed())
                    }
                } else {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                }
            });

        policy_enforcer_mock
            .expect_health_check()
            .returning(|| Ok(()));

        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(policy_enforcer_mock),
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn health_returns_service_unavailable_for_disconnected_db() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None, None).await;
        let (router, _api) = super::openapi_router().split_for_parts();
        let app = router.with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
