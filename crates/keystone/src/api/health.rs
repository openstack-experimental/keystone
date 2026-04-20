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
//! # Keystone health check
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

/// The health status.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[repr(usize)]
enum HealthStatus {
    /// The check has been skipped.
    Skipped = 0,
    /// Up and running.
    Ok = 1,
    /// Warn.
    Warn = 2,
    /// Error.
    Error = 3,
}

/// Health status of the Raft storage.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
struct RaftStatus {
    /// The error message.
    message: Option<String>,
    /// Status of Raft cluster.
    status: HealthStatus,
}

impl RaftStatus {
    pub fn ok() -> Self {
        Self {
            message: None,
            status: HealthStatus::Ok,
        }
    }

    pub fn err<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            message: Some(error.to_string()),
            status: HealthStatus::Error,
        }
    }

    pub fn skipped() -> Self {
        Self {
            message: None,
            status: HealthStatus::Skipped,
        }
    }

    pub fn warn<M>(message: M) -> Self
    where
        M: Into<String>,
    {
        Self {
            message: Some(message.into()),
            status: HealthStatus::Warn,
        }
    }
}

/// Health status of the database.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
struct DatabaseStatus {
    /// The error message.
    message: Option<String>,
    /// Status of database.
    status: HealthStatus,
}

impl DatabaseStatus {
    pub fn ok() -> Self {
        Self {
            message: None,
            status: HealthStatus::Ok,
        }
    }

    pub fn err<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            message: Some(error.to_string()),
            status: HealthStatus::Error,
        }
    }
}

/// Health status of the policy engine.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
struct PolicyStatus {
    /// The error message.
    message: Option<String>,
    /// Status of Raft cluster.
    status: HealthStatus,
}

impl PolicyStatus {
    pub fn ok() -> Self {
        Self {
            message: None,
            status: HealthStatus::Ok,
        }
    }

    pub fn warn<M>(message: M) -> Self
    where
        M: Into<String>,
    {
        Self {
            message: Some(message.into()),
            status: HealthStatus::Warn,
        }
    }
}

/// The health components of the system.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
struct HealthComponents {
    /// Status of the raft storage.
    raft: RaftStatus,
    /// Status of the database.
    database: DatabaseStatus,
    /// Status of the policy enforcement engine.
    policy: PolicyStatus,
}

impl HealthComponents {
    /// Return the overall health status of the system taking the highest status among all
    /// components.
    pub fn overall_status(&self) -> HealthStatus {
        self.raft
            .status
            .max(self.database.status)
            .max(self.policy.status)
    }
}

/// Health check response.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct HealthResponse {
    /// Overall health status of the system.
    status: HealthStatus,
    /// Individual health checks.
    components: HealthComponents,
}

/// Health check router.
pub fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(ready))
}

/// Readiness health check endpoint.
///
/// Perform relevant checks only returning `OK` when all of them are ok. Any check in the
/// degraded/warn state would result in `SERVICE_UNAVAILABLE` response.
#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = OK, description = "Service is healthy", body = HealthResponse),
        (status = SERVICE_UNAVAILABLE, description = "Service is unhealthy", body = HealthResponse),
    ),
    tag = "health"
)]
async fn ready(State(state): State<ServiceState>) -> impl IntoResponse {
    let components = HealthComponents {
        database: check_database(&state).await,
        policy: check_policy_engine(&state).await,
        raft: check_storage(&state).await,
    };

    let status = components.overall_status();

    let status_code = match status {
        HealthStatus::Skipped => StatusCode::OK,
        HealthStatus::Ok => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(HealthResponse { status, components })).into_response()
}

/// Health check endpoint.
///
/// Perform diverse checks to identify the overall status of the system. It can be `OK`,
/// `SERVICE_UNAVAILABLE`. In difference to the `/ready` check this does not return
/// `SERVICE_UNAVAILABLE` when components are in the degraded state to prevent from the restart. It
/// is similar to the `/live` check.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = OK, description = "Service is healthy", body = HealthResponse),
        (status = SERVICE_UNAVAILABLE, description = "Service is unhealthy", body = HealthResponse),
    ),
    tag = "health"
)]
async fn health(State(state): State<ServiceState>) -> impl IntoResponse {
    let components = HealthComponents {
        database: check_database(&state).await,
        policy: check_policy_engine(&state).await,
        raft: check_storage(&state).await,
    };

    let status = components.overall_status();

    let status_code = match status {
        HealthStatus::Skipped => StatusCode::OK,
        HealthStatus::Ok => StatusCode::OK,
        HealthStatus::Warn => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(HealthResponse { status, components })).into_response()
}

/// Perform DB related checks.
async fn check_database(state: &ServiceState) -> DatabaseStatus {
    match state.db.ping().await {
        Ok(()) => DatabaseStatus::ok(),
        Err(err) => DatabaseStatus::err(err),
    }
}

/// Perform Raft storage checks.
async fn check_storage(state: &ServiceState) -> RaftStatus {
    match &state.storage {
        None => RaftStatus::skipped(),
        Some(storage) => {
            // TODO: many more raft checks should be processed here (e.g., log state,
            // connection to the leader, storage readiness, etc).
            match storage.raft.is_initialized().await {
                Ok(true) => RaftStatus::ok(),
                Ok(false) => RaftStatus::warn("storage is not initialized"),
                Err(err) => RaftStatus::err(err),
            }
        }
    }
}

/// Perform policy health checks.
async fn check_policy_engine(state: &ServiceState) -> PolicyStatus {
    match state.policy_enforcer.health_check().await {
        Ok(()) => PolicyStatus::ok(),
        Err(_) => PolicyStatus::warn("policy not enforced"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::super::tests::get_mocked_state;
    use super::*;
    use crate::api::health::HealthComponents;
    use crate::provider::Provider;

    #[tokio::test]
    async fn health_returns_service_unavailable_for_disconnected_db() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None, None).await;
        let (router, _api) = super::super::openapi_router().split_for_parts();
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

    #[test]
    fn test_overall_status() {
        let dummy_err = || std::io::Error::new(std::io::ErrorKind::Other, "dummy error");
        assert_eq!(
            HealthStatus::Ok,
            HealthComponents {
                raft: RaftStatus::ok(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok()
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Ok,
            HealthComponents {
                raft: RaftStatus::skipped(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok()
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Warn,
            HealthComponents {
                raft: RaftStatus::warn("warn"),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok()
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Warn,
            HealthComponents {
                raft: RaftStatus::skipped(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::warn("")
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Error,
            HealthComponents {
                raft: RaftStatus::err(dummy_err()),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::warn("")
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Error,
            HealthComponents {
                raft: RaftStatus::ok(),
                database: DatabaseStatus::err(dummy_err()),
                policy: PolicyStatus::ok()
            }
            .overall_status()
        );
    }
}
