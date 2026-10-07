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
use openstack_keystone_core::keystone::SpiffeHealthStatus;
use openstack_keystone_storage_api::{StorageReadiness, StoreError};

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
    /// Creates a successful Raft status.
    ///
    /// # Returns
    /// A `RaftStatus` indicating the check was successful.
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

/// Health status of the SPIFFE mTLS material (ADR 0016-v2).
///
/// Tracks whether this node's live SPIFFE `X509Source` is still able to
/// present a fresh SVID. A pod that has been running long enough for its
/// SVID/trust bundle to silently drift out of sync with a freshly-joined
/// peer will keep failing peer mTLS handshakes without ever tripping the
/// other health checks (DB/policy/raft can all be fine) — this check exists
/// so k8s notices and restarts the pod instead of it wedging for weeks.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
struct SpiffeStatus {
    /// The error message.
    message: Option<String>,
    /// Status of the SPIFFE mTLS material.
    status: HealthStatus,
}

impl SpiffeStatus {
    pub fn ok() -> Self {
        Self {
            message: None,
            status: HealthStatus::Ok,
        }
    }

    /// Builds an `Error` status from a plain message.
    ///
    /// Used instead of an `err<E: std::error::Error>(...)` constructor
    /// because the underlying
    /// [`openstack_keystone_core::keystone::SpiffeHealthStatus::Error`]
    /// variant only carries a `String` — the real `spiffe::X509SourceError`
    /// is converted to a message inside the `crates/keystone`-local closure
    /// that builds it, since `core` must not depend on the `spiffe` crate.
    pub fn err_msg<M>(message: M) -> Self
    where
        M: Into<String>,
    {
        Self {
            message: Some(message.into()),
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
    /// Status of the SPIFFE mTLS material.
    spiffe: SpiffeStatus,
}

impl HealthComponents {
    /// Return the overall health status of the system taking the highest status
    /// among all components.
    pub fn overall_status(&self) -> HealthStatus {
        self.raft
            .status
            .max(self.database.status)
            .max(self.policy.status)
            .max(self.spiffe.status)
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
/// Perform relevant checks only returning `OK` when all of them are ok. Any
/// check in the degraded/warn state would result in `SERVICE_UNAVAILABLE`
/// response.
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
        spiffe: check_spiffe(&state).await,
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
/// Perform diverse checks to identify the overall status of the system. It can
/// be `OK`, `SERVICE_UNAVAILABLE`. In difference to the `/ready` check this
/// does not return `SERVICE_UNAVAILABLE` when components are in the degraded
/// state to prevent from the restart. It is similar to the `/live` check.
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
        spiffe: check_spiffe(&state).await,
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
    match state.db.connection().ping().await {
        Ok(()) => DatabaseStatus::ok(),
        Err(err) => DatabaseStatus::err(err),
    }
}

/// Perform Raft storage checks.
///
/// Reports `warn` (so `/ready` returns `SERVICE_UNAVAILABLE` while `/health`
/// stays `OK` and the pod is not restarted) when the cluster is not
/// initialized, or when the node should not receive traffic: no leader is
/// known, the leader lost quorum contact, the applied index lags the cluster
/// commit index (snapshot install, catch-up after a partition, or a DEK epoch
/// not yet applied), or a partition is quarantined. All of these recover on
/// their own, so they are not fatal to the process.
///
/// A Raft core that has stopped (fatal storage error, panic, or shutdown)
/// cannot recover: `readiness` returns an error for it, which maps to
/// `error` here so `/health` fails and the liveness probe restarts the pod.
async fn check_storage(state: &ServiceState) -> RaftStatus {
    let Some(storage) = state.storage.as_deref() else {
        return RaftStatus::skipped();
    };
    raft_status(storage.readiness().await)
}

/// Maps a storage readiness report to the Raft health component status.
fn raft_status(readiness: Result<StorageReadiness, StoreError>) -> RaftStatus {
    match readiness {
        Ok(readiness) if !readiness.initialized => RaftStatus::warn("storage is not initialized"),
        Ok(readiness) if readiness.issues.is_empty() => RaftStatus::ok(),
        Ok(readiness) => RaftStatus::warn(readiness.issues.join("; ")),
        Err(err) => RaftStatus::err(err),
    }
}

/// Perform policy health checks.
async fn check_policy_engine(state: &ServiceState) -> PolicyStatus {
    match state.policy_enforcer.health_check().await {
        Ok(()) => PolicyStatus::ok(),
        Err(_) => PolicyStatus::warn("policy not enforced"),
    }
}

/// Perform SPIFFE mTLS material health checks.
///
/// Returns `skipped` when no SPIFFE health-check hook has been installed on
/// this node (no SPIFFE mTLS interface configured — see
/// `Service::set_spiffe_health_check`). Otherwise calls the installed hook,
/// which queries the live `spiffe::X509Source`'s own reported health/expiry
/// rather than attempting a real loopback mTLS handshake, mirroring
/// `check_storage`'s `is_initialized()`-only approach. `core` (and thus the
/// `SpiffeHealthStatus` type this maps from) has no dependency on the
/// `spiffe` crate — the actual `X509Source` inspection happens in the
/// closure built by `crates/keystone/src/bin/keystone.rs`:
///
/// * `err` — the source itself is unreachable/closed.
/// * `warn` — the source is open but its current SVID/material is stale or
///   expired; this is exactly the incident scenario: a 40-day-old pod whose
///   SVID silently drifted out of sync with a freshly-joined peer.
/// * `ok` — the source is open and reports healthy, current material.
async fn check_spiffe(state: &ServiceState) -> SpiffeStatus {
    let guard = state.spiffe_health_check.read().await;
    let Some(check) = guard.as_ref() else {
        return SpiffeStatus::skipped();
    };

    match check() {
        SpiffeHealthStatus::Ok => SpiffeStatus::ok(),
        SpiffeHealthStatus::Warn(msg) => SpiffeStatus::warn(msg),
        SpiffeHealthStatus::Error(msg) => SpiffeStatus::err_msg(msg),
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
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let (router, _api) = super::super::metrics_router().split_for_parts();
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
    fn raft_status_reflects_storage_readiness() {
        assert_eq!(
            raft_status(Ok(StorageReadiness {
                initialized: true,
                issues: vec![],
            })),
            RaftStatus::ok()
        );
        assert_eq!(
            raft_status(Ok(StorageReadiness {
                initialized: false,
                issues: vec![],
            })),
            RaftStatus::warn("storage is not initialized")
        );
        assert_eq!(
            raft_status(Ok(StorageReadiness {
                initialized: true,
                issues: vec![
                    "no raft leader known".into(),
                    "quarantined partitions: data".into()
                ],
            })),
            RaftStatus::warn("no raft leader known; quarantined partitions: data")
        );
        assert_eq!(
            raft_status(Err(StoreError::other("boom"))).status,
            HealthStatus::Error
        );
    }

    #[test]
    fn test_overall_status() {
        let dummy_err = || std::io::Error::other("dummy error");
        assert_eq!(
            HealthStatus::Ok,
            HealthComponents {
                raft: RaftStatus::ok(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok(),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Ok,
            HealthComponents {
                raft: RaftStatus::skipped(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok(),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Warn,
            HealthComponents {
                raft: RaftStatus::warn("warn"),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::ok(),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Warn,
            HealthComponents {
                raft: RaftStatus::skipped(),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::warn(""),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Error,
            HealthComponents {
                raft: RaftStatus::err(dummy_err()),
                database: DatabaseStatus::ok(),
                policy: PolicyStatus::warn(""),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
        assert_eq!(
            HealthStatus::Error,
            HealthComponents {
                raft: RaftStatus::ok(),
                database: DatabaseStatus::err(dummy_err()),
                policy: PolicyStatus::ok(),
                spiffe: SpiffeStatus::skipped(),
            }
            .overall_status()
        );
    }
}
