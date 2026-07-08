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
//! SCIM resource janitor: permanent purge of tombstoned Users/Groups past
//! the configured retention window (ADR 0024 §6.C).
//!
//! Mirrors the leader-gated background sweep pattern already used by
//! `crates/core/src/api_key/janitor.rs`: [`spawn`] runs on every cluster
//! node on a fixed interval, but [`run_once`]'s work only actually executes
//! when that node is the current Raft leader, so exactly one purge -- and
//! one audit record -- is produced per resource per retention crossing.
//!
//! [`purge_now`] is the operator-triggered erasure-request path (ADR 0024
//! §6.C, last paragraph): it purges a single already-deprovisioned resource
//! immediately, bypassing the configured retention window.

use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::scim::{ScimResourceIndex, ScimResourceType};

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;
use crate::scim_resource::error::ScimResourceProviderError;

/// Interval between sweep passes. Retention is day-granularity, so this is
/// deliberately coarse -- it only needs to run often enough to keep
/// wall-clock drift against the configured threshold small.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Outcome of a single sweep pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JanitorReport {
    /// Tombstoned resources physically purged this pass.
    pub purged: usize,
    /// Purge attempts that failed this pass (e.g. a Raft CAS conflict with
    /// a concurrent write, or the underlying Identity row already gone).
    /// Failures are isolated per resource -- one failing resource does not
    /// prevent the rest of the sweep from running -- and are retried on the
    /// next pass.
    pub errors: usize,
}

/// Run a single janitor sweep pass over every domain's SCIM resources.
/// Idempotent and safe to call repeatedly: a resource already purged is
/// simply not matched again on the next pass (it no longer appears in
/// [`crate::scim_resource::ScimResourceApi::list_all_index`]).
///
/// Only `list_all_index` failing aborts the whole pass (there is nothing to
/// sweep without it); a failure purging one resource is logged and counted
/// in [`JanitorReport::errors`], and the pass continues with the remaining
/// resources.
pub async fn run_once(state: &ServiceState) -> Result<JanitorReport, ScimResourceProviderError> {
    let cfg = state
        .config_manager
        .config
        .read()
        .await
        .scim_resource
        .clone();
    let retention_secs = i64::from(cfg.janitor_deprovisioned_retention_days) * 86_400;
    let now = Utc::now().timestamp();

    let ctx = ExecutionContext::internal(state);
    let mut report = JanitorReport::default();

    let all = state
        .provider
        .get_scim_resource_provider()
        .list_all_index(&ctx)
        .await?;

    for idx in all {
        let Some(deprovisioned_at) = idx.deprovisioned_at else {
            continue;
        };
        if now - deprovisioned_at <= retention_secs {
            continue;
        }

        match purge_one(state, &ctx, &idx).await {
            Ok(()) => report.purged += 1,
            Err(e) => {
                warn!(
                    keystone_id = %idx.keystone_id,
                    domain_id = %idx.domain_id,
                    provider_id = %idx.provider_id,
                    error = %e,
                    "scim_resource janitor: failed to purge tombstoned resource, continuing sweep"
                );
                report.errors += 1;
            }
        }
    }

    Ok(report)
}

/// Operator-triggered purge of a single resource, bypassing the retention
/// window (ADR 0024 §6.C's erasure-request path). The resource must
/// already be deprovisioned (soft-deleted) -- purging a live resource is
/// refused, since that would skip the deprovisioning steps (role
/// stripping, session revocation) `DELETE` performs.
pub async fn purge_now(
    state: &ServiceState,
    domain_id: &str,
    provider_id: &str,
    resource_type: ScimResourceType,
    keystone_id: &str,
) -> Result<(), ScimResourceProviderError> {
    let ctx = ExecutionContext::internal(state);
    let idx = state
        .provider
        .get_scim_resource_provider()
        .get_index(&ctx, domain_id, provider_id, resource_type, keystone_id)
        .await?
        .ok_or_else(|| ScimResourceProviderError::NotFound(keystone_id.to_string()))?;

    if idx.deprovisioned_at.is_none() {
        return Err(ScimResourceProviderError::Conflict(
            "resource must be deprovisioned (DELETEd) before it can be purged".to_string(),
        ));
    }

    purge_one(state, &ctx, &idx).await
}

/// Hard-delete the underlying `User`/`Group` row, purge its
/// `ScimResourceIndex` anchor, and emit a CADF `delete` audit event.
async fn purge_one(
    state: &ServiceState,
    ctx: &ExecutionContext<'_>,
    idx: &ScimResourceIndex,
) -> Result<(), ScimResourceProviderError> {
    match idx.resource_type {
        ScimResourceType::User => {
            state
                .provider
                .get_identity_provider()
                .delete_user(ctx, &idx.keystone_id)
                .await
                .map_err(ScimResourceProviderError::driver)?;
        }
        ScimResourceType::Group => {
            state
                .provider
                .get_identity_provider()
                .delete_group(ctx, &idx.keystone_id)
                .await
                .map_err(ScimResourceProviderError::driver)?;
        }
    }

    state
        .provider
        .get_scim_resource_provider()
        .purge_index(
            ctx,
            &idx.domain_id,
            &idx.provider_id,
            idx.resource_type,
            &idx.keystone_id,
        )
        .await?;

    let payload = match idx.resource_type {
        ScimResourceType::User => EventPayload::User {
            id: idx.keystone_id.clone(),
        },
        ScimResourceType::Group => EventPayload::Group {
            id: idx.keystone_id.clone(),
        },
    };
    state
        .event_dispatcher
        .emit(Event::new(Operation::Delete, payload))
        .await;

    Ok(())
}

/// Spawn the leader-gated background sweep loop. Intended to be called once
/// at server startup with the long-lived `ServiceState`.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;

            let Some(storage) = state.storage.as_deref() else {
                continue;
            };
            if storage.current_leader().await != Some(storage.node_id().await) {
                continue;
            }

            match run_once(&state).await {
                Ok(report) if report.purged > 0 || report.errors > 0 => {
                    info!(
                        purged = report.purged,
                        errors = report.errors,
                        "scim_resource janitor: sweep complete"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(
                    error = %e,
                    "scim_resource janitor: list_all_index failed, sweep aborted"
                ),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::scim_resource::MockScimResourceProvider;
    use crate::tests::get_mocked_state;

    fn index(
        keystone_id: &str,
        resource_type: ScimResourceType,
        deprovisioned_at: Option<i64>,
    ) -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain-1".to_string(),
            provider_id: "provider-1".to_string(),
            resource_type,
            keystone_id: keystone_id.to_string(),
            external_id: None,
            version: 0,
            deprovisioned_at,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_run_once_purges_old_tombstoned_user() {
        let now = Utc::now().timestamp();
        // 365 day default retention comfortably exceeded.
        let old = now - (400 * 86_400);
        let idx = index("user-1", ScimResourceType::User, Some(old));

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_list_all_index()
            .returning(move |_| Ok(vec![idx.clone()]));
        scim_mock
            .expect_purge_index()
            .withf(|_, domain_id, provider_id, resource_type, keystone_id| {
                domain_id == "domain-1"
                    && provider_id == "provider-1"
                    && *resource_type == ScimResourceType::User
                    && keystone_id == "user-1"
            })
            .returning(|_, _, _, _, _| Ok(()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_user()
            .withf(|_, id| id == "user-1")
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_scim_resource(scim_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.purged, 1);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_purges_old_tombstoned_group() {
        let now = Utc::now().timestamp();
        let old = now - (400 * 86_400);
        let idx = index("group-1", ScimResourceType::Group, Some(old));

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_list_all_index()
            .returning(move |_| Ok(vec![idx.clone()]));
        scim_mock
            .expect_purge_index()
            .returning(|_, _, _, _, _| Ok(()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_group()
            .withf(|_, id| id == "group-1")
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_scim_resource(scim_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.purged, 1);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_recent_tombstone_alone() {
        let now = Utc::now().timestamp();
        let recent = now - 3_600;
        let idx = index("user-1", ScimResourceType::User, Some(recent));

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_list_all_index()
            .returning(move |_| Ok(vec![idx.clone()]));
        // No `expect_purge_index`: calling it would panic the mock.

        let provider = Provider::mocked_builder().mock_scim_resource(scim_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.purged, 0);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_active_resource_alone() {
        let idx = index("user-1", ScimResourceType::User, None);

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_list_all_index()
            .returning(move |_| Ok(vec![idx.clone()]));
        // No `expect_purge_index`/`expect_delete_user`: calling either would
        // panic the mock.

        let provider = Provider::mocked_builder().mock_scim_resource(scim_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.purged, 0);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_isolates_per_resource_failure() {
        let now = Utc::now().timestamp();
        let old = now - (400 * 86_400);
        let failing = index("user-fails", ScimResourceType::User, Some(old));
        let ok = index("user-ok", ScimResourceType::User, Some(old));

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_list_all_index()
            .returning(move |_| Ok(vec![failing.clone(), ok.clone()]));
        scim_mock
            .expect_purge_index()
            .withf(|_, _, _, _, keystone_id| keystone_id == "user-ok")
            .returning(|_, _, _, _, _| Ok(()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_user()
            .withf(|_, id| id == "user-fails")
            .returning(|_, _| {
                Err(
                    openstack_keystone_core_types::identity::IdentityProviderError::Driver(
                        "cas conflict".to_string(),
                    ),
                )
            });
        identity_mock
            .expect_delete_user()
            .withf(|_, id| id == "user-ok")
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_scim_resource(scim_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.purged, 1, "the second resource must still be purged");
        assert_eq!(
            report.errors, 1,
            "the first resource's failure must be counted"
        );
    }

    #[tokio::test]
    async fn test_purge_now_succeeds_for_deprovisioned_resource() {
        let idx = index("user-1", ScimResourceType::User, Some(1));

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_get_index()
            .returning(move |_, _, _, _, _| Ok(Some(idx.clone())));
        scim_mock
            .expect_purge_index()
            .returning(|_, _, _, _, _| Ok(()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_delete_user().returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_scim_resource(scim_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        purge_now(
            &state,
            "domain-1",
            "provider-1",
            ScimResourceType::User,
            "user-1",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_purge_now_rejects_live_resource() {
        let idx = index("user-1", ScimResourceType::User, None);

        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_get_index()
            .returning(move |_, _, _, _, _| Ok(Some(idx.clone())));
        // No `expect_purge_index`/`expect_delete_user`: calling either would
        // panic the mock.

        let provider = Provider::mocked_builder().mock_scim_resource(scim_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let result = purge_now(
            &state,
            "domain-1",
            "provider-1",
            ScimResourceType::User,
            "user-1",
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimResourceProviderError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn test_purge_now_missing_resource_not_found() {
        let mut scim_mock = MockScimResourceProvider::default();
        scim_mock
            .expect_get_index()
            .returning(|_, _, _, _, _| Ok(None));

        let provider = Provider::mocked_builder().mock_scim_resource(scim_mock);
        let state = get_mocked_state(None, Some(provider)).await;

        let result = purge_now(
            &state,
            "domain-1",
            "provider-1",
            ScimResourceType::User,
            "nonexistent",
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimResourceProviderError::NotFound(_))
        ));
    }
}
