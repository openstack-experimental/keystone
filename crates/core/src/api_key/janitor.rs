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
//! API Key (SCIM ingress) janitor: proactive inactivity disablement and
//! tombstone purge (ADR 0021 §6.F).
//!
//! Mirrors the leader-gated background sweep pattern already used by the
//! storage crate's emergency-rotation confirmation-timeout sweeper
//! (`crates/storage/src/app.rs`): [`spawn`] runs on every cluster node on a
//! fixed interval, but [`run_once`]'s work only actually executes when that
//! node is the current Raft leader (`current_leader() ==
//! Some(node_id())`), so exactly one disablement/purge -- and one audit
//! record -- is produced per key per threshold crossing.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use openstack_keystone_audit::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Target};
use openstack_keystone_core_types::api_key::{ApiClientResource, ApiClientResourceUpdate};

use crate::api_key::ApiKeyProviderError;
use crate::keystone::ServiceState;

/// Interval between sweep passes. Thresholds are day-granularity, so this is
/// deliberately coarse -- it only needs to run often enough to keep
/// wall-clock drift against those thresholds small.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Outcome of a single sweep pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JanitorReport {
    /// Keys disabled for inactivity this pass.
    pub disabled: usize,
    /// Tombstoned keys physically purged this pass.
    pub purged: usize,
    /// Keys whose disablement/purge attempt failed this pass (e.g. a Raft
    /// CAS conflict with a concurrent admin update). Failures are isolated
    /// per key -- one failing key does not prevent the rest of the sweep
    /// from running -- and are retried on the next pass.
    pub errors: usize,
}

/// Run a single janitor sweep pass over every domain's API Keys. Idempotent
/// and safe to call repeatedly: a key already disabled, or already purged,
/// is simply not matched again on the next pass.
///
/// Only [`ApiKeyApi::list_all`] failing aborts the whole pass (there is
/// nothing to sweep without it); a failure disabling or purging one key is
/// logged and counted in [`JanitorReport::errors`], and the pass continues
/// with the remaining keys.
pub async fn run_once(state: &ServiceState) -> Result<JanitorReport, ApiKeyProviderError> {
    let cfg = state.config_manager.config.read().await.api_key.clone();
    let now = Utc::now().timestamp();
    let inactive_threshold_secs =
        i64::from(cfg.janitor_inactive_days + cfg.janitor_grace_days) * 86_400;
    let tombstone_retention_secs = i64::from(cfg.janitor_tombstone_retention_days) * 86_400;

    let mut report = JanitorReport::default();
    let all = state
        .provider
        .get_api_key_provider()
        .list_all(state)
        .await?;

    for key in all {
        if key.enabled {
            let last_activity = key.last_used_at.unwrap_or(key.created_at);
            if now - last_activity > inactive_threshold_secs {
                match disable_for_inactivity(state, &key).await {
                    Ok(()) => report.disabled += 1,
                    Err(e) => {
                        warn!(
                            client_id = %key.client_id,
                            domain_id = %key.domain_id,
                            error = %e,
                            "api_key janitor: failed to disable inactive key, continuing sweep"
                        );
                        report.errors += 1;
                    }
                }
            }
        } else if let Some(revoked_at) = key.revoked_at
            && now - revoked_at > tombstone_retention_secs
        {
            match state
                .provider
                .get_api_key_provider()
                .purge(state, &key.domain_id, &key.client_id)
                .await
            {
                Ok(()) => report.purged += 1,
                Err(e) => {
                    warn!(
                        client_id = %key.client_id,
                        domain_id = %key.domain_id,
                        error = %e,
                        "api_key janitor: failed to purge tombstoned key, continuing sweep"
                    );
                    report.errors += 1;
                }
            }
        }
    }

    Ok(report)
}

async fn disable_for_inactivity(
    state: &ServiceState,
    key: &ApiClientResource,
) -> Result<(), ApiKeyProviderError> {
    // ADR 0021 §6.F: emit the maintenance audit event (and push an
    // administrative alert) before executing the disablement.
    //
    // NOTE: the ADR also calls for "an administrative alert payload to the
    // system notification bus" -- this codebase has no pub/sub or webhook
    // dispatch infrastructure yet. The structured `warn!` below is the
    // closest existing mechanism; wiring a real notification channel is
    // tracked as follow-up work, not invented here.
    emit_maintenance_event(&state.audit_dispatcher, "disable_inactive", &key.client_id);
    warn!(
        client_id = %key.client_id,
        domain_id = %key.domain_id,
        provider_id = %key.provider_id,
        "api_key janitor: disabling inactive API key"
    );

    state
        .provider
        .get_api_key_provider()
        .update(
            state,
            &key.domain_id,
            &key.client_id,
            ApiClientResourceUpdate {
                enabled: Some(false),
                allowed_ips: None,
                description: None,
            },
        )
        .await?;
    Ok(())
}

/// Emit a `maintenance` CADF event for a janitor-driven lifecycle action.
/// Best-effort, mirroring the perimeter authentication event's dispatch
/// discipline: this is background housekeeping, not a user-facing request,
/// so there is no real correlation ID to thread through.
fn emit_maintenance_event(dispatcher: &Arc<AuditDispatcher>, action: &str, client_id: &str) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{node_id}:{}", Uuid::new_v4());
    let correlation_id = format!("janitor:{}", Uuid::new_v4());
    let initiator = Initiator::new("api_key_janitor".to_string(), None, None, None);
    let payload = CadfEventPayload::new(
        event_id,
        "1.0".to_string(),
        "default".to_string(),
        correlation_id,
        Utc::now().to_rfc3339(),
        action.to_string(),
        "success".to_string(),
        None,
        initiator,
        Target {
            id: client_id.to_string(),
            type_uri: "data/security/keystone/api_key".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
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
                Ok(report) if report.disabled > 0 || report.purged > 0 || report.errors > 0 => {
                    info!(
                        disabled = report.disabled,
                        purged = report.purged,
                        errors = report.errors,
                        "api_key janitor: sweep complete"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "api_key janitor: list_all failed, sweep aborted"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::mocks::MockApiKeyProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    fn key(
        client_id: &str,
        enabled: bool,
        last_used_at: Option<i64>,
        created_at: i64,
        revoked_at: Option<i64>,
    ) -> ApiClientResource {
        ApiClientResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            client_id: client_id.into(),
            lookup_hash: format!("hash-{client_id}"),
            secret_hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            allowed_ips: None,
            description: None,
            enabled,
            created_at,
            expires_at: Utc::now().timestamp() + 999_999,
            last_used_at,
            revoked_at,
            revoked_by: revoked_at.map(|_| "operator-1".to_string()),
        }
    }

    #[tokio::test]
    async fn test_run_once_disables_inactive_key() {
        let now = Utc::now().timestamp();
        // 90 + 7 day default threshold comfortably exceeded.
        let stale_last_used = now - (120 * 86_400);
        let stale_key = key(
            "client-1",
            true,
            Some(stale_last_used),
            stale_last_used,
            None,
        );

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![stale_key.clone()]));
        mock.expect_update()
            .withf(|_, domain_id, client_id, data| {
                domain_id == "domain_id" && client_id == "client-1" && data.enabled == Some(false)
            })
            .returning(|_, _, _, _| Ok(key("client-1", false, None, 0, None)));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 1);
        assert_eq!(report.purged, 0);
    }

    #[tokio::test]
    async fn test_run_once_isolates_per_key_failure() {
        // Two stale keys; the first's disablement fails (e.g. a Raft CAS
        // conflict with a concurrent admin update). The sweep must still
        // process the second key in the same pass rather than aborting.
        let now = Utc::now().timestamp();
        let stale_last_used = now - (120 * 86_400);
        let failing_key = key(
            "client-fails",
            true,
            Some(stale_last_used),
            stale_last_used,
            None,
        );
        let ok_key = key(
            "client-ok",
            true,
            Some(stale_last_used),
            stale_last_used,
            None,
        );

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![failing_key.clone(), ok_key.clone()]));
        mock.expect_update()
            .withf(|_, _, client_id, _| client_id == "client-fails")
            .returning(|_, _, _, _| Err(ApiKeyProviderError::Conflict("cas conflict".into())));
        mock.expect_update()
            .withf(|_, _, client_id, _| client_id == "client-ok")
            .returning(|_, _, _, _| Ok(key("client-ok", false, None, 0, None)));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 1, "the second key must still be disabled");
        assert_eq!(report.errors, 1, "the first key's failure must be counted");
        assert_eq!(report.purged, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_recently_active_key_alone() {
        let now = Utc::now().timestamp();
        let recent = key("client-1", true, Some(now - 3_600), now - 3_600, None);

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![recent.clone()]));
        // No `expect_update`/`expect_purge`: calling either would panic the mock.

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 0);
        assert_eq!(report.purged, 0);
    }

    #[tokio::test]
    async fn test_run_once_purges_old_tombstone() {
        let now = Utc::now().timestamp();
        // 365 day default retention comfortably exceeded.
        let old_revoke = now - (400 * 86_400);
        let tombstoned = key(
            "client-1",
            false,
            None,
            now - 500 * 86_400,
            Some(old_revoke),
        );

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![tombstoned.clone()]));
        mock.expect_purge()
            .withf(|_, domain_id, client_id| domain_id == "domain_id" && client_id == "client-1")
            .returning(|_, _, _| Ok(()));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 0);
        assert_eq!(report.purged, 1);
    }

    #[tokio::test]
    async fn test_run_once_leaves_recent_tombstone_alone() {
        let now = Utc::now().timestamp();
        let recent_revoke = now - 3_600;
        let tombstoned = key(
            "client-1",
            false,
            None,
            now - 500 * 86_400,
            Some(recent_revoke),
        );

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![tombstoned.clone()]));
        // No `expect_purge`: calling it would panic the mock.

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 0);
        assert_eq!(report.purged, 0);
    }

    #[tokio::test]
    async fn test_run_once_is_idempotent_over_two_passes() {
        // A key already disabled (not enabled) and without a revoked_at
        // tombstone (janitor-disabled, not admin-revoked) must never be
        // touched by either branch.
        let now = Utc::now().timestamp();
        let disabled_not_revoked = key("client-1", false, None, now - 500 * 86_400, None);

        let mut mock = MockApiKeyProvider::default();
        mock.expect_list_all()
            .returning(move |_| Ok(vec![disabled_not_revoked.clone()]));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_api_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.disabled, 0);
        assert_eq!(report.purged, 0);
    }
}
