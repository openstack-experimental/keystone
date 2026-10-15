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
//! Service grant janitor (ADR 0036 §8): disables grants past `expires_at`
//! as `Expired`, and deletes them once they have been expired for
//! `[delegation] expired_grant_retention`.
//!
//! Expiry is enforced at redemption regardless; the janitor keeps the
//! `enabled` flag honest for grants nobody redeems and bounds storage.
//!
//! Same leader-gated pattern as [`crate::oauth2_session::janitor`]:
//! [`spawn`] runs on every node, [`sweep_if_leader`] only works on the
//! current Raft leader.

use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{info, warn};

use openstack_keystone_core_types::service_grant::*;

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;

/// Outcome of one sweep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JanitorReport {
    /// Grants disabled as expired.
    pub disabled: usize,
    /// Expired grants deleted after the retention period.
    pub deleted: usize,
    /// Grants a write failed for.
    pub errors: usize,
}

/// What the janitor does with one grant at `now`.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Keep,
    Disable,
    Delete,
}

fn action(grant: &ServiceGrant, now: DateTime<Utc>, retention: chrono::Duration) -> Action {
    let Some(expires_at) = grant.expires_at else {
        return Action::Keep;
    };
    if expires_at > now {
        return Action::Keep;
    }
    if expires_at
        .checked_add_signed(retention)
        .is_some_and(|purge_at| purge_at <= now)
    {
        return Action::Delete;
    }
    if grant.enabled {
        return Action::Disable;
    }
    Action::Keep
}

/// Run one sweep over every grant.
pub async fn run_once(state: &ServiceState) -> Result<JanitorReport, ServiceGrantProviderError> {
    let retention = state
        .config_manager
        .config
        .read()
        .await
        .delegation
        .expired_grant_retention;
    let retention = i64::try_from(retention)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .unwrap_or(chrono::Duration::MAX);
    let ctx = ExecutionContext::internal(state);
    let provider = state.provider.get_service_grant_provider();
    let now = Utc::now();

    let mut report = JanitorReport::default();
    for grant in provider
        .list_service_grants(&ctx, &ServiceGrantListParameters::default())
        .await?
    {
        let result = match action(&grant, now, retention) {
            Action::Keep => continue,
            Action::Disable => provider
                .update_service_grant(
                    &ctx,
                    &grant.domain_id,
                    &grant.id,
                    ServiceGrantUpdate {
                        enabled: Some(false),
                        disabled_reason: Some(DisabledReason::Expired),
                        last_redeemed_at: None,
                    },
                    grant.version,
                )
                .await
                .map(|_| report.disabled += 1),
            Action::Delete => provider
                .delete_service_grant(&ctx, &grant.domain_id, &grant.id)
                .await
                .map(|()| report.deleted += 1),
        };
        if let Err(e) = result {
            warn!(grant_id = %grant.id, error = %e, "service grant janitor: write failed");
            report.errors += 1;
        }
    }
    Ok(report)
}

/// Run one sweep if this node is the current Raft leader; `None` otherwise.
pub async fn sweep_if_leader(
    state: &ServiceState,
) -> Option<Result<JanitorReport, ServiceGrantProviderError>> {
    let storage = state.storage.as_deref()?;
    if storage.current_leader().await != Some(storage.node_id().await) {
        return None;
    }
    Some(run_once(state).await)
}

/// Spawn the leader-gated sweep loop, on the `[delegation]
/// janitor_interval` re-read every tick.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(configured_interval(&state).await);
        loop {
            interval.tick().await;
            let period = configured_interval(&state).await;
            if interval.period() != period {
                interval = tokio::time::interval(period);
                continue;
            }
            match sweep_if_leader(&state).await {
                Some(Ok(report)) if report != JanitorReport::default() => info!(
                    disabled = report.disabled,
                    deleted = report.deleted,
                    errors = report.errors,
                    "service grant janitor: sweep complete"
                ),
                Some(Ok(_)) | None => {}
                Some(Err(e)) => warn!(error = %e, "service grant janitor: sweep aborted"),
            }
        }
    });
}

async fn configured_interval(state: &ServiceState) -> Duration {
    let secs = state
        .config_manager
        .config
        .read()
        .await
        .delegation
        .janitor_interval;
    // `tokio::time::interval` panics on a zero period.
    Duration::from_secs(secs.max(1))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::provider::Provider;
    use crate::service_grant::MockServiceGrantProvider;
    use crate::tests::get_mocked_state;

    fn grant(id: &str, expires_in: Option<i64>, enabled: bool) -> ServiceGrant {
        ServiceGrant {
            id: id.into(),
            version: 1,
            domain_id: "d1".into(),
            grantor_user_id: "u1".into(),
            grantee: Grantee::Client {
                client_id: "c1".into(),
                client_domain_id: "d1".into(),
            },
            target: GrantTarget::Project {
                project_id: "p1".into(),
                project_domain_id: "d1".into(),
            },
            role_ids: vec!["member".into()],
            expires_at: expires_in.map(|s| Utc::now() + Duration::seconds(s)),
            description: None,
            enabled,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    #[test]
    fn test_action() {
        let now = Utc::now();
        let retention = Duration::days(30);
        assert_eq!(
            action(&grant("a", None, true), now, retention),
            Action::Keep
        );
        assert_eq!(
            action(&grant("a", Some(60), true), now, retention),
            Action::Keep
        );
        assert_eq!(
            action(&grant("a", Some(-60), true), now, retention),
            Action::Disable
        );
        assert_eq!(
            action(&grant("a", Some(-60), false), now, retention),
            Action::Keep
        );
        assert_eq!(
            action(&grant("a", Some(-31 * 86_400), false), now, retention),
            Action::Delete
        );
    }

    #[tokio::test]
    async fn test_run_once() {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_list_service_grants().returning(|_, _| {
            Ok(vec![
                grant("live", Some(60), true),
                grant("expired", Some(-60), true),
                grant("old", Some(-31 * 86_400), false),
            ])
        });
        mock.expect_update_service_grant()
            .withf(|_, _, id, u, _| {
                id == "expired" && u.disabled_reason == Some(DisabledReason::Expired)
            })
            .times(1)
            .returning(|_, _, _, _, _| Ok(grant("expired", Some(-60), false)));
        mock.expect_delete_service_grant()
            .withf(|_, _, id| id == "old")
            .times(1)
            .returning(|_, _, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_service_grant(mock)),
        )
        .await;
        assert_eq!(
            run_once(&state).await.unwrap(),
            JanitorReport {
                disabled: 1,
                deleted: 1,
                errors: 0
            }
        );
    }
}
