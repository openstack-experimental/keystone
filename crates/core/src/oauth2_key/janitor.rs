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
//! OAuth2 signing key janitor: demoted-key retirement and proactive JTI
//! revocation-list pruning (ADR 0026 §3).
//!
//! Mirrors the leader-gated background sweep pattern used by
//! [`crate::api_key::janitor`]: [`spawn`] runs on every cluster node on a
//! fixed interval, but [`run_once`]'s work only actually executes when that
//! node is the current Raft leader, so exactly one retirement -- and one
//! audit record -- is produced per key past its retention window.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use openstack_keystone_audit::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Target};

use crate::keystone::ServiceState;
use crate::oauth2_key::Oauth2KeyProviderError;

/// Interval between sweep passes. Retention is measured in whole access-token
/// lifetimes (minutes to hours), so this is deliberately coarse.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Outcome of a single sweep pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JanitorReport {
    /// Demoted `Previous` keys retired (removed from JWKS) this pass.
    pub retired: usize,
    /// Domains whose JTI revocation list was proactively pruned this pass.
    pub jtis_pruned: usize,
    /// Operations that failed this pass (e.g. a Raft CAS conflict with a
    /// concurrent rotation). Failures are isolated per domain -- one
    /// failing domain does not prevent the rest of the sweep from running
    /// -- and are retried on the next pass.
    pub errors: usize,
}

/// Run a single janitor sweep pass over every domain's OAuth2 signing keys.
/// Idempotent and safe to call repeatedly: a `Previous` key already retired
/// is simply absent from the next pass's [`Oauth2KeyApi::list_all_active_keys`]
/// result.
///
/// Only `list_all_active_keys` failing aborts the whole pass (there is
/// nothing to sweep without it); a failure retiring one domain's key or
/// pruning its JTI list is logged and counted in [`JanitorReport::errors`],
/// and the pass continues with the remaining domains.
///
/// [`Oauth2KeyApi::list_all_active_keys`]: crate::oauth2_key::Oauth2KeyApi::list_all_active_keys
pub async fn run_once(state: &ServiceState) -> Result<JanitorReport, Oauth2KeyProviderError> {
    let access_token_lifetime_secs = i64::from(
        state
            .config_manager
            .config
            .read()
            .await
            .oauth2
            .access_token_lifetime_minutes,
    ) * 60;
    let now = Utc::now();

    let mut report = JanitorReport::default();
    let all = state
        .provider
        .get_oauth2_key_provider()
        .list_all_active_keys(state)
        .await?;

    for (domain_id, active) in all {
        match state
            .provider
            .get_oauth2_key_provider()
            .prune_expired_jtis(state, &domain_id)
            .await
        {
            Ok(()) => report.jtis_pruned += 1,
            Err(e) => {
                warn!(
                    domain_id = %domain_id,
                    error = %e,
                    "oauth2_key janitor: failed to prune JTI revocation list, continuing sweep"
                );
                report.errors += 1;
            }
        }

        let Some(previous) = active.previous else {
            continue;
        };
        // A `Previous` key with no `demoted_at` predates this field's
        // introduction; leave it alone rather than force-retiring it --
        // there's no way to tell how long ago it was actually demoted.
        let Some(demoted_at) = previous.demoted_at else {
            continue;
        };
        if (now - demoted_at).num_seconds() <= access_token_lifetime_secs {
            continue;
        }

        match state
            .provider
            .get_oauth2_key_provider()
            .retire_previous_key(state, &domain_id)
            .await
        {
            Ok(true) => {
                emit_maintenance_event(&state.audit_dispatcher, "retire_previous_key", &domain_id);
                report.retired += 1;
            }
            Ok(false) => {}
            Err(e) => {
                warn!(
                    domain_id = %domain_id,
                    error = %e,
                    "oauth2_key janitor: failed to retire previous signing key, continuing sweep"
                );
                report.errors += 1;
            }
        }
    }

    Ok(report)
}

/// Emit a `maintenance` CADF event for a janitor-driven lifecycle action.
/// Best-effort, mirroring `api_key::janitor`'s dispatch discipline: this is
/// background housekeeping, not a user-facing request, so there is no real
/// correlation ID to thread through.
fn emit_maintenance_event(dispatcher: &Arc<AuditDispatcher>, action: &str, domain_id: &str) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{node_id}:{}", Uuid::new_v4());
    let correlation_id = format!("janitor:{}", Uuid::new_v4());
    let initiator = Initiator::new("oauth2_key_janitor".to_string(), None, None, None);
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
            id: domain_id.to_string(),
            type_uri: "data/security/keystone/oauth2_signing_key".to_string(),
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
                Ok(report) if report.retired > 0 || report.errors > 0 => {
                    info!(
                        retired = report.retired,
                        jtis_pruned = report.jtis_pruned,
                        errors = report.errors,
                        "oauth2_key janitor: sweep complete"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(
                    error = %e,
                    "oauth2_key janitor: list_all_active_keys failed, sweep aborted"
                ),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Duration as ChronoDuration;
    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, KeyMaterial, SigningAlgorithm, generate_keypair,
    };

    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    fn key() -> KeyMaterial {
        generate_keypair(SigningAlgorithm::Es256).unwrap()
    }

    fn key_with_demotion(demoted_at: Option<chrono::DateTime<Utc>>) -> KeyMaterial {
        KeyMaterial {
            demoted_at,
            ..key()
        }
    }

    #[tokio::test]
    async fn test_run_once_retires_previous_key_past_retention() {
        let stale_demotion = Utc::now() - ChronoDuration::hours(2);
        let previous = key_with_demotion(Some(stale_demotion));

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![(
                "domain-1".to_string(),
                ActiveKeys {
                    primary: key(),
                    previous: Some(previous.clone()),
                },
            )])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        mock.expect_retire_previous_key()
            .withf(|_, domain_id| domain_id == "domain-1")
            .returning(|_, _| Ok(true));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.retired, 1);
        assert_eq!(report.jtis_pruned, 1);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_recently_demoted_key_alone() {
        let recent_demotion = Utc::now() - ChronoDuration::seconds(60);
        let previous = key_with_demotion(Some(recent_demotion));

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![(
                "domain-1".to_string(),
                ActiveKeys {
                    primary: key(),
                    previous: Some(previous.clone()),
                },
            )])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        // No `expect_retire_previous_key`: calling it would panic the mock.

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.retired, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_key_with_no_demoted_at_alone() {
        // Pre-migration data: a `Previous` key with no `demoted_at` must
        // never be force-retired, since there's no way to tell how long
        // ago it was actually demoted.
        let previous = key_with_demotion(None);

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![(
                "domain-1".to_string(),
                ActiveKeys {
                    primary: key(),
                    previous: Some(previous.clone()),
                },
            )])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        // No `expect_retire_previous_key`: calling it would panic the mock.

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.retired, 0);
    }

    #[tokio::test]
    async fn test_run_once_isolates_per_domain_failure() {
        let stale_demotion = Utc::now() - ChronoDuration::hours(2);
        let previous_a = key_with_demotion(Some(stale_demotion));
        let previous_b = key_with_demotion(Some(stale_demotion));

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![
                (
                    "domain-fails".to_string(),
                    ActiveKeys {
                        primary: key(),
                        previous: Some(previous_a.clone()),
                    },
                ),
                (
                    "domain-ok".to_string(),
                    ActiveKeys {
                        primary: key(),
                        previous: Some(previous_b.clone()),
                    },
                ),
            ])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        mock.expect_retire_previous_key()
            .withf(|_, domain_id| domain_id == "domain-fails")
            .returning(|_, _| Err(Oauth2KeyProviderError::NotFound("domain-fails".into())));
        mock.expect_retire_previous_key()
            .withf(|_, domain_id| domain_id == "domain-ok")
            .returning(|_, _| Ok(true));

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.retired, 1, "the second domain must still be retired");
        assert_eq!(
            report.errors, 1,
            "the first domain's failure must be counted"
        );
    }

    #[tokio::test]
    async fn test_run_once_no_previous_key_is_a_noop_for_retirement() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![(
                "domain-1".to_string(),
                ActiveKeys {
                    primary: key(),
                    previous: None,
                },
            )])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        // No `expect_retire_previous_key`: calling it would panic the mock.

        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.retired, 0);
        assert_eq!(report.jtis_pruned, 1);
    }
}
