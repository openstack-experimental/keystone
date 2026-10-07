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
//! OAuth2 signing key janitor: automatic signing-key rotation, demoted-key
//! retirement and proactive JTI revocation-list pruning (ADR 0026 §3).
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

use cadf::{AuditDispatcher, CadfEventPayload, Initiator, Observer, Outcome, Target};

use crate::auth::ExecutionContext;
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
    /// Domains whose `Primary` key exceeded `signing_key_rotation_days` and
    /// was automatically rotated this pass.
    pub rotated: usize,
    /// Operations that failed this pass (e.g. a transient backend failure).
    /// Failures are isolated per domain -- one failing domain does not
    /// prevent the rest of the sweep from running -- and are retried on the
    /// next pass.
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
    let (access_token_lifetime_secs, rotation_interval_secs) = {
        let cfg = state.config_manager.config.read().await;
        (
            i64::from(cfg.oauth2.access_token_lifetime_minutes) * 60,
            i64::from(cfg.oauth2.signing_key_rotation_days) * 24 * 3600,
        )
    };
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

        // Retirement runs before rotation: rotation demotes the current
        // `Primary` into the `Previous` slot, which must not be retired
        // in the same pass.
        //
        // A `Previous` key with no `demoted_at` predates this field's
        // introduction; leave it alone rather than force-retiring it --
        // there's no way to tell how long ago it was actually demoted.
        if let Some(demoted_at) = active.previous.as_ref().and_then(|k| k.demoted_at)
            && (now - demoted_at).num_seconds() > access_token_lifetime_secs
        {
            match state
                .provider
                .get_oauth2_key_provider()
                .retire_previous_key(state, &domain_id)
                .await
            {
                Ok(true) => {
                    emit_maintenance_event(
                        &state.audit_dispatcher,
                        "retire_previous_key",
                        &domain_id,
                    );
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

        // `created_at` is reset by every rotation (including emergency
        // ones), so the cadence timer restarts automatically.
        if (now - active.primary.created_at).num_seconds() >= rotation_interval_secs {
            match rotate_if_eligible(state, &domain_id).await {
                Ok(true) => {
                    emit_maintenance_event(
                        &state.audit_dispatcher,
                        "rotate_signing_key",
                        &domain_id,
                    );
                    report.rotated += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(
                        domain_id = %domain_id,
                        error = %e,
                        "oauth2_key janitor: failed to rotate signing key, continuing sweep"
                    );
                    report.errors += 1;
                }
            }
        }
    }

    Ok(report)
}

/// Rotate `domain_id`'s signing key unless the domain is disabled/gone or an
/// emergency rotation is staged. Returns whether a rotation happened.
///
/// Note that the backend writes keys without a compare-and-swap, so a
/// rotation racing this one (e.g. a manual `rotate-signing-key` against the
/// hourly sweep) does *not* surface as a backend error: the writes are
/// last-write-wins and the loser's freshly generated keypair is silently
/// discarded. The janitor is leader-gated, so a manual operator rotation is
/// the only realistic contender.
async fn rotate_if_eligible(
    state: &ServiceState,
    domain_id: &str,
) -> Result<bool, Oauth2KeyProviderError> {
    let ctx = ExecutionContext::internal(state);
    match state
        .provider
        .get_resource_provider()
        .get_domain(&ctx, domain_id)
        .await
    {
        Ok(Some(domain)) if domain.enabled => {}
        Ok(_) => return Ok(false),
        Err(e) => return Err(Oauth2KeyProviderError::DomainLookup(e.to_string())),
    }
    let keys = state.provider.get_oauth2_key_provider();
    // NB: this check and the rotation below are separate reads; the backend
    // does not re-check pending emergency state inside the rotation
    // transaction. An emergency rotation staged in that window would still
    // be honored on confirmation -- the staged key becomes `Primary` and the
    // auto-rotated key is demoted to `Previous` (kept in the JWKS until
    // retirement) -- so the race narrows rather than closes the window.
    if keys
        .has_pending_emergency_rotation(state, domain_id)
        .await?
    {
        return Ok(false);
    }
    keys.rotate_signing_key(&ctx, domain_id).await?;
    Ok(true)
}

/// Emit a `maintenance` CADF event for a janitor-driven lifecycle action.
/// Best-effort, mirroring `api_key::janitor`'s dispatch discipline: this is
/// background housekeeping, not a user-facing request, so there is no real
/// correlation ID to thread through.
fn emit_maintenance_event(dispatcher: &Arc<AuditDispatcher>, action: &str, domain_id: &str) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{node_id}:{}", Uuid::new_v4());
    let correlation_id = format!("janitor:{}", Uuid::new_v4());
    let initiator = Initiator::system("oauth2_key_janitor");
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        correlation_id,
        Utc::now().to_rfc3339(),
        action.to_string(),
        Outcome::Success,
        None,
        initiator,
        Target::new(domain_id, "data/security/keystone/oauth2_signing_key"),
        Observer::new(
            node_id.clone(),
            format!("service/security/keystone/{node_id}"),
        ),
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
                Ok(report) if report.retired > 0 || report.rotated > 0 || report.errors > 0 => {
                    info!(
                        retired = report.retired,
                        rotated = report.rotated,
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

    use openstack_keystone_core_types::resource::Domain;

    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
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

    fn old_key() -> KeyMaterial {
        KeyMaterial {
            created_at: Utc::now() - ChronoDuration::days(91),
            ..key()
        }
    }

    fn resource_mock(enabled: bool) -> MockResourceProvider {
        let mut mock = MockResourceProvider::default();
        mock.expect_get_domain().returning(move |_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                enabled,
                ..Default::default()
            }))
        });
        mock
    }

    fn single_domain_keys(primary: KeyMaterial) -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(vec![(
                "domain-1".to_string(),
                ActiveKeys {
                    primary: primary.clone(),
                    previous: None,
                },
            )])
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        mock
    }

    #[tokio::test]
    async fn test_run_once_rotates_key_older_than_cadence() {
        let mut mock = single_domain_keys(old_key());
        mock.expect_has_pending_emergency_rotation()
            .returning(|_, _| Ok(false));
        mock.expect_rotate_signing_key()
            .withf(|_, domain_id| domain_id == "domain-1")
            .times(1)
            .returning(|_, _| Ok(key()));

        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_oauth2_key(mock)
                    .mock_resource(resource_mock(true)),
            ),
        )
        .await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.rotated, 1);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_does_not_rotate_young_key() {
        // No `expect_rotate_signing_key`: calling it would panic the mock.
        let mock = single_domain_keys(key());
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_oauth2_key(mock))).await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.rotated, 0);
    }

    #[tokio::test]
    async fn test_run_once_skips_disabled_domain() {
        let mock = single_domain_keys(old_key());
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_oauth2_key(mock)
                    .mock_resource(resource_mock(false)),
            ),
        )
        .await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.rotated, 0);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_skips_domain_with_pending_emergency_rotation() {
        let mut mock = single_domain_keys(old_key());
        mock.expect_has_pending_emergency_rotation()
            .returning(|_, _| Ok(true));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_oauth2_key(mock)
                    .mock_resource(resource_mock(true)),
            ),
        )
        .await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.rotated, 0);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_isolates_rotation_failure() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_all_active_keys().returning(move |_| {
            Ok(["domain-fails", "domain-ok"]
                .into_iter()
                .map(|id| {
                    (
                        id.to_string(),
                        ActiveKeys {
                            primary: old_key(),
                            previous: None,
                        },
                    )
                })
                .collect())
        });
        mock.expect_prune_expired_jtis().returning(|_, _| Ok(()));
        mock.expect_has_pending_emergency_rotation()
            .returning(|_, _| Ok(false));
        mock.expect_rotate_signing_key()
            .withf(|_, domain_id| domain_id == "domain-fails")
            .returning(|_, _| Err(Oauth2KeyProviderError::RaftNotAvailable));
        mock.expect_rotate_signing_key()
            .withf(|_, domain_id| domain_id == "domain-ok")
            .returning(|_, _| Ok(key()));

        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_oauth2_key(mock)
                    .mock_resource(resource_mock(true)),
            ),
        )
        .await;

        let report = run_once(&state).await.unwrap();
        assert_eq!(report.rotated, 1);
        assert_eq!(report.errors, 1);
    }
}
