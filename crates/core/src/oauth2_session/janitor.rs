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
//! OAuth2 session janitor: purges expired pre-auth sessions, authorization
//! codes, device grants and refresh tokens (ADR 0026 §9, §10 Phase 4).
//!
//! Expiry is otherwise enforced lazily on read only, so a record that is
//! never read again (an abandoned `GET /authorize`, an unredeemed code, an
//! unpolled device grant, a refresh token whose RP stopped rotating) would
//! stay in the Raft log and keyspace forever.
//!
//! Mirrors the leader-gated background sweep of
//! [`crate::oauth2_key::janitor`]: [`spawn`] runs on every cluster node on a
//! fixed interval, but [`run_once`]'s work only executes when that node is
//! the current Raft leader, so each record is purged -- and each audit
//! record produced -- exactly once. [`run_once`] itself is idempotent
//! (purging an already-deleted record is a no-op), so calling it on several
//! nodes is safe, merely redundant.
//!
//! Retention:
//!
//! - sessions, codes, device grants and refresh tokens that were never revoked
//!   (live leaves, spent rotated parents) are purged once they have been
//!   expired for [`EXPIRY_GRACE_SECONDS`];
//! - tombstones of revoked refresh families (expiry index kind
//!   `refresh_tombstone`, set when the family is revoked) are purged once they
//!   have been expired for `[oauth2] revoked_family_retention_days`. Presenting
//!   an expired token is rejected regardless, so this retention only keeps the
//!   records around for forensics and correlation with the critical breach
//!   audit event.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use openstack_keystone_audit::{
    AuditDispatcher, CadfEventPayload, Initiator, Observer, OutcomeReason, Target,
};

use crate::keystone::ServiceState;
use crate::oauth2_session::Oauth2SessionProviderError;

/// Seconds a session, code or device grant must have been expired before it
/// is purged, so a request racing the expiry boundary still sees a clean
/// "expired" rather than a missing record.
const EXPIRY_GRACE_SECONDS: i64 = 60;

/// Upper bound on the records of one kind purged per pass. The backend
/// reads its whole expiry index on every listing, so each kind is listed
/// exactly once per pass (no batching); a backlog beyond this bound is
/// drained over the following passes.
const MAX_PURGED_PER_KIND: usize = 50_000;

/// Record kinds swept, in order (the expiry index kinds written by the raft
/// driver).
const KINDS: [&str; 5] = ["session", "code", "device", "refresh", "refresh_tombstone"];

/// Outcome of a single sweep pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JanitorReport {
    /// Records purged this pass, by kind (`session`, `code`, `device`,
    /// `refresh`, `refresh_tombstone`).
    pub purged_by_kind: BTreeMap<String, usize>,
    /// Operations that failed this pass. Failures are isolated per record
    /// -- one failing delete does not abort the sweep -- and retried on the
    /// next pass.
    pub errors: usize,
}

impl JanitorReport {
    /// Total number of records purged across all kinds.
    pub fn total_purged(&self) -> usize {
        self.purged_by_kind.values().sum()
    }
}

/// Run a single janitor sweep pass. Idempotent and safe to call repeatedly.
///
/// Failing to list the expired records of one kind, or to purge one record,
/// is logged and counted in [`JanitorReport::errors`]; the pass continues
/// with the remaining records and kinds.
pub async fn run_once(state: &ServiceState) -> Result<JanitorReport, Oauth2SessionProviderError> {
    let retention_secs = i64::from(
        state
            .config_manager
            .config
            .read()
            .await
            .oauth2
            .revoked_family_retention_days,
    ) * 86_400;
    let now = Utc::now().timestamp();

    let mut report = JanitorReport::default();
    for kind in KINDS {
        let before = if kind == "refresh_tombstone" {
            now - retention_secs
        } else {
            now - EXPIRY_GRACE_SECONDS
        };
        sweep_kind(state, kind, before, &mut report).await;
    }

    if report.total_purged() > 0 || report.errors > 0 {
        emit_maintenance_event(&state.audit_dispatcher, &report);
    }
    Ok(report)
}

/// Purge up to [`MAX_PURGED_PER_KIND`] expired records of `kind`.
async fn sweep_kind(state: &ServiceState, kind: &str, before: i64, report: &mut JanitorReport) {
    let provider = state.provider.get_oauth2_session_provider();
    let expired = match provider
        .list_expired(state, kind, before, MAX_PURGED_PER_KIND)
        .await
    {
        Ok(expired) => expired,
        Err(e) => {
            warn!(
                kind,
                error = %e,
                "oauth2_session janitor: failed to list expired records, skipping kind"
            );
            report.errors += 1;
            return;
        }
    };

    for (kind, primary_key) in expired {
        match provider.purge_expired(state, &kind, &primary_key).await {
            Ok(()) => *report.purged_by_kind.entry(kind).or_default() += 1,
            Err(e) => {
                warn!(
                    kind = %kind,
                    error = %e,
                    "oauth2_session janitor: failed to purge record, continuing sweep"
                );
                report.errors += 1;
            }
        }
    }
}

/// Emit one `maintenance` CADF event per pass, carrying the purge counts.
/// Best-effort, mirroring [`crate::oauth2_key::janitor`]: this is background
/// housekeeping, not a user-facing request, so there is no real correlation
/// ID to thread through. The outcome is `success` when nothing failed,
/// `partial` when some records were purged but some operations failed, and
/// `failure` when the pass made no progress at all.
fn emit_maintenance_event(dispatcher: &Arc<AuditDispatcher>, report: &JanitorReport) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{node_id}:{}", Uuid::new_v4());
    let correlation_id = format!("janitor:{}", Uuid::new_v4());
    let initiator = Initiator::system("oauth2_session_janitor");
    let counts: Vec<(&str, u64)> = report
        .purged_by_kind
        .iter()
        .map(|(kind, count)| (kind.as_str(), *count as u64))
        .chain(std::iter::once(("errors", report.errors as u64)))
        .collect();
    let outcome = if report.errors == 0 {
        "success"
    } else if report.total_purged() > 0 {
        "partial"
    } else {
        "failure"
    };
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        "default".to_string(),
        correlation_id,
        Utc::now().to_rfc3339(),
        "purge_expired_sessions".to_string(),
        outcome.to_string(),
        Some(OutcomeReason::counts(&counts)),
        initiator,
        Target {
            id: node_id.clone(),
            type_uri: "data/security/keystone/oauth2_session".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
}

/// Run one sweep pass if this node is the current Raft leader. Returns
/// `None` when the node has no storage or is not the leader (nothing is
/// swept), `Some` with the pass outcome otherwise.
pub async fn sweep_if_leader(
    state: &ServiceState,
) -> Option<Result<JanitorReport, Oauth2SessionProviderError>> {
    let storage = state.storage.as_deref()?;
    if storage.current_leader().await != Some(storage.node_id().await) {
        return None;
    }
    Some(run_once(state).await)
}

/// Spawn the leader-gated background sweep loop. Intended to be called once
/// at server startup with the long-lived `ServiceState`. The interval is
/// read from `[oauth2] session_janitor_interval_seconds` on every tick, so a
/// config reload takes effect without a restart.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(configured_interval(&state).await);
        loop {
            interval.tick().await;

            let period = configured_interval(&state).await;
            if interval.period() != period {
                // `tokio::time::Interval` has no period setter; rebuild
                // instead. The fresh interval ticks immediately, so one
                // extra sweep runs right after a config change, then the
                // new period applies.
                interval = tokio::time::interval(period);
                continue;
            }

            match sweep_if_leader(&state).await {
                Some(Ok(report)) if report.total_purged() > 0 || report.errors > 0 => {
                    info!(
                        purged = report.total_purged(),
                        purged_by_kind = ?report.purged_by_kind,
                        errors = report.errors,
                        "oauth2_session janitor: sweep complete"
                    );
                }
                Some(Ok(_)) | None => {}
                Some(Err(e)) => warn!(
                    error = %e,
                    "oauth2_session janitor: sweep aborted"
                ),
            }
        }
    });
}

/// Current `[oauth2] session_janitor_interval_seconds` as a `Duration`.
async fn configured_interval(state: &ServiceState) -> Duration {
    let interval_secs = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .session_janitor_interval_seconds;
    Duration::from_secs(u64::from(interval_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;
    use crate::tests::get_mocked_state;

    async fn state_with(mock: MockOauth2SessionProvider) -> ServiceState {
        get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_oauth2_session(mock)),
        )
        .await
    }

    #[tokio::test]
    async fn test_run_once_purges_expired_records() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_expired().returning(|_, kind, _, _| {
            Ok(match kind {
                "session" => vec![("session".to_string(), "s1".to_string())],
                "code" => vec![("code".to_string(), "c1".to_string())],
                _ => vec![],
            })
        });
        mock.expect_purge_expired()
            .times(2)
            .returning(|_, _, _| Ok(()));

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report.purged_by_kind.get("session"), Some(&1));
        assert_eq!(report.purged_by_kind.get("code"), Some(&1));
        assert_eq!(report.total_purged(), 2);
        assert_eq!(report.errors, 0);
    }

    #[tokio::test]
    async fn test_run_once_leaves_unexpired_records_alone() {
        let mut mock = MockOauth2SessionProvider::default();
        // Nothing is expired; `purge_expired` has no expectation, so any
        // call panics the mock.
        mock.expect_list_expired()
            .returning(|_, _, _, _| Ok(vec![]));

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report, JanitorReport::default());
    }

    #[tokio::test]
    async fn test_run_once_uses_retention_for_tombstones_only() {
        let mut mock = MockOauth2SessionProvider::default();
        let now = Utc::now().timestamp();
        mock.expect_list_expired()
            .returning(move |_, kind, before, _| {
                if kind == "refresh_tombstone" {
                    // Default retention: 30 days.
                    assert!((now - before - 30 * 86_400).abs() <= 5, "before={before}");
                } else {
                    assert!((now - before - EXPIRY_GRACE_SECONDS).abs() <= 5);
                }
                Ok(vec![])
            });

        run_once(&state_with(mock).await).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_once_purges_revoked_family_after_retention() {
        let mut mock = MockOauth2SessionProvider::default();
        // The backend only lists a tombstone once it is past the retention
        // cutoff; the janitor purges whatever it lists.
        mock.expect_list_expired().returning(|_, kind, _, _| {
            Ok(if kind == "refresh_tombstone" {
                vec![("refresh_tombstone".to_string(), "tombstone".to_string())]
            } else {
                vec![]
            })
        });
        mock.expect_purge_expired()
            .withf(|_, kind, pk| kind == "refresh_tombstone" && pk == "tombstone")
            .times(1)
            .returning(|_, _, _| Ok(()));

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report.purged_by_kind.get("refresh_tombstone"), Some(&1));
    }

    #[tokio::test]
    async fn test_run_once_isolates_failing_purge() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_expired().returning(|_, kind, _, _| {
            Ok(if kind == "session" {
                vec![
                    ("session".to_string(), "bad".to_string()),
                    ("session".to_string(), "good".to_string()),
                ]
            } else {
                vec![]
            })
        });
        mock.expect_purge_expired().returning(|_, _, pk| {
            if pk == "bad" {
                Err(Oauth2SessionProviderError::RaftNotAvailable)
            } else {
                Ok(())
            }
        });

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report.purged_by_kind.get("session"), Some(&1));
        assert_eq!(report.errors, 1);
    }

    #[tokio::test]
    async fn test_run_once_isolates_failing_list() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_expired().returning(|_, kind, _, _| {
            if kind == "session" {
                Err(Oauth2SessionProviderError::RaftNotAvailable)
            } else if kind == "code" {
                Ok(vec![("code".to_string(), "c1".to_string())])
            } else {
                Ok(vec![])
            }
        });
        mock.expect_purge_expired().returning(|_, _, _| Ok(()));

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report.purged_by_kind.get("code"), Some(&1));
        assert_eq!(report.errors, 1);
    }

    #[tokio::test]
    async fn test_run_once_lists_each_kind_once_per_pass() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_expired()
            .times(KINDS.len())
            .withf(|_, _, _, limit| *limit == MAX_PURGED_PER_KIND)
            .returning(|_, kind, _, _| {
                Ok(if kind == "session" {
                    (0..1_000)
                        .map(|i| ("session".to_string(), format!("s{i}")))
                        .collect()
                } else {
                    vec![]
                })
            });
        mock.expect_purge_expired().returning(|_, _, _| Ok(()));

        let report = run_once(&state_with(mock).await).await.unwrap();
        assert_eq!(report.purged_by_kind.get("session"), Some(&1_000));
    }

    #[tokio::test]
    async fn test_sweep_if_leader_skips_node_without_storage() {
        // No expectations: any call into the provider panics the mock.
        let state = state_with(MockOauth2SessionProvider::default()).await;
        assert!(state.storage.is_none());
        assert!(sweep_if_leader(&state).await.is_none());
    }

    #[tokio::test]
    async fn test_emit_maintenance_event_carries_counts() {
        let key: Arc<[u8]> = Arc::from(b"test-key".as_slice());
        let (dispatcher, mut receivers) =
            AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 0);
        let mut report = JanitorReport::default();
        report.purged_by_kind.insert("session".to_string(), 3);
        report.errors = 1;

        emit_maintenance_event(&dispatcher, &report);

        let event = receivers.perimeter.try_recv().unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["action"], "purge_expired_sessions");
        assert_eq!(json["outcome"], "partial");
        assert_eq!(json["outcome_reason"], "session=3,errors=1");
        assert_eq!(
            json["target"]["type_uri"],
            "data/security/keystone/oauth2_session"
        );

        // A pass with no failures at all is `success` ...
        let mut clean = JanitorReport::default();
        clean.purged_by_kind.insert("code".to_string(), 2);
        emit_maintenance_event(&dispatcher, &clean);
        let json = serde_json::to_value(receivers.perimeter.try_recv().unwrap()).unwrap();
        assert_eq!(json["outcome"], "success");
        assert_eq!(json["outcome_reason"], "code=2,errors=0");

        // ... and a pass that made no progress at all is `failure`.
        let broken = JanitorReport {
            errors: 2,
            ..JanitorReport::default()
        };
        emit_maintenance_event(&dispatcher, &broken);
        let json = serde_json::to_value(receivers.perimeter.try_recv().unwrap()).unwrap();
        assert_eq!(json["outcome"], "failure");
        assert_eq!(json["outcome_reason"], "errors=2");
    }
}
