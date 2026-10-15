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

//! Progress reporting while a node catches up with the cluster.
//!
//! A node that (re)joins with an empty or stale log replays entries or
//! installs a snapshot before it can serve traffic (`/ready` stays 503, see
//! [`crate::readiness`]). Without any log output that looks like a hang, so
//! a background task logs the catch-up progress periodically and once more
//! when it is done.

use std::time::{Duration, Instant};

use openraft::RaftMetrics;

use crate::TypeConfig;
use crate::prometheus_metrics::apply_lag;

/// How often the catch-up progress is logged while the node is syncing.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Entries by which the applied index may trail the cluster commit index
/// before the node counts as syncing. Smaller gaps are normal under load.
const SYNC_LAG_THRESHOLD: u64 = 100;

/// What [`SyncTracker::observe`] asks the caller to log.
#[derive(Debug, PartialEq)]
pub(crate) enum SyncEvent {
    /// The node is still catching up.
    Progress {
        applied: u64,
        committed: u64,
        /// Entries applied per second since the previous observation.
        rate: f64,
        /// Estimated time to completion, when the rate is known.
        eta: Option<Duration>,
    },
    /// The node has caught up with the cluster.
    Complete { applied: u64, elapsed: Duration },
}

/// Tracks catch-up state across observations of the Raft metrics.
#[derive(Debug, Default)]
pub(crate) struct SyncTracker {
    /// Start of the current catch-up and the applied index at that time.
    syncing_since: Option<(Instant, u64)>,
    last: Option<(Instant, u64)>,
}

impl SyncTracker {
    /// Feed the applied and commit indexes observed at `now`.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        applied: u64,
        committed: u64,
    ) -> Option<SyncEvent> {
        let lag = committed.saturating_sub(applied);
        let previous = self.last.replace((now, applied));

        if lag <= SYNC_LAG_THRESHOLD {
            return self
                .syncing_since
                .take()
                .map(|(since, _)| SyncEvent::Complete {
                    applied,
                    elapsed: now.duration_since(since),
                });
        }

        self.syncing_since.get_or_insert((now, applied));
        let rate = previous
            .and_then(|(at, idx)| {
                let secs = now.duration_since(at).as_secs_f64();
                (secs > 0.0).then(|| applied.saturating_sub(idx) as f64 / secs)
            })
            .unwrap_or(0.0);
        let eta = (rate > 0.0).then(|| Duration::from_secs_f64(lag as f64 / rate));
        Some(SyncEvent::Progress {
            applied,
            committed,
            rate,
            eta,
        })
    }
}

/// Log catch-up progress of this node. `live` returns the current Raft
/// metrics; the task runs for the lifetime of the process.
pub(crate) async fn report_sync_progress(live: impl Fn() -> RaftMetrics<TypeConfig>, node_id: u64) {
    let mut tracker = SyncTracker::default();
    let mut interval = tokio::time::interval(REPORT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let snapshot = live();
        // The commit index is only known once a leader has contacted us.
        let Some(lag) = apply_lag(&snapshot) else {
            continue;
        };
        let applied = snapshot.last_applied.map(|l| l.index).unwrap_or(0);
        match tracker.observe(Instant::now(), applied, applied + lag) {
            Some(SyncEvent::Progress {
                applied,
                committed,
                rate,
                eta,
            }) => {
                tracing::info!(
                    node_id,
                    applied,
                    committed,
                    remaining = committed.saturating_sub(applied),
                    percent = percent(applied, committed),
                    entries_per_sec = rate.round() as u64,
                    eta_secs = eta.map(|d| d.as_secs()),
                    leader = ?snapshot.current_leader,
                    "Syncing with the cluster: node is catching up and not ready yet"
                );
            }
            Some(SyncEvent::Complete { applied, elapsed }) => {
                tracing::info!(
                    node_id,
                    applied,
                    elapsed_secs = elapsed.as_secs(),
                    "Sync with the cluster finished"
                );
            }
            None => {}
        }
    }
}

fn percent(applied: u64, committed: u64) -> u64 {
    if committed == 0 {
        return 100;
    }
    (applied.min(committed) as u128 * 100 / committed as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_lag_is_not_syncing() {
        let mut t = SyncTracker::default();
        assert_eq!(t.observe(Instant::now(), 950, 1000), None);
    }

    #[test]
    fn reports_progress_rate_and_eta() {
        let mut t = SyncTracker::default();
        let t0 = Instant::now();
        let first = t.observe(t0, 0, 10_000);
        assert!(matches!(first, Some(SyncEvent::Progress { rate, .. }) if rate == 0.0));
        let second = t.observe(t0 + Duration::from_secs(10), 2_000, 10_000);
        assert_eq!(
            second,
            Some(SyncEvent::Progress {
                applied: 2_000,
                committed: 10_000,
                rate: 200.0,
                eta: Some(Duration::from_secs(40)),
            })
        );
    }

    #[test]
    fn completes_once_after_catching_up() {
        let mut t = SyncTracker::default();
        let t0 = Instant::now();
        t.observe(t0, 0, 10_000);
        let done = t.observe(t0 + Duration::from_secs(30), 9_990, 10_000);
        assert_eq!(
            done,
            Some(SyncEvent::Complete {
                applied: 9_990,
                elapsed: Duration::from_secs(30),
            })
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(40), 10_000, 10_000),
            None
        );
    }

    #[test]
    fn percent_is_bounded() {
        assert_eq!(percent(0, 0), 100);
        assert_eq!(percent(50, 200), 25);
        assert_eq!(percent(300, 200), 100);
    }
}
