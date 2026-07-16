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

//! Quorum-bypass guardrail (ADR 0028 §1).
//!
//! The local-write path must only unlock when the node genuinely cannot
//! reach Raft quorum, not merely on operator say-so — `--local-quorum-bypass`
//! is refused unless the guardrail agrees. This module intentionally depends
//! on nothing beyond `chrono`, so it can be unit-tested with synthetic
//! inputs; callers translate their real `RaftMetrics`/`StorageApi` state
//! into the plain parameters below.

use std::sync::Mutex;

use chrono::{DateTime, Utc};

/// Guardrail policy, sourced from the `[local_emergency]` config section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardrailConfig {
    /// Node-local opt-in: `[local_emergency].enabled`. When `false`, the
    /// bypass is refused unconditionally.
    pub enabled: bool,
    /// How long the leader must have been unknown before the bypass
    /// unlocks, in seconds
    /// (`[local_emergency].leaderless_grace_period_seconds`).
    pub leaderless_grace_period_seconds: u64,
}

/// Decide whether a `--local-quorum-bypass` request may proceed.
///
/// # Parameters
/// - `config`: the node's `[local_emergency]` policy
/// - `current_leader`: `StorageApi::current_leader()` result — `Some` means
///   quorum is healthy and the bypass must be refused regardless of grace
///   period
/// - `leaderless_since`: when the leader was first observed to be unknown;
///   `None` means it just became unknown this instant (grace period starts now,
///   so the request is refused)
/// - `now`: caller-supplied clock, so tests don't need to sleep in wall time
///
/// # Returns
/// `true` only if the node opted in *and* quorum has been unreachable for at
/// least the configured grace period.
pub fn is_quorum_bypass_allowed(
    config: &GuardrailConfig,
    current_leader: Option<u64>,
    leaderless_since: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if !config.enabled {
        return false;
    }
    if current_leader.is_some() {
        return false;
    }
    let Some(since) = leaderless_since else {
        return false;
    };
    let elapsed = (now - since).num_seconds().max(0) as u64;
    elapsed >= config.leaderless_grace_period_seconds
}

/// Tracks how long the Raft leader has been unknown, so the quorum-bypass
/// guardrail can require a sustained outage rather than unlocking on a
/// single transient election blip.
///
/// `StorageApi::current_leader()` (defined in the much heavier
/// `storage-api`/`storage` crates, deliberately not a dependency of this
/// one) only reports the leader at the instant it's called; this wrapper is
/// what turns repeated `None` observations into the "since when" timestamp
/// [`is_quorum_bypass_allowed`] needs.
pub struct LeaderlessTracker {
    leaderless_since: Mutex<Option<DateTime<Utc>>>,
}

impl Default for LeaderlessTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaderlessTracker {
    /// Create a tracker that has not yet observed a leaderless state.
    pub fn new() -> Self {
        Self {
            leaderless_since: Mutex::new(None),
        }
    }

    /// Record the latest `current_leader()` observation.
    ///
    /// Call this on every poll of Raft state (or at least whenever the
    /// guardrail is evaluated) — a `Some(_)` observation resets the tracked
    /// outage start, so a leader re-election immediately re-arms the grace
    /// period.
    pub fn observe(&self, current_leader: Option<u64>, now: DateTime<Utc>) {
        let mut guard = match self.leaderless_since.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match current_leader {
            Some(_) => *guard = None,
            None => {
                if guard.is_none() {
                    *guard = Some(now);
                }
            }
        }
    }

    /// Evaluate the guardrail using the latest observation recorded via
    /// [`Self::observe`].
    pub fn is_bypass_allowed(
        &self,
        config: &GuardrailConfig,
        current_leader: Option<u64>,
        now: DateTime<Utc>,
    ) -> bool {
        let leaderless_since = match self.leaderless_since.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        };
        is_quorum_bypass_allowed(config, current_leader, leaderless_since, now)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn config(enabled: bool) -> GuardrailConfig {
        GuardrailConfig {
            enabled,
            leaderless_grace_period_seconds: 30,
        }
    }

    #[test]
    fn refused_when_disabled() {
        let now = Utc::now();
        assert!(!is_quorum_bypass_allowed(
            &config(false),
            None,
            Some(now - Duration::seconds(60)),
            now
        ));
    }

    #[test]
    fn refused_when_leader_known() {
        let now = Utc::now();
        assert!(!is_quorum_bypass_allowed(
            &config(true),
            Some(1),
            Some(now - Duration::seconds(60)),
            now
        ));
    }

    #[test]
    fn refused_when_leaderless_since_unknown() {
        let now = Utc::now();
        assert!(!is_quorum_bypass_allowed(&config(true), None, None, now));
    }

    #[test]
    fn refused_within_grace_period() {
        let now = Utc::now();
        assert!(!is_quorum_bypass_allowed(
            &config(true),
            None,
            Some(now - Duration::seconds(5)),
            now
        ));
    }

    #[test]
    fn allowed_after_grace_period() {
        let now = Utc::now();
        assert!(is_quorum_bypass_allowed(
            &config(true),
            None,
            Some(now - Duration::seconds(31)),
            now
        ));
    }

    #[test]
    fn leaderless_tracker_refuses_before_grace_period() {
        let tracker = LeaderlessTracker::new();
        let t0 = Utc::now();
        tracker.observe(None, t0);

        assert!(!tracker.is_bypass_allowed(&config(true), None, t0 + Duration::seconds(5)));
    }

    #[test]
    fn leaderless_tracker_allows_after_grace_period() {
        let tracker = LeaderlessTracker::new();
        let t0 = Utc::now();
        tracker.observe(None, t0);

        assert!(tracker.is_bypass_allowed(&config(true), None, t0 + Duration::seconds(31)));
    }

    #[test]
    fn leaderless_tracker_resets_on_leader_observed() {
        let tracker = LeaderlessTracker::new();
        let t0 = Utc::now();
        tracker.observe(None, t0);
        // Leader comes back before the grace period elapses.
        tracker.observe(Some(1), t0 + Duration::seconds(10));
        // And is lost again — the outage clock must restart from here, not
        // from t0.
        tracker.observe(None, t0 + Duration::seconds(20));

        assert!(!tracker.is_bypass_allowed(&config(true), None, t0 + Duration::seconds(40)));
        assert!(tracker.is_bypass_allowed(&config(true), None, t0 + Duration::seconds(51)));
    }

    #[test]
    fn leaderless_tracker_refused_when_leader_currently_known() {
        let tracker = LeaderlessTracker::new();
        let t0 = Utc::now();
        tracker.observe(None, t0);

        assert!(!tracker.is_bypass_allowed(&config(true), Some(1), t0 + Duration::seconds(60)));
    }
}
