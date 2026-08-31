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
//! # Raft Prometheus metrics (ADR 0031, "Raft / distributed storage" section)
//!
//! Unlike the other ADR 0031 subsystems (audit, auth-plugin, ...), which are
//! pure process-wide counters and are naturally modeled as a single global
//! `static`, Raft state is inherently **per-node-instance**: each Raft node
//! (this process) has its own term/leadership/log-position view. This module
//! therefore exposes [`KeystoneRaftPrometheusMetrics`] as a small struct
//! owned by the storage layer (one instance per `FjallStateMachine`/
//! `app::Storage` pair), not a `static`.
//!
//! Named distinctly from `openraft::RaftMetrics<C>` (re-exported in this
//! crate as `types::RaftMetrics`) to avoid confusion between openraft's own
//! live-metrics snapshot type and this Prometheus-exposition wrapper around
//! it.
//!
//! Four of the six series (`is_leader`, `term`, `last_log_index`,
//! `last_applied_index`, `replication_lag`) are point-in-time gauges derived
//! by reading through to `openraft`'s own metrics watch channel
//! (`Raft::metrics().borrow_watched()`) on every call to
//! [`KeystoneRaftPrometheusMetrics::snapshot_from`] — that read is a cheap,
//! non-blocking watch-channel borrow, so it is safe to do on every `/metrics`
//! scrape rather than caching. The sixth, `apply_duration_seconds`, is a real
//! per-operation latency histogram recorded incrementally at the actual
//! state-machine apply call site (`store::state_machine`), since a snapshot
//! read can't reconstruct latency after the fact.

use std::collections::BTreeMap;

use openstack_keystone_metrics::{Gauge, Histogram, LabeledGauge, write_metric_header};

use crate::TypeConfig;

/// Per-node Raft Prometheus metrics (ADR 0031). See the module docs for why
/// this is a struct instance rather than a `static`, and for the naming
/// rationale relative to `openraft::RaftMetrics`.
pub struct KeystoneRaftPrometheusMetrics {
    is_leader: Gauge,
    term: Gauge,
    last_log_index: Gauge,
    last_applied_index: Gauge,
    /// `peer_id` is openraft's own `u64` node id, stringified — a small,
    /// config-fixed cluster member set (ADR 0031 cardinality guardrail).
    replication_lag: LabeledGauge<1>,
    /// Recorded incrementally via `.record()` at the actual apply call site
    /// (`store::state_machine::FjallStateMachine::apply`) — a real
    /// per-operation latency measurement, not a snapshot read-through like
    /// the gauges above. `pub` so the apply call site (a different module
    /// in this crate) can record into it directly.
    pub apply_duration_seconds: Histogram,
}

impl Default for KeystoneRaftPrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystoneRaftPrometheusMetrics {
    pub fn new() -> Self {
        Self {
            is_leader: Gauge::new(),
            term: Gauge::new(),
            last_log_index: Gauge::new(),
            last_applied_index: Gauge::new(),
            replication_lag: LabeledGauge::new(["peer_id"]),
            apply_duration_seconds: Histogram::new(),
        }
    }

    /// Updates the gauges from a live `openraft::RaftMetrics` snapshot.
    /// `node_id` is this node's own Raft id, used to derive
    /// `keystone_raft_is_leader`.
    ///
    /// Cheap to call on every `/metrics` scrape: `metrics` is expected to
    /// come straight from `Raft::metrics().borrow_watched()`, which is a
    /// non-blocking watch-channel read, not a round-trip into the Raft core.
    pub fn snapshot_from(&self, metrics: &openraft::RaftMetrics<TypeConfig>, node_id: u64) {
        self.is_leader
            .set(i64::from(metrics.current_leader == Some(node_id)));
        // `Term` for this crate's `TypeConfig` is `u64` (see
        // `proto_impl::impl_leader_id`); term/index values won't
        // realistically exceed `i64::MAX`.
        self.term.set(metrics.current_term as i64);

        let last_log_index = metrics.last_log_index.unwrap_or(0);
        self.last_log_index.set(last_log_index as i64);

        let last_applied_index = metrics
            .last_applied
            .as_ref()
            .map(|l| l.index())
            .unwrap_or(0);
        self.last_applied_index.set(last_applied_index as i64);

        // `replication` is only `Some` when this node is the cluster
        // leader (openraft only tracks per-peer replication progress on
        // the leader). On a follower/candidate the previously-recorded
        // per-peer lag values are simply left stale until this node
        // becomes leader again; they carry no meaning while not leader,
        // so they are harmless to leave as-is.
        if let Some(replication) = &metrics.replication {
            self.set_replication_lag(replication, last_log_index);
        }
    }

    fn set_replication_lag(
        &self,
        replication: &BTreeMap<u64, Option<crate::types::LogId>>,
        last_log_index: u64,
    ) {
        for (peer_id, match_log_id) in replication {
            let match_index = match_log_id.as_ref().map(|l| l.index()).unwrap_or(0);
            let lag = last_log_index.saturating_sub(match_index);
            self.replication_lag.set([&peer_id.to_string()], lag as i64);
        }
    }

    /// Renders all six `keystone_raft_*` series (ADR 0031) in Prometheus
    /// text-exposition format, first refreshing the gauges from
    /// `live_metrics` (see [`Self::snapshot_from`]).
    ///
    /// Not a `PrometheusText` impl: that trait's `format_prometheus_text`
    /// takes no arguments, but rendering the gauges needs a fresh
    /// `openraft::RaftMetrics` snapshot and this node's id on every call —
    /// an explicit-argument inherent method expresses that read-through
    /// requirement directly, without a mutable/interior-cached copy of the
    /// live metrics elsewhere just to satisfy the trait's `&self`-only shape.
    pub fn format_prometheus_text(
        &self,
        live_metrics: &openraft::RaftMetrics<TypeConfig>,
        node_id: u64,
    ) -> String {
        self.snapshot_from(live_metrics, node_id);

        let mut out = String::new();

        write_metric_header(
            &mut out,
            "keystone_raft_is_leader",
            "Whether this node is the current Raft leader (1) or not (0).",
            "gauge",
        );
        self.is_leader
            .write_line(&mut out, "keystone_raft_is_leader");

        write_metric_header(
            &mut out,
            "keystone_raft_term",
            "Current Raft term of this node.",
            "gauge",
        );
        self.term.write_line(&mut out, "keystone_raft_term");

        write_metric_header(
            &mut out,
            "keystone_raft_last_log_index",
            "Last Raft log index appended to this node's log (tail position).",
            "gauge",
        );
        self.last_log_index
            .write_line(&mut out, "keystone_raft_last_log_index");

        write_metric_header(
            &mut out,
            "keystone_raft_last_applied_index",
            "Last Raft log index applied to this node's state machine.",
            "gauge",
        );
        self.last_applied_index
            .write_line(&mut out, "keystone_raft_last_applied_index");

        write_metric_header(
            &mut out,
            "keystone_raft_replication_lag",
            "Log entries by which a peer's match index trails this leader's \
             last log index (last_log_index - peer match_index); only \
             populated while this node is leader.",
            "gauge",
        );
        self.replication_lag
            .write_lines(&mut out, "keystone_raft_replication_lag");

        write_metric_header(
            &mut out,
            "keystone_raft_apply_duration_seconds",
            "State-machine apply latency (per committed log entry).",
            "histogram",
        );
        self.apply_duration_seconds.write_lines(
            &mut out,
            "keystone_raft_apply_duration_seconds",
            &[],
            &[],
        );

        out
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use openraft::RaftMetrics;

    use super::*;
    use crate::types::LogId;

    /// Builds a hand-crafted `openraft::RaftMetrics<TypeConfig>` snapshot —
    /// spinning up a real raft cluster is out of scope for a unit test, so
    /// this mirrors the `openraft::RaftMetrics::new_initial` starting point
    /// and overrides the fields this module actually reads.
    fn metrics_fixture(
        node_id: u64,
        current_leader: Option<u64>,
        term: u64,
        last_log_index: Option<u64>,
        last_applied_index: Option<u64>,
        replication: Option<BTreeMap<u64, Option<u64>>>,
    ) -> RaftMetrics<TypeConfig> {
        let mut metrics = RaftMetrics::<TypeConfig>::new_initial(node_id);
        metrics.current_leader = current_leader;
        metrics.current_term = term;
        metrics.last_log_index = last_log_index;
        metrics.last_applied = last_applied_index.map(|idx| LogId::new(term, idx));
        metrics.replication = replication.map(|m| {
            m.into_iter()
                .map(|(id, idx)| (id, idx.map(|i| LogId::new(term, i))))
                .collect()
        });
        metrics
    }

    #[test]
    fn snapshot_from_sets_leader_and_position_gauges_when_leader() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let live = metrics_fixture(1, Some(1), 7, Some(100), Some(90), None);
        m.snapshot_from(&live, 1);

        assert_eq!(m.is_leader.get(), 1);
        assert_eq!(m.term.get(), 7);
        assert_eq!(m.last_log_index.get(), 100);
        assert_eq!(m.last_applied_index.get(), 90);
    }

    #[test]
    fn snapshot_from_reports_not_leader_for_a_different_current_leader() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let live = metrics_fixture(2, Some(1), 7, Some(100), Some(90), None);
        m.snapshot_from(&live, 2);

        assert_eq!(m.is_leader.get(), 0);
    }

    #[test]
    fn snapshot_from_reports_not_leader_when_no_leader_elected() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let live = metrics_fixture(1, None, 3, None, None, None);
        m.snapshot_from(&live, 1);

        assert_eq!(m.is_leader.get(), 0);
        assert_eq!(m.last_log_index.get(), 0);
        assert_eq!(m.last_applied_index.get(), 0);
    }

    #[test]
    fn snapshot_from_computes_replication_lag_per_peer() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let replication = BTreeMap::from([(2u64, Some(80u64)), (3u64, Some(100u64)), (4u64, None)]);
        let live = metrics_fixture(1, Some(1), 7, Some(100), Some(100), Some(replication));
        m.snapshot_from(&live, 1);

        assert_eq!(m.replication_lag.get(["2"]), 20);
        assert_eq!(m.replication_lag.get(["3"]), 0);
        assert_eq!(m.replication_lag.get(["4"]), 100);
        // Unknown/unseen peer defaults to 0, not a panic.
        assert_eq!(m.replication_lag.get(["5"]), 0);
    }

    #[test]
    fn replication_lag_absent_when_not_leader() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let live = metrics_fixture(2, Some(1), 7, Some(100), Some(90), None);
        m.snapshot_from(&live, 2);

        assert_eq!(m.replication_lag.get(["1"]), 0);
    }

    #[test]
    fn format_prometheus_text_includes_all_six_series() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let replication = BTreeMap::from([(2u64, Some(90u64))]);
        let live = metrics_fixture(1, Some(1), 7, Some(100), Some(95), Some(replication));

        let text = m.format_prometheus_text(&live, 1);

        assert!(text.contains("# TYPE keystone_raft_is_leader gauge"));
        assert!(text.contains("keystone_raft_is_leader 1\n"));
        assert!(text.contains("# TYPE keystone_raft_term gauge"));
        assert!(text.contains("keystone_raft_term 7\n"));
        assert!(text.contains("# TYPE keystone_raft_last_log_index gauge"));
        assert!(text.contains("keystone_raft_last_log_index 100\n"));
        assert!(text.contains("# TYPE keystone_raft_last_applied_index gauge"));
        assert!(text.contains("keystone_raft_last_applied_index 95\n"));
        assert!(text.contains("# TYPE keystone_raft_replication_lag gauge"));
        assert!(text.contains("keystone_raft_replication_lag{peer_id=\"2\"} 10\n"));
        assert!(text.contains("# TYPE keystone_raft_apply_duration_seconds histogram"));
        assert!(text.contains("keystone_raft_apply_duration_seconds_count 0\n"));
    }

    #[test]
    fn apply_duration_seconds_is_recorded_incrementally_and_rendered() {
        let m = KeystoneRaftPrometheusMetrics::new();
        m.apply_duration_seconds.record(0.01);
        m.apply_duration_seconds.record(0.2);

        let live = metrics_fixture(1, None, 0, None, None, None);
        let text = m.format_prometheus_text(&live, 1);

        assert!(text.contains("keystone_raft_apply_duration_seconds_count 2\n"));
    }
}
