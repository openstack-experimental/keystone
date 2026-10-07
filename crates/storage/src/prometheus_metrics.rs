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
//!
//! The operational series the operator guide refers to (quarantine, DEK
//! lifecycle, log nonce counter, snapshot and disk usage; GitHub #1306) are
//! split in two groups:
//!
//! * event counters recorded where the event happens
//!   (`gcm_failures_total`, `dek_reencrypt_*_total`,
//!   `write_rate_version_max`), owned by this struct;
//! * point-in-time state read on every scrape from the state machine and log
//!   store, passed in as a [`RaftNodeStatus`] and rendered by
//!   [`format_node_status_text`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};

use openstack_keystone_metrics::{
    Counter, Gauge, Histogram, LabeledGauge, escape_label_value, write_metric_header,
};

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
    /// Raft leader id as seen by this node; `-1` while no leader is known.
    current_leader_id: Gauge,
    /// Number of voters in the effective membership config.
    membership_voters: Gauge,
    /// Number of learners in the effective membership config.
    membership_learners: Gauge,
    /// Cluster commit index (as reported by the leader) minus this node's
    /// last applied index.
    apply_lag: Gauge,
    /// Last log index included in this node's latest snapshot.
    snapshot_last_index: Gauge,
    /// AES-GCM tag verification failures on state reads (the quarantine
    /// trigger). Incremented on every failure, not only on the one that
    /// crosses the quarantine threshold.
    pub gcm_failures_total: Counter,
    /// Highest per-record write version seen by this node since start
    /// (ADR 0016-v2 §10 invariant 9).
    write_rate_version_max: AtomicU32,
    /// Records re-encrypted under the current DEK by background sweeps.
    dek_reencrypt_migrated_total: Counter,
    /// Records the background sweeps skipped (CAS retries exhausted).
    dek_reencrypt_skipped_total: Counter,
    /// Records skipped by the most recent sweep pass.
    dek_reencrypt_last_skipped: Gauge,
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
            current_leader_id: Gauge::new(),
            membership_voters: Gauge::new(),
            membership_learners: Gauge::new(),
            apply_lag: Gauge::new(),
            snapshot_last_index: Gauge::new(),
            gcm_failures_total: Counter::new(),
            write_rate_version_max: AtomicU32::new(0),
            dek_reencrypt_migrated_total: Counter::new(),
            dek_reencrypt_skipped_total: Counter::new(),
            dek_reencrypt_last_skipped: Gauge::new(),
        }
    }

    /// Records a per-record write version, keeping the maximum.
    pub fn record_write_version(&self, version: u32) {
        self.write_rate_version_max
            .fetch_max(version, Ordering::Relaxed);
    }

    /// Records the outcome of one background re-encryption pass.
    pub fn record_reencrypt_report(&self, report: &crate::store::state_machine::ReencryptReport) {
        self.dek_reencrypt_migrated_total.add(report.migrated);
        self.dek_reencrypt_skipped_total.add(report.skipped);
        self.dek_reencrypt_last_skipped
            .set(i64::try_from(report.skipped).unwrap_or(i64::MAX));
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

        self.current_leader_id
            .set(metrics.current_leader.map_or(-1, |id| id as i64));
        let membership = metrics.membership_config.membership();
        self.membership_voters
            .set(membership.voter_ids().count() as i64);
        self.membership_learners
            .set(membership.learner_ids().count() as i64);
        self.apply_lag
            .set(apply_lag(metrics).map_or(0, |lag| lag as i64));
        self.snapshot_last_index.set(
            metrics
                .snapshot
                .as_ref()
                .map(|l| l.index() as i64)
                .unwrap_or(0),
        );
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

        let gauges: [(&str, &str, &Gauge); 6] = [
            (
                "keystone_raft_current_leader_id",
                "Raft node id of the leader as seen by this node (-1 when unknown).",
                &self.current_leader_id,
            ),
            (
                "keystone_raft_membership_voters",
                "Number of voters in the effective Raft membership.",
                &self.membership_voters,
            ),
            (
                "keystone_raft_membership_learners",
                "Number of learners in the effective Raft membership.",
                &self.membership_learners,
            ),
            (
                "keystone_raft_apply_lag",
                "Log entries by which this node's last applied index trails the \
                 cluster commit index reported by the leader.",
                &self.apply_lag,
            ),
            (
                "keystone_raft_snapshot_last_index",
                "Last Raft log index included in this node's latest snapshot.",
                &self.snapshot_last_index,
            ),
            (
                "keystone_raft_dek_reencrypt_last_skipped",
                "Records skipped by the most recent DEK re-encryption pass.",
                &self.dek_reencrypt_last_skipped,
            ),
        ];
        for (name, help, gauge) in gauges {
            write_metric_header(&mut out, name, help, "gauge");
            gauge.write_line(&mut out, name);
        }

        write_metric_header(
            &mut out,
            "keystone_raft_write_rate_version_max",
            "Highest per-record write version seen by this node since start \
             (DEK rotation is required before it reaches 2^30).",
            "gauge",
        );
        out.push_str(&format!(
            "keystone_raft_write_rate_version_max {}\n",
            self.write_rate_version_max.load(Ordering::Relaxed)
        ));

        let counters: [(&str, &str, &Counter); 3] = [
            (
                "keystone_raft_gcm_failures_total",
                "AES-GCM tag verification failures on state reads.",
                &self.gcm_failures_total,
            ),
            (
                "keystone_raft_dek_reencrypt_migrated_total",
                "Records re-encrypted under the current DEK by background sweeps.",
                &self.dek_reencrypt_migrated_total,
            ),
            (
                "keystone_raft_dek_reencrypt_skipped_total",
                "Records skipped by background DEK re-encryption sweeps.",
                &self.dek_reencrypt_skipped_total,
            ),
        ];
        for (name, help, counter) in counters {
            write_metric_header(&mut out, name, help, "counter");
            counter.write_line(&mut out, name);
        }

        out
    }
}

/// Log entries by which `last_applied` trails the cluster commit index
/// reported by the leader, or `None` when the commit index is unknown.
pub fn apply_lag(metrics: &openraft::RaftMetrics<TypeConfig>) -> Option<u64> {
    let committed = metrics.cluster_committed.as_ref()?.index();
    let applied = metrics
        .last_applied
        .as_ref()
        .map(|l| l.index())
        .unwrap_or(0);
    Some(committed.saturating_sub(applied))
}

/// Point-in-time node state read on every `/metrics` scrape (see the module
/// docs). `None` fields could not be read and are not rendered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RaftNodeStatus {
    /// Partitions this node has quarantined (reads blocked).
    pub quarantined_partitions: Vec<String>,
    /// Version of the active DEK epoch.
    pub dek_version: u32,
    /// Retired DEK epochs still held for decryption / re-encryption.
    pub dek_retired_epochs: usize,
    /// Revoked DEK versions (emergency rotations).
    pub dek_revoked_epochs: usize,
    /// Emergency DEK rotations staged and awaiting confirmation.
    pub dek_pending_rotations: usize,
    /// Next log-encryption nonce counter value.
    pub log_nonce_counter: Option<u32>,
    /// Nonce counter values left before DEK rotation is mandatory.
    pub log_nonce_remaining: Option<u32>,
    /// Size of the latest snapshot file on disk.
    pub snapshot_size_bytes: Option<u64>,
    /// Seconds since the latest snapshot file was written.
    pub snapshot_age_seconds: Option<u64>,
    /// Disk space used by the whole Fjall database.
    pub disk_space_bytes: Option<u64>,
    /// Disk space used by the Raft log keyspace.
    pub log_disk_space_bytes: Option<u64>,
}

/// Renders a [`RaftNodeStatus`] in Prometheus text-exposition format.
pub fn format_node_status_text(status: &RaftNodeStatus) -> String {
    let mut out = String::new();

    write_metric_header(
        &mut out,
        "keystone_raft_quarantined_partitions",
        "Partitions quarantined on this node after repeated GCM failures \
         (1 per quarantined partition).",
        "gauge",
    );
    for partition in &status.quarantined_partitions {
        out.push_str(&format!(
            "keystone_raft_quarantined_partitions{{partition=\"{}\"}} 1\n",
            escape_label_value(partition)
        ));
    }

    let gauges: [(&str, &str, Option<u64>); 11] = [
        (
            "keystone_raft_quarantined_partitions_count",
            "Number of partitions quarantined on this node.",
            Some(status.quarantined_partitions.len() as u64),
        ),
        (
            "keystone_raft_dek_version",
            "Version of the active data encryption key epoch.",
            Some(u64::from(status.dek_version)),
        ),
        (
            "keystone_raft_dek_retired_epochs",
            "Retired DEK epochs still held for decryption and re-encryption.",
            Some(status.dek_retired_epochs as u64),
        ),
        (
            "keystone_raft_dek_revoked_epochs",
            "Revoked DEK versions (emergency rotations).",
            Some(status.dek_revoked_epochs as u64),
        ),
        (
            "keystone_raft_dek_pending_rotation",
            "Emergency DEK rotations staged and awaiting confirmation.",
            Some(status.dek_pending_rotations as u64),
        ),
        (
            "keystone_raft_log_nonce_counter",
            "Next log-encryption nonce counter value of this node.",
            status.log_nonce_counter.map(u64::from),
        ),
        (
            "keystone_raft_log_nonce_remaining",
            "Nonce counter values left before a DEK rotation is mandatory (2^31 limit).",
            status.log_nonce_remaining.map(u64::from),
        ),
        (
            "keystone_raft_snapshot_size_bytes",
            "Size of the latest snapshot file on disk.",
            status.snapshot_size_bytes,
        ),
        (
            "keystone_raft_snapshot_age_seconds",
            "Seconds since the latest snapshot file was written.",
            status.snapshot_age_seconds,
        ),
        (
            "keystone_raft_disk_space_bytes",
            "Disk space used by the Fjall database (all keyspaces).",
            status.disk_space_bytes,
        ),
        (
            "keystone_raft_log_disk_space_bytes",
            "Disk space used by the Raft log keyspace.",
            status.log_disk_space_bytes,
        ),
    ];
    for (name, help, value) in gauges {
        if let Some(value) = value {
            write_metric_header(&mut out, name, help, "gauge");
            out.push_str(&format!("{name} {value}\n"));
        }
    }

    out
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
    fn snapshot_from_sets_leader_id_membership_and_apply_lag() {
        let m = KeystoneRaftPrometheusMetrics::new();
        let mut live = metrics_fixture(2, Some(1), 7, Some(100), Some(90), None);
        live.cluster_committed = Some(LogId::new(7, 98));
        live.snapshot = Some(LogId::new(7, 50));
        m.snapshot_from(&live, 2);

        assert_eq!(m.current_leader_id.get(), 1);
        assert_eq!(m.apply_lag.get(), 8);
        assert_eq!(m.snapshot_last_index.get(), 50);
        // `new_initial` starts with an empty membership.
        assert_eq!(m.membership_voters.get(), 0);
        assert_eq!(m.membership_learners.get(), 0);

        let live = metrics_fixture(2, None, 7, Some(100), Some(90), None);
        m.snapshot_from(&live, 2);
        assert_eq!(m.current_leader_id.get(), -1);
        assert_eq!(m.apply_lag.get(), 0);
    }

    #[test]
    fn event_counters_are_rendered() {
        let m = KeystoneRaftPrometheusMetrics::new();
        m.gcm_failures_total.inc();
        m.record_write_version(5);
        m.record_write_version(3);
        m.record_reencrypt_report(&crate::store::state_machine::ReencryptReport {
            migrated: 10,
            already_current: 2,
            skipped: 1,
        });
        m.record_reencrypt_report(&crate::store::state_machine::ReencryptReport {
            migrated: 4,
            already_current: 0,
            skipped: 0,
        });

        let live = metrics_fixture(1, None, 0, None, None, None);
        let text = m.format_prometheus_text(&live, 1);

        assert!(text.contains("keystone_raft_gcm_failures_total 1\n"));
        assert!(text.contains("keystone_raft_write_rate_version_max 5\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_migrated_total 14\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_skipped_total 1\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_last_skipped 0\n"));
        assert!(text.contains("keystone_raft_current_leader_id -1\n"));
        assert!(text.contains("# TYPE keystone_raft_membership_voters gauge"));
        assert!(text.contains("# TYPE keystone_raft_apply_lag gauge"));
    }

    #[test]
    fn node_status_text_renders_all_known_values() {
        let status = RaftNodeStatus {
            quarantined_partitions: vec!["data".into(), "x\"y".into()],
            dek_version: 4,
            dek_retired_epochs: 2,
            dek_revoked_epochs: 1,
            dek_pending_rotations: 1,
            log_nonce_counter: Some(2048),
            log_nonce_remaining: Some((1u32 << 31) - 2048),
            snapshot_size_bytes: Some(4096),
            snapshot_age_seconds: Some(30),
            disk_space_bytes: Some(1_000_000),
            log_disk_space_bytes: Some(200_000),
        };
        let text = format_node_status_text(&status);

        assert!(text.contains("keystone_raft_quarantined_partitions{partition=\"data\"} 1\n"));
        assert!(text.contains("keystone_raft_quarantined_partitions{partition=\"x\\\"y\"} 1\n"));
        assert!(text.contains("keystone_raft_quarantined_partitions_count 2\n"));
        assert!(text.contains("keystone_raft_dek_version 4\n"));
        assert!(text.contains("keystone_raft_dek_retired_epochs 2\n"));
        assert!(text.contains("keystone_raft_dek_revoked_epochs 1\n"));
        assert!(text.contains("keystone_raft_dek_pending_rotation 1\n"));
        assert!(text.contains("keystone_raft_log_nonce_counter 2048\n"));
        assert!(text.contains("keystone_raft_log_nonce_remaining 2147481600\n"));
        assert!(text.contains("keystone_raft_snapshot_size_bytes 4096\n"));
        assert!(text.contains("keystone_raft_snapshot_age_seconds 30\n"));
        assert!(text.contains("keystone_raft_disk_space_bytes 1000000\n"));
        assert!(text.contains("keystone_raft_log_disk_space_bytes 200000\n"));
    }

    #[test]
    fn node_status_text_omits_unknown_values() {
        let text = format_node_status_text(&RaftNodeStatus::default());

        assert!(text.contains("# TYPE keystone_raft_quarantined_partitions gauge"));
        assert!(!text.contains("keystone_raft_quarantined_partitions{"));
        assert!(text.contains("keystone_raft_quarantined_partitions_count 0\n"));
        assert!(!text.contains("keystone_raft_log_nonce_counter"));
        assert!(!text.contains("keystone_raft_snapshot_age_seconds"));
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
