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
//! The series fall in three groups, all exposed on the OpenTelemetry SDK
//! (ADR 0040):
//!
//! * point-in-time gauges derived by reading through to `openraft`'s own
//!   metrics watch channel (`Raft::metrics().borrow_watched()`) every time
//!   metrics are collected ([`register_gauges`]) — that read is a cheap,
//!   non-blocking watch-channel borrow;
//! * event counters recorded where the event happens (`gcm_failures_total`,
//!   `dek_reencrypt_*_total`, `write_rate_version_max`) and the
//!   `apply_duration_seconds` latency histogram, owned by
//!   [`KeystoneRaftPrometheusMetrics`]. A snapshot read can't reconstruct these
//!   after the fact;
//! * point-in-time node state (quarantine, DEK lifecycle, log nonce counter,
//!   snapshot and disk usage; GitHub #1306) read from the state machine and log
//!   store when metrics are collected ([`register_node_status`]).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openstack_keystone_telemetry::metrics::{
    HistogramVec, LATENCY_BUCKETS, Label, Meter, observe_counter, observe_gauge,
    observe_gauge_signed,
};

use crate::TypeConfig;

/// A monotonic total kept in an atomic and read when metrics are collected.
#[derive(Clone, Debug, Default)]
pub struct EventCounter(Arc<AtomicU64>);

impl EventCounter {
    /// Count one event.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Count `n` events.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Events counted so far.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn register(&self, meter: &Meter, name: &'static str, help: &'static str) {
        let total = self.clone();
        observe_counter(meter, name, help, [], move |emit| emit([], total.get()));
    }
}

/// Per-node Raft Prometheus metrics (ADR 0031). See the module docs for why
/// this is a struct instance rather than a `static`, and for the naming
/// rationale relative to `openraft::RaftMetrics`.
pub struct KeystoneRaftPrometheusMetrics {
    /// Recorded incrementally at the actual apply call site
    /// (`store::state_machine::FjallStateMachine::apply`) — a real
    /// per-operation latency measurement, not a snapshot read-through like
    /// the gauges.
    apply_duration_seconds: HistogramVec<0>,
    /// AES-GCM tag verification failures on state reads (the quarantine
    /// trigger). Incremented on every failure, not only on the one that
    /// crosses the quarantine threshold.
    pub gcm_failures_total: EventCounter,
    /// Highest per-record write version seen by this node since start
    /// (ADR 0016-v2 §10 invariant 9).
    write_rate_version_max: Arc<AtomicU32>,
    /// Records re-encrypted under the current DEK by background sweeps.
    dek_reencrypt_migrated_total: EventCounter,
    /// Records the background sweeps skipped (CAS retries exhausted).
    dek_reencrypt_skipped_total: EventCounter,
    /// Records skipped by the most recent sweep pass.
    dek_reencrypt_last_skipped: Arc<AtomicU64>,
}

impl KeystoneRaftPrometheusMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        let this = Self {
            apply_duration_seconds: HistogramVec::new(
                meter,
                "keystone_raft_apply_duration_seconds",
                "State-machine apply latency (per committed log entry).",
                [],
                &LATENCY_BUCKETS,
            ),
            gcm_failures_total: EventCounter::default(),
            write_rate_version_max: Arc::new(AtomicU32::new(0)),
            dek_reencrypt_migrated_total: EventCounter::default(),
            dek_reencrypt_skipped_total: EventCounter::default(),
            dek_reencrypt_last_skipped: Arc::new(AtomicU64::new(0)),
        };
        this.gcm_failures_total.register(
            meter,
            "keystone_raft_gcm_failures_total",
            "AES-GCM tag verification failures on state reads.",
        );
        this.dek_reencrypt_migrated_total.register(
            meter,
            "keystone_raft_dek_reencrypt_migrated_total",
            "Records re-encrypted under the current DEK by background sweeps.",
        );
        this.dek_reencrypt_skipped_total.register(
            meter,
            "keystone_raft_dek_reencrypt_skipped_total",
            "Records skipped by background DEK re-encryption sweeps.",
        );
        let version = Arc::clone(&this.write_rate_version_max);
        observe_gauge(
            meter,
            "keystone_raft_write_rate_version_max",
            "Highest per-record write version seen by this node since start \
             (DEK rotation is required before it reaches 2^30).",
            [],
            move |emit| emit([], u64::from(version.load(Ordering::Relaxed))),
        );
        let skipped = Arc::clone(&this.dek_reencrypt_last_skipped);
        observe_gauge(
            meter,
            "keystone_raft_dek_reencrypt_last_skipped",
            "Records skipped by the most recent DEK re-encryption pass.",
            [],
            move |emit| emit([], skipped.load(Ordering::Relaxed)),
        );
        this
    }

    /// Record the latency of applying one committed log entry.
    pub fn record_apply(&self, seconds: f64) {
        self.apply_duration_seconds.record(seconds, []);
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
            .store(report.skipped, Ordering::Relaxed);
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

/// Expose the `keystone_raft_*` gauges derived from openraft's metrics on
/// `meter`. `live` returns the current `openraft::RaftMetrics` snapshot and is
/// called on every collection; `node_id` is this node's own Raft id, used to
/// derive `keystone_raft_is_leader`.
///
/// `peer_id` is openraft's own `u64` node id, stringified — a small,
/// config-fixed cluster member set (ADR 0031 cardinality guardrail).
/// `replication_lag` is only reported while this node is the leader: openraft
/// only tracks per-peer replication progress there.
pub fn register_gauges(
    meter: &Meter,
    node_id: u64,
    live: impl Fn() -> openraft::RaftMetrics<TypeConfig> + Clone + Send + Sync + 'static,
) {
    // `Term` for this crate's `TypeConfig` is `u64` (see
    // `proto_impl::impl_leader_id`).
    let gauge = |name: &'static str,
                 help: &'static str,
                 read: fn(&openraft::RaftMetrics<TypeConfig>, u64) -> u64| {
        let live = live.clone();
        observe_gauge(meter, name, help, [], move |emit| {
            emit([], read(&live(), node_id));
        });
    };
    gauge(
        "keystone_raft_is_leader",
        "Whether this node is the current Raft leader (1) or not (0).",
        |m, node_id| u64::from(m.current_leader == Some(node_id)),
    );
    gauge(
        "keystone_raft_term",
        "Current Raft term of this node.",
        |m, _| m.current_term,
    );
    gauge(
        "keystone_raft_last_log_index",
        "Last Raft log index appended to this node's log (tail position).",
        |m, _| m.last_log_index.unwrap_or(0),
    );
    gauge(
        "keystone_raft_last_applied_index",
        "Last Raft log index applied to this node's state machine.",
        |m, _| m.last_applied.as_ref().map(|l| l.index()).unwrap_or(0),
    );
    gauge(
        "keystone_raft_membership_voters",
        "Number of voters in the effective Raft membership.",
        |m, _| m.membership_config.membership().voter_ids().count() as u64,
    );
    gauge(
        "keystone_raft_membership_learners",
        "Number of learners in the effective Raft membership.",
        |m, _| m.membership_config.membership().learner_ids().count() as u64,
    );
    gauge(
        "keystone_raft_apply_lag",
        "Log entries by which this node's last applied index trails the \
         cluster commit index reported by the leader.",
        |m, _| apply_lag(m).unwrap_or(0),
    );
    gauge(
        "keystone_raft_snapshot_last_index",
        "Last Raft log index included in this node's latest snapshot.",
        |m, _| m.snapshot.as_ref().map(|l| l.index()).unwrap_or(0),
    );
    let leader = live.clone();
    observe_gauge_signed(
        meter,
        "keystone_raft_current_leader_id",
        "Raft node id of the leader as seen by this node (-1 when unknown).",
        [],
        move |emit| {
            emit(
                [],
                leader()
                    .current_leader
                    .map_or(-1, |id| i64::try_from(id).unwrap_or(i64::MAX)),
            );
        },
    );
    observe_gauge(
        meter,
        "keystone_raft_replication_lag",
        "Log entries by which a peer's match index trails this leader's \
         last log index (last_log_index - peer match_index); only \
         populated while this node is leader.",
        ["peer_id"],
        move |emit| {
            let metrics = live();
            let last_log_index = metrics.last_log_index.unwrap_or(0);
            for (peer_id, match_log_id) in metrics.replication.iter().flatten() {
                let match_index = match_log_id.as_ref().map(|l| l.index()).unwrap_or(0);
                let peer = peer_id.to_string();
                emit(
                    [Label::bounded(&peer)],
                    last_log_index.saturating_sub(match_index),
                );
            }
        },
    );
}

/// Point-in-time node state read when metrics are collected (see the module
/// docs). `None` fields could not be read and are not exposed.
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

/// How long a [`RaftNodeStatus`] read is reused. One collection reads many
/// gauges; the status touches the disk, so it is read once per collection.
const STATUS_TTL: Duration = Duration::from_secs(1);

type StatusRead = fn(&RaftNodeStatus) -> Option<u64>;

const STATUS_GAUGES: [(&str, &str, StatusRead); 11] = [
    (
        "keystone_raft_quarantined_partitions_count",
        "Number of partitions quarantined on this node.",
        |s| Some(s.quarantined_partitions.len() as u64),
    ),
    (
        "keystone_raft_dek_version",
        "Version of the active data encryption key epoch.",
        |s| Some(u64::from(s.dek_version)),
    ),
    (
        "keystone_raft_dek_retired_epochs",
        "Retired DEK epochs still held for decryption and re-encryption.",
        |s| Some(s.dek_retired_epochs as u64),
    ),
    (
        "keystone_raft_dek_revoked_epochs",
        "Revoked DEK versions (emergency rotations).",
        |s| Some(s.dek_revoked_epochs as u64),
    ),
    (
        "keystone_raft_dek_pending_rotation",
        "Emergency DEK rotations staged and awaiting confirmation.",
        |s| Some(s.dek_pending_rotations as u64),
    ),
    (
        "keystone_raft_log_nonce_counter",
        "Next log-encryption nonce counter value of this node.",
        |s| s.log_nonce_counter.map(u64::from),
    ),
    (
        "keystone_raft_log_nonce_remaining",
        "Nonce counter values left before a DEK rotation is mandatory (2^31 limit).",
        |s| s.log_nonce_remaining.map(u64::from),
    ),
    (
        "keystone_raft_snapshot_size_bytes",
        "Size of the latest snapshot file on disk.",
        |s| s.snapshot_size_bytes,
    ),
    (
        "keystone_raft_snapshot_age_seconds",
        "Seconds since the latest snapshot file was written.",
        |s| s.snapshot_age_seconds,
    ),
    (
        "keystone_raft_disk_space_bytes",
        "Disk space used by the Fjall database (all keyspaces).",
        |s| s.disk_space_bytes,
    ),
    (
        "keystone_raft_log_disk_space_bytes",
        "Disk space used by the Raft log keyspace.",
        |s| s.log_disk_space_bytes,
    ),
];

/// Expose the node state gauges on `meter`. `source` reads the current
/// [`RaftNodeStatus`] when metrics are collected, or `None` when the node is
/// gone (it must not keep the node alive).
pub fn register_node_status(
    meter: &Meter,
    source: impl Fn() -> Option<RaftNodeStatus> + Send + Sync + 'static,
) {
    let cache: Arc<Mutex<Option<(Instant, RaftNodeStatus)>>> = Arc::new(Mutex::new(None));
    let read = Arc::new(move || -> Option<RaftNodeStatus> {
        let mut cached = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, status)) = cached.as_ref()
            && at.elapsed() < STATUS_TTL
        {
            return Some(status.clone());
        }
        let status = source()?;
        *cached = Some((Instant::now(), status.clone()));
        Some(status)
    });

    for (name, help, value) in STATUS_GAUGES {
        let read = Arc::clone(&read);
        observe_gauge(meter, name, help, [], move |emit| {
            if let Some(value) = read().and_then(|status| value(&status)) {
                emit([], value);
            }
        });
    }
    // One series per quarantined partition (keyspace names: a small, fixed
    // set).
    observe_gauge(
        meter,
        "keystone_raft_quarantined_partitions",
        "Partitions quarantined on this node after repeated GCM failures \
         (1 per quarantined partition).",
        ["partition"],
        move |emit| {
            for partition in read().iter().flat_map(|s| &s.quarantined_partitions) {
                emit([Label::bounded(partition)], 1);
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use openraft::RaftMetrics;

    use openstack_keystone_telemetry::metrics::MetricsPipeline;

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

    /// Render `live` the way `/metrics` would, with an apply latency of each
    /// of `applies` seconds recorded.
    fn render(live: RaftMetrics<TypeConfig>, node_id: u64, applies: &[f64]) -> String {
        let pipeline = MetricsPipeline::new();
        let m = KeystoneRaftPrometheusMetrics::new(&pipeline.meter());
        for apply in applies {
            m.record_apply(*apply);
        }
        register_gauges(&pipeline.meter(), node_id, move || live.clone());
        pipeline.render()
    }

    /// Pins the rendered exposition text against `tests/golden/raft.prom`
    /// (ADR 0040).
    #[test]
    fn golden_exposition() {
        let replication = BTreeMap::from([(2u64, Some(90u64)), (3u64, None)]);
        let live = metrics_fixture(1, Some(1), 7, Some(100), Some(95), Some(replication));
        openstack_keystone_telemetry::assert_golden!("raft", render(live, 1, &[0.002, 0.2]));
    }

    #[test]
    fn sets_leader_and_position_gauges_when_leader() {
        let text = render(
            metrics_fixture(1, Some(1), 7, Some(100), Some(90), None),
            1,
            &[],
        );
        assert!(text.contains("keystone_raft_is_leader 1\n"));
        assert!(text.contains("keystone_raft_term 7\n"));
        assert!(text.contains("keystone_raft_last_log_index 100\n"));
        assert!(text.contains("keystone_raft_last_applied_index 90\n"));
    }

    #[test]
    fn reports_not_leader_for_a_different_current_leader() {
        let text = render(
            metrics_fixture(2, Some(1), 7, Some(100), Some(90), None),
            2,
            &[],
        );
        assert!(text.contains("keystone_raft_is_leader 0\n"));
    }

    #[test]
    fn reports_not_leader_when_no_leader_elected() {
        let text = render(metrics_fixture(1, None, 3, None, None, None), 1, &[]);
        assert!(text.contains("keystone_raft_is_leader 0\n"));
        assert!(text.contains("keystone_raft_last_log_index 0\n"));
        assert!(text.contains("keystone_raft_last_applied_index 0\n"));
    }

    #[test]
    fn computes_replication_lag_per_peer() {
        let replication = BTreeMap::from([(2u64, Some(80u64)), (3u64, Some(100u64)), (4u64, None)]);
        let text = render(
            metrics_fixture(1, Some(1), 7, Some(100), Some(100), Some(replication)),
            1,
            &[],
        );
        assert!(text.contains("keystone_raft_replication_lag{peer_id=\"2\"} 20\n"));
        assert!(text.contains("keystone_raft_replication_lag{peer_id=\"3\"} 0\n"));
        assert!(text.contains("keystone_raft_replication_lag{peer_id=\"4\"} 100\n"));
        // Unknown/unseen peer has no series.
        assert!(!text.contains("peer_id=\"5\""));
    }

    #[test]
    fn replication_lag_absent_when_not_leader() {
        let text = render(
            metrics_fixture(2, Some(1), 7, Some(100), Some(90), None),
            2,
            &[],
        );
        assert!(!text.contains("keystone_raft_replication_lag{"));
    }

    #[test]
    fn has_all_six_series() {
        let replication = BTreeMap::from([(2u64, Some(90u64))]);
        let live = metrics_fixture(1, Some(1), 7, Some(100), Some(95), Some(replication));
        let text = render(live, 1, &[0.01]);

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
        assert!(text.contains("keystone_raft_apply_duration_seconds_count 1\n"));
    }

    #[test]
    fn apply_duration_seconds_is_recorded_incrementally_and_rendered() {
        let live = metrics_fixture(1, None, 0, None, None, None);
        let text = render(live, 1, &[0.01, 0.2]);
        assert!(text.contains("keystone_raft_apply_duration_seconds_count 2\n"));
    }

    #[test]
    fn exposes_leader_id_membership_and_apply_lag() {
        let mut live = metrics_fixture(2, Some(1), 7, Some(100), Some(90), None);
        live.cluster_committed = Some(LogId::new(7, 98));
        live.snapshot = Some(LogId::new(7, 50));
        let text = render(live, 2, &[]);
        assert!(text.contains("keystone_raft_current_leader_id 1\n"));
        assert!(text.contains("keystone_raft_apply_lag 8\n"));
        assert!(text.contains("keystone_raft_snapshot_last_index 50\n"));
        // `RaftMetrics::new_initial` starts with an empty membership.
        assert!(text.contains("keystone_raft_membership_voters 0\n"));
        assert!(text.contains("keystone_raft_membership_learners 0\n"));

        let live = metrics_fixture(2, None, 7, Some(100), Some(90), None);
        let text = render(live, 2, &[]);
        assert!(text.contains("keystone_raft_current_leader_id -1\n"));
        assert!(text.contains("keystone_raft_apply_lag 0\n"));
    }

    #[test]
    fn event_counters_are_rendered() {
        let pipeline = MetricsPipeline::new();
        let m = KeystoneRaftPrometheusMetrics::new(&pipeline.meter());
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

        let text = pipeline.render();
        assert!(text.contains("keystone_raft_gcm_failures_total 1\n"));
        assert!(text.contains("keystone_raft_write_rate_version_max 5\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_migrated_total 14\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_skipped_total 1\n"));
        assert!(text.contains("keystone_raft_dek_reencrypt_last_skipped 0\n"));
    }

    fn render_status(status: RaftNodeStatus) -> String {
        let pipeline = MetricsPipeline::new();
        register_node_status(&pipeline.meter(), move || Some(status.clone()));
        pipeline.render()
    }

    #[test]
    fn node_status_renders_all_known_values() {
        let text = render_status(RaftNodeStatus {
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
        });

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
    fn node_status_omits_unknown_values() {
        let text = render_status(RaftNodeStatus::default());

        assert!(!text.contains("keystone_raft_quarantined_partitions{"));
        assert!(text.contains("keystone_raft_quarantined_partitions_count 0\n"));
        assert!(!text.contains("keystone_raft_log_nonce_counter"));
        assert!(!text.contains("keystone_raft_snapshot_age_seconds"));
    }
}
