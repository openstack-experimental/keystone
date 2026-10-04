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
//! Audit framework configuration.

use std::path::PathBuf;

use serde::Deserialize;

fn default_enabled() -> bool {
    true
}

fn default_spool_dir() -> PathBuf {
    PathBuf::from("/var/lib/keystone/audit")
}

fn default_node_id() -> String {
    // Use the HOSTNAME env var if set (common in containerised environments),
    // otherwise fall back to a static sentinel. Full gethostname(2) is
    // available via nix::unistd::gethostname but that dep is optional;
    // operators should set node_id explicitly in config.
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-node".to_string())
}

fn default_spool_drain_timeout_secs() -> u64 {
    10
}

fn default_perimeter_channel_capacity() -> usize {
    4096
}

fn default_critical_channel_capacity() -> usize {
    256
}

fn default_shipper_batch_size() -> usize {
    500
}

fn default_shipper_poll_interval_secs() -> u64 {
    5
}

fn default_shipper_initial_backoff_secs() -> u64 {
    1
}

fn default_shipper_max_backoff_secs() -> u64 {
    60
}

fn default_spool_max_segment_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_spool_max_segment_age_secs() -> u64 {
    24 * 60 * 60
}

/// Downstream sink that sealed spool segments are shipped to.
///
/// A segment is deleted from the spool only after the sink has accepted all of
/// its events.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditSinkConfig {
    /// No sink: sealed segments stay in the spool for an external shipper
    /// (e.g. a log forwarder tailing `spool_dir`). Nothing is acknowledged.
    #[default]
    None,
    /// Write each event as a JSON line to the process's standard output.
    Stdout,
}

/// Configuration for the CADF audit framework (ADR 0023).
#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    /// Enable the audit framework. Defaults to `true`.
    ///
    /// When `false`, no spool directory, lock, HMAC key or writer is created
    /// and audit events are discarded. Use this only for development or
    /// deployments that do not need an audit trail; the remaining `[audit]`
    /// options are ignored.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Directory for per-node JSONL spool files.
    #[serde(default = "default_spool_dir")]
    pub spool_dir: PathBuf,

    /// Node identifier used in `observer.node_id` and spool file names.
    /// Defaults to the system hostname.
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Rotate the live spool into a sealed segment once it reaches this many
    /// bytes. Defaults to 256 MiB.
    #[serde(default = "default_spool_max_segment_bytes")]
    pub spool_max_segment_bytes: u64,

    /// Rotate the live spool into a sealed segment once it is this many
    /// seconds old, even if it is small. Defaults to 24 hours.
    #[serde(default = "default_spool_max_segment_age_secs")]
    pub spool_max_segment_age_secs: u64,

    /// Maximum number of sealed segments to keep; the oldest are deleted
    /// beyond this. Unset (the default) keeps every segment: audit records are
    /// never deleted unless the operator opts in, since no downstream sink
    /// has acknowledged them yet. Deletion is logged at `ERROR`.
    #[serde(default)]
    pub spool_max_segments: Option<usize>,

    /// Keep the spool within this many bytes, counting the sealed segments
    /// plus room for one full live segment (`spool_max_segment_bytes`); the
    /// oldest sealed segments are deleted beyond it. Unset (the
    /// default) applies no size cap. Deletion is logged at `ERROR` and counted
    /// in `keystone_audit_spool_retention_deleted_total`.
    #[serde(default)]
    pub spool_max_bytes: Option<u64>,

    /// Delete sealed segments older than this many seconds. Unset (the
    /// default) keeps them regardless of age. Deletion is logged at `ERROR`
    /// and counted like `spool_max_bytes`.
    #[serde(default)]
    pub spool_retention_secs: Option<u64>,

    /// Capacity of the best-effort perimeter event channel. Events are dropped
    /// (and counted) when it is full. Defaults to 4096.
    #[serde(default = "default_perimeter_channel_capacity")]
    pub perimeter_channel_capacity: usize,

    /// Capacity of the fail-closed critical event channel. Senders wait when
    /// it is full. Defaults to 256.
    #[serde(default = "default_critical_channel_capacity")]
    pub critical_channel_capacity: usize,

    /// Events handed to the sink per call. Defaults to 500.
    #[serde(default = "default_shipper_batch_size")]
    pub shipper_batch_size: usize,

    /// Seconds between checks for newly sealed segments when the shipper is
    /// idle. Defaults to 5.
    #[serde(default = "default_shipper_poll_interval_secs")]
    pub shipper_poll_interval_secs: u64,

    /// First retry delay in seconds after a sink failure; doubles up to
    /// `shipper_max_backoff_secs`. Defaults to 1.
    #[serde(default = "default_shipper_initial_backoff_secs")]
    pub shipper_initial_backoff_secs: u64,

    /// Upper bound in seconds for the sink retry delay. Defaults to 60.
    #[serde(default = "default_shipper_max_backoff_secs")]
    pub shipper_max_backoff_secs: u64,

    /// Seconds the spool writer may spend writing out already-queued events
    /// after shutdown is requested. Events still queued at the deadline are
    /// dropped and logged at `ERROR`. Defaults to 10.
    #[serde(default = "default_spool_drain_timeout_secs")]
    pub spool_drain_timeout_secs: u64,

    /// Downstream sink for sealed segments, e.g. `sink = { type = "stdout" }`.
    /// Defaults to `{ type = "none" }`.
    #[serde(default)]
    pub sink: AuditSinkConfig,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            spool_dir: default_spool_dir(),
            node_id: default_node_id(),
            spool_max_segment_bytes: default_spool_max_segment_bytes(),
            spool_max_segment_age_secs: default_spool_max_segment_age_secs(),
            spool_max_segments: None,
            spool_max_bytes: None,
            spool_retention_secs: None,
            perimeter_channel_capacity: default_perimeter_channel_capacity(),
            critical_channel_capacity: default_critical_channel_capacity(),
            shipper_batch_size: default_shipper_batch_size(),
            shipper_poll_interval_secs: default_shipper_poll_interval_secs(),
            shipper_initial_backoff_secs: default_shipper_initial_backoff_secs(),
            shipper_max_backoff_secs: default_shipper_max_backoff_secs(),
            spool_drain_timeout_secs: default_spool_drain_timeout_secs(),
            sink: AuditSinkConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_to_an_empty_section() {
        let cfg: AuditConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.spool_dir, PathBuf::from("/var/lib/keystone/audit"));
        assert_eq!(cfg.spool_max_segment_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.spool_max_segment_age_secs, 24 * 60 * 60);
        assert_eq!(cfg.spool_max_segments, None);
        assert_eq!(cfg.spool_drain_timeout_secs, 10);
        assert!(!cfg.node_id.is_empty());
    }

    #[test]
    fn explicit_values_override_the_defaults() {
        let cfg: AuditConfig = serde_json::from_str(
            r#"{"spool_dir": "/srv/audit", "node_id": "ks-0", "spool_max_segments": 4,
                "spool_drain_timeout_secs": 3, "sink": {"type": "stdout"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.spool_dir, PathBuf::from("/srv/audit"));
        assert_eq!(cfg.node_id, "ks-0");
        assert_eq!(cfg.spool_max_segments, Some(4));
        assert_eq!(cfg.spool_drain_timeout_secs, 3);
        assert!(matches!(cfg.sink, AuditSinkConfig::Stdout));
    }

    #[test]
    fn defaults_match_previous_hard_coded_values() {
        let cfg: AuditConfig = serde_json::from_str("{}").expect("empty config parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.perimeter_channel_capacity, 4096);
        assert_eq!(cfg.critical_channel_capacity, 256);
        assert_eq!(cfg.shipper_batch_size, 500);
        assert_eq!(cfg.shipper_poll_interval_secs, 5);
        assert_eq!(cfg.shipper_initial_backoff_secs, 1);
        assert_eq!(cfg.shipper_max_backoff_secs, 60);
        assert_eq!(cfg.spool_max_bytes, None);
        assert_eq!(cfg.spool_retention_secs, None);
    }

    #[test]
    fn limits_are_configurable() {
        let cfg: AuditConfig = serde_json::from_str(
            r#"{"spool_max_bytes": 1048576, "spool_retention_secs": 3600,
                "perimeter_channel_capacity": 8, "critical_channel_capacity": 2,
                "shipper_batch_size": 10}"#,
        )
        .expect("config parses");
        assert_eq!(cfg.spool_max_bytes, Some(1_048_576));
        assert_eq!(cfg.spool_retention_secs, Some(3600));
        assert_eq!(cfg.perimeter_channel_capacity, 8);
        assert_eq!(cfg.critical_channel_capacity, 2);
        assert_eq!(cfg.shipper_batch_size, 10);
    }
}
