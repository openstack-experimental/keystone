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
//! Configuration of the audit framework.
//!
//! [`AuditConfig`] is the `[audit]` section of a service's configuration file.
//! Service-specific defaults (spool directory, syslog `APP-NAME`) derive from
//! the [`ServiceIdentity`] passed to the accessors instead of being stored
//! here, so every service gets its own without redefining the struct.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::ServiceIdentity;
use crate::metrics::AuditMetrics;
use crate::sink::ShipperConfig;
use crate::spool::SpoolConfig;

fn default_syslog_connect_timeout_secs() -> u64 {
    10
}

fn default_syslog_write_timeout_secs() -> u64 {
    30
}

fn default_enabled() -> bool {
    true
}

fn default_node_id() -> String {
    // `HOSTNAME` is set in most containers but not for services started by
    // systemd, so fall back to the kernel's hostname before giving up with a
    // sentinel that `AuditConfig::validate_node_id` rejects. Operators should
    // still set `node_id` explicitly when hostnames are not unique.
    std::env::var("HOSTNAME")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            ["/proc/sys/kernel/hostname", "/etc/hostname"]
                .iter()
                .filter_map(|path| std::fs::read_to_string(path).ok())
                .map(|h| h.trim().to_string())
                .find(|h| !h.is_empty())
        })
        .unwrap_or_else(|| UNKNOWN_NODE_ID.to_string())
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
    /// Send each event as an RFC 5424 syslog message (octet-counted framing,
    /// RFC 6587) over TCP, optionally wrapped in TLS. Requires the service to
    /// be built with the `syslog` feature of this crate.
    ///
    /// Delivery is at-least-once: a batch that could not be written is
    /// retried, so the receiver may see an event twice and should deduplicate
    /// on the event `id`.
    Syslog {
        /// `APP-NAME` header field. Defaults to the service name.
        #[serde(default)]
        app_name: Option<String>,
        /// PEM bundle of CA certificates trusted for the receiver. Defaults to
        /// the system trust store.
        #[serde(default)]
        ca_file: Option<PathBuf>,
        /// Seconds allowed for connecting (including the TLS handshake).
        /// Defaults to 10.
        #[serde(default = "default_syslog_connect_timeout_secs")]
        connect_timeout_secs: u64,
        /// `host:port` of the syslog receiver.
        endpoint: String,
        /// Wrap the connection in TLS. Defaults to `false`.
        #[serde(default)]
        tls: bool,
        /// Seconds allowed for writing one batch. Defaults to 30.
        #[serde(default = "default_syslog_write_timeout_secs")]
        write_timeout_secs: u64,
    },
}

/// Configuration of the audit framework, deserialised from a service's
/// `[audit]` section (ADR 0023).
#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    /// Capacity of the fail-closed critical event channel. Senders wait when
    /// it is full. Defaults to 256.
    #[serde(default = "default_critical_channel_capacity")]
    pub critical_channel_capacity: usize,

    /// Enable the audit framework. Defaults to `true`.
    ///
    /// When `false`, no spool directory, lock, HMAC key or writer is created
    /// and audit events are discarded. Use this only for development or
    /// deployments that do not need an audit trail; the remaining `[audit]`
    /// options are ignored.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// File holding the audit HMAC key-encryption-key(s), created with mode
    /// `0600` if missing. It must NOT be inside `spool_dir`: anyone who can
    /// write the spool must not also be able to read the signing key.
    ///
    /// When unset, the legacy location `<spool_dir>/hmac-key.bin` is used so
    /// existing deployments keep working; the service logs a warning. Set this
    /// explicitly (for example `/etc/<service>/audit-hmac.keyring`).
    #[serde(default)]
    pub hmac_kek_file: Option<PathBuf>,

    /// Node identifier used in `observer.node_id` and spool file names.
    /// Must be unique per node and is validated at startup. Defaults to the
    /// `HOSTNAME` environment variable, then the system hostname.
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Also record a perimeter event for every request authenticated by an
    /// existing token (the ADR 0023 Phase 2 ingress record), not only the
    /// authentication endpoints. Defaults to `false`: this is high volume and
    /// the perimeter channel drops (and counts) events when it is full.
    #[serde(default)]
    pub perimeter_all_requests: bool,

    /// Capacity of the best-effort perimeter event channel. Events are dropped
    /// (and counted) when it is full. Defaults to 4096.
    #[serde(default = "default_perimeter_channel_capacity")]
    pub perimeter_channel_capacity: usize,

    /// Events handed to the sink per call. Defaults to 500.
    #[serde(default = "default_shipper_batch_size")]
    pub shipper_batch_size: usize,

    /// First retry delay in seconds after a sink failure; doubles up to
    /// `shipper_max_backoff_secs`. Defaults to 1.
    #[serde(default = "default_shipper_initial_backoff_secs")]
    pub shipper_initial_backoff_secs: u64,

    /// Upper bound in seconds for the sink retry delay. Defaults to 60.
    #[serde(default = "default_shipper_max_backoff_secs")]
    pub shipper_max_backoff_secs: u64,

    /// Seconds between checks for newly sealed segments when the shipper is
    /// idle. Defaults to 5.
    #[serde(default = "default_shipper_poll_interval_secs")]
    pub shipper_poll_interval_secs: u64,

    /// Downstream sink for sealed segments, e.g. `sink = { type = "stdout" }`.
    /// Defaults to `{ type = "none" }`.
    #[serde(default)]
    pub sink: AuditSinkConfig,

    /// Directory for per-node JSONL spool files. Defaults to
    /// `/var/lib/<service>/audit`, see [`AuditConfig::spool_dir`].
    #[serde(default)]
    pub spool_dir: Option<PathBuf>,

    /// Seconds the spool writer may spend writing out already-queued events
    /// after shutdown is requested. Events still queued at the deadline are
    /// dropped and logged at `ERROR`. Defaults to 10.
    #[serde(default = "default_spool_drain_timeout_secs")]
    pub spool_drain_timeout_secs: u64,

    /// Keep the spool within this many bytes, counting the sealed segments
    /// plus room for one full live segment (`spool_max_segment_bytes`); the
    /// oldest sealed segments are deleted beyond it. Unset (the
    /// default) applies no size cap. Deletion is logged at `ERROR` and counted
    /// in `keystone_audit_spool_retention_deleted_total`.
    #[serde(default)]
    pub spool_max_bytes: Option<u64>,

    /// Rotate the live spool into a sealed segment once it is this many
    /// seconds old, even if it is small. Defaults to 24 hours.
    #[serde(default = "default_spool_max_segment_age_secs")]
    pub spool_max_segment_age_secs: u64,

    /// Rotate the live spool into a sealed segment once it reaches this many
    /// bytes. Defaults to 256 MiB.
    #[serde(default = "default_spool_max_segment_bytes")]
    pub spool_max_segment_bytes: u64,

    /// Maximum number of sealed segments to keep; the oldest are deleted
    /// beyond this. Unset (the default) keeps every segment: audit records are
    /// never deleted unless the operator opts in, since no downstream sink
    /// has acknowledged them yet. Deletion is logged at `ERROR`.
    #[serde(default)]
    pub spool_max_segments: Option<usize>,

    /// Delete sealed segments older than this many seconds. Unset (the
    /// default) keeps them regardless of age. Deletion is logged at `ERROR`
    /// and counted like `spool_max_bytes`.
    #[serde(default)]
    pub spool_retention_secs: Option<u64>,
}

/// Node id used when neither `[audit] node_id` nor `HOSTNAME` is available.
pub const UNKNOWN_NODE_ID: &str = "unknown-node";

impl AuditConfig {
    /// Where the HMAC keyring lives: `hmac_kek_file`, or the legacy
    /// `<spool_dir>/hmac-key.bin` when unset.
    pub fn hmac_kek_path(&self, service: &ServiceIdentity) -> PathBuf {
        self.hmac_kek_file
            .clone()
            .unwrap_or_else(|| self.spool_dir(service).join("hmac-key.bin"))
    }

    /// Settings of the segment shipper, reporting into `metrics`.
    ///
    /// A zero interval or backoff would turn the shipper into a busy loop
    /// against a failing sink, so each is raised to one second and the ceiling
    /// never sits below the starting backoff.
    pub fn shipper_config(&self, metrics: Arc<AuditMetrics>) -> ShipperConfig {
        let initial_backoff = Duration::from_secs(self.shipper_initial_backoff_secs.max(1));
        ShipperConfig {
            batch_size: self.shipper_batch_size.max(1),
            initial_backoff,
            max_backoff: Duration::from_secs(self.shipper_max_backoff_secs).max(initial_backoff),
            metrics,
            poll_interval: Duration::from_secs(self.shipper_poll_interval_secs.max(1)),
        }
    }

    /// Settings of the spool writer, reporting into `metrics`.
    pub fn spool_config(&self, metrics: Arc<AuditMetrics>) -> SpoolConfig {
        SpoolConfig {
            drain_timeout: Duration::from_secs(self.spool_drain_timeout_secs),
            max_bytes: self.spool_max_bytes,
            max_segment_age: Duration::from_secs(self.spool_max_segment_age_secs),
            max_segment_bytes: self.spool_max_segment_bytes,
            max_segments: self.spool_max_segments,
            metrics,
            retention: self.spool_retention_secs.map(Duration::from_secs),
        }
    }

    /// The spool directory: `spool_dir`, or `/var/lib/<service>/audit`.
    pub fn spool_dir(&self, service: &ServiceIdentity) -> PathBuf {
        self.spool_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/var/lib/{}/audit", service.name())))
    }

    /// Reject a `node_id` that cannot safely identify a node.
    ///
    /// The id keys the per-node signing key and names the spool files, so it
    /// must be unique per node (the `unknown-node` fallback is not), and may
    /// only contain `A-Z a-z 0-9 . _ -` (at most 128 characters).
    pub fn validate_node_id(&self) -> Result<(), String> {
        let id = self.node_id.as_str();
        if id.is_empty() || id == UNKNOWN_NODE_ID {
            return Err(format!(
                "[audit] node_id is not set (got `{id}`); set a value unique to this node"
            ));
        }
        if id.len() > 128
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "[audit] node_id `{id}` must be at most 128 characters of A-Z a-z 0-9 . _ -"
            ));
        }
        Ok(())
    }

    /// Reject spool limits that would destroy or thrash the audit spool.
    ///
    /// A zero rotation bound makes the writer rotate the live spool on every
    /// event, and a zero retention bound deletes every sealed segment as
    /// soon as it is sealed. `None` retention means "keep forever" and is
    /// always fine, as is a zero drain timeout (drain nothing).
    pub fn validate_spool_limits(&self) -> Result<(), String> {
        if self.spool_max_segment_bytes == 0 {
            return Err(
                "[audit] spool_max_segment_bytes must be greater than zero: a zero bound \
                  makes the spool writer rotate on every event"
                    .to_string(),
            );
        }
        if self.spool_max_segment_age_secs == 0 {
            return Err(
                "[audit] spool_max_segment_age_secs must be greater than zero: a zero bound \
                  makes the spool writer rotate on every event"
                    .to_string(),
            );
        }
        if self.spool_max_segments == Some(0) {
            return Err(
                "[audit] spool_max_segments must not be zero: it would delete every sealed \
                  segment as soon as it is sealed"
                    .to_string(),
            );
        }
        if self.spool_max_bytes == Some(0) {
            return Err(
                "[audit] spool_max_bytes must not be zero: it would delete every sealed \
                  segment as soon as it is sealed"
                    .to_string(),
            );
        }
        if self.spool_retention_secs == Some(0) {
            return Err(
                "[audit] spool_retention_secs must not be zero: it would delete every \
                  sealed segment as soon as it is sealed"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            critical_channel_capacity: default_critical_channel_capacity(),
            enabled: default_enabled(),
            hmac_kek_file: None,
            node_id: default_node_id(),
            perimeter_all_requests: false,
            perimeter_channel_capacity: default_perimeter_channel_capacity(),
            shipper_batch_size: default_shipper_batch_size(),
            shipper_initial_backoff_secs: default_shipper_initial_backoff_secs(),
            shipper_max_backoff_secs: default_shipper_max_backoff_secs(),
            shipper_poll_interval_secs: default_shipper_poll_interval_secs(),
            sink: AuditSinkConfig::default(),
            spool_dir: None,
            spool_drain_timeout_secs: default_spool_drain_timeout_secs(),
            spool_max_bytes: None,
            spool_max_segment_age_secs: default_spool_max_segment_age_secs(),
            spool_max_segment_bytes: default_spool_max_segment_bytes(),
            spool_max_segments: None,
            spool_retention_secs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");

    #[test]
    fn defaults_apply_to_an_empty_section() {
        let cfg: AuditConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.spool_dir, None);
        assert_eq!(
            cfg.spool_dir(&SERVICE),
            PathBuf::from("/var/lib/keystone/audit")
        );
        assert_eq!(
            cfg.spool_dir(&ServiceIdentity::new("glance")),
            PathBuf::from("/var/lib/glance/audit")
        );
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
        assert_eq!(cfg.spool_dir(&SERVICE), PathBuf::from("/srv/audit"));
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
    fn syslog_sink_parses_with_defaults() {
        let cfg: AuditConfig = serde_json::from_str(
            r#"{"sink": {"type": "syslog", "endpoint": "siem:6514", "tls": true}}"#,
        )
        .expect("config parses");
        assert_eq!(
            cfg.sink,
            AuditSinkConfig::Syslog {
                app_name: None,
                ca_file: None,
                connect_timeout_secs: 10,
                endpoint: "siem:6514".to_string(),
                tls: true,
                write_timeout_secs: 30,
            }
        );
    }

    #[test]
    fn kek_path_defaults_to_legacy_location_and_can_be_overridden() {
        let mut cfg = AuditConfig {
            spool_dir: Some(PathBuf::from("/spool")),
            ..AuditConfig::default()
        };
        assert_eq!(
            cfg.hmac_kek_path(&SERVICE),
            PathBuf::from("/spool/hmac-key.bin")
        );
        cfg.hmac_kek_file = Some(PathBuf::from("/etc/keystone/audit.keyring"));
        assert_eq!(
            cfg.hmac_kek_path(&SERVICE),
            PathBuf::from("/etc/keystone/audit.keyring")
        );
    }

    #[test]
    fn node_id_validation() {
        let mut cfg = AuditConfig::default();
        for ok in ["node-1", "ks.example.com", "a_b-C.9"] {
            cfg.node_id = ok.to_string();
            assert!(cfg.validate_node_id().is_ok(), "{ok}");
        }
        for bad in [
            UNKNOWN_NODE_ID,
            "",
            "a/b",
            "../x",
            "has space",
            &"n".repeat(129),
        ] {
            cfg.node_id = bad.to_string();
            assert!(cfg.validate_node_id().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn spool_limit_validation() {
        // The defaults are fine; `None` retention means "keep forever" and a
        // zero drain timeout means "drain nothing".
        let cfg = AuditConfig::default();
        assert!(cfg.validate_spool_limits().is_ok());

        let drain_now = AuditConfig {
            spool_drain_timeout_secs: 0,
            ..AuditConfig::default()
        };
        assert!(drain_now.validate_spool_limits().is_ok());

        let degenerate = [
            AuditConfig {
                spool_max_segment_bytes: 0,
                ..AuditConfig::default()
            },
            AuditConfig {
                spool_max_segment_age_secs: 0,
                ..AuditConfig::default()
            },
            AuditConfig {
                spool_max_segments: Some(0),
                ..AuditConfig::default()
            },
            AuditConfig {
                spool_max_bytes: Some(0),
                ..AuditConfig::default()
            },
            AuditConfig {
                spool_retention_secs: Some(0),
                ..AuditConfig::default()
            },
        ];
        for cfg in &degenerate {
            assert!(cfg.validate_spool_limits().is_err());
        }
    }

    #[test]
    fn shipper_config_never_busy_loops() {
        let cfg = AuditConfig {
            shipper_batch_size: 0,
            shipper_poll_interval_secs: 0,
            shipper_initial_backoff_secs: 0,
            shipper_max_backoff_secs: 0,
            ..AuditConfig::default()
        };
        let shipper = cfg.shipper_config(Arc::new(AuditMetrics::default()));
        assert_eq!(shipper.batch_size, 1);
        assert_eq!(shipper.poll_interval, Duration::from_secs(1));
        assert_eq!(shipper.initial_backoff, Duration::from_secs(1));
        assert_eq!(shipper.max_backoff, Duration::from_secs(1));
    }

    #[test]
    fn spool_config_follows_the_settings() {
        let cfg = AuditConfig {
            spool_max_segments: Some(3),
            spool_retention_secs: Some(60),
            spool_drain_timeout_secs: 7,
            ..AuditConfig::default()
        };
        let spool = cfg.spool_config(Arc::new(AuditMetrics::default()));
        assert_eq!(spool.max_segments, Some(3));
        assert_eq!(spool.retention, Some(Duration::from_secs(60)));
        assert_eq!(spool.drain_timeout, Duration::from_secs(7));
        assert_eq!(spool.max_segment_bytes, 256 * 1024 * 1024);
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
