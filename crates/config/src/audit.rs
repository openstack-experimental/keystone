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

fn default_syslog_app_name() -> String {
    "keystone".to_string()
}

fn default_syslog_connect_timeout_secs() -> u64 {
    10
}

fn default_syslog_write_timeout_secs() -> u64 {
    30
}

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
    std::env::var("HOSTNAME").unwrap_or_else(|_| UNKNOWN_NODE_ID.to_string())
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
    /// RFC 6587) over TCP, optionally wrapped in TLS. Requires Keystone to be
    /// built with the `audit-syslog` feature.
    ///
    /// Delivery is at-least-once: a batch that could not be written is
    /// retried, so the receiver may see an event twice and should deduplicate
    /// on the event `id`.
    Syslog {
        /// `host:port` of the syslog receiver.
        endpoint: String,
        /// Wrap the connection in TLS. Defaults to `false`.
        #[serde(default)]
        tls: bool,
        /// PEM bundle of CA certificates trusted for the receiver. Defaults to
        /// the system trust store.
        #[serde(default)]
        ca_file: Option<PathBuf>,
        /// `APP-NAME` header field. Defaults to `keystone`.
        #[serde(default = "default_syslog_app_name")]
        app_name: String,
        /// Seconds allowed for connecting (including the TLS handshake).
        /// Defaults to 10.
        #[serde(default = "default_syslog_connect_timeout_secs")]
        connect_timeout_secs: u64,
        /// Seconds allowed for writing one batch. Defaults to 30.
        #[serde(default = "default_syslog_write_timeout_secs")]
        write_timeout_secs: u64,
    },
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

    /// File holding the audit HMAC key-encryption-key(s), created with mode
    /// `0600` if missing. It must NOT be inside `spool_dir`: anyone who can
    /// write the spool must not also be able to read the signing key.
    ///
    /// When unset, the legacy location `<spool_dir>/hmac-key.bin` is used so
    /// existing deployments keep working; Keystone logs a warning. Set this
    /// explicitly (for example `/etc/keystone/audit-hmac.keyring`) and rotate
    /// keys with `keystone-manage audit rotate-hmac-key`.
    #[serde(default)]
    pub hmac_kek_file: Option<PathBuf>,

    /// Node identifier used in `observer.node_id` and spool file names.
    /// Must be unique per node and is validated at startup. Defaults to the
    /// `HOSTNAME` environment variable.
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

/// Node id used when neither `[audit] node_id` nor `HOSTNAME` is available.
pub const UNKNOWN_NODE_ID: &str = "unknown-node";

impl AuditConfig {
    /// Where the HMAC keyring lives: `hmac_kek_file`, or the legacy
    /// `<spool_dir>/hmac-key.bin` when unset.
    pub fn hmac_kek_path(&self) -> PathBuf {
        self.hmac_kek_file
            .clone()
            .unwrap_or_else(|| self.spool_dir.join("hmac-key.bin"))
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
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            spool_dir: default_spool_dir(),
            hmac_kek_file: None,
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
                endpoint: "siem:6514".to_string(),
                tls: true,
                ca_file: None,
                app_name: "keystone".to_string(),
                connect_timeout_secs: 10,
                write_timeout_secs: 30,
            }
        );
    }

    #[test]
    fn kek_path_defaults_to_legacy_location_and_can_be_overridden() {
        let mut cfg = AuditConfig {
            spool_dir: PathBuf::from("/spool"),
            ..AuditConfig::default()
        };
        assert_eq!(cfg.hmac_kek_path(), PathBuf::from("/spool/hmac-key.bin"));
        cfg.hmac_kek_file = Some(PathBuf::from("/etc/keystone/audit.keyring"));
        assert_eq!(
            cfg.hmac_kek_path(),
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
