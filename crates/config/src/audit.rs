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
            spool_dir: default_spool_dir(),
            node_id: default_node_id(),
            spool_max_segment_bytes: default_spool_max_segment_bytes(),
            spool_max_segment_age_secs: default_spool_max_segment_age_secs(),
            spool_max_segments: None,
            spool_drain_timeout_secs: default_spool_drain_timeout_secs(),
            sink: AuditSinkConfig::default(),
        }
    }
}
