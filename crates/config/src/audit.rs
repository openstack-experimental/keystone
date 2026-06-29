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
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            spool_dir: default_spool_dir(),
            node_id: default_node_id(),
        }
    }
}
