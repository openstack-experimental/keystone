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

//! `[local_emergency]` configuration section (ADR 0028).
//!
//! Governs the node-local, quorum-bypass emergency write path shared by
//! OAuth2 signing-key and DEK emergency rotation. Disabled by default: an
//! operator must opt in per-node before `--local-quorum-bypass` requests are
//! accepted.

use serde::Deserialize;

/// Default guardrail: how long the Raft leader must be unknown before the
/// local-write path unlocks, in seconds.
fn default_leaderless_grace_period_seconds() -> u64 {
    30
}

/// Default best-effort gossip fan-out interval, in seconds.
fn default_gossip_interval_seconds() -> u64 {
    10
}

/// `[local_emergency]` INI section.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct LocalEmergencyProvider {
    /// When `false` (the default), every `--local-quorum-bypass` request is
    /// rejected regardless of cluster state. Operators must explicitly opt a
    /// node into the bypass path.
    #[serde(default)]
    pub enabled: bool,

    /// How long the Raft leader must be unknown (per
    /// `StorageApi::current_leader`) before the guardrail allows a local
    /// write. Guards against using the bypass merely because of a transient
    /// leader-election blip.
    #[serde(default = "default_leaderless_grace_period_seconds")]
    pub leaderless_grace_period_seconds: u64,

    /// Interval between best-effort gossip fan-out attempts to reachable
    /// peers while partitioned.
    #[serde(default = "default_gossip_interval_seconds")]
    pub gossip_interval_seconds: u64,
}

impl Default for LocalEmergencyProvider {
    fn default() -> Self {
        Self {
            enabled: false,
            leaderless_grace_period_seconds: default_leaderless_grace_period_seconds(),
            gossip_interval_seconds: default_gossip_interval_seconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn default_is_disabled() {
        let s = LocalEmergencyProvider::default();
        assert!(!s.enabled);
        assert_eq!(s.leaderless_grace_period_seconds, 30);
        assert_eq!(s.gossip_interval_seconds, 10);
    }

    #[test]
    fn deserialize_enabled_section() {
        let s: LocalEmergencyProvider = serde_json::from_value(json!({
            "enabled": true,
            "leaderless_grace_period_seconds": 5,
            "gossip_interval_seconds": 2
        }))
        .unwrap();
        assert!(s.enabled);
        assert_eq!(s.leaderless_grace_period_seconds, 5);
        assert_eq!(s.gossip_interval_seconds, 2);
    }

    #[test]
    fn deserialize_defaults_when_fields_absent() {
        let s: LocalEmergencyProvider = serde_json::from_value(json!({})).unwrap();
        assert!(!s.enabled);
        assert_eq!(s.leaderless_grace_period_seconds, 30);
        assert_eq!(s.gossip_interval_seconds, 10);
    }
}
