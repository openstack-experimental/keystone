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

//! Rate limiting configuration sections (ADR-0022).
//!
//! Each `[rate_limit_*]` INI section deserializes into a [`RateLimitSection`].
//! The section carries only the *policy* scalars; the actual `governor`
//! [`RateLimiter`](https://docs.rs/governor) instances live in
//! [`crate::rate_limit::RateLimitState`] and are constructed once at startup
//! from these values.
//!
//! # Security invariant (ADR-0022 §2, config bounds)
//!
//! If `enabled = true` and either `burst_size` or `replenish_rate_per_second`
//! falls outside `[1, 100000]`, the application **must** refuse to start. This
//! is enforced in
//! [`RateLimitState::from_config`](openstack_keystone_core::rate_limit::RateLimitState::from_config),
//! not here — a disabled section with out-of-range values is harmless and must
//! not cause a startup failure, so the bound cannot be a field-level
//! `validator` range that would fire unconditionally.

use serde::Deserialize;

use crate::common::csv;

/// Default burst capacity when the key is absent from the config file.
fn default_burst_size() -> u32 {
    100
}

/// Default replenishment rate when the key is absent from the config file.
fn default_replenish_rate_per_second() -> u32 {
    10
}

/// A single rate-limiting bucket, mapped from one INI `[rate_limit_*]` section.
///
/// The same struct is reused for every bucket (global-IP, per-user, per-domain
/// …) so operators see a consistent configuration shape across all limiters.
///
/// ```ini
/// [rate_limit_global_ip]
/// enabled = true
/// burst_size = 100
/// replenish_rate_per_second = 10
/// ```
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct RateLimitSection {
    /// When `false` (the default) the corresponding `governor` limiter is not
    /// instantiated and the handler bypasses this check entirely.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum number of cells that can be consumed in a burst before
    /// replenishment kicks in. Must be within `[1, 100000]` when
    /// `enabled = true`.
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    /// How many cells are added back to the bucket per second. Must be within
    /// `[1, 100000]` when `enabled = true`.
    #[serde(default = "default_replenish_rate_per_second")]
    pub replenish_rate_per_second: u32,
}

/// Trusted reverse proxies for the global per-IP limiter.
///
/// This is deliberately separate from the API-key and dynamic-plugin proxy
/// lists because each protects a different ingress trust boundary.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub struct RateLimitTrustedProxiesSection {
    /// CIDR ranges allowed to contribute `X-Forwarded-For` hops.
    #[serde(default, deserialize_with = "csv")]
    pub trusted_proxies: Vec<String>,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            enabled: false,
            burst_size: default_burst_size(),
            replenish_rate_per_second: default_replenish_rate_per_second(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn default_is_disabled() {
        let s = RateLimitSection::default();
        assert!(!s.enabled);
        assert_eq!(s.burst_size, 100);
        assert_eq!(s.replenish_rate_per_second, 10);
    }

    #[test]
    fn deserialize_enabled_section() {
        let s: RateLimitSection = serde_json::from_value(json!({"enabled": true, "burst_size": 5,
                "replenish_rate_per_second": 1}))
        .unwrap();
        assert!(s.enabled);
        assert_eq!(s.burst_size, 5);
        assert_eq!(s.replenish_rate_per_second, 1);
    }

    #[test]
    fn deserialize_disabled_ignores_zero_values() {
        // Disabled sections with zero limits are valid config (no startup failure).
        let s: RateLimitSection = serde_json::from_value(json!({"enabled": false, "burst_size": 0,
                "replenish_rate_per_second": 0}))
        .unwrap();
        assert!(!s.enabled);
    }

    #[test]
    fn deserialize_defaults_when_fields_absent() {
        let s: RateLimitSection = serde_json::from_value(json!({})).unwrap();
        assert!(!s.enabled);
        assert_eq!(s.burst_size, 100);
        assert_eq!(s.replenish_rate_per_second, 10);
    }

    #[test]
    fn deserialize_trusted_proxies() {
        let section: RateLimitTrustedProxiesSection =
            serde_json::from_value(json!({"trusted_proxies": "10.0.0.0/8,192.0.2.0/24"})).unwrap();
        assert_eq!(
            section.trusted_proxies,
            vec!["10.0.0.0/8".to_string(), "192.0.2.0/24".to_string()]
        );
    }
}
