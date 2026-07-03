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

//! Handler-level rate limiting framework (ADR-0022).
//!
//! The active limiter configuration is an immutable snapshot behind
//! [`ArcSwap`]. Requests take a lock-free snapshot, while configuration
//! reloads build and validate a complete replacement before atomically
//! publishing it. A failed reload therefore leaves the last-known-good
//! limiter and its counters in service.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use governor::clock::Clock as _;
use governor::{DefaultKeyedRateLimiter, Quota};
use ipnet::IpNet;
use tracing::warn;

use openstack_keystone_config::{Config, RateLimitSection, RateLimitTrustedProxiesSection};
use openstack_keystone_core_types::error::KeystoneError;

use crate::net::resolve_client_ip_from_nets;

/// Allocation-free global-IP bucket key.
///
/// IPv4 uses the complete `/32`; IPv6 stores only the network half of its
/// `/64`, grouping privacy-extension addresses without allocating a string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IpRateLimitKey {
    V4(u32),
    V6([u8; 8]),
}

type IpRateLimiter = DefaultKeyedRateLimiter<IpRateLimitKey>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedRateLimitConfig {
    global_ip: RateLimitSection,
    trusted_proxies: RateLimitTrustedProxiesSection,
}

impl AppliedRateLimitConfig {
    fn from_config(config: &Config) -> Self {
        Self {
            global_ip: config.rate_limit_global_ip.clone(),
            trusted_proxies: config.rate_limit_trusted_proxies.clone(),
        }
    }
}

struct RateLimitSnapshot {
    applied_config: AppliedRateLimitConfig,
    global_ip_limiter: Option<Arc<IpRateLimiter>>,
    trusted_proxies: Vec<IpNet>,
}

impl RateLimitSnapshot {
    fn disabled() -> Self {
        Self {
            applied_config: AppliedRateLimitConfig {
                global_ip: RateLimitSection::default(),
                trusted_proxies: RateLimitTrustedProxiesSection::default(),
            },
            global_ip_limiter: None,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Shared, hot-reloadable rate-limiting state held by the Keystone service.
pub struct RateLimitState {
    snapshot: ArcSwap<RateLimitSnapshot>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            snapshot: ArcSwap::new(Arc::new(RateLimitSnapshot::disabled())),
        }
    }
}

impl RateLimitState {
    /// Build the initial rate-limit snapshot.
    ///
    /// Enabled buckets with values outside `[1, 100000]`, or with malformed
    /// trusted-proxy CIDRs, fail startup.
    pub fn from_config(config: &Config) -> Result<Self, KeystoneError> {
        Ok(Self {
            snapshot: ArcSwap::new(Arc::new(build_snapshot(config)?)),
        })
    }

    /// Atomically apply changed rate-limit configuration.
    ///
    /// Returns `true` when a new snapshot was installed and `false` when the
    /// relevant configuration was unchanged. An invalid replacement returns
    /// an error without modifying the active snapshot.
    pub fn reload(&self, config: &Config) -> Result<bool, KeystoneError> {
        let requested = AppliedRateLimitConfig::from_config(config);
        if self.snapshot.load().applied_config == requested {
            return Ok(false);
        }

        self.snapshot.store(Arc::new(build_snapshot(config)?));
        Ok(true)
    }

    /// Check the global per-IP bucket for an inbound request.
    ///
    /// The effective address is the rightmost non-trusted
    /// `X-Forwarded-For` hop when the TCP peer is trusted. An absent peer
    /// identifies an internal/admin interface and bypasses this public-ingress
    /// limiter.
    pub fn check_ip(
        &self,
        xff_header: Option<&str>,
        peer_ip: Option<IpAddr>,
    ) -> Result<(), Duration> {
        let snapshot = self.snapshot.load();
        let Some(limiter) = snapshot.global_ip_limiter.as_ref() else {
            return Ok(());
        };
        let Some(client_ip) =
            resolve_client_ip_from_nets(xff_header, peer_ip, &snapshot.trusted_proxies)
        else {
            return Ok(());
        };

        let key = rate_limit_key_for_ip(client_ip);
        limiter.check_key(&key).map_err(|not_until| {
            let wait = not_until.wait_time_from(limiter.clock().now());
            wait.max(Duration::from_secs(1))
        })
    }

    /// Return whether the global-IP limiter is active.
    pub fn global_ip_enabled(&self) -> bool {
        self.snapshot.load().global_ip_limiter.is_some()
    }

    /// Evict stale entries from every active keyed state store.
    pub fn retain_recent(&self) {
        if let Some(limiter) = self.snapshot.load().global_ip_limiter.as_ref() {
            limiter.retain_recent();
        }
    }
}

const MAX_RATE_LIMIT_VALUE: u32 = 100_000;

fn validated_scalar(value: u32, field: &str, name: &str) -> Result<NonZeroU32, KeystoneError> {
    NonZeroU32::new(value)
        .filter(|value| value.get() <= MAX_RATE_LIMIT_VALUE)
        .ok_or_else(|| {
            KeystoneError::RateLimitConfig(format!(
                "[{name}] {field} must be in [1, {MAX_RATE_LIMIT_VALUE}] when enabled = true"
            ))
        })
}

fn build_snapshot(config: &Config) -> Result<RateLimitSnapshot, KeystoneError> {
    let applied_config = AppliedRateLimitConfig::from_config(config);
    let global_ip_limiter = build_limiter(&applied_config.global_ip, "rate_limit_global_ip")?;
    let trusted_proxies = if global_ip_limiter.is_some() {
        let parsed = applied_config
            .trusted_proxies
            .trusted_proxies
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNet>().map_err(|error| {
                    KeystoneError::RateLimitConfig(format!(
                        "[rate_limit_trusted_proxies] invalid CIDR {cidr:?}: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parsed.is_empty() {
            warn!(
                "Global IP rate limiting is enabled without trusted proxies; \
                 reverse-proxied deployments will share the proxy's bucket"
            );
        }
        parsed
    } else {
        Vec::new()
    };

    Ok(RateLimitSnapshot {
        applied_config,
        global_ip_limiter,
        trusted_proxies,
    })
}

fn build_limiter(
    section: &RateLimitSection,
    name: &str,
) -> Result<Option<Arc<IpRateLimiter>>, KeystoneError> {
    if !section.enabled {
        return Ok(None);
    }

    let replenish = validated_scalar(
        section.replenish_rate_per_second,
        "replenish_rate_per_second",
        name,
    )?;
    let burst = validated_scalar(section.burst_size, "burst_size", name)?;
    let quota = Quota::per_second(replenish).allow_burst(burst);

    Ok(Some(Arc::new(IpRateLimiter::keyed(quota))))
}

fn rate_limit_key_for_ip(ip: IpAddr) -> IpRateLimitKey {
    match ip {
        IpAddr::V4(ip) => IpRateLimitKey::V4(u32::from(ip)),
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            IpRateLimitKey::V6([
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                octets[7],
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn config(enabled: bool, burst: u32, replenish: u32) -> Config {
        Config {
            rate_limit_global_ip: RateLimitSection {
                enabled,
                burst_size: burst,
                replenish_rate_per_second: replenish,
            },
            ..Config::default()
        }
    }

    fn check(state: &RateLimitState, ip: IpAddr) -> Result<(), Duration> {
        state.check_ip(None, Some(ip))
    }

    #[test]
    fn ipv4_key_is_u32_address() {
        let ip = Ipv4Addr::new(203, 0, 113, 1);
        assert_eq!(
            rate_limit_key_for_ip(IpAddr::V4(ip)),
            IpRateLimitKey::V4(u32::from(ip))
        );
    }

    #[test]
    fn ipv6_key_is_first_64_bits() {
        let ip: IpAddr = "2001:db8:cafe:1::1".parse().unwrap();
        assert_eq!(
            rate_limit_key_for_ip(ip),
            IpRateLimitKey::V6([0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0x00, 0x01])
        );
    }

    #[test]
    fn different_ipv6_privacy_addresses_share_key() {
        let first: IpAddr = "2001:db8::dead:beef:1234:5678".parse().unwrap();
        let second: IpAddr = "2001:db8::dead:beef:abcd:ef01".parse().unwrap();
        assert_eq!(rate_limit_key_for_ip(first), rate_limit_key_for_ip(second));
    }

    #[test]
    fn disabled_section_yields_no_limiter() {
        let state = RateLimitState::from_config(&Config::default()).unwrap();
        assert!(!state.global_ip_enabled());
    }

    #[test]
    fn enabled_section_yields_limiter() {
        let state = RateLimitState::from_config(&config(true, 10, 5)).unwrap();
        assert!(state.global_ip_enabled());
    }

    #[test]
    fn invalid_bounds_fail_hard() {
        for (burst, replenish) in [
            (0, 5),
            (10, 0),
            (MAX_RATE_LIMIT_VALUE + 1, 5),
            (10, MAX_RATE_LIMIT_VALUE + 1),
        ] {
            assert!(RateLimitState::from_config(&config(true, burst, replenish)).is_err());
        }
        assert!(
            RateLimitState::from_config(&config(true, MAX_RATE_LIMIT_VALUE, MAX_RATE_LIMIT_VALUE))
                .is_ok()
        );
    }

    #[test]
    fn disabled_out_of_range_values_are_ignored() {
        assert!(RateLimitState::from_config(&config(false, 0, u32::MAX)).is_ok());
    }

    #[test]
    fn disabled_limiter_always_allows() {
        let state = RateLimitState::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(check(&state, ip).is_ok());
        }
    }

    #[test]
    fn enabled_limiter_allows_burst_then_rejects() {
        let state = RateLimitState::from_config(&config(true, 3, 1)).unwrap();
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        assert!(check(&state, ip).is_ok());
        assert!(check(&state, ip).is_ok());
        assert!(check(&state, ip).is_ok());
        assert!(check(&state, ip).unwrap_err() >= Duration::from_secs(1));
    }

    #[test]
    fn different_ips_have_independent_quotas() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(check(&state, first).is_ok());
        assert!(check(&state, first).is_err());
        assert!(check(&state, second).is_ok());
    }

    #[test]
    fn ipv6_privacy_addresses_share_quota() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        let first: IpAddr = "2001:db8::1".parse().unwrap();
        let second: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(check(&state, first).is_ok());
        assert!(check(&state, second).is_err());
    }

    #[test]
    fn trusted_proxy_uses_originating_client_bucket() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".to_string()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("10.0.0.1".parse().unwrap());

        assert!(state.check_ip(Some("203.0.113.1"), peer).is_ok());
        assert!(state.check_ip(Some("203.0.113.1"), peer).is_err());
        assert!(state.check_ip(Some("203.0.113.2"), peer).is_ok());
    }

    #[test]
    fn untrusted_peer_cannot_spoof_bucket_with_xff() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".to_string()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("198.51.100.10".parse().unwrap());

        assert!(state.check_ip(Some("203.0.113.1"), peer).is_ok());
        assert!(state.check_ip(Some("203.0.113.2"), peer).is_err());
    }

    #[test]
    fn missing_peer_bypasses_public_ingress_limiter() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        assert!(state.check_ip(Some("203.0.113.1"), None).is_ok());
        assert!(state.check_ip(Some("203.0.113.1"), None).is_ok());
    }

    #[test]
    fn unchanged_reload_preserves_counters() {
        let cfg = config(true, 1, 1);
        let state = RateLimitState::from_config(&cfg).unwrap();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(check(&state, ip).is_ok());
        assert!(!state.reload(&cfg).unwrap());
        assert!(check(&state, ip).is_err());
    }

    #[test]
    fn changed_reload_atomically_replaces_limiter() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(check(&state, ip).is_ok());

        assert!(state.reload(&config(true, 2, 1)).unwrap());
        assert!(check(&state, ip).is_ok());
        assert!(check(&state, ip).is_ok());
        assert!(check(&state, ip).is_err());
    }

    #[test]
    fn invalid_reload_keeps_last_known_good_limiter() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(check(&state, ip).is_ok());

        assert!(state.reload(&config(true, 0, 1)).is_err());
        assert!(check(&state, ip).is_err());
    }

    #[test]
    fn invalid_trusted_proxy_fails_when_limiter_enabled() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["not-a-cidr".to_string()];
        assert!(RateLimitState::from_config(&cfg).is_err());
    }
}
