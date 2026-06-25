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

//! # Handler-level rate limiting framework (ADR-0022)
//!
//! Provides [`RateLimitState`], which is stored on [`crate::keystone::Service`]
//! and holds one [`governor`] keyed rate-limiter per *bucket* (key
//! dimension). The framework is extensible: new buckets (per-user,
//! per-domain, per-IdP) are added as new `Option<…>` fields without changing
//! existing callers.
//!
//! ## Currently wired bucket
//!
//! | Bucket | Config section | Key | ADR invariant |
//! |---|---|---|---|
//! | Global per-IP | `[rate_limit_global_ip]` | IPv4 `/32`, IPv6 `/64` prefix | 1, 2, 3, 4, 5, 6 |
//!
//! ## Deferred buckets
//!
//! Per-user, per-domain, and per-IdP limiting require keying on a *confirmed*
//! user / domain ID, which is only available after the DB lookup inside
//! `identity-driver-sql` (ADR-0022 Invariant 8). These are deferred to a
//! follow-up PR that will refactor the driver to expose the lookup result
//! before password verification.
//!
//! ## Security invariants (ADR-0022 §4)
//!
//! * **Invariant 2 — fail-hard init:** if a bucket is `enabled = true` and
//!   `burst_size` or `replenish_rate_per_second` is zero,
//!   [`RateLimitState::from_config`] returns
//!   [`KeystoneError::RateLimitConfig`] and the application refuses to start.
//! * **Invariant 3 — response uniformity:** the `Duration` returned by
//!   [`RateLimitState::check_ip`] is used to build the single `Retry-After`
//!   header; no key-identifying information is exposed.
//! * **Invariant 6 — monotonic clock:** all limiters use
//!   [`governor::clock::DefaultClock`] which resolves to
//!   `MonotonicClock` on `std` targets, preventing NTP backward-shift resets.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::Clock as _;
use governor::{DefaultKeyedRateLimiter, Quota};

use openstack_keystone_config::Config;
use openstack_keystone_core_types::error::KeystoneError;

/// Shared rate-limiting state, held on [`crate::keystone::Service`].
///
/// Each field is an `Option<Arc<…>>`: `None` when the bucket is disabled in
/// `keystone.conf`; `Some(…)` when enabled. Disabled buckets cost only the
/// `Option` discriminant — no `governor` state is allocated.
///
/// The struct is `Clone`-able via `Arc` sharing, not by copying limiter state.
pub struct RateLimitState {
    /// Global per-IP limiter — `[rate_limit_global_ip]` in `keystone.conf`.
    ///
    /// Keyed on IPv4 `/32` (full address) or IPv6 `/64` network prefix.
    /// `None` when `enabled = false`.
    pub global_ip_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    // Future buckets:
    // pub user_auth_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    // pub domain_limiter:    Option<Arc<DefaultKeyedRateLimiter<String>>>,
    // pub idp_limiter:       Option<Arc<DefaultKeyedRateLimiter<String>>>,
}

impl RateLimitState {
    /// Build [`RateLimitState`] from the application configuration.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoneError::RateLimitConfig`] and aborts startup when a
    /// bucket is `enabled = true` but has a `burst_size` or
    /// `replenish_rate_per_second` of zero (ADR-0022 Invariant 2).
    pub fn from_config(cfg: &Config) -> Result<Self, KeystoneError> {
        let global_ip_limiter = build_limiter(&cfg.rate_limit_global_ip, "rate_limit_global_ip")?;

        Ok(Self { global_ip_limiter })
    }

    /// Check the global per-IP bucket for `ip`.
    ///
    /// Returns `Ok(())` when:
    /// - the bucket is disabled (`enabled = false`), or
    /// - the IP is under its quota.
    ///
    /// Returns `Err(retry_after)` — the `Duration` to place in the
    /// `Retry-After` HTTP header — when the bucket is enabled and the IP has
    /// exceeded its quota.
    ///
    /// SPIFFE interfaces (internal / admin) do not populate
    /// `ConnectInfo<SocketAddr>`, so the caller holds an
    /// `Option<ConnectInfo<…>>` and skips this call when it is `None`.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), Duration> {
        let Some(ref limiter) = self.global_ip_limiter else {
            return Ok(()); // bucket disabled — bypass
        };
        let key = rate_limit_key_for_ip(ip);
        limiter.check_key(&key).map_err(|not_until| {
            // `DefaultKeyedRateLimiter` uses `DefaultClock` (`QuantaClock` on
            // std targets). Its `Instant` type is `QuantaInstant`, not
            // `std::time::Instant`, so we obtain the current time through the
            // limiter's own clock rather than `Instant::now()`.
            // `QuantaClock` reads the CPU's TSC — always monotonic; satisfies
            // ADR-0022 Invariant 6.
            let now = limiter.clock().now();
            let wait = not_until.wait_time_from(now);
            // Ensure at least 1 s so a well-behaved client doesn't busy-retry.
            wait.max(Duration::from_secs(1))
        })
    }

    /// Evict stale entries from all keyed state stores.
    ///
    /// Should be called on a ~60 s background timer (ADR-0022 §Consequences).
    /// This prevents unbounded memory growth under adversarial unique-key
    /// flooding. Callers that no longer appear in the store within the last
    /// quota window are pruned.
    pub fn retain_recent(&self) {
        if let Some(ref limiter) = self.global_ip_limiter {
            limiter.retain_recent();
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a single keyed `governor` rate limiter from a [`RateLimitSection`].
///
/// Returns `None` when the section is disabled. Returns
/// `Err(KeystoneError::RateLimitConfig)` when the section is enabled but
/// has invalid parameters (ADR-0022 Invariant 2).
fn build_limiter(
    section: &openstack_keystone_config::RateLimitSection,
    name: &str,
) -> Result<Option<Arc<DefaultKeyedRateLimiter<String>>>, KeystoneError> {
    if !section.enabled {
        return Ok(None);
    }

    let replenish = NonZeroU32::new(section.replenish_rate_per_second).ok_or_else(|| {
        KeystoneError::RateLimitConfig(format!(
            "[{name}] replenish_rate_per_second must be ≥ 1 when enabled = true"
        ))
    })?;

    let burst = NonZeroU32::new(section.burst_size).ok_or_else(|| {
        KeystoneError::RateLimitConfig(format!(
            "[{name}] burst_size must be ≥ 1 when enabled = true"
        ))
    })?;

    // Quota: `replenish` cells per second, up to `burst` in a burst.
    // Uses `DefaultClock` = `MonotonicClock` (ADR-0022 Invariant 6).
    let quota = Quota::per_second(replenish).allow_burst(burst);
    let limiter = DefaultKeyedRateLimiter::keyed(quota);

    Ok(Some(Arc::new(limiter)))
}

/// Derive a rate-limiting key from a client IP address.
///
/// - **IPv4** addresses are keyed per `/32` (full address), since IPv4 address
///   exhaustion means each address genuinely maps to a distinct node.
/// - **IPv6** addresses are aggregated to their `/64` prefix. RFC 4291 §2.5.1
///   allocates a `/64` subnet per link, and OS privacy extensions
///   (`RFC 4941`) randomise the lower 64 bits per connection — keying on the
///   full `/128` would give each connection its own independent quota.
fn rate_limit_key_for_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => ip.to_string(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // Zero the host portion (lower 8 bytes) to get the /64 prefix.
            let prefix = std::net::Ipv6Addr::from([
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                octets[7], 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            prefix.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use openstack_keystone_config::RateLimitSection;

    use super::*;

    fn enabled_section(burst: u32, replenish: u32) -> RateLimitSection {
        RateLimitSection {
            enabled: true,
            burst_size: burst,
            replenish_rate_per_second: replenish,
        }
    }

    fn disabled_section() -> RateLimitSection {
        RateLimitSection::default()
    }

    // --- key derivation ---

    #[test]
    fn ipv4_key_is_full_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(rate_limit_key_for_ip(ip), "203.0.113.1");
    }

    #[test]
    fn ipv6_key_is_slash_64_prefix() {
        // Full address: 2001:db8:cafe:1::1
        let ip = IpAddr::V6("2001:db8:cafe:0001:0000:0000:0000:0001".parse().unwrap());
        let key = rate_limit_key_for_ip(ip);
        // Lower 64 bits zeroed → 2001:db8:cafe:1::
        assert_eq!(key, "2001:db8:cafe:1::");
    }

    #[test]
    fn different_ipv6_privacy_addrs_share_key() {
        // Two privacy extension addresses in the same /64 must get the same key.
        let a: IpAddr = "2001:db8::dead:beef:1234:5678".parse().unwrap();
        let b: IpAddr = "2001:db8::dead:beef:abcd:ef01".parse().unwrap();
        assert_eq!(rate_limit_key_for_ip(a), rate_limit_key_for_ip(b));
    }

    // --- from_config ---

    #[test]
    fn disabled_section_yields_none() {
        let result = build_limiter(&disabled_section(), "test");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn enabled_section_yields_some() {
        let result = build_limiter(&enabled_section(10, 5), "test");
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn zero_replenish_is_fail_hard() {
        let section = RateLimitSection {
            enabled: true,
            burst_size: 10,
            replenish_rate_per_second: 0,
        };
        let err = build_limiter(&section, "rate_limit_global_ip").unwrap_err();
        assert!(
            matches!(err, KeystoneError::RateLimitConfig(msg) if msg.contains("replenish_rate_per_second"))
        );
    }

    #[test]
    fn zero_burst_is_fail_hard() {
        let section = RateLimitSection {
            enabled: true,
            burst_size: 0,
            replenish_rate_per_second: 5,
        };
        let err = build_limiter(&section, "rate_limit_global_ip").unwrap_err();
        assert!(matches!(err, KeystoneError::RateLimitConfig(msg) if msg.contains("burst_size")));
    }

    #[test]
    fn disabled_with_zero_values_does_not_fail() {
        // Invariant: disabled sections must never cause a startup error.
        let section = RateLimitSection {
            enabled: false,
            burst_size: 0,
            replenish_rate_per_second: 0,
        };
        let result = build_limiter(&section, "test");
        assert!(result.unwrap().is_none());
    }

    // --- check_ip ---

    #[test]
    fn disabled_limiter_always_allows() {
        let state = RateLimitState {
            global_ip_limiter: None,
        };
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(state.check_ip(ip).is_ok());
        }
    }

    #[test]
    fn enabled_limiter_allows_up_to_burst_then_rejects() {
        // burst=3, replenish=1/s — the first 3 calls must pass, the 4th fails.
        let state = RateLimitState {
            global_ip_limiter: Some(Arc::new(DefaultKeyedRateLimiter::keyed(
                Quota::per_second(NonZeroU32::new(1).unwrap())
                    .allow_burst(NonZeroU32::new(3).unwrap()),
            ))),
        };
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        assert!(state.check_ip(ip).is_ok());
        assert!(state.check_ip(ip).is_ok());
        assert!(state.check_ip(ip).is_ok());
        // 4th request must be rejected.
        let err = state.check_ip(ip).unwrap_err();
        // Retry-After should be at least 1 second.
        assert!(err >= Duration::from_secs(1));
    }

    #[test]
    fn different_ips_have_independent_quotas() {
        let state = RateLimitState {
            global_ip_limiter: Some(Arc::new(DefaultKeyedRateLimiter::keyed(
                Quota::per_second(NonZeroU32::new(1).unwrap())
                    .allow_burst(NonZeroU32::new(1).unwrap()),
            ))),
        };
        let ip_a: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.2".parse().unwrap();
        // Exhaust ip_a's quota.
        let _ = state.check_ip(ip_a);
        let _ = state.check_ip(ip_a);
        // ip_b should still be allowed.
        assert!(state.check_ip(ip_b).is_ok());
    }

    #[test]
    fn ipv6_privacy_addrs_share_quota() {
        // Two /128 addresses in the same /64 must hit the *same* bucket.
        let state = RateLimitState {
            global_ip_limiter: Some(Arc::new(DefaultKeyedRateLimiter::keyed(
                Quota::per_second(NonZeroU32::new(1).unwrap())
                    .allow_burst(NonZeroU32::new(1).unwrap()),
            ))),
        };
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        // First call on `a` consumes the burst.
        let _ = state.check_ip(a);
        // Second call on `b` (same /64) should be rejected.
        assert!(state.check_ip(b).is_err());
    }
}
