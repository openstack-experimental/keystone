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

#[cfg(any(feature = "api", test))]
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use governor::clock::Clock as _;
use governor::{DefaultKeyedRateLimiter, Quota};
use ipnet::IpNet;
#[cfg(any(feature = "api", test))]
use sha2::{Digest, Sha256};
use tracing::warn;

use openstack_keystone_config::{Config, RateLimitSection, RateLimitTrustedProxiesSection};
use openstack_keystone_core_types::error::KeystoneError;

#[cfg(any(feature = "api", test))]
use crate::net::resolve_client_ip_from_headers;
#[cfg(any(feature = "api", test))]
use crate::rate_limit_metrics::SCOPE_PER_IP;
use crate::rate_limit_metrics::{RATE_LIMIT_METRICS, SCOPE_PER_USER};

/// Allocation-free global-IP bucket key.
///
/// IPv4 uses the complete `/32`; IPv6 stores only the network half of its
/// `/64`, grouping privacy-extension addresses without allocating a string.
// Variants are only constructed by `rate_limit_key_for_ip`, which is
// `#[cfg(any(feature = "api", test))]`-gated (it needs `axum::http::HeaderMap`
// to resolve the client IP); the type itself must stay always-available since
// `IpRateLimiter`/`global_ip_limiter` are not feature-gated.
#[cfg_attr(not(any(feature = "api", test)), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IpRateLimitKey {
    V4(u32),
    V6([u8; 8]),
}

type IpRateLimiter = DefaultKeyedRateLimiter<IpRateLimitKey>;

/// Per-user authentication bucket, keyed on the canonical user ID.
///
/// The key is the immutable `user.id` loaded from the backend, never a
/// caller-supplied username. ADR-0022 Invariant 7 (NFKC + case-fold
/// normalization of user-input keys) is therefore satisfied structurally:
/// no user-input-derived key exists to normalize, and Unicode homoglyph
/// usernames cannot mint distinct buckets for the same account.
type UserRateLimiter = DefaultKeyedRateLimiter<String>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedRateLimitConfig {
    global_ip: RateLimitSection,
    trusted_proxies: RateLimitTrustedProxiesSection,
    user_auth: RateLimitSection,
}

impl AppliedRateLimitConfig {
    fn from_config(config: &Config) -> Self {
        Self {
            global_ip: config.rate_limit_global_ip.clone(),
            trusted_proxies: config.rate_limit_trusted_proxies.clone(),
            user_auth: config.rate_limit_user_auth.clone(),
        }
    }
}

struct RateLimitSnapshot {
    applied_config: AppliedRateLimitConfig,
    global_ip_limiter: Option<Arc<IpRateLimiter>>,
    // Only read by `check_ip`, which is `#[cfg(any(feature = "api", test))]`-gated.
    #[cfg_attr(not(any(feature = "api", test)), allow(dead_code))]
    trusted_proxies: Vec<IpNet>,
    user_auth_limiter: Option<Arc<UserRateLimiter>>,
}

impl RateLimitSnapshot {
    fn disabled() -> Self {
        Self {
            applied_config: AppliedRateLimitConfig {
                global_ip: RateLimitSection::default(),
                trusted_proxies: RateLimitTrustedProxiesSection::default(),
                user_auth: RateLimitSection::default(),
            },
            global_ip_limiter: None,
            trusted_proxies: Vec::new(),
            user_auth_limiter: None,
        }
    }
}

/// Upper bound on tracked [`FailureBackoff`] entries, so an attacker spraying
/// random keys cannot grow the map without limit. At the cap a new key
/// displaces an entry with no earned penalty history (see
/// [`FailureBackoff::make_room`]), so flooding the map with throwaway keys
/// cannot stop a key from being tracked.
const BACKOFF_MAX_ENTRIES: usize = 100_000;

/// Minimum spacing of the O(n) eviction scan used when every tracked key is
/// under an active penalty, so a flood of new keys cannot turn each failed
/// request into a full-map scan.
const BACKOFF_FULL_SCAN_INTERVAL: Duration = Duration::from_secs(1);

/// First penalty once the free failures are used up; doubles per failure.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Penalty ceiling. Also the idle time after which a key's history is dropped.
const BACKOFF_MAX: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
struct BackoffEntry {
    failures: u32,
    until: Instant,
    last_failure: Instant,
}

/// Node-local, in-memory exponential backoff on failed attempts.
///
/// From the `free_failures`-th failure on (a per-call threshold, so it follows
/// live configuration), a key is refused for `BACKOFF_BASE`,
/// doubling with every further failure up to `BACKOFF_MAX`. A key idle for
/// longer than `BACKOFF_MAX` starts over. Keys are SHA-256 digests so no
/// user-supplied value is retained.
struct FailureBackoff {
    entries: DashMap<[u8; 32], BackoffEntry>,
    last_full_scan: Mutex<Instant>,
}

impl FailureBackoff {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            entries: DashMap::new(),
            last_full_scan: Mutex::new(now.checked_sub(BACKOFF_FULL_SCAN_INTERVAL).unwrap_or(now)),
        }
    }

    /// Free one slot for a new key while the map is at capacity.
    ///
    /// Entries that never earned a penalty (still within their free
    /// failures) or have gone idle carry no escalation history worth
    /// keeping, so one of those goes first; the search stops at the first
    /// hit. Entries that did earn a penalty are kept even after it expires,
    /// so flooding the map cannot reset an attacker's escalation. Only when
    /// every entry has earned one is the entry with the fewest failures
    /// evicted, and that O(n) scan runs at most once per
    /// `BACKOFF_FULL_SCAN_INTERVAL`. Returns `false` if no slot was freed,
    /// in which case the new key goes untracked.
    fn make_room(&self, now: Instant, free_failures: u32) -> bool {
        let unpenalised = self
            .entries
            .iter()
            .find(|e| {
                e.failures < free_failures || now.duration_since(e.last_failure) > BACKOFF_MAX
            })
            .map(|e| *e.key());
        if let Some(key) = unpenalised {
            self.entries.remove(&key);
            return true;
        }
        let Ok(mut last) = self.last_full_scan.try_lock() else {
            return false;
        };
        if now.duration_since(*last) < BACKOFF_FULL_SCAN_INTERVAL {
            return false;
        }
        *last = now;
        let soonest = self
            .entries
            .iter()
            .min_by_key(|e| (e.failures, e.until))
            .map(|e| *e.key());
        match soonest {
            Some(key) => self.entries.remove(&key).is_some(),
            None => false,
        }
    }

    /// Remaining penalty for `key`, if it is still in force.
    fn check(&self, key: &[u8; 32]) -> Result<(), Duration> {
        let Some(entry) = self.entries.get(key).map(|e| *e) else {
            return Ok(());
        };
        match entry.until.checked_duration_since(Instant::now()) {
            Some(remaining) => Err(remaining.max(Duration::from_secs(1))),
            None => Ok(()),
        }
    }

    /// Register a failure and return the penalty now in force (zero while
    /// failures are still free).
    fn record_failure(&self, key: [u8; 32], free_failures: u32) -> Duration {
        let now = Instant::now();
        if self.entries.len() >= BACKOFF_MAX_ENTRIES
            && !self.entries.contains_key(&key)
            && !self.make_room(now, free_failures)
        {
            return Duration::ZERO;
        }
        let mut entry = self.entries.entry(key).or_insert(BackoffEntry {
            failures: 0,
            until: now,
            last_failure: now,
        });
        if now.duration_since(entry.last_failure) > BACKOFF_MAX {
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = now;
        // The `free_failures`-th failure is the first to carry a penalty, so
        // attempt `free_failures + 1` is the first one refused.
        let penalty = match (entry.failures + 1).checked_sub(free_failures) {
            Some(exponent) if exponent > 0 => BACKOFF_BASE
                .saturating_mul(1u32.checked_shl(exponent - 1).unwrap_or(u32::MAX))
                .min(BACKOFF_MAX),
            _ => Duration::ZERO,
        };
        entry.until = now + penalty;
        penalty
    }

    fn retain_recent(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, e| now.duration_since(e.last_failure) <= BACKOFF_MAX);
    }
}

/// Shared, hot-reloadable rate-limiting state held by the Keystone service.
pub struct RateLimitState {
    snapshot: ArcSwap<RateLimitSnapshot>,
    /// Device-flow `user_code` brute-force backoff keyed on
    /// `(user_code, client_ip)` (ADR 0026 §7.C). Kept outside the reloadable
    /// snapshot: it has no configuration, so reloads must not reset it.
    device_code_backoff: FailureBackoff,
    /// Device-flow failed-lookup backoff keyed on the client IP alone, which
    /// bounds guessing across many different `user_code`s.
    device_ip_backoff: FailureBackoff,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::with_snapshot(RateLimitSnapshot::disabled())
    }
}

impl RateLimitState {
    /// Build the initial rate-limit snapshot.
    ///
    /// Enabled buckets with values outside `[1, 100000]`, or with malformed
    /// trusted-proxy CIDRs, fail startup.
    pub fn from_config(config: &Config) -> Result<Self, KeystoneError> {
        Ok(Self::with_snapshot(build_snapshot(config)?))
    }

    fn with_snapshot(snapshot: RateLimitSnapshot) -> Self {
        Self {
            snapshot: ArcSwap::new(Arc::new(snapshot)),
            device_code_backoff: FailureBackoff::new(),
            device_ip_backoff: FailureBackoff::new(),
        }
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
    /// The effective address is the rightmost non-trusted hop in the one
    /// operator-selected forwarding header when the TCP peer is trusted. An
    /// absent peer identifies an internal/admin interface and bypasses this
    /// public-ingress limiter.
    ///
    /// Records `keystone_rate_limit_evaluations_total{scope="per_ip",...}`
    /// (and `..._rejections_total` on the `Err` branch) only when a live
    /// limiter actually evaluates a bucket key — the disabled-limiter and
    /// no-resolvable-client-ip bypass paths above return early without
    /// recording, since no rate-limit evaluation actually took place there.
    #[cfg(any(feature = "api", test))]
    pub fn check_ip(
        &self,
        headers: &axum::http::HeaderMap,
        peer_ip: Option<IpAddr>,
    ) -> Result<(), Duration> {
        let snapshot = self.snapshot.load();
        let Some(limiter) = snapshot.global_ip_limiter.as_ref() else {
            return Ok(());
        };
        let Some(client_ip) = resolve_client_ip_from_headers(
            headers,
            peer_ip,
            &snapshot.trusted_proxies,
            snapshot.applied_config.trusted_proxies.trusted_header,
        ) else {
            return Ok(());
        };

        let key = rate_limit_key_for_ip(client_ip);
        let result = limiter.check_key(&key).map_err(|not_until| {
            let wait = not_until.wait_time_from(limiter.clock().now());
            wait.max(Duration::from_secs(1))
        });
        RATE_LIMIT_METRICS.record(SCOPE_PER_IP, result.is_ok());
        result
    }

    /// Check the per-user authentication bucket (ADR-0022, Invariant 8).
    ///
    /// Callers MUST pass the canonical user ID of a user that is already
    /// confirmed to exist in the backend, and MUST run this check before any
    /// CPU-intensive credential verification (Invariant 4). Keying on
    /// unverified input would let an attacker mint unlimited fresh buckets
    /// from novel usernames.
    ///
    /// Records `keystone_rate_limit_evaluations_total{scope="per_user",...}`
    /// (and `..._rejections_total` on the `Err` branch) only when the
    /// limiter is enabled; see [`Self::check_ip`] for why the disabled-case
    /// early return is not counted as an evaluation.
    pub fn check_user(&self, user_id: &str) -> Result<(), Duration> {
        let snapshot = self.snapshot.load();
        let Some(limiter) = snapshot.user_auth_limiter.as_ref() else {
            return Ok(());
        };

        let result = limiter.check_key(&user_id.to_owned()).map_err(|not_until| {
            let wait = not_until.wait_time_from(limiter.clock().now());
            wait.max(Duration::from_secs(1))
        });
        RATE_LIMIT_METRICS.record(SCOPE_PER_USER, result.is_ok());
        result
    }

    /// Digest keys for the device-flow backoffs.
    ///
    /// The `user_code` is normalized (trimmed, upper-cased) so case/space
    /// variants cannot mint fresh keys. The client IP is resolved like
    /// [`Self::check_ip`] (and shares its `/64` grouping for IPv6) but is
    /// resolved even when the global-IP limiter is disabled; trusted-proxy
    /// settings only apply while it is enabled. `None` means an
    /// internal/admin interface, which is not throttled.
    #[cfg(any(feature = "api", test))]
    fn device_code_keys(
        &self,
        headers: &axum::http::HeaderMap,
        peer_ip: Option<IpAddr>,
        user_code: &str,
    ) -> Option<([u8; 32], [u8; 32])> {
        let snapshot = self.snapshot.load();
        let client_ip = resolve_client_ip_from_headers(
            headers,
            peer_ip,
            &snapshot.trusted_proxies,
            snapshot.applied_config.trusted_proxies.trusted_header,
        )?;
        let ip_key = rate_limit_key_for_ip(client_ip);
        let ip_bytes: Vec<u8> = match ip_key {
            IpRateLimitKey::V4(v) => v.to_be_bytes().to_vec(),
            IpRateLimitKey::V6(v) => v.to_vec(),
        };

        let mut ip_hasher = Sha256::new();
        ip_hasher.update(&ip_bytes);
        let mut code_hasher = Sha256::new();
        code_hasher.update(user_code.trim().to_uppercase().as_bytes());
        code_hasher.update([0u8]);
        code_hasher.update(&ip_bytes);
        Some((code_hasher.finalize().into(), ip_hasher.finalize().into()))
    }

    /// Pre-lookup check for `user_code` submission at `/device` (ADR 0026
    /// §7.C). Refuses with the remaining penalty when either the
    /// `(user_code, ip)` pair or the client IP is in backoff. Run before any
    /// storage lookup; pair with [`Self::record_device_code_failure`].
    ///
    /// The key includes the client IP so a third party cannot lock a
    /// victim's pending code out by hammering it from elsewhere.
    #[cfg(any(feature = "api", test))]
    pub fn check_device_code(
        &self,
        headers: &axum::http::HeaderMap,
        peer_ip: Option<IpAddr>,
        user_code: &str,
    ) -> Result<(), Duration> {
        let Some((code_key, ip_key)) = self.device_code_keys(headers, peer_ip, user_code) else {
            return Ok(());
        };
        self.device_code_backoff
            .check(&code_key)
            .and_then(|()| self.device_ip_backoff.check(&ip_key))
    }

    /// Register a failed `user_code` lookup (unknown/expired code or wrong
    /// domain) for the backoff checked by [`Self::check_device_code`].
    ///
    /// The check and this call are not atomic, so concurrent in-flight
    /// guesses can slip a few extra attempts through before the first
    /// failure lands; the excess is bounded by request concurrency.
    /// The tracked-key map is capped: at the cap a new key displaces an
    /// entry with no earned penalty history; only if every entry is under an active penalty and
    /// the eviction scan is rate limited does it go untracked (fail-open).
    #[cfg(any(feature = "api", test))]
    pub fn record_device_code_failure(
        &self,
        headers: &axum::http::HeaderMap,
        peer_ip: Option<IpAddr>,
        user_code: &str,
        code_free_failures: u32,
        ip_free_failures: u32,
    ) {
        if let Some((code_key, ip_key)) = self.device_code_keys(headers, peer_ip, user_code) {
            self.device_code_backoff
                .record_failure(code_key, code_free_failures);
            // 0 disables the IP-wide key (shared-IP deployments).
            if ip_free_failures > 0 {
                self.device_ip_backoff
                    .record_failure(ip_key, ip_free_failures);
            }
        }
    }

    /// Return whether the global-IP limiter is active.
    pub fn global_ip_enabled(&self) -> bool {
        self.snapshot.load().global_ip_limiter.is_some()
    }

    /// Return whether the per-user authentication limiter is active.
    pub fn user_auth_enabled(&self) -> bool {
        self.snapshot.load().user_auth_limiter.is_some()
    }

    /// Evict stale entries from every active keyed state store.
    pub fn retain_recent(&self) {
        let snapshot = self.snapshot.load();
        if let Some(limiter) = snapshot.global_ip_limiter.as_ref() {
            limiter.retain_recent();
        }
        if let Some(limiter) = snapshot.user_auth_limiter.as_ref() {
            limiter.retain_recent();
        }
        self.device_code_backoff.retain_recent();
        self.device_ip_backoff.retain_recent();
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
    let user_auth_limiter = build_limiter(&applied_config.user_auth, "rate_limit_user_auth")?;
    // The CIDRs are already parsed into `IpNet` at configuration-load time
    // (`csv_ipnet`), so a malformed entry can never reach this point.
    let trusted_proxies = applied_config.trusted_proxies.trusted_proxies.clone();
    if global_ip_limiter.is_some() && trusted_proxies.is_empty() {
        warn!(
            "Global IP rate limiting is enabled without trusted proxies; \
             reverse-proxied deployments will share the proxy's bucket"
        );
    }

    Ok(RateLimitSnapshot {
        applied_config,
        global_ip_limiter,
        trusted_proxies,
        user_auth_limiter,
    })
}

fn build_limiter<K: Clone + Eq + std::hash::Hash>(
    section: &RateLimitSection,
    name: &str,
) -> Result<Option<Arc<DefaultKeyedRateLimiter<K>>>, KeystoneError> {
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

    Ok(Some(Arc::new(DefaultKeyedRateLimiter::keyed(quota))))
}

#[cfg(any(feature = "api", test))]
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

    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use openstack_keystone_config::ProxyHeader;

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
        state.check_ip(&HeaderMap::new(), Some(ip))
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
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
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("10.0.0.1".parse().unwrap());

        assert!(
            state
                .check_ip(&headers(&[("x-forwarded-for", "203.0.113.1")]), peer)
                .is_ok()
        );
        assert!(
            state
                .check_ip(&headers(&[("x-forwarded-for", "203.0.113.1")]), peer)
                .is_err()
        );
        assert!(
            state
                .check_ip(&headers(&[("x-forwarded-for", "203.0.113.2")]), peer)
                .is_ok()
        );
    }

    #[test]
    fn trusted_proxy_honours_rfc7239_forwarded_header() {
        // A proxy emitting RFC 7239 `Forwarded` must land clients in their
        // own buckets exactly like one emitting X-Forwarded-For.
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        cfg.rate_limit_trusted_proxies.trusted_header = ProxyHeader::Forwarded;
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("10.0.0.1".parse().unwrap());

        assert!(
            state
                .check_ip(
                    &headers(&[("forwarded", "for=203.0.113.1;proto=https")]),
                    peer,
                )
                .is_ok()
        );
        assert!(
            state
                .check_ip(
                    &headers(&[("forwarded", "for=203.0.113.1;proto=https")]),
                    peer,
                )
                .is_err()
        );
        assert!(
            state
                .check_ip(
                    &headers(&[("forwarded", "for=203.0.113.2;proto=https")]),
                    peer,
                )
                .is_ok()
        );
    }

    #[test]
    fn default_xff_ignores_client_forged_forwarded_header() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("10.0.0.1".parse().unwrap());

        assert!(
            state
                .check_ip(
                    &headers(&[
                        ("forwarded", "for=203.0.113.1"),
                        ("x-forwarded-for", "198.51.100.7"),
                    ]),
                    peer,
                )
                .is_ok()
        );
        // Changing only the untrusted Forwarded value cannot mint a new bucket.
        assert!(
            state
                .check_ip(
                    &headers(&[
                        ("forwarded", "for=203.0.113.2"),
                        ("x-forwarded-for", "198.51.100.7"),
                    ]),
                    peer,
                )
                .is_err()
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof_bucket_with_forwarding_headers() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("198.51.100.10".parse().unwrap());

        assert!(
            state
                .check_ip(
                    &headers(&[
                        ("forwarded", "for=203.0.113.1"),
                        ("x-forwarded-for", "203.0.113.1"),
                    ]),
                    peer,
                )
                .is_ok()
        );
        assert!(
            state
                .check_ip(
                    &headers(&[
                        ("forwarded", "for=203.0.113.2"),
                        ("x-forwarded-for", "203.0.113.2"),
                    ]),
                    peer,
                )
                .is_err()
        );
    }

    #[test]
    fn missing_peer_bypasses_public_ingress_limiter() {
        let state = RateLimitState::from_config(&config(true, 1, 1)).unwrap();
        let headers = headers(&[("x-forwarded-for", "203.0.113.1")]);
        assert!(state.check_ip(&headers, None).is_ok());
        assert!(state.check_ip(&headers, None).is_ok());
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

    fn user_config(enabled: bool, burst: u32, replenish: u32) -> Config {
        Config {
            rate_limit_user_auth: RateLimitSection {
                enabled,
                burst_size: burst,
                replenish_rate_per_second: replenish,
            },
            ..Config::default()
        }
    }

    #[test]
    fn user_auth_disabled_by_default() {
        let state = RateLimitState::from_config(&Config::default()).unwrap();
        assert!(!state.user_auth_enabled());
        for _ in 0..1000 {
            assert!(state.check_user("uid").is_ok());
        }
    }

    #[test]
    fn user_auth_enabled_section_yields_limiter() {
        let state = RateLimitState::from_config(&user_config(true, 5, 1)).unwrap();
        assert!(state.user_auth_enabled());
    }

    #[test]
    fn user_auth_invalid_bounds_fail_hard() {
        for (burst, replenish) in [
            (0, 1),
            (5, 0),
            (MAX_RATE_LIMIT_VALUE + 1, 1),
            (5, MAX_RATE_LIMIT_VALUE + 1),
        ] {
            assert!(RateLimitState::from_config(&user_config(true, burst, replenish)).is_err());
        }
    }

    #[test]
    fn user_auth_allows_burst_then_rejects_with_min_wait() {
        let state = RateLimitState::from_config(&user_config(true, 3, 1)).unwrap();
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").unwrap_err() >= Duration::from_secs(1));
    }

    #[test]
    fn different_users_have_independent_quotas() {
        let state = RateLimitState::from_config(&user_config(true, 1, 1)).unwrap();
        assert!(state.check_user("alice").is_ok());
        assert!(state.check_user("alice").is_err());
        assert!(state.check_user("bob").is_ok());
    }

    /// ADR-0022 Invariant 5: the IP and user buckets are physically separate
    /// limiters — exhausting one must not consume cells from the other.
    #[test]
    fn user_and_ip_buckets_are_distinct() {
        let mut cfg = config(true, 1, 1);
        cfg.rate_limit_user_auth = RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        };
        let state = RateLimitState::from_config(&cfg).unwrap();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_err());
        assert!(check(&state, ip).is_ok(), "ip bucket unaffected");
    }

    #[test]
    fn user_auth_reload_change_is_applied() {
        let state = RateLimitState::from_config(&user_config(true, 1, 1)).unwrap();
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_err());

        assert!(state.reload(&user_config(true, 2, 1)).unwrap());
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_ok());
        assert!(state.check_user("uid").is_err());
    }

    #[test]
    fn user_auth_unchanged_reload_preserves_counters() {
        let cfg = user_config(true, 1, 1);
        let state = RateLimitState::from_config(&cfg).unwrap();
        assert!(state.check_user("uid").is_ok());
        assert!(!state.reload(&cfg).unwrap());
        assert!(state.check_user("uid").is_err());
    }

    #[test]
    fn retain_recent_covers_user_bucket() {
        let state = RateLimitState::from_config(&user_config(true, 1, 1)).unwrap();
        assert!(state.check_user("uid").is_ok());
        state.retain_recent();
        assert!(
            state.check_user("uid").is_err(),
            "fresh entry survives trim"
        );
    }

    const TEST_CODE_FREE: u32 = 3;
    const TEST_IP_FREE: u32 = 10;

    fn device_check(state: &RateLimitState, ip: &str, code: &str) -> Result<(), Duration> {
        state.check_device_code(&HeaderMap::new(), Some(ip.parse().unwrap()), code)
    }

    fn device_fail(state: &RateLimitState, ip: &str, code: &str) {
        state.record_device_code_failure(
            &HeaderMap::new(),
            Some(ip.parse().unwrap()),
            code,
            TEST_CODE_FREE,
            TEST_IP_FREE,
        );
    }

    #[test]
    fn device_code_backoff_rejects_after_free_failures() {
        let state = RateLimitState::default();
        for _ in 0..TEST_CODE_FREE {
            assert!(device_check(&state, "203.0.113.1", "ABCD-EFGH").is_ok());
            device_fail(&state, "203.0.113.1", "ABCD-EFGH");
        }
        let wait = device_check(&state, "203.0.113.1", "ABCD-EFGH").unwrap_err();
        assert!(wait >= Duration::from_secs(1));
    }

    #[test]
    fn device_code_backoff_normalizes_user_code() {
        let state = RateLimitState::default();
        for _ in 0..TEST_CODE_FREE {
            device_fail(&state, "203.0.113.1", "abcd-efgh");
        }
        assert!(device_check(&state, "203.0.113.1", "  ABCD-EFGH ").is_err());
    }

    #[test]
    fn device_code_backoff_is_per_ip_for_the_same_code() {
        let state = RateLimitState::default();
        for _ in 0..TEST_CODE_FREE {
            device_fail(&state, "203.0.113.1", "ABCD-EFGH");
        }
        assert!(device_check(&state, "203.0.113.1", "ABCD-EFGH").is_err());
        // A different client submitting the (valid) code is unaffected.
        assert!(device_check(&state, "203.0.113.2", "ABCD-EFGH").is_ok());
    }

    #[test]
    fn device_ip_backoff_bounds_guessing_across_codes() {
        let state = RateLimitState::default();
        for i in 0..TEST_IP_FREE {
            device_fail(&state, "203.0.113.1", &format!("CODE-{i:04}"));
        }
        // A never-tried code is refused for the spraying IP only.
        assert!(device_check(&state, "203.0.113.1", "FRESH-CODE").is_err());
        assert!(device_check(&state, "203.0.113.2", "FRESH-CODE").is_ok());
    }

    #[test]
    fn failure_backoff_grows_exponentially_and_is_capped() {
        let backoff = FailureBackoff::new();
        let key = [7u8; 32];
        assert_eq!(backoff.record_failure(key, 2), Duration::ZERO);
        assert_eq!(backoff.record_failure(key, 2), Duration::from_secs(1));
        assert_eq!(backoff.record_failure(key, 2), Duration::from_secs(2));
        assert_eq!(backoff.record_failure(key, 2), Duration::from_secs(4));
        for _ in 0..40 {
            backoff.record_failure(key, 2);
        }
        assert_eq!(backoff.record_failure(key, 2), BACKOFF_MAX);
    }

    fn fill_backoff(backoff: &FailureBackoff, free_failures: u32) {
        for i in 0..BACKOFF_MAX_ENTRIES as u32 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            backoff.record_failure(key, free_failures);
        }
        assert_eq!(backoff.entries.len(), BACKOFF_MAX_ENTRIES);
    }

    #[test]
    fn failure_backoff_tracks_new_key_when_map_is_full_of_fresh_keys() {
        let backoff = FailureBackoff::new();
        fill_backoff(&backoff, 2);

        let key = [0xffu8; 32];
        assert_eq!(backoff.record_failure(key, 2), Duration::ZERO);
        assert_eq!(backoff.record_failure(key, 2), Duration::from_secs(1));
        assert!(backoff.check(&key).is_err());
        assert!(backoff.entries.len() <= BACKOFF_MAX_ENTRIES);
    }

    #[test]
    fn failure_backoff_flood_cannot_reset_escalation() {
        let backoff = FailureBackoff::new();
        let guesser = [0xaau8; 32];
        for _ in 0..5 {
            backoff.record_failure(guesser, 2);
        }
        fill_backoff(&backoff, 2);
        // Fresh keys displace each other, never the escalated key.
        for i in 0..1000u32 {
            let mut key = [0xbbu8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            backoff.record_failure(key, 2);
        }
        assert!(backoff.entries.contains_key(&guesser));
        assert!(
            backoff
                .entries
                .get(&guesser)
                .is_some_and(|e| e.failures == 5)
        );
    }

    #[test]
    fn failure_backoff_full_of_penalised_keys_evicts_rate_limited() {
        let backoff = FailureBackoff::new();
        fill_backoff(&backoff, 1);

        let first = [0xfeu8; 32];
        let second = [0xfdu8; 32];
        assert!(backoff.record_failure(first, 1) > Duration::ZERO);
        assert!(backoff.check(&first).is_err());
        // The O(n) scan is throttled: the next new key goes untracked.
        assert_eq!(backoff.record_failure(second, 1), Duration::ZERO);
        assert!(backoff.entries.len() <= BACKOFF_MAX_ENTRIES);
    }

    #[test]
    fn device_ip_backoff_can_be_disabled() {
        let state = RateLimitState::default();
        for i in 0..50 {
            state.record_device_code_failure(
                &HeaderMap::new(),
                Some("203.0.113.1".parse().unwrap()),
                &format!("CODE-{i:04}"),
                TEST_CODE_FREE,
                0,
            );
        }
        assert!(device_check(&state, "203.0.113.1", "FRESH-CODE").is_ok());
    }

    #[test]
    fn trusted_proxies_apply_with_global_limiter_disabled() {
        let mut cfg = Config::default();
        cfg.rate_limit_trusted_proxies.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let state = RateLimitState::from_config(&cfg).unwrap();
        let peer = Some("10.0.0.1".parse().unwrap());
        let victim = headers(&[("x-forwarded-for", "203.0.113.2")]);
        let attacker = headers(&[("x-forwarded-for", "203.0.113.1")]);
        for _ in 0..TEST_IP_FREE {
            state.record_device_code_failure(
                &attacker,
                peer,
                "GUESS",
                TEST_CODE_FREE,
                TEST_IP_FREE,
            );
        }
        assert!(state.check_device_code(&attacker, peer, "GUESS").is_err());
        assert!(state.check_device_code(&victim, peer, "OTHER").is_ok());
    }

    #[test]
    fn device_code_backoff_bypassed_without_peer() {
        let state = RateLimitState::default();
        for _ in 0..50 {
            state.record_device_code_failure(&HeaderMap::new(), None, "ABCD-EFGH", 3, 10);
        }
        assert!(
            state
                .check_device_code(&HeaderMap::new(), None, "ABCD-EFGH")
                .is_ok()
        );
    }

    #[test]
    fn device_code_backoff_survives_reload() {
        let state = RateLimitState::default();
        for _ in 0..TEST_CODE_FREE {
            device_fail(&state, "203.0.113.1", "ABCD-EFGH");
        }
        assert!(state.reload(&config(true, 5, 1)).unwrap());
        assert!(device_check(&state, "203.0.113.1", "ABCD-EFGH").is_err());
    }

    // NOTE: a malformed trusted-proxy CIDR can no longer reach
    // `RateLimitState::from_config` — `[rate_limit_trusted_proxies]` is
    // deserialized straight into `Vec<IpNet>` (`csv_ipnet`), so a bad entry
    // fails configuration loading. That path is covered by
    // `deserialize_malformed_trusted_proxy_fails` in
    // `crates/config/src/rate_limit.rs`.
}
