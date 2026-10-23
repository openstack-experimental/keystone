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
//! # Process-wide DPoP state (ADR 0043 §2)
//!
//! The replay cache and the nonce generator live for the whole process and
//! are shared by every request, so they hang off the service state. Both are
//! per node: the nonce key is derived from the cluster salt and is identical
//! on every node, the replay cache is best effort across nodes.
//!
//! The proof lifetime is captured here once, next to the replay cache whose
//! entry lifetime it sets, so the window the verifier accepts can never
//! outgrow the window the cache remembers, whatever a config reload does.

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use secrecy::ExposeSecret;

use openstack_keystone_config::Config;

use super::dpop_nonce::DpopNonceGenerator;
use super::dpop_replay::DpopReplayCache;

/// Replay cache and nonce generator, built once from the configuration.
///
/// The settings are read at startup: changing `[oauth2] dpop_*` or
/// `[mapping] cluster_salt` needs a restart.
pub struct DpopRuntime {
    /// Seen `(jkt, jti)` pairs.
    pub replay: DpopReplayCache,
    /// Seconds a proof stays acceptable (`[oauth2] dpop_proof_lifetime_seconds`
    /// at startup): the `iat` window of the verifier and the lifetime of the
    /// replay entries.
    pub proof_lifetime_secs: u64,
    /// Throttle keyed on the verified thumbprint of the proof key. Its own
    /// pool, so the keys of the attacker-chosen `client_id` limiter can never
    /// collide with it.
    pub throttle: DefaultKeyedRateLimiter<String>,
    /// The same throttle for proofs presented at the resource endpoints. A
    /// pool of its own with the same quota: reads with an access token are
    /// far more frequent than token requests, and sharing a bucket would let
    /// them starve issuance and refresh of the same key.
    pub resource_throttle: DefaultKeyedRateLimiter<String>,
    /// Nonce source. `None` when `[mapping] cluster_salt` is not set, in which
    /// case no request can be served in a DPoP mode other than `disabled`.
    pub nonces: Option<DpopNonceGenerator>,
}

impl DpopRuntime {
    /// Build the runtime from the configuration.
    pub fn from_config(config: &Config) -> Self {
        let oauth2 = &config.oauth2;
        let nonces = config.mapping.cluster_salt.as_ref().and_then(|salt| {
            DpopNonceGenerator::new(
                salt.expose_secret().as_bytes(),
                u64::from(oauth2.dpop_nonce_lifetime_seconds),
            )
            .inspect_err(|e| tracing::warn!(error = %e, "DPoP nonces are unavailable"))
            .ok()
        });
        let quota = Quota::per_minute(
            oauth2
                .token_rate_limit_replenish_per_minute
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        )
        .allow_burst(
            oauth2
                .token_rate_limit_burst_size
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        );
        Self {
            proof_lifetime_secs: u64::from(oauth2.dpop_proof_lifetime_seconds),
            throttle: RateLimiter::keyed(quota),
            resource_throttle: RateLimiter::keyed(quota),
            replay: DpopReplayCache::new(
                u64::from(oauth2.dpop_proof_lifetime_seconds),
                oauth2.dpop_replay_cache_max_entries_per_key as usize,
                oauth2.dpop_replay_cache_max_entries as usize,
            ),
            nonces,
        }
    }
}

impl Default for DpopRuntime {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_salt_means_no_nonces() {
        assert!(DpopRuntime::default().nonces.is_none());
    }

    /// Reads with a token must not use up the quota of token requests.
    #[test]
    fn test_resource_and_token_throttles_are_separate_pools() {
        let runtime = DpopRuntime::default();
        let burst = Config::default().oauth2.token_rate_limit_burst_size;
        for _ in 0..burst {
            assert!(
                runtime
                    .resource_throttle
                    .check_key(&"k1".to_string())
                    .is_ok()
            );
        }
        assert!(
            runtime
                .resource_throttle
                .check_key(&"k1".to_string())
                .is_err()
        );
        assert!(runtime.throttle.check_key(&"k1".to_string()).is_ok());
    }

    #[test]
    fn test_salt_enables_nonces() {
        let mut config = Config::default();
        config.mapping.cluster_salt = Some("salt-value".to_string().into());
        assert!(DpopRuntime::from_config(&config).nonces.is_some());
    }
}
