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
// Crypto inventory: none (bookkeeping of identifiers only).
//! # Replay cache for external assertions (ADR 0026 §1, ADR 0036 §6.4)
//!
//! A JWT from an external IdP can be presented to the token endpoint more
//! than once while it is valid. This cache remembers the `jti` of each
//! accepted assertion, per `(domain, issuer)`, and refuses a second use.
//!
//! An entry is kept until the assertion can no longer pass verification: the
//! profile accepts a token up to the clock skew after its `exp`, so the entry
//! lives until `exp` plus that skew. The profile also caps the lifetime of
//! an assertion, so the cache stays small.
//!
//! Call it only with the `exp` of a token that
//! [`verify_subject_token_jwt`](super::verify::verify_subject_token_jwt)
//! accepted. The bounds, the no-eviction rule and the per-process limits are
//! those of [`ReplayCache`].
use super::replay::{ReplayCache, ReplayError};
use super::verify::PROFILE_CLOCK_SKEW;

/// Replay cache for the `jti` of external assertions.
pub struct AssertionReplayCache {
    cache: ReplayCache,
}

impl AssertionReplayCache {
    /// Create a cache. `max_per_issuer` bounds the live entries of one
    /// `(domain, issuer)` so a single IdP cannot fill the cache; `max_total`
    /// bounds all of them.
    pub fn new(max_per_issuer: usize, max_total: usize) -> Self {
        Self {
            cache: ReplayCache::new(max_per_issuer, max_total),
        }
    }

    /// Record the `jti` of a verified assertion, refusing a replay.
    ///
    /// `exp` is the `exp` claim of the verified token and `now` the current
    /// unix time.
    ///
    /// # Errors
    /// [`ReplayError::Replayed`] for a seen `(domain, issuer, jti)`, and the
    /// quota errors when the bounds are reached; live entries are never
    /// evicted.
    pub fn check_and_insert(
        &self,
        domain_id: &str,
        issuer: &str,
        jti: &str,
        exp: i64,
        now: i64,
    ) -> Result<(), ReplayError> {
        let skew = i64::try_from(PROFILE_CLOCK_SKEW.as_secs()).unwrap_or(i64::MAX / 4);
        let expires = exp.saturating_add(skew).saturating_add(1);
        self.cache
            .check_and_insert(&scope(domain_id, issuer), jti, expires, now)
    }

    /// Drop expired entries; meant for a periodic background task.
    pub fn purge_expired(&self, now: i64) {
        self.cache.purge_expired(now);
    }

    /// Number of entries currently held (live or not yet purged).
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache holds no entry.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// The scope of an entry. The length prefix keeps `(domain, issuer)` pairs
/// that concatenate to the same text apart.
fn scope(domain_id: &str, issuer: &str) -> String {
    format!("{}:{domain_id}{issuer}", domain_id.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;
    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const SKEW: i64 = 60;

    #[test]
    fn test_second_use_of_a_jti_is_refused() {
        let cache = AssertionReplayCache::new(10, 100);
        let exp = NOW + 300;
        assert!(cache.check_and_insert("d1", ISSUER, "a", exp, NOW).is_ok());
        assert_eq!(
            cache.check_and_insert("d1", ISSUER, "a", exp, NOW + 1),
            Err(ReplayError::Replayed)
        );
        assert!(cache.check_and_insert("d1", ISSUER, "b", exp, NOW).is_ok());
    }

    #[test]
    fn test_same_jti_is_independent_per_domain_and_issuer() {
        let cache = AssertionReplayCache::new(10, 100);
        let exp = NOW + 300;
        cache.check_and_insert("d1", ISSUER, "a", exp, NOW).unwrap();
        assert!(cache.check_and_insert("d2", ISSUER, "a", exp, NOW).is_ok());
        assert!(
            cache
                .check_and_insert("d1", "https://idp.example.com", "a", exp, NOW)
                .is_ok()
        );
    }

    #[test]
    fn test_scope_is_injective() {
        // Both pairs concatenate to "ab"; the scopes still differ.
        assert_ne!(scope("a", "b"), scope("ab", ""));
        let cache = AssertionReplayCache::new(10, 100);
        let exp = NOW + 300;
        cache.check_and_insert("a", "b", "x", exp, NOW).unwrap();
        assert!(cache.check_and_insert("ab", "", "x", exp, NOW).is_ok());
    }

    /// The token still passes verification until `exp` plus the skew, so a
    /// replay up to then must be caught and not a second longer.
    #[test]
    fn test_entry_lives_until_exp_plus_skew() {
        let cache = AssertionReplayCache::new(10, 100);
        let exp = NOW + 300;
        cache.check_and_insert("d1", ISSUER, "a", exp, NOW).unwrap();
        assert_eq!(
            cache.check_and_insert("d1", ISSUER, "a", exp, exp + SKEW),
            Err(ReplayError::Replayed)
        );
        assert!(
            cache
                .check_and_insert("d1", ISSUER, "a", exp + 2 * SKEW, exp + SKEW + 1)
                .is_ok()
        );
    }

    #[test]
    fn test_one_issuer_cannot_fill_the_cache() {
        let cache = AssertionReplayCache::new(2, 100);
        let exp = NOW + 300;
        cache.check_and_insert("d1", ISSUER, "a", exp, NOW).unwrap();
        cache.check_and_insert("d1", ISSUER, "b", exp, NOW).unwrap();
        assert_eq!(
            cache.check_and_insert("d1", ISSUER, "c", exp, NOW),
            Err(ReplayError::ScopeQuotaExceeded)
        );
        assert!(
            cache
                .check_and_insert("d1", "https://idp.example.com", "a", exp, NOW)
                .is_ok()
        );
    }

    #[test]
    fn test_purge_expired() {
        let cache = AssertionReplayCache::new(10, 100);
        cache
            .check_and_insert("d1", ISSUER, "a", NOW + 300, NOW)
            .unwrap();
        cache.purge_expired(NOW + 300 + SKEW);
        assert_eq!(cache.len(), 1);
        cache.purge_expired(NOW + 300 + SKEW + 1);
        assert!(cache.is_empty());
    }
}
