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
//! # DPoP proof replay cache (RFC 9449 §11.1, ADR 0043 §2)
//!
//! Set of `(jkt, jti)` pairs, kept for as long as a proof can still pass the
//! `iat` window. The bounds, the no-eviction rule and the per-process
//! limits are those of [`ReplayCache`].
use thiserror::Error;

use super::dpop::VerifiedDpopProof;
use super::replay::{ReplayCache, ReplayError};

/// Why a proof was refused by the cache.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpopReplayError {
    /// The cache holds its maximum number of live entries.
    #[error("DPoP replay cache is full")]
    CacheFull,

    /// The key already holds its share of live entries.
    #[error("too many live DPoP proofs for this key")]
    KeyQuotaExceeded,

    /// The `(jkt, jti)` pair was already seen inside its window.
    #[error("DPoP proof was already used")]
    Replayed,
}

impl From<ReplayError> for DpopReplayError {
    fn from(error: ReplayError) -> Self {
        match error {
            ReplayError::CacheFull => Self::CacheFull,
            ReplayError::ScopeQuotaExceeded => Self::KeyQuotaExceeded,
            ReplayError::Replayed => Self::Replayed,
        }
    }
}

/// Replay cache for DPoP proofs.
pub struct DpopReplayCache {
    cache: ReplayCache,
    /// Seconds an entry outlives its `iat`: the verifier's `max_skew_secs`.
    window_secs: i64,
}

impl DpopReplayCache {
    /// Create a cache.
    ///
    /// `window_secs` must be the `max_skew_secs` the verifier checks `iat`
    /// against (`[oauth2] dpop_proof_lifetime_seconds`). An entry is kept until
    /// `iat + window_secs`, the last moment the same proof could still pass
    /// the check; a smaller value would open a replay gap. `max_per_key` and
    /// `max_total` bound the live entries.
    pub fn new(window_secs: u64, max_per_key: usize, max_total: usize) -> Self {
        Self {
            cache: ReplayCache::new(max_per_key, max_total),
            window_secs: i64::try_from(window_secs).unwrap_or(i64::MAX / 4),
        }
    }

    /// Record a verified proof, refusing a replay.
    ///
    /// # Errors
    /// [`DpopReplayError::Replayed`] for a seen `(jkt, jti)`, and the quota
    /// errors when the bounds are reached; live entries are never evicted.
    pub fn check_and_insert(
        &self,
        proof: &VerifiedDpopProof,
        now: i64,
    ) -> Result<(), DpopReplayError> {
        let expires = proof.iat.saturating_add(self.window_secs).saturating_add(1);
        Ok(self
            .cache
            .check_and_insert(&proof.jkt, &proof.jti, expires, now)?)
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;

    fn proof(jkt: &str, jti: &str, iat: i64) -> VerifiedDpopProof {
        VerifiedDpopProof {
            jkt: jkt.into(),
            jti: jti.into(),
            iat,
        }
    }

    #[test]
    fn test_replay_rejected_and_other_jti_or_key_accepted() {
        let cache = DpopReplayCache::new(60, 10, 100);
        assert!(cache.check_and_insert(&proof("k1", "a", NOW), NOW).is_ok());
        assert_eq!(
            cache.check_and_insert(&proof("k1", "a", NOW), NOW),
            Err(DpopReplayError::Replayed)
        );
        assert!(cache.check_and_insert(&proof("k1", "b", NOW), NOW).is_ok());
        assert!(cache.check_and_insert(&proof("k2", "a", NOW), NOW).is_ok());
    }

    #[test]
    fn test_entry_lives_until_proof_leaves_iat_window() {
        let cache = DpopReplayCache::new(60, 10, 100);
        let p = proof("k1", "a", NOW);
        cache.check_and_insert(&p, NOW).unwrap();
        // Still inside the window (iat + 60): a replay is caught.
        assert_eq!(
            cache.check_and_insert(&p, NOW + 60),
            Err(DpopReplayError::Replayed)
        );
        // After the window the proof fails the iat check anyway, so the
        // entry may be reused.
        assert!(cache.check_and_insert(&p, NOW + 61).is_ok());
    }

    #[test]
    fn test_per_key_quota_does_not_evict() {
        let cache = DpopReplayCache::new(60, 2, 100);
        cache.check_and_insert(&proof("k1", "a", NOW), NOW).unwrap();
        cache.check_and_insert(&proof("k1", "b", NOW), NOW).unwrap();
        assert_eq!(
            cache.check_and_insert(&proof("k1", "c", NOW), NOW),
            Err(DpopReplayError::KeyQuotaExceeded)
        );
        // The earlier entries are still protected.
        assert_eq!(
            cache.check_and_insert(&proof("k1", "a", NOW), NOW),
            Err(DpopReplayError::Replayed)
        );
        // Other keys are unaffected.
        assert!(cache.check_and_insert(&proof("k2", "a", NOW), NOW).is_ok());
    }

    #[test]
    fn test_fresh_key_flood_sheds_load_and_keeps_live_entries() {
        let cache = DpopReplayCache::new(60, 10, 3);
        cache
            .check_and_insert(&proof("victim", "x", NOW), NOW)
            .unwrap();
        cache.check_and_insert(&proof("f1", "a", NOW), NOW).unwrap();
        cache.check_and_insert(&proof("f2", "a", NOW), NOW).unwrap();
        assert_eq!(
            cache.check_and_insert(&proof("f3", "a", NOW), NOW),
            Err(DpopReplayError::CacheFull)
        );
        assert_eq!(cache.len(), 3);
        // The victim's captured proof is still rejected as a replay.
        assert_eq!(
            cache.check_and_insert(&proof("victim", "x", NOW), NOW),
            Err(DpopReplayError::Replayed)
        );
    }

    #[test]
    fn test_expired_entries_free_room() {
        let cache = DpopReplayCache::new(60, 10, 2);
        cache.check_and_insert(&proof("k1", "a", NOW), NOW).unwrap();
        cache.check_and_insert(&proof("k2", "a", NOW), NOW).unwrap();
        let later = NOW + 100;
        assert!(
            cache
                .check_and_insert(&proof("k3", "a", later), later)
                .is_ok()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_reusing_expired_jti_does_not_inflate_count() {
        let cache = DpopReplayCache::new(60, 10, 2);
        // Each round reuses the jti once the previous entry has expired,
        // without a purge in between.
        for round in 0..5 {
            let t = NOW + round * 100;
            cache.check_and_insert(&proof("k1", "a", t), t).unwrap();
        }
        assert_eq!(cache.len(), 1);
        // The cache is not spuriously full.
        let t = NOW + 500;
        assert!(cache.check_and_insert(&proof("k2", "a", t), t).is_ok());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_overwrite_allowed_at_quota() {
        let cache = DpopReplayCache::new(60, 1, 1);
        cache.check_and_insert(&proof("k1", "a", NOW), NOW).unwrap();
        let later = NOW + 100;
        assert!(
            cache
                .check_and_insert(&proof("k1", "a", later), later)
                .is_ok()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_purge_skipped_while_nothing_expired() {
        let cache = DpopReplayCache::new(60, 10, 100);
        cache.check_and_insert(&proof("k1", "a", NOW), NOW).unwrap();
        cache
            .check_and_insert(&proof("k1", "b", NOW + 30), NOW)
            .unwrap();
        // Nothing dead yet: the entries stay, and the bound is recomputed
        // after a real purge.
        cache.purge_expired(NOW + 10);
        assert_eq!(cache.len(), 2);
        cache.purge_expired(NOW + 70);
        assert_eq!(cache.len(), 1);
        cache.purge_expired(NOW + 91);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_purge_expired() {
        let cache = DpopReplayCache::new(60, 10, 100);
        cache.check_and_insert(&proof("k1", "a", NOW), NOW).unwrap();
        cache.purge_expired(NOW + 30);
        assert_eq!(cache.len(), 1);
        cache.purge_expired(NOW + 100);
        assert!(cache.is_empty());
    }
}
