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
//! Bounded in-memory set of `(jkt, jti)` pairs, kept for as long as a proof
//! can still pass the `iat` window. The cache never evicts a live entry to
//! make room: once a key exceeds its share or the cache is full, new proofs
//! are rejected instead. Otherwise an attacker could flood the cache with
//! proofs from fresh keys, push out the entry of a captured proof and replay
//! it.
//!
//! The cache is per process; see ADR 0043 "Consequences" for the cross-node
//! limits.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use thiserror::Error;

use super::dpop::VerifiedDpopProof;

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

#[derive(Default)]
struct Inner {
    /// Lower bound of the earliest expiry held. Nothing can be dead before
    /// it, so a purge before then is skipped instead of scanning every entry.
    earliest: i64,
    /// `jkt` -> (`jti` -> unix second after which the entry is dead).
    keys: HashMap<String, HashMap<String, i64>>,
    total: usize,
}

impl Inner {
    fn purge(&mut self, now: i64) {
        if self.earliest > now {
            return;
        }
        let mut removed = 0;
        let mut earliest = i64::MAX;
        self.keys.retain(|_, jtis| {
            let before = jtis.len();
            jtis.retain(|_, expires| *expires > now);
            removed += before - jtis.len();
            earliest = jtis.values().fold(earliest, |acc, e| acc.min(*e));
            !jtis.is_empty()
        });
        self.total -= removed;
        self.earliest = earliest;
    }
}

/// Replay cache for DPoP proofs.
pub struct DpopReplayCache {
    inner: Mutex<Inner>,
    max_per_key: usize,
    max_total: usize,
    /// Seconds an entry outlives its `iat`: the verifier's `max_skew_secs`.
    window_secs: i64,
}

impl DpopReplayCache {
    /// Create a cache.
    ///
    /// `window_secs` must be the `max_skew_secs` the verifier checks `iat`
    /// against (`[oauth2] dpop_proof_lifetime_seconds`). An entry is kept until
    /// `iat + window_secs`, the last moment the same proof could still pass
    /// the check; a smaller value would open a replay gap. `max_per_key` and `max_total` bound the
    /// live entries.
    pub fn new(window_secs: u64, max_per_key: usize, max_total: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            window_secs: i64::try_from(window_secs).unwrap_or(i64::MAX / 4),
            max_per_key,
            max_total,
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
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        // Free dead entries only when a bound is about to be hit; the common
        // path stays O(1).
        if inner.total >= self.max_total
            || inner
                .keys
                .get(&proof.jkt)
                .is_some_and(|jtis| jtis.len() >= self.max_per_key)
        {
            inner.purge(now);
        }

        // An expired entry for the same `jti` is overwritten, so it neither
        // grows the key nor the cache.
        let mut overwrites = false;
        if let Some(jtis) = inner.keys.get(&proof.jkt) {
            match jtis.get(&proof.jti) {
                Some(e) if *e > now => return Err(DpopReplayError::Replayed),
                Some(_) => overwrites = true,
                None => {}
            }
            if !overwrites && jtis.len() >= self.max_per_key {
                return Err(DpopReplayError::KeyQuotaExceeded);
            }
        }
        if !overwrites && inner.total >= self.max_total {
            return Err(DpopReplayError::CacheFull);
        }

        inner
            .keys
            .entry(proof.jkt.clone())
            .or_default()
            .insert(proof.jti.clone(), expires);
        if !overwrites {
            inner.total += 1;
        }
        inner.earliest = inner.earliest.min(expires);
        Ok(())
    }

    /// Drop expired entries; meant for a periodic background task.
    pub fn purge_expired(&self, now: i64) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .purge(now);
    }

    /// Number of entries currently held (live or not yet purged).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }

    /// Whether the cache holds no entry.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
