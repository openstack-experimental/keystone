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
//! # Bounded replay cache
//!
//! Bounded in-memory set of `(scope, id)` pairs, each kept until the moment
//! the caller says the credential can no longer be accepted. The cache never
//! evicts a live entry to make room: once a scope exceeds its share or the
//! cache is full, new credentials are rejected instead. Otherwise an attacker
//! could flood the cache with credentials from fresh scopes, push out the
//! entry of a captured credential and replay it.
//!
//! The caller picks what the scope and the id are and when an entry dies:
//! [`DpopReplayCache`](super::dpop_replay::DpopReplayCache) (RFC 9449 §11.1)
//! and [`AssertionReplayCache`](super::assertion_replay::AssertionReplayCache)
//! (`jti` of external assertions) are the two users.
//!
//! The cache is per process; see ADR 0043 "Consequences" for the cross-node
//! limits.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use thiserror::Error;

/// Why a credential was refused by the cache.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    /// The cache holds its maximum number of live entries.
    #[error("replay cache is full")]
    CacheFull,

    /// The scope already holds its share of live entries.
    #[error("too many live entries for this scope")]
    ScopeQuotaExceeded,

    /// The `(scope, id)` pair was already seen and has not expired.
    #[error("credential was already used")]
    Replayed,
}

#[derive(Default)]
struct Inner {
    /// Lower bound of the earliest expiry held. Nothing can be dead before
    /// it, so a purge before then is skipped instead of scanning every entry.
    earliest: i64,
    /// scope -> (id -> unix second after which the entry is dead).
    scopes: HashMap<String, HashMap<String, i64>>,
    total: usize,
}

impl Inner {
    fn purge(&mut self, now: i64) {
        if self.earliest > now {
            return;
        }
        let mut removed = 0;
        let mut earliest = i64::MAX;
        self.scopes.retain(|_, ids| {
            let before = ids.len();
            ids.retain(|_, expires| *expires > now);
            removed += before - ids.len();
            earliest = ids.values().fold(earliest, |acc, e| acc.min(*e));
            !ids.is_empty()
        });
        self.total -= removed;
        self.earliest = earliest;
    }
}

/// Bounded set of seen `(scope, id)` pairs.
pub struct ReplayCache {
    inner: Mutex<Inner>,
    max_per_scope: usize,
    max_total: usize,
}

impl ReplayCache {
    /// Create a cache. `max_per_scope` and `max_total` bound the live
    /// entries.
    pub fn new(max_per_scope: usize, max_total: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_per_scope,
            max_total,
        }
    }

    /// Record a credential, refusing a replay.
    ///
    /// `expires` is the first unix second at which the entry is dead. It must
    /// not be earlier than the last moment the same credential could still
    /// pass verification; an earlier value opens a replay gap.
    ///
    /// # Errors
    /// [`ReplayError::Replayed`] for a seen `(scope, id)`, and the quota errors
    /// when the bounds are reached; live entries are never evicted.
    pub fn check_and_insert(
        &self,
        scope: &str,
        id: &str,
        expires: i64,
        now: i64,
    ) -> Result<(), ReplayError> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        // Free dead entries only when a bound is about to be hit; the common
        // path stays O(1).
        if inner.total >= self.max_total
            || inner
                .scopes
                .get(scope)
                .is_some_and(|ids| ids.len() >= self.max_per_scope)
        {
            inner.purge(now);
        }

        // An expired entry for the same id is overwritten, so it neither
        // grows the scope nor the cache.
        let mut overwrites = false;
        if let Some(ids) = inner.scopes.get(scope) {
            match ids.get(id) {
                Some(e) if *e > now => return Err(ReplayError::Replayed),
                Some(_) => overwrites = true,
                None => {}
            }
            if !overwrites && ids.len() >= self.max_per_scope {
                return Err(ReplayError::ScopeQuotaExceeded);
            }
        }
        if !overwrites && inner.total >= self.max_total {
            return Err(ReplayError::CacheFull);
        }

        inner
            .scopes
            .entry(scope.to_owned())
            .or_default()
            .insert(id.to_owned(), expires);
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
    const LIFETIME: i64 = 60;

    fn insert(cache: &ReplayCache, scope: &str, id: &str, at: i64) -> Result<(), ReplayError> {
        cache.check_and_insert(scope, id, at + LIFETIME, at)
    }

    #[test]
    fn test_replay_rejected_and_other_id_or_scope_accepted() {
        let cache = ReplayCache::new(10, 100);
        assert!(insert(&cache, "s1", "a", NOW).is_ok());
        assert_eq!(insert(&cache, "s1", "a", NOW), Err(ReplayError::Replayed));
        assert!(insert(&cache, "s1", "b", NOW).is_ok());
        assert!(insert(&cache, "s2", "a", NOW).is_ok());
    }

    #[test]
    fn test_entry_dies_exactly_at_expires() {
        let cache = ReplayCache::new(10, 100);
        cache
            .check_and_insert("s1", "a", NOW + LIFETIME, NOW)
            .unwrap();
        // One second before the expiry the entry is still live.
        assert_eq!(
            cache.check_and_insert("s1", "a", NOW + 2 * LIFETIME, NOW + LIFETIME - 1),
            Err(ReplayError::Replayed)
        );
        // From the expiry on it is dead and the id can be recorded again.
        assert!(
            cache
                .check_and_insert("s1", "a", NOW + 2 * LIFETIME, NOW + LIFETIME)
                .is_ok()
        );
    }

    #[test]
    fn test_scope_quota_does_not_evict() {
        let cache = ReplayCache::new(2, 100);
        insert(&cache, "s1", "a", NOW).unwrap();
        insert(&cache, "s1", "b", NOW).unwrap();
        assert_eq!(
            insert(&cache, "s1", "c", NOW),
            Err(ReplayError::ScopeQuotaExceeded)
        );
        // The earlier entries are still protected.
        assert_eq!(insert(&cache, "s1", "a", NOW), Err(ReplayError::Replayed));
        // Other scopes are unaffected.
        assert!(insert(&cache, "s2", "a", NOW).is_ok());
    }

    #[test]
    fn test_fresh_scope_flood_sheds_load_and_keeps_live_entries() {
        let cache = ReplayCache::new(10, 3);
        insert(&cache, "victim", "x", NOW).unwrap();
        insert(&cache, "f1", "a", NOW).unwrap();
        insert(&cache, "f2", "a", NOW).unwrap();
        assert_eq!(insert(&cache, "f3", "a", NOW), Err(ReplayError::CacheFull));
        assert_eq!(cache.len(), 3);
        // The victim's captured credential is still rejected as a replay.
        assert_eq!(
            insert(&cache, "victim", "x", NOW),
            Err(ReplayError::Replayed)
        );
    }

    #[test]
    fn test_expired_entries_free_room() {
        let cache = ReplayCache::new(10, 2);
        insert(&cache, "s1", "a", NOW).unwrap();
        insert(&cache, "s2", "a", NOW).unwrap();
        let later = NOW + 100;
        assert!(insert(&cache, "s3", "a", later).is_ok());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_reusing_expired_id_does_not_inflate_count() {
        let cache = ReplayCache::new(10, 2);
        // Each round reuses the id once the previous entry has expired,
        // without a purge in between.
        for round in 0..5 {
            insert(&cache, "s1", "a", NOW + round * 100).unwrap();
        }
        assert_eq!(cache.len(), 1);
        // The cache is not spuriously full.
        assert!(insert(&cache, "s2", "a", NOW + 500).is_ok());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_overwrite_allowed_at_quota() {
        let cache = ReplayCache::new(1, 1);
        insert(&cache, "s1", "a", NOW).unwrap();
        assert!(insert(&cache, "s1", "a", NOW + 100).is_ok());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_purge_expired() {
        let cache = ReplayCache::new(10, 100);
        insert(&cache, "s1", "a", NOW).unwrap();
        insert(&cache, "s1", "b", NOW + 30).unwrap();
        // Nothing dead yet: the entries stay.
        cache.purge_expired(NOW + 10);
        assert_eq!(cache.len(), 2);
        cache.purge_expired(NOW + 70);
        assert_eq!(cache.len(), 1);
        cache.purge_expired(NOW + 91);
        assert!(cache.is_empty());
    }
}
