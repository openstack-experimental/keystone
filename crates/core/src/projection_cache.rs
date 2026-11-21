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
//! # Driver-side projection cache
//!
//! A SQL driver caches *projections*: small, derived, non-secret facts (a
//! password expiry, the options of a user, the domain of a project), never the
//! rows they were computed from and never secret material.
//!
//! An entry is served only when the reader's [`Freshness`] allows it:
//!
//! - [`Freshness::Linearizable`] always reads through.
//! - With the table watermark poller running, an entry is valid while the
//!   counters of the tables it depends on are unchanged *and* the counters
//!   themselves are recent enough for the requested tolerance. A tolerance
//!   below the poll interval is a forced read (see
//!   [`TableWatermarks::stamp_for`]).
//! - Without the poller a tolerance is honoured by the age of the entry.
//!
//! A read that is not served from the cache still refreshes it, so a tight
//! reader keeps the entries warm for the relaxed ones.
//!
//! The driver invalidates the cache itself on the writes it performs
//! ([`ProjectionCache::invalidate_key`], or [`ProjectionCache::invalidate`]
//! when the affected keys are unknown): the watermark only reaches this replica
//! after the next poll, and a replica must see its own writes.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use openstack_keystone_core_types::freshness::Freshness;

use crate::table_watermark::TableWatermarks;

/// How long an entry is trusted for [`Freshness::Any`] when there is no
/// watermark poller to say that it is outdated.
pub const ANY_TTL_WITHOUT_POLLER: Duration = Duration::from_secs(60);

/// Number of invalidation shards. A write to one key also drops the entries
/// loaded concurrently for keys of the same shard, which is harmless.
const SHARDS: usize = 64;

struct Entry<V> {
    /// Counters of the tables before the load, `None` without a poller.
    stamp: Option<u64>,
    /// Invalidation generation of the key's shard before the load.
    generation: u64,
    loaded_at: Instant,
    value: V,
}

/// A bounded map of projections of the `tables`.
pub struct ProjectionCache<V> {
    tables: &'static [&'static str],
    capacity: usize,
    generations: Vec<AtomicU64>,
    entries: Mutex<HashMap<String, Entry<V>>>,
}

impl<V: Clone> ProjectionCache<V> {
    /// Create a cache of projections that depend on the `tables`.
    ///
    /// When `capacity` entries are reached an arbitrary entry is evicted.
    pub fn new(tables: &'static [&'static str], capacity: usize) -> Self {
        Self {
            tables,
            capacity,
            generations: (0..SHARDS).map(|_| AtomicU64::new(0)).collect(),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn shard(&self, key: &str) -> &AtomicU64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        // The modulo keeps the value below SHARDS, so the index is in range.
        let index = usize::try_from(hasher.finish() % SHARDS as u64).unwrap_or(0);
        &self.generations[index]
    }

    /// Drop everything, e.g. after the driver wrote rows whose keys it does
    /// not know.
    ///
    /// A load that started before the call cannot repopulate the cache with a
    /// result that predates the write.
    pub fn invalidate(&self) {
        for generation in &self.generations {
            generation.fetch_add(1, Ordering::AcqRel);
        }
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Drop the projection of one `key`, e.g. after the driver wrote it.
    ///
    /// A load of the key that started before the call cannot store a result
    /// that predates the write.
    pub fn invalidate_key(&self, key: &str) {
        self.shard(key).fetch_add(1, Ordering::AcqRel);
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }

    /// Number of entries, for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lookup(
        &self,
        watermarks: &TableWatermarks,
        key: &str,
        freshness: Freshness,
        generation: u64,
    ) -> Option<V> {
        if freshness.is_linearizable() {
            return None;
        }
        let current = if watermarks.interval().is_zero() {
            None
        } else {
            Some(watermarks.stamp_for(self.tables, freshness)?)
        };
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.generation != generation {
            return None;
        }
        let valid = match current {
            Some(current) => entry.stamp == Some(current),
            None => {
                let ttl = freshness.bound().unwrap_or(ANY_TTL_WITHOUT_POLLER);
                entry.loaded_at.elapsed() <= ttl
            }
        };
        valid.then(|| entry.value.clone())
    }

    /// Get the projection for the `key` or load it.
    ///
    /// # Parameters
    /// - `watermarks`: counters of the connection the loader reads through.
    /// - `key`: what the projection is about, e.g. a user ID.
    /// - `freshness`: how stale the result may be.
    /// - `load`: reads the projection from the database. It must not
    ///   depend on anything but the `tables` of the cache.
    pub async fn get_or_load<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let generation = self.shard(key).load(Ordering::Acquire);
        if let Some(hit) = self.lookup(watermarks, key, freshness, generation) {
            return Ok(hit);
        }
        // The stamp is taken before the load: the value is at least as new
        // as the counters it is labelled with.
        let stamp = watermarks.stamp(self.tables);
        let value = load().await?;
        self.store(key, stamp, generation, &value);
        Ok(value)
    }

    /// Like [`Self::get_or_load`] for a loader that may find nothing.
    ///
    /// A missing value is returned but never stored: a stale "does not
    /// exist" is worse than a stale value, and misses are cheap to repeat.
    pub async fn get_or_load_some<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        let generation = self.shard(key).load(Ordering::Acquire);
        if let Some(hit) = self.lookup(watermarks, key, freshness, generation) {
            return Ok(Some(hit));
        }
        let stamp = watermarks.stamp(self.tables);
        let value = load().await?;
        if let Some(value) = &value {
            self.store(key, stamp, generation, value);
        }
        Ok(value)
    }

    fn store(&self, key: &str, stamp: Option<u64>, generation: u64, value: &V) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        // An invalidation since the load started: the value may predate it.
        if self.shard(key).load(Ordering::Acquire) != generation {
            return;
        }
        if entries.len() >= self.capacity && !entries.contains_key(key) {
            let victim = entries.keys().next().cloned();
            if let Some(victim) = victim {
                entries.remove(&victim);
            }
        }
        entries.insert(
            key.to_string(),
            Entry {
                stamp,
                generation,
                loaded_at: Instant::now(),
                value: value.clone(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    const TABLES: &[&str] = &["t"];
    const SEC: Duration = Duration::from_secs(1);

    fn watermarks(interval_ms: u64, version: i64) -> TableWatermarks {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(interval_ms));
        wm.publish(HashMap::from([("t".to_string(), version)]));
        wm
    }

    async fn load(
        cache: &ProjectionCache<u32>,
        wm: &TableWatermarks,
        f: Freshness,
        calls: &AtomicUsize,
    ) -> u32 {
        cache
            .get_or_load::<(), _, _>(wm, "k", f, || async {
                Ok(u32::try_from(calls.fetch_add(1, Ordering::SeqCst)).unwrap_or(u32::MAX) + 1)
            })
            .await
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn invalidating_a_key_keeps_the_others() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        for key in ["a", "b"] {
            let _ = cache
                .get_or_load::<(), _, _>(&wm, key, relaxed, || async { Ok(1u32) })
                .await;
        }
        cache.invalidate_key("a");
        assert_eq!(cache.len(), 1);
        let hit = cache
            .get_or_load::<(), _, _>(&wm, "b", relaxed, || async { Ok(2u32) })
            .await;
        assert_eq!(hit, Ok(1));
    }

    #[tokio::test]
    async fn full_cache_evicts_one_entry() {
        let cache = ProjectionCache::new(TABLES, 2);
        let wm = watermarks(1000, 1);
        for key in ["a", "b", "c"] {
            let _ = cache
                .get_or_load::<(), _, _>(&wm, key, Freshness::Any, || async { Ok(1u32) })
                .await;
        }
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test]
    async fn linearizable_always_reads_through() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 1);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 2);
        // the linearizable reads refreshed the cache for the relaxed ones
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn relaxed_reads_hit_while_the_watermark_is_unchanged() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // a foreign write moves the counter
        wm.publish(HashMap::from([("t".to_string(), 2)]));
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
    }

    #[tokio::test]
    async fn tolerance_below_the_poll_interval_is_a_forced_read() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(5000, 1);
        let calls = AtomicUsize::new(0);
        let tight = Freshness::MaxStaleness(Duration::from_millis(100));
        assert_eq!(load(&cache, &wm, tight, &calls).await, 1);
        assert_eq!(load(&cache, &wm, tight, &calls).await, 2);
        assert_eq!(load(&cache, &wm, tight, &calls).await, 3);
    }

    #[tokio::test]
    async fn tolerance_at_the_poll_interval_may_hit() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(SEC);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
    }

    #[tokio::test]
    async fn an_old_snapshot_is_a_forced_read() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(10, 1);
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(Duration::from_millis(20));
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        // the poller stalls: the counters get older than the tolerance
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(load(&cache, &wm, at, &calls).await, 2);
    }

    #[tokio::test]
    async fn local_invalidation_is_immediate() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        cache.invalidate();
        assert!(cache.is_empty());
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
    }

    #[tokio::test]
    async fn a_load_racing_an_invalidation_is_not_stored() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let value = cache
            .get_or_load::<(), _, _>(&wm, "k", relaxed, || async {
                cache.invalidate();
                Ok(7u32)
            })
            .await;
        assert_eq!(value, Ok(7));
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn without_a_poller_the_age_decides() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = TableWatermarks::new();
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(Duration::from_millis(30));
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(load(&cache, &wm, at, &calls).await, 2);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 3);
    }

    #[tokio::test]
    async fn an_unhealthy_poller_is_a_forced_read() {
        let cache = ProjectionCache::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        wm.reset();
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 3);
    }

    #[tokio::test]
    async fn a_missing_value_is_not_stored() {
        let cache = ProjectionCache::<u32>::new(TABLES, 8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        for _ in 0..2 {
            let value = cache
                .get_or_load_some::<(), _, _>(&wm, "k", relaxed, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                })
                .await;
            assert_eq!(value, Ok(None));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(cache.is_empty());
        let value = cache
            .get_or_load_some::<(), _, _>(&wm, "k", relaxed, || async { Ok(Some(3)) })
            .await;
        assert_eq!(value, Ok(Some(3)));
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn the_cache_is_bounded() {
        let cache = ProjectionCache::<u32>::new(TABLES, 2);
        let wm = watermarks(1000, 1);
        for key in ["a", "b", "c"] {
            let _ = cache
                .get_or_load::<(), _, _>(&wm, key, Freshness::Any, || async { Ok(1) })
                .await;
        }
        assert!(cache.len() <= 2);
    }
}
