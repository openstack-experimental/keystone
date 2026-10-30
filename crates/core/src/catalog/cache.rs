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
//! # Process-wide catalog cache
//!
//! The assembled service catalog is embedded into every token response, is
//! small and changes rarely. [`CatalogCache`] keeps the result of
//! `get_catalog` in memory for a bounded time (`[catalog] cache_time`, when `[catalog] caching` is enabled).
//!
//! Local mutations call [`CatalogCache::invalidate`], so changes made through
//! this process are visible immediately. Changes made elsewhere (other
//! replicas, `keystone-manage`) become visible once the TTL expires, which
//! is therefore also the upper bound of staleness.
//!
//! Each slot is guarded by an async mutex that is held while the value is
//! loaded. That coalesces concurrent misses into a single backend call and
//! makes invalidation race-free: an invalidation issued after a write has
//! committed waits for any load started before the commit and then clears
//! its (possibly stale) result.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use openstack_keystone_core_types::catalog::{Endpoint, Service};

use crate::catalog::CatalogProviderError;
use crate::request_cache::CACHE_METRICS;

/// Metric namespace of the catalog cache.
const NAMESPACE: &str = "catalog";

/// Catalog content as returned by `get_catalog`.
pub type CatalogEntries = Vec<(Service, Vec<Endpoint>)>;

struct Slot {
    value: Option<(Instant, Arc<CatalogEntries>)>,
}

/// TTL cache of the `get_catalog` result.
pub struct CatalogCache {
    /// Entry lifetime. [`Duration::ZERO`] disables the cache.
    ttl: Duration,
    /// Slot for `enabled = false` at index 0 and `enabled = true` at index 1.
    slots: [Mutex<Slot>; 2],
}

impl CatalogCache {
    /// Create a cache whose entries live for `ttl`; zero disables caching.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slots: [
                Mutex::new(Slot { value: None }),
                Mutex::new(Slot { value: None }),
            ],
        }
    }

    /// Return the cached catalog for `enabled` or load it with `load`.
    ///
    /// Load errors are returned as is and are not cached.
    pub async fn get_or_load<F, Fut>(
        &self,
        enabled: bool,
        load: F,
    ) -> Result<Arc<CatalogEntries>, CatalogProviderError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CatalogEntries, CatalogProviderError>>,
    {
        if self.ttl.is_zero() {
            return Ok(Arc::new(load().await?));
        }
        let mut slot = self.slots[usize::from(enabled)].lock().await;
        if let Some((loaded_at, value)) = &slot.value
            && loaded_at.elapsed() < self.ttl
        {
            CACHE_METRICS.record(NAMESPACE, true);
            return Ok(value.clone());
        }
        CACHE_METRICS.record(NAMESPACE, false);
        let value = Arc::new(load().await?);
        slot.value = Some((Instant::now(), value.clone()));
        Ok(value)
    }

    /// Drop all cached catalogs.
    ///
    /// Call after a mutation of services or endpoints has been committed.
    pub async fn invalidate(&self) {
        if self.ttl.is_zero() {
            return;
        }
        for slot in &self.slots {
            slot.lock().await.value = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    async fn load(counter: &AtomicUsize) -> Result<CatalogEntries, CatalogProviderError> {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    #[tokio::test]
    async fn test_hit_within_ttl() {
        let cache = CatalogCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_enabled_flag_is_part_of_the_key() {
        let cache = CatalogCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        cache.get_or_load(false, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_reload_after_ttl() {
        let cache = CatalogCache::new(Duration::from_millis(20));
        let calls = AtomicUsize::new(0);
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_invalidate_forces_reload() {
        let cache = CatalogCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        cache.get_or_load(false, || load(&calls)).await.unwrap();
        cache.invalidate().await;
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        cache.get_or_load(false, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_zero_ttl_disables_cache() {
        let cache = CatalogCache::new(Duration::ZERO);
        let calls = AtomicUsize::new(0);
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_errors_are_not_cached() {
        let cache = CatalogCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        let failed = cache
            .get_or_load(true, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(CatalogProviderError::Driver("boom".into()))
            })
            .await;
        assert!(failed.is_err());
        cache.get_or_load(true, || load(&calls)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_concurrent_misses_are_coalesced() {
        let cache = Arc::new(CatalogCache::new(Duration::from_secs(60)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (cache, calls) = (cache.clone(), calls.clone());
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_load(true, || async {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        load(&calls).await
                    })
                    .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
