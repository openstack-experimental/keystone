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
//! # Process-wide role cache
//!
//! Every token validation resolves the assigned roles: the names of the
//! roles and the role inference rules. Both are tiny and change rarely, but
//! without a process-wide cache they cost a database round trip per request.
//! [`RoleCache`] keeps them in memory for a bounded time (`[role]
//! cache_time`, when `[role] caching` is enabled).
//!
//! Local mutations call [`RoleCache::invalidate`], so changes made through
//! this process are visible immediately. Changes made elsewhere (other
//! replicas, `keystone-manage`) become visible once the TTL expires, which
//! is therefore also the upper bound of staleness.
//!
//! Invalidation is race-free without holding a lock across the load: every
//! invalidation bumps a generation counter, and a value loaded before the
//! bump is not stored.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use openstack_keystone_core_types::role::{Role, RoleImply};

use crate::request_cache::CACHE_METRICS;

/// Upper bound of the entries of a single map. A map that reached it stops
/// admitting new entries until it is invalidated or entries expire.
const MAX_ENTRIES: usize = 10_000;

/// Key of the complete imply rule table.
const ALL: &str = "all";

/// Map of values that expire after a TTL.
struct TtlMap<V> {
    namespace: &'static str,
    ttl: Duration,
    generation: AtomicU64,
    entries: DashMap<String, (Instant, V)>,
}

impl<V: Clone> TtlMap<V> {
    fn new(namespace: &'static str, ttl: Duration) -> Self {
        Self {
            namespace,
            ttl,
            generation: AtomicU64::new(0),
            entries: DashMap::new(),
        }
    }

    /// The generation to hand to [`Self::insert`]; take it before loading.
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn get(&self, key: &str) -> Option<V> {
        if self.ttl.is_zero() {
            return None;
        }
        let value = match self.entries.get(key) {
            Some(entry) if entry.0.elapsed() < self.ttl => Some(entry.1.clone()),
            Some(_) => {
                // Release the read guard before removing.
                None
            }
            None => None,
        };
        if value.is_none() {
            self.entries
                .remove_if(key, |_, (loaded_at, _)| loaded_at.elapsed() >= self.ttl);
        }
        CACHE_METRICS.record(self.namespace, value.is_some());
        value
    }

    /// Store a value loaded while the map was at `generation`; it is dropped
    /// when the map was invalidated since.
    fn insert(&self, key: &str, value: V, generation: u64) {
        if self.ttl.is_zero() || self.generation() != generation {
            return;
        }
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(key) {
            return;
        }
        self.entries
            .insert(key.to_string(), (Instant::now(), value));
        // An invalidation that ran between the check and the insert has
        // already cleared the map: take the stale value out again.
        if self.generation() != generation {
            self.entries.remove(key);
        }
    }

    fn invalidate(&self) {
        if self.ttl.is_zero() {
            return;
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.entries.clear();
    }
}

/// A generation-tagged read of one of the cache maps, see
/// [`RoleCache::role`].
pub struct Loaded {
    generation: u64,
}

/// TTL cache of roles and role imply rules.
pub struct RoleCache {
    roles: TtlMap<Role>,
    names: TtlMap<Role>,
    imply_by_prior: TtlMap<Vec<RoleImply>>,
    imply_all: TtlMap<Vec<RoleImply>>,
}

impl RoleCache {
    /// Create a cache whose entries live for `ttl`; zero disables caching.
    pub fn new(ttl: Duration) -> Self {
        Self {
            roles: TtlMap::new("role.process.role", ttl),
            names: TtlMap::new("role.process.name", ttl),
            imply_by_prior: TtlMap::new("role.process.imply_by_prior", ttl),
            imply_all: TtlMap::new("role.process.imply_all", ttl),
        }
    }

    /// The cached role (with its options).
    pub fn get_role(&self, id: &str) -> Option<Role> {
        self.roles.get(id)
    }

    /// Take the generation before loading a role.
    pub fn begin_role(&self) -> Loaded {
        Loaded {
            generation: self.roles.generation(),
        }
    }

    /// Store a role loaded after [`Self::begin_role`].
    pub fn put_role(&self, role: &Role, loaded: &Loaded) {
        self.roles.insert(&role.id, role.clone(), loaded.generation);
    }

    /// The cached role without options, as used for the name resolution.
    pub fn get_name(&self, id: &str) -> Option<Role> {
        self.names.get(id)
    }

    /// Take the generation before loading role names.
    pub fn begin_name(&self) -> Loaded {
        Loaded {
            generation: self.names.generation(),
        }
    }

    /// Store a role loaded after [`Self::begin_name`].
    pub fn put_name(&self, role: &Role, loaded: &Loaded) {
        self.names.insert(&role.id, role.clone(), loaded.generation);
    }

    /// The cached direct imply rules of a prior role.
    pub fn get_imply_by_prior(&self, prior_role_id: &str) -> Option<Vec<RoleImply>> {
        self.imply_by_prior.get(prior_role_id)
    }

    /// Take the generation before loading imply rules by prior role.
    pub fn begin_imply_by_prior(&self) -> Loaded {
        Loaded {
            generation: self.imply_by_prior.generation(),
        }
    }

    /// Store the rules of a prior role loaded after
    /// [`Self::begin_imply_by_prior`].
    pub fn put_imply_by_prior(&self, prior_role_id: &str, rules: Vec<RoleImply>, loaded: &Loaded) {
        self.imply_by_prior
            .insert(prior_role_id, rules, loaded.generation);
    }

    /// The cached complete imply rule table.
    pub fn get_imply_all(&self) -> Option<Vec<RoleImply>> {
        self.imply_all.get(ALL)
    }

    /// Take the generation before loading the complete rule table.
    pub fn begin_imply_all(&self) -> Loaded {
        Loaded {
            generation: self.imply_all.generation(),
        }
    }

    /// Store the complete rule table loaded after [`Self::begin_imply_all`].
    pub fn put_imply_all(&self, rules: Vec<RoleImply>, loaded: &Loaded) {
        self.imply_all.insert(ALL, rules, loaded.generation);
    }

    /// Drop everything cached.
    ///
    /// Call after a mutation of roles or imply rules has been committed.
    pub fn invalidate(&self) {
        self.roles.invalidate();
        self.names.invalidate();
        self.imply_by_prior.invalidate();
        self.imply_all.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::role::RoleBuilder;

    use super::*;

    fn role(id: &str) -> Role {
        RoleBuilder::default().id(id).name(id).build().unwrap()
    }

    #[test]
    fn test_hit_after_put() {
        let cache = RoleCache::new(Duration::from_secs(60));
        assert!(cache.get_role("a").is_none());
        let loaded = cache.begin_role();
        cache.put_role(&role("a"), &loaded);
        assert_eq!("a", cache.get_role("a").unwrap().id);
    }

    #[test]
    fn test_expires() {
        let cache = RoleCache::new(Duration::from_millis(20));
        let loaded = cache.begin_role();
        cache.put_role(&role("a"), &loaded);
        std::thread::sleep(Duration::from_millis(40));
        assert!(cache.get_role("a").is_none());
    }

    #[test]
    fn test_invalidate_clears() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let loaded = cache.begin_role();
        cache.put_role(&role("a"), &loaded);
        let loaded = cache.begin_imply_all();
        cache.put_imply_all(Vec::new(), &loaded);
        cache.invalidate();
        assert!(cache.get_role("a").is_none());
        assert!(cache.get_imply_all().is_none());
    }

    #[test]
    fn test_value_loaded_before_invalidation_is_dropped() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let loaded = cache.begin_role();
        // A write commits while the load is in flight.
        cache.invalidate();
        cache.put_role(&role("a"), &loaded);
        assert!(cache.get_role("a").is_none());
    }

    #[test]
    fn test_zero_ttl_disables_cache() {
        let cache = RoleCache::new(Duration::ZERO);
        let loaded = cache.begin_role();
        cache.put_role(&role("a"), &loaded);
        assert!(cache.get_role("a").is_none());
    }

    #[test]
    fn test_empty_rule_list_is_cached() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let loaded = cache.begin_imply_by_prior();
        cache.put_imply_by_prior("a", Vec::new(), &loaded);
        assert_eq!(Some(Vec::new()), cache.get_imply_by_prior("a"));
    }
}
