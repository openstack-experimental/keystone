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
//! # Per-Request Cache
//!
//! Request-scoped cache backed by `tokio::task_local!` (see ADR 0030).
//! Callers establish the scope once per request (the Axum middleware in
//! `crates/keystone` does this); provider code anywhere on that task can
//! then read/write it via [`cache_get`]/[`cache_set`] without threading a
//! new parameter through provider trait signatures.
//!
//! Outside an established scope (unit tests calling provider methods
//! directly, CLI tooling, background jobs) [`cache_get`] always returns
//! `None` and [`cache_set`] is a silent no-op — the same defensive style
//! already used by the `EMIT_CRITICAL_RECURSION` task_local in
//! `crate::events`.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;

tokio::task_local! {
    /// Per-request cache. Established once per incoming request; absent
    /// outside a request scope.
    static REQUEST_CACHE: RequestCache;
}

type CacheKey = (&'static str, String);
type CacheEntries = RefCell<HashMap<CacheKey, Box<dyn Any + Send>>>;

/// Request-scoped cache of arbitrary, `Send` values keyed by
/// `(namespace, id)`.
///
/// Not `Sync` and does not need to be: it is only ever accessed from the
/// single task it is scoped to, never concurrently.
#[derive(Default)]
pub struct RequestCache {
    entries: CacheEntries,
}

impl RequestCache {
    /// Runs `fut` with a fresh, empty [`RequestCache`] established as the
    /// current task's request cache for its duration.
    pub async fn scope<F: Future>(fut: F) -> F::Output {
        REQUEST_CACHE.scope(RequestCache::default(), fut).await
    }

    fn get<T: Clone + 'static>(&self, namespace: &'static str, id: &str) -> Option<T> {
        self.entries
            .borrow()
            .get(&(namespace, id.to_string()))
            .and_then(|v| v.downcast_ref::<T>())
            .cloned()
    }

    fn set<T: Send + 'static>(&self, namespace: &'static str, id: &str, value: T) {
        self.entries
            .borrow_mut()
            .insert((namespace, id.to_string()), Box::new(value));
    }

    fn remove(&self, namespace: &'static str, id: &str) {
        self.entries
            .borrow_mut()
            .remove(&(namespace, id.to_string()));
    }
}

/// Reads `id` from the current request's cache under `namespace`.
///
/// Returns `None` both on a cache miss and when called outside an
/// established request scope.
pub fn cache_get<T: Clone + 'static>(namespace: &'static str, id: &str) -> Option<T> {
    REQUEST_CACHE
        .try_with(|cache| cache.get(namespace, id))
        .ok()
        .flatten()
}

/// Writes `value` into the current request's cache under `namespace`/`id`.
///
/// Silently does nothing when called outside an established request scope.
pub fn cache_set<T: Send + 'static>(namespace: &'static str, id: &str, value: T) {
    let _ = REQUEST_CACHE.try_with(|cache| cache.set(namespace, id, value));
}

/// Removes `id` from the current request's cache under `namespace`, if
/// present.
///
/// Call after a mutation (update/delete) so a later read in the same
/// request doesn't observe a stale cached value. Silently does nothing
/// when called outside an established request scope.
pub fn cache_remove(namespace: &'static str, id: &str) {
    let _ = REQUEST_CACHE.try_with(|cache| cache.remove(namespace, id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_set_within_scope() {
        RequestCache::scope(async {
            assert_eq!(cache_get::<String>("ns", "k"), None);
            cache_set("ns", "k", "value".to_string());
            assert_eq!(cache_get::<String>("ns", "k"), Some("value".to_string()));
        })
        .await;
    }

    #[tokio::test]
    async fn test_outside_scope_is_noop() {
        cache_set("ns", "k", "value".to_string());
        assert_eq!(cache_get::<String>("ns", "k"), None);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        RequestCache::scope(async {
            cache_set("ns_a", "k", 1u64);
            cache_set("ns_b", "k", 2u64);
            assert_eq!(cache_get::<u64>("ns_a", "k"), Some(1));
            assert_eq!(cache_get::<u64>("ns_b", "k"), Some(2));
        })
        .await;
    }

    #[tokio::test]
    async fn test_type_mismatch_is_miss() {
        RequestCache::scope(async {
            cache_set("ns", "k", 1u64);
            assert_eq!(cache_get::<String>("ns", "k"), None);
        })
        .await;
    }

    #[tokio::test]
    async fn test_remove_clears_entry() {
        RequestCache::scope(async {
            cache_set("ns", "k", "value".to_string());
            cache_remove("ns", "k");
            assert_eq!(cache_get::<String>("ns", "k"), None);
        })
        .await;
    }

    #[tokio::test]
    async fn test_remove_missing_key_is_noop() {
        RequestCache::scope(async {
            cache_remove("ns", "missing");
            assert_eq!(cache_get::<String>("ns", "missing"), None);
        })
        .await;
    }

    #[tokio::test]
    async fn test_remove_outside_scope_is_noop() {
        cache_remove("ns", "k");
    }

    #[tokio::test]
    async fn test_scope_does_not_leak_to_new_scope() {
        RequestCache::scope(async {
            cache_set("ns", "k", "value".to_string());
        })
        .await;

        RequestCache::scope(async {
            assert_eq!(cache_get::<String>("ns", "k"), None);
        })
        .await;
    }
}
