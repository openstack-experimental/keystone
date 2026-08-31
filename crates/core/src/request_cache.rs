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
use std::sync::LazyLock;

use openstack_keystone_metrics::{LabeledCounter, PrometheusText, write_metric_header};

/// Per-request-cache Prometheus counters (ADR 0031).
///
/// `cache` is the fixed, code-defined set of `tokio::task_local!` caches
/// ADR 0030 introduces (e.g. `role_assignments`, `catalog_endpoints`) — the
/// `&'static str` namespace passed to [`cache_get`]/[`cache_set`], never
/// per-request data. These counters are process-wide, aggregating hit/miss
/// events across every request's short-lived [`RequestCache`], which is
/// intentional: the cache itself stays request-scoped, only the counters
/// summarizing its effectiveness are global.
pub struct CacheMetrics {
    /// `keystone_cache_hits_total{cache}`.
    pub hits_total: LabeledCounter<1>,
    /// `keystone_cache_misses_total{cache}`.
    pub misses_total: LabeledCounter<1>,
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self {
            hits_total: LabeledCounter::new(["cache"]),
            misses_total: LabeledCounter::new(["cache"]),
        }
    }
}

impl PrometheusText for CacheMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_cache_hits_total",
            "Per-request cache hits by cache namespace.",
            "counter",
        );
        self.hits_total
            .write_lines(&mut out, "keystone_cache_hits_total");

        write_metric_header(
            &mut out,
            "keystone_cache_misses_total",
            "Per-request cache misses by cache namespace.",
            "counter",
        );
        self.misses_total
            .write_lines(&mut out, "keystone_cache_misses_total");
        out
    }
}

/// Process-wide per-request cache hit/miss metrics.
pub static CACHE_METRICS: LazyLock<CacheMetrics> = LazyLock::new(CacheMetrics::default);

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
/// established request scope. Either case increments
/// `keystone_cache_misses_total{cache=namespace}`; a found entry increments
/// `keystone_cache_hits_total{cache=namespace}` instead (ADR 0031).
pub fn cache_get<T: Clone + 'static>(namespace: &'static str, id: &str) -> Option<T> {
    let result = REQUEST_CACHE
        .try_with(|cache| cache.get(namespace, id))
        .ok()
        .flatten();
    if result.is_some() {
        CACHE_METRICS.hits_total.inc([namespace]);
    } else {
        CACHE_METRICS.misses_total.inc([namespace]);
    }
    result
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

    // -------------------------------------------------------------------
    // Cache hit/miss metrics (ADR 0031). `CACHE_METRICS` is a process-wide
    // static shared across every test in this binary, so each test below
    // uses its own unique namespace to keep assertions independent of
    // execution order/parallelism.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_get_miss_increments_miss_counter() {
        let before = CACHE_METRICS.misses_total.get(["metrics_ns_miss"]);
        RequestCache::scope(async {
            assert_eq!(cache_get::<String>("metrics_ns_miss", "k"), None);
        })
        .await;
        assert_eq!(
            CACHE_METRICS.misses_total.get(["metrics_ns_miss"]),
            before + 1
        );
        assert_eq!(CACHE_METRICS.hits_total.get(["metrics_ns_miss"]), 0);
    }

    #[tokio::test]
    async fn test_cache_get_hit_increments_hit_counter() {
        let before = CACHE_METRICS.hits_total.get(["metrics_ns_hit"]);
        RequestCache::scope(async {
            cache_set("metrics_ns_hit", "k", "value".to_string());
            assert_eq!(
                cache_get::<String>("metrics_ns_hit", "k"),
                Some("value".to_string())
            );
        })
        .await;
        assert_eq!(CACHE_METRICS.hits_total.get(["metrics_ns_hit"]), before + 1);
    }

    #[tokio::test]
    async fn test_cache_get_outside_scope_counts_as_miss() {
        let before = CACHE_METRICS.misses_total.get(["metrics_ns_outside"]);
        assert_eq!(cache_get::<String>("metrics_ns_outside", "k"), None);
        assert_eq!(
            CACHE_METRICS.misses_total.get(["metrics_ns_outside"]),
            before + 1
        );
    }

    #[tokio::test]
    async fn test_cache_metrics_isolated_per_namespace() {
        RequestCache::scope(async {
            cache_set("metrics_ns_a", "k", 1u64);
            let _ = cache_get::<u64>("metrics_ns_a", "k");
            let _ = cache_get::<u64>("metrics_ns_b", "k");
        })
        .await;
        assert!(CACHE_METRICS.hits_total.get(["metrics_ns_a"]) >= 1);
        assert!(CACHE_METRICS.misses_total.get(["metrics_ns_b"]) >= 1);
        assert_eq!(CACHE_METRICS.hits_total.get(["metrics_ns_b"]), 0);
    }

    #[test]
    fn test_cache_metrics_prometheus_text_contains_headers() {
        CACHE_METRICS.hits_total.inc(["metrics_ns_text"]);
        CACHE_METRICS.misses_total.inc(["metrics_ns_text"]);
        let text = CACHE_METRICS.format_prometheus_text();
        assert!(text.contains("# HELP keystone_cache_hits_total"));
        assert!(text.contains("# TYPE keystone_cache_hits_total counter"));
        assert!(text.contains("# HELP keystone_cache_misses_total"));
        assert!(text.contains("# TYPE keystone_cache_misses_total counter"));
        assert!(text.contains("keystone_cache_hits_total{cache=\"metrics_ns_text\"}"));
        assert!(text.contains("keystone_cache_misses_total{cache=\"metrics_ns_text\"}"));
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
