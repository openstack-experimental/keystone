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
//! # `dpop_required` of an issuer, as seen by a verifier (ADR 0043 §4)
//!
//! A resource server rejects the unbound access tokens of an issuer whose
//! discovery document says `dpop_required: true`. Without this a token issued
//! before the switch would still be accepted as `Bearer` until its `exp`.
//!
//! The flag is cached per issuer for [`DPOP_REQUIRED_TTL`], no longer than the
//! `Cache-Control` of the discovery document. The lookup fails closed: once
//! the cached value is older than the TTL and the document cannot be
//! fetched, the answer is an error and the caller rejects the request, so
//! interfering with the fetch cannot downgrade enforcement. An expired value
//! is never served.
//!
//! Like [`crate::oauth2_client::verify`] this module does no I/O itself: the
//! caller passes the fetch of the discovery document. The answer feeds the
//! `require_bound` argument of
//! [`enforce_token_binding`](crate::oauth2_client::enforce_token_binding).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;
use thiserror::Error;

/// How long a fetched `dpop_required` is trusted.
pub const DPOP_REQUIRED_TTL: Duration = Duration::from_secs(60);

/// Most issuers kept; when it is reached the expired values are dropped, and
/// the cache is cleared if that does not make room.
const MAX_ISSUERS: usize = 1024;

/// The flag could not be determined.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpopRequiredError {
    /// The discovery document could not be fetched or understood, and no
    /// fresh cached value exists.
    #[error("the discovery document of `{issuer}` is unavailable: {reason}")]
    Unavailable {
        /// Issuer the lookup was for.
        issuer: String,
        /// Why the fetch failed.
        reason: String,
    },
}

/// Read `dpop_required` from an OIDC discovery document. An issuer that does
/// not publish the field does not require DPoP; a field that is not a
/// boolean is an error, so a malformed document cannot turn enforcement off.
pub fn dpop_required_from_discovery(document: &Value) -> Result<bool, String> {
    match document.get("dpop_required") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(required)) => Ok(*required),
        Some(_) => Err("`dpop_required` is not a boolean".to_string()),
    }
}

/// Per-issuer cache of `dpop_required`.
#[derive(Debug)]
pub struct DpopRequiredCache {
    ttl: Duration,
    entries: Mutex<HashMap<String, (bool, Instant)>>,
}

impl Default for DpopRequiredCache {
    fn default() -> Self {
        Self::new(DPOP_REQUIRED_TTL)
    }
}

impl DpopRequiredCache {
    /// A cache trusting a value for `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `issuer` requires DPoP. `fetch` returns the discovery document
    /// and is called only when no value younger than the TTL is cached.
    ///
    /// # Errors
    /// [`DpopRequiredError::Unavailable`] when `fetch` fails or the document
    /// is malformed and the cached value (if any) is expired.
    pub async fn is_required<F, Fut, E>(
        &self,
        issuer: &str,
        fetch: F,
    ) -> Result<bool, DpopRequiredError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Value, E>>,
        E: std::fmt::Display,
    {
        if let Some(required) = self.fresh(issuer) {
            return Ok(required);
        }
        let unavailable = |reason: String| DpopRequiredError::Unavailable {
            issuer: issuer.to_string(),
            reason,
        };
        let document = fetch().await.map_err(|e| unavailable(e.to_string()))?;
        let required = dpop_required_from_discovery(&document).map_err(unavailable)?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= MAX_ISSUERS {
            // Expired values go first: they are never served anyway. Only a
            // cache that is still full of live values is emptied.
            entries.retain(|_, (_, fetched)| fetched.elapsed() < self.ttl);
            if entries.len() >= MAX_ISSUERS {
                entries.clear();
            }
        }
        entries.insert(issuer.to_string(), (required, Instant::now()));
        Ok(required)
    }

    fn fresh(&self, issuer: &str) -> Option<bool> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(issuer)
            .filter(|(_, fetched)| fetched.elapsed() < self.ttl)
            .map(|(required, _)| *required)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://ks.example/v4/oauth2/d1";

    async fn lookup(
        cache: &DpopRequiredCache,
        calls: &AtomicUsize,
        document: Result<Value, &'static str>,
    ) -> Result<bool, DpopRequiredError> {
        cache
            .is_required(ISSUER, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                document
            })
            .await
    }

    #[test]
    fn test_flag_from_discovery() {
        assert_eq!(
            dpop_required_from_discovery(&json!({"dpop_required": true})),
            Ok(true)
        );
        assert_eq!(
            dpop_required_from_discovery(&json!({"dpop_required": false})),
            Ok(false)
        );
        // An issuer that does not know the field does not require DPoP.
        assert_eq!(dpop_required_from_discovery(&json!({})), Ok(false));
        assert!(dpop_required_from_discovery(&json!({"dpop_required": "true"})).is_err());
        assert!(dpop_required_from_discovery(&json!({"dpop_required": 1})).is_err());
    }

    #[tokio::test]
    async fn test_value_is_cached_within_the_ttl() {
        let cache = DpopRequiredCache::default();
        let calls = AtomicUsize::new(0);
        let doc = json!({"dpop_required": true});
        assert_eq!(lookup(&cache, &calls, Ok(doc.clone())).await, Ok(true));
        // A second lookup, even with a failing fetch, is answered from cache.
        assert_eq!(lookup(&cache, &calls, Err("down")).await, Ok(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_an_expired_value_is_refetched_and_picks_up_a_change() {
        let cache = DpopRequiredCache::new(Duration::ZERO);
        let calls = AtomicUsize::new(0);
        assert_eq!(
            lookup(&cache, &calls, Ok(json!({"dpop_required": false}))).await,
            Ok(false)
        );
        assert_eq!(
            lookup(&cache, &calls, Ok(json!({"dpop_required": true}))).await,
            Ok(true)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_fetch_failure_after_expiry_fails_closed() {
        let cache = DpopRequiredCache::new(Duration::ZERO);
        let calls = AtomicUsize::new(0);
        assert_eq!(
            lookup(&cache, &calls, Ok(json!({"dpop_required": true}))).await,
            Ok(true)
        );
        // The value is stale and the fetch is blocked: no answer at all, the
        // stale `true` is not served and `false` is not assumed.
        assert!(matches!(
            lookup(&cache, &calls, Err("blocked")).await,
            Err(DpopRequiredError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn test_without_a_cached_value_a_failure_is_an_error() {
        let cache = DpopRequiredCache::default();
        let calls = AtomicUsize::new(0);
        let err = lookup(&cache, &calls, Err("connection refused"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DpopRequiredError::Unavailable {
                issuer: ISSUER.to_string(),
                reason: "connection refused".to_string()
            }
        );
        // A failure is not cached: the next lookup tries again.
        assert_eq!(
            lookup(&cache, &calls, Ok(json!({"dpop_required": false}))).await,
            Ok(false)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_malformed_document_is_an_error() {
        let cache = DpopRequiredCache::default();
        let calls = AtomicUsize::new(0);
        assert!(matches!(
            lookup(&cache, &calls, Ok(json!({"dpop_required": "no"}))).await,
            Err(DpopRequiredError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn test_a_full_cache_drops_expired_values_before_live_ones() {
        let cache = DpopRequiredCache::new(Duration::from_secs(3600));
        {
            let mut entries = cache.entries.lock().unwrap();
            let long_ago = Instant::now() - Duration::from_secs(7200);
            for i in 0..MAX_ISSUERS {
                let fetched = if i == 0 { Instant::now() } else { long_ago };
                entries.insert(format!("https://issuer-{i}"), (true, fetched));
            }
        }
        let fresh = cache
            .is_required("https://new", || async {
                Ok::<_, String>(json!({"dpop_required": false}))
            })
            .await;
        assert_eq!(fresh, Ok(false));
        let entries = cache.entries.lock().unwrap();
        // The one live value survived next to the new one.
        assert_eq!(entries.len(), 2);
        assert!(entries.contains_key("https://issuer-0"));
    }

    #[tokio::test]
    async fn test_issuers_are_cached_independently() {
        let cache = DpopRequiredCache::default();
        let required = cache
            .is_required("https://a", || async {
                Ok::<_, String>(json!({"dpop_required": true}))
            })
            .await;
        let optional = cache
            .is_required("https://b", || async {
                Ok::<_, String>(json!({"dpop_required": false}))
            })
            .await;
        assert_eq!((required, optional), (Ok(true), Ok(false)));
    }
}
