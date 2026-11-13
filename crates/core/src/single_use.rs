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
//! # Single-use credential registry (ADR 0044)
//!
//! [`SingleUseStore`] records that a `(scope, id)` pair was used, so that an
//! external assertion, a TOTP passcode or a DPoP proof is accepted at most once
//! inside its validity window. Callers own the meaning of scope, id and
//! lifetime; the store only enforces the shared preconditions
//! ([`check_preconditions`]).
use std::error::Error;

use async_trait::async_trait;
use thiserror::Error;

#[cfg(test)]
pub(crate) mod conformance;

/// Longest accepted `id`, in bytes. A caller may apply a lower cap first.
pub const MAX_ID_LEN: usize = 256;

/// Why a credential was not recorded.
#[derive(Debug, Error)]
pub enum SingleUseError {
    /// Already recorded and not yet expired.
    #[error("credential was already used")]
    Replayed,

    /// Local store bounds, or the cluster store's admission limit, reached.
    #[error("single-use store capacity reached")]
    Capacity,

    /// `expires` is in the past or beyond the use case's maximum lifetime, or
    /// `id` is longer than [`MAX_ID_LEN`]; the caller computed it wrongly.
    #[error("invalid credential lifetime or identifier")]
    InvalidLifetime,

    /// The cluster store cannot be reached, did not answer, or rejected the
    /// write for a reason other than a conflict.
    #[error("single-use store unavailable: {0}")]
    Unavailable(#[source] Box<dyn Error + Send + Sync>),
}

/// Records that a `(scope, id)` pair was used.
#[async_trait]
pub trait SingleUseStore: Send + Sync {
    /// Record `(scope, id)`. `expires` is the first unix second at which the
    /// entry is dead; it must not be earlier than the last moment the same
    /// credential could still pass verification.
    ///
    /// # Errors
    /// [`SingleUseError::Replayed`] for a live entry, [`SingleUseError::Capacity`]
    /// when a bound is reached (a live entry is never evicted),
    /// [`SingleUseError::InvalidLifetime`] for failed preconditions and
    /// [`SingleUseError::Unavailable`] for a backend failure.
    async fn consume(
        &self,
        scope: &str,
        id: &str,
        expires: i64,
        now: i64,
    ) -> Result<(), SingleUseError>;

    /// Periodic maintenance: drop entries that are dead at `now`.
    async fn cleanup(&self, now: i64) -> Result<(), SingleUseError>;
}

/// Encode the scope of an external assertion: `"{len(domain_id)}:{domain_id}{issuer}"`.
///
/// Lengths count bytes, so `("a", "b")` and `("ab", "")` stay apart.
pub fn assertion_scope(domain_id: &str, issuer: &str) -> String {
    format!("{}:{domain_id}{issuer}", domain_id.len())
}

/// Domain part of a scope built by [`assertion_scope`], if well-formed.
pub fn assertion_scope_domain(scope: &str) -> Option<&str> {
    let (len, rest) = scope.split_once(':')?;
    let len: usize = len.parse().ok()?;
    rest.get(..len)
}

/// Preconditions every implementation enforces before touching its store.
///
/// - `expires > now`;
/// - `expires - now <= max_lifetime_secs`;
/// - `id` is at most [`MAX_ID_LEN`] bytes.
///
/// # Errors
/// [`SingleUseError::InvalidLifetime`] when any of them fails.
pub fn check_preconditions(
    id: &str,
    expires: i64,
    now: i64,
    max_lifetime_secs: i64,
) -> Result<(), SingleUseError> {
    if expires <= now || expires.saturating_sub(now) > max_lifetime_secs || id.len() > MAX_ID_LEN {
        return Err(SingleUseError::InvalidLifetime);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal reference implementation: proves the suite itself is sound.
    mod reference {
        use std::collections::HashMap;
        use std::sync::Mutex;

        use async_trait::async_trait;

        use super::super::conformance::{MAX_LIFETIME_SECS, run_suite};
        use super::super::*;

        struct Reference {
            max_total: usize,
            max_per_scope: usize,
            entries: Mutex<HashMap<(String, String), i64>>,
        }

        #[async_trait]
        impl SingleUseStore for Reference {
            async fn consume(
                &self,
                scope: &str,
                id: &str,
                expires: i64,
                now: i64,
            ) -> Result<(), SingleUseError> {
                check_preconditions(id, expires, now, MAX_LIFETIME_SECS)?;
                let mut m = self.entries.lock().unwrap();
                m.retain(|_, e| *e > now);
                let key = (scope.to_string(), id.to_string());
                if m.contains_key(&key) {
                    return Err(SingleUseError::Replayed);
                }
                if m.len() >= self.max_total
                    || m.keys().filter(|(s, _)| s == scope).count() >= self.max_per_scope
                {
                    return Err(SingleUseError::Capacity);
                }
                m.insert(key, expires);
                Ok(())
            }

            async fn cleanup(&self, now: i64) -> Result<(), SingleUseError> {
                self.entries.lock().unwrap().retain(|_, e| *e > now);
                Ok(())
            }
        }

        #[tokio::test]
        async fn suite_passes_for_reference_store() {
            run_suite(|max_total, max_per_scope| Reference {
                max_total,
                max_per_scope,
                entries: Mutex::new(HashMap::new()),
            })
            .await;
        }
    }

    #[test]
    fn scope_encoding() {
        assert_ne!(assertion_scope("a", "b"), assertion_scope("ab", ""));
        let s = assertion_scope("dom", "https://idp");
        assert_eq!(assertion_scope_domain(&s), Some("dom"));
        assert_eq!(assertion_scope_domain("x:abc"), None);
        assert_eq!(assertion_scope_domain("nolen"), None);
    }

    #[test]
    fn preconditions() {
        assert!(check_preconditions("a", 110, 100, 10).is_ok());
        assert!(matches!(
            check_preconditions("a", 100, 100, 10),
            Err(SingleUseError::InvalidLifetime)
        ));
        assert!(matches!(
            check_preconditions("a", 111, 100, 10),
            Err(SingleUseError::InvalidLifetime)
        ));
        assert!(matches!(
            check_preconditions(&"x".repeat(MAX_ID_LEN + 1), 105, 100, 10),
            Err(SingleUseError::InvalidLifetime)
        ));
        assert!(check_preconditions(&"x".repeat(MAX_ID_LEN), 105, 100, 10).is_ok());
    }
}
