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
// Crypto inventory: none (bookkeeping of identifiers only).
//! Behavioural suite every [`SingleUseStore`] implementation must pass
//! (ADR 0044, implementation notes step 4).
//!
//! An implementation calls [`run_suite`] from its own tests with a factory
//! that builds a fresh store with the given bounds and a maximum lifetime of
//! [`MAX_LIFETIME_SECS`].
use super::{SingleUseError, SingleUseStore};

/// Maximum `expires - now` the stores under test are built with.
pub const MAX_LIFETIME_SECS: i64 = 600;

const NOW: i64 = 1_760_000_000;

/// Run the whole suite. `make(max_total, max_per_scope)` builds a fresh store.
pub async fn run_suite<S: SingleUseStore>(make: impl Fn(usize, usize) -> S) {
    replay_until_expires(&make(10, 10)).await;
    scopes_are_separate(&make(10, 10)).await;
    invalid_lifetime(&make(10, 10)).await;
    id_length_cap(&make(10, 10)).await;
    per_scope_quota_without_eviction(&make(10, 2)).await;
    total_quota_without_eviction(&make(2, 2)).await;
    cleanup_keeps_live_entries(&make(10, 10)).await;
}

async fn replay_until_expires(s: &impl SingleUseStore) {
    s.consume("s", "a", NOW + 60, NOW).await.unwrap();
    assert!(matches!(
        s.consume("s", "a", NOW + 60, NOW + 59).await,
        Err(SingleUseError::Replayed)
    ));
    // Dead at `expires`: the same id is accepted again.
    s.consume("s", "a", NOW + 120, NOW + 60).await.unwrap();
}

async fn scopes_are_separate(s: &impl SingleUseStore) {
    s.consume("s1", "a", NOW + 60, NOW).await.unwrap();
    s.consume("s2", "a", NOW + 60, NOW).await.unwrap();
    assert!(matches!(
        s.consume("s1", "a", NOW + 60, NOW).await,
        Err(SingleUseError::Replayed)
    ));
}

async fn invalid_lifetime(s: &impl SingleUseStore) {
    for expires in [NOW - 1, NOW, NOW + MAX_LIFETIME_SECS + 1] {
        assert!(
            matches!(
                s.consume("s", "a", expires, NOW).await,
                Err(SingleUseError::InvalidLifetime)
            ),
            "expires = now + {}",
            expires - NOW
        );
    }
    // A refused credential is not recorded.
    s.consume("s", "a", NOW + MAX_LIFETIME_SECS, NOW)
        .await
        .unwrap();
}

async fn id_length_cap(s: &impl SingleUseStore) {
    let at_cap = "x".repeat(super::MAX_ID_LEN);
    s.consume("s", &at_cap, NOW + 60, NOW).await.unwrap();
    let over = "x".repeat(super::MAX_ID_LEN + 1);
    assert!(matches!(
        s.consume("s", &over, NOW + 60, NOW).await,
        Err(SingleUseError::InvalidLifetime)
    ));
}

/// Needs `max_per_scope == 2`.
async fn per_scope_quota_without_eviction(s: &impl SingleUseStore) {
    s.consume("s", "a", NOW + 60, NOW).await.unwrap();
    s.consume("s", "b", NOW + 60, NOW).await.unwrap();
    assert!(matches!(
        s.consume("s", "c", NOW + 60, NOW).await,
        Err(SingleUseError::Capacity)
    ));
    // The flood attempt did not push out a live entry.
    assert!(matches!(
        s.consume("s", "a", NOW + 60, NOW).await,
        Err(SingleUseError::Replayed)
    ));
    // Another scope is not affected.
    s.consume("other", "c", NOW + 60, NOW).await.unwrap();
    // Dead entries free room.
    s.consume("s", "c", NOW + 120, NOW + 60).await.unwrap();
}

/// Needs `max_total == 2`.
async fn total_quota_without_eviction(s: &impl SingleUseStore) {
    s.consume("x", "a", NOW + 60, NOW).await.unwrap();
    s.consume("y", "a", NOW + 60, NOW).await.unwrap();
    assert!(matches!(
        s.consume("z", "a", NOW + 60, NOW).await,
        Err(SingleUseError::Capacity)
    ));
    assert!(matches!(
        s.consume("x", "a", NOW + 60, NOW).await,
        Err(SingleUseError::Replayed)
    ));
}

async fn cleanup_keeps_live_entries(s: &impl SingleUseStore) {
    s.consume("s", "live", NOW + 120, NOW).await.unwrap();
    s.consume("s", "dead", NOW + 60, NOW).await.unwrap();
    s.cleanup(NOW + 60).await.unwrap();
    assert!(matches!(
        s.consume("s", "live", NOW + 120, NOW + 60).await,
        Err(SingleUseError::Replayed)
    ));
    s.consume("s", "dead", NOW + 180, NOW + 60).await.unwrap();
}
