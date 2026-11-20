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
//! Time since this node last heard from a Raft leader.
//!
//! A follower or learner serving [`ReadConsistency::Local`] reads has no
//! other way to bound how stale its state machine may be: an idle cluster
//! applies no entries, so the applied index says nothing about age. Every
//! `AppendEntries` (a heartbeat when empty) from a leader proves the node's
//! log, and therefore its state machine once applied, was current at that
//! moment (ADR 0045 §2, `max_staleness`).
//!
//! [`ReadConsistency::Local`]: openstack_keystone_storage_api::ReadConsistency::Local

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Marker for "no leader contact yet". Contacts are stored as `ms + 1` so
/// that `fetch_max` keeps the newest one.
const NEVER: u64 = 0;

/// Records the instant of the last leader contact.
#[derive(Debug)]
pub struct LeaderContact {
    epoch: Instant,
    /// One plus the milliseconds since `epoch` of the last contact, or
    /// [`NEVER`].
    last_ms: AtomicU64,
}

impl Default for LeaderContact {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            last_ms: AtomicU64::new(NEVER),
        }
    }
}

impl LeaderContact {
    /// Record contact with a leader now.
    pub fn touch(&self) {
        let ms = u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        // `fetch_max`: a slower concurrent caller must not move the time back.
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// Time since the last leader contact, `None` if there was none.
    pub fn age(&self) -> Option<Duration> {
        match self.last_ms.load(Ordering::Relaxed) {
            NEVER => None,
            ms => Some(
                self.epoch
                    .elapsed()
                    .saturating_sub(Duration::from_millis(ms - 1)),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_contact_has_no_age() {
        assert_eq!(LeaderContact::default().age(), None);
    }

    #[test]
    fn age_grows_after_touch() {
        let c = LeaderContact::default();
        c.touch();
        let first = c.age().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(c.age().unwrap() >= first + Duration::from_millis(10));
        c.touch();
        assert!(c.age().unwrap() < Duration::from_millis(10));
    }

    #[test]
    fn older_touch_does_not_move_contact_back() {
        let c = LeaderContact::default();
        c.last_ms.store(10_000, Ordering::Relaxed);
        c.last_ms.fetch_max(5_000, Ordering::Relaxed);
        assert_eq!(c.last_ms.load(Ordering::Relaxed), 10_000);
    }
}
