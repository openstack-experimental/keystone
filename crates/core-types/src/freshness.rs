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
//! # Read freshness
//!
//! How stale the data returned by a read may be. The caller states the
//! tolerance, the driver decides whether a cache (or a replica) can satisfy it
//! and otherwise reads through.

use std::time::Duration;

/// How stale the result of a read is allowed to be.
///
/// [`Freshness::Linearizable`] is the default: a read that does not state a
/// tolerance reflects every committed write.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Freshness {
    /// Must reflect every committed write (authentication, writes, admin).
    #[default]
    Linearizable,
    /// May be at most this far behind the latest committed write.
    MaxStaleness(Duration),
    /// The caller accepts whatever the driver has cached (non-sensitive,
    /// derived data).
    Any,
}

impl Freshness {
    /// The tolerance as a bounded duration. `None` for [`Freshness::Any`].
    #[must_use]
    pub fn bound(&self) -> Option<Duration> {
        match self {
            Self::Linearizable => Some(Duration::ZERO),
            Self::MaxStaleness(bound) => Some(*bound),
            Self::Any => None,
        }
    }

    /// Whether the read must go to the authoritative store.
    #[must_use]
    pub fn is_linearizable(&self) -> bool {
        matches!(self, Self::Linearizable)
            || matches!(self, Self::MaxStaleness(bound) if bound.is_zero())
    }

    /// The stricter of two tolerances.
    ///
    /// A request can only tighten what the endpoint policy allows.
    #[must_use]
    pub fn tighten(self, other: Self) -> Self {
        match (self.bound(), other.bound()) {
            (Some(a), Some(b)) if a <= b => self,
            (Some(_), Some(_)) => other,
            (Some(_), None) => self,
            (None, _) => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn default_is_linearizable() {
        assert_eq!(Freshness::default(), Freshness::Linearizable);
        assert!(Freshness::default().is_linearizable());
    }

    #[test]
    fn zero_staleness_is_linearizable() {
        assert!(Freshness::MaxStaleness(Duration::ZERO).is_linearizable());
        assert!(!Freshness::MaxStaleness(SEC).is_linearizable());
        assert!(!Freshness::Any.is_linearizable());
    }

    #[test]
    fn tighten_picks_the_stricter() {
        let a = Freshness::MaxStaleness(SEC);
        let b = Freshness::MaxStaleness(SEC * 5);
        assert_eq!(a.tighten(b), a);
        assert_eq!(b.tighten(a), a);
        assert_eq!(Freshness::Any.tighten(a), a);
        assert_eq!(a.tighten(Freshness::Any), a);
        assert_eq!(Freshness::Linearizable.tighten(b), Freshness::Linearizable);
        assert_eq!(b.tighten(Freshness::Linearizable), Freshness::Linearizable);
        assert_eq!(Freshness::Any.tighten(Freshness::Any), Freshness::Any);
    }
}
