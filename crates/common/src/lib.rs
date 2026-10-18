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
//! # Keystone common types
//!
//! Dependency-free types shared by crates that must not depend on each other
//! (e.g. `storage-api` and `core-types`).

use std::error::Error;

/// Marker error: the storage layer could not complete an operation with a
/// linearizability guarantee (election in progress, leader unreachable, retry
/// budget exhausted).
///
/// Storage errors carry it as their [`Error::source`] so that API layers,
/// which only see a type-erased error, can recognise a transient condition
/// with [`is_storage_unavailable`] and answer `503` instead of `500`.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct StorageUnavailable(pub String);

impl StorageUnavailable {
    /// Create the marker with a description of the failure.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Whether `err` or anything in its [`Error::source`] chain is a
/// [`StorageUnavailable`].
pub fn is_storage_unavailable(err: &(dyn Error + 'static)) -> bool {
    let mut cur: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.is::<StorageUnavailable>() {
            return true;
        }
        cur = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("wrapper")]
    struct Wrapper {
        #[source]
        source: Box<dyn Error + Send + Sync + 'static>,
    }

    #[test]
    fn test_detects_marker_in_chain() {
        let inner = StorageUnavailable::new("no leader");
        assert!(is_storage_unavailable(&inner));
        let wrapped = Wrapper {
            source: Box::new(Wrapper {
                source: Box::new(inner),
            }),
        };
        assert!(is_storage_unavailable(&wrapped));
    }

    #[test]
    fn test_other_errors_not_matched() {
        let other = Wrapper {
            source: Box::new(std::fmt::Error),
        };
        assert!(!is_storage_unavailable(&other));
    }
}
