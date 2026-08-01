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
//! Per-provider list-pagination limits, mirroring python-keystone's
//! per-resource `list_limit` config plus a global `[DEFAULT] list_limit` /
//! `max_db_limit` fallback (see `keystone.common.driver_hints.Hints`).
use serde::de::{Deserializer, Error as _};
use serde::{Deserialize, Serialize, Serializer};

/// Reusable per-provider pagination limit configuration.
///
/// Embedded as a field in each domain's provider config section (e.g.
/// `IdentityProvider.list_limit`), rather than duplicated inline, so every
/// domain gets the same two knobs.
///
/// Both spellings of the option are accepted:
///
/// ```ini
/// [identity]
/// # python-keystone's spelling: the page size on its own
/// list_limit = 100
/// ```
///
/// ```yaml
/// identity:
///   list_limit:
///     list_limit: 100
///     max_list_limit: 1000
/// ```
///
/// and the scalar spelling is what serialization produces whenever
/// `max_list_limit` is unset, so an `[identity] list_limit` reported by — or
/// overridden through — the per-domain configuration API keeps the shape
/// python-keystone gives it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ListLimitConfig {
    /// Default page size applied when the client omits `limit`. Falls back
    /// to the global `[DEFAULT] list_limit` when unset.
    pub list_limit: Option<u64>,
    /// Absolute cap a client-supplied `limit` is clamped to. Falls back to
    /// the global `[DEFAULT] max_db_limit` when unset.
    ///
    /// It has no scalar spelling of its own: python-keystone only knows the
    /// global `[DEFAULT] max_db_limit`.
    pub max_list_limit: Option<u64>,
}

/// The two accepted spellings of a [`ListLimitConfig`].
#[derive(Deserialize)]
#[serde(untagged)]
enum Repr {
    /// `list_limit = 100`, python-keystone's spelling.
    Limit(Option<u64>),
    /// The same, as delivered by a source that only carries strings.
    Text(String),
    /// The full mapping of both knobs.
    Full {
        /// See [`ListLimitConfig::list_limit`].
        #[serde(default)]
        list_limit: Option<u64>,
        /// See [`ListLimitConfig::max_list_limit`].
        #[serde(default)]
        max_list_limit: Option<u64>,
    },
}

impl<'de> Deserialize<'de> for ListLimitConfig {
    /// Accept either the scalar page size or the full mapping.
    ///
    /// # Parameters
    /// - `deserializer`: The serde deserializer.
    ///
    /// # Returns
    /// - `Result<Self, D::Error>` - The parsed limits, or an error when the
    ///   value is neither spelling.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Limit(list_limit) => Self {
                list_limit,
                max_list_limit: None,
            },
            Repr::Text(text) => Self {
                list_limit: Some(text.trim().parse().map_err(|_| {
                    D::Error::custom(format!("expected a page size, got `{text}`"))
                })?),
                max_list_limit: None,
            },
            Repr::Full {
                list_limit,
                max_list_limit,
            } => Self {
                list_limit,
                max_list_limit,
            },
        })
    }
}

impl Serialize for ListLimitConfig {
    /// Use the scalar spelling unless `max_list_limit` needs saying.
    ///
    /// # Parameters
    /// - `serializer`: The serde serializer.
    ///
    /// # Returns
    /// - `Result<S::Ok, S::Error>` - The serialized limits.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self.max_list_limit {
            None => self.list_limit.serialize(serializer),
            Some(max_list_limit) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("list_limit", &self.list_limit)?;
                map.serialize_entry("max_list_limit", &max_list_limit)?;
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_the_scalar_spelling() {
        let parsed: ListLimitConfig = serde_json::from_value(json!(100)).unwrap();
        assert_eq!(parsed.list_limit, Some(100));
        assert_eq!(parsed.max_list_limit, None);
    }

    #[test]
    fn accepts_the_full_spelling() {
        let parsed: ListLimitConfig =
            serde_json::from_value(json!({"list_limit": 10, "max_list_limit": 20})).unwrap();
        assert_eq!(parsed.list_limit, Some(10));
        assert_eq!(parsed.max_list_limit, Some(20));
    }

    #[test]
    fn accepts_a_partial_mapping() {
        let parsed: ListLimitConfig =
            serde_json::from_value(json!({"max_list_limit": 20})).unwrap();
        assert_eq!(parsed.list_limit, None);
        assert_eq!(parsed.max_list_limit, Some(20));
    }

    #[test]
    fn accepts_null() {
        let parsed: ListLimitConfig = serde_json::from_value(json!(null)).unwrap();
        assert_eq!(parsed, ListLimitConfig::default());
    }

    #[test]
    fn serializes_as_a_scalar_without_a_cap() {
        let config = ListLimitConfig {
            list_limit: Some(100),
            max_list_limit: None,
        };
        assert_eq!(serde_json::to_value(&config).unwrap(), json!(100));
        assert_eq!(
            serde_json::to_value(ListLimitConfig::default()).unwrap(),
            json!(null)
        );
    }

    #[test]
    fn serializes_as_a_mapping_with_a_cap() {
        let config = ListLimitConfig {
            list_limit: None,
            max_list_limit: Some(20),
        };
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            json!({"list_limit": null, "max_list_limit": 20})
        );
    }

    #[test]
    fn round_trips_both_spellings() {
        for config in [
            ListLimitConfig::default(),
            ListLimitConfig {
                list_limit: Some(5),
                max_list_limit: None,
            },
            ListLimitConfig {
                list_limit: Some(5),
                max_list_limit: Some(50),
            },
        ] {
            let encoded = serde_json::to_value(&config).unwrap();
            let decoded: ListLimitConfig = serde_json::from_value(encoded).unwrap();
            assert_eq!(decoded, config);
        }
    }
}
