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
//! In-memory implementation of `StorageApi` for unit testing raft drivers.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::StoreError;
use crate::api::StorageApi;
use crate::pb::api::{Response, response::Violation};
use crate::store_command::*;
use crate::types::{Metadata, StoreDataEnvelope};

/// In-memory storage that implements the `StorageApi` trait.
///
/// Uses `Mutex` for interior mutability so it is `Send + Sync`,
/// satisfying the trait bounds required by raft drivers.
#[derive(Default)]
pub struct MockStorage {
    /// keyspace -> data_key -> serialized data bytes.
    data: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
    /// data_key -> serialized `Metadata`.
    /// Stored flat, regardless of keyspace, matching the real Fjall
    /// state machine which keeps metadata in a single "meta" keyspace.
    metadata: Mutex<HashMap<String, Vec<u8>>>,
    /// index_key -> ()  (flat, no keyspace).
    indexes: Mutex<HashMap<Vec<u8>, ()>>,
}

fn lock<'a, T>(m: &'a Mutex<T>) -> Result<std::sync::MutexGuard<'a, T>, StoreError> {
    m.lock().map_err(|_| StoreError::IO {
        source: io::Error::other("mutex poisoned"),
    })
}

fn resolve_keyspace<S: Into<String>>(ks: Option<S>) -> String {
    ks.map(Into::into).unwrap_or_else(|| "data".to_string())
}

impl MockStorage {
    /// Store a value under `key` in `keyspace`, recording `metadata`.
    /// Returns a `Violation` when `expected_revision` mismatches.
    /// When a violation occurs, the write is skipped (true CAS behavior).
    fn set_value_inner(
        data: &mut HashMap<String, HashMap<String, Vec<u8>>>,
        metadata_map: &mut HashMap<String, Vec<u8>>,
        key: &str,
        keyspace: &str,
        value_bytes: Vec<u8>,
        metadata: &Metadata,
        expected_revision: Option<u64>,
    ) -> Result<Option<Violation>, StoreError> {
        let violation = expected_revision.and_then(|exp_rev| {
            metadata_map
                .get(key)
                .and_then(|m| Metadata::unpack(m).ok())
                .filter(|stored_meta| stored_meta.revision != exp_rev)
                .map(|stored_meta| Violation {
                    r#type: "CONFLICT".to_string(),
                    subject: key.to_string(),
                    description: format!(
                        "Current revision is {}, expected {}",
                        stored_meta.revision, exp_rev
                    ),
                })
        });

        // Only write if no violation occurred
        if violation.is_none() {
            data.entry(keyspace.to_string())
                .or_default()
                .insert(key.to_string(), value_bytes);
            metadata_map.insert(key.to_string(), metadata.pack()?);
        }
        Ok(violation)
    }

    /// Create a value under `key` only if the key does not already exist.
    /// Returns a `Violation` with type "CONFLICT" when the key already exists.
    /// When a violation occurs, the write is skipped.
    fn create_if_absent_inner(
        data: &mut HashMap<String, HashMap<String, Vec<u8>>>,
        metadata_map: &mut HashMap<String, Vec<u8>>,
        key: &str,
        keyspace: &str,
        value_bytes: Vec<u8>,
        metadata: &Metadata,
    ) -> Result<Option<Violation>, StoreError> {
        let exists = metadata_map.contains_key(key);
        if exists {
            Ok(Some(Violation {
                r#type: "CONFLICT".to_string(),
                subject: key.to_string(),
                description: "key already exists (create_if_absent)".to_string(),
            }))
        } else {
            data.entry(keyspace.to_string())
                .or_default()
                .insert(key.to_string(), value_bytes);
            metadata_map.insert(key.to_string(), metadata.pack()?);
            Ok(None)
        }
    }

    /// Fetch `Metadata` for a key, returning a default if absent.
    fn get_metadata(metadata_map: &HashMap<String, Vec<u8>>, key: &str) -> Metadata {
        metadata_map
            .get(key)
            .and_then(|m| Metadata::unpack(m).ok())
            .unwrap_or_default()
    }
}

#[async_trait]
impl StorageApi for MockStorage {
    async fn contains_key<K, S>(&self, key: K, keyspace: Option<S>) -> Result<bool, StoreError>
    where
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send,
    {
        let ks = match keyspace {
            Some(name) => name.as_ref().to_string(),
            None => "data".to_string(),
        };
        let key_str = String::from_utf8(key.as_ref().to_vec())?;
        Ok(lock(&self.data)?
            .get(&ks)
            .is_some_and(|m| m.contains_key(&key_str)))
    }

    async fn get_by_key<T, K, S>(
        &self,
        key: K,
        keyspace: Option<S>,
    ) -> Result<Option<StoreDataEnvelope<T>>, StoreError>
    where
        T: DeserializeOwned + Send,
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send,
    {
        let ks = match keyspace {
            Some(name) => name.as_ref().to_string(),
            None => "data".to_string(),
        };
        let key_str = String::from_utf8(key.as_ref().to_vec())?;

        let data = lock(&self.data)?;
        let metadata_map = lock(&self.metadata)?;

        let Some(data_map) = data.get(&ks) else {
            return Ok(None);
        };
        let Some(value_bytes) = data_map.get(&key_str) else {
            return Ok(None);
        };

        let t: T = rmp_serde::from_slice(value_bytes)?;
        let meta = Self::get_metadata(&metadata_map, &key_str);

        Ok(Some(StoreDataEnvelope {
            data: t,
            metadata: meta,
        }))
    }

    async fn prefix<T, K, S>(
        &self,
        prefix: K,
        keyspace: Option<S>,
    ) -> Result<Vec<(String, StoreDataEnvelope<T>)>, StoreError>
    where
        T: DeserializeOwned + Send,
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send,
    {
        let ks = match keyspace {
            Some(name) => name.as_ref().to_string(),
            None => "data".to_string(),
        };
        let prefix_str = String::from_utf8(prefix.as_ref().to_vec())?;

        let data = lock(&self.data)?;
        let metadata_map = lock(&self.metadata)?;

        let Some(data_map) = data.get(&ks) else {
            return Ok(Vec::new());
        };

        let mut result: Vec<(String, StoreDataEnvelope<T>)> = data_map
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix_str))
            .map(|(k, v)| {
                let t: T = rmp_serde::from_slice(v)?;
                let meta = Self::get_metadata(&metadata_map, k);
                Ok::<_, StoreError>((
                    k.clone(),
                    StoreDataEnvelope {
                        data: t,
                        metadata: meta,
                    },
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }

    async fn prefix_index<K>(&self, prefix: K) -> Result<Vec<String>, StoreError>
    where
        K: AsRef<[u8]> + Send,
    {
        let indexes = lock(&self.indexes)?;

        let mut result: Vec<String> = indexes
            .keys()
            .filter(|k| k.starts_with(prefix.as_ref()))
            .filter_map(|k| String::from_utf8(k.clone()).ok())
            .collect();

        result.sort();
        Ok(result)
    }

    async fn remove<K, S>(&self, key: K, keyspace: Option<S>) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send,
        S: Into<String> + Send,
    {
        let key_bytes = key.into();
        let ks = resolve_keyspace(keyspace);
        let key_str = String::from_utf8(key_bytes)?;

        let mut data = lock(&self.data)?;
        let mut metadata_map = lock(&self.metadata)?;
        if let Some(data_map) = data.get_mut(&ks) {
            data_map.remove(&key_str);
        }
        metadata_map.remove(&key_str);

        Ok(Response::default())
    }

    async fn remove_index<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send,
    {
        let key_bytes = key.into();
        lock(&self.indexes)?.remove(&key_bytes);
        Ok(Response::default())
    }

    async fn set_value<K, V, S>(
        &self,
        key: K,
        value: StoreDataEnvelope<V>,
        keyspace: Option<S>,
        expected_revision: Option<u64>,
    ) -> Result<Response, StoreError>
    where
        K: Into<String> + Send,
        V: Serialize + Send,
        S: Into<String> + Send,
    {
        let key_str = key.into();
        let ks = resolve_keyspace(keyspace);
        let value_bytes = rmp_serde::to_vec(&value.data)?;

        let mut data = lock(&self.data)?;
        let mut metadata_map = lock(&self.metadata)?;
        let violation = Self::set_value_inner(
            &mut data,
            &mut metadata_map,
            &key_str,
            &ks,
            value_bytes,
            &value.metadata,
            expected_revision,
        )?;

        let violations = violation.map_or(Vec::new(), |v| vec![v]);
        Ok(Response {
            value: None,
            violations,
        })
    }

    async fn set_index_key<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<String> + Send,
    {
        let key_bytes: Vec<u8> = key.into().into_bytes();
        lock(&self.indexes)?.insert(key_bytes, ());
        Ok(Response::default())
    }

    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<Response, StoreError> {
        let mut violations: Vec<Violation> = Vec::new();

        let mut data = lock(&self.data)?;
        let mut metadata_map = lock(&self.metadata)?;
        let mut indexes = lock(&self.indexes)?;

        for mutation in mutations {
            match mutation {
                Mutation::Remove {
                    key,
                    keyspace,
                    expected_revision,
                } => {
                    let key_str = String::from_utf8(key)?;
                    let violation = expected_revision.and_then(|exp_rev| {
                        metadata_map
                            .get(&key_str)
                            .and_then(|m| Metadata::unpack(m).ok())
                            .filter(|stored_meta| stored_meta.revision != exp_rev)
                            .map(|stored_meta| Violation {
                                r#type: "CONFLICT".to_string(),
                                subject: key_str.clone(),
                                description: format!(
                                    "removal CAS conflict: expected revision {exp_rev}, found {}",
                                    stored_meta.revision
                                ),
                            })
                    });
                    // If key doesn't exist and expected_revision is set, it's also a conflict
                    let violation = violation.or_else(|| {
                        expected_revision.map(|exp_rev| {
                            Violation {
                                r#type: "CONFLICT".to_string(),
                                subject: key_str.clone(),
                                description: format!(
                                    "removal CAS conflict: key {key_str} does not exist (expected revision {exp_rev})"
                                ),
                            }
                        }).filter(|_| !metadata_map.contains_key(&key_str))
                    });
                    if let Some(v) = violation {
                        violations.push(v);
                    } else {
                        if let Some(data_map) = data.get_mut(&keyspace) {
                            data_map.remove(&key_str);
                        }
                        metadata_map.remove(&key_str);
                    }
                }

                Mutation::RemoveIndex { key } => {
                    indexes.remove(&key);
                }

                Mutation::Set {
                    key,
                    keyspace,
                    value,
                    metadata,
                    expected_revision,
                } => {
                    let key_str = String::from_utf8_lossy(&key).to_string();
                    if let Some(v) = Self::set_value_inner(
                        &mut data,
                        &mut metadata_map,
                        &key_str,
                        &keyspace,
                        value,
                        &metadata,
                        expected_revision,
                    )? {
                        violations.push(v);
                    }
                }

                Mutation::CreateIfAbsent {
                    key,
                    keyspace,
                    value,
                    metadata,
                } => {
                    let key_str = String::from_utf8_lossy(&key).to_string();
                    if let Some(v) = Self::create_if_absent_inner(
                        &mut data,
                        &mut metadata_map,
                        &key_str,
                        &keyspace,
                        value,
                        &metadata,
                    )? {
                        violations.push(v);
                    }
                }

                Mutation::SetIndex { key } => {
                    indexes.insert(key, ());
                }
            }
        }

        Ok(Response {
            value: None,
            violations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_value_without_revision_succeeds() {
        let storage = MockStorage::default();
        let resp = storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "value".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();
        assert!(resp.violations.is_empty());
    }

    #[tokio::test]
    async fn test_set_value_with_matching_revision_succeeds() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "initial".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 1,
                        created_at: 0,
                    },
                    data: "updated".to_string(),
                },
                None::<String>,
                Some(0),
            )
            .await
            .unwrap();
        assert!(resp.violations.is_empty());
    }

    #[tokio::test]
    async fn test_set_value_with_mismatching_revision_fails() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "initial".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 1,
                        created_at: 0,
                    },
                    data: "updated".to_string(),
                },
                None::<String>,
                Some(99),
            )
            .await
            .unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");
    }

    #[tokio::test]
    async fn test_set_value_skips_write_on_conflict() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "initial".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 5,
                        created_at: 0,
                    },
                    data: "should-not-appear".to_string(),
                },
                None::<String>,
                Some(99),
            )
            .await
            .unwrap();
        assert_eq!(resp.violations.len(), 1);

        let fetched: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("test-key", None::<&str>).await.unwrap();
        assert_eq!(fetched.unwrap().data, "initial");
    }

    #[tokio::test]
    async fn test_create_if_absent_succeeds_when_key_absent() {
        let storage = MockStorage::default();
        let mutations = vec![
            Mutation::create_if_absent(b"new-key", "value", Metadata::new(), None::<&str>).unwrap(),
        ];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("new-key", None::<&str>).await.unwrap();
        assert_eq!(fetched.unwrap().data, "value");
    }

    #[tokio::test]
    async fn test_create_if_absent_conflicts_when_key_exists() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "existing-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "initial".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![
            Mutation::create_if_absent(b"existing-key", "new-value", Metadata::new(), None::<&str>)
                .unwrap(),
        ];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");

        let fetched: Option<StoreDataEnvelope<String>> = storage
            .get_by_key("existing-key", None::<&str>)
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().data, "initial");
    }

    #[tokio::test]
    async fn test_remove_without_expected_revision_succeeds() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "value".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, None).unwrap()];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("test-key", None::<&str>).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_remove_with_matching_expected_revision_succeeds() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "value".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();
        // Update metadata to revision 5
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 5,
                        created_at: 0,
                    },
                    data: "value2".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, Some(5)).unwrap()];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("test-key", None::<&str>).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_remove_with_mismatching_expected_revision_conflicts() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "value".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, Some(99)).unwrap()];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");

        // Key should still exist since the removal was rejected
        let fetched: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("test-key", None::<&str>).await.unwrap();
        assert_eq!(fetched.unwrap().data, "value");
    }

    #[tokio::test]
    async fn test_remove_nonexistent_key_with_expected_revision_conflicts() {
        let storage = MockStorage::default();
        let mutations = vec![Mutation::remove("no-such-key", None::<&str>, Some(1)).unwrap()];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");
    }

    #[tokio::test]
    async fn test_batch_remove_only_rejects_conflicting_entry() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "key1",
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: "v1".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();
        storage
            .set_value(
                "key2",
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 3,
                        created_at: 0,
                    },
                    data: "v2".to_string(),
                },
                None::<String>,
                None,
            )
            .await
            .unwrap();

        // key1 has revision 0 (Metadata::new()), requesting wrong revision -> conflict
        // key2 has revision 3, requesting correct revision -> success
        let mutations = vec![
            Mutation::remove("key1", None::<&str>, Some(99)).unwrap(),
            Mutation::remove("key2", None::<&str>, Some(3)).unwrap(),
        ];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");

        // key1 should still exist (CAS conflict)
        let fetched1: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("key1", None::<&str>).await.unwrap();
        assert_eq!(fetched1.unwrap().data, "v1");

        // key2 should be removed (CAS match)
        let fetched2: Option<StoreDataEnvelope<String>> =
            storage.get_by_key("key2", None::<&str>).await.unwrap();
        assert!(fetched2.is_none());
    }
}
