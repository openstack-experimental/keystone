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

use crate::ApiStoreError;
use crate::StorageApi;
use crate::StoreError;
use crate::StoreResponse;
use crate::Violation;
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
    /// This node's simulated Raft node id. Defaults to `0`.
    node_id: Mutex<u64>,
    /// The simulated current Raft leader id. Defaults to `None` (no
    /// leader), matching `current_leader()`'s prior hardcoded behavior.
    leader_id: Mutex<Option<u64>>,
}

fn lock<'a, T>(m: &'a Mutex<T>) -> Result<std::sync::MutexGuard<'a, T>, StoreError> {
    m.lock().map_err(|_| StoreError::IO {
        source: io::Error::other("mutex poisoned"),
    })
}

impl MockStorage {
    /// Sets this node's simulated Raft node id, for tests exercising
    /// leader-only logic (`current_leader() == Some(node_id())`).
    pub fn set_node_id(&self, id: u64) {
        *self.node_id.lock().unwrap_or_else(|p| p.into_inner()) = id;
    }

    /// Sets the simulated current Raft leader id, for tests exercising
    /// leader-only logic.
    pub fn set_current_leader(&self, leader: Option<u64>) {
        *self.leader_id.lock().unwrap_or_else(|p| p.into_inner()) = leader;
    }

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
    async fn contains_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<bool, ApiStoreError> {
        let ks = keyspace.unwrap_or("data").to_string();
        let key_str = String::from_utf8(key.to_vec())?;
        let res = lock(&self.data)?
            .get(&ks)
            .is_some_and(|m| m.contains_key(&key_str));
        Ok(res)
    }

    async fn get_by_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
        let ks = keyspace.unwrap_or("data").to_string();
        let key_str = String::from_utf8(key.to_vec())?;

        let data = lock(&self.data)?;
        let metadata_map = lock(&self.metadata)?;

        let Some(data_map) = data.get(&ks) else {
            return Ok(None);
        };
        let Some(value_bytes) = data_map.get(&key_str) else {
            return Ok(None);
        };

        let meta = Self::get_metadata(&metadata_map, &key_str);

        Ok(Some(StoreDataEnvelope {
            data: value_bytes.clone(),
            metadata: meta,
        }))
    }

    async fn prefix(
        &self,
        prefix: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
        let ks = keyspace.unwrap_or("data").to_string();
        let prefix_str = String::from_utf8(prefix.to_vec())?;

        let data = lock(&self.data)?;
        let metadata_map = lock(&self.metadata)?;

        let Some(data_map) = data.get(&ks) else {
            return Ok(Vec::new());
        };

        let mut result: Vec<(String, StoreDataEnvelope<Vec<u8>>)> = data_map
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix_str))
            .map(|(k, v)| {
                let meta = Self::get_metadata(&metadata_map, k);
                (
                    k.clone(),
                    StoreDataEnvelope {
                        data: v.clone(),
                        metadata: meta,
                    },
                )
            })
            .collect();

        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }

    async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, ApiStoreError> {
        let indexes = lock(&self.indexes)?;

        let mut result: Vec<String> = indexes
            .keys()
            .filter(|k| k.starts_with(prefix))
            .filter_map(|k| String::from_utf8(k.clone()).ok())
            .collect();

        result.sort();
        Ok(result)
    }

    async fn remove(
        &self,
        key: String,
        keyspace: Option<String>,
    ) -> Result<StoreResponse, ApiStoreError> {
        let ks = keyspace.unwrap_or_else(|| "data".to_string());

        let mut data = lock(&self.data)?;
        let mut metadata_map = lock(&self.metadata)?;
        if let Some(data_map) = data.get_mut(&ks) {
            data_map.remove(&key);
        }
        metadata_map.remove(&key);

        Ok(StoreResponse {
            value: None,
            violations: vec![],
        })
    }

    async fn remove_index(&self, key: String) -> Result<StoreResponse, ApiStoreError> {
        lock(&self.indexes)?.remove(&key.into_bytes());
        Ok(StoreResponse {
            value: None,
            violations: vec![],
        })
    }

    async fn set_value(
        &self,
        key: String,
        value: StoreDataEnvelope<Vec<u8>>,
        keyspace: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<StoreResponse, ApiStoreError> {
        let ks = keyspace.unwrap_or_else(|| "data".to_string());

        let mut data = lock(&self.data)?;
        let mut metadata_map = lock(&self.metadata)?;
        let violation = Self::set_value_inner(
            &mut data,
            &mut metadata_map,
            &key,
            &ks,
            value.data,
            &value.metadata,
            expected_revision,
        )?;

        let violations = violation.map_or(Vec::new(), |v| vec![v]);
        Ok(StoreResponse {
            value: None,
            violations,
        })
    }

    async fn set_index_key(&self, key: String) -> Result<StoreResponse, ApiStoreError> {
        lock(&self.indexes)?.insert(key.into_bytes(), ());
        Ok(StoreResponse {
            value: None,
            violations: vec![],
        })
    }

    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<StoreResponse, ApiStoreError> {
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

        Ok(StoreResponse {
            value: None,
            violations,
        })
    }

    async fn is_initialized(&self) -> Result<bool, ApiStoreError> {
        Ok(false)
    }

    async fn current_leader(&self) -> Option<u64> {
        *self.leader_id.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn keyspace_exists(&self, keyspace: &str) -> Result<bool, ApiStoreError> {
        Ok(lock(&self.data)?.contains_key(keyspace))
    }

    async fn drop_keyspace(&self, keyspace: &str) -> Result<(), ApiStoreError> {
        if matches!(keyspace, "data" | "meta" | "index") {
            return Err(ApiStoreError::other(format!(
                "refusing to drop core keyspace '{keyspace}'"
            )));
        }
        let mut data = lock(&self.data)?;
        if data.get(keyspace).is_some_and(|m| !m.is_empty()) {
            return Err(ApiStoreError::other(format!(
                "refusing to drop non-empty keyspace '{keyspace}'"
            )));
        }
        data.remove(keyspace);
        Ok(())
    }

    async fn node_id(&self) -> u64 {
        *self.node_id.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn initialize(
        &self,
        _nodes: HashMap<u64, openstack_keystone_storage_api::Node>,
    ) -> Result<(), ApiStoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serialize(s: &str) -> Vec<u8> {
        rmp_serde::to_vec(s).unwrap()
    }

    #[tokio::test]
    async fn test_set_value_without_revision_succeeds() {
        let storage = MockStorage::default();
        let resp = storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("value"),
                },
                None,
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
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("initial"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 1,
                        created_at: 0,
                        ..Default::default()
                    },
                    data: serialize("updated"),
                },
                None,
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
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("initial"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 1,
                        created_at: 0,
                        ..Default::default()
                    },
                    data: serialize("updated"),
                },
                None,
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
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("initial"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let resp = storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 5,
                        created_at: 0,
                        ..Default::default()
                    },
                    data: serialize("should-not-appear"),
                },
                None,
                Some(99),
            )
            .await
            .unwrap();
        assert_eq!(resp.violations.len(), 1);

        let fetched = storage
            .get_by_key(b"test-key", None)
            .await
            .unwrap()
            .unwrap();
        let typed: String = rmp_serde::from_slice(&fetched.data).unwrap();
        assert_eq!(typed, "initial");
    }

    #[tokio::test]
    async fn test_create_if_absent_succeeds_when_key_absent() {
        let storage = MockStorage::default();
        let mutations = vec![
            Mutation::create_if_absent(b"new-key", "value", Metadata::new(), None::<&str>).unwrap(),
        ];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched = storage.get_by_key(b"new-key", None).await.unwrap().unwrap();
        let typed: String = rmp_serde::from_slice(&fetched.data).unwrap();
        assert_eq!(typed, "value");
    }

    #[tokio::test]
    async fn test_create_if_absent_conflicts_when_key_exists() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "existing-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("initial"),
                },
                None,
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

        let fetched = storage
            .get_by_key(b"existing-key", None)
            .await
            .unwrap()
            .unwrap();
        let typed: String = rmp_serde::from_slice(&fetched.data).unwrap();
        assert_eq!(typed, "initial");
    }

    #[tokio::test]
    async fn test_remove_without_expected_revision_succeeds() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("value"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, None)];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched = storage.get_by_key(b"test-key", None).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_remove_with_matching_expected_revision_succeeds() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("value"),
                },
                None,
                None,
            )
            .await
            .unwrap();
        // Update metadata to revision 5
        storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 5,
                        created_at: 0,
                        ..Default::default()
                    },
                    data: serialize("value2"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, Some(5))];
        let resp = storage.transaction(mutations).await.unwrap();
        assert!(resp.violations.is_empty());

        let fetched = storage.get_by_key(b"test-key", None).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_remove_with_mismatching_expected_revision_conflicts() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "test-key".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("value"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        let mutations = vec![Mutation::remove("test-key", None::<&str>, Some(99))];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");

        // Key should still exist since the removal was rejected
        let fetched = storage
            .get_by_key(b"test-key", None)
            .await
            .unwrap()
            .unwrap();
        let typed: String = rmp_serde::from_slice(&fetched.data).unwrap();
        assert_eq!(typed, "value");
    }

    #[tokio::test]
    async fn test_remove_nonexistent_key_with_expected_revision_conflicts() {
        let storage = MockStorage::default();
        let mutations = vec![Mutation::remove("no-such-key", None::<&str>, Some(1))];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");
    }

    #[tokio::test]
    async fn test_batch_remove_only_rejects_conflicting_entry() {
        let storage = MockStorage::default();
        storage
            .set_value(
                "key1".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata::new(),
                    data: serialize("v1"),
                },
                None,
                None,
            )
            .await
            .unwrap();
        storage
            .set_value(
                "key2".to_string(),
                StoreDataEnvelope {
                    metadata: Metadata {
                        revision: 3,
                        created_at: 0,
                        ..Default::default()
                    },
                    data: serialize("v2"),
                },
                None,
                None,
            )
            .await
            .unwrap();

        // key1 has revision 0 (Metadata::new()), requesting wrong revision -> conflict
        // key2 has revision 3, requesting correct revision -> success
        let mutations = vec![
            Mutation::remove("key1", None::<&str>, Some(99)),
            Mutation::remove("key2", None::<&str>, Some(3)),
        ];
        let resp = storage.transaction(mutations).await.unwrap();
        assert_eq!(resp.violations.len(), 1);
        assert_eq!(resp.violations[0].r#type, "CONFLICT");

        // key1 should still exist (CAS conflict)
        let fetched1 = storage.get_by_key(b"key1", None).await.unwrap().unwrap();
        let typed1: String = rmp_serde::from_slice(&fetched1.data).unwrap();
        assert_eq!(typed1, "v1");

        // key2 should be removed (CAS match)
        let fetched2 = storage.get_by_key(b"key2", None).await.unwrap();
        assert!(fetched2.is_none());
    }
}
