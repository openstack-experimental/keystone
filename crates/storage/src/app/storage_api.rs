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
//! The [`StorageApi`] implementation of [`Storage`]: linearizable reads,
//! Raft-proposed writes and leader forwarding.

use super::*;

use openstack_keystone_storage_api::{DataTier, ReadConsistency};

impl Storage {
    /// Whether a read asking for `consistency` may be tried against the local
    /// state machine at all (ADR 0016-v2 §3). The per-record tier check
    /// happens in [`Self::local_get`] / [`Self::local_prefix`].
    fn local_read_allowed(&self, consistency: ReadConsistency) -> bool {
        consistency == ReadConsistency::Local
            && self.local_reads_mode == LocalReadsMode::LocalForPublic
    }

    /// Reads one record from the local state machine without any
    /// linearizability check.
    ///
    /// Returns `Ok(None)` without decrypting when the record's tier is above
    /// `max_tier`, so callers can fall back to a linearizable read; a missing
    /// record is `Ok(Some(None))`.
    #[allow(clippy::type_complexity)]
    fn local_get(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
        max_tier: DataTier,
    ) -> Result<Option<Option<StoreDataEnvelope<Vec<u8>>>>, ApiStoreError> {
        let keyspace_name = keyspace.unwrap_or("data");
        let keyspace_bytes = keyspace_name.as_bytes();
        if self
            .state_machine_store
            .is_ephemeral_keyspace(keyspace_name)
        {
            return Ok(self
                .state_machine_store
                .ephemeral_get(keyspace_name, key)
                .map(|(data, metadata)| StoreDataEnvelope { data, metadata })
                .map_or(Some(None), |env| {
                    (env.metadata.tier as u8 <= max_tier as u8).then_some(Some(env))
                }));
        }

        let metadata: Option<Metadata> = (|| -> Result<_, StoreError> {
            Ok(self
                .state_machine_store
                .meta()
                .get(crate::store::state_machine::meta_key(keyspace_name, key))?
                .map(|raw| Metadata::unpack(raw.as_ref()))
                .transpose()?)
        })()
        .map_err(ApiStoreError::from)?;

        let Some(metadata) = metadata else {
            // Data without metadata has an unknown tier: only the
            // linearizable path (max_tier == Secret) may serve it.
            if max_tier != DataTier::Secret {
                let ks = match keyspace {
                    None => self.state_machine_store.data().clone(),
                    Some(name) => self
                        .state_machine_store
                        .keyspace(name)
                        .map_err(ApiStoreError::from)?,
                };
                if ks
                    .get(key)
                    .map_err(|e| ApiStoreError::from(StoreError::from(e)))?
                    .is_some()
                {
                    return Ok(None);
                }
            }
            return Ok(Some(None));
        };
        if metadata.tier as u8 > max_tier as u8 {
            return Ok(None);
        }

        let res: Result<Option<StoreDataEnvelope<Vec<u8>>>, StoreError> =
            (|| -> Result<_, StoreError> {
                let ks = match keyspace {
                    None => self.state_machine_store.data().clone(),
                    Some(name) => self.state_machine_store.keyspace(name)?,
                };
                let Some(encrypted) = ks.get(key)? else {
                    return Ok(None);
                };
                let data = self.state_machine_store.decrypt_state(
                    encrypted.as_ref(),
                    metadata.tier as u8,
                    keyspace_bytes,
                    key,
                    metadata.dek_version,
                )?;
                Ok(Some(StoreDataEnvelope { data, metadata }))
            })();
        Ok(Some(res?))
    }

    /// Prefix scan of the local state machine without any linearizability
    /// check.
    ///
    /// Returns `Ok(None)` when any matching record's tier is above `max_tier`
    /// (nothing is decrypted in that case), so callers can fall back to a
    /// linearizable scan.
    #[allow(clippy::type_complexity)]
    fn local_prefix(
        &self,
        prefix: &[u8],
        keyspace: Option<&str>,
        max_tier: DataTier,
    ) -> Result<Option<Vec<(String, StoreDataEnvelope<Vec<u8>>)>>, ApiStoreError> {
        let keyspace_bytes = keyspace.unwrap_or("data").as_bytes();

        let ephemeral_ks_name = keyspace.unwrap_or("data");
        if let Some(entries) = self
            .state_machine_store
            .ephemeral_prefix(ephemeral_ks_name, prefix)
        {
            if entries
                .iter()
                .any(|(_, _, meta)| meta.tier as u8 > max_tier as u8)
            {
                return Ok(None);
            }
            return entries
                .into_iter()
                .map(|(key_bytes, data, metadata)| {
                    let k = String::from_utf8(key_bytes)
                        .map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
                    Ok((k, StoreDataEnvelope { data, metadata }))
                })
                .collect::<Result<Vec<_>, StoreError>>()
                .map(Some)
                .map_err(ApiStoreError::from);
        }

        // Collect raw encrypted bytes + metadata locally, then decrypt.
        let raw_items: Result<Vec<(String, Vec<u8>, Option<Metadata>)>, StoreError> = (|| {
            let ks_owned = keyspace
                .map(|n| self.state_machine_store.keyspace(n))
                .transpose()?;
            let ks = match ks_owned.as_ref() {
                None => self.state_machine_store.data(),
                Some(k) => k,
            };
            let effective_keyspace = keyspace.unwrap_or("data");
            ks.prefix(prefix)
                .map(|item| {
                    let (key_bytes, val) = item.into_inner()?;
                    let k = String::from_utf8(key_bytes.to_vec())?;
                    let meta_key =
                        crate::store::state_machine::meta_key(effective_keyspace, k.as_bytes());
                    // A record lacking metadata (legacy/edge case) gets a
                    // synthesized default *in memory only* — this is a
                    // read path and must never write. Persisting it here
                    // was a non-Raft write reachable only on the leader
                    // (GitHub #1297 item 3): it diverged the leader from
                    // followers, discarded the legacy-probe fallback a
                    // real `dek_version` hint would have carried, and gave
                    // a later CAS write's `revision` starting point a
                    // value that depended on whether this read happened
                    // to run first.
                    let meta = self
                        .state_machine_store
                        .meta()
                        .get(&meta_key)?
                        .map(|meta| Metadata::unpack(&meta))
                        .transpose()?;
                    Ok((k, val.to_vec(), meta))
                })
                .collect()
        })();
        let raw_items = raw_items.map_err(ApiStoreError::from)?;
        // A record without metadata has an unknown tier: restricted scans
        // must not guess, they fall back to the linearizable path.
        if max_tier != DataTier::Secret && raw_items.iter().any(|(_, _, meta)| meta.is_none()) {
            return Ok(None);
        }
        let raw_items: Vec<(String, Vec<u8>, Metadata)> = raw_items
            .into_iter()
            .map(|(k, v, meta)| (k, v, meta.unwrap_or_else(Metadata::new)))
            .collect();
        if raw_items
            .iter()
            .any(|(_, _, meta)| meta.tier as u8 > max_tier as u8)
        {
            return Ok(None);
        }

        raw_items
            .into_iter()
            .map(|(k, val_bytes, meta)| {
                let data = self
                    .state_machine_store
                    .decrypt_state(
                        &val_bytes,
                        meta.tier as u8,
                        keyspace_bytes,
                        k.as_bytes(),
                        meta.dek_version,
                    )
                    .map_err(ApiStoreError::from)?;
                Ok((
                    k,
                    StoreDataEnvelope {
                        data,
                        metadata: meta,
                    },
                ))
            })
            .collect::<Result<Vec<_>, ApiStoreError>>()
            .map(Some)
    }
}

#[async_trait]
impl StorageApi for Storage {
    /// Checks whether a given key is present in the keyspace of the distributed
    /// store.
    ///
    /// # Parameters
    /// - `key`: Contains the key to retrieve.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing a boolean indicating if the key exists, or a
    /// `ApiStoreError`.
    async fn contains_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<bool, ApiStoreError> {
        self.get_by_key(key, keyspace).await.map(|v| v.is_some())
    }

    async fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    async fn drop_keyspace(&self, keyspace: &str) -> Result<(), ApiStoreError> {
        self.state_machine_store
            .drop_keyspace(keyspace)
            .map_err(ApiStoreError::from)
    }

    /// Gets a value for a given key from the distributed store.
    ///
    /// # Parameters
    /// - `key`: Contains the key to retrieve.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `StoreDataEnvelope<Vec<u8>>`
    /// if found, or an `ApiStoreError`.
    async fn get_by_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
        self.get_by_key_with_consistency(key, keyspace, ReadConsistency::Linearizable)
            .await
    }

    /// Gets a value with an explicit [`ReadConsistency`].
    ///
    /// A `Local` request is served from this node's state machine only when
    /// `local_reads_mode` allows it and the record is Tier 0/1. Anything else
    /// takes the linearizable path.
    async fn get_by_key_with_consistency(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
        consistency: ReadConsistency,
    ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
        // An error here may be a torn meta/data read racing a concurrent
        // apply on a live follower; the linearizable path decides instead.
        if self.local_read_allowed(consistency)
            && let Ok(Some(res)) = self.local_get(key, keyspace, DataTier::Internal)
        {
            return Ok(res);
        }

        // Check ReadIndex first. On the leader we can safely proceed to
        // local reads. On a follower ReadIndex returns ForwardToLeader and
        // we forward the entire read to the leader – which already has the
        // committed data. The retry loop also handles transient QuorumNotEnough
        // errors that occur during concurrent Raft activity.
        if let Some(res) = self
            .route_read(|lead_id, leader_addr| async move {
                self.forwarded_get_by_key(lead_id, leader_addr, key, keyspace)
                    .await
            })
            .await?
        {
            return Ok(res);
        }

        // Leader path: local metadata + data read of any tier.
        Ok(self
            .local_get(key, keyspace, DataTier::Secret)?
            .unwrap_or_default())
    }

    async fn initialize(&self, nodes: HashMap<u64, Node>) -> Result<(), ApiStoreError> {
        let pb_nodes: HashMap<u64, pb::raft::Node> = nodes
            .into_iter()
            .map(|(id, node)| {
                (
                    id,
                    pb::raft::Node {
                        node_id: node.node_id,
                        rpc_addr: normalize_rpc_addr(&node.rpc_addr).to_owned(),
                    },
                )
            })
            .collect();
        self.raft
            .initialize(pb_nodes)
            .await
            .map_err(|e| StoreError::RaftInitError { source: e })?;
        Ok(())
    }

    async fn is_initialized(&self) -> Result<bool, ApiStoreError> {
        Ok(self
            .raft
            .is_initialized()
            .await
            .map_err(|e| StoreError::RaftFatal { source: e })?)
    }

    async fn keyspace_exists(&self, keyspace: &str) -> Result<bool, ApiStoreError> {
        Ok(self.state_machine_store.keyspace_exists(keyspace))
    }
    async fn node_id(&self) -> u64 {
        self.node_id
    }

    /// List key value pairs by the prefix.
    ///
    /// Return key value pairs matching the specified prefix as raw bytes.
    ///
    /// # Parameters
    /// - `prefix`: The prefix to query.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing a vector of key-value pairs, or an
    /// `ApiStoreError`.
    async fn prefix(
        &self,
        prefix: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
        self.prefix_with_consistency(prefix, keyspace, ReadConsistency::Linearizable)
            .await
    }

    /// Prefix scan with an explicit [`ReadConsistency`].
    ///
    /// A `Local` scan is served from this node's state machine only when
    /// `local_reads_mode` allows it and every matching record is Tier 0/1.
    /// One Tier 2/3 record sends the whole scan down the linearizable path.
    async fn prefix_with_consistency(
        &self,
        prefix: &[u8],
        keyspace: Option<&str>,
        consistency: ReadConsistency,
    ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
        if self.local_read_allowed(consistency)
            && let Ok(Some(res)) = self.local_prefix(prefix, keyspace, DataTier::Internal)
        {
            return Ok(res);
        }

        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix scan to
        // the leader via gRPC. The retry loop also handles transient
        // QuorumNotEnough errors that occur during concurrent Raft
        // activity.
        if let Some(res) = self
            .route_read(|lead_id, leader_addr| async move {
                self.forwarded_prefix_read(lead_id, leader_addr, prefix, keyspace)
                    .await
            })
            .await?
        {
            return Ok(res);
        }

        Ok(self
            .local_prefix(prefix, keyspace, DataTier::Secret)?
            .unwrap_or_default())
    }

    /// List all index entries with keys matching the given prefix.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of keys, or an `ApiStoreError`.
    async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, ApiStoreError> {
        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix-index
        // scan to the leader via gRPC. The retry loop also handles transient
        // QuorumNotEnough errors that occur during concurrent Raft activity.
        if let Some(res) = self
            .route_read(|lead_id, leader_addr| async move {
                self.forwarded_prefix_index(lead_id, leader_addr, prefix)
                    .await
            })
            .await?
        {
            return Ok(res);
        }

        // Leader path: local index scan.
        let res: Result<Vec<String>, StoreError> = self
            .state_machine_store
            .index()
            .prefix(prefix)
            .map(|item| -> Result<String, StoreError> {
                let key = item.key()?;
                Ok(String::from_utf8(key.to_vec())?)
            })
            .collect();
        Ok(res?)
    }

    async fn readiness(&self) -> Result<StorageReadiness, ApiStoreError> {
        let initialized = self.is_initialized().await?;
        if !initialized {
            return Ok(StorageReadiness {
                initialized,
                issues: Vec::new(),
            });
        }
        let metrics = self.raft.metrics().borrow_watched().clone();
        let quorum_ack_age = metrics
            .last_quorum_acked
            .as_ref()
            .map(|acked| openraft::Instant::elapsed(&**acked));
        Ok(StorageReadiness {
            initialized,
            issues: crate::readiness::readiness_issues(
                &metrics,
                self.node_id,
                quorum_ack_age,
                &self.state_machine_store.quarantined_partitions(),
            ),
        })
    }

    /// Deletes a value for a given key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing the `StoreResponse`, or an `ApiStoreError`.
    async fn remove(
        &self,
        key: String,
        keyspace: Option<String>,
    ) -> Result<StoreResponse, ApiStoreError> {
        let response: crate::ZeroizingResponse = {
            let inner =
                MutationInner::convert(Mutation::remove(key.into_bytes(), keyspace.clone(), None))?;
            let request = StoreCommand::Transaction(vec![inner]);
            let payload = crate::pb::api::CommandRequest::try_from(request)?;
            self.write_command_to_storage(payload).await?
        };
        Ok(rb_resp_to_store_response(response))
    }

    /// Deletes index key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    ///
    /// # Returns
    /// A `Result` containing the `StoreResponse`, or an `ApiStoreError`.
    async fn remove_index(&self, key: String) -> Result<StoreResponse, ApiStoreError> {
        let response: crate::ZeroizingResponse = {
            let request = StoreCommand::Transaction(vec![MutationInner::RemoveIndex {
                key: key.into_bytes(),
            }]);
            let payload = crate::pb::api::CommandRequest::try_from(request)?;
            self.write_command_to_storage(payload).await?
        };
        Ok(rb_resp_to_store_response(response))
    }

    /// Sets an index key in the distributed store.
    ///
    /// Sets the key with an empty value in the index keyspace of the storage.
    ///
    /// # Parameters
    /// - `key`: The key.
    ///
    /// # Returns
    /// A `Result` containing the `StoreResponse`, or an `ApiStoreError`.
    async fn set_index_key(&self, key: String) -> Result<StoreResponse, ApiStoreError> {
        let request = StoreCommand::Transaction(vec![MutationInner::SetIndex {
            key: key.into_bytes(),
        }]);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        Ok(rb_resp_to_store_response(
            self.write_command_to_storage(payload).await?,
        ))
    }

    /// Sets a value for a given key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    /// - `value`: The value to set for the key (pre-serialized bytes).
    /// - `keyspace`: Optional keyspace name.
    /// - `expected_revision`: Expected revision.
    ///
    /// # Returns
    /// A `Result` containing the `StoreResponse`, or an `ApiStoreError`.
    async fn set_value(
        &self,
        key: String,
        value: StoreDataEnvelope<Vec<u8>>,
        keyspace: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<StoreResponse, ApiStoreError> {
        let inner = MutationInner::convert(Mutation::Set {
            key: key.into_bytes(),
            value: value.data,
            keyspace: keyspace.unwrap_or_else(|| "data".to_string()),
            metadata: value.metadata,
            expected_revision,
        })?;
        let request = StoreCommand::Transaction(vec![inner]);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        Ok(rb_resp_to_store_response(
            self.write_command_to_storage(payload).await?,
        ))
    }

    /// Mutation transaction.
    ///
    /// # Parameters
    /// - `mutations`: List of mutations that must be applied as a single
    ///   transaction.
    ///
    /// # Returns
    /// A `Result` containing the `StoreResponse`, or an `ApiStoreError`.
    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<StoreResponse, ApiStoreError> {
        let inners: Vec<MutationInner> = mutations
            .into_iter()
            .map(MutationInner::convert)
            .collect::<Result<_, _>>()?;
        let request = StoreCommand::Transaction(inners);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        Ok(rb_resp_to_store_response(
            self.write_command_to_storage(payload).await?,
        ))
    }
}

/// Convert the internal `ZeroizingResponse` to the public `StoreResponse`.
///
/// This is the legitimate hand-off point to the caller: the plaintext
/// leaves the zeroizing wrapper here because the caller needs an owned,
/// ordinary `Vec<u8>` to use (e.g. deserialize into a typed struct).
fn rb_resp_to_store_response(resp: crate::ZeroizingResponse) -> StoreResponse {
    StoreResponse {
        value: resp.value.map(|v| v.to_vec()),
        violations: resp
            .violations
            .into_iter()
            .map(|v| Violation {
                r#type: v.r#type,
                subject: v.subject,
                description: v.description,
            })
            .collect(),
    }
}
