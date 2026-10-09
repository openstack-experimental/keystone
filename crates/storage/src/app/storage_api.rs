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
        let keyspace_bytes = keyspace.unwrap_or("data").as_bytes().to_vec();

        // Check ReadIndex first. On the leader we can safely proceed to
        // local reads. On a follower ReadIndex returns ForwardToLeader and
        // we forward the entire read to the leader – which already has the
        // committed data. The retry loop also handles transient QuorumNotEnough
        // errors that occur during concurrent Raft activity.
        match self.ensure_linearizable_with_retry().await? {
            EnsureLinearizableOutcome::Leader => {}
            EnsureLinearizableOutcome::Forward(lead_id, leader_addr) => {
                debug!(
                    leader_id = lead_id,
                    leader_addr = %leader_addr,
                    "ensure_linearizable (ReadIndex) returned ForwardToLeader; \
                     forwarding get_by_key to leader"
                );

                // The leader has already confirmed linearizability for us;
                // its response is authoritative. If forwarding itself fails
                // (leader unreachable, TLS error, timeout), propagate the
                // error rather than falling back to a non-linearizable local
                // read (security invariant 4 — no stale reads for sensitive
                // data).
                return self
                    .forwarded_get_by_key(lead_id, leader_addr, key, keyspace)
                    .await;
            }
        }

        let keyspace_name = keyspace.unwrap_or("data");
        if self
            .state_machine_store
            .is_ephemeral_keyspace(keyspace_name)
        {
            return Ok(self
                .state_machine_store
                .ephemeral_get(keyspace_name, key)
                .map(|(data, metadata)| StoreDataEnvelope { data, metadata }));
        }

        // Leader path: local metadata + data read.
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
            return Ok(None);
        };

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
                    &keyspace_bytes,
                    key,
                    metadata.dek_version,
                )?;
                Ok(Some(StoreDataEnvelope { data, metadata }))
            })();
        Ok(res?)
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
        let keyspace_name = keyspace.map(String::from);
        let keyspace_bytes = keyspace.unwrap_or("data").as_bytes().to_vec();

        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix scan to
        // the leader via gRPC. The retry loop also handles transient
        // QuorumNotEnough errors that occur during concurrent Raft
        // activity.
        match self.ensure_linearizable_with_retry().await? {
            EnsureLinearizableOutcome::Leader => {}
            EnsureLinearizableOutcome::Forward(lead_id, leader_addr) => {
                debug!(
                    leader_id = lead_id,
                    leader_addr = %leader_addr,
                    "ensure_linearizable (ReadIndex) returned ForwardToLeader; \
                     forwarding prefix to leader"
                );

                // See get_by_key: propagate forward failures rather than
                // falling back to a non-linearizable local read.
                return self
                    .forwarded_prefix_read(lead_id, leader_addr, prefix, keyspace)
                    .await;
            }
        }

        let ephemeral_ks_name = keyspace.unwrap_or("data");
        if let Some(entries) = self
            .state_machine_store
            .ephemeral_prefix(ephemeral_ks_name, prefix)
        {
            return entries
                .into_iter()
                .map(|(key_bytes, data, metadata)| {
                    let k = String::from_utf8(key_bytes)
                        .map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
                    Ok((k, StoreDataEnvelope { data, metadata }))
                })
                .collect::<Result<Vec<_>, StoreError>>()
                .map_err(ApiStoreError::from);
        }

        // Leader path: collect raw encrypted bytes + metadata locally,
        // then decrypt.
        let raw_items: Result<Vec<(String, Vec<u8>, Metadata)>, StoreError> = (|| {
            let ks_owned = keyspace_name
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
                    let meta = match self.state_machine_store.meta().get(&meta_key)? {
                        Some(meta) => Metadata::unpack(&meta)?,
                        None => Metadata::new(),
                    };
                    Ok((k, val.to_vec(), meta))
                })
                .collect()
        })();
        let raw_items = raw_items.map_err(ApiStoreError::from)?;

        raw_items
            .into_iter()
            .map(|(k, val_bytes, meta)| {
                let data = self
                    .state_machine_store
                    .decrypt_state(
                        &val_bytes,
                        meta.tier as u8,
                        &keyspace_bytes,
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
            .collect()
    }

    /// A `Result` containing a vector of keys, or an `ApiStoreError`.
    async fn prefix_index(&self, prefix: &[u8]) -> Result<Vec<String>, ApiStoreError> {
        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix-index
        // scan to the leader via gRPC. The retry loop also handles transient
        // QuorumNotEnough errors that occur during concurrent Raft activity.
        match self.ensure_linearizable_with_retry().await? {
            EnsureLinearizableOutcome::Leader => {}
            EnsureLinearizableOutcome::Forward(lead_id, leader_addr) => {
                debug!(
                    leader_id = lead_id,
                    leader_addr = %leader_addr,
                    "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                     for prefix_index; forwarding to leader"
                );

                // See get_by_key: propagate forward failures rather than
                // falling back to a non-linearizable local read.
                return self
                    .forwarded_prefix_index(lead_id, leader_addr, prefix)
                    .await;
            }
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
