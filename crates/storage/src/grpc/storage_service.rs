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

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::DataTier;
use crate::pb;
use crate::protobuf::api::Response as PbResponse;
use crate::protobuf::api::storage_service_server::StorageService;
use crate::types::*;

/// Internal service implementation for Raft protocol communications.
/// This service handles the core Raft consensus protocol operations between
/// cluster nodes.
///
/// # Responsibilities
/// - Vote requests/responses during leader election
/// - Log replication between nodes
/// - Snapshot installation for state synchronization
/// - Forwarded read requests from followers to leader
///
/// # Protocol Safety
/// This service implements critical consensus protocol operations and should
/// only be exposed to other trusted Raft cluster nodes, never to external
/// clients.
pub struct StorageServiceImpl {
    /// The local Raft node instance that this service operates on.
    pub(crate) raft_node: Raft,
    /// Direct access to the state machine store for forwarded reads.
    state_machine_store: Arc<StateMachineStore>,
}

impl StorageServiceImpl {
    /// Creates a new instance of the internal service.
    ///
    /// # Parameters
    /// - `raft_node`: The Raft node instance this service will operate on.
    /// - `state_machine_store`: The state machine store for direct reads.
    ///
    /// # Returns
    /// A new `StorageServiceImpl` instance.
    pub fn new(raft_node: Raft, state_machine_store: Arc<StateMachineStore>) -> Self {
        Self {
            raft_node,
            state_machine_store,
        }
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    /// Saves a storage modification command.
    ///
    /// # Parameters
    /// - `request`: Contains the key and value to set.
    ///
    /// # Returns
    /// A `Result` containing a `Response` after the value is set, or a `Status`
    /// error.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn command(
        &self,
        request: Request<pb::api::CommandRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        let req = request.into_inner();

        let res =
            self.raft_node.client_write(req).await.map_err(|e| {
                Status::internal(format!("Failed to write command to store: {}", e))
            })?;

        Ok(Response::new(res.data))
    }

    /// Handles a forwarded get request from a follower.
    ///
    /// Reads the requested key from the local state machine store, decrypts
    /// it, and returns the plaintext value along with packed metadata bytes
    /// (including revision and data tier) so that the follower can preserve
    /// the leader's metadata for correct revision-check semantics.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_get(
        &self,
        request: Request<pb::api::ForwardedGetRequest>,
    ) -> Result<Response<pb::api::ForwardedGetResponse>, Status> {
        let req = request.into_inner();
        let key = match std::str::from_utf8(&req.key) {
            Ok(s) => s.to_string(),
            Err(e) => return Err(Status::invalid_argument(format!("invalid key: {}", e))),
        };

        // Read metadata to determine the data tier
        let metadata = self
            .state_machine_store
            .meta()
            .get(&key)
            .map_err(|e| Status::internal(format!("metadata read error: {}", e)))?
            .map(|raw| Metadata::unpack(raw.as_ref()))
            .transpose()
            .map_err(|e| Status::internal(format!("metadata unpack error: {}", e)))?;

        // Read encrypted value from leader's FjallDB
        let ks = match &req.keyspace {
            Some(name) => self
                .state_machine_store
                .keyspace(name)
                .map_err(|e| Status::internal(format!("keyspace error: {}", e)))?,
            None => self.state_machine_store.data().clone(),
        };

        let encrypted = ks
            .get(key.as_bytes())
            .map_err(|e| Status::internal(format!("data read error: {}", e)))?;

        let not_found = encrypted.is_none() || metadata.is_none();
        let tier = (metadata.as_ref().map(|m| m.tier as u8)).unwrap_or(DataTier::Internal as u8);

        let value = encrypted.and_then(|enc| {
            let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
            let keyspace_bytes = keyspace_name.as_bytes();
            self.state_machine_store
                .decrypt_state(&enc, tier, keyspace_bytes, key.as_bytes())
                .ok()
        });

        let metadata_bytes = metadata
            .map(|m| m.pack())
            .transpose()
            .map_err(|e| Status::internal(format!("metadata pack error: {}", e)))?
            .unwrap_or_default();

        let response = pb::api::ForwardedGetResponse {
            value,
            not_found,
            metadata: metadata_bytes,
        };

        Ok(Response::new(response))
    }

    /// Handles a forwarded prefix scan request from a follower.
    ///
    /// Scans the local state machine store for keys matching the prefix,
    /// decrypts them, and returns the plaintext values.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_prefix(
        &self,
        request: Request<pb::api::ForwardedPrefixRequest>,
    ) -> Result<Response<pb::api::ForwardedPrefixResponse>, Status> {
        let req = request.into_inner();

        let ks = match &req.keyspace {
            Some(name) => self
                .state_machine_store
                .keyspace(name)
                .map_err(|e| Status::internal(format!("keyspace error: {}", e)))?,
            None => self.state_machine_store.data().clone(),
        };

        let meta = self.state_machine_store.meta();
        let keyspace_name = req.keyspace.as_deref().unwrap_or("data");
        let keyspace_bytes = keyspace_name.as_bytes();

        let items: Vec<_> = ks
            .prefix(&req.prefix)
            .filter_map(|item| {
                let (key_bytes, val) = match item.into_inner() {
                    Ok(i) => i,
                    Err(_) => return None,
                };
                let k = match String::from_utf8(key_bytes.to_vec()) {
                    Ok(k) => k,
                    Err(_) => return None,
                };

                // Read metadata to determine tier
                let (tier, meta_bytes) = match meta.get(k.as_bytes()) {
                    Ok(Some(raw)) => (
                        Metadata::unpack(raw.as_ref())
                            .map(|m| m.tier as u8)
                            .unwrap_or(DataTier::Internal as u8),
                        raw.to_vec(),
                    ),
                    _ => (DataTier::Internal as u8, Vec::new()),
                };

                // Decrypt using leader's DEK
                let data = self
                    .state_machine_store
                    .decrypt_state(&val, tier, keyspace_bytes, k.as_bytes())
                    .ok()?;

                Some(pb::api::PrefixEntry {
                    key: k,
                    value: data,
                    metadata: meta_bytes,
                })
            })
            .collect();
        Ok(Response::new(pb::api::ForwardedPrefixResponse {
            entries: items,
        }))
    }

    // Forwarded prefix-index scan from follower to leader.
    #[tracing::instrument(level = "trace", skip(self))]
    async fn forwarded_prefix_index(
        &self,
        request: Request<pb::api::ForwardedPrefixIndexRequest>,
    ) -> Result<Response<pb::api::ForwardedPrefixIndexResponse>, Status> {
        let req = request.into_inner();

        let items: Vec<_> = self
            .state_machine_store
            .index()
            .prefix(&req.prefix)
            .filter_map(|item| -> Option<String> {
                let key = match item.key() {
                    Ok(k) => k,
                    Err(_) => return None,
                };
                String::from_utf8(key.to_vec()).ok()
            })
            .collect();

        Ok(Response::new(pb::api::ForwardedPrefixIndexResponse {
            keys: items,
        }))
    }
}
