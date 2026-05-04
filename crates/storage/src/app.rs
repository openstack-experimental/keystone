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

use async_trait::async_trait;
use dashmap::DashMap;
use eyre::eyre;
use openraft::Config;
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ForwardToLeader, RaftError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::debug;

use openstack_keystone_config::DistributedStorageConfiguration;

use crate::StoreError;
use crate::api::StorageApi;
use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::grpc::storage_service::StorageServiceImpl;
use crate::network::NetworkManager;
use crate::network::init_tls_watcher;
use crate::pb::api::Response;
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::protobuf::api::storage_service_client::StorageServiceClient;
use crate::protobuf::api::storage_service_server::StorageServiceServer;
use crate::store_command::*;
use crate::types::*;

/// gRPC metadata header used to communicate the leader's endpoint to clients.
///
/// When a non-leader node receives a write request, it returns
/// `Status::unavailable` with this header set to the leader's address, so
/// clients can retry against the leader.
pub const LEADER_ENDPOINT_HEADER: &str = "x-openraft-leader-endpoint";
pub const LEADER_ID_HEADER: &str = "x-openraft-leader-id";

/// Initialize storage services backed by the raft.
///
/// # Parameters
/// - `ks_config`: Distributed storage configuration.
///
/// # Returns
/// A `Result` containing the `Storage` instance, or a `StoreError`.
pub async fn init_storage(
    ks_config: &DistributedStorageConfiguration,
) -> Result<Storage, StoreError> {
    // Create a configuration for the raft instance.
    let raft_config = Arc::new(
        Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        }
        .validate()?,
    );

    // Create stores and network
    let (log_store, sm) = crate::new::<crate::TypeConfig, _>(ks_config.path.clone()).await?;
    let state_machine_store = Arc::new(sm);
    let tls_watcher = init_tls_watcher(ks_config)?;
    let network = Arc::new(NetworkManager::new(tls_watcher.clone())?);

    // Create Raft instance
    let raft = Raft::new(
        ks_config.node_id,
        raft_config.clone(),
        network.clone(),
        log_store,
        state_machine_store.clone(),
    )
    .await?;

    Ok(Storage {
        connection_pool: DashMap::new(),
        raft,
        state_machine_store,
        tls_watcher,
    })
}

/// Build a tonic `Server` instance for the raft instance.
///
/// # Parameters
/// - `storage`: Reference to the storage instance.
///
/// # Returns
/// A `Result` containing the `Routes`, or a `StoreError`.
pub async fn get_app_server(storage: &Storage) -> Result<Routes, StoreError> {
    let raft_svc_impl = RaftServiceImpl::new(storage.raft.clone());
    let cluster_admin_svc_impl = ClusterAdminServiceImpl::new(storage.raft.clone());
    let storage_svc_impl = StorageServiceImpl::new(storage.raft.clone());

    let mut router = Routes::builder();
    router
        .add_service(RaftServiceServer::new(raft_svc_impl))
        .add_service(ClusterAdminServiceServer::new(cluster_admin_svc_impl))
        .add_service(StorageServiceServer::new(storage_svc_impl));

    Ok(router.routes())
}

/// Distributed storage.
pub struct Storage {
    /// Raft cluster nodes connection pool.
    connection_pool: DashMap<u64, Channel>,
    /// Tls client config watcher.
    tls_watcher: watch::Receiver<ClientTlsConfig>,
    /// Raft instance.
    pub raft: Raft,
    /// The state machine store for direct reads.
    state_machine_store: Arc<StateMachineStore>,
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
    /// `StoreError`.
    async fn contains_key<K, S>(&self, key: K, keyspace: Option<S>) -> Result<bool, StoreError>
    where
        K: AsRef<[u8]> + Send,
        S: AsRef<str> + Send,
    {
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        let ks = match keyspace {
            None => self.state_machine_store.data(),
            Some(name) => &self.state_machine_store.keyspace(name)?,
        };
        Ok(ks.contains_key(&key)?)
    }

    /// Gets a value for a given key from the distributed store.
    ///
    /// # Parameters
    /// - `key`: Contains the key to retrieve.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `StoreDataEnvelope<T>` if
    /// found, or a `StoreError`.
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
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        let ks = match keyspace {
            None => self.state_machine_store.data(),
            Some(name) => &self.state_machine_store.keyspace(name)?,
        };
        // NOTE: running lookup in separate tasks makes huge negative performance impact
        // (+1000%).
        if let Some(data) = ks
            .get(&key)?
            .map(|x| StoreDataInnerEnvelope::unpack(x.as_ref()))
            .transpose()?
        {
            let metadata = if let Some(meta) = self.state_machine_store.meta().get(&key)? {
                Metadata::unpack(&meta)?
            } else {
                // Need to repair data and insert the new metadata
                let res = Metadata::new();
                self.state_machine_store
                    .meta()
                    .insert(key.as_ref(), res.pack()?)?;
                res
            };
            return Ok(Some(StoreDataEnvelope { data, metadata }));
        }
        Ok(None)
    }

    /// List key value pairs by the prefix.
    ///
    /// Return key value pairs matching the specified prefix deserializing the
    /// data back to the requested type.
    ///
    /// # Parameters
    /// - `prefix`: The prefix to query.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing a vector of key-value pairs, or a `StoreError`.
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
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        let ks = match keyspace {
            None => self.state_machine_store.data(),
            Some(name) => &self.state_machine_store.keyspace(name)?,
        };
        ks.prefix(&prefix)
            .map(|item| {
                let (key, val) = item.into_inner()?;
                let k = String::from_utf8(key.to_vec())?;
                let meta = if let Some(meta) = self.state_machine_store.meta().get(&k)? {
                    Metadata::unpack(&meta)?
                } else {
                    // Need to repair data and insert the new metadata
                    let res = Metadata::new();
                    self.state_machine_store
                        .meta()
                        .insert(k.clone(), res.pack()?)?;
                    res
                };
                Ok((
                    k.clone(),
                    StoreDataEnvelope {
                        data: StoreDataInnerEnvelope::unpack(val.as_ref())?,
                        metadata: meta,
                    },
                ))
            })
            .collect()
    }

    /// List index keys the prefix.
    ///
    /// Return keys matching the specified prefix in the index keyspace.
    ///
    /// # Parameters
    /// - `prefix`: The prefix to query.
    ///
    /// # Returns
    /// A `Result` containing a vector of keys, or a `StoreError`.
    async fn prefix_index<K>(&self, prefix: K) -> Result<Vec<String>, StoreError>
    where
        K: AsRef<[u8]> + Send,
    {
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        self.state_machine_store
            .index()
            .prefix(&prefix)
            .map(|item| {
                let key = item.key()?;
                let k = String::from_utf8(key.to_vec())?;
                Ok(k)
            })
            .collect()
    }

    /// Deletes a value for a given key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    /// - `keyspace`: Optional keyspace name.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn remove<K, S>(&self, key: K, keyspace: Option<S>) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send,
        S: Into<String> + Send,
    {
        let request = StoreCommand::Transaction(vec![MutationInner::convert(
            Mutation::remove(key, keyspace)?,
            Nonce::default(),
        )?]);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        self.write_command_to_storage(payload).await
    }

    /// Deletes index key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn remove_index<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<Vec<u8>> + Send,
    {
        let request =
            StoreCommand::Transaction(vec![MutationInner::RemoveIndex { key: key.into() }]);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        self.write_command_to_storage(payload).await
    }

    /// Sets a value for a given key in the distributed store.
    ///
    /// # Parameters
    /// - `key`: The key.
    /// - `value`: The value to set for the key.
    /// - `keyspace`: Optional keyspace name.
    /// - `expected_revision`: Expected revision.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
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
        let key: String = key.into();
        let metrics = self.raft.metrics().borrow_watched().clone();
        let nonce = Nonce::new(metrics.current_term, metrics.last_log_index.unwrap_or(1));
        let request = StoreCommand::Transaction(vec![MutationInner::convert(
            Mutation::set(key, value.data, value.metadata, keyspace, expected_revision)?,
            nonce,
        )?]);

        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        self.write_command_to_storage(payload).await
    }

    /// Sets an index key in the distributed store.
    ///
    /// Sets the key with an empty value in the index keyspace of the storage.
    ///
    /// # Parameters
    /// - `key`: The key.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn set_index_key<K>(&self, key: K) -> Result<Response, StoreError>
    where
        K: Into<String> + Send,
    {
        let key: String = key.into();
        let request = StoreCommand::Transaction(vec![MutationInner::SetIndex { key: key.into() }]);

        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        self.write_command_to_storage(payload).await
    }

    /// Mutation transaction.
    ///
    /// # Parameters
    /// - `mutations`: List of mutations that must be applied as a single
    ///   transaction.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn transaction(&self, mutations: Vec<Mutation>) -> Result<Response, StoreError> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        let nonce = Nonce::new(metrics.current_term, metrics.last_log_index.unwrap_or(1));
        let request = StoreCommand::Transaction(
            mutations
                .into_iter()
                .map(|x| MutationInner::convert(x, nonce.clone()))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        self.write_command_to_storage(payload).await
    }
}

impl Storage {
    /// Get the last log index processed by the node.
    ///
    /// # Returns
    /// The last log index, if available.
    pub fn last_log_index(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().last_log_index
    }

    /// Get the channel to the given node.
    ///
    /// Get the channel to the node if it is already established or create a new
    /// one. This method uses the connection pool.
    ///
    /// # Parameters
    /// - `target`: Node Id.
    /// - `addr`: String address of the node.
    ///
    /// # Returns
    /// A `Result` containing the `Channel`, or a `StoreError`.
    fn get_or_create_channel(&self, target: u64, addr: String) -> Result<Channel, StoreError> {
        // 1. Return existing connection if valid
        if let Some(channel) = self.connection_pool.get(&target) {
            return Ok(channel.clone());
        }

        // 2. Otherwise, build it (applying Optional TLS)
        let endpoint = Endpoint::from_shared(format!("https://{}", addr))?
            .tls_config(self.tls_watcher.borrow().clone())?;

        let channel = endpoint.connect_lazy();

        // 3. Cache it
        self.connection_pool.insert(target, channel.clone());
        Ok(channel)
    }

    /// Try to commit the command to the raft cluster.
    ///
    /// Attempt to commit command to the current node forwarding the request
    /// with a retry mechanism to the leader node.
    ///
    /// # Parameters
    /// - `command`: A command to apply to the cluster.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn write_command_to_storage(
        &self,
        command: crate::pb::api::CommandRequest,
    ) -> Result<Response, StoreError> {
        match self.raft.client_write(command.clone()).await {
            Ok(rsp) => Ok(rsp.data),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => {
                self.command_with_forwarding(command, leader_id, leader_node.rpc_addr)
                    .await
            }
            Err(other) => Err(other)?,
        }
    }

    /// Generic retry loop: on `Unavailable` with leader metadata, switch
    /// endpoint and retry.
    ///
    /// Apply the command to the cluster node by the ID and ADDR forwarding it
    /// to the "new" leader if the switch happens and a generic retry
    /// mechanism.
    ///
    /// # Parameters
    /// - `command`: A command to apply.
    /// - `node_id`: The cluster node id to connect to.
    /// - `node_addr`: The cluster node address.
    ///
    /// # Returns
    /// A `Result` containing the `Response`, or a `StoreError`.
    async fn command_with_forwarding(
        &self,
        command: crate::pb::api::CommandRequest,
        node_id: u64,
        node_addr: String,
    ) -> Result<Response, StoreError> {
        let max_retries = 3;

        let mut node_addr = node_addr;
        let mut node_id = node_id;

        for _attempt in 0..=max_retries {
            // Establish a gRPC channel to the given node
            let channel = self.get_or_create_channel(node_id, node_addr)?;
            // Init the client
            let mut client = StorageServiceClient::new(channel);
            // Try to execute the command
            let result = client.command(command.clone()).await;

            match result {
                Ok(resp) => return Ok(resp.into_inner()),
                Err(status) if status.code() == Code::Unavailable => {
                    // Extract leader endpoint from gRPC metadata
                    // TODO: teach the gRPC app to start exposing the headers.
                    let leader_addr = status
                        .metadata()
                        .get(LEADER_ENDPOINT_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let leader_id: Option<u64> = status
                        .metadata()
                        .get(LEADER_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.parse())
                        .transpose()?;

                    if let (Some(addr), Some(id)) = (leader_addr, leader_id) {
                        debug!("forwarding request to leader at {}", addr);
                        node_addr = addr;
                        node_id = id;
                        continue;
                    }

                    return Err(eyre!(
                        "Unavailable but no leader endpoint in metadata: {}",
                        status
                    )
                    .into());
                }
                Err(status) => {
                    return Err(eyre!("RPC failed: {}", status).into());
                }
            }
        }

        Err(eyre!("max retries exceeded").into())
    }
}
