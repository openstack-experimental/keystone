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

use dashmap::DashMap;
use openraft::Config;
// use openraft::ReadPolicy;
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ForwardToLeader, RaftError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tonic::service::Routes;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use openstack_keystone_config::DistributedStorageConfiguration;

use crate::StoreError;
use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::grpc::storage_service::StorageServiceImpl;
use crate::network::NetworkManager;
use crate::network::init_tls_watcher;
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::protobuf::api::storage_service_client::StorageServiceClient;
use crate::protobuf::api::storage_service_server::StorageServiceServer;
use crate::store_command::*;
use crate::types::*;

/// Initialize storage services backed by the raft.
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
pub async fn get_app_server(storage: &Storage) -> Result<Routes, StoreError> {
    //// The app service uses the default limit since it's user-facing.

    let raft_svc_impl = RaftServiceImpl::new(storage.raft.clone());
    let cluster_admin_svc_impl = ClusterAdminServiceImpl::new(storage.raft.clone());
    let storage_svc_impl = StorageServiceImpl::new(storage.raft.clone());

    let raft_service = RaftServiceServer::new(raft_svc_impl);
    let cluster_admin_service = ClusterAdminServiceServer::new(cluster_admin_svc_impl);
    let storage_service = StorageServiceServer::new(storage_svc_impl);

    let mut router = Routes::builder();
    router
        .add_service(raft_service)
        .add_service(cluster_admin_service)
        .add_service(storage_service);

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

impl Storage {
    /// Mutation transaction
    ///
    /// # Arguments
    /// * `mutations` - List of mutations that must be applied as a single transaction.
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is deleted
    /// * `Err(Status)` - Error status if the set operation fails
    pub async fn transaction(&self, mutations: Vec<Mutation>) -> Result<(), StoreError> {
        let request = StoreCommand::Transaction(mutations);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        match self.raft.client_write(payload.clone()).await {
            Ok(_) => {}
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => {
                let channel = self.get_or_create_channel(leader_id, leader_node.rpc_addr)?;

                let mut client = StorageServiceClient::new(channel);
                client.command(payload).await?;
            }
            Err(other) => {
                return Err(other)?;
            }
        };
        Ok(())
    }

    /// Deletes a value for a given key in the distributed store.
    ///
    /// # Arguments
    /// * `key` - The key.
    /// * `keyspace` - Optional keyspace name.
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is deleted
    /// * `Err(Status)` - Error status if the set operation fails
    pub async fn remove<K, S>(&self, key: K, keyspace: Option<S>) -> Result<(), StoreError>
    where
        K: Into<Vec<u8>>,
        S: Into<String>,
    {
        let request = StoreCommand::Transaction(vec![Mutation::remove(key, keyspace)?]);
        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        match self.raft.client_write(payload.clone()).await {
            Ok(_) => {}
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => {
                let channel = self.get_or_create_channel(leader_id, leader_node.rpc_addr)?;

                let mut client = StorageServiceClient::new(channel);
                client.command(payload).await?;
            }
            Err(other) => {
                return Err(other)?;
            }
        };
        Ok(())
    }

    /// Gets a value for a given key from the distributed store.
    ///
    /// # Arguments
    /// * `key` - Contains the key to retrieve.
    /// * `keyspace` - Optional keyspace name.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Success response containing the value as bytes
    /// * `Err(Status)` - Error status if the get operation fails
    pub async fn get_by_key<T, K, S>(
        &self,
        key: K,
        keyspace: Option<S>,
    ) -> Result<Option<T>, StoreError>
    where
        T: DeserializeOwned,
        K: AsRef<[u8]>,
        S: AsRef<str>,
    {
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        let ks = match keyspace {
            None => self.state_machine_store.data(),
            Some(name) => &self.state_machine_store.keyspace(name)?,
        };
        let value = ks
            .get(&key)?
            .map(|x| rmp_serde::from_slice(x.as_ref()))
            .transpose()?;
        // TODO: at REST decryption would come here
        Ok(value)
    }

    /// List key value pairs by the prefix.
    ///
    /// Return key value pairs matching the specified prefix deserializing the data back to the
    /// requested type.
    ///
    /// # Arguments
    /// * `prefix` - The prefix to query.
    /// * `keyspace` - Optional keyspace name.
    ///
    /// # Returns
    /// * `Ok(Vec<(String, T)>` - Success response containing the value as bytes
    /// * `Err(Status)` - Error status if the operation fails
    pub async fn prefix<T, K, S>(
        &self,
        prefix: K,
        keyspace: Option<S>,
    ) -> Result<Vec<(String, T)>, StoreError>
    where
        T: DeserializeOwned,
        K: AsRef<[u8]>,
        S: AsRef<str>,
    {
        // wait for the node to apply the latest state
        // self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await?;

        let ks = match keyspace {
            None => self.state_machine_store.data(),
            Some(name) => &self.state_machine_store.keyspace(name)?,
        };
        // TODO: at REST decryption would come here
        ks.prefix(&prefix)
            .map(|item| {
                let (key, val) = item.into_inner()?;
                Ok((
                    String::from_utf8(key.to_vec())?,
                    rmp_serde::from_slice(val.as_ref())?,
                ))
            })
            .collect()
    }

    /// Sets a value for a given key in the distributed store.
    ///
    /// # Arguments
    /// * `key` - The key.
    /// * `value` - The value to set for the key.
    /// * `keyspace` - Optional keyspace name.
    ///
    /// # Returns
    /// * `Ok(Response)` - Success response after the value is set
    /// * `Err(StoreError)` - Error status if the set operation fails
    pub async fn set_value<K, V, S>(
        &self,
        key: K,
        value: V,
        keyspace: Option<S>,
    ) -> Result<(), StoreError>
    where
        K: Into<String>,
        V: Serialize,
        S: Into<String>,
    {
        let key: String = key.into();
        let request = StoreCommand::Transaction(vec![Mutation::set(key, value, keyspace)?]);

        let payload = crate::pb::api::CommandRequest::try_from(request)?;
        match self.raft.client_write(payload.clone()).await {
            Ok(_) => {
                tracing::debug!("written");
            }
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => {
                tracing::debug!("need to redirect to {:?}", leader_id);
                let channel = self.get_or_create_channel(leader_id, leader_node.rpc_addr)?;

                let mut client = StorageServiceClient::new(channel);
                client.command(payload).await?;
            }
            Err(other) => {
                tracing::debug!("error {:?}", other);
                return Err(other)?;
            }
        };
        Ok(())
    }

    /// Get the last log index processed by the node.
    pub fn last_log_index(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().last_log_index
    }

    /// Get the channel to the given node.
    ///
    /// Get the channel to the node if it is already establed or create a new one. This method uses
    /// the connection pool.
    ///
    /// # Arguments
    /// * `target` - Node Id.
    /// * `addr` - String address of the node.
    ///
    /// # Returns
    /// * `Ok(Channel)` - A channel result.
    /// * `Err(StoreError)` - An error if the operation fails.
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
}
