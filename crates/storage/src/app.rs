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

use openraft::Config;
use tonic::service::Routes;

use openstack_keystone_config::DistributedStorageConfiguration;

use crate::cluster_admin_service::ClusterAdminService;
use crate::network::Network;
use crate::pb::api::identity_service_server::IdentityServiceServer;
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::raft_service::RaftService;
use crate::store_service::StoreService;
use crate::{FjallStateMachine, types::*};

/// Build a Raft instance.
pub async fn init_raft(
    ks_config: &DistributedStorageConfiguration,
) -> Result<(Raft, Arc<FjallStateMachine>), StoreError> {
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
    let network = Network::new(ks_config)?;

    // Create Raft instance
    Ok((
        Raft::new(
            ks_config.node_id,
            raft_config.clone(),
            network,
            log_store,
            state_machine_store.clone(),
        )
        .await?,
        state_machine_store,
    ))
}

/// Initialize storage services backed by the raft.
pub async fn init_storage(
    ks_config: &DistributedStorageConfiguration,
) -> Result<Storage, StoreError> {
    // Create Raft instance
    let (raft, state_machine_store) = init_raft(ks_config).await?;

    //// Create the management service with raft instance
    let internal_service_impl = RaftService::new(raft.clone());
    let cluster_admin_impl = ClusterAdminService::new(raft.clone());
    let store_impl = StoreService::new(raft.clone(), state_machine_store.clone());

    Ok(Storage {
        admin: Arc::new(cluster_admin_impl),
        store: Arc::new(store_impl),
        raft: Arc::new(internal_service_impl),
    })
}

/// Distributed storage.
pub struct Storage {
    /// Admin service (cluster management).
    pub admin: Arc<ClusterAdminService>,
    /// Identity service (read/write operations).
    pub store: Arc<StoreService>,
    /// Raft service (voting and sync).
    pub raft: Arc<RaftService>,
}

/// Build a tonic `Server` instance for the raft instance.
pub async fn get_app_server(storage: &Storage) -> Result<Routes, StoreError> {
    //// The app service uses the default limit since it's user-facing.
    let raft_service = RaftServiceServer::new(storage.raft.clone());
    let identity_service = IdentityServiceServer::new(storage.store.clone());
    let cluster_admin_service = ClusterAdminServiceServer::new(storage.admin.clone());

    let mut router = Routes::builder();
    router
        .add_service(raft_service)
        .add_service(cluster_admin_service)
        .add_service(identity_service);

    Ok(router.routes())
}
