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
use std::path::Path;
use std::sync::Arc;

use openraft::Config;
use tonic::transport::{Server, server::Router};
use tracing::info;

use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::identity_service::IdentityServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::network::Network;
use crate::pb::api::identity_service_server::IdentityServiceServer;
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::types::*;

/// Start storage node.
pub async fn start_raft_app<P: AsRef<Path>>(
    node_id: NodeId,
    http_addr: String,
    db_path: P,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_future = get_app_server(node_id, db_path)
        .await?
        .serve(http_addr.parse()?);

    info!("Node {node_id} starting server at {http_addr}");
    server_future.await?;

    Ok(())
}

/// Build a tonic `Server` instance for the raft instance.
pub async fn get_app_server<P: AsRef<Path>>(
    node_id: NodeId,
    db_path: P,
) -> Result<Router, StoreError> {
    // Create a configuration for the raft instance.
    let config = Arc::new(
        Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        }
        .validate()?,
    );

    // Create stores and network
    let (log_store, sm) = crate::new::<crate::TypeConfig, _>(db_path).await?;
    let state_machine_store = Arc::new(sm);
    let network = Network {};

    // Create Raft instance
    let raft = Raft::new(
        node_id,
        config.clone(),
        network,
        log_store,
        state_machine_store.clone(),
    )
    .await?;

    //// Create the management service with raft instance
    let internal_service = RaftServiceImpl::new(raft.clone());
    let cluster_admin_service = ClusterAdminServiceImpl::new(raft.clone());
    let identity_service = IdentityServiceImpl::new(raft.clone(), state_machine_store.clone());

    //// The app service uses the default limit since it's user-facing.
    let raft_service = RaftServiceServer::new(internal_service);
    let identity_service = IdentityServiceServer::new(identity_service);
    let cluster_admin_service = ClusterAdminServiceServer::new(cluster_admin_service);

    Ok(Server::builder()
        .add_service(raft_service)
        .add_service(cluster_admin_service)
        .add_service(identity_service))
}
