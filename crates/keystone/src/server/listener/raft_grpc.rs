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
//! Main Keystone executable.
//!
//! This is the entry point of the `keystone` binary.
use std::collections::HashMap;

use color_eyre::eyre::{Report, Result};
use tokio_util::sync::CancellationToken;
use tracing::info;

use openstack_keystone_distributed_storage::{app::get_app_server, network::get_server_tls_config};

use crate::config::Config;
use crate::keystone::ServiceState;

/// Start Raft backed distributed storage.
pub async fn start_raft_app(
    state: ServiceState,
    config: Config,
    cancel_token: CancellationToken,
) -> Result<(), Report> {
    if let Some(ds) = &config.distributed_storage
        && let Some(storage) = &state.storage
    {
        let storage_app = get_app_server(storage).await?;

        //let state_clone = shared_state.clone();

        // Without an explicit select of the default provider the initialization fails
        // since some of the dependencies cause rustls to have `ring` and
        // `aws_lc_rs` enabled.
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        rustls::crypto::CryptoProvider::install_default(provider).unwrap();

        let mut server =
            tonic::transport::Server::builder().tls_config(get_server_tls_config(&config)?)?;

        let tonic_router = server.add_routes(storage_app);

        let grpc_addr = ds.node_listener_addr;
        info!("Starting distributed storage at {:?}", grpc_addr);

        tonic_router
            .serve_with_shutdown(grpc_addr, async move {
                cancel_token.cancelled().await;
            })
            .await
            .unwrap();
    }

    Ok(())
}

/// Ensure Raft cluster is initialized with at least the current node.
pub async fn ensure_raft_initialized(state: ServiceState, config: Config) -> Result<(), Report> {
    if let Some(ds) = &config.distributed_storage
        && let Some(storage) = &state.storage
    {
        if !storage.raft.is_initialized().await?
            && ds.node_id == 0
            && let (Some(host), Some(port)) =
                (ds.node_cluster_addr.host(), ds.node_cluster_addr.port())
        {
            info!("Initializing the integrated storage since it is not initialized.");
            storage
                .raft
                .initialize(HashMap::from([(
                    0,
                    openstack_keystone_distributed_storage::pb::raft::Node {
                        node_id: 0,
                        rpc_addr: format!("{host}:{port}"),
                    },
                )]))
                .await?;
        }
    }
    Ok(())
}
