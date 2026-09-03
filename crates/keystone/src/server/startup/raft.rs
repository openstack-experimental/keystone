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

//! Raft gRPC listener startup and cluster join.

use color_eyre::eyre::{Report, Result};
use tokio::task::JoinSet;
use tracing::{debug, error};

use super::Startup;
use crate::server::listener::raft_grpc;

/// Start the Raft gRPC listener and join the cluster, when distributed
/// storage is configured.
pub async fn start(startup: &Startup, handles: &mut JoinSet<()>) -> Result<(), Report> {
    let cfg = &startup.cfg;
    if cfg.distributed_storage.is_none() {
        return Ok(());
    }
    let token = &startup.token;
    #[allow(clippy::expect_used)]
    let raft_storage = startup
        .concrete_storage
        .as_ref()
        .expect("storage is None")
        .clone();
    let raft_storage_init = raft_storage.clone();
    let raft_config = cfg.clone();

    // Signal channel: start_raft_app sends `true` once the gRPC listener is
    // bound. `ensure_raft_initialized` waits for this before calling
    // join_cluster, ensuring the new node's listener is ready to accept
    // replication traffic from the leader.
    let (raft_bound_tx, raft_bound_rx) = tokio::sync::watch::channel(false);
    let raft_cancel_token = token.clone();
    let raft_task_token = token.clone();
    handles.spawn(async move {
        if let Err(e) =
            raft_grpc::start_raft_app(raft_storage, raft_config, raft_cancel_token, raft_bound_tx)
                .await
        {
            error!("Raft gRPC listener error: {:#}", e);
            raft_task_token.cancel();
        }
        debug!("Raft gRPC task exited");
    });
    debug!("Raft task spawned, calling ensure_raft_initialized...");
    raft_grpc::ensure_raft_initialized(raft_storage_init, cfg.clone(), raft_bound_rx).await?;
    debug!("Raft initialized and ready");
    Ok(())
}
