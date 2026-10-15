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

//! First-start Raft membership: self-bootstrap or auto-join.

use std::sync::Arc;

use crate::StorageApi;
use crate::app::Storage;
use crate::config::DistributedStorageConfiguration;

/// Ensure Raft cluster is initialized with at least the current node, or join
/// an existing cluster if this node is not the bootstrap node.
///
/// `listener_bound` is a watch channel that the Raft gRPC listener task
/// signals once the listener is bound.  Non-bootstrap nodes wait for this
/// signal before calling `add_learner`, ensuring their own listener is ready to
/// accept replication traffic from the leader.
pub async fn ensure_raft_initialized(
    storage: Arc<Storage>,
    ds: DistributedStorageConfiguration,
    mut listener_bound: tokio::sync::watch::Receiver<bool>,
) -> Result<(), eyre::Report> {
    let ds = &ds;

    let node_id = storage.node_id();
    let my_cluster_addr = ds.node_cluster_addr.to_string();
    tracing::debug!(
        node_id,
        peers = ds.retry_join_nodes.len(),
        "Checking whether Raft storage is initialized..."
    );

    // Bootstrap node (node_id == 0): self-bootstrap as a single-node cluster.
    // Known peers join later via [add_learner] (non-bootstrap path below).
    // Skipped with `auto_bootstrap = false` so a disaster-recovery restore
    // can still install the backup's Raft state into this node.
    if ds.auto_bootstrap && !storage.is_initialized().await? && node_id == 0 {
        let self_node = openstack_keystone_storage_api::Node {
            node_id,
            rpc_addr: my_cluster_addr.clone(),
        };

        tracing::info!("Self-bootstrapping integrated storage as single-node cluster.");
        storage
            .initialize([(node_id, self_node)].into_iter().collect())
            .await?;
        return Ok(());
    }

    // `auto_bootstrap = false`: stay uninitialized and wait for an operator
    // `storage restore` (disaster recovery) or `storage init`/`join`.
    if !ds.auto_bootstrap && !storage.is_initialized().await? {
        tracing::info!(
            node_id,
            "auto_bootstrap is disabled — Raft storage left uninitialized, \
             waiting for `storage restore`, `storage init` or `storage join`"
        );
        return Ok(());
    }

    // Non-bootstrap node: auto-join using known peer addresses.
    if ds.retry_join_nodes.is_empty() {
        if !storage.is_initialized().await? {
            return Err(eyre::Report::msg(
                "Raft cluster is not initialized and no retry_join_nodes configured - \
                 set retry_join_nodes or join manually",
            ));
        }
        return Ok(());
    }

    // Already-initialized node (e.g. pod restart): storage has persisted Raft
    // state including membership. The node is already a member, so no need to
    // call add_learner which would fail with "node_id already registered".
    if storage.is_initialized().await? {
        let node_id = storage.node_id();
        tracing::info!(
            node_id,
            "Raft storage already initialized — skipping cluster join (node restart)"
        );
        return Ok(());
    }

    let join_addrs: Vec<&str> = ds
        .retry_join_nodes
        .iter()
        .filter(|(pid, _)| *pid != node_id)
        .map(|(_, addr)| addr.as_str())
        .collect();

    if join_addrs.is_empty() {
        return Err(eyre::Report::msg(
            "retry_join_nodes contains only this node - no peers to join",
        ));
    }

    // Wait for our own Raft gRPC listener to be bound before calling
    // add_learner.  Without this, the leader may try to replicate back to us
    // before the port is accepting connections, causing join timeouts.
    tracing::debug!("Waiting up to 30s for the Raft gRPC listener to bind...");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let _ = listener_bound.changed().await;
    })
    .await
    .map_err(|_| {
        eyre::Report::msg("Raft listener did not bind within 30s — aborting cluster join")
    })?;

    // With publishNotReadyAddresses: true on the headless service, DNS records
    // are available for non-ready pods.  The FQDN from config will resolve
    // correctly, so the leader can replicate to us once replication starts.
    tracing::info!(
        node_id,
        join_count = join_addrs.len(),
        "Waiting for Raft cluster to be available before joining..."
    );
    for attempt in 0..60 {
        for join_addr in &join_addrs {
            match storage.join_cluster(join_addr, &my_cluster_addr).await {
                Ok(()) => {
                    tracing::info!(node_id, join_addr, "Successfully joined Raft cluster.");
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!(
                        node_id,
                        join_addr,
                        attempt,
                        ?e,
                        "join attempt failed, trying next address"
                    );
                }
            }
        }
        if attempt % 10 == 0 {
            tracing::info!(
                node_id,
                attempt,
                "still waiting for join addresses to be available"
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(eyre::Report::msg(
        "timed out joining Raft cluster - none of the retry_join_nodes responded",
    ))
}
