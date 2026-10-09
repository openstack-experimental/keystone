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
//! Write forwarding and cluster administration on [`Storage`]: join,
//! demote, leadership transfer and DEK rotation proposals.

use super::*;

impl Storage {
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
    /// A `Result` containing the `ZeroizingResponse`, or a `StoreError`.
    async fn command_with_forwarding(
        &self,
        command: crate::pb::api::CommandRequest,
        node_id: u64,
        node_addr: String,
    ) -> Result<crate::ZeroizingResponse, StoreError> {
        let max_retries = 3;

        let mut node_addr = node_addr;
        let mut node_id = node_id;

        for _attempt in 0..=max_retries {
            // Establish a gRPC channel to the given node
            let channel = self.get_or_create_channel(node_id, node_addr).await?;
            // Init the client
            let mut client = StorageServiceClient::new(channel);
            // Try to execute the command
            let result = client.command(command.clone()).await;

            match result {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    // Check for violations
                    if let Some(v) = resp.violations.first() {
                        return Err(StoreError::Conflict {
                            subject: v.subject.clone(),
                            description: v.description.clone(),
                        });
                    }
                    // Wrap the deserialized wire response in the zeroizing
                    // type so it's scrubbed on drop for the rest of its
                    // lifetime in this process (ADR 0016-v2 §8).
                    return Ok(crate::ZeroizingResponse {
                        value: resp.value.map(zeroize::Zeroizing::new),
                        violations: resp.violations,
                    });
                }
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

    /// Return the current Raft leader node id, if elected.
    pub fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    /// Forward a `get_by_key` read to the leader via gRPC.
    /// Leader decrypts and returns plaintext; follower wraps it in
    /// StoreDataEnvelope.
    pub(super) async fn forwarded_get_by_key(
        &self,
        leader_id: u64,
        leader_addr: String,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Option<StoreDataEnvelope<Vec<u8>>>, ApiStoreError> {
        let channel = self.get_or_create_channel(leader_id, leader_addr).await?;
        let mut client = StorageServiceClient::new(channel);

        let msg = pb::api::ForwardedGetRequest {
            key: key.to_vec(),
            keyspace: keyspace.map(String::from),
        };
        let resp = client.forwarded_get(msg).await.map_err(|status| {
            ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                "forwarded get failed: {status}"
            ))))
        })?;
        let inner = resp.into_inner();

        if inner.not_found {
            return Ok(None);
        }

        let metadata = if inner.metadata.is_empty() {
            Metadata::new()
        } else {
            Metadata::unpack(&inner.metadata).map_err(|e| {
                ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                    "forwarded get: leader returned unparsable metadata: {e}"
                ))))
            })?
        };

        match inner.value {
            Some(data) => Ok(Some(StoreDataEnvelope { data, metadata })),
            None => Ok(None),
        }
    }

    /// Forward a `prefix_index` scan to the leader via gRPC.
    pub(super) async fn forwarded_prefix_index(
        &self,
        leader_id: u64,
        leader_addr: String,
        prefix: &[u8],
    ) -> Result<Vec<String>, ApiStoreError> {
        let channel = self.get_or_create_channel(leader_id, leader_addr).await?;
        let mut client = StorageServiceClient::new(channel);

        let msg = pb::api::ForwardedPrefixIndexRequest {
            prefix: prefix.to_vec(),
        };
        let resp = client.forwarded_prefix_index(msg).await.map_err(|status| {
            ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                "forwarded prefix_index failed: {status}"
            ))))
        })?;

        Ok(resp.into_inner().keys)
    }

    /// Forward a `prefix` scan to the leader via gRPC.
    /// Leader decrypts and returns plaintext values with metadata.
    pub(super) async fn forwarded_prefix_read(
        &self,
        leader_id: u64,
        leader_addr: String,
        prefix: &[u8],
        keyspace: Option<&str>,
    ) -> Result<Vec<(String, StoreDataEnvelope<Vec<u8>>)>, ApiStoreError> {
        let channel = self.get_or_create_channel(leader_id, leader_addr).await?;
        let mut client = StorageServiceClient::new(channel);

        let msg = pb::api::ForwardedPrefixRequest {
            prefix: prefix.to_vec(),
            keyspace: keyspace.map(String::from),
        };
        let resp = client.forwarded_prefix(msg).await.map_err(|status| {
            ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                "forwarded prefix failed: {status}"
            ))))
        })?;
        let inner = resp.into_inner();

        let mut result = Vec::new();
        for entry in inner.entries {
            let metadata = if entry.metadata.is_empty() {
                Metadata::new()
            } else {
                Metadata::unpack(&entry.metadata).map_err(|e| {
                    ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                        "forwarded prefix: leader returned unparsable metadata for key {:?}: {e}",
                        entry.key
                    ))))
                })?
            };

            result.push((
                entry.key,
                StoreDataEnvelope {
                    data: entry.value,
                    metadata,
                },
            ));
        }

        Ok(result)
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
    async fn get_or_create_channel(
        &self,
        target: u64,
        addr: String,
    ) -> Result<Channel, StoreError> {
        if let Some(channel) = self.connection_pool.get(&target) {
            return Ok(channel.clone());
        }

        let channel = self.tls_client.connect(&addr).await?;
        self.connection_pool.insert(target, channel.clone());
        Ok(channel)
    }

    /// Best-effort push of one local-origin emergency candidate to every
    /// current Raft membership peer (ADR 0028 §5). Independent of Raft/quorum
    /// -- reachability failures are logged and otherwise ignored; the next
    /// gossip sweep tick retries.
    pub(super) async fn gossip_candidate_to_peers(
        &self,
        candidate: &openstack_keystone_local_emergency_store::EmergencyCandidate,
    ) {
        let subsystem = match candidate.subsystem {
            openstack_keystone_local_emergency_store::Subsystem::Oauth2SigningKey => {
                pb::raft::EmergencySubsystem::Oauth2SigningKey
            }
            openstack_keystone_local_emergency_store::Subsystem::Dek => {
                pb::raft::EmergencySubsystem::Dek
            }
        };
        let req = pb::raft::GossipLocalEmergencyCandidateRequest {
            origin_node_id: self.node_id,
            subsystem: subsystem as i32,
            scope_id: candidate.scope_id.clone(),
            rotation_id: candidate.rotation_id.clone(),
            payload: candidate.payload.clone(),
            initiator: candidate.initiator.clone(),
            justification: candidate.justification.clone(),
            created_at_unix: candidate.created_at.timestamp(),
        };

        for (peer_id, peer_addr) in self.local_emergency_peers() {
            let channel = match self.tls_client.connect(&peer_addr).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(
                        peer_id,
                        peer_addr,
                        error = %e,
                        "local emergency gossip: peer unreachable"
                    );
                    continue;
                }
            };
            let mut client = ClusterAdminServiceClient::new(channel);
            match client
                .gossip_local_emergency_candidate(tonic::Request::new(req.clone()))
                .await
            {
                Ok(resp) => {
                    if resp.into_inner().conflict {
                        tracing::warn!(
                            peer_id,
                            rotation_id = candidate.rotation_id,
                            "SECURITY: LOCAL_EMERGENCY_CONFLICT -- peer holds a different \
                             active emergency candidate for this subsystem/scope; \
                             reconciliation must make an explicit choice (ADR 0028 §6)"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        peer_id,
                        peer_addr,
                        error = %e,
                        "local emergency gossip push failed"
                    );
                }
            }
        }
    }

    /// Join this node to the Raft cluster by calling `add_learner` on the
    /// leader.  Returns `Ok(())` once the leader accepts the learner; the
    /// actual Raft replication (heartbeats, log entries) happens asynchronously
    /// via OpenRaft's built-in retry loop.
    ///
    /// # Parameters
    /// - `leader_addr`: The gRPC address of the current cluster leader (e.g.
    ///   `hostname:8300`).
    /// - `my_cluster_addr`: This node's address that peers will connect to
    ///   (e.g. `hostname:8300`).
    pub async fn join_cluster(
        &self,
        leader_addr: &str,
        my_cluster_addr: &str,
    ) -> Result<(), StoreError> {
        let channel = self.tls_client.connect(leader_addr).await?;
        let mut client = ClusterAdminServiceClient::new(channel);

        adopt_cluster_dek(&mut client, &self.state_machine_store).await?;

        let _resp = client
            .add_learner(tonic::Request::new(AddLearnerRequest {
                node: Some(PbNode {
                    node_id: self.node_id,
                    rpc_addr: my_cluster_addr.to_string(),
                }),
            }))
            .await
            .map_err(|s| StoreError::Other(eyre::eyre!("add_learner gRPC call failed: {s}")))?;

        tracing::info!(
            my_id = self.node_id,
            leader_addr,
            my_cluster_addr,
            "add_learner accepted, replication will start asynchronously"
        );

        // Replication is handled by OpenRaft's ReplicationHandler which retries
        // on transient failures (DNS propagation delay, port not yet bound,
        // etc.). No need to block here waiting for `current_leader()`.
        Ok(())
    }

    pub fn last_log_index(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().last_log_index
    }

    /// Enumerate current Raft membership peers (excluding self) from the
    /// live metrics snapshot, for the ADR 0028 §5 gossip sweep. Reuses the
    /// same membership source `Metrics`/`list_peers` already expose --
    /// gossip does not maintain its own peer list.
    fn local_emergency_peers(&self) -> Vec<(u64, String)> {
        self.raft
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .nodes()
            .filter(|(nid, _)| **nid != self.node_id)
            .map(|(nid, node)| (*nid, node.rpc_addr.clone()))
            .collect()
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Propose `AbortPendingRotation` locally. Only the leader proposes it
    /// (admin mutations are rejected on the forwarded `command` RPC); on a
    /// follower this is a no-op (`Ok(false)`) because the leader's own
    /// sweeper handles it.
    pub async fn propose_abort_pending_rotation(
        &self,
        rotation_id: &str,
    ) -> Result<bool, StoreError> {
        let cmd = StoreCommand::Transaction(vec![MutationInner::AbortPendingRotation {
            rotation_id: rotation_id.to_owned(),
        }]);
        let payload = crate::pb::api::CommandRequest::try_from(cmd)
            .map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
        match self.raft.client_write(payload).await {
            Ok(_) => Ok(true),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => Ok(false),
            Err(other) => Err(other)?,
        }
    }

    /// Propose a `Quarantine` mutation via Raft, forwarding to the leader if
    /// this node is not currently leader (ADR 0016-v2 §10 invariant 5).
    ///
    /// Called from the background quarantine-forwarding task in
    /// [`init_storage`] whenever a local GCM failure threshold is reached.
    /// Best effort: the local, synchronous quarantine (in-memory block plus
    /// local Fjall marker) already took effect before this is invoked, so a
    /// failure here only delays cluster-wide visibility, not local safety.
    ///
    /// A follower forwards through the dedicated `ReportQuarantine` RPC; the
    /// data-plane `command` RPC rejects admin mutations such as `Quarantine`.
    pub(super) async fn propose_quarantine(
        &self,
        node_id: u64,
        partition: String,
    ) -> Result<(), StoreError> {
        let cmd = StoreCommand::Transaction(vec![MutationInner::Quarantine {
            node_id,
            partition: partition.clone(),
        }]);
        let payload = crate::pb::api::CommandRequest::try_from(cmd)
            .map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
        match self.raft.client_write(payload).await {
            Ok(_) => Ok(()),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader {
                leader_id: Some(leader_id),
                leader_node: Some(leader_node),
            }))) => {
                self.report_quarantine_with_forwarding(
                    node_id,
                    partition,
                    leader_id,
                    leader_node.rpc_addr,
                )
                .await
            }
            Err(other) => Err(other)?,
        }
    }

    /// Send a `ReportQuarantine` to `leader_id`, following `Unavailable`
    /// leader hints (same retry semantics as
    /// [`Self::command_with_forwarding`]).
    async fn report_quarantine_with_forwarding(
        &self,
        node_id: u64,
        partition: String,
        leader_id: u64,
        leader_addr: String,
    ) -> Result<(), StoreError> {
        let max_retries = 3;
        let mut target_id = leader_id;
        let mut target_addr = leader_addr;
        let request = crate::pb::api::ReportQuarantineRequest { node_id, partition };

        for _attempt in 0..=max_retries {
            let channel = self.get_or_create_channel(target_id, target_addr).await?;
            let mut client = StorageServiceClient::new(channel);
            match client.report_quarantine(request.clone()).await {
                Ok(_) => return Ok(()),
                Err(status) if status.code() == Code::Unavailable => {
                    let addr = status
                        .metadata()
                        .get(LEADER_ENDPOINT_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let id: Option<u64> = status
                        .metadata()
                        .get(LEADER_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map(str::parse)
                        .transpose()?;
                    if let (Some(addr), Some(id)) = (addr, id) {
                        debug!("forwarding quarantine report to leader at {}", addr);
                        target_addr = addr;
                        target_id = id;
                        continue;
                    }
                    return Err(eyre!(
                        "ReportQuarantine unavailable and no leader hint: {}",
                        status
                    )
                    .into());
                }
                Err(status) => {
                    return Err(eyre!("ReportQuarantine failed: {}", status).into());
                }
            }
        }

        Err(eyre!("ReportQuarantine: max retries exceeded").into())
    }

    /// Direct access to the underlying state machine store, for callers
    /// that need the lower-level `FjallStateMachine` API (e.g. `decrypt_state`,
    /// raw keyspace access) rather than the `StorageApi` request/response
    /// surface.
    pub fn state_machine_store(&self) -> &Arc<StateMachineStore> {
        &self.state_machine_store
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
    /// A `Result` containing the `ZeroizingResponse`, or a `StoreError`.
    pub(super) async fn write_command_to_storage(
        &self,
        command: crate::pb::api::CommandRequest,
    ) -> Result<crate::ZeroizingResponse, StoreError> {
        match self.raft.client_write(command.clone()).await {
            Ok(rsp) => {
                let rsp = rsp.data;
                // Check for violations (e.g., CAS conflicts)
                if let Some(v) = rsp.violations.first() {
                    return Err(StoreError::Conflict {
                        subject: v.subject.clone(),
                        description: v.description.clone(),
                    });
                }
                Ok(rsp)
            }
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
}
