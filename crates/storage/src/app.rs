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
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use dashmap::DashMap;
use eyre::eyre;
use openraft::Config;
use openraft::async_runtime::WatchReceiver;
use openstack_keystone_storage_crypto::{DekEpoch, EnvKek, KekProvider};

use crate::protobuf as pb;
use openraft::ReadPolicy;
use openraft::errors::{ForwardToLeader, RaftError};
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::Channel;
use tracing::debug;

use openstack_keystone_config::ConfigManager;

use crate::ApiStoreError;
use crate::DataTier;
use crate::StorageApi;
use crate::StoreError;
use crate::StoreResponse;
use crate::Violation;
use crate::audit::AuditForwarder;
use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::grpc::storage_service::StorageServiceImpl;
use crate::network::{CertExpiryWatchdog, NetworkManager, RaftTlsClient, init_tls_watcher};
use crate::pb::api::Response;
use crate::pb::raft::cluster_admin_service_server::ClusterAdminServiceServer;
use crate::pb::raft::raft_service_server::RaftServiceServer;
use crate::protobuf::api::storage_service_client::StorageServiceClient;
use crate::protobuf::api::storage_service_server::StorageServiceServer;
use crate::protobuf::raft::AddLearnerRequest;
use crate::protobuf::raft::Node as PbNode;
use crate::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;
use crate::store_command::*;
use crate::types::*;
use openstack_keystone_storage_api::Node;

/// gRPC metadata header used to communicate the leader's endpoint to clients.
///
/// When a non-leader node receives a write request, it returns
/// `Status::unavailable` with this header set to the leader's address, so
/// clients can retry against the leader.
pub const LEADER_ENDPOINT_HEADER: &str = "x-openraft-leader-endpoint";
pub const LEADER_ID_HEADER: &str = "x-openraft-leader-id";

/// Check that `node_id` is not already registered in the committed cluster
/// membership with a different `rpc_addr`.
///
/// Reads local committed membership state — no network access required.  If
/// the committed membership contains `node_id` at a different address, this
/// indicates a misconfiguration or an impersonation attempt: we refuse to
/// start (fail-closed, per ADR 0016-v2 §4.3 / F7).
async fn check_node_id_uniqueness(
    raft: &Raft,
    node_id: u64,
    rpc_addr: &str,
) -> Result<(), StoreError> {
    let check_addr = rpc_addr.to_owned();
    let check_id = node_id;
    let conflict = raft
        .with_raft_state(move |s| {
            s.membership_state
                .committed()
                .nodes()
                .find_map(|(nid, node)| {
                    if *nid == check_id && node.rpc_addr != check_addr {
                        Some(node.rpc_addr.clone())
                    } else {
                        None
                    }
                })
        })
        .await
        .map_err(|e| StoreError::Other(eyre!("failed to read Raft membership state: {e}")))?;

    if let Some(existing_addr) = conflict {
        tracing::error!(
            node_id,
            rpc_addr,
            existing_addr,
            "FATAL: node_id already registered in cluster at a different address"
        );
        return Err(StoreError::Other(eyre!(
            "FATAL: node_id {node_id} already registered in cluster at {existing_addr}; \
             refusing to start with address {rpc_addr}"
        )));
    }

    tracing::debug!(node_id, rpc_addr, "node_id uniqueness check passed");
    Ok(())
}

/// Initialize storage services backed by the raft.
///
/// # Parameters
/// - `config_manager`: Configuration manager.
///
/// # Returns
/// A `Result` containing the `Storage` instance, or a `StoreError`.
pub async fn init_storage(config_manager: &Arc<ConfigManager>) -> Result<Storage, StoreError> {
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

    let ds_config = config_manager
        .config
        .read()
        .await
        .distributed_storage
        .as_ref()
        .ok_or(StoreError::ConfigMissing)?
        .clone();

    // Read and erase the Key Encryption Key from the environment before any
    // further initialisation (ADR 0016-v2 §2.1).  Erasing it first means core
    // dumps triggered during preflight cannot leak the key.
    let kek: Arc<dyn KekProvider> = Arc::new(
        EnvKek::from_env()
            .map_err(|e| StoreError::Other(eyre!("failed to load KEYSTONE_DEV_KEK: {e}")))?,
    );

    // Run OS-level security pre-flight checks after key material is cleared.
    // In production mode (dev_mode = false) any failure is fatal per ADR
    // 0016-v2 §9 / §12 invariant 12.
    crate::preflight::preflight_check(ds_config.dev_mode)
        .map_err(|msg| StoreError::Other(eyre::eyre!("{msg}")))?;

    if ds_config.dev_mode {
        tracing::warn!(
            "Distributed storage starting in dev_mode; production deployments \
             should not enable this (ADR 0016-v2 §12)"
        );
    }

    // Create stores and network
    let (log_store, sm, current_dek, _revoked_deks, pending_rotations) =
        crate::new::<crate::TypeConfig, _>(ds_config.path, ds_config.node_id, kek.clone()).await?;
    let state_machine_store = Arc::new(sm);
    let tls_client = init_tls_watcher(config_manager).await?;
    let network = Arc::new(NetworkManager::new(tls_client.clone())?);

    // Spawn TLS cert expiry watchdog for manual-TLS fallback (ADR §4.2).
    if let openstack_keystone_config::RaftTlsConfiguration::Tls(tls) = &ds_config.tls_configuration
        && let Some(cert_content) = tls.tls_cert_content.as_ref()
    {
        use secrecy::ExposeSecret;
        let cert_bytes = cert_content.expose_secret().to_vec();
        CertExpiryWatchdog::spawn(cert_bytes, false);
    }

    // Create Raft instance
    let raft = Raft::new(
        ds_config.node_id,
        raft_config.clone(),
        network.clone(),
        log_store,
        state_machine_store.clone(),
    )
    .await?;

    // Refuse to start if our node_id is already in the cluster under a different
    // address.
    let rpc_addr = ds_config.node_cluster_addr.to_string();
    check_node_id_uniqueness(&raft, ds_config.node_id, &rpc_addr).await?;

    // Derive the per-node audit HMAC key from the current DEK epoch (ADR §3.1).
    let audit_key = {
        let guard = current_dek.read().unwrap();
        guard
            .derive_audit_key(ds_config.node_id)
            .expect("derive audit key from DEK")
    };
    let (audit_forwarder, _audit_task) = AuditForwarder::spawn(audit_key);

    // Extract SPIFFE configuration when the cluster is in SPIFFE mTLS mode
    // so the admin service interceptor can validate SVID patterns.
    let (spiffe_trust_domains, spiffe_path_prefix, operator_role, allowed_peer_svids) =
        if let openstack_keystone_config::RaftTlsConfiguration::Spiffe(spiffe) =
            &ds_config.tls_configuration
        {
            (
                Some(spiffe.trust_domains.clone()),
                spiffe.spiffe_path_prefix.clone(),
                spiffe.operator_role.clone(),
                spiffe.allowed_peer_svids.clone(),
            )
        } else {
            (None, String::new(), String::new(), Vec::new())
        };

    Ok(Storage {
        connection_pool: DashMap::new(),
        raft,
        node_id: ds_config.node_id,
        state_machine_store,
        tls_client,
        kek,
        current_dek,
        audit_forwarder,
        pending_rotations,
        spiffe_trust_domains,
        spiffe_path_prefix,
        operator_role,
        allowed_peer_svids,
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
    let cluster_admin_svc_impl = ClusterAdminServiceImpl::new(
        storage.raft.clone(),
        storage.node_id,
        storage.kek.clone(),
        storage.current_dek.clone(),
        storage.audit_forwarder.clone(),
        storage.pending_rotations.clone(),
        storage.state_machine_store.clone(),
        storage.spiffe_trust_domains.clone(),
        storage.spiffe_path_prefix.clone(),
        storage.operator_role.clone(),
        storage.allowed_peer_svids.clone(),
    );
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
    /// TLS client mode for Raft peer connections.
    pub(crate) tls_client: RaftTlsClient,
    /// Raft instance.
    pub raft: Raft,
    /// This node's Raft ID (used to tag audit records for per-node
    /// attribution).
    node_id: u64,
    /// The state machine store for direct reads.
    state_machine_store: Arc<StateMachineStore>,
    /// Key Encryption Key for wrapping new DEKs during rotation.
    kek: Arc<dyn KekProvider>,
    /// Shared current DEK epoch, used by rotate_dek to determine the next
    /// version.
    current_dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// Audit record forwarder (non-blocking, HMAC-signed).
    pub audit_forwarder: AuditForwarder,
    /// Pending emergency DEK rotations (shared with FjallStateMachine).
    pending_rotations: Arc<Mutex<HashMap<String, crate::store_command::PendingRotation>>>,
    /// SPIFFE trust domains for SVID pattern validation. `None` in
    /// TLS-fallback mode — pattern and role checks are skipped.
    pub spiffe_trust_domains: Option<Vec<String>>,
    /// SPIFFE path prefix for SVID pattern validation (e.g.
    /// `/keystone/storage/`). Empty when in TLS-fallback mode — pattern
    /// checks are skipped.
    pub spiffe_path_prefix: String,
    /// SPIFFE role that authorizes sensitive management operations.  Empty when
    /// in TLS-fallback mode — role checks are skipped.
    pub operator_role: String,
    /// Allow-list of SPIFFE SVIDs accepted for peer-to-peer Raft operations.
    /// Empty list means trust-domain-only validation is used.
    pub allowed_peer_svids: Vec<String>,
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
    /// `ApiStoreError`.
    async fn contains_key(
        &self,
        key: &[u8],
        keyspace: Option<&str>,
    ) -> Result<bool, ApiStoreError> {
        let res: Result<bool, StoreError> = || -> Result<_, StoreError> {
            let ks = match keyspace {
                None => self.state_machine_store.data(),
                Some(name) => &self.state_machine_store.keyspace(name)?,
            };
            Ok(ks.contains_key(key)?)
        }();
        Ok(res?)
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

        // Read metadata first to determine the sensitivity tier.
        let key_str =
            String::from_utf8(key.to_vec()).map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
        let metadata: Option<Metadata> = (|| -> Result<_, StoreError> {
            Ok(self
                .state_machine_store
                .meta()
                .get(&key_str)?
                .map(|raw| Metadata::unpack(raw.as_ref()))
                .transpose()?)
        })()
        .map_err(ApiStoreError::from)?;

        // If the key has no metadata it does not exist yet.
        let Some(metadata) = metadata else {
            return Ok(None);
        };

        // Tier 2 (Sensitive) and 3 (Secret) require a linearizable ReadIndex
        // before reading from local state.
        if metadata.tier as u8 >= DataTier::Sensitive as u8 {
            self.raft
                .ensure_linearizable(ReadPolicy::ReadIndex)
                .await
                .map_err(|e| {
                    ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                        "ReadIndex failed: {e:?}"
                    ))))
                })?;
        }

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
                )?;
                Ok(Some(StoreDataEnvelope { data, metadata }))
            })();
        Ok(res?)
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

        // Phase 1: collect raw encrypted bytes + metadata synchronously.
        // Decryption happens after a potential async ReadIndex round-trip.
        let raw_items: Result<Vec<(String, Vec<u8>, Metadata)>, StoreError> = (|| {
            let ks_owned = keyspace_name
                .map(|n| self.state_machine_store.keyspace(n))
                .transpose()?;
            let ks = match ks_owned.as_ref() {
                None => self.state_machine_store.data(),
                Some(k) => k,
            };
            ks.prefix(prefix)
                .map(|item| {
                    let (key_bytes, val) = item.into_inner()?;
                    let k = String::from_utf8(key_bytes.to_vec())?;
                    let meta = if let Some(meta) = self.state_machine_store.meta().get(&k)? {
                        Metadata::unpack(&meta)?
                    } else {
                        let res = Metadata::new();
                        self.state_machine_store
                            .meta()
                            .insert(k.clone(), res.pack()?)?;
                        res
                    };
                    Ok((k, val.to_vec(), meta))
                })
                .collect()
        })();
        let raw_items = raw_items.map_err(ApiStoreError::from)?;

        // Phase 2: if any entry is SENSITIVE or SECRET, enforce linearizable read.
        let needs_read_index = raw_items
            .iter()
            .any(|(_, _, meta)| meta.tier as u8 >= DataTier::Sensitive as u8);
        if needs_read_index {
            self.raft
                .ensure_linearizable(ReadPolicy::ReadIndex)
                .await
                .map_err(|e| {
                    ApiStoreError::Other(Box::new(StoreError::Other(eyre::eyre!(
                        "ReadIndex failed: {e:?}"
                    ))))
                })?;
        }

        // Phase 3: decrypt all entries using the per-entry tier.
        raw_items
            .into_iter()
            .map(|(k, val_bytes, meta)| {
                let data = self
                    .state_machine_store
                    .decrypt_state(&val_bytes, meta.tier as u8, &keyspace_bytes, k.as_bytes())
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
        let response: Response = {
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
        let response: Response = {
            let request = StoreCommand::Transaction(vec![MutationInner::RemoveIndex {
                key: key.into_bytes(),
            }]);
            let payload = crate::pb::api::CommandRequest::try_from(request)?;
            self.write_command_to_storage(payload).await?
        };
        Ok(rb_resp_to_store_response(response))
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

    async fn is_initialized(&self) -> Result<bool, ApiStoreError> {
        Ok(self
            .raft
            .is_initialized()
            .await
            .map_err(|e| StoreError::RaftFatal { source: e })?)
    }

    async fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    async fn initialize(&self, nodes: HashMap<u64, Node>) -> Result<(), ApiStoreError> {
        let pb_nodes: HashMap<u64, pb::raft::Node> = nodes
            .into_iter()
            .map(|(id, node)| {
                (
                    id,
                    pb::raft::Node {
                        node_id: node.node_id,
                        rpc_addr: node.rpc_addr,
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
}

impl Storage {
    pub fn last_log_index(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().last_log_index
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Return the current Raft leader node id, if elected.
    pub fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    /// Join this node to the Raft cluster by calling [`add_learner`] on the
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
        // on transient failures (DNS propagation delay, port not yet bound, etc.).
        // No need to block here waiting for `current_leader()`.
        Ok(())
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
                    return Ok(resp);
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
}

/// Convert protobuf `Response` to lightweight `StoreResponse`.
fn rb_resp_to_store_response(resp: Response) -> StoreResponse {
    StoreResponse {
        value: resp.value,
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
