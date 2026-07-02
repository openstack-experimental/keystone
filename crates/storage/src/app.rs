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
use openstack_keystone_storage_crypto::{DekEpoch, EnvKek, KekProvider, Pkcs11KekStub};

use crate::protobuf as pb;
use openraft::ReadPolicy;
use openraft::errors::{ForwardToLeader, LinearizableReadError, RaftError};
use tonic::Code;
use tonic::service::Routes;
use tonic::transport::Channel;
use tracing::debug;

use openstack_keystone_config::ConfigManager;

use crate::ApiStoreError;
use crate::StorageApi;
use crate::StoreError;
use crate::StoreResponse;
use crate::Violation;
use crate::audit::{AuditForwarder, AuditRecord};
use crate::grpc::cluster_admin_service::ClusterAdminServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::grpc::storage_service::StorageServiceImpl;
use crate::network::{CertExpiryWatchdog, NetworkManager, RaftTlsClient, init_tls_watcher};
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

/// Strip scheme (e.g. "https://") and trailing slash from an rpc_addr so that
/// "https://host:8300/" compares equal to "host:8300".  Both formats encode the
/// same gRPC endpoint and should not trigger uniqueness violations on restart.
pub fn normalize_rpc_addr(addr: &str) -> &str {
    let addr = addr.trim_end_matches('/');
    if let Some(pos) = addr.find("://") {
        // Skip scheme (e.g. "https" in "https://host:8300")
        let rest = &addr[pos + 3..];
        rest.trim_start_matches('/')
    } else {
        addr
    }
}

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
    let check_addr = normalize_rpc_addr(rpc_addr).to_owned();
    let check_id = node_id;
    let conflict = raft
        .with_raft_state(move |s| {
            s.membership_state
                .committed()
                .nodes()
                .find_map(|(nid, node)| {
                    if *nid == check_id && normalize_rpc_addr(&node.rpc_addr) != check_addr {
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

/// Best-effort live verification of node_id uniqueness against a reachable
/// cluster peer's *current* membership (ADR 0016-v2 §4.3 / F7).
///
/// `check_node_id_uniqueness` only reads this node's own persisted Raft
/// state, which cannot detect a conflict that appeared on the live cluster
/// while this node was offline (e.g. its old `(node_id, rpc_addr)` was
/// reused by a misconfigured or impersonating node during an outage).
///
/// Returns:
/// - `Ok(true)` if at least one configured peer was reached and its live
///   membership confirms no conflict.
/// - `Ok(false)` if no configured peer could be reached at all — verification
///   is inconclusive. The caller should log a prominent warning but proceed
///   rather than refuse to start: treating "no peer reachable" as fail-closed
///   would make it impossible to recover from a full-cluster outage where every
///   node restarts simultaneously with no live peer to ask (the ADR's literal
///   fail-closed wording does not distinguish that case from an active network
///   partition, so this is a deliberate, documented deviation in favor of
///   cluster recoverability).
/// - `Err` if a reachable peer's live membership shows an actual `(node_id,
///   rpc_addr)` conflict — a real, actionable signal, so this remains
///   fail-closed.
async fn verify_node_id_uniqueness_live(
    tls_client: &RaftTlsClient,
    node_id: u64,
    rpc_addr: &str,
    peers: &[(u64, String)],
) -> Result<bool, StoreError> {
    const PEER_CONTACT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let check_addr = normalize_rpc_addr(rpc_addr);

    for (_peer_id, peer_addr) in peers {
        // Skip only entries that are literally our own address — NOT
        // entries that share our node_id, since a peer advertising our
        // node_id at a *different* address is exactly the conflict this
        // check must detect (skipping on node_id would defeat the purpose
        // whenever a misconfigured node's own retry_join_nodes list still
        // contains the entry for the id it is impersonating).
        if normalize_rpc_addr(peer_addr) == check_addr {
            continue;
        }

        let attempt = async {
            let channel = tls_client.connect(peer_addr).await?;
            let mut client = ClusterAdminServiceClient::new(channel);
            client
                .metrics(())
                .await
                .map(|resp| resp.into_inner())
                .map_err(|s| StoreError::Other(eyre!("metrics RPC failed: {s}")))
        };

        let metrics = match tokio::time::timeout(PEER_CONTACT_TIMEOUT, attempt).await {
            Ok(Ok(metrics)) => metrics,
            Ok(Err(e)) => {
                tracing::debug!(peer_addr, error = %e, "peer unreachable during live uniqueness check");
                continue;
            }
            Err(_) => {
                tracing::debug!(peer_addr, "peer live uniqueness check timed out");
                continue;
            }
        };

        if let Some(membership) = metrics.membership {
            for (nid, node) in &membership.nodes {
                if *nid == node_id && normalize_rpc_addr(&node.rpc_addr) != check_addr {
                    tracing::error!(
                        node_id,
                        rpc_addr,
                        existing_addr = node.rpc_addr,
                        peer_addr,
                        "FATAL: live peer reports node_id already registered at a \
                         different address"
                    );
                    return Err(StoreError::Other(eyre!(
                        "FATAL: node_id {node_id} is registered at {} per live peer {peer_addr}; \
                         refusing to start with address {rpc_addr}",
                        node.rpc_addr
                    )));
                }
            }
        }

        // Reached a peer and found no conflict — verification complete;
        // no need to contact additional peers.
        return Ok(true);
    }

    Ok(false)
}

/// Initialize storage services backed by the raft.
///
/// # Parameters
/// - `config_manager`: Configuration manager.
///
/// # Returns
/// A `Result` containing the `Storage` instance, or a `StoreError`.
pub async fn init_storage(config_manager: &Arc<ConfigManager>) -> Result<Arc<Storage>, StoreError> {
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

    // Select and load the Key Encryption Key before any further
    // initialisation (ADR 0016-v2 §2.1).  Loading/erasing it first means core
    // dumps triggered during preflight cannot leak the key.
    //
    // The environment-provided KEK is a dev-mode-only fallback: ADR 0016-v2
    // §2.1 and invariant 6 require both `--dev-mode` and
    // `KEYSTONE_ALLOW_ENV_KEK=1` before it may be used. Outside dev-mode there
    // is currently no production KekProvider implementation (HSM/PKCS#11/KMS
    // is not yet wired up — see Pkcs11KekStub), so the node refuses to start
    // rather than silently falling back to an environment-provided key.
    let kek: Arc<dyn KekProvider> = if ds_config.dev_mode {
        if std::env::var("KEYSTONE_ALLOW_ENV_KEK").as_deref() != Ok("1") {
            return Err(StoreError::Other(eyre!(
                "dev_mode is enabled but KEYSTONE_ALLOW_ENV_KEK=1 is not set; \
                 refusing to start with an environment-provided KEK \
                 (ADR 0016-v2 §2.1, invariant 6)"
            )));
        }
        Arc::new(
            EnvKek::from_env()
                .map_err(|e| StoreError::Other(eyre!("failed to load KEYSTONE_DEV_KEK: {e}")))?,
        )
    } else {
        Arc::new(Pkcs11KekStub)
    };

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
    let (log_store, sm, current_dek, _revoked_deks, pending_rotations, quarantine_rx) =
        crate::new::<crate::TypeConfig, _>(ds_config.path, ds_config.node_id, kek.clone()).await?;
    let state_machine_store = Arc::new(sm);
    let tls_client = init_tls_watcher(config_manager).await?;
    let network = Arc::new(NetworkManager::new(tls_client.clone())?);

    // Spawn expiry watchdog for manual-TLS fallback (ADR §4.2). The 30-day
    // max-validity cap itself is enforced inside `get_client_tls_config` /
    // `get_server_tls_config` (network.rs) on every load — including the
    // `init_tls_watcher` call above — so it's checked here on startup and on
    // every subsequent hot-reload, not just once.
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

    // Additionally verify against a live peer's current membership, since
    // the local check above cannot detect a conflict that appeared while
    // this node was offline (ADR 0016-v2 §4.3 / F7).
    if !ds_config.retry_join_nodes.is_empty() {
        match verify_node_id_uniqueness_live(
            &tls_client,
            ds_config.node_id,
            &rpc_addr,
            &ds_config.retry_join_nodes,
        )
        .await
        {
            Ok(true) => {
                tracing::debug!("node_id uniqueness verified against a live cluster peer");
            }
            Ok(false) => {
                tracing::warn!(
                    node_id = ds_config.node_id,
                    "SECURITY: could not verify node_id uniqueness against any live peer \
                     (ADR 0016-v2 §4.3); proceeding on local state only. If this is a \
                     network partition rather than a full-cluster restart, a duplicate \
                     node_id may go undetected until Raft consensus surfaces it."
                );
            }
            Err(e) => return Err(e),
        }
    }

    // Derive the per-node audit HMAC key from the current DEK epoch (ADR §3.1).
    let audit_key = {
        let guard = current_dek.read().unwrap_or_else(|p| p.into_inner());
        guard
            .derive_audit_key(ds_config.node_id)
            .map_err(|e| StoreError::Other(eyre!("failed to derive audit HMAC key: {e}")))?
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

    let storage = Arc::new(Storage {
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
    });

    // Best-effort background forwarding of Raft-committed quarantine events
    // (ADR 0016-v2 §10 invariant 5). The local, synchronous quarantine
    // already took effect in FjallStateMachine::decrypt_state before this
    // channel is signalled; this task only propagates the fact cluster-wide.
    //
    // Holds a Weak reference so this task never keeps `Storage` (and the
    // underlying Fjall database handle) alive on its own — once the last
    // strong reference is dropped, the next upgrade() fails and the task
    // exits instead of leaking the node's resources indefinitely.
    {
        let storage_weak = Arc::downgrade(&storage);
        let mut quarantine_rx = quarantine_rx;
        tokio::spawn(async move {
            while let Some((node_id, partition)) = quarantine_rx.recv().await {
                let Some(storage) = storage_weak.upgrade() else {
                    break;
                };
                if let Err(e) = storage.propose_quarantine(node_id, partition.clone()).await {
                    tracing::warn!(
                        node_id,
                        partition,
                        error = %e,
                        "failed to propose quarantine via Raft; local quarantine \
                         remains in effect, cluster-wide visibility delayed"
                    );
                }
            }
        });
    }

    // Emergency-rotation confirmation-timeout sweeper (ADR 0016-v2 §6.2
    // step 1): only the current leader proactively aborts pending
    // emergency rotations whose 5-minute confirmation window has elapsed
    // with no ConfirmRotateDek, so the abort and its audit trail don't
    // depend on some future RPC happening to touch the same rotation_id.
    // Runs on every node but is a no-op unless that node is leader, so
    // exactly one abort (and one audit record) is produced per timeout.
    {
        let storage_weak = Arc::downgrade(&storage);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let Some(storage) = storage_weak.upgrade() else {
                    break;
                };
                if storage.current_leader() != Some(storage.node_id()) {
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expired: Vec<crate::store_command::PendingRotation> = {
                    let pending = storage
                        .pending_rotations
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    pending
                        .values()
                        .filter(|e| e.expires_at <= now)
                        .cloned()
                        .collect()
                };

                for entry in expired {
                    let cmd =
                        StoreCommand::Transaction(vec![MutationInner::AbortPendingRotation {
                            rotation_id: entry.rotation_id.clone(),
                        }]);
                    let Ok(payload) = crate::pb::api::CommandRequest::try_from(cmd) else {
                        continue;
                    };
                    match storage.write_command_to_storage(payload).await {
                        Ok(_) => {
                            storage.audit_forwarder.emit(AuditRecord::now(
                                "DEK_ROTATION_EMERGENCY_ABORTED",
                                &entry.initiator,
                                storage.node_id(),
                                entry.dek_version,
                                serde_json::json!({
                                    "rotation_id": entry.rotation_id,
                                    "expires_at": entry.expires_at,
                                    "reason": "confirmation window expired with no \
                                               ConfirmRotateDek",
                                }),
                            ));
                            tracing::warn!(
                                rotation_id = entry.rotation_id,
                                initiator = entry.initiator,
                                "SECURITY: emergency DEK rotation confirmation window \
                                 expired; automatically aborted"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                rotation_id = entry.rotation_id,
                                error = %e,
                                "failed to propose AbortPendingRotation via Raft"
                            );
                        }
                    }
                }
            }
        });
    }

    Ok(storage)
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
    let storage_svc_impl =
        StorageServiceImpl::new(storage.raft.clone(), storage.state_machine_store.clone());

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
        self.get_by_key(key, keyspace).await.map(|v| v.is_some())
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

        // Check ReadIndex first. On the leader we can safely proceed to
        // local reads. On a follower ReadIndex returns ForwardToLeader and
        // we forward the entire read to the leader – which already has the
        // committed data.
        match self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
            Ok(_) => {}
            Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(ForwardToLeader {
                leader_id,
                leader_node,
            }))) => {
                if let (Some(lead_id), Some(lead_node)) = (leader_id, leader_node) {
                    debug!(
                        leader_id = lead_id,
                        leader_addr = lead_node.rpc_addr,
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader; \
                         forwarding get_by_key to leader"
                    );

                    if let Ok(forwarded) = self
                        .forwarded_get_by_key(lead_id, lead_node.rpc_addr, key, keyspace)
                        .await
                    {
                        return Ok(forwarded);
                    }
                    debug!("forwarded get_by_key failed; falling back to local read");
                } else {
                    debug!(
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                         without leader info; falling back to local read"
                    );
                }
            }
            Err(e) => {
                return Err(ApiStoreError::Other(Box::new(StoreError::Other(
                    eyre::eyre!("ReadIndex failed: {e:?}"),
                ))));
            }
        }

        // Leader path: local metadata + data read.
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

        let Some(metadata) = metadata else {
            return Ok(None);
        };

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
                    metadata.dek_version,
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

        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix scan to
        // the leader via gRPC.
        match self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
            Ok(_) => {}
            Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(ForwardToLeader {
                leader_id,
                leader_node,
            }))) => {
                if let (Some(lead_id), Some(lead_node)) = (leader_id, leader_node) {
                    debug!(
                        leader_id = lead_id,
                        leader_addr = lead_node.rpc_addr,
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader; \
                         forwarding prefix to leader"
                    );

                    if let Ok(forwarded) = self
                        .forwarded_prefix_read(lead_id, lead_node.rpc_addr, prefix, keyspace)
                        .await
                    {
                        return Ok(forwarded);
                    }
                    debug!("forwarded prefix failed; falling back to local read");
                } else {
                    // No leader info — fall back to local read (e.g., removed node).
                    debug!(
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                         without leader info; falling back to local read"
                    );
                }
            }
            Err(e) => {
                return Err(ApiStoreError::Other(Box::new(StoreError::Other(
                    eyre::eyre!("ReadIndex failed: {e:?}"),
                ))));
            }
        }

        // Leader path: collect raw encrypted bytes + metadata locally,
        // then decrypt.
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

        raw_items
            .into_iter()
            .map(|(k, val_bytes, meta)| {
                let data = self
                    .state_machine_store
                    .decrypt_state(
                        &val_bytes,
                        meta.tier as u8,
                        &keyspace_bytes,
                        k.as_bytes(),
                        meta.dek_version,
                    )
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
        // On the leader, ReadIndex guarantees linearizable read. On a follower,
        // ReadIndex returns ForwardToLeader, so we forward the prefix-index
        // scan to the leader via gRPC.
        match self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
            Ok(_) => {}
            Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(ForwardToLeader {
                leader_id,
                leader_node,
            }))) => {
                if let (Some(lead_id), Some(lead_node)) = (leader_id, leader_node) {
                    debug!(
                        leader_id = lead_id,
                        leader_addr = lead_node.rpc_addr,
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                         for prefix_index; forwarding to leader"
                    );

                    if let Ok(forwarded) = self
                        .forwarded_prefix_index(lead_id, lead_node.rpc_addr, prefix)
                        .await
                    {
                        return Ok(forwarded);
                    }
                    debug!("forwarded prefix_index failed; falling back to local read");
                } else {
                    debug!(
                        "ensure_linearizable (ReadIndex) returned ForwardToLeader \
                         without leader info; falling back to local read"
                    );
                }
            }
            Err(e) => {
                return Err(ApiStoreError::Other(Box::new(StoreError::Other(
                    eyre::eyre!("ReadIndex failed: {e:?}"),
                ))));
            }
        }

        // Leader path: local index scan.
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
        let response: crate::ZeroizingResponse = {
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
        let response: crate::ZeroizingResponse = {
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

    async fn keyspace_exists(&self, keyspace: &str) -> Result<bool, ApiStoreError> {
        Ok(self.state_machine_store.keyspace_exists(keyspace))
    }

    async fn drop_keyspace(&self, keyspace: &str) -> Result<(), ApiStoreError> {
        self.state_machine_store
            .drop_keyspace(keyspace)
            .map_err(ApiStoreError::from)
    }

    async fn node_id(&self) -> u64 {
        self.node_id
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

    /// Forward a `get_by_key` read to the leader via gRPC.
    /// Leader decrypts and returns plaintext; follower wraps it in
    /// StoreDataEnvelope.
    async fn forwarded_get_by_key(
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
            Metadata::unpack(&inner.metadata).unwrap_or_else(|_| Metadata::new())
        };

        match inner.value {
            Some(data) => Ok(Some(StoreDataEnvelope { data, metadata })),
            None => Ok(None),
        }
    }

    /// Forward a `prefix` scan to the leader via gRPC.
    /// Leader decrypts and returns plaintext values with metadata.
    async fn forwarded_prefix_read(
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
                Metadata::unpack(&entry.metadata).unwrap_or_else(|_| Metadata::new())
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

    /// Forward a `prefix_index` scan to the leader via gRPC.
    async fn forwarded_prefix_index(
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
    async fn write_command_to_storage(
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

    /// Propose a `Quarantine` mutation via Raft, forwarding to the leader if
    /// this node is not currently leader (ADR 0016-v2 §10 invariant 5).
    ///
    /// Called from the background quarantine-forwarding task in
    /// [`init_storage`] whenever a local GCM failure threshold is reached.
    /// Best effort: the local, synchronous quarantine (in-memory block plus
    /// local Fjall marker) already took effect before this is invoked, so a
    /// failure here only delays cluster-wide visibility, not local safety.
    async fn propose_quarantine(&self, node_id: u64, partition: String) -> Result<(), StoreError> {
        let cmd = StoreCommand::Transaction(vec![MutationInner::Quarantine { node_id, partition }]);
        let payload = crate::pb::api::CommandRequest::try_from(cmd)
            .map_err(|e| StoreError::Other(eyre::eyre!("{e}")))?;
        self.write_command_to_storage(payload).await?;
        Ok(())
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
}

/// Convert the internal `ZeroizingResponse` to the public `StoreResponse`.
///
/// This is the legitimate hand-off point to the caller: the plaintext
/// leaves the zeroizing wrapper here because the caller needs an owned,
/// ordinary `Vec<u8>` to use (e.g. deserialize into a typed struct).
fn rb_resp_to_store_response(resp: crate::ZeroizingResponse) -> StoreResponse {
    StoreResponse {
        value: resp.value.map(|v| v.to_vec()),
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

#[cfg(test)]
mod normalize_tests {
    use super::normalize_rpc_addr;

    #[test]
    fn test_bare_address_unchanged() {
        assert_eq!(normalize_rpc_addr("host:8300"), "host:8300");
        assert_eq!(
            normalize_rpc_addr("keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"),
            "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"
        );
    }

    #[test]
    fn test_strips_scheme_and_trailing_slash() {
        assert_eq!(
            normalize_rpc_addr(
                "https://keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300/"
            ),
            "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300"
        );
        assert_eq!(normalize_rpc_addr("http://host:8300/"), "host:8300");
    }

    #[test]
    fn test_scheme_only_no_trailing_slash() {
        assert_eq!(normalize_rpc_addr("https://host:8300"), "host:8300");
    }

    #[test]
    fn test_normalization_is_equivalence_check() {
        // Same host:port, different formats → identical
        assert_eq!(
            normalize_rpc_addr("host:8300"),
            normalize_rpc_addr("https://host:8300/")
        );
    }

    #[test]
    fn test_different_hosts_not_equivalent() {
        assert_ne!(
            normalize_rpc_addr("host-a:8300"),
            normalize_rpc_addr("https://host-b:8300/")
        );
    }
}
